#ifdef MONTAUK_HAVE_URING

#include "app/MetricsServer.hpp"
#include <liburing.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <charconv>

namespace montauk::app {

// Tags for distinguishing CQE sources
enum class UringTag : uint64_t { ListenPoll = 1, StopPoll = 2 };

MetricsServer::MetricsServer(const SnapshotBuffers& buffers, uint16_t port)
    : buffers_(buffers), port_(port) {}

MetricsServer::~MetricsServer() { stop(); }

void MetricsServer::start() {
  thread_ = std::jthread([this](std::stop_token st){ run(st); });
}

void MetricsServer::stop() {
  if (stop_eventfd_ >= 0) {
    uint64_t val = 1;
    (void)::write(stop_eventfd_, &val, sizeof(val));
  }
  if (thread_.joinable()) {
    thread_.request_stop();
    thread_.join();
  }
}

void MetricsServer::run(std::stop_token st) {
  // Create listening socket
  listen_fd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (listen_fd_ < 0) {
    std::fprintf(stderr, "montauk: metrics server: socket() failed: %s\n", std::strerror(errno));
    return;
  }

  int optval = 1;
  (void)::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port_);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (::bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
    std::fprintf(stderr, "montauk: metrics server: bind(:%d) failed: %s\n", port_, std::strerror(errno));
    ::close(listen_fd_);
    listen_fd_ = -1;
    return;
  }

  if (::listen(listen_fd_, 4) < 0) {
    std::fprintf(stderr, "montauk: metrics server: listen() failed: %s\n", std::strerror(errno));
    ::close(listen_fd_);
    listen_fd_ = -1;
    return;
  }

  // Create eventfd for clean shutdown
  stop_eventfd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (stop_eventfd_ < 0) {
    std::fprintf(stderr, "montauk: metrics server: eventfd() failed: %s\n", std::strerror(errno));
    ::close(listen_fd_);
    listen_fd_ = -1;
    return;
  }

  // Initialize io_uring
  struct io_uring ring{};
  if (io_uring_queue_init(16, &ring, 0) < 0) {
    std::fprintf(stderr, "montauk: metrics server: io_uring_queue_init() failed: %s\n", std::strerror(errno));
    ::close(stop_eventfd_);
    stop_eventfd_ = -1;
    ::close(listen_fd_);
    listen_fd_ = -1;
    return;
  }

  // Submit poll requests for listen_fd and stop_eventfd
  auto submit_poll = [&](int fd, UringTag tag) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
    io_uring_prep_poll_add(sqe, fd, POLLIN);
    io_uring_sqe_set_data64(sqe, static_cast<uint64_t>(tag));
  };

  submit_poll(listen_fd_, UringTag::ListenPoll);
  submit_poll(stop_eventfd_, UringTag::StopPoll);
  io_uring_submit(&ring);

  std::fprintf(stderr, "montauk: metrics server listening on :%d\n", port_);

  // Event loop
  while (!st.stop_requested()) {
    struct io_uring_cqe* cqe = nullptr;
    int ret = io_uring_wait_cqe(&ring, &cqe);
    if (ret < 0) {
      if (ret == -EINTR) continue;
      break;
    }

    auto tag = static_cast<UringTag>(io_uring_cqe_get_data64(cqe));
    int res = cqe->res;
    io_uring_cqe_seen(&ring, cqe);

    if (tag == UringTag::StopPoll || st.stop_requested()) {
      break;
    }

    if (tag == UringTag::ListenPoll && res >= 0) {
      // Accept and handle client
      int client_fd = ::accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
      if (client_fd >= 0) {
        handle_client(client_fd);
        ::close(client_fd);
      }
      // Re-arm listen poll
      submit_poll(listen_fd_, UringTag::ListenPoll);
      io_uring_submit(&ring);
    }
  }

  // Cleanup
  io_uring_queue_exit(&ring);
  if (stop_eventfd_ >= 0) { ::close(stop_eventfd_); stop_eventfd_ = -1; }
  if (listen_fd_ >= 0) { ::close(listen_fd_); listen_fd_ = -1; }
}

void MetricsServer::handle_client(int fd) {
  // Set timeouts to prevent slow clients from blocking the server
  struct timeval tv{.tv_sec = 5, .tv_usec = 0};
  (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  int one = 1;
  (void)::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

  // Read HTTP request
  char reqbuf[4096];
  ssize_t nr = ::recv(fd, reqbuf, sizeof(reqbuf) - 1, 0);
  if (nr <= 0) return;
  reqbuf[nr] = '\0';

  // Find end of request line
  std::string_view req(reqbuf, static_cast<size_t>(nr));
  auto line_end = req.find('\r');
  if (line_end == std::string_view::npos) line_end = req.find('\n');
  std::string_view request_line = req.substr(0, line_end);

  // Route
  std::string headers;
  std::string body;

  if (request_line.contains("GET /metrics")) {
    // Serve Prometheus metrics
    MetricsSnapshot ms = read_metrics_snapshot();
    body = snapshot_to_prometheus(ms);

    headers = "HTTP/1.1 200 OK\r\n"
              "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
              "Connection: close\r\n"
              "Content-Length: ";
    char len_buf[16];
    auto [ptr, ec] = std::to_chars(len_buf, len_buf + sizeof(len_buf), body.size());
    headers.append(len_buf, ptr);
    headers += "\r\n\r\n";
  } else if (request_line.starts_with("GET / ") || request_line == "GET /") {
    body = "montauk: use /metrics\n";
    headers = "HTTP/1.1 200 OK\r\n"
              "Content-Type: text/plain\r\n"
              "Connection: close\r\n"
              "Content-Length: ";
    char len_buf[16];
    auto [ptr, ec] = std::to_chars(len_buf, len_buf + sizeof(len_buf), body.size());
    headers.append(len_buf, ptr);
    headers += "\r\n\r\n";
  } else {
    body = "404 Not Found\n";
    headers = "HTTP/1.1 404 Not Found\r\n"
              "Content-Type: text/plain\r\n"
              "Connection: close\r\n"
              "Content-Length: 14\r\n\r\n";
  }

  // Send response via scatter-gather (headers + body, no concatenation)
  struct iovec iov[2] = {
    {.iov_base = headers.data(), .iov_len = headers.size()},
    {.iov_base = body.data(), .iov_len = body.size()}
  };
  struct msghdr msg{};
  msg.msg_iov = iov;
  msg.msg_iovlen = 2;
  (void)::sendmsg(fd, &msg, MSG_NOSIGNAL);
}

MetricsSnapshot MetricsServer::read_metrics_snapshot() {
  MetricsSnapshot ms{};
  uint64_t seq_before, seq_after;
  do {
    seq_before = buffers_.seq();
    const auto& s = buffers_.front();
    ms.cpu = s.cpu;
    ms.mem = s.mem;
    ms.vram = s.vram;
    ms.net = s.net;
    ms.disk = s.disk;
    ms.fs = s.fs;
    ms.thermal = s.thermal;
    ms.total_processes = s.procs.total_processes;
    ms.running_processes = s.procs.running_processes;
    ms.state_sleeping = s.procs.state_sleeping;
    ms.state_zombie = s.procs.state_zombie;
    ms.total_threads = s.procs.total_threads;
    int n = std::min(static_cast<int>(s.procs.processes.size()), MetricsSnapshot::MAX_TOP_PROCS);
    std::copy_n(s.procs.processes.begin(), n, ms.top_procs.begin());
    ms.top_procs_count = n;
    seq_after = buffers_.seq();
  } while (seq_before != seq_after);
  return ms;
}

} // namespace montauk::app

#endif // MONTAUK_HAVE_URING
