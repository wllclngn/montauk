#include "app/ProviderEmitter.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace montauk::app {

namespace {
// Same location ProviderCollector scans, so montauk's emitter sits in the mesh
// alongside every other producer's own socket.
std::string providers_dir() {
  const char* xdg = std::getenv("XDG_RUNTIME_DIR");
  if (xdg && *xdg) return std::string(xdg) + "/montauk/providers";
  return "/run/montauk/providers";
}
} // namespace

ProviderEmitter::ProviderEmitter(std::string name) : name_(std::move(name)) {
  path_ = providers_dir() + "/" + name_ + ".sock";
}

ProviderEmitter::~ProviderEmitter() {
  thread_.request_stop();
  // Break a blocking poll/accept by closing the listener.
  if (listen_fd_ >= 0) {
    ::shutdown(listen_fd_, SHUT_RDWR);
    ::close(listen_fd_);
    listen_fd_ = -1;
  }
  if (thread_.joinable()) thread_.join();
  if (!path_.empty()) ::unlink(path_.c_str());
}

bool ProviderEmitter::start() {
  std::error_code ec;
  std::filesystem::create_directories(providers_dir(), ec);

  if (path_.size() >= sizeof(sockaddr_un::sun_path)) return false;
  ::unlink(path_.c_str()); // clear a stale socket from a previous run

  int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return false;

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::memcpy(addr.sun_path, path_.c_str(), path_.size() + 1);
  if (::bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
    ::close(fd);
    return false;
  }
  if (::listen(fd, 8) < 0) {
    ::close(fd);
    ::unlink(path_.c_str());
    return false;
  }
  listen_fd_ = fd;
  thread_ = std::jthread([this](std::stop_token st) { serve(st); });
  return true;
}

void ProviderEmitter::update(std::string payload) {
  std::lock_guard<std::mutex> g(mu_);
  snapshot_ = std::move(payload);
}

void ProviderEmitter::serve(std::stop_token st) {
  while (!st.stop_requested()) {
    pollfd pfd{listen_fd_, POLLIN, 0};
    int r = ::poll(&pfd, 1, 200); // bounded so stop is observed promptly
    if (r <= 0) continue;
    if (!(pfd.revents & POLLIN)) continue;

    int conn = ::accept(listen_fd_, nullptr, nullptr);
    if (conn < 0) continue;

    // Clone under the lock, write outside it — a slow reader must not block the
    // producer's update().
    std::string data;
    {
      std::lock_guard<std::mutex> g(mu_);
      data = snapshot_;
    }
    size_t off = 0;
    while (off < data.size()) {
      ssize_t n = ::write(conn, data.data() + off, data.size() - off);
      if (n <= 0) {
        if (n < 0 && errno == EINTR) continue;
        break;
      }
      off += static_cast<size_t>(n);
    }
    ::close(conn); // EOF signals end-of-snapshot to the reader
  }
}

} // namespace montauk::app
