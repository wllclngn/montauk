#include "app/LogWriter.hpp"
#include "app/MetricsServer.hpp"
#include <cstdio>
#include <cstring>
#include <ctime>
#include <charconv>
#include <cerrno>

namespace montauk::app {

LogWriter::LogWriter(const SnapshotBuffers& buffers, std::filesystem::path log_dir,
                     std::chrono::milliseconds interval)
    : buffers_(buffers), log_dir_(std::move(log_dir)), interval_(interval) {
  std::error_code ec;
  std::filesystem::create_directories(log_dir_, ec);
  if (ec) {
    std::fprintf(stderr, "montauk: LogWriter: failed to create %s: %s\n",
                 log_dir_.c_str(), ec.message().c_str());
  }
}

LogWriter::~LogWriter() { stop(); }

void LogWriter::start() {
  thread_ = std::jthread([this](std::stop_token st){ run(st); });
}

void LogWriter::stop() {
  if (thread_.joinable()) {
    thread_.request_stop();
    thread_.join();
  }
}

void LogWriter::run(std::stop_token st) {
  std::ofstream file;
  std::filesystem::path current_path;

  std::fprintf(stderr, "montauk: LogWriter: writing to %s/ (interval %lldms)\n",
               log_dir_.c_str(), static_cast<long long>(interval_.count()));

  // Wait for first real publish to avoid writing all-zeros cold-start block
  while (buffers_.seq() == 0 && !st.stop_requested()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }

  while (!st.stop_requested()) {
    auto now = std::chrono::system_clock::now();
    auto required_path = chunk_path();

    // Rotate on hour boundary
    if (required_path != current_path) {
      if (file.is_open()) {
        file.flush();
        file.close();
      }
      file.open(required_path, std::ios::app);
      if (!file) {
        std::fprintf(stderr, "montauk: LogWriter: failed to open %s: %s\n",
                     required_path.c_str(), std::strerror(errno));
        std::this_thread::sleep_for(std::chrono::seconds(1));
        continue;
      }
      current_path = required_path;
    }

    // Read snapshot via seqlock
    MetricsSnapshot ms = read_metrics_snapshot(buffers_);

    // Timestamp in milliseconds since epoch
    auto epoch_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    char ts_buf[32];
    auto [ptr, ec] = std::to_chars(ts_buf, ts_buf + sizeof(ts_buf), epoch_ms);

    // Write timestamp + snapshot block
    file.write("# montauk_scrape_timestamp_ms ", 30);
    file.write(ts_buf, ptr - ts_buf);
    file.put('\n');

    std::string body = snapshot_to_prometheus(ms);
    file.write(body.data(), static_cast<std::streamsize>(body.size()));

    file.flush();

    auto wake = now + interval_;
    std::this_thread::sleep_until(wake);
  }

  if (file.is_open()) {
    file.flush();
    file.close();
  }
}

std::filesystem::path LogWriter::chunk_path() const {
  auto now = std::chrono::system_clock::now();
  auto now_t = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
  ::localtime_r(&now_t, &tm);

  char buf[64];
  std::snprintf(buf, sizeof(buf), "montauk_%04d-%02d-%02d_%02d.prom",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour);

  return log_dir_ / buf;
}

} // namespace montauk::app
