#pragma once

#include <filesystem>
#include <fstream>
#include <thread>
#include <stop_token>
#include <chrono>
#include "app/SnapshotBuffers.hpp"

namespace montauk::app {

class LogWriter {
public:
  LogWriter(const SnapshotBuffers& buffers, std::filesystem::path log_dir,
            std::chrono::milliseconds interval = std::chrono::milliseconds(1000));
  ~LogWriter();
  LogWriter(const LogWriter&) = delete;
  LogWriter& operator=(const LogWriter&) = delete;

  void start();
  void stop();

private:
  void run(std::stop_token st);
  [[nodiscard]] std::filesystem::path chunk_path() const;

  const SnapshotBuffers& buffers_;
  std::filesystem::path log_dir_;
  std::chrono::milliseconds interval_;
  std::jthread thread_;
};

} // namespace montauk::app
