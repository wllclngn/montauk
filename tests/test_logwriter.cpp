#include "minitest.hpp"
#include "app/LogWriter.hpp"
#include "app/Producer.hpp"
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>
#include <string>
#include <cstdlib>
#include <unistd.h>

static std::filesystem::path test_dir(const char* suffix) {
  return std::filesystem::temp_directory_path() /
         ("montauk_logwriter_test_" + std::to_string(::getpid()) + "_" + suffix);
}

TEST(logwriter_creates_directory) {
  auto dir = test_dir("mkdir");
  std::filesystem::remove_all(dir);
  ASSERT_TRUE(!std::filesystem::exists(dir));

  montauk::app::SnapshotBuffers buffers;
  montauk::app::LogWriter writer(buffers, dir);
  ASSERT_TRUE(std::filesystem::is_directory(dir));

  std::filesystem::remove_all(dir);
}

TEST(logwriter_writes_snapshots) {
  auto dir = test_dir("write");
  std::filesystem::remove_all(dir);

  montauk::app::SnapshotBuffers buffers;
  montauk::app::Producer producer(buffers);
  producer.start();

  // Wait for first publish
  auto t0 = std::chrono::steady_clock::now();
  while (buffers.seq() == 0 &&
         std::chrono::steady_clock::now() - t0 < std::chrono::seconds(2)) {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  montauk::app::LogWriter writer(buffers, dir);
  writer.start();
  std::this_thread::sleep_for(std::chrono::milliseconds(2500));
  writer.stop();
  producer.stop();

  // Verify at least one .prom file exists
  int file_count = 0;
  for (const auto& entry : std::filesystem::directory_iterator(dir)) {
    if (entry.path().extension() == ".prom") ++file_count;
  }
  ASSERT_TRUE(file_count >= 1);

  // Verify file has at least 2 timestamp blocks
  int ts_count = 0;
  for (const auto& entry : std::filesystem::directory_iterator(dir)) {
    std::ifstream f(entry.path());
    std::string line;
    while (std::getline(f, line)) {
      if (line.starts_with("# montauk_scrape_timestamp_ms")) ++ts_count;
    }
  }
  ASSERT_TRUE(ts_count >= 2);

  std::filesystem::remove_all(dir);
}

TEST(logwriter_empty_snapshot) {
  auto dir = test_dir("empty");
  std::filesystem::remove_all(dir);

  // No Producer -- seq() stays 0, LogWriter waits and writes nothing
  montauk::app::SnapshotBuffers buffers;
  montauk::app::LogWriter writer(buffers, dir);
  writer.start();
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  writer.stop();

  // Should not crash; no output because no publish occurred
  int file_count = 0;
  for (const auto& entry : std::filesystem::directory_iterator(dir)) {
    if (entry.path().extension() == ".prom") ++file_count;
  }
  ASSERT_TRUE(file_count == 0);

  std::filesystem::remove_all(dir);
}
