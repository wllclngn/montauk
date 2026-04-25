#include "app/SnapshotBuffers.hpp"
#include "app/Producer.hpp"
#include "app/MetricsServer.hpp"
#include "app/LogWriter.hpp"
#include "app/TraceBuffers.hpp"
#ifdef MONTAUK_HAVE_BPF
#include "collectors/BpfTraceCollector.hpp"
#endif
#include "model/Snapshot.hpp"
#include "ui/Terminal.hpp"
#include "ui/Renderer.hpp"
#include "ui/Config.hpp"
#include "util/TomlReader.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>
#include <unistd.h>
#include <poll.h>
#include <clocale>
#include <filesystem>

using namespace std::chrono_literals;
using montauk::ui::g_stop;
using montauk::ui::restore_terminal_minimal;
using montauk::ui::on_sigint;
using montauk::ui::on_atexit_restore;
using montauk::ui::tty_stdout;
using montauk::ui::config;


int main(int argc, char** argv) {
  std::setlocale(LC_ALL, "");  // Required for wcwidth() to work correctly
  std::signal(SIGINT, on_sigint);
  // Text-only UI is the default and only mode. Ctrl+C to exit.
  // Default: run indefinitely with 250ms refresh (no flags needed).
  int iterations = 0; // 0 or less => run until Ctrl+C
  int self_test_secs = 0; // if >0, run self-test and print stats
  uint16_t metrics_port = 0; // >0 enables Prometheus metrics endpoint
  std::filesystem::path log_dir; // non-empty enables LogWriter
  int log_interval_ms = 1000;    // default 1s write interval
  bool headless = false;     // --headless: skip TUI, daemon mode
  std::string trace_pattern; // --trace PATTERN: trace process group
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--iterations" && i + 1 < argc) iterations = std::stoi(argv[++i]);
    else if (a == "--self-test-seconds" && i + 1 < argc) self_test_secs = std::stoi(argv[++i]);
    else if (a == "--metrics" && i + 1 < argc) metrics_port = static_cast<uint16_t>(std::stoi(argv[++i]));
    else if (a == "--log" && i + 1 < argc) log_dir = argv[++i];
    else if (a == "--log-interval-ms" && i + 1 < argc) log_interval_ms = std::stoi(argv[++i]);
    else if (a == "--headless") headless = true;
    else if (a == "--trace" && i + 1 < argc) trace_pattern = argv[++i];
    else if (a == "--init-theme") {
      auto colors = montauk::ui::detect_palette();
      montauk::util::TomlReader toml;
      auto cfg_path = montauk::ui::config_file_path();
      if (cfg_path.empty()) { std::cerr << "Error: cannot determine config path (no HOME)\n"; return 1; }
      // Load existing config if present (preserve user edits)
      (void)toml.load(cfg_path);
      // Write detected palette
      for (int ci = 0; ci < 16; ++ci) {
        if (!colors[ci].empty())
          toml.set("palette", "color" + std::to_string(ci), colors[ci]);
      }
      // Write default roles if not already set
      auto set_role_default = [&](const char* name, const std::string& val) {
        if (!toml.has("roles", name)) toml.set("roles", name, val);
      };
      set_role_default("accent",  "11");
      set_role_default("caution", "9");
      set_role_default("warning", "1");
      set_role_default("normal",  "2");
      set_role_default("muted",   "#787878");
      set_role_default("border",  "#383838");
      set_role_default("binary",  "#8F00FF");
      // Write default thresholds if not already set
      auto set_int_default = [&](const char* sec, const char* key, int val) {
        if (!toml.has(sec, key)) toml.set(sec, key, val);
      };
      set_int_default("thresholds", "proc_caution_pct", 60);
      set_int_default("thresholds", "proc_warning_pct", 80);
      set_int_default("thresholds", "cpu_temp_warning_c", 90);
      set_int_default("thresholds", "temp_caution_delta_c", 10);
      set_int_default("thresholds", "gpu_temp_warning_c", 90);
      set_int_default("thresholds", "alert_frames", 5);
      // Write default ui if not already set
      auto set_bool_default = [&](const char* sec, const char* key, bool val) {
        if (!toml.has(sec, key)) toml.set(sec, key, val);
      };
      auto set_str_default = [&](const char* sec, const char* key, const std::string& val) {
        if (!toml.has(sec, key)) toml.set(sec, key, val);
      };
      set_bool_default("ui", "alt_screen", true);
      set_bool_default("ui", "system_focus", false);
      set_str_default("ui", "cpu_scale", "total");
      set_str_default("ui", "gpu_scale", "utilization");
      // Write default process settings
      set_int_default("process", "max_procs", 256);
      set_int_default("process", "enrich_top_n", 256);
      set_str_default("process", "collector", "auto");
      // Write default nvidia settings
      set_str_default("nvidia", "smi_path", "auto");
      set_bool_default("nvidia", "smi_dev", true);
      set_bool_default("nvidia", "pmon", true);
      set_bool_default("nvidia", "mem", true);
      set_bool_default("nvidia", "disable_nvml", false);
      // Write default chart settings. Line colors reference
      // role names so the chart palette tracks [roles] automatically on any
      // theme swap; users who prefer literal hex can overwrite.
      set_int_default("chart", "history_seconds", 60);
      set_str_default("chart.cpu",     "line", "accent");
      set_str_default("chart.cpu",     "fill", "auto");
      set_str_default("chart.gpu",     "line", "warning");
      set_str_default("chart.gpu",     "fill", "auto");
      set_str_default("chart.memory",  "line", "normal");
      set_str_default("chart.memory",  "fill", "auto");
      set_str_default("chart.network", "line",     "binary");
      set_str_default("chart.network", "line_alt", "caution");
      set_str_default("chart.network", "fill",     "auto");
      // Ensure directory exists
      auto last_slash = cfg_path.rfind('/');
      if (last_slash != std::string::npos)
        std::filesystem::create_directories(cfg_path.substr(0, last_slash));
      if (toml.save(cfg_path))
        std::cout << "Wrote " << cfg_path << "\n";
      else
        std::cerr << "Error: failed to write " << cfg_path << "\n";
      return 0;
    }
    else if (a == "-h" || a == "--help") {
      std::cout << "Usage: montauk [--self-test-seconds S] [--iterations N]\n";
      std::cout << "               [--metrics PORT] [--log DIR] [--log-interval-ms MS] [--headless]\n";
      std::cout << "               [--trace PATTERN] [--init-theme]\n";
      std::cout << "Notes: Text UI runs until Ctrl+C by default.\n";
      std::cout << "       --metrics PORT        Enable Prometheus endpoint on PORT\n";
      std::cout << "       --log DIR             Write timestamped snapshots to DIR\n";
      std::cout << "       --log-interval-ms MS  Write interval in ms (default: 1000)\n";
      std::cout << "       --headless            Daemon mode (no TUI, requires --metrics or --log)\n";
      std::cout << "       --trace PATTERN       Trace process group matching PATTERN (headless)\n";
      std::cout << "       --init-theme          Detect terminal palette and write config.toml\n";
      return 0;
    }
  }
  // --trace implies headless
  if (!trace_pattern.empty()) headless = true;

  if (headless && metrics_port == 0 && log_dir.empty() && trace_pattern.empty()) {
    std::cerr << "Error: --headless requires --metrics PORT or --log DIR\n";
    return 1;
  }

  try {
    montauk::app::SnapshotBuffers buffers;
    montauk::app::Producer producer(buffers);
    producer.start();

    // Trace subsystem (optional, parallel to main pipeline)
    std::unique_ptr<montauk::app::TraceBuffers> trace_buffers;
#ifdef MONTAUK_HAVE_BPF
    std::unique_ptr<montauk::collectors::BpfTraceCollector> trace_collector;
    if (!trace_pattern.empty()) {
      trace_buffers = std::make_unique<montauk::app::TraceBuffers>();
      trace_collector = std::make_unique<montauk::collectors::BpfTraceCollector>(
          *trace_buffers, trace_pattern);
      trace_collector->start();
    }
#else
    if (!trace_pattern.empty()) {
      std::cerr << "Error: --trace requires eBPF support (libbpf + bpftool + clang)\n";
      std::cerr << "Rebuild with libbpf installed: pacman -S libbpf bpf\n";
      return 1;
    }
#endif

    std::unique_ptr<montauk::app::MetricsServer> metrics;
    if (metrics_port > 0) {
      metrics = std::make_unique<montauk::app::MetricsServer>(
          buffers, metrics_port, trace_buffers.get());
      metrics->start();
    }

    std::unique_ptr<montauk::app::LogWriter> log_writer;
    if (!log_dir.empty()) {
      log_writer = std::make_unique<montauk::app::LogWriter>(
          buffers, log_dir, std::chrono::milliseconds(log_interval_ms),
          trace_buffers.get());
      log_writer->start();
    }

    // Headless mode: no TUI, just run Producer + outputs until Ctrl+C
    if (headless) {
#ifdef MONTAUK_HAVE_BPF
      // Wait briefly for BPF to initialize, then check for failure
      if (trace_collector) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        if (trace_collector->failed()) {
          std::cerr << "Error: --trace requires root or CAP_BPF + CAP_PERFMON\n";
          trace_collector->stop();
          producer.stop();
          return 1;
        }
      }
#endif
      while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
      }
#ifdef MONTAUK_HAVE_BPF
      if (trace_collector) trace_collector->stop();
#endif
      if (log_writer) log_writer->stop();
      if (metrics) metrics->stop();
      producer.stop();
      return 0;
    }

  // No JSON stream output path

  if (self_test_secs > 0) {
    using clock = std::chrono::steady_clock;
    auto start = clock::now();
    auto endt  = start + std::chrono::seconds(self_test_secs);
    uint64_t last = buffers.seq();
    uint64_t updates = 0;
    while (clock::now() < endt) {
      auto seq = buffers.seq();
      if (seq != last) { updates++; last = seq; }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    double secs = std::chrono::duration<double>(clock::now() - start).count();
    std::cout << "Self-test: updates=" << updates << " in " << secs << "s (~" << (updates/secs) << "/s)\n";
    producer.stop();
    return 0;
  }

  // Wait for Producer's warm-up to complete (~200ms) so first frame has real deltas
  while (buffers.seq() == 0 && !g_stop.load()) {
    std::this_thread::sleep_for(std::chrono::microseconds(500));
  }

  // Text mode (default, continuous until Ctrl+C) with keyboard interactivity
  const auto& cfg = config();
  bool use_alt = cfg.ui.alt_screen && tty_stdout();
  montauk::ui::RawTermGuard raw{}; montauk::ui::CursorGuard curs{}; montauk::ui::AltScreenGuard alt{use_alt};
  std::atexit(&on_atexit_restore);

  if (iterations <= 0) iterations = INT32_MAX;
  montauk::ui::Renderer renderer;
  renderer.seed_from_config();

  for (int i = 0; (iterations <= 0 || i < iterations) && !g_stop.load(); ++i) {
    // Non-blocking input with poll. Bytes → InputEvents → Renderer.
    struct pollfd pfd{.fd=STDIN_FILENO,.events=POLLIN,.revents=0};
    int to = (i == 0) ? 0 : renderer.sleep_ms();
    if (to < 10 && i > 0) to = 10;
    if (to > 1000) to = 1000;
    int rv = ::poll(&pfd, 1, to);
    if (rv > 0 && (pfd.revents & POLLIN)) {
      unsigned char buf[32];
      ssize_t n = ::read(STDIN_FILENO, buf, sizeof(buf));
      if (n > 0) {
        auto events = montauk::ui::widget::parse_input_bytes(buf, static_cast<size_t>(n));
        for (const auto& ev : events) {
          renderer.handle_input(ev);
          if (renderer.should_quit()) break;
        }
        if (renderer.should_quit()) g_stop.store(true);
      }
    }
    // Concurrency hardening: atomic snapshot capture with sequence validation.
    montauk::model::Snapshot s_copy;
    uint64_t seq_before, seq_after;
    do {
      seq_before = buffers.seq();
      s_copy = buffers.front();
      seq_after = buffers.seq();
    } while (seq_before != seq_after);
    renderer.render(s_copy);
  }
#ifdef MONTAUK_HAVE_BPF
  if (trace_collector) trace_collector->stop();
#endif
  if (log_writer) log_writer->stop();
  if (metrics) metrics->stop();
  producer.stop();
  return 0;

  } catch (const std::exception& e) {
    // Safety net: catch any unhandled exceptions to prevent crashes
    restore_terminal_minimal();
    std::cerr << "\nFATAL ERROR: Unhandled exception: " << e.what() << "\n";
    std::cerr << "This is likely caused by a transient filesystem issue (proc/sys files disappearing).\n";
    std::cerr << "Please report this error if it persists.\n";
    return 1;
  } catch (...) {
    // Catch-all for non-standard exceptions
    restore_terminal_minimal();
    std::cerr << "\nFATAL ERROR: Unknown exception caught.\n";
    std::cerr << "This is likely caused by a transient filesystem issue (proc/sys files disappearing).\n";
    std::cerr << "Please report this error if it persists.\n";
    return 1;
  }

  return 0;
}
