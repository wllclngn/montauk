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
#include "util/Log.hpp"
#include "util/sink.h"

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

// CLI/usage stdout drains through one buffered sink, drained at exit.
static montauk_sink g_out;
static void drain_out() { montauk_sink_drain(&g_out); }
using montauk::ui::on_atexit_restore;
using montauk::ui::tty_stdout;
using montauk::ui::config;


int main(int argc, char** argv) {
  std::setlocale(LC_ALL, "");  // Required for wcwidth() to work correctly
  std::signal(SIGINT, on_sigint);
  montauk_sink_init(&g_out, 1);
  std::atexit(drain_out);
  // Text-only UI is the default and only mode. Ctrl+C to exit.
  // Default: run indefinitely with 250ms refresh (no flags needed).
  int iterations = 0; // 0 or less => run until Ctrl+C
  int self_test_secs = 0; // if >0, run self-test and print stats
  uint16_t metrics_port = 0; // >0 enables Prometheus metrics endpoint
  std::filesystem::path log_dir; // non-empty enables LogWriter
  int log_interval_ms = 1000;    // default 1s write interval
  bool headless = false;     // --headless: skip TUI, daemon mode
  std::string trace_pattern; // --trace PATTERN: trace process group
  std::string trace_out;     // --trace-out FILE: raw binary event log
  std::string stream_out;    // --stream-out DEVICE: second binary stream, meant for a character
                              //   device (e.g. a qemu-backed serial port) so it survives a hang
                              //   that takes --trace-out's own filesystem down with it
  // --sched-detail: stream per-CPU idle boundaries (off by default). maybe_unused:
  // consumed only inside the MONTAUK_HAVE_BPF block below; a libbpf-less build
  // otherwise dies on -Werror=unused-but-set-variable.
  [[maybe_unused]] bool sched_detail = false;
  bool json_once = false;      // --json: one-shot structured snapshot to stdout, then exit
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--iterations" && i + 1 < argc) iterations = std::stoi(argv[++i]);
    else if (a == "--json") json_once = true;
    else if (a == "--self-test-seconds" && i + 1 < argc) self_test_secs = std::stoi(argv[++i]);
    else if (a == "--metrics" && i + 1 < argc) metrics_port = static_cast<uint16_t>(std::stoi(argv[++i]));
    else if (a == "--log" && i + 1 < argc) log_dir = argv[++i];
    else if (a == "--log-interval-ms" && i + 1 < argc) log_interval_ms = std::stoi(argv[++i]);
    else if (a == "--headless") headless = true;
    else if (a == "--trace" && i + 1 < argc) trace_pattern = argv[++i];
    else if (a == "--trace-out" && i + 1 < argc) trace_out = argv[++i];
    else if (a == "--stream-out" && i + 1 < argc) stream_out = argv[++i];
    else if (a == "--sched-detail") sched_detail = true;
    else if (a == "--init-theme") {
      auto colors = montauk::ui::detect_palette();
      montauk::util::TomlReader toml;
      auto cfg_path = montauk::ui::config_file_path();
      if (cfg_path.empty()) { montauk::util::log_error("cannot determine config path (no HOME)"); return 1; }
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
      set_bool_default("ui", "cpu_topology", false);
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
        montauk_sink_appendf(&g_out, "Wrote %s\n", cfg_path.c_str());
      else
        montauk::util::log_error("failed to write %s", cfg_path.c_str());
      return 0;
    }
    else if (a == "-h" || a == "--help") {
      montauk_sink_appendf(&g_out, "Usage: montauk [--self-test-seconds S] [--iterations N]\n");
      montauk_sink_appendf(&g_out, "               [--metrics PORT] [--log DIR] [--log-interval-ms MS] [--headless]\n");
      montauk_sink_appendf(&g_out, "               [--trace PATTERN] [--trace-out FILE] [--stream-out DEVICE] [--sched-detail] [--init-theme]\n");
      montauk_sink_appendf(&g_out, "Notes: Text UI runs until Ctrl+C by default.\n");
      montauk_sink_appendf(&g_out, "       --metrics PORT        Enable Prometheus endpoint on PORT\n");
      montauk_sink_appendf(&g_out, "       --log DIR             Write timestamped snapshots to DIR\n");
      montauk_sink_appendf(&g_out, "       --log-interval-ms MS  Write interval in ms (default: 1000)\n");
      montauk_sink_appendf(&g_out, "       --headless            Daemon mode (no TUI, requires --metrics or --log)\n");
      montauk_sink_appendf(&g_out, "       --trace PATTERN       Trace process group matching PATTERN (headless)\n");
      montauk_sink_appendf(&g_out, "       --trace-out FILE      Write raw binary event log; decode with montauk_trace_decode\n");
      montauk_sink_appendf(&g_out, "       --stream-out DEVICE   Second, independent binary stream (same format as --trace-out), meant for a character device (e.g. a qemu-backed serial port) so capture survives a hang that takes --trace-out's filesystem down with it\n");
      montauk_sink_appendf(&g_out, "       --sched-detail        Stream the heavy per-switch scheduler-decision detail -- per-CPU idle boundaries and the EEVDF pick fallback (off by default; the placement/slice/stall reports need it, ~6x cost on CPU-cycling workloads)\n");
      montauk_sink_appendf(&g_out, "       --init-theme          Detect terminal palette and write config.toml\n");
      montauk_sink_appendf(&g_out, "       --json                One-shot structured system snapshot to stdout, then exit\n");
      return 0;
    }
  }
  // --trace implies headless
  if (!trace_pattern.empty()) headless = true;

  if (headless && metrics_port == 0 && log_dir.empty() && trace_pattern.empty()) {
    montauk::util::log_error("--headless requires --metrics PORT or --log DIR");
    return 1;
  }

  try {
    montauk::app::SnapshotBuffers buffers;
    montauk::app::Producer producer(buffers);
    // PMU counters (perf_event_open) belong to the trace→analyze pipeline,
    // not the monitor: they need CAP_PERFMON or perf_event_paranoid<=0,
    // which a plain `montauk` TUI run must never demand. Only trace mode
    // opts in.
    if (!trace_pattern.empty()) producer.enable_pmu();
    producer.start();

    // Trace subsystem (optional, parallel to main pipeline). Constructed
    // before the --json one-shot branch below so that branch can warm it up
    // and emit trace_to_json too, when --trace PATTERN is also given.
    std::unique_ptr<montauk::app::TraceBuffers> trace_buffers;
#ifdef MONTAUK_HAVE_BPF
    std::unique_ptr<montauk::collectors::BpfTraceCollector> trace_collector;
    if (!trace_pattern.empty()) {
      trace_buffers = std::make_unique<montauk::app::TraceBuffers>();
      trace_collector = std::make_unique<montauk::collectors::BpfTraceCollector>(
          *trace_buffers, trace_pattern);
      if (!trace_out.empty()) trace_collector->set_binary_output(trace_out);
      if (!stream_out.empty()) trace_collector->set_stream_output(stream_out);
      trace_collector->set_sched_detail(sched_detail);  // before start(): sets a frozen rodata bit
      trace_collector->start();
    }
#else
    if (!trace_pattern.empty()) {
      montauk::util::log_error("--trace requires eBPF support (libbpf + bpftool + clang)");
      montauk::util::log_error("rebuild with libbpf installed: pacman -S libbpf bpf");
      return 1;
    }
#endif

    // --json: one-shot structured snapshot. Warm up two producer cycles so the
    // rate deltas (cpu ctxt/s, net bps, disk bps) are real, read one snapshot
    // via the seqlock, serialize to JSON, print and exit. No TUI, no server, no
    // daemon -- the agent-facing analog of `montauk_analyze --json` for the live
    // monitor. With --trace PATTERN also given, a second JSON line follows with
    // the trace snapshot (JSON-lines style: one structured record per line).
    if (json_once) {
      for (int spins = 0; buffers.seq() < 2 && !g_stop.load() && spins < 4000; ++spins)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      montauk::app::MetricsSnapshot ms = montauk::app::read_metrics_snapshot(buffers);
      std::string js = montauk::app::snapshot_to_json(ms);
      montauk_sink_append(&g_out, js.data(), js.size());

      if (trace_buffers) {
        for (int spins = 0; trace_buffers->seq() < 2 && !g_stop.load() && spins < 4000; ++spins)
          std::this_thread::sleep_for(std::chrono::milliseconds(1));
        montauk::model::TraceSnapshot ts = montauk::app::read_trace_snapshot(*trace_buffers);
        std::string tjs = montauk::app::trace_to_json(ts);
        montauk_sink_append(&g_out, tjs.data(), tjs.size());
      }

#ifdef MONTAUK_HAVE_BPF
      if (trace_collector) trace_collector->stop();
#endif
      producer.stop();
      return 0;
    }

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
          montauk::util::log_error("--trace requires root or CAP_BPF + CAP_PERFMON");
          trace_collector->stop();
          producer.stop();
          return 1;
        }
      }
#endif
      while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));  // snappy Ctrl+C response
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
    montauk_sink_appendf(&g_out, "Self-test: updates=%llu in %gs (~%g/s)\n",
                         (unsigned long long)updates, secs, updates / secs);
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
  montauk::ui::start_async_writer();

  if (iterations <= 0) iterations = INT32_MAX;
  montauk::ui::Renderer renderer;
  renderer.seed_from_config();

  // Snapshot copy target lives outside the render loop so its vector
  // members reuse capacity across frames instead of reallocating.
  montauk::model::Snapshot s_copy;
  for (int i = 0; i < iterations && !g_stop.load(); ++i) {
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
  montauk::ui::stop_async_writer();
  return 0;

  } catch (const std::exception& e) {
    // Safety net: catch any unhandled exceptions to prevent crashes
    restore_terminal_minimal();
    montauk::util::log_error("FATAL: unhandled exception: %s", e.what());
    montauk::util::log_error("likely a transient filesystem issue (proc/sys files disappearing); please report if it persists");
    return 1;
  } catch (...) {
    // Catch-all for non-standard exceptions
    restore_terminal_minimal();
    montauk::util::log_error("FATAL: unknown exception caught");
    montauk::util::log_error("likely a transient filesystem issue (proc/sys files disappearing); please report if it persists");
    return 1;
  }

  return 0;
}
