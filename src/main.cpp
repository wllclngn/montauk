#include "tools/Entrypoints.hpp"
#include <vector>
#include <cstring>
#include "app/SnapshotBuffers.hpp"
#include "app/Producer.hpp"
#include "collectors/CpuCollector.hpp"
#include <cmath>
#include <algorithm>
#include "sublimation_signal.h"
#include "sublimation_spectral.h"
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

// A crash (SIGSEGV/SIGABRT/SIGBUS/SIGQUIT) skips the RAII terminal guards and
// atexit, leaving the terminal in raw mode + alt screen + hidden cursor.
// Restore what is async-signal-safe to restore, then re-raise with the default
// disposition so the core dump / abort still happens.
static void on_fatal_signal(int sig) {
  restore_terminal_minimal();
  std::signal(sig, SIG_DFL);
  std::raise(sig);
}

// Parse an integer CLI argument, returning `fallback` on non-numeric input
// instead of throwing (std::stoi on e.g. `--iterations abc` would escape main
// as std::invalid_argument and std::terminate the process).
static int parse_int_arg(const char* s, int fallback) {
  char* end = nullptr;
  long v = std::strtol(s, &end, 10);
  if (end == s || *end != '\0') return fallback;
  return static_cast<int>(v);
}

// The analyzer and the decoder are FLAGS on montauk, and that is the only way to
// reach them. They were separate executables named montauk_analyze and
// montauk_trace_decode; those names are gone rather than symlinked, because a
// platform that means "one binary" cannot keep shipping the second and third
// names as aliases and still claim it.
//
// Dispatch happens before ANY montauk setup: no locale, no signal handlers, no
// output sink. The tools own their whole process when they run, exactly as they
// did as separate binaries, so their behaviour cannot drift from what the corpus
// goldens froze.
static int dispatch_tool(int argc, char** argv) {
  if (argc <= 1) return -1;
  // The tool is handed argv as if it had been called directly: argv[0] set to
  // the mode name for its own usage text, the flag dropped, the rest passed
  // through untouched. That keeps every one of the tool's own flags working
  // without re-parsing any of them here.
  auto forward = [&](const char* name, int (*entry)(int, char**)) {
    std::vector<char*> fwd;
    fwd.push_back(const_cast<char*>(name));
    for (int i = 2; i < argc; ++i) fwd.push_back(argv[i]);
    return entry(static_cast<int>(fwd.size()), fwd.data());
  };
  if (std::strcmp(argv[1], "--analyze") == 0) return forward("montauk --analyze", montauk_analyze_main);
  if (std::strcmp(argv[1], "--decode") == 0) return forward("montauk --decode", montauk_decode_main);
  return -1;  // not a tool invocation; fall through to montauk proper
}

int main(int argc, char** argv) {
  if (int rc = dispatch_tool(argc, argv); rc >= 0) return rc;

  std::setlocale(LC_ALL, "");  // Required for wcwidth() to work correctly
  std::signal(SIGINT, on_sigint);
  // SIGTERM too (systemd/kill default): run the same graceful teardown -- the
  // final drop-snapshot flush and the trace-pattern liveness WARN -- rather
  // than a hard kill that skips the whole run-loop teardown.
  std::signal(SIGTERM, on_sigint);
  // Fatal-crash signals: restore the terminal before the default action runs so
  // a segfault mid-render does not leave the user's shell in raw/alt-screen.
  std::signal(SIGSEGV, on_fatal_signal);
  std::signal(SIGABRT, on_fatal_signal);
  std::signal(SIGBUS,  on_fatal_signal);
  std::signal(SIGQUIT, on_fatal_signal);
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
  // --trace-ring-bytes / --trace-classes: the two knobs a capture that lost most
  // of itself needed and did not have. Both default to today's behaviour.
  [[maybe_unused]] uint64_t trace_ring_bytes = 0;
  [[maybe_unused]] uint64_t trace_class_mask = 0;
  bool json_once = false;      // --json: one-shot structured snapshot to stdout, then exit
  int  cpu_window = 0;         // --cpu-window N: sample aggregate CPU N times, emit the series
  int  anomalies_n = 0;        // --anomalies N: rank the published anomaly scores
  int  similar_pid = 0;        // --similar PID: processes behaving like PID
  int  similar_n = 5;
  int  regime_n = 0;           // --regime N: did the load regime shift, and when
  // --pmu-comm / --pmu-pid: per-process hardware-counter attribution. Separate
  // from --trace's per-CPU PMU because the permission story is different --
  // perf_event_open(pid>=0, cpu=-1) needs no privilege and no sysctl, while the
  // per-CPU form needs perf_event_paranoid<=0. Gating this behind --trace would
  // put an unprivileged capability behind BPF and root.
  std::string pmu_comm;
  std::vector<int> pmu_pids;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--iterations" && i + 1 < argc) iterations = parse_int_arg(argv[++i], iterations);
    else if (a == "--json") json_once = true;
    else if (a == "--cpu-window" && i + 1 < argc) cpu_window = parse_int_arg(argv[++i], cpu_window);
    else if (a == "--anomalies") anomalies_n = (i + 1 < argc && argv[i+1][0] != '-') ? parse_int_arg(argv[++i], 5) : 5;
    else if (a == "--similar" && i + 1 < argc) similar_pid = parse_int_arg(argv[++i], 0);
    else if (a == "--similar-top" && i + 1 < argc) similar_n = parse_int_arg(argv[++i], similar_n);
    else if (a == "--regime") regime_n = (i + 1 < argc && argv[i+1][0] != '-') ? parse_int_arg(argv[++i], 64) : 64;
    else if (a == "--self-test-seconds" && i + 1 < argc) self_test_secs = parse_int_arg(argv[++i], self_test_secs);
    else if (a == "--metrics" && i + 1 < argc) metrics_port = static_cast<uint16_t>(parse_int_arg(argv[++i], metrics_port));
    else if (a == "--log" && i + 1 < argc) log_dir = argv[++i];
    else if (a == "--log-interval-ms" && i + 1 < argc) log_interval_ms = parse_int_arg(argv[++i], log_interval_ms);
    else if (a == "--headless") headless = true;
    else if (a == "--trace" && i + 1 < argc) trace_pattern = argv[++i];
    else if (a == "--trace-out" && i + 1 < argc) trace_out = argv[++i];
    else if (a == "--stream-out" && i + 1 < argc) stream_out = argv[++i];
    else if (a == "--sched-detail") sched_detail = true;
    else if (a == "--trace-ring-bytes" && i + 1 < argc) {
      // Accept a plain byte count or a K/M/G suffix: a ring is discussed in
      // megabytes and typing seven zeroes is how the wrong number gets set.
      char* endp = nullptr;
      unsigned long long v = std::strtoull(argv[++i], &endp, 10);
      if (endp && *endp) {
        switch (*endp) {
          case 'k': case 'K': v *= 1024ULL; break;
          case 'm': case 'M': v *= 1024ULL * 1024ULL; break;
          case 'g': case 'G': v *= 1024ULL * 1024ULL * 1024ULL; break;
          default:
            montauk::util::log_error("--trace-ring-bytes: unknown suffix '%s' "
                                     "(use a plain count, or K/M/G)", endp);
            return 1;
        }
      }
      trace_ring_bytes = v;
    }
    else if (a == "--trace-classes" && i + 1 < argc) {
      // NAMES, not a bitmask. An operator narrowing a capture is already doing
      // something subtle; making them hand-assemble 1<<7 invites the mistake
      // that loses the class they cared about.
      static const struct { const char* name; int bit; } kClasses[] = {
        {"fork",1},{"exec",2},{"exit",3},{"comm",4},{"io",5},{"ntsync",6},
        {"sched",7},{"heap",8},{"signal",9},{"mmap",10},{"provider",11},
        {"abort",12},{"heapstack",13},{"keyedevt",14},
      };
      std::string list = argv[++i];
      uint64_t mask = 0;
      size_t pos2 = 0;
      while (pos2 <= list.size()) {
        size_t c = list.find(',', pos2);
        if (c == std::string::npos) c = list.size();
        std::string tok = list.substr(pos2, c - pos2);
        pos2 = c + 1;
        if (tok.empty()) { if (c == list.size()) break; continue; }
        bool found = false;
        for (const auto& k : kClasses)
          if (tok == k.name) { mask |= (1ULL << k.bit); found = true; break; }
        if (!found) {
          std::string known;
          for (const auto& k : kClasses) { known += " "; known += k.name; }
          montauk::util::log_error("--trace-classes: unknown class '%s' (known:%s)",
                                   tok.c_str(), known.c_str());
          return 1;
        }
        if (c == list.size()) break;
      }
      if (!mask) {
        montauk::util::log_error("--trace-classes selected nothing -- a capture "
                                 "with no classes records nothing at all");
        return 1;
      }
      trace_class_mask = mask;
    }
    else if (a == "--pmu-comm" && i + 1 < argc) pmu_comm = argv[++i];
    else if (a == "--pmu-pid" && i + 1 < argc) pmu_pids.push_back(parse_int_arg(argv[++i], 0));
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
      montauk_sink_appendf(&g_out, "               [--pmu-comm SUBSTR] [--pmu-pid N]\n"
               "               [--json] [--anomalies N] [--similar PID] [--regime N] [--cpu-window N]\n");
      montauk_sink_appendf(&g_out, "Notes: Text UI runs until Ctrl+C by default.\n");
      montauk_sink_appendf(&g_out, "       --metrics PORT        Enable Prometheus endpoint on PORT\n");
      montauk_sink_appendf(&g_out, "       --log DIR             Write timestamped snapshots to DIR\n");
      montauk_sink_appendf(&g_out, "       --log-interval-ms MS  Write interval in ms (default: 1000)\n");
      montauk_sink_appendf(&g_out, "       --headless            Daemon mode (no TUI, requires --metrics or --log)\n");
      montauk_sink_appendf(&g_out, "       --trace PATTERN       Trace process group matching PATTERN (headless)\n");
      montauk_sink_appendf(&g_out, "       --trace-out FILE      Write raw binary event log; decode with --decode\n");
      montauk_sink_appendf(&g_out, "       --stream-out DEVICE   Second, independent binary stream (same format as --trace-out), meant for a character device (e.g. a qemu-backed serial port) so capture survives a hang that takes --trace-out's filesystem down with it\n");
      montauk_sink_appendf(&g_out, "       --trace-ring-bytes N  BPF ring size (default 1M; accepts K/M/G). The default was never sized against a real offered rate: one sched-messaging capture offered ~2.8M events/s against ~254k/s drained and kept 5.7%% of its stream. Rounded up to a power of two\n");
      montauk_sink_appendf(&g_out, "       --trace-classes LIST  Capture only these event classes (comma-separated: fork,exec,exit,comm,io,ntsync,sched,heap,signal,mmap,provider,abort,heapstack,keyedevt). Stops one loud class drowning the one the capture is FOR -- excluded classes are never reserved, and are NOT counted as drops\n");
      montauk_sink_appendf(&g_out, "       --sched-detail        Stream the heavy per-switch scheduler-decision detail -- per-CPU idle boundaries and the EEVDF pick fallback (off by default; the placement/slice/stall reports need it, ~6x cost on CPU-cycling workloads)\n");
      montauk_sink_appendf(&g_out, "       --init-theme          Detect terminal palette and write config.toml\n");
      montauk_sink_appendf(&g_out, "       --pmu-comm SUBSTR     Attach hardware counters to processes whose command matches SUBSTR (instructions, cycles, dTLB load misses, cache misses, per process). Needs no root and no sysctl, unlike --trace's system-wide PMU; re-resolved every tick, so a workload started later is picked up\n");
      montauk_sink_appendf(&g_out, "       --pmu-pid N           Same, for one explicit pid (repeatable; composes with --pmu-comm)\n");
      montauk_sink_appendf(&g_out, "       --json                One-shot structured system snapshot to stdout, then exit\n");
      montauk_sink_appendf(&g_out, "       --anomalies [N]       Rank what is anomalous right now (default 5) with each process's dominant axis, as JSON. The conclusion, not the matrix: ~600 bytes against --json's ~67,000\n");
      montauk_sink_appendf(&g_out, "       --similar PID         Processes behaving like PID, by effective resistance over a self-tuning affinity graph. Identical feature vectors collapse to one node first, since a process table is mostly idle duplicates and an uncollapsed graph ties every one of them\n");
      montauk_sink_appendf(&g_out, "       --similar-top N       How many neighbours --similar returns (default 5)\n");
      montauk_sink_appendf(&g_out, "       --regime [N]          Did the load regime shift recently, and when: spectral residual over N sampled CPU points (default 64, clamped 16-256, 100ms apart)\n");
      montauk_sink_appendf(&g_out, "       --cpu-window N        Sample aggregate CPU N times at 100ms and emit the raw series, for a caller that wants the window rather than a verdict\n");
      return 0;
    }
    // AN UNRECOGNIZED ARGUMENT IS FATAL. It used to be silently ignored, and
    // montauk went on to start the TUI -- so a caller that misspelled a flag, or
    // passed a file where a mode word belonged, got an interactive UI that spins
    // forever instead of an error. In a test harness with stdout captured that
    // is indistinguishable from a slow run: one such invocation
    // (`montauk ARCHIVE --analyze ...`, from a splice that assumed argv[0] was
    // the whole binary) burned twenty-five minutes of a gate before anyone
    // looked at what the child process actually was.
    //
    // montauk takes no positional arguments -- --analyze and --decode are
    // handled before this loop -- so anything unconsumed here is a mistake, and
    // saying so costs nothing.
    else {
      montauk::util::log_error("unrecognized argument '%s' (see --help)", a.c_str());
      return 2;
    }
  }
  // --trace implies headless
  if (!trace_pattern.empty()) headless = true;

  // A TUI WITH NOWHERE TO DRAW CANNOT WORK, so refuse rather than spin. Without
  // this, redirecting montauk's stdout starts a full render loop against a pipe
  // that no one is reading -- the same silent-hang failure as above, reached a
  // different way. --headless, --json and the conclusion modes all still work
  // when piped; only the interactive UI needs a terminal.
  // The one-shot modes PRINT AND EXIT; none of them draws a UI, and every one is
  // meant to be piped. Guarding on `headless` alone was wrong -- it rejected
  // --json, the very mode the message below recommends.
  const bool one_shot = json_once || cpu_window > 0 || anomalies_n > 0
                     || similar_pid > 0 || regime_n > 0;
  if (!headless && !one_shot && !::isatty(STDOUT_FILENO)) {
    montauk::util::log_error(
        "stdout is not a terminal: the TUI needs one. Use --headless with "
        "--metrics/--log, or --json / --anomalies / --regime for piped output");
    return 2;
  }

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
    // Per-process attribution is the unprivileged half and stands on its own.
    if (!pmu_comm.empty() || !pmu_pids.empty())
      producer.set_pmu_process_filter(pmu_comm, pmu_pids);
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
      trace_collector->set_ring_bytes(trace_ring_bytes);   // before load: libbpf freezes map size
      trace_collector->set_capture_mask(trace_class_mask); // before load: .rodata
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
    // daemon -- the agent-facing analog of `montauk --analyze --json` for the live
    // monitor. With --trace PATTERN also given, a second JSON line follows with
    // the trace snapshot (JSON-lines style: one structured record per line).
    // --cpu-window N: a TEMPORAL window montauk's one-shot cannot otherwise
    // serve. --json is instantaneous, so any consumer wanting "did the load
    // regime shift" had to sample repeatedly itself -- which is exactly what
    // vector's montauk_regime was doing, reading /proc/stat directly and making
    // vector a second collector. Collection belongs in the instrument: this
    // samples montauk's own CpuCollector N times and emits the series, so the
    // consumer makes one call and reads a result.
    if (cpu_window > 0) {
      int n = cpu_window;
      if (n < 2) n = 2;
      if (n > 1024) n = 1024;
      montauk::collectors::CpuCollector cpu;
      montauk::model::CpuSnapshot cs{};
      (void)cpu.sample(cs);   // prime: the first delta has no predecessor
      montauk_sink_appendf(&g_out, "{\"interval_ms\":100,\"samples\":[");
      for (int k = 0; k < n && !g_stop.load(); ++k) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        (void)cpu.sample(cs);
        montauk_sink_appendf(&g_out, "%s%.6f", k ? "," : "", cs.usage_pct);
      }
      montauk_sink_appendf(&g_out, "],\"source\":\"montauk CpuCollector\"}\n");
      drain_out();
      return 0;
    }

    // --regime N: the temporal conclusion. Samples its own window through
    // CpuCollector (same path as --cpu-window) and runs sublimation's Spectral
    // Residual over it. Lives here rather than only behind an MCP tool because
    // a conclusion is small: a handful of flagged points, not a payload.
    if (regime_n > 0) {
      size_t n = 1; while (n < (size_t)regime_n) n <<= 1;
      if (n < 16) n = 16;
      if (n > 256) n = 256;
      montauk::collectors::CpuCollector cpu;
      montauk::model::CpuSnapshot cs{};
      (void)cpu.sample(cs);
      std::vector<double> sig; sig.reserve(n);
      for (size_t k = 0; k < n && !g_stop.load(); ++k) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        (void)cpu.sample(cs);
        sig.push_back(cs.usage_pct);
      }
      if (sig.size() != n) return 1;
      std::vector<double> sal(n);
      std::vector<uint8_t> flags(n);
      const size_t z = (n / 4) ? (n / 4) : 1;
      if (sublimation_spectral_residual(sig.data(), n, 3, 3.0, z, sal.data(), flags.data()) != 0) {
        fputs("montauk: spectral residual failed\n", stderr);
        return 1;
      }
      double mean = 0.0;
      for (double v : sig) mean += v;
      mean /= (double)n;
      montauk_sink_appendf(&g_out, "{\"samples\":%zu,\"interval_ms\":100,\"mean_cpu_pct\":%.2f,\"shifts\":[", n, mean);
      int emitted = 0;
      for (size_t k = 0; k < n; ++k) {
        if (!flags[k]) continue;
        montauk_sink_appendf(&g_out,
            "%s{\"seconds_ago\":%.1f,\"cpu_pct\":%.1f,\"saliency\":%.3f}",
            emitted++ ? "," : "", (double)(n - 1 - k) * 0.1, sig[k], sal[k]);
      }
      montauk_sink_appendf(&g_out, "],\"shifted\":%s,\"basis\":\"spectral residual over montauk CpuCollector\"}\n",
                           emitted ? "true" : "false");
      drain_out();
      return 0;
    }

    if (json_once || anomalies_n > 0 || similar_pid > 0) {
      for (int spins = 0; buffers.seq() < 2 && !g_stop.load() && spins < 4000; ++spins)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      // The warm-up above only guarantees the deltas EXIST, not that they span
      // a usable window: it fires several process samples a kernel tick apart,
      // and a cpu_pct diffed across those is quantized noise -- most processes
      // accrue no jiffy at all and read 0 (so top-K by cpu_pct ranks
      // arbitrarily and misses the real burners), while an unlucky one catches
      // a whole jiffy and reads far above 100% per core. Wait for a
      // steady-loop sample, which only lands a full kProcessInterval later,
      // then for the publish that carries it. The TUI needs none of this; it
      // resamples and settles on its own.
      {
        const uint64_t warm_samples = producer.process_samples();
        for (int spins = 0; !g_stop.load() && spins < 8000; ++spins) {
          if (producer.process_samples() > warm_samples) break;
          std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        const auto settled_seq = buffers.seq();
        for (int spins = 0; !g_stop.load() && spins < 2000; ++spins) {
          if (buffers.seq() > settled_seq) break;
          std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
      }
      montauk::app::MetricsSnapshot ms = montauk::app::read_metrics_snapshot(buffers);

      // --anomalies N: the ranked conclusion, not the matrix it came from.
      // montauk already fuses and publishes a score per process; this sorts and
      // names. Returning the whole snapshot for this question costs ~630x what
      // the answer does, which is the entire argument for the mode existing.
      if (anomalies_n > 0) {
        static const char* kAx[] = {"cpu", "rss", "gpu", "faults", "threads", "ctxsw"};
        std::vector<const montauk::app::AnomalyFeatureRow*> rows;
        rows.reserve(ms.anomaly_features.size());
        for (const auto& r : ms.anomaly_features) rows.push_back(&r);
        std::sort(rows.begin(), rows.end(),
                  [](auto* a, auto* b) { return a->anomaly_score > b->anomaly_score; });
        const size_t k = std::min<size_t>((size_t)anomalies_n, rows.size());
        montauk_sink_appendf(&g_out, "{\"anomalies\":[");
        for (size_t idx = 0; idx < k; ++idx) {
          const auto* r = rows[idx];
          const char* ax = (r->anomaly_axis >= 0 && r->anomaly_axis < 6)
                               ? kAx[r->anomaly_axis] : "none";
          montauk_sink_appendf(&g_out,
              "%s{\"pid\":%lld,\"comm\":\"%s\",\"anomaly_score\":%.4f,\"axis\":\"%s\","
              "\"cpu_pct\":%.2f,\"rss_mb\":%.0f}",
              idx ? "," : "", (long long)r->pid, r->comm.data(), r->anomaly_score, ax,
              r->cpu_pct, r->rss_kb / 1024.0);
        }
        montauk_sink_appendf(&g_out, "],\"population\":%zu,\"basis\":\"fused MAD, "
            "Mahalanobis and Half-Space Trees (rank-averaged); higher is more anomalous\"}\n",
            ms.anomaly_features.size());
        drain_out();
        return 0;
      }

      // --similar PID: effective-resistance nearest over a self-tuning affinity
      // graph of the live population. The one conclusion montauk did not
      // already compute anywhere.
      if (similar_pid > 0) {
        constexpr size_t D = 6;
        const size_t total = ms.anomaly_features.size();
        if (total < 3) { fputs("montauk: too few processes for a similarity graph\n", stderr); return 1; }
        size_t qi_all = total;
        for (size_t idx = 0; idx < total; ++idx)
          if (ms.anomaly_features[idx].pid == similar_pid) { qi_all = idx; break; }
        if (qi_all == total) {
          fprintf(stderr, "montauk: pid %d is not in the live process population\n", similar_pid);
          return 1;
        }
        auto featv = [](const montauk::app::AnomalyFeatureRow& r, size_t j) {
          switch (j) {
            case 0: return r.cpu_pct; case 1: return r.rss_kb; case 2: return r.gpu_util_pct;
            case 3: return r.fault_delta; case 4: return r.thread_count; default: return r.ctxsw_delta;
          }
        };
        // O(n^3) solve: cap the candidate set to the query's nearest by
        // standardized distance, and say so in the output rather than implying
        // the whole population was related.
        constexpr size_t CAP = 512;
        double mean[D] = {0}, sd[D] = {0};
        for (const auto& r : ms.anomaly_features)
          for (size_t j = 0; j < D; ++j) mean[j] += featv(r, j);
        for (size_t j = 0; j < D; ++j) mean[j] /= (double)total;
        for (const auto& r : ms.anomaly_features)
          for (size_t j = 0; j < D; ++j) { double e = featv(r, j) - mean[j]; sd[j] += e * e; }
        for (size_t j = 0; j < D; ++j) { sd[j] = std::sqrt(sd[j] / (double)total); if (sd[j] <= 0.0) sd[j] = 1.0; }

        // COLLAPSE IDENTICAL VECTORS FIRST. Most of a process table is idle:
        // measured here, 221 of 302 processes carry the exact same feature
        // vector (0,0,0,0,1,0) and only 82 distinct points exist. Identical
        // points are ONE node, so effective resistance from an outlier to each
        // of them is equal by symmetry -- which is why an uncollapsed graph
        // returned 0.7140 for its entire top 12 and ranked kworkers by whatever
        // order the tie broke in. Collapsing is not an optimisation bolted on
        // top; it is what makes the ranking mean anything. It also takes the
        // O(n^3) solve from 302 nodes to 82.
        std::vector<size_t> sel;          // representative index per distinct vector
        std::vector<size_t> members;      // how many processes each represents
        {
          std::vector<size_t> key_of(total);
          for (size_t idx = 0; idx < total; ++idx) {
            size_t found = sel.size();
            for (size_t u = 0; u < sel.size(); ++u) {
              bool same = true;
              for (size_t j = 0; j < D; ++j)
                if (featv(ms.anomaly_features[sel[u]], j) != featv(ms.anomaly_features[idx], j)) { same = false; break; }
              if (same) { found = u; break; }
            }
            if (found == sel.size()) { sel.push_back(idx); members.push_back(1); }
            else { members[found]++; if (idx == qi_all) sel[found] = idx; }
            key_of[idx] = found;
          }
          qi_all = sel[key_of[qi_all]];
        }
        const size_t distinct = sel.size();
        if (distinct < 3) {
          fputs("montauk: the live population has fewer than three distinct behaviours\n", stderr);
          return 1;
        }
        if (distinct > CAP) {
          std::sort(sel.begin(), sel.end(), [&](size_t a, size_t b) {
            double da = 0, db = 0;
            for (size_t j = 0; j < D; ++j) {
              double ea = (featv(ms.anomaly_features[a], j) - featv(ms.anomaly_features[qi_all], j)) / sd[j];
              double eb = (featv(ms.anomaly_features[b], j) - featv(ms.anomaly_features[qi_all], j)) / sd[j];
              da += ea * ea; db += eb * eb;
            }
            return da < db;
          });
          sel.resize(CAP);
          members.resize(CAP);
        }
        const size_t n = sel.size();
        size_t qi = n;
        for (size_t idx = 0; idx < n; ++idx) if (sel[idx] == qi_all) { qi = idx; break; }
        std::vector<double> x(n * D);
        for (size_t idx = 0; idx < n; ++idx)
          for (size_t j = 0; j < D; ++j) x[idx * D + j] = featv(ms.anomaly_features[sel[idx]], j);
        std::vector<double> W(n * n), reff(n * n);
        unsigned knn = (unsigned)std::min<size_t>(7, n - 1);
        if (sublimation_self_tuning_affinity(x.data(), n, D, knn, W.data()) != 0 ||
            sublimation_effective_resistance(W.data(), n, reff.data()) != 0) {
          fputs("montauk: affinity/resistance failed\n", stderr);
          return 1;
        }
        std::vector<size_t> ord;
        for (size_t idx = 0; idx < n; ++idx) if (idx != qi) ord.push_back(idx);
        std::sort(ord.begin(), ord.end(),
                  [&](size_t a, size_t b) { return reff[qi * n + a] < reff[qi * n + b]; });
        const size_t k = std::min<size_t>((size_t)similar_n, ord.size());
        const auto& q = ms.anomaly_features[qi_all];
        montauk_sink_appendf(&g_out, "{\"query\":{\"pid\":%lld,\"comm\":\"%s\"},\"similar\":[",
                             (long long)q.pid, q.comm.data());
        for (size_t idx = 0; idx < k; ++idx) {
          const auto& r = ms.anomaly_features[sel[ord[idx]]];
          montauk_sink_appendf(&g_out, "%s{\"pid\":%lld,\"comm\":\"%s\",\"resistance\":%.3f,\"identical_peers\":%zu}",
                               idx ? "," : "", (long long)r.pid, r.comm.data(), reff[qi * n + ord[idx]],
                               members[ord[idx]]);
        }
        montauk_sink_appendf(&g_out, "],\"graph_nodes\":%zu,\"population\":%zu,\"basis\":"
            "\"effective-resistance (commute-time) nearest over a self-tuning affinity graph "
            "(cpu, rss, gpu, faults, threads, ctxsw); lower resistance is more similar\"}\n",
            n, total);
        drain_out();
        return 0;
      }

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
    // Concurrency hardening: copy the front snapshot under the buffer's reuse
    // guard so the writer cannot recycle it (freeing its vectors) mid-copy.
    s_copy = buffers.read([](const montauk::model::Snapshot& s) { return s; });
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
