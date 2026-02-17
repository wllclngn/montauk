#include "app/SnapshotBuffers.hpp"
#include "app/Producer.hpp"
#include "app/Security.hpp"
#include "app/MetricsServer.hpp"
#include "app/LogWriter.hpp"
#include "util/Retro.hpp"
#include "model/Snapshot.hpp"
#include "ui/Terminal.hpp"
#include "ui/Formatting.hpp"
#include "ui/Renderer.hpp"
#include "ui/Config.hpp"
#include "util/TomlReader.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <iostream>
#include <iomanip>
#include <string>
#include <thread>
#include <vector>
#include <sstream>
#include <algorithm>
#include <numeric>
#include <climits>
#include <cmath>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstring>
#include <unordered_map>
#include <termios.h>
#include <poll.h>
#include <fcntl.h>
#include <cctype>
#include <ctime>
#include <clocale>
#include <fstream>
#include <filesystem>
#include <iterator>
#include <langinfo.h>
#include "util/Procfs.hpp"

using namespace std::chrono_literals;

// Import from Terminal module
using montauk::ui::g_stop;
using montauk::ui::g_alt_in_use;
using montauk::ui::restore_terminal_minimal;
using montauk::ui::on_sigint;
using montauk::ui::on_atexit_restore;
using montauk::ui::best_effort_write;
using montauk::ui::tty_stdout;
using montauk::ui::sgr_reset;

// Import from Config module
using montauk::ui::Config;
using montauk::ui::SortMode;
using montauk::ui::UIState;
using montauk::ui::g_ui;
using montauk::ui::config;
using montauk::ui::ui_config;
using montauk::ui::reset_ui_defaults;

// -------- System info helpers (best-effort, lightweight) --------
struct CpuFreqInfo { bool has_cur{false}; bool has_max{false}; double cur_ghz{0.0}; double max_ghz{0.0}; std::string governor; std::string turbo; };

 

int main(int argc, char** argv) {
  std::setlocale(LC_ALL, "");  // Required for wcwidth() to work correctly
  std::signal(SIGINT, on_sigint);
  // Text-only UI is the default and only mode. Ctrl+C to exit.
  // Default: run indefinitely with 250ms refresh (no flags needed).
  int iterations = 0; // 0 or less => run until Ctrl+C
  int sleep_ms = 250;
  int self_test_secs = 0; // if >0, run self-test and print stats
  uint16_t metrics_port = 0; // >0 enables Prometheus metrics endpoint
  std::filesystem::path log_dir; // non-empty enables LogWriter
  int log_interval_ms = 1000;    // default 1s write interval
  bool headless = false;     // --headless: skip TUI, daemon mode
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--iterations" && i + 1 < argc) iterations = std::stoi(argv[++i]);
    else if (a == "--sleep-ms" && i + 1 < argc) sleep_ms = std::stoi(argv[++i]);
    else if (a == "--self-test-seconds" && i + 1 < argc) self_test_secs = std::stoi(argv[++i]);
    else if (a == "--metrics" && i + 1 < argc) metrics_port = static_cast<uint16_t>(std::stoi(argv[++i]));
    else if (a == "--log" && i + 1 < argc) log_dir = argv[++i];
    else if (a == "--log-interval-ms" && i + 1 < argc) log_interval_ms = std::stoi(argv[++i]);
    else if (a == "--headless") headless = true;
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
      std::cout << "Usage: montauk [--self-test-seconds S] [--iterations N] [--sleep-ms MS]\n";
      std::cout << "               [--metrics PORT] [--log DIR] [--log-interval-ms MS] [--headless]\n";
      std::cout << "               [--init-theme]\n";
      std::cout << "Notes: Text UI runs until Ctrl+C by default.\n";
      std::cout << "       --metrics PORT        Enable Prometheus endpoint on PORT\n";
      std::cout << "       --log DIR             Write timestamped snapshots to DIR\n";
      std::cout << "       --log-interval-ms MS  Write interval in ms (default: 1000)\n";
      std::cout << "       --headless            Daemon mode (no TUI, requires --metrics or --log)\n";
      std::cout << "       --init-theme          Detect terminal palette and write config.toml\n";
      return 0;
    }
  }
  if (headless && metrics_port == 0 && log_dir.empty()) {
    std::cerr << "Error: --headless requires --metrics PORT or --log DIR\n";
    return 1;
  }

  try {
    montauk::app::SnapshotBuffers buffers;
    montauk::app::Producer producer(buffers);
    producer.start();

    std::unique_ptr<montauk::app::MetricsServer> metrics;
    if (metrics_port > 0) {
      metrics = std::make_unique<montauk::app::MetricsServer>(buffers, metrics_port);
      metrics->start();
    }

    std::unique_ptr<montauk::app::LogWriter> log_writer;
    if (!log_dir.empty()) {
      log_writer = std::make_unique<montauk::app::LogWriter>(
          buffers, log_dir, std::chrono::milliseconds(log_interval_ms));
      log_writer->start();
    }

    // Headless mode: no TUI, just run Producer + outputs until Ctrl+C
    if (headless) {
      while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
      }
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
  reset_ui_defaults();
  // Apply config defaults
  auto scale_str = cfg.ui.cpu_scale;
  for (auto& ch : scale_str) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  g_ui.cpu_scale = (scale_str == "core" || scale_str == "percore" || scale_str == "irix")
                     ? UIState::CPUScale::Core : UIState::CPUScale::Total;
  g_ui.system_focus = cfg.ui.system_focus;
  g_ui.show_gpumon = true;
  g_ui.show_disk = true;
  g_ui.show_net = true;
  if (iterations <= 0) iterations = INT32_MAX;
  bool show_help = false;
  auto help_text = std::string("Keys: q quit  / search  c/m/p/n sort  g GPU sort  v GMEM sort  G toggle GPU  +/- fps  arrows/PgUp/PgDn scroll  t Thermal  d Disk  N Net  i CPU scale  u GPU scale  s System focus  R reset UI  h help");
  int alert_frames = 0; int alert_needed = cfg.thresholds.alert_frames;
  for (int i = 0; (iterations <= 0 || i < iterations) && !g_stop.load(); ++i) {
    // Non-blocking input with poll
    struct pollfd pfd{.fd=STDIN_FILENO,.events=POLLIN,.revents=0};
    int to = (i == 0) ? 0 : sleep_ms; if (to < 10 && i > 0) to = 10; if (to > 1000) to = 1000;
    int rv = ::poll(&pfd, 1, to);
    if (rv > 0 && (pfd.revents & POLLIN)) {
      unsigned char buf[8]; ssize_t n = ::read(STDIN_FILENO, buf, sizeof(buf));
      if (n > 0) {
        // Search mode: capture keystrokes for filter query
        if (g_ui.search_mode) {
          for (ssize_t ki = 0; ki < n; ++ki) {
            unsigned char c = buf[ki];
            if (c == 0x1B) { // Esc
              g_ui.search_mode = false;
              if (g_ui.filter_query.empty()) { /* already clear */ }
            } else if (c == '\r' || c == '\n') { // Enter
              g_ui.search_mode = false;
              g_ui.scroll = 0;
            } else if (c == 127 || c == 0x08) { // Backspace
              if (!g_ui.filter_query.empty()) {
                g_ui.filter_query.pop_back();
                g_ui.scroll = 0;
              } else {
                g_ui.search_mode = false;
              }
            } else if (std::isprint(c)) {
              g_ui.filter_query += static_cast<char>(c);
              g_ui.scroll = 0;
            }
            // All other keys (arrows, etc.) swallowed
          }
        } else {
        // Keybind-driven input handler
        size_t k = 0;
        while (k < (size_t)n) {
          unsigned char c = buf[k++];
          auto action = cfg.lookup_key(static_cast<char>(c));
          switch (action) {
            case Config::Action::QUIT: g_stop.store(true); break;
            case Config::Action::HELP: show_help = !show_help; break;
            case Config::Action::FPS_UP: sleep_ms = std::max(33, sleep_ms - 10); break;
            case Config::Action::FPS_DOWN: sleep_ms = std::min(1000, sleep_ms + 10); break;
            case Config::Action::SORT_CPU: g_ui.sort = SortMode::CPU; break;
            case Config::Action::SORT_MEM: g_ui.sort = SortMode::MEM; break;
            case Config::Action::SORT_PID: g_ui.sort = SortMode::PID; break;
            case Config::Action::SORT_NAME: g_ui.sort = SortMode::NAME; break;
            case Config::Action::SORT_GPU: g_ui.sort = SortMode::GPU; break;
            case Config::Action::SORT_GMEM: g_ui.sort = SortMode::GMEM; break;
            case Config::Action::TOGGLE_GPU: g_ui.show_gpumon = !g_ui.show_gpumon; break;
            case Config::Action::TOGGLE_THERMAL: g_ui.show_thermal = !g_ui.show_thermal; break;
            case Config::Action::TOGGLE_DISK: g_ui.show_disk = !g_ui.show_disk; break;
            case Config::Action::TOGGLE_NET: g_ui.show_net = !g_ui.show_net; break;
            case Config::Action::TOGGLE_CPU_SCALE:
              g_ui.cpu_scale = (g_ui.cpu_scale==UIState::CPUScale::Total? UIState::CPUScale::Core : UIState::CPUScale::Total); break;
            case Config::Action::TOGGLE_GPU_SCALE:
              g_ui.gpu_scale = (g_ui.gpu_scale==UIState::GPUScale::Capacity? UIState::GPUScale::Utilization : UIState::GPUScale::Capacity); break;
            case Config::Action::TOGGLE_SYSTEM_FOCUS:
              g_ui.system_focus = !g_ui.system_focus;
              if (g_ui.system_focus) { g_ui.show_gpumon = false; g_ui.show_disk = false; g_ui.show_net = false; }
              else { g_ui.show_gpumon = true; g_ui.show_disk = true; g_ui.show_net = true; }
              break;
            case Config::Action::RESET_UI: reset_ui_defaults(); break;
            case Config::Action::SEARCH:
              g_ui.search_mode = true; g_ui.filter_query.clear(); g_ui.scroll = 0; break;
            case Config::Action::NONE:
              if (c == 0x1B) {
                unsigned char a=0,b=0, d=0;
                if (k < (size_t)n) a = buf[k++]; else {
                  if (!g_ui.filter_query.empty()) { g_ui.filter_query.clear(); g_ui.scroll = 0; }
                  break;
                }
                if (a == '[') {
                  if (k < (size_t)n) b = buf[k++]; else break;
                  if (b >= 'A' && b <= 'D') {
                    int max_scroll = std::max(0, g_ui.last_proc_total - g_ui.last_proc_page_rows);
                    if (b=='A') { if (g_ui.scroll > 0) g_ui.scroll--; }
                    else if (b=='B') { g_ui.scroll = std::min(g_ui.scroll + 1, max_scroll); }
                  } else if (b=='5' || b=='6') {
                    if (k < (size_t)n) d = buf[k++];
                    if (d=='~') {
                      int page = std::max(1, g_ui.last_proc_page_rows - 2);
                      int max_scroll = std::max(0, g_ui.last_proc_total - g_ui.last_proc_page_rows);
                      if (b=='5') { g_ui.scroll = std::max(0, g_ui.scroll - page); }
                      else { g_ui.scroll = std::min(g_ui.scroll + page, max_scroll); }
                    }
                  }
                }
              }
              break;
          } // switch
          if (action == Config::Action::QUIT) break;
        }
      } // end else (normal mode)
      }
    }
    // Concurrency hardening: atomic snapshot capture with sequence validation
    montauk::model::Snapshot s_copy;
    uint64_t seq_before, seq_after;
    do {
      seq_before = buffers.seq();
      s_copy = buffers.front();
      seq_after = buffers.seq();
    } while (seq_before != seq_after);
    const auto& s = s_copy;
    // Dynamic help with current sort/fps and optional alert banner
    // Report the active sort mode accurately in the help line
    std::string sort_name =
      (g_ui.sort==SortMode::CPU?  "cpu" :
      (g_ui.sort==SortMode::MEM?  "mem" :
      (g_ui.sort==SortMode::PID?  "pid" :
      (g_ui.sort==SortMode::NAME? "name" :
      (g_ui.sort==SortMode::GPU?  "gpu" : "gmem")))));
    int fps = (sleep_ms>0)? (1000/std::max(1,sleep_ms)) : 0;
    // Alert: sustained top process CPU over warning threshold (respect current CPU scale)
    const auto& ui = ui_config();
    int ncpu = (int)std::max<size_t>(1, s.cpu.per_core_pct.size());
    auto scale_proc = [&](double v){ return (g_ui.cpu_scale==UIState::CPUScale::Total)? (v/(double)ncpu) : v; };
    double top_cpu = 0.0; for (const auto& p : s.procs.processes) { double v = scale_proc(p.cpu_pct); if (v > top_cpu) top_cpu = v; }
    if ((int)(top_cpu+0.5) >= ui.warning_pct) alert_frames++; else alert_frames = 0;
    std::string alert;
    if (alert_frames >= alert_needed) {
      std::ostringstream os; os << ui.warning << "ALERT: top CPU " << (int)(top_cpu+0.5) << "%" << sgr_reset() << "  ";
      alert = os.str();
    }
    std::string dyn_help = alert + "SORT:" + sort_name + " " + montauk::ui::grey_bullet() + " FOCUS:" + (g_ui.system_focus? "SYSTEM":"DEFAULT") + " " + montauk::ui::grey_bullet() + " FPS:" + std::to_string(fps) + "  " + help_text;
    montauk::ui::render_screen(s, show_help, dyn_help);
  }
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
