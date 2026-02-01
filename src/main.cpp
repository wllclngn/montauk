#include "app/SnapshotBuffers.hpp"
#include "app/Producer.hpp"
#include "app/Security.hpp"
#include "util/Retro.hpp"
#include "model/Snapshot.hpp"
#include "ui/Terminal.hpp"
#include "ui/Formatting.hpp"
#include "ui/Renderer.hpp"
#include "ui/Config.hpp"

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
#ifdef __linux__
#include <langinfo.h>
#endif
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
using montauk::ui::SortMode;
using montauk::ui::UIState;
using montauk::ui::g_ui;
using montauk::ui::ui_config;
using montauk::ui::reset_ui_defaults;
using montauk::ui::getenv_compat;
using montauk::ui::getenv_int;
using montauk::ui::getenv_cpu_scale;

// -------- System info helpers (best-effort, lightweight) --------
struct CpuFreqInfo { bool has_cur{false}; bool has_max{false}; double cur_ghz{0.0}; double max_ghz{0.0}; std::string governor; std::string turbo; };

 

// Simple EMA smoother for bar fill only; numbers remain exact.

static bool env_flag(const char* name, bool defv=true){ const char* v=getenv_compat(name); if(!v) return defv; if(v[0]=='0'||v[0]=='f'||v[0]=='F') return false; return true; }

// Format a colored CPU% field with fixed visible width (aligned to match 4-char "CPU%" header).
int main(int argc, char** argv) {
  std::setlocale(LC_ALL, "");  // Required for wcwidth() to work correctly
  std::signal(SIGINT, on_sigint);
  // Text-only UI is the default and only mode. Ctrl+C to exit.
  // Default: run indefinitely with 250ms refresh (no flags needed).
  int iterations = 0; // 0 or less => run until Ctrl+C
  int sleep_ms = 250;
  // JSON stream is removed; no runtime JSON output from the application
  int self_test_secs = 0; // if >0, run self-test and print stats
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--iterations" && i + 1 < argc) iterations = std::stoi(argv[++i]);
    else if (a == "--sleep-ms" && i + 1 < argc) sleep_ms = std::stoi(argv[++i]);
    // --json-stream-ms and --duration-seconds intentionally unsupported (removed)
    else if (a == "--self-test-seconds" && i + 1 < argc) self_test_secs = std::stoi(argv[++i]);
    // --tui/--no-tui removed: text UI is the only mode
    else if (a == "-h" || a == "--help") {
      std::cout << "Usage: montauk [--self-test-seconds S] [--iterations N] [--sleep-ms MS]\n";
      std::cout << "Notes: Text UI runs until Ctrl+C by default.\n";
      return 0;
    }
  }

  try {
    montauk::app::SnapshotBuffers buffers;
    montauk::app::Producer producer(buffers);
    producer.start();

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

  // Wait briefly for the initial warm snapshot publish to reduce startup flicker
  {
    uint64_t s0 = buffers.seq();
    auto t0 = std::chrono::steady_clock::now();
    auto deadline = t0 + std::chrono::milliseconds(250);
    while (buffers.seq() == s0 && std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
  }

  // Text mode (default, continuous until Ctrl+C) with keyboard interactivity
  bool use_alt = env_flag("MONTAUK_ALT_SCREEN", true) && tty_stdout();
  montauk::ui::RawTermGuard raw{}; montauk::ui::CursorGuard curs{}; montauk::ui::AltScreenGuard alt{use_alt};
  std::atexit(&on_atexit_restore);
  // Ensure a known-good default UI on startup (no sticky focus/panels)
  // This prevents launching in System focus (same effect as pressing 's').
  reset_ui_defaults();
  // Initialize CPU scale from env (default: total/machine share)
  g_ui.cpu_scale = getenv_cpu_scale("MONTAUK_PROC_CPU_SCALE", UIState::CPUScale::Total);
  // Hard-enable the default right-side panels to match the documented default layout.
  // Allow override via env: MONTAUK_SYSTEM_FOCUS=1 to start condensed.
  g_ui.system_focus = env_flag("MONTAUK_SYSTEM_FOCUS", false);
  g_ui.show_gpumon = true;
  g_ui.show_disk = true;
  g_ui.show_net = true;
  if (iterations <= 0) iterations = INT32_MAX; // effectively run until Ctrl+C
  bool show_help = false;
  auto help_text = std::string("Keys: q quit  c/m/p/n sort  g GPU sort  v GMEM sort  G toggle GPU  +/- fps  arrows/PgUp/PgDn scroll  t Thermal  d Disk  N Net  i CPU scale  u GPU scale  s System focus  R reset UI  h help");
  int alert_frames = 0; int alert_needed = getenv_int("MONTAUK_TOPPROC_ALERT_FRAMES", 5); // consecutive frames over threshold
  bool did_first_clear = false;
  for (int i = 0; (iterations <= 0 || i < iterations) && !g_stop.load(); ++i) {
    if (use_alt && !did_first_clear) { best_effort_write(STDOUT_FILENO, "\x1B[2J\x1B[H", 7); did_first_clear = true; }
    // Non-blocking input with poll
    struct pollfd pfd{.fd=STDIN_FILENO,.events=POLLIN,.revents=0};
    int to = sleep_ms; if (to < 10) to = 10; if (to > 1000) to = 1000;
    int rv = ::poll(&pfd, 1, to);
    if (rv > 0 && (pfd.revents & POLLIN)) {
      unsigned char buf[8]; ssize_t n = ::read(STDIN_FILENO, buf, sizeof(buf));
      if (n > 0) {
        // Very small decoder: handle ESC [ sequences and plain keys
        size_t k = 0;
        while (k < (size_t)n) {
          unsigned char c = buf[k++];
          if (c == 'q' || c == 'Q') { g_stop.store(true); break; }
          else if (c == 'h' || c == 'H') { show_help = !show_help; }
          else if (c == '+') { sleep_ms = std::max(33, sleep_ms - 10); }
          else if (c == '-') { sleep_ms = std::min(1000, sleep_ms + 10); }
          else if (c == 'c' || c == 'C') { g_ui.sort = SortMode::CPU; }
          else if (c == 'm' || c == 'M') { g_ui.sort = SortMode::MEM; }
          else if (c == 'p' || c == 'P') { g_ui.sort = SortMode::PID; }
          else if (c == 'n' || c == 'N') { g_ui.sort = SortMode::NAME; }
          else if (c == 'G') { g_ui.show_gpumon = !g_ui.show_gpumon; }
          else if (c == 'v' || c == 'V') { g_ui.sort = SortMode::GMEM; }
          else if (c == 'g') { g_ui.sort = SortMode::GPU; }
          else if (c == 'i' || c == 'I') { g_ui.cpu_scale = (g_ui.cpu_scale==UIState::CPUScale::Total? UIState::CPUScale::Core : UIState::CPUScale::Total); }
          else if (c == 'u' || c == 'U') { g_ui.gpu_scale = (g_ui.gpu_scale==UIState::GPUScale::Capacity? UIState::GPUScale::Utilization : UIState::GPUScale::Capacity); }
          else if (c == 's' || c == 'S') {
            g_ui.system_focus = !g_ui.system_focus;
            // Entering SYSTEM focus: hide other right-side panels
            if (g_ui.system_focus) {
              g_ui.show_gpumon = false;
              g_ui.show_disk = false;
              g_ui.show_net = false;
            } else {
              // Leaving SYSTEM focus: restore default panels
              g_ui.show_gpumon = true;
              g_ui.show_disk = true;
              g_ui.show_net = true;
            }
          }
          else if (c == 'R') { reset_ui_defaults(); }
          // 'o' previously toggled Ops UI; now Ops-style SYSTEM is default and 'o' is unused
          else if (c == 't' || c == 'T') { g_ui.show_thermal = !g_ui.show_thermal; }
          else if (c == 'd' || c == 'D') { g_ui.show_disk = !g_ui.show_disk; }
          else if (c == 'N') { g_ui.show_net = !g_ui.show_net; }
          else if (c == 0x1B) {
            // Try to parse ESC [ A/B/C/D or PgUp/PgDn (~)
            unsigned char a=0,b=0, d=0;
            if (k < (size_t)n) a = buf[k++]; else break;
            if (a == '[') {
              if (k < (size_t)n) b = buf[k++]; else break;
              if (b >= 'A' && b <= 'D') {
                // arrows: A up, B down (clamped to process list bounds)
                int max_scroll = std::max(0, g_ui.last_proc_total - g_ui.last_proc_page_rows);
                if (b=='A') { if (g_ui.scroll > 0) g_ui.scroll--; }
                else if (b=='B') { g_ui.scroll = std::min(g_ui.scroll + 1, max_scroll); }
              } else if (b=='5' || b=='6') { // PgUp/PgDn expect '~'
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
        }
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
    std::string dyn_help = alert + "SORT:" + sort_name + " • FOCUS:" + (g_ui.system_focus? "SYSTEM":"DEFAULT") + " • FPS:" + std::to_string(fps) + "  " + help_text;
    montauk::ui::render_screen(s, show_help, dyn_help);
  }
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
