#pragma once

#include <string>
#include <atomic>
#include <vector>
#include <termios.h>

namespace montauk::ui {

// Terminal state management
extern std::atomic<bool> g_stop;
extern std::atomic<bool> g_alt_in_use;

void restore_terminal_minimal();
void on_sigint(int);
void on_atexit_restore();

// Terminal capability detection
[[nodiscard]] bool tty_stdout();
[[nodiscard]] bool truecolor_capable();
[[nodiscard]] int term_cols();
[[nodiscard]] int term_rows();

// SGR code generation
[[nodiscard]] std::string sgr(const char* code);
[[nodiscard]] std::string sgr_reset();
[[nodiscard]] std::string sgr_code_int(int code);
[[nodiscard]] std::string sgr_palette_idx(int idx);
[[nodiscard]] std::string sgr_truecolor(int r, int g, int b);

// Unified color helpers (source thresholds and colors from UIConfig)
[[nodiscard]] std::string bar_color(double pct);
[[nodiscard]] std::string grey_bullet();

// OSC 4 palette detection (one-time, for --init-theme)
[[nodiscard]] std::string query_palette_color(int idx);
[[nodiscard]] std::vector<std::string> detect_palette();

// Best-effort terminal write (async-signal-safe). Used by guards
// (alt-screen, cursor) and signal/atexit handlers — these need ordered,
// synchronous writes so terminal state is correct on shutdown.
void best_effort_write(int fd, const char* buf, size_t len);

// Async writer thread for frame output. The renderer hot loop hands
// finished frame buffers to enqueue_frame() and returns immediately;
// the writer drains the queue with blocking write()s on its own thread,
// keeping the render loop unaffected by PTY backpressure.
//
// Frames are dropped if the queue grows past a small bound (the writer
// is slower than the producer is wedged — better to skip a frame than
// pile up). On shutdown, stop_async_writer() drains then joins.
void start_async_writer();
void stop_async_writer();
void enqueue_frame(std::string frame);

// RAII guards for terminal state
class RawTermGuard {
  bool active_{false};
  termios old_{};
  int old_flags_{0};
public:
  RawTermGuard();
  ~RawTermGuard();
};

class CursorGuard {
  bool active_{false};
public:
  CursorGuard();
  ~CursorGuard();
};

class AltScreenGuard {
  bool active_{false};
public:
  explicit AltScreenGuard(bool enable);
  ~AltScreenGuard();
};

} // namespace montauk::ui
