#pragma once

#include <string>
#include <atomic>
#include <termios.h>

namespace montauk::ui {

// Terminal state management
extern std::atomic<bool> g_stop;
extern std::atomic<bool> g_alt_in_use;

void restore_terminal_minimal();
void on_sigint(int);
void on_atexit_restore();

// Terminal capability detection
bool tty_stdout();
bool truecolor_capable();
int term_cols();
int term_rows();

// SGR code generation
std::string sgr(const char* code);
std::string sgr_reset();
std::string sgr_bold();
std::string sgr_fg_grey();
std::string sgr_fg_cyan();
std::string sgr_fg_red();
std::string sgr_fg_yel();
std::string sgr_fg_grn();
std::string sgr_code_int(int code);
std::string sgr_palette_idx(int idx);
std::string sgr_truecolor(int r, int g, int b);

// Best-effort terminal write (async-signal-safe)
void best_effort_write(int fd, const char* buf, size_t len);

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
