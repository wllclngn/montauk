#include "ui/Terminal.hpp"
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <cstdlib>
#include <string>

// Forward declaration for ui_config (will be in Config module)
namespace montauk::ui { 
  struct UIConfig { 
    std::string accent, caution, warning, base, success, info, muted, title;
    int caution_pct, warning_pct;
  };
  const UIConfig& ui_config(); 
}

namespace montauk::ui {

std::atomic<bool> g_stop{false};
std::atomic<bool> g_alt_in_use{false};

void best_effort_write(int fd, const char* buf, size_t len) {
  if (len == 0) return;
  if (::write(fd, buf, len) < 0) { /* ignore */ }
}

void restore_terminal_minimal() {
  // Async-signal-safe restoration: exit alt screen first, then show cursor, reset SGR
  const char* alt_off = "\x1B[?1049l";
  const char* show_cur = "\x1B[?25h";
  const char* reset = "\x1B[0m";
  if (g_alt_in_use.load()) best_effort_write(STDOUT_FILENO, alt_off, std::char_traits<char>::length(alt_off));
  best_effort_write(STDOUT_FILENO, show_cur, std::char_traits<char>::length(show_cur));
  best_effort_write(STDOUT_FILENO, reset, std::char_traits<char>::length(reset));
}

void on_sigint(int){ restore_terminal_minimal(); g_stop.store(true); }

void on_atexit_restore(){
  // Ensure all buffered output is written, then restore terminal state
  std::fflush(stdout);
  restore_terminal_minimal();
  if (::isatty(STDOUT_FILENO) == 1) {
    // best-effort drain (not signal-safe; fine here)
    tcdrain(STDOUT_FILENO);
  }
}

bool tty_stdout() {
  return ::isatty(STDOUT_FILENO) == 1;
}

bool truecolor_capable() {
  const char* ct = std::getenv("COLORTERM");
  if (ct) {
    std::string s = ct; 
    for (auto& c : s) c = std::tolower((unsigned char)c);
    if (s.find("truecolor") != std::string::npos || s.find("24bit") != std::string::npos) return true;
  }
  return false;
}

bool use_unicode() {
#ifdef __linux__
  const char* lc = std::getenv("LANG");
  if (!lc || !*lc) lc = std::getenv("LC_ALL");
  if (!lc || !*lc) return false;
  std::string s = lc; 
  for (auto& c : s) c = std::tolower((unsigned char)c);
  return s.find("utf") != std::string::npos || s.find("utf8") != std::string::npos || s.find("utf-8") != std::string::npos;
#else
  return false;
#endif
}

int term_cols() {
  struct winsize ws{};
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
    return ws.ws_col;
  const char* c = std::getenv("COLUMNS");
  if (c && *c) {
    try { return std::max(20, std::stoi(c)); } catch(...) {}
  }
  return 80;
}

std::string sgr(const char* code) {
  if (!tty_stdout()) return {};
  return std::string("\x1B[") + code + "m";
}

std::string sgr_reset() {
  if (!tty_stdout()) return {};
  return std::string("\x1B[0m");
}

std::string sgr_bold() { 
  return sgr("1"); 
}

std::string sgr_fg_grey() { 
  return sgr("90"); 
}

std::string sgr_fg_cyan() { 
  return sgr("96"); 
}

std::string sgr_fg_red() { 
  return sgr("31"); 
}

std::string sgr_fg_yel() { 
  return sgr("33"); 
}

std::string sgr_fg_grn() { 
  return sgr("32"); 
}

std::string sgr_code_int(int code) {
  if (!tty_stdout()) return {};
  return std::string("\x1B[") + std::to_string(code) + "m";
}

std::string sgr_palette_idx(int idx) {
  if (!tty_stdout()) return {};
  if (idx < 0) idx = 0;
  if (idx <= 7) return sgr_code_int(30 + idx);
  if (idx <= 15) return sgr_code_int(90 + (idx - 8));
  // 256-color fallback
  return std::string("\x1B[38;5;") + std::to_string(idx) + "m";
}

std::string sgr_truecolor(int r, int g, int b) {
  if (!tty_stdout()) return {};
  r = std::clamp(r,0,255); g = std::clamp(g,0,255); b = std::clamp(b,0,255);
  return std::string("\x1B[38;2;") + std::to_string(r) + ";" + std::to_string(g) + ";" + std::to_string(b) + "m";
}
int term_rows() {
  struct winsize ws{};
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0)
    return ws.ws_row;
  const char* env = std::getenv("LINES");
  if (env) { int r = std::atoi(env); if (r > 0) return r; }
  return 40;
}


// RAII guards for terminal state
RawTermGuard::RawTermGuard() {
  if (::isatty(STDIN_FILENO) == 1) {
    if (tcgetattr(STDIN_FILENO, &old_) == 0) {
      termios neo = old_;
      neo.c_lflag &= ~(ICANON | ECHO);
      neo.c_cc[VMIN] = 0;
      neo.c_cc[VTIME] = 0;
      tcsetattr(STDIN_FILENO, TCSANOW, &neo);
      old_flags_ = fcntl(STDIN_FILENO, F_GETFL, 0);
      fcntl(STDIN_FILENO, F_SETFL, old_flags_ | O_NONBLOCK);
      active_ = true;
    }
  }
}

RawTermGuard::~RawTermGuard() {
  if (active_) {
    tcsetattr(STDIN_FILENO, TCSANOW, &old_);
    fcntl(STDIN_FILENO, F_SETFL, old_flags_);
  }
}

CursorGuard::CursorGuard() {
  if (tty_stdout()) {
    best_effort_write(STDOUT_FILENO, "\x1B[?25l", 6);
    active_ = true;
  }
}

CursorGuard::~CursorGuard() {
  if (active_) best_effort_write(STDOUT_FILENO, "\x1B[?25h", 6);
}

AltScreenGuard::AltScreenGuard(bool enable) {
  if (enable && tty_stdout()) {
    best_effort_write(STDOUT_FILENO, "\x1B[?1049h", 8);
    active_ = true;
    g_alt_in_use.store(true);
  }
}

AltScreenGuard::~AltScreenGuard() {
  if (active_) {
    best_effort_write(STDOUT_FILENO, "\x1B[?1049l", 8);
    g_alt_in_use.store(false);
  }
}

} // namespace montauk::ui
