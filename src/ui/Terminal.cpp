#include "ui/Terminal.hpp"
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <cctype>
#include "util/AsciiLower.hpp"
#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <format>
#include <poll.h>
#include <string>
#include <vector>

#include "ui/Config.hpp"

namespace montauk::ui {

constinit std::atomic<bool> g_stop{false};
constinit std::atomic<bool> g_alt_in_use{false};

void best_effort_write(int fd, const char* buf, size_t len) {
  while (len > 0) {
    ssize_t n = ::write(fd, buf, len);
    if (n < 0) {
      if (errno == EINTR) continue;
      return;
    }
    if (n == 0) return;
    buf += n;
    len -= n;
  }
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
    for (auto& c : s) c = montauk::util::ascii_lower((unsigned char)c);
    if (s.find("truecolor") != std::string::npos || s.find("24bit") != std::string::npos) return true;
  }
  return false;
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

std::string sgr_code_int(int code) {
  if (!tty_stdout()) return {};
  return std::format("\x1B[{}m", code);
}

std::string sgr_palette_idx(int idx) {
  if (!tty_stdout()) return {};
  if (idx < 0) idx = 0;
  if (idx <= 7) return sgr_code_int(30 + idx);
  if (idx <= 15) return sgr_code_int(90 + (idx - 8));
  // 256-color fallback
  return std::format("\x1B[38;5;{}m", idx);
}

std::string sgr_truecolor(int r, int g, int b) {
  if (!tty_stdout()) return {};
  r = std::clamp(r,0,255); g = std::clamp(g,0,255); b = std::clamp(b,0,255);
  return std::format("\x1B[38;2;{};{};{}m", r, g, b);
}
std::string bar_color(double pct) {
  if (!tty_stdout()) return {};
  const auto& ui = ui_config();
  if (pct <= (double)ui.caution_pct) return ui.normal;
  if (pct <= (double)ui.warning_pct) return ui.caution;
  return ui.warning;
}

std::string grey_bullet() {
  if (!tty_stdout()) return std::string("\xE2\x80\xA2");
  const auto& ui = ui_config();
  return ui.muted + std::string("\xE2\x80\xA2") + sgr_reset();
}

int term_rows() {
  struct winsize ws{};
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0)
    return ws.ws_row;
  const char* env = std::getenv("LINES");
  if (env) { int r = std::atoi(env); if (r > 0) return r; }
  return 40;
}


// OSC 4 palette detection -- queries terminal for ANSI color at index.
// Sends: ESC ] 4 ; {idx} ; ? BEL
// Expects: ESC ] 4 ; {idx} ; rgb:RRRR/GGGG/BBBB ST (or BEL)
// Returns "#RRGGBB" or empty string on timeout/failure.
std::string query_palette_color(int idx) {
  if (!::isatty(STDIN_FILENO) || !::isatty(STDOUT_FILENO)) return {};

  // Enter raw mode for reading response
  termios old;
  if (tcgetattr(STDIN_FILENO, &old) != 0) return {};
  termios raw = old;
  raw.c_lflag &= ~(ICANON | ECHO);
  raw.c_cc[VMIN] = 0;
  raw.c_cc[VTIME] = 0;
  tcsetattr(STDIN_FILENO, TCSANOW, &raw);
  int old_fl = fcntl(STDIN_FILENO, F_GETFL, 0);
  fcntl(STDIN_FILENO, F_SETFL, old_fl | O_NONBLOCK);

  // Flush any pending input
  char discard[256];
  while (::read(STDIN_FILENO, discard, sizeof(discard)) > 0) {}

  // Send OSC 4 query
  auto query = std::format("\033]4;{};?\007", idx);
  best_effort_write(STDOUT_FILENO, query.c_str(), query.size());

  // Read response with timeout
  char buf[128];
  size_t pos = 0;
  struct pollfd pfd{.fd = STDIN_FILENO, .events = POLLIN, .revents = 0};
  auto deadline = 100; // ms
  while (pos < sizeof(buf) - 1) {
    int rv = ::poll(&pfd, 1, deadline);
    if (rv <= 0) break;
    ssize_t n = ::read(STDIN_FILENO, buf + pos, sizeof(buf) - 1 - pos);
    if (n <= 0) break;
    pos += n;
    // Check for terminator: BEL (0x07) or ST (ESC \)
    for (size_t i = 0; i < pos; ++i) {
      if (buf[i] == '\007' || (i > 0 && buf[i-1] == '\033' && buf[i] == '\\')) {
        pos = i;
        goto done;
      }
    }
    deadline = 50; // shorter timeout for subsequent reads
  }
done:
  buf[pos] = '\0';

  // Restore terminal
  tcsetattr(STDIN_FILENO, TCSANOW, &old);
  fcntl(STDIN_FILENO, F_SETFL, old_fl);

  // Parse response: look for "rgb:RRRR/GGGG/BBBB"
  std::string resp(buf, pos);
  auto rgb_pos = resp.find("rgb:");
  if (rgb_pos == std::string::npos) return {};

  auto rgb = resp.substr(rgb_pos + 4);
  // Parse RRRR/GGGG/BBBB (16-bit per channel)
  unsigned int r16 = 0, g16 = 0, b16 = 0;
  if (std::sscanf(rgb.c_str(), "%x/%x/%x", &r16, &g16, &b16) != 3) return {};

  // Scale 16-bit to 8-bit
  int r8 = static_cast<int>(r16 >> 8);
  int g8 = static_cast<int>(g16 >> 8);
  int b8 = static_cast<int>(b16 >> 8);

  return std::format("#{:02X}{:02X}{:02X}", r8, g8, b8);
}

std::vector<std::string> detect_palette() {
  std::vector<std::string> colors(16);
  for (int i = 0; i < 16; ++i)
    colors[i] = query_palette_color(i);
  return colors;
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
    best_effort_write(STDOUT_FILENO, "\x1B[?1049h\x1B[2J\x1B[H", 15);
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
