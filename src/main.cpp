#include "app/SnapshotBuffers.hpp"
#include "app/Producer.hpp"
#include "util/Retro.hpp"
#include "model/Snapshot.hpp"

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

// Forward declaration used before definition below
static inline void best_effort_write(int fd, const char* buf, size_t len);

using namespace std::chrono_literals;

static std::atomic<bool> g_stop{false};
static std::atomic<bool> g_alt_in_use{false};
static void restore_terminal_minimal() {
  // Async-signal-safe restoration: exit alt screen first, then show cursor, reset SGR
  const char* alt_off = "\x1B[?1049l";
  const char* show_cur = "\x1B[?25h";
  const char* reset = "\x1B[0m";
  if (g_alt_in_use.load()) best_effort_write(STDOUT_FILENO, alt_off, std::char_traits<char>::length(alt_off));
  best_effort_write(STDOUT_FILENO, show_cur, std::char_traits<char>::length(show_cur));
  best_effort_write(STDOUT_FILENO, reset, std::char_traits<char>::length(reset));
}
static void on_sigint(int){ restore_terminal_minimal(); g_stop.store(true); }

static void on_atexit_restore(){
  // Ensure all buffered output is written, then restore terminal state
  std::fflush(stdout);
  restore_terminal_minimal();
  if (::isatty(STDOUT_FILENO) == 1) {
    // best-effort drain (not signal-safe; fine here)
    tcdrain(STDOUT_FILENO);
  }
}

// -------- UI state (keyboard‑driven) --------
enum class SortMode{CPU,MEM,PID,NAME,GPU,GMEM};
struct UIState {
  SortMode sort{SortMode::CPU};
  int scroll{0};
  bool show_disk{true}, show_net{true}, show_gpuinfo{true}, show_vram{true}, show_thermal{true}, show_gpumon{true};
  int last_proc_page_rows{14};
  enum class CPUScale { Total, Core } cpu_scale{CPUScale::Total};
  enum class GPUScale { Capacity, Utilization } gpu_scale{GPUScale::Capacity};
  // Dynamic process table column widths (sticky with gentle shrink)
  int col_pid_w{5};       // 4..6
  int col_user_w{8};      // 6..12
  int col_gpu_digit_w{4}; // 3..4 (digits area only; then we append "%  ")
  int col_mem_w{5};       // 4..6 (human_kib width)
  // Optional GMEM column toggle and width
  bool show_gmem{true};
  int  col_gmem_w{5};     // 4..6 (human_kib width)
};
static UIState g_ui{};

// Runtime-only terminal styling that inherits the terminal palette.
// Uses only standard SGR indices (no 24-bit RGB, no flags, no external deps).
static bool tty_stdout() {
  return ::isatty(STDOUT_FILENO) == 1;
}

static std::string sgr(const char* code) {
  if (!tty_stdout()) return {};
  return std::string("\x1B[") + code + "m";
}

// Best-effort terminal write that satisfies warn_unused_result without
// escalating errors. Used for small control sequences and frame flushes.
static inline void best_effort_write(int fd, const char* buf, size_t len) {
  if (len == 0) return;
  if (::write(fd, buf, len) < 0) { /* ignore */ }
}

static std::string sgr_reset() { return tty_stdout()? std::string("\x1B[0m") : std::string(); }
static std::string sgr_bold()  { return sgr("1"); }
static std::string sgr_fg_grey(){ return sgr("90"); }      // bright black → theme grey
static std::string sgr_fg_cyan(){ return sgr("96"); }      // cyan (legacy default)
static std::string sgr_fg_red() { return sgr("31"); }
static std::string sgr_fg_yel() { return sgr("33"); }
static std::string sgr_fg_grn() { return sgr("32"); }

// Dynamic palette-driven accents and alert colors.
static std::string sgr_code_int(int code) {
  if (!tty_stdout()) return {};
  return std::string("\x1B[") + std::to_string(code) + "m";
}
static std::string sgr_palette_idx(int idx) {
  if (!tty_stdout()) return {};
  if (idx < 0) idx = 0;
  if (idx <= 7) return sgr_code_int(30 + idx);
  if (idx <= 15) return sgr_code_int(90 + (idx - 8));
  // 256-color fallback
  return std::string("\x1B[38;5;") + std::to_string(idx) + "m";
}
static bool truecolor_capable() {
  const char* ct = std::getenv("COLORTERM");
  if (ct) {
    std::string s = ct; for (auto& c : s) c = std::tolower((unsigned char)c);
    if (s.find("truecolor") != std::string::npos || s.find("24bit") != std::string::npos) return true;
  }
  return false;
}
static std::string sgr_truecolor(int r, int g, int b) {
  if (!tty_stdout()) return {};
  r = std::clamp(r,0,255); g = std::clamp(g,0,255); b = std::clamp(b,0,255);
  return std::string("\x1B[38;2;") + std::to_string(r) + ";" + std::to_string(g) + ";" + std::to_string(b) + "m";
}
static bool parse_hex_rgb(const std::string& hex, int& r, int& g, int& b) {
  if (hex.size()!=7 || hex[0] != '#') return false;
  auto hexv = [&](char c)->int{ if (c>='0'&&c<='9') return c-'0'; if (c>='a'&&c<='f') return c-'a'+10; if (c>='A'&&c<='F') return c-'A'+10; return -1; };
  int v1=hexv(hex[1]), v2=hexv(hex[2]), v3=hexv(hex[3]), v4=hexv(hex[4]), v5=hexv(hex[5]), v6=hexv(hex[6]);
  if (v1<0||v2<0||v3<0||v4<0||v5<0||v6<0) return false;
  r = v1*16+v2; g = v3*16+v4; b = v5*16+v6; return true;
}
static const char* getenv_compat(const char* name) {
  const char* v = std::getenv(name);
  if (v && *v) return v;
  // Accept both legacy MONTAUK_ and new montauk_ prefixes
  std::string alt;
  std::string n(name);
  if (n.rfind("MONTAUK_", 0) == 0) {
    alt = std::string("montauk_") + n.substr(8);
  } else if (n.rfind("montauk_", 0) == 0) {
    alt = std::string("MONTAUK_") + n.substr(8);
  }
  if (!alt.empty()) {
    v = std::getenv(alt.c_str());
    if (v && *v) return v;
  }
  return nullptr;
}
static int getenv_int(const char* name, int defv) {
  const char* v = getenv_compat(name);
  if (!v || !*v) return defv;
  try { return std::stoi(v); } catch(...) { return defv; }
}
static UIState::CPUScale getenv_cpu_scale(const char* name, UIState::CPUScale defv){
  const char* v = getenv_compat(name);
  if (!v || !*v) return defv;
  std::string s = v; for (auto& c : s) c = std::tolower((unsigned char)c);
  if (s=="core"||s=="percore"||s=="irix") return UIState::CPUScale::Core;
  if (s=="total"||s=="machine"||s=="share") return UIState::CPUScale::Total;
  return defv;
}

struct UIConfig { std::string accent; std::string caution; std::string warning; int caution_pct; int warning_pct; std::string title; };
static const UIConfig& ui_config() {
  static UIConfig cfg = []{
    UIConfig c{};
    // Defaults tuned to your Kitty theme mapping: accent=11(#00FFA6), caution=9(#FFF6A7), warning=1(#EA1717)
    int acc_idx = getenv_int("MONTAUK_ACCENT_IDX", 11);
    int cau_idx = getenv_int("MONTAUK_CAUTION_IDX", 9);
    int war_idx = getenv_int("MONTAUK_WARNING_IDX", 1);
    // Title: classic amber CRT; default to Kitty's color31 (~#FFBF00). Override with MONTAUK_TITLE_IDX.
    int ttl_idx = getenv_int("MONTAUK_TITLE_IDX", 31);
    c.accent  = sgr_palette_idx(acc_idx);
    c.caution = sgr_palette_idx(cau_idx);
    c.warning = sgr_palette_idx(war_idx);
    // Prefer truecolor MONTAUK_TITLE_HEX or montauk_TITLE_HEX if provided
    const char* th = getenv_compat("MONTAUK_TITLE_HEX");
    if (th && truecolor_capable()) {
      int r=0,g=0,b=0; if (parse_hex_rgb(th, r,g,b)) c.title = sgr_truecolor(r,g,b);
    }
    // Default truecolor amber: #FFB000
    if (c.title.empty()) c.title = truecolor_capable()? sgr_truecolor(255,176,0) : sgr_palette_idx(ttl_idx);
    c.caution_pct = getenv_int("MONTAUK_PROC_CAUTION_PCT", 60);
    c.warning_pct = getenv_int("MONTAUK_PROC_WARNING_PCT", 80);
    return c;
  }();
  return cfg;
}

static void print_bar(const std::string& label, double pct, const std::string& suffix) {
  std::cout << label << " " << montauk::util::retro_bar(pct, 20) << " "
            << std::fixed << std::setprecision(1) << pct << "% " << suffix << "\n";
}

static int term_cols() {
  struct winsize ws{};
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
    return ws.ws_col;
  const char* env = std::getenv("COLUMNS");
  if (env) { int c = std::atoi(env); if (c > 0) return c; }
  return 120; // fallback
}

static bool use_unicode() {
  const char* lc = std::getenv("LC_ALL");
  if (!lc) lc = std::getenv("LC_CTYPE");
  if (!lc) lc = std::getenv("LANG");
  if (lc) {
    std::string s = lc;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    if (s.find("utf-8") != std::string::npos || s.find("utf8") != std::string::npos) return true;
  }
  return false;
}

// Visible-width aware truncate+pad. Counts UTF-8 codepoints as width 1
// (good enough for our glyph set: ASCII + box/blocks). No SGR in inputs.
static int u8_len(unsigned char c){
  if (c < 0x80) return 1;        // ASCII
  if ((c >> 5) == 0x6) return 2; // 110xxxxx
  if ((c >> 4) == 0xE) return 3; // 1110xxxx
  if ((c >> 3) == 0x1E) return 4;// 11110xxx
  return 1;
}
static int display_cols(const std::string& s){
  int cols = 0; for (size_t i=0;i<s.size();){ int len = u8_len((unsigned char)s[i]); i += len; cols += 1; } return cols; }
static std::string take_cols(const std::string& s, int cols){
  if (cols <= 0) return std::string();
  std::string out; out.reserve(s.size());
  int seen = 0; size_t i = 0;
  while (i < s.size() && seen < cols) {
    int len = u8_len((unsigned char)s[i]);
    if (i + (size_t)len > s.size()) len = 1; // guard
    out.append(s, i, len);
    i += len; seen += 1;
  }
  return out;
}
static std::string trunc_pad(const std::string& s, int w) {
  if (w <= 0) return "";
  int cols = display_cols(s);
  if (cols == w) return s;
  if (cols < w) return s + std::string(w - cols, ' ');
  if (w <= 1) return take_cols(s, w);
  return take_cols(s, w - 1) + (use_unicode()? "…" : ".");
}

// Left/Right align within interior width (iw): left label on the left, numeric cluster on the right.
// Preserves visible width using UTF-8 aware counters; no SGR in inputs.
static std::string lr_align(int iw, const std::string& left, const std::string& right){
  if (iw <= 0) return std::string();
  int rvis = display_cols(right);
  int tlw = iw - rvis - 1; if (tlw < 0) tlw = 0;
  std::string l = trunc_pad(left, tlw);
  int lvis = display_cols(l);
  int space = iw - lvis - rvis; if (space < 0) space = 0;
  return l + std::string(space, ' ') + right;
}

static std::vector<std::string> make_box(const std::string& title, const std::vector<std::string>& lines, int width, int min_height = 0) {
  // width includes borders; interior width is width-2
  int iw = std::max(3, width - 2);
  std::vector<std::string> out;
  auto repeat = [](const std::string& ch, int n){ std::string r; r.reserve(std::max(0,n* (int)ch.size())); for (int i=0;i<n;i++) r += ch; return r; };
  const bool uni = use_unicode();
  const std::string TL = uni? "╭" : "+";
  const std::string TR = uni? "╮" : "+";
  const std::string BL = uni? "╰" : "+";
  const std::string BR = uni? "╯" : "+";
  const std::string H  = uni? "─" : "-";
  const std::string V  = uni? "│" : "|";
  auto top = [&]{
    std::string t = "[ " + title + " ]";
    int fill = std::max(0, iw - (int)t.size());
    int left = fill / 2; int right = fill - left;
    return TL + repeat(H, left) + t + repeat(H, right) + TR;
  }();
  out.push_back(top);
  int content_lines = std::max((int)lines.size(), min_height);
  for (int i = 0; i < content_lines; ++i) {
    std::string ln = (i < (int)lines.size()) ? lines[i] : std::string();
    out.push_back(V + trunc_pad(ln, iw) + V);
  }
  out.push_back(BL + repeat(H, iw) + BR);
  return out;
}

// Colorize a single rendered line while preserving visible column widths.
// We only inject SGR sequences; the string’s visible width is unchanged.
static std::string colorize_line(const std::string& s) {
  if (!tty_stdout()) return s;
  auto uni = use_unicode();
  const char* V = uni ? "│" : "|";
  // Top/bottom borders: color whole line grey, accent the [ TITLE ] if present.
  auto is_border = [&](const std::string& str){
    if (str.empty()) return false;
    // If a vertical border exists in the line, it is a content row, not a top/bottom border.
    if (str.find(uni ? "│" : "|") != std::string::npos) return false;
    // Consider as border only if it starts with specific box-drawing corners/lines (UTF-8) or ASCII fallbacks
    if (uni) {
      if (str.rfind("╭",0)==0 || str.rfind("╮",0)==0 || str.rfind("╰",0)==0 || str.rfind("╯",0)==0 || str.rfind("─",0)==0)
        return true;
      return false; // do not treat arbitrary UTF-8 (e.g., box drawing chars) as borders
    }
    return str.rfind("+",0)==0 || str.rfind("-",0)==0;
  };
  if (is_border(s)) {
    size_t lb = s.find('[');
    size_t rb = (lb!=std::string::npos) ? s.find(']', lb+1) : std::string::npos;
    if (lb != std::string::npos && rb != std::string::npos && rb > lb) {
      std::string pre = s.substr(0, lb);
      std::string mid = s.substr(lb, rb - lb + 1);
      std::string suf = s.substr(rb + 1);
      const auto& ui = ui_config();
      return sgr_fg_grey() + pre + ui.accent + mid + sgr_fg_grey() + suf + sgr_reset();
    }
    return sgr_fg_grey() + s + sgr_reset();
  }
  // Content rows: color side borders grey.
  size_t lpos = s.rfind(V);
  size_t fpos = s.find(V);
  if (fpos != std::string::npos && lpos != std::string::npos && lpos > fpos) {
    std::string pre = s.substr(0, fpos);
    std::string leftb = s.substr(fpos, std::strlen(V));
    std::string mid = s.substr(fpos + std::strlen(V), lpos - (fpos + std::strlen(V)));
    std::string rightb = s.substr(lpos, std::strlen(V));
    std::string suf = s.substr(lpos + std::strlen(V));
    // Attempt to color progress bar segments inside mid if present.
    auto color_bar = [&](const std::string& part)->std::string{
      size_t lb = part.find('[');
      size_t rb = (lb!=std::string::npos) ? part.find(']', lb+1) : std::string::npos;
      if (lb==std::string::npos || rb==std::string::npos || rb<=lb) return part;
      // Extract percent near the end of the line (.. 82%).
      double pct = -1.0; {
        size_t p = part.rfind('%');
        if (p != std::string::npos) {
          size_t st = p; while (st>0 && (std::isdigit((unsigned char)part[st-1]) || part[st-1]=='.')) --st;
          try { pct = std::stod(part.substr(st, p-st)); } catch (...) { pct = -1.0; }
        }
      }
      std::string pre2 = part.substr(0, lb+1);
      std::string bar = part.substr(lb+1, rb - (lb+1));
      std::string suf2 = part.substr(rb);
      // If no explicit percent, estimate from bar fill (█) vs total width
      if (pct < 0.0) {
        int total = display_cols(bar);
        int filled = 0;
        size_t pos = 0;
        const std::string full = "█"; // default fill used by retro_bar
        while (true) {
          size_t f = bar.find(full, pos);
          if (f == std::string::npos) break;
          filled += 1; pos = f + full.size();
        }
        if (total > 0) pct = 100.0 * (double)filled / (double)total;
      }
      const std::string bar_color = (pct < 0.0) ? sgr_fg_cyan() : (pct <= 60.0 ? sgr_fg_grn() : (pct <= 80.0 ? sgr_fg_yel() : sgr_fg_red()));
      return pre2 + bar_color + bar + sgr_reset() + suf2;
    };
    std::string mid2 = color_bar(mid);
    return pre + sgr_fg_grey() + leftb + sgr_reset() + mid2 + sgr_fg_grey() + rightb + sgr_reset() + suf;
  }
  // Title row (outside boxes)
  if (s.find("SYSTEM MONITOR") != std::string::npos) {
    return sgr_bold() + s + sgr_reset();
  }
  return s;
}

 

// Simple EMA smoother for bar fill only; numbers remain exact.
static double smooth_value(const std::string& key, double raw, double alpha = 0.25) {
  static std::unordered_map<std::string, double> prev;
  auto it = prev.find(key);
  if (it == prev.end()) { prev.emplace(key, raw); return raw; }
  double sm = alpha * raw + (1.0 - alpha) * it->second;
  it->second = sm;
  return sm;
}

static int term_rows() {
  struct winsize ws{};
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0)
    return ws.ws_row;
  const char* env = std::getenv("LINES");
  if (env) { int r = std::atoi(env); if (r > 0) return r; }
  return 40; // fallback
}

// ------- Runtime terminal guards (RAII) for interactivity -------
class RawTermGuard {
  bool active_{false};
  termios old_{};
  int old_flags_{0};
public:
  RawTermGuard() {
    if (::isatty(STDIN_FILENO) == 1) {
      if (tcgetattr(STDIN_FILENO, &old_) == 0) {
        termios neo = old_;
        neo.c_lflag &= ~(ICANON | ECHO);
        neo.c_cc[VMIN] = 0; // non-blocking by poll
        neo.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &neo);
        old_flags_ = fcntl(STDIN_FILENO, F_GETFL, 0);
        fcntl(STDIN_FILENO, F_SETFL, old_flags_ | O_NONBLOCK);
        active_ = true;
      }
    }
  }
  ~RawTermGuard() {
    if (active_) {
      tcsetattr(STDIN_FILENO, TCSANOW, &old_);
      fcntl(STDIN_FILENO, F_SETFL, old_flags_);
    }
  }
};

class CursorGuard {
  bool active_{false};
public:
  CursorGuard() {
    if (tty_stdout()) { best_effort_write(STDOUT_FILENO, "\x1B[?25l", 6); active_ = true; }
  }
  ~CursorGuard() {
    if (active_) best_effort_write(STDOUT_FILENO, "\x1B[?25h", 6);
  }
};

class AltScreenGuard {
  bool active_{false};
public:
  explicit AltScreenGuard(bool enable) {
    if (enable && tty_stdout()) { best_effort_write(STDOUT_FILENO, "\x1B[?1049h", 8); active_ = true; g_alt_in_use.store(true); }
  }
  ~AltScreenGuard() {
    if (active_) { best_effort_write(STDOUT_FILENO, "\x1B[?1049l", 8); g_alt_in_use.store(false); }
  }
};

static bool env_flag(const char* name, bool defv=true){ const char* v=getenv_compat(name); if(!v) return defv; if(v[0]=='0'||v[0]=='f'||v[0]=='F') return false; return true; }

// Format a colored CPU% field with fixed visible width (aligned to match 4-char "CPU%" header).
static std::string fmt_cpu_field(double cpu_pct, bool colorize=true) {
  std::string digits;
  int display_val;
  
  // For values < 1%, show decimal precision (0.1%, 0.2%, etc.)
  if (cpu_pct > 0.0 && cpu_pct < 1.0) {
    double rounded = std::round(cpu_pct * 10.0) / 10.0;
    if (rounded < 0.1) rounded = 0.1; // minimum 0.1%
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << rounded;
    digits = oss.str();
    display_val = 0; // for color thresholding
  } else {
    display_val = (int)(cpu_pct + 0.5);
    digits = std::to_string(display_val);
  }
  
  // Build the value string with %
  std::string value_str = digits + "%";
  int pad = 4 - (int)value_str.size(); if (pad < 0) pad = 0;
  
  const auto& ui = ui_config();
  const std::string* col = nullptr;
  if (colorize) {
    if (display_val >= ui.warning_pct) col = &ui.warning;
    else if (display_val >= ui.caution_pct) col = &ui.caution;
  }
  
  std::string out;
  out.reserve(4 + 3 + 16);
  out.append(pad, ' ');
  if (col) out += *col;
  out += digits;
  if (col) out += sgr_reset();
  out += "%  ";
  return out;
}

#include "util/AdaptiveSort.hpp"

static std::vector<std::string> render_left_column(const montauk::model::Snapshot& s, int width, int target_rows) {
  std::vector<std::string> all;
  int iw = std::max(3, width - 2);
  auto ncpu = (int)std::max<size_t>(1, s.cpu.per_core_pct.size());
  auto scale_proc_cpu = [&](double raw)->double{
    return (g_ui.cpu_scale==UIState::CPUScale::Total) ? (raw / (double)ncpu) : raw;
  };
  // CPU and Memory panels moved to right column.

  // Processes
  std::vector<std::string> proc_lines; proc_lines.reserve(64);
  std::vector<int> proc_sev; proc_sev.reserve(64); // 0=none,1=caution,2=warning
  // Prepare order and sorting for process list
  std::vector<size_t> order(s.procs.processes.size());
  std::iota(order.begin(), order.end(), 0);
  std::vector<double> sm(order.size(), 0.0);
  for (size_t i = 0; i < order.size(); ++i) {
    const auto& p = s.procs.processes[i];
    sm[i] = smooth_value(std::string("proc.cpu.") + std::to_string(p.pid), scale_proc_cpu(p.cpu_pct), 0.35);
  }
  montauk::util::adaptive_timsort(order.begin(), order.end(), [&](size_t a, size_t b){
    const auto& A = s.procs.processes[a];
    const auto& B = s.procs.processes[b];
    switch (g_ui.sort) {
      case SortMode::CPU:
        if (sm[a] != sm[b]) return sm[a] > sm[b];
        break;
      case SortMode::MEM:
        if (A.rss_kb != B.rss_kb) return A.rss_kb > B.rss_kb;
        break;
      case SortMode::PID:
        if (A.pid != B.pid) return A.pid < B.pid;
        break;
      case SortMode::NAME:
        if (A.cmd != B.cmd) return A.cmd < B.cmd;
        break;
      case SortMode::GPU: {
        auto val = [&](const montauk::model::ProcSample& P){
          bool has = P.has_gpu_util_raw ? true : P.has_gpu_util;
          double v = P.has_gpu_util_raw ? P.gpu_util_pct_raw : P.gpu_util_pct;
          return std::pair<bool,double>{has,v};
        };
        auto [Ah, av] = val(A); auto [Bh, bv] = val(B);
        if (!Ah && !Bh) { if (sm[a] != sm[b]) return sm[a] > sm[b]; break; }
        if (Ah != Bh) return Ah > Bh;
        if (av != bv) return av > bv;
        if (sm[a] != sm[b]) return sm[a] > sm[b];
        break;
      }
      case SortMode::GMEM: {
        auto valm = [&](const montauk::model::ProcSample& P){
          return std::pair<bool,uint64_t>{P.has_gpu_mem, P.gpu_mem_kb};
        };
        auto [Ah, am] = valm(A); auto [Bh, bm] = valm(B);
        if (!Ah && !Bh) { if (sm[a] != sm[b]) return sm[a] > sm[b]; break; }
        if (Ah != Bh) return Ah > Bh;
        if (am != bm) return am > bm;
        if (sm[a] != sm[b]) return sm[a] > sm[b];
        break;
      }
    }
    return A.pid < B.pid;
  });
  // Visible slice indices
  size_t avail = order.size();
  if (g_ui.scroll < 0) g_ui.scroll = 0;
  if ((size_t)g_ui.scroll > (avail>0? (size_t)avail-1:0)) g_ui.scroll = (int)(avail==0?0:avail-1);
  size_t start = std::min<size_t>((size_t)g_ui.scroll, avail);
  size_t desired_rows = std::max(1, g_ui.last_proc_page_rows);
  size_t lim = std::min<size_t>(avail, start + (size_t)desired_rows);
  // Measure visible rows for dynamic widths (two-pass for visible slice)
  int pid_w_meas = 4, user_w_meas = 6, gpu_digit_w_meas = 3, mem_w_meas = 4, gmem_w_meas = 4;
  for (size_t ii=start; ii<lim; ++ii) {
    const auto& p = s.procs.processes[order[ii]];
    int pid_digits = (int)std::to_string(p.pid).size(); if (pid_digits > pid_w_meas) pid_w_meas = pid_digits;
    int user_vis = display_cols(p.user_name); if (user_vis > user_w_meas) user_w_meas = user_vis;
    if (p.has_gpu_util) { int gdig = (int)std::to_string((int)(p.gpu_util_pct+0.5)).size(); if (gdig > gpu_digit_w_meas) gpu_digit_w_meas = gdig; }
    std::string hm = [&]{ uint64_t kib=p.rss_kb; if (kib >= (1024ull*1024ull)) { double g=kib/(1024.0*1024.0); return std::to_string((int)(g+0.5))+"G"; } if (kib>=1024ull){ double m=kib/1024.0; return std::to_string((int)(m+0.5))+"M";} return std::to_string((int)kib)+"K"; }();
    if ((int)hm.size() > mem_w_meas) mem_w_meas = (int)hm.size();
    std::string hg = [&]{ if (!p.has_gpu_mem) return std::string("-"); uint64_t kib=p.gpu_mem_kb; if (kib >= (1024ull*1024ull)) { double g=kib/(1024.0*1024.0); return std::to_string((int)(g+0.5))+"G"; } if (kib>=1024ull){ double m=kib/1024.0; return std::to_string((int)(m+0.5))+"M";} return std::to_string((int)kib)+"K"; }();
    if ((int)hg.size() > gmem_w_meas) gmem_w_meas = (int)hg.size();
  }
  // Clamp
  pid_w_meas = std::min(6, std::max(4, pid_w_meas));
  user_w_meas = std::min(12, std::max(6, user_w_meas));
  gpu_digit_w_meas = std::min(4, std::max(3, gpu_digit_w_meas));
  mem_w_meas = std::min(6, std::max(4, mem_w_meas));
  gmem_w_meas = std::min(6, std::max(4, gmem_w_meas));
  // Sticky with gentle shrink
  auto shrink_one = [](int current, int target){ return (target >= current)? target : std::max(target, current-1); };
  g_ui.col_pid_w = shrink_one(g_ui.col_pid_w, pid_w_meas);
  g_ui.col_user_w = shrink_one(g_ui.col_user_w, user_w_meas);
  g_ui.col_gpu_digit_w = shrink_one(g_ui.col_gpu_digit_w, gpu_digit_w_meas);
  g_ui.col_mem_w = shrink_one(g_ui.col_mem_w, mem_w_meas);
  g_ui.col_gmem_w = shrink_one(g_ui.col_gmem_w, gmem_w_meas);
  int pidw = g_ui.col_pid_w, userw = g_ui.col_user_w, gpud = g_ui.col_gpu_digit_w, memw = g_ui.col_mem_w, gmemw = g_ui.col_gmem_w;
  // Header (align numeric headers to the right of their columns)
  {
    std::ostringstream h;
    h << std::setw(pidw) << "PID" << "  "
      << trunc_pad("USER", userw) << "  "
      << std::setw(4) << "CPU%" << "  "
      << std::setw(gpud) << "GPU%" << "  "
      << std::setw(gmemw) << "GMEM" << "  "
      << std::setw(memw) << "MEM" << "  "
      << "COMMAND";
    proc_lines.push_back(trunc_pad(h.str(), iw));
  }
  proc_sev.push_back(0);
  // (sorting done above)
  // Compute how many rows we want to fill on the left side.
  // We already appended cpu_box and mem_box to 'all'. Compute their heights:
  // Note: cpu_box and mem_box were appended above.
  int used_fixed = (int)all.size();
  int remaining_for_proc = std::max(5, target_rows - used_fixed);
  int proc_inner_min = std::max(14, remaining_for_proc - 2); // minus borders
  int desired_rows2 = std::max(1, proc_inner_min - 1); // minus header row inside box
  g_ui.last_proc_page_rows = desired_rows2;
  for (size_t ii=start; ii<lim; ++ii) {
    const auto& p = s.procs.processes[order[ii]];
    std::ostringstream os;
    std::string user = p.user_name.empty() ? "" : p.user_name;
    auto human_kib = [](uint64_t kib){ if (kib >= (1024ull*1024ull)) { double g=kib/(1024.0*1024.0); return std::to_string((int)(g+0.5))+"G"; } if (kib>=1024ull){ double m=kib/1024.0; return std::to_string((int)(m+0.5))+"M";} return std::to_string((int)kib)+"K"; };
    double cpu_disp = sm[order[ii]]; // show smoothed CPU (scaled per setting)
    int val = (int)(cpu_disp + 0.5);
    const auto& ui = ui_config();
    int sev = 0; if (p.churn) sev = 2; else if (val >= ui.warning_pct) sev = 2; else if (val >= ui.caution_pct) sev = 1;
    auto fmt_gpu = [&](const montauk::model::ProcSample& pp){
      // Heuristic: prefer raw if present this frame; otherwise use smoothed
      bool has = pp.has_gpu_util_raw ? true : pp.has_gpu_util;
      double v = pp.has_gpu_util_raw ? pp.gpu_util_pct_raw : pp.gpu_util_pct;
      
      // GPU scale modes:
      // - Capacity (default): shows raw smUtil (% of GPU computational power)
      // - Utilization (press 'u'): same as Capacity (kept for future distinction)
      // Note: smUtil from NVML is already the correct "% of GPU power used"
      
      std::string digits;
      if (!has) {
        digits = "0";
      } else if (v > 0.0 && v < 1.0) {
        // For values < 1%, show decimal precision (0.1%, 0.2%, etc.)
        double rounded = std::round(v * 10.0) / 10.0;
        if (rounded < 0.1) rounded = 0.1; // minimum 0.1%
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(1) << rounded;
        digits = oss.str();
      } else {
        int g = (int)(v + 0.5);
        if (g < 0) g = 0;
        digits = std::to_string(g);
      }
      
      int pad = gpud - (int)digits.size(); if (pad < 0) pad = 0;
      return std::string(pad, ' ') + digits + "%  ";
    };
    auto fmt_mem = [&](uint64_t rss_kb){
      std::string m = human_kib(rss_kb);
      int pad = memw - (int)m.size(); if (pad < 0) pad = 0;
      return std::string(pad, ' ') + m + "  ";
    };
    auto fmt_gmem = [&](bool has, uint64_t gkib){
      std::string m = has ? human_kib(gkib) : std::string("0K");
      int pad = gmemw - (int)m.size(); if (pad < 0) pad = 0;
      return std::string(pad, ' ') + m + "  ";
    };
    // Compute command width dynamically
    const int fields_w = 6 + (gpud+3) + (gmemw+2) + (memw+2);
    const int cmd_w = iw - (pidw+2 + userw+2 + fields_w);
    os << std::setw(pidw) << p.pid << "  "
       << trunc_pad(user,userw) << "  "
       << [&]{
            if (!p.churn) {
              std::ostringstream tmp; tmp
                << fmt_cpu_field(cpu_disp, /*colorize=*/sev==0)
                << fmt_gpu(p)
                << fmt_gmem(p.has_gpu_mem, p.gpu_mem_kb)
                << fmt_mem(p.rss_kb);
              return tmp.str();
            } else {
              std::string msg = "PROC CHURN DETECTED";
              if ((int)msg.size() < fields_w) msg += std::string(fields_w - (int)msg.size(), ' ');
              else if ((int)msg.size() > fields_w) msg = msg.substr(0, fields_w);
              return msg;
            }
          }()
       << trunc_pad(p.cmd.empty()? std::to_string(p.pid) : p.cmd, std::max(8, cmd_w));
    proc_lines.push_back(os.str());
    proc_sev.push_back(sev);
  }
  auto proc_box = make_box("PROCESS MONITOR", proc_lines, width, proc_inner_min);
  // Apply full-line caution/warning coloring for process rows (content area only)
  if (!proc_box.empty()) {
    const bool uni = use_unicode();
    const std::string V = uni? "│" : "|";
    for (size_t li = 1; li + 1 < proc_box.size() && (li-1) < proc_sev.size(); ++li) {
      int sev = proc_sev[li-1];
      if (sev <= 0) continue; // skip header and non-severe rows
      auto& line = proc_box[li];
      size_t fpos = line.find(V);
      size_t lpos = line.rfind(V);
      if (fpos == std::string::npos || lpos == std::string::npos || lpos <= fpos) continue;
      size_t start = fpos + V.size();
      std::string pre = line.substr(0, start);
      std::string mid = line.substr(start, lpos - start);
      std::string suf = line.substr(lpos);
      const auto& uic = ui_config();
      const std::string& col = (sev==2) ? uic.warning : uic.caution;
      line = pre + col + mid + sgr_reset() + suf;
    }
  }
  all.insert(all.end(), proc_box.begin(), proc_box.end());
  return all;
}

static std::vector<std::string> render_right_column(const montauk::model::Snapshot& s, int width, int target_rows) {
  std::vector<std::string> out;
  int iw = std::max(3, width - 2);
  auto box_add = [&](const std::string& title, const std::vector<std::string>& lines, int min_h=0){
    auto b = make_box(title, lines, width, min_h); out.insert(out.end(), b.begin(), b.end());
  };
  bool show_disk = g_ui.show_disk, show_net = g_ui.show_net,
       show_thermal = g_ui.show_thermal, show_gpumon = g_ui.show_gpumon;
  // Shared helper for one-line retro bars (label width 8, bar-only)
  auto bar_line8 = [&](const std::string& key, const char* label8, double pct_raw){
    const int label_w = 8;
    int barw = std::max(10, iw - (label_w + 3));
    double bar_pct = smooth_value(key, pct_raw);
    std::string bar = montauk::util::retro_bar(bar_pct, barw);
    std::ostringstream os; os << trunc_pad(label8, label_w) << " " << bar;
    return os.str();
  };

  // PROCESSOR (CPU) — first on right
  {
    std::vector<std::string> lines;
    lines.push_back(bar_line8("cpu.total", "CPU", s.cpu.usage_pct));
    box_add("PROCESSOR", lines, 1);
  }
  // (DISK I/O and NETWORK moved below GPU MONITOR)
  // GPU Info removed (details live in SYSTEM)
  // VRAM panel removed; VRAM appears as a row in GPU MONITOR and details in SYSTEM
  // THERMALS moved into SYSTEM box (removed)
  // GPU — fixed size with gentle spacing between rows
  if (show_gpumon) {
    std::vector<std::string> lines;
    auto gpu_line = [&](const std::string& key, const char* label8, double pct_raw){
      const int label_w = 8;
      // Bar only (percent shown in SYSTEM)
      // label + space + '[' + bar + ']' must fit
      int barw = std::max(10, iw - (label_w + 3));
      double bar_pct = smooth_value(key, pct_raw);
      std::string bar = montauk::util::retro_bar(bar_pct, barw);
      std::ostringstream os; os << trunc_pad(label8, label_w) << " " << bar;
      return os.str();
    };
    auto add_row = [&](const std::string& row){ if (!row.empty()) lines.push_back(row); if (!lines.empty()) lines.push_back(""); };
    // Order: GPU → VRAM → MEM → ENC → DEC
    if (s.vram.has_util)    { add_row(gpu_line("gpu.util", "GPU", s.vram.gpu_util_pct)); }
    if (s.vram.total_mb > 0) { add_row(gpu_line("gpu.vram_used", "VRAM", s.vram.used_pct)); }
    if (s.vram.has_mem_util){ add_row(gpu_line("gpu.mem_util", "MEM", s.vram.mem_util_pct)); }
    if (s.vram.has_encdec) {
      add_row(gpu_line("gpu.enc", "ENC", s.vram.enc_util_pct));
      add_row(gpu_line("gpu.dec", "DEC", s.vram.dec_util_pct));
    }
    // POWER removed from GPU MONITOR (shown in SYSTEM)
    // Remove the trailing spacer if present
    if (!lines.empty() && lines.back().empty()) lines.pop_back();
    box_add("GPU", lines, (int)lines.size());
  }
  // MEMORY (after GPU)
  {
    std::vector<std::string> lines;
    lines.push_back(bar_line8("mem.used", "MEMORY", s.mem.used_pct));
    box_add("MEMORY", lines, 1);
  }
  // DISK I/O (after MEMORY)
  if (show_disk) {
    std::vector<std::string> lines;
    {
      std::ostringstream rs; rs << "R:" << (int)(s.disk.total_read_bps/1000000) << "MB/s  W:" << (int)(s.disk.total_write_bps/1000000) << "MB/s";
      lines.push_back(lr_align(iw, "", rs.str()));
    }
    size_t lim = std::min<size_t>(s.disk.devices.size(), 3);
    for (size_t i=0;i<lim;i++) {
      const auto& d = s.disk.devices[i];
      std::ostringstream r; r << (int)(d.util_pct+0.5) << "%";
      lines.push_back(lr_align(iw, d.name, r.str()));
    }
    box_add("DISK I/O", lines, 3);
  }
  // NETWORK (after DISK I/O)
  if (show_net) {
    std::vector<std::string> lines;
    {
      std::ostringstream rs; rs << "↓" << (int)(s.net.agg_rx_bps/1024) << "KB/s  ↑" << (int)(s.net.agg_tx_bps/1024) << "KB/s";
      lines.push_back(lr_align(iw, "", rs.str()));
    }
    size_t lim = std::min<size_t>(s.net.interfaces.size(), 3);
    for (size_t i=0;i<lim;i++) {
      const auto& n = s.net.interfaces[i];
      std::ostringstream rr; rr << "↓" << (int)(n.rx_bps/1024) << "KB/s  ↑" << (int)(n.tx_bps/1024) << "KB/s";
      lines.push_back(lr_align(iw, n.name, rr.str()));
    }
    box_add("NETWORK", lines, 3);
  }
  // SYSTEM box — last, elastic to fill all remaining space to match PROCESS MONITOR height
  {
    int remaining = std::max(0, target_rows - (int)out.size());
    // Always create SYSTEM box, minimum 1 line of content
    int inner_min = std::max(1, remaining - 2);
    std::vector<std::string> sys; std::vector<int> sys_sev; // 0 none, 1 caution, 2 warning
    auto push = [&](const std::string& s, int sev=0){ sys.push_back(trunc_pad(s, iw)); sys_sev.push_back(sev); };
    // CPU model header (show 6C/12T when available)
    if (!s.cpu.model.empty()) {
      std::ostringstream hdr;
      hdr << "CPU: " << s.cpu.model;
      int phys = s.cpu.physical_cores;
      // Show only core count; omit threads to avoid redundancy with next line
      if (phys > 0) {
        hdr << " (" << phys << "C)";
      }
      push(hdr.str(), 0);
    }
    // CPU summary (right-aligned only)
    int ncpu = (int)std::max<size_t>(1, s.cpu.per_core_pct.size());
    double topc = 0.0; for (double v : s.cpu.per_core_pct) if (v > topc) topc = v;
    {
      std::ostringstream rt; rt << "THREADS: " << ncpu
                                << " TOP: " << (int)(topc+0.5) << "%  AVG: " << (int)(s.cpu.usage_pct+0.5) << "%";
      push(lr_align(iw, "", rt.str()), 0);
    }
    // subtle spacing between sections
    push("", 0);
    // DISK omitted here to avoid redundancy with DISK I/O box
    // NET omitted here to avoid redundancy with NETWORK box
    // GPU summary
    if (!s.vram.name.empty()) push(std::string("GPU: ") + trunc_pad(s.vram.name, iw-5), 0);
    if (s.vram.total_mb > 0) {
      std::ostringstream rr; rr << std::fixed << std::setprecision(1) << s.vram.used_pct << "%  ["
                                 << std::setprecision(2) << (s.vram.used_mb/1024.0) << "GB/" << (s.vram.total_mb/1024.0) << "GB]";
      push(lr_align(iw, "VRAM", rr.str()), 0);
    }
    if (s.vram.has_util) {
      std::ostringstream rr; rr << "G:" << (int)(s.vram.gpu_util_pct+0.5) << "%  M:" << (int)(s.vram.mem_util_pct+0.5) << "%";
      if (s.vram.has_encdec) rr << "  E:" << (int)(s.vram.enc_util_pct+0.5) << "%  D:" << (int)(s.vram.dec_util_pct+0.5) << "%";
      push(lr_align(iw, "UTIL", rr.str()), 0);
    }
    // NVML diagnostic line (always show when available)
    if (s.nvml.available) {
      // Derive a simple per‑PID attribution status so users can tell at a glance
      // whether per‑process GPU% comes from NVML samples or a fallback. No env flags.
      auto pid_status = [&](){
        // When NVML returned per‑PID samples this cycle
        if (s.nvml.sampled_pids > 0) return std::string("nvml");
        // If device shows activity and we detected running GPU PIDs, UI will
        // attribute by normalized share heuristics – call this "share".
        int dev_util = (int)(s.vram.gpu_util_pct + 0.5);
        if (dev_util > 0 && s.nvml.running_pids > 0) return std::string("share");
        // Otherwise we have no visibility
        return std::string("none");
      }();
      std::ostringstream rr; rr << (s.nvml.available? "OK" : "OFF")
                                << " dev:" << s.nvml.devices
                                << " run:" << s.nvml.running_pids
                                << " samp:" << s.nvml.sampled_pids
                                << " age:" << s.nvml.sample_age_ms << "ms"
                                << " mig:" << (s.nvml.mig_enabled? "on":"off")
                                << " pid:" << pid_status;
      push(lr_align(iw, "NVML", rr.str()), 0);
    }
    if (s.vram.has_power) { std::ostringstream rr; rr << (int)(s.vram.power_draw_w+0.5) << "W"; push(lr_align(iw, "POWER", rr.str()), 0); }
    // subtle spacing between sections
    push("", 0);
    // Memory (moved below GPU)
    double mem_used_gb = s.mem.used_kb/1048576.0, mem_tot_gb = s.mem.total_kb/1048576.0;
    {
      std::ostringstream rr; rr << std::fixed << std::setprecision(1) << s.mem.used_pct << "%  ["
                                 << std::setprecision(2) << mem_used_gb << "GB/" << mem_tot_gb << "GB]";
      push(lr_align(iw, "MEM", rr.str()), 0);
    }
    if (s.mem.swap_total_kb > 0) {
      double swap_used_gb = s.mem.swap_used_kb/1048576.0, swap_tot_gb = s.mem.swap_total_kb/1048576.0;
      double swap_pct = (s.mem.swap_total_kb>0)? (100.0 * (double)s.mem.swap_used_kb / (double)s.mem.swap_total_kb) : 0.0;
      std::ostringstream rr; rr << std::fixed << std::setprecision(1) << swap_pct << "%  ["
                                 << std::setprecision(2) << swap_used_gb << "GB/" << swap_tot_gb << "GB]";
      push(lr_align(iw, "SWAP", rr.str()), 0);
    }
    // subtle spacing before temps
    push("", 0);
    // Process monitoring statistics
    {
      std::ostringstream rr; 
      rr << "tracked:" << s.procs.processes.size() << "  total:" << s.procs.total_processes;
      push(lr_align(iw, "PROCESSES", rr.str()), 0);
    }
    // subtle spacing before temps
    push("", 0);
    // Temps (respect thermal toggle) — CPU line and per-GPU device lines with severity
    if (show_thermal) {
      auto thr_from = [&](bool has_thr, double thr_c, const char* env_warn, const char* env_warn_fallback){
        int def_warn = getenv_int(env_warn_fallback, 90);
        int warn = has_thr ? (int)(thr_c + 0.5) : getenv_int(env_warn, def_warn);
        int caution = getenv_int((std::string(env_warn).substr(0, std::string(env_warn).find_last_of('_')) + "_CAUTION_C").c_str(),
                                 getenv_int("MONTAUK_GPU_TEMP_CAUTION_C", std::max(0, warn - getenv_int("MONTAUK_TEMP_CAUTION_DELTA_C", 10))));
        return std::pair<int,int>{caution,warn};
      };
      // CPU line
      if (s.thermal.has_temp) {
        int warn = s.thermal.has_warn ? (int)(s.thermal.warn_c + 0.5) : getenv_int("MONTAUK_CPU_TEMP_WARNING_C", 90);
        int caution = getenv_int("MONTAUK_CPU_TEMP_CAUTION_C", std::max(0, warn - getenv_int("MONTAUK_TEMP_CAUTION_DELTA_C", 10)));
        int val = (int)(s.thermal.cpu_max_c + 0.5);
        int sev = (val>=warn)?2:((val>=caution)?1:0);
        std::ostringstream rr; rr << val << "°C";
        push(lr_align(iw, "CPU TEMP", rr.str()), sev);
      }
      // Per-GPU lines
      for (size_t i=0;i<s.vram.devices.size(); ++i) {
        const auto& d = s.vram.devices[i];
        if (!(d.has_temp_edge || d.has_temp_hotspot || d.has_temp_mem)) continue;
        std::ostringstream rr;
        bool first=false;
        int dev_sev = 0;
        if (d.has_temp_edge) { auto [cau,warn] = thr_from(d.has_thr_edge, d.thr_edge_c, "MONTAUK_GPU_TEMP_EDGE_WARNING_C", "MONTAUK_GPU_TEMP_WARNING_C"); int v=(int)(d.temp_edge_c+0.5); dev_sev=std::max(dev_sev,(v>=warn)?2:((v>=cau)?1:0)); rr << "E:" << v << "°C"; first=true; }
        if (d.has_temp_hotspot) { auto [cau,warn] = thr_from(d.has_thr_hotspot, d.thr_hotspot_c, "MONTAUK_GPU_TEMP_HOT_WARNING_C", "MONTAUK_GPU_TEMP_WARNING_C"); int v=(int)(d.temp_hotspot_c+0.5); dev_sev=std::max(dev_sev,(v>=warn)?2:((v>=cau)?1:0)); rr << (first?"  ":"") << "H:" << v << "°C"; first=true; }
        if (d.has_temp_mem) { auto [cau,warn] = thr_from(d.has_thr_mem, d.thr_mem_c, "MONTAUK_GPU_TEMP_MEM_WARNING_C", "MONTAUK_GPU_TEMP_WARNING_C"); int v=(int)(d.temp_mem_c+0.5); dev_sev=std::max(dev_sev,(v>=warn)?2:((v>=cau)?1:0)); rr << (first?"  ":"") << "M:" << v << "°C"; }
        {
          std::string label = (s.vram.devices.size()>1) ? (std::string("GPU") + std::to_string(i) + " TEMP") : std::string("GPU TEMP");
          push(lr_align(iw, label, rr.str()), dev_sev);
        }
      }
    }
    // Add sticky churn summary below temps (warning) when recent events occurred
    if (s.churn.recent_2s_events > 0) {
      std::ostringstream rr; rr << s.churn.recent_2s_events << " events [LAST 2s]";
      push(lr_align(iw, "PROC CHURN", rr.str()), 2);
    }
    // Build box then apply full-line coloring for temperature lines if needed
    auto sys_box = make_box("SYSTEM", sys, width, inner_min);
    if (!sys_box.empty()) {
      const bool uni = use_unicode(); const std::string V = uni? "│" : "|"; const auto& uic = ui_config();
      for (size_t li=1; li+1<sys_box.size() && (li-1)<sys_sev.size(); ++li) {
        int sv = sys_sev[li-1]; if (sv <= 0) continue;
        auto& line = sys_box[li]; size_t fpos = line.find(V); size_t lpos = line.rfind(V);
        if (fpos==std::string::npos || lpos==std::string::npos || lpos<=fpos) continue;
        size_t start = fpos + V.size();
        std::string pre = line.substr(0, start);
        std::string mid = line.substr(start, lpos - start);
        std::string suf = line.substr(lpos);
        const std::string& col = (sv==2) ? uic.warning : uic.caution;
        line = pre + col + mid + sgr_reset() + suf;
      }
    }
    out.insert(out.end(), sys_box.begin(), sys_box.end());
  }
  // Pad to exactly target_rows to match PROCESS MONITOR height
  while ((int)out.size() < target_rows) {
    out.push_back(std::string(width, ' '));
  }
  return out;
}

static void render_screen(const montauk::model::Snapshot& s, bool show_help_line, const std::string& help_text) {
  int cols = term_cols();
  int gutter = 2;
  int left_w = (cols * 2) / 3; if (left_w < 40) left_w = cols - 20; if (left_w > cols-20) left_w = cols-20;
  int right_w = cols - left_w - gutter; if (right_w < 20) right_w = 20;
  int rows = term_rows();
  // Optional 1 line for help; remaining rows for content
  int content_rows = std::max(5, rows - (show_help_line?1:0));
  auto left = render_left_column(s, left_w, content_rows);
  auto right = render_right_column(s, right_w, content_rows);
  // Compose rows: consume left and right vectors line by line
  // Move cursor to home; avoid full clear to reduce flicker
  std::string frame; frame.reserve((size_t)rows * (size_t)cols + 64);
  frame += "\x1B[H";
  // Optional help line (no title/header row)
  if (show_help_line) {
    std::string hline = trunc_pad(help_text, cols);
    frame += colorize_line(hline) + std::string("\n");
  }
  // Emit exactly rows lines: header_lines already printed; produce body_lines below.
  int header_lines = (show_help_line?1:0);
  int body_lines = std::max(0, rows - header_lines);
  for (int row = 0; row < body_lines; ++row) {
    std::string l = (row < (int)left.size()) ? left[row] : std::string(left_w, ' ');
    std::string r = (row < (int)right.size()) ? right[row] : std::string(right_w, ' ');
    if ((int)l.size() < left_w) l += std::string(left_w - (int)l.size(), ' ');
    if ((int)r.size() < right_w) r += std::string(right_w - (int)r.size(), ' ');
    auto line = colorize_line(l) + std::string(gutter, ' ') + colorize_line(r);
    if (row < body_lines - 1) line += "\n";
    frame += line;
  }
  // Position cursor to last cell and flush so teardown never interleaves with the frame
  frame += "\x1B[" + std::to_string(rows) + ";" + std::to_string(cols) + "H";
  best_effort_write(STDOUT_FILENO, frame.data(), frame.size());
}


[[maybe_unused]] static void render_snapshot(const montauk::model::Snapshot& s) {
  double mem_gb_used = s.mem.used_kb / 1048576.0;
  double mem_gb_total = s.mem.total_kb / 1048576.0;
  std::cout << "=== cpp rusttop (text) ===\n";
  print_bar("CPU     ", s.cpu.usage_pct, "");
  print_bar("MEMORY  ", s.mem.used_pct, "(" + std::to_string(mem_gb_used) + "GB/" + std::to_string(mem_gb_total) + "GB)");
  std::cout << "NET     ↓" << static_cast<int>(s.net.agg_rx_bps/1024) << "KB/s  ↑" << static_cast<int>(s.net.agg_tx_bps/1024) << "KB/s\n";
  std::cout << "DISK    R:" << static_cast<int>(s.disk.total_read_bps/1000000) << "MB/s  W:" << static_cast<int>(s.disk.total_write_bps/1000000) << "MB/s\n";
  if (s.thermal.has_temp) {
    std::cout << "CPU TEMP" << "  " << static_cast<int>(s.thermal.cpu_max_c) << "°C\n";
  }

  if (s.vram.total_mb > 0) {
    double used_gb = s.vram.used_mb / 1024.0;
    double total_gb = s.vram.total_mb / 1024.0;
    print_bar("VRAM    ", s.vram.used_pct, "(" + std::to_string(used_gb) + "GB/" + std::to_string(total_gb) + "GB)");
  } else {
    std::cout << "VRAM    GPU monitoring disabled or unavailable\n";
  }
  // Top processes
  if (!s.procs.processes.empty()) {
    std::cout << "\nTop processes (CPU%)\n";
    size_t lim = std::min<size_t>(s.procs.processes.size(), 10);
    for (size_t i=0;i<lim;i++) {
      const auto& p = s.procs.processes[i];
      std::string name = p.cmd.empty() ? std::to_string(p.pid) : p.cmd.substr(0,40);
      std::cout << "  " << std::setw(4) << p.pid << "  " << std::setw(5) << std::fixed << std::setprecision(1) << p.cpu_pct << "%  " << name << "\n";
    }
  }
  // Alerts
  if (!s.alerts.empty()) {
    std::cout << "\nALERTS" << "\n";
    for (auto& a : s.alerts) {
      std::cout << "  [" << a.severity << "] " << a.message << "\n";
    }
  }
}

int main(int argc, char** argv) {
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
  RawTermGuard raw{}; CursorGuard curs{}; AltScreenGuard alt{use_alt};
  std::atexit(&on_atexit_restore);
  // Initialize CPU scale from env (default: total/machine share)
  g_ui.cpu_scale = getenv_cpu_scale("MONTAUK_PROC_CPU_SCALE", UIState::CPUScale::Total);
  if (iterations <= 0) iterations = INT32_MAX; // effectively run until Ctrl+C
  bool show_help = false;
  auto help_text = std::string("Keys: q quit  c/m/p/n sort  g GPU sort  v GMEM sort  G toggle GPU  +/- fps  arrows/PgUp/PgDn scroll  t Thermal  d Disk  N Net  i CPU scale  u GPU scale  h help");
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
                // arrows: A up, B down
                if (b=='A') { if (g_ui.scroll > 0) g_ui.scroll--; }
                else if (b=='B') { g_ui.scroll++; }
              } else if (b=='5' || b=='6') { // PgUp/PgDn expect '~'
                if (k < (size_t)n) d = buf[k++];
                if (d=='~') {
                  int page = std::max(1, g_ui.last_proc_page_rows - 2);
                  if (b=='5') { g_ui.scroll = std::max(0, g_ui.scroll - page); }
                  else { g_ui.scroll += page; }
                }
              }
            }
          }
        }
      }
    }
    // Concurrency hardening: optionally copy the front snapshot at frame start
    const montauk::model::Snapshot* s_ptr = &buffers.front();
    montauk::model::Snapshot s_copy;
    if (env_flag("MONTAUK_COPY_FRONT", true)) { s_copy = *s_ptr; s_ptr = &s_copy; }
    const auto& s = *s_ptr;
    // Dynamic help with current sort/fps and optional alert banner
    std::string sort_name = (g_ui.sort==SortMode::CPU?"cpu": g_ui.sort==SortMode::MEM?"mem": g_ui.sort==SortMode::PID?"pid":"name");
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
    std::string dyn_help = alert + "[sort:" + sort_name + "] [fps:" + std::to_string(fps) + "]  " + help_text;
    render_screen(s, show_help, dyn_help);
  }
  producer.stop();
  return 0;

  return 0;
}
