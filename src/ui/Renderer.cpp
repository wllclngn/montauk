#include "ui/Renderer.hpp"
#include "ui/Config.hpp"
#include "ui/Terminal.hpp"
#include "ui/Formatting.hpp"
#include "ui/Panels.hpp"
#include "ui/ProcessTable.hpp"
#include "app/Security.hpp"
#include "util/Retro.hpp"
#include "util/Churn.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <format>
#include <iomanip>
#include <unordered_map>
using namespace montauk::ui;
#include <sstream>
#include <climits>

namespace montauk::ui {

namespace {
  struct ColorCache {
    uint64_t snapshot_seq = 0;
    std::unordered_map<std::string, std::string> cache;
    
    void invalidate(uint64_t new_seq) {
      if (new_seq != snapshot_seq) {
        cache.clear();
        snapshot_seq = new_seq;
      }
    }
  };
}

// Forward declare helper needed by make_box
static std::string repeat_str(const std::string& ch, int n){ 
  std::string r; 
  r.reserve(std::max(0,n* (int)ch.size())); 
  for (int i=0;i<n;i++) r += ch; 
  return r; 
}

std::vector<std::string> make_box(const std::string& title, const std::vector<std::string>& lines, int width, int min_height) {
  int iw = std::max(3, width - 2);
  std::vector<std::string> out;
  const std::string TL = "┌";
  const std::string TR = "┐";
  const std::string BL = "└";
  const std::string BR = "┘";
  const std::string H  = "─";
  const std::string V  = "│";
  auto top = [&]{
    std::string t = " " + title + " ";
    int fill = std::max(0, iw - (int)t.size());
    int left = fill / 2; int right = fill - left;
    return TL + repeat_str(H, left) + t + repeat_str(H, right) + TR;
  }();
  out.push_back(top);
  int content_lines = std::max((int)lines.size(), min_height);
  for (int i = 0; i < content_lines; ++i) {
    std::string ln = (i < (int)lines.size()) ? lines[i] : std::string();
    out.push_back(V + trunc_pad(ln, iw) + V);
  }
  out.push_back(BL + repeat_str(H, iw) + BR);
  return out;
}

static std::string colorize_line_impl(const std::string& s) {
  if (!tty_stdout()) return s;
  const auto& ui = ui_config();
  const char* V = "│";

  auto is_border = [&](const std::string& str){
    if (str.empty()) return false;
    if (str.find("│") != std::string::npos) return false;
    if (str.rfind("┌",0)==0 || str.rfind("┐",0)==0 || str.rfind("└",0)==0 || str.rfind("┘",0)==0 || str.rfind("─",0)==0)
      return true;
    return false;
  };
  
  if (is_border(s)) {
    // Find title by locating text between ─ characters (format: ┌───── TITLE ─────┐)
    size_t first_space = s.find(' ');
    size_t last_space = s.rfind(' ');
    if (first_space != std::string::npos && last_space != std::string::npos && last_space > first_space) {
      std::string pre = s.substr(0, first_space);
      std::string mid = s.substr(first_space, last_space - first_space + 1);
      std::string suf = s.substr(last_space + 1);
      return sgr_fg_grey() + pre + ui.accent + mid + sgr_fg_grey() + suf + sgr_reset();
    }
    return sgr_fg_grey() + s + sgr_reset();
  }
  
  size_t lpos = s.rfind(V);
  size_t fpos = s.find(V);
  if (fpos != std::string::npos && lpos != std::string::npos && lpos > fpos) {
    std::string pre = s.substr(0, fpos);
    std::string leftb = s.substr(fpos, std::strlen(V));
    std::string mid = s.substr(fpos + std::strlen(V), lpos - (fpos + std::strlen(V)));
    std::string rightb = s.substr(lpos, std::strlen(V));
    std::string suf = s.substr(lpos + std::strlen(V));
    
    auto color_bar = [&](const std::string& part)->std::string{
      // If the part already contains ANSI escape codes, don't recolor it
      if (part.find('\x1B') != std::string::npos) return part;

      const std::string bullet = "•";
      const std::string full = "█";
      const std::string empty = "░";

      // Find bar by locating block characters (█ or ░)
      size_t bar_start = part.find(full);
      if (bar_start == std::string::npos) bar_start = part.find(empty);

      // No bar - but if there's a bullet, color content after it with accent
      if (bar_start == std::string::npos) {
        size_t bullet_pos = part.find(bullet);
        if (bullet_pos != std::string::npos) {
          std::string before = part.substr(0, bullet_pos);
          std::string after = part.substr(bullet_pos + bullet.size());
          return before + sgr_fg_grey() + bullet + sgr_reset() + sgr_fg_grn() + after + sgr_reset();
        }
        return part;
      }

      // Find end of bar (last block character)
      size_t bar_end = bar_start;
      size_t pos = bar_start;
      while (pos < part.size()) {
        size_t f = part.find(full, pos);
        size_t e = part.find(empty, pos);
        size_t next = std::string::npos;
        if (f != std::string::npos && e != std::string::npos) next = std::min(f, e);
        else if (f != std::string::npos) next = f;
        else if (e != std::string::npos) next = e;
        if (next == std::string::npos || next > bar_end + 4) break; // gap means end of bar
        bar_end = next + ((part.compare(next, full.size(), full) == 0) ? full.size() : empty.size());
        pos = bar_end;
      }
      if (bar_end <= bar_start) return part;

      double pct = -1.0; {
        size_t p = part.rfind('%');
        if (p != std::string::npos) {
          size_t st = p;
          while (st>0 && (std::isdigit((unsigned char)part[st-1]) || part[st-1]=='.')) --st;
          try { pct = std::stod(part.substr(st, p-st)); } catch (...) { pct = -1.0; }
        }
      }

      std::string pre2 = part.substr(0, bar_start);
      std::string bar = part.substr(bar_start, bar_end - bar_start);
      std::string suf2 = part.substr(bar_end);
      
      if (pct < 0.0) {
        int total = display_cols(bar);
        int filled = 0;
        size_t pos = 0;
        const std::string full = "█";
        while (true) {
          size_t f = bar.find(full, pos);
          if (f == std::string::npos) break;
          filled += 1; pos = f + full.size();
        }
        if (total > 0) pct = 100.0 * (double)filled / (double)total;
      }
      
      const std::string bar_color = (pct < 0.0) ? sgr_fg_cyan() :
        (pct <= 60.0 ? sgr_fg_grn() :
        (pct <= 80.0 ? sgr_fg_yel() : sgr_fg_red()));

      // Also color content after bullet separator with same severity color
      size_t bullet_pos = suf2.find(bullet);
      if (bullet_pos != std::string::npos) {
        std::string before_bullet = suf2.substr(0, bullet_pos);
        std::string after_bullet = suf2.substr(bullet_pos + bullet.size());
        return pre2 + bar_color + bar + sgr_reset() + before_bullet +
               sgr_fg_grey() + bullet + sgr_reset() + bar_color + after_bullet + sgr_reset();
      }
      return pre2 + bar_color + bar + sgr_reset() + suf2;
    };
    
    std::string mid2 = color_bar(mid);
    std::string result = pre + sgr_fg_grey() + leftb + sgr_reset() + mid2 + sgr_fg_grey() + rightb + sgr_reset() + suf;

    // Colorize bullet separators
    const std::string bullet = "•";
    const std::string grey_bullet = sgr_fg_grey() + bullet + sgr_reset();
    size_t pos = 0;
    while ((pos = result.find(bullet, pos)) != std::string::npos) {
      // Skip if already inside an escape sequence
      if (pos > 0 && result[pos-1] == '[') { pos += bullet.size(); continue; }
      result.replace(pos, bullet.size(), grey_bullet);
      pos += grey_bullet.size();
    }
    return result;
  }

  if (s.find("SYSTEM MONITOR") != std::string::npos) {
    return sgr_bold() + s + sgr_reset();
  }

  // Colorize bullet separators in non-box lines (like status bar)
  if (s.find("•") != std::string::npos) {
    std::string result = s;
    const std::string bullet = "•";
    const std::string grey_bullet = sgr_fg_grey() + bullet + sgr_reset();
    size_t pos = 0;
    while ((pos = result.find(bullet, pos)) != std::string::npos) {
      result.replace(pos, bullet.size(), grey_bullet);
      pos += grey_bullet.size();
    }
    return result;
  }

  return s;
}

std::string colorize_line(const std::string& s, uint64_t snapshot_seq) {
  if (!tty_stdout()) return s;
  
  static ColorCache g_cache;
  g_cache.invalidate(snapshot_seq);
  
  auto it = g_cache.cache.find(s);
  if (it != g_cache.cache.end()) {
    return it->second;
  }
  
  std::string result = colorize_line_impl(s);
  g_cache.cache.emplace(s, result);
  
  return result;
}

// Forward declarations for functions still in main.cpp temporarily
extern int term_cols();

void render_screen(const montauk::model::Snapshot& s, bool show_help_line, const std::string& help_text) {
  uint64_t seq = s.seq;
  
  int cols = term_cols();
  int gutter = 1;
  int left_w = (cols * 2) / 3; if (left_w < 40) left_w = cols - 20; if (left_w > cols-20) left_w = cols-20;
  if ((cols - (left_w + 1) - gutter) >= 20) left_w += 1;
  int right_w = cols - left_w - gutter; if (right_w < 20) right_w = 20;
  int rows = term_rows();
  int content_rows = std::max(5, rows - (show_help_line?1:0));
  auto left = render_process_table(s, left_w, content_rows);
  auto right = render_right_column(s, right_w, content_rows);
  std::string frame; frame.reserve((size_t)rows * (size_t)cols + 64);
  frame += "\x1B[H";
  if (show_help_line) {
    std::string hline = trunc_pad(help_text, cols);
    frame += colorize_line(hline, seq) + std::string("\n");
  }
  int header_lines = (show_help_line?1:0);
  int body_lines = std::max(0, rows - header_lines);
  for (int row = 0; row < body_lines; ++row) {
    std::string l = (row < (int)left.size()) ? left[row] : std::string(left_w, ' ');
    std::string r = (row < (int)right.size()) ? right[row] : std::string(right_w, ' ');
    if ((int)l.size() < left_w) l += std::string(left_w - (int)l.size(), ' ');
    if ((int)r.size() < right_w) r += std::string(right_w - (int)r.size(), ' ');
    auto line = colorize_line(l, seq) + std::string(gutter, ' ') + colorize_line(r, seq);
    if (row < body_lines - 1) line += "\n";
    frame += line;
  }
  frame += std::format("\x1B[{};{}H", rows, cols);
  best_effort_write(STDOUT_FILENO, frame.data(), frame.size());
}

} // namespace montauk::ui
