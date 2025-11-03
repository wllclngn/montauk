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
#include <iomanip>
using namespace montauk::ui;
#include <sstream>
#include <climits>

namespace montauk::ui {

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

std::string colorize_line(const std::string& s) {
  if (!tty_stdout()) return s;
  const auto& ui = ui_config();
  auto uni = use_unicode();
  const char* V = uni ? "│" : "|";
  
  auto is_border = [&](const std::string& str){
    if (str.empty()) return false;
    if (str.find(uni ? "│" : "|") != std::string::npos) return false;
    if (uni) {
      if (str.rfind("╭",0)==0 || str.rfind("╮",0)==0 || str.rfind("╰",0)==0 || str.rfind("╯",0)==0 || str.rfind("─",0)==0)
        return true;
      return false;
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
      
      size_t lb = part.find('[');
      size_t rb = (lb!=std::string::npos) ? part.find(']', lb+1) : std::string::npos;
      if (lb==std::string::npos || rb==std::string::npos || rb<=lb) return part;
      
      double pct = -1.0; {
        size_t p = part.rfind('%');
        if (p != std::string::npos) {
          size_t st = p; 
          while (st>0 && (std::isdigit((unsigned char)part[st-1]) || part[st-1]=='.')) --st;
          try { pct = std::stod(part.substr(st, p-st)); } catch (...) { pct = -1.0; }
        }
      }
      
      std::string pre2 = part.substr(0, lb+1);
      std::string bar = part.substr(lb+1, rb - (lb+1));
      std::string suf2 = part.substr(rb);
      
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
      return pre2 + bar_color + bar + sgr_reset() + suf2;
    };
    
    std::string mid2 = color_bar(mid);
    return pre + sgr_fg_grey() + leftb + sgr_reset() + mid2 + sgr_fg_grey() + rightb + sgr_reset() + suf;
  }
  
  if (s.find("SYSTEM MONITOR") != std::string::npos) {
    return sgr_bold() + s + sgr_reset();
  }
  return s;
}

// Forward declarations for functions still in main.cpp temporarily
extern int term_cols();

void render_screen(const montauk::model::Snapshot& s, bool show_help_line, const std::string& help_text) {
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
    frame += colorize_line(hline) + std::string("\n");
  }
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
  frame += "\x1B[" + std::to_string(rows) + ";" + std::to_string(cols) + "H";
  best_effort_write(STDOUT_FILENO, frame.data(), frame.size());
}

} // namespace montauk::ui
