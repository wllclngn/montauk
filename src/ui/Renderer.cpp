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
#include <sstream>
using namespace montauk::ui;

namespace montauk::ui {

static std::string repeat_str(const std::string& ch, int n){
  std::string r;
  r.reserve(std::max(0,n* (int)ch.size()));
  for (int i=0;i<n;i++) r += ch;
  return r;
}

std::vector<std::string> make_box(const std::string& title, const std::vector<std::string>& lines, int width, int min_height) {
  int iw = std::max(3, width - 2);
  std::vector<std::string> out;
  const std::string TL = "┌", TR = "┐", BL = "└", BR = "┘", H = "─", V = "│";
  bool color = tty_stdout();
  // Top border with title
  {
    std::string t = " " + title + " ";
    int fill = std::max(0, iw - (int)t.size());
    int left = fill / 2; int right = fill - left;
    if (color) {
      const auto& ui = ui_config();
      out.push_back(ui.border + TL + repeat_str(H, left)
                   + ui.accent + t
                   + ui.border + repeat_str(H, right) + TR + sgr_reset());
    } else {
      out.push_back(TL + repeat_str(H, left) + t + repeat_str(H, right) + TR);
    }
  }
  // Content lines (plain side borders -- colored by caller's severity pass)
  int content_lines = std::max((int)lines.size(), min_height);
  for (int i = 0; i < content_lines; ++i) {
    std::string ln = (i < (int)lines.size()) ? lines[i] : std::string();
    out.push_back(V + trunc_pad(ln, iw) + V);
  }
  // Bottom border
  if (color)
    out.push_back(ui_config().border + BL + repeat_str(H, iw) + BR + sgr_reset());
  else
    out.push_back(BL + repeat_str(H, iw) + BR);
  return out;
}

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
    frame += trunc_pad(help_text, cols) + "\n";
  }
  int header_lines = (show_help_line?1:0);
  int body_lines = std::max(0, rows - header_lines);
  for (int row = 0; row < body_lines; ++row) {
    std::string l = (row < (int)left.size()) ? left[row] : std::string(left_w, ' ');
    std::string r = (row < (int)right.size()) ? right[row] : std::string(right_w, ' ');
    if ((int)l.size() < left_w) l += std::string(left_w - (int)l.size(), ' ');
    if ((int)r.size() < right_w) r += std::string(right_w - (int)r.size(), ' ');
    auto line = l + std::string(gutter, ' ') + r;
    if (row < body_lines - 1) line += "\n";
    frame += line;
  }
  frame += std::format("\x1B[{};{}H", rows, cols);
  best_effort_write(STDOUT_FILENO, frame.data(), frame.size());
}

} // namespace montauk::ui
