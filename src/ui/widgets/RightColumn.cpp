#include "ui/widgets/RightColumn.hpp"

#include <algorithm>
#include <array>

namespace montauk::ui::widgets {

RightColumn::RightColumn() = default;

void RightColumn::reset() {
  show_gpumon_  = true;
  show_thermal_ = true;
  system_focus_ = false;
  system_panel_.set_show_thermal(true);
}

void RightColumn::render(widget::Canvas& canvas,
                         const widget::LayoutRect& rect,
                         const montauk::model::Snapshot& s) {
  // SYSTEM-focus mode: hide any live chart placements, then render the
  // dense info panel filling the column.
  if (system_focus_) {
    ChartPanel* charts[] = {&cpu_chart_, &gpu_util_chart_, &vram_chart_,
                            &gpu_mem_chart_, &enc_chart_, &dec_chart_,
                            &mem_chart_, &net_chart_};
    for (auto* c : charts) if (c->is_placed()) c->hide(canvas);
    system_panel_.render(canvas, rect, s);
    return;
  }

  // Chart-stack mode: drive each chart's visibility from the toggle state +
  // hardware availability, then divide the vertical space evenly across
  // visible panels.
  struct Slot { ChartPanel* panel; bool visible; };
  const std::array<Slot, 8> slots = {{
      {&cpu_chart_,      true},
      {&gpu_util_chart_, show_gpumon_ && s.vram.has_util},
      {&vram_chart_,     show_gpumon_ && s.vram.total_mb > 0},
      {&gpu_mem_chart_,  show_gpumon_ && s.vram.has_mem_util},
      {&enc_chart_,      show_gpumon_ && s.vram.has_encdec},
      {&dec_chart_,      show_gpumon_ && s.vram.has_encdec},
      {&mem_chart_,      true},
      {&net_chart_,      true},
  }};

  // Hide stale Kitty placements before drawing this frame.
  for (const auto& sl : slots) {
    if (!sl.visible && sl.panel->is_placed()) sl.panel->hide(canvas);
  }

  int n_visible = 0;
  for (const auto& sl : slots) if (sl.visible) ++n_visible;
  if (n_visible == 0) return;

  const int target_rows = rect.height;
  const int base = std::max(3, target_rows / n_visible);
  int remainder = target_rows - base * n_visible;
  if (remainder < 0) remainder = 0;

  int current_y = rect.y;
  for (const auto& sl : slots) {
    if (!sl.visible) continue;
    if (current_y >= rect.y + target_rows) break;
    int rows = base + (remainder > 0 ? 1 : 0);
    if (remainder > 0) --remainder;
    int avail = (rect.y + target_rows) - current_y;
    if (rows > avail) rows = avail;
    if (rows < 3) continue;
    widget::LayoutRect panel_rect{rect.x, current_y, rect.width, rows};
    sl.panel->render(canvas, panel_rect, s);
    current_y += rows;
  }
}

} // namespace montauk::ui::widgets
