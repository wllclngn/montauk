#pragma once

#include "ui/widget/Chart.hpp"
#include "ui/widget/Component.hpp"
#include <cstdint>
#include <vector>

namespace montauk::ui::widgets {

// Grid of bordered boxes — one per logical CPU. Each box renders a small
// pixel-rasterized area chart of that core's last-N-seconds utilization
// history (read from app::ChartHistories::cpu_per_core), with a header
// label centered on the top border showing "CPU<n> NN%".
//
// Toggled by the Renderer with Shift+C in normal mode; replaces the
// PROCESS MONITOR widget in the left rect. Scrollable for high-core
// systems via Up/Down/PageUp/PageDown. Esc or Shift+C closes.
//
// Pattern ported from OUROBOROS's AlbumBrowser dynamic grid: dynamic
// column count derived from the available rect, partial bottom row
// allowed (border clips overflow), per-cell pixel-rendered content via
// the existing Kitty/Sixel emit path.
class CpuGrid : public widget::Component {
 public:
  CpuGrid() = default;

  void render(widget::Canvas& canvas,
              const widget::LayoutRect& rect,
              const montauk::model::Snapshot& snap) override;

  void handle_input(const widget::InputEvent& event) override;

  // Renderer polls this each frame; when the user presses Esc or Shift+C
  // inside the grid, the flag flips to true and the renderer returns to
  // the PROCESS MONITOR view. Reading clears the flag.
  bool consume_close_request() {
    bool w = wants_close_;
    wants_close_ = false;
    return w;
  }

  // Wipe Kitty placements for every cell — call when the renderer flips
  // the view off so stale chart images don't bleed under the next view.
  void hide(widget::Canvas& canvas);

 private:
  // One per logical CPU. Persistent across frames so each cell owns its
  // own RGBA buffer + Kitty image ID.
  struct Cell {
    widget::Chart chart;
    uint32_t image_id   = 0;
    int      last_px_w  = 0;
    int      last_px_h  = 0;
    bool     placed     = false;
    int      frame_tick = 0;  // throttled emit (every 4th frame)
    Cell() : chart(1, 1) {}
  };

  // Lazily sized to the snapshot's per-core count. Grows on hotplug.
  std::vector<Cell> cells_;

  // Scroll offset measured in cell-rows. Up/Down move by 1 row,
  // PageUp/PageDown move by visible_rows-1.
  int scroll_rows_ = 0;

  bool wants_close_ = false;
};

} // namespace montauk::ui::widgets
