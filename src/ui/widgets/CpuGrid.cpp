#include "ui/widgets/CpuGrid.hpp"
#include "ui/Config.hpp"
#include "ui/widget/GraphicsProtocol.hpp"
#include "app/ChartHistories.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <string>

namespace montauk::ui::widgets {

namespace {

// Unique Kitty image ID per cell, allocated once at lazy-init. Picks IDs
// well above ChartPanel's 100-base so the two widgets never collide on
// terminal placements.
std::atomic<uint32_t> g_next_cpu_cell_id{2000};
uint32_t next_cell_id() { return g_next_cpu_cell_id.fetch_add(1, std::memory_order_relaxed); }

// Minimum cell footprint, in terminal cells. Cells go no smaller than
// this on either axis — below it the chart loses readability and the
// box title gets clipped.
constexpr int kMinCellW = 14;  // border + " CPU99 100% " label + border
constexpr int kMinCellH = 5;   // border + 3 inner chart rows + border

// Target visual aspect for a single cell (cell_w / cell_h). Terminal
// cells are roughly twice as tall as wide in pixels, so a 2.5:1 char-
// space cell renders at ~1.25:1 visually — comfortable for area-chart
// reading without going chunky on either side.
constexpr float kTargetAspect = 2.5f;

// Pick (cols, cell_w, cell_h, rows_total) that fills the rect best.
// Preference: minimize deviation from kTargetAspect on the resulting
// cell shape, while keeping cell_w >= kMinCellW. If the full grid
// doesn't fit vertically, switch to scroll mode (cell_h = kMinCellH).
struct GridGeom {
  int cols;
  int rows_total;
  int cell_w;
  int cell_h;
  int visible_rows;
  bool scroll_mode;
};

GridGeom pick_geom(int ncpu, int avail_w, int avail_h) {
  GridGeom best{1, ncpu, avail_w, std::max(kMinCellH, avail_h / std::max(1, ncpu)),
                std::max(1, avail_h / std::max(kMinCellH, 1)), false};
  float best_score = 1e9f;
  for (int c = 1; c <= ncpu; ++c) {
    int rows = (ncpu + c - 1) / c;
    int cell_w = avail_w / c;
    if (cell_w < kMinCellW) break;  // narrower won't help
    bool scroll = rows * kMinCellH > avail_h;
    int cell_h = scroll ? kMinCellH : avail_h / rows;
    if (cell_h < kMinCellH) cell_h = kMinCellH;
    float aspect = static_cast<float>(cell_w) / static_cast<float>(cell_h);
    float score  = std::abs(aspect - kTargetAspect);
    if (score < best_score) {
      best_score = score;
      best.cols         = c;
      best.rows_total   = rows;
      best.cell_w       = cell_w;
      best.cell_h       = cell_h;
      best.scroll_mode  = scroll;
      best.visible_rows = std::max(1, avail_h / cell_h);
    }
  }
  return best;
}

widget::Chart::Style resolve_cpu_style() {
  // Reuse the resolved color of the PROCESSOR chart panel. Reading
  // ui_config().accent gives an SGR string; parse_sgr_style returns a
  // Style whose .fg is the truecolor we want for line + fill.
  widget::Style s = widget::parse_sgr_style(ui_config().accent);
  return widget::Chart::Style{s.fg, s.fg, s.fg, 0.40};
}

} // namespace

void CpuGrid::hide(widget::Canvas& canvas) {
  auto& gfx = widget::GraphicsEmitter::instance();
  for (auto& c : cells_) {
    if (!c.placed) continue;
    std::string del = gfx.emit_delete(c.image_id);
    if (!del.empty()) canvas.push_graphics_command(std::move(del));
    c.placed = false;
    c.last_px_w = 0;
    c.last_px_h = 0;
  }
}

void CpuGrid::handle_input(const widget::InputEvent& ev) {
  // Esc or Shift+C closes the view.
  if (ev.is(widget::Key::Escape)) { wants_close_ = true; return; }
  if (ev.is_char('C'))            { wants_close_ = true; return; }

  if (ev.is(widget::Key::ArrowUp))   { if (scroll_rows_ > 0) --scroll_rows_; return; }
  if (ev.is(widget::Key::ArrowDown)) { ++scroll_rows_; return; }
  if (ev.is(widget::Key::PageUp))    { scroll_rows_ = std::max(0, scroll_rows_ - 4); return; }
  if (ev.is(widget::Key::PageDown))  { scroll_rows_ += 4; return; }
}

void CpuGrid::render(widget::Canvas& canvas,
                     const widget::LayoutRect& rect,
                     const montauk::model::Snapshot& snap) {
  const auto& uic = ui_config();
  const widget::Style border_style = widget::parse_sgr_style(uic.border);
  const widget::Style title_style  = widget::parse_sgr_style(uic.accent);

  // Outer panel border + title.
  widget::LayoutRect inner = draw_box_border(canvas, rect, "CPU TOPOLOGY",
                                              border_style, title_style);
  if (inner.width <= 0 || inner.height <= 0) return;

  // Lazy-size cells_ to match the snapshot's per-core count. Allocate
  // image IDs once; resize only grows.
  const int ncpu = static_cast<int>(snap.cpu.per_core_pct.size());
  if (ncpu <= 0) return;
  if (static_cast<int>(cells_.size()) < ncpu) {
    cells_.resize(static_cast<size_t>(ncpu));
    for (auto& c : cells_) {
      if (c.image_id == 0) c.image_id = next_cell_id();
    }
  }

  // Grid math: optimize (cols × rows × cell_w × cell_h) to fill the
  // available rect while keeping each cell visually balanced. For low
  // core counts the grid stretches to fill both axes; for very high
  // counts it falls into scroll mode at the minimum cell height.
  const GridGeom g = pick_geom(ncpu, inner.width, inner.height);
  const int cols         = g.cols;
  const int cell_w       = g.cell_w;
  const int cell_h       = g.cell_h;
  const int total_rows   = g.rows_total;
  const int visible_rows = g.visible_rows;
  const int max_scroll   = std::max(0, total_rows - visible_rows);
  if (scroll_rows_ > max_scroll) scroll_rows_ = max_scroll;
  if (scroll_rows_ < 0)          scroll_rows_ = 0;

  // Locate which cells will be drawn this frame so we can hide stale
  // images for cells that scrolled out of view.
  const int first_row = scroll_rows_;
  const int last_row  = std::min(total_rows, scroll_rows_ + visible_rows);
  const int first_idx = first_row * cols;
  const int last_idx  = last_row  * cols;

  auto& gfx = widget::GraphicsEmitter::instance();

  // Drop placements for cells that aren't visible this frame.
  for (int i = 0; i < ncpu; ++i) {
    if ((i >= first_idx && i < last_idx) || !cells_[i].placed) continue;
    std::string del = gfx.emit_delete(cells_[i].image_id);
    if (!del.empty()) canvas.push_graphics_command(std::move(del));
    cells_[i].placed     = false;
    cells_[i].last_px_w  = 0;
    cells_[i].last_px_h  = 0;
  }

  // No graphics support — render a notice and bail.
  if (gfx.protocol() == widget::Protocol::None) {
    const widget::Style muted = widget::parse_sgr_style(uic.muted);
    const char* note = "(terminal lacks Kitty/Sixel — see montauk.1)";
    int nlen = static_cast<int>(std::string_view(note).size());
    int x = inner.x + std::max(0, (inner.width - nlen) / 2);
    int y = inner.y + inner.height / 2;
    canvas.draw_text(x, y, note, muted);
    return;
  }

  const auto cell_px = gfx.cell_size();
  const widget::Chart::Style style = resolve_cpu_style();
  const widget::Style muted_style  = widget::parse_sgr_style(uic.muted);

  // Snapshot per-core histories under the histories mutex once per frame
  // so the rasterize loop doesn't hold the lock per-cell.
  auto& hist = montauk::app::chart_histories();
  std::vector<std::vector<float>> samples;
  samples.reserve(static_cast<size_t>(ncpu));
  {
    std::lock_guard<std::mutex> lock(hist.mu);
    const int n = static_cast<int>(hist.cpu_per_core.size());
    for (int i = 0; i < ncpu; ++i) {
      if (i < n) {
        auto& h = hist.cpu_per_core[i];
        samples.push_back(h.recent(h.capacity()));
      } else {
        samples.emplace_back();  // empty: this core hasn't pushed yet
      }
    }
  }

  // Forward-pass EMA smoother — same alpha as ChartPanel uses on the
  // PROCESSOR chart so per-core mini-charts read with the same character.
  auto ema_smooth = [](std::vector<float>& v, float a) {
    if (v.size() < 2) return;
    for (size_t k = 1; k < v.size(); ++k) v[k] = a * v[k] + (1.0f - a) * v[k - 1];
  };

  // Render each visible cell.
  for (int row = first_row; row < last_row; ++row) {
    for (int c = 0; c < cols; ++c) {
      int idx = row * cols + c;
      if (idx >= ncpu) break;

      const int cx = inner.x + c * cell_w;
      const int cy = inner.y + (row - first_row) * cell_h;
      const int cw = (c == cols - 1) ? (inner.x + inner.width - cx) : cell_w;
      // Last visible row spans whatever's left so the grid fills exactly.
      const bool is_last_visible_row = (row == last_row - 1);
      const int ch = is_last_visible_row
                         ? std::max(0, inner.y + inner.height - cy)
                         : cell_h;
      if (cw < 4 || ch < 3) continue;

      const widget::LayoutRect cell_rect{cx, cy, cw, ch};

      // Per-cell bordered box. Title centered on top border:
      // " CPU<n> NN% ", in accent.
      const double live_pct = snap.cpu.per_core_pct[static_cast<size_t>(idx)];
      char hdr[32];
      std::snprintf(hdr, sizeof(hdr), " CPU%d %d%% ", idx,
                    static_cast<int>(live_pct + 0.5));
      widget::LayoutRect cell_inner =
          draw_box_border(canvas, cell_rect, hdr, border_style, title_style);
      if (cell_inner.width <= 0 || cell_inner.height <= 0) continue;

      // Pixel dims for this cell's chart; resize buffer + force re-emit
      // on geometry change.
      const int px_w = cell_inner.width  * cell_px.w;
      const int px_h = cell_inner.height * cell_px.h;
      if (px_w <= 0 || px_h <= 0) continue;

      Cell& cell = cells_[idx];
      if (px_w != cell.last_px_w || px_h != cell.last_px_h) {
        cell.chart.resize(px_w, px_h);
        cell.last_px_w = px_w;
        cell.last_px_h = px_h;
        cell.placed    = false;
      }

      // Rasterize. For empty histories (no samples yet) skip — the cell
      // shows just its border + label, fills in once samples arrive.
      auto& s = samples[static_cast<size_t>(idx)];
      if (s.empty()) {
        // Draw a muted placeholder dash so the box reads as "live but
        // waiting" instead of broken.
        const char* dash = "—";
        int x = cell_inner.x + cell_inner.width / 2;
        int y = cell_inner.y + cell_inner.height / 2;
        canvas.draw_text(x, y, dash, muted_style);
        continue;
      }
      ema_smooth(s, 0.4f);
      cell.chart.update(s, style);

      // Throttled emit (1 Hz at 4 Hz producer) — same cadence ChartPanel
      // uses. First frame and resizes always emit.
      const bool must_emit     = !cell.placed || cell.chart.dirty_full();
      const bool throttle_emit = (cell.frame_tick % 4) == 0;
      cell.frame_tick++;
      if (!must_emit && !throttle_emit) continue;

      std::string esc = gfx.emit_full(cell.image_id,
                                       cell_inner.x, cell_inner.y,
                                       cell_inner.width, cell_inner.height,
                                       cell.chart.pixels(), px_w, px_h);
      cell.chart.clear_dirty_full();
      cell.placed = true;
      canvas.paint_image(cell_inner, std::move(esc));
    }
  }
}

} // namespace montauk::ui::widgets
