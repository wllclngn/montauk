#pragma once

#include "ui/widget/Chart.hpp"
#include "ui/widget/Component.hpp"
#include "util/History.hpp"
#include <cstdint>
#include <string>

namespace montauk::ui::widgets {

// Pixel-rendered area chart panel. Draws the box border + title as cell-grid
// text (same as widget::Panel), then paints the chart image via the graphics
// protocol onto the panel's inner content rect.
//
// The widget is persistent across frames — it owns its Chart buffer and Kitty
// image ID. Callers should declare ChartPanel instances as static locals (or
// otherwise keep them alive) so the scroll buffer and image ID survive.
//
// When the terminal doesn't support Kitty or Sixel, the inner rect is filled
// with a "(graphics unavailable)" notice styled in the muted color.
class ChartPanel : public widget::Component {
 public:
  struct DualCurveSources {
    montauk::util::History<float>* primary = nullptr;    // e.g. RX
    montauk::util::History<float>* secondary = nullptr;  // e.g. TX (nullptr for single-curve)
  };

  // Single-curve constructor. `history` must outlive the panel.
  ChartPanel(std::string title,
             std::string panel_name,
             montauk::util::History<float>* history);

  // Dual-curve constructor (NETWORK RX+TX).
  ChartPanel(std::string title,
             std::string panel_name,
             DualCurveSources sources);

  void render(widget::Canvas& canvas,
              const widget::LayoutRect& rect,
              const montauk::model::Snapshot& snap) override;

  // Whether this chart currently owns a live Kitty placement (i.e. was
  // rendered at least once since the last hide() or resize).
  bool is_placed() const { return has_emitted_once_; }

  // Emit a delete escape for this chart's placement onto `canvas` and mark
  // the chart as unplaced. Call when the chart transitions from visible to
  // hidden (e.g. SYSTEM-focus activated, GPU toggle off). On non-Kitty
  // protocols the escape is empty and this is a no-op beyond state reset.
  void hide(widget::Canvas& canvas);

 private:
  std::string title_;
  std::string panel_name_;
  DualCurveSources sources_{};
  widget::Chart chart_;
  uint32_t chart_id_ = 0;
  int last_px_w_ = 0;
  int last_px_h_ = 0;
  bool has_emitted_once_ = false;
  int frame_counter_ = 0;  // used to throttle chart emission to ~1 Hz

  // Resolve a widget::Style from the panel's color config. Uses [chart.<name>]
  // overrides if present, falling back to [chart] globals, then to sensible
  // per-panel defaults.
  widget::Chart::Style resolve_style() const;
};

} // namespace montauk::ui::widgets
