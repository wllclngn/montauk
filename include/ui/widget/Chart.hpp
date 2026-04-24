#pragma once

#include "ui/widget/Color.hpp"
#include <cstdint>
#include <span>
#include <vector>

namespace montauk::ui::widget {

// Chart rasterizer. Renders a scrolling area chart as RGBA pixels.
//
// Interpolation: monotone cubic Hermite — smooth wave-like curves that never
// overshoot between monotone samples (critical for bounded-percentage data
// like CPU%, memory%, etc.).
//
// Scroll optimization: the RGBA buffer is persistent across frames. On each
// update, the buffer is memmoved left by `cols_per_sample` pixels and only
// the trailing 2 segments (the newly-dependent region) are re-rasterized.
// This makes per-frame rasterization cost independent of buffer width.
//
// Input samples are expected in the range [0.0, 1.0]. Callers normalize
// percentages (pct / 100.0) or other metrics (value / max) before pushing.
class Chart {
 public:
  struct Style {
    Color line        = Color::Default;
    Color line_alt    = Color::Default;  // used only by dual-curve mode
    Color fill        = Color::Default;
    double fill_alpha = 0.4;  // 0.0 .. 1.0
  };

  Chart(int width_px, int height_px);

  // Resize the buffer. Clears contents; next update() re-rasterizes full.
  void resize(int width_px, int height_px);

  // Rasterize a single-curve area chart from `samples` (oldest → newest,
  // already in [0, 1]). Samples should typically be drawn from the most
  // recent N samples of a History<float> where N is chosen so the chart
  // shows the user's preferred time window.
  void update(std::span<const float> samples, const Style& style);

  // Dual-curve mode: `primary` rendered with fill, `secondary` as line-only
  // overlay. Shared y-axis: values normalized by caller to same scale (we
  // don't auto-scale here — NETWORK panel does that before calling).
  void update_dual(std::span<const float> primary,
                   std::span<const float> secondary,
                   const Style& style);

  // Access the persistent RGBA buffer (width_px * height_px * 4 bytes).
  [[nodiscard]] const uint8_t* pixels() const { return buffer_.data(); }
  [[nodiscard]] int width_px() const { return w_; }
  [[nodiscard]] int height_px() const { return h_; }

  // Extract the rightmost 1-pixel column as a flat RGBA vector
  // (height_px * 4 bytes). Used for Kitty's incremental-column emit.
  [[nodiscard]] std::vector<uint8_t> rightmost_column() const;

  // Whether a full emit is required next frame (first render after construct
  // or resize). After the first emit, clear_dirty_full() can be called.
  [[nodiscard]] bool dirty_full() const { return dirty_full_; }
  void clear_dirty_full() { dirty_full_ = false; }

 private:
  int w_ = 0;
  int h_ = 0;
  std::vector<uint8_t> buffer_;  // RGBA, tightly packed, row-major
  bool dirty_full_ = true;

  void clear();
  // Rasterize a single-curve fill over [x_start_px, x_end_px) in the buffer,
  // computing curve values from `samples` at normalized positions.
  void rasterize_single(std::span<const float> samples,
                        int x_start_px, int x_end_px,
                        const Style& style);
};

} // namespace montauk::ui::widget
