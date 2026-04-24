#include "ui/widget/Chart.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace montauk::ui::widget {

namespace {

// Resolve a Style (Color) to 8-bit RGB. For named palette colors we use a
// reasonable default approximation; truecolor values are exact.
struct Rgb {
  uint8_t r, g, b;
};

Rgb color_to_rgb(Color c) {
  if (is_truecolor(c)) {
    return {color_r(c), color_g(c), color_b(c)};
  }
  switch (c) {
    case Color::Black:         return {  0,   0,   0};
    case Color::Red:           return {205,  49,  49};
    case Color::Green:         return { 13, 188, 121};
    case Color::Yellow:        return {229, 229,  16};
    case Color::Blue:           return { 36, 114, 200};
    case Color::Magenta:       return {188,  63, 188};
    case Color::Cyan:          return { 17, 168, 205};
    case Color::White:         return {229, 229, 229};
    case Color::BrightBlack:   return {102, 102, 102};
    case Color::BrightRed:     return {241,  76,  76};
    case Color::BrightGreen:   return { 35, 209, 139};
    case Color::BrightYellow:  return {245, 245,  67};
    case Color::BrightBlue:    return { 59, 142, 234};
    case Color::BrightMagenta: return {214, 112, 214};
    case Color::BrightCyan:    return { 41, 184, 219};
    case Color::BrightWhite:   return {229, 229, 229};
    case Color::Default:
    default:                   return {180, 180, 210};  // soft lavender default
  }
}

// Compute the tangents for monotone cubic Hermite interpolation at each
// sample point. Follows the Fritsch-Carlson algorithm: standard three-point
// tangent, then scale to enforce monotonicity.
void monotone_tangents(std::span<const float> y, std::vector<double>& out) {
  const size_t n = y.size();
  out.assign(n, 0.0);
  if (n < 2) return;

  std::vector<double> d(n - 1, 0.0);
  for (size_t i = 0; i + 1 < n; ++i) {
    d[i] = double(y[i + 1]) - double(y[i]);  // Δx = 1 (uniform spacing)
  }

  // Raw three-point tangents
  out[0] = d[0];
  out[n - 1] = d[n - 2];
  for (size_t i = 1; i + 1 < n; ++i) {
    out[i] = (d[i - 1] + d[i]) / 2.0;
  }

  // Enforce monotonicity
  for (size_t i = 0; i + 1 < n; ++i) {
    if (d[i] == 0.0) {
      out[i] = 0.0;
      out[i + 1] = 0.0;
    } else {
      double a = out[i]     / d[i];
      double b = out[i + 1] / d[i];
      double s = a * a + b * b;
      if (s > 9.0) {
        double t = 3.0 / std::sqrt(s);
        out[i]     = t * a * d[i];
        out[i + 1] = t * b * d[i];
      }
    }
  }
}

// Hermite basis evaluation: parametric position t ∈ [0, 1] between two
// consecutive sample points with values (y0, m0) and (y1, m1).
inline double hermite(double y0, double m0, double y1, double m1, double t) {
  const double t2 = t * t;
  const double t3 = t2 * t;
  const double h00 = 2 * t3 - 3 * t2 + 1;
  const double h10 = t3 - 2 * t2 + t;
  const double h01 = -2 * t3 + 3 * t2;
  const double h11 = t3 - t2;
  return h00 * y0 + h10 * m0 + h01 * y1 + h11 * m1;
}

inline double clamp01(double v) {
  return v < 0.0 ? 0.0 : (v > 1.0 ? 1.0 : v);
}

// Set pixel at (x, y) to an RGBA value, blending onto the existing pixel.
// Assumes source alpha in [0, 1]; pre-multiplies.
inline void blend_pixel(uint8_t* buf, int w, int x, int y, Rgb rgb, double alpha) {
  uint8_t* px = buf + (static_cast<size_t>(y) * static_cast<size_t>(w) + static_cast<size_t>(x)) * 4;
  const double sa = alpha;
  const double da = px[3] / 255.0;
  const double out_a = sa + da * (1.0 - sa);
  if (out_a <= 0.0) {
    px[0] = px[1] = px[2] = px[3] = 0;
    return;
  }
  auto chan = [&](uint8_t s, uint8_t d) {
    double v = (double(s) * sa + double(d) * da * (1.0 - sa)) / out_a;
    if (v < 0.0) v = 0.0;
    if (v > 255.0) v = 255.0;
    return static_cast<uint8_t>(v + 0.5);
  };
  px[0] = chan(rgb.r, px[0]);
  px[1] = chan(rgb.g, px[1]);
  px[2] = chan(rgb.b, px[2]);
  px[3] = static_cast<uint8_t>(out_a * 255.0 + 0.5);
}

// Set pixel directly (opaque).
inline void set_pixel(uint8_t* buf, int w, int x, int y, Rgb rgb, uint8_t alpha = 255) {
  uint8_t* px = buf + (static_cast<size_t>(y) * static_cast<size_t>(w) + static_cast<size_t>(x)) * 4;
  px[0] = rgb.r; px[1] = rgb.g; px[2] = rgb.b; px[3] = alpha;
}

} // namespace

Chart::Chart(int width_px, int height_px) {
  resize(width_px, height_px);
}

void Chart::resize(int width_px, int height_px) {
  w_ = std::max(1, width_px);
  h_ = std::max(1, height_px);
  buffer_.assign(static_cast<size_t>(w_) * static_cast<size_t>(h_) * 4, 0);
  dirty_full_ = true;
}

void Chart::clear() {
  std::fill(buffer_.begin(), buffer_.end(), uint8_t{0});
}

// Rasterize the full buffer each frame. The scroll-buffer optimization
// (memmove + 1-column rerender) is left for a future pass — correctness
// first, optimization second. The bandwidth win (1-column Kitty emit) is
// still available because rightmost_column() extracts the right strip.
void Chart::rasterize_single(std::span<const float> samples,
                             int x_start_px, int x_end_px,
                             const Style& style) {
  if (samples.empty() || x_start_px >= x_end_px) return;

  const Rgb line_rgb = color_to_rgb(style.line);
  const Rgb fill_rgb = (style.fill == Color::Default) ? line_rgb : color_to_rgb(style.fill);
  const double alpha = clamp01(style.fill_alpha);

  // Compute Hermite tangents once
  std::vector<double> tangents;
  monotone_tangents(samples, tangents);

  const double n_segments = double(samples.size() - 1);
  if (n_segments <= 0.0) {
    // Single sample: flat line at sample[0]
    double y_norm = clamp01(samples[0]);
    int y_px = static_cast<int>(std::round((1.0 - y_norm) * (h_ - 1)));
    for (int x = x_start_px; x < x_end_px; ++x) {
      for (int y = y_px; y < h_; ++y) {
        blend_pixel(buffer_.data(), w_, x, y, fill_rgb, alpha);
      }
      set_pixel(buffer_.data(), w_, x, y_px, line_rgb);
    }
    return;
  }

  // Curve-line thickness in pixels. 1.5 gives a visibly solid line that
  // still anti-aliases cleanly at the edges — 1.0 renders too thin at
  // sparkline density, 2.0 tends to look chunky.
  constexpr double kLineThickness = 1.5;
  const double kHalfThick = kLineThickness * 0.5;

  for (int x = x_start_px; x < x_end_px; ++x) {
    // Map pixel x → sample-space position s ∈ [0, n_segments]
    double s = (double(x) / double(w_ - 1)) * n_segments;
    if (s < 0.0) s = 0.0;
    if (s > n_segments) s = n_segments;

    size_t i = static_cast<size_t>(std::floor(s));
    if (i >= samples.size() - 1) i = samples.size() - 2;
    double t = s - double(i);

    double y0 = samples[i];
    double y1 = samples[i + 1];
    double m0 = tangents[i];
    double m1 = tangents[i + 1];
    double y_norm = clamp01(hermite(y0, m0, y1, m1, t));

    // Row in pixel space (0 = top). Keep as double for sub-pixel AA.
    double y_px = (1.0 - y_norm) * double(h_ - 1);

    // Clear column first (for redraw correctness when samples change shape).
    for (int y = 0; y < h_; ++y) {
      uint8_t* px = buffer_.data() + (static_cast<size_t>(y) * static_cast<size_t>(w_) + static_cast<size_t>(x)) * 4;
      px[0] = px[1] = px[2] = px[3] = 0;
    }

    // Anti-aliased fill: for each pixel row, coverage is the fraction of
    // the row that lies below the curve. Rows strictly above y_px contribute
    // nothing; rows strictly below contribute 1; the transition row gets a
    // fractional coverage. Kills the stair-step between samples.
    for (int y = 0; y < h_; ++y) {
      double coverage;
      const double row_top = double(y);
      const double row_bot = double(y + 1);
      if (row_bot <= y_px) {
        coverage = 0.0;
      } else if (row_top >= y_px) {
        coverage = 1.0;
      } else {
        coverage = row_bot - y_px;
      }
      if (coverage > 0.0) {
        blend_pixel(buffer_.data(), w_, x, y, fill_rgb, alpha * coverage);
      }
    }

    // Anti-aliased line: a horizontal strip of thickness kLineThickness
    // centered on y_px. For each integer row touched, the coverage is the
    // length of the strip's overlap with that row. This replaces the hard
    // 2-pixel stamp with a soft, fractional line that visually smooths
    // sample-to-sample transitions.
    const double line_top = y_px - kHalfThick;
    const double line_bot = y_px + kHalfThick;
    int y_first = std::max(0, static_cast<int>(std::floor(line_top)));
    int y_last  = std::min(h_ - 1, static_cast<int>(std::ceil(line_bot)) - 1);
    for (int y = y_first; y <= y_last; ++y) {
      double overlap = std::min(line_bot, double(y + 1))
                     - std::max(line_top, double(y));
      if (overlap <= 0.0) continue;
      double cov = overlap / kLineThickness;
      if (cov > 1.0) cov = 1.0;
      blend_pixel(buffer_.data(), w_, x, y, line_rgb, cov);
    }
  }
}

void Chart::update(std::span<const float> samples, const Style& style) {
  if (samples.empty()) { clear(); return; }
  rasterize_single(samples, 0, w_, style);
}

void Chart::update_dual(std::span<const float> primary,
                        std::span<const float> secondary,
                        const Style& style) {
  if (primary.empty() && secondary.empty()) { clear(); return; }

  // Primary with fill
  if (!primary.empty()) {
    rasterize_single(primary, 0, w_, style);
  } else {
    clear();
  }

  // Secondary as line-only overlay (fill_alpha = 0), anti-aliased to match
  // the primary. Same thickness so RX and TX curves read equally on the
  // NETWORK panel.
  if (!secondary.empty()) {
    constexpr double kLineThickness = 1.5;
    const double kHalfThick = kLineThickness * 0.5;
    const Rgb alt_rgb = color_to_rgb(style.line_alt);
    std::vector<double> tangents;
    monotone_tangents(secondary, tangents);
    const double n_segments = double(secondary.size() - 1);
    if (n_segments > 0.0) {
      for (int x = 0; x < w_; ++x) {
        double s = (double(x) / double(w_ - 1)) * n_segments;
        size_t i = static_cast<size_t>(std::floor(s));
        if (i >= secondary.size() - 1) i = secondary.size() - 2;
        double t = s - double(i);
        double y_norm = clamp01(hermite(secondary[i], tangents[i],
                                        secondary[i + 1], tangents[i + 1], t));
        double y_px = (1.0 - y_norm) * double(h_ - 1);
        const double line_top = y_px - kHalfThick;
        const double line_bot = y_px + kHalfThick;
        int y_first = std::max(0, static_cast<int>(std::floor(line_top)));
        int y_last  = std::min(h_ - 1, static_cast<int>(std::ceil(line_bot)) - 1);
        for (int y = y_first; y <= y_last; ++y) {
          double overlap = std::min(line_bot, double(y + 1))
                         - std::max(line_top, double(y));
          if (overlap <= 0.0) continue;
          double cov = overlap / kLineThickness;
          if (cov > 1.0) cov = 1.0;
          blend_pixel(buffer_.data(), w_, x, y, alt_rgb, cov);
        }
      }
    }
  }
}

std::vector<uint8_t> Chart::rightmost_column() const {
  std::vector<uint8_t> col(static_cast<size_t>(h_) * 4, 0);
  const int x = w_ - 1;
  for (int y = 0; y < h_; ++y) {
    const uint8_t* px = buffer_.data() + (static_cast<size_t>(y) * static_cast<size_t>(w_) + static_cast<size_t>(x)) * 4;
    size_t o = static_cast<size_t>(y) * 4;
    col[o + 0] = px[0];
    col[o + 1] = px[1];
    col[o + 2] = px[2];
    col[o + 3] = px[3];
  }
  return col;
}

} // namespace montauk::ui::widget
