#include "ui/widgets/ChartPanel.hpp"
#include "ui/Config.hpp"
#include "ui/widget/GraphicsProtocol.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>

namespace montauk::ui::widgets {

namespace {

// Allocate a unique Kitty image ID per ChartPanel instance. Using lower-range
// IDs (< 2^16) avoids collisions with other terminal use cases.
std::atomic<uint32_t> g_next_chart_id{100};

uint32_t next_chart_id() { return g_next_chart_id.fetch_add(1, std::memory_order_relaxed); }

// Parse "#RRGGBB" into a widget::Color via rgb_color(). Returns std::nullopt
// on any parse failure.
bool parse_hex(const std::string& s, widget::Color& out) {
  if (s.size() != 7 || s[0] != '#') return false;
  auto hex = [](char c, int& v) -> bool {
    if (c >= '0' && c <= '9') { v = c - '0'; return true; }
    char lc = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (lc >= 'a' && lc <= 'f') { v = 10 + (lc - 'a'); return true; }
    return false;
  };
  int h[6];
  for (int i = 0; i < 6; ++i) {
    if (!hex(s[1 + i], h[i])) return false;
  }
  uint8_t r = static_cast<uint8_t>((h[0] << 4) | h[1]);
  uint8_t g = static_cast<uint8_t>((h[2] << 4) | h[3]);
  uint8_t b = static_cast<uint8_t>((h[4] << 4) | h[5]);
  out = widget::rgb_color(r, g, b);
  return true;
}

// Resolve a color spec into a widget::Color. Spec may be:
//   - "#RRGGBB"     → truecolor
//   - "accent" / "muted" / "normal" / "warning" / "caution" / "border"
//   - "" (empty)    → fallback
widget::Color resolve_color(const std::string& spec, widget::Color fallback) {
  if (spec.empty()) return fallback;
  widget::Color out = fallback;
  if (parse_hex(spec, out)) return out;

  const auto& cfg = ui_config();
  const std::string* role_sgr = nullptr;
  if      (spec == "accent")  role_sgr = &cfg.accent;
  else if (spec == "muted")   role_sgr = &cfg.muted;
  else if (spec == "normal")  role_sgr = &cfg.normal;
  else if (spec == "warning") role_sgr = &cfg.warning;
  else if (spec == "caution") role_sgr = &cfg.caution;
  else if (spec == "border")  role_sgr = &cfg.border;
  else if (spec == "binary")  role_sgr = &cfg.binary;

  if (role_sgr) {
    return widget::parse_sgr_style(*role_sgr).fg;
  }
  return fallback;
}

// Per-panel compiled defaults — applied when both the [chart.<panel>] override
// and the [chart] global are empty. The spec document lists the exact values.
widget::Color default_line_for(const std::string& panel_name) {
  if (panel_name == "cpu")     return widget::rgb_color(0x4A, 0xDE, 0x80);  // green
  if (panel_name == "gpu")     return widget::rgb_color(0xF8, 0x71, 0x71);  // red
  if (panel_name == "memory")  return widget::rgb_color(0x60, 0xA5, 0xFA);  // blue
  if (panel_name == "network") return widget::rgb_color(0xA7, 0x8B, 0xFA);  // purple (RX)
  return widget::rgb_color(0xB4, 0xB4, 0xD2);  // soft lavender
}

widget::Color default_line_alt_for(const std::string& panel_name) {
  if (panel_name == "network") return widget::rgb_color(0xFB, 0xBF, 0x24);  // yellow (TX)
  return widget::rgb_color(0x78, 0x78, 0x78);  // muted
}

const Config::ChartColors& panel_overrides_for(const std::string& name) {
  const auto& c = config().chart;
  if (name == "cpu")     return c.cpu;
  if (name == "gpu")     return c.gpu;
  if (name == "memory")  return c.memory;
  if (name == "network") return c.network;
  return c.global;
}

// Normalize a NETWORK-style byte/sec sample array by the window max. Returns
// a new vector in [0, 1]. A floor (1 KB/s) avoids divide-by-zero and keeps an
// idle network visually flat at ~0 rather than amplifying sensor noise.
std::vector<float> normalize_network(const std::vector<float>& rx,
                                      const std::vector<float>& tx) {
  float peak = 1024.0f;
  for (float v : rx) if (v > peak) peak = v;
  for (float v : tx) if (v > peak) peak = v;
  (void)rx; (void)tx;
  return {};  // unused — see render() where we normalize inline
}

} // namespace

ChartPanel::ChartPanel(std::string title,
                       std::string panel_name,
                       montauk::util::History<float>* history)
    : title_(std::move(title)),
      panel_name_(std::move(panel_name)),
      sources_{history, nullptr},
      chart_(1, 1),
      chart_id_(next_chart_id()) {}

ChartPanel::ChartPanel(std::string title,
                       std::string panel_name,
                       DualCurveSources sources)
    : title_(std::move(title)),
      panel_name_(std::move(panel_name)),
      sources_(sources),
      chart_(1, 1),
      chart_id_(next_chart_id()) {}

widget::Chart::Style ChartPanel::resolve_style() const {
  const auto& ovr = panel_overrides_for(panel_name_);
  const auto& glo = config().chart.global;

  widget::Color line_default     = default_line_for(panel_name_);
  widget::Color line_alt_default = default_line_alt_for(panel_name_);

  widget::Color line = resolve_color(
      !ovr.line.empty() ? ovr.line : glo.line, line_default);

  widget::Color line_alt = resolve_color(
      !ovr.line_alt.empty() ? ovr.line_alt : glo.line_alt, line_alt_default);

  const std::string& fill_spec = !ovr.fill.empty() ? ovr.fill : glo.fill;
  widget::Color fill;
  if (fill_spec.empty() || fill_spec == "auto") {
    fill = line;  // inherit line color; alpha applied via fill_alpha
  } else {
    fill = resolve_color(fill_spec, line);
  }

  double alpha = !ovr.fill.empty() ? ovr.fill_alpha : glo.fill_alpha;
  if (alpha <= 0.0 && glo.fill_alpha > 0.0) alpha = glo.fill_alpha;
  if (alpha < 0.0) alpha = 0.0;
  if (alpha > 1.0) alpha = 1.0;
  if (alpha == 0.0) alpha = 0.40;  // spec default

  return widget::Chart::Style{line, line_alt, fill, alpha};
}

void ChartPanel::render(widget::Canvas& canvas,
                        const widget::LayoutRect& rect,
                        const montauk::model::Snapshot& /*snap*/) {
  // Draw border + title using the standard helper.
  widget::Style border_style = widget::parse_sgr_style(ui_config().border);
  widget::Style title_style  = widget::parse_sgr_style(ui_config().accent);
  widget::LayoutRect inner = draw_box_border(canvas, rect, title_, border_style, title_style);
  if (inner.width <= 0 || inner.height <= 0) return;

  auto& gfx = widget::GraphicsEmitter::instance();

  // No graphics support: render a muted notice inside the inner rect.
  if (gfx.protocol() == widget::Protocol::None) {
    widget::Style muted = widget::parse_sgr_style(ui_config().muted);
    const char* note = "(terminal lacks Kitty/Sixel — see montauk.1)";
    int nlen = static_cast<int>(std::string_view(note).size());
    int x = inner.x + std::max(0, (inner.width - nlen) / 2);
    int y = inner.y + inner.height / 2;
    canvas.draw_text(x, y, note, muted);
    return;
  }

  // Compute pixel dimensions from inner cell rect × cell size.
  const auto cell = gfx.cell_size();
  const int px_w = inner.width * cell.w;
  const int px_h = inner.height * cell.h;
  if (px_w <= 0 || px_h <= 0) return;

  // Resize chart buffer if geometry changed.
  if (px_w != last_px_w_ || px_h != last_px_h_) {
    chart_.resize(px_w, px_h);
    last_px_w_ = px_w;
    last_px_h_ = px_h;
    has_emitted_once_ = false;
  }

  widget::Chart::Style style = resolve_style();

  // Forward-pass EMA over the sample window. Alpha = 0.4 is a balance:
  // low enough to flatten single-frame spikes (a 15%→2% CPU blip becomes
  // a soft dip instead of a vertical cliff), high enough that the latest
  // sample still lands near its true value. Applied per frame over the
  // whole window — idempotent given the same history, no state kept.
  auto ema_smooth = [](std::vector<float>& v, float a) {
    if (v.size() < 2) return;
    for (size_t i = 1; i < v.size(); ++i) {
      v[i] = a * v[i] + (1.0f - a) * v[i - 1];
    }
  };

  // Fetch samples under the history mutex, rasterize, then release.
  // Chart::update_dual normalizes separately by caller for NETWORK.
  if (sources_.secondary != nullptr && sources_.primary != nullptr) {
    // Dual-curve path (NETWORK RX + TX). Normalize by shared window max.
    std::vector<float> rx = sources_.primary->recent(sources_.primary->capacity());
    std::vector<float> tx = sources_.secondary->recent(sources_.secondary->capacity());
    float peak = 1024.0f;
    for (float v : rx) if (v > peak) peak = v;
    for (float v : tx) if (v > peak) peak = v;
    for (float& v : rx) v /= peak;
    for (float& v : tx) v /= peak;
    ema_smooth(rx, 0.4f);
    ema_smooth(tx, 0.4f);
    chart_.update_dual(rx, tx, style);
    (void)normalize_network;  // silence unused
  } else if (sources_.primary != nullptr) {
    std::vector<float> samples = sources_.primary->recent(sources_.primary->capacity());
    // Samples are already normalized to [0, 1] by ChartHistories (for pct metrics).
    ema_smooth(samples, 0.4f);
    chart_.update(samples, style);
  }

  // Throttled emission: charts re-emit only every 4th frame (roughly 1 Hz
  // at the 4 Hz producer cadence). The producer's 4 MB/s of escape data
  // was saturating the PTY and starving input polling. At 1 Hz we emit
  // ~125 KB/s which the PTY handles comfortably.
  //
  // On non-emit frames Kitty keeps displaying the last-transmitted image
  // (placements persist until explicitly deleted), so the chart remains
  // visible. Chart data updates visually at 1 Hz; for system metrics
  // that's imperceptibly slower than 4 Hz.
  //
  // First frame and resizes always emit to establish the placement.
  const bool must_emit = !has_emitted_once_ || chart_.dirty_full();
  const bool throttle_emit = (frame_counter_ % 4) == 0;
  frame_counter_++;

  if (!must_emit && !throttle_emit) {
    return;
  }

  std::string escape = gfx.emit_full(chart_id_, inner.x, inner.y,
                                      inner.width, inner.height,
                                      chart_.pixels(), px_w, px_h);
  chart_.clear_dirty_full();
  has_emitted_once_ = true;

  canvas.paint_image(inner, std::move(escape));
}

void ChartPanel::hide(widget::Canvas& canvas) {
  if (!has_emitted_once_) return;
  auto& gfx = widget::GraphicsEmitter::instance();
  std::string del = gfx.emit_delete(chart_id_);
  if (!del.empty()) {
    canvas.push_graphics_command(std::move(del));
  }
  has_emitted_once_ = false;
  // Force a full re-emit next time the chart becomes visible so Kitty
  // has a fresh placement.
  last_px_w_ = 0;
  last_px_h_ = 0;
}

} // namespace montauk::ui::widgets
