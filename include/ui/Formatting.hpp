#pragma once
#include <span>
#include <string_view>

#include "ui/widget/Color.hpp"

#include <cstdint>
#include <string>

namespace montauk::ui {

// Date/time formatting
[[nodiscard]] bool prefer_12h_clock_from_locale();
[[nodiscard]] std::string format_time_now(bool prefer12h);
[[nodiscard]] std::string format_date_now_locale();

// System information helpers
[[nodiscard]] std::string read_hostname();
[[nodiscard]] std::string read_kernel_version();
[[nodiscard]] std::string read_scheduler();
[[nodiscard]] std::string read_uptime_formatted();
void read_loadavg(double& a1, double& a5, double& a15);

// CPU frequency info
struct CpuFreqInfo {
  bool has_cur{false};
  bool has_max{false};
  double cur_ghz{0.0};
  double max_ghz{0.0};
  std::string governor;
  std::string turbo;
};
[[nodiscard]] CpuFreqInfo read_cpu_freq_info();

// EMA smoother for UI (bar fill smoothing)
// key is probed without allocating: the cache hashes transparently, so a
// string_view over a caller's stack buffer is enough.
[[nodiscard]] double smooth_value(std::string_view key, double raw, double alpha = 0.25);

// Forward-pass EMA over a series, in place. Idempotent given the same history --
// no state is kept between frames, so applying it per frame over the whole
// window is well defined.
//
// ChartPanel and CpuGrid each carried a byte-identical copy of this lambda (the
// same 0.4 alpha, the loop variable renamed), so the PROCESSOR chart and the
// per-core mini-charts could drift apart in character without anyone noticing.
// It stays a plain function over a span: sublimation cannot absorb it, because
// sublimation_ewma_scores is a per-row ANOMALY SCORE over a row-major matrix,
// not a smoother, and it allocates.
void ema_smooth(std::span<float> v, float alpha);

// GRAPHICS EMISSION THROTTLE, one policy for every chart surface.
//
// Charts re-emit only every Nth frame (roughly 1 Hz at the 4 Hz producer
// cadence). The producer's 4 MB/s of escape data was saturating the PTY and
// starving input polling; at 1 Hz it is ~125 KB/s, which the PTY handles. On a
// skipped frame Kitty keeps displaying the last-transmitted image -- placements
// persist until explicitly deleted -- so the chart stays visible, and system
// metrics updating at 1 Hz instead of 4 Hz is imperceptible.
//
// `forced` is the escape hatch a first frame or a resize needs: the placement
// has to be established before throttling means anything. ChartPanel and CpuGrid
// each carried this rule inline, so the PROCESSOR panel and the per-core grid
// could have drifted to different cadences without anyone noticing.
[[nodiscard]] bool chart_should_emit(uint64_t frame_tick, bool forced);



// Security: sanitize strings for terminal display
[[nodiscard]] std::string sanitize_for_display(const std::string& s, size_t max_len = 512);

// Severity level from a numeric value and two thresholds.
// Returns 0 (normal), 1 (caution), 2 (warning). The thresholds are
// inclusive-lower: value >= warning → 2, value >= caution → 1, else 0.
[[nodiscard]] inline int compute_severity(int value, int caution, int warning) {
  if (value >= warning) return 2;
  if (value >= caution) return 1;
  return 0;
}

// Style for a value rendered at a given severity (0 normal, 1 caution,
// 2 warning), resolved from the active UI palette.
[[nodiscard]] widget::Style severity_style(int severity);

// Format a byte count as a human-readable size (e.g. "3.5G", "42M", "128K").
// `precision` controls trailing decimals for non-KB units (pass 0 for whole
// numbers). When `include_tb` is true, values >= 1TB report in T.
[[nodiscard]] std::string format_size(uint64_t bytes, int precision = 1, bool include_tb = true);

// Convenience wrapper: same as format_size but input is in KiB (1024-byte
// blocks). Equivalent to format_size(kib * 1024, precision, include_tb).
[[nodiscard]] std::string format_size_kib(uint64_t kib, int precision = 0, bool include_tb = false);

} // namespace montauk::ui
