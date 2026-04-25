#pragma once

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
[[nodiscard]] double smooth_value(const std::string& key, double raw, double alpha = 0.25);

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

// Format a byte count as a human-readable size (e.g. "3.5G", "42M", "128K").
// `precision` controls trailing decimals for non-KB units (pass 0 for whole
// numbers). When `include_tb` is true, values >= 1TB report in T.
[[nodiscard]] std::string format_size(uint64_t bytes, int precision = 1, bool include_tb = true);

// Convenience wrapper: same as format_size but input is in KiB (1024-byte
// blocks). Equivalent to format_size(kib * 1024, precision, include_tb).
[[nodiscard]] std::string format_size_kib(uint64_t kib, int precision = 0, bool include_tb = false);

} // namespace montauk::ui
