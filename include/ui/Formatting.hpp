#pragma once

#include <string>

namespace montauk::ui {

// UTF-8 text width utilities (uses wcwidth for proper wide char support)
[[nodiscard]] int display_cols(const std::string& s);
[[nodiscard]] std::string take_cols(const std::string& s, int cols);

// Text formatting and alignment
[[nodiscard]] std::string trunc_pad(const std::string& s, int w);
[[nodiscard]] std::string rpad_trunc(const std::string& s, int w);
[[nodiscard]] std::string lr_align(int iw, const std::string& left, const std::string& right);

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

} // namespace montauk::ui
