#pragma once

#include <string>

namespace montauk::ui {

// UTF-8 text width utilities
int u8_len(unsigned char c);
int display_cols(const std::string& s);
std::string take_cols(const std::string& s, int cols);

// Text formatting and alignment
std::string trunc_pad(const std::string& s, int w);
std::string rpad_trunc(const std::string& s, int w);
std::string lr_align(int iw, const std::string& left, const std::string& right);

// Date/time formatting
bool prefer_12h_clock_from_locale();
std::string format_time_now(bool prefer12h);
std::string format_date_now_locale();

// System information helpers
std::string read_hostname();
std::string read_kernel_version();
std::string read_uptime_formatted();
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
CpuFreqInfo read_cpu_freq_info();

// EMA smoother for UI (bar fill smoothing)
double smooth_value(const std::string& key, double raw, double alpha = 0.25);

} // namespace montauk::ui
