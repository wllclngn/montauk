#pragma once

#include <cmath>
#include <string>
#include <unordered_map>

namespace montauk::ui {

// UI Configuration structures
struct UIConfig {
  std::string accent;     // palette 11 -- titles, labels
  std::string caution;    // palette 9  -- mid-severity
  std::string warning;    // palette 1  -- high-severity
  std::string normal;     // palette 2  -- bar normal range, post-bullet data
  std::string muted;      // #787878 -- bullets, secondary text, dim paths/args
  std::string border;     // #383838 -- box-drawing characters, TUI borders
  std::string binary;     // #8F00FF (dome hyperpurp) -- application/binary name in COMMAND column
  int caution_pct;
  int warning_pct;
};

enum class SortMode { CPU, MEM, PID, NAME, GPU, GMEM };

struct UIState {
  SortMode sort{SortMode::CPU};
  int scroll{0};
  bool show_disk{true};
  bool show_net{true};
  bool show_thermal{true};
  bool show_gpumon{true};
  int last_proc_page_rows{14};
  int last_proc_total{0};  // Total process count for scroll clamping
  enum class CPUScale { Total, Core } cpu_scale{CPUScale::Total};
  enum class GPUScale { Capacity, Utilization } gpu_scale{GPUScale::Utilization};
  bool system_focus{false};
  int col_pid_w{5};
  int col_user_w{4};
  int col_gpu_digit_w{4};
  int col_mem_w{5};
  bool show_gmem{true};
  int col_gmem_w{5};
  std::string filter_query;   // Active search filter (empty = no filter)
  bool search_mode{false};    // True when search input is focused
};

// Global UI state
extern UIState g_ui;

// Configuration functions
[[nodiscard]] const UIConfig& ui_config();
void reset_ui_defaults();

// Environment variable helpers
[[nodiscard]] const char* getenv_compat(const char* name);
[[nodiscard]] int getenv_int(const char* name, int defv);
[[nodiscard]] UIState::CPUScale getenv_cpu_scale(const char* name, UIState::CPUScale defv);
[[nodiscard]] bool parse_hex_rgb(const std::string& hex, int& r, int& g, int& b);

} // namespace montauk::ui
