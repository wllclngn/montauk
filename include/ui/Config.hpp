#pragma once

#include <cmath>
#include <string>
#include <unordered_map>

namespace montauk::ui {

// UI Configuration structures
struct UIConfig {
  std::string accent;
  std::string caution;
  std::string warning;
  std::string title;
  int caution_pct;
  int warning_pct;
};

enum class SortMode { CPU, MEM, PID, NAME, GPU, GMEM };

struct UIState {
  SortMode sort{SortMode::CPU};
  int scroll{0};
  bool show_disk{true};
  bool show_net{true};
  bool show_gpuinfo{true};
  bool show_vram{true};
  bool show_thermal{true};
  bool show_gpumon{true};
  int last_proc_page_rows{14};
  enum class CPUScale { Total, Core } cpu_scale{CPUScale::Total};
  enum class GPUScale { Capacity, Utilization } gpu_scale{GPUScale::Utilization};
  bool system_focus{false};
  int col_pid_w{5};
  int col_user_w{4};
  int col_gpu_digit_w{4};
  int col_mem_w{5};
  bool show_gmem{true};
  int col_gmem_w{5};
};

// Global UI state
extern UIState g_ui;

// Configuration functions
const UIConfig& ui_config();
void reset_ui_defaults();

// Environment variable helpers
const char* getenv_compat(const char* name);
int getenv_int(const char* name, int defv);
UIState::CPUScale getenv_cpu_scale(const char* name, UIState::CPUScale defv);
bool parse_hex_rgb(const std::string& hex, int& r, int& g, int& b);

} // namespace montauk::ui
