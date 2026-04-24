#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace montauk::ui {

// Full application configuration, loaded from TOML -> env -> compiled defaults
struct Config {
  // [roles] -- resolved to SGR escape strings
  struct Colors {
    std::string accent;     // palette 11 -- titles, labels
    std::string caution;    // palette 9  -- mid-severity
    std::string warning;    // palette 1  -- high-severity
    std::string normal;     // palette 2  -- bar normal range, post-bullet data
    std::string muted;      // #787878 -- bullets, secondary text, dim paths/args
    std::string border;     // #383838 -- box-drawing characters, TUI borders
    std::string binary;     // #8F00FF (dome hyperpurp) -- application/binary name
  } colors;

  // [thresholds]
  struct Thresholds {
    int proc_caution_pct = 60;
    int proc_warning_pct = 80;
    int cpu_temp_warning_c = 90;
    int cpu_temp_caution_c = 0;      // 0 = derive from warning - delta
    int temp_caution_delta_c = 10;
    int gpu_temp_warning_c = 90;
    int gpu_temp_caution_c = 0;      // 0 = derive from warning - delta
    int gpu_temp_edge_warning_c = 0; // 0 = use gpu_temp_warning_c
    int gpu_temp_hot_warning_c = 0;  // 0 = use gpu_temp_warning_c
    int gpu_temp_mem_warning_c = 0;  // 0 = use gpu_temp_warning_c
    int alert_frames = 5;
  } thresholds;

  // [ui]
  struct UI {
    bool alt_screen = true;
    bool system_focus = false;
    std::string cpu_scale = "total";   // "total" | "core"
    std::string gpu_scale = "utilization"; // "utilization" | "capacity"
    std::string time_format;
  } ui;

  // [process]
  struct Process {
    int max_procs = 256;
    int enrich_top_n = 256;
    std::string collector = "auto";   // "auto" | "procfs" | "netlink" | "kernel"
  } process;

  // [nvidia]
  struct Nvidia {
    std::string smi_path = "auto";
    bool smi_dev = true;
    int smi_min_interval_ms = 0;
    bool pmon = true;
    bool mem = true;
    bool log_nvml = false;
    bool gpu_debug = false;
    bool disable_nvml = false;
    std::string nvml_path;
  } nvidia;

  // [chart] — global defaults + per-panel color overrides.
  // Color values: role name ("accent", "muted", etc.), hex "#RRGGBB",
  // palette index "0".."15", or "auto" (meaning: inherit from line).
  struct ChartColors {
    std::string line;       // primary curve color; empty => inherit [roles].accent
    std::string line_alt;   // secondary curve color (NETWORK TX); empty => [roles].muted
    std::string fill;       // "auto" => line color at fill_alpha; explicit => that color
    double      fill_alpha = 0.40;
  };
  struct Chart {
    // History retention in seconds. Ring buffer capacity = history_seconds *
    // refresh_hz. Clamped [1, 3600] during parse. 0 means "use default".
    int history_seconds = 60;

    // Global defaults applied to every chart unless a per-panel section
    // overrides. Per-panel overrides live in ChartColors instances below.
    ChartColors global;

    // Per-panel overrides. Any string left empty inherits from `global`,
    // which in turn inherits from [roles]. Pass 4 parses the [chart.<panel>]
    // sections into these.
    ChartColors cpu;
    ChartColors gpu;
    ChartColors memory;
    ChartColors network;
  } chart;

  // [keybinds]
  enum class Action : uint8_t {
    NONE, QUIT, HELP, FPS_UP, FPS_DOWN,
    SORT_CPU, SORT_MEM, SORT_PID, SORT_NAME, SORT_GPU, SORT_GMEM,
    TOGGLE_GPU, TOGGLE_THERMAL,
    TOGGLE_CPU_SCALE, TOGGLE_GPU_SCALE, TOGGLE_SYSTEM_FOCUS,
    RESET_UI, SEARCH,
  };
  std::unordered_map<char, Action> keybinds;

  [[nodiscard]] Action lookup_key(char c) const {
    auto it = keybinds.find(c);
    return (it != keybinds.end()) ? it->second : Action::NONE;
  }
};

// Backward-compatible UIConfig (wraps Config::Colors + thresholds)
struct UIConfig {
  std::string accent;
  std::string caution;
  std::string warning;
  std::string normal;
  std::string muted;
  std::string border;
  std::string binary;
  int caution_pct;
  int warning_pct;
};

enum class SortMode { CPU, MEM, PID, NAME, GPU, GMEM };

struct UIState {
  SortMode sort{SortMode::CPU};
  int scroll{0};
  bool show_thermal{true};
  bool show_gpumon{true};
  int last_proc_page_rows{14};
  int last_proc_total{0};
  enum class CPUScale { Total, Core } cpu_scale{CPUScale::Total};
  enum class GPUScale { Capacity, Utilization } gpu_scale{GPUScale::Utilization};
  bool system_focus{false};
  int col_pid_w{5};
  int col_user_w{4};
  int col_gpu_digit_w{4};
  int col_mem_w{5};
  bool show_gmem{true};
  int col_gmem_w{5};
  std::string filter_query;
  bool search_mode{false};
};

// Global UI state
extern UIState g_ui;

// Configuration singletons
[[nodiscard]] const Config& config();
[[nodiscard]] const UIConfig& ui_config();
void reset_ui_defaults();

// Environment variable helpers (used as fallback layer in config resolution)
[[nodiscard]] const char* getenv_compat(const char* name);
[[nodiscard]] int getenv_int(const char* name, int defv);
[[nodiscard]] UIState::CPUScale getenv_cpu_scale(const char* name, UIState::CPUScale defv);
[[nodiscard]] bool parse_hex_rgb(const std::string& hex, int& r, int& g, int& b);

// Config file path (shared between config() and --init-theme)
[[nodiscard]] std::string config_file_path();

} // namespace montauk::ui
