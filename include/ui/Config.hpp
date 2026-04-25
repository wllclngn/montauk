#pragma once

#include <string>

namespace montauk::ui {

// Full application configuration, loaded from TOML → env → compiled defaults.
// Keybinds are owned by the widgets themselves now (see widget::InputEvent
// and each widget's handle_input override) — no central keybind table.
struct Config {
  // [roles] — resolved to SGR escape strings.
  struct Colors {
    std::string accent;     // titles, labels, panel headers
    std::string caution;    // mid-severity highlight
    std::string warning;    // high-severity highlight
    std::string normal;     // post-bullet data values
    std::string muted;      // bullets, secondary text, dim paths/args
    std::string border;     // box-drawing characters
    std::string binary;     // application/binary names in command column
  } colors;

  // [thresholds]
  struct Thresholds {
    int proc_caution_pct = 60;
    int proc_warning_pct = 80;
    int cpu_temp_warning_c = 90;
    int cpu_temp_caution_c = 0;       // 0 = derive from warning - delta
    int temp_caution_delta_c = 10;
    int gpu_temp_warning_c = 90;
    int gpu_temp_caution_c = 0;       // 0 = derive
    int gpu_temp_edge_warning_c = 0;  // 0 = use gpu_temp_warning_c
    int gpu_temp_hot_warning_c = 0;   // 0 = use gpu_temp_warning_c
    int gpu_temp_mem_warning_c = 0;   // 0 = use gpu_temp_warning_c
    int alert_frames = 5;
  } thresholds;

  // [ui]
  struct UI {
    bool alt_screen = true;
    bool system_focus = false;
    std::string cpu_scale = "total";        // "total" | "core"
    std::string gpu_scale = "utilization";  // "utilization" | "capacity"
    std::string time_format;
  } ui;

  // [process]
  struct Process {
    int max_procs = 256;
    int enrich_top_n = 256;
    std::string collector = "auto";
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

  // [chart] — global defaults + per-panel color overrides. Color values:
  // role name ("accent", "muted", etc.), hex "#RRGGBB", or "auto".
  struct ChartColors {
    std::string line;        // primary curve; empty => baked-in default
    std::string line_alt;    // secondary curve (NETWORK TX)
    std::string fill;        // "auto" => match line at fill_alpha
    double      fill_alpha = 0.40;
  };
  struct Chart {
    int history_seconds = 60;     // ring buffer capacity = seconds * 4 Hz
    ChartColors global;
    ChartColors cpu;
    ChartColors gpu;
    ChartColors memory;
    ChartColors network;
  } chart;
};

// Resolved color roles + caution/warning thresholds for fast access at
// draw time (avoids walking `config()` per cell).
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

// Singletons.
[[nodiscard]] const Config&   config();
[[nodiscard]] const UIConfig& ui_config();

// Environment-variable helpers used by the config-resolution layer.
[[nodiscard]] const char* getenv_compat(const char* name);
[[nodiscard]] int         getenv_int(const char* name, int defv);
[[nodiscard]] bool        parse_hex_rgb(const std::string& hex, int& r, int& g, int& b);

// Path of the user's TOML config (resolved from XDG_CONFIG_HOME / HOME).
[[nodiscard]] std::string config_file_path();

} // namespace montauk::ui
