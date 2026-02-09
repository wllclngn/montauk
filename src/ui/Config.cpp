#include "ui/Config.hpp"
#include "ui/Terminal.hpp"
#include "util/AsciiLower.hpp"
#include "util/TomlReader.hpp"
#include <cctype>
#include <cstdlib>
#include <string>

namespace montauk::ui {

constinit UIState g_ui{};

bool parse_hex_rgb(const std::string& hex, int& r, int& g, int& b) {
  if (hex.size()!=7 || hex[0] != '#') return false;
  auto hexv = [&](char c)->int{
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return c-'a'+10;
    if (c>='A'&&c<='F') return c-'A'+10;
    return -1;
  };
  int v1=hexv(hex[1]), v2=hexv(hex[2]), v3=hexv(hex[3]), v4=hexv(hex[4]), v5=hexv(hex[5]), v6=hexv(hex[6]);
  if (v1<0||v2<0||v3<0||v4<0||v5<0||v6<0) return false;
  r = v1*16+v2; g = v3*16+v4; b = v5*16+v6;
  return true;
}

const char* getenv_compat(const char* name) {
  const char* v = std::getenv(name);
  if (v && *v) return v;
  std::string alt;
  std::string n(name);
  if (n.rfind("MONTAUK_", 0) == 0) {
    alt = std::string("montauk_") + n.substr(8);
  } else if (n.rfind("montauk_", 0) == 0) {
    alt = std::string("MONTAUK_") + n.substr(8);
  }
  if (!alt.empty()) {
    v = std::getenv(alt.c_str());
    if (v && *v) return v;
  }
  return nullptr;
}

int getenv_int(const char* name, int defv) {
  const char* v = getenv_compat(name);
  if (!v || !*v) return defv;
  try { return std::stoi(v); } catch(...) { return defv; }
}

UIState::CPUScale getenv_cpu_scale(const char* name, UIState::CPUScale defv){
  const char* v = getenv_compat(name);
  if (!v || !*v) return defv;
  std::string s = v;
  for (auto& c : s) c = montauk::util::ascii_lower((unsigned char)c);
  if (s=="core"||s=="percore"||s=="irix") return UIState::CPUScale::Core;
  if (s=="total"||s=="machine"||s=="share") return UIState::CPUScale::Total;
  return defv;
}

static bool env_flag(const char* name, bool defv) {
  const char* v = getenv_compat(name);
  if (!v) return defv;
  if (v[0]=='0'||v[0]=='f'||v[0]=='F') return false;
  return true;
}

std::string config_file_path() {
  if (const char* xdg = std::getenv("XDG_CONFIG_HOME"); xdg && *xdg)
    return std::string(xdg) + "/montauk/config.toml";
  if (const char* home = std::getenv("HOME"); home && *home)
    return std::string(home) + "/.config/montauk/config.toml";
  return {};
}

// Resolve a color role from TOML -> env -> compiled default.
// TOML value can be integer (palette index) or "#RRGGBB" (hex override).
// If palette index, look up the hex in [palette] and use truecolor if available.
static std::string resolve_color(const montauk::util::TomlReader& toml, bool have_toml,
                                  const char* role, int def_palette_idx,
                                  const char* def_hex) {
  if (have_toml && toml.has("roles", role)) {
    std::string val = toml.get_string("roles", role);
    if (!val.empty() && (std::isdigit(static_cast<unsigned char>(val[0])) || val[0]=='-')) {
      int idx = 0;
      try { idx = std::stoi(val); } catch(...) { idx = def_palette_idx; }
      // Look up palette hex for this index
      std::string pkey = "color" + std::to_string(idx);
      if (toml.has("palette", pkey)) {
        std::string hex = toml.get_string("palette", pkey);
        int r, g, b;
        if (parse_hex_rgb(hex, r, g, b)) return sgr_truecolor(r, g, b);
      }
      return sgr_palette_idx(idx);
    }
    if (val.size() == 7 && val[0] == '#') {
      int r, g, b;
      if (parse_hex_rgb(val, r, g, b)) return sgr_truecolor(r, g, b);
    }
  }
  // Compiled default
  if (def_hex && def_hex[0] == '#') {
    int r, g, b;
    if (parse_hex_rgb(std::string(def_hex), r, g, b)) return sgr_truecolor(r, g, b);
  }
  return sgr_palette_idx(def_palette_idx);
}

// Resolve an int from TOML -> env -> compiled default
static int resolve_int(const montauk::util::TomlReader& toml, bool have_toml,
                        const char* section, const char* key,
                        const char* env_name, int def) {
  if (have_toml && toml.has(section, key))
    return toml.get_int(section, key, def);
  if (env_name)
    return getenv_int(env_name, def);
  return def;
}

// Resolve a bool from TOML -> env -> compiled default
static bool resolve_bool(const montauk::util::TomlReader& toml, bool have_toml,
                          const char* section, const char* key,
                          const char* env_name, bool def) {
  if (have_toml && toml.has(section, key))
    return toml.get_bool(section, key, def);
  if (env_name)
    return env_flag(env_name, def);
  return def;
}

// Resolve a string from TOML -> env -> compiled default
static std::string resolve_string(const montauk::util::TomlReader& toml, bool have_toml,
                                   const char* section, const char* key,
                                   const char* env_name, const std::string& def) {
  if (have_toml && toml.has(section, key))
    return toml.get_string(section, key, def);
  if (env_name) {
    const char* v = getenv_compat(env_name);
    if (v && *v) return std::string(v);
  }
  return def;
}

// Default keybind table
struct KeybindDef { const char* name; char key; Config::Action action; };
static constexpr KeybindDef default_keybinds[] = {
  {"quit",                'q', Config::Action::QUIT},
  {"help",                'h', Config::Action::HELP},
  {"fps_up",              '+', Config::Action::FPS_UP},
  {"fps_down",            '-', Config::Action::FPS_DOWN},
  {"sort_cpu",            'c', Config::Action::SORT_CPU},
  {"sort_mem",            'm', Config::Action::SORT_MEM},
  {"sort_pid",            'p', Config::Action::SORT_PID},
  {"sort_name",           'n', Config::Action::SORT_NAME},
  {"sort_gpu",            'g', Config::Action::SORT_GPU},
  {"sort_gmem",           'v', Config::Action::SORT_GMEM},
  {"toggle_gpu",          'G', Config::Action::TOGGLE_GPU},
  {"toggle_thermal",      't', Config::Action::TOGGLE_THERMAL},
  {"toggle_disk",         'd', Config::Action::TOGGLE_DISK},
  {"toggle_net",          'N', Config::Action::TOGGLE_NET},
  {"toggle_cpu_scale",    'i', Config::Action::TOGGLE_CPU_SCALE},
  {"toggle_gpu_scale",    'u', Config::Action::TOGGLE_GPU_SCALE},
  {"toggle_system_focus", 's', Config::Action::TOGGLE_SYSTEM_FOCUS},
  {"reset_ui",            'R', Config::Action::RESET_UI},
  {"search",              '/', Config::Action::SEARCH},
};

static void populate_keybinds(Config& c, const montauk::util::TomlReader& toml, bool have_toml) {
  for (const auto& kb : default_keybinds) {
    char key = kb.key;
    if (have_toml && toml.has("keybinds", kb.name)) {
      std::string val = toml.get_string("keybinds", kb.name);
      if (!val.empty()) key = val[0];
    }
    c.keybinds[key] = kb.action;
    // For letter keys, also map the opposite case (unless already mapped)
    if (std::isalpha(static_cast<unsigned char>(key))) {
      char alt = std::isupper(static_cast<unsigned char>(key))
                   ? static_cast<char>(std::tolower(static_cast<unsigned char>(key)))
                   : static_cast<char>(std::toupper(static_cast<unsigned char>(key)));
      // Only auto-map if the alt case isn't already explicitly bound
      if (c.keybinds.find(alt) == c.keybinds.end()) {
        // Don't auto-map if another keybind explicitly uses that case
        bool alt_explicit = false;
        for (const auto& kb2 : default_keybinds) {
          char k2 = kb2.key;
          if (have_toml && toml.has("keybinds", kb2.name)) {
            std::string v2 = toml.get_string("keybinds", kb2.name);
            if (!v2.empty()) k2 = v2[0];
          }
          if (k2 == alt) { alt_explicit = true; break; }
        }
        if (!alt_explicit) c.keybinds[alt] = kb.action;
      }
    }
  }
  // Always map Ctrl+F to search (0x06)
  c.keybinds[0x06] = Config::Action::SEARCH;
}

const Config& config() {
  static Config cfg = []{
    Config c{};
    montauk::util::TomlReader toml;
    auto path = config_file_path();
    bool have_toml = !path.empty() && toml.load(path);

    // --- [roles] ---
    c.colors.accent  = resolve_color(toml, have_toml, "accent",  11, nullptr);
    c.colors.caution = resolve_color(toml, have_toml, "caution",  9, nullptr);
    c.colors.warning = resolve_color(toml, have_toml, "warning",  1, nullptr);
    c.colors.normal  = resolve_color(toml, have_toml, "normal",   2, nullptr);
    c.colors.muted   = resolve_color(toml, have_toml, "muted",   -1, "#787878");
    c.colors.border  = resolve_color(toml, have_toml, "border",  -1, "#383838");
    c.colors.binary  = resolve_color(toml, have_toml, "binary",  -1, "#8F00FF");

    // --- [thresholds] ---
    c.thresholds.proc_caution_pct    = resolve_int(toml, have_toml, "thresholds", "proc_caution_pct",    "MONTAUK_PROC_CAUTION_PCT", 60);
    c.thresholds.proc_warning_pct    = resolve_int(toml, have_toml, "thresholds", "proc_warning_pct",    "MONTAUK_PROC_WARNING_PCT", 80);
    c.thresholds.cpu_temp_warning_c  = resolve_int(toml, have_toml, "thresholds", "cpu_temp_warning_c",  "MONTAUK_CPU_TEMP_WARNING_C", 90);
    c.thresholds.cpu_temp_caution_c  = resolve_int(toml, have_toml, "thresholds", "cpu_temp_caution_c",  "MONTAUK_CPU_TEMP_CAUTION_C", 0);
    c.thresholds.temp_caution_delta_c= resolve_int(toml, have_toml, "thresholds", "temp_caution_delta_c","MONTAUK_TEMP_CAUTION_DELTA_C", 10);
    c.thresholds.gpu_temp_warning_c  = resolve_int(toml, have_toml, "thresholds", "gpu_temp_warning_c",  "MONTAUK_GPU_TEMP_WARNING_C", 90);
    c.thresholds.gpu_temp_caution_c  = resolve_int(toml, have_toml, "thresholds", "gpu_temp_caution_c",  "MONTAUK_GPU_TEMP_CAUTION_C", 0);
    c.thresholds.gpu_temp_edge_warning_c = resolve_int(toml, have_toml, "thresholds", "gpu_temp_edge_warning_c", "MONTAUK_GPU_TEMP_EDGE_WARNING_C", 0);
    c.thresholds.gpu_temp_hot_warning_c  = resolve_int(toml, have_toml, "thresholds", "gpu_temp_hot_warning_c",  "MONTAUK_GPU_TEMP_HOT_WARNING_C", 0);
    c.thresholds.gpu_temp_mem_warning_c  = resolve_int(toml, have_toml, "thresholds", "gpu_temp_mem_warning_c",  "MONTAUK_GPU_TEMP_MEM_WARNING_C", 0);
    c.thresholds.alert_frames        = resolve_int(toml, have_toml, "thresholds", "alert_frames",        "MONTAUK_TOPPROC_ALERT_FRAMES", 5);

    // --- [ui] ---
    c.ui.alt_screen    = resolve_bool(toml, have_toml, "ui", "alt_screen",    "MONTAUK_ALT_SCREEN", true);
    c.ui.system_focus  = resolve_bool(toml, have_toml, "ui", "system_focus",  "MONTAUK_SYSTEM_FOCUS", false);
    c.ui.cpu_scale     = resolve_string(toml, have_toml, "ui", "cpu_scale",   "MONTAUK_PROC_CPU_SCALE", "total");
    c.ui.gpu_scale     = resolve_string(toml, have_toml, "ui", "gpu_scale",   nullptr, "utilization");
    c.ui.time_format   = resolve_string(toml, have_toml, "ui", "time_format", "MONTAUK_TIME_FORMAT", "");

    // --- [process] ---
    c.process.max_procs    = resolve_int(toml, have_toml, "process", "max_procs",    "MONTAUK_MAX_PROCS", 256);
    c.process.enrich_top_n = resolve_int(toml, have_toml, "process", "enrich_top_n", "MONTAUK_ENRICH_TOP_N", c.process.max_procs);
    c.process.collector    = resolve_string(toml, have_toml, "process", "collector",  "MONTAUK_COLLECTOR", "auto");

    // --- [nvidia] ---
    c.nvidia.smi_path            = resolve_string(toml, have_toml, "nvidia", "smi_path",            "MONTAUK_NVIDIA_SMI_PATH", "auto");
    c.nvidia.smi_dev             = resolve_bool(toml, have_toml, "nvidia", "smi_dev",               "MONTAUK_NVIDIA_SMI_DEV", true);
    c.nvidia.smi_min_interval_ms = resolve_int(toml, have_toml, "nvidia", "smi_min_interval_ms",    "MONTAUK_SMI_MIN_INTERVAL_MS", 0);
    c.nvidia.pmon                = resolve_bool(toml, have_toml, "nvidia", "pmon",                   "MONTAUK_NVIDIA_PMON", true);
    c.nvidia.mem                 = resolve_bool(toml, have_toml, "nvidia", "mem",                    "MONTAUK_NVIDIA_MEM", true);
    c.nvidia.log_nvml            = resolve_bool(toml, have_toml, "nvidia", "log_nvml",               "MONTAUK_LOG_NVML", false);
    c.nvidia.gpu_debug           = resolve_bool(toml, have_toml, "nvidia", "gpu_debug",              "MONTAUK_GPU_DEBUG", false);
    c.nvidia.disable_nvml        = resolve_bool(toml, have_toml, "nvidia", "disable_nvml",           "MONTAUK_DISABLE_NVML", false);
    c.nvidia.nvml_path           = resolve_string(toml, have_toml, "nvidia", "nvml_path",            "MONTAUK_NVML_PATH", "");

    // --- [keybinds] ---
    populate_keybinds(c, toml, have_toml);

    return c;
  }();
  return cfg;
}

const UIConfig& ui_config() {
  static UIConfig uic = []{
    const auto& c = config();
    return UIConfig{
      c.colors.accent, c.colors.caution, c.colors.warning,
      c.colors.normal, c.colors.muted, c.colors.border, c.colors.binary,
      c.thresholds.proc_caution_pct, c.thresholds.proc_warning_pct
    };
  }();
  return uic;
}

void reset_ui_defaults() {
  g_ui.sort = SortMode::CPU;
  g_ui.scroll = 0;
  g_ui.system_focus = false;
  g_ui.show_disk = true;
  g_ui.show_net = true;
  g_ui.show_gpumon = true;
  g_ui.cpu_scale = UIState::CPUScale::Total;
  g_ui.gpu_scale = UIState::GPUScale::Utilization;
  g_ui.filter_query.clear();
  g_ui.search_mode = false;
}

} // namespace montauk::ui
