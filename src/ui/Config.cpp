#include "ui/Config.hpp"
#include "ui/Terminal.hpp"
#include <algorithm>
#include <cctype>
#include "util/AsciiLower.hpp"
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
  // Accept both MONTAUK_ and montauk_ prefixes
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

const UIConfig& ui_config() {
  static UIConfig cfg = []{
    UIConfig c{};
    // Defaults use terminal's 16-color palette (respects user's theme)
    // Standard terminals: 11=bright yellow, 9=bright red, 1=red
    // User can override via MONTAUK_*_IDX env vars
    int acc_idx = getenv_int("MONTAUK_ACCENT_IDX", 11);  // bright yellow (or user's color11)
    int cau_idx = getenv_int("MONTAUK_CAUTION_IDX", 9);  // bright red (or user's color9)
    int war_idx = getenv_int("MONTAUK_WARNING_IDX", 1);  // red (or user's color1)
    c.accent  = sgr_palette_idx(acc_idx);
    c.caution = sgr_palette_idx(cau_idx);
    c.warning = sgr_palette_idx(war_idx);

    c.caution_pct = getenv_int("MONTAUK_PROC_CAUTION_PCT", 60);
    c.warning_pct = getenv_int("MONTAUK_PROC_WARNING_PCT", 80);
    
    return c;
  }();
  return cfg;
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
