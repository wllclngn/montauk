#include "ui/Formatting.hpp"
#include "ui/Config.hpp"
#include "ui/widget/Canvas.hpp"
#include "util/Procfs.hpp"
#include <algorithm>
#include <chrono>
#include <clocale>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <list>
#include <mutex>
#include <sstream>
#include <unordered_map>
#include <langinfo.h>

namespace montauk::ui {

bool prefer_12h_clock_from_locale() {
  static std::once_flag init_flag;
  static bool result = false;

  std::call_once(init_flag, []{
    std::setlocale(LC_TIME, "");

#ifdef T_FMT
    const char* tfmt = nl_langinfo(T_FMT);
    if (tfmt && *tfmt) {
      std::string f = tfmt;
      if (f.find("%I") != std::string::npos || f.find("%p") != std::string::npos) {
        result = true;
      }
    }
#endif
  });

  return result;
}

std::string format_time_now(bool prefer12h) {
  std::time_t t = std::time(nullptr);
  std::tm lt{};
  localtime_r(&t, &lt);
  char buf[64];
  const char* fmt = prefer12h ? "%I:%M:%S %p %Z" : "%H:%M:%S %Z";
  if (std::strftime(buf, sizeof(buf), fmt, &lt) == 0) return std::string();
  if (prefer12h && buf[0] == '0') {
    return std::string(buf + 1);
  }
  return std::string(buf);
}

std::string format_date_now_locale() {
  std::time_t t = std::time(nullptr);
  std::tm lt{};
  localtime_r(&t, &lt);
  char buf[64];
  const char* fmt = "%x";
  if (std::strftime(buf, sizeof(buf), fmt, &lt) == 0) return std::string();
  return std::string(buf);
}

namespace {

// Current MONTAUK_PROC_ROOT + MONTAUK_SYS_ROOT overrides, joined as one cache
// key. The identity readers below cache their /proc//sys parses (hostname and
// kernel are session constants; scheduler refreshes at 1s), but the caches
// must not outlive a root redirection — tests point these env vars at fixture
// trees per test case and expect a fresh read.
std::string identity_root_key() {
  const char* p = std::getenv("MONTAUK_PROC_ROOT");
  const char* s = std::getenv("MONTAUK_SYS_ROOT");
  std::string key = p ? p : "";
  key += '\x1f';
  if (s) key += s;
  return key;
}

} // namespace

std::string read_hostname() {
  // Session constant — read /proc once per root and cache.
  static std::string cached_root;
  static std::string cached;
  static bool have = false;
  std::string root = identity_root_key();
  if (have && root == cached_root) return cached;
  auto txt = montauk::util::read_file_string("/proc/sys/kernel/hostname");
  std::string host = txt ? *txt : std::string();
  while (!host.empty() && (host.back() == '\n' || host.back() == '\r' || host.back() == ' '))
    host.pop_back();
  if (host.empty()) host = "unknown";
  cached = std::move(host);
  cached_root = std::move(root);
  have = true;
  return cached;
}

std::string read_kernel_version() {
  // Session constant — read /proc once per root and cache.
  static std::string cached_root;
  static std::string cached;
  static bool have = false;
  std::string root = identity_root_key();
  if (have && root == cached_root) return cached;
  auto txt = montauk::util::read_file_string("/proc/sys/kernel/osrelease");
  std::string ver = txt ? *txt : std::string();
  while (!ver.empty() && (ver.back() == '\n' || ver.back() == '\r' || ver.back() == ' '))
    ver.pop_back();
  if (ver.empty()) ver = "unknown";
  cached = std::move(ver);
  cached_root = std::move(root);
  have = true;
  return cached;
}

std::string read_scheduler() {
  // Can change at runtime (sched_ext load/unload) — refresh at most once
  // per second, same cache shape as read_cpu_freq_info. A root-override
  // change (fixture redirection) also invalidates.
  static auto last = std::chrono::steady_clock::time_point{};
  static std::string cached_root;
  static std::string cache;
  auto now = std::chrono::steady_clock::now();
  std::string root = identity_root_key();
  if (last.time_since_epoch().count() != 0 && root == cached_root) {
    auto dt = std::chrono::duration_cast<std::chrono::milliseconds>(now - last).count();
    if (dt < 1000) return cache;
  }
  std::string out = "CFS";
  auto txt = montauk::util::read_file_string("/sys/kernel/sched_ext/root/ops");
  bool resolved = false;
  if (txt) {
    std::string name = *txt;
    while (!name.empty() && (name.back() == '\n' || name.back() == '\r' || name.back() == ' '))
      name.pop_back();
    if (!name.empty()) { out = std::move(name); resolved = true; }
  }
  if (!resolved) {
    auto ver = montauk::util::read_file_string("/proc/sys/kernel/osrelease");
    if (ver) {
      int major = 0, minor = 0;
      auto dot = ver->find('.');
      if (dot != std::string::npos) {
        major = std::atoi(ver->c_str());
        minor = std::atoi(ver->c_str() + dot + 1);
      }
      if (major > 6 || (major == 6 && minor >= 6))
        out = "EEVDF";
    }
  }
  cache = std::move(out);
  cached_root = std::move(root);
  last = now;
  return cache;
}

std::string read_uptime_formatted() {
  auto txt = montauk::util::read_file_string("/proc/uptime");
  if (!txt) return "0D 0H 0M 0S";
  std::istringstream ss(*txt);
  double uptime_seconds = 0.0;
  ss >> uptime_seconds;
  
  uint64_t total_secs = (uint64_t)uptime_seconds;
  uint64_t days = total_secs / 86400;
  uint64_t hours = (total_secs % 86400) / 3600;
  uint64_t minutes = (total_secs % 3600) / 60;
  uint64_t seconds = total_secs % 60;
  
  std::ostringstream os;
  os << days << "D " << hours << "H " << minutes << "M " << seconds << "S";
  return os.str();
}

void read_loadavg(double& a1, double& a5, double& a15) {
  a1=a5=a15=0.0; 
  auto txt = montauk::util::read_file_string("/proc/loadavg"); 
  if (!txt) return;
  std::istringstream ss(*txt);
  ss >> a1 >> a5 >> a15;
}

CpuFreqInfo read_cpu_freq_info() {
  static auto last = std::chrono::steady_clock::time_point{}; 
  static CpuFreqInfo cache; 
  auto now = std::chrono::steady_clock::now();
  if (last.time_since_epoch().count()!=0) {
    auto dt = std::chrono::duration_cast<std::chrono::milliseconds>(now - last).count();
    if (dt < 1000) return cache;
  }
  CpuFreqInfo out;
  auto rd = [](const std::string& p)->std::string{ 
    auto s = montauk::util::read_file_string(p); 
    return s? *s : std::string(); 
  };
  auto to_num = [](const std::string& s)->long long{ 
    try { return std::stoll(s); } catch(...) { return 0; } 
  };
  std::string cur = rd("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq");
  if (!cur.empty()) { 
    long long khz = to_num(cur); 
    if (khz>0) { 
      out.has_cur = true; 
      out.cur_ghz = (double)khz / 1'000'000.0; 
    } 
  }
  std::string mx = rd("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq");
  if (!mx.empty()) { 
    long long khz = to_num(mx); 
    if (khz>0) { 
      out.has_max = true; 
      out.max_ghz = (double)khz / 1'000'000.0; 
    } 
  }
  out.governor = rd("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor");
  if (!out.governor.empty()) { 
    while(!out.governor.empty() && (out.governor.back()=='\n'||out.governor.back()=='\r')) 
      out.governor.pop_back(); 
  }
  std::string nt = rd("/sys/devices/system/cpu/intel_pstate/no_turbo");
  if (!nt.empty()) { 
    long long v = to_num(nt); 
    out.turbo = (v==0? "on":"off"); 
  } else {
    std::string boost = rd("/sys/devices/system/cpu/cpufreq/boost"); 
    if (!boost.empty()) { 
      long long v = to_num(boost); 
      out.turbo = (v!=0? "on":"off"); 
    }
  }
  cache = out; 
  last = now; 
  return out;
}


// EMA smoother for bar fill only
namespace {
  struct LRUCache {
    static constexpr size_t MAX_SIZE = 512;
    
    using Item = std::pair<std::string, double>;
    std::list<Item> items_;
    std::unordered_map<std::string, decltype(items_)::iterator> index_;
    
    double* get(const std::string& key) {
      auto it = index_.find(key);
      if (it == index_.end()) return nullptr;
      
      items_.splice(items_.begin(), items_, it->second);
      return &it->second->second;
    }
    
    void put(const std::string& key, double value) {
      auto it = index_.find(key);
      
      if (it != index_.end()) {
        items_.splice(items_.begin(), items_, it->second);
        it->second->second = value;
      } else {
        items_.emplace_front(key, value);
        index_[key] = items_.begin();
        
        if (items_.size() > MAX_SIZE) {
          const auto& last = items_.back();
          index_.erase(last.first);
          items_.pop_back();
        }
      }
    }
  };
}

double smooth_value(const std::string& key, double raw, double alpha) {
  static LRUCache cache;
  
  double* prev = cache.get(key);
  if (!prev) {
    cache.put(key, raw);
    return raw;
  }
  
  double smoothed = alpha * raw + (1.0 - alpha) * (*prev);
  cache.put(key, smoothed);
  return smoothed;
}

widget::Style severity_style(int severity) {
  const auto& uic = ui_config();
  if (severity >= 2) return widget::parse_sgr_style(uic.warning);
  if (severity >= 1) return widget::parse_sgr_style(uic.caution);
  return widget::Style{};
}

std::string sanitize_for_display(const std::string& s, size_t max_len) {
  std::string out;
  out.reserve(std::min(s.size(), max_len));
  
  for (size_t i = 0; i < s.size() && out.size() < max_len; ++i) {
    unsigned char c = static_cast<unsigned char>(s[i]);
    
    if (c >= 32 && c < 127) {
      out += c;
    } else if (c >= 0x80) {
      out += c;
    } else if (c == '\t') {
      out += ' ';
    } else {
      out += '?';
    }
  }

  return out;
}

std::string format_size(uint64_t bytes, int precision, bool include_tb) {
  const double kb = 1024.0, mb = kb * 1024.0, gb = mb * 1024.0, tb = gb * 1024.0;
  std::ostringstream os;
  if (precision > 0) { os.setf(std::ios::fixed); os << std::setprecision(precision); }

  if (include_tb && bytes >= static_cast<uint64_t>(tb)) {
    os << (bytes / tb) << "T";
  } else if (bytes >= static_cast<uint64_t>(gb)) {
    if (precision > 0) os << (bytes / gb) << "G";
    else               os << static_cast<int>(bytes / gb + 0.5) << "G";
  } else if (bytes >= static_cast<uint64_t>(mb)) {
    if (precision > 0) os << (bytes / mb) << "M";
    else               os << static_cast<int>(bytes / mb + 0.5) << "M";
  } else {
    os << static_cast<int>(bytes / kb + 0.5) << "K";
  }
  return os.str();
}

std::string format_size_kib(uint64_t kib, int precision, bool include_tb) {
  return format_size(kib * 1024ull, precision, include_tb);
}

} // namespace montauk::ui
