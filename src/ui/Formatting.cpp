#include "ui/Formatting.hpp"
#include "ui/Terminal.hpp"
#include "util/Procfs.hpp"
#include <algorithm>
#include <chrono>
#include <clocale>
#include <cstdlib>
#include <ctime>
#include <sstream>
#include <unordered_map>
#ifdef __linux__
#include <langinfo.h>
#endif

namespace montauk::ui {

int u8_len(unsigned char c){
  if (c < 0x80) return 1;
  if ((c >> 5) == 0x6) return 2;
  if ((c >> 4) == 0xE) return 3;
  if ((c >> 3) == 0x1E) return 4;
  return 1;
}

int display_cols(const std::string& s){
  int cols = 0; 
  for (size_t i=0; i<s.size();){ 
    // Skip ANSI escape sequences
    if (s[i] == '\x1B' && i+1 < s.size() && s[i+1] == '[') {
      i += 2;
      while (i < s.size() && (s[i] < '@' || s[i] > '~')) i++;
      if (i < s.size()) i++; // skip final byte
      continue;
    }
    int len = u8_len((unsigned char)s[i]); 
    i += len; 
    cols += 1; 
  } 
  return cols;
}

std::string take_cols(const std::string& s, int cols){
  if (cols <= 0) return std::string();
  std::string out; 
  out.reserve(s.size());
  int seen = 0; 
  size_t i = 0;
  while (i < s.size() && seen < cols) {
    // Copy ANSI escape sequences without counting them
    if (s[i] == '\x1B' && i+1 < s.size() && s[i+1] == '[') {
      size_t start = i;
      i += 2;
      while (i < s.size() && (s[i] < '@' || s[i] > '~')) i++;
      if (i < s.size()) i++; // include final byte
      out.append(s, start, i - start);
      continue;
    }
    int len = u8_len((unsigned char)s[i]);
    if (i + (size_t)len > s.size()) len = 1;
    out.append(s, i, len);
    i += len; 
    seen += 1;
  }
  return out;
}

std::string trunc_pad(const std::string& s, int w) {
  if (w <= 0) return "";
  int cols = display_cols(s);
  if (cols == w) return s;
  if (cols < w) return s + std::string(w - cols, ' ');
  if (w <= 1) return take_cols(s, w);
  return take_cols(s, w - 1) + (use_unicode()? "…" : ".");
}

std::string rpad_trunc(const std::string& s, int w) {
  if (w <= 0) return "";
  int cols = display_cols(s);
  if (cols == w) return s;
  if (cols < w) return std::string(w - cols, ' ') + s;
  return take_cols(s, w);
}

std::string lr_align(int iw, const std::string& left, const std::string& right){
  if (iw <= 0) return std::string();
  int rvis = display_cols(right);
  int tlw = iw - rvis - 1; 
  if (tlw < 0) tlw = 0;
  std::string l = trunc_pad(left, tlw);
  int lvis = display_cols(l);
  int space = iw - lvis - rvis; 
  if (space < 0) space = 0;
  return l + std::string(space, ' ') + right;
}

bool prefer_12h_clock_from_locale() {
#ifdef __linux__
  static bool inited = false; 
  if (!inited) { 
    std::setlocale(LC_TIME, ""); 
    inited = true; 
  }
#ifdef T_FMT
  const char* tfmt = nl_langinfo(T_FMT);
  if (tfmt && *tfmt) {
    std::string f = tfmt;
    if (f.find("%I") != std::string::npos || f.find("%p") != std::string::npos) return true;
  }
#endif
#endif
  return false;
}

std::string format_time_now(bool prefer12h) {
  std::time_t t = std::time(nullptr);
  std::tm lt{};
#ifdef _GNU_SOURCE
  localtime_r(&t, &lt);
#else
  lt = *std::localtime(&t);
#endif
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
#ifdef _GNU_SOURCE
  localtime_r(&t, &lt);
#else
  lt = *std::localtime(&t);
#endif
  char buf[64];
  const char* fmt = "%x";
  if (std::strftime(buf, sizeof(buf), fmt, &lt) == 0) return std::string();
  return std::string(buf);
}

std::string read_hostname() {
  auto txt = montauk::util::read_file_string("/proc/sys/kernel/hostname");
  if (!txt) return "unknown";
  std::string host = *txt;
  while (!host.empty() && (host.back() == '\n' || host.back() == '\r' || host.back() == ' ')) 
    host.pop_back();
  return host.empty() ? "unknown" : host;
}

std::string read_kernel_version() {
  auto txt = montauk::util::read_file_string("/proc/sys/kernel/osrelease");
  if (!txt) return "unknown";
  std::string ver = *txt;
  while (!ver.empty() && (ver.back() == '\n' || ver.back() == '\r' || ver.back() == ' ')) 
    ver.pop_back();
  return ver.empty() ? "unknown" : ver;
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
double smooth_value(const std::string& key, double raw, double alpha) {
  static std::unordered_map<std::string, double> prev;
  auto it = prev.find(key);
  if (it == prev.end()) { prev.emplace(key, raw); return raw; }
  double sm = alpha * raw + (1.0 - alpha) * it->second;
  it->second = sm;
  return sm;
}

} // namespace montauk::ui
