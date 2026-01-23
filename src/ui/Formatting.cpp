#include "ui/Formatting.hpp"
#include "ui/Terminal.hpp"
#include "util/Procfs.hpp"
#include <algorithm>
#include <chrono>
#include <clocale>
#include <cstdlib>
#include <ctime>
#include <cwchar>
#include <list>
#include <mutex>
#include <sstream>
#include <unordered_map>
#ifdef __linux__
#include <langinfo.h>
#endif

namespace montauk::ui {

// Helper: decode UTF-8 character to wchar_t, return bytes consumed (0 on error)
static int utf8_to_wchar(const char* s, size_t len, wchar_t* out) {
  if (len == 0 || !s) return 0;
  unsigned char c = s[0];

  if ((c & 0x80) == 0) {
    // ASCII
    *out = c;
    return 1;
  } else if ((c & 0xE0) == 0xC0 && len >= 2) {
    // 2-byte
    *out = ((c & 0x1F) << 6) | (s[1] & 0x3F);
    return 2;
  } else if ((c & 0xF0) == 0xE0 && len >= 3) {
    // 3-byte (includes CJK)
    *out = ((c & 0x0F) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F);
    return 3;
  } else if ((c & 0xF8) == 0xF0 && len >= 4) {
    // 4-byte
    *out = ((c & 0x07) << 18) | ((s[1] & 0x3F) << 12) |
           ((s[2] & 0x3F) << 6) | (s[3] & 0x3F);
    return 4;
  }
  return 0;  // Invalid
}

int display_cols(const std::string& s) {
  int cols = 0;
  for (size_t i = 0; i < s.size(); ) {
    // Skip ANSI escape sequences (CSI: \x1B[...m)
    if (s[i] == '\x1B' && i+1 < s.size() && s[i+1] == '[') {
      i += 2;
      while (i < s.size() && (s[i] < '@' || s[i] > '~')) i++;
      if (i < s.size()) i++; // skip final byte
      continue;
    }
    // Decode UTF-8 and use wcwidth for proper display width
    wchar_t wc;
    int len = utf8_to_wchar(s.c_str() + i, s.size() - i, &wc);
    if (len > 0) {
      int w = wcwidth(wc);
      cols += (w > 0) ? w : 1;  // wcwidth returns -1 for non-printable, use 1
      i += len;
    } else {
      // Invalid UTF-8, skip byte
      cols++;
      i++;
    }
  }
  return cols;
}

std::string take_cols(const std::string& s, int cols) {
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
    // Decode UTF-8 and check display width
    wchar_t wc;
    int len = utf8_to_wchar(s.c_str() + i, s.size() - i, &wc);
    if (len > 0) {
      int w = wcwidth(wc);
      if (w < 0) w = 1;  // Non-printable, assume 1
      // Don't exceed requested columns (important for wide chars)
      if (seen + w > cols) break;
      out.append(s, i, len);
      i += len;
      seen += w;
    } else {
      // Invalid UTF-8, skip byte
      out += s[i];
      i++;
      seen++;
    }
  }
  return out;
}

std::string trunc_pad(const std::string& s, int w) {
  if (w <= 0) return "";
  int cols = display_cols(s);
  if (cols == w) return s;
  if (cols < w) return s + std::string(w - cols, ' ');
  if (w <= 1) return take_cols(s, w);
  return take_cols(s, w - 1) + "…";
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
#else
  return false;
#endif
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

} // namespace montauk::ui
