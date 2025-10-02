#include "collectors/MemoryCollector.hpp"
#include "util/Procfs.hpp"

#include <charconv>
#include <string_view>

namespace montauk::collectors {

static inline uint64_t parse_u64(const std::string_view& sv) {
  uint64_t v = 0;
  auto s = sv;
  // strip non-digits on right (e.g., kB)
  while (!s.empty() && (s.back() < '0' || s.back() > '9')) s.remove_suffix(1);
  // strip spaces on left
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  std::from_chars(s.data(), s.data() + s.size(), v);
  return v;
}

bool MemoryCollector::sample(montauk::model::Memory& out) const {
  auto txt_opt = montauk::util::read_file_string("/proc/meminfo");
  if (!txt_opt) return false;
  const std::string& txt = *txt_opt;

  uint64_t mem_total = 0, mem_free = 0, mem_avail = 0, buffers = 0, cached = 0, swap_total = 0, swap_free = 0;
  size_t start = 0;
  while (start < txt.size()) {
    size_t end = txt.find('\n', start);
    if (end == std::string::npos) end = txt.size();
    std::string_view line(txt.data() + start, end - start);
    if (line.starts_with("MemTotal:")) mem_total = parse_u64(line.substr(9));
    else if (line.starts_with("MemFree:")) mem_free = parse_u64(line.substr(8));
    else if (line.starts_with("MemAvailable:")) mem_avail = parse_u64(line.substr(13));
    else if (line.starts_with("Buffers:")) buffers = parse_u64(line.substr(8));
    else if (line.starts_with("Cached:")) cached = parse_u64(line.substr(7));
    else if (line.starts_with("SwapTotal:")) swap_total = parse_u64(line.substr(10));
    else if (line.starts_with("SwapFree:")) swap_free = parse_u64(line.substr(9));
    start = end + 1;
  }

  out.total_kb = mem_total;
  if (mem_avail > 0) {
    out.used_kb = (mem_total > mem_avail) ? (mem_total - mem_avail) : 0;
  } else {
    uint64_t sum = mem_free + buffers + cached;
    out.used_kb = (mem_total > sum) ? (mem_total - sum) : 0;
  }
  out.swap_total_kb = swap_total;
  out.swap_used_kb  = (swap_total > swap_free) ? (swap_total - swap_free) : 0;
  out.used_pct = (out.total_kb > 0) ? (100.0 * static_cast<double>(out.used_kb) / static_cast<double>(out.total_kb)) : 0.0;
  return true;
}

} // namespace montauk::collectors

