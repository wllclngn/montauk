// Shared /proc/PID parsing and top-K ranking, factored out of
// ProcessCollector/NetlinkProcessCollector/KernelProcessCollector, which
// each hand-rolled their own copy of some or all of this.
#pragma once
#include "util/Procfs.hpp"
#include "util/Churn.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace montauk::collectors {

// Parse the (comm)-delimited fields of a /proc/PID/stat line. comm may
// itself contain spaces/parens, so the value between the first '(' and the
// last ')' is taken verbatim; everything after is whitespace-delimited.
inline bool parse_stat_line(const std::string& content, char& state,
                             int32_t& ppid, uint64_t& utime, uint64_t& stime,
                             int64_t& rss_pages, std::string& comm) {
  auto lp = content.find('(');
  auto rp = content.rfind(')');
  if (lp == std::string::npos || rp == std::string::npos || rp < lp) return false;
  comm = content.substr(lp + 1, rp - lp - 1);
  std::string rest = content.substr(rp + 2);
  std::istringstream ss(rest);
  ss >> state;  // state
  ss >> ppid;   // ppid
  // Skip fields up to utime (9 fields).
  for (int i = 0; i < 9; i++) { std::string tmp; ss >> tmp; }
  ss >> utime; ss >> stime;
  // Skip: cutime, cstime, priority, nice, num_threads, itrealvalue, starttime
  // (7 fields).
  for (int i = 0; i < 7; i++) { std::string tmp; ss >> tmp; }
  // Next two fields are vsize (bytes) then rss (pages). Discard vsize, keep
  // rss.
  {
    unsigned long long vsize_bytes = 0;
    ss >> vsize_bytes;
  }
  ss >> rss_pages;
  return true;
}

// Read /proc/PID/cmdline, turning its NUL-separated argv into a single
// space-joined string. Union of every prior copy's guards: an empty read
// short-circuits before the join loop, and read_file_bytes is defensively
// try/catch'd (it does not itself throw, but callers relied on the guard).
inline std::string read_cmdline(int32_t pid) {
  auto path = std::string("/proc/") + std::to_string(pid) + "/cmdline";
  std::optional<std::vector<unsigned char>> bytes;
  try {
    bytes = montauk::util::read_file_bytes(path);
  } catch (...) {
    bytes = std::nullopt;
    montauk::util::note_churn(montauk::util::ChurnKind::Proc);
  }
  if (!bytes || bytes->empty()) return {};
  std::string out;
  out.reserve(bytes->size());
  bool sep = true;
  for (auto b : *bytes) {
    if (b == 0) {
      if (!sep) { out.push_back(' '); sep = true; }
    } else {
      out.push_back(static_cast<char>(b));
      sep = false;
    }
  }
  if (!out.empty() && out.back() == ' ') out.pop_back();
  return out;
}

// Truncate v to its top-k entries by cpu_pct (descending), then sort those k
// entries the same way. nth_element partitions in O(n), avoiding a full
// O(n log n) sort of every process when only the top-K are kept.
template <typename T>
void top_k_by_cpu_pct(std::vector<T>& v, size_t k) {
  if (v.size() > k) {
    auto nth = v.begin() + static_cast<std::ptrdiff_t>(k);
    std::nth_element(v.begin(), nth, v.end(),
                      [](const T& a, const T& b) { return a.cpu_pct > b.cpu_pct; });
    v.resize(k);
  }
  std::sort(v.begin(), v.end(),
            [](const T& a, const T& b) { return a.cpu_pct > b.cpu_pct; });
}

}  // namespace montauk::collectors
