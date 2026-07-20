// Shared /proc/PID parsing and top-K ranking, factored out of
// ProcessCollector/NetlinkProcessCollector/KernelProcessCollector, which
// each hand-rolled their own copy of some or all of this.
#pragma once
#include "util/Procfs.hpp"
#include "util/Churn.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "sublimation_pack.h"  // after std headers (c23_compat unreachable macro)

namespace montauk::collectors {

// Steady-clock timestamp in seconds, shared by the rate-delta collectors.
inline double now_secs() {
  using namespace std::chrono;
  return duration_cast<duration<double>>(steady_clock::now().time_since_epoch()).count();
}

// Parse the (comm)-delimited fields of a /proc/PID/stat line. comm may
// itself contain spaces/parens, so the value between the first '(' and the
// last ')' is taken verbatim; everything after is whitespace-delimited.
// Parses in place over the line (this runs per process per cycle); a field
// that fails to parse leaves its out-param untouched, like the istringstream
// extraction it replaced.
inline bool parse_stat_line(const std::string& content, char& state,
                             uint64_t& utime, uint64_t& stime,
                             int64_t& rss_pages, std::string& comm) {
  const auto lp = content.find('(');
  const auto rp = content.rfind(')');
  if (lp == std::string::npos || rp == std::string::npos || rp < lp) return false;
  comm.assign(content, lp + 1, rp - lp - 1);
  const char* p = content.data() + rp + 1;
  const char* const end = content.data() + content.size();
  auto next_field = [&]() {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n')) ++p;
    const char* b = p;
    while (p < end && *p != ' ' && *p != '\t' && *p != '\n') ++p;
    return std::pair{b, p};
  };
  {
    auto [b, e] = next_field();  // state
    if (b < e) state = *b;
  }
  (void)next_field();  // ppid (no caller uses it)
  // Skip fields up to utime (9 fields: pgrp..cmajflt).
  for (int i = 0; i < 9; ++i) (void)next_field();
  { auto [b, e] = next_field(); std::from_chars(b, e, utime); }
  { auto [b, e] = next_field(); std::from_chars(b, e, stime); }
  // Skip: cutime, cstime, priority, nice, num_threads, itrealvalue, starttime
  // (7 fields), then vsize.
  for (int i = 0; i < 8; ++i) (void)next_field();
  { auto [b, e] = next_field(); std::from_chars(b, e, rss_pages); }
  return true;
}

// Total jiffies from the aggregate "cpu " line of /proc/stat. Only the first
// line is examined; the per-core block below it is never touched, so this
// stays cheap for the collectors that re-read it every cycle.
inline uint64_t read_cpu_total() {
  auto txt = montauk::util::read_file_string("/proc/stat");
  if (!txt) return 0;
  std::string_view first(*txt);
  if (auto nl = first.find('\n'); nl != std::string_view::npos) first = first.substr(0, nl);
  auto pos = first.find(' ');
  if (pos == std::string_view::npos) return 0;
  std::string_view rest = first.substr(pos + 1);
  uint64_t vals[8]{}; int i = 0; size_t start = 0;
  while (i < 8 && start < rest.size()) {
    while (start < rest.size() && (rest[start] == ' ' || rest[start] == '\t')) ++start;
    size_t end = start;
    while (end < rest.size() && rest[end] >= '0' && rest[end] <= '9') ++end;
    if (end > start) { std::from_chars(rest.data() + start, rest.data() + end, vals[i++]); }
    start = end + 1;
  }
  uint64_t total = 0;
  for (int j = 0; j < 8; ++j) total += vals[j];
  return total;
}

// Count per-core "cpuN" lines of /proc/stat (aggregate "cpu " line skipped).
inline unsigned read_cpu_count() {
  auto txt = montauk::util::read_file_string("/proc/stat");
  if (!txt) return 1;
  const std::string& s = *txt;
  unsigned count = 0; bool first = true;
  size_t start = 0;
  while (start < s.size()) {
    size_t end = s.find('\n', start);
    if (end == std::string::npos) end = s.size();
    std::string_view line(s.data() + start, end - start);
    if (line.starts_with("cpu")) {
      if (first) { first = false; }
      else if (line.size() >= 4 && line[3] >= '0' && line[3] <= '9') count++;
    } else if (!first) {
      break;  // stop after cpu block
    }
    start = end + 1;
  }
  if (count == 0) count = 1;
  return count;
}

inline std::string read_exe_path(int32_t pid) {
  auto link = montauk::util::read_symlink(std::string("/proc/") + std::to_string(pid) + "/exe");
  if (!link) return {};
  return *link;
}

// uid -> user name via /etc/passwd, cached. Mutex-guarded and negative-caching
// (an unknown uid caches its numeric string) so repeated misses stay cheap.
inline std::string user_name_cached(uint32_t uid) {
  static std::mutex cache_mutex;
  static std::unordered_map<uint32_t, std::string> cache;

  {
    std::lock_guard<std::mutex> lock(cache_mutex);
    auto it = cache.find(uid);
    if (it != cache.end()) return it->second;
  }

  std::string name;
  std::ifstream pw("/etc/passwd");
  std::string pl;
  bool found = false;

  while (std::getline(pw, pl)) {
    auto c1 = pl.find(':');
    if (c1 == std::string::npos) continue;
    auto c2 = pl.find(':', c1 + 1);
    if (c2 == std::string::npos) continue;
    auto c3 = pl.find(':', c2 + 1);
    if (c3 == std::string::npos) continue;

    uint32_t fuid = std::strtoul(pl.c_str() + c2 + 1, nullptr, 10);
    if (fuid == uid) {
      name = pl.substr(0, c1);
      found = true;
      break;
    }
  }

  if (!found) {
    name = std::to_string(uid);
  }

  {
    std::lock_guard<std::mutex> lock(cache_mutex);
    cache.emplace(uid, name);
  }

  return name;
}

struct StatusInfo {
  std::string user;
  int thread_count{1};
};

// User name and thread count from /proc/PID/status.
inline StatusInfo info_from_status(int32_t pid) {
  StatusInfo info;
  auto path = std::string("/proc/") + std::to_string(pid) + "/status";
  std::optional<std::string> txt;
  try { txt = montauk::util::read_file_string(path); }
  catch (...) { txt = std::nullopt; montauk::util::note_churn(montauk::util::ChurnKind::Proc); }
  if (!txt) return info;
  const std::string& s = *txt;
  size_t start = 0;
  while (start < s.size()) {
    size_t end = s.find('\n', start);
    if (end == std::string::npos) end = s.size();
    std::string_view line(s.data() + start, end - start);
    if (line.starts_with("Uid:")) {
      uint32_t uid = 0;
      size_t p = 4;
      while (p < line.size() && (line[p] == ' ' || line[p] == '\t')) ++p;
      std::from_chars(line.data() + p, line.data() + line.size(), uid);
      info.user = user_name_cached(uid);
    } else if (line.starts_with("Threads:")) {
      size_t p = 8;
      while (p < line.size() && (line[p] == ' ' || line[p] == '\t')) ++p;
      std::from_chars(line.data() + p, line.data() + line.size(), info.thread_count);
    }
    start = end + 1;
  }
  return info;
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

// Truncate v to its top-k entries by cpu_pct (descending) in sorted order.
// One stable pack index sort (sublimation_pack_sort_f64) covers both the old
// select-then-sort steps: the index sort orders every row by key without
// moving the structs, then only the kept top-k rows are gathered. Stable on
// equal cpu_pct (original order kept), where the old nth_element/std::sort
// pair left tie order arbitrary.
template <typename T>
void top_k_by_cpu_pct(std::vector<T>& v, size_t k) {
  const size_t n = v.size();
  if (n < 2) {
    if (n > k) v.resize(k);
    return;
  }
  std::vector<double> keys(n);
  std::vector<uint32_t> idx(n);
  for (size_t i = 0; i < n; ++i) {
    keys[i] = static_cast<double>(v[i].cpu_pct);
    idx[i] = static_cast<uint32_t>(i);
  }
  sublimation_pack_sort_f64(keys.data(), idx.data(), n, true);
  const size_t keep = n < k ? n : k;
  std::vector<T> out;
  out.reserve(keep);
  for (size_t i = 0; i < keep; ++i) out.push_back(std::move(v[idx[i]]));
  v = std::move(out);
}

}  // namespace montauk::collectors
