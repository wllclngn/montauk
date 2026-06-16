// prom_population — cross-run / cross-version statistical analysis over a
// population of bench `.prom` archives. This is the capability montauk_analyze
// gained from PANDEMONIUM's removed bench-analyze.py: montauk's `.events`
// reports analyze ONE trace; this analyzes a POPULATION of runs (one `.prom`
// per run) and answers "is version/scheduler X really better than Y, and how
// many runs would prove it."
//
// Generic by metric family: every gauge is a per-run scalar (the inferential
// unit). Cells are keyed by (metric, labels minus the compare axis); within a
// cell the runs are split by the compare axis (default `scheduler`, or
// `version` for the cross-release hunt) and compared with the full battery.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace montauk::pop {

struct PopOptions {
  std::string compare_axis = "scheduler";  // label (or "version") to split on
  std::string metric_filter;               // substring; empty = every family
  double quantile = 99.0;                   // within-run quantile (Path A)
  uint64_t seed = 1729;
  bool lower_is_better = true;
  bool emit_prom = true;
  bool full = false;  // Path A: within-run Games-Howell on the histograms
};

// Analyze the given `.prom` files as a population. Prints the report and
// (unless disabled) writes an analysis `.prom`. Returns a process exit code.
int run_population(const std::vector<std::string>& files, const PopOptions& opt);

// Localize cache misses across CPUs from a montauk --trace recording dir: sum
// montauk_pmu_l2_misses_per_cpu over the busy (storm) scrapes and report the
// per-CPU distribution + concentration. Answers "which cores eat the misses."
int run_l2_by_cpu(const std::string& dir);

// The single hottest CPU by L2-miss share over the busy window -- the same
// computation as run_l2_by_cpu, returned as data so the digest can fold it into
// the offender ranking even for a .prom-only recording (no .events needed).
struct HotCpu {
  bool found{false};
  int cpu{-1};
  double share_pct{0.0};    // top CPU's share of busy-window L2 misses
  double uniform_pct{0.0};  // 100 / cpu count (the even-spread baseline)
  int sev{0};               // 0 spread, 1 skewed, 2 concentrated (hotspot)
};
HotCpu l2_hot_cpu(const std::string& dir);

// All `*.prom` in `dir` except the analyzer's own `analysis-*` outputs.
std::vector<std::string> glob_proms(const std::string& dir);

// Format the montauk_system_info{} from a recording dir's scrapes into a
// human SYSTEM specs block (cpu, memory, gpu, kernel, scheduler) for the digest
// header. Empty string if no system-info line is present.
std::string system_info_block(const std::string& dir);

// Summarize montauk_thermal_*/montauk_power_watts across a recording's scrapes
// into a THERMAL/POWER block (peak/avg cpu temp, peak fan, avg/peak watts) for
// the digest. Empty string if none of those metrics are present.
std::string thermal_power_block(const std::string& dir);

}  // namespace montauk::pop
