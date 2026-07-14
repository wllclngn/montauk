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
#include <map>
#include <string>
#include <vector>

namespace montauk::pop {

struct PopOptions {
  std::string compare_axis = "scheduler";  // label to split on: any prom label,
                                           // plus synthetic version/commit/capture
                                           // (capture = per-run filename stamp, so
                                           // an uncommitted A/B still separates)
  std::string metric_filter;               // substring; empty = every family
  double quantile = 99.0;                   // within-run quantile (Path A)
  uint64_t seed = 1729;
  bool lower_is_better = true;
  bool emit_prom = true;
  bool full = false;  // Path A: within-run Games-Howell on the histograms
  // Explicit A/B: input path -> comparison-group name, injected as a synthetic
  // `group` label. Set by --group NAME=path; when non-empty the CLI forces
  // compare_axis="group". Lets two run-sets whose committed labels are identical
  // (an in-place kernel A/B: same scheduler, same version, same commit) compare
  // on their per-run distributions -- the bimodal cliff A/B that `capture`
  // (per-filename stamp) cannot express for same-named per-run `.prom` files.
  std::map<std::string, std::string> file_group;
  // Pair selector: "adjacent" | "all" | "vs-best". Empty = auto (adjacent for
  // the ordered axes version/capture, all for categorical axes). All-pairs is
  // O(V^2) in axis values; adjacent is the archive default.
  std::string pairs;
  // Version-ordered change-point view (the rank-scan trajectory engine)
  // instead of the pairwise comparison engine.
  bool trajectory = false;
  // Trajectory knobs, operator-supplied: permutation count for the joint
  // null (ignored when the split space is small enough to enumerate), the
  // familywise alpha for the dense/sparse pair, and the Cliff's-delta
  // magnitude floor below which a boundary is not reported.
  int traj_perms = 999;
  double traj_alpha = 0.05;
  double traj_min_effect = 0.147;
  // Population pool size; 0 = MONTAUK_POP_THREADS env, else all cores.
  int threads = 0;
  // Metric-family aliasing across producer renames (--alias OLD=NEW,
  // repeatable, exact match, no chaining). montauk holds the mechanism only;
  // the mapping is operator input.
  std::map<std::string, std::string> family_alias;
  // Axis-value display aliasing (--alias-axis OLD=NEW), replacing any
  // hardcoded display compression.
  std::map<std::string, std::string> axis_alias;
  // Labels dropped from cell identity (--drop-label L, repeatable): the
  // generic answer to high-cardinality foreign archives and to co-moving
  // label pairs beyond the built-in version/commit rule.
  std::vector<std::string> drop_labels;
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

// Structured system specs parsed from a recording dir's montauk_system_info{}
// scrape -- the data behind system_info_block(), so a JSON digest can emit
// these fields directly instead of re-parsing the text block.
struct SystemInfo {
  bool found{false};
  std::string cpu_model, physical_cores, logical_cpus, cache_domains,
      mem_total_gib, gpu, kernel, sched;
};
SystemInfo system_info_data(const std::string& dir);

// Format the montauk_system_info{} from a recording dir's scrapes into a
// human SYSTEM specs block (cpu, memory, gpu, kernel, scheduler) for the digest
// header. Empty string if no system-info line is present.
std::string system_info_block(const std::string& dir);

// One scx ejection event, structured -- the data behind scx_stability_block()'s
// "EJECTED ..." lines.
struct ScxEjection {
  std::string scheduler, reason, phase, cores;
};

// Structured scx stability data -- crash/ejection + clean-room + watchdog
// proximity, the data behind scx_stability_block().
struct ScxStability {
  std::vector<ScxEjection> ejections;
  std::string cleanroom_verdict, cleanroom_detail;
  double watchdog_worst_pct{-1.0};  // -1 = not present
  std::string watchdog_where;
};
ScxStability scx_stability_data(const std::string& dir);

// CRASH/EJECTION + CLEAN-ROOM + watchdog-proximity, formatted to LEAD the digest
// (a scheduler that got ejected invalidates every latency number under it).
// Scrapes the montauk_scx_ejected / montauk_cleanroom / montauk_watchdog_proximity
// markers bench-enduser writes into the recording. Empty when none are present.
std::string scx_stability_block(const std::string& dir);

// Structured thermal/power aggregates -- the data behind thermal_power_block().
// A `*_n == 0` (or `energy_joules_total < 0`) field means that metric family
// was never scraped in this recording.
struct ThermalPower {
  double temp_peak_c{0.0}, temp_avg_c{0.0}; int temp_n{0};
  double fan_peak_rpm{0.0};
  double power_avg_w{0.0}, power_peak_w{0.0}; int power_n{0};
  double energy_joules_total{-1.0};
  double freq_avg_mhz{0.0}, freq_peak_mhz{0.0}; int freq_n{0};
  double energy_per_instr_pj{0.0}; int epi_n{0};
  double ctx_switches_per_sec{0.0}; int ctx_n{0};
  double migrations_per_sec{0.0}; int mig_n{0};
  double branch_misses_per_sec{0.0}; int br_n{0};
  std::string dominant_cstate; double dominant_cstate_pct{-1.0};
};
ThermalPower thermal_power_data(const std::string& dir);

// Summarize montauk_thermal_*/montauk_power_watts across a recording's scrapes
// into a THERMAL/POWER block (peak/avg cpu temp, peak fan, avg/peak watts) for
// the digest. Empty string if none of those metrics are present.
std::string thermal_power_block(const std::string& dir);

}  // namespace montauk::pop
