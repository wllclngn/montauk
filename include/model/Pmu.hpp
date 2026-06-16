#pragma once
#include <cstdint>
#include <vector>

namespace montauk::model {

// Hardware performance counter snapshot (perf_event_open counting mode).
// All counts are DELTAS over the most recent sample interval (interval_s),
// not lifetime totals — mirroring the delta semantics of CpuSnapshot.
struct PmuSnapshot {
  bool available{false};     // core PMU counters opened successfully
  bool l3_available{false};  // amd_l3 uncore PMU present and opened
  int  nr_cpus{};            // number of online logical CPUs with core fds

  // Aggregate (summed across all logical CPUs) deltas for this interval.
  uint64_t l2_misses{};      // PERF_TYPE_RAW 0x077e (L2 misses, Zen2)
  uint64_t l2_refs{};        // PERF_TYPE_RAW 0x077d (L2 references, Zen2)
  uint64_t instructions{};   // PERF_COUNT_HW_INSTRUCTIONS
  uint64_t cycles{};         // PERF_COUNT_HW_CPU_CYCLES
  uint64_t context_switches{}; // PERF_COUNT_SW_CONTEXT_SWITCHES
  uint64_t cpu_migrations{};   // PERF_COUNT_SW_CPU_MIGRATIONS
  uint64_t branch_misses{};    // PERF_COUNT_HW_BRANCH_MISSES

  // Per-second rates for the scheduler-relevant counters.
  double context_switches_per_sec{};
  double cpu_migrations_per_sec{};
  double branch_misses_per_sec{};

  // Derived aggregate metrics.
  double ipc{};               // instructions / cycles
  double l2_miss_pct{};       // 100 * l2_misses / l2_refs
  double cycles_per_l2_miss{};// cycles / l2_misses

  // Per-logical-CPU interval deltas. Index is the online-CPU slot (0..nr_cpus);
  // per_cpu_ids[i] is that slot's actual logical CPU id (NOT equal to i on a
  // sparse online set, e.g. a restrict_cpus core-count sweep), so a consumer
  // can map a miss back to the right CPU/CCX.
  std::vector<int>      per_cpu_ids;
  std::vector<uint64_t> per_cpu_l2_misses;
  std::vector<uint64_t> per_cpu_l2_refs;
  std::vector<uint64_t> per_cpu_instructions;
  std::vector<uint64_t> per_cpu_cycles;

  // Per-CCX L3 traffic. Each amd_l3 fd is opened on one cpumask CPU which
  // owns one L3/CCX domain, so each entry is PER-CCX traffic (kept separate,
  // not summed, so cross-CCX behaviour stays visible). Zen2 (3600) has 2 CCX.
  struct CcxL3 {
    int      domain_cpu{};  // the cpumask CPU representing this CCX
    uint64_t accesses{};    // L3 access/lookup delta
    uint64_t misses{};      // L3 miss delta
    double   miss_pct{};    // 100 * misses / accesses
  };
  std::vector<CcxL3> l3_per_ccx;
  uint64_t l3_accesses_total{};
  uint64_t l3_misses_total{};

  // Seconds elapsed since the previous sample (for per-second rate derivation).
  double interval_s{};

  // Per-second rates over the interval (convenience for serializers/UI).
  double instructions_per_sec{};
  double cycles_per_sec{};
  double l2_misses_per_sec{};
};

} // namespace montauk::model
