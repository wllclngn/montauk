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

  // Derived aggregate metrics.
  double ipc{};               // instructions / cycles
  double l2_miss_pct{};       // 100 * l2_misses / l2_refs
  double cycles_per_l2_miss{};// cycles / l2_misses

  // Per-logical-CPU interval deltas (index == logical CPU id order).
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
