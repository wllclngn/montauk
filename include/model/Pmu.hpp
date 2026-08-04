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
  uint64_t dtlb_load_misses{}; // HW_CACHE dTLB / READ / MISS
  uint64_t cache_misses{};     // PERF_COUNT_HW_CACHE_MISSES (last level)

  // CUMULATIVE totals since montauk opened the counters, NOT interval deltas
  // -- the only fields here with that semantic, which is why they are named
  // apart. A rate divides by wall time and inherits every source of variance a
  // latency gauge has; a total is invariant to clock scaling and thermals,
  // which is the whole property a counter baseline rests on. Summed from the
  // same per-CPU deltas the fields above carry, so a total and its rate cannot
  // describe different counters.
  uint64_t instructions_total{};
  uint64_t cycles_total{};
  uint64_t context_switches_total{};
  uint64_t cpu_migrations_total{};
  uint64_t branch_misses_total{};
  uint64_t l2_misses_total{};
  uint64_t dtlb_load_misses_total{};
  uint64_t cache_misses_total{};

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
  // can map a miss back to the right CPU/cache-domain.
  std::vector<int>      per_cpu_ids;
  std::vector<uint64_t> per_cpu_l2_misses;
  std::vector<uint64_t> per_cpu_l2_refs;
  std::vector<uint64_t> per_cpu_instructions;
  std::vector<uint64_t> per_cpu_cycles;

  // per-cache-domain L3 traffic. Each amd_l3 fd is opened on one cpumask CPU which
  // owns one L3 cache domain, so each entry is per-cache-domain traffic (kept separate,
  // not summed, so cross-domain behaviour stays visible). Zen2 (3600) has 2 cache domains.
  struct DomainL3 {
    int      domain_cpu{};  // the cpumask CPU representing this cache domain
    uint64_t accesses{};    // L3 access/lookup delta
    uint64_t misses{};      // L3 miss delta
    double   miss_pct{};    // 100 * misses / accesses
  };
  std::vector<DomainL3> l3_per_cache_domain;
  uint64_t l3_accesses_total{};
  uint64_t l3_misses_total{};

  // PER-PROCESS ATTRIBUTION. The counters above are per-CPU / system-wide and
  // need perf_event_paranoid <= 0, so on a default box (paranoid 2) they are
  // simply off. perf_event_open(pid=<owned>, cpu=-1) is permitted at paranoid 2
  // with NO privilege and NO sysctl, and answers the strictly more useful
  // question: WHICH process is thrashing the TLB rather than that someone is.
  // PMU was the one sensor with no per-process attribution; GPU and thermal are
  // the precedent.
  //
  // inherit=1, so a counter follows threads and children created AFTER the
  // attach. Threads that already existed when montauk attached are NOT counted
  // -- stated because it decides how a measurement is set up (attach before the
  // workload spawns its pool, not mid-run).
  struct ProcCounters {
    int32_t  pid{};
    char     comm[64]{};
    // Interval deltas.
    uint64_t instructions{}, cycles{}, dtlb_load_misses{}, cache_misses{};
    double   ipc{};
    // Cumulative since attach -- the form a baseline compares, invariant to
    // clock scaling and thermals in a way a rate is not.
    uint64_t instructions_total{}, cycles_total{};
    uint64_t dtlb_load_misses_total{}, cache_misses_total{};
    // Derived, per thousand instructions: the scale-free form, so a short run
    // and a long one over the same workload are directly comparable.
    double   dtlb_misses_per_kilo_instr{}, cache_misses_per_kilo_instr{};
  };
  bool per_process_available{false};
  // Per-process counts exclude kernel time. Forced at
  // perf_event_paranoid >= 2, which is the ordinary distro default, so
  // this is the common case rather than the exception.
  bool per_process_user_only{false};
  std::vector<ProcCounters> per_process;

  // Seconds elapsed since the previous sample (for per-second rate derivation).
  double interval_s{};

  // Per-second rates over the interval (convenience for serializers/UI).
  double instructions_per_sec{};
  double cycles_per_sec{};
  double l2_misses_per_sec{};
};

} // namespace montauk::model
