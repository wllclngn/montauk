#pragma once
#include <unordered_map>
#include <unordered_set>
#include <chrono>

namespace montauk::collectors {

// Minimal per-process GPU utilization collector using Linux DRM fdinfo.
// Supports a subset of AMD/Intel fdinfo formats to attribute per-PID GPU%.
// - Intel (i915/xe): parses drm-cycles-* and drm-total-cycles-* counters and
//   computes utilization from deltas.
// - AMD (amdgpu new): parses drm-engine-*(ns) counters and computes busy
//   utilization from time delta between samples.
// - Per-process VRAM: parses drm-memory-vram (KiB) when present.
// Returns best-effort maps. Values are 0..100 integers.
class FdinfoProcessCollector {
public:
  using Clock = std::chrono::steady_clock;
  // Minimal public helper structs to allow test and parser helpers access
  struct IntelCycles { uint64_t cycles_rcs{0}, total_rcs{0}; uint64_t cycles_ccs{0}, total_ccs{0}; uint64_t cycles_vcs{0}, total_vcs{0}; };
  struct AmdEngines  { uint64_t gfx_ns{0}, compute_ns{0}, enc_ns{0}, dec_ns{0}; };

  // Populate per-PID GPU% and optional GPU memory (KB). running_pids is filled with
  // PIDs that have DRM fdinfo entries this cycle. Returns true if any data observed.
  [[nodiscard]] bool sample(std::unordered_map<int,int>& pid_to_gpu,
              std::unordered_map<int, uint64_t>& pid_to_gpu_mem_kb,
              std::unordered_set<int>& running_pids);

private:
  struct LastSample { IntelCycles intel{}; AmdEngines amd{}; Clock::time_point tp{}; };
  std::unordered_map<int, LastSample> last_;
};

} // namespace montauk::collectors
