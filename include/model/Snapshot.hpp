#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "model/Cpu.hpp"
#include "model/Net.hpp"
#include "model/Disk.hpp"
#include "model/Process.hpp"
#include "model/Thermal.hpp"
#include "model/Fs.hpp"

namespace montauk::model {

struct Memory {
  uint64_t total_kb{};
  uint64_t used_kb{};
  uint64_t cached_kb{};
  uint64_t buffers_kb{};
  uint64_t swap_total_kb{};
  uint64_t swap_used_kb{};
  double   used_pct{}; // 0..100
};

struct GpuVramDevice {
  std::string name;
  uint64_t total_mb{};
  uint64_t used_mb{};
  // Optional temps per device (°C)
  bool   has_temp_edge{false};
  double temp_edge_c{0.0};
  bool   has_temp_hotspot{false};
  double temp_hotspot_c{0.0};
  bool   has_temp_mem{false};
  double temp_mem_c{0.0};
  // Optional warning thresholds per sensor (°C)
  bool   has_thr_edge{false};
  double thr_edge_c{0.0};
  bool   has_thr_hotspot{false};
  double thr_hotspot_c{0.0};
  bool   has_thr_mem{false};
  double thr_mem_c{0.0};
};

struct GpuVram {
  std::vector<GpuVramDevice> devices;
  uint64_t total_mb{};
  uint64_t used_mb{};
  double   used_pct{}; // 0..100
  // Optional friendly name (e.g., "NVIDIA GeForce RTX 2060") if discoverable
  std::string name;
  // Optional instantaneous power draw in Watts if available via sysfs/hwmon
  bool    has_power{false};
  double  power_draw_w{0.0};
  // Optional power limit (Watts) and P-state (NVML)
  bool    has_power_limit{false};
  double  power_limit_w{0.0};
  bool    has_pstate{false};
  int     pstate{-1}; // 0..15 for P0..P15
  // Optional GPU utilization (aggregated across devices when multiple are present)
  bool    has_util{false};        // true if core utilization is available
  double  gpu_util_pct{0.0};      // SM/3D engine utilization percent (0..100)
  bool    has_mem_util{false};    // true if memory controller utilization available
  double  mem_util_pct{0.0};
  bool    has_encdec{false};      // true if encoder/decoder utilization available
  double  enc_util_pct{0.0};
  double  dec_util_pct{0.0};
};

struct AlertItem {
  std::string severity; // info|warn|crit
  std::string message;
};

struct NvmlDiag {
  bool available{false};
  int devices{0};
  int running_pids{0};
  int sampled_pids{0};
  uint64_t sample_age_ms{0};
  int last_error{0};
  bool mig_enabled{false};
};

struct Snapshot {
  uint64_t seq{};
  montauk::model::CpuSnapshot cpu;
  Memory   mem;
  GpuVram  vram;
  NetSnapshot net;
  DiskSnapshot disk;
  FsSnapshot fs;
  ProcessSnapshot procs;
  std::vector<AlertItem> alerts; // latest generated alerts with severity
  Thermal thermal;
  NvmlDiag nvml;
  struct ChurnDiag { int recent_2s_events{0}; int recent_2s_proc{0}; int recent_2s_sys{0}; } churn;
  // Active process collector indicator (e.g., "Event-Driven Netlink" or "Traditional /proc Scanner")
  std::string collector_name;
};

} // namespace montauk::model
