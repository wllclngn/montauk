// JsonSerializer -- the live monitor snapshot rendered to JSON, beside the
// Prometheus one (PrometheusSerializer.cpp). Same MetricsSnapshot model, a
// second renderer: an AI agent reads system state as structured JSON via
// `montauk --json`, exactly as it reads the analyzer's reports via
// `montauk_analyze --json`. Reuses include/util/json.h -- one JSON writer
// across the whole codebase, so the two surfaces cannot diverge in encoding.

#include "app/MetricsServer.hpp"
#include "ui/Formatting.hpp"
#include "util/sink.h"
#include "util/json.h"

#include <string>

namespace montauk::app {

std::string snapshot_to_json(const MetricsSnapshot& s) {
  montauk_sink sink;
  montauk_sink_init(&sink, -1);  // fd -1: never drains, buffer holds the doc
  montauk_json j;
  montauk_json_init(&j, &sink);

  montauk_json_obj_begin(&j);
  montauk_json_ku64(&j, "schema_version", 1u);

  // System specs -- the machine the snapshot describes.
  {
    std::string gpu = s.vram.name;
    if (gpu.empty() && !s.vram.devices.empty()) gpu = s.vram.devices.front().name;
    montauk_json_key(&j, "system");
    montauk_json_obj_begin(&j);
    montauk_json_kstr(&j, "cpu_model", s.cpu.model.c_str());
    montauk_json_ki64(&j, "physical_cores", s.cpu.physical_cores);
    montauk_json_ki64(&j, "logical_cpus", s.cpu.logical_threads);
    montauk_json_knum(&j, "mem_total_gib",
                      static_cast<double>(s.mem.total_kb) / (1024.0 * 1024.0));
    montauk_json_kstr(&j, "gpu", gpu.c_str());
    montauk_json_kstr(&j, "kernel", montauk::ui::read_kernel_version().c_str());
    montauk_json_kstr(&j, "scheduler", montauk::ui::read_scheduler().c_str());
    montauk_json_obj_end(&j);
  }

  // CPU utilization.
  {
    montauk_json_key(&j, "cpu");
    montauk_json_obj_begin(&j);
    montauk_json_knum(&j, "usage_pct", s.cpu.usage_pct);
    montauk_json_knum(&j, "user_pct", s.cpu.pct_user);
    montauk_json_knum(&j, "system_pct", s.cpu.pct_system);
    montauk_json_knum(&j, "iowait_pct", s.cpu.pct_iowait);
    montauk_json_knum(&j, "irq_pct", s.cpu.pct_irq);
    montauk_json_knum(&j, "steal_pct", s.cpu.pct_steal);
    if (s.cpu.has_freq) montauk_json_knum(&j, "freq_mhz_avg", s.cpu.freq_avg_mhz);
    montauk_json_knum(&j, "context_switches_per_sec", s.cpu.ctxt_per_sec);
    montauk_json_knum(&j, "interrupts_per_sec", s.cpu.intr_per_sec);
    if (!s.cpu.per_core_pct.empty()) {
      montauk_json_key(&j, "per_core_pct");
      montauk_json_arr_begin(&j);
      for (double p : s.cpu.per_core_pct) montauk_json_num(&j, p);
      montauk_json_arr_end(&j);
    }
    montauk_json_obj_end(&j);
  }

  // PMU hardware counters (present only when the core PMU opened).
  {
    montauk_json_key(&j, "pmu");
    montauk_json_obj_begin(&j);
    montauk_json_kbool(&j, "available", s.pmu.available ? 1 : 0);
    if (s.pmu.available) {
      montauk_json_knum(&j, "l2_misses_per_sec", s.pmu.l2_misses_per_sec);
      montauk_json_knum(&j, "l2_miss_pct", s.pmu.l2_miss_pct);
      montauk_json_knum(&j, "ipc", s.pmu.ipc);
      montauk_json_knum(&j, "cycles_per_l2_miss", s.pmu.cycles_per_l2_miss);
      montauk_json_knum(&j, "instructions_per_sec", s.pmu.instructions_per_sec);
      montauk_json_knum(&j, "context_switches_per_sec", s.pmu.context_switches_per_sec);
      montauk_json_knum(&j, "cpu_migrations_per_sec", s.pmu.cpu_migrations_per_sec);
      montauk_json_knum(&j, "branch_misses_per_sec", s.pmu.branch_misses_per_sec);
    }
    montauk_json_obj_end(&j);
  }

  // Memory.
  {
    montauk_json_key(&j, "memory");
    montauk_json_obj_begin(&j);
    montauk_json_ku64(&j, "total_kb", s.mem.total_kb);
    montauk_json_ku64(&j, "used_kb", s.mem.used_kb);
    montauk_json_ku64(&j, "available_kb", s.mem.available_kb);
    montauk_json_ku64(&j, "cached_kb", s.mem.cached_kb);
    montauk_json_ku64(&j, "buffers_kb", s.mem.buffers_kb);
    montauk_json_ku64(&j, "swap_total_kb", s.mem.swap_total_kb);
    montauk_json_ku64(&j, "swap_used_kb", s.mem.swap_used_kb);
    montauk_json_knum(&j, "used_pct", s.mem.used_pct);
    montauk_json_obj_end(&j);
  }

  // GPU / VRAM (aggregate + per device).
  {
    montauk_json_key(&j, "gpu");
    montauk_json_obj_begin(&j);
    montauk_json_kstr(&j, "name", s.vram.name.c_str());
    montauk_json_ku64(&j, "total_mb", s.vram.total_mb);
    montauk_json_ku64(&j, "used_mb", s.vram.used_mb);
    montauk_json_knum(&j, "used_pct", s.vram.used_pct);
    if (s.vram.has_util) montauk_json_knum(&j, "util_pct", s.vram.gpu_util_pct);
    if (s.vram.has_mem_util) montauk_json_knum(&j, "mem_util_pct", s.vram.mem_util_pct);
    if (s.vram.has_power) montauk_json_knum(&j, "power_draw_w", s.vram.power_draw_w);
    if (s.vram.has_power_limit) montauk_json_knum(&j, "power_limit_w", s.vram.power_limit_w);
    if (!s.vram.devices.empty()) {
      montauk_json_key(&j, "devices");
      montauk_json_arr_begin(&j);
      for (const auto& d : s.vram.devices) {
        montauk_json_obj_begin(&j);
        montauk_json_kstr(&j, "name", d.name.c_str());
        montauk_json_ku64(&j, "total_mb", d.total_mb);
        montauk_json_ku64(&j, "used_mb", d.used_mb);
        if (d.has_temp_edge) montauk_json_knum(&j, "temp_edge_c", d.temp_edge_c);
        if (d.has_temp_hotspot) montauk_json_knum(&j, "temp_hotspot_c", d.temp_hotspot_c);
        if (d.has_fan) montauk_json_knum(&j, "fan_speed_pct", d.fan_speed_pct);
        montauk_json_obj_end(&j);
      }
      montauk_json_arr_end(&j);
    }
    montauk_json_obj_end(&j);
  }

  // Thermal / power.
  {
    montauk_json_key(&j, "thermal");
    montauk_json_obj_begin(&j);
    if (s.thermal.has_temp) montauk_json_knum(&j, "cpu_max_c", s.thermal.cpu_max_c);
    if (s.thermal.has_fan) montauk_json_knum(&j, "fan_rpm", s.thermal.fan_rpm);
    if (s.thermal.has_power) montauk_json_knum(&j, "power_watts", s.thermal.power_watts);
    montauk_json_obj_end(&j);
  }

  // Network (aggregate + per interface).
  {
    montauk_json_key(&j, "network");
    montauk_json_obj_begin(&j);
    montauk_json_knum(&j, "agg_rx_bps", s.net.agg_rx_bps);
    montauk_json_knum(&j, "agg_tx_bps", s.net.agg_tx_bps);
    montauk_json_key(&j, "interfaces");
    montauk_json_arr_begin(&j);
    for (const auto& n : s.net.interfaces) {
      montauk_json_obj_begin(&j);
      montauk_json_kstr(&j, "name", n.name.c_str());
      montauk_json_knum(&j, "rx_bps", n.rx_bps);
      montauk_json_knum(&j, "tx_bps", n.tx_bps);
      montauk_json_obj_end(&j);
    }
    montauk_json_arr_end(&j);
    montauk_json_obj_end(&j);
  }

  // Disk (aggregate + per device).
  {
    montauk_json_key(&j, "disk");
    montauk_json_obj_begin(&j);
    montauk_json_knum(&j, "total_read_bps", s.disk.total_read_bps);
    montauk_json_knum(&j, "total_write_bps", s.disk.total_write_bps);
    montauk_json_key(&j, "devices");
    montauk_json_arr_begin(&j);
    for (const auto& d : s.disk.devices) {
      montauk_json_obj_begin(&j);
      montauk_json_kstr(&j, "name", d.name.c_str());
      montauk_json_knum(&j, "read_bps", d.read_bps);
      montauk_json_knum(&j, "write_bps", d.write_bps);
      montauk_json_knum(&j, "util_pct", d.util_pct);
      montauk_json_obj_end(&j);
    }
    montauk_json_arr_end(&j);
    montauk_json_obj_end(&j);
  }

  // Filesystems.
  {
    montauk_json_key(&j, "filesystems");
    montauk_json_arr_begin(&j);
    for (const auto& m : s.fs.mounts) {
      montauk_json_obj_begin(&j);
      montauk_json_kstr(&j, "device", m.device.c_str());
      montauk_json_kstr(&j, "mountpoint", m.mountpoint.c_str());
      montauk_json_kstr(&j, "fstype", m.fstype.c_str());
      montauk_json_ku64(&j, "total_bytes", m.total_bytes);
      montauk_json_ku64(&j, "used_bytes", m.used_bytes);
      montauk_json_ku64(&j, "avail_bytes", m.avail_bytes);
      montauk_json_knum(&j, "used_pct", m.used_pct);
      montauk_json_obj_end(&j);
    }
    montauk_json_arr_end(&j);
  }

  // Processes: the aggregate counts + the ranked top-N.
  {
    montauk_json_key(&j, "processes");
    montauk_json_obj_begin(&j);
    montauk_json_ku64(&j, "total", s.total_processes);
    montauk_json_ku64(&j, "running", s.running_processes);
    montauk_json_ku64(&j, "sleeping", s.state_sleeping);
    montauk_json_ku64(&j, "zombie", s.state_zombie);
    montauk_json_ku64(&j, "threads", s.total_threads);
    montauk_json_key(&j, "top");
    montauk_json_arr_begin(&j);
    for (int i = 0; i < s.top_procs_count; ++i) {
      const auto& p = s.top_procs[i];
      montauk_json_obj_begin(&j);
      montauk_json_ki64(&j, "pid", p.pid);
      montauk_json_kstr(&j, "cmd", p.cmd.c_str());
      montauk_json_kstr(&j, "user", p.user_name.c_str());
      montauk_json_knum(&j, "cpu_pct", p.cpu_pct);
      montauk_json_ku64(&j, "rss_kb", p.rss_kb);
      if (p.has_gpu_util) montauk_json_knum(&j, "gpu_util_pct", p.gpu_util_pct);
      if (p.has_gpu_mem) montauk_json_ku64(&j, "gpu_mem_kb", p.gpu_mem_kb);
      montauk_json_obj_end(&j);
    }
    montauk_json_arr_end(&j);
    montauk_json_obj_end(&j);
  }

  montauk_json_obj_end(&j);
  montauk_sink_appendc(&sink, '\n');

  std::string out(sink.data, sink.len);
  montauk_sink_free(&sink);
  return out;
}

} // namespace montauk::app
