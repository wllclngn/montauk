#include "app/MetricsServer.hpp"
#include "model/Trace.hpp"
#include "ui/Formatting.hpp"
#include <charconv>
#include <cstdio>
#include <algorithm>
#include <string>

namespace {

void append_double(std::string& out, double v) {
  char buf[32];
  auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf), v);
  if (ec == std::errc{}) {
    out.append(buf, ptr);
  } else {
    out += '0';
  }
}

void append_uint(std::string& out, uint64_t v) {
  char buf[24];
  auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf), v);
  out.append(buf, ptr);
}

void append_int(std::string& out, int v) {
  char buf[16];
  auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf), v);
  out.append(buf, ptr);
}


void append_escaped(std::string& out, std::string_view sv, size_t max_len = 0) {
  size_t limit = (max_len > 0) ? std::min(sv.size(), max_len) : sv.size();
  for (size_t i = 0; i < limit; ++i) {
    char c = sv[i];
    if (c == '\\') out += "\\\\";
    else if (c == '"') out += "\\\"";
    else if (c == '\n') out += "\\n";
    else out += c;
  }
}

void emit_header(std::string& out, const char* name, const char* help, const char* type) {
  out += "# HELP ";  out += name;  out += ' ';  out += help;  out += '\n';
  out += "# TYPE ";  out += name;  out += ' ';  out += type;  out += '\n';
}

void emit_gauge_d(std::string& out, const char* name, double value) {
  out += name;  out += ' ';  append_double(out, value);  out += '\n';
}

void emit_gauge_u(std::string& out, const char* name, uint64_t value) {
  out += name;  out += ' ';  append_uint(out, value);  out += '\n';
}

void emit_gauge_i(std::string& out, const char* name, int value) {
  out += name;  out += ' ';  append_int(out, value);  out += '\n';
}

// 1-label variant: name{key="val"} value
void emit_labeled_d(std::string& out, const char* name,
                    const char* lk, std::string_view lv, double value) {
  out += name;  out += '{';  out += lk;  out += "=\"";
  append_escaped(out, lv);
  out += "\"} ";  append_double(out, value);  out += '\n';
}

void emit_labeled_u(std::string& out, const char* name,
                    const char* lk, std::string_view lv, uint64_t value) {
  out += name;  out += '{';  out += lk;  out += "=\"";
  append_escaped(out, lv);
  out += "\"} ";  append_uint(out, value);  out += '\n';
}

// 2-label: name{k1="v1",k2="v2"} value
void emit_labeled_2d(std::string& out, const char* name,
                     const char* k1, std::string_view v1,
                     const char* k2, std::string_view v2, double value) {
  out += name;  out += '{';
  out += k1;  out += "=\"";  append_escaped(out, v1);  out += "\",";
  out += k2;  out += "=\"";  append_escaped(out, v2, 32);  out += "\"} ";
  append_double(out, value);  out += '\n';
}

void emit_labeled_2u(std::string& out, const char* name,
                     const char* k1, std::string_view v1,
                     const char* k2, std::string_view v2, uint64_t value) {
  out += name;  out += '{';
  out += k1;  out += "=\"";  append_escaped(out, v1);  out += "\",";
  out += k2;  out += "=\"";  append_escaped(out, v2, 32);  out += "\"} ";
  append_uint(out, value);  out += '\n';
}

// 3-label: name{k1="v1",k2="v2",k3="v3"} value
void emit_labeled_3d(std::string& out, const char* name,
                     const char* k1, std::string_view v1,
                     const char* k2, std::string_view v2,
                     const char* k3, std::string_view v3, double value) {
  out += name;  out += '{';
  out += k1;  out += "=\"";  append_escaped(out, v1);  out += "\",";
  out += k2;  out += "=\"";  append_escaped(out, v2);  out += "\",";
  out += k3;  out += "=\"";  append_escaped(out, v3);  out += "\"} ";
  append_double(out, value);  out += '\n';
}

void emit_labeled_3u(std::string& out, const char* name,
                     const char* k1, std::string_view v1,
                     const char* k2, std::string_view v2,
                     const char* k3, std::string_view v3, uint64_t value) {
  out += name;  out += '{';
  out += k1;  out += "=\"";  append_escaped(out, v1);  out += "\",";
  out += k2;  out += "=\"";  append_escaped(out, v2);  out += "\",";
  out += k3;  out += "=\"";  append_escaped(out, v3);  out += "\"} ";
  append_uint(out, value);  out += '\n';
}

// 4-label: name{k1="v1",k2="v2",k3="v3",k4="v4"} value
void emit_labeled_4i(std::string& out, const char* name,
                     const char* k1, std::string_view v1,
                     const char* k2, std::string_view v2,
                     const char* k3, std::string_view v3,
                     const char* k4, std::string_view v4, int value) {
  out += name;  out += '{';
  out += k1;  out += "=\"";  append_escaped(out, v1);  out += "\",";
  out += k2;  out += "=\"";  append_escaped(out, v2);  out += "\",";
  out += k3;  out += "=\"";  append_escaped(out, v3);  out += "\",";
  out += k4;  out += "=\"";  append_escaped(out, v4);  out += "\"} ";
  append_int(out, value);  out += '\n';
}

// 5-label: name{k1="v1",...,k5="v5"} value
void emit_labeled_5i(std::string& out, const char* name,
                     const char* k1, std::string_view v1,
                     const char* k2, std::string_view v2,
                     const char* k3, std::string_view v3,
                     const char* k4, std::string_view v4,
                     const char* k5, std::string_view v5, int value) {
  out += name;  out += '{';
  out += k1;  out += "=\"";  append_escaped(out, v1);  out += "\",";
  out += k2;  out += "=\"";  append_escaped(out, v2);  out += "\",";
  out += k3;  out += "=\"";  append_escaped(out, v3);  out += "\",";
  out += k4;  out += "=\"";  append_escaped(out, v4);  out += "\",";
  out += k5;  out += "=\"";  append_escaped(out, v5);  out += "\"} ";
  append_int(out, value);  out += '\n';
}

} // anonymous namespace

namespace montauk::app {

std::string snapshot_to_prometheus(const MetricsSnapshot& s) {
  std::string out;
  out.reserve(8192);

  // System specs, emitted first so a report leads with the PC it ran on. This
  // is data montauk already collects (cpu model/cores, mem, gpu) plus the
  // kernel + active scheduler; hostname is intentionally omitted (identity,
  // not spec). Value 1, everything in labels -- one capture carries the specs.
  {
    auto san = [](std::string v) {
      for (char& c : v)
        if (c == '"' || c == '\\' || c == '\n') c = ' ';
      return v;
    };
    std::string gpu = s.vram.name;
    if (gpu.empty() && !s.vram.devices.empty()) gpu = s.vram.devices.front().name;
    char mem[32];
    std::snprintf(mem, sizeof(mem), "%.1f",
                  static_cast<double>(s.mem.total_kb) / (1024.0 * 1024.0));
    emit_header(out, "montauk_system_info",
                "System specs: cpu model, cores, memory, gpu, kernel, scheduler",
                "gauge");
    out += "montauk_system_info{cpu_model=\""; out += san(s.cpu.model);
    out += "\",physical_cores=\""; out += std::to_string(s.cpu.physical_cores);
    out += "\",logical_cpus=\""; out += std::to_string(s.cpu.logical_threads);
    out += "\",mem_total_gib=\""; out += mem;
    out += "\",gpu=\""; out += san(gpu);
    out += "\",kernel=\""; out += san(montauk::ui::read_kernel_version());
    out += "\",sched=\""; out += san(montauk::ui::read_scheduler());
    if (!s.pmu.l3_per_cache_domain.empty()) {
      out += "\",cache_domain=\""; out += std::to_string(s.pmu.l3_per_cache_domain.size());
    }
    out += "\"} 1\n";
  }

  // ---- CPU ----
  emit_header(out, "montauk_cpu_usage_percent", "Aggregate CPU utilization", "gauge");
  emit_gauge_d(out, "montauk_cpu_usage_percent", s.cpu.usage_pct);

  if (!s.cpu.per_core_pct.empty()) {
    emit_header(out, "montauk_cpu_core_usage_percent", "Per-core CPU utilization", "gauge");
    for (size_t i = 0; i < s.cpu.per_core_pct.size(); ++i) {
      char idx[8];
      auto [ptr, ec] = std::to_chars(idx, idx + sizeof(idx), i);
      emit_labeled_d(out, "montauk_cpu_core_usage_percent", "core",
                     std::string_view(idx, ptr), s.cpu.per_core_pct[i]);
    }
  }

  emit_header(out, "montauk_cpu_user_percent", "CPU user time percent", "gauge");
  emit_gauge_d(out, "montauk_cpu_user_percent", s.cpu.pct_user);
  emit_header(out, "montauk_cpu_system_percent", "CPU system time percent", "gauge");
  emit_gauge_d(out, "montauk_cpu_system_percent", s.cpu.pct_system);
  emit_header(out, "montauk_cpu_iowait_percent", "CPU I/O wait percent", "gauge");
  emit_gauge_d(out, "montauk_cpu_iowait_percent", s.cpu.pct_iowait);
  emit_header(out, "montauk_cpu_irq_percent", "CPU IRQ handling percent", "gauge");
  emit_gauge_d(out, "montauk_cpu_irq_percent", s.cpu.pct_irq);
  emit_header(out, "montauk_cpu_steal_percent", "CPU steal percent", "gauge");
  emit_gauge_d(out, "montauk_cpu_steal_percent", s.cpu.pct_steal);
  if (s.cpu.has_freq) {
    emit_header(out, "montauk_cpu_frequency_mhz_avg",
                "Average current CPU frequency across online cores (MHz)", "gauge");
    emit_gauge_d(out, "montauk_cpu_frequency_mhz_avg", s.cpu.freq_avg_mhz);
  }

  emit_header(out, "montauk_cpu_context_switches_per_second", "Context switches per second", "gauge");
  emit_gauge_d(out, "montauk_cpu_context_switches_per_second", s.cpu.ctxt_per_sec);
  emit_header(out, "montauk_cpu_interrupts_per_second", "Hardware interrupts per second", "gauge");
  emit_gauge_d(out, "montauk_cpu_interrupts_per_second", s.cpu.intr_per_sec);

  emit_header(out, "montauk_cpu_physical_cores", "Physical CPU cores", "gauge");
  emit_gauge_i(out, "montauk_cpu_physical_cores", s.cpu.physical_cores);
  emit_header(out, "montauk_cpu_logical_threads", "Logical CPU threads", "gauge");
  emit_gauge_i(out, "montauk_cpu_logical_threads", s.cpu.logical_threads);

  // ---- PMU hardware counters (interval deltas / rates). All values are over
  // the last sample interval. L2 = per-physical-core private cache (the
  // migration-cost signal on Zen2); L3 is kept per-cache-domain so cross-domain traffic
  // stays visible. Emitted only when the core PMU opened (root / paranoid<=1).
  emit_header(out, "montauk_pmu_available", "Core PMU counters available", "gauge");
  emit_gauge_i(out, "montauk_pmu_available", s.pmu.available ? 1 : 0);
  if (s.pmu.available) {
    emit_header(out, "montauk_pmu_l2_misses_per_second", "L2 cache misses per second (sysfs cache-misses event)", "gauge");
    emit_gauge_d(out, "montauk_pmu_l2_misses_per_second", s.pmu.l2_misses_per_sec);
    emit_header(out, "montauk_pmu_l2_miss_percent", "L2 misses as percent of L2 references", "gauge");
    emit_gauge_d(out, "montauk_pmu_l2_miss_percent", s.pmu.l2_miss_pct);
    emit_header(out, "montauk_pmu_ipc", "Instructions per cycle (interval)", "gauge");
    emit_gauge_d(out, "montauk_pmu_ipc", s.pmu.ipc);
    emit_header(out, "montauk_pmu_cycles_per_l2_miss", "Cycles per L2 miss (interval)", "gauge");
    emit_gauge_d(out, "montauk_pmu_cycles_per_l2_miss", s.pmu.cycles_per_l2_miss);
    emit_header(out, "montauk_pmu_l2_misses_interval", "L2 misses this interval", "gauge");
    emit_gauge_u(out, "montauk_pmu_l2_misses_interval", s.pmu.l2_misses);
    emit_header(out, "montauk_pmu_instructions_per_second", "Instructions per second (interval)", "gauge");
    emit_gauge_d(out, "montauk_pmu_instructions_per_second", s.pmu.instructions_per_sec);
    emit_header(out, "montauk_pmu_context_switches_per_second", "Context switches per second", "gauge");
    emit_gauge_d(out, "montauk_pmu_context_switches_per_second", s.pmu.context_switches_per_sec);
    emit_header(out, "montauk_pmu_cpu_migrations_per_second", "CPU migrations per second", "gauge");
    emit_gauge_d(out, "montauk_pmu_cpu_migrations_per_second", s.pmu.cpu_migrations_per_sec);
    emit_header(out, "montauk_pmu_branch_misses_per_second", "Branch mispredictions per second", "gauge");
    emit_gauge_d(out, "montauk_pmu_branch_misses_per_second", s.pmu.branch_misses_per_sec);
    // Energy per instruction (pJ) -- derived from RAPL power + retired instr.
    if (s.thermal.has_power && s.pmu.instructions_per_sec > 0.0) {
      emit_header(out, "montauk_energy_per_instruction_pj",
                  "Energy per retired instruction (picojoules), RAPL power / IPS",
                  "gauge");
      emit_gauge_d(out, "montauk_energy_per_instruction_pj",
                   s.thermal.power_watts / s.pmu.instructions_per_sec * 1e12);
    }

    // Per-CPU L2 this interval. cpu label = actual logical CPU id (per_cpu_ids),
    // so misses localize to the right core/cache domain even on a sparse online set.
    emit_header(out, "montauk_pmu_l2_misses_per_cpu", "L2 misses this interval, per logical CPU", "gauge");
    for (size_t i = 0; i < s.pmu.per_cpu_l2_misses.size(); ++i) {
      char cb[12], vb[20];
      int cpu = i < s.pmu.per_cpu_ids.size() ? s.pmu.per_cpu_ids[i]
                                             : static_cast<int>(i);
      auto [c1, ce] = std::to_chars(cb, cb + sizeof(cb), cpu);
      auto [v1, ve] = std::to_chars(vb, vb + sizeof(vb), s.pmu.per_cpu_l2_misses[i]);
      out += "montauk_pmu_l2_misses_per_cpu{cpu=\""; out.append(cb, c1);
      out += "\"} "; out.append(vb, v1); out += '\n';
    }
    emit_header(out, "montauk_pmu_l2_miss_percent_per_cpu", "L2 miss percent, per logical CPU", "gauge");
    for (size_t i = 0; i < s.pmu.per_cpu_l2_misses.size(); ++i) {
      char cb[12];
      int cpu = i < s.pmu.per_cpu_ids.size() ? s.pmu.per_cpu_ids[i]
                                             : static_cast<int>(i);
      auto [c1, ce] = std::to_chars(cb, cb + sizeof(cb), cpu);
      double refs = i < s.pmu.per_cpu_l2_refs.size()
                        ? static_cast<double>(s.pmu.per_cpu_l2_refs[i]) : 0.0;
      double pct = refs > 0.0
                       ? 100.0 * static_cast<double>(s.pmu.per_cpu_l2_misses[i]) / refs
                       : 0.0;
      out += "montauk_pmu_l2_miss_percent_per_cpu{cpu=\""; out.append(cb, c1);
      out += "\"} "; append_double(out, pct); out += '\n';
    }

    emit_header(out, "montauk_pmu_l3_available", "amd_l3 uncore PMU available", "gauge");
    emit_gauge_i(out, "montauk_pmu_l3_available", s.pmu.l3_available ? 1 : 0);
    if (s.pmu.l3_available) {
      // Per-cache domain L3 traffic this interval. cache_domain label = the L3-domain owner CPU.
      emit_header(out, "montauk_pmu_l3_misses_interval", "L3 misses this interval, per cache domain domain", "gauge");
      for (const auto& d : s.pmu.l3_per_cache_domain) {
        char cb[12], vb[20];
        auto [c1, ce] = std::to_chars(cb, cb + sizeof(cb), d.domain_cpu);
        auto [v1, ve] = std::to_chars(vb, vb + sizeof(vb), d.misses);
        out += "montauk_pmu_l3_misses_interval{cache_domain=\""; out.append(cb, c1);
        out += "\"} "; out.append(vb, v1); out += '\n';
      }
      emit_header(out, "montauk_pmu_l3_accesses_interval", "L3 accesses this interval, per cache domain domain", "gauge");
      for (const auto& d : s.pmu.l3_per_cache_domain) {
        char cb[12], vb[20];
        auto [c1, ce] = std::to_chars(cb, cb + sizeof(cb), d.domain_cpu);
        auto [v1, ve] = std::to_chars(vb, vb + sizeof(vb), d.accesses);
        out += "montauk_pmu_l3_accesses_interval{cache_domain=\""; out.append(cb, c1);
        out += "\"} "; out.append(vb, v1); out += '\n';
      }
      emit_header(out, "montauk_pmu_l3_miss_percent", "L3 miss percent, per cache domain domain", "gauge");
      for (const auto& d : s.pmu.l3_per_cache_domain) {
        char cb[12];
        auto [c1, ce] = std::to_chars(cb, cb + sizeof(cb), d.domain_cpu);
        out += "montauk_pmu_l3_miss_percent{cache_domain=\""; out.append(cb, c1);
        out += "\"} "; append_double(out, d.miss_pct); out += '\n';
      }
    }
  }

  // ---- Memory (KB * 1024 -> bytes) ----
  emit_header(out, "montauk_memory_total_bytes", "Total physical memory", "gauge");
  emit_gauge_u(out, "montauk_memory_total_bytes", s.mem.total_kb * 1024ULL);
  emit_header(out, "montauk_memory_used_bytes", "Used physical memory", "gauge");
  emit_gauge_u(out, "montauk_memory_used_bytes", s.mem.used_kb * 1024ULL);
  emit_header(out, "montauk_memory_available_bytes", "Available memory (MemAvailable)", "gauge");
  emit_gauge_u(out, "montauk_memory_available_bytes", s.mem.available_kb * 1024ULL);
  emit_header(out, "montauk_memory_cached_bytes", "Cached memory", "gauge");
  emit_gauge_u(out, "montauk_memory_cached_bytes", s.mem.cached_kb * 1024ULL);
  emit_header(out, "montauk_memory_buffers_bytes", "Buffer memory", "gauge");
  emit_gauge_u(out, "montauk_memory_buffers_bytes", s.mem.buffers_kb * 1024ULL);
  emit_header(out, "montauk_memory_swap_total_bytes", "Total swap space", "gauge");
  emit_gauge_u(out, "montauk_memory_swap_total_bytes", s.mem.swap_total_kb * 1024ULL);
  emit_header(out, "montauk_memory_swap_used_bytes", "Used swap space", "gauge");
  emit_gauge_u(out, "montauk_memory_swap_used_bytes", s.mem.swap_used_kb * 1024ULL);
  emit_header(out, "montauk_memory_used_percent", "Memory utilization percent", "gauge");
  emit_gauge_d(out, "montauk_memory_used_percent", s.mem.used_pct);

  // ---- Network ----
  if (!s.net.interfaces.empty()) {
    emit_header(out, "montauk_network_interface_receive_bps", "Per-interface receive bytes/sec", "gauge");
    for (const auto& iface : s.net.interfaces)
      emit_labeled_d(out, "montauk_network_interface_receive_bps", "interface", iface.name, iface.rx_bps);
    emit_header(out, "montauk_network_interface_transmit_bps", "Per-interface transmit bytes/sec", "gauge");
    for (const auto& iface : s.net.interfaces)
      emit_labeled_d(out, "montauk_network_interface_transmit_bps", "interface", iface.name, iface.tx_bps);
  }
  emit_header(out, "montauk_network_receive_bps_total", "Aggregate receive bytes/sec", "gauge");
  emit_gauge_d(out, "montauk_network_receive_bps_total", s.net.agg_rx_bps);
  emit_header(out, "montauk_network_transmit_bps_total", "Aggregate transmit bytes/sec", "gauge");
  emit_gauge_d(out, "montauk_network_transmit_bps_total", s.net.agg_tx_bps);

  // ---- Disk ----
  if (!s.disk.devices.empty()) {
    emit_header(out, "montauk_disk_device_read_bps", "Per-device read bytes/sec", "gauge");
    for (const auto& dev : s.disk.devices)
      emit_labeled_d(out, "montauk_disk_device_read_bps", "device", dev.name, dev.read_bps);
    emit_header(out, "montauk_disk_device_write_bps", "Per-device write bytes/sec", "gauge");
    for (const auto& dev : s.disk.devices)
      emit_labeled_d(out, "montauk_disk_device_write_bps", "device", dev.name, dev.write_bps);
    emit_header(out, "montauk_disk_device_utilization_percent", "Per-device I/O utilization", "gauge");
    for (const auto& dev : s.disk.devices)
      emit_labeled_d(out, "montauk_disk_device_utilization_percent", "device", dev.name, dev.util_pct);
  }
  emit_header(out, "montauk_disk_read_bps_total", "Aggregate disk read bytes/sec", "gauge");
  emit_gauge_d(out, "montauk_disk_read_bps_total", s.disk.total_read_bps);
  emit_header(out, "montauk_disk_write_bps_total", "Aggregate disk write bytes/sec", "gauge");
  emit_gauge_d(out, "montauk_disk_write_bps_total", s.disk.total_write_bps);

  // ---- Filesystem ----
  if (!s.fs.mounts.empty()) {
    emit_header(out, "montauk_filesystem_total_bytes", "Filesystem total size", "gauge");
    for (const auto& m : s.fs.mounts)
      emit_labeled_3u(out, "montauk_filesystem_total_bytes", "device", m.device, "mountpoint", m.mountpoint, "fstype", m.fstype, m.total_bytes);
    emit_header(out, "montauk_filesystem_used_bytes", "Filesystem used bytes", "gauge");
    for (const auto& m : s.fs.mounts)
      emit_labeled_3u(out, "montauk_filesystem_used_bytes", "device", m.device, "mountpoint", m.mountpoint, "fstype", m.fstype, m.used_bytes);
    emit_header(out, "montauk_filesystem_available_bytes", "Filesystem available bytes", "gauge");
    for (const auto& m : s.fs.mounts)
      emit_labeled_3u(out, "montauk_filesystem_available_bytes", "device", m.device, "mountpoint", m.mountpoint, "fstype", m.fstype, m.avail_bytes);
    emit_header(out, "montauk_filesystem_used_percent", "Filesystem utilization percent", "gauge");
    for (const auto& m : s.fs.mounts)
      emit_labeled_3d(out, "montauk_filesystem_used_percent", "device", m.device, "mountpoint", m.mountpoint, "fstype", m.fstype, m.used_pct);
  }

  // Providers already speak Prometheus text; pass each snapshot through
  // verbatim so their metric names and HELP/TYPE lines are preserved.
  for (const auto& p : s.providers) {
    out += p.raw_text;
    if (!p.raw_text.empty() && p.raw_text.back() != '\n') out += '\n';
  }

  // ---- Process summary ----
  emit_header(out, "montauk_processes_total", "Total processes", "gauge");
  emit_gauge_u(out, "montauk_processes_total", static_cast<uint64_t>(s.total_processes));
  emit_header(out, "montauk_processes_running", "Running processes", "gauge");
  emit_gauge_u(out, "montauk_processes_running", static_cast<uint64_t>(s.running_processes));
  emit_header(out, "montauk_processes_sleeping", "Sleeping processes", "gauge");
  emit_gauge_u(out, "montauk_processes_sleeping", static_cast<uint64_t>(s.state_sleeping));
  emit_header(out, "montauk_processes_zombie", "Zombie processes", "gauge");
  emit_gauge_u(out, "montauk_processes_zombie", static_cast<uint64_t>(s.state_zombie));
  emit_header(out, "montauk_threads_total", "Total threads", "gauge");
  emit_gauge_u(out, "montauk_threads_total", static_cast<uint64_t>(s.total_threads));

  // ---- Per-process top-N ----
  if (s.top_procs_count > 0) {
    emit_header(out, "montauk_process_cpu_percent", "Per-process CPU utilization", "gauge");
    for (int i = 0; i < s.top_procs_count; ++i) {
      const auto& p = s.top_procs[i];
      char pid_buf[12];
      auto [pptr, pec] = std::to_chars(pid_buf, pid_buf + sizeof(pid_buf), p.pid);
      emit_labeled_2d(out, "montauk_process_cpu_percent",
                      "pid", std::string_view(pid_buf, pptr), "cmd", p.cmd, p.cpu_pct);
    }

    emit_header(out, "montauk_process_memory_bytes", "Per-process resident memory", "gauge");
    for (int i = 0; i < s.top_procs_count; ++i) {
      const auto& p = s.top_procs[i];
      char pid_buf[12];
      auto [pptr, pec] = std::to_chars(pid_buf, pid_buf + sizeof(pid_buf), p.pid);
      emit_labeled_2u(out, "montauk_process_memory_bytes",
                      "pid", std::string_view(pid_buf, pptr), "cmd", p.cmd, p.rss_kb * 1024ULL);
    }

    // GPU utilization (conditional per-process)
    bool any_gpu_util = false;
    for (int i = 0; i < s.top_procs_count; ++i)
      if (s.top_procs[i].has_gpu_util) { any_gpu_util = true; break; }
    if (any_gpu_util) {
      emit_header(out, "montauk_process_gpu_utilization_percent", "Per-process GPU utilization", "gauge");
      for (int i = 0; i < s.top_procs_count; ++i) {
        const auto& p = s.top_procs[i];
        if (!p.has_gpu_util) continue;
        char pid_buf[12];
        auto [pptr, pec] = std::to_chars(pid_buf, pid_buf + sizeof(pid_buf), p.pid);
        emit_labeled_2d(out, "montauk_process_gpu_utilization_percent",
                        "pid", std::string_view(pid_buf, pptr), "cmd", p.cmd, p.gpu_util_pct);
      }
    }

    bool any_gpu_mem = false;
    for (int i = 0; i < s.top_procs_count; ++i)
      if (s.top_procs[i].has_gpu_mem) { any_gpu_mem = true; break; }
    if (any_gpu_mem) {
      emit_header(out, "montauk_process_gpu_memory_bytes", "Per-process GPU memory", "gauge");
      for (int i = 0; i < s.top_procs_count; ++i) {
        const auto& p = s.top_procs[i];
        if (!p.has_gpu_mem) continue;
        char pid_buf[12];
        auto [pptr, pec] = std::to_chars(pid_buf, pid_buf + sizeof(pid_buf), p.pid);
        emit_labeled_2u(out, "montauk_process_gpu_memory_bytes",
                        "pid", std::string_view(pid_buf, pptr), "cmd", p.cmd, p.gpu_mem_kb * 1024ULL);
      }
    }
  }

  // ---- GPU ----
  if (!s.vram.devices.empty()) {
    emit_header(out, "montauk_gpu_vram_total_bytes", "Per-device GPU VRAM total", "gauge");
    for (const auto& d : s.vram.devices)
      emit_labeled_u(out, "montauk_gpu_vram_total_bytes", "device", d.name, d.total_mb * 1048576ULL);
    emit_header(out, "montauk_gpu_vram_used_bytes", "Per-device GPU VRAM used", "gauge");
    for (const auto& d : s.vram.devices)
      emit_labeled_u(out, "montauk_gpu_vram_used_bytes", "device", d.name, d.used_mb * 1048576ULL);

    // Per-device temps
    bool any_edge = false, any_hotspot = false, any_tmem = false, any_fan = false;
    for (const auto& d : s.vram.devices) {
      if (d.has_temp_edge) any_edge = true;
      if (d.has_temp_hotspot) any_hotspot = true;
      if (d.has_temp_mem) any_tmem = true;
      if (d.has_fan) any_fan = true;
    }
    if (any_edge) {
      emit_header(out, "montauk_gpu_temperature_edge_celsius", "GPU edge temperature", "gauge");
      for (const auto& d : s.vram.devices)
        if (d.has_temp_edge) emit_labeled_d(out, "montauk_gpu_temperature_edge_celsius", "device", d.name, d.temp_edge_c);
    }
    if (any_hotspot) {
      emit_header(out, "montauk_gpu_temperature_hotspot_celsius", "GPU hotspot temperature", "gauge");
      for (const auto& d : s.vram.devices)
        if (d.has_temp_hotspot) emit_labeled_d(out, "montauk_gpu_temperature_hotspot_celsius", "device", d.name, d.temp_hotspot_c);
    }
    if (any_tmem) {
      emit_header(out, "montauk_gpu_temperature_memory_celsius", "GPU memory temperature", "gauge");
      for (const auto& d : s.vram.devices)
        if (d.has_temp_mem) emit_labeled_d(out, "montauk_gpu_temperature_memory_celsius", "device", d.name, d.temp_mem_c);
    }
    if (any_fan) {
      emit_header(out, "montauk_gpu_fan_speed_percent", "GPU fan speed percent", "gauge");
      for (const auto& d : s.vram.devices)
        if (d.has_fan) emit_labeled_d(out, "montauk_gpu_fan_speed_percent", "device", d.name, d.fan_speed_pct);
    }
  }

  // GPU aggregate
  emit_header(out, "montauk_gpu_vram_total_bytes_aggregate", "Total GPU VRAM", "gauge");
  emit_gauge_u(out, "montauk_gpu_vram_total_bytes_aggregate", s.vram.total_mb * 1048576ULL);
  emit_header(out, "montauk_gpu_vram_used_bytes_aggregate", "Used GPU VRAM", "gauge");
  emit_gauge_u(out, "montauk_gpu_vram_used_bytes_aggregate", s.vram.used_mb * 1048576ULL);
  emit_header(out, "montauk_gpu_vram_used_percent", "GPU VRAM utilization percent", "gauge");
  emit_gauge_d(out, "montauk_gpu_vram_used_percent", s.vram.used_pct);

  if (s.vram.has_util) {
    emit_header(out, "montauk_gpu_utilization_percent", "GPU core utilization", "gauge");
    emit_gauge_d(out, "montauk_gpu_utilization_percent", s.vram.gpu_util_pct);
  }
  if (s.vram.has_mem_util) {
    emit_header(out, "montauk_gpu_memory_controller_percent", "GPU memory controller utilization", "gauge");
    emit_gauge_d(out, "montauk_gpu_memory_controller_percent", s.vram.mem_util_pct);
  }
  if (s.vram.has_encdec) {
    emit_header(out, "montauk_gpu_encoder_percent", "GPU encoder utilization", "gauge");
    emit_gauge_d(out, "montauk_gpu_encoder_percent", s.vram.enc_util_pct);
    emit_header(out, "montauk_gpu_decoder_percent", "GPU decoder utilization", "gauge");
    emit_gauge_d(out, "montauk_gpu_decoder_percent", s.vram.dec_util_pct);
  }
  if (s.vram.has_power) {
    emit_header(out, "montauk_gpu_power_draw_watts", "GPU power draw", "gauge");
    emit_gauge_d(out, "montauk_gpu_power_draw_watts", s.vram.power_draw_w);
  }
  if (s.vram.has_power_limit) {
    emit_header(out, "montauk_gpu_power_limit_watts", "GPU power limit", "gauge");
    emit_gauge_d(out, "montauk_gpu_power_limit_watts", s.vram.power_limit_w);
  }

  // ---- Thermal ----
  if (s.thermal.has_temp) {
    emit_header(out, "montauk_thermal_cpu_temperature_celsius", "CPU max temperature", "gauge");
    emit_gauge_d(out, "montauk_thermal_cpu_temperature_celsius", s.thermal.cpu_max_c);
  }
  if (s.thermal.has_fan) {
    emit_header(out, "montauk_thermal_fan_speed_rpm", "CPU fan speed RPM", "gauge");
    emit_gauge_d(out, "montauk_thermal_fan_speed_rpm", s.thermal.fan_rpm);
  }
  if (s.thermal.has_power) {
    emit_header(out, "montauk_power_watts",
                "Package power draw from RAPL/powercap (energy delta per interval)",
                "gauge");
    emit_gauge_d(out, "montauk_power_watts", s.thermal.power_watts);
  }
  if (s.thermal.has_energy) {
    emit_header(out, "montauk_package_energy_joules_total",
                "Cumulative package energy from RAPL/powercap (joules, wrap-safe); "
                "window-integral energy is the counter delta", "counter");
    emit_gauge_d(out, "montauk_package_energy_joules_total", s.thermal.energy_joules_total);
  }
  if (!s.thermal.cstates.empty()) {
    emit_header(out, "montauk_cstate_residency_percent",
                "Idle-state residency this interval, per state (across CPUs)",
                "gauge");
    char vb[32];
    for (const auto& cs : s.thermal.cstates) {
      auto [v1, ve] = std::to_chars(vb, vb + sizeof(vb), cs.residency_pct,
                                    std::chars_format::fixed, 3);
      out += "montauk_cstate_residency_percent{state=\"";
      out += cs.name;
      out += "\"} "; out.append(vb, v1); out += '\n';
    }
  }

  return out;
}

std::string trace_to_prometheus(const montauk::model::TraceSnapshot& t) {
  std::string out;
  out.reserve(4096);

  out += "\n# ---- Trace ----\n";

  // ---- Trace metadata ----
  emit_header(out, "montauk_trace_waiting", "Trace mode waiting for pattern match", "gauge");
  emit_gauge_i(out, "montauk_trace_waiting", t.waiting_for_match ? 1 : 0);

  emit_header(out, "montauk_trace_group_size", "Number of processes in traced group", "gauge");
  emit_gauge_i(out, "montauk_trace_group_size", t.procs_count);

  emit_header(out, "montauk_trace_thread_total", "Total threads across traced group", "gauge");
  emit_gauge_i(out, "montauk_trace_thread_total", t.thread_count);

  if (t.procs_count == 0) return out;

  // ---- Per-process info ----
  emit_header(out, "montauk_trace_process_info", "Traced process group member", "gauge");
  for (int i = 0; i < t.procs_count; ++i) {
    const auto& p = t.procs[i];
    char pid_buf[12], ppid_buf[12];
    auto [p1, e1] = std::to_chars(pid_buf, pid_buf + sizeof(pid_buf), p.pid);
    auto [p2, e2] = std::to_chars(ppid_buf, ppid_buf + sizeof(ppid_buf), p.ppid);
    // Lifecycle: exit_code encodes signal (low 7 bits) and status (bits 8-15)
    int sig = p.exit_code & 0x7f;
    int status = (p.exit_code >> 8) & 0xff;
    char exit_buf[12], sig_buf[12], fork_buf[24], exec_buf[24], exitts_buf[24];
    auto [p3, e3] = std::to_chars(exit_buf, exit_buf + sizeof(exit_buf), status);
    auto [p4, e4] = std::to_chars(sig_buf, sig_buf + sizeof(sig_buf), sig);
    auto [p5, e5] = std::to_chars(fork_buf, fork_buf + sizeof(fork_buf), p.fork_ts);
    auto [p6, e6] = std::to_chars(exec_buf, exec_buf + sizeof(exec_buf), p.exec_ts);
    auto [p7, e7] = std::to_chars(exitts_buf, exitts_buf + sizeof(exitts_buf), p.exit_ts);

    out += "montauk_trace_process_info{pid=\"";
    out.append(pid_buf, p1);
    out += "\",ppid=\"";
    out.append(ppid_buf, p2);
    out += "\",cmd=\"";
    append_escaped(out, std::string_view(p.cmd));
    out += "\",root=\"";
    out += p.is_root ? "1" : "0";
    out += "\",exited=\"";
    out += p.exited ? "1" : "0";
    out += "\",exit_status=\"";
    out.append(exit_buf, p3);
    out += "\",exit_signal=\"";
    out.append(sig_buf, p4);
    out += "\",exec_file=\"";
    append_escaped(out, std::string_view(p.exec_file));
    out += "\",fork_ts=\"";
    out.append(fork_buf, p5);
    out += "\",exec_ts=\"";
    out.append(exec_buf, p6);
    out += "\",exit_ts=\"";
    out.append(exitts_buf, p7);
    out += "\"} 1\n";
  }

  // ---- Scheduler-decision counts (per op, summed across CPUs) ----
  {
    static const char* const op_name[7] = {
      "", "enqueue", "pick", "pick_empty", "preempt_tick", "preempt_wakeup", "wakeup"
    };
    bool any = false;
    for (int o = 1; o < 7; ++o)
      if (t.sched_op_total[o]) { any = true; break; }
    if (any) {
      emit_header(out, "montauk_sched_op_total",
                  "Scheduler-decision tracepoint counts (per op, summed across CPUs)",
                  "counter");
      for (int o = 1; o < 7; ++o) {
        char v[24];
        auto [pv, ev] = std::to_chars(v, v + sizeof(v), t.sched_op_total[o]);
        out += "montauk_sched_op_total{op=\"";
        out += op_name[o];
        out += "\"} ";
        out.append(v, pv);
        out += '\n';
      }
    }
  }

  // ---- Per-thread state ----
  if (t.thread_count > 0) {
    emit_header(out, "montauk_trace_thread_state", "Per-thread state for traced group", "gauge");
    for (int i = 0; i < t.thread_count; ++i) {
      const auto& th = t.threads[i];
      char pid_buf[12], tid_buf[12];
      auto [p1, e1] = std::to_chars(pid_buf, pid_buf + sizeof(pid_buf), th.pid);
      auto [p2, e2] = std::to_chars(tid_buf, tid_buf + sizeof(tid_buf), th.tid);
      char state_str[2] = {th.state, '\0'};
      emit_labeled_4i(out, "montauk_trace_thread_state",
                      "pid", std::string_view(pid_buf, p1),
                      "tid", std::string_view(tid_buf, p2),
                      "comm", std::string_view(th.comm),
                      "state", std::string_view(state_str), 1);
    }

    // ---- Per-thread CPU% ----
    emit_header(out, "montauk_trace_thread_cpu_percent", "Per-thread CPU utilization", "gauge");
    for (int i = 0; i < t.thread_count; ++i) {
      const auto& th = t.threads[i];
      char pid_buf[12], tid_buf[12];
      auto [p1, e1] = std::to_chars(pid_buf, pid_buf + sizeof(pid_buf), th.pid);
      auto [p2, e2] = std::to_chars(tid_buf, tid_buf + sizeof(tid_buf), th.tid);
      out += "montauk_trace_thread_cpu_percent{pid=\"";
      out.append(pid_buf, p1);
      out += "\",tid=\"";
      out.append(tid_buf, p2);
      out += "\",comm=\"";
      append_escaped(out, std::string_view(th.comm));
      out += "\"} ";
      append_double(out, th.cpu_pct);
      out += '\n';
    }

    // ---- Per-thread current on-CPU core ----
    emit_header(out, "montauk_trace_thread_cpu", "Per-thread current on-CPU core", "gauge");
    for (int i = 0; i < t.thread_count; ++i) {
      const auto& th = t.threads[i];
      char pid_buf[12], tid_buf[12];
      auto [p1, e1] = std::to_chars(pid_buf, pid_buf + sizeof(pid_buf), th.pid);
      auto [p2, e2] = std::to_chars(tid_buf, tid_buf + sizeof(tid_buf), th.tid);
      out += "montauk_trace_thread_cpu{pid=\"";
      out.append(pid_buf, p1);
      out += "\",tid=\"";
      out.append(tid_buf, p2);
      out += "\",comm=\"";
      append_escaped(out, std::string_view(th.comm));
      out += "\"} ";
      char cpu_buf[12];
      auto [c1, ce] = std::to_chars(cpu_buf, cpu_buf + sizeof(cpu_buf), th.cur_cpu);
      out.append(cpu_buf, c1);
      out += '\n';
    }

    // ---- Per-thread cross-CPU migrations (fork-storm thrash signal) ----
    emit_header(out, "montauk_trace_thread_migrations", "Per-thread cross-CPU migration count", "counter");
    for (int i = 0; i < t.thread_count; ++i) {
      const auto& th = t.threads[i];
      char pid_buf[12], tid_buf[12];
      auto [p1, e1] = std::to_chars(pid_buf, pid_buf + sizeof(pid_buf), th.pid);
      auto [p2, e2] = std::to_chars(tid_buf, tid_buf + sizeof(tid_buf), th.tid);
      out += "montauk_trace_thread_migrations{pid=\"";
      out.append(pid_buf, p1);
      out += "\",tid=\"";
      out.append(tid_buf, p2);
      out += "\",comm=\"";
      append_escaped(out, std::string_view(th.comm));
      out += "\"} ";
      char mig_buf[20];
      auto [m1, me] = std::to_chars(mig_buf, mig_buf + sizeof(mig_buf), th.migrations);
      out.append(mig_buf, m1);
      out += '\n';
    }

    // ---- Global migration classification by cache domain (cumulative since attach) ----
    // The decisive fork-storm signal: intra- vs cross-domain moves are the per-core L2-refill
    // cost (warm L3, cold L2 — what the Zen2 "cache-misses" counter measures);
    // cross-domain moves are the cross-domain interconnect cost.
    {
      char b[20];
      emit_header(out, "montauk_trace_migrations_intra_domain",
                  "Cross-core migrations within one cache domain/L3 domain", "counter");
      auto [p1, e1] = std::to_chars(b, b + sizeof(b), t.mig_intra_domain);
      out += "montauk_trace_migrations_intra_domain "; out.append(b, p1); out += '\n';
      emit_header(out, "montauk_trace_migrations_cross_domain",
                  "Cross-core migrations across cache domain/L3 domains (cross-domain interconnect)", "counter");
      auto [p2, e2] = std::to_chars(b, b + sizeof(b), t.mig_cross_domain);
      out += "montauk_trace_migrations_cross_domain "; out.append(b, p2); out += '\n';
      emit_header(out, "montauk_trace_migrations_unknown_domain",
                  "Cross-core migrations with unmapped cache domain (topology not pushed)", "counter");
      auto [p3, e3] = std::to_chars(b, b + sizeof(b), t.mig_unknown_domain);
      out += "montauk_trace_migrations_unknown_domain "; out.append(b, p3); out += '\n';
      emit_header(out, "montauk_trace_migrations_intra_wake",
                  "Intra-domain migrations that placed a woken task (select_cpu / enqueue spill push)", "counter");
      auto [pw, ew] = std::to_chars(b, b + sizeof(b), t.mig_intra_wake);
      out += "montauk_trace_migrations_intra_wake "; out.append(b, pw); out += '\n';
      emit_header(out, "montauk_trace_migrations_intra_steal",
                  "Intra-domain migrations that pulled an already-runnable task at dispatch (steal)", "counter");
      auto [ps, es] = std::to_chars(b, b + sizeof(b), t.mig_intra_steal);
      out += "montauk_trace_migrations_intra_steal "; out.append(b, ps); out += '\n';
      emit_header(out, "montauk_trace_migrations_cross_wake",
                  "Cross-domain wake-placements (select_cpu / enqueue spill push)", "counter");
      auto [pcw, ecw] = std::to_chars(b, b + sizeof(b), t.mig_cross_wake);
      out += "montauk_trace_migrations_cross_wake "; out.append(b, pcw); out += '\n';
      emit_header(out, "montauk_trace_migrations_cross_steal",
                  "Cross-domain dispatch steals (pull)", "counter");
      auto [pcs, ecs] = std::to_chars(b, b + sizeof(b), t.mig_cross_steal);
      out += "montauk_trace_migrations_cross_steal "; out.append(b, pcs); out += '\n';
    }

    // ---- Per-thread syscall ----
    emit_header(out, "montauk_trace_thread_syscall", "Per-thread current syscall", "gauge");
    for (int i = 0; i < t.thread_count; ++i) {
      const auto& th = t.threads[i];
      char pid_buf[12], tid_buf[12];
      auto [p1, e1] = std::to_chars(pid_buf, pid_buf + sizeof(pid_buf), th.pid);
      auto [p2, e2] = std::to_chars(tid_buf, tid_buf + sizeof(tid_buf), th.tid);
      emit_labeled_5i(out, "montauk_trace_thread_syscall",
                      "pid", std::string_view(pid_buf, p1),
                      "tid", std::string_view(tid_buf, p2),
                      "comm", std::string_view(th.comm),
                      "syscall", std::string_view(th.syscall_name),
                      "wchan", std::string_view(th.wchan),
                      th.syscall_nr);
    }

    // ---- Per-thread I/O details ----
    emit_header(out, "montauk_trace_thread_io", "Per-thread last I/O syscall details", "gauge");
    for (int i = 0; i < t.thread_count; ++i) {
      const auto& th = t.threads[i];
      if (th.io_fd < 0)
        continue; // no valid I/O data

      char pid_buf[12], tid_buf[12], fd_buf[12], count_buf[24], result_buf[24], whence_buf[12];
      auto [p1, e1] = std::to_chars(pid_buf, pid_buf + sizeof(pid_buf), th.pid);
      auto [p2, e2] = std::to_chars(tid_buf, tid_buf + sizeof(tid_buf), th.tid);
      auto [p3, e3] = std::to_chars(fd_buf, fd_buf + sizeof(fd_buf), th.io_fd);
      auto [p4, e4] = std::to_chars(count_buf, count_buf + sizeof(count_buf), th.io_count);
      auto [p5, e5] = std::to_chars(result_buf, result_buf + sizeof(result_buf), th.io_result);
      auto [p6, e6] = std::to_chars(whence_buf, whence_buf + sizeof(whence_buf), th.io_whence);

      out += "montauk_trace_thread_io{pid=\"";
      out.append(pid_buf, p1);
      out += "\",tid=\"";
      out.append(tid_buf, p2);
      out += "\",comm=\"";
      append_escaped(out, std::string_view(th.comm));
      out += "\",syscall=\"";
      append_escaped(out, std::string_view(th.syscall_name));
      out += "\",fd=\"";
      out.append(fd_buf, p3);
      out += "\",count=\"";
      out.append(count_buf, p4);
      out += "\",result=\"";
      out.append(result_buf, p5);
      out += "\",whence=\"";
      out.append(whence_buf, p6);
      out += "\"} ";
      append_uint(out, th.io_timestamp_ns);
      out += '\n';
    }
  }

  // ---- ntsync operations ----
  if (t.ntsync_count > 0) {
    static const char* nts_ops[] = {
      "create_sem", "sem_release", "wait_any", "wait_all",
      "create_mutex", "mutex_unlock", "mutex_kill",
      "create_event", "event_set", "event_reset", "event_pulse",
      "sem_read", "mutex_read", "event_read"
    };
    emit_header(out, "montauk_trace_ntsync", "ntsync synchronization operations", "gauge");
    for (int i = 0; i < t.ntsync_count; ++i) {
      const auto& ns = t.ntsync_events[i];
      char pid_buf[12], tid_buf[12], fd_buf[12], result_buf[24];
      auto [p1, e1] = std::to_chars(pid_buf, pid_buf + sizeof(pid_buf), ns.pid);
      auto [p2, e2] = std::to_chars(tid_buf, tid_buf + sizeof(tid_buf), ns.tid);
      auto [p3, e3] = std::to_chars(fd_buf, fd_buf + sizeof(fd_buf), ns.fd);
      auto [p4, e4] = std::to_chars(result_buf, result_buf + sizeof(result_buf), ns.result);
      const char* op_str = (ns.op < 14) ? nts_ops[ns.op] : "unknown";

      char arg0_buf[12], arg1_buf[12], owner_buf[12];
      auto [p5, e5] = std::to_chars(arg0_buf, arg0_buf + sizeof(arg0_buf), ns.arg0);
      auto [p6, e6] = std::to_chars(arg1_buf, arg1_buf + sizeof(arg1_buf), ns.arg1);
      auto [p7, e7] = std::to_chars(owner_buf, owner_buf + sizeof(owner_buf), ns.wait_owner);

      out += "montauk_trace_ntsync{pid=\"";
      out.append(pid_buf, p1);
      out += "\",tid=\"";
      out.append(tid_buf, p2);
      out += "\",comm=\"";
      append_escaped(out, std::string_view(ns.comm));
      out += "\",op=\"";
      out += op_str;
      out += "\",fd=\"";
      out.append(fd_buf, p3);
      out += "\",result=\"";
      out.append(result_buf, p4);
      out += "\",arg0=\"";
      out.append(arg0_buf, p5);
      out += "\",arg1=\"";
      out.append(arg1_buf, p6);
      out += "\",owner=\"";
      out.append(owner_buf, p7);
      out += "\"} ";
      append_uint(out, ns.timestamp_ns);
      out += '\n';
    }
  }

  // ---- FD targets ----
  if (t.fd_count > 0) {
    emit_header(out, "montauk_trace_fd_target", "Per-process fd targets", "gauge");
    for (int i = 0; i < t.fd_count; ++i) {
      const auto& fd = t.fds[i];
      char pid_buf[12], fd_buf[12];
      auto [p1, e1] = std::to_chars(pid_buf, pid_buf + sizeof(pid_buf), fd.pid);
      auto [p2, e2] = std::to_chars(fd_buf, fd_buf + sizeof(fd_buf), fd.fd_num);
      out += "montauk_trace_fd_target{pid=\"";
      out.append(pid_buf, p1);
      out += "\",fd=\"";
      out.append(fd_buf, p2);
      out += "\",target=\"";
      append_escaped(out, std::string_view(fd.target));
      out += "\"} 1\n";
    }
  }

  return out;
}

} // namespace montauk::app
