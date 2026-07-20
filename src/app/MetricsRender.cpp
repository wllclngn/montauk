// The single walk over MetricsSnapshot that both snapshot_to_json and
// snapshot_to_prometheus drive through their own MetricsSink -- every field
// read and visited exactly once here. Section order follows the original
// JSON layout (system, cpu, pmu, memory, gpu, thermal, network, disk,
// filesystems, providers, processes); Prometheus's original section order
// differed from JSON's (its own metric-family order doesn't matter to a
// Prometheus scraper, and JSON object key order doesn't matter to a JSON
// reader, so unifying onto one canonical order changes surface *ordering*
// for both formats relative to before, not values).
#include "app/MetricsRender.hpp"
#include "ui/Formatting.hpp"

#include <cstdio>

namespace montauk::app {

namespace {

void render_system(MetricsSink& sink, const MetricsSnapshot& s) {
  std::string gpu = s.vram.name;
  if (gpu.empty() && !s.vram.devices.empty()) gpu = s.vram.devices.front().name;
  std::string kernel = montauk::ui::read_kernel_version();
  std::string sched = montauk::ui::read_scheduler();
  double mem_gib = static_cast<double>(s.mem.total_kb) / (1024.0 * 1024.0);

  sink.section_begin("system");
  sink.str({"cpu_model", nullptr, nullptr}, s.cpu.model);
  sink.i64({"physical_cores", nullptr, nullptr}, s.cpu.physical_cores);
  sink.i64({"logical_cpus", nullptr, nullptr}, s.cpu.logical_threads);
  sink.f64({"mem_total_gib", nullptr, nullptr}, mem_gib);
  sink.str({"gpu", nullptr, nullptr}, gpu);
  sink.str({"kernel", nullptr, nullptr}, kernel);
  sink.str({"scheduler", nullptr, nullptr}, sched);
  sink.section_end();

  char mem_buf[32];
  std::snprintf(mem_buf, sizeof(mem_buf), "%.1f", mem_gib);
  std::string physical_cores = std::to_string(s.cpu.physical_cores);
  std::string logical_cpus = std::to_string(s.cpu.logical_threads);
  std::string cache_domain = std::to_string(s.pmu.l3_per_cache_domain.size());

  // montauk_system_info sanitizes by replacing quote/backslash/newline with a
  // space, not the backslash-escaping every other labeled Prometheus metric
  // uses -- preserved verbatim from the pre-unification code.
  auto san = [](std::string v) {
    for (char& c : v)
      if (c == '"' || c == '\\' || c == '\n') c = ' ';
    return v;
  };
  std::string cpu_model_san = san(s.cpu.model);
  std::string gpu_san = san(gpu);
  std::string kernel_san = san(kernel);
  std::string sched_san = san(sched);

  std::vector<Label> labels = {
      {"cpu_model", cpu_model_san}, {"physical_cores", physical_cores},
      {"logical_cpus", logical_cpus}, {"mem_total_gib", mem_buf},
      {"gpu", gpu_san},              {"kernel", kernel_san},
      {"sched", sched_san},
  };
  if (!s.pmu.l3_per_cache_domain.empty()) labels.push_back({"cache_domain", cache_domain});
  sink.info_line("montauk_system_info",
                 "System specs: cpu model, cores, memory, gpu, kernel, scheduler", labels);
}

void render_cpu(MetricsSink& sink, const MetricsSnapshot& s) {
  sink.section_begin("cpu");
  sink.f64({"usage_pct", "montauk_cpu_usage_percent", "Aggregate CPU utilization"}, s.cpu.usage_pct);
  sink.f64({"user_pct", "montauk_cpu_user_percent", "CPU user time percent"}, s.cpu.pct_user);
  sink.f64({"system_pct", "montauk_cpu_system_percent", "CPU system time percent"}, s.cpu.pct_system);
  sink.f64({"iowait_pct", "montauk_cpu_iowait_percent", "CPU I/O wait percent"}, s.cpu.pct_iowait);
  sink.f64({"irq_pct", "montauk_cpu_irq_percent", "CPU IRQ handling percent"}, s.cpu.pct_irq);
  sink.f64({"steal_pct", "montauk_cpu_steal_percent", "CPU steal percent"}, s.cpu.pct_steal);
  if (s.cpu.has_freq)
    sink.f64({"freq_mhz_avg", "montauk_cpu_frequency_mhz_avg",
              "Average current CPU frequency across online cores (MHz)"}, s.cpu.freq_avg_mhz);
  sink.f64({"context_switches_per_sec", "montauk_cpu_context_switches_per_second",
            "Context switches per second"}, s.cpu.ctxt_per_sec);
  sink.f64({"interrupts_per_sec", "montauk_cpu_interrupts_per_second",
            "Hardware interrupts per second"}, s.cpu.intr_per_sec);
  sink.i64({nullptr, "montauk_cpu_physical_cores", "Physical CPU cores"}, s.cpu.physical_cores);
  sink.i64({nullptr, "montauk_cpu_logical_threads", "Logical CPU threads"}, s.cpu.logical_threads);

  if (!s.cpu.per_core_pct.empty()) {
    // json_key is null on purpose: this MetricDesc drives entries of a
    // Scalars-shaped collection (bare values, no per-entry key) -- the array
    // itself is already named "per_core_pct" by the collection_begin call.
    MetricDesc core_desc{nullptr, "montauk_cpu_core_usage_percent", "Per-core CPU utilization"};
    sink.collection_begin("per_core_pct", Shape::Scalars);
    for (size_t i = 0; i < s.cpu.per_core_pct.size(); ++i) {
      std::string core = std::to_string(i);
      Label l[]{{"core", core}};
      sink.labeled_f64(core_desc, l, s.cpu.per_core_pct[i]);
    }
    sink.collection_end();
  }
  sink.section_end();
}

void render_pmu(MetricsSink& sink, const MetricsSnapshot& s) {
  sink.section_begin("pmu");
  sink.boolean({"available", "montauk_pmu_available", "Core PMU counters available"}, s.pmu.available);
  if (s.pmu.available) {
    sink.f64({"l2_misses_per_sec", "montauk_pmu_l2_misses_per_second",
              "L2 cache misses per second (sysfs cache-misses event)"}, s.pmu.l2_misses_per_sec);
    sink.f64({"l2_miss_pct", "montauk_pmu_l2_miss_percent",
              "L2 misses as percent of L2 references"}, s.pmu.l2_miss_pct);
    sink.f64({"ipc", "montauk_pmu_ipc", "Instructions per cycle (interval)"}, s.pmu.ipc);
    sink.f64({"cycles_per_l2_miss", "montauk_pmu_cycles_per_l2_miss",
              "Cycles per L2 miss (interval)"}, s.pmu.cycles_per_l2_miss);
    sink.u64({nullptr, "montauk_pmu_l2_misses_interval", "L2 misses this interval"}, s.pmu.l2_misses);
    sink.f64({"instructions_per_sec", "montauk_pmu_instructions_per_second",
              "Instructions per second (interval)"}, s.pmu.instructions_per_sec);
    sink.f64({"context_switches_per_sec", "montauk_pmu_context_switches_per_second",
              "Context switches per second"}, s.pmu.context_switches_per_sec);
    sink.f64({"cpu_migrations_per_sec", "montauk_pmu_cpu_migrations_per_second",
              "CPU migrations per second"}, s.pmu.cpu_migrations_per_sec);
    sink.f64({"branch_misses_per_sec", "montauk_pmu_branch_misses_per_second",
              "Branch mispredictions per second"}, s.pmu.branch_misses_per_sec);

    if (s.thermal.has_power && s.pmu.instructions_per_sec > 0.0)
      sink.f64({nullptr, "montauk_energy_per_instruction_pj",
                "Energy per retired instruction (picojoules), RAPL power / IPS"},
               s.thermal.power_watts / s.pmu.instructions_per_sec * 1e12);

    if (!s.pmu.per_cpu_l2_misses.empty()) {
      // One entity-major loop drives both Prometheus families
      // (montauk_pmu_l2_misses_per_cpu / l2_miss_percent_per_cpu) --
      // PrometheusSink's family buffering groups by metric name regardless
      // of call interleaving, so the two still flush as separate blocks --
      // and a combined JSON "per_cpu" array, closing the "per-CPU L2 misses"
      // completeness gap.
      sink.collection_begin("per_cpu", Shape::Objects);
      MetricDesc miss_desc{nullptr, "montauk_pmu_l2_misses_per_cpu",
                            "L2 misses this interval, per logical CPU"};
      MetricDesc pct_desc{nullptr, "montauk_pmu_l2_miss_percent_per_cpu",
                           "L2 miss percent, per logical CPU"};
      for (size_t i = 0; i < s.pmu.per_cpu_l2_misses.size(); ++i) {
        int cpu = i < s.pmu.per_cpu_ids.size() ? s.pmu.per_cpu_ids[i] : static_cast<int>(i);
        double refs = i < s.pmu.per_cpu_l2_refs.size() ? static_cast<double>(s.pmu.per_cpu_l2_refs[i]) : 0.0;
        double pct = refs > 0.0 ? 100.0 * static_cast<double>(s.pmu.per_cpu_l2_misses[i]) / refs : 0.0;
        sink.entry_begin();
        sink.i64({"cpu", nullptr, nullptr}, cpu);
        sink.u64({"l2_misses", nullptr, nullptr}, s.pmu.per_cpu_l2_misses[i]);
        sink.f64({"l2_miss_pct", nullptr, nullptr}, pct);
        std::string cpu_str = std::to_string(cpu);
        Label l[]{{"cpu", cpu_str}};
        sink.labeled_u64(miss_desc, l, s.pmu.per_cpu_l2_misses[i]);
        sink.labeled_f64(pct_desc, l, pct);
        sink.entry_end();
      }
      sink.collection_end();
    }

    sink.boolean({"l3_available", "montauk_pmu_l3_available", "amd_l3 uncore PMU available"}, s.pmu.l3_available);
    if (s.pmu.l3_available) {
      sink.collection_begin("l3_per_cache_domain", Shape::Objects);
      MetricDesc l3_miss{nullptr, "montauk_pmu_l3_misses_interval",
                          "L3 misses this interval, per cache domain domain"};
      MetricDesc l3_acc{nullptr, "montauk_pmu_l3_accesses_interval",
                         "L3 accesses this interval, per cache domain domain"};
      MetricDesc l3_pct{nullptr, "montauk_pmu_l3_miss_percent",
                         "L3 miss percent, per cache domain domain"};
      for (const auto& d : s.pmu.l3_per_cache_domain) {
        sink.entry_begin();
        sink.i64({"cache_domain", nullptr, nullptr}, d.domain_cpu);
        sink.u64({"misses", nullptr, nullptr}, d.misses);
        sink.u64({"accesses", nullptr, nullptr}, d.accesses);
        sink.f64({"miss_pct", nullptr, nullptr}, d.miss_pct);
        std::string domain = std::to_string(d.domain_cpu);
        Label l[]{{"cache_domain", domain}};
        sink.labeled_u64(l3_miss, l, d.misses);
        sink.labeled_u64(l3_acc, l, d.accesses);
        sink.labeled_f64(l3_pct, l, d.miss_pct);
        sink.entry_end();
      }
      sink.collection_end();
    }
  }
  sink.section_end();
}

void render_memory(MetricsSink& sink, const MetricsSnapshot& s) {
  sink.section_begin("memory");
  sink.u64({"total_kb", nullptr, nullptr}, s.mem.total_kb);
  sink.u64({nullptr, "montauk_memory_total_bytes", "Total physical memory"}, s.mem.total_kb * 1024ULL);
  sink.u64({"used_kb", nullptr, nullptr}, s.mem.used_kb);
  sink.u64({nullptr, "montauk_memory_used_bytes", "Used physical memory"}, s.mem.used_kb * 1024ULL);
  sink.u64({"available_kb", nullptr, nullptr}, s.mem.available_kb);
  sink.u64({nullptr, "montauk_memory_available_bytes", "Available memory (MemAvailable)"}, s.mem.available_kb * 1024ULL);
  sink.u64({"cached_kb", nullptr, nullptr}, s.mem.cached_kb);
  sink.u64({nullptr, "montauk_memory_cached_bytes", "Cached memory"}, s.mem.cached_kb * 1024ULL);
  sink.u64({"buffers_kb", nullptr, nullptr}, s.mem.buffers_kb);
  sink.u64({nullptr, "montauk_memory_buffers_bytes", "Buffer memory"}, s.mem.buffers_kb * 1024ULL);
  sink.u64({"swap_total_kb", nullptr, nullptr}, s.mem.swap_total_kb);
  sink.u64({nullptr, "montauk_memory_swap_total_bytes", "Total swap space"}, s.mem.swap_total_kb * 1024ULL);
  sink.u64({"swap_used_kb", nullptr, nullptr}, s.mem.swap_used_kb);
  sink.u64({nullptr, "montauk_memory_swap_used_bytes", "Used swap space"}, s.mem.swap_used_kb * 1024ULL);
  sink.f64({"used_pct", "montauk_memory_used_percent", "Memory utilization percent"}, s.mem.used_pct);
  sink.section_end();
}

void render_gpu(MetricsSink& sink, const MetricsSnapshot& s) {
  sink.section_begin("gpu");
  sink.str({"name", nullptr, nullptr}, s.vram.name);
  sink.u64({"total_mb", nullptr, nullptr}, s.vram.total_mb);
  sink.u64({nullptr, "montauk_gpu_vram_total_bytes_aggregate", "Total GPU VRAM"}, s.vram.total_mb * 1048576ULL);
  sink.u64({"used_mb", nullptr, nullptr}, s.vram.used_mb);
  sink.u64({nullptr, "montauk_gpu_vram_used_bytes_aggregate", "Used GPU VRAM"}, s.vram.used_mb * 1048576ULL);
  sink.f64({"used_pct", "montauk_gpu_vram_used_percent", "GPU VRAM utilization percent"}, s.vram.used_pct);
  if (s.vram.has_util) sink.f64({"util_pct", "montauk_gpu_utilization_percent", "GPU core utilization"}, s.vram.gpu_util_pct);
  if (s.vram.has_mem_util) sink.f64({"mem_util_pct", "montauk_gpu_memory_controller_percent", "GPU memory controller utilization"}, s.vram.mem_util_pct);
  if (s.vram.has_encdec) {
    sink.f64({"enc_util_pct", "montauk_gpu_encoder_percent", "GPU encoder utilization"}, s.vram.enc_util_pct);
    sink.f64({"dec_util_pct", "montauk_gpu_decoder_percent", "GPU decoder utilization"}, s.vram.dec_util_pct);
  }
  if (s.vram.has_power) sink.f64({"power_draw_w", "montauk_gpu_power_draw_watts", "GPU power draw"}, s.vram.power_draw_w);
  if (s.vram.has_power_limit) sink.f64({"power_limit_w", "montauk_gpu_power_limit_watts", "GPU power limit"}, s.vram.power_limit_w);

  if (!s.vram.devices.empty()) {
    sink.collection_begin("devices", Shape::Objects);
    MetricDesc total_bytes{nullptr, "montauk_gpu_vram_total_bytes", "Per-device GPU VRAM total"};
    MetricDesc used_bytes{nullptr, "montauk_gpu_vram_used_bytes", "Per-device GPU VRAM used"};
    MetricDesc edge{nullptr, "montauk_gpu_temperature_edge_celsius", "GPU edge temperature"};
    MetricDesc hotspot{nullptr, "montauk_gpu_temperature_hotspot_celsius", "GPU hotspot temperature"};
    MetricDesc mem_temp{nullptr, "montauk_gpu_temperature_memory_celsius", "GPU memory temperature"};
    MetricDesc fan{nullptr, "montauk_gpu_fan_speed_percent", "GPU fan speed percent"};
    for (const auto& d : s.vram.devices) {
      sink.entry_begin();
      sink.str({"name", nullptr, nullptr}, d.name);
      sink.u64({"total_mb", nullptr, nullptr}, d.total_mb);
      sink.u64({"used_mb", nullptr, nullptr}, d.used_mb);
      Label name_label[]{{"device", d.name}};
      sink.labeled_u64(total_bytes, name_label, d.total_mb * 1048576ULL);
      sink.labeled_u64(used_bytes, name_label, d.used_mb * 1048576ULL);
      if (d.has_temp_edge) { sink.f64({"temp_edge_c", nullptr, nullptr}, d.temp_edge_c); sink.labeled_f64(edge, name_label, d.temp_edge_c); }
      if (d.has_temp_hotspot) { sink.f64({"temp_hotspot_c", nullptr, nullptr}, d.temp_hotspot_c); sink.labeled_f64(hotspot, name_label, d.temp_hotspot_c); }
      if (d.has_temp_mem) { sink.f64({"temp_mem_c", nullptr, nullptr}, d.temp_mem_c); sink.labeled_f64(mem_temp, name_label, d.temp_mem_c); }
      if (d.has_fan) { sink.f64({"fan_speed_pct", nullptr, nullptr}, d.fan_speed_pct); sink.labeled_f64(fan, name_label, d.fan_speed_pct); }
      sink.entry_end();
    }
    sink.collection_end();
  }
  sink.section_end();
}

void render_thermal(MetricsSink& sink, const MetricsSnapshot& s) {
  sink.section_begin("thermal");
  if (s.thermal.has_temp) {
    sink.f64({"cpu_max_c", nullptr, nullptr}, s.thermal.cpu_max_c);
    sink.f64({nullptr, "montauk_thermal_cpu_temperature_celsius", "CPU max temperature"}, s.thermal.cpu_max_c);
  }
  if (s.thermal.has_fan) {
    sink.f64({"fan_rpm", nullptr, nullptr}, s.thermal.fan_rpm);
    sink.f64({nullptr, "montauk_thermal_fan_speed_rpm", "CPU fan speed RPM"}, s.thermal.fan_rpm);
  }
  if (s.thermal.has_power) {
    sink.f64({"power_watts", nullptr, nullptr}, s.thermal.power_watts);
    sink.f64({nullptr, "montauk_power_watts",
              "Package power draw from RAPL/powercap (energy delta per interval)"}, s.thermal.power_watts);
  }
  if (s.thermal.has_energy)
    sink.f64({nullptr, "montauk_package_energy_joules_total",
              "Cumulative package energy from RAPL/powercap (joules, wrap-safe); "
              "window-integral energy is the counter delta", MetricKind::Counter},
             s.thermal.energy_joules_total);
  if (!s.thermal.cstates.empty()) {
    sink.collection_begin("cstates", Shape::Objects);
    MetricDesc cs_desc{nullptr, "montauk_cstate_residency_percent",
                        "Idle-state residency this interval, per state (across CPUs)"};
    for (const auto& cs : s.thermal.cstates) {
      sink.entry_begin();
      sink.str({"name", nullptr, nullptr}, cs.name);
      sink.f64({"residency_pct", nullptr, nullptr}, cs.residency_pct);
      Label l[]{{"state", cs.name}};
      sink.labeled_f64(cs_desc, l, cs.residency_pct);
      sink.entry_end();
    }
    sink.collection_end();
  }
  sink.section_end();
}

void render_network(MetricsSink& sink, const MetricsSnapshot& s) {
  sink.section_begin("network");
  sink.f64({"agg_rx_bps", "montauk_network_receive_bps_total", "Aggregate receive bytes/sec"}, s.net.agg_rx_bps);
  sink.f64({"agg_tx_bps", "montauk_network_transmit_bps_total", "Aggregate transmit bytes/sec"}, s.net.agg_tx_bps);
  if (!s.net.interfaces.empty()) {
    sink.collection_begin("interfaces", Shape::Objects);
    MetricDesc rx{nullptr, "montauk_network_interface_receive_bps", "Per-interface receive bytes/sec"};
    MetricDesc tx{nullptr, "montauk_network_interface_transmit_bps", "Per-interface transmit bytes/sec"};
    for (const auto& iface : s.net.interfaces) {
      sink.entry_begin();
      sink.str({"name", nullptr, nullptr}, iface.name);
      sink.f64({"rx_bps", nullptr, nullptr}, iface.rx_bps);
      sink.f64({"tx_bps", nullptr, nullptr}, iface.tx_bps);
      Label l[]{{"interface", iface.name}};
      sink.labeled_f64(rx, l, iface.rx_bps);
      sink.labeled_f64(tx, l, iface.tx_bps);
      sink.entry_end();
    }
    sink.collection_end();
  }
  sink.section_end();
}

void render_disk(MetricsSink& sink, const MetricsSnapshot& s) {
  sink.section_begin("disk");
  sink.f64({"total_read_bps", "montauk_disk_read_bps_total", "Aggregate disk read bytes/sec"}, s.disk.total_read_bps);
  sink.f64({"total_write_bps", "montauk_disk_write_bps_total", "Aggregate disk write bytes/sec"}, s.disk.total_write_bps);
  if (!s.disk.devices.empty()) {
    sink.collection_begin("devices", Shape::Objects);
    MetricDesc rd{nullptr, "montauk_disk_device_read_bps", "Per-device read bytes/sec"};
    MetricDesc wr{nullptr, "montauk_disk_device_write_bps", "Per-device write bytes/sec"};
    MetricDesc ut{nullptr, "montauk_disk_device_utilization_percent", "Per-device I/O utilization"};
    for (const auto& d : s.disk.devices) {
      sink.entry_begin();
      sink.str({"name", nullptr, nullptr}, d.name);
      sink.f64({"read_bps", nullptr, nullptr}, d.read_bps);
      sink.f64({"write_bps", nullptr, nullptr}, d.write_bps);
      sink.f64({"util_pct", nullptr, nullptr}, d.util_pct);
      Label l[]{{"device", d.name}};
      sink.labeled_f64(rd, l, d.read_bps);
      sink.labeled_f64(wr, l, d.write_bps);
      sink.labeled_f64(ut, l, d.util_pct);
      sink.entry_end();
    }
    sink.collection_end();
  }
  sink.section_end();
}

void render_filesystems(MetricsSink& sink, const MetricsSnapshot& s) {
  sink.collection_begin("filesystems", Shape::Objects);
  MetricDesc total{nullptr, "montauk_filesystem_total_bytes", "Filesystem total size"};
  MetricDesc used{nullptr, "montauk_filesystem_used_bytes", "Filesystem used bytes"};
  MetricDesc avail{nullptr, "montauk_filesystem_available_bytes", "Filesystem available bytes"};
  MetricDesc pct{nullptr, "montauk_filesystem_used_percent", "Filesystem utilization percent"};
  for (const auto& m : s.fs.mounts) {
    sink.entry_begin();
    sink.str({"device", nullptr, nullptr}, m.device);
    sink.str({"mountpoint", nullptr, nullptr}, m.mountpoint);
    sink.str({"fstype", nullptr, nullptr}, m.fstype);
    sink.u64({"total_bytes", nullptr, nullptr}, m.total_bytes);
    sink.u64({"used_bytes", nullptr, nullptr}, m.used_bytes);
    sink.u64({"avail_bytes", nullptr, nullptr}, m.avail_bytes);
    sink.f64({"used_pct", nullptr, nullptr}, m.used_pct);
    Label l[]{{"device", m.device}, {"mountpoint", m.mountpoint}, {"fstype", m.fstype}};
    sink.labeled_u64(total, l, m.total_bytes);
    sink.labeled_u64(used, l, m.used_bytes);
    sink.labeled_u64(avail, l, m.avail_bytes);
    sink.labeled_f64(pct, l, m.used_pct);
    sink.entry_end();
  }
  sink.collection_end();
}

void render_providers(MetricsSink& sink, const MetricsSnapshot& s) {
  if (s.providers.empty()) return;
  sink.collection_begin("providers", Shape::Objects);
  for (const auto& p : s.providers) {
    sink.entry_begin();
    sink.provider(p);
    sink.entry_end();
  }
  sink.collection_end();
}

void render_processes(MetricsSink& sink, const MetricsSnapshot& s) {
  sink.section_begin("processes");
  sink.u64({"total", "montauk_processes_total", "Total processes"}, s.total_processes);
  sink.u64({"running", "montauk_processes_running", "Running processes"}, s.running_processes);
  sink.u64({"sleeping", "montauk_processes_sleeping", "Sleeping processes"}, s.state_sleeping);
  sink.u64({"zombie", "montauk_processes_zombie", "Zombie processes"}, s.state_zombie);
  sink.u64({"threads", "montauk_threads_total", "Total threads"}, s.total_threads);

  if (s.top_procs_count > 0) {
    sink.collection_begin("top", Shape::Objects);
    MetricDesc cpu_desc{nullptr, "montauk_process_cpu_percent", "Per-process CPU utilization"};
    MetricDesc mem_desc{nullptr, "montauk_process_memory_bytes", "Per-process resident memory"};
    MetricDesc gpu_util_desc{nullptr, "montauk_process_gpu_utilization_percent", "Per-process GPU utilization"};
    MetricDesc gpu_mem_desc{nullptr, "montauk_process_gpu_memory_bytes", "Per-process GPU memory"};
    MetricDesc anom_desc{nullptr, "montauk_process_anomaly_score", "Per-process fused anomaly score"};
    for (int i = 0; i < s.top_procs_count; ++i) {
      const auto& p = s.top_procs[i];
      sink.entry_begin();
      sink.i64({"pid", nullptr, nullptr}, p.pid);
      sink.str({"cmd", nullptr, nullptr}, p.cmd);
      sink.str({"user", nullptr, nullptr}, p.user_name);
      sink.f64({"cpu_pct", nullptr, nullptr}, p.cpu_pct);
      sink.u64({"rss_kb", nullptr, nullptr}, p.rss_kb);
      if (p.has_gpu_util) sink.f64({"gpu_util_pct", nullptr, nullptr}, p.gpu_util_pct);
      if (p.has_gpu_mem) sink.u64({"gpu_mem_kb", nullptr, nullptr}, p.gpu_mem_kb);
      sink.f64({"anomaly_score", nullptr, nullptr}, p.anomaly_score);
      sink.i64({"anomaly_axis", nullptr, nullptr}, p.anomaly_axis);

      // Prometheus per-process labels: pid + cmd, cmd truncated to 32 chars --
      // preserved verbatim from emit_labeled_2d/2u's original max_len=32 arg.
      std::string pid_str = std::to_string(p.pid);
      std::string cmd_trunc = p.cmd.substr(0, 32);
      Label l[]{{"pid", pid_str}, {"cmd", cmd_trunc}};
      sink.labeled_f64(cpu_desc, l, p.cpu_pct);
      sink.labeled_u64(mem_desc, l, p.rss_kb * 1024ULL);
      if (p.has_gpu_util) sink.labeled_f64(gpu_util_desc, l, p.gpu_util_pct);
      if (p.has_gpu_mem) sink.labeled_u64(gpu_mem_desc, l, p.gpu_mem_kb * 1024ULL);
      sink.labeled_f64(anom_desc, l, p.anomaly_score);
      sink.entry_end();
    }
    sink.collection_end();
  }
  sink.section_end();
}

}  // namespace

void render_snapshot(MetricsSink& sink, const MetricsSnapshot& s) {
  render_system(sink, s);
  render_cpu(sink, s);
  render_pmu(sink, s);
  render_memory(sink, s);
  render_gpu(sink, s);
  render_thermal(sink, s);
  render_network(sink, s);
  render_disk(sink, s);
  render_filesystems(sink, s);
  render_providers(sink, s);
  render_processes(sink, s);
}

}  // namespace montauk::app
