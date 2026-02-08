#include "app/MetricsServer.hpp"
#include <charconv>
#include <cstdio>
#include <algorithm>

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

} // anonymous namespace

namespace montauk::app {

std::string snapshot_to_prometheus(const MetricsSnapshot& s) {
  std::string out;
  out.reserve(8192);

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

  emit_header(out, "montauk_cpu_context_switches_per_second", "Context switches per second", "gauge");
  emit_gauge_d(out, "montauk_cpu_context_switches_per_second", s.cpu.ctxt_per_sec);
  emit_header(out, "montauk_cpu_interrupts_per_second", "Hardware interrupts per second", "gauge");
  emit_gauge_d(out, "montauk_cpu_interrupts_per_second", s.cpu.intr_per_sec);

  emit_header(out, "montauk_cpu_physical_cores", "Physical CPU cores", "gauge");
  emit_gauge_i(out, "montauk_cpu_physical_cores", s.cpu.physical_cores);
  emit_header(out, "montauk_cpu_logical_threads", "Logical CPU threads", "gauge");
  emit_gauge_i(out, "montauk_cpu_logical_threads", s.cpu.logical_threads);

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

  return out;
}

} // namespace montauk::app
