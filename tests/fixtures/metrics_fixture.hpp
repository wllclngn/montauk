// A fixed, deterministic MetricsSnapshot/TraceSnapshot -- no clocks, no
// randomness, same spirit as gen_synthetic_trace.cpp -- so the renderer
// unification refactor (JsonSerializer.cpp/PrometheusSerializer.cpp ->
// MetricsSink/MetricsRender/TraceRender) has a real byte-identical oracle to
// verify against, and so snapshot_to_json/snapshot_to_prometheus/
// trace_to_prometheus/trace_to_json have permanent golden coverage
// afterward. Touches every top-level section at least once, and exercises
// both the present and absent branch of several optional fields (GPU
// mem-temp/thr_* deliberately left absent; edge/hotspot temp present).
#pragma once

#include "app/MetricsServer.hpp"
#include "model/Trace.hpp"

inline montauk::app::MetricsSnapshot make_fixture_snapshot() {
  using namespace montauk::model;
  montauk::app::MetricsSnapshot s{};

  s.cpu.model = "Test CPU";
  s.cpu.physical_cores = 6;
  s.cpu.logical_threads = 12;
  s.cpu.usage_pct = 42.5;
  s.cpu.pct_user = 20.0;
  s.cpu.pct_system = 15.0;
  s.cpu.pct_iowait = 5.0;
  s.cpu.pct_irq = 1.5;
  s.cpu.pct_steal = 1.0;
  s.cpu.has_freq = true;
  s.cpu.freq_avg_mhz = 3800.0;
  s.cpu.ctxt_per_sec = 12345.0;
  s.cpu.intr_per_sec = 6789.0;
  s.cpu.per_core_pct = {10.0, 20.0, 30.0, 40.0};

  s.pmu.available = true;
  s.pmu.l2_misses_per_sec = 1000.0;
  s.pmu.l2_miss_pct = 5.5;
  s.pmu.ipc = 1.25;
  s.pmu.cycles_per_l2_miss = 200.0;
  s.pmu.l2_misses = 500;
  s.pmu.instructions_per_sec = 2000000.0;
  s.pmu.context_switches_per_sec = 300.0;
  s.pmu.cpu_migrations_per_sec = 4.0;
  s.pmu.branch_misses_per_sec = 55.0;
  s.pmu.per_cpu_ids = {0, 1};
  s.pmu.per_cpu_l2_misses = {100, 200};
  s.pmu.per_cpu_l2_refs = {1000, 2000};
  s.pmu.l3_available = true;
  s.pmu.l3_per_cache_domain = {
      PmuSnapshot::DomainL3{0, 5000, 250, 5.0},
      PmuSnapshot::DomainL3{6, 6000, 300, 5.0},
  };

  s.mem.total_kb = 65757452;
  s.mem.used_kb = 4210212;
  s.mem.available_kb = 61547240;
  s.mem.cached_kb = 2301072;
  s.mem.buffers_kb = 998164;
  s.mem.swap_total_kb = 0;
  s.mem.swap_used_kb = 0;
  s.mem.used_pct = 6.4;

  s.vram.name = "Test GPU";
  s.vram.total_mb = 6144;
  s.vram.used_mb = 849;
  s.vram.used_pct = 13.8;
  s.vram.has_util = true;
  s.vram.gpu_util_pct = 18.0;
  s.vram.has_mem_util = true;
  s.vram.mem_util_pct = 14.0;
  s.vram.has_power = true;
  s.vram.power_draw_w = 24.19;
  s.vram.has_power_limit = true;
  s.vram.power_limit_w = 160.0;
  s.vram.has_encdec = true;
  s.vram.enc_util_pct = 3.0;
  s.vram.dec_util_pct = 2.0;
  {
    GpuVramDevice d{};
    d.name = "Test GPU";
    d.total_mb = 6144;
    d.used_mb = 849;
    d.has_temp_edge = true;
    d.temp_edge_c = 57.0;
    d.has_temp_hotspot = true;
    d.temp_hotspot_c = 68.0;
    d.has_fan = true;
    d.fan_speed_pct = 0.0;
    // Deliberately absent: has_temp_mem, has_thr_edge/hotspot/mem, has_pstate.
    s.vram.devices.push_back(d);
  }

  s.net.agg_rx_bps = 8759.98;
  s.net.agg_tx_bps = 107977.30;
  s.net.interfaces.push_back(NetIf{.name = "enp5s0", .rx_bps = 8759.98, .tx_bps = 107977.30});
  s.net.interfaces.push_back(NetIf{.name = "wlan0", .rx_bps = 0.0, .tx_bps = 0.0});

  s.disk.total_read_bps = 0.0;
  s.disk.total_write_bps = 0.0;
  s.disk.devices.push_back(DiskDev{.name = "sda", .read_bps = 0.0, .write_bps = 0.0, .util_pct = 0.0});
  s.disk.devices.push_back(DiskDev{.name = "nvme0n1", .read_bps = 100.0, .write_bps = 50.0, .util_pct = 2.5});

  s.fs.mounts.push_back(FsMount{.device = "/dev/nvme0n1p2", .mountpoint = "/", .fstype = "ext4",
                                 .total_bytes = 244466741248ULL, .used_bytes = 165133987840ULL,
                                 .avail_bytes = 79332753408ULL, .used_pct = 67.5});
  s.fs.mounts.push_back(FsMount{.device = "/dev/nvme0n1p1", .mountpoint = "/boot", .fstype = "vfat",
                                 .total_bytes = 535805952ULL, .used_bytes = 243392512ULL,
                                 .avail_bytes = 292413440ULL, .used_pct = 45.4});

  {
    Provider p;
    p.name = "test-provider";
    p.raw_text = "# HELP test_metric a test metric\n# TYPE test_metric gauge\ntest_metric 1\n";
    p.metrics.push_back(ProviderMetric{.name = "test_metric", .labels = "", .value = 1.0});
    s.providers.push_back(std::move(p));
  }

  s.thermal.has_temp = true;
  s.thermal.cpu_max_c = 52.25;
  s.thermal.has_fan = true;
  s.thermal.fan_rpm = 1200.0;
  s.thermal.has_power = true;
  s.thermal.power_watts = 45.2;
  s.thermal.has_energy = true;
  s.thermal.energy_joules_total = 987654.0;
  s.thermal.cstates.push_back(CpuIdleState{.name = "C2", .residency_pct = 60.0});
  s.thermal.cstates.push_back(CpuIdleState{.name = "C6", .residency_pct = 30.0});

  s.total_processes = 305;
  s.running_processes = 2;
  s.state_sleeping = 300;
  s.state_zombie = 0;
  s.total_threads = 900;
  s.top_procs_count = 2;
  {
    ProcSample& p0 = s.top_procs[0];
    p0.pid = 805;
    p0.cmd = "montauk";
    p0.user_name = "mod";
    p0.cpu_pct = 1.5;
    p0.rss_kb = 45548;
    // has_gpu_util/has_gpu_mem deliberately left false on this one.
    ProcSample& p1 = s.top_procs[1];
    p1.pid = 939;
    p1.cmd = "gpu-process";
    p1.user_name = "mod";
    p1.cpu_pct = 0.5;
    p1.rss_kb = 267992;
    p1.has_gpu_util = true;
    p1.gpu_util_pct = 9.0;
    p1.has_gpu_mem = true;
    p1.gpu_mem_kb = 54984;
  }

  return s;
}

inline void set_cstr(char* dst, size_t cap, const char* src) {
  std::snprintf(dst, cap, "%s", src);
}

inline montauk::model::TraceSnapshot make_fixture_trace() {
  using namespace montauk::model;
  TraceSnapshot t{};
  t.seq = 42;
  t.waiting_for_match = false;

  t.procs_count = 1;
  TracedProcess& proc = t.procs[0];
  proc.pid = 1000;
  proc.ppid = 1;
  proc.is_root = true;
  proc.exited = false;
  proc.exit_code = 0;
  proc.fork_ts = 1000;
  proc.exec_ts = 1500;
  proc.exit_ts = 0;
  set_cstr(proc.cmd, sizeof(proc.cmd), "worker.exe");
  set_cstr(proc.exec_file, sizeof(proc.exec_file), "/usr/bin/worker");

  t.sched_op_total = {0, 100, 200, 5, 50, 25, 300};

  t.thread_count = 2;
  ThreadSample& th0 = t.threads[0];
  th0.pid = 1000; th0.tid = 1000; th0.state = 'R'; th0.cpu_pct = 12.5;
  th0.syscall_nr = -1; th0.cur_cpu = 2; th0.migrations = 3;
  set_cstr(th0.comm, sizeof(th0.comm), "worker.A");
  set_cstr(th0.wchan, sizeof(th0.wchan), "");
  set_cstr(th0.syscall_name, sizeof(th0.syscall_name), "");
  th0.io_fd = -1;

  ThreadSample& th1 = t.threads[1];
  th1.pid = 1000; th1.tid = 1001; th1.state = 'S'; th1.cpu_pct = 0.0;
  th1.syscall_nr = 0; th1.cur_cpu = -1; th1.migrations = 0;
  set_cstr(th1.comm, sizeof(th1.comm), "worker.B");
  set_cstr(th1.wchan, sizeof(th1.wchan), "futex_wait");
  set_cstr(th1.syscall_name, sizeof(th1.syscall_name), "read");
  th1.io_fd = 10;
  th1.io_count = 4096;
  th1.io_whence = 0;
  th1.io_result = 4096;
  th1.io_timestamp_ns = 123456789;

  t.mig_intra_domain = 10;
  t.mig_cross_domain = 3;
  t.mig_unknown_domain = 0;
  t.mig_intra_wake = 4;
  t.mig_intra_steal = 2;
  t.mig_cross_wake = 1;
  t.mig_cross_steal = 1;

  t.ntsync_count = 1;
  NtsyncSample& ns = t.ntsync_events[0];
  ns.pid = 1000; ns.tid = 1000; ns.op = 1 /* sem_release */; ns.fd = 10;
  ns.result = 0; ns.timestamp_ns = 987654321; ns.arg0 = 1; ns.arg1 = 0; ns.wait_owner = 0;
  set_cstr(ns.comm, sizeof(ns.comm), "worker.A");

  t.fd_count = 1;
  FdSample& fd = t.fds[0];
  fd.pid = 1000; fd.fd_num = 10;
  set_cstr(fd.target, sizeof(fd.target), "anon_inode:[ntsync]");

  return t;
}
