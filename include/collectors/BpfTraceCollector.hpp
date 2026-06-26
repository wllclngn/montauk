#pragma once
#include "app/TraceBuffers.hpp"
#include "app/ProviderEmitter.hpp"
#include "collectors/ProviderCollector.hpp"
#include "sublimation_text.hpp"
#include <thread>
#include <string>
#include <vector>
#include <atomic>
#include <cstdint>
#include <unordered_set>

// Forward-declare libbpf types (avoid pulling in libbpf headers here)
struct montauk_trace_bpf;
struct ring_buffer;
struct bpf_link;

namespace montauk::collectors {

class BpfTraceCollector {
public:
  BpfTraceCollector(montauk::app::TraceBuffers& buffers, std::string pattern);
  ~BpfTraceCollector();
  BpfTraceCollector(const BpfTraceCollector&) = delete;
  BpfTraceCollector& operator=(const BpfTraceCollector&) = delete;

  void start();
  void stop();

  // Enable raw binary event logging to `path` (the --trace-out target).
  // Must be called before start(). Opens the file and writes the format
  // header; every ring event is then appended verbatim and flushed in
  // batches. No-op if path is empty.
  void set_binary_output(const std::string& path);

private:
  void run(std::stop_token st);

  // Append one raw ring record ([len][payload]) to the binary log buffer;
  // flush if the buffer crosses the batch threshold. No-op when binary
  // output is disabled.
  void trace_append(const void* data, size_t len);
  // Write the accumulated buffer to the trace fd in one (retried) write
  // and clear it. No-op when disabled or empty.
  void trace_flush();

  // Scrape metrics providers and append one TRACE_EVT_PROVIDER record per
  // provider to the binary log. No-op when binary output is disabled.
  void append_provider_snapshots();

  // Track quark's wineserver daemon by the daemon_pid="N" label it publishes in
  // its provider text — writes the pid straight into the BPF proc_map. Comm- and
  // timing-independent: quark knows its own pid, so it tells us.
  void track_daemon_from_provider(const std::string& provider_text);

  // Embed a generic cpu -> cache-hierarchy (L2/L3/socket) snapshot once, so the
  // offline analyzer can turn each migration into a cache-tier distance with no
  // live /sys read (decode-anywhere). Named "cache_topology"; names no scheduler.
  void append_cache_topology_snapshot();
  bool cache_topo_emitted_ = false;

  // Read the per-CPU sched_ext kick-storm counters, delta vs the previous cycle,
  // and append one TRACE_EVT_SCX_STORM sample. Names the cpu_release storm from the
  // trace -- replaces the scheduler-stdout scrape (storm_score).
  void append_scx_storm_sample();
  uint64_t scx_kicks_last_ = 0, scx_preempt_last_ = 0, scx_reenq_last_ = 0;
  uint64_t scx_sample_last_ns_ = 0;

  // Add a PID to the BPF proc_map (tracked set)
  void track_pid(int32_t pid, int32_t ppid, bool is_root, const char* comm);
  // Snapshot /proc/<pid>/maps to the per-incident sidecar while the process
  // is alive (death-time snapshots race the reap and land empty).
  void snapshot_maps(uint32_t pid);

  // Read BPF maps and fill TraceSnapshot — zero /proc
  void snapshot_from_maps(montauk::model::TraceSnapshot& snap);

  // Periodic re-scan of BPF map comms for pattern matching — zero /proc
  void rescan_comms();

  // Build self-exclusion set via getpid/getppid — zero /proc
  void build_self_exclusion();

  // Ring buffer event callback
  static int handle_event(void* ctx, void* data, size_t len);

  // Syscall decode
  static const char* syscall_name(int nr);

  // True if `s` matches any of the --trace pattern tokens (substring, ci).
  bool matches_any(const std::string& s) const;

  montauk::app::TraceBuffers& buffers_;
  std::string pattern_;            // full --trace value (comma-separated list)
  std::string primary_pattern_;    // first token: the BPF .rodata fast-path
  std::vector<sublimation::BMH> matchers_;  // one per token; OR
  // montauk's own producer endpoint in the provider mesh: serves the trace
  // snapshot as Prometheus text so montauk is a peer, not a stderr dumper.
  montauk::app::ProviderEmitter emitter_{montauk::app::ProviderEmitter::kSelfName};
  std::jthread thread_;

  struct montauk_trace_bpf* skel_{nullptr};
  struct ring_buffer* rb_{nullptr};
  struct bpf_link* enroll_iter_link_{nullptr};  // task-iterator thread enrollment

  uint64_t last_snapshot_ns_{};

  // Pending ntsync events accumulated between snapshots (same thread, no lock)
  std::vector<montauk::model::NtsyncSample> pending_ntsync_;

  bool printed_waiting_{false};
  std::atomic<bool> load_failed_{false};
  std::unordered_set<int32_t> excluded_pids_;
  // Pids whose /proc/<pid>/maps sidecar has been snapshotted (first HEAP
  // event), so heapstack/abort IPs resolve to module+offset. Once per pid.
  std::unordered_set<uint32_t> maps_snapshotted_;

  // Binary trace log (--trace-out). -1 fd = disabled. Buffer is owned by
  // the collector thread (ring callback + run loop are the only writers),
  // so no lock is needed.
  int trace_fd_{-1};
  std::vector<uint8_t> trace_buf_;
  ProviderCollector providers_{};

public:
  [[nodiscard]] bool failed() const { return load_failed_.load(); }
};

} // namespace montauk::collectors
