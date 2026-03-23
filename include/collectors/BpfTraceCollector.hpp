#pragma once
#include "app/TraceBuffers.hpp"
#include "util/BoyerMoore.hpp"
#include <thread>
#include <string>
#include <atomic>
#include <unordered_set>

// Forward-declare libbpf types (avoid pulling in libbpf headers here)
struct montauk_trace_bpf;
struct ring_buffer;

namespace montauk::collectors {

class BpfTraceCollector {
public:
  BpfTraceCollector(montauk::app::TraceBuffers& buffers, std::string pattern);
  ~BpfTraceCollector();
  BpfTraceCollector(const BpfTraceCollector&) = delete;
  BpfTraceCollector& operator=(const BpfTraceCollector&) = delete;

  void start();
  void stop();

private:
  void run(std::stop_token st);

  // Add a PID to the BPF proc_map (tracked set)
  void track_pid(int32_t pid, int32_t ppid, bool is_root, const char* comm);

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

  montauk::app::TraceBuffers& buffers_;
  std::string pattern_;
  montauk::util::BoyerMooreSearch matcher_;
  std::jthread thread_;

  struct montauk_trace_bpf* skel_{nullptr};
  struct ring_buffer* rb_{nullptr};

  uint64_t last_snapshot_ns_{};

  bool printed_waiting_{false};
  std::atomic<bool> load_failed_{false};
  std::unordered_set<int32_t> excluded_pids_;

public:
  [[nodiscard]] bool failed() const { return load_failed_.load(); }
};

} // namespace montauk::collectors
