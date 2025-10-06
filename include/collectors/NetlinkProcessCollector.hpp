#pragma once

#include "collectors/IProcessCollector.hpp"
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_set>
#include <unordered_map>
#include <string>

namespace montauk::collectors {

// Event-driven process collector using Linux Process Events Connector (netlink)
// Falls back gracefully if unavailable.
class NetlinkProcessCollector : public IProcessCollector {
public:
  explicit NetlinkProcessCollector(size_t max_procs = 256);
  ~NetlinkProcessCollector() override;

  bool init() override;        // returns false if socket cannot be created/bound
  void shutdown() override;    // stop thread, unsubscribe, close socket
  bool sample(montauk::model::ProcessSnapshot& out) override;
  const char* name() const override { return "Event-Driven Netlink"; }

private:
  // Netlink socket (Linux only)
  int nl_sock_{-1};

  // Event processing thread
  std::thread event_thread_;
  std::atomic<bool> running_{false};

  // Thread-safe process tracking and comm cache
  std::mutex active_mu_;
  std::unordered_set<int32_t> active_pids_;
  std::unordered_map<int32_t, std::string> pid_to_comm_;

  // CPU deltas for percentage computation
  std::unordered_map<int32_t, uint64_t> last_per_proc_{}; // pid -> total_time
  uint64_t last_cpu_total_{};
  bool have_last_{false};
  unsigned ncpu_{0};

  // Limits
  size_t max_procs_{};
  size_t sample_budget_{2048}; // max processes to sample per tick
  size_t rr_cursor_{0};        // round-robin cursor over active set
  std::vector<int32_t> last_top_; // last published top-K pids
  std::unordered_set<int32_t> hot_pids_; // recently fork/exec pids to prioritize

  // Event processing helpers (Linux only)
  void event_loop();
  void handle_cn_msg(void* cn_msg_ptr, ssize_t len);
  void send_control_message(int op);

  // Sampling helpers (shared with traditional logic but replicated here to avoid refactor)
  static uint64_t read_cpu_total();
  static unsigned read_cpu_count();
  static bool parse_stat_line(const std::string& content, int32_t& ppid, uint64_t& utime, uint64_t& stime, int64_t& rss_pages, std::string& comm);
  static std::string read_cmdline(int32_t pid);
  static std::string user_from_status(int32_t pid);
};

} // namespace montauk::collectors
