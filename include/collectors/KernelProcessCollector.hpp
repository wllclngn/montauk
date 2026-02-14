#pragma once

#include "collectors/IProcessCollector.hpp"
#include <unordered_map>
#include <string>
#include <cstdint>

namespace montauk::collectors {

/**
 * Process collector that communicates with the montauk kernel module
 * via Generic Netlink. Provides complete process data without any
 * /proc reads when the kernel module is loaded.
 */
class KernelProcessCollector : public IProcessCollector {
public:
  KernelProcessCollector();
  ~KernelProcessCollector();

  bool init() override;
  void shutdown() override;
  bool sample(montauk::model::ProcessSnapshot& out) override;
  const char* name() const override { return "Kernel Module"; }

private:
  int nl_sock_{-1};
  int family_id_{-1};
  uint32_t seq_{0};

  // For CPU% delta calculation
  std::unordered_map<int32_t, uint64_t> last_per_proc_;
  uint64_t last_cpu_total_{0};
  bool have_last_{false};
  int ncpu_{0};

  // Cmdline cache (one-shot per PID, populated from /proc in userspace)
  std::unordered_map<int32_t, std::string> cmdline_cache_;

  // Helpers
  bool resolve_family();
  bool send_get_snapshot();
  bool recv_snapshot(montauk::model::ProcessSnapshot& out);
  uint64_t read_cpu_total();
  int read_cpu_count();
  std::string read_cmdline(int32_t pid);
};

} // namespace montauk::collectors
