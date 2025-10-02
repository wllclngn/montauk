#include "app/Alerts.hpp"
#include <chrono>
namespace steady = std::chrono;

namespace montauk::app {

AlertEngine::AlertEngine(AlertRules rules) : rules_(rules) {}

std::vector<Alert> AlertEngine::evaluate(const montauk::model::Snapshot& s) {
  std::vector<Alert> out;
  auto now = steady::steady_clock::now();
  // CPU total sustained
  if (s.cpu.usage_pct >= rules_.cpu_total_high_pct) {
    if (cpu_high_since_.time_since_epoch().count() == 0) cpu_high_since_ = now;
    if (now - cpu_high_since_ >= rules_.sustain) out.push_back({"crit", "CPU total sustained high"});
  } else { cpu_high_since_ = {}; }

  // Memory
  if (s.mem.used_pct >= rules_.mem_high_pct) {
    if (mem_high_since_.time_since_epoch().count() == 0) mem_high_since_ = now;
    if (now - mem_high_since_ >= rules_.sustain) out.push_back({"crit", "Memory usage sustained high"});
  } else { mem_high_since_ = {}; }

  // Top process
  if (!s.procs.processes.empty()) {
    if (s.procs.processes[0].cpu_pct >= rules_.top_proc_cpu_pct) out.push_back({"warn", "Top process CPU high"});
  }
  return out;
}

} // namespace montauk::app
