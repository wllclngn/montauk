#pragma once
#include "model/Snapshot.hpp"
#include <string>
#include <vector>
#include <chrono>

namespace montauk::app {

struct Alert {
  std::string severity; // info|warn|crit
  std::string message;
};

struct AlertRules {
  double cpu_total_high_pct = 90.0;   // crit if sustained
  double mem_high_pct       = 90.0;   // warn/crit
  double top_proc_cpu_pct   = 80.0;   // warn
  std::chrono::seconds sustain = std::chrono::seconds(3);
};

class AlertEngine {
public:
  explicit AlertEngine(AlertRules rules = {});
  // Evaluate snapshot; may return empty if healthy
  std::vector<Alert> evaluate(const montauk::model::Snapshot& s);
private:
  AlertRules rules_;
  std::chrono::steady_clock::time_point cpu_high_since_{};
  std::chrono::steady_clock::time_point mem_high_since_{};
};

} // namespace montauk::app

