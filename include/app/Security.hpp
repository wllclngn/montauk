#pragma once

#include "model/Snapshot.hpp"
#include <string>
#include <vector>

namespace montauk::app {

struct SecurityFinding {
  int severity{0};             // 0=none,1=caution,2=warning
  std::string subject;         // e.g., "PID 1324 root /tmp/.kworkerd"
  std::string reason;          // e.g., "root exec in /tmp"
};

auto collect_security_findings(const montauk::model::Snapshot& s)
    -> std::vector<SecurityFinding>;

auto format_security_line_default(const SecurityFinding& f) -> std::string;
auto format_security_line_system(const SecurityFinding& f) -> std::string;

} // namespace montauk::app

