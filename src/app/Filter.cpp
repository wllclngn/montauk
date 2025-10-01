#include "app/Filter.hpp"

namespace lsm::app {

ProcessFilter::ProcessFilter(ProcessFilterSpec spec) : spec_(std::move(spec)) {
  if (spec_.name_regex) compiled_.emplace(*spec_.name_regex, std::regex::icase);
}

std::vector<size_t> ProcessFilter::apply(const lsm::model::ProcessSnapshot& ps) const {
  std::vector<size_t> out;
  out.reserve(ps.processes.size());
  for (size_t i=0;i<ps.processes.size();++i) {
    const auto& p = ps.processes[i];
    bool ok = true;
    if (spec_.name_contains) {
      auto hay = p.cmd; for (auto& c: hay) c = std::tolower(c);
      auto needle = *spec_.name_contains; for (auto& c: needle) c = std::tolower(c);
      if (hay.find(needle) == std::string::npos) ok = false;
    }
    if (ok && compiled_) { if (!std::regex_search(p.cmd, *compiled_)) ok = false; }
    if (ok && spec_.user_equals) { if (p.user_name != *spec_.user_equals) ok = false; }
    if (ok && spec_.cpu_min) { if (p.cpu_pct < *spec_.cpu_min) ok = false; }
    if (ok && spec_.mem_min_kb) { if (p.rss_kb < *spec_.mem_min_kb) ok = false; }
    if (ok) out.push_back(i);
  }
  return out;
}

} // namespace lsm::app

