#include "app/Filter.hpp"
#include "util/BoyerMoore.hpp"

namespace montauk::app {

ProcessFilter::ProcessFilter(ProcessFilterSpec spec) : spec_(std::move(spec)) {
  if (spec_.name_regex) compiled_.emplace(*spec_.name_regex, std::regex::icase);
  if (spec_.name_contains) bmh_.emplace(*spec_.name_contains);
}

std::vector<size_t> ProcessFilter::apply(const montauk::model::ProcessSnapshot& ps) const {
  std::vector<size_t> out;
  out.reserve(ps.processes.size());
  for (size_t i = 0; i < ps.processes.size(); ++i) {
    const auto& p = ps.processes[i];
    bool ok = true;
    if (bmh_) {
      if (bmh_->search(p.cmd) == -1) ok = false;
    }
    if (ok && compiled_) { if (!std::regex_search(p.cmd, *compiled_)) ok = false; }
    if (ok && spec_.user_equals) { if (p.user_name != *spec_.user_equals) ok = false; }
    if (ok && spec_.cpu_min) { if (p.cpu_pct < *spec_.cpu_min) ok = false; }
    if (ok && spec_.mem_min_kb) { if (p.rss_kb < *spec_.mem_min_kb) ok = false; }
    if (ok) out.push_back(i);
  }
  return out;
}

} // namespace montauk::app

