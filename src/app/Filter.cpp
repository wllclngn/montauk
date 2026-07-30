#include "app/Filter.hpp"
#include <string>

namespace montauk::app {

ProcessFilter::ProcessFilter(ProcessFilterSpec spec) : spec_(std::move(spec)) {
  if (spec_.name_regex) {
    // ICASE, not a hand-folded copy of pattern and input. The predecessor here
    // folded both because "the Thompson NFA has no icase flag" -- that engine
    // was retired in v8.0.0, and the Glushkov field folds case into its class
    // sets at COMPILE time, which is also more correct than match-time folding
    // for negated classes. Folding the input separately allocated a lowered
    // std::string per process, per call.
    const std::string& rx = *spec_.name_regex;
    compiled_.emplace();
    sublimation_search_compile(&*compiled_, rx.data(), rx.size(),
                               SUBLIMATION_SEARCH_ICASE, 0);
    if (!sublimation_search_valid(&*compiled_)) compiled_.reset();  // bad pattern -> regex filter ignored
  }
  // An empty substring query is no constraint (matches all), so only build a
  // matcher for a non-empty needle -- the engine treats an empty fixed pattern as
  // invalid rather than the old BMH's match-at-0.
  if (spec_.name_contains && !spec_.name_contains->empty()) {
    const std::string& sub = *spec_.name_contains;
    bmh_.emplace();
    sublimation_search_compile(&*bmh_, sub.data(), sub.size(),
                               SUBLIMATION_SEARCH_FIXED | SUBLIMATION_SEARCH_ICASE, 0);
  }
}

std::vector<size_t> ProcessFilter::apply(const montauk::model::ProcessSnapshot& ps) const {
  std::vector<size_t> out;
  out.reserve(ps.processes.size());
  for (size_t i = 0; i < ps.processes.size(); ++i) {
    const auto& p = ps.processes[i];
    bool ok = true;
    if (bmh_) {
      if (sublimation_search_find(&*bmh_, p.cmd.data(), p.cmd.size(), nullptr) == -1) ok = false;
    }
    if (ok && compiled_) {
      if (sublimation_search_find(&*compiled_, p.cmd.data(), p.cmd.size(), nullptr) < 0) ok = false;
    }
    if (ok && spec_.user_equals) { if (p.user_name != *spec_.user_equals) ok = false; }
    if (ok && spec_.cpu_min) { if (p.cpu_pct < *spec_.cpu_min) ok = false; }
    if (ok && spec_.mem_min_kb) { if (p.rss_kb < *spec_.mem_min_kb) ok = false; }
    if (ok) out.push_back(i);
  }
  return out;
}

} // namespace montauk::app

