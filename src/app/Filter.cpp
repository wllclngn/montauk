#include "app/Filter.hpp"
#include <string>
#include <string_view>

namespace montauk::app {

namespace {
// The Thompson NFA has no icase flag, so we ASCII-case-fold both the pattern
// and the input -- preserving the case-insensitive behavior the old
// std::regex::icase filter had (and matching the Boyer-Moore --contains path).
std::string ascii_lower(std::string_view s) {
  std::string out(s);
  for (char& c : out) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
  return out;
}
} // namespace

ProcessFilter::ProcessFilter(ProcessFilterSpec spec) : spec_(std::move(spec)) {
  if (spec_.name_regex) {
    std::string lc = ascii_lower(*spec_.name_regex);
    compiled_.emplace();
    sublimation_search_compile(&*compiled_, lc.data(), lc.size(), 0u, 0);
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
      std::string lc = ascii_lower(p.cmd);
      if (sublimation_search_find(&*compiled_, lc.data(), lc.size(), nullptr) < 0) ok = false;
    }
    if (ok && spec_.user_equals) { if (p.user_name != *spec_.user_equals) ok = false; }
    if (ok && spec_.cpu_min) { if (p.cpu_pct < *spec_.cpu_min) ok = false; }
    if (ok && spec_.mem_min_kb) { if (p.rss_kb < *spec_.mem_min_kb) ok = false; }
    if (ok) out.push_back(i);
  }
  return out;
}

} // namespace montauk::app

