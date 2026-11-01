#pragma once
#include "model/Snapshot.hpp"
#include "sublimation_text.h"
#include <optional>

namespace montauk::app {

struct ProcessFilterSpec {
  std::optional<std::string> name_contains;
  std::optional<std::string> name_regex;
  std::optional<std::string> user_equals;
  std::optional<double> cpu_min;   // percent
  std::optional<uint64_t> mem_min_kb;
};

class ProcessFilter {
public:
  explicit ProcessFilter(ProcessFilterSpec spec);
  // The fixed-face matcher borrows its needle from spec_, so a copy or move
  // would leave it pointing into the old object.
  ProcessFilter(const ProcessFilter&) = delete;
  ProcessFilter& operator=(const ProcessFilter&) = delete;
  // Returns filtered indices into ps.processes
  [[nodiscard]] std::vector<size_t> apply(const montauk::model::ProcessSnapshot& ps) const;
private:
  ProcessFilterSpec spec_;
  std::optional<sublimation_search> compiled_;  // regex face (field)
  std::optional<sublimation_search> bmh_;        // fixed face (anchor), icase
};

} // namespace montauk::app

