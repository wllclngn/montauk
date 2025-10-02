#pragma once
#include "model/Snapshot.hpp"
#include <regex>
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
  // Returns filtered indices into ps.processes
  std::vector<size_t> apply(const montauk::model::ProcessSnapshot& ps) const;
private:
  ProcessFilterSpec spec_;
  std::optional<std::regex> compiled_;
};

} // namespace montauk::app

