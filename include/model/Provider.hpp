#pragma once
#include <string>
#include <vector>

namespace montauk::model {

// One parsed sample from a provider's Prometheus text exposition.
struct ProviderMetric {
  std::string name;
  std::string labels; // raw label string between braces, empty when unlabeled
  double value{};
};

// Snapshot of one external metrics provider. Providers self-identify at
// runtime by their socket filename ("<name>.sock"); montauk names none of
// them in source.
struct Provider {
  std::string name;     // from the socket filename, without ".sock"
  std::string raw_text; // full Prometheus text as received
  std::vector<ProviderMetric> metrics;
};

} // namespace montauk::model
