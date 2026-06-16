#pragma once
#include "model/Provider.hpp"
#include <vector>

namespace montauk::collectors {

// Scrapes external metrics providers: unix sockets named "<name>.sock" in
// $XDG_RUNTIME_DIR/montauk/providers/ (fallback /run/montauk/providers/).
// Protocol: connect, read one full Prometheus-text snapshot until EOF.
// A missing directory or unreachable/garbled provider is a silent no-op
// for that scrape — providers come and go at runtime.
class ProviderCollector {
public:
  [[nodiscard]] bool sample(std::vector<montauk::model::Provider>& out);
};

} // namespace montauk::collectors
