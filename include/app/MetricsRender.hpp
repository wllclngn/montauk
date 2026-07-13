#pragma once

#include "app/MetricsSink.hpp"
#include "app/MetricsServer.hpp"

namespace montauk::app {

// The single walk over MetricsSnapshot both snapshot_to_json and
// snapshot_to_prometheus drive through their own MetricsSink. Every field is
// read and visited exactly once here, regardless of which sink is attached.
void render_snapshot(MetricsSink& sink, const MetricsSnapshot& s);

}  // namespace montauk::app
