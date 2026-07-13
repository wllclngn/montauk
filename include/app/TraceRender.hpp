#pragma once

#include "app/MetricsSink.hpp"
#include "model/Trace.hpp"

namespace montauk::app {

// The single walk over TraceSnapshot both trace_to_prometheus and the new
// trace_to_json drive through their own MetricsSink -- trace_to_json falls
// out of this for free, no new per-field code beyond wiring JsonSink +
// render_trace.
void render_trace(MetricsSink& sink, const montauk::model::TraceSnapshot& t);

}  // namespace montauk::app
