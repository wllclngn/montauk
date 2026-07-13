// JsonSerializer -- thin wrapper. All field logic lives in MetricsRender.cpp
// (MetricsSnapshot) and TraceRender.cpp (TraceSnapshot); this file and
// PrometheusSerializer.cpp are the only two places allowed to construct a
// sink and call the shared walk, so the two renderings cannot re-diverge the
// way they did before the MetricsSink unification.
#include "app/JsonSink.hpp"
#include "app/MetricsRender.hpp"
#include "app/TraceRender.hpp"

namespace montauk::app {

std::string snapshot_to_json(const MetricsSnapshot& s) {
  JsonSink sink;
  render_snapshot(sink, s);
  return sink.finish();
}

std::string trace_to_json(const montauk::model::TraceSnapshot& t) {
  JsonSink sink;
  render_trace(sink, t);
  return sink.finish();
}

} // namespace montauk::app
