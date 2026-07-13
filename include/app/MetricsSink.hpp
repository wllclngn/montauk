// Single walk, multiple sinks: MetricsRender.cpp/TraceRender.cpp walk
// MetricsSnapshot/TraceSnapshot exactly once, visiting each field through
// this interface. JsonSink and PrometheusSink are the two concrete
// renderings -- a value is read and visited exactly once regardless of
// output format, so the two can no longer independently drift the way
// JsonSerializer.cpp/PrometheusSerializer.cpp did before this.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace montauk::model { struct Provider; }

namespace montauk::app {

enum class MetricKind { Gauge, Counter };   // Prometheus TYPE only; JSON ignores it
enum class Shape { Scalars, Objects };      // shape of a repeated collection

struct Label {
  std::string_view key;
  std::string_view value;
};

// Static description of one metric, shared by both renderers. A null
// json_key or null prom_name means "this call is for the other sink only" --
// lets one call site carry a unit/shape difference (e.g. KB in JSON vs bytes
// in Prometheus) without becoming two independent computations of the same
// fact.
struct MetricDesc {
  const char* json_key;
  const char* prom_name;
  const char* help;
  MetricKind kind{MetricKind::Gauge};
};

class MetricsSink {
public:
  virtual ~MetricsSink() = default;

  // JSON nests a named object; Prometheus has no nesting, so this is a
  // no-op there.
  virtual void section_begin(const char* json_key) = 0;
  virtual void section_end() = 0;

  // A repeated collection (per-core, per-device, per-interface, per-process,
  // per-thread, per-ntsync-event, ...). JSON opens/closes an array
  // (bare-scalar or array-of-objects, per `shape`). Prometheus buffers every
  // metric family touched inside the bracket and flushes each (HELP+TYPE
  // once, then every entry's line) at collection_end(), in first-seen order
  // -- this reproduces both field-major (GPU) and entity-major (trace
  // threads) Prometheus output from the same entity-major walk.
  virtual void collection_begin(const char* json_key, Shape shape) = 0;
  virtual void collection_end() = 0;
  // One element of an Objects-shaped collection. No-op for Scalars-shaped
  // collections and for Prometheus (labels alone carry entry identity there).
  virtual void entry_begin() = 0;
  virtual void entry_end() = 0;

  // Leaf scalars, unlabeled.
  virtual void f64(const MetricDesc& d, double v) = 0;
  virtual void u64(const MetricDesc& d, uint64_t v) = 0;
  virtual void i64(const MetricDesc& d, int64_t v) = 0;
  virtual void boolean(const MetricDesc& d, bool v) = 0;
  virtual void str(const MetricDesc& d, std::string_view v) = 0;

  // Labeled leaf, inside a collection.
  virtual void labeled_f64(const MetricDesc& d, std::span<const Label> labels, double v) = 0;
  virtual void labeled_u64(const MetricDesc& d, std::span<const Label> labels, uint64_t v) = 0;
  virtual void labeled_i64(const MetricDesc& d, std::span<const Label> labels, int64_t v) = 0;

  // Escape hatch: the one denormalized composite Prometheus row
  // (montauk_system_info). JSON does not call this -- render_system()
  // writes its own per-field keys directly instead.
  virtual void info_line(const char* prom_name, const char* help,
                          std::span<const Label> labels) = 0;

  // Escape hatch: provider passthrough -- dynamically shaped data with no
  // fixed struct schema, so it isn't run through per-field sink calls.
  virtual void provider(const montauk::model::Provider& p) = 0;

  // Cosmetic-only, default no-op: PrometheusSink overrides to prepend a
  // literal banner line ("\n# Trace\n"); JsonSink ignores it.
  virtual void raw_comment(std::string_view) {}

  [[nodiscard]] virtual std::string finish() = 0;
};

}  // namespace montauk::app
