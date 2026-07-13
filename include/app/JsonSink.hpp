#pragma once

#include "app/MetricsSink.hpp"
#include "util/sink.h"
#include "util/json.h"

#include <vector>

namespace montauk::app {

// Concrete MetricsSink writing through include/util/json.h -- the same
// write-only JSON writer used everywhere else in montauk, so this surface
// cannot diverge from the rest of the codebase's JSON encoding.
class JsonSink : public MetricsSink {
public:
  JsonSink();

  void section_begin(const char* json_key) override;
  void section_end() override;

  void collection_begin(const char* json_key, Shape shape) override;
  void collection_end() override;
  void entry_begin() override;
  void entry_end() override;

  void f64(const MetricDesc& d, double v) override;
  void u64(const MetricDesc& d, uint64_t v) override;
  void i64(const MetricDesc& d, int64_t v) override;
  void boolean(const MetricDesc& d, bool v) override;
  void str(const MetricDesc& d, std::string_view v) override;

  void labeled_f64(const MetricDesc& d, std::span<const Label> labels, double v) override;
  void labeled_u64(const MetricDesc& d, std::span<const Label> labels, uint64_t v) override;
  void labeled_i64(const MetricDesc& d, std::span<const Label> labels, int64_t v) override;

  void info_line(const char* prom_name, const char* help, std::span<const Label> labels) override;
  void provider(const montauk::model::Provider& p) override;

  [[nodiscard]] std::string finish() override;

private:
  montauk_sink sink_;
  montauk_json j_;
  std::vector<Shape> collection_stack_;
};

}  // namespace montauk::app
