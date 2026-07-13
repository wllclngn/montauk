#pragma once

#include "app/MetricsSink.hpp"

#include <string>
#include <vector>

namespace montauk::app {

// Concrete MetricsSink producing the exact text snapshot_to_prometheus /
// trace_to_prometheus shipped before the renderer unification -- the
// formatting helpers (PrometheusSink.cpp's anonymous-namespace functions)
// moved here verbatim from the old PrometheusSerializer.cpp, so the bytes
// this produces are unchanged; only who calls them changed.
class PrometheusSink : public MetricsSink {
public:
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
  void raw_comment(std::string_view text) override;

  [[nodiscard]] std::string finish() override;

private:
  struct Family {
    std::string name, help;
    MetricKind kind;
    std::vector<std::string> lines;
  };

  Family& family_for(const MetricDesc& d);
  void flush_families();

  std::string out_;
  std::vector<Family> pending_;
  int collection_depth_{0};
};

}  // namespace montauk::app
