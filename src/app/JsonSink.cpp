#include "app/JsonSink.hpp"
#include "model/Provider.hpp"

namespace montauk::app {

JsonSink::JsonSink() {
  sublimation_sink_init(&sink_, -1);  // fd -1: never drains, buffer holds the doc
  sublimation_json_init(&j_, &sink_);
  sublimation_json_obj_begin(&j_);
  sublimation_json_ku64(&j_, "schema_version", 1u);
}

void JsonSink::section_begin(const char* json_key) {
  sublimation_json_key(&j_, json_key);
  sublimation_json_obj_begin(&j_);
}

void JsonSink::section_end() { sublimation_json_obj_end(&j_); }

void JsonSink::collection_begin(const char* json_key, Shape shape) {
  sublimation_json_key(&j_, json_key);
  sublimation_json_arr_begin(&j_);
  collection_stack_.push_back(shape);
}

void JsonSink::collection_end() {
  sublimation_json_arr_end(&j_);
  collection_stack_.pop_back();
}

void JsonSink::entry_begin() {
  if (!collection_stack_.empty() && collection_stack_.back() == Shape::Objects)
    sublimation_json_obj_begin(&j_);
}

void JsonSink::entry_end() {
  if (!collection_stack_.empty() && collection_stack_.back() == Shape::Objects)
    sublimation_json_obj_end(&j_);
}

void JsonSink::f64(const MetricDesc& d, double v) {
  if (d.json_key) sublimation_json_knum(&j_, d.json_key, v);
}

void JsonSink::u64(const MetricDesc& d, uint64_t v) {
  if (d.json_key) sublimation_json_ku64(&j_, d.json_key, v);
}

void JsonSink::i64(const MetricDesc& d, int64_t v) {
  if (d.json_key) sublimation_json_ki64(&j_, d.json_key, v);
}

void JsonSink::boolean(const MetricDesc& d, bool v) {
  if (d.json_key) sublimation_json_kbool(&j_, d.json_key, v ? 1 : 0);
}

void JsonSink::str(const MetricDesc& d, std::string_view v) {
  if (!d.json_key) return;
  std::string tmp(v);  // sublimation_json_kstr wants a NUL-terminated C string
  sublimation_json_kstr(&j_, d.json_key, tmp.c_str());
}

void JsonSink::labeled_f64(const MetricDesc& d, std::span<const Label>, double v) {
  if (d.json_key) sublimation_json_knum(&j_, d.json_key, v);
  else if (!collection_stack_.empty() && collection_stack_.back() == Shape::Scalars) sublimation_json_num(&j_, v);
}

void JsonSink::labeled_u64(const MetricDesc& d, std::span<const Label>, uint64_t v) {
  if (d.json_key) sublimation_json_ku64(&j_, d.json_key, v);
  else if (!collection_stack_.empty() && collection_stack_.back() == Shape::Scalars) sublimation_json_u64(&j_, v);
}

void JsonSink::labeled_i64(const MetricDesc& d, std::span<const Label>, int64_t v) {
  if (d.json_key) sublimation_json_ki64(&j_, d.json_key, v);
  else if (!collection_stack_.empty() && collection_stack_.back() == Shape::Scalars) sublimation_json_i64(&j_, v);
}

void JsonSink::info_line(const char*, const char*, std::span<const Label>) {
  // Denormalized Prometheus-only composite row; JSON already carries these
  // same fields as separate keys via render_system()'s ordinary str/i64/f64
  // calls, so this is a no-op here.
}

void JsonSink::provider(const montauk::model::Provider& p) {
  sublimation_json_kstr(&j_, "name", p.name.c_str());
  if (!p.metrics.empty()) {
    sublimation_json_key(&j_, "metrics");
    sublimation_json_arr_begin(&j_);
    for (const auto& m : p.metrics) {
      sublimation_json_obj_begin(&j_);
      sublimation_json_kstr(&j_, "name", m.name.c_str());
      if (!m.labels.empty()) sublimation_json_kstr(&j_, "labels", m.labels.c_str());
      sublimation_json_knum(&j_, "value", m.value);
      sublimation_json_obj_end(&j_);
    }
    sublimation_json_arr_end(&j_);
  } else {
    sublimation_json_kstr(&j_, "raw_text", p.raw_text.c_str());
  }
}

std::string JsonSink::finish() {
  sublimation_json_obj_end(&j_);
  sublimation_sink_appendc(&sink_, '\n');
  std::string out(sink_.data, sink_.len);
  sublimation_sink_free(&sink_);
  return out;
}

}  // namespace montauk::app
