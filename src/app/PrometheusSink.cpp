#include "app/PrometheusSink.hpp"
#include "model/Provider.hpp"

#include <algorithm>
#include <charconv>

namespace montauk::app {

namespace {

void append_double(std::string& out, double v) {
  char buf[32];
  auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf), v);
  if (ec == std::errc{}) {
    out.append(buf, ptr);
  } else {
    out += '0';
  }
}

void append_uint(std::string& out, uint64_t v) {
  char buf[24];
  auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf), v);
  out.append(buf, ptr);
}

void append_int(std::string& out, int64_t v) {
  char buf[24];
  auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf), v);
  out.append(buf, ptr);
}

void append_escaped(std::string& out, std::string_view sv) {
  for (char c : sv) {
    if (c == '\\') out += "\\\\";
    else if (c == '"') out += "\\\"";
    else if (c == '\n') out += "\\n";
    else out += c;
  }
}

void emit_header(std::string& out, const std::string& name, const std::string& help, const char* type) {
  out += "# HELP "; out += name; out += ' '; out += help; out += '\n';
  out += "# TYPE "; out += name; out += ' '; out += type; out += '\n';
}

// Builds "name{k1="v1",k2="v2"} value\n" for however many labels are given.
std::string labeled_line(const char* name, std::span<const Label> labels) {
  std::string line = name;
  if (!labels.empty()) {
    line += '{';
    for (size_t i = 0; i < labels.size(); ++i) {
      if (i > 0) line += ',';
      line += labels[i].key;
      line += "=\"";
      append_escaped(line, labels[i].value);
      line += '"';
    }
    line += "} ";
  } else {
    line += ' ';
  }
  return line;
}

}  // namespace

void PrometheusSink::section_begin(const char*) {}
void PrometheusSink::section_end() {}

void PrometheusSink::collection_begin(const char*, Shape) { ++collection_depth_; }

void PrometheusSink::collection_end() {
  if (--collection_depth_ == 0) flush_families();
}

void PrometheusSink::entry_begin() {}
void PrometheusSink::entry_end() {}

PrometheusSink::Family& PrometheusSink::family_for(const MetricDesc& d) {
  for (auto& f : pending_)
    if (f.name == d.prom_name) return f;
  pending_.push_back({d.prom_name, d.help, d.kind, {}});
  return pending_.back();
}

void PrometheusSink::flush_families() {
  for (auto& f : pending_) {
    emit_header(out_, f.name, f.help, f.kind == MetricKind::Counter ? "counter" : "gauge");
    for (auto& line : f.lines) out_ += line;
  }
  pending_.clear();
}

void PrometheusSink::f64(const MetricDesc& d, double v) {
  if (!d.prom_name) return;
  emit_header(out_, d.prom_name, d.help, d.kind == MetricKind::Counter ? "counter" : "gauge");
  out_ += d.prom_name; out_ += ' '; append_double(out_, v); out_ += '\n';
}

void PrometheusSink::u64(const MetricDesc& d, uint64_t v) {
  if (!d.prom_name) return;
  emit_header(out_, d.prom_name, d.help, d.kind == MetricKind::Counter ? "counter" : "gauge");
  out_ += d.prom_name; out_ += ' '; append_uint(out_, v); out_ += '\n';
}

void PrometheusSink::i64(const MetricDesc& d, int64_t v) {
  if (!d.prom_name) return;
  emit_header(out_, d.prom_name, d.help, d.kind == MetricKind::Counter ? "counter" : "gauge");
  out_ += d.prom_name; out_ += ' '; append_int(out_, v); out_ += '\n';
}

void PrometheusSink::boolean(const MetricDesc& d, bool v) {
  if (!d.prom_name) return;
  i64(d, v ? 1 : 0);
}

void PrometheusSink::str(const MetricDesc&, std::string_view) {
  // Prometheus has no bare-string gauge; string fields only ever reach
  // Prometheus via info_line's label set.
}

void PrometheusSink::labeled_f64(const MetricDesc& d, std::span<const Label> labels, double v) {
  if (!d.prom_name) return;
  std::string line = labeled_line(d.prom_name, labels);
  append_double(line, v);
  line += '\n';
  if (collection_depth_ > 0) family_for(d).lines.push_back(std::move(line));
  else { emit_header(out_, d.prom_name, d.help, d.kind == MetricKind::Counter ? "counter" : "gauge"); out_ += line; }
}

void PrometheusSink::labeled_u64(const MetricDesc& d, std::span<const Label> labels, uint64_t v) {
  if (!d.prom_name) return;
  std::string line = labeled_line(d.prom_name, labels);
  append_uint(line, v);
  line += '\n';
  if (collection_depth_ > 0) family_for(d).lines.push_back(std::move(line));
  else { emit_header(out_, d.prom_name, d.help, d.kind == MetricKind::Counter ? "counter" : "gauge"); out_ += line; }
}

void PrometheusSink::labeled_i64(const MetricDesc& d, std::span<const Label> labels, int64_t v) {
  if (!d.prom_name) return;
  std::string line = labeled_line(d.prom_name, labels);
  append_int(line, v);
  line += '\n';
  if (collection_depth_ > 0) family_for(d).lines.push_back(std::move(line));
  else { emit_header(out_, d.prom_name, d.help, d.kind == MetricKind::Counter ? "counter" : "gauge"); out_ += line; }
}

void PrometheusSink::info_line(const char* prom_name, const char* help, std::span<const Label> labels) {
  // Standard backslash-escaping (same as every other labeled metric) --
  // montauk_trace_process_info and montauk_trace_fd_target both used
  // append_escaped originally. montauk_system_info is the one true
  // exception (space-replacement, not backslash-escaping); that's handled
  // by pre-sanitizing its label values at the render_system() call site,
  // not here, so this stays the single shared escaping behavior.
  emit_header(out_, prom_name, help, "gauge");
  out_ += labeled_line(prom_name, labels);
  out_ += "1\n";
}

void PrometheusSink::provider(const montauk::model::Provider& p) {
  out_ += p.raw_text;
  if (!p.raw_text.empty() && p.raw_text.back() != '\n') out_ += '\n';
}

void PrometheusSink::raw_comment(std::string_view text) {
  out_ += text;
}

std::string PrometheusSink::finish() {
  flush_families();  // safety net; every collection_begin should already be balanced
  return std::move(out_);
}

}  // namespace montauk::app
