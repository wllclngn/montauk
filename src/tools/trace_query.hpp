// The trace as a queryable thing. Every event class montauk records, its
// fields by name, a selection over them, and the operators a question about a
// capture is built from -- so a question is a command line, not a class.
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace montauk::query {

// FIELD TABLE. One row per field of every event struct in montauk_trace.h,
// read by offset from the raw record. A field is a number (unsigned or
// signed, any width up to 8) or fixed-width text (comm).
enum class Kind : uint8_t { U, I, Text };
struct Field { const char* name; uint16_t off; uint8_t size; Kind kind; };
struct EventClass {
  uint32_t type;
  const char* name;
  uint32_t size;                            // minimum record length
  const Field* fields;
  uint8_t nfields;
  int8_t op_field;                          // the field an op name selects on, or -1
  const char* (*op_name)(uint32_t);         // op value -> name, or null
  int8_t ts_field;                          // timestamp field, or -1 (lifecycle records)
};

const EventClass* class_named(std::string_view name);
const EventClass* class_of(uint32_t type);
int field_named(const EventClass& c, std::string_view name);
// Read on every record by every collector, so inline.
// Fixed-width loads, one per field width, so each read is a load rather than a
// memcpy call; a text field reads as 0.
inline int64_t read_int(const Field& f, const uint8_t* data) {
  const uint8_t* p = data + f.off;
  const bool sgn = f.kind == Kind::I;
  switch (f.kind == Kind::Text ? 0 : f.size) {
    case 1: return sgn ? static_cast<int64_t>(static_cast<int8_t>(*p)) : static_cast<int64_t>(*p);
    case 2: { uint16_t v; std::memcpy(&v, p, 2); return sgn ? static_cast<int16_t>(v) : static_cast<int64_t>(v); }
    case 4: { uint32_t v; std::memcpy(&v, p, 4); return sgn ? static_cast<int32_t>(v) : static_cast<int64_t>(v); }
    case 8: { uint64_t v; std::memcpy(&v, p, 8); return static_cast<int64_t>(v); }
    default: return 0;
  }
}
inline std::string_view read_text(const Field& f, const uint8_t* data) {
  const char* p = reinterpret_cast<const char*>(data + f.off);
  return std::string_view(p, strnlen(p, f.size));
}
// Every class, for the help listing.
const EventClass* const* all_classes(size_t* n);

// SELECTION: one class, an optional set of its ops, and field comparisons.
enum class Cmp : uint8_t { Eq, Ne, Lt, Le, Gt, Ge };
struct Clause { int field; Cmp cmp; int64_t value; std::string text; };
struct Select {
  const EventClass* cls = nullptr;
  std::vector<uint32_t> ops;                // empty = every op
  uint64_t op_mask = 0;                     // the same set as bits, when every op is below 64
  std::vector<Clause> where;
  // Every collector asks this of every record: the type, length and op tests
  // inline, the field clauses out of line.
  bool matches(uint32_t type, const uint8_t* data, uint32_t len) const {
    if (!cls || type != cls->type || len < cls->size) return false;
    if (op_mask) {
      const auto op = static_cast<uint64_t>(read_int(cls->fields[cls->op_field], data));
      if (op >= 64 || !((op_mask >> op) & 1)) return false;
    } else if (!ops.empty() && !matches_ops(data)) {
      return false;
    }
    return where.empty() || matches_where(data);
  }
  bool matches_ops(const uint8_t* data) const;
  bool matches_where(const uint8_t* data) const;
};
// "sched", "sched.wake2run", "sched.pick,switch_in". Op names match
// case-insensitively; a number is accepted as an op value.
bool parse_select(std::string_view spec, Select& out, std::string& err);
// "runtime_ns>=900000", "comm=wine", "cpu!=3", against the select's class.
bool parse_clause(std::string_view spec, Select& sel, std::string& err);

// A TABLE: named columns of int64 cells, text columns interned. The one
// result shape every operator produces and every renderer reads.
struct Table {
  std::vector<std::string> cols;
  std::vector<bool> text;                   // per column: cell is an index into `strings`
  std::vector<int64_t> cells;               // row-major
  std::vector<std::string> strings;
  std::unordered_map<std::string, int64_t> interned;

  size_t width() const { return cols.size(); }
  size_t rows() const { return cols.empty() ? 0 : cells.size() / cols.size(); }
  int64_t at(size_t r, size_t c) const { return cells[r * cols.size() + c]; }
  int64_t intern(std::string_view s);
  std::string cell_text(size_t r, size_t c) const;
};

// A QUERY: what to select, how to key it, and which operator turns the
// selected events into the answer.
enum class Op : uint8_t {
  Rows,    // the selected events themselves
  Count,   // per key: n, and sum/min/max/mean of the value field
  Gap,     // per key: time since the previous selected event
  Pair,    // per key: an A event to the next B event, before the next A
  Last,    // per key: the last selected event
};
struct Query {
  Select a;
  Select b;                                 // Pair only: the closing event
  std::vector<int> key;                     // field indices into a's class
  int value = -1;                           // field index, or -1
  Op op = Op::Rows;
  double t0_s = -1, t1_s = -1;              // window in seconds from the first event; <0 = open
};

// Folds the stream once and answers the query. Events must arrive in trace
// order; per-key ordering is restored by timestamp before Gap and Pair.
class Engine {
 public:
  explicit Engine(Query q);
  void fold(uint32_t type, const uint8_t* data, uint32_t len);
  Table finish();
  uint64_t misses() const { return misses_; }   // Pair: A events never closed

 private:
  struct Ev { int64_t ts; uint32_t row; bool is_b; };
  Query q_;
  Table raw_;                               // key cols, value col, ts, per selected event
  std::vector<Ev> evs_;
  int64_t first_ts_ = -1;
  uint64_t misses_ = 0;
  void append(const Select& s, const uint8_t* data, bool is_b, int64_t ts);
};

// Nearest-rank quantile over a SORTED vector: floor(q*n), clamped -- the same
// estimator every report uses, so a CLI p99 and a report p99 agree.
int64_t quantile_sorted(const std::vector<int64_t>& v, double q);

}  // namespace montauk::query
