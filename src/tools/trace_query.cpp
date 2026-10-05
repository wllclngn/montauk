#include "trace_query.hpp"

#include "model/TraceEnumNames.hpp"
#include "montauk_trace.h"
#include "sublimation_order.hpp"

#include <array>
#include <cctype>
#include <cstddef>
#include <cstdlib>
#include <cstring>

namespace montauk::query {
namespace {

using montauk::model::io_syscall_name;
using montauk::model::ntsync_op_name;
using montauk::model::sched_op_name;

#define F(S, M, K) Field{#M, static_cast<uint16_t>(offsetof(S, M)), sizeof(S::M), K}
// The innermost eight frames of a captured stack, one field each.
#define FR(S, i) Field{"frame" #i, static_cast<uint16_t>(offsetof(S, stack_user) + 8 * (i)), 8, Kind::U}
#define FRAMES(S) FR(S, 0), FR(S, 1), FR(S, 2), FR(S, 3), FR(S, 4), FR(S, 5), FR(S, 6), FR(S, 7)
// A wait's per-object arrays, one field per slot.
#define WF(i) Field{"wait_fd" #i, static_cast<uint16_t>(offsetof(montauk_ntsync_event, wait_fds) + 4 * (i)), 4, Kind::U}
#define WO(i) Field{"wait_obj" #i, static_cast<uint16_t>(offsetof(montauk_ntsync_event, wait_objs) + 8 * (i)), 8, Kind::U}
constexpr Kind U = Kind::U, I = Kind::I, T = Kind::Text;

const Field kSched[] = {
    F(montauk_sched_event, op, U),         F(montauk_sched_event, cpu, U),
    F(montauk_sched_event, pid, I),        F(montauk_sched_event, secondary_pid, I),
    F(montauk_sched_event, last_cpu, I),   F(montauk_sched_event, sub_idx, U),
    F(montauk_sched_event, freq_mhz, U),   F(montauk_sched_event, score, U),
    F(montauk_sched_event, runtime_ns, U), F(montauk_sched_event, budget_ns, U),
    F(montauk_sched_event, timestamp_ns, U)};
const Field kIo[] = {
    F(montauk_io_event, pid, U),        F(montauk_io_event, tid, U),
    F(montauk_io_event, syscall_nr, I), F(montauk_io_event, fd, I),
    F(montauk_io_event, result, I),     F(montauk_io_event, count, U),
    F(montauk_io_event, whence, U),     F(montauk_io_event, comm, T),
    F(montauk_io_event, timestamp_ns, U), F(montauk_io_event, duration_ns, U)};
const Field kNtsync[] = {
    F(montauk_ntsync_event, pid, U),        F(montauk_ntsync_event, tid, U),
    F(montauk_ntsync_event, op, U),         F(montauk_ntsync_event, fd, I),
    F(montauk_ntsync_event, result, I),     F(montauk_ntsync_event, timestamp_ns, U),
    F(montauk_ntsync_event, arg0, U),       F(montauk_ntsync_event, arg1, U),
    F(montauk_ntsync_event, timeout_ns, U), F(montauk_ntsync_event, wait_count, U),
    F(montauk_ntsync_event, wait_index, U), F(montauk_ntsync_event, wait_owner, U),
    F(montauk_ntsync_event, wait_alert, U), F(montauk_ntsync_event, obj_ptr, U),
    F(montauk_ntsync_event, comm, T),
    WF(0), WF(1), WF(2), WF(3), WF(4), WF(5), WF(6), WF(7),
    WO(0), WO(1), WO(2), WO(3), WO(4), WO(5), WO(6), WO(7)};
const Field kHeap[] = {
    F(montauk_heap_event, pid, U),  F(montauk_heap_event, tid, U),
    F(montauk_heap_event, op, U),   F(montauk_heap_event, addr, U),
    F(montauk_heap_event, size, U), F(montauk_heap_event, new_addr, U),
    F(montauk_heap_event, timestamp_ns, U), F(montauk_heap_event, comm, T)};
const Field kSignal[] = {
    F(montauk_signal_event, pid, U),         F(montauk_signal_event, tid, U),
    F(montauk_signal_event, kind, U),        F(montauk_signal_event, signal_nr, I),
    F(montauk_signal_event, sender_pid, I),  F(montauk_signal_event, exit_code, I),
    F(montauk_signal_event, stack_depth, U), F(montauk_signal_event, timestamp_ns, U),
    F(montauk_signal_event, comm, T),        F(montauk_signal_event, syscall_nr, I),
    F(montauk_signal_event, io_fd, I), FRAMES(montauk_signal_event)};
const Field kMmap[] = {
    F(montauk_mmap_event, pid, U),    F(montauk_mmap_event, tid, U),
    F(montauk_mmap_event, fd, I),     F(montauk_mmap_event, addr, U),
    F(montauk_mmap_event, length, U), F(montauk_mmap_event, offset, U),
    F(montauk_mmap_event, prot, U),   F(montauk_mmap_event, flags, U),
    F(montauk_mmap_event, timestamp_ns, U), F(montauk_mmap_event, comm, T)};
const Field kAbort[] = {
    F(montauk_abort_event, pid, U),  F(montauk_abort_event, tid, U),
    F(montauk_abort_event, func, U), F(montauk_abort_event, line, U),
    F(montauk_abort_event, stack_depth, U), F(montauk_abort_event, timestamp_ns, U),
    F(montauk_abort_event, comm, T), FRAMES(montauk_abort_event)};
const Field kHeapStack[] = {
    F(montauk_heapstack_event, pid, U),  F(montauk_heapstack_event, tid, U),
    F(montauk_heapstack_event, op, U),   F(montauk_heapstack_event, addr, U),
    F(montauk_heapstack_event, size, U), F(montauk_heapstack_event, stack_depth, U),
    F(montauk_heapstack_event, timestamp_ns, U), F(montauk_heapstack_event, comm, T),
    FRAMES(montauk_heapstack_event)};
const Field kKeyed[] = {
    F(montauk_keyedevt_event, pid, U), F(montauk_keyedevt_event, tid, U),
    F(montauk_keyedevt_event, op, U),  F(montauk_keyedevt_event, key, U),
    F(montauk_keyedevt_event, timestamp_ns, U), F(montauk_keyedevt_event, comm, T)};
const Field kKstrand[] = {
    F(montauk_kstrand_event, tid, U),        F(montauk_kstrand_event, cpu, U),
    F(montauk_kstrand_event, nr_cpus_allowed, U), F(montauk_kstrand_event, latency_ns, U),
    F(montauk_kstrand_event, timestamp_ns, U), F(montauk_kstrand_event, comm, T)};
const Field kWaitStack[] = {
    F(montauk_waitstack_event, pid, U),     F(montauk_waitstack_event, tid, U),
    F(montauk_waitstack_event, stack_depth, U), F(montauk_waitstack_event, obj_ptr, U),
    F(montauk_waitstack_event, timeout_ns, U),  F(montauk_waitstack_event, timestamp_ns, U),
    F(montauk_waitstack_event, comm, T), FRAMES(montauk_waitstack_event)};
const Field kStorm[] = {
    F(montauk_scx_storm_event, interval_ms, U), F(montauk_scx_storm_event, kicks, U),
    F(montauk_scx_storm_event, preempt_kicks, U), F(montauk_scx_storm_event, reenq, U),
    F(montauk_scx_storm_event, timestamp_ns, U)};
const Field kProvider[] = {
    F(montauk_provider_event, timestamp_ns, U), F(montauk_provider_event, name, T),
    F(montauk_provider_event, payload_len, U)};
const Field kRawStack[] = {
    F(montauk_rawstack_event, pid, U), F(montauk_rawstack_event, tid, U),
    F(montauk_rawstack_event, stack_len, U), F(montauk_rawstack_event, rip, U),
    F(montauk_rawstack_event, rsp, U), F(montauk_rawstack_event, rbp, U),
    F(montauk_rawstack_event, obj_ptr, U), F(montauk_rawstack_event, timestamp_ns, U),
    F(montauk_rawstack_event, comm, T)};
const Field kRing[] = {
    F(montauk_ring_event, pid, U),       F(montauk_ring_event, ppid, U),
    F(montauk_ring_event, child_pid, U), F(montauk_ring_event, comm, T),
    F(montauk_ring_event, filename, T)};
#undef WO
#undef WF
#undef FRAMES
#undef FR
#undef F

const char* heap_op(uint32_t op) {
  static const char* n[] = {"malloc", "free", "realloc", "calloc"};
  return op < 4 ? n[op] : "?";
}
const char* signal_kind(uint32_t k) { return k == 0 ? "deliver" : k == 1 ? "exit_abnormal" : "?"; }
const char* abort_fn(uint32_t f) {
  static const char* n[] = {"assert_fail", "libc_message", "abort"};
  return f < 3 ? n[f] : "?";
}
const char* keyed_op(uint32_t op) { return op == 0 ? "wait" : op == 1 ? "release" : "?"; }
const char* io_op(uint32_t nr) { return io_syscall_name(static_cast<int32_t>(nr)); }
const char* ntsync_op(uint32_t op) { return ntsync_op_name(static_cast<uint8_t>(op)); }

template <size_t N>
constexpr uint8_t count(const Field (&)[N]) { return static_cast<uint8_t>(N); }

const EventClass kClasses[] = {
    {TRACE_EVT_SCHED, "sched", sizeof(montauk_sched_event), kSched, count(kSched), 0, sched_op_name, 10},
    {TRACE_EVT_IO, "io", sizeof(montauk_io_event), kIo, count(kIo), 2, io_op, 8},
    {TRACE_EVT_NTSYNC, "ntsync", sizeof(montauk_ntsync_event), kNtsync, count(kNtsync), 2, ntsync_op, 5},
    {TRACE_EVT_HEAP, "heap", sizeof(montauk_heap_event), kHeap, count(kHeap), 2, heap_op, 6},
    {TRACE_EVT_SIGNAL, "signal", sizeof(montauk_signal_event), kSignal, count(kSignal), 2, signal_kind, 7},
    {TRACE_EVT_MMAP, "mmap", sizeof(montauk_mmap_event), kMmap, count(kMmap), -1, nullptr, 8},
    {TRACE_EVT_ABORT, "abort", sizeof(montauk_abort_event), kAbort, count(kAbort), 2, abort_fn, 5},
    {TRACE_EVT_HEAPSTACK, "heapstk", sizeof(montauk_heapstack_event), kHeapStack, count(kHeapStack), 2, heap_op, 6},
    {TRACE_EVT_KEYEDEVT, "keyedevt", sizeof(montauk_keyedevt_event), kKeyed, count(kKeyed), 2, keyed_op, 4},
    {TRACE_EVT_KSTRAND, "kstrand", sizeof(montauk_kstrand_event), kKstrand, count(kKstrand), -1, nullptr, 4},
    {TRACE_EVT_WAITSTACK, "waitstack", sizeof(montauk_waitstack_event), kWaitStack, count(kWaitStack), -1, nullptr, 5},
    {TRACE_EVT_SCX_STORM, "scx_storm", sizeof(montauk_scx_storm_event), kStorm, count(kStorm), -1, nullptr, 4},
    {TRACE_EVT_PROVIDER, "provider", sizeof(montauk_provider_event), kProvider, count(kProvider), -1, nullptr, 0},
    {TRACE_EVT_RAWSTACK, "rawstack", sizeof(montauk_rawstack_event), kRawStack, count(kRawStack), -1, nullptr, 7},
    {TRACE_EVT_FORK, "fork", sizeof(montauk_ring_event), kRing, count(kRing), -1, nullptr, -1},
    {TRACE_EVT_EXEC, "exec", sizeof(montauk_ring_event), kRing, count(kRing), -1, nullptr, -1},
    {TRACE_EVT_EXIT, "exit", sizeof(montauk_ring_event), kRing, count(kRing), -1, nullptr, -1},
    {TRACE_EVT_COMM_CHANGE, "comm", sizeof(montauk_ring_event), kRing, count(kRing), -1, nullptr, -1},
    {TRACE_EVT_THREAD_NAME, "thread_name", sizeof(montauk_ring_event), kRing, count(kRing), -1, nullptr, -1},
};
const EventClass* const kClassPtrs[] = {
    &kClasses[0], &kClasses[1], &kClasses[2],  &kClasses[3],  &kClasses[4],  &kClasses[5],
    &kClasses[6], &kClasses[7], &kClasses[8],  &kClasses[9],  &kClasses[10], &kClasses[11],
    &kClasses[12], &kClasses[13], &kClasses[14], &kClasses[15], &kClasses[16],
    &kClasses[17], &kClasses[18]};
static_assert(sizeof(kClassPtrs) / sizeof(kClassPtrs[0]) == sizeof(kClasses) / sizeof(kClasses[0]));

bool iequal(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i)
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i])))
      return false;
  return true;
}

bool parse_int(std::string_view s, int64_t& out) {
  if (s.empty()) return false;
  std::string t(s);
  char* end = nullptr;
  const bool hex = t.size() > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X');
  out = hex ? static_cast<int64_t>(std::strtoull(t.c_str(), &end, 16))
            : std::strtoll(t.c_str(), &end, 10);
  return end && *end == '\0';
}

// Signed int64 -> an order-preserving u64, for the unsigned sort keys.
uint64_t ordkey(int64_t v) { return static_cast<uint64_t>(v) ^ (1ull << 63); }

}  // namespace

const EventClass* class_named(std::string_view name) {
  for (const auto& c : kClasses)
    if (iequal(c.name, name)) return &c;
  return nullptr;
}

// Every record in the stream asks this, so it is an index, not a search.
const EventClass* class_of(uint32_t type) {
  static const auto table = [] {
    std::array<const EventClass*, 64> t{};
    for (const auto& c : kClasses) t[c.type] = &c;
    return t;
  }();
  return type < table.size() ? table[type] : nullptr;
}

const EventClass* const* all_classes(size_t* n) {
  *n = sizeof(kClassPtrs) / sizeof(kClassPtrs[0]);
  return kClassPtrs;
}

int field_named(const EventClass& c, std::string_view name) {
  for (int i = 0; i < c.nfields; ++i)
    if (iequal(c.fields[i].name, name)) return i;
  if (c.ts_field >= 0 && iequal(name, "ts")) return c.ts_field;
  return -1;
}

bool Select::matches_ops(const uint8_t* data) const {
  const auto op = static_cast<uint32_t>(read_int(cls->fields[cls->op_field], data));
  for (uint32_t o : ops) if (o == op) return true;
  return false;
}

bool Select::matches_where(const uint8_t* data) const {
  for (const Clause& c : where) {
    const Field& f = cls->fields[c.field];
    int r;
    if (f.kind == Kind::Text) {
      r = read_text(f, data).compare(c.text);
      r = r < 0 ? -1 : r > 0 ? 1 : 0;
    } else {
      const int64_t v = read_int(f, data);
      r = v < c.value ? -1 : v > c.value ? 1 : 0;
    }
    switch (c.cmp) {
      case Cmp::Eq: if (r != 0) return false; break;
      case Cmp::Ne: if (r == 0) return false; break;
      case Cmp::Lt: if (r >= 0) return false; break;
      case Cmp::Le: if (r > 0) return false; break;
      case Cmp::Gt: if (r <= 0) return false; break;
      case Cmp::Ge: if (r < 0) return false; break;
    }
  }
  return true;
}

bool parse_select(std::string_view spec, Select& out, std::string& err) {
  out = Select{};
  const size_t dot = spec.find('.');
  const std::string_view cname = spec.substr(0, dot);
  out.cls = class_named(cname);
  if (!out.cls) {
    err = "unknown event class '" + std::string(cname) + "'";
    return false;
  }
  if (dot == std::string_view::npos) return true;
  if (out.cls->op_field < 0) {
    err = "class '" + std::string(cname) + "' has no ops to select";
    return false;
  }
  std::string_view rest = spec.substr(dot + 1);
  while (!rest.empty()) {
    const size_t comma = rest.find(',');
    const std::string_view name = rest.substr(0, comma);
    rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
    int64_t v;
    if (parse_int(name, v)) { out.ops.push_back(static_cast<uint32_t>(v)); continue; }
    bool found = false;
    for (uint32_t op = 0; op < 512 && !found; ++op)
      if (iequal(out.cls->op_name(op), name)) { out.ops.push_back(op); found = true; }
    if (!found) {
      err = "class '" + std::string(cname) + "' has no op '" + std::string(name) + "'";
      return false;
    }
  }
  out.op_mask = 0;
  for (uint32_t o : out.ops) {
    if (o >= 64) { out.op_mask = 0; break; }
    out.op_mask |= 1ull << o;
  }
  return true;
}

bool parse_clause(std::string_view spec, Select& sel, std::string& err) {
  static const struct { const char* s; Cmp c; } kOps[] = {
      {">=", Cmp::Ge}, {"<=", Cmp::Le}, {"!=", Cmp::Ne},
      {"=", Cmp::Eq},  {">", Cmp::Gt},  {"<", Cmp::Lt}};
  for (const auto& o : kOps) {
    const size_t at = spec.find(o.s);
    if (at == std::string_view::npos || at == 0) continue;
    const std::string_view name = spec.substr(0, at);
    const std::string_view val = spec.substr(at + std::strlen(o.s));
    const int fi = field_named(*sel.cls, name);
    if (fi < 0) {
      err = "class '" + std::string(sel.cls->name) + "' has no field '" + std::string(name) + "'";
      return false;
    }
    Clause c{fi, o.c, 0, {}};
    if (sel.cls->fields[fi].kind == Kind::Text) {
      c.text = std::string(val);
    } else if (!parse_int(val, c.value)) {
      err = "field '" + std::string(name) + "' is numeric, got '" + std::string(val) + "'";
      return false;
    }
    sel.where.push_back(std::move(c));
    return true;
  }
  err = "no comparison in '" + std::string(spec) + "' (use = != < <= > >=)";
  return false;
}

int64_t Table::intern(std::string_view s) {
  auto it = interned.find(std::string(s));
  if (it != interned.end()) return it->second;
  const auto id = static_cast<int64_t>(strings.size());
  strings.emplace_back(s);
  interned.emplace(std::string(s), id);
  return id;
}

std::string Table::cell_text(size_t r, size_t c) const {
  const int64_t v = at(r, c);
  if (text[c]) return strings[static_cast<size_t>(v)];
  return std::to_string(v);
}

int64_t quantile_sorted(const std::vector<int64_t>& v, double q) {
  if (v.empty()) return 0;
  size_t i = static_cast<size_t>(static_cast<double>(v.size()) * q);
  if (i >= v.size()) i = v.size() - 1;
  return v[i];
}

// raw_ holds, per selected event: the key fields, then the value field when one
// was asked for, then every field of the class when neither was (Rows), and
// last the timestamp relative to the first selected event.
Engine::Engine(Query q) : q_(std::move(q)) {
  const EventClass& c = *q_.a.cls;
  auto add = [&](const Field& f) {
    raw_.cols.emplace_back(f.name);
    raw_.text.push_back(f.kind == Kind::Text);
  };
  for (int k : q_.key) add(c.fields[k]);
  if (q_.value >= 0) add(c.fields[q_.value]);
  if (q_.op == Op::Rows && q_.key.empty() && q_.value < 0)
    for (int i = 0; i < c.nfields; ++i)
      if (i != c.ts_field) add(c.fields[i]);
  raw_.cols.emplace_back("t_ns");
  raw_.text.push_back(false);
}

void Engine::append(const Select& s, const uint8_t* data, bool is_b, int64_t ts) {
  const EventClass& c = *s.cls;
  const auto row = static_cast<uint32_t>(raw_.rows());
  auto put = [&](const Field& f) {
    raw_.cells.push_back(f.kind == Kind::Text ? raw_.intern(read_text(f, data))
                                              : read_int(f, data));
  };
  for (int k : q_.key) put(c.fields[k]);
  if (q_.value >= 0) put(c.fields[q_.value]);
  if (q_.op == Op::Rows && q_.key.empty() && q_.value < 0)
    for (int i = 0; i < c.nfields; ++i)
      if (i != c.ts_field) put(c.fields[i]);
  raw_.cells.push_back(ts);
  evs_.push_back({ts, row, is_b});
}

void Engine::fold(uint32_t type, const uint8_t* data, uint32_t len) {
  const bool a = q_.a.matches(type, data, len);
  const bool b = !a && q_.op == Op::Pair && q_.b.matches(type, data, len);
  if (!a && !b) return;
  const EventClass& c = *q_.a.cls;
  int64_t ts = c.ts_field >= 0 ? read_int(c.fields[c.ts_field], data)
                               : static_cast<int64_t>(evs_.size());
  if (first_ts_ < 0) first_ts_ = ts;
  ts -= first_ts_;
  if (q_.t0_s >= 0 && static_cast<double>(ts) < q_.t0_s * 1e9) return;
  if (q_.t1_s >= 0 && static_cast<double>(ts) > q_.t1_s * 1e9) return;
  append(a ? q_.a : q_.b, data, b, ts);
}

Table Engine::finish() {
  Table out;
  const size_t nk = q_.key.size();
  const size_t w = raw_.width();
  const size_t tcol = w - 1;
  auto header = [&](std::initializer_list<const char*> extra) {
    for (size_t k = 0; k < nk; ++k) {
      out.cols.push_back(raw_.cols[k]);
      out.text.push_back(raw_.text[k]);
    }
    for (const char* e : extra) { out.cols.emplace_back(e); out.text.push_back(false); }
  };
  auto key_cells = [&](uint32_t row) {
    for (size_t k = 0; k < nk; ++k) {
      const int64_t v = raw_.at(row, k);
      out.cells.push_back(raw_.text[k] ? out.intern(raw_.strings[static_cast<size_t>(v)]) : v);
    }
  };

  if (q_.op == Op::Rows) {
    out.cols = raw_.cols;
    out.text = raw_.text;
    out.strings = raw_.strings;
    out.interned = raw_.interned;
    out.cells = raw_.cells;
    return out;
  }

  // Group id per event, then order every event by (group, ts): time first, the
  // group second, both stable, so ties keep trace order.
  std::unordered_map<std::string, uint32_t> gid;
  std::vector<uint32_t> group(evs_.size());
  std::vector<uint32_t> first_row;
  for (size_t i = 0; i < evs_.size(); ++i) {
    std::string kb;
    for (size_t k = 0; k < nk; ++k) {
      const int64_t v = raw_.at(evs_[i].row, k);
      kb.append(reinterpret_cast<const char*>(&v), sizeof v);
    }
    auto [it, fresh] = gid.emplace(std::move(kb), static_cast<uint32_t>(first_row.size()));
    if (fresh) first_row.push_back(evs_[i].row);
    group[i] = it->second;
  }
  // Groups print in key order; rank them once.
  std::vector<uint32_t> gorder(first_row.size());
  for (uint32_t g = 0; g < gorder.size(); ++g) gorder[g] = g;
  for (size_t k = nk; k-- > 0;) {
    if (raw_.text[k])
      sublimation_order_strings(gorder, false, [&](uint32_t g) {
        return raw_.strings[static_cast<size_t>(raw_.at(first_row[g], k))].c_str();
      });
    else
      sublimation_order_u64(gorder, false,
                            [&](uint32_t g) { return ordkey(raw_.at(first_row[g], k)); });
  }
  std::vector<uint32_t> rank(gorder.size());
  for (uint32_t r = 0; r < gorder.size(); ++r) rank[gorder[r]] = r;

  std::vector<uint32_t> idx(evs_.size());
  for (uint32_t i = 0; i < idx.size(); ++i) idx[i] = i;
  sublimation_order_u64(idx, false, [&](uint32_t i) { return ordkey(evs_[i].ts); });
  sublimation_order_u64(idx, false, [&](uint32_t i) { return static_cast<uint64_t>(rank[group[i]]); });

  const bool has_val = q_.value >= 0;
  const size_t vcol = nk;

  if (q_.op == Op::Count) {
    if (has_val) header({"n", "sum", "min", "max", "mean"});
    else header({"n"});
    for (size_t i = 0; i < idx.size();) {
      const uint32_t g = group[idx[i]];
      int64_t n = 0, sum = 0, mn = 0, mx = 0;
      const uint32_t row0 = evs_[idx[i]].row;
      for (; i < idx.size() && group[idx[i]] == g; ++i) {
        const int64_t v = has_val ? raw_.at(evs_[idx[i]].row, vcol) : 0;
        if (n == 0 || v < mn) mn = v;
        if (n == 0 || v > mx) mx = v;
        sum += v;
        ++n;
      }
      key_cells(row0);
      out.cells.push_back(n);
      if (has_val) {
        out.cells.push_back(sum);
        out.cells.push_back(mn);
        out.cells.push_back(mx);
        out.cells.push_back(n ? sum / n : 0);
      }
    }
    return out;
  }

  if (q_.op == Op::Last) {
    header({"t_ns"});
    if (has_val) { out.cols.push_back(raw_.cols[vcol]); out.text.push_back(raw_.text[vcol]); }
    for (size_t i = 0; i < idx.size();) {
      const uint32_t g = group[idx[i]];
      uint32_t last = evs_[idx[i]].row;
      for (; i < idx.size() && group[idx[i]] == g; ++i) last = evs_[idx[i]].row;
      key_cells(last);
      out.cells.push_back(raw_.at(last, tcol));
      if (has_val) {
        const int64_t v = raw_.at(last, vcol);
        out.cells.push_back(raw_.text[vcol] ? out.intern(raw_.strings[static_cast<size_t>(v)]) : v);
      }
    }
    return out;
  }

  if (q_.op == Op::Gap) {
    header({"t_ns", "gap_ns"});
    for (size_t i = 0; i < idx.size(); ++i) {
      if (i == 0 || group[idx[i]] != group[idx[i - 1]]) continue;
      const uint32_t row = evs_[idx[i]].row;
      key_cells(row);
      out.cells.push_back(raw_.at(row, tcol));
      out.cells.push_back(evs_[idx[i]].ts - evs_[idx[i - 1]].ts);
    }
    return out;
  }

  // Pair: an A opens, the next B on the same key closes it; a second A, or the
  // end of the trace, before any B leaves the first one unanswered.
  header({"t_ns", "latency_ns"});
  for (size_t i = 0; i < idx.size();) {
    const uint32_t g = group[idx[i]];
    int64_t open = -1;
    uint32_t open_row = 0;
    for (; i < idx.size() && group[idx[i]] == g; ++i) {
      const Ev& e = evs_[idx[i]];
      if (!e.is_b) {
        if (open >= 0) ++misses_;
        open = e.ts;
        open_row = e.row;
      } else if (open >= 0) {
        key_cells(open_row);
        out.cells.push_back(open);
        out.cells.push_back(e.ts - open);
        open = -1;
      }
    }
    if (open >= 0) ++misses_;
  }
  return out;
}

}  // namespace montauk::query
