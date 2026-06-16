// montauk_analyze — offline analysis reports over a binary --trace-out log.
//
// Trace-only by design: the old live /proc sampler is gone. Every registered
// report folds events in a SINGLE pass over the file (traces reach 450 MB+),
// then emits in registry order. Adding a report = one struct deriving from
// Report + one entry in make_reports().
//
// Usage:
//   montauk_analyze FILE [--report name[,name...]]   # default: all reports

#include "model/TraceReader.hpp"
#include "montauk_trace.h"

#include "sublimation.h"        // in-tree sub-system: flow-model sort, classify
#include "sublimation_pack.h"   // index-by-key sorts (u64/f64) for report rows

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <sys/stat.h>

#ifndef MONTAUK_VERSION
#define MONTAUK_VERSION "unknown"
#endif

namespace {

// NTSYNC wait result semantics: >= 0 is the signaled object index,
// -110 is ETIMEDOUT, other negatives are -errno. The BPF side also emits
// an ENTRY event per wait with this sentinel result so blocked calls are
// visible; analysis counts completions only and reports entries separately.
constexpr int64_t kWaitEntrySentinel = -999;
constexpr int64_t kEtimedout = -110;

// Spin detection: consecutive wait completions on the same (tid,fd) closer
// than this are spinning, not sleeping (a healthy waiter blocks for at
// least a scheduler tick), and a run must sustain this many iterations to
// be a livelock rather than a wakeup burst.
constexpr uint64_t kSpinGapNs = 1000000;
constexpr uint64_t kSpinMinIters = 1000;

// Pairing: an fd whose waits outnumber its signal-side ops by this factor
// has no plausible signaler; the minimum filters out fds with too little
// traffic to judge.
constexpr uint64_t kPairingWaitSignalRatio = 100;
constexpr uint64_t kPairingMinWaits = 1000;

// Distinct result values shown per row in the waits table.
constexpr size_t kWaitsTopResults = 4;

const char* ntsync_op_name(uint8_t op) {
  switch (op) {
    case NTS_CREATE_SEM:   return "create_sem";
    case NTS_SEM_RELEASE:  return "sem_release";
    case NTS_WAIT_ANY:     return "wait_any";
    case NTS_WAIT_ALL:     return "wait_all";
    case NTS_CREATE_MUTEX: return "create_mutex";
    case NTS_MUTEX_UNLOCK: return "mutex_unlock";
    case NTS_MUTEX_KILL:   return "mutex_kill";
    case NTS_CREATE_EVENT: return "create_event";
    case NTS_EVENT_SET:    return "event_set";
    case NTS_EVENT_RESET:  return "event_reset";
    case NTS_EVENT_PULSE:  return "event_pulse";
    case NTS_SEM_READ:     return "sem_read";
    case NTS_MUTEX_READ:   return "mutex_read";
    case NTS_EVENT_READ:   return "event_read";
    default:               return "unknown";
  }
}

const char* io_syscall_name(int32_t nr) {
  switch (nr) {
    case 0:   return "read";
    case 1:   return "write";
    case 5:   return "fstat";
    case 8:   return "lseek";
    case 17:  return "pread64";
    case 257: return "openat";
    default:  return "?";
  }
}

const char* sched_op_name(uint32_t op) {
  switch (op) {
    case SCHED_OP_ENQUEUE:        return "ENQUEUE";
    case SCHED_OP_PICK:           return "PICK";
    case SCHED_OP_PICK_EMPTY:     return "PICK_EMPTY";
    case SCHED_OP_PREEMPT_TICK:   return "PREEMPT_TICK";
    case SCHED_OP_PREEMPT_WAKEUP: return "PREEMPT_WAKEUP";
    case SCHED_OP_WAKEUP:         return "WAKEUP";
    case SCHED_OP_WAKE2RUN:       return "WAKE2RUN";
    default:                      return "?";
  }
}

// Format an absolute wall-clock ns-since-epoch into HH:MM:SS.mmm.
std::string wall_str(uint64_t wall_ns) {
  time_t secs = static_cast<time_t>(wall_ns / 1000000000ull);
  uint32_t ms = static_cast<uint32_t>((wall_ns % 1000000000ull) / 1000000ull);
  tm lt{};
  localtime_r(&secs, &lt);
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03u", lt.tm_hour, lt.tm_min, lt.tm_sec, ms);
  return buf;
}

bool is_wait_op(uint8_t op) { return op == NTS_WAIT_ANY || op == NTS_WAIT_ALL; }
bool is_signal_op(uint8_t op) {
  return op == NTS_EVENT_SET || op == NTS_EVENT_RESET || op == NTS_SEM_RELEASE ||
         op == NTS_MUTEX_UNLOCK;
}

// ── Generic synchronization model ────────────────────────────────────────────
// The wait/spin/contention reports fold over this unified shape so the SAME
// analysis applies to NTSYNC objects AND futexes (and any future primitive) --
// a generic interface, not a Wine-only one. A wait COMPLETION carries the
// waiter tid, an opaque lock identity (ntsync object fd / futex uaddr), the
// completion timestamp, and the wait result (>=0 ok, -110 ETIMEDOUT, -errno).
// A SIGNAL carries the signaler tid and the same opaque id.
constexpr int32_t kFutexSyscallNr = 202;
// futex cmd (op with PRIVATE/CLOCK flags masked): which block, which wake.
inline bool futex_is_wait(uint32_t opb) { return opb == 0 || opb == 9 || opb == 6 || opb == 11; }
inline bool futex_is_wake(uint32_t opb) { return opb == 1 || opb == 10 || opb == 7; }

struct SyncWait   { uint32_t tid; uint64_t obj; uint64_t ts; int64_t result; };
struct SyncSignal { uint32_t tid; uint64_t obj; uint64_t ts; };

// Mix tid + opaque object id into one map key (obj is 64-bit: a futex uaddr).
inline uint64_t tid_obj_key(uint32_t tid, uint64_t obj) {
  return (static_cast<uint64_t>(tid) * 0x9E3779B97F4A7C15ULL) ^ (obj + 0x165667B19E3779F9ULL);
}

// True iff this event is a generic wait COMPLETION; fills `w`.
inline bool sync_wait(uint32_t type, const uint8_t* data, uint32_t len, SyncWait& w) {
  if (type == TRACE_EVT_NTSYNC && len >= sizeof(montauk_ntsync_event)) {
    auto* e = reinterpret_cast<const montauk_ntsync_event*>(data);
    if (!is_wait_op(e->op) || e->result == kWaitEntrySentinel) return false;
    w = {e->tid, static_cast<uint32_t>(e->fd), e->timestamp_ns, e->result};
    return true;
  }
  if (type == TRACE_EVT_IO && len >= sizeof(montauk_io_event)) {
    auto* e = reinterpret_cast<const montauk_io_event*>(data);
    if (e->syscall_nr != kFutexSyscallNr) return false;
    if (!futex_is_wait(static_cast<uint32_t>(e->fd) & 0x7f)) return false;
    w = {e->tid, e->count, e->timestamp_ns, e->result};
    return true;
  }
  return false;
}

// True iff this event is a generic SIGNAL (wake/release); fills `s`.
inline bool sync_signal(uint32_t type, const uint8_t* data, uint32_t len, SyncSignal& s) {
  if (type == TRACE_EVT_NTSYNC && len >= sizeof(montauk_ntsync_event)) {
    auto* e = reinterpret_cast<const montauk_ntsync_event*>(data);
    if (!is_signal_op(e->op)) return false;
    s = {e->tid, static_cast<uint32_t>(e->fd), e->timestamp_ns};
    return true;
  }
  if (type == TRACE_EVT_IO && len >= sizeof(montauk_io_event)) {
    auto* e = reinterpret_cast<const montauk_io_event*>(data);
    if (e->syscall_nr != kFutexSyscallNr) return false;
    if (!futex_is_wake(static_cast<uint32_t>(e->fd) & 0x7f)) return false;
    s = {e->tid, e->count, e->timestamp_ns};
    return true;
  }
  return false;
}

// Humanize a count for VERDICT lines: 1700000 -> "1.7M", 580 -> "580".
std::string fmt_count(double n) {
  static const char* units[] = {"", "k", "M", "G", "T"};
  int u = 0;
  while (std::fabs(n) >= 1000.0 && u < 4) { n /= 1000.0; ++u; }
  char buf[32];
  std::snprintf(buf, sizeof(buf), (u == 0 || std::fabs(n) >= 99.95) ? "%.0f%s" : "%.1f%s",
                n, units[u]);
  return buf;
}

// Order a vector of report rows through sublimation instead of std::sort: pull
// a numeric key from each element, index-sort it with the flow-model pack
// (sublimation_pack_sort_u64/f64), then gather into key order. This is the
// row-ordering counterpart to the numeric-vector sorts (gaps_ns, wake2run) --
// every ordering the analyzer emits now runs through sublimation. Stable:
// equal keys keep input order (the pack tiebreaks on the original index), so
// the output is deterministic where std::sort's tie order was not.
template <class T, class KeyFn>
void sublimation_order_u64(std::vector<T>& v, bool descending, KeyFn key) {
  const size_t n = v.size();
  if (n < 2) return;
  std::vector<uint64_t> keys(n);
  std::vector<uint32_t> idx(n);
  for (size_t i = 0; i < n; ++i) { keys[i] = key(v[i]); idx[i] = static_cast<uint32_t>(i); }
  sublimation_pack_sort_u64(keys.data(), idx.data(), n, descending);
  std::vector<T> out;
  out.reserve(n);
  for (size_t i = 0; i < n; ++i) out.push_back(std::move(v[idx[i]]));
  v = std::move(out);
}

template <class T, class KeyFn>
void sublimation_order_f64(std::vector<T>& v, bool descending, KeyFn key) {
  const size_t n = v.size();
  if (n < 2) return;
  std::vector<double> keys(n);
  std::vector<uint32_t> idx(n);
  for (size_t i = 0; i < n; ++i) { keys[i] = key(v[i]); idx[i] = static_cast<uint32_t>(i); }
  sublimation_pack_sort_f64(keys.data(), idx.data(), n, descending);
  std::vector<T> out;
  out.reserve(n);
  for (size_t i = 0; i < n; ++i) out.push_back(std::move(v[idx[i]]));
  v = std::move(out);
}

// PROMETHEUS RE-EMISSION. Analysis results are written back out as
// montauk_analysis_* gauges so the loop stays inside Prometheus (the
// bench-analyze pattern): each report contributes labeled samples after it
// has emitted its text, and main() writes them to the cache dir stamped
// with the trace's own start time (re-analysis of a trace overwrites).
struct PromMetric {
  const char* name;    // metric family (string literal)
  std::string labels;  // pre-formatted: k="v",k="v"
  double value;
};

const char* prom_help(const char* name) {
  static constexpr struct { const char* name; const char* help; } kHelp[] = {
    {"montauk_analysis_events_total",
     "Event count per type+subtype over the whole trace"},
    {"montauk_analysis_waits_total",
     "NTSYNC wait completions per (tid,fd)"},
    {"montauk_analysis_wait_gap_ms",
     "Inter-wait gap quantile in ms per (tid,fd)"},
    {"montauk_analysis_spin_runs_total",
     "Spin runs per (tid,fd) by verdict (gap<1ms sustained >=1000 iters)"},
    {"montauk_analysis_spin_peak_rate_per_s",
     "Peak wait rate across spin runs per (tid,fd)"},
    {"montauk_analysis_pairing_waits",
     "Wait completions attributed to the object fd"},
    {"montauk_analysis_pairing_signals",
     "Signal-side ops (set/reset/sem_release/mutex_unlock) on the object fd"},
    {"montauk_analysis_unsignaled_flag",
     "1 if the fd's waits exceed 100x its signals (no plausible signaler)"},
    {"montauk_analysis_wake2run_us",
     "Wake-to-run (runqueue) latency quantile in us over WAKE2RUN events"},
    {"montauk_analysis_wake2run_tickfloor_pct",
     "Percent of wake2run latencies on the CONFIG_HZ tick floor (>=900us)"},
    {"montauk_analysis_wake2run_crossccx_pct",
     "Percent of wake2run events that ran on a cross-CCX CPU"},
    {"montauk_analysis_info",
     "Build and trace metadata (montauk version, trace pattern, format version)"},
    {"montauk_analysis_timestamp_seconds",
     "Trace start time (unix seconds, from the trace's real-time anchor)"},
  };
  for (const auto& h : kHelp)
    if (std::strcmp(h.name, name) == 0) return h.help;
  return name;
}

// Sample value: integral gauges print as integers, the rest with enough
// digits to round-trip a quantile.
std::string prom_num(double v) {
  char buf[32];
  if (v == std::floor(v) && std::fabs(v) < 1e15)
    std::snprintf(buf, sizeof(buf), "%.0f", v);
  else
    std::snprintf(buf, sizeof(buf), "%.6g", v);
  return buf;
}

// $XDG_CACHE_HOME|~/.cache /montauk/analysis-<trace-basename>-<stamp>.prom,
// stamp from the trace header's real-time anchor (NOT wall-now).
std::string analysis_prom_path(const char* trace_path, uint64_t real_anchor_ns) {
  const char* xdg = std::getenv("XDG_CACHE_HOME");
  std::string dir;
  if (xdg && *xdg) {
    dir = xdg;
  } else {
    const char* home = std::getenv("HOME");
    dir = std::string(home && *home ? home : ".") + "/.cache";
  }
  ::mkdir(dir.c_str(), 0755);
  dir += "/montauk";
  ::mkdir(dir.c_str(), 0755);
  std::string base = trace_path;
  size_t slash = base.find_last_of('/');
  if (slash != std::string::npos) base.erase(0, slash + 1);
  size_t dot = base.find_last_of('.');
  if (dot != std::string::npos && dot > 0) base.erase(dot);
  time_t secs = static_cast<time_t>(real_anchor_ns / 1000000000ull);
  tm lt{};
  localtime_r(&secs, &lt);
  char stamp[80];
  std::snprintf(stamp, sizeof(stamp), "%04d%02d%02d-%02d%02d%02d",
                lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday,
                lt.tm_hour, lt.tm_min, lt.tm_sec);
  return dir + "/analysis-" + base + "-" + stamp + ".prom";
}

bool write_analysis_prom(const std::string& out_path, const std::vector<PromMetric>& prom) {
  FILE* f = std::fopen(out_path.c_str(), "w");
  if (!f) return false;
  std::set<std::string> emitted;
  for (const PromMetric& m : prom) {
    if (emitted.insert(m.name).second)
      std::fprintf(f, "# HELP %s %s\n# TYPE %s gauge\n", m.name, prom_help(m.name), m.name);
    // House style: label-less metrics print bare, no empty braces.
    if (m.labels.empty())
      std::fprintf(f, "%s %s\n", m.name, prom_num(m.value).c_str());
    else
      std::fprintf(f, "%s{%s} %s\n", m.name, m.labels.c_str(), prom_num(m.value).c_str());
  }
  return std::fclose(f) == 0;
}

struct Report {
  virtual ~Report() = default;
  virtual const char* name() const = 0;
  virtual void fold(uint32_t type, const uint8_t* data, uint32_t len) = 0;
  virtual void emit(const montauk::model::TraceReader& reader) = 0;
  // Called after emit(); appends this report's montauk_analysis_* samples.
  virtual void prom(std::vector<PromMetric>& out) { (void)out; }
};

// REPORT summary: header info, duration, throughput, per type+subtype counts.
struct SummaryReport final : Report {
  uint64_t total_ = 0;
  uint64_t min_ts_ = 0, max_ts_ = 0;
  uint64_t ntsync_done_[14] {};   // completions, indexed by ntsync_trace_op
  uint64_t ntsync_enter_[14] {};  // wait ENTRY sentinels
  std::map<int32_t, uint64_t> io_;
  uint64_t sched_[MONTAUK_SCHED_OP_MAX] {};
  uint64_t heap_[4] {};
  uint64_t signal_[2] {};         // indexed by signal_event_kind
  uint64_t abort_[3] {};          // indexed by abort_fn
  uint64_t heapstack_ = 0;        // size-filtered allocation stack captures
  uint64_t lifecycle_[5] {};      // indexed by FORK..COMM_CHANGE (1..4)
  uint64_t mmap_ = 0;
  std::map<std::string, uint64_t> provider_;  // provider name -> snapshot count
  std::map<uint32_t, uint64_t> unknown_;

  const char* name() const override { return "summary"; }

  void note_ts(uint64_t ts) {
    if (ts == 0) return;
    if (min_ts_ == 0 || ts < min_ts_) min_ts_ = ts;
    if (ts > max_ts_) max_ts_ = ts;
  }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    ++total_;
    switch (type) {
      case TRACE_EVT_NTSYNC: {
        if (len < sizeof(montauk_ntsync_event)) break;
        auto* e = reinterpret_cast<const montauk_ntsync_event*>(data);
        note_ts(e->timestamp_ns);
        if (e->op < 14) {
          if (e->result == kWaitEntrySentinel) ++ntsync_enter_[e->op];
          else ++ntsync_done_[e->op];
        }
        break;
      }
      case TRACE_EVT_IO: {
        if (len < sizeof(montauk_io_event)) break;
        auto* e = reinterpret_cast<const montauk_io_event*>(data);
        note_ts(e->timestamp_ns);
        ++io_[e->syscall_nr];
        break;
      }
      case TRACE_EVT_SCHED: {
        if (len < sizeof(montauk_sched_event)) break;
        auto* e = reinterpret_cast<const montauk_sched_event*>(data);
        note_ts(e->timestamp_ns);
        if (e->op < MONTAUK_SCHED_OP_MAX) ++sched_[e->op];
        break;
      }
      case TRACE_EVT_HEAP: {
        if (len < sizeof(montauk_heap_event)) break;
        auto* e = reinterpret_cast<const montauk_heap_event*>(data);
        note_ts(e->timestamp_ns);
        if (e->op < 4) ++heap_[e->op];
        break;
      }
      case TRACE_EVT_SIGNAL: {
        if (len < sizeof(montauk_signal_event)) break;
        auto* e = reinterpret_cast<const montauk_signal_event*>(data);
        note_ts(e->timestamp_ns);
        if (e->kind < 2) ++signal_[e->kind];
        break;
      }
      case TRACE_EVT_MMAP: {
        if (len < sizeof(montauk_mmap_event)) break;
        auto* e = reinterpret_cast<const montauk_mmap_event*>(data);
        note_ts(e->timestamp_ns);
        ++mmap_;
        break;
      }
      case TRACE_EVT_ABORT: {
        if (len < sizeof(montauk_abort_event)) break;
        auto* e = reinterpret_cast<const montauk_abort_event*>(data);
        note_ts(e->timestamp_ns);
        if (e->func < 3) ++abort_[e->func];
        break;
      }
      case TRACE_EVT_HEAPSTACK: {
        if (len < sizeof(montauk_heapstack_event)) break;
        auto* e = reinterpret_cast<const montauk_heapstack_event*>(data);
        note_ts(e->timestamp_ns);
        ++heapstack_;
        break;
      }
      case TRACE_EVT_FORK:
      case TRACE_EVT_EXEC:
      case TRACE_EVT_EXIT:
      case TRACE_EVT_COMM_CHANGE:
        ++lifecycle_[type];  // montauk_ring_event carries no timestamp
        break;
      case TRACE_EVT_PROVIDER: {
        if (len < sizeof(montauk_provider_event)) break;
        auto* e = reinterpret_cast<const montauk_provider_event*>(data);
        note_ts(e->timestamp_ns);
        char nm[33];
        std::snprintf(nm, sizeof(nm), "%.32s", e->name);
        ++provider_[nm];
        break;
      }
      default:
        ++unknown_[type];
        break;
    }
  }

  struct Row {
    const char* type;
    std::string sub;
    uint64_t n;
  };

  std::vector<Row> rows() const {
    std::vector<Row> out;
    auto row = [&out](const char* t, const char* sub, uint64_t n) {
      if (n) out.push_back({t, sub, n});
    };
    for (uint8_t op = 0; op < 14; ++op) {
      row("NTSYNC", ntsync_op_name(op), ntsync_done_[op]);
      if (ntsync_enter_[op]) {
        char sub[32];
        std::snprintf(sub, sizeof(sub), "%s.enter", ntsync_op_name(op));
        row("NTSYNC", sub, ntsync_enter_[op]);
      }
    }
    for (const auto& [nr, n] : io_) {
      char sub[32];
      const char* nm = io_syscall_name(nr);
      if (std::strcmp(nm, "?") == 0) std::snprintf(sub, sizeof(sub), "nr=%d", nr);
      else std::snprintf(sub, sizeof(sub), "%s", nm);
      row("IO", sub, n);
    }
    for (uint32_t op = 1; op < MONTAUK_SCHED_OP_MAX; ++op) row("SCHED", sched_op_name(op), sched_[op]);
    row("HEAP", "malloc", heap_[HEAP_OP_MALLOC]);
    row("HEAP", "free", heap_[HEAP_OP_FREE]);
    row("HEAP", "realloc", heap_[HEAP_OP_REALLOC]);
    row("HEAP", "calloc", heap_[HEAP_OP_CALLOC]);
    row("SIGNAL", "deliver", signal_[SIGEVT_DELIVER]);
    row("SIGNAL", "exit_abnormal", signal_[SIGEVT_EXIT_ABNL]);
    row("ABORT", "__assert_fail", abort_[ABORT_FN_ASSERT_FAIL]);
    row("ABORT", "__libc_message", abort_[ABORT_FN_LIBC_MESSAGE]);
    row("ABORT", "abort", abort_[ABORT_FN_ABORT]);
    row("HEAPSTK", "size_filtered", heapstack_);
    row("MMAP", "file_backed", mmap_);
    row("FORK", "", lifecycle_[TRACE_EVT_FORK]);
    row("EXEC", "", lifecycle_[TRACE_EVT_EXEC]);
    row("EXIT", "", lifecycle_[TRACE_EVT_EXIT]);
    row("COMM", "change", lifecycle_[TRACE_EVT_COMM_CHANGE]);
    for (const auto& [nm, n] : provider_) row("PROVIDER", nm.c_str(), n);
    for (const auto& [t, n] : unknown_) {
      char sub[32];
      std::snprintf(sub, sizeof(sub), "type=%u", t);
      row("UNKNOWN", sub, n);
    }
    return out;
  }

  void emit(const montauk::model::TraceReader& reader) override {
    const auto& hdr = reader.header();
    char pat[33];
    std::snprintf(pat, sizeof(pat), "%.*s", static_cast<int>(sizeof(hdr.pattern)), hdr.pattern);
    double dur_s = (max_ts_ > min_ts_) ? static_cast<double>(max_ts_ - min_ts_) / 1e9 : 0.0;
    double eps = dur_s > 0.0 ? static_cast<double>(total_) / dur_s : 0.0;
    std::vector<Row> rs = rows();
    std::printf("REPORT summary\n");
    if (total_ == 0 || rs.empty()) {
      std::printf("VERDICT: empty trace — no events\n");
    } else {
      const Row* dom = &rs[0];
      for (const Row& r : rs)
        if (r.n > dom->n) dom = &r;
      std::printf("VERDICT: %s events in %.1f s (%s/s), dominated by %s %s (%.0f%%)\n",
                  fmt_count(static_cast<double>(total_)).c_str(), dur_s, fmt_count(eps).c_str(),
                  dom->type, dom->sub.c_str(),
                  100.0 * static_cast<double>(dom->n) / static_cast<double>(total_));
    }
    std::printf("pattern         %s\n", pat);
    std::printf("start           %s\n", wall_str(hdr.real_anchor_ns).c_str());
    std::printf("format_version  %u\n", hdr.version);
    std::printf("first_event_ms  %.3f\n", min_ts_ ? reader.elapsed_ms(min_ts_) : 0.0);
    std::printf("duration_s      %.3f\n", dur_s);
    std::printf("events          %" PRIu64 "\n", total_);
    std::printf("events_per_sec  %.0f\n", eps);
    std::printf("type    subtype          count\n");
    for (const Row& r : rs)
      std::printf("%-7s %-16s %12" PRIu64 "\n", r.type, r.sub.c_str(), r.n);
  }

  void prom(std::vector<PromMetric>& out) override {
    for (const Row& r : rows()) {
      char lab[80];
      std::snprintf(lab, sizeof(lab), "type=\"%s\",subtype=\"%s\"", r.type, r.sub.c_str());
      out.push_back({"montauk_analysis_events_total", lab, static_cast<double>(r.n)});
    }
  }
};

// REPORT waits: per (tid,fd) NTSYNC wait-completion stats.
struct WaitsReport final : Report {
  struct Agg {
    uint32_t tid = 0;
    uint64_t obj = 0;
    uint64_t count = 0;
    uint64_t last_ts = 0;
    std::unordered_map<int64_t, uint64_t> results;
    std::vector<uint64_t> gaps_ns;
  };
  std::unordered_map<uint64_t, Agg> aggs_;

  const char* name() const override { return "waits"; }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    SyncWait w;
    if (!sync_wait(type, data, len, w)) return;
    auto& a = aggs_[tid_obj_key(w.tid, w.obj)];
    if (a.count == 0) { a.tid = w.tid; a.obj = w.obj; }
    ++a.count;
    ++a.results[w.result];
    if (a.last_ts && w.ts > a.last_ts) a.gaps_ns.push_back(w.ts - a.last_ts);
    a.last_ts = w.ts;
  }

  // Sort gaps in place once; med/p99 stay valid for emit and prom. Sorted
  // through sublimation (u64 flow-model), the same path the sched report
  // uses for wake2run latencies -- montauk's sort does montauk's analysis.
  static bool gap_quantiles(Agg& a, double& med_ms, double& p99_ms) {
    if (a.gaps_ns.empty()) return false;
    sublimation_u64(a.gaps_ns.data(), a.gaps_ns.size());
    med_ms = static_cast<double>(a.gaps_ns[a.gaps_ns.size() / 2]) / 1e6;
    p99_ms = static_cast<double>(a.gaps_ns[(a.gaps_ns.size() * 99) / 100]) / 1e6;
    return true;
  }

  void emit(const montauk::model::TraceReader&) override {
    std::printf("REPORT waits\n");
    if (aggs_.empty()) {
      std::printf("VERDICT: no sync wait completions in trace (NTSYNC or futex)\n");
      return;
    }
    uint64_t total = 0;
    const Agg* top = nullptr;
    for (const auto& [k, a] : aggs_) {
      (void)k;
      total += a.count;
      if (!top || a.count > top->count) top = &a;
    }
    double share = 100.0 * static_cast<double>(top->count) / static_cast<double>(total);
    if (share >= 50.0)
      std::printf("VERDICT: tid=%u obj=0x%016" PRIx64 " dominates — %s of %s wait completions (%.0f%%) across %zu tid/obj pairs\n",
                  top->tid, top->obj, fmt_count(static_cast<double>(top->count)).c_str(),
                  fmt_count(static_cast<double>(total)).c_str(), share, aggs_.size());
    else
      std::printf("VERDICT: wait load spread across %zu tid/obj pairs — top tid=%u obj=0x%016" PRIx64 " holds %.0f%% (%s of %s)\n",
                  aggs_.size(), top->tid, top->obj, share,
                  fmt_count(static_cast<double>(top->count)).c_str(),
                  fmt_count(static_cast<double>(total)).c_str());
    std::printf("result legend: >=0 signaled object index, %" PRId64 " ETIMEDOUT, other negative -errno\n",
                kEtimedout);
    std::vector<Agg*> rows;
    rows.reserve(aggs_.size());
    for (auto& [k, a] : aggs_) { (void)k; rows.push_back(&a); }
    sublimation_order_u64(rows, true, [](const Agg* p) { return p->count; });
    std::printf("tid      obj                waits      gap_med_ms gap_p99_ms results\n");
    for (Agg* a : rows) {
      char med[24] = "-", p99[24] = "-";
      double med_ms = 0.0, p99_ms = 0.0;
      if (gap_quantiles(*a, med_ms, p99_ms)) {
        std::snprintf(med, sizeof(med), "%.3f", med_ms);
        std::snprintf(p99, sizeof(p99), "%.3f", p99_ms);
      }
      std::vector<std::pair<int64_t, uint64_t>> res(a->results.begin(), a->results.end());
      sublimation_order_u64(res, true, [](const std::pair<int64_t, uint64_t>& p) { return p.second; });
      std::string res_s;
      for (size_t i = 0; i < res.size() && i < kWaitsTopResults; ++i) {
        char one[48];
        std::snprintf(one, sizeof(one), "%s%" PRId64 ":%" PRIu64,
                      res_s.empty() ? "" : " ", res[i].first, res[i].second);
        res_s += one;
      }
      std::printf("%-8u 0x%016" PRIx64 " %-10" PRIu64 " %-10s %-10s %s\n",
                  a->tid, a->obj, a->count, med, p99, res_s.c_str());
    }
  }

  // Samples grouped per metric family (the text format expects families
  // contiguous).
  void prom(std::vector<PromMetric>& out) override {
    for (const auto& [k, a] : aggs_) {
      (void)k;
      char lab[64];
      std::snprintf(lab, sizeof(lab), "tid=\"%u\",obj=\"0x%016" PRIx64 "\"", a.tid, a.obj);
      out.push_back({"montauk_analysis_waits_total", lab, static_cast<double>(a.count)});
    }
    for (auto& [k, a] : aggs_) {
      (void)k;
      double med_ms = 0.0, p99_ms = 0.0;
      if (!gap_quantiles(a, med_ms, p99_ms)) continue;
      char qlab[96];
      std::snprintf(qlab, sizeof(qlab), "tid=\"%u\",obj=\"0x%016" PRIx64 "\",quantile=\"0.5\"", a.tid, a.obj);
      out.push_back({"montauk_analysis_wait_gap_ms", qlab, med_ms});
      std::snprintf(qlab, sizeof(qlab), "tid=\"%u\",obj=\"0x%016" PRIx64 "\",quantile=\"0.99\"", a.tid, a.obj);
      out.push_back({"montauk_analysis_wait_gap_ms", qlab, p99_ms});
    }
  }
};

// REPORT spins: livelock detector. A run is a streak of consecutive wait
// completions on one (tid,fd) with inter-wait gap < kSpinGapNs; runs that
// sustain >= kSpinMinIters iterations are reported with a verdict.
struct SpinsReport final : Report {
  struct RunState {
    uint32_t tid = 0;       // stored: the hashed map key is not reversible
    uint64_t obj = 0;       // opaque lock id (ntsync fd / futex uaddr)
    uint64_t last_ts = 0;
    int64_t last_result = 0;
    uint64_t iters = 0;     // 0 = no active run
    uint64_t start_ts = 0;
    uint64_t succ = 0, timeo = 0, other = 0;
  };
  struct Run {
    uint32_t tid;
    uint64_t obj;
    uint64_t iters, start_ts, end_ts, succ, timeo, other;
  };
  std::unordered_map<uint64_t, RunState> state_;
  std::vector<Run> runs_;

  const char* name() const override { return "spins"; }

  static void tally(RunState& s, int64_t result) {
    if (result >= 0) ++s.succ;
    else if (result == kEtimedout) ++s.timeo;
    else ++s.other;
  }

  void finalize(uint32_t tid, uint64_t obj, RunState& s, uint64_t end_ts) {
    if (s.iters >= kSpinMinIters)
      runs_.push_back({tid, obj, s.iters, s.start_ts, end_ts, s.succ, s.timeo, s.other});
    s.iters = 0;
    s.succ = s.timeo = s.other = 0;
  }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    SyncWait w;
    if (!sync_wait(type, data, len, w)) return;
    auto& s = state_[tid_obj_key(w.tid, w.obj)];
    s.tid = w.tid;
    s.obj = w.obj;
    if (s.last_ts && w.ts > s.last_ts && w.ts - s.last_ts < kSpinGapNs) {
      if (s.iters == 0) {
        // Run opens retroactively: the previous wait was its first iteration.
        s.iters = 1;
        s.start_ts = s.last_ts;
        tally(s, s.last_result);
      }
      ++s.iters;
      tally(s, w.result);
    } else {
      finalize(w.tid, w.obj, s, s.last_ts);
    }
    s.last_ts = w.ts;
    s.last_result = w.result;
  }

  // Idempotent: finalize() resets iters, so whichever of emit/prom runs
  // first drains open runs and the second pass is a no-op.
  void finalize_all() {
    for (auto& [key, s] : state_) {
      (void)key;
      finalize(s.tid, s.obj, s, s.last_ts);
    }
  }

  // Classify a run by its dominant result tally (mirrors the table verdict).
  static const char* run_class(const Run& r) {
    if (r.succ >= r.timeo && r.succ >= r.other) return "instant-success";
    if (r.timeo >= r.other) return "timeout";
    return "error";
  }

  static double run_rate(const Run& r) {
    double span_ms = static_cast<double>(r.end_ts - r.start_ts) / 1e6;
    return span_ms > 0.0 ? static_cast<double>(r.iters) * 1000.0 / span_ms : 0.0;
  }

  void emit(const montauk::model::TraceReader& reader) override {
    finalize_all();
    std::printf("REPORT spins\n");
    if (runs_.empty()) {
      std::printf("VERDICT: no spin runs detected\n");
      std::printf("criteria: inter-wait gap < %.1f ms sustained >= %" PRIu64 " iterations\n",
                  static_cast<double>(kSpinGapNs) / 1e6, kSpinMinIters);
      return;
    }
    std::map<std::string, uint64_t> by_class;
    std::set<uint64_t> pairs;
    double peak = 0.0;
    for (const Run& r : runs_) {
      ++by_class[run_class(r)];
      pairs.insert(tid_obj_key(r.tid, r.obj));
      peak = std::max(peak, run_rate(r));
    }
    const auto dom_cls = std::max_element(by_class.begin(), by_class.end(),
                                          [](const auto& l, const auto& r) { return l.second < r.second; });
    const char* word = "error spin";
    if (dom_cls->first == "instant-success") word = "livelock";
    else if (dom_cls->first == "timeout") word = "starved waiter";
    char counts[80];
    if (dom_cls->second == runs_.size())
      std::snprintf(counts, sizeof(counts), "%zu %s spin runs", runs_.size(), dom_cls->first.c_str());
    else
      std::snprintf(counts, sizeof(counts), "%" PRIu64 " of %zu spin runs %s",
                    dom_cls->second, runs_.size(), dom_cls->first.c_str());
    char where[64];
    if (pairs.size() == 1)
      std::snprintf(where, sizeof(where), "all tid=%u obj=0x%016" PRIx64, runs_[0].tid, runs_[0].obj);
    else
      std::snprintf(where, sizeof(where), "across %zu tid/obj pairs", pairs.size());
    std::printf("VERDICT: %s — %s, %s, peak %s waits/s\n",
                word, counts, where, fmt_count(peak).c_str());
    std::printf("criteria: inter-wait gap < %.1f ms sustained >= %" PRIu64 " iterations\n",
                static_cast<double>(kSpinGapNs) / 1e6, kSpinMinIters);
    sublimation_order_u64(runs_, true, [](const Run& r) { return r.iters; });
    std::printf("tid      obj                iters      start_ms     span_ms    rate_per_s dominant              verdict\n");
    for (const Run& r : runs_) {
      double span_ms = static_cast<double>(r.end_ts - r.start_ts) / 1e6;
      double rate = span_ms > 0.0 ? static_cast<double>(r.iters) * 1000.0 / span_ms : 0.0;
      const char* dom;
      const char* verdict;
      if (r.succ >= r.timeo && r.succ >= r.other) {
        dom = "success";
        verdict = "instant-success spin (stuck-signaled object suspected)";
      } else if (r.timeo >= r.other) {
        dom = "timeout";
        verdict = "timeout spin (starved waiter suspected)";
      } else {
        dom = "error";
        verdict = "error spin (inspect result distribution)";
      }
      char dom_s[32];
      std::snprintf(dom_s, sizeof(dom_s), "%s:%" PRIu64, dom,
                    std::max(r.succ, std::max(r.timeo, r.other)));
      std::printf("%-8u 0x%016" PRIx64 " %-10" PRIu64 " %-12.3f %-10.3f %-10.0f %-21s %s\n",
                  r.tid, r.obj, r.iters, reader.elapsed_ms(r.start_ts), span_ms, rate,
                  dom_s, verdict);
    }
  }

  void prom(std::vector<PromMetric>& out) override {
    finalize_all();
    std::map<std::string, uint64_t> run_counts;  // label string -> runs
    std::map<uint64_t, std::pair<const Run*, double>> peaks;  // (tid,fd) -> peak run
    for (const Run& r : runs_) {
      char lab[96];
      std::snprintf(lab, sizeof(lab), "tid=\"%u\",obj=\"0x%016" PRIx64 "\",verdict=\"%s\"",
                    r.tid, r.obj, run_class(r));
      ++run_counts[lab];
      auto& p = peaks[tid_obj_key(r.tid, r.obj)];
      double rate = run_rate(r);
      if (!p.first || rate > p.second) p = {&r, rate};
    }
    for (const auto& [lab, n] : run_counts)
      out.push_back({"montauk_analysis_spin_runs_total", lab, static_cast<double>(n)});
    for (const auto& [key, p] : peaks) {
      (void)key;
      char lab[64];
      std::snprintf(lab, sizeof(lab), "tid=\"%u\",obj=\"0x%016" PRIx64 "\"", p.first->tid, p.first->obj);
      out.push_back({"montauk_analysis_spin_peak_rate_per_s", lab, p.second});
    }
  }
};

// REPORT pairing: per object fd, waits vs signal-side ops. Waits are
// attributed to the object fds in wait_fds[] (the wait ioctl itself targets
// the ntsync device fd, not the object); signals use the event's own fd.
struct PairingReport final : Report {
  struct Agg {
    uint64_t waits = 0;
    uint64_t set = 0, reset = 0, sem_release = 0, mutex_unlock = 0;
  };
  std::map<int32_t, Agg> aggs_;

  const char* name() const override { return "pairing"; }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type != TRACE_EVT_NTSYNC || len < sizeof(montauk_ntsync_event)) return;
    auto* e = reinterpret_cast<const montauk_ntsync_event*>(data);
    if (is_wait_op(e->op)) {
      if (e->result == kWaitEntrySentinel) return;  // count completions once
      uint32_t n = e->wait_count;
      if (n > NTSYNC_MAX_WAIT_FDS) n = NTSYNC_MAX_WAIT_FDS;
      for (uint32_t i = 0; i < n; ++i) ++aggs_[static_cast<int32_t>(e->wait_fds[i])].waits;
    } else if (is_signal_op(e->op)) {
      auto& a = aggs_[e->fd];
      switch (e->op) {
        case NTS_EVENT_SET:    ++a.set; break;
        case NTS_EVENT_RESET:  ++a.reset; break;
        case NTS_SEM_RELEASE:  ++a.sem_release; break;
        case NTS_MUTEX_UNLOCK: ++a.mutex_unlock; break;
        default: break;
      }
    }
  }

  static uint64_t signal_total(const Agg& a) {
    return a.set + a.reset + a.sem_release + a.mutex_unlock;
  }

  static bool flagged(const Agg& a) {
    return a.waits >= kPairingMinWaits && a.waits > signal_total(a) * kPairingWaitSignalRatio;
  }

  void emit(const montauk::model::TraceReader&) override {
    std::printf("REPORT pairing\n");
    if (aggs_.empty()) {
      std::printf("VERDICT: no NTSYNC activity in trace\n");
      return;
    }
    size_t n_flagged = 0;
    const Agg* worst = nullptr;
    int32_t worst_fd = 0;
    for (const auto& [fd, a] : aggs_) {
      if (!flagged(a)) continue;
      ++n_flagged;
      if (!worst || a.waits > worst->waits) { worst = &a; worst_fd = fd; }
    }
    if (!worst) {
      std::printf("VERDICT: all waited fds have plausible signalers\n");
    } else {
      char more[64] = "";
      if (n_flagged > 1)
        std::snprintf(more, sizeof(more), ", +%zu more flagged fds", n_flagged - 1);
      std::printf("VERDICT: fd %d stuck-signaled — %s waits, %s signals%s\n",
                  worst_fd, fmt_count(static_cast<double>(worst->waits)).c_str(),
                  fmt_count(static_cast<double>(signal_total(*worst))).c_str(), more);
    }
    std::printf("flag: waits > %" PRIu64 "x signals (min %" PRIu64 " waits) = waits with no plausible signaler\n",
                kPairingWaitSignalRatio, kPairingMinWaits);
    std::vector<std::pair<int32_t, const Agg*>> rows;
    rows.reserve(aggs_.size());
    for (const auto& [fd, a] : aggs_) rows.emplace_back(fd, &a);
    sublimation_order_u64(rows, true, [](const std::pair<int32_t, const Agg*>& p) { return p.second->waits; });
    std::printf("fd     waits      event_set  event_reset sem_release mutex_unlock signals    flag\n");
    for (const auto& [fd, a] : rows) {
      std::printf("%-6d %-10" PRIu64 " %-10" PRIu64 " %-11" PRIu64 " %-11" PRIu64 " %-12" PRIu64 " %-10" PRIu64 " %s\n",
                  fd, a->waits, a->set, a->reset, a->sem_release, a->mutex_unlock,
                  signal_total(*a), flagged(*a) ? "waits with no plausible signaler" : "");
    }
  }

  void prom(std::vector<PromMetric>& out) override {
    auto family = [&](const char* name, auto value) {
      for (const auto& [fd, a] : aggs_) {
        char lab[32];
        std::snprintf(lab, sizeof(lab), "fd=\"%d\"", fd);
        out.push_back({name, lab, value(a)});
      }
    };
    family("montauk_analysis_pairing_waits",
           [](const Agg& a) { return static_cast<double>(a.waits); });
    family("montauk_analysis_pairing_signals",
           [](const Agg& a) { return static_cast<double>(signal_total(a)); });
    family("montauk_analysis_unsignaled_flag",
           [](const Agg& a) { return flagged(a) ? 1.0 : 0.0; });
  }
};

// REPORT abortpm: per-ABORT arena post-mortem. The glibc top-chunk / !prev
// corruption class presents as a linear overrun of the allocation that abuts
// the arena top: replaying the heap stream up to each abort and reporting
// the highest live chunks in the aborting thread's arena names the victim
// allocation without a debugger attached. Also dumps the aborting thread's
// last events (heap/mmap/wait) so the work item that owned the victim is
// visible in place.
struct AbortPostmortemReport final : Report {
  static constexpr uint64_t kArenaSize = 64ull << 20;  // glibc HEAP_MAX_SIZE
  static constexpr size_t kRingCap = 8;
  static constexpr size_t kTopChunks = 5;

  struct Chunk { uint64_t size; uint32_t tid; char comm[16]; };
  struct RingItem { uint64_t ts; uint8_t kind; uint8_t op; int32_t fd; uint64_t a; uint64_t b; };
  struct Ring {
    RingItem items[kRingCap] {};
    size_t n = 0, idx = 0;
    void push(const RingItem& it) {
      items[idx] = it;
      idx = (idx + 1) % kRingCap;
      if (n < kRingCap) ++n;
    }
  };

  std::unordered_map<uint64_t, Chunk> live_;          // addr -> live chunk
  std::unordered_map<uint32_t, uint64_t> last_alloc_; // tid -> last alloc addr
  std::unordered_map<uint32_t, Ring> rings_;          // tid -> recent events
  std::vector<std::string> findings_;

  const char* name() const override { return "abortpm"; }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type == TRACE_EVT_HEAP && len >= sizeof(montauk_heap_event)) {
      auto* e = reinterpret_cast<const montauk_heap_event*>(data);
      if (e->op == HEAP_OP_MALLOC || e->op == HEAP_OP_CALLOC) {
        if (e->addr) {
          auto& c = live_[e->addr];
          c.size = e->size;
          c.tid = e->tid;
          std::memcpy(c.comm, e->comm, sizeof(c.comm));
          last_alloc_[e->tid] = e->addr;
        }
      } else if (e->op == HEAP_OP_FREE) {
        if (e->addr) live_.erase(e->addr);
      } else if (e->op == HEAP_OP_REALLOC) {
        if (e->addr) live_.erase(e->addr);
        if (e->new_addr) {
          auto& c = live_[e->new_addr];
          c.size = e->size;
          c.tid = e->tid;
          std::memcpy(c.comm, e->comm, sizeof(c.comm));
          last_alloc_[e->tid] = e->new_addr;
        }
      }
      rings_[e->tid].push({e->timestamp_ns, 0, static_cast<uint8_t>(e->op), 0, e->addr, e->size});
      return;
    }
    if (type == TRACE_EVT_MMAP && len >= sizeof(montauk_mmap_event)) {
      auto* e = reinterpret_cast<const montauk_mmap_event*>(data);
      rings_[e->tid].push({e->timestamp_ns, 1, 0, e->fd, e->addr, e->length});
      return;
    }
    if (type == TRACE_EVT_NTSYNC && len >= sizeof(montauk_ntsync_event)) {
      auto* e = reinterpret_cast<const montauk_ntsync_event*>(data);
      if (is_wait_op(e->op) && e->result != kWaitEntrySentinel)
        rings_[e->tid].push({e->timestamp_ns, 2, e->op, e->fd,
                             static_cast<uint64_t>(e->result), e->wait_count});
      return;
    }
    if (type != TRACE_EVT_ABORT || len < sizeof(montauk_abort_event)) return;

    auto* a = reinterpret_cast<const montauk_abort_event*>(data);
    // Arena of the aborting thread = the 64MB-aligned window holding its
    // most recent allocation. The chunk with the highest address inside it
    // abuts the arena top: the overrun suspect.
    char buf[512];
    std::string f;
    std::snprintf(buf, sizeof(buf),
                  "ABORT @%.3fs pid=%u tid=%u comm='%.16s'\n",
                  a->timestamp_ns / 1e9, a->pid, a->tid, a->comm);
    f += buf;
    auto la = last_alloc_.find(a->tid);
    if (la == last_alloc_.end()) {
      f += "  no allocations recorded for this tid — no arena attribution\n";
    } else {
      uint64_t base = la->second & ~(kArenaSize - 1);
      std::vector<std::pair<uint64_t, const Chunk*>> in;
      for (const auto& [addr, c] : live_)
        if (addr >= base && addr < base + kArenaSize) in.emplace_back(addr, &c);
      sublimation_order_u64(in, true, [](const std::pair<uint64_t, const Chunk*>& p) { return p.first; });
      std::snprintf(buf, sizeof(buf),
                    "  arena window 0x%" PRIx64 " (+64MB): %zu live chunks; top-adjacent first:\n",
                    base, in.size());
      f += buf;
      for (size_t i = 0; i < in.size() && i < kTopChunks; ++i) {
        std::snprintf(buf, sizeof(buf),
                      "    %s addr=0x%" PRIx64 " size=%-8" PRIu64 " tid=%u comm='%.16s'%s\n",
                      i == 0 ? "VICTIM?" : "       ",
                      in[i].first, in[i].second->size, in[i].second->tid,
                      in[i].second->comm,
                      i == 0 ? "  <- header at addr+size is the corrupt top" : "");
        f += buf;
      }
    }
    auto rg = rings_.find(a->tid);
    if (rg != rings_.end()) {
      f += "  last events of aborting tid:\n";
      const Ring& r = rg->second;
      for (size_t k = 0; k < r.n; ++k) {
        const RingItem& it = r.items[(r.idx + kRingCap - r.n + k) % kRingCap];
        switch (it.kind) {
          case 0:
            std::snprintf(buf, sizeof(buf),
                          "    %.3fs HEAP op=%u addr=0x%" PRIx64 " size=%" PRIu64 "\n",
                          it.ts / 1e9, it.op, it.a, it.b);
            break;
          case 1:
            std::snprintf(buf, sizeof(buf),
                          "    %.3fs MMAP fd=%d addr=0x%" PRIx64 " len=%" PRIu64 "\n",
                          it.ts / 1e9, it.fd, it.a, it.b);
            break;
          default:
            std::snprintf(buf, sizeof(buf),
                          "    %.3fs WAIT fd=%d result=%" PRId64 " count=%" PRIu64 "\n",
                          it.ts / 1e9, it.fd, static_cast<int64_t>(it.a), it.b);
        }
        f += buf;
      }
    }
    findings_.push_back(std::move(f));
  }

  void emit(const montauk::model::TraceReader&) override {
    std::printf("REPORT abortpm\n");
    if (findings_.empty()) {
      std::printf("VERDICT: no abort events in trace\n");
      return;
    }
    std::printf("VERDICT: %zu abort(s); victim chunk = highest live allocation in the aborting arena\n",
                findings_.size());
    for (const auto& f : findings_) std::printf("%s", f.c_str());
  }

  void prom(std::vector<PromMetric>& out) override {
    out.push_back({"montauk_analysis_aborts_total", "",
                   static_cast<double>(findings_.size())});
  }
};

// REPORT endstate: who was doing what when the trace ENDED. The generic
// stall question: after a user hits STOP because a game wedged, the threads
// still parked in ntsync waits at end-of-trace — and how long they had been
// parked — name the stall. A thread whose wait opened minutes before the
// end and never completed is the wedge; a thread active until the last
// moment is not.
struct EndstateReport final : Report {
  struct TidState {
    uint64_t last_ts = 0;
    uint32_t pid = 0;
    char comm[16] = {};
    bool wait_open = false;
    uint64_t wait_since = 0;
    int32_t wait_dev_fd = 0;
    uint32_t wait_count = 0;
    uint64_t timeout_ns = 0;
    bool exited = false;
    uint64_t wait_objs[NTSYNC_MAX_WAIT_FDS] = {};  // stable kernel obj ptrs of the open wait
    uint32_t wait_fds[NTSYNC_MAX_WAIT_FDS] = {};   // object fds of the open wait
  };
  // Signal history per stable kernel object pointer (file->private_data),
  // so a parked thread's wait object can be joined to whoever signals it.
  struct ObjSig {
    uint64_t signals = 0;
    uint64_t waits = 0;
    uint64_t last_signal_ts = 0;
    uint32_t last_signal_tid = 0;
    uint8_t  last_signal_op = 0;
  };
  std::map<uint32_t, TidState> tids_;
  std::map<uint64_t, ObjSig> objs_;
  uint64_t max_ts_ = 0;

  const char* name() const override { return "endstate"; }

  void touch(uint32_t tid, uint32_t pid, uint64_t ts, const char* comm) {
    auto& t = tids_[tid];
    if (ts > t.last_ts) t.last_ts = ts;
    t.pid = pid;
    if (comm && comm[0]) std::memcpy(t.comm, comm, sizeof(t.comm));
    if (ts > max_ts_) max_ts_ = ts;
  }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type == TRACE_EVT_NTSYNC && len >= sizeof(montauk_ntsync_event)) {
      auto* e = reinterpret_cast<const montauk_ntsync_event*>(data);
      touch(e->tid, e->pid, e->timestamp_ns, nullptr);
      auto& t = tids_[e->tid];
      if (is_wait_op(e->op)) {
        if (e->result == kWaitEntrySentinel) {
          t.wait_open = true;
          t.wait_since = e->timestamp_ns;
          t.wait_dev_fd = e->fd;
          t.wait_count = e->wait_count;
          t.timeout_ns = e->timeout_ns;
          uint32_t n = e->wait_count;
          if (n > NTSYNC_MAX_WAIT_FDS) n = NTSYNC_MAX_WAIT_FDS;
          for (uint32_t i = 0; i < n; ++i) {
            t.wait_objs[i] = e->wait_objs[i];
            t.wait_fds[i] = e->wait_fds[i];
            ++objs_[e->wait_objs[i]].waits;
          }
        } else {
          t.wait_open = false;
        }
      } else if (is_signal_op(e->op)) {
        auto& o = objs_[e->obj_ptr];
        ++o.signals;
        o.last_signal_ts = e->timestamp_ns;
        o.last_signal_tid = e->tid;
        o.last_signal_op = static_cast<uint8_t>(e->op);
      }
      return;
    }
    if (type == TRACE_EVT_HEAP && len >= sizeof(montauk_heap_event)) {
      auto* e = reinterpret_cast<const montauk_heap_event*>(data);
      touch(e->tid, e->pid, e->timestamp_ns, e->comm);
      return;
    }
    if (type == TRACE_EVT_IO && len >= sizeof(montauk_io_event)) {
      auto* e = reinterpret_cast<const montauk_io_event*>(data);
      touch(e->tid, e->pid, e->timestamp_ns, e->comm);
      return;
    }
    if (type == TRACE_EVT_SIGNAL && len >= sizeof(montauk_signal_event)) {
      auto* e = reinterpret_cast<const montauk_signal_event*>(data);
      touch(e->tid, e->pid, e->timestamp_ns, e->comm);
      if (e->kind == SIGEVT_EXIT_ABNL) tids_[e->tid].exited = true;
      return;
    }
  }

  void emit(const montauk::model::TraceReader&) override {
    std::printf("REPORT endstate\n");
    if (tids_.empty()) {
      std::printf("VERDICT: no per-thread activity in trace\n");
      return;
    }
    std::vector<std::pair<uint32_t, const TidState*>> blocked;
    for (const auto& [tid, t] : tids_)
      if (t.wait_open && !t.exited) blocked.emplace_back(tid, &t);
    sublimation_order_u64(blocked, false, [](const std::pair<uint32_t, const TidState*>& p) { return p.second->wait_since; });
    if (blocked.empty()) {
      std::printf("VERDICT: no threads parked in ntsync waits at trace end\n");
      return;
    }
    // A thread is GENUINELY parked only if it executed nothing after its wait
    // entry. Any later event of any type (last_ts > wait_since) means it woke
    // and the completion was lost/corrupted by the per-CPU ntsync_scratch race
    // (single key-0 slot, tgid-only disambiguation) — not a real park.
    constexpr uint64_t kParkSlackNs = 1'000'000;  // 1ms
    size_t genuine = 0;
    for (const auto& [tid, t] : blocked)
      if (t->last_ts <= t->wait_since + kParkSlackNs) ++genuine;
    const auto& w = *blocked.front().second;
    std::printf("VERDICT: %zu thread(s) show an open wait at trace end; %zu GENUINELY parked "
                "(no activity after wait entry), %zu woke (completion lost to scratch race)\n",
                blocked.size(), genuine, blocked.size() - genuine);
    std::printf("longest open wait: tid=%u comm='%.16s' since %.1fs before end\n",
                blocked.front().first, w.comm, (max_ts_ - w.wait_since) / 1e9);
    std::printf("tid      pid      comm             open_s    act_after_ms  status         objs  timeout_ns\n");
    for (const auto& [tid, t] : blocked) {
      double act_after_ms = (t->last_ts > t->wait_since) ? (t->last_ts - t->wait_since) / 1e6 : 0.0;
      bool parked = t->last_ts <= t->wait_since + kParkSlackNs;
      std::printf("%-8u %-8u %-16.16s %-9.1f %-13.1f %-14s %-5u %" PRIu64 "\n",
                  tid, t->pid, t->comm, (max_ts_ - t->wait_since) / 1e9,
                  act_after_ms, parked ? "PARKED" : "woke(lost-compl)",
                  t->wait_count, t->timeout_ns);
    }

    // Per-parked-thread wait-object signal history — the missed-wakeup vs
    // dead-producer discriminator. For each object a parked thread is stuck
    // on: did anything ever signal it, and did that signal land AFTER the
    // park (a real lost wakeup) or never come at all (dead producer / no
    // signaler).
    std::printf("\nparked-thread wait objects (signal history):\n");
    std::printf("tid      obj                  fd     signals  waits     verdict\n");
    for (const auto& [tid, t] : blocked) {
      uint32_t n = t->wait_count;
      if (n > NTSYNC_MAX_WAIT_FDS) n = NTSYNC_MAX_WAIT_FDS;
      for (uint32_t i = 0; i < n; ++i) {
        uint64_t ptr = t->wait_objs[i];
        auto it = objs_.find(ptr);
        uint64_t sigs = (it != objs_.end()) ? it->second.signals : 0;
        uint64_t wts  = (it != objs_.end()) ? it->second.waits : 0;
        char verdict[192];
        if (sigs == 0) {
          std::snprintf(verdict, sizeof(verdict),
                        "NEVER signaled — dead producer / no signaler");
        } else if (it->second.last_signal_ts > t->wait_since) {
          std::snprintf(verdict, sizeof(verdict),
                        "signaled +%.1fms AFTER park by tid=%u (%s) — LOST WAKEUP",
                        (it->second.last_signal_ts - t->wait_since) / 1e6,
                        it->second.last_signal_tid,
                        ntsync_op_name(it->second.last_signal_op));
        } else {
          std::snprintf(verdict, sizeof(verdict),
                        "last signal -%.1fms BEFORE park by tid=%u (%s)",
                        (t->wait_since - it->second.last_signal_ts) / 1e6,
                        it->second.last_signal_tid,
                        ntsync_op_name(it->second.last_signal_op));
        }
        std::printf("%-8u 0x%016" PRIx64 " %-6u %-8" PRIu64 " %-9" PRIu64 " %s\n",
                    tid, ptr, t->wait_fds[i], sigs, wts, verdict);
      }
    }
  }

  void prom(std::vector<PromMetric>& out) override {
    size_t blocked = 0;
    for (const auto& [tid, t] : tids_) {
      (void)tid;
      if (t.wait_open && !t.exited) ++blocked;
    }
    out.push_back({"montauk_analysis_endstate_blocked_threads", "",
                   static_cast<double>(blocked)});
  }
};

// REPORT heapstk: deduplicated caller stacks from size-filtered allocation
// captures (MONTAUK_HEAP_STACK_SIZE). One run with the filter set produces
// the unique allocation sites of the victim size, ranked by count.
struct HeapstkReport final : Report {
  struct Site { uint64_t count = 0; uint32_t depth = 0; uint64_t frames[8] = {}; char comm[16] = {}; uint64_t size = 0; };
  std::map<uint64_t, Site> sites_;  // keyed by frame hash

  const char* name() const override { return "heapstk"; }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type != TRACE_EVT_HEAPSTACK || len < sizeof(montauk_heapstack_event)) return;
    auto* e = reinterpret_cast<const montauk_heapstack_event*>(data);
    uint64_t h = 1469598103934665603ull;
    uint32_t n = e->stack_depth;
    if (n > 8) n = 8;
    for (uint32_t i = 0; i < n; ++i) { h ^= e->stack_user[i]; h *= 1099511628211ull; }
    auto& s = sites_[h];
    if (s.count == 0) {
      s.depth = n;
      for (uint32_t i = 0; i < n; ++i) s.frames[i] = e->stack_user[i];
      std::memcpy(s.comm, e->comm, sizeof(s.comm));
      s.size = e->size;
    }
    ++s.count;
  }

  void emit(const montauk::model::TraceReader&) override {
    std::printf("REPORT heapstk\n");
    if (sites_.empty()) {
      std::printf("VERDICT: no heapstack captures in trace (set MONTAUK_HEAP_STACK_SIZE)\n");
      return;
    }
    std::vector<const Site*> rows;
    for (const auto& [h, s] : sites_) { (void)h; rows.push_back(&s); }
    sublimation_order_u64(rows, true, [](const Site* p) { return p->count; });
    std::printf("VERDICT: %zu unique allocation site(s) for size=%" PRIu64 "\n",
                rows.size(), rows.front()->size);
    for (const Site* s : rows) {
      std::printf("site x%-8" PRIu64 " first_comm='%.16s'\n", s->count, s->comm);
      for (uint32_t i = 0; i < s->depth; ++i)
        std::printf("  #%-2u 0x%016" PRIx64 "\n", i, s->frames[i]);
    }
  }
};

// REPORT doublefree: scans the heap stream for an address freed while not
// currently allocated — a double-free or free-of-unallocated. Reports the
// address, the size it last carried, and BOTH freeing tids/comms: same tid
// twice = a logic double-destroy; two different tids = a concurrent free
// race. Directly discriminates the free_dce double-free hypothesis without
// a rerun. Realloc moves are tracked so a moved chunk's old address is not
// mis-flagged.
struct DoubleFreeReport final : Report {
  struct Live { uint64_t size; uint32_t tid; char comm[16]; };
  struct Hit {
    uint64_t addr; uint64_t size;
    uint32_t first_tid; char first_comm[16];
    uint32_t second_tid; char second_comm[16];
  };
  // Keyed by (pid, addr): heap addresses are per-process, and short-lived
  // forks (nvidia-modprobe x280) reuse the same arena addresses — keying by
  // address alone reports those as cross-process false double-frees.
  static uint64_t key(uint32_t pid, uint64_t addr) {
    return (static_cast<uint64_t>(pid) * 1099511628211ull) ^ addr;
  }
  std::unordered_map<uint64_t, Live> live_;
  std::unordered_map<uint64_t, Live> freed_;  // (pid,addr) -> who freed last
  std::vector<Hit> hits_;
  uint64_t total_frees_ = 0;

  const char* name() const override { return "doublefree"; }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type != TRACE_EVT_HEAP || len < sizeof(montauk_heap_event)) return;
    auto* e = reinterpret_cast<const montauk_heap_event*>(data);
    auto store = [&](std::unordered_map<uint64_t, Live>& m, uint64_t a, uint64_t sz) {
      Live l; l.size = sz; l.tid = e->tid;
      std::memcpy(l.comm, e->comm, sizeof(l.comm));
      m[key(e->pid, a)] = l;
    };
    switch (e->op) {
      case HEAP_OP_MALLOC:
      case HEAP_OP_CALLOC:
        if (e->addr) { store(live_, e->addr, e->size); freed_.erase(key(e->pid, e->addr)); }
        break;
      case HEAP_OP_REALLOC:
        if (e->addr) { live_.erase(key(e->pid, e->addr)); freed_.erase(key(e->pid, e->addr)); }
        if (e->new_addr) { store(live_, e->new_addr, e->size); freed_.erase(key(e->pid, e->new_addr)); }
        break;
      case HEAP_OP_FREE: {
        if (!e->addr) break;  // free(NULL) is legal
        ++total_frees_;
        uint64_t k = key(e->pid, e->addr);
        auto it = live_.find(k);
        if (it != live_.end()) {
          store(freed_, e->addr, it->second.size);
          live_.erase(it);
        } else {
          // freed while not live: double-free or free-of-unallocated
          auto pf = freed_.find(k);
          if (pf != freed_.end() && hits_.size() < 64) {
            Hit h; h.addr = e->addr; h.size = pf->second.size;
            h.first_tid = pf->second.tid; std::memcpy(h.first_comm, pf->second.comm, 16);
            h.second_tid = e->tid; std::memcpy(h.second_comm, e->comm, 16);
            hits_.push_back(h);
          }
          store(freed_, e->addr, pf != freed_.end() ? pf->second.size : 0);
        }
        break;
      }
      default: break;
    }
  }

  void emit(const montauk::model::TraceReader&) override {
    std::printf("REPORT doublefree\n");
    if (hits_.empty()) {
      std::printf("VERDICT: no double-frees in %" PRIu64 " frees\n", total_frees_);
      return;
    }
    size_t cross = 0;
    for (const auto& h : hits_) if (h.first_tid != h.second_tid) ++cross;
    std::printf("VERDICT: %zu double-free(s) in %" PRIu64 " frees — %zu cross-thread (race), %zu same-thread (logic)\n",
                hits_.size(), total_frees_, cross, hits_.size() - cross);
    std::printf("addr               size     freed_by_1            freed_by_2           kind\n");
    for (const auto& h : hits_) {
      std::printf("0x%016" PRIx64 " %-8" PRIu64 " tid=%-7u %-10.10s tid=%-7u %-10.10s %s\n",
                  h.addr, h.size, h.first_tid, h.first_comm, h.second_tid, h.second_comm,
                  h.first_tid == h.second_tid ? "same-thread(logic)" : "cross-thread(RACE)");
    }
  }
};

// REPORT futex: threads blocked on a futex-backed lock at trace end, grouped
// by opaque uaddr. A thread whose last activity is a FUTEX_WAIT — especially
// re-issued repeatedly on the same uaddr — is wedged entering that lock.
// Addresses and tids are opaque; any lock naming or cadence interpretation is
// a consumer's job (join the uaddrs against externally-supplied metadata). The
// futex enter-capture stores op in fd, uaddr in count, val in result.
struct FutexReport final : Report {
  struct TidF {
    uint64_t last_ts = 0;        // last activity of any type
    uint64_t last_wait_ts = 0;   // last FUTEX_WAIT entry
    uint64_t wait_uaddr = 0;
    uint32_t retries = 0;        // consecutive FUTEX_WAITs on the same uaddr
    uint32_t pid = 0;
    char comm[16] = {};
  };
  struct UaddrWake {
    uint64_t wakes = 0;
    uint64_t last_wake_ts = 0;
    uint32_t last_wake_tid = 0;
  };
  std::map<uint32_t, TidF> tids_;
  std::map<uint64_t, UaddrWake> wakes_;
  uint64_t max_ts_ = 0;

  const char* name() const override { return "futex"; }

  // FUTEX cmd (op with PRIVATE/CLOCK flags masked off). WAIT family blocks.
  static bool is_wait_cmd(uint32_t opb) { return opb == 0 || opb == 9 || opb == 6 || opb == 11; }
  static bool is_wake_cmd(uint32_t opb) { return opb == 1 || opb == 10 || opb == 7; }

  void touch(uint32_t tid, uint64_t ts) {
    auto& t = tids_[tid];
    if (ts > t.last_ts) t.last_ts = ts;
    if (ts > max_ts_) max_ts_ = ts;
  }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type == TRACE_EVT_IO && len >= sizeof(montauk_io_event)) {
      auto* e = reinterpret_cast<const montauk_io_event*>(data);
      touch(e->tid, e->timestamp_ns);
      auto& t = tids_[e->tid];
      t.pid = e->pid;
      if (e->comm[0]) std::memcpy(t.comm, e->comm, sizeof(t.comm));
      if (e->syscall_nr == 202) {  // futex
        uint32_t opb = static_cast<uint32_t>(e->fd) & 0x7f;
        uint64_t uaddr = e->count;
        if (is_wait_cmd(opb)) {
          if (t.wait_uaddr == uaddr && t.last_wait_ts != 0) t.retries++;
          else t.retries = 1;
          t.last_wait_ts = e->timestamp_ns;
          t.wait_uaddr = uaddr;
        } else if (is_wake_cmd(opb)) {
          auto& w = wakes_[uaddr];
          w.wakes++;
          w.last_wake_ts = e->timestamp_ns;
          w.last_wake_tid = e->tid;
        }
      }
      return;
    }
    if (type == TRACE_EVT_NTSYNC && len >= sizeof(montauk_ntsync_event)) {
      touch(reinterpret_cast<const montauk_ntsync_event*>(data)->tid,
            reinterpret_cast<const montauk_ntsync_event*>(data)->timestamp_ns);
      return;
    }
    if (type == TRACE_EVT_HEAP && len >= sizeof(montauk_heap_event)) {
      touch(reinterpret_cast<const montauk_heap_event*>(data)->tid,
            reinterpret_cast<const montauk_heap_event*>(data)->timestamp_ns);
      return;
    }
    if (type == TRACE_EVT_MMAP && len >= sizeof(montauk_mmap_event)) {
      touch(reinterpret_cast<const montauk_mmap_event*>(data)->tid,
            reinterpret_cast<const montauk_mmap_event*>(data)->timestamp_ns);
      return;
    }
    if (type == TRACE_EVT_SIGNAL && len >= sizeof(montauk_signal_event)) {
      touch(reinterpret_cast<const montauk_signal_event*>(data)->tid,
            reinterpret_cast<const montauk_signal_event*>(data)->timestamp_ns);
      return;
    }
  }

  void emit(const montauk::model::TraceReader&) override {
    std::printf("REPORT futex\n");
    constexpr uint64_t kSlackNs = 1'000'000;  // wait is the thread's last activity

    struct Row { uint32_t tid; const TidF* t; double stuck_s; double s_per_retry; const char* cls; };
    std::vector<Row> rows;
    for (const auto& [tid, t] : tids_) {
      if (t.last_wait_ts == 0) continue;
      if (t.last_ts > t.last_wait_ts + kSlackNs) continue;  // woke after its wait
      double stuck_s = (max_ts_ - t.last_wait_ts) / 1e9;
      double spr = t.retries ? stuck_s / t.retries : stuck_s;
      uint64_t wk = wakes_.count(t.wait_uaddr) ? wakes_.at(t.wait_uaddr).wakes : 0;
      // Generic, name-free shape classes. Domain meaning (which uaddr is a
      // given lock, what a given retry cadence signifies) is a consumer's job:
      // join these opaque uaddrs against externally-supplied metadata.
      const char* cls;
      if (t.retries <= 1 && wk == 0)         cls = "idle-park";   // parked once, uncontended
      else if (t.retries >= 50 && spr < 0.1) cls = "spin";        // fast adaptive spin
      else                                   cls = "wait";        // contended / retrying
      rows.push_back({tid, &t, stuck_s, spr, cls});
    }
    if (rows.empty()) {
      std::printf("VERDICT: no threads blocked on a futex at trace end\n");
      return;
    }

    // Per-uaddr aggregate: opaque addresses only.
    struct Agg { int waiters = 0; double max_stuck = 0; uint64_t wakes = 0; };
    std::map<uint64_t, Agg> aggs;
    for (const auto& r : rows) {
      auto& a = aggs[r.t->wait_uaddr];
      a.waiters++;
      if (r.stuck_s > a.max_stuck) a.max_stuck = r.stuck_s;
    }
    for (auto& [u, a] : aggs) a.wakes = wakes_.count(u) ? wakes_.at(u).wakes : 0;

    size_t idle = 0, spin = 0;
    for (const auto& r : rows) {
      if (!std::strcmp(r.cls, "idle-park")) idle++;
      else if (!std::strcmp(r.cls, "spin")) spin++;
    }
    uint64_t worst_uaddr = 0; double worst_stuck = 0;
    for (const auto& [u, a] : aggs)
      if (a.max_stuck > worst_stuck) { worst_stuck = a.max_stuck; worst_uaddr = u; }

    std::printf("VERDICT: %zu threads blocked on futexes (%zu idle-park, %zu spin, %zu wait); "
                "worst uaddr=0x%" PRIx64 " stuck %.1fs\n",
                rows.size(), idle, spin, rows.size() - idle - spin, worst_uaddr, worst_stuck);
    std::printf("(op in fd, uaddr in count; addresses are opaque — join externally for lock identity)\n");

    std::printf("\ncontended addresses (>=2 waiters):\n");
    std::printf("uaddr              waiters  wakes      max_stuck_s\n");
    std::vector<std::pair<uint64_t, const Agg*>> au;
    for (const auto& [u, a] : aggs)
      if (a.waiters >= 2) au.emplace_back(u, &a);
    sublimation_order_f64(au, true, [](const std::pair<uint64_t, const Agg*>& p) { return p.second->max_stuck; });
    for (const auto& [u, a] : au)
      std::printf("0x%016" PRIx64 " %-8d %-10" PRIu64 " %-12.1f\n",
                  u, a->waiters, a->wakes, a->max_stuck);

    std::printf("\nblocked threads (idle-park excluded):\n");
    std::printf("uaddr              tid      comm             stuck_s   retries  s/retry  class\n");
    sublimation_order_f64(rows, true, [](const Row& r) { return r.stuck_s; });
    for (const auto& r : rows) {
      if (!std::strcmp(r.cls, "idle-park")) continue;
      std::printf("0x%016" PRIx64 " %-8u %-16.16s %-9.1f %-8u %-8.2f %s\n",
                  r.t->wait_uaddr, r.tid, r.t->comm, r.stuck_s, r.t->retries, r.s_per_retry, r.cls);
    }
  }

  void prom(std::vector<PromMetric>& out) override {
    size_t blocked = 0;
    for (const auto& [tid, t] : tids_) {
      (void)tid;
      if (t.last_wait_ts != 0 && t.last_ts <= t.last_wait_ts + 1'000'000) ++blocked;
    }
    out.push_back({"montauk_analysis_futex_blocked_threads", "", static_cast<double>(blocked)});
  }
};

// REPORT keyedevt: keyed-event contention by opaque key, from a configured
// wait/release uprobe pair (the key is whatever the hooked symbol passes — for
// NT keyed events, a lock address). A thread whose last activity is a keyed
// wait is wedged; if the key got no RELEASE after that wait, no one signalled
// it — the holder never left. Key and tids are opaque; lock naming is a
// consumer's job (join the key against externally-supplied metadata).
struct KeyedEvtReport final : Report {
  struct TidK {
    uint64_t last_ts = 0;       // last activity of any type
    uint64_t last_wait_ts = 0;  // last CS wait entry
    uint64_t wait_key = 0;      // CS address of that wait
    uint32_t pid = 0;
    char comm[16] = {};
  };
  struct KeyK {
    uint64_t waits = 0, releases = 0;
    uint64_t last_release_ts = 0;
  };
  std::map<uint32_t, TidK> tids_;
  std::map<uint64_t, KeyK> keys_;
  uint64_t max_ts_ = 0;

  const char* name() const override { return "keyedevt"; }

  void touch(uint32_t tid, uint64_t ts) {
    auto& t = tids_[tid];
    if (ts > t.last_ts) t.last_ts = ts;
    if (ts > max_ts_) max_ts_ = ts;
  }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type == TRACE_EVT_KEYEDEVT && len >= sizeof(montauk_keyedevt_event)) {
      auto* e = reinterpret_cast<const montauk_keyedevt_event*>(data);
      touch(e->tid, e->timestamp_ns);
      auto& t = tids_[e->tid];
      t.pid = e->pid;
      if (e->comm[0]) std::memcpy(t.comm, e->comm, sizeof(t.comm));
      auto& k = keys_[e->key];
      if (e->op == KEVT_RELEASE) { k.releases++; k.last_release_ts = e->timestamp_ns; }
      else { k.waits++; t.last_wait_ts = e->timestamp_ns; t.wait_key = e->key; }
      return;
    }
    if (type == TRACE_EVT_IO && len >= sizeof(montauk_io_event))
      touch(reinterpret_cast<const montauk_io_event*>(data)->tid,
            reinterpret_cast<const montauk_io_event*>(data)->timestamp_ns);
    else if (type == TRACE_EVT_NTSYNC && len >= sizeof(montauk_ntsync_event))
      touch(reinterpret_cast<const montauk_ntsync_event*>(data)->tid,
            reinterpret_cast<const montauk_ntsync_event*>(data)->timestamp_ns);
    else if (type == TRACE_EVT_HEAP && len >= sizeof(montauk_heap_event))
      touch(reinterpret_cast<const montauk_heap_event*>(data)->tid,
            reinterpret_cast<const montauk_heap_event*>(data)->timestamp_ns);
    else if (type == TRACE_EVT_MMAP && len >= sizeof(montauk_mmap_event))
      touch(reinterpret_cast<const montauk_mmap_event*>(data)->tid,
            reinterpret_cast<const montauk_mmap_event*>(data)->timestamp_ns);
    else if (type == TRACE_EVT_SIGNAL && len >= sizeof(montauk_signal_event))
      touch(reinterpret_cast<const montauk_signal_event*>(data)->tid,
            reinterpret_cast<const montauk_signal_event*>(data)->timestamp_ns);
  }

  void emit(const montauk::model::TraceReader&) override {
    std::printf("REPORT keyedevt\n");
    if (keys_.empty()) {
      std::printf("VERDICT: no keyed-event activity "
                  "(was a keyed-event uprobe configured when the trace was captured?)\n");
      return;
    }
    constexpr uint64_t kSlackNs = 1'000'000;
    std::map<uint64_t, std::vector<std::pair<uint32_t, const TidK*>>> blocked;
    for (const auto& [tid, t] : tids_) {
      if (t.last_wait_ts == 0) continue;
      if (t.last_ts <= t.last_wait_ts + kSlackNs) blocked[t.wait_key].emplace_back(tid, &t);
    }
    if (blocked.empty()) {
      std::printf("VERDICT: %zu CS keys seen; no thread wedged entering a CS at trace end\n",
                  keys_.size());
      return;
    }
    uint64_t worst_key = 0, worst_stuck = 0;
    for (const auto& [key, ws] : blocked)
      for (const auto& [tid, t] : ws) { (void)tid;
        uint64_t s = max_ts_ - t->last_wait_ts;
        if (s > worst_stuck) { worst_stuck = s; worst_key = key; }
      }
    std::printf("VERDICT: %zu CS key(s) have a thread wedged entering them; "
                "worst key=0x%" PRIx64 " stuck %.1fs\n",
                blocked.size(), worst_key, worst_stuck / 1e9);
    std::printf("(key = CRITICAL_SECTION address; no release after the wait => the holder never left it)\n");
    std::printf("key                waiters  total_waits  releases  rel_after_wait  note\n");
    for (const auto& [key, ws] : blocked) {
      const auto& k = keys_[key];
      uint64_t latest_wait = 0;
      for (const auto& [tid, t] : ws) { (void)tid; if (t->last_wait_ts > latest_wait) latest_wait = t->last_wait_ts; }
      bool rel_after = k.last_release_ts > latest_wait;
      std::printf("0x%016" PRIx64 " %-8zu %-12" PRIu64 " %-9" PRIu64 " %-15s %s\n",
                  key, ws.size(), k.waits, k.releases, rel_after ? "yes" : "none",
                  rel_after ? "released after wait — waiter should wake"
                            : "NO release after wait — holder wedged");
    }
    std::printf("\nwedged threads (last activity = CS wait):\n");
    std::printf("key                tid      comm             stuck_s\n");
    std::vector<std::pair<uint32_t, const TidK*>> rows;
    for (const auto& [key, ws] : blocked) for (const auto& [tid, t] : ws) rows.emplace_back(tid, t);
    sublimation_order_u64(rows, true, [mt = max_ts_](const std::pair<uint32_t, const TidK*>& p) {
      return mt - p.second->last_wait_ts;
    });
    for (const auto& [tid, t] : rows)
      std::printf("0x%016" PRIx64 " %-8u %-16.16s %.1f\n",
                  t->wait_key, tid, t->comm, (max_ts_ - t->last_wait_ts) / 1e9);
  }

  void prom(std::vector<PromMetric>& out) override {
    size_t wedged = 0;
    for (const auto& [tid, t] : tids_) { (void)tid;
      if (t.last_wait_ts && t.last_ts <= t.last_wait_ts + 1'000'000) ++wedged;
    }
    out.push_back({"montauk_analysis_keyedevt_wedged_threads", "", static_cast<double>(wedged)});
  }
};

// REPORT sched: wake-to-run latency over SCHED_OP_WAKE2RUN events (runtime_ns =
// became-runnable -> ran). Surfaces the BIMODAL split -- the cache-hot fast mode
// vs the CONFIG_HZ tick-quantized floor -- and how much of the slow tail is
// cross-CCX (sub_idx). The report that resolves an IPC p99 sitting on the kernel
// tick instead of inferring it from aggregates. Latencies are u64 ns, sorted
// with sublimation's direct type-generic entry (sublimation_u64), not the u32
// index-pack path.
// Name for sublimation's disorder classification of a latency-over-trace
// sequence (classified in ARRIVAL order, before the quantile sort). PHASED =
// a regime change mid-trace; FEW_UNIQUE = quantized onto a handful of values;
// NEARLY_SORTED = monotonic drift; RANDOM = no exploitable temporal structure.
static const char* disorder_name(sub_disorder_t d) {
  switch (d) {
    case SUB_SORTED:        return "SORTED";
    case SUB_REVERSED:      return "REVERSED";
    case SUB_NEARLY_SORTED: return "NEARLY_SORTED";
    case SUB_FEW_UNIQUE:    return "FEW_UNIQUE";
    case SUB_RANDOM:        return "RANDOM";
    case SUB_PHASED:        return "PHASED";
    case SUB_SPECTRAL:      return "SPECTRAL";
  }
  return "?";
}

struct SchedLatencyReport final : Report {
  std::vector<uint64_t> lat_;        // wake2run latencies (ns)
  std::vector<uint64_t> cross_lat_;  // cross-CCX subset (ns)
  sub_profile_t prof_{};             // flow-model profile of lat_ in arrival order

  const char* name() const override { return "sched"; }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type != TRACE_EVT_SCHED || len < sizeof(montauk_sched_event)) return;
    const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
    if (s->op != SCHED_OP_WAKE2RUN) return;
    lat_.push_back(s->runtime_ns);
    if (s->sub_idx) cross_lat_.push_back(s->runtime_ns);
  }

  static double us(uint64_t ns) { return static_cast<double>(ns) / 1000.0; }
  // v must already be sorted ascending.
  static double q_us(const std::vector<uint64_t>& v, double f) {
    if (v.empty()) return 0.0;
    size_t i = static_cast<size_t>(static_cast<double>(v.size()) * f);
    if (i >= v.size()) i = v.size() - 1;
    return us(v[i]);
  }

  void emit(const montauk::model::TraceReader&) override {
    std::printf("REPORT sched\n");
    if (lat_.empty()) {
      std::printf("VERDICT: no WAKE2RUN events in trace "
                  "(wake-to-run tracepoint not streamed?)\n\n");
      return;
    }
    // Classify the latency sequence in ARRIVAL order first -- the flow-model
    // reads temporal structure the quantiles can't: a mid-trace regime change
    // (PHASED), quantization onto a few tick values (FEW_UNIQUE), or monotonic
    // drift (NEARLY_SORTED). Must run before the in-place sort destroys the
    // timeline. classify is pure (reads, never writes), so lat_ is untouched.
    prof_ = sublimation_classify_u64(lat_.data(), lat_.size());

    // Flow-model sort, in place: direct u64 entry (not the u32 index-pack path).
    sublimation_u64(lat_.data(), lat_.size());
    if (!cross_lat_.empty()) sublimation_u64(cross_lat_.data(), cross_lat_.size());

    const size_t n = lat_.size();
    constexpr uint64_t kFastNs = 100000;  // 100us: cache-hot fast mode
    constexpr uint64_t kTickNs = 900000;  // ~one 1000Hz tick: CONFIG_HZ floor
    size_t fast = 0, tick = 0;
    for (uint64_t v : lat_) {
      if (v < kFastNs) ++fast;
      else if (v >= kTickNs) ++tick;
    }
    const double dn = static_cast<double>(n);
    const double fastpct = 100.0 * static_cast<double>(fast) / dn;
    const double tickpct = 100.0 * static_cast<double>(tick) / dn;
    const double midpct = 100.0 - fastpct - tickpct;
    const double crosspct = 100.0 * static_cast<double>(cross_lat_.size()) / dn;

    std::printf("VERDICT: %s wake2run; p50 %.0fus p99 %.0fus p999 %.0fus "
                "worst %.0fus; %.1f%% fast(<100us) / %.1f%% mid / "
                "%.1f%% tick-floor(>=900us); %.1f%% cross-CCX\n",
                fmt_count(dn).c_str(), q_us(lat_, 0.50), q_us(lat_, 0.99),
                q_us(lat_, 0.999), us(lat_.back()), fastpct, midpct, tickpct,
                crosspct);
    if (!cross_lat_.empty())
      std::printf("cross-CCX wake2run: %s events; p50 %.0fus p99 %.0fus "
                  "worst %.0fus (high here = scatter feeds the slow mode)\n",
                  fmt_count(static_cast<double>(cross_lat_.size())).c_str(),
                  q_us(cross_lat_, 0.50), q_us(cross_lat_, 0.99),
                  us(cross_lat_.back()));
    // Temporal structure from the flow-model classify (arrival order).
    std::printf("STRUCTURE: latency-over-trace %s", disorder_name(prof_.disorder));
    if (prof_.phase_boundary)
      std::printf(" (regime change at ~%.0f%% of trace)",
                  100.0 * static_cast<double>(prof_.phase_boundary) / dn);
    std::printf("; ~%zu distinct values", prof_.distinct_estimate);
    if (prof_.inversion_ratio > 0.0f)
      std::printf("; inversion ratio %.2f",
                  static_cast<double>(prof_.inversion_ratio));
    std::printf("\n\n");
  }

  void prom(std::vector<PromMetric>& out) override {
    if (lat_.empty()) return;  // already sorted in emit()
    auto push = [&](const char* ql, double v) {
      out.push_back({"montauk_analysis_wake2run_us",
                     std::string("quantile=\"") + ql + "\"", v});
    };
    push("0.5", q_us(lat_, 0.50));
    push("0.99", q_us(lat_, 0.99));
    push("0.999", q_us(lat_, 0.999));
    push("worst", us(lat_.back()));
    const double dn = static_cast<double>(lat_.size());
    size_t tick = 0;
    for (uint64_t v : lat_) if (v >= 900000) ++tick;
    out.push_back({"montauk_analysis_wake2run_tickfloor_pct", "",
                   100.0 * static_cast<double>(tick) / dn});
    out.push_back({"montauk_analysis_wake2run_crossccx_pct", "",
                   100.0 * static_cast<double>(cross_lat_.size()) / dn});
    // Flow-model distinct-value estimate: a low count on a large trace means
    // latency is quantized onto a few values (a fixed timer/quantum).
    out.push_back({"montauk_analysis_wake2run_distinct", "",
                   static_cast<double>(prof_.distinct_estimate)});
  }
};

std::vector<std::unique_ptr<Report>> make_reports() {
  std::vector<std::unique_ptr<Report>> reports;
  reports.push_back(std::make_unique<SummaryReport>());
  reports.push_back(std::make_unique<SchedLatencyReport>());
  reports.push_back(std::make_unique<WaitsReport>());
  reports.push_back(std::make_unique<SpinsReport>());
  reports.push_back(std::make_unique<PairingReport>());
  reports.push_back(std::make_unique<AbortPostmortemReport>());
  reports.push_back(std::make_unique<EndstateReport>());
  reports.push_back(std::make_unique<FutexReport>());
  reports.push_back(std::make_unique<KeyedEvtReport>());
  reports.push_back(std::make_unique<HeapstkReport>());
  reports.push_back(std::make_unique<DoubleFreeReport>());
  return reports;
}

} // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: montauk_analyze FILE [--report name[,name...]]\n");
    return 2;
  }
  const char* path = argv[1];

  auto reports = make_reports();

  std::vector<Report*> active;
  if (argc >= 3) {
    if (std::strcmp(argv[2], "--report") != 0 || argc < 4) {
      std::fprintf(stderr, "usage: montauk_analyze FILE [--report name[,name...]]\n");
      return 2;
    }
    std::string list = argv[3];
    size_t pos = 0;
    while (pos <= list.size()) {
      size_t comma = list.find(',', pos);
      if (comma == std::string::npos) comma = list.size();
      std::string want = list.substr(pos, comma - pos);
      pos = comma + 1;
      if (want.empty()) continue;
      Report* found = nullptr;
      for (auto& r : reports)
        if (want == r->name()) { found = r.get(); break; }
      if (!found) {
        std::fprintf(stderr, "montauk_analyze: unknown report '%s' (known:", want.c_str());
        for (auto& r : reports) std::fprintf(stderr, " %s", r->name());
        std::fprintf(stderr, ")\n");
        return 2;
      }
      if (std::find(active.begin(), active.end(), found) == active.end())
        active.push_back(found);
    }
  } else {
    for (auto& r : reports) active.push_back(r.get());
  }

  montauk::model::TraceReader reader;
  switch (reader.open(path)) {
    case montauk::model::TraceReadStatus::Ok:
      break;
    case montauk::model::TraceReadStatus::OpenFailed:
      std::fprintf(stderr, "montauk_analyze: cannot open '%s'\n", path);
      return 1;
    case montauk::model::TraceReadStatus::ShortHeader:
      std::fprintf(stderr, "montauk_analyze: short read on header\n");
      return 1;
    case montauk::model::TraceReadStatus::BadMagic:
      std::fprintf(stderr, "montauk_analyze: bad magic (not a montauk trace log)\n");
      return 1;
    default:
      std::fprintf(stderr, "montauk_analyze: format version %u, this build expects %u\n",
                   reader.header().version, montauk::model::kTraceFormatVersion);
      return 1;
  }

  const auto t0 = std::chrono::steady_clock::now();
  auto status = reader.for_each([&](uint32_t type, const uint8_t* data, uint32_t len) {
    for (Report* r : active) r->fold(type, data, len);
  });
  if (status == montauk::model::TraceReadStatus::CorruptLength) {
    std::fprintf(stderr, "montauk_analyze: corrupt record length %u at event %" PRIu64 "; reporting on data read so far\n",
                 reader.corrupt_len(), reader.events_read());
  } else if (status == montauk::model::TraceReadStatus::TruncatedRecord) {
    std::fprintf(stderr, "montauk_analyze: truncated record at event %" PRIu64 "; reporting on data read so far\n",
                 reader.events_read());
  }

  bool first = true;
  for (Report* r : active) {
    if (!first) std::printf("\n");
    first = false;
    r->emit(reader);
  }

  // Self-timing: how long this analysis took end to end (fold + sort + emit),
  // timestamped [HH:MM:SS] [INFO] in the house format.
  {
    const double secs = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t0).count();
    const uint64_t nev = reader.events_read();
    time_t tnow = ::time(nullptr);
    tm tlt{};
    localtime_r(&tnow, &tlt);
    std::printf("\n[%02d:%02d:%02d] [INFO]   analyzed %s events in %.2fs (%s/s)\n",
                tlt.tm_hour, tlt.tm_min, tlt.tm_sec,
                fmt_count(static_cast<double>(nev)).c_str(), secs,
                fmt_count(secs > 0.0 ? static_cast<double>(nev) / secs : 0.0).c_str());
  }

  std::vector<PromMetric> prom;
  for (Report* r : active) r->prom(prom);

  // PANDEMONIUM house-style metadata header: provenance + trace time stamped
  // FIRST on every analysis .prom, matching the bench-* .prom files.
  {
    const auto& mh = reader.header();
    char mpat[33];
    std::snprintf(mpat, sizeof(mpat), "%.*s",
                  static_cast<int>(sizeof(mh.pattern)), mh.pattern);
    std::string info = "montauk_version=\"" MONTAUK_VERSION "\",trace_pattern=\"";
    info += mpat;
    info += "\",format_version=\"" + std::to_string(mh.version) + "\"";
    std::vector<PromMetric> meta = {
      {"montauk_analysis_info", info, 1.0},
      {"montauk_analysis_timestamp_seconds", "",
       static_cast<double>(mh.real_anchor_ns / 1000000000ull)},
    };
    prom.insert(prom.begin(), meta.begin(), meta.end());
  }

  if (!prom.empty()) {
    std::string out_path = analysis_prom_path(path, reader.header().real_anchor_ns);
    if (!write_analysis_prom(out_path, prom)) {
      std::fprintf(stderr, "montauk_analyze: cannot write %s\n", out_path.c_str());
      return 1;
    }
    time_t now = ::time(nullptr);
    tm lt{};
    localtime_r(&now, &lt);
    std::printf("\n[%02d:%02d:%02d] [INFO]   analysis written to %s\n",
                lt.tm_hour, lt.tm_min, lt.tm_sec, out_path.c_str());
  }
  return 0;
}
