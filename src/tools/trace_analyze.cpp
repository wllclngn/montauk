// montauk --analyze — offline analysis reports over a binary --trace-out log.
//
// Trace-only by design: the old live /proc sampler is gone. Every registered
// report folds events in a SINGLE pass over the file (traces reach 450 MB+),
// then emits in registry order. Adding a report = one struct deriving from
// Report + one entry in make_reports().
//
// Usage:
//   montauk --analyze FILE [--report name[,name...]]   # default: all reports

#include "model/TraceReader.hpp"
#include "model/TraceEnumNames.hpp"
#include "montauk_trace.h"
#include "prom_population.hpp"
#include "prom_stats.hpp"
#include "trace_query.hpp"
#include "util/Log.hpp"

#include <algorithm>
#include <cctype>
#include <cinttypes>
#include <cstdlib>
#include <deque>
#include <dirent.h>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

// After the std headers: c23_compat.h's C23 unreachable() macro must not
// precede the libstdc++ headers. Guarded; re-included with the rest below.
#include "sublimation_order.hpp"  // struct-by-key ordering

using montauk::util::log_info;
using montauk::util::log_warn;
using montauk::util::log_error;

// Address resolution against captured /proc/PID/maps sidecars
//
// montauk writes a <PID>.maps sidecar beside the trace at track time. A wait on
// a futex names the lock by its userspace address (the uaddr); resolving that
// address against the owning process's maps turns an opaque 0x7ff6e1249ac0 into
// "ntdll.so+0x...", naming WHERE the contended lock lives. The same machinery
// would symbolize heapstk/abort IPs; for now it serves the sync reports.
struct MapsResolver {
  struct Seg { uint64_t start, end, file_off; bool exec; std::string path; };
  std::unordered_map<uint32_t, std::vector<Seg>> by_pid_;
  bool empty_ = true;

  void load_dir(const char* trace_path) {
    std::string tp = trace_path ? trace_path : "";
    std::string dir = ".";
    auto slash = tp.find_last_of('/');
    if (slash != std::string::npos) dir = tp.substr(0, slash);
    DIR* d = ::opendir(dir.c_str());
    if (!d) return;
    for (struct dirent* ent; (ent = ::readdir(d)) != nullptr; ) {
      std::string name = ent->d_name;
      if (name.size() < 6 || name.compare(name.size() - 5, 5, ".maps") != 0)
        continue;
      std::string pid_s = name.substr(0, name.size() - 5);
      if (pid_s.empty() ||
          !std::all_of(pid_s.begin(), pid_s.end(),
                       [](unsigned char c) { return std::isdigit(c); }))
        continue;
      load_file(dir + "/" + name,
                static_cast<uint32_t>(std::strtoul(pid_s.c_str(), nullptr, 10)));
    }
    ::closedir(d);
    for (auto& [pid, segs] : by_pid_) {
      (void)pid;
      sublimation_order_u64(segs, false, [](const Seg& s) { return s.start; });
      if (!segs.empty()) empty_ = false;
    }
  }

  void load_file(const std::string& path, uint32_t pid) {
    std::ifstream f(path);
    if (!f) return;
    auto& segs = by_pid_[pid];
    std::string line;
    while (std::getline(f, line)) {
      // "start-end perms file_off dev inode path"
      char* e = nullptr;
      uint64_t start = std::strtoull(line.c_str(), &e, 16);
      if (*e != '-') continue;
      uint64_t end = std::strtoull(e + 1, &e, 16);
      while (*e == ' ') ++e;
      const char* perms = e;
      while (*e && *e != ' ') ++e;                 // perms
      bool exec = (e - perms) >= 3 && perms[2] == 'x';
      while (*e == ' ') ++e;
      uint64_t off = std::strtoull(e, &e, 16);
      while (*e == ' ') ++e;
      while (*e && *e != ' ') ++e;                 // dev
      while (*e == ' ') ++e;
      while (*e && *e != ' ') ++e;                 // inode
      while (*e == ' ') ++e;
      segs.push_back({start, end, off, exec, *e ? std::string(e) : std::string()});
    }
  }

  // Binary search: the last segment with start <= addr (nullptr if none).
  const Seg* find_seg(uint32_t pid, uint64_t addr) const {
    auto it = by_pid_.find(pid);
    if (it == by_pid_.end()) return nullptr;
    const auto& segs = it->second;
    size_t lo = 0, hi = segs.size();
    while (lo < hi) {                              // last seg with start <= addr
      size_t mid = (lo + hi) / 2;
      if (segs[mid].start <= addr) lo = mid + 1; else hi = mid;
    }
    return lo == 0 ? nullptr : &segs[lo - 1];
  }

  // "module.so+0xoffset" for an addr known to fall within s.
  std::string fmt_module_offset(const Seg& s, uint64_t addr) const {
    auto sl = s.path.find_last_of('/');
    std::string base = sl == std::string::npos ? s.path : s.path.substr(sl + 1);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "+0x%" PRIx64, addr - s.start + s.file_off);
    return base + buf;
  }

  // addr -> "module.so+0xoffset" / "[anon]" / "" (no maps for pid, or unmapped).
  std::string resolve(uint32_t pid, uint64_t addr) const {
    const Seg* s = find_seg(pid, addr);
    if (!s || addr >= s->end) return "";
    if (s->path.empty()) return "[anon]";
    return fmt_module_offset(*s, addr);
  }

  // Like resolve() but only matches EXECUTABLE (r-x) segments -- a stack word that
  // lands in code is a plausible return address; one landing in data is not.
  std::string resolve_exec(uint32_t pid, uint64_t addr) const {
    const Seg* s = find_seg(pid, addr);
    if (!s || addr >= s->end || !s->exec || s->path.empty()) return "";
    return fmt_module_offset(*s, addr);
  }

  bool empty() const { return empty_; }
};

static MapsResolver g_maps;

// Human identity for a sync-wait object: a futex uaddr resolved to module+offset
// via the captured maps, else an ntsync object fd. "" when unresolvable.
static std::string sync_obj_name(uint32_t pid, uint64_t obj, bool is_futex) {
  if (!is_futex) {
    char b[32];
    std::snprintf(b, sizeof(b), "ntsync fd %" PRIu64, obj);
    return b;
  }
  return g_maps.resolve(pid, obj);
}

// "0x<obj> (<name>)" for reports that print an object id, name appended when
// resolvable. The name is what turns "suspected" into "this lock, here".
static std::string fmt_obj(uint32_t pid, uint64_t obj, bool is_futex) {
  char b[24];
  std::snprintf(b, sizeof(b), "0x%016" PRIx64, obj);
  std::string s = b;
  std::string n = sync_obj_name(pid, obj, is_futex);
  if (!n.empty()) { s += " ("; s += n; s += ")"; }
  return s;
}

// Comm redaction. For a shareable / public report (Discord), the literal
// process comm is replaced with a STABLE hash handle -- same comm -> same
// "comm#xxxxxxxx" -- so an offender stays identifiable and correlatable across
// a user's reports without leaking the process name. tids, CPU ids, and object
// pointers are not PII and are never redacted. Off by default (dev wants real
// comms); --redact (and the bench-enduser report flow) turns it on.
static bool g_redact_comm = false;

// Row qualifiers. Generic --sig/--comm/--pid/--tid/--window inputs that any
// per-event report can consume to narrow WHAT it decomposes, so a question
// like "show me thread X's SIGSEGVs" is a command line, not a code change.
// Unset qualifiers match everything. g_qual_window_s bounds the trailing
// capture-teardown window some reports separate from the body of the trace.
static int32_t g_qual_sig = -1;
static std::string g_qual_comm;
static int64_t g_qual_pid = -1;
static int64_t g_qual_tid = -1;
static double g_qual_window_s = 2.0;

// THE WAKE-CLASSIFICATION FLOOR, in ns. placement-race and dispatch-stall
// attribute a wake only when it waited at least this long. The default is one
// CONFIG_HZ tick, which is the pathology those reports were built to name: a
// wake that missed a whole tick. That default silently made them TAIL-ONLY
// instruments -- on a 212k-wake capture it classified 757 of them, 0.36%, and
// a reader asking where the MEDIAN wake goes got a verdict computed from the
// worst third of a percent. The events were always folded and counted; only
// the attribution was gated. Lowering the floor re-reads captures already on
// disk, so this answers a median question with no new probes and no re-run.
static uint64_t g_qual_floor_ns = 900000ULL;

// Capture-loss accounting: the last TRACE_EVT_DROPS snapshot seen in the
// fold. Snapshots carry free-running cumulative totals, so the last one IS
// the whole recording's loss. Every surface (text block, gauges, JSON
// envelope) renders from this one value; a capture with no snapshot records
// predates drop accounting and reports nothing (absence of the counter is
// not evidence of zero loss, and the text says so).
static montauk_drop_event g_drop_final{};
static bool g_drop_seen = false;

static void fold_drop_snapshot(uint32_t type, const uint8_t* data, uint32_t len) {
  if (type == TRACE_EVT_DROPS && len >= sizeof(montauk_drop_event)) {
    std::memcpy(&g_drop_final, data, sizeof(g_drop_final));
    g_drop_seen = true;
  }
}

static uint64_t drops_total() {
  uint64_t t = 0;
  for (uint32_t i = 0; i < MONTAUK_DROP_SLOTS; ++i) t += g_drop_final.dropped[i];
  return t;
}

static bool qual_match(int32_t sig, uint32_t pid, uint32_t tid, const char* comm) {
  if (g_qual_sig >= 0 && sig != g_qual_sig) return false;
  if (g_qual_pid >= 0 && pid != static_cast<uint32_t>(g_qual_pid)) return false;
  if (g_qual_tid >= 0 && tid != static_cast<uint32_t>(g_qual_tid)) return false;
  if (!g_qual_comm.empty()) {
    size_t n = 0;
    while (n < 16 && comm[n]) ++n;
    if (std::string(comm, n).find(g_qual_comm) == std::string::npos) return false;
  }
  return true;
}

static std::string redact_comm(const char* comm) {
  size_t n = 0;
  while (n < 16 && comm[n]) ++n;
  if (!g_redact_comm) return std::string(comm, n);
  uint64_t h = 1469598103934665603ULL;  // FNV-1a 64
  for (size_t i = 0; i < n; ++i) {
    h ^= static_cast<unsigned char>(comm[i]);
    h *= 1099511628211ULL;
  }
  char buf[16];
  std::snprintf(buf, sizeof(buf), "comm#%08x", static_cast<uint32_t>(h));
  return std::string(buf);
}

#include "sublimation.h"        // in-tree sub-system: flow-model sort, classify
#include "sublimation_order.hpp" // sublimation_order_u64/_f64: struct-by-key ordering (pulls in sublimation_pack.h)
#include "sublimation_locate.h" // structural locator: where a disorder pattern sits
#include "sublimation_signal.h" // matrix profile (STOMP on the FFT): discords + motifs
#include "util/sink.h"          // buffered stdout sink: one drain, not a printf per line
#include "util/json.h"          // write-only JSON serializer on the sink (the --json renderer)

#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <sys/stat.h>

#ifndef MONTAUK_VERSION
#define MONTAUK_VERSION "unknown"
#endif

namespace {

// All report stdout flows through one buffered sink, drained once at exit
// (atexit, set in main) -- one write instead of a syscall per std::printf. The
// .prom file writers and stderr logs are unaffected.
montauk_sink g_out;
void drain_out() { montauk_sink_drain(&g_out); }

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

using montauk::model::sched_op_name;
using montauk::model::ntsync_op_name;
using montauk::model::io_syscall_name;
using montauk::model::signal_name;
using montauk::model::evt_type_name;

std::string signal_label(int32_t n) {
  if (const char* s = signal_name(n)) return s;
  char b[16];
  std::snprintf(b, sizeof(b), "sig%d", n);
  return b;
}

// "--sig 11", "--sig SIGSEGV" and "--sig SEGV" all name the same signal.
// Returns -1 when the string names nothing.
int32_t signal_nr_from(const std::string& s) {
  if (!s.empty() && std::isdigit(static_cast<unsigned char>(s[0])))
    return static_cast<int32_t>(std::strtol(s.c_str(), nullptr, 10));
  std::string want = s;
  for (auto& c : want) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  if (want.compare(0, 3, "SIG") != 0) want = "SIG" + want;
  for (int32_t n = 1; n < 64; ++n) {
    const char* nm = signal_name(n);
    if (nm && want == nm) return n;
  }
  return -1;
}

// ROW QUALIFIERS, PARSED IN ONE PLACE FOR EVERY MODE.
// The qualifiers are the sanctioned generic narrowing surface: any per-event
// report consumes them, so "show me thread X's SIGSEGVs" is a command line
// rather than a code change. They were parsed only inside single-trace mode's
// flag loop, which meant the recording-dir modes (--digest, --l2-by-cpu)
// returned before the loop ran and READ PAST every qualifier given to them --
// not rejected, not warned about, silently unapplied. A caller had no way to
// learn the narrowing never happened. This is that parsing, callable from both.
//
// Returns 0 when argv[i] was a qualifier and was applied, 2 on a malformed
// value, and kQualNotMine when argv[i] is some other flag entirely (the caller
// keeps matching). *consumed is set to the number of EXTRA argv slots eaten (1
// for a qualifier's value), which the caller adds to its own index.
//
// Flags are matched with strcmp on the argv pointer rather than by constructing
// a std::string per argument: no allocation on a startup path that does not
// need one.
//
// The attribute is a TOOLCHAIN WORKAROUND, scoped as narrowly as it can be.
// gcc 16.x segfaults compiling this function at -O3 -- `during GIMPLE pass:
// ifcvt`, in tree_if_conversion -- and it is a genuine compiler bug, not a code
// defect: bisected to -O3 alone (clean at -O0 and -O2), reproduced against both
// the std::string and the strcmp form of the matcher, and it survived a stack
// limit raise. Disabling that ONE pass for this ONE function is the smallest
// intervention that keeps the project's -O3 -Werror build whole; nothing else in
// the file changes optimization level. Remove the attribute when the toolchain
// is fixed and confirm the build still passes.
constexpr int kQualNotMine = -1;

// gcc-only: clang has neither the bug nor the attribute, and warns (fatal under
// this build's -Werror) on an attribute it does not know.
#if defined(__GNUC__) && !defined(__clang__)
#define MONTAUK_NO_IFCVT __attribute__((optimize("no-tree-loop-if-convert")))
#else
#define MONTAUK_NO_IFCVT
#endif

MONTAUK_NO_IFCVT
int take_row_qualifier(int argc, char** argv, int i, int* consumed) {
  *consumed = 0;
  const char* a = argv[i];
  const char* val = (i + 1 < argc) ? argv[i + 1] : nullptr;
  auto is = [a](const char* flag) { return std::strcmp(a, flag) == 0; };
  if (is("--sig") && val) {
    *consumed = 1;
    g_qual_sig = signal_nr_from(val);
    if (g_qual_sig < 0) {
      log_error("--sig '%s' names no signal (number, SIGSEGV or SEGV)", val);
      return 2;
    }
  } else if (is("--comm") && val) {
    *consumed = 1;
    g_qual_comm = val;
  } else if (is("--pid") && val) {
    *consumed = 1;
    g_qual_pid = std::strtol(val, nullptr, 10);
  } else if (is("--tid") && val) {
    *consumed = 1;
    g_qual_tid = std::strtol(val, nullptr, 10);
  } else if (is("--floor-us") && val) {
    *consumed = 1;
    char* end = nullptr;
    double us = std::strtod(val, &end);
    if (end == val || us < 0) {
      log_error("--floor-us takes microseconds >= 0, got '%s'", val);
      return 2;
    }
    g_qual_floor_ns = (uint64_t)(us * 1000.0);
  } else if (is("--window") && val) {
    *consumed = 1;
    g_qual_window_s = std::strtod(val, nullptr);
    if (g_qual_window_s < 0) {
      log_error("--window takes seconds >= 0, got '%s'", val);
      return 2;
    }
  } else {
    return kQualNotMine;
  }
  return 0;
}

bool is_wait_op(uint8_t op) { return op == NTS_WAIT_ANY || op == NTS_WAIT_ALL; }
bool is_signal_op(uint8_t op) {
  return op == NTS_EVENT_SET || op == NTS_EVENT_RESET || op == NTS_SEM_RELEASE ||
         op == NTS_MUTEX_UNLOCK;
}
// Wakeup-worthy: ops that can WAKE a waiter. event_reset CLEARS the signal and
// wakes nothing, so a reset-heavy event is not a busy producer. Excluding reset
// is what separates a genuine lost wakeup (a real wake landed after the park)
// from a producer that simply went quiet (its last actual wake was before it).
bool is_wakeup_op(uint8_t op) {
  return op == NTS_EVENT_SET || op == NTS_EVENT_PULSE || op == NTS_SEM_RELEASE ||
         op == NTS_MUTEX_UNLOCK;
}

// Generic synchronization model
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

struct SyncWait   { uint32_t tid; uint32_t pid; uint64_t obj; uint64_t ts; int64_t result; bool is_futex; };
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
    w = {e->tid, e->pid, static_cast<uint32_t>(e->fd), e->timestamp_ns, e->result, false};
    return true;
  }
  if (type == TRACE_EVT_IO && len >= sizeof(montauk_io_event)) {
    auto* e = reinterpret_cast<const montauk_io_event*>(data);
    if (e->syscall_nr != kFutexSyscallNr) return false;
    if (!futex_is_wait(static_cast<uint32_t>(e->fd) & 0x7f)) return false;
    w = {e->tid, e->pid, e->count, e->timestamp_ns, e->result, true};
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

// Struct/row ordering by one key runs through sublimation_order_u64 / _f64
// (sublimation_order.hpp): index-sort via the flow-model pack, gather into key
// order, stable on ties -- deterministic where std::sort's tie order was not.

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

// CAPTURE LOSS, ONE EMITTER FOR EVERY SURFACE.
// Overload drop is load-correlated -- the tracer sheds exactly when the
// interesting events are produced -- so observed counts are LOWER BOUNDS, tail
// quantiles are biased downward, and an absence-of-anomaly verdict over a lossy
// window is not the same claim as one over a lossless capture. That
// qualification is not optional decoration on a verdict; it is part of the
// verdict, so every path that states a conclusion states this beside it.
//
// It lived inline in the --report path, which left the DIGEST -- the compact
// redacted file that actually gets shared with someone else -- asserting clean
// quantiles over captures as low as 5.7% complete. Shared here so the two
// cannot drift again, and so the digest's envelope can publish the same numbers
// its text prints.

static double capture_completeness(uint64_t observed) {
  const uint64_t dropped = g_drop_seen ? drops_total() : 0;
  const uint64_t offered = observed + dropped;
  return offered > 0 ? static_cast<double>(observed) /
                           static_cast<double>(offered)
                     : 1.0;
}

// Text block + the prom family. No-op when the capture predates drop accounting:
// absence of the counter is not evidence of zero loss, so nothing is claimed.
static void emit_capture_loss(uint64_t observed,
                              std::vector<PromMetric>& prom) {
  if (!g_drop_seen) return;
  const uint64_t dropped = drops_total();
  const double completeness = capture_completeness(observed);
  prom.push_back({"montauk_analysis_events_dropped_total", "",
                  static_cast<double>(dropped)});
  prom.push_back({"montauk_analysis_capture_completeness", "", completeness});
  for (uint32_t t = 0; t < MONTAUK_DROP_SLOTS; ++t)
    if (g_drop_final.dropped[t] > 0)
      prom.push_back({"montauk_analysis_events_dropped_total",
                      std::string("type=\"") + evt_type_name(t) + "\"",
                      static_cast<double>(g_drop_final.dropped[t])});
  if (dropped > 0) {
    montauk_sink_appendf(&g_out,
        "\nCAPTURE LOSS: %" PRIu64 " event(s) dropped at the ring "
        "(completeness %.4f%%)\n",
        dropped, completeness * 100.0);
    for (uint32_t t = 0; t < MONTAUK_DROP_SLOTS; ++t)
      if (g_drop_final.dropped[t] > 0)
        montauk_sink_appendf(
            &g_out, "  %s: %" PRIu64 "\n", evt_type_name(t),
            static_cast<uint64_t>(g_drop_final.dropped[t]));
    montauk_sink_appendf(&g_out,
        "  counts above are lower bounds; tail quantiles are biased "
        "downward\n"
        "  (loss lands in the busy windows); absence-of-anomaly verdicts "
        "for the\n"
        "  types listed are qualified, not clean\n");
  }
  if (g_drop_final.writer_errors > 0)
    montauk_sink_appendf(&g_out,
        "CAPTURE LOSS: %" PRIu64 " trace write error(s), %" PRIu64
        " byte(s) short at the disk path\n",
        static_cast<uint64_t>(g_drop_final.writer_errors),
        static_cast<uint64_t>(g_drop_final.writer_lost_bytes));
}

const char* prom_help(const char* name) {
  static constexpr struct { const char* name; const char* help; } kHelp[] = {
    {"montauk_analysis_events_total",
     "Event count per type+subtype over the whole trace"},
    {"montauk_analysis_iolat_pwrite64_count",
     "Tracked pwrite64 completions -- true O_DIRECT block-I/O completion latency, enter to exit"},
    {"montauk_analysis_iolat_pwrite64_p50_ms",
     "pwrite64 completion latency, p50, in ms"},
    {"montauk_analysis_iolat_pwrite64_p99_ms",
     "pwrite64 completion latency, p99, in ms"},
    {"montauk_analysis_iolat_pwrite64_worst_ms",
     "pwrite64 completion latency, worst observed, in ms"},
    {"montauk_analysis_dispatches_per_sec",
     "Scheduler dispatch rate per second over the trace, from PICK where the\n      scheduler binds it and from SWITCH_IN otherwise"},
    {"montauk_analysis_preempts_per_sec",
     "Preemption (tick + wakeup) rate per second over the trace"},
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
    {"montauk_analysis_wake2run_fast_pct",
     "Percent of wake2run latencies in the cache-hot fast mode (<100us)"},
    {"montauk_analysis_wake2run_mid_pct",
     "Percent of wake2run latencies between fast mode and the tick floor"},
    {"montauk_analysis_wake2run_tickfloor_pct",
     "Percent of wake2run latencies on the CONFIG_HZ tick floor (>=900us)"},
    {"montauk_analysis_dispatch_dark_pct",
     "Of PREEMPT-STARVED floored wakes, percent whose run-CPU was IDLE through the wait (tickless strand)"},
    {"montauk_analysis_dispatch_held_pct",
     "Of PREEMPT-STARVED floored wakes, percent whose run-CPU was busy through the wait (held by a task)"},
    {"montauk_analysis_dispatch_worst_dark_ms",
     "Longest dark-CPU (idle, un-ticked) dispatch strand in ms"},
    {"montauk_analysis_wake2run_crossdomain_pct",
     "Percent of wake2run events that ran on a cross-domain CPU"},
    {"montauk_analysis_coldwake_count",
     "Count of wakes landing on a core idle >=20ms (cold-wake samples)"},
    {"montauk_analysis_coldwake_wake2run_us",
     "Cold-wake wake-to-run latency quantile in us (wakes from a cold core)"},
    {"montauk_analysis_coldwake_freq_min_mhz",
     "Minimum core frequency (MHz) seen at any cold-wake (platform floor proxy)"},
    {"montauk_analysis_coldwake_freq_slowq_mhz",
     "Median core frequency (MHz) of the slowest-quartile cold-wakes; near the "
     "min implies ramp-bound (governor/arch), nominal implies dispatch-bound"},
    {"montauk_analysis_info",
     "Build and trace metadata (montauk version, trace pattern, format version)"},
    {"montauk_analysis_timestamp_seconds",
     "Trace start time (unix seconds, from the trace's real-time anchor)"},
    {"montauk_fractal_hurst_dfa",
     "DFA Hurst exponent of the raw-event rate series (0.5=uncorrelated, >0.5=persistent)"},
    {"montauk_fractal_hurst_dfa_se",
     "Standard error of the DFA Hurst slope"},
    {"montauk_fractal_hurst_rs",
     "Rescaled-range (R/S) Hurst cross-check of the rate series"},
    {"montauk_fractal_dimension",
     "Fractal dimension D=2-H of the rate series"},
    {"montauk_fractal_decades",
     "Decades of scale spanned by the DFA fit (raw-event timeline)"},
    {"montauk_fractal_avalanches",
     "Migration-avalanche count above the active-interval median"},
    {"montauk_fractal_avalanche_slope",
     "CCDF log-log slope of the migration-avalanche sizes (SOC tail)"},
    {"montauk_offender",
     "A specific misbehaving entity (kind/id/metric/sev); value is the metric"},
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

// Shared quantile + unit helpers. These were duplicated as static members
// across the SchedLatency / Slice / Wakers / KStrand / Service report
// structs; hoisted here so every report indexes a pre-sorted vector the
// same way (R1 consolidation).
namespace {
double us(uint64_t ns) { return static_cast<double>(ns) / 1000.0; }
double ms(uint64_t ns) { return static_cast<double>(ns) / 1e6; }
// Raw quantile over a pre-sorted vector -- the one indexing convention every
// report uses; q_us/q_ms wrap it for the two common units, unitless counts
// (e.g. dispatch-stall pass-overs) read it directly.
//
// ONE OF THREE PERCENTILE CONVENTIONS IN THIS BINARY, and the divergence is
// deliberate rather than an oversight, so it is stated here instead of being
// left for the next reader to rediscover:
//   1. this q_at            -- floor(q*n), clamped. NEAREST-RANK: returns a
//                              value that is actually IN the data.
//   2. sublimation_quantile_f64 with nearest==0 -- floor(q*n). AGREES with this
//      exactly; tests/test_percentile_agreement.cpp asserts it, because today
//      they agree only by shared authorship and a silent drift would move every
//      p99 in every report.
//   3. montauk::stats::percentile (prom_stats.cpp) -- numpy method="linear",
//      INTERPOLATING. Does NOT agree, and must not: the cross-run population
//      path is validated for scipy parity and needs the interpolating
//      estimator. See the note at its definition.
// Reports use the nearest-rank form because a report's p99 should be an
// observed latency, not an average of two that never happened.
//
// DO NOT route this through sublimation_quantile_f64: its vectors are uint64_t
// already sorted by sublimation_u64, so the swap would add a u64->double
// conversion AND a redundant in-place re-sort for an identical answer.
uint64_t q_at(const std::vector<uint64_t>& v, double f) {
  if (v.empty()) return 0;
  size_t i = static_cast<size_t>(static_cast<double>(v.size()) * f);
  if (i >= v.size()) i = v.size() - 1;
  return v[i];
}
double q_us(const std::vector<uint64_t>& v, double f) { return us(q_at(v, f)); }
double q_ms(const std::vector<uint64_t>& v, double f) { return ms(q_at(v, f)); }
// One gauge per quantile label, the shape three reports each hand-rolled as a
// local push lambda.
void push_quantile_gauges(std::vector<PromMetric>& out, const char* metric,
                          std::initializer_list<std::pair<const char*, double>> qs) {
  for (const auto& [ql, v] : qs)
    out.push_back({metric, std::string("quantile=\"") + ql + "\"", v});
}
}  // namespace

// A specific misbehaving entity any report can surface. Domain-agnostic by
// design: kind/metric are free strings (no scheduler/sync enums baked in), so
// the same model and the montauk_offender{} family are reusable across every
// project montauk traces. The contributing report sets severity -- it knows
// what is bad; the consolidator only ranks. id/obj name the entity (id is the
// redacted handle when it is a comm).
struct Offender {
  std::string kind;    // "spin" | "unsignaled" | "idle-strand" | "hot-cpu" | ...
  std::string id;      // primary entity (tid, cpu, obj, comm-handle)
  std::string obj;     // secondary entity, optional (e.g. the waited object)
  std::string metric;  // what value measures, e.g. "waits_per_s"
  double value{0.0};
  int sev{0};          // 0 low, 1 med, 2 high -- set by the contributing report
};

// A value in a report's detail block -- what a structured face carries beyond
// the gauges: a number, a count, a flag, a string, or a nested object or array.
struct Detail {
  enum Kind { Num, U64, Bool, Str, Obj, Arr } k = Num;
  double num = 0;
  uint64_t u = 0;
  std::string str;
  std::string key;                           // this value's name inside an object
  std::vector<Detail> obj;                   // members, each carrying its key
  std::vector<Detail> arr;
  static Detail of(double v) { Detail d; d.k = Num; d.num = v; return d; }
  static Detail count(uint64_t v) { Detail d; d.k = U64; d.u = v; return d; }
  static Detail flag(bool v) { Detail d; d.k = Bool; d.u = v; return d; }
  static Detail text(std::string v) { Detail d; d.k = Str; d.str = std::move(v); return d; }
  static Detail object() { Detail d; d.k = Obj; return d; }
  static Detail array() { Detail d; d.k = Arr; return d; }
  Detail& put(std::string name, Detail v) { v.key = std::move(name); obj.push_back(std::move(v)); return *this; }
};

// THE RESULT every face renders. Text, JSON and prom read this and nothing
// else, and only a report's derive step writes it, so the faces cannot
// disagree and no conclusion can be composed at print time.
struct ReportResult {
  // The conclusion as a SENTENCE, for a human. It carries numbers and drifts.
  std::string verdict;
  // The same conclusion as a TOKEN, for a machine: short, SCREAMING-KEBAB, from
  // a small fixed set per report, comparable exactly where the sentence is not.
  // A report that found nothing emits "NONE", so "no finding" is a comparable
  // state and never an absence indistinguishable from a report that never ran.
  std::string klass;
  std::vector<PromMetric> gauges;
  std::vector<Offender> offenders;
  std::vector<std::pair<std::string, Detail>> detail;   // ordered, between class and gauges
};

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
  }
  return "?";
}

// Per-CPU idle intervals from SCHED_OP_CPU_IDLE (enter ts -> exit ts). On a
// tickless-idle kernel an idle CPU gets no scheduler tick, hence no ops.tick,
// hence no tick-driven rescue scan: a task stranded there ages un-dispatched.
// This is the signal that separates a HELD CPU (busy hog, real preempt gap)
// from a DARK CPU (idle, no tick -- the strand bug). Shared by kstrand and
// dispatch-stall, the two reports that need "how much of [a,b) was this CPU
// idle" -- an overlap-over-a-range query, distinct from sched's point-in-time
// "still open" check and placement-race's point-in-time "idle at instant t"
// boundary search, so those two keep their own tailored shapes.
struct CpuIdleIntervals {
  std::unordered_map<uint32_t, std::vector<std::pair<uint64_t, uint64_t>>> iv_;
  std::unordered_map<uint32_t, uint64_t> open_;  // cpu -> enter ts (open)

  // Call for every SCHED_OP_CPU_IDLE event (sub_idx==1 enter, else exit).
  void fold(uint32_t cpu, uint32_t sub_idx, uint64_t ts) {
    if (sub_idx == 1) {
      open_[cpu] = ts;
    } else {
      auto it = open_.find(cpu);
      if (it != open_.end() && ts > it->second) {
        iv_[cpu].push_back({it->second, ts});
        open_.erase(it);
      }
    }
  }

  bool empty() const { return iv_.empty(); }

  void finalize() {
    for (auto& kv : iv_)
      sublimation_order_u64(kv.second, false,
                            [](const std::pair<uint64_t, uint64_t>& e) { return e.first; });
  }

  // ns of [a,b) the given CPU spent idle (overlap with its idle intervals).
  // Intervals are disjoint and sorted by start (finalize), so their ends ascend
  // too: binary-search the first interval reaching past `a`, then walk until one
  // starts at/after `b`. Every skipped interval contributes zero, so this is
  // exactly the old full scan without its O(n) cost per query (was O(n^2) over a
  // sched-heavy trace).
  uint64_t overlap(uint32_t cpu, uint64_t a, uint64_t b) const {
    auto it = iv_.find(cpu);
    if (it == iv_.end() || b <= a) return 0;
    const auto& ivs = it->second;
    auto first = std::lower_bound(ivs.begin(), ivs.end(), a,
        [](const std::pair<uint64_t, uint64_t>& iv, uint64_t v) { return iv.second <= v; });
    uint64_t acc = 0;
    for (auto i = first; i != ivs.end() && i->first < b; ++i) {
      uint64_t lo = i->first > a ? i->first : a;
      uint64_t hi = i->second < b ? i->second : b;
      if (hi > lo) acc += hi - lo;
    }
    return acc;
  }
};

// Per-CPU ownership ledger: who held each CPU across any time window. Folds the
// SWITCH_IN / PICK stream (one "task took this CPU at ts" record per context
// switch, system-wide -- the holder need not be in the traced comm group) into a
// per-CPU timeline, and resolves tids to names from the tid-bearing events. The
// kstrand and dispatch-stall reports both query it to name the task that HELD a
// CPU while a victim waited -- the holder the HELD/DARK split could only infer
// before. An untraced holder (no tid->comm seen) renders as tid=N; the dominant-
// owner coverage still shows whether one task held the whole window.
struct CpuHolderLedger {
  std::unordered_map<uint32_t, std::vector<std::pair<uint64_t, uint32_t>>> own_;  // cpu -> (ts, tid)
  std::unordered_map<uint32_t, std::string> name_;  // tid -> comm
  bool sorted_ = false;

  // Two-tier: a FALLBACK name (learn) only fills a gap, never overwrites --
  // for sources that catch a tid's comm incidentally (IO, KSTRAND, WAITSTACK,
  // FORK's parent-inherited guess for the child) and may be stale by
  // construction. An AUTHORITATIVE name (learn_authoritative) always
  // overwrites -- for sources that are explicitly reporting a rename at the
  // moment it happens (EXEC, COMM_CHANGE, THREAD_NAME's live next_comm read).
  // Confirmed bug this fixes: a forked-then-exec'd child's very first
  // scheduling moment (fork returned, execve not yet run) is legitimately
  // named after its parent for a few dozen microseconds; a fallback learn()
  // from that moment used to lock in forever under the old write-once
  // policy, permanently misattributing every later strand on that tid to the
  // parent's name instead of the child's real, exec'd identity (a
  // forked-then-exec'd child held a CPU for 79ms attributed to "init", its
  // parent, verified against raw SWITCH_IN ground truth once trace_decode
  // could tell SWITCH_IN from CPU_IDLE -- see the sched_op_name fix landing
  // in this same release).
  void learn(uint32_t tid, const char* comm) {
    if (!comm || !comm[0]) return;
    if (name_.find(tid) == name_.end()) name_.emplace(tid, redact_comm(comm));
  }

  void learn_authoritative(uint32_t tid, const char* comm) {
    if (!comm || !comm[0]) return;
    name_[tid] = redact_comm(comm);
  }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) {
    if (type == TRACE_EVT_SCHED && len >= sizeof(montauk_sched_event)) {
      const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
      if (s->op == SCHED_OP_SWITCH_IN || s->op == SCHED_OP_PICK)
        own_[s->cpu].push_back({s->timestamp_ns, (uint32_t)s->pid});
      return;
    }
    if (type == TRACE_EVT_KSTRAND && len >= sizeof(montauk_kstrand_event)) {
      const auto* e = reinterpret_cast<const montauk_kstrand_event*>(data);
      learn(e->tid, e->comm);
    } else if (type == TRACE_EVT_IO && len >= sizeof(montauk_io_event)) {
      const auto* e = reinterpret_cast<const montauk_io_event*>(data);
      learn(e->tid, e->comm);
    } else if (type == TRACE_EVT_WAITSTACK && len >= sizeof(montauk_waitstack_event)) {
      const auto* e = reinterpret_cast<const montauk_waitstack_event*>(data);
      learn(e->tid, e->comm);
    } else if ((type == TRACE_EVT_FORK || type == TRACE_EVT_EXEC ||
                type == TRACE_EVT_COMM_CHANGE || type == TRACE_EVT_THREAD_NAME) &&
               len >= sizeof(montauk_ring_event)) {
      const auto* e = reinterpret_cast<const montauk_ring_event*>(data);
      bool authoritative = type != TRACE_EVT_FORK;
      if (authoritative) {
        learn_authoritative(e->pid, e->comm);
        if (e->child_pid) learn_authoritative(e->child_pid, e->comm);
      } else {
        // FORK: the child's comm here is the parent's, inherited at fork
        // time (handle_fork's own comment: "Child inherits parent comm
        // initially; exec will update it") -- a guess, never authoritative.
        // The parent's own comm at fork time is genuinely its own, current
        // name, so that half stays a normal (harmless either way) learn.
        learn(e->pid, e->comm);
        if (e->child_pid) learn(e->child_pid, e->comm);
      }
    }
  }

  void finalize() {
    if (sorted_) return;
    sorted_ = true;
    // Pair order (ts, then tid) via LSD-composed stable index sorts: minor key
    // first, major key second -- equivalent to the old whole-pair operator<.
    for (auto& kv : own_) {
      sublimation_order_u64(kv.second,
                            false, [](const std::pair<uint64_t, uint32_t>& p) { return p.second; });
      sublimation_order_u64(kv.second,
                            false, [](const std::pair<uint64_t, uint32_t>& p) { return p.first; });
    }
  }

  std::string name_of(uint32_t tid) const {
    auto it = name_.find(tid);
    if (it != name_.end()) return it->second;
    return "tid=" + std::to_string(tid);
  }

  // Dominant owner of [t0,t1) on cpu: the tid that ran the most of the window and
  // the ns it held. held_ns == window_ns => one task held the entire wait.
  struct Holder { uint32_t tid = 0; uint64_t held_ns = 0; uint64_t window_ns = 0; };
  Holder dominant(uint32_t cpu, uint64_t t0, uint64_t t1) const {
    Holder h;
    if (t1 <= t0) return h;
    h.window_ns = t1 - t0;
    auto it = own_.find(cpu);
    if (it == own_.end()) return h;
    const auto& tl = it->second;
    std::unordered_map<uint32_t, uint64_t> acc;
    size_t i = (size_t)(std::lower_bound(tl.begin(), tl.end(),
                          std::make_pair(t0, 0u)) - tl.begin());
    if (i > 0) --i;  // the segment covering t0 starts before t0
    for (; i < tl.size(); ++i) {
      uint64_t seg_lo = tl[i].first;
      if (seg_lo >= t1) break;
      uint64_t seg_hi = (i + 1 < tl.size()) ? tl[i + 1].first : t1;
      uint64_t lo = seg_lo > t0 ? seg_lo : t0;
      uint64_t hi = seg_hi < t1 ? seg_hi : t1;
      if (hi > lo) acc[tl[i].second] += hi - lo;
    }
    for (const auto& kv : acc)
      if (kv.second > h.held_ns) { h.held_ns = kv.second; h.tid = kv.first; }
    return h;
  }

  // Top pick-recipient (by pick count) on cpu across [t0,t1), excluding one pid
  // -- the ORDER-STARVED dual of dominant(): while dominant() names who HELD the
  // CPU (runtime) during a victim's wait, this names who the CPU kept RE-PICKING
  // instead of the victim. Same per-CPU pick timeline, a count query. Generic:
  // any report asking "who monopolized this CPU's picks in a window" can call it.
  struct Recip { uint32_t tid = 0; uint64_t count = 0; };
  Recip top_picked(uint32_t cpu, uint64_t t0, uint64_t t1, int exclude) const {
    Recip p;
    auto it = own_.find(cpu);
    if (it == own_.end()) return p;
    const auto& tl = it->second;
    std::unordered_map<uint32_t, uint64_t> cnt;
    auto lo = std::lower_bound(tl.begin(), tl.end(), std::make_pair(t0, 0u));
    for (auto i = lo; i != tl.end() && i->first < t1; ++i)
      if ((int)i->second != exclude) cnt[i->second]++;
    for (const auto& kv : cnt)
      if (kv.second > p.count) { p.count = kv.second; p.tid = kv.first; }
    return p;
  }
};

// SHARED SCHED SUBSTRATE. Both of these fold the whole sched stream and were
// instantiated TWICE -- DispatchStallReport and KStrandReport each held a
// private copy and folded independently, doubling the work and the memory for
// two structures whose own comment already said both reports query them. Folded
// once by the driver (see for_each below), queried by both. The fold conditions
// were byte-identical in the two reports before this, which is what makes the
// share safe: holder unconditionally, idle on SCHED_OP_CPU_IDLE only.
// The per-CPU pick timeline, held ONCE. dispatch-stall buffered these as full
// records and slice buffered a timestamp-only copy of the same stream -- the
// ~6x peak RAM on a 450MB trace. One buffer now; slice reads .ts off the same
// records.
struct CpuPickTimeline {
  // ts, picked pid, LANE (sub_idx: 0=primary, >0=steal), dispatch score. The
  // class occupies the score's high bits; within a class the oldest waiter
  // sorts highest, so cls = score>>48.
  struct Pk { uint64_t ts; int pid; uint32_t lane; uint64_t score; };
  std::unordered_map<uint32_t, std::vector<Pk>> picks;         // native PICK
  std::unordered_map<uint32_t, std::vector<Pk>> switch_picks;  // SWITCH_IN fallback

  void fold(const montauk_sched_event* s) {
    if (s->op == SCHED_OP_PICK)
      picks[s->cpu].push_back({s->timestamp_ns, s->pid, s->sub_idx, s->score});
    else if (s->op == SCHED_OP_SWITCH_IN)
      // Reconstructed pick: switch-in = pick; lane/score unavailable (zeroed).
      switch_picks[s->cpu].push_back({s->timestamp_ns, s->pid, 0, 0});
  }

  // Prefer the scheduler's own PICK stream; fall back to the SWITCH_IN
  // reconstruction when no pick tracepoint was bound (stock EEVDF, scx modes
  // without pick). Both callers spelled this rule differently before -- one as
  // `picks.empty() && !switch.empty()`, one as `!picks.empty() ? picks : switch`
  // -- which agree in every case; this is the single statement of it.
  [[nodiscard]] bool reconstructed() const {
    return picks.empty() && !switch_picks.empty();
  }
  [[nodiscard]] const std::unordered_map<uint32_t, std::vector<Pk>>& active() const {
    return reconstructed() ? switch_picks : picks;
  }

  // Sort the ACTIVE stream per CPU by timestamp. Only the active one, because
  // only it is ever read -- sorting both would be work nobody consumes.
  void finalize() {
    auto& src = reconstructed() ? switch_picks : picks;
    for (auto& kv : src)
      sublimation_order_u64(kv.second, false, [](const Pk& e) { return e.ts; });
  }
};

// Bin a timestamp stream into a rate series over [t0, t0 + w*nbins). Shared by
// fractal and matrix-profile, which both turn the same SCHED stream into a rate
// series and each carried a private copy of this loop.
//
// The RESOLUTION stays the caller's: fractal asks for ~120k bins because DFA
// needs several decades of scale to be rigorous (its predecessor ran on ~340
// .prom points, under one decade, and its own author marked it INDICATIVE
// ONLY), while matrix profile asks for 128 because STOMP's cost scales with
// window count. Sharing the loop is right; unifying the bin counts would break
// one of the two algorithms.
// The tail CLAMPS into the last bin rather than being dropped. That is
// matrix-profile's existing behaviour and a no-op for fractal, which sizes
// nbins as span/w + 1 so its largest index is already exactly nbins-1 -- which
// is what lets one helper serve both without moving either's numbers.
static std::vector<double> bin_rate_series(const std::vector<uint64_t>& ts,
                                           uint64_t t0, uint64_t w, size_t nbins) {
  std::vector<double> r(nbins, 0.0);
  if (w == 0 || nbins == 0) return r;
  for (uint64_t t : ts) {
    if (t < t0) continue;
    size_t i = static_cast<size_t>((t - t0) / w);
    if (i >= nbins) i = nbins - 1;
    r[i] += 1.0;
  }
  return r;
}

static CpuIdleIntervals g_sched_idle;
static CpuHolderLedger  g_sched_holder;
static CpuPickTimeline  g_sched_picks;
// The highest CPU number and the last timestamp over EVERY sched event: the
// denominators the per-CPU lanes need, folded once rather than per report.
static int64_t  g_sched_max_cpu = 0;
static uint64_t g_sched_max_ts = 0;

// Per class, the field indices the census and ledger read on every record,
// resolved once rather than by name per event.
struct ClassFields { const montauk::query::EventClass* cls = nullptr; int tid = -1, pid = -1, comm = -1; };
static const std::array<ClassFields, 64> g_class_fields = [] {
  std::array<ClassFields, 64> t{};
  for (uint32_t ty = 0; ty < t.size(); ++ty) {
    const auto* c = montauk::query::class_of(ty);
    if (!c) continue;
    t[ty] = {c, montauk::query::field_named(*c, "tid"), montauk::query::field_named(*c, "pid"),
             montauk::query::field_named(*c, "comm")};
  }
  return t;
}();
static const ClassFields& class_fields(uint32_t type) {
  static const ClassFields none{};
  return type < g_class_fields.size() ? g_class_fields[type] : none;
}

// THE CENSUS: every record counted by type and op, and each type's timestamp
// span. Summary renders from it and the time-relative reports take their trace
// window from it, so no report stores every event just to count them.
struct Census {
  static constexpr int64_t kEntry = 4096;   // a wait ENTRY counts apart from its completion
  uint64_t total = 0;
  std::array<uint64_t, 64> type_n{};
  std::map<uint32_t, uint64_t> other_type;                  // types past the table
  std::array<std::vector<uint64_t>, 64> op_n;               // type -> op -> records
  std::map<std::string, uint64_t> provider;                 // provider name -> snapshots
  std::array<std::pair<uint64_t, uint64_t>, 64> span{};     // type -> (min, max) nonzero ts
  void fold(uint32_t type, const uint8_t* data, uint32_t len) {
    ++total;
    if (type >= type_n.size()) { ++other_type[type]; return; }
    ++type_n[type];
    const ClassFields& cf = class_fields(type);
    if (!cf.cls || len < cf.cls->size) return;
    const auto& c = *cf.cls;
    if (c.op_field >= 0) {
      int64_t op = montauk::query::read_int(c.fields[c.op_field], data);
      if (type == TRACE_EVT_NTSYNC &&
          reinterpret_cast<const montauk_ntsync_event*>(data)->result == kWaitEntrySentinel)
        op += kEntry;
      if (op >= 0 && op < 2 * kEntry) {
        auto& v = op_n[type];
        if (v.empty()) v.resize(2 * kEntry);   // once per type seen
        ++v[static_cast<size_t>(op)];
      }
    }
    if (type == TRACE_EVT_PROVIDER) {
      char nm[33];
      std::snprintf(nm, sizeof(nm), "%.32s", reinterpret_cast<const montauk_provider_event*>(data)->name);
      ++provider[nm];
    }
    if (c.ts_field >= 0) {
      const uint64_t ts = static_cast<uint64_t>(montauk::query::read_int(c.fields[c.ts_field], data));
      if (ts == 0) return;
      auto& sp = span[type];
      if (sp.first == 0 || ts < sp.first) sp.first = ts;
      if (ts > sp.second) sp.second = ts;
    }
  }
  uint64_t op(uint32_t type, int64_t o) const {
    if (type >= op_n.size() || o < 0 || static_cast<size_t>(o) >= op_n[type].size()) return 0;
    return op_n[type][static_cast<size_t>(o)];
  }
  // Every type the stream carried, with its count.
  std::map<uint32_t, uint64_t> by_type() const {
    std::map<uint32_t, uint64_t> out = other_type;
    for (uint32_t t = 0; t < type_n.size(); ++t) if (type_n[t]) out[t] = type_n[t];
    return out;
  }
  // The span over a set of types: (min, max), zeros when none of them carried a timestamp.
  std::pair<uint64_t, uint64_t> span_of(std::initializer_list<uint32_t> types) const {
    uint64_t lo = 0, hi = 0;
    for (uint32_t t : types) {
      if (t >= span.size() || span[t].second == 0) continue;
      if (lo == 0 || span[t].first < lo) lo = span[t].first;
      hi = std::max(hi, span[t].second);
    }
    return {lo, hi};
  }
};
static Census g_census;

// PER-THREAD LEDGER: for every thread and every class that names one, the
// latest timestamp, the last pid, and the last non-empty comm with its place
// in the stream. "When did this thread last do anything" is the question the
// end-of-trace reports share; each asks it over its own set of classes. Folded
// only when an active report declares it needs one.
struct ThreadLedger {
  struct Last { uint32_t type = 0; uint64_t max_ts = 0, seq = 0, comm_seq = 0; int64_t pid = -1; char comm[16] = {}; };
  std::unordered_map<uint32_t, std::vector<Last>> by_tid;   // a thread touches a handful of classes
  uint64_t seq = 0;
  bool on = false;
  void fold(uint32_t type, const uint8_t* data, uint32_t len) {
    ++seq;
    const ClassFields& cf = class_fields(type);
    if (!cf.cls || cf.tid < 0 || len < cf.cls->size) return;
    const auto& c = *cf.cls;
    auto& v = by_tid[static_cast<uint32_t>(montauk::query::read_int(c.fields[cf.tid], data))];
    Last* l = nullptr;
    for (auto& x : v) if (x.type == type) { l = &x; break; }
    if (!l) { v.push_back({}); l = &v.back(); l->type = type; }
    if (c.ts_field >= 0)
      l->max_ts = std::max(l->max_ts, static_cast<uint64_t>(montauk::query::read_int(c.fields[c.ts_field], data)));
    l->seq = seq;
    if (cf.pid >= 0) l->pid = montauk::query::read_int(c.fields[cf.pid], data);
    if (cf.comm >= 0) {
      const auto& f = c.fields[cf.comm];
      if (data[f.off]) { std::memcpy(l->comm, data + f.off, std::min<size_t>(f.size, sizeof l->comm)); l->comm_seq = seq; }
    }
  }
  const Last* of(uint32_t tid, uint32_t type) const {
    auto it = by_tid.find(tid);
    if (it == by_tid.end()) return nullptr;
    for (const auto& x : it->second) if (x.type == type) return &x;
    return nullptr;
  }
  // The record of a set of classes that came LAST in the stream for a thread,
  // by position rather than timestamp; `comm_only` considers only records that
  // carried a non-empty comm.
  const Last* latest(uint32_t tid, std::initializer_list<uint32_t> types, bool comm_only) const {
    const Last* best = nullptr;
    for (uint32_t ty : types) {
      const Last* l = of(tid, ty);
      if (!l || (comm_only && l->comm_seq == 0)) continue;
      const uint64_t at = comm_only ? l->comm_seq : l->seq;
      if (!best || at > (comm_only ? best->comm_seq : best->seq)) best = l;
    }
    return best;
  }
  // A thread's latest timestamp over a set of classes, 0 when it touched none.
  uint64_t last_ts(uint32_t tid, std::initializer_list<uint32_t> types) const {
    uint64_t t = 0;
    for (uint32_t ty : types) if (const Last* l = of(tid, ty)) t = std::max(t, l->max_ts);
    return t;
  }
  static std::string comm(const Last* l) { return l ? std::string(l->comm, strnlen(l->comm, sizeof l->comm)) : ""; }
};
static ThreadLedger g_threads;
// finalize() sorts the per-CPU timelines and must run once, after the last
// fold and before the first query. Reports call ensure_sched_substrate() from
// their own compute(); the flag makes the second and later calls free.
static bool g_sched_substrate_ready = false;
static void ensure_sched_substrate() {
  if (g_sched_substrate_ready) return;
  g_sched_substrate_ready = true;
  g_sched_idle.finalize();
  g_sched_holder.finalize();
  g_sched_picks.finalize();
}

// DRIVER-LEVEL FOLD: everything that must be folded ONCE per event, outside the
// per-report loop -- the shared sched substrate the reports hold references to,
// and the capture-loss snapshot.
//
// This exists as a function because having it inline in one driver was a defect
// with teeth. run_digest ran its own fold loop that called only r->fold(), so in
// the digest the substrate stayed EMPTY and the reports that query it answered
// from nothing: dispatch-stall reported PREEMPT-STARVED 100% with 0 pass-overs
// on a trace the --report path reads as ORDER-STARVED 100% with 11.0 average
// pass-overs and named offenders. Two renderings of one capture, opposite
// diagnoses, and the wrong one was on the shareable face. Every fold path calls
// this; adding driver state means adding it here and both paths get it.
static void fold_driver_state(uint32_t type, const uint8_t* data, uint32_t len) {
  fold_drop_snapshot(type, data, len);
  g_census.fold(type, data, len);
  if (g_threads.on) g_threads.fold(type, data, len);
  g_sched_holder.fold(type, data, len);
  if (type == TRACE_EVT_SCHED && len >= sizeof(montauk_sched_event)) {
    const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
    if (s->op == SCHED_OP_CPU_IDLE)
      g_sched_idle.fold(s->cpu, s->sub_idx, s->timestamp_ns);
    g_sched_picks.fold(s);
    if (static_cast<int64_t>(s->cpu) > g_sched_max_cpu) g_sched_max_cpu = s->cpu;
    if (s->timestamp_ns > g_sched_max_ts) g_sched_max_ts = s->timestamp_ns;
  }
}

// SAVED QUERIES. A report is a row: a name, the sources it folds -- each a
// selection over the field table and the fields it keeps, data rather than
// code -- and a derive step from those rows to the result. Every face renders
// that result and nothing else, so a conclusion can only ever be composed in
// derive; there is no print-time path left to compose one in.
struct Source {
  const char* select;                        // "sched.wake2run,cpu_idle"
  std::vector<const char*> fields;           // kept per matching event, in order
  std::vector<const char*> where = {};       // field comparisons, "result!=-999"
  bool raw = false;                          // also keep the whole record (Row::raw)
  bool tally = false;                        // count by the fields instead of keeping rows
};

// Every source's matching events as rows of int64, in trace order: the source
// index (only when there is more than one source), the timestamp, then the
// source's fields. Text fields are interned. A TALLY source keeps no rows: it
// counts its events by their field values (at most two), which is all a census
// needs and costs a counter rather than a row per event.
struct Collected {
  struct TallyKey {
    int64_t a, b;
    bool operator==(const TallyKey&) const = default;
  };
  struct TallyHash {
    size_t operator()(const TallyKey& k) const {
      return std::hash<int64_t>{}(k.a) * 0x9E3779B97F4A7C15ull ^ std::hash<int64_t>{}(k.b);
    }
  };
  struct TextHash {
    using is_transparent = void;
    size_t operator()(std::string_view s) const { return std::hash<std::string_view>{}(s); }
  };
  std::vector<montauk::query::Select> sel;
  std::vector<std::vector<int>> fidx;
  std::vector<bool> keep_raw, is_tally;
  std::vector<std::unordered_map<TallyKey, uint64_t, TallyHash>> tallies;
  size_t base = 1;                           // cells before the fields: [src,] ts
  std::vector<size_t> span;                  // per source: cells a row of it takes
  size_t nrows = 0;
  const void* folder = nullptr;              // the report that folds this buffer
  std::vector<int64_t> cells;
  std::vector<std::string> strings;
  std::unordered_map<std::string, int64_t, TextHash, std::equal_to<>> interned;
  std::vector<uint8_t> raw_bytes;            // raw sources' records, back to back
  std::vector<size_t> raw_off;

  struct Row {
    const Collected* c;
    const int64_t* p;
    int src() const { return c->base == 2 ? static_cast<int>(p[0]) : 0; }
    int64_t ts() const { return p[c->base - 1]; }
    int64_t operator[](size_t i) const { return p[c->base + i]; }
    uint64_t u(size_t i) const { return static_cast<uint64_t>(p[c->base + i]); }
    const std::string& text(size_t i) const { return c->strings[static_cast<size_t>(p[c->base + i])]; }
    // A raw source's whole record, as the struct it was captured as.
    template <class T> const T& raw() const {
      return *reinterpret_cast<const T*>(c->raw_bytes.data() + c->raw_off[static_cast<size_t>(p[c->span[src()] - 1])]);
    }
  };

  void init(const std::vector<Source>& srcs) {
    for (const Source& s : srcs) {
      montauk::query::Select q;
      std::string err;
      if (!montauk::query::parse_select(s.select, q, err)) {
        log_error("saved query source '%s': %s", s.select, err.c_str());
        std::abort();
      }
      for (const char* w : s.where)
        if (!montauk::query::parse_clause(w, q, err)) {
          log_error("saved query source '%s': %s", s.select, err.c_str());
          std::abort();
        }
      std::vector<int> f;
      for (const char* name : s.fields) {
        const int i = montauk::query::field_named(*q.cls, name);
        if (i < 0) { log_error("saved query '%s': no field '%s'", s.select, name); std::abort(); }
        f.push_back(i);
      }
      if (s.tally && f.size() > 2) { log_error("saved query '%s': a tally keys on at most two fields", s.select); std::abort(); }
      sel.push_back(std::move(q));
      fidx.push_back(std::move(f));
      keep_raw.push_back(s.raw);
      is_tally.push_back(s.tally);
    }
    tallies.resize(sel.size());
    base = sel.size() > 1 ? 2 : 1;
    // A row is exactly as wide as its source: no padding to the widest. A raw
    // source's last cell indexes its record.
    for (size_t i = 0; i < sel.size(); ++i) span.push_back(base + fidx[i].size() + (keep_raw[i] ? 1 : 0));
  }
  int64_t intern(std::string_view t) {
    auto it = interned.find(t);
    if (it != interned.end()) return it->second;
    const auto id = static_cast<int64_t>(strings.size());
    strings.emplace_back(t);
    interned.emplace(strings.back(), id);
    return id;
  }
  void fold(uint32_t type, const uint8_t* data, uint32_t len) {
    for (size_t s = 0; s < sel.size(); ++s) {
      if (!sel[s].matches(type, data, len)) continue;
      const auto& cls = *sel[s].cls;
      if (is_tally[s]) {
        TallyKey k{0, 0};
        if (!fidx[s].empty()) k.a = montauk::query::read_int(cls.fields[fidx[s][0]], data);
        if (fidx[s].size() > 1) k.b = montauk::query::read_int(cls.fields[fidx[s][1]], data);
        ++tallies[s][k];
        return;
      }
      if (base == 2) cells.push_back(static_cast<int64_t>(s));
      cells.push_back(cls.ts_field >= 0 ? montauk::query::read_int(cls.fields[cls.ts_field], data) : 0);
      for (int fi : fidx[s]) {
        const auto& f = cls.fields[fi];
        cells.push_back(f.kind == montauk::query::Kind::Text ? intern(montauk::query::read_text(f, data))
                                                             : montauk::query::read_int(f, data));
      }
      if (keep_raw[s]) {
        cells.push_back(static_cast<int64_t>(raw_off.size()));
        raw_off.push_back(raw_bytes.size());
        raw_bytes.insert(raw_bytes.end(), data, data + len);
      }
      ++nrows;
      return;                                // one source per event: the first that matches
    }
  }
  size_t rows() const { return nrows; }
  // Rows in trace order. Variable width, so they are walked, not indexed.
  template <class Fn> void each(Fn fn) const {
    for (size_t at = 0; at < cells.size();) {
      Row r{this, cells.data() + at};
      fn(r);
      at += span[static_cast<size_t>(r.src())];
    }
  }
};

// Reports whose sources are identical read one buffer: the first to ask folds
// it, the rest only read. waits and spins fold the sync stream once.
std::shared_ptr<Collected> shared_collected(const std::vector<Source>& srcs) {
  static std::vector<std::pair<std::string, std::shared_ptr<Collected>>> pool;
  std::string sig;
  for (const Source& s : srcs) {
    sig += s.select; sig += '|';
    for (const char* f : s.fields) { sig += f; sig += ','; }
    sig += '|';
    for (const char* w : s.where) { sig += w; sig += ','; }
    sig += s.raw ? "|r" : "|-";
    sig += s.tally ? "t;" : "-;";
  }
  for (auto& [k, c] : pool)
    if (k == sig) return c;
  auto c = std::make_shared<Collected>();
  c->init(srcs);
  pool.emplace_back(sig, c);
  return c;
}

// A VERDICT ROW: this token when the named measure clears the threshold. The
// first row that matches wins; a row with no measure always matches, so the
// last row is the default.
struct VerdictRow { const char* klass; const char* measure; char cmp; double v; };
struct Measures {
  std::vector<std::pair<const char*, double>> m;
  void set(const char* k, double v) { m.emplace_back(k, v); }
  double get(const char* k) const {
    for (const auto& [n, v] : m) if (std::strcmp(n, k) == 0) return v;
    return 0.0;
  }
};
const char* pick_verdict(std::initializer_list<VerdictRow> rows, const Measures& ms) {
  for (const VerdictRow& r : rows) {
    if (!r.measure) return r.klass;
    const double x = ms.get(r.measure);
    if ((r.cmp == '>' && x > r.v) || (r.cmp == 'G' && x >= r.v) ||
        (r.cmp == '<' && x < r.v) || (r.cmp == 'L' && x <= r.v) ||
        (r.cmp == '=' && x == r.v))
      return r.klass;
  }
  return "NONE";
}

void compose_verdict(ReportResult& r, const char* klass, const char* fmt, ...)
    __attribute__((format(printf, 3, 4)));
void compose_verdict(ReportResult& r, const char* klass, const char* fmt, ...) {
  char buf[512];
  va_list ap;
  va_start(ap, fmt);
  std::vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  r.verdict = buf;
  r.klass = klass;
}

// A STREAM is per-event state a report keeps itself: a running state machine
// over the busiest streams in the trace (every wake, switch and idle boundary),
// where a row per event would cost far more than the few counters and lists
// the analysis actually needs. It folds and nothing else; derive reads it.
struct Stream {
  virtual ~Stream() = default;
  virtual void fold(uint32_t type, const uint8_t* data, uint32_t len) = 0;
};

struct ReportDef {
  const char* name;
  std::vector<Source> sources;
  bool substrate;                            // reads the shared per-CPU sched timelines
  void (*derive)(const Collected&, ReportResult&);
  bool ledger = false;                       // reads the per-thread ledger
  std::unique_ptr<Stream> (*stream)() = nullptr;               // a stream report's state
  void (*derive_stream)(const Stream&, ReportResult&) = nullptr;
};

void json_detail(montauk_json& j, const Detail& d) {
  switch (d.k) {
    case Detail::Num: montauk_json_num(&j, d.num); break;
    case Detail::U64: montauk_json_u64(&j, d.u); break;
    case Detail::Bool: montauk_json_bool(&j, d.u ? 1 : 0); break;
    case Detail::Str: montauk_json_str(&j, d.str.c_str()); break;
    case Detail::Obj:
      montauk_json_obj_begin(&j);
      for (const auto& v : d.obj) { montauk_json_key(&j, v.key.c_str()); json_detail(j, v); }
      montauk_json_obj_end(&j);
      break;
    case Detail::Arr:
      montauk_json_arr_begin(&j);
      for (const auto& v : d.arr) json_detail(j, v);
      montauk_json_arr_end(&j);
      break;
  }
}

std::string detail_text(const Detail& d) {
  char b[64];
  switch (d.k) {
    case Detail::Num: std::snprintf(b, sizeof b, "%.6g", d.num); return b;
    case Detail::U64: return std::to_string(d.u);
    case Detail::Bool: return d.u ? "yes" : "no";
    case Detail::Str: return d.str;
    default: return "";
  }
}

// THE TEXT FACE, generic: the verdict, every detail block, every gauge. A
// block that is an array of objects prints as a table, one column per key.
void text_result(const char* name, const ReportResult& r) {
  montauk_sink_appendf(&g_out, "REPORT %s\nVERDICT: %s\n", name, r.verdict.c_str());
  for (const auto& [key, d] : r.detail) {
    if (d.k == Detail::Arr && !d.arr.empty() && d.arr[0].k == Detail::Obj) {
      montauk_sink_appendf(&g_out, "%s:\n", key.c_str());
      std::vector<std::string> cols;
      for (const auto& v : d.arr[0].obj) if (v.k != Detail::Obj) cols.push_back(v.key);
      std::vector<size_t> w(cols.size());
      for (size_t c = 0; c < cols.size(); ++c) w[c] = cols[c].size();
      std::vector<std::vector<std::string>> cells;
      for (const auto& row : d.arr) {
        std::vector<std::string> line(cols.size());
        for (size_t c = 0; c < cols.size(); ++c)
          for (const auto& v : row.obj)
            if (v.key == cols[c]) { line[c] = detail_text(v); w[c] = std::max(w[c], line[c].size()); }
        cells.push_back(std::move(line));
      }
      auto put = [&](const std::vector<std::string>& line) {
        montauk_sink_appendf(&g_out, " ");
        for (size_t c = 0; c < cols.size(); ++c)
          montauk_sink_appendf(&g_out, " %-*s", static_cast<int>(w[c]), line[c].c_str());
        montauk_sink_appendc(&g_out, '\n');
      };
      put(cols);
      for (const auto& line : cells) put(line);
    } else if (d.k == Detail::Obj) {
      montauk_sink_appendf(&g_out, "%s:", key.c_str());
      for (const auto& v : d.obj)
        if (v.k != Detail::Obj && v.k != Detail::Arr)
          montauk_sink_appendf(&g_out, " %s=%s", v.key.c_str(), detail_text(v).c_str());
      montauk_sink_appendc(&g_out, '\n');
    } else if (d.k != Detail::Arr) {
      montauk_sink_appendf(&g_out, "%s: %s\n", key.c_str(), detail_text(d).c_str());
    }
  }
  for (const PromMetric& g : r.gauges) {
    const char* n = g.name;
    if (std::strncmp(n, "montauk_analysis_", 17) == 0) n += 17;
    montauk_sink_appendf(&g_out, "  %s%s%s%s %s\n", n, g.labels.empty() ? "" : "{",
                         g.labels.c_str(), g.labels.empty() ? "" : "}", prom_num(g.value).c_str());
  }
}

// The JSON face of one result: name, verdict, class, the detail blocks in
// order, then the gauges (each with its HELP) and the offenders.
void json_result(montauk_json& j, const char* name, const ReportResult& r) {
  montauk_json_obj_begin(&j);
  montauk_json_kstr(&j, "name", name);
  if (!r.verdict.empty()) montauk_json_kstr(&j, "verdict", r.verdict.c_str());
  if (!r.klass.empty()) montauk_json_kstr(&j, "class", r.klass.c_str());
  for (const auto& [k, d] : r.detail) { montauk_json_key(&j, k.c_str()); json_detail(j, d); }
  if (!r.gauges.empty()) {
    montauk_json_key(&j, "gauges");
    montauk_json_arr_begin(&j);
    for (const auto& m : r.gauges) {
      montauk_json_obj_begin(&j);
      montauk_json_kstr(&j, "name", m.name);
      montauk_json_knum(&j, "value", m.value);
      if (!m.labels.empty()) montauk_json_kstr(&j, "labels", m.labels.c_str());
      const char* help = prom_help(m.name);
      if (help && *help) montauk_json_kstr(&j, "help", help);
      montauk_json_obj_end(&j);
    }
    montauk_json_arr_end(&j);
  }
  if (!r.offenders.empty()) {
    montauk_json_key(&j, "offenders");
    montauk_json_arr_begin(&j);
    for (const auto& o : r.offenders) {
      montauk_json_obj_begin(&j);
      montauk_json_kstr(&j, "kind", o.kind.c_str());
      montauk_json_kstr(&j, "id", o.id.c_str());
      if (!o.obj.empty()) montauk_json_kstr(&j, "obj", o.obj.c_str());
      montauk_json_kstr(&j, "metric", o.metric.c_str());
      montauk_json_knum(&j, "value", o.value);
      montauk_json_ki64(&j, "sev", o.sev);
      montauk_json_obj_end(&j);
    }
    montauk_json_arr_end(&j);
  }
  montauk_json_obj_end(&j);
}

// A REPORT is one run of a saved query: its definition, the rows or stream it
// folds, and the result every face renders.
struct Report {
  const ReportDef& def;
  std::shared_ptr<Collected> in;
  std::unique_ptr<Stream> stream;
  ReportResult res;
  explicit Report(const ReportDef& d)
      : def(d), in(shared_collected(d.sources)), stream(d.stream ? d.stream() : nullptr) {}
  const char* name() const { return def.name; }
  // The first ACTIVE report on a shared buffer folds it; a selected report
  // whose twin was not selected still gets its rows.
  void fold(uint32_t type, const uint8_t* data, uint32_t len) {
    if (stream) { stream->fold(type, data, len); return; }
    if (!in->folder) in->folder = this;
    if (in->folder == this) in->fold(type, data, len);
  }
  void compute() {
    if (def.substrate) ensure_sched_substrate();
    if (stream) def.derive_stream(*stream, res);
    else def.derive(*in, res);
  }
  const ReportResult& result_base() const { return res; }
  void emit(const montauk::model::TraceReader&) const {
    text_result(def.name, res);
    montauk_sink_appendc(&g_out, '\n');
  }
  void prom(std::vector<PromMetric>& out) const { out.insert(out.end(), res.gauges.begin(), res.gauges.end()); }
  void offenders(std::vector<Offender>& out) const { out.insert(out.end(), res.offenders.begin(), res.offenders.end()); }
  void json(montauk_json& j) const { json_result(j, def.name, res); }
};

// REPORT storm: the sched_ext cpu_release kick-storm, from TRACE_EVT_SCX_STORM
// per-interval counters (fentry on scx_bpf_kick_cpu / scx_bpf_reenqueue_local).
// Reenqueue rate is the storm intensity; the preempt-kick share splits a REAL
// IPI storm from benign IDLE re-enqueue churn, and the two are DIFFERENT
// DEFECTS, not degrees of one: a real IPI storm burns interrupts, idle churn
// burns nothing and means the kicks are no-ops.
void derive_storm(const Collected& in, ReportResult& r) {
  constexpr double kStormReenqPerS = 50000.0;  // a core reenqueuing this hard is storming
  constexpr double kHardFrac = 0.5;            // preempt >= frac*reenq => real IPI storm
  uint64_t kicks = 0, preempt = 0, reenq = 0, total_ms = 0;
  std::vector<uint64_t> rates;
  size_t storm = 0;
  in.each([&](Collected::Row e) {
    kicks += e.u(0); preempt += e.u(1); reenq += e.u(2); total_ms += e.u(3);
    const double rate = e.u(3) ? static_cast<double>(e.u(2)) * 1000.0 / static_cast<double>(e.u(3)) : 0.0;
    rates.push_back(static_cast<uint64_t>(rate));
    if (rate >= kStormReenqPerS) ++storm;
  });
  // Availability bit: 0 says the scx storm probes were not attached, which is
  // distinct from a capture that genuinely saw zero kicks.
  if (rates.empty() || total_ms == 0) {
    compose_verdict(r, "NONE", "no sched_ext kick activity captured (non-scx scheduler, "
                               "or no cpu_release storm)");
    r.gauges.push_back({"montauk_analysis_storm_captured", "", 0.0});
    return;
  }
  const double pct = 100.0 * static_cast<double>(storm) / static_cast<double>(rates.size());
  sublimation_u64(rates.data(), rates.size());
  const double peak = static_cast<double>(rates.back());
  const double p50 = static_cast<double>(q_at(rates, 0.50));
  const double secs = static_cast<double>(total_ms) / 1000.0;
  Measures m;
  m.set("storm_intervals", static_cast<double>(storm));
  m.set("real_ipi", reenq && static_cast<double>(preempt) >= kHardFrac * static_cast<double>(reenq));
  const char* klass = pick_verdict({{"CLEAN", "storm_intervals", '=', 0},
                                    {"REAL-IPI-STORM", "real_ipi", '>', 0},
                                    {"IDLE-REENQUEUE-CHURN", nullptr, 0, 0}}, m);
  const char* kind = storm == 0 ? "clean -- no storm intervals"
                   : m.get("real_ipi") > 0 ? "REAL IPI storm (preempt-kick dominant)"
                                           : "IDLE re-enqueue churn (kicks no-op on busy CPUs)";
  compose_verdict(r, klass,
      "%s; storm %zu/%zu intervals (%.1f%%); reenq/s p50=%.0f peak=%.0f; "
      "kick/s=%.0f (preempt %.0f) reenq/s=%.0f",
      kind, storm, rates.size(), pct, p50, peak, static_cast<double>(kicks) / secs,
      static_cast<double>(preempt) / secs, static_cast<double>(reenq) / secs);
  r.gauges.push_back({"montauk_analysis_storm_captured", "", 1.0});
  r.gauges.push_back({"montauk_analysis_storm_pct", "", pct});
  r.gauges.push_back({"montauk_analysis_storm_reenq_per_s", "stat=\"peak\"", peak});
  r.gauges.push_back({"montauk_analysis_storm_kick_per_s", "flag=\"all\"", static_cast<double>(kicks) / secs});
  r.gauges.push_back({"montauk_analysis_storm_kick_per_s", "flag=\"preempt\"", static_cast<double>(preempt) / secs});
  if (peak >= kStormReenqPerS)
    r.offenders.push_back({"scx-storm", "scheduler", "", "reenq_per_s", peak,
                           peak > 5.0 * kStormReenqPerS ? 2 : 1});
}

const ReportDef kStorm = {
    "storm", {{"scx_storm", {"kicks", "preempt_kicks", "reenq", "interval_ms"}}}, false, derive_storm};

// A metric family whose name carries a key (iolat's per-syscall families).
// PromMetric names are borrowed pointers, so the names live here, for the run.
const char* metric_name(std::string name) {
  static std::deque<std::string> pool;
  for (const auto& n : pool) if (n == name) return n.c_str();
  pool.push_back(std::move(name));
  return pool.back().c_str();
}

// REPORT classmix: the absolute per-class distribution of ENQUEUEd tasks, from
// the frozen dispatch score (cls_weight in bits 48+). dispatch-stall gives
// class only RELATIVE to the wakee; this gives the mix, so a uniform worker
// pool split across classes -- cross-class starvation no within-class lever
// can override -- is answerable from data rather than assumed.
void derive_classmix(const Collected& in, ReportResult& r) {
  std::unordered_map<int64_t, uint64_t> pid_cls;   // pid -> its last enqueue's class
  std::map<uint64_t, uint64_t> enq;                // class -> enqueues
  in.each([&](Collected::Row e) {
    const uint64_t c = e.u(1) >> 48;
    pid_cls[e[0]] = c;
    ++enq[c];
  });
  if (pid_cls.empty()) { compose_verdict(r, "NO-ENQUEUE", "no ENQUEUE events"); return; }
  compose_verdict(r, "CLASS-MIX",
                  "%zu distinct enqueued pids; class mix (cls_weight in score bits 48+):",
                  pid_cls.size());
  std::map<uint64_t, uint64_t> distinct;
  for (const auto& kv : pid_cls) ++distinct[kv.second];
  uint64_t tot = 0;
  for (const auto& kv : enq) tot += kv.second;
  Detail classes = Detail::array();
  for (const auto& [w, n] : distinct)
    classes.arr.push_back(Detail::object()
        .put("cls_weight", Detail::count(w))
        .put("class", Detail::text(w >= 32 ? "LAT_CRITICAL" : w >= 8 ? "LATENCY"
                                 : w >= 4 ? "INTERACTIVE" : w >= 1 ? "BATCH" : "stalled/other"))
        .put("distinct_pids", Detail::count(n))
        .put("enqueues", Detail::count(enq[w]))
        .put("pct", Detail::of(tot ? 100.0 * static_cast<double>(enq[w]) / static_cast<double>(tot) : 0.0)));
  r.detail.emplace_back("classes", std::move(classes));
}

// REPORT field-persist: does an adaptive scheduler's discrete workload
// classification MOVE over the capture, or is it PINNED? A latched classifier
// -- one signature held the whole run however often its gate fires -- cannot
// tell apart two operating states it committed between at start: the per-boot
// bistable tell, since a scalar regime reads identical in both basins.
void derive_field_persist(const Collected& in, ReportResult& r) {
  struct G { int64_t ts; uint64_t sig; bool changed; };
  std::vector<G> gates;
  in.each([&](Collected::Row e) { gates.push_back({e.ts(), e.u(0), e[1] != 0}); });
  if (gates.empty()) {
    compose_verdict(r, "NO-FIELD-GATE", "no field-gate events (adaptive reclassification gate not streamed)");
    return;
  }
  sublimation_order_u64(gates, false, [](const G& g) { return static_cast<uint64_t>(g.ts); });
  // Dwell per signature = time to the next gate tick.
  std::map<uint64_t, uint64_t> dwell, seen;
  uint64_t rederiv = 0;
  for (size_t i = 0; i < gates.size(); ++i) {
    ++seen[gates[i].sig];
    if (gates[i].changed) ++rederiv;
    const int64_t next = i + 1 < gates.size() ? gates[i + 1].ts : gates[i].ts;
    dwell[gates[i].sig] += next > gates[i].ts ? static_cast<uint64_t>(next - gates[i].ts) : 0;
  }
  const uint64_t span = static_cast<uint64_t>(gates.back().ts - gates.front().ts);
  uint64_t dom_sig = gates.front().sig, dom_dwell = 0;
  for (const auto& kv : dwell)
    if (kv.second > dom_dwell) { dom_dwell = kv.second; dom_sig = kv.first; }
  const double dom_pct = span ? 100.0 * static_cast<double>(dom_dwell) / static_cast<double>(span) : 100.0;
  const double dur_s = static_cast<double>(span) / 1e9;
  const double rate = dur_s > 0 ? static_cast<double>(gates.size()) / dur_s : 0.0;
  if (seen.size() <= 1)
    compose_verdict(r, "LATCHED",
        "%s gate fires over %.1fs (%.1f/s), signature PINNED at one value (0x%llx) the "
        "entire capture; %llu re-derivations",
        fmt_count(static_cast<double>(gates.size())).c_str(), dur_s, rate,
        static_cast<unsigned long long>(dom_sig), static_cast<unsigned long long>(rederiv));
  else
    compose_verdict(r, "LIVE",
        "%s gate fires over %.1fs (%.1f/s); %zu distinct signatures, %llu re-derivations; "
        "dominant signature 0x%llx held %.1f%% of the span",
        fmt_count(static_cast<double>(gates.size())).c_str(), dur_s, rate, seen.size(),
        static_cast<unsigned long long>(rederiv), static_cast<unsigned long long>(dom_sig), dom_pct);
  r.gauges.push_back({"montauk_analysis_field_gate_fires", "", static_cast<double>(gates.size())});
  r.gauges.push_back({"montauk_analysis_field_distinct_signatures", "", static_cast<double>(seen.size())});
  r.gauges.push_back({"montauk_analysis_field_rederivations", "", static_cast<double>(rederiv)});
  r.gauges.push_back({"montauk_analysis_field_dominant_dwell_pct", "", dom_pct});
  if (seen.size() <= 1 && gates.size() >= 4)
    r.offenders.push_back({"field-latched", "-", "", "distinct_signatures",
                           static_cast<double>(seen.size()), 2});
}

// REPORT iolat: per-syscall I/O completion latency, by the syscall the thread
// actually blocked in. A blocking pwrite64() on an O_DIRECT fd does not return
// until the write completed at the device, so its enter->exit time IS the
// block-I/O completion latency; io_getevents() is the async analog, and the
// iowait syscalls carry their own durations. The question it answers is
// whether any individual operation stalled, or this is ordinary queueing --
// which the scheduling reports cannot, since they see the WAITER's latency.
void derive_iolat(const Collected& in, ReportResult& r) {
  struct Call { uint64_t dur; int64_t tid; int64_t comm; };
  std::map<int64_t, std::vector<Call>> by;
  in.each([&](Collected::Row e) {
    if (e[1] > 0) by[e[0]].push_back({e.u(1), e[2], e[3]});
  });
  if (by.empty()) { compose_verdict(r, "NO-IO", "no tracked I/O completions in this trace"); return; }
  Detail syscalls = Detail::array(), worst_calls = Detail::array();
  size_t total = 0;
  int64_t worst_nr = 0;
  double worst_ms = -1, worst_p99 = 0;
  for (auto& [nr, calls] : by) {
    std::vector<uint64_t> durs;
    durs.reserve(calls.size());
    for (const Call& c : calls) durs.push_back(c.dur);
    sublimation_u64(durs.data(), durs.size());
    total += durs.size();
    const char* sys = io_syscall_name(static_cast<int32_t>(nr));
    const std::string base = std::string("montauk_analysis_iolat_") + sys + "_";
    r.gauges.push_back({metric_name(base + "count"), "", static_cast<double>(durs.size())});
    r.gauges.push_back({metric_name(base + "p50_ms"), "", q_ms(durs, 0.50)});
    r.gauges.push_back({metric_name(base + "p99_ms"), "", q_ms(durs, 0.99)});
    r.gauges.push_back({metric_name(base + "worst_ms"), "", ms(durs.back())});
    syscalls.arr.push_back(Detail::object()
        .put("syscall", Detail::text(sys)).put("completions", Detail::count(durs.size()))
        .put("p50_ms", Detail::of(q_ms(durs, 0.50))).put("p99_ms", Detail::of(q_ms(durs, 0.99)))
        .put("p999_ms", Detail::of(q_ms(durs, 0.999))).put("worst_ms", Detail::of(ms(durs.back()))));
    if (ms(durs.back()) > worst_ms) { worst_ms = ms(durs.back()); worst_nr = nr; worst_p99 = q_ms(durs, 0.99); }
    // The worst individual calls, named: exactly the outliers this report
    // exists to find, rather than a p999 that hides them.
    sublimation_order_u64(calls, true, [](const Call& c) { return c.dur; });
    const std::string label = std::string(sys) + "-slow";
    for (size_t i = 0; i < calls.size() && i < 5; ++i) {
      const double d = ms(calls[i].dur);
      const std::string comm = in.strings[static_cast<size_t>(calls[i].comm)];
      worst_calls.arr.push_back(Detail::object()
          .put("syscall", Detail::text(sys)).put("tid", Detail::count(static_cast<uint64_t>(calls[i].tid)))
          .put("comm", Detail::text(redact_comm(comm.c_str()))).put("ms", Detail::of(d)));
      // >1s is the severity line: an ordinary O_DIRECT/AIO completion under
      // load is sub-100ms; multi-second is the class this report catches.
      r.offenders.push_back({label, std::to_string(calls[i].tid), comm, "duration_ms", d,
                             d >= 1000.0 ? 2 : (d >= 100.0 ? 1 : 0)});
    }
  }
  Measures m;
  m.set("worst_ms", worst_ms);
  compose_verdict(r, pick_verdict({{"STALLED-IO", "worst_ms", 'G', 1000.0},
                                   {"SLOW-IO", "worst_ms", 'G', 100.0},
                                   {"NOMINAL", nullptr, 0, 0}}, m),
                  "%zu completion(s) across %zu syscall(s); worst %s %.3fms (its p99 %.3fms)",
                  total, by.size(), io_syscall_name(static_cast<int32_t>(worst_nr)), worst_ms, worst_p99);
  r.detail.emplace_back("syscalls", std::move(syscalls));
  r.detail.emplace_back("worst_calls", std::move(worst_calls));
}

// REPORT heapstk: deduplicated caller stacks from size-filtered allocation
// captures (MONTAUK_HEAP_STACK_SIZE). One run with the filter set produces the
// unique allocation sites of the victim size, ranked by count.
void derive_heapstk(const Collected& in, ReportResult& r) {
  struct Site { uint64_t count = 0, size = 0; int64_t comm = 0; std::vector<uint64_t> frames; };
  std::map<uint64_t, Site> sites;   // keyed by frame hash
  in.each([&](Collected::Row e) {
    const uint32_t n = static_cast<uint32_t>(std::min<uint64_t>(e.u(1), 8));
    uint64_t h = 1469598103934665603ull;
    for (uint32_t i = 0; i < n; ++i) { h ^= e.u(3 + i); h *= 1099511628211ull; }
    Site& s = sites[h];
    if (s.count == 0) {
      for (uint32_t i = 0; i < n; ++i) s.frames.push_back(e.u(3 + i));
      s.comm = e[2];
      s.size = e.u(0);
    }
    ++s.count;
  });
  if (sites.empty()) {
    compose_verdict(r, "NO-HEAPSTACK", "no heapstack captures in trace (set MONTAUK_HEAP_STACK_SIZE)");
    return;
  }
  std::vector<const Site*> rows;
  for (const auto& kv : sites) rows.push_back(&kv.second);
  sublimation_order_u64(rows, true, [](const Site* s) { return s->count; });
  compose_verdict(r, "HEAPSTACK", "%zu unique allocation site(s) for size=%" PRIu64,
                  rows.size(), rows.front()->size);
  Detail out = Detail::array();
  for (const Site* s : rows) {
    std::string fr;
    for (uint64_t f : s->frames) {
      char b[24];
      std::snprintf(b, sizeof b, "%s0x%" PRIx64, fr.empty() ? "" : " ", f);
      fr += b;
    }
    out.arr.push_back(Detail::object()
        .put("count", Detail::count(s->count)).put("size", Detail::count(s->size))
        .put("first_comm", Detail::text(redact_comm(in.strings[static_cast<size_t>(s->comm)].c_str())))
        .put("frames", Detail::text(fr)));
  }
  r.detail.emplace_back("sites", std::move(out));
}

// REPORT iowait: who was parked in a blocking I/O-wait syscall (poll, ppoll,
// epoll_wait, select, recvmsg...) when the trace ENDED. The I/O-bound analog of
// endstate: a thread asleep in poll() on a socket is parked on its data source
// the way an ntsync waiter is parked on a signaler, in a syscall that may never
// return. BPF emits a pending enter marker (result=-999) and a completion on
// return; an enter with no completion at trace end is parked.
void derive_iowait(const Collected& in, ReportResult& r) {
  struct Parked { bool open = false; int64_t since = 0, nr = 0, fd = -1, pid = 0, comm = 0; };
  std::map<int64_t, Parked> tids;
  const auto max_ts = static_cast<int64_t>(g_census.span_of({TRACE_EVT_IO}).second);
  in.each([&](Collected::Row e) {
    Parked& p = tids[e[4]];
    if (e[1] == kWaitEntrySentinel) p = {true, e.ts(), e[0], e[2], e[3], e[5]};
    else p.open = false;
  });
  std::vector<std::pair<int64_t, const Parked*>> parked;
  for (const auto& [tid, p] : tids) if (p.open) parked.emplace_back(tid, &p);
  if (parked.empty()) {
    compose_verdict(r, "NO-IOWAIT", "no threads parked in a blocking I/O-wait syscall at trace end");
    return;
  }
  sublimation_order_u64(parked, false,
                        [](const std::pair<int64_t, const Parked*>& p) { return static_cast<uint64_t>(p.second->since); });
  auto comm_of = [&](const Parked* p) { return redact_comm(in.strings[static_cast<size_t>(p->comm)].c_str()); };
  const Parked* lp = parked.front().second;
  compose_verdict(r, "IOWAIT-PARKED",
      "%zu thread(s) parked in a blocking I/O-wait at trace end "
      "(asleep on its data source -- e.g. poll() on a socket or pipe fd); "
      "longest tid=%u '%s' in %s(fd=%d) %.1fs",
      parked.size(), static_cast<uint32_t>(parked.front().first), comm_of(lp).c_str(),
      io_syscall_name(static_cast<int32_t>(lp->nr)), static_cast<int>(lp->fd),
      static_cast<double>(max_ts - lp->since) / 1e9);
  Detail out = Detail::array();
  for (const auto& [tid, p] : parked)
    out.arr.push_back(Detail::object()
        .put("tid", Detail::count(static_cast<uint64_t>(tid))).put("pid", Detail::count(static_cast<uint64_t>(p->pid)))
        .put("comm", Detail::text(comm_of(p))).put("syscall", Detail::text(io_syscall_name(static_cast<int32_t>(p->nr))))
        .put("fd", Detail::of(static_cast<double>(p->fd)))
        .put("parked_s", Detail::of(static_cast<double>(max_ts - p->since) / 1e9)));
  r.detail.emplace_back("parked", std::move(out));
}

const ReportDef kClassMix = {"classmix", {{"sched.enqueue", {"pid", "score"}}}, false, derive_classmix};
const ReportDef kFieldPersist = {"field-persist", {{"sched.field_gate", {"score", "sub_idx"}}}, false, derive_field_persist};
const ReportDef kIolat = {"iolat", {{"io", {"syscall_nr", "duration_ns", "tid", "comm"}, {"duration_ns>0"}}},
                          false, derive_iolat};
const ReportDef kHeapstk = {"heapstk", {{"heapstk", {"size", "stack_depth", "comm", "frame0", "frame1", "frame2",
                                                     "frame3", "frame4", "frame5", "frame6", "frame7"}}},
                            false, derive_heapstk};
const ReportDef kIowait = {"iowait",
                           {{"io.poll,ppoll,epoll_wait,epoll_pwait,recvmsg,recvfrom,select,pselect6,ioctl",
                             {"syscall_nr", "result", "fd", "pid", "tid", "comm"}}},
                           false, derive_iowait};

// REPORT seat: self-preemption and CPU-seat anchoring from the per-CPU SWITCH_IN
// stream every scheduler emits. A task's stints (SWITCH_INs) over its wakes
// (WAKE2RUNs) expose self-preemption -- rescheduled without a fresh wake, a cost
// wake2run alone cannot show. Seat dominance is the share of a task's stints on
// its most frequent CPU: 1.0 is anchored, low is churning across CPUs.
void derive_seat(const Collected& in, ReportResult& r) {
  std::map<int64_t, uint64_t> stints, wakes;
  std::map<int64_t, std::map<int64_t, uint64_t>> cpu_stints;
  uint64_t total_wakes = 0, floored = 0;
  for (const auto& [k, n] : in.tallies[0]) { stints[k.a] += n; cpu_stints[k.a][k.b] += n; }
  for (size_t s = 1; s <= 2; ++s)
    for (const auto& [k, n] : in.tallies[s]) {
      wakes[k.a] += n;
      total_wakes += n;
      if (s == 1) floored += n;
    }
  struct Row { int64_t pid; uint64_t stints, wakes; double ratio, dom; int64_t cpu; };
  std::vector<Row> rows;
  for (const auto& [pid, st] : stints) {
    if (st < 8) continue;  // one-off scheduling, not churn
    const auto w = wakes.find(pid);
    const uint64_t wk = w == wakes.end() ? 0 : w->second;
    const double ratio = wk ? static_cast<double>(st) / static_cast<double>(wk) : static_cast<double>(st);
    uint64_t top = 0;
    int64_t top_cpu = 0;
    for (const auto& [cpu, c] : cpu_stints[pid]) if (c > top) { top = c; top_cpu = cpu; }
    rows.push_back({pid, st, wk, ratio, static_cast<double>(top) / static_cast<double>(st), top_cpu});
  }
  sublimation_order_f64(rows, true, [](const Row& x) { return x.ratio; });
  const double fl = total_wakes ? static_cast<double>(floored) / static_cast<double>(total_wakes) : 0.0;
  size_t sp = 0;
  for (const Row& x : rows) if (x.ratio > 1.5) ++sp;
  if (rows.empty()) compose_verdict(r, "NONE", "no SWITCH_IN stints to rank");
  else compose_verdict(r, sp ? "SELF-PREEMPTING" : "SEATED",
                       "%zu ranked pids, %zu self-preempting (stints/wakes > 1.5); "
                       "floored-wake share %.1f%%", rows.size(), sp, fl * 100.0);
  r.gauges.push_back({"montauk_analysis_seat_floored_wake_ratio", "", fl});
  r.gauges.push_back({"montauk_analysis_seat_self_preempting", "", static_cast<double>(sp)});
  Detail top = Detail::array();
  for (size_t k = 0; k < rows.size() && k < 8 && rows[k].ratio > 1.5; ++k) {
    const Row& x = rows[k];
    r.offenders.push_back({"self-preempt", "tid=" + std::to_string(x.pid), "", "stint_wake_ratio",
                           x.ratio, x.ratio > 4.0 ? 2 : (x.ratio > 2.0 ? 1 : 0)});
    top.arr.push_back(Detail::object()
        .put("tid", Detail::count(static_cast<uint64_t>(x.pid))).put("stints", Detail::count(x.stints))
        .put("wakes", Detail::count(x.wakes)).put("ratio", Detail::of(x.ratio))
        .put("seat_pct", Detail::of(x.dom * 100.0)).put("cpu", Detail::count(static_cast<uint64_t>(x.cpu))));
  }
  if (!top.arr.empty()) r.detail.emplace_back("self_preempting", std::move(top));
}

// REPORT matrix-profile: the unsupervised complement to the hand-written
// lenses. Bins the scheduling-event stream into a fixed set of windows and runs
// sublimation's matrix profile over the per-window rate, surfacing the run's
// discord (the most anomalous window) and motif (the most recurring pattern)
// without being told what to look for.
void derive_matrix_profile(const Collected& in, ReportResult& r) {
  constexpr size_t NBINS = 128, WIN = 8;
  std::vector<uint64_t> ts;
  ts.reserve(in.rows());
  in.each([&](Collected::Row e) { ts.push_back(static_cast<uint64_t>(e.ts())); });
  const uint64_t n_ev = ts.size();
  auto none = [&] { compose_verdict(r, "NO-PROFILE", "too few scheduling events for a profile"); };
  if (n_ev < NBINS * 2) { none(); return; }
  sublimation_u64(ts.data(), ts.size());
  const uint64_t t0 = ts.front(), t1 = ts.back();
  if (t1 <= t0) { none(); return; }
  const uint64_t span = t1 - t0;
  // 128 bins, not fractal's ~120k: STOMP's cost scales with window count.
  uint64_t w = span / NBINS;
  if (w == 0) w = 1;
  std::vector<double> series = bin_rate_series(ts, t0, w, NBINS);
  const size_t L = NBINS - WIN + 1;
  std::vector<double> mp(L);
  std::vector<int64_t> mpi(L);
  if (sublimation_matrix_profile(series.data(), NBINS, WIN, mp.data(), mpi.data()) != 0) { none(); return; }
  size_t dbin = 0, mbin = 0;
  double sum = 0.0;
  for (size_t i = 0; i < L; i++) {
    sum += mp[i];
    if (mp[i] > mp[dbin]) dbin = i;
    if (mp[i] < mp[mbin]) mbin = i;
  }
  const double bin_ms = static_cast<double>(span) / static_cast<double>(NBINS) / 1e6;
  const double mean = sum / static_cast<double>(L);
  r.gauges.push_back({"montauk_analysis_matrix_profile_discord_score", "", mp[dbin]});
  r.gauges.push_back({"montauk_analysis_matrix_profile_mean", "", mean});
  r.gauges.push_back({"montauk_analysis_matrix_profile_discord_ms", "", static_cast<double>(dbin) * bin_ms});
  // The token is the discord's ratio to the mean: how far the least-like-
  // anything-else window stands out. A flat trace never promotes noise.
  Measures m;
  m.set("ratio", mean > 0.0 ? mp[dbin] / mean : 0.0);
  compose_verdict(r, pick_verdict({{"DISCORD-STRONG", "ratio", 'G', 3.0},
                                   {"DISCORD", "ratio", 'G', 1.5},
                                   {"UNIFORM", nullptr, 0, 0}}, m),
      "%llu sched events over %zu windows of %.2fms; discord (most "
      "anomalous) window %lld at %.0fms, profile %.2f vs mean %.2f; motif "
      "(most recurring) windows %lld~%lld at distance %.2f",
      static_cast<unsigned long long>(n_ev), NBINS, bin_ms, static_cast<long long>(dbin),
      static_cast<double>(dbin) * bin_ms, mp[dbin], mean, static_cast<long long>(mbin),
      static_cast<long long>(mpi[mbin]), mp[mbin]);
  if (mean > 0.0 && m.get("ratio") >= 1.5) {
    char idb[32];
    std::snprintf(idb, sizeof(idb), "%.0fms", static_cast<double>(dbin) * bin_ms);
    r.offenders.push_back({"discord", idb, "", "profile_vs_mean", m.get("ratio"), m.get("ratio") >= 3.0 ? 2 : 1});
  }
}

// REPORT work-conservation: per-CPU idle strands and how each one ENDED. A
// strand is a long gap between dispatches on one CPU; the gap-ending dispatch
// is a PULL if that task last ran on a DIFFERENT CPU (it migrated in), or a
// LOCAL-REWAKE if it last ran on this one. A high local-rewake share means idle
// CPUs sit on remote runnable work instead of pulling it.
void derive_work_conservation(const Collected& in, ReportResult& r) {
  constexpr uint64_t kStrandNs = 50000000ULL;  // 50ms: a strand, not jitter
  std::unordered_map<int64_t, int64_t> last_pick, last_cpu_of;
  std::vector<uint64_t> strands;
  uint64_t pulled = 0, local = 0;
  in.each([&](Collected::Row e) {
    const int64_t cpu = e[0], pid = e[1], ts = e.ts();
    auto it = last_pick.find(cpu);
    if (it != last_pick.end() && ts > it->second && static_cast<uint64_t>(ts - it->second) >= kStrandNs) {
      strands.push_back(static_cast<uint64_t>(ts - it->second));
      auto p = last_cpu_of.find(pid);
      if (p != last_cpu_of.end() && p->second != cpu) ++pulled; else ++local;
    }
    last_pick[cpu] = ts;
    last_cpu_of[pid] = cpu;
  });
  if (strands.empty()) {
    compose_verdict(r, "CONSERVING", "no idle strands >= 50ms (work-conserving, or PICK events not streamed)");
    return;
  }
  sublimation_u64(strands.data(), strands.size());
  const uint64_t n = pulled + local;
  Measures m;
  m.set("pull_pct", n ? 100.0 * static_cast<double>(pulled) / static_cast<double>(n) : 0.0);
  m.set("local_pct", n ? 100.0 * static_cast<double>(local) / static_cast<double>(n) : 0.0);
  // The token names WHICH WAY the gap closes, which is the actionable half.
  compose_verdict(r, pick_verdict({{"LOCAL-REWAKE-GAP", "local_pct", 'G', 66.0},
                                   {"PULL-CLOSED", "pull_pct", 'G', 66.0},
                                   {"MIXED-CLOSE", nullptr, 0, 0}}, m),
      "%s idle strands (>=50ms); p50 %.1fms p99 %.1fms worst %.1fms; "
      "closed by PULL %.0f%% / LOCAL-REWAKE %.0f%%",
      fmt_count(static_cast<double>(strands.size())).c_str(), q_ms(strands, 0.50),
      q_ms(strands, 0.99), ms(strands.back()), m.get("pull_pct"), m.get("local_pct"));
  push_quantile_gauges(r.gauges, "montauk_analysis_idle_strand_ms",
                       {{"0.5", q_ms(strands, 0.50)}, {"0.99", q_ms(strands, 0.99)}, {"worst", ms(strands.back())}});
  r.gauges.push_back({"montauk_analysis_strand_pull_pct", "", m.get("pull_pct")});
  r.gauges.push_back({"montauk_analysis_strand_count", "", static_cast<double>(strands.size())});
  // Aggregate, not per-CPU: the hot-cpu offender carries the localization.
  r.offenders.push_back({"idle-strand", "-", "", "strand_count", static_cast<double>(strands.size()),
                         (strands.size() >= 10 && m.get("local_pct") > 50.0) ? 2 : (strands.size() >= 3 ? 1 : 0)});
}

// REPORT placement-race: of the wakes over the floor (one tick by default,
// --floor-us), how many had an IDLE CPU available at the wake instant? An idle
// CPU free means placement LOST THE RACE -- the wakee queued behind a busy CPU
// while another sat idle, so the fix is winning the race. None free means the
// box was GENUINELY SATURATED, and the fix is on the busy CPU. Built from the
// per-CPU idle boundaries, queried at each floored wake's became-runnable
// instant.
void derive_placement_race(const Collected& in, ReportResult& r) {
  std::unordered_map<int64_t, std::vector<std::pair<uint64_t, uint8_t>>> idle;
  std::vector<std::pair<uint64_t, int64_t>> floored;   // (wake instant, run cpu)
  in.each([&](Collected::Row e) {
    if (e.src() == 0) { idle[e[0]].push_back({static_cast<uint64_t>(e.ts()), static_cast<uint8_t>(e[1] ? 1 : 0)}); return; }
    const uint64_t wait = e.u(1);
    if (wait < g_qual_floor_ns) return;
    const uint64_t run = static_cast<uint64_t>(e.ts());
    floored.push_back({run > wait ? run - wait : 0, e[0]});
  });
  // NO-IDLE-STREAM is a CAPTURE limitation and must not read as clean: the
  // difference between "re-capture" and "this run was clean".
  if (idle.empty()) {
    compose_verdict(r, "NO-IDLE-STREAM", "no CPU_IDLE events -- trace captured by a montauk "
                    "without per-CPU idle streaming; re-capture to resolve");
    return;
  }
  if (floored.empty()) {
    compose_verdict(r, "NONE", "no wakeups over the %.0fus floor -- nothing to attribute",
                    static_cast<double>(g_qual_floor_ns) / 1000.0);
    return;
  }
  for (auto& kv : idle)
    sublimation_order_u64(kv.second, false, [](const std::pair<uint64_t, uint8_t>& p) { return p.first; });
  // Idle at t: the flag of the last boundary at or before t; none -> busy.
  auto idle_at = [](const std::vector<std::pair<uint64_t, uint8_t>>& ev, uint64_t t) {
    if (ev.empty() || t < ev.front().first) return false;
    size_t lo = 0, hi = ev.size();
    while (lo < hi) { const size_t mid = lo + (hi - lo) / 2; if (ev[mid].first <= t) lo = mid + 1; else hi = mid; }
    return lo > 0 && ev[lo - 1].second == 1;
  };
  uint64_t miss = 0, saturated = 0, idle_sum = 0;
  for (const auto& [wake, run_cpu] : floored) {
    uint32_t idle_n = 0;
    for (int64_t c = 0; c <= g_sched_max_cpu; ++c) {
      if (c == run_cpu) continue;  // count BETTER homes than where it waited
      auto it = idle.find(c);
      if (it != idle.end() && idle_at(it->second, wake)) ++idle_n;
    }
    if (idle_n) { ++miss; idle_sum += idle_n; } else ++saturated;
  }
  const uint64_t n = miss + saturated;
  Measures m;
  m.set("miss_pct", 100.0 * static_cast<double>(miss) / static_cast<double>(n));
  m.set("sat_pct", 100.0 * static_cast<double>(saturated) / static_cast<double>(n));
  const double avg_idle = miss ? static_cast<double>(idle_sum) / static_cast<double>(miss) : 0.0;
  compose_verdict(r, pick_verdict({{"PLACEMENT-MISS", "miss_pct", 'G', 66.0},
                                   {"SATURATED", "sat_pct", 'G', 66.0},
                                   {"MIXED", nullptr, 0, 0}}, m),
      "%s wakes over the %.0fus floor; PLACEMENT-MISS %.0f%% "
      "(idle CPU was free) / SATURATED %.0f%% (all busy); "
      "avg %.1f idle CPUs free at a miss",
      fmt_count(static_cast<double>(n)).c_str(), static_cast<double>(g_qual_floor_ns) / 1000.0,
      m.get("miss_pct"), m.get("sat_pct"), avg_idle);
  r.gauges.push_back({"montauk_analysis_floored_wakes", "", static_cast<double>(n)});
  r.gauges.push_back({"montauk_analysis_placement_miss_pct", "", m.get("miss_pct")});
  r.gauges.push_back({"montauk_analysis_reroutable_pct", "", m.get("miss_pct")});
  r.gauges.push_back({"montauk_analysis_saturated_pct", "", m.get("sat_pct")});
  r.gauges.push_back({"montauk_analysis_avg_idle_at_miss", "", avg_idle});
}

// REPORT slice: per-CPU dispatched-slice length -- the interval between
// consecutive picks on one CPU, idle strands (>10ms) excluded. If the
// saturation tail is a wakee waiting behind N tasks each running a long slice,
// this is the per-slice multiplier: tail ~ pass-overs x slice.
void derive_slice(const Collected&, ReportResult& r) {
  constexpr uint64_t kStrandNs = 10000000ULL;
  std::vector<uint64_t> slices;
  std::vector<std::pair<uint64_t, uint64_t>> tl;   // (slice start, duration), for the trajectory
  for (const auto& kv : g_sched_picks.active()) {
    const auto& v = kv.second;
    for (size_t i = 1; i < v.size(); ++i) {
      const uint64_t d = v[i].ts - v[i - 1].ts;
      if (d > 0 && d < kStrandNs) { slices.push_back(d); tl.push_back({v[i - 1].ts, d}); }
    }
  }
  // A capture limitation, not a finding: the PICK stream needs --sched-detail.
  if (slices.empty()) { compose_verdict(r, "NO-PICK-STREAM", "no slices (PICK stream absent)"); return; }
  sublimation_u64(slices.data(), slices.size());
  // TRAJECTORY: segment the run by wall-clock, take each segment's median slice
  // in TIME order, and classify the sequence. A quantum that tracks load
  // coherently reads SORTED / NEARLY_SORTED / PHASED; one that oscillates reads
  // RANDOM -- the control loop hunting rather than converging.
  constexpr size_t kSegs = 8;
  std::vector<uint64_t> seg_med;
  bool traj = false;
  sub_profile_t tp{};
  if (tl.size() >= 2 * kSegs) {
    sublimation_order_u64(tl, false, [](const std::pair<uint64_t, uint64_t>& p) { return p.first; });
    const uint64_t t0 = tl.front().first, t1 = tl.back().first;
    if (t1 > t0) {
      const uint64_t span = t1 - t0;
      std::vector<uint64_t> bucket;
      for (size_t g = 0; g < kSegs; ++g) {
        const uint64_t lo = t0 + span * g / kSegs, hi = t0 + span * (g + 1) / kSegs;
        bucket.clear();
        for (const auto& pr : tl)
          if (pr.first >= lo && (pr.first < hi || (g + 1 == kSegs && pr.first <= hi))) bucket.push_back(pr.second);
        if (bucket.empty()) continue;
        sublimation_u64(bucket.data(), bucket.size());
        seg_med.push_back(bucket[bucket.size() / 2]);
      }
      if (seg_med.size() >= 3) { tp = sublimation_classify_u64(seg_med.data(), seg_med.size()); traj = true; }
    }
  }
  double mean = 0;
  for (uint64_t s : slices) mean += static_cast<double>(s);
  mean /= static_cast<double>(slices.size());
  // The TAIL is the finding: a p99 an order of magnitude past the p50 is a
  // different regime from one that tracks it.
  const double p50 = q_us(slices, 0.50), p99 = q_us(slices, 0.99);
  compose_verdict(r, p50 > 0.0 && p99 >= 10.0 * p50 ? "HEAVY-TAIL" : "EVEN",
                  "%s dispatched slices; p50 %.1fus p90 %.1fus p99 %.1fus worst %.1fus; mean %.1fus",
                  fmt_count(static_cast<double>(slices.size())).c_str(), p50, q_us(slices, 0.90), p99,
                  us(slices.back()), mean / 1000.0);
  push_quantile_gauges(r.gauges, "montauk_analysis_slice_us",
                       {{"0.5", p50}, {"0.99", p99}, {"worst", us(slices.back())}});
  if (traj) {
    r.gauges.push_back({"montauk_analysis_slice_trajectory_inversion", "", static_cast<double>(tp.inversion_ratio)});
    Detail t = Detail::object();
    std::string meds;
    for (uint64_t m : seg_med) meds += (meds.empty() ? "" : " ") + std::to_string(static_cast<long long>(us(m)));
    t.put("segment_p50_us", Detail::text(meds)).put("shape", Detail::text(disorder_name(tp.disorder)))
     .put("inversion", Detail::of(static_cast<double>(tp.inversion_ratio)));
    r.detail.emplace_back("trajectory", std::move(t));
  }
  // PREEMPT OVERRUN: slices that ran far past a ~1ms quantum uninterrupted are
  // hogs the tick preempt never touched.
  auto over = [&](uint64_t ns) {
    const size_t k = slices.size() - sublimation_searchsorted_u64(slices.data(), slices.size(), ns, 0);
    return Detail::object().put("slices", Detail::count(k))
        .put("pct", Detail::of(100.0 * static_cast<double>(k) / static_cast<double>(slices.size())));
  };
  r.detail.emplace_back("overrun", Detail::object().put("over_2ms", over(2000000ULL))
                                        .put("over_5ms", over(5000000ULL)).put("over_8ms", over(8000000ULL)));
}

// REPORT kick-latency: each KICK_ISSUE paired against the next RESCHED on the
// SAME cpu: was a kick for a CPU that went dark delivered, or swallowed? A kick
// with no resched before the next kick (or trace end) is UNANSWERED; one that
// landed within 5ms of a successful TICK_STOP on that cpu raced the CPU's own
// idle entry. A SELF-kick (issuer == target) is the scheduler preempting
// itself -- it cannot buy parallelism, only reorder its own queue.
void derive_kick_latency(const Collected& in, ReportResult& r) {
  struct Ev { uint64_t ts; uint32_t issuer_or_ok; uint64_t aux; };
  std::unordered_map<int64_t, std::vector<Ev>> kicks, tick_stop;
  std::unordered_map<int64_t, std::vector<uint64_t>> resched;
  in.each([&](Collected::Row e) {
    const uint64_t ts = static_cast<uint64_t>(e.ts());
    if (e.src() == 0) kicks[e[0]].push_back({ts, static_cast<uint32_t>(e[1]), e.u(2)});
    else if (e.src() == 1) resched[e[0]].push_back(ts);
    else tick_stop[e[0]].push_back({ts, static_cast<uint32_t>(e[1]), e.u(2)});
  });
  const uint64_t last_ts = g_sched_max_ts;
  uint64_t total = 0, unanswered = 0, raced = 0, self_total = 0, self_preempt = 0;
  std::vector<uint64_t> lat;
  struct Miss { int64_t cpu; uint64_t ts; bool tickless; };
  std::vector<Miss> misses;
  std::unordered_map<int64_t, uint64_t> unanswered_by_cpu, self_preempt_by_cpu;
  for (auto& [cpu, kv] : kicks) {
    std::vector<uint64_t> rs = resched[cpu];
    if (!rs.empty()) sublimation_u64(rs.data(), rs.size());
    std::vector<Ev> ks = kv;
    sublimation_order_u64(ks, false, [](const Ev& e) { return e.ts; });
    std::vector<Ev> stop = tick_stop[cpu];
    sublimation_order_u64(stop, false, [](const Ev& e) { return e.ts; });
    uint64_t cpu_unanswered = 0;
    for (size_t i = 0; i < ks.size(); ++i) {
      const uint64_t kick = ks[i].ts, bound = i + 1 < ks.size() ? ks[i + 1].ts : last_ts;
      ++total;
      // SCX_KICK_PREEMPT is 0x2 in the scx ABI; aux is the flag bitmask.
      if (ks[i].issuer_or_ok == static_cast<uint32_t>(cpu)) {
        ++self_total;
        if (ks[i].aux & 0x2ULL) { ++self_preempt; ++self_preempt_by_cpu[cpu]; }
      }
      const size_t ri = sublimation_searchsorted_u64(rs.data(), rs.size(), kick, 0);
      if (ri < rs.size() && rs[ri] <= bound) { lat.push_back(rs[ri] - kick); continue; }
      ++unanswered;
      ++cpu_unanswered;
      bool tickless = false;
      for (auto it = stop.rbegin(); it != stop.rend(); ++it) {
        if (it->ts > kick) continue;
        if (kick - it->ts <= 5'000'000ULL && it->issuer_or_ok == 1) tickless = true;
        break;
      }
      if (tickless) ++raced;
      misses.push_back({cpu, kick, tickless});
    }
    if (cpu_unanswered) unanswered_by_cpu[cpu] = cpu_unanswered;
  }
  if (!lat.empty()) sublimation_u64(lat.data(), lat.size());
  sublimation_order_u64(misses, true, [](const Miss& m) { return m.tickless ? 1u : 0u; });
  // Availability bit: 0 => no kick capture in this trace, so a consumer never
  // reads absence as a measured zero.
  r.gauges.push_back({"montauk_analysis_kick_captured", "", kicks.empty() ? 0.0 : 1.0});
  if (kicks.empty()) {
    compose_verdict(r, "NONE", "no kicks captured (scx_bpf_kick_cpu never fired, or "
                               "MONTAUK_SCX_STORM off -- the storm probes are not attached)");
    return;
  }
  auto pct = [&](uint64_t x) { return total ? 100.0 * static_cast<double>(x) / static_cast<double>(total) : 0.0; };
  compose_verdict(r, unanswered == 0 ? "ALL-ANSWERED" : raced ? "UNANSWERED-TICKSTOP-RACE" : "UNANSWERED",
      "%" PRIu64 " kicks, %" PRIu64 " unanswered (no resched observed "
      "before the next kick or trace end), %" PRIu64
      " of those raced a fresh tick-stop; %.1f%% were SELF-kicks (issuer == "
      "target), %.1f%% self-preempts",
      total, unanswered, raced, pct(self_total), pct(self_preempt));
  r.gauges.push_back({"montauk_analysis_kicks_total", "", static_cast<double>(total)});
  r.gauges.push_back({"montauk_analysis_kicks_unanswered", "", static_cast<double>(unanswered)});
  r.gauges.push_back({"montauk_analysis_kicks_tickless_raced", "", static_cast<double>(raced)});
  r.gauges.push_back({"montauk_analysis_kick_unanswered_pct", "", pct(unanswered)});
  r.gauges.push_back({"montauk_analysis_kicks_self", "", static_cast<double>(self_total)});
  r.gauges.push_back({"montauk_analysis_kicks_self_preempt", "", static_cast<double>(self_preempt)});
  r.gauges.push_back({"montauk_analysis_kick_self_pct", "", pct(self_total)});
  r.gauges.push_back({"montauk_analysis_kick_self_preempt_pct", "", pct(self_preempt)});
  if (!lat.empty())
    push_quantile_gauges(r.gauges, "montauk_analysis_kick_resched_us",
                         {{"0.5", q_us(lat, 0.50)}, {"0.99", q_us(lat, 0.99)}, {"worst", q_us(lat, 1.0)}});
  for (const auto& [cpu, n] : unanswered_by_cpu)
    r.offenders.push_back({"kick-latency", "cpu" + std::to_string(cpu), "", "unanswered_kicks",
                           static_cast<double>(n), n >= 3 ? 2 : 1});
  // A CPU carrying a tenth of every kick as its own preempt ranks; a share,
  // not a count, so the threshold survives any trace length or CPU count.
  for (const auto& [cpu, n] : self_preempt_by_cpu)
    r.offenders.push_back({"kick-latency", "cpu" + std::to_string(cpu), "", "self_preempts",
                           static_cast<double>(n), (total && n * 10 >= total) ? 2 : 1});
  Detail mt = Detail::array();
  for (size_t i = 0; i < misses.size() && i < 20; ++i)
    mt.arr.push_back(Detail::object().put("cpu", Detail::count(static_cast<uint64_t>(misses[i].cpu)))
                         .put("t_ms", Detail::of(ms(misses[i].ts)))
                         .put("tick_stop_raced", Detail::flag(misses[i].tickless)));
  if (!mt.arr.empty()) r.detail.emplace_back("unanswered", std::move(mt));
}

// REPORT service: per-PID CPU service (the sum of its dispatched slices) and
// its SKEW. A fair-share / lag term helps only if service is skewed -- a few
// tasks over-consume, so deprioritizing them frees the starved wakee. If every
// task gets roughly its fair share, there is nothing to redistribute.
void derive_service(const Collected&, ReportResult& r) {
  constexpr uint64_t kStrandNs = 10000000ULL;
  std::unordered_map<int, uint64_t> by_pid;
  for (const auto& kv : g_sched_picks.active()) {
    const auto& v = kv.second;
    for (size_t i = 1; i < v.size(); ++i) {
      const uint64_t d = v[i].ts - v[i - 1].ts;
      if (d > 0 && d < kStrandNs) by_pid[v[i - 1].pid] += d;
    }
  }
  if (by_pid.empty()) { compose_verdict(r, "NO-SERVICE", "no service (PICK stream absent)"); return; }
  std::vector<uint64_t> svc;
  for (const auto& kv : by_pid) svc.push_back(kv.second);
  sublimation_u64(svc.data(), svc.size());
  uint64_t total = 0;
  for (uint64_t s : svc) total += s;
  const size_t np = svc.size();
  uint64_t top5 = 0;
  for (size_t k = 0; k < 5 && k < np; ++k) top5 += svc[np - 1 - k];
  const double top1_pct = total ? 100.0 * static_cast<double>(svc.back()) / static_cast<double>(total) : 0.0;
  const double fair = static_cast<double>(total) / static_cast<double>(np);
  compose_verdict(r, top1_pct >= 50.0 ? "SKEWED" : "EVEN",
                  "%s PIDs ran; per-PID service p50 %.1fms p99 %.1fms max %.1fms; fair-share %.1fms",
                  fmt_count(static_cast<double>(np)).c_str(), q_ms(svc, 0.50), q_ms(svc, 0.99),
                  ms(svc.back()), fair / 1e6);
  r.gauges.push_back({"montauk_analysis_service_top1_pct", "", top1_pct});
  r.gauges.push_back({"montauk_analysis_service_pids", "", static_cast<double>(np)});
  r.detail.emplace_back("skew", Detail::object()
      .put("top1_pct", Detail::of(top1_pct))
      .put("top5_pct", Detail::of(total ? 100.0 * static_cast<double>(top5) / static_cast<double>(total) : 0.0))
      .put("p99_over_fair", Detail::of(fair > 0 ? q_ms(svc, 0.99) * 1e6 / fair : 0.0)));
}

// Stints by (pid, cpu); wakes by pid, the sub-tick ones counted apart.
const ReportDef kSeat = {"seat",
                         {{"sched.switch_in", {"pid", "cpu"}, {}, false, true},
                          {"sched.wake2run", {"pid"}, {"runtime_ns<900000"}, false, true},
                          {"sched.wake2run", {"pid"}, {}, false, true}},
                         false, derive_seat};
const ReportDef kMatrixProfile = {"matrix-profile", {{"sched", {}}}, false, derive_matrix_profile};
const ReportDef kWorkConservation = {"work-conservation", {{"sched.pick", {"cpu", "pid"}}}, false,
                                     derive_work_conservation};
const ReportDef kPlacementRace = {"placement-race", {{"sched.cpu_idle", {"cpu", "sub_idx"}},
                                                     {"sched.wake2run", {"cpu", "runtime_ns"}}},
                                  true, derive_placement_race};
const ReportDef kSlice = {"slice", {}, true, derive_slice};
const ReportDef kKickLatency = {"kick-latency", {{"sched.kick_issue", {"cpu", "last_cpu", "score"}},
                                                 {"sched.resched", {"cpu"}},
                                                 {"sched.tick_stop", {"cpu", "sub_idx", "score"}}},
                                true, derive_kick_latency};
const ReportDef kService = {"service", {}, true, derive_service};

// REPORT summary: the census -- every record by type and subtype, the span the
// trace covers, and the dispatch and preempt rates.
void derive_summary(const Collected&, ReportResult& r) {
  struct Row { std::string type, sub; uint64_t n; };
  std::vector<Row> rows;
  auto row = [&](const char* t, std::string sub, uint64_t n) { if (n) rows.push_back({t, std::move(sub), n}); };
  auto op = [](uint32_t type, int64_t o) { return g_census.op(type, o); };
  const auto by_type = g_census.by_type();
  auto of_type = [&](uint32_t type) {
    auto it = by_type.find(type);
    return it == by_type.end() ? uint64_t{0} : it->second;
  };
  for (uint8_t o = 0; o < 14; ++o) {
    row("NTSYNC", ntsync_op_name(o), op(TRACE_EVT_NTSYNC, o));
    row("NTSYNC", std::string(ntsync_op_name(o)) + ".enter", op(TRACE_EVT_NTSYNC, Census::kEntry + o));
  }
  const auto& io_ops = g_census.op_n[TRACE_EVT_IO];
  for (size_t nr = 0; nr < io_ops.size(); ++nr) {
    const char* nm = io_syscall_name(static_cast<int32_t>(nr));
    row("IO", std::strcmp(nm, "?") == 0 ? "nr=" + std::to_string(nr) : std::string(nm), io_ops[nr]);
  }
  for (uint32_t o = 1; o < MONTAUK_SCHED_OP_MAX; ++o) row("SCHED", sched_op_name(o), op(TRACE_EVT_SCHED, o));
  row("HEAP", "malloc", op(TRACE_EVT_HEAP, HEAP_OP_MALLOC));
  row("HEAP", "free", op(TRACE_EVT_HEAP, HEAP_OP_FREE));
  row("HEAP", "realloc", op(TRACE_EVT_HEAP, HEAP_OP_REALLOC));
  row("HEAP", "calloc", op(TRACE_EVT_HEAP, HEAP_OP_CALLOC));
  row("SIGNAL", "deliver", op(TRACE_EVT_SIGNAL, SIGEVT_DELIVER));
  row("SIGNAL", "exit_abnormal", op(TRACE_EVT_SIGNAL, SIGEVT_EXIT_ABNL));
  row("ABORT", "__assert_fail", op(TRACE_EVT_ABORT, ABORT_FN_ASSERT_FAIL));
  row("ABORT", "__libc_message", op(TRACE_EVT_ABORT, ABORT_FN_LIBC_MESSAGE));
  row("ABORT", "abort", op(TRACE_EVT_ABORT, ABORT_FN_ABORT));
  row("HEAPSTK", "size_filtered", of_type(TRACE_EVT_HEAPSTACK));
  row("MMAP", "file_backed", of_type(TRACE_EVT_MMAP));
  row("KSTRAND", "pcpu_kthread", of_type(TRACE_EVT_KSTRAND));
  row("FORK", "", of_type(TRACE_EVT_FORK));
  row("EXEC", "", of_type(TRACE_EVT_EXEC));
  row("EXIT", "", of_type(TRACE_EVT_EXIT));
  row("COMM", "change", of_type(TRACE_EVT_COMM_CHANGE));
  for (const auto& [nm, n] : g_census.provider) row("PROVIDER", nm, n);
  // Every other type the stream carried. One montauk knows by name is named;
  // only a type it has no name for is UNKNOWN.
  static constexpr uint32_t kRowed[] = {TRACE_EVT_NTSYNC, TRACE_EVT_IO, TRACE_EVT_SCHED, TRACE_EVT_HEAP,
                                        TRACE_EVT_SIGNAL, TRACE_EVT_ABORT, TRACE_EVT_HEAPSTACK, TRACE_EVT_MMAP,
                                        TRACE_EVT_KSTRAND, TRACE_EVT_FORK, TRACE_EVT_EXEC, TRACE_EVT_EXIT,
                                        TRACE_EVT_COMM_CHANGE, TRACE_EVT_PROVIDER};
  std::vector<Row> unknown;
  for (const auto& [t, n] : by_type) {
    if (std::find(std::begin(kRowed), std::end(kRowed), t) != std::end(kRowed)) continue;
    std::string nm = evt_type_name(t);
    if (nm == "unknown") { row("UNKNOWN", "type=" + std::to_string(t), n); continue; }
    for (char& ch : nm) ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    unknown.push_back({nm, "", n});
  }
  for (auto& u : unknown) rows.push_back(std::move(u));

  const auto [lo, hi] = g_census.span_of({TRACE_EVT_NTSYNC, TRACE_EVT_IO, TRACE_EVT_SCHED, TRACE_EVT_HEAP,
                                          TRACE_EVT_SIGNAL, TRACE_EVT_MMAP, TRACE_EVT_ABORT,
                                          TRACE_EVT_HEAPSTACK, TRACE_EVT_KSTRAND, TRACE_EVT_PROVIDER});
  const double dur_s = hi > lo ? static_cast<double>(hi - lo) / 1e9 : 0.0;
  const double eps = dur_s > 0.0 ? static_cast<double>(g_census.total) / dur_s : 0.0;
  if (g_census.total == 0 || rows.empty()) {
    compose_verdict(r, "EMPTY", "empty trace — no events");
  } else {
    const Row* dom = &rows[0];
    for (const Row& x : rows) if (x.n > dom->n) dom = &x;
    compose_verdict(r, "EVENTS", "%s events in %.1f s (%s/s), dominated by %s %s (%.0f%%)",
                    fmt_count(static_cast<double>(g_census.total)).c_str(), dur_s, fmt_count(eps).c_str(),
                    dom->type.c_str(), dom->sub.c_str(),
                    100.0 * static_cast<double>(dom->n) / static_cast<double>(g_census.total));
  }
  for (const Row& x : rows)
    r.gauges.push_back({"montauk_analysis_events_total",
                        "type=\"" + x.type + "\",subtype=\"" + x.sub + "\"", static_cast<double>(x.n)});
  if (dur_s > 0.0) {
    // SWITCH_IN stands in for PICK when the scheduler exports no pick
    // tracepoint, which no sched_ext scheduler does.
    const uint64_t picks = op(TRACE_EVT_SCHED, SCHED_OP_PICK) ? op(TRACE_EVT_SCHED, SCHED_OP_PICK)
                                                              : op(TRACE_EVT_SCHED, SCHED_OP_SWITCH_IN);
    r.gauges.push_back({"montauk_analysis_dispatches_per_sec", "", static_cast<double>(picks) / dur_s});
    r.gauges.push_back({"montauk_analysis_preempts_per_sec", "",
                        static_cast<double>(op(TRACE_EVT_SCHED, SCHED_OP_PREEMPT_TICK) +
                                            op(TRACE_EVT_SCHED, SCHED_OP_PREEMPT_WAKEUP)) / dur_s});
  }
}

// THE SYNC SOURCES every wait-shaped report folds, so the same analysis reads
// NTSYNC objects and futexes alike: ntsync wait completions, ntsync signal
// ops, and the futex syscall through the IO door.
const std::vector<Source> kSyncSources = {
    {"ntsync.wait_any,wait_all", {"tid", "pid", "fd", "result"}, {"result!=-999"}},
    {"ntsync.event_set,event_reset,sem_release,mutex_unlock", {"tid", "pid", "fd", "result"}},
    {"io", {"tid", "pid", "count", "result", "fd"}, {"syscall_nr=202"}},
};
bool row_wait(const Collected::Row& e, SyncWait& w) {
  if (e.src() == 0) {
    w = {static_cast<uint32_t>(e[0]), static_cast<uint32_t>(e[1]), static_cast<uint32_t>(e[2]),
         static_cast<uint64_t>(e.ts()), e[3], false};
    return true;
  }
  if (e.src() == 2 && futex_is_wait(static_cast<uint32_t>(e[4]) & 0x7f)) {
    w = {static_cast<uint32_t>(e[0]), static_cast<uint32_t>(e[1]), e.u(2), static_cast<uint64_t>(e.ts()), e[3], true};
    return true;
  }
  return false;
}
bool row_signal(const Collected::Row& e, SyncSignal& s) {
  if (e.src() == 1) { s = {static_cast<uint32_t>(e[0]), static_cast<uint32_t>(e[2]), static_cast<uint64_t>(e.ts())}; return true; }
  if (e.src() == 2 && futex_is_wake(static_cast<uint32_t>(e[4]) & 0x7f)) {
    s = {static_cast<uint32_t>(e[0]), e.u(2), static_cast<uint64_t>(e.ts())};
    return true;
  }
  return false;
}

// REPORT waits: per (tid, object) wait-completion stats -- how often each
// thread waits on each object, the spacing between its waits, and how they
// return.
void derive_waits(const Collected& in, ReportResult& r) {
  struct Agg {
    uint32_t tid = 0, pid = 0; bool is_futex = false; uint64_t obj = 0, count = 0, last_ts = 0;
    std::map<int64_t, uint64_t> results; std::vector<uint64_t> gaps;
  };
  std::map<std::pair<uint32_t, uint64_t>, Agg> aggs;
  in.each([&](Collected::Row e) {
    SyncWait w;
    if (!row_wait(e, w)) return;
    Agg& a = aggs[{w.tid, w.obj}];
    if (a.count == 0) { a.tid = w.tid; a.pid = w.pid; a.is_futex = w.is_futex; a.obj = w.obj; }
    ++a.count;
    ++a.results[w.result];
    if (a.last_ts && w.ts > a.last_ts) a.gaps.push_back(w.ts - a.last_ts);
    a.last_ts = w.ts;
  });
  if (aggs.empty()) { compose_verdict(r, "NO-WAITS", "no sync wait completions in trace (NTSYNC or futex)"); return; }
  uint64_t total = 0;
  const Agg* top = nullptr;
  for (const auto& [k, a] : aggs) { total += a.count; if (!top || a.count > top->count) top = &a; }
  const double share = 100.0 * static_cast<double>(top->count) / static_cast<double>(total);
  const std::string topobj = fmt_obj(top->pid, top->obj, top->is_futex);
  if (share >= 50.0)
    compose_verdict(r, "CONCENTRATED",
                    "tid=%u obj=%s dominates — %s of %s wait completions (%.0f%%) across %zu tid/obj pairs",
                    top->tid, topobj.c_str(), fmt_count(static_cast<double>(top->count)).c_str(),
                    fmt_count(static_cast<double>(total)).c_str(), share, aggs.size());
  else
    compose_verdict(r, "SPREAD",
                    "wait load spread across %zu tid/obj pairs — top tid=%u obj=%s holds %.0f%% (%s of %s)",
                    aggs.size(), top->tid, topobj.c_str(), share,
                    fmt_count(static_cast<double>(top->count)).c_str(), fmt_count(static_cast<double>(total)).c_str());
  char lab[96];
  for (const auto& [k, a] : aggs) {
    std::snprintf(lab, sizeof(lab), "tid=\"%u\",obj=\"0x%016" PRIx64 "\"", a.tid, a.obj);
    r.gauges.push_back({"montauk_analysis_waits_total", lab, static_cast<double>(a.count)});
  }
  std::vector<Agg*> rows;
  for (auto& [k, a] : aggs) {
    if (!a.gaps.empty()) {
      sublimation_u64(a.gaps.data(), a.gaps.size());
      std::snprintf(lab, sizeof(lab), "tid=\"%u\",obj=\"0x%016" PRIx64 "\",quantile=\"0.5\"", a.tid, a.obj);
      r.gauges.push_back({"montauk_analysis_wait_gap_ms", lab, q_ms(a.gaps, 0.50)});
      std::snprintf(lab, sizeof(lab), "tid=\"%u\",obj=\"0x%016" PRIx64 "\",quantile=\"0.99\"", a.tid, a.obj);
      r.gauges.push_back({"montauk_analysis_wait_gap_ms", lab, q_ms(a.gaps, 0.99)});
    }
    rows.push_back(&a);
  }
  sublimation_order_u64(rows, true, [](const Agg* p) { return p->count; });
  Detail t = Detail::array();
  for (const Agg* a : rows) {
    // Result legend: >=0 the signaled object index, -110 ETIMEDOUT, other negatives -errno.
    std::vector<std::pair<int64_t, uint64_t>> res(a->results.begin(), a->results.end());
    sublimation_order_u64(res, true, [](const std::pair<int64_t, uint64_t>& p) { return p.second; });
    std::string rs;
    for (size_t i = 0; i < res.size() && i < kWaitsTopResults; ++i)
      rs += (rs.empty() ? "" : " ") + std::to_string(res[i].first) + ":" + std::to_string(res[i].second);
    Detail row = Detail::object();
    row.put("tid", Detail::count(a->tid)).put("obj", Detail::text(fmt_obj(a->pid, a->obj, a->is_futex)))
       .put("waits", Detail::count(a->count));
    if (!a->gaps.empty())
      row.put("gap_med_ms", Detail::of(q_ms(a->gaps, 0.50))).put("gap_p99_ms", Detail::of(q_ms(a->gaps, 0.99)));
    row.put("results", Detail::text(rs));
    t.arr.push_back(std::move(row));
  }
  r.detail.emplace_back("pairs", std::move(t));
}

// REPORT spins: livelock detector. A run is a streak of consecutive wait
// completions on one (tid, object) closer than a tick apart; a run that
// sustains a thousand iterations is a spin, not a wakeup burst. The three
// classes are three DIFFERENT bugs: instant-success is a livelock (the object
// is stuck signalled), timeout a starved waiter, error a caller mistake.
void derive_spins(const Collected& in, ReportResult& r) {
  struct State { uint32_t tid = 0, pid = 0; bool is_futex = false; uint64_t obj = 0, last_ts = 0;
                 int64_t last_result = 0; uint64_t iters = 0, start_ts = 0, succ = 0, timeo = 0, other = 0; };
  struct Run { uint32_t tid; uint64_t obj, iters, start_ts, end_ts, succ, timeo, other; uint32_t pid; bool is_futex; };
  std::map<uint64_t, State> state;
  std::vector<Run> runs;
  std::unordered_map<uint64_t, uint64_t> obj_waits, obj_signals;
  auto tally = [](State& s, int64_t res) { if (res >= 0) ++s.succ; else if (res == kEtimedout) ++s.timeo; else ++s.other; };
  auto close = [&](State& s, uint64_t end_ts) {
    if (s.iters >= kSpinMinIters)
      runs.push_back({s.tid, s.obj, s.iters, s.start_ts, end_ts, s.succ, s.timeo, s.other, s.pid, s.is_futex});
    s.iters = 0;
    s.succ = s.timeo = s.other = 0;
  };
  in.each([&](Collected::Row e) {
    SyncSignal sig;
    if (row_signal(e, sig)) { ++obj_signals[sig.obj]; return; }
    SyncWait w;
    if (!row_wait(e, w)) return;
    ++obj_waits[w.obj];
    State& s = state[tid_obj_key(w.tid, w.obj)];
    s.tid = w.tid; s.pid = w.pid; s.is_futex = w.is_futex; s.obj = w.obj;
    if (s.last_ts && w.ts > s.last_ts && w.ts - s.last_ts < kSpinGapNs) {
      if (s.iters == 0) { s.iters = 1; s.start_ts = s.last_ts; tally(s, s.last_result); }  // opens retroactively
      ++s.iters;
      tally(s, w.result);
    } else {
      close(s, s.last_ts);
    }
    s.last_ts = w.ts;
    s.last_result = w.result;
  });
  for (auto& [k, s] : state) close(s, s.last_ts);
  auto cls = [](const Run& x) {
    return x.succ >= x.timeo && x.succ >= x.other ? "instant-success" : x.timeo >= x.other ? "timeout" : "error";
  };
  auto rate = [](const Run& x) {
    const double span_ms = static_cast<double>(x.end_ts - x.start_ts) / 1e6;
    return span_ms > 0.0 ? static_cast<double>(x.iters) * 1000.0 / span_ms : 0.0;
  };
  if (runs.empty()) {
    compose_verdict(r, "NONE", "no spin runs detected");
  } else {
    std::map<std::string, uint64_t> by_class;
    std::set<uint64_t> pairs;
    double peak = 0.0;
    for (const Run& x : runs) { ++by_class[cls(x)]; pairs.insert(tid_obj_key(x.tid, x.obj)); peak = std::max(peak, rate(x)); }
    const auto dom = std::max_element(by_class.begin(), by_class.end(),
                                      [](const auto& a, const auto& b) { return a.second < b.second; });
    const char* word = "error spin";
    const char* tok = "ERROR-SPIN";
    if (dom->first == "instant-success") { word = "livelock"; tok = "LIVELOCK"; }
    else if (dom->first == "timeout") { word = "starved waiter"; tok = "STARVED-WAITER"; }
    char counts[80];
    if (dom->second == runs.size())
      std::snprintf(counts, sizeof(counts), "%zu %s spin runs", runs.size(), dom->first.c_str());
    else
      std::snprintf(counts, sizeof(counts), "%" PRIu64 " of %zu spin runs %s", dom->second, runs.size(), dom->first.c_str());
    const std::string where = pairs.size() == 1
        ? "all tid=" + std::to_string(runs[0].tid) + " obj=" + fmt_obj(runs[0].pid, runs[0].obj, runs[0].is_futex)
        : "across " + std::to_string(pairs.size()) + " tid/obj pairs";
    compose_verdict(r, tok, "%s — %s, %s, peak %s waits/s", word, counts, where.c_str(), fmt_count(peak).c_str());
  }
  std::map<std::string, uint64_t> run_counts;
  std::map<uint64_t, std::pair<const Run*, double>> peaks;
  for (const Run& x : runs) {
    char lab[96];
    std::snprintf(lab, sizeof(lab), "tid=\"%u\",obj=\"0x%016" PRIx64 "\",verdict=\"%s\"", x.tid, x.obj, cls(x));
    ++run_counts[lab];
    auto& p = peaks[tid_obj_key(x.tid, x.obj)];
    if (!p.first || rate(x) > p.second) p = {&x, rate(x)};
  }
  for (const auto& [lab, n] : run_counts)
    r.gauges.push_back({"montauk_analysis_spin_runs_total", lab, static_cast<double>(n)});
  for (const auto& [k, p] : peaks) {
    char lab[64];
    std::snprintf(lab, sizeof(lab), "tid=\"%u\",obj=\"0x%016" PRIx64 "\"", p.first->tid, p.first->obj);
    r.gauges.push_back({"montauk_analysis_spin_peak_rate_per_s", lab, p.second});
  }
  // PROGRESS TEST: a healthy ping-pong is woken by its partner on every
  // iteration (signals within the pairing ratio of its waits) and looks
  // identical to a livelock by gap and result alone; only a signal-starved
  // object or a failing run is an offender.
  for (const auto& [k, p] : peaks) {
    const Run& x = *p.first;
    const uint64_t waits = obj_waits.count(x.obj) ? obj_waits[x.obj] : x.iters;
    const uint64_t sigs = obj_signals.count(x.obj) ? obj_signals[x.obj] : 0;
    const bool partnered = sigs > 0 && waits <= sigs * kPairingWaitSignalRatio;
    const bool failed = !(x.succ >= x.timeo && x.succ >= x.other);
    if (partnered && !failed) continue;
    r.offenders.push_back({"spin", std::to_string(x.tid), fmt_obj(x.pid, x.obj, x.is_futex), "waits_per_s", p.second,
                           failed ? 2 : (p.second >= 10000.0 ? 2 : 1)});
  }
  std::vector<Run> ranked = runs;
  sublimation_order_u64(ranked, true, [](const Run& x) { return x.iters; });
  Detail t = Detail::array();
  for (const Run& x : ranked)
    t.arr.push_back(Detail::object()
        .put("tid", Detail::count(x.tid)).put("obj", Detail::text(fmt_obj(x.pid, x.obj, x.is_futex)))
        .put("iters", Detail::count(x.iters)).put("span_ms", Detail::of(static_cast<double>(x.end_ts - x.start_ts) / 1e6))
        .put("rate_per_s", Detail::of(rate(x))).put("class", Detail::text(cls(x))));
  if (!t.arr.empty()) r.detail.emplace_back("runs", std::move(t));
}

// REPORT pairing: per object fd, waits against signal-side ops. Waits are
// attributed to the object fds in the wait (the ioctl itself targets the
// device fd); signals carry their own. An fd whose waits outnumber its signals
// a hundredfold has no plausible signaler -- a lost wakeup or a dead producer.
void derive_pairing(const Collected& in, ReportResult& r) {
  struct Agg { uint64_t waits = 0, set = 0, reset = 0, sem_release = 0, mutex_unlock = 0; };
  std::map<int32_t, Agg> aggs;
  in.each([&](Collected::Row e) {
    if (e.src() == 0) {
      const uint32_t n = static_cast<uint32_t>(std::min<int64_t>(e[0], NTSYNC_MAX_WAIT_FDS));
      for (uint32_t i = 0; i < n; ++i) ++aggs[static_cast<int32_t>(static_cast<uint32_t>(e[1 + i]))].waits;
      return;
    }
    Agg& a = aggs[static_cast<int32_t>(e[0])];
    switch (e[1]) {
      case NTS_EVENT_SET: ++a.set; break;
      case NTS_EVENT_RESET: ++a.reset; break;
      case NTS_SEM_RELEASE: ++a.sem_release; break;
      case NTS_MUTEX_UNLOCK: ++a.mutex_unlock; break;
      default: break;
    }
  });
  auto signals = [](const Agg& a) { return a.set + a.reset + a.sem_release + a.mutex_unlock; };
  auto flagged = [&](const Agg& a) { return a.waits >= kPairingMinWaits && a.waits > signals(a) * kPairingWaitSignalRatio; };
  if (aggs.empty()) { compose_verdict(r, "NONE", "no NTSYNC activity in trace"); return; }
  size_t n_flagged = 0;
  const Agg* worst = nullptr;
  int32_t worst_fd = 0;
  for (const auto& [fd, a] : aggs) {
    if (!flagged(a)) continue;
    ++n_flagged;
    if (!worst || a.waits > worst->waits) { worst = &a; worst_fd = fd; }
  }
  if (!worst) {
    compose_verdict(r, "PAIRED", "all waited fds have plausible signalers");
  } else {
    char more[64] = "";
    if (n_flagged > 1) std::snprintf(more, sizeof(more), ", +%zu more flagged fds", n_flagged - 1);
    compose_verdict(r, "STUCK-SIGNALED", "fd %d stuck-signaled — %s waits, %s signals%s", worst_fd,
                    fmt_count(static_cast<double>(worst->waits)).c_str(),
                    fmt_count(static_cast<double>(signals(*worst))).c_str(), more);
  }
  auto family = [&](const char* name, auto value) {
    for (const auto& [fd, a] : aggs)
      r.gauges.push_back({name, "fd=\"" + std::to_string(fd) + "\"", value(a)});
  };
  family("montauk_analysis_pairing_waits", [](const Agg& a) { return static_cast<double>(a.waits); });
  family("montauk_analysis_pairing_signals", [&](const Agg& a) { return static_cast<double>(signals(a)); });
  family("montauk_analysis_unsignaled_flag", [&](const Agg& a) { return flagged(a) ? 1.0 : 0.0; });
  for (const auto& [fd, a] : aggs) {
    if (!flagged(a)) continue;
    char idb[24];
    std::snprintf(idb, sizeof(idb), "0x%x", static_cast<unsigned>(fd));
    r.offenders.push_back({"unsignaled", idb, "", "waits", static_cast<double>(a.waits), 2});
  }
}

// REPORT doublefree: an address freed while not currently allocated -- a
// double-free or a free of something never allocated -- with the size it last
// carried and BOTH freeing threads. Same tid twice is a logic double-destroy;
// two tids is a concurrent free race. Keyed by (pid, addr): short-lived forks
// reuse the same arena addresses. Realloc moves are tracked so a moved chunk's
// old address is not mis-flagged.
void derive_doublefree(const Collected& in, ReportResult& r) {
  struct Live { uint64_t size; uint32_t tid; int64_t comm; };
  struct Hit { uint64_t addr, size; uint32_t first_tid; int64_t first_comm; uint32_t second_tid; int64_t second_comm; };
  auto key = [](int64_t pid, uint64_t addr) { return (static_cast<uint64_t>(pid) * 1099511628211ull) ^ addr; };
  std::unordered_map<uint64_t, Live> live, freed;
  std::vector<Hit> hits;
  uint64_t frees = 0;
  in.each([&](Collected::Row e) {
    const int64_t pid = e[0];
    const uint32_t tid = static_cast<uint32_t>(e[1]);
    const uint64_t addr = e.u(3), size = e.u(4), new_addr = e.u(5);
    auto store = [&](std::unordered_map<uint64_t, Live>& m, uint64_t a, uint64_t sz) { m[key(pid, a)] = {sz, tid, e[6]}; };
    switch (e[2]) {
      case HEAP_OP_MALLOC: case HEAP_OP_CALLOC:
        if (addr) { store(live, addr, size); freed.erase(key(pid, addr)); }
        break;
      case HEAP_OP_REALLOC:
        if (addr) { live.erase(key(pid, addr)); freed.erase(key(pid, addr)); }
        if (new_addr) { store(live, new_addr, size); freed.erase(key(pid, new_addr)); }
        break;
      case HEAP_OP_FREE: {
        if (!addr) break;  // free(NULL) is legal
        ++frees;
        const uint64_t k = key(pid, addr);
        auto it = live.find(k);
        if (it != live.end()) { store(freed, addr, it->second.size); live.erase(it); break; }
        auto pf = freed.find(k);
        if (pf != freed.end() && hits.size() < 64)
          hits.push_back({addr, pf->second.size, pf->second.tid, pf->second.comm, tid, e[6]});
        store(freed, addr, pf != freed.end() ? pf->second.size : 0);
        break;
      }
      default: break;
    }
  });
  size_t cross = 0;
  for (const Hit& h : hits) if (h.first_tid != h.second_tid) ++cross;
  // RACE outranks LOGIC: a cross-thread double free is a synchronization
  // defect, a same-thread one a bookkeeping defect.
  if (hits.empty()) compose_verdict(r, "CLEAN", "no double-frees in %" PRIu64 " frees", frees);
  else compose_verdict(r, cross ? "RACE" : "LOGIC",
                       "%zu double-free(s) in %" PRIu64 " frees — %zu cross-thread (race), %zu same-thread (logic)",
                       hits.size(), frees, cross, hits.size() - cross);
  r.gauges.push_back({"montauk_analysis_doublefree_total", "", static_cast<double>(hits.size())});
  r.gauges.push_back({"montauk_analysis_doublefree_cross_thread_total", "", static_cast<double>(cross)});
  r.gauges.push_back({"montauk_analysis_frees_total", "", static_cast<double>(frees)});
  Detail t = Detail::array();
  for (const Hit& h : hits) {
    char addrb[32];
    std::snprintf(addrb, sizeof(addrb), "0x%016" PRIx64, h.addr);
    // Memory corruption, not a tuning finding: every hit is sev 2.
    r.offenders.push_back({h.first_tid != h.second_tid ? "doublefree-race" : "doublefree-logic",
                           std::to_string(h.second_tid), addrb, "bytes", static_cast<double>(h.size), 2});
    t.arr.push_back(Detail::object()
        .put("addr", Detail::text(addrb)).put("size", Detail::count(h.size))
        .put("first_tid", Detail::count(h.first_tid)).put("first_comm", Detail::text(in.strings[static_cast<size_t>(h.first_comm)]))
        .put("second_tid", Detail::count(h.second_tid)).put("second_comm", Detail::text(in.strings[static_cast<size_t>(h.second_comm)])));
  }
  if (!t.arr.empty()) r.detail.emplace_back("hits", std::move(t));
}

// REPORT futex: threads blocked on a futex-backed lock at trace end, grouped by
// opaque uaddr. A thread whose last activity is a FUTEX_WAIT -- above all one
// re-issued on the same uaddr -- is wedged entering that lock. Addresses are
// opaque; naming a lock is a consumer's join against its own metadata.
void derive_futex(const Collected& in, ReportResult& r) {
  struct TidF { uint64_t last_wait_ts = 0, wait_uaddr = 0; uint32_t retries = 0; };
  struct Wake { uint64_t wakes = 0; };
  std::map<uint32_t, TidF> tids;
  std::map<uint64_t, Wake> wakes;
  in.each([&](Collected::Row e) {
    const uint32_t opb = static_cast<uint32_t>(e[1]) & 0x7f;
    const uint64_t uaddr = e.u(2);
    TidF& t = tids[static_cast<uint32_t>(e[0])];
    if (futex_is_wait(opb)) {
      if (t.wait_uaddr == uaddr && t.last_wait_ts != 0) ++t.retries; else t.retries = 1;
      t.last_wait_ts = static_cast<uint64_t>(e.ts());
      t.wait_uaddr = uaddr;
    } else if (futex_is_wake(opb)) {
      ++wakes[uaddr].wakes;
    }
  });
  static constexpr std::initializer_list<uint32_t> kActivity = {
      TRACE_EVT_IO, TRACE_EVT_NTSYNC, TRACE_EVT_HEAP, TRACE_EVT_MMAP, TRACE_EVT_SIGNAL};
  const uint64_t max_ts = g_census.span_of(kActivity).second;
  constexpr uint64_t kSlackNs = 1'000'000;   // the wait is the thread's last activity
  struct Row { uint32_t tid; const TidF* t; double stuck_s, s_per_retry; const char* cls; };
  std::vector<Row> rows;
  size_t blocked = 0;
  for (const auto& [tid, t] : tids) {
    if (t.last_wait_ts == 0) continue;
    if (g_threads.last_ts(tid, kActivity) > t.last_wait_ts + kSlackNs) continue;   // woke after its wait
    ++blocked;
    const double stuck = static_cast<double>(max_ts - t.last_wait_ts) / 1e9;
    const double spr = t.retries ? stuck / t.retries : stuck;
    const uint64_t wk = wakes.count(t.wait_uaddr) ? wakes.at(t.wait_uaddr).wakes : 0;
    // Name-free shape classes: parked once uncontended, a fast adaptive spin,
    // or contended and retrying.
    const char* cls = t.retries <= 1 && wk == 0 ? "idle-park" : t.retries >= 50 && spr < 0.1 ? "spin" : "wait";
    rows.push_back({tid, &t, stuck, spr, cls});
  }
  r.gauges.push_back({"montauk_analysis_futex_blocked_threads", "", static_cast<double>(blocked)});
  if (rows.empty()) { compose_verdict(r, "NO-FUTEX-BLOCKED", "no threads blocked on a futex at trace end"); return; }
  struct Agg { int waiters = 0; double max_stuck = 0; uint64_t wakes = 0; };
  std::map<uint64_t, Agg> aggs;
  for (const Row& x : rows) {
    Agg& a = aggs[x.t->wait_uaddr];
    ++a.waiters;
    a.max_stuck = std::max(a.max_stuck, x.stuck_s);
  }
  for (auto& [u, a] : aggs) a.wakes = wakes.count(u) ? wakes.at(u).wakes : 0;
  size_t idle = 0, spin = 0;
  for (const Row& x : rows) { if (!std::strcmp(x.cls, "idle-park")) ++idle; else if (!std::strcmp(x.cls, "spin")) ++spin; }
  uint64_t worst_uaddr = 0;
  double worst_stuck = 0;
  for (const auto& [u, a] : aggs) if (a.max_stuck > worst_stuck) { worst_stuck = a.max_stuck; worst_uaddr = u; }
  compose_verdict(r, spin > idle ? "FUTEX-SPIN" : "FUTEX-PARKED",
                  "%zu threads blocked on futexes (%zu idle-park, %zu spin, %zu wait); worst uaddr=0x%" PRIx64 " stuck %.1fs",
                  rows.size(), idle, spin, rows.size() - idle - spin, worst_uaddr, worst_stuck);
  sublimation_order_f64(rows, true, [](const Row& x) { return x.stuck_s; });
  auto hex = [](uint64_t v) { char b[24]; std::snprintf(b, sizeof b, "0x%016" PRIx64, v); return std::string(b); };
  Detail contended = Detail::array(), threads = Detail::array();
  std::vector<std::pair<uint64_t, const Agg*>> au;
  for (const auto& [u, a] : aggs) if (a.waiters >= 2) au.emplace_back(u, &a);
  sublimation_order_f64(au, true, [](const std::pair<uint64_t, const Agg*>& p) { return p.second->max_stuck; });
  for (const auto& [u, a] : au)
    contended.arr.push_back(Detail::object().put("uaddr", Detail::text(hex(u)))
        .put("waiters", Detail::count(static_cast<uint64_t>(a->waiters))).put("wakes", Detail::count(a->wakes))
        .put("max_stuck_s", Detail::of(a->max_stuck)));
  for (const Row& x : rows) {
    if (!std::strcmp(x.cls, "idle-park")) continue;
    const auto* io = g_threads.of(x.tid, TRACE_EVT_IO);
    threads.arr.push_back(Detail::object().put("uaddr", Detail::text(hex(x.t->wait_uaddr)))
        .put("tid", Detail::count(x.tid))
        .put("comm", Detail::text(ThreadLedger::comm(io)))
        .put("stuck_s", Detail::of(x.stuck_s)).put("retries", Detail::count(x.t->retries))
        .put("s_per_retry", Detail::of(x.s_per_retry)).put("class", Detail::text(x.cls)));
  }
  if (!contended.arr.empty()) r.detail.emplace_back("contended", std::move(contended));
  if (!threads.arr.empty()) r.detail.emplace_back("blocked", std::move(threads));
}

// REPORT keyedevt: keyed-event contention by opaque key, from a configured
// wait/release uprobe pair (for NT keyed events the key is a lock address). A
// thread whose last activity is a keyed wait is wedged; if the key got no
// release after that wait, the holder never left.
void derive_keyedevt(const Collected& in, ReportResult& r) {
  struct TidK { uint64_t last_wait_ts = 0, wait_key = 0; int64_t comm = -1; };
  struct KeyK { uint64_t waits = 0, releases = 0, last_release_ts = 0; };
  std::map<uint32_t, TidK> tids;
  std::map<uint64_t, KeyK> keys;
  in.each([&](Collected::Row e) {
    TidK& t = tids[static_cast<uint32_t>(e[0])];
    if (!in.strings[static_cast<size_t>(e[2])].empty()) t.comm = e[2];
    KeyK& k = keys[e.u(4)];
    if (e[3] == KEVT_RELEASE) { ++k.releases; k.last_release_ts = static_cast<uint64_t>(e.ts()); }
    else { ++k.waits; t.last_wait_ts = static_cast<uint64_t>(e.ts()); t.wait_key = e.u(4); }
  });
  static constexpr std::initializer_list<uint32_t> kActivity = {
      TRACE_EVT_KEYEDEVT, TRACE_EVT_IO, TRACE_EVT_NTSYNC, TRACE_EVT_HEAP, TRACE_EVT_MMAP, TRACE_EVT_SIGNAL};
  const uint64_t max_ts = g_census.span_of(kActivity).second;
  constexpr uint64_t kSlackNs = 1'000'000;
  std::map<uint64_t, std::vector<std::pair<uint32_t, const TidK*>>> blocked;
  size_t wedged = 0;
  for (const auto& [tid, t] : tids) {
    if (t.last_wait_ts == 0) continue;
    if (g_threads.last_ts(tid, kActivity) <= t.last_wait_ts + kSlackNs) { ++wedged; blocked[t.wait_key].emplace_back(tid, &t); }
  }
  r.gauges.push_back({"montauk_analysis_keyedevt_wedged_threads", "", static_cast<double>(wedged)});
  if (keys.empty()) {
    compose_verdict(r, "NO-KEYED-EVENTS", "no keyed-event activity (was a keyed-event "
                    "uprobe configured when the trace was captured?)");
    return;
  }
  if (blocked.empty()) {
    compose_verdict(r, "NO-WEDGED", "%zu key(s) seen; no thread wedged entering a keyed wait at trace end", keys.size());
    return;
  }
  uint64_t worst_key = 0, worst = 0;
  for (const auto& [key, ws] : blocked)
    for (const auto& [tid, t] : ws)
      if (max_ts - t->last_wait_ts > worst) { worst = max_ts - t->last_wait_ts; worst_key = key; }
  compose_verdict(r, "WEDGED", "%zu key(s) have a thread wedged entering them; worst key=0x%" PRIx64 " stuck %.1fs",
                  blocked.size(), worst_key, static_cast<double>(worst) / 1e9);
  auto hex = [](uint64_t v) { char b[24]; std::snprintf(b, sizeof b, "0x%016" PRIx64, v); return std::string(b); };
  Detail kd = Detail::array(), td = Detail::array();
  for (const auto& [key, ws] : blocked) {
    const KeyK& k = keys[key];
    uint64_t latest = 0;
    for (const auto& [tid, t] : ws) latest = std::max(latest, t->last_wait_ts);
    kd.arr.push_back(Detail::object().put("key", Detail::text(hex(key))).put("waiters", Detail::count(ws.size()))
        .put("total_waits", Detail::count(k.waits)).put("releases", Detail::count(k.releases))
        .put("released_after_wait", Detail::flag(k.last_release_ts > latest)));
    for (const auto& [tid, t] : ws)
      td.arr.push_back(Detail::object().put("key", Detail::text(hex(key))).put("tid", Detail::count(tid))
          .put("comm", Detail::text(t->comm >= 0 ? in.strings[static_cast<size_t>(t->comm)] : ""))
          .put("stuck_s", Detail::of(static_cast<double>(max_ts - t->last_wait_ts) / 1e9)));
  }
  r.detail.emplace_back("keys", std::move(kd));
  r.detail.emplace_back("wedged", std::move(td));
}

const ReportDef kSummary = {"summary", {}, false, derive_summary};
const ReportDef kWaits = {"waits", kSyncSources, false, derive_waits};
const ReportDef kSpins = {"spins", kSyncSources, false, derive_spins};
const ReportDef kPairing = {"pairing",
                            {{"ntsync.wait_any,wait_all", {"wait_count", "wait_fd0", "wait_fd1", "wait_fd2", "wait_fd3",
                                                           "wait_fd4", "wait_fd5", "wait_fd6", "wait_fd7"},
                              {"result!=-999"}},
                             {"ntsync.event_set,event_reset,sem_release,mutex_unlock", {"fd", "op"}}},
                            false, derive_pairing};
const ReportDef kDoubleFree = {"doublefree", {{"heap", {"pid", "tid", "op", "addr", "size", "new_addr", "comm"}}},
                               false, derive_doublefree};
const ReportDef kFutex = {"futex", {{"io", {"tid", "fd", "count"}, {"syscall_nr=202"}}}, false, derive_futex, true};
const ReportDef kKeyedEvt = {"keyedevt", {{"keyedevt", {"tid", "pid", "comm", "op", "key"}}}, false, derive_keyedevt, true};

// REPORT abortpm: per-ABORT arena post-mortem. The glibc top-chunk / !prev
// corruption class presents as a linear overrun of the allocation that abuts
// the arena top, so replaying the heap stream up to each abort and naming the
// highest live chunk in the aborting thread's arena names the victim without a
// debugger. The aborting thread's last events ride along, so the work item
// that owned the victim is visible in place.
void derive_abortpm(const Collected& in, ReportResult& r) {
  constexpr uint64_t kArenaSize = 64ull << 20;   // glibc HEAP_MAX_SIZE
  constexpr size_t kRingCap = 8, kTopChunks = 5;
  struct Chunk { uint64_t size; uint32_t tid; int64_t comm; };
  struct Item { uint64_t ts; int kind; int64_t op, fd; uint64_t a, b; };
  struct Ring { Item items[kRingCap]{}; size_t n = 0, idx = 0;
                void push(const Item& it) { items[idx] = it; idx = (idx + 1) % kRingCap; if (n < kRingCap) ++n; } };
  std::unordered_map<uint64_t, Chunk> live;
  std::unordered_map<uint32_t, uint64_t> last_alloc;
  std::unordered_map<uint32_t, Ring> rings;
  Detail aborts = Detail::array();
  auto hex = [](uint64_t v) { char b[24]; std::snprintf(b, sizeof b, "0x%" PRIx64, v); return std::string(b); };
  in.each([&](Collected::Row e) {
    const uint32_t tid = static_cast<uint32_t>(e[0]);
    const uint64_t ts = static_cast<uint64_t>(e.ts());
    switch (e.src()) {
      case 0: {   // heap: tid op addr size new_addr comm
        const int64_t op = e[1];
        const uint64_t addr = e.u(2), size = e.u(3), new_addr = e.u(4);
        if (op == HEAP_OP_MALLOC || op == HEAP_OP_CALLOC) {
          if (addr) { live[addr] = {size, tid, e[5]}; last_alloc[tid] = addr; }
        } else if (op == HEAP_OP_FREE) {
          if (addr) live.erase(addr);
        } else if (op == HEAP_OP_REALLOC) {
          if (addr) live.erase(addr);
          if (new_addr) { live[new_addr] = {size, tid, e[5]}; last_alloc[tid] = new_addr; }
        }
        rings[tid].push({ts, 0, op, 0, addr, size});
        return;
      }
      case 1: rings[tid].push({ts, 1, 0, e[1], e.u(2), e.u(3)}); return;          // mmap: tid fd addr length
      case 2: rings[tid].push({ts, 2, e[1], e[2], e.u(3), e.u(4)}); return;       // wait: tid op fd result count
      default: break;
    }
    // abort: pid tid comm. The arena of the aborting thread is the 64MB-aligned
    // window holding its most recent allocation; its highest live chunk abuts
    // the arena top and is the overrun suspect.
    const uint32_t atid = static_cast<uint32_t>(e[1]);
    Detail a = Detail::object();
    a.put("t_s", Detail::of(static_cast<double>(ts) / 1e9)).put("pid", Detail::count(e.u(0)))
     .put("tid", Detail::count(atid)).put("comm", Detail::text(redact_comm(e.text(2).c_str())));
    uint64_t victim_addr = 0, victim_size = 0;
    bool have_victim = false;
    auto la = last_alloc.find(atid);
    if (la != last_alloc.end()) {
      const uint64_t base = la->second & ~(kArenaSize - 1);
      std::vector<std::pair<uint64_t, const Chunk*>> chunks;
      for (const auto& [addr, c] : live) if (addr >= base && addr < base + kArenaSize) chunks.emplace_back(addr, &c);
      sublimation_order_u64(chunks, true, [](const std::pair<uint64_t, const Chunk*>& p) { return p.first; });
      a.put("arena", Detail::text(hex(base))).put("live_chunks", Detail::count(chunks.size()));
      if (!chunks.empty()) { victim_addr = chunks[0].first; victim_size = chunks[0].second->size; have_victim = true; }
      Detail top = Detail::array();
      for (size_t i = 0; i < chunks.size() && i < kTopChunks; ++i)
        top.arr.push_back(Detail::object().put("addr", Detail::text(hex(chunks[i].first)))
            .put("size", Detail::count(chunks[i].second->size)).put("tid", Detail::count(chunks[i].second->tid))
            .put("comm", Detail::text(redact_comm(in.strings[static_cast<size_t>(chunks[i].second->comm)].c_str()))));
      a.put("top_adjacent", std::move(top));
    }
    auto rg = rings.find(atid);
    if (rg != rings.end()) {
      Detail last = Detail::array();
      const Ring& ring = rg->second;
      for (size_t k = 0; k < ring.n; ++k) {
        const Item& it = ring.items[(ring.idx + kRingCap - ring.n + k) % kRingCap];
        static const char* kKind[] = {"HEAP", "MMAP", "WAIT"};
        last.arr.push_back(Detail::object().put("t_s", Detail::of(static_cast<double>(it.ts) / 1e9))
            .put("kind", Detail::text(kKind[it.kind])).put("op", Detail::of(static_cast<double>(it.op)))
            .put("fd", Detail::of(static_cast<double>(it.fd))).put("a", Detail::text(hex(it.a)))
            .put("b", Detail::count(it.b)));
      }
      a.put("last_events", std::move(last));
    }
    aborts.arr.push_back(std::move(a));
    // An abort is a crash post-mortem, not a tuning finding: sev 2, always.
    char addrb[32];
    if (have_victim) std::snprintf(addrb, sizeof(addrb), "0x%016" PRIx64, victim_addr);
    else std::snprintf(addrb, sizeof(addrb), "unattributed");
    r.offenders.push_back({"abort", std::to_string(atid), addrb, "victim_bytes", static_cast<double>(victim_size), 2});
  });
  // Memory corruption reaching glibc: the token is binary, there is no degree.
  if (aborts.arr.empty()) compose_verdict(r, "NONE", "no abort events in trace");
  else compose_verdict(r, "ABORT", "%zu abort(s); victim chunk = highest live allocation in the aborting arena",
                       aborts.arr.size());
  r.gauges.push_back({"montauk_analysis_aborts_total", "", static_cast<double>(aborts.arr.size())});
  if (!aborts.arr.empty()) r.detail.emplace_back("aborts", std::move(aborts));
}

// REPORT signals: every TRACE_EVT_SIGNAL decomposed -- who died or took a
// signal, which, from whom, in which syscall and when relative to the trace
// window, with the death stack joined against the maps sidecar. A death inside
// the trailing --window seconds is capture teardown; one before it is a
// MID-TRACE death, the kind that happened while the workload was running.
// Rows honor --sig/--comm/--pid/--tid.
void derive_signals(const Collected& in, ReportResult& r) {
  auto is_fault = [](int64_t n) { return n == 4 || n == 5 || n == 6 || n == 7 || n == 8 || n == 11 || n == 31; };
  const auto [min_ts, max_ts] = g_census.span_of({TRACE_EVT_NTSYNC, TRACE_EVT_IO, TRACE_EVT_SCHED,
                                                   TRACE_EVT_HEAP, TRACE_EVT_SIGNAL});
  struct Ev { uint64_t ts; Collected::Row row; };
  std::vector<Ev> evs;
  in.each([&](Collected::Row e) {
    // pid tid kind signal_nr sender_pid exit_code syscall_nr io_fd stack_depth comm frame0..7
    char comm[16] = {};
    std::memcpy(comm, e.text(9).data(), std::min<size_t>(e.text(9).size(), sizeof comm));
    if (!qual_match(static_cast<int32_t>(e[3]), static_cast<uint32_t>(e[0]), static_cast<uint32_t>(e[1]), comm)) return;
    evs.push_back({static_cast<uint64_t>(e.ts()), e});
  });
  const uint64_t window_ns = static_cast<uint64_t>(g_qual_window_s * 1e9);
  auto teardown = [&](const Ev& v) { return max_ts != 0 && v.ts + window_ns >= max_ts; };
  // A death is an abnormal exit CARRYING a signal; exit(N) helpers are not.
  auto death = [&](const Ev& v) { return v.row[2] == SIGEVT_EXIT_ABNL && v.row[3] != 0 && !teardown(v); };
  auto label = [](const Ev& v) {
    return v.row[2] == SIGEVT_EXIT_ABNL && v.row[3] == 0 ? std::string("exit") : signal_label(static_cast<int32_t>(v.row[3]));
  };
  if (evs.empty()) {
    compose_verdict(r, "NO-SIGNALS", "no signal events in trace%s",
                    (g_qual_sig >= 0 || !g_qual_comm.empty() || g_qual_pid >= 0 || g_qual_tid >= 0)
                        ? " matching the given qualifiers" : "");
  }
  sublimation_order_u64(evs, false, [](const Ev& v) { return v.ts; });
  uint64_t exits = 0, delivers = 0, deaths = 0;
  std::set<uint32_t> tids;
  const Ev* first_death = nullptr;
  struct Tally { uint64_t exits = 0, delivers = 0, first_ts = 0, last_ts = 0; std::vector<std::string> sigs; };
  std::map<std::string, Tally> by_comm;
  for (const Ev& v : evs) {
    (v.row[2] == SIGEVT_EXIT_ABNL ? exits : delivers)++;
    tids.insert(static_cast<uint32_t>(v.row[1]));
    if (death(v)) { ++deaths; if (!first_death) first_death = &v; }
    Tally& t = by_comm[redact_comm(v.row.text(9).c_str())];
    (v.row[2] == SIGEVT_EXIT_ABNL ? t.exits : t.delivers)++;
    if (t.first_ts == 0) t.first_ts = v.ts;
    t.last_ts = v.ts;
    const std::string lab = label(v);
    if (std::find(t.sigs.begin(), t.sigs.end(), lab) == t.sigs.end()) t.sigs.push_back(lab);
  }
  if (!evs.empty()) {
    if (deaths > 0 && first_death)
      compose_verdict(r, "MIDTRACE-DEATH",
          "%" PRIu64 " MID-TRACE signal death(s) (>%.1fs before trace end) — earliest '%s' tid=%u %s at +%.3fs, %.3fs before end; "
          "%" PRIu64 " abnormal exit(s) + %" PRIu64 " delivery(ies) across %zu thread(s) total",
          deaths, g_qual_window_s, redact_comm(first_death->row.text(9).c_str()).c_str(),
          static_cast<uint32_t>(first_death->row[1]), signal_label(static_cast<int32_t>(first_death->row[3])).c_str(),
          static_cast<double>(first_death->ts - min_ts) / 1e9, static_cast<double>(max_ts - first_death->ts) / 1e9,
          exits, delivers, tids.size());
    else
      compose_verdict(r, "TEARDOWN-ONLY",
          "no mid-trace signal deaths — %" PRIu64 " abnormal exit(s) + %" PRIu64 " delivery(ies) across %zu thread(s), all signal deaths inside the trailing %.1fs teardown window",
          exits, delivers, tids.size(), g_qual_window_s);
  }
  r.gauges.push_back({"montauk_analysis_signal_exits_total", "", static_cast<double>(exits)});
  r.gauges.push_back({"montauk_analysis_signal_delivers_total", "", static_cast<double>(delivers)});
  r.gauges.push_back({"montauk_analysis_midtrace_signal_deaths_total", "", static_cast<double>(deaths)});
  size_t added = 0;
  for (const Ev& v : evs) {
    if (!death(v)) continue;
    if (++added > 16) break;
    r.offenders.push_back({"mid-trace-death", redact_comm(v.row.text(9).c_str()), std::to_string(v.row[1]),
                           "before_end_s", static_cast<double>(max_ts - v.ts) / 1e9, is_fault(v.row[3]) ? 2 : 1});
  }
  if (evs.empty()) return;
  std::vector<std::pair<std::string, const Tally*>> rows;
  for (const auto& [c, t] : by_comm) rows.emplace_back(c, &t);
  sublimation_order_u64(rows, true, [](const std::pair<std::string, const Tally*>& p) { return p.second->exits + p.second->delivers; });
  Detail rollup = Detail::array(), events = Detail::array();
  for (const auto& [c, t] : rows) {
    std::string sigs;
    for (size_t i = 0; i < t->sigs.size(); ++i) { if (i == 4) { sigs += " +"; break; } sigs += (i ? " " : "") + t->sigs[i]; }
    rollup.arr.push_back(Detail::object().put("comm", Detail::text(c)).put("exits", Detail::count(t->exits))
        .put("delivers", Detail::count(t->delivers))
        .put("first_s", Detail::of(static_cast<double>(t->first_ts - min_ts) / 1e9))
        .put("last_s", Detail::of(static_cast<double>(t->last_ts - min_ts) / 1e9)).put("sigs", Detail::text(sigs)));
  }
  for (const Ev& v : evs) {
    const Collected::Row& e = v.row;
    std::string state = "usermode";
    if (e[6] >= 0) {
      const char* io = io_syscall_name(static_cast<int32_t>(e[6]));
      state = std::string("in ") + (io[0] == '?' ? "syscall " + std::to_string(e[6]) : std::string(io));
      if (e[7] >= 0) state += " fd=" + std::to_string(e[7]);
    }
    // The death site: the stack joined against the maps sidecar, when it resolves.
    std::string site;
    int shown = 0;
    for (uint64_t i = 0; i < std::min<uint64_t>(e.u(8), 8); ++i) {
      const std::string res = g_maps.resolve(static_cast<uint32_t>(e[0]), e.u(10 + i));
      if (res.empty() || res == "[anon]") continue;
      site += (site.empty() ? "" : " <- ") + res;
      if (++shown >= 4) break;
    }
    Detail row = Detail::object();
    row.put("t_s", Detail::of(static_cast<double>(v.ts - min_ts) / 1e9))
       .put("before_end_s", Detail::of(static_cast<double>(max_ts - v.ts) / 1e9))
       .put("kind", Detail::text(e[2] == SIGEVT_EXIT_ABNL ? "EXIT" : "DELIVER"))
       .put("pid", Detail::count(e.u(0))).put("tid", Detail::count(e.u(1)))
       .put("comm", Detail::text(redact_comm(e.text(9).c_str()))).put("signal", Detail::text(label(v)))
       .put("sender", Detail::of(static_cast<double>(e[4])))
       .put("status", Detail::text(e[2] == SIGEVT_EXIT_ABNL ? std::to_string((e[5] >> 8) & 0xff) : "-"))
       .put("state", Detail::text(state)).put("midtrace_death", Detail::flag(death(v)));
    if (!site.empty()) row.put("site", Detail::text(site));
    events.arr.push_back(std::move(row));
  }
  r.detail.emplace_back("by_comm", std::move(rollup));
  r.detail.emplace_back("events", std::move(events));
}

// REPORT endstate: who was doing what when the trace ENDED. After a wedged
// program is stopped, the threads still parked in ntsync waits -- and how long
// they had been parked -- name the stall; a thread killed while parked is a
// victim too, since the usual capture is taken after a force-quit. Each parked
// thread's wait objects carry their signal history: never signaled is a dead
// producer, signaled after the park is a lost wakeup.
void derive_endstate(const Collected& in, ReportResult& r) {
  struct TidState { bool wait_open = false, exited = false; uint64_t wait_since = 0, timeout_ns = 0;
                    uint32_t wait_count = 0; uint64_t objs[NTSYNC_MAX_WAIT_FDS]{}; uint32_t fds[NTSYNC_MAX_WAIT_FDS]{}; };
  struct ObjSig { uint64_t signals = 0, waits = 0, last_signal_ts = 0; uint32_t last_signal_tid = 0;
                  uint8_t last_signal_op = 0, create_op = 0xFF; };
  std::map<uint32_t, TidState> tids;
  std::map<uint64_t, ObjSig> objs;
  std::map<uint32_t, std::vector<uint64_t>> wait_stack;
  struct RawStack { uint32_t pid; uint64_t rip; std::vector<uint8_t> bytes; };
  std::map<uint32_t, RawStack> raw_stack;
  in.each([&](Collected::Row e) {
    const uint32_t tid = static_cast<uint32_t>(e[0]);
    switch (e.src()) {
      case 0: {
        const auto& w = e.raw<montauk_waitstack_event>();
        auto& v = wait_stack[tid];
        v.assign(w.stack_user, w.stack_user + std::min<uint32_t>(w.stack_depth, TRACE_STACK_MAX_FRAMES));
        return;
      }
      case 1: {
        const auto& w = e.raw<montauk_rawstack_event>();
        raw_stack[tid] = {w.pid, w.rip, std::vector<uint8_t>(w.stack, w.stack + std::min<uint32_t>(w.stack_len, TRACE_RAWSTACK_BYTES))};
        return;
      }
      case 3:
        if (e[1] == SIGEVT_EXIT_ABNL) tids[tid].exited = true;
        return;
      default: break;
    }
    // ntsync: tid op fd result wait_count timeout_ns obj_ptr wait_fd0..7 wait_obj0..7
    TidState& t = tids[tid];
    const auto op = static_cast<uint8_t>(e[1]);
    if (is_wait_op(op)) {
      if (e[3] == kWaitEntrySentinel) {
        t.wait_open = true;
        t.wait_since = static_cast<uint64_t>(e.ts());
        t.wait_count = static_cast<uint32_t>(e[4]);
        t.timeout_ns = e.u(5);
        const uint32_t n = std::min<uint32_t>(t.wait_count, NTSYNC_MAX_WAIT_FDS);
        for (uint32_t i = 0; i < n; ++i) {
          t.fds[i] = static_cast<uint32_t>(e[7 + i]);
          t.objs[i] = e.u(15 + i);
          ++objs[t.objs[i]].waits;
        }
      } else {
        t.wait_open = false;
      }
    } else if (is_wakeup_op(op)) {
      // Only an op that can WAKE a waiter counts: event_reset wakes no one and
      // would make a quiet producer look busy.
      ObjSig& o = objs[e.u(6)];
      ++o.signals;
      o.last_signal_ts = static_cast<uint64_t>(e.ts());
      o.last_signal_tid = tid;
      o.last_signal_op = op;
    } else if (op == NTS_CREATE_SEM || op == NTS_CREATE_MUTEX || op == NTS_CREATE_EVENT) {
      objs[e.u(6)].create_op = op;
    }
  });
  static constexpr std::initializer_list<uint32_t> kTouch = {
      TRACE_EVT_WAITSTACK, TRACE_EVT_RAWSTACK, TRACE_EVT_NTSYNC, TRACE_EVT_HEAP, TRACE_EVT_IO, TRACE_EVT_SIGNAL};
  static constexpr std::initializer_list<uint32_t> kNamed = {
      TRACE_EVT_WAITSTACK, TRACE_EVT_RAWSTACK, TRACE_EVT_HEAP, TRACE_EVT_IO, TRACE_EVT_SIGNAL};
  const uint64_t max_ts = g_census.span_of(kTouch).second;
  auto pid_of = [&](uint32_t tid) { const auto* l = g_threads.latest(tid, kTouch, false); return l ? l->pid : 0; };
  auto comm_of = [&](uint32_t tid) {
    const auto* l = g_threads.latest(tid, kNamed, true);
    return redact_comm(ThreadLedger::comm(l).c_str());
  };
  size_t blocked_now = 0;
  for (const auto& [tid, t] : tids) if (t.wait_open && !t.exited) ++blocked_now;
  r.gauges.push_back({"montauk_analysis_endstate_blocked_threads", "", static_cast<double>(blocked_now)});
  if (tids.empty() && g_threads.by_tid.empty()) { compose_verdict(r, "NO-THREADS", "no per-thread activity in trace"); return; }
  // A stall victim: still parked at trace end, or killed after holding an
  // open wait for at least 2s.
  constexpr uint64_t kParkSlackNs = 1'000'000, kKilledStallNs = 2'000'000'000ULL;
  std::vector<std::pair<uint32_t, const TidState*>> blocked;
  for (const auto& [tid, t] : tids) {
    if (!t.wait_open) continue;
    const uint64_t open_ns = max_ts > t.wait_since ? max_ts - t.wait_since : 0;
    if (!t.exited || open_ns >= kKilledStallNs) blocked.emplace_back(tid, &t);
  }
  sublimation_order_u64(blocked, false, [](const std::pair<uint32_t, const TidState*>& p) { return p.second->wait_since; });
  if (blocked.empty()) { compose_verdict(r, "NO-PARKED", "no threads parked or killed-while-parked in this trace"); return; }
  // Genuinely parked only if it did nothing after the wait entry; any later
  // event means it woke and the completion was lost.
  auto status_of = [&](uint32_t tid, const TidState& t) -> const char* {
    if (t.exited) return "KILLED-PARKED";
    return g_threads.last_ts(tid, kTouch) <= t.wait_since + kParkSlackNs ? "PARKED" : "woke(lost-compl)";
  };
  auto type_name = [](uint8_t create_op, uint8_t signal_op) {
    switch (create_op) { case NTS_CREATE_SEM: return "SEM"; case NTS_CREATE_MUTEX: return "MUTEX"; case NTS_CREATE_EVENT: return "EVENT"; default: break; }
    switch (signal_op) {
      case NTS_SEM_RELEASE: return "SEM"; case NTS_MUTEX_UNLOCK: return "MUTEX";
      case NTS_EVENT_SET: case NTS_EVENT_RESET: case NTS_EVENT_PULSE: return "EVENT";
      default: return "object";
    }
  };
  size_t genuine = 0;
  for (const auto& [tid, t] : blocked) if (std::string(status_of(tid, *t)) != "woke(lost-compl)") ++genuine;
  const auto& [wtid, w] = blocked.front();
  // The verdict NAMES what the longest-parked thread is starved of.
  std::string objdesc;
  if (w->wait_count > 0) {
    auto it = objs.find(w->objs[0]);
    const char* ty = type_name(it != objs.end() ? it->second.create_op : 0xFF, it != objs.end() ? it->second.last_signal_op : 0xFF);
    if (it == objs.end() || it->second.signals == 0) objdesc = std::string("; ") + ty + " NEVER signaled (dead producer / no signaler)";
    else if (it->second.last_signal_ts > w->wait_since) objdesc = std::string("; ") + ty + " signaled AFTER park (lost wakeup)";
    else objdesc = std::string("; ") + ty + " last wakeup BEFORE the park — producer went quiet";
  }
  compose_verdict(r, genuine ? "STALLED" : "LOST-COMPLETION",
                  "%zu thread(s) stuck in an ntsync wait (%zu genuine stall victims, "
                  "%zu woke/lost-compl); longest tid=%u '%s' %s %.1fs%s",
                  blocked.size(), genuine, blocked.size() - genuine, wtid, comm_of(wtid).c_str(),
                  w->exited ? "killed while parked" : "parked", static_cast<double>(max_ts - w->wait_since) / 1e9,
                  objdesc.c_str());
  auto hex = [](uint64_t v) { char b[24]; std::snprintf(b, sizeof b, "0x%016" PRIx64, v); return std::string(b); };
  Detail threads = Detail::array(), waits = Detail::array();
  for (const auto& [tid, t] : blocked) {
    const uint64_t last = g_threads.last_ts(tid, kTouch);
    Detail th = Detail::object();
    th.put("tid", Detail::count(tid)).put("pid", Detail::count(static_cast<uint64_t>(pid_of(tid))))
      .put("comm", Detail::text(comm_of(tid)))
      .put("open_s", Detail::of(static_cast<double>(max_ts - t->wait_since) / 1e9))
      .put("act_after_ms", Detail::of(last > t->wait_since ? static_cast<double>(last - t->wait_since) / 1e6 : 0.0))
      .put("status", Detail::text(status_of(tid, *t))).put("objs", Detail::count(t->wait_count))
      .put("timeout_ns", Detail::count(t->timeout_ns));
    // Where in the code it is parked: its last infinite-wait stack against
    // the maps sidecar, and a scan of its raw stack slice for return
    // addresses a frame-pointer-less walk cannot reach.
    auto ws = wait_stack.find(tid);
    if (ws != wait_stack.end()) {
      std::string site;
      int shown = 0;
      for (uint64_t ip : ws->second) {
        const std::string res = g_maps.resolve(static_cast<uint32_t>(pid_of(tid)), ip);
        if (res.empty() || res == "[anon]") continue;
        site += (site.empty() ? "" : " <- ") + res;
        if (++shown >= 4) break;
      }
      if (!site.empty()) th.put("parked_at", Detail::text(site));
    }
    auto rs = raw_stack.find(tid);
    if (rs != raw_stack.end() && !rs->second.bytes.empty()) {
      std::vector<std::string> sites;
      const std::string head = g_maps.resolve(rs->second.pid, rs->second.rip);
      if (!head.empty() && head != "[anon]") sites.push_back(head);
      for (size_t i = 0; i < rs->second.bytes.size() / 8 && sites.size() < 7; ++i) {
        uint64_t word;
        std::memcpy(&word, rs->second.bytes.data() + i * 8, sizeof word);
        const std::string sres = g_maps.resolve_exec(rs->second.pid, word);
        if (!sres.empty() && std::find(sites.begin(), sites.end(), sres) == sites.end()) sites.push_back(sres);
      }
      std::string scan;
      for (const auto& x : sites) scan += (scan.empty() ? "" : " <- ") + x;
      if (!scan.empty()) th.put("wait_site_scan", Detail::text(scan));
    }
    threads.arr.push_back(std::move(th));
    for (uint32_t i = 0; i < std::min<uint32_t>(t->wait_count, NTSYNC_MAX_WAIT_FDS); ++i) {
      auto it = objs.find(t->objs[i]);
      const uint64_t sigs = it != objs.end() ? it->second.signals : 0;
      std::string verdict;
      char b[192];
      if (sigs == 0) {
        verdict = "NEVER signaled — dead producer / no signaler";
      } else if (it->second.last_signal_ts > t->wait_since) {
        std::snprintf(b, sizeof b, "signaled +%.1fms AFTER park by tid=%u (%s) — LOST WAKEUP",
                      static_cast<double>(it->second.last_signal_ts - t->wait_since) / 1e6,
                      it->second.last_signal_tid, ntsync_op_name(it->second.last_signal_op));
        verdict = b;
      } else {
        std::snprintf(b, sizeof b, "last signal -%.1fms BEFORE park by tid=%u (%s)",
                      static_cast<double>(t->wait_since - it->second.last_signal_ts) / 1e6,
                      it->second.last_signal_tid, ntsync_op_name(it->second.last_signal_op));
        verdict = b;
      }
      waits.arr.push_back(Detail::object().put("tid", Detail::count(tid)).put("obj", Detail::text(hex(t->objs[i])))
          .put("fd", Detail::count(t->fds[i]))
          .put("type", Detail::text(type_name(it != objs.end() ? it->second.create_op : 0xFF,
                                              it != objs.end() ? it->second.last_signal_op : 0xFF)))
          .put("signals", Detail::count(sigs)).put("waits", Detail::count(it != objs.end() ? it->second.waits : 0))
          .put("verdict", Detail::text(verdict)));
    }
  }
  r.detail.emplace_back("parked", std::move(threads));
  r.detail.emplace_back("wait_objects", std::move(waits));
}

const ReportDef kAbortPm = {"abortpm",
                            {{"heap", {"tid", "op", "addr", "size", "new_addr", "comm"}},
                             {"mmap", {"tid", "fd", "addr", "length"}},
                             {"ntsync.wait_any,wait_all", {"tid", "op", "fd", "result", "wait_count"}, {"result!=-999"}},
                             {"abort", {"pid", "tid", "comm"}}},
                            false, derive_abortpm};
const ReportDef kSignals = {"signals",
                            {{"signal", {"pid", "tid", "kind", "signal_nr", "sender_pid", "exit_code", "syscall_nr",
                                         "io_fd", "stack_depth", "comm", "frame0", "frame1", "frame2", "frame3",
                                         "frame4", "frame5", "frame6", "frame7"}}},
                            false, derive_signals};
const ReportDef kEndstate = {"endstate",
                             {{"waitstack", {"tid"}, {}, true},
                              {"rawstack", {"tid"}, {}, true},
                              {"ntsync", {"tid", "op", "fd", "result", "wait_count", "timeout_ns", "obj_ptr",
                                          "wait_fd0", "wait_fd1", "wait_fd2", "wait_fd3", "wait_fd4", "wait_fd5",
                                          "wait_fd6", "wait_fd7", "wait_obj0", "wait_obj1", "wait_obj2", "wait_obj3",
                                          "wait_obj4", "wait_obj5", "wait_obj6", "wait_obj7"}},
                              {"signal", {"tid", "kind"}}},
                             false, derive_endstate, true};

// REPORT wakers: localize request-level latency to the WAKER's critical path.
// A request round-trip through a messenger inherits the messenger's own
// dispatch delay, which per-hop wake2run cannot see. Hot wakers (messengers,
// by wakes issued) are split from their wakees (workers): a messenger tail
// that dwarfs the worker tail puts the cliff on the waker path. And how long
// a wakee is woken by the SAME waker before another takes over separates long
// exclusive pairings from an interleave -- identical totals, different trust.
struct WakersStream final : Stream {
  std::unordered_map<int, uint64_t> wake_count;            // waker pid -> wakes issued
  std::unordered_map<int, std::vector<uint64_t>> w2r_by_pid;
  uint64_t total_wakes = 0, continued = 0;
  std::unordered_map<int, int> run_waker;                  // wakee -> waker of its current run
  std::unordered_map<int, uint64_t> run_len;
  std::vector<uint64_t> runs;                              // every CLOSED run length
  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type != TRACE_EVT_SCHED || len < sizeof(montauk_sched_event)) return;
    const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
    if (s->op == SCHED_OP_WAKEUP) {
      // Unfiltered: hot is relative across ALL wakers, not a qualified subset.
      if (s->secondary_pid < 0) return;
      ++wake_count[s->secondary_pid];
      ++total_wakes;
      auto it = run_waker.find(s->pid);
      if (it == run_waker.end()) { run_waker[s->pid] = s->secondary_pid; run_len[s->pid] = 1; }
      else if (it->second == s->secondary_pid) { ++run_len[s->pid]; ++continued; }
      else { runs.push_back(run_len[s->pid]); it->second = s->secondary_pid; run_len[s->pid] = 1; }
      return;
    }
    if (s->op == SCHED_OP_WAKE2RUN && qual_match(-1, static_cast<uint32_t>(s->pid), static_cast<uint32_t>(s->pid), ""))
      w2r_by_pid[s->pid].push_back(s->runtime_ns);
  }
};

void derive_wakers(const Stream& st, ReportResult& r) {
  const auto& w = static_cast<const WakersStream&>(st);
  if (w.wake_count.empty()) {
    compose_verdict(r, "NO-WAKER-EDGES", "no waker edges (pre-v7.9.0 trace -- sched_wakeup did "
                                         "not stamp the waker); re-capture to resolve");
    return;
  }
  uint64_t sum = 0;
  for (const auto& kv : w.wake_count) sum += kv.second;
  uint64_t thresh = static_cast<uint64_t>(static_cast<double>(sum) / static_cast<double>(w.wake_count.size()) * 8.0);
  if (thresh < 8) thresh = 8;
  std::vector<std::pair<uint32_t, uint64_t>> hot;
  std::unordered_set<int> hot_set;
  for (const auto& kv : w.wake_count)
    if (kv.second >= thresh) { hot_set.insert(kv.first); hot.emplace_back(static_cast<uint32_t>(kv.first), kv.second); }
  sublimation_order_u64(hot, true, [](const std::pair<uint32_t, uint64_t>& p) { return p.second; });
  std::vector<uint64_t> msg, wrk;
  for (const auto& kv : w.w2r_by_pid) {
    auto& dst = hot_set.count(kv.first) ? msg : wrk;
    dst.insert(dst.end(), kv.second.begin(), kv.second.end());
  }
  sublimation_u64(msg.data(), msg.size());
  sublimation_u64(wrk.data(), wrk.size());
  // A run still open at capture end is a real run; dropping it would truncate
  // exactly the longest exclusive pairings.
  std::vector<uint64_t> runs = w.runs;
  for (const auto& kv : w.run_len) if (kv.second) runs.push_back(kv.second);
  sublimation_u64(runs.data(), runs.size());
  const double mp99 = msg.empty() ? 0.0 : q_us(msg, 0.99), wp99 = wrk.empty() ? 0.0 : q_us(wrk, 0.99);
  compose_verdict(r, mp99 > 0.0 && wp99 > 0.0 && mp99 >= 2.0 * wp99 ? "MESSENGER-CLIFF"
                     : hot.empty() ? "NO-HOT-WAKERS" : "HOT-WAKERS",
      "%s waker pids, %s hot (messengers, >=%llu wakes); %s total wakes",
      fmt_count(static_cast<double>(w.wake_count.size())).c_str(), fmt_count(static_cast<double>(hot.size())).c_str(),
      static_cast<unsigned long long>(thresh), fmt_count(static_cast<double>(w.total_wakes)).c_str());
  auto& g = r.gauges;
  g.push_back({"montauk_analysis_waker_pids", "", static_cast<double>(w.wake_count.size())});
  g.push_back({"montauk_analysis_waker_hot_pids", "", static_cast<double>(hot.size())});
  g.push_back({"montauk_analysis_waker_wakes_total", "", static_cast<double>(w.total_wakes)});
  g.push_back({"montauk_analysis_waker_hot_threshold", "", static_cast<double>(thresh)});
  push_quantile_gauges(g, "montauk_analysis_waker_messenger_wake2run_us",
                       {{"0.5", q_us(msg, 0.50)}, {"0.99", q_us(msg, 0.99)}, {"0.999", q_us(msg, 0.999)}});
  push_quantile_gauges(g, "montauk_analysis_waker_worker_wake2run_us",
                       {{"0.5", q_us(wrk, 0.50)}, {"0.99", q_us(wrk, 0.99)}, {"0.999", q_us(wrk, 0.999)}});
  g.push_back({"montauk_analysis_waker_runs_total", "", static_cast<double>(runs.size())});
  g.push_back({"montauk_analysis_waker_monogamy_ratio", "",
               w.total_wakes ? static_cast<double>(w.continued) / static_cast<double>(w.total_wakes) : 0.0});
  push_quantile_gauges(g, "montauk_analysis_waker_run_length",
                       {{"0.5", static_cast<double>(q_at(runs, 0.50))}, {"0.9", static_cast<double>(q_at(runs, 0.90))},
                        {"0.99", static_cast<double>(q_at(runs, 0.99))}});
  g.push_back({"montauk_analysis_waker_run_length_max", "", runs.empty() ? 0.0 : static_cast<double>(runs.back())});
  // A hot waker is an offender only when its own tail is what its wakees inherit.
  if (!hot.empty() && !msg.empty() && mp99 > wp99 * 1.5)
    for (size_t i = 0; i < hot.size() && i < 3; ++i)
      r.offenders.push_back({"hot-waker", std::to_string(hot[i].first), "", "wakes_issued",
                             static_cast<double>(hot[i].second), mp99 > wp99 * 4.0 ? 2 : 1});
}

// REPORT fractal: self-similarity of the dispatch and migration timeline, on
// the RAW event stream binned at microsecond resolution -- many decades of
// scale, where the old .prom-scrape version spanned under one. DFA Hurst
// (primary), R/S as a cross-check, dimension D=2-H, and a migration-avalanche
// tail. Only a series two standard errors clear of 0.5 promotes.
struct FractalStream final : Stream {
  std::vector<uint64_t> disp_ts, mig_ts;     // WAKE2RUN run events; the cross-domain subset
  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type != TRACE_EVT_SCHED || len < sizeof(montauk_sched_event)) return;
    const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
    if (s->op != SCHED_OP_WAKE2RUN || !qual_match(-1, static_cast<uint32_t>(s->pid), static_cast<uint32_t>(s->pid), "")) return;
    disp_ts.push_back(s->timestamp_ns);
    if (s->sub_idx) mig_ts.push_back(s->timestamp_ns);
  }
};

void derive_fractal(const Stream& st, ReportResult& r) {
  const auto& f = static_cast<const FractalStream&>(st);
  if (f.disp_ts.empty() && f.mig_ts.empty()) { compose_verdict(r, "NO-SCHED", "no SCHED events in trace -- nothing to analyze"); return; }
  uint64_t t0 = UINT64_MAX, t1 = 0;
  for (uint64_t t : f.disp_ts) { t0 = std::min(t0, t); t1 = std::max(t1, t); }
  for (uint64_t t : f.mig_ts) { t0 = std::min(t0, t); t1 = std::max(t1, t); }
  if (t1 <= t0) { compose_verdict(r, "ZERO-DURATION", "zero-duration timeline -- nothing to analyze"); return; }
  // ~120k bins so the DFA spans 3-4 decades; bin width clamped to [10us, 10ms].
  const uint64_t span = t1 - t0;
  const uint64_t bw = std::clamp<uint64_t>(span / 120000, 10000, 10000000);
  const size_t nbins = static_cast<size_t>(span / bw) + 1;
  struct Series { const char* name; double h, se, hrs, dim, decades; bool ok; };
  auto analyze = [](const char* nm, const std::vector<double>& rate) {
    Series o{nm, NAN, NAN, NAN, NAN, 0.0, false};
    if (rate.size() < 32) return o;
    o.h = montauk::stats::dfa_hurst(rate, &o.se, &o.decades);
    o.hrs = montauk::stats::rs_hurst(rate);
    o.dim = 2.0 - o.h;
    o.ok = std::isfinite(o.h);
    return o;
  };
  const std::vector<double> disp = bin_rate_series(f.disp_ts, t0, bw, nbins);
  const std::vector<double> mig = bin_rate_series(f.mig_ts, t0, bw, nbins);
  const Series out[] = {analyze("dispatch-rate", disp), analyze("migration-rate", mig)};
  double slope = NAN;
  const int avalanches = montauk::stats::avalanche_tail(mig, &slope);
  Detail table = Detail::array();
  size_t pers = 0, anti = 0;
  for (const Series& o : out) {
    if (!o.ok) continue;
    const std::string lab = std::string("series=\"") + o.name + "\"";
    r.gauges.push_back({"montauk_fractal_hurst_dfa", lab, o.h});
    r.gauges.push_back({"montauk_fractal_hurst_dfa_se", lab, o.se});
    r.gauges.push_back({"montauk_fractal_hurst_rs", lab, o.hrs});
    r.gauges.push_back({"montauk_fractal_dimension", lab, o.dim});
    r.gauges.push_back({"montauk_fractal_decades", lab, o.decades});
    const bool persistent = o.h - 2 * o.se > 0.5, mean_rev = o.h + 2 * o.se < 0.5;
    pers += persistent;
    anti += mean_rev && !persistent;
    if (persistent || mean_rev)
      r.offenders.push_back({persistent ? "long-range-dependent" : "mean-reverting", o.name, "", "hurst", o.h,
                             o.decades >= 2.0 ? 1 : 0});
    table.arr.push_back(Detail::object().put("series", Detail::text(o.name)).put("hurst_dfa", Detail::of(o.h))
        .put("se", Detail::of(o.se)).put("hurst_rs", Detail::of(o.hrs)).put("dimension", Detail::of(o.dim))
        .put("decades", Detail::of(o.decades)));
  }
  if (avalanches >= 5) {
    r.gauges.push_back({"montauk_fractal_avalanches", "", static_cast<double>(avalanches)});
    r.gauges.push_back({"montauk_fractal_avalanche_slope", "", slope});
    r.offenders.push_back({"migration-avalanche", "migration-rate", "", "runs", static_cast<double>(avalanches), 1});
  }
  if (pers)
    compose_verdict(r, "PERSISTENT", "%zu of %zu series long-range dependent (Hurst 2 s.e. above "
                    "0.5) over %zu bins -- bursts beget bursts", pers, std::size(out), nbins);
  else if (anti)
    compose_verdict(r, "ANTI-PERSISTENT", "%zu of %zu series mean-reverting (Hurst 2 s.e. below 0.5) "
                    "over %zu bins", anti, std::size(out), nbins);
  else
    compose_verdict(r, "UNCORRELATED", "no series separates from uncorrelated (Hurst within 2 s.e. "
                    "of 0.5) over %zu bins", nbins);
  if (!table.arr.empty()) r.detail.emplace_back("series", std::move(table));
}

// REPORT kstrand: per-CPU kernel-thread dispatch strands. A per-CPU kthread
// (ksoftirqd/N, a bound kworker, an endio worker) can run only on its one CPU,
// so a scheduler that strands it behind a long slice backs up I/O completion
// and wedges every fsync waiter into D state without tripping the runnable
// watchdog. Each strand is HELD (its CPU was busy through the wait -- the
// freeze signature) or DARK (its CPU sat idle and tickless).
void derive_kstrand(const Collected& in, ReportResult& r) {
  struct Agg { uint32_t cpu = 0; std::vector<uint64_t> lat; uint64_t held = 0, dark = 0, max_ns = 0, worst_run_ts = 0; };
  std::unordered_map<std::string, Agg> by_comm;
  uint64_t total = 0, worst_held = 0;
  in.each([&](Collected::Row e) {
    ++total;
    const uint64_t run_ts = static_cast<uint64_t>(e.ts()), lat = e.u(1);
    Agg& a = by_comm[e.text(2)];
    a.cpu = static_cast<uint32_t>(e[0]);
    a.lat.push_back(lat);
    if (lat > a.max_ns) { a.max_ns = lat; a.worst_run_ts = run_ts; }
    const uint64_t idle = g_sched_idle.overlap(a.cpu, run_ts > lat ? run_ts - lat : 0, run_ts);
    // Majority-idle through the wait is DARK; otherwise HELD.
    if (idle * 2 >= lat) ++a.dark;
    else { ++a.held; worst_held = std::max(worst_held, lat); }
  });
  std::vector<std::pair<std::string, Agg*>> rows;
  for (auto& kv : by_comm) rows.push_back({kv.first, &kv.second});
  sublimation_order_u64(rows, true, [](const std::pair<std::string, Agg*>& x) { return x.second->max_ns; });
  for (auto& [c, a] : rows) sublimation_u64(a->lat.data(), a->lat.size());
  if (total == 0) {
    compose_verdict(r, "NO-STRAND", "no per-CPU kthread strands over threshold (no I/O-completion starvation captured)");
  } else {
    uint64_t held = 0, dark = 0;
    for (const auto& kv : by_comm) { held += kv.second.held; dark += kv.second.dark; }
    compose_verdict(r, held > dark ? "STRAND-HELD" : dark ? "STRAND-DARK" : "STRAND",
                    "%zu strands across %zu per-CPU kthreads; worst HELD strand %.1fms (I/O-completion freeze signature)",
                    static_cast<size_t>(total), by_comm.size(), ms(worst_held));
    Detail kt = Detail::array();
    for (size_t i = 0; i < rows.size() && i < 20; ++i) {
      const Agg* a = rows[i].second;
      Detail k = Detail::object();
      k.put("kthread", Detail::text(redact_comm(rows[i].first.c_str()))).put("cpu", Detail::count(a->cpu))
       .put("strands", Detail::count(a->lat.size())).put("max_ms", Detail::of(ms(a->max_ns)))
       .put("p99_ms", Detail::of(q_ms(a->lat, 0.99))).put("held", Detail::count(a->held)).put("dark", Detail::count(a->dark));
      if (a->held && a->worst_run_ts) {
        const uint64_t ws = a->worst_run_ts > a->max_ns ? a->worst_run_ts - a->max_ns : 0;
        const CpuHolderLedger::Holder hd = g_sched_holder.dominant(a->cpu, ws, a->worst_run_ts);
        if (hd.window_ns)
          k.put("held_by", Detail::object().put("task", Detail::text(g_sched_holder.name_of(hd.tid)))
                               .put("tid", Detail::count(hd.tid))
                               .put("coverage_pct", Detail::of(100.0 * static_cast<double>(hd.held_ns) / static_cast<double>(hd.window_ns))));
      }
      kt.arr.push_back(std::move(k));
    }
    r.detail.emplace_back("kthreads", std::move(kt));
  }
  r.gauges.push_back({"montauk_analysis_kstrand_events_total", "", static_cast<double>(total)});
  r.gauges.push_back({"montauk_analysis_kstrand_worst_held_ms", "", ms(worst_held)});
  // DARK-only strands are a tickless-rescue gap, not a held strand.
  for (auto& [c, a] : by_comm)
    if (a.held) r.offenders.push_back({"kthread-strand", redact_comm(c.c_str()), "", "max_strand_ms", ms(a.max_ns),
                                       a.max_ns >= 100000000ULL ? 2 : 1});
}

// The cache_topology provider snapshot, parsed: cpu -> {l2, l3, socket}, and the
// tier distance between two CPUs (0 same-L2 ... 3 cross-socket, -1 unmapped).
struct Topology {
  std::unordered_map<uint32_t, std::array<uint32_t, 3>> cpu;
  uint32_t nr_cpus = 0;
  bool fold(uint32_t type, const uint8_t* data, uint32_t len) {
    if (type != TRACE_EVT_PROVIDER || len < sizeof(montauk_provider_event)) return false;
    const auto* e = reinterpret_cast<const montauk_provider_event*>(data);
    if (std::strncmp(e->name, "cache_topology", sizeof(e->name)) != 0) return true;
    const uint32_t avail = len - static_cast<uint32_t>(sizeof(montauk_provider_event));
    const std::string text(reinterpret_cast<const char*>(data + sizeof(montauk_provider_event)),
                           std::min(e->payload_len, avail));
    auto pu = [](const std::string& line, const char* key, uint32_t& out) {
      const std::string pat = std::string(key) + "=\"";
      const size_t k = line.find(pat);
      if (k == std::string::npos) return false;
      out = static_cast<uint32_t>(std::strtoul(line.c_str() + k + pat.size(), nullptr, 10));
      return true;
    };
    for (size_t pos = 0; pos < text.size();) {
      const size_t eol = text.find('\n', pos);
      const std::string line = text.substr(pos, eol == std::string::npos ? std::string::npos : eol - pos);
      pos = eol == std::string::npos ? text.size() : eol + 1;
      uint32_t c, l2, l3, sock;
      if (pu(line, "cpu", c) && pu(line, "l2", l2) && pu(line, "l3", l3) && pu(line, "socket", sock)) {
        cpu[c] = {l2, l3, sock};
        nr_cpus = std::max(nr_cpus, c + 1);
      }
    }
    return true;
  }
  bool empty() const { return cpu.empty(); }
  int tier(uint32_t a, uint32_t b) const {
    auto ia = cpu.find(a), ib = cpu.find(b);
    if (ia == cpu.end() || ib == cpu.end()) return -1;
    for (int t = 0; t < 3; ++t) if (ia->second[t] == ib->second[t]) return t;
    return 3;
  }
};
constexpr const char* kTierName[4] = {"same_l2", "same_l3", "same_socket", "cross_socket"};

// REPORT locality: each migration as a cache-tier distance (same-L2, same-L3,
// same-socket, cross-socket) and how migration density decays with distance --
// a lens that characterizes any scheduler equally. Plus WAKE AFFINITY: a wake
// placed relative to the WAKER's CPU, since the data the wakee is about to touch
// was written there, which a task's distance from its own past cannot show.
struct LocalityStream final : Stream {
  Topology topo;
  std::array<uint64_t, 4> tier{}, si_tier{}, wake_tier{};
  uint64_t migrations = 0, unmapped = 0, si_migrations = 0, si_unmapped = 0;
  uint64_t wake_same_cpu = 0, wake_edges = 0, wake_unresolved = 0;
  uint64_t steal_mig = 0, place_mig = 0, ts_min = 0, ts_max = 0;
  bool have_lane = false;
  std::unordered_map<int, uint64_t> last_mig_ts, si_last_mig_ts;
  std::unordered_map<int, uint32_t> last_lane, cpu_of;
  std::vector<uint64_t> intervals, si_intervals, steal_iv, place_iv;
  void span(uint64_t ts) {
    if (ts_min == 0 || ts < ts_min) ts_min = ts;
    if (ts > ts_max) ts_max = ts;
  }
  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (topo.fold(type, data, len)) return;
    if (type != TRACE_EVT_SCHED || len < sizeof(montauk_sched_event)) return;
    const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
    const bool mine = qual_match(-1, static_cast<uint32_t>(s->pid), static_cast<uint32_t>(s->pid), "");
    // Occupancy is tracked BEFORE the row qualifier: the waker is by definition
    // another pid, so narrowing this would make every waker unresolvable.
    if (s->op == SCHED_OP_SWITCH_IN) {
      cpu_of[s->pid] = s->cpu;
      if (!mine) return;
      span(s->timestamp_ns);
      if (s->last_cpu >= 0 && s->last_cpu != static_cast<int32_t>(s->cpu)) {
        ++si_migrations;
        const int t = topo.tier(static_cast<uint32_t>(s->last_cpu), s->cpu);
        if (t >= 0) ++si_tier[t]; else ++si_unmapped;
        auto m = si_last_mig_ts.find(s->pid);
        if (m != si_last_mig_ts.end() && s->timestamp_ns > m->second) si_intervals.push_back(s->timestamp_ns - m->second);
        si_last_mig_ts[s->pid] = s->timestamp_ns;
      }
      return;
    }
    if (!mine) return;
    if (s->op == SCHED_OP_WAKEUP) {
      if (s->secondary_pid < 0) return;   // kernel/IRQ wake, no task origin
      auto it = cpu_of.find(s->secondary_pid);
      if (it == cpu_of.end()) { ++wake_unresolved; return; }
      ++wake_edges;
      if (it->second == s->cpu) { ++wake_same_cpu; return; }
      const int t = topo.tier(it->second, s->cpu);
      if (t >= 0) ++wake_tier[t]; else ++wake_unresolved;
      return;
    }
    span(s->timestamp_ns);
    // PICK lane: 0 the task ran where it was placed, >0 a steal pulled it.
    if (s->op == SCHED_OP_PICK) { last_lane[s->pid] = s->sub_idx; have_lane = true; return; }
    if (s->op != SCHED_OP_WAKE2RUN || s->last_cpu < 0 || s->last_cpu == static_cast<int32_t>(s->cpu)) return;
    ++migrations;
    auto lit = last_lane.find(s->pid);
    const bool by_steal = lit != last_lane.end() && lit->second > 0;
    (by_steal ? steal_mig : place_mig)++;
    auto m = last_mig_ts.find(s->pid);
    if (m != last_mig_ts.end() && s->timestamp_ns > m->second) {
      intervals.push_back(s->timestamp_ns - m->second);
      (by_steal ? steal_iv : place_iv).push_back(s->timestamp_ns - m->second);
    }
    last_mig_ts[s->pid] = s->timestamp_ns;
    const int t = topo.tier(static_cast<uint32_t>(s->last_cpu), s->cpu);
    if (t < 0) ++unmapped; else ++tier[t];
  }
};

void derive_locality(const Stream& st, ReportResult& r) {
  const auto& L = static_cast<const LocalityStream&>(st);
  // The complete population: SWITCH_IN carries every task's every move; a
  // capture without it has only the woken subset through WAKE2RUN.
  const bool si = L.si_migrations > 0;
  const uint64_t migrations = si ? L.si_migrations : L.migrations, unmapped = si ? L.si_unmapped : L.unmapped;
  const std::array<uint64_t, 4> tier = si ? L.si_tier : L.tier;
  std::vector<uint64_t> intervals = si ? L.si_intervals : L.intervals;
  if (L.topo.empty()) {
    compose_verdict(r, "NO-TOPOLOGY", "no cache_topology snapshot in the trace -- cannot map "
                                      "migration distance (recapture with montauk >= 7.8.0)");
    return;
  }
  const uint64_t cl = tier[0] + tier[1] + tier[2] + tier[3];
  if (cl == 0) {
    compose_verdict(r, "NONE", "no cross-CPU migrations captured");
    return;
  }
  // Monotone from the first POPULATED tier: an empty finer tier (same-L2 on a
  // part with no shared L2) does not exist on that hardware.
  bool mono = true, seen = false;
  uint64_t prev = 0;
  for (int t = 0; t < 4; t++) {
    if (!seen && tier[t] == 0) continue;
    if (seen && tier[t] > prev) { mono = false; break; }
    prev = tier[t];
    seen = true;
  }
  const double local_pct = 100.0 * static_cast<double>(tier[0] + tier[1]) / static_cast<double>(cl);
  // SCATTERED -- density not decaying with distance -- is placement ignoring
  // the cache hierarchy, a different defect from migrating often but locally.
  compose_verdict(r, !mono ? "SCATTERED" : local_pct >= 90.0 ? "CACHE-LOCAL" : "SPREAD",
                  "%.1f%% of migrations stay cache-local (same-L2/L3); density %s", local_pct,
                  mono ? "decays with distance (locality preserved)"
                       : "does NOT decay with distance (placement scatters across domains)");
  auto& g = r.gauges;
  for (int t = 0; t < 4; t++)
    g.push_back({"montauk_analysis_locality_tier_moves", std::string("tier=\"") + kTierName[t] + "\"", static_cast<double>(tier[t])});
  g.push_back({"montauk_analysis_locality_local_pct", "", local_pct});
  const double span_s = L.ts_max > L.ts_min ? static_cast<double>(L.ts_max - L.ts_min) / 1e9 : 0.0;
  g.push_back({"montauk_analysis_locality_migration_rate_hz", "", span_s > 0.0 ? static_cast<double>(migrations) / span_s : 0.0});
  if (!intervals.empty()) {
    sublimation_u64(intervals.data(), intervals.size());
    g.push_back({"montauk_analysis_locality_intermigration_us", "quantile=\"p50\"", q_us(intervals, 0.50)});
    g.push_back({"montauk_analysis_locality_intermigration_us", "quantile=\"p99\"", q_us(intervals, 0.99)});
  }
  const uint64_t wt = L.wake_tier[0] + L.wake_tier[1] + L.wake_tier[2] + L.wake_tier[3];
  if (L.wake_edges > 0) {
    g.push_back({"montauk_analysis_wake_affine_edges", "", static_cast<double>(L.wake_edges)});
    g.push_back({"montauk_analysis_wake_affine_same_cpu_pct", "",
                 100.0 * static_cast<double>(L.wake_same_cpu) / static_cast<double>(L.wake_edges)});
    for (int t = 0; t < 4; t++)
      g.push_back({"montauk_analysis_wake_affine_tier_edges", std::string("tier=\"") + kTierName[t] + "\"",
                   static_cast<double>(L.wake_tier[t])});
    g.push_back({"montauk_analysis_wake_affine_local_pct", "",
                 wt ? 100.0 * static_cast<double>(L.wake_tier[0] + L.wake_tier[1]) / static_cast<double>(wt) : 0.0});
    g.push_back({"montauk_analysis_wake_affine_unresolved", "", static_cast<double>(L.wake_unresolved)});
  }
  r.detail.emplace_back("migrations", Detail::object()
      .put("moves", Detail::count(migrations)).put("unmapped", Detail::count(unmapped))
      .put("source", Detail::text(si ? "switch-in (all dispatches)"
                                     : "wake2run (woken tasks only -- recapture with --sched-detail for the full population)")));
  if (L.have_lane) {
    auto cadence = [](std::vector<uint64_t> v) {
      if (v.empty()) return 0.0;
      sublimation_u64(v.data(), v.size());
      return q_us(v, 0.50);
    };
    const uint64_t a = L.steal_mig + L.place_mig;
    r.detail.emplace_back("migration_cause", Detail::object()
        .put("steal_pct", Detail::of(a ? 100.0 * static_cast<double>(L.steal_mig) / static_cast<double>(a) : 0.0))
        .put("steal_cadence_p50_us", Detail::of(cadence(L.steal_iv)))
        .put("placement_pct", Detail::of(a ? 100.0 * static_cast<double>(L.place_mig) / static_cast<double>(a) : 0.0))
        .put("placement_cadence_p50_us", Detail::of(cadence(L.place_iv))));
  }
}

// REPORT dsq-placement: WHO DECIDED EACH MIGRATION. A task a policy sent to a
// far core and a task dropped into a shared queue a far core happened to win
// produce identical switch events and want opposite fixes. Two lanes answer it.
// MIGRATE (always on, class-agnostic): the CPU that executed the move names the
// decider -- the destination PULLED, the source PUSHED, or a third party
// PLACED it. The DSQ kfuncs (opt-in): dsq_id is self-describing, an id below
// the CPU count names a destination (NAMED), one above defers it to whoever
// drains (POOL, the drain race), and a per-CPU queue drained by another CPU is
// a STEAL. A drain names no task, so the next SWITCH_IN on that CPU supplies it.
struct DsqStream final : Stream {
  static constexpr uint64_t kDrainPairWindowNs = 1000000;   // one tick
  Topology topo;
  uint64_t ins_total = 0, ins_named = 0, ins_pool = 0, ins_unknown_src = 0, named_stay = 0, named_move = 0;
  std::array<uint64_t, 4> named_tier{}, pool_tier{}, steal_tier{};
  std::unordered_map<uint64_t, uint64_t> pool_ins;                                   // dsq -> inserts
  std::unordered_map<uint32_t, uint64_t> pend_dsq, pend_ts;                          // cpu -> its pending drain
  std::unordered_map<uint64_t, std::unordered_map<uint32_t, uint64_t>> pool_drain_by_cpu;
  uint64_t pool_moves = 0, steal_moves = 0, drain_stays = 0, drains_unmatched = 0, drains_total = 0;
  uint64_t mig_total = 0, mig_pull = 0, mig_push = 0, mig_place = 0, place_to_decider_cpu = 0, place_decider_local = 0;
  std::array<uint64_t, 4> mig_pull_tier{}, mig_push_tier{}, mig_place_tier{};
  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (topo.fold(type, data, len)) return;
    if (type != TRACE_EVT_SCHED || len < sizeof(montauk_sched_event)) return;
    const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
    const bool mine = qual_match(-1, static_cast<uint32_t>(s->pid), static_cast<uint32_t>(s->pid), "");
    const uint32_t ncpu = topo.nr_cpus;
    if (s->op == SCHED_OP_MIGRATE) {
      if (!mine || s->last_cpu < 0) return;
      const uint32_t src = static_cast<uint32_t>(s->last_cpu), dst = s->cpu, dec = s->sub_idx;
      if (src == dst) return;
      ++mig_total;
      const int t = topo.tier(src, dst);
      if (dec == dst) { ++mig_pull; if (t >= 0) ++mig_pull_tier[t]; }
      else if (dec == src) { ++mig_push; if (t >= 0) ++mig_push_tier[t]; }
      else {
        ++mig_place;
        if (t >= 0) ++mig_place_tier[t];
        // A handoff keeps producer and consumer together; a placement blind
        // to the decider does not.
        if (dst == dec) ++place_to_decider_cpu;
        const int dt = topo.tier(dec, dst);
        if (dt == 0 || dt == 1) ++place_decider_local;
      }
      return;
    }
    if (s->op == SCHED_OP_DSQ_INSERT) {
      if (!mine) return;
      ++ins_total;
      if (ncpu && s->score < ncpu) {
        ++ins_named;
        const auto dst = static_cast<uint32_t>(s->score);
        if (s->last_cpu < 0) ++ins_unknown_src;
        else if (static_cast<uint32_t>(s->last_cpu) == dst) ++named_stay;
        else { ++named_move; const int t = topo.tier(static_cast<uint32_t>(s->last_cpu), dst); if (t >= 0) ++named_tier[t]; }
      } else {
        ++ins_pool;
        ++pool_ins[s->score];
      }
      return;
    }
    if (s->op == SCHED_OP_DSQ_DRAIN) {
      ++drains_total;
      if (pend_ts.count(s->cpu)) ++drains_unmatched;   // replaced before a switch-in claimed it
      pend_dsq[s->cpu] = s->score;
      pend_ts[s->cpu] = s->timestamp_ns;
      if (!ncpu || s->score >= ncpu) ++pool_drain_by_cpu[s->score][s->cpu];
      return;
    }
    if (s->op != SCHED_OP_SWITCH_IN) return;
    auto pt = pend_ts.find(s->cpu);
    if (pt == pend_ts.end()) return;
    const uint64_t dsq = pend_dsq[s->cpu];
    const uint64_t age = s->timestamp_ns >= pt->second ? s->timestamp_ns - pt->second : 0;
    pend_ts.erase(pt);
    pend_dsq.erase(s->cpu);
    if (age > kDrainPairWindowNs) { ++drains_unmatched; return; }
    if (!mine) return;
    if (!(s->last_cpu >= 0 && s->last_cpu != static_cast<int32_t>(s->cpu))) { ++drain_stays; return; }
    const int t = topo.tier(static_cast<uint32_t>(s->last_cpu), s->cpu);
    if (ncpu && dsq < ncpu && static_cast<uint32_t>(dsq) != s->cpu) { ++steal_moves; if (t >= 0) ++steal_tier[t]; }
    else if (!ncpu || dsq >= ncpu) { ++pool_moves; if (t >= 0) ++pool_tier[t]; }
    // dsq == this cpu: its own queue; the NAMED insert already decided the move.
  }
};

void derive_dsq_placement(const Stream& st, ReportResult& r) {
  const auto& d = static_cast<const DsqStream&>(st);
  auto pct = [](uint64_t a, uint64_t b) { return b ? 100.0 * static_cast<double>(a) / static_cast<double>(b) : 0.0; };
  auto tiers = [&](const std::array<uint64_t, 4>& t, uint64_t tot) {
    Detail o = Detail::object();
    for (int i = 0; i < 4; ++i) o.put(kTierName[i], Detail::of(pct(t[i], tot)));
    return o;
  };
  if (d.mig_total)
    r.detail.emplace_back("by_decider", Detail::object()
        .put("migrations", Detail::count(d.mig_total))
        .put("place_pct", Detail::of(pct(d.mig_place, d.mig_total))).put("pull_pct", Detail::of(pct(d.mig_pull, d.mig_total)))
        .put("push_pct", Detail::of(pct(d.mig_push, d.mig_total)))
        .put("place_onto_decider_cpu_pct", Detail::of(pct(d.place_to_decider_cpu, d.mig_place)))
        .put("place_decider_local_pct", Detail::of(pct(d.place_decider_local, d.mig_place)))
        .put("place_tiers", tiers(d.mig_place_tier, d.mig_place)).put("pull_tiers", tiers(d.mig_pull_tier, d.mig_pull))
        .put("push_tiers", tiers(d.mig_push_tier, d.mig_push)));
  const uint64_t decided = d.named_move + d.pool_moves + d.steal_moves;
  if (decided)
    r.detail.emplace_back("by_dsq", Detail::object()
        .put("inserts", Detail::count(d.ins_total)).put("named_pct", Detail::of(pct(d.ins_named, d.ins_total)))
        .put("pool_pct", Detail::of(pct(d.ins_pool, d.ins_total))).put("attributed", Detail::count(decided))
        .put("placement_pct", Detail::of(pct(d.named_move, decided)))
        .put("drain_race_pct", Detail::of(pct(d.pool_moves, decided))).put("steal_pct", Detail::of(pct(d.steal_moves, decided)))
        .put("drains", Detail::count(d.drains_total)).put("drains_unmatched", Detail::count(d.drains_unmatched))
        .put("drains_unmoved", Detail::count(d.drain_stays)));
  if (decided) {
    if (d.named_move >= d.pool_moves && d.named_move >= d.steal_moves)
      compose_verdict(r, "PLACEMENT", "%llu attributed moves; PLACEMENT names these CPUs -- the fix is "
                      "in the placement function", static_cast<unsigned long long>(decided));
    else if (d.pool_moves >= d.steal_moves)
      compose_verdict(r, "DRAIN-RACE", "%llu attributed moves; THE DRAIN RACE owns them -- narrow the "
                      "shared queue or bind its drain", static_cast<unsigned long long>(decided));
    else
      compose_verdict(r, "STEAL", "%llu attributed moves; STEALS pull placed tasks -- price or gate "
                      "the steal", static_cast<unsigned long long>(decided));
    return;
  }
  if (d.mig_total) {
    if (d.mig_place >= d.mig_pull && d.mig_place >= d.mig_push)
      compose_verdict(r, "PLACE", "%llu migrations by executing CPU; a THIRD PARTY sends most moves "
                      "(on a wake, the waker) -- the fix is in wake placement", static_cast<unsigned long long>(d.mig_total));
    else if (d.mig_pull >= d.mig_push)
      compose_verdict(r, "PULL", "%llu migrations by executing CPU; DESTINATIONS pull most moves -- "
                      "the fix is in the steal or the shared-queue drain", static_cast<unsigned long long>(d.mig_total));
    else
      compose_verdict(r, "PUSH", "%llu migrations by executing CPU; SOURCES shed most moves -- the "
                      "fix is in the balance/push path", static_cast<unsigned long long>(d.mig_total));
    return;
  }
  compose_verdict(r, "NONE", "no migration or DSQ placement events in this capture");
}

const ReportDef kWakers = {"wakers", {}, false, nullptr, false,
                           [] { return std::unique_ptr<Stream>(new WakersStream); }, derive_wakers};
const ReportDef kFractal = {"fractal", {}, false, nullptr, false,
                            [] { return std::unique_ptr<Stream>(new FractalStream); }, derive_fractal};
const ReportDef kKStrand = {"kstrand", {{"kstrand", {"cpu", "latency_ns", "comm"}}}, true, derive_kstrand};
const ReportDef kLocality = {"locality", {}, false, nullptr, false,
                             [] { return std::unique_ptr<Stream>(new LocalityStream); }, derive_locality};
const ReportDef kDsqPlacement = {"dsq-placement", {}, false, nullptr, false,
                                 [] { return std::unique_ptr<Stream>(new DsqStream); }, derive_dsq_placement};

// REPORT sched: wake-to-run latency over WAKE2RUN (became-runnable -> ran).
// It surfaces the BIMODAL split -- the cache-hot fast mode against the
// CONFIG_HZ tick-quantized floor -- and how much of the slow tail is
// cross-domain. The arrival-order sequence is classified before the quantile
// sort destroys it: a mid-trace regime change, quantization onto a few tick
// values, or drift. Cold wakes -- onto a core idle >= 20ms, tagged with its
// frequency at the wake -- separate a ramp from minimum frequency from a slow
// dispatch path.
struct SchedStream final : Stream {
  static constexpr uint64_t kColdIdleNs = 20000000ULL;
  struct Cold { uint64_t lat_ns; uint32_t freq_mhz; uint64_t idle_ns; };
  std::vector<uint64_t> lat, cross;
  std::unordered_map<uint32_t, uint64_t> idle_enter;   // cpu -> ts it entered idle
  std::vector<Cold> cold;
  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type != TRACE_EVT_SCHED || len < sizeof(montauk_sched_event)) return;
    const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
    // The CPU_IDLE leave lands just AFTER the WAKE2RUN of the task coming on,
    // so at WAKE2RUN the enter stamp is still live and the idle span exact.
    if (s->op == SCHED_OP_CPU_IDLE) {
      if (s->sub_idx == 1) idle_enter[s->cpu] = s->timestamp_ns;
      else idle_enter.erase(s->cpu);
      return;
    }
    if (s->op != SCHED_OP_WAKE2RUN || !qual_match(-1, static_cast<uint32_t>(s->pid), static_cast<uint32_t>(s->pid), "")) return;
    lat.push_back(s->runtime_ns);
    if (s->sub_idx) cross.push_back(s->runtime_ns);
    auto it = idle_enter.find(s->cpu);
    if (it != idle_enter.end() && s->timestamp_ns > it->second && s->timestamp_ns - it->second >= kColdIdleNs)
      cold.push_back({s->runtime_ns, s->freq_mhz, s->timestamp_ns - it->second});
  }
};

void derive_sched(const Stream& st, ReportResult& r) {
  const auto& S = static_cast<const SchedStream&>(st);
  if (S.lat.empty()) {
    compose_verdict(r, "NO-WAKE2RUN", "no WAKE2RUN events in trace (wake-to-run tracepoint not streamed?)");
    return;
  }
  std::vector<uint64_t> lat = S.lat, cross = S.cross;
  const double dn = static_cast<double>(lat.size());
  // WHAT the arrival-order sequence is, then WHERE its structure sits: the
  // profile slides the classifier across the stream, so the structured
  // stretches are named and their share measured.
  const sub_profile_t prof = sublimation_classify_u64(lat.data(), lat.size());
  double structured = 0.0;
  Detail regions = Detail::array();
  if (lat.size() >= 1024) {
    const size_t win = std::min<size_t>(512, lat.size() / 8);
    std::vector<sub_match_t> wins(lat.size() / win + 2);
    const size_t nw = sublimation_profile_u64(lat.data(), lat.size(), win, win, wins.data(), wins.size());
    size_t n_struct = 0;
    for (size_t i = 0; i < nw; ++i) if (wins[i].disorder != SUB_RANDOM) ++n_struct;
    structured = nw ? static_cast<double>(n_struct) / static_cast<double>(nw) : 0.0;
    for (size_t i = 0; i < nw;) {
      if (wins[i].disorder == SUB_RANDOM) { ++i; continue; }
      const sub_disorder_t cls = wins[i].disorder;
      const size_t start = wins[i].start;
      size_t j = i;
      while (j < nw && wins[j].disorder == cls) ++j;
      const size_t end = wins[j - 1].start + wins[j - 1].len;
      regions.arr.push_back(Detail::object().put("class", Detail::text(disorder_name(cls)))
          .put("start_pct", Detail::of(100.0 * static_cast<double>(start) / dn))
          .put("end_pct", Detail::of(100.0 * static_cast<double>(end) / dn)));
      i = j;
    }
  }
  sublimation_u64(lat.data(), lat.size());
  if (!cross.empty()) sublimation_u64(cross.data(), cross.size());
  constexpr uint64_t kFastNs = 100000, kTickNs = 900000;
  size_t fast = 0, tick = 0;
  for (uint64_t v : lat) { if (v < kFastNs) ++fast; else if (v >= kTickNs) ++tick; }
  const double p50 = q_us(lat, 0.50), p99 = q_us(lat, 0.99), p999 = q_us(lat, 0.999), worst = us(lat.back());
  const double fastpct = 100.0 * static_cast<double>(fast) / dn, tickpct = 100.0 * static_cast<double>(tick) / dn;
  // From the count: the residual 100 - fast - tick printed "-0.0% mid".
  const double midpct = 100.0 * static_cast<double>(lat.size() - fast - tick) / dn;
  const double crosspct = 100.0 * static_cast<double>(cross.size()) / dn;
  Measures m;
  m.set("tick_pct", tickpct);
  m.set("fast_pct", fastpct);
  compose_verdict(r, pick_verdict({{"TICK-FLOORED", "tick_pct", 'G', 50.0}, {"FAST", "fast_pct", 'G', 90.0},
                                   {"MIXED", nullptr, 0, 0}}, m),
                  "%s wake2run; p50 %.0fus p99 %.0fus p999 %.0fus worst %.0fus; "
                  "%.1f%% fast(<100us) / %.1f%% mid / %.1f%% tick-floor(>=900us); %.1f%% cross-domain",
                  fmt_count(dn).c_str(), p50, p99, p999, worst, fastpct, midpct, tickpct, crosspct);
  r.detail.emplace_back("wake2run", Detail::object()
      .put("count", Detail::count(lat.size())).put("p50_us", Detail::of(p50)).put("p99_us", Detail::of(p99))
      .put("p999_us", Detail::of(p999)).put("worst_us", Detail::of(worst)).put("fast_pct", Detail::of(fastpct))
      .put("mid_pct", Detail::of(midpct)).put("tickfloor_pct", Detail::of(tickpct))
      .put("crossdomain_pct", Detail::of(crosspct)));
  if (!cross.empty())
    r.detail.emplace_back("cross_domain", Detail::object()
        .put("count", Detail::count(cross.size())).put("p50_us", Detail::of(q_us(cross, 0.50)))
        .put("p99_us", Detail::of(q_us(cross, 0.99))).put("worst_us", Detail::of(us(cross.back()))));
  Detail structure = Detail::object();
  structure.put("class", Detail::text(disorder_name(prof.disorder)));
  if (prof.phase_boundary) structure.put("phase_pct", Detail::of(100.0 * static_cast<double>(prof.phase_boundary) / dn));
  structure.put("distinct_estimate", Detail::count(prof.distinct_estimate))
           .put("inversion_ratio", Detail::of(static_cast<double>(prof.inversion_ratio)))
           .put("structured_pct", Detail::of(100.0 * structured));
  r.detail.emplace_back("structure", std::move(structure));
  if (!regions.arr.empty()) r.detail.emplace_back("located_regions", std::move(regions));
  push_quantile_gauges(r.gauges, "montauk_analysis_wake2run_us", {{"0.5", p50}, {"0.99", p99}, {"0.999", p999}, {"worst", worst}});
  r.gauges.push_back({"montauk_analysis_wake2run_fast_pct", "", fastpct});
  r.gauges.push_back({"montauk_analysis_wake2run_mid_pct", "", midpct});
  r.gauges.push_back({"montauk_analysis_wake2run_tickfloor_pct", "", tickpct});
  r.gauges.push_back({"montauk_analysis_wake2run_crossdomain_pct", "", crosspct});
  r.gauges.push_back({"montauk_analysis_wake2run_distinct", "", static_cast<double>(prof.distinct_estimate)});
  r.gauges.push_back({"montauk_analysis_wake2run_structured_pct", "", 100.0 * structured});
  if (S.cold.empty()) return;
  // Slow cold wakes at the minimum frequency seen are a ramp from deep idle;
  // at nominal frequency they are the scheduler's wake path.
  std::vector<SchedStream::Cold> c = S.cold;
  sublimation_order_u64(c, false, [](const SchedStream::Cold& w) { return w.lat_ns; });
  auto cq = [&](double f) { return us(c[std::min(c.size() - 1, static_cast<size_t>(static_cast<double>(c.size()) * f))].lat_ns); };
  uint32_t fmin = 0, slowq = 0;
  bool have_freq = false;
  for (const auto& w : c) if (w.freq_mhz) { have_freq = true; if (!fmin || w.freq_mhz < fmin) fmin = w.freq_mhz; }
  if (have_freq && c.size() >= 4) {
    std::vector<uint32_t> sf;
    for (size_t i = c.size() - c.size() / 4; i < c.size(); ++i) if (c[i].freq_mhz) sf.push_back(c[i].freq_mhz);
    if (!sf.empty()) { sublimation_u32(sf.data(), sf.size()); slowq = sf[sf.size() / 2]; }
  }
  Detail cw = Detail::object();
  cw.put("count", Detail::count(c.size())).put("p50_us", Detail::of(cq(0.50))).put("p99_us", Detail::of(cq(0.99)))
    .put("worst_us", Detail::of(us(c.back().lat_ns))).put("have_freq", Detail::flag(have_freq));
  if (have_freq)
    cw.put("freq_min_mhz", Detail::count(fmin)).put("freq_slowq_mhz", Detail::count(slowq))
      .put("freq_verdict", Detail::text(slowq && fmin && slowq <= fmin + fmin / 4
                                            ? "RAMP-BOUND (slow cold-wakes at min freq -- governor/arch, not dispatch)"
                                        : slowq ? "DISPATCH-BOUND (slow cold-wakes at nominal freq -- scheduler wake path)"
                                                : "inconclusive (freq spread too sparse)"));
  r.detail.emplace_back("cold_wake", std::move(cw));
  r.gauges.push_back({"montauk_analysis_coldwake_count", "", static_cast<double>(c.size())});
  r.gauges.push_back({"montauk_analysis_coldwake_wake2run_us", "quantile=\"0.5\"", cq(0.50)});
  r.gauges.push_back({"montauk_analysis_coldwake_wake2run_us", "quantile=\"0.99\"", cq(0.99)});
  r.gauges.push_back({"montauk_analysis_coldwake_wake2run_us", "quantile=\"worst\"", us(c.back().lat_ns)});
  r.gauges.push_back({"montauk_analysis_coldwake_freq_min_mhz", "", static_cast<double>(fmin)});
  r.gauges.push_back({"montauk_analysis_coldwake_freq_slowq_mhz", "", static_cast<double>(slowq)});
}

// REPORT dispatch-stall: why each wake over the floor waited on its run-CPU,
// by the picks that CPU made of OTHER tasks during the wait. None is
// PREEMPT-STARVED -- one task held the CPU; the fix is wakeup preemption. Some
// is ORDER-STARVED -- the CPU kept serving others first; the fix is in pick
// order. PREEMPT-STARVED splits again into HELD (a task ran the CPU through the
// wait) and DARK (it sat idle and tickless, no rescue), and a CPU still dark at
// trace end is a CENSORED strand, the host-death signature.
struct DispatchStream final : Stream {
  struct FW { uint64_t wake_ts, run_ts; uint32_t cpu; int pid; };
  std::vector<FW> floored;
  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type != TRACE_EVT_SCHED || len < sizeof(montauk_sched_event)) return;
    const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
    if (s->op != SCHED_OP_WAKE2RUN || s->runtime_ns < g_qual_floor_ns) return;
    // Qualifiers narrow WHICH wakes are analyzed, never the pass-over context.
    if (!qual_match(-1, static_cast<uint32_t>(s->pid), static_cast<uint32_t>(s->pid), "")) return;
    floored.push_back({s->timestamp_ns > s->runtime_ns ? s->timestamp_ns - s->runtime_ns : 0, s->timestamp_ns, s->cpu, s->pid});
  }
};

void derive_dispatch_stall(const Stream& st, ReportResult& r) {
  // ONE TICK, A LOOKAHEAD BOUND: how far past run_ts the serving pick is
  // sought. It must not follow --floor-us down, or no wake would find it.
  constexpr uint64_t kTickFloorNs = 900000ULL, kCensoredStrandNs = 50000000ULL;
  const auto& D = static_cast<const DispatchStream&>(st);
  using Pk = CpuPickTimeline::Pk;
  auto cls_of = [](uint64_t score) { return score >> 48; };
  // Censored strands first: a wedged host emits no WAKE2RUN, so nothing is
  // floored in exactly the lethal case the summary must not read as healthy.
  uint64_t censored = 0, worst_censored = 0;
  for (const auto& kv : g_sched_idle.open_)
    if (g_sched_max_ts > kv.second && g_sched_max_ts - kv.second >= kCensoredStrandNs) {
      ++censored;
      worst_censored = std::max(worst_censored, g_sched_max_ts - kv.second);
    }
  const double floor_us = static_cast<double>(g_qual_floor_ns) / 1000.0;
  char b[512];
  if (censored) {
    r.gauges.push_back({"montauk_analysis_dispatch_censored_strands", "", static_cast<double>(censored)});
    r.gauges.push_back({"montauk_analysis_dispatch_worst_censored_ms", "", static_cast<double>(worst_censored) / 1e6});
  }
  auto add_censored = [&](std::string& v) {
    if (!censored) return;
    std::snprintf(b, sizeof b, "; CENSORED %llu CPU(s) dark at trace end, worst %.1fms unresolved "
                  "(host-death signature, not in worst-dark)",
                  static_cast<unsigned long long>(censored), static_cast<double>(worst_censored) / 1e6);
    v += b;
    r.detail.emplace_back("censored_strands", Detail::object().put("cpus", Detail::count(censored))
                                                  .put("worst_ms", Detail::of(static_cast<double>(worst_censored) / 1e6)));
  };
  if (D.floored.empty()) {
    std::snprintf(b, sizeof b, "no wakes over the %.0fus floor to attribute%s", floor_us, censored ? "" : " (nothing pending)");
    std::string v = b;
    add_censored(v);
    r.verdict = v;
    r.klass = "NONE";
    return;
  }
  const bool reconstructed = g_sched_picks.reconstructed();
  const auto& src = g_sched_picks.active();
  const bool have_idle = !g_sched_idle.empty();
  uint64_t preempt = 0, order = 0, inter_sum = 0, held = 0, dark = 0, worst_dark = 0;
  uint64_t po_total = 0, po_mirror = 0, served_total = 0, served_mirror = 0;
  uint64_t cls_total = 0, cls_higher = 0, cls_same = 0, cls_lower = 0, same_newer = 0, distinct_sum = 0;
  std::vector<uint64_t> inter_v, legit_v;
  struct CTL { uint64_t ts; uint32_t distinct, inter; };
  std::vector<CTL> conc;
  std::unordered_map<uint32_t, uint64_t> offender, held_by;
  for (const auto& fw : D.floored) {
    auto it = src.find(fw.cpu);
    uint64_t inter = 0, legit = 0;
    std::unordered_set<int> po_pids;
    if (it != src.end()) {
      const auto& pv = it->second;
      // The pick that finally served this wakee, and its class and score.
      bool have_served = false;
      uint64_t served_cls = 0, served_score = 0;
      for (auto p = std::lower_bound(pv.begin(), pv.end(), fw.run_ts, [](const Pk& e, uint64_t v) { return e.ts < v; });
           p != pv.end() && p->ts <= fw.run_ts + kTickFloorNs; ++p)
        if (p->pid == fw.pid) {
          ++served_total;
          if (p->lane == 0) ++served_mirror;
          served_cls = cls_of(p->score); served_score = p->score; have_served = true;
          break;
        }
      // Pass-overs: picks of OTHER pids during [wake, run). HIGHER class or an
      // older same-class task is a legitimate drain; LOWER class or a newer
      // same-class task is an inversion the score key should have prevented.
      for (auto p = std::lower_bound(pv.begin(), pv.end(), fw.wake_ts, [](const Pk& e, uint64_t v) { return e.ts < v; });
           p != pv.end() && p->ts < fw.run_ts; ++p) {
        if (p->pid == fw.pid) continue;
        ++inter; ++po_total;
        if (p->lane == 0) ++po_mirror;
        po_pids.insert(p->pid);
        if (!have_served) { ++legit; continue; }
        const uint64_t c = cls_of(p->score);
        ++cls_total;
        if (c > served_cls) { ++cls_higher; ++legit; }
        else if (c < served_cls) ++cls_lower;
        else { ++cls_same; if (p->score < served_score) ++same_newer; else ++legit; }
      }
    }
    if (inter == 0) {
      ++preempt;
      // Majority-idle through the wait is DARK, the tickless strand.
      if (have_idle) {
        const uint64_t wait_ns = fw.run_ts > fw.wake_ts ? fw.run_ts - fw.wake_ts : 0;
        const uint64_t idle_ns = g_sched_idle.overlap(fw.cpu, fw.wake_ts, fw.run_ts);
        if (wait_ns && idle_ns * 2 >= wait_ns) { ++dark; worst_dark = std::max(worst_dark, wait_ns); }
        else {
          ++held;
          const CpuHolderLedger::Holder hd = g_sched_holder.dominant(fw.cpu, fw.wake_ts, fw.run_ts);
          if (hd.tid) held_by[hd.tid] += hd.held_ns;
        }
      }
    } else {
      ++order; inter_sum += inter;
      const CpuHolderLedger::Recip rc = g_sched_holder.top_picked(fw.cpu, fw.wake_ts, fw.run_ts, fw.pid);
      if (rc.tid) offender[rc.tid] += rc.count;
    }
    distinct_sum += po_pids.size();
    inter_v.push_back(inter);
    legit_v.push_back(legit);
    conc.push_back({fw.wake_ts, static_cast<uint32_t>(po_pids.size()), static_cast<uint32_t>(inter)});
  }
  const uint64_t n = preempt + order;
  auto pct = [](uint64_t a, uint64_t d) { return d ? 100.0 * static_cast<double>(a) / static_cast<double>(d) : 0.0; };
  const double preempt_pct = pct(preempt, n), order_pct = pct(order, n);
  const double dark_pct = pct(dark, preempt), held_pct = pct(held, preempt);
  const double avg_inter = order ? static_cast<double>(inter_sum) / static_cast<double>(order) : 0.0;
  const double avg_distinct = n ? static_cast<double>(distinct_sum) / static_cast<double>(n) : 0.0;
  sublimation_u64(inter_v.data(), inter_v.size());
  sublimation_u64(legit_v.data(), legit_v.size());
  const uint64_t p99 = q_at(inter_v, 0.99), p99_legit = q_at(legit_v, 0.99);
  const double ceiling_remains = p99 ? 100.0 * static_cast<double>(p99_legit) / static_cast<double>(p99) : 0.0;
  // MIXED is a real state, not rounding: a run split between the mechanisms
  // is a different finding from either pure one.
  Measures m;
  m.set("preempt_pct", preempt_pct);
  m.set("order_pct", order_pct);
  r.klass = pick_verdict({{"PREEMPT-STARVED", "preempt_pct", 'G', 66.0}, {"ORDER-STARVED", "order_pct", 'G', 66.0},
                          {"MIXED", nullptr, 0, 0}}, m);
  std::snprintf(b, sizeof b, "%s saturated wakes over the %.0fus floor; PREEMPT-STARVED %.0f%% / "
                "ORDER-STARVED %.0f%%; avg %.1f pass-overs, p99 %llu",
                fmt_count(static_cast<double>(n)).c_str(), floor_us, preempt_pct, order_pct, avg_inter,
                static_cast<unsigned long long>(p99));
  std::string v = b;
  if (have_idle) {
    std::snprintf(b, sizeof b, "; %.0f%% DARK (worst %.1fms) / %.0f%% HELD", dark_pct,
                  static_cast<double>(worst_dark) / 1e6, held_pct);
    v += b;
  }
  add_censored(v);
  r.verdict = v;
  if (!held_by.empty()) {
    std::vector<std::pair<uint32_t, uint64_t>> hv(held_by.begin(), held_by.end());
    sublimation_order_u64(hv, true, [](const std::pair<uint32_t, uint64_t>& p) { return p.second; });
    Detail hb = Detail::array();
    for (size_t i = 0; i < hv.size() && i < 8; ++i)
      hb.arr.push_back(Detail::object().put("task", Detail::text(g_sched_holder.name_of(hv[i].first)))
          .put("tid", Detail::count(hv[i].first)).put("held_ms", Detail::of(static_cast<double>(hv[i].second) / 1e6)));
    r.detail.emplace_back("held_by", std::move(hb));
  }
  auto& g = r.gauges;
  g.push_back({"montauk_analysis_dispatch_preempt_pct", "", preempt_pct});
  g.push_back({"montauk_analysis_dispatch_order_pct", "", order_pct});
  if (have_idle) {
    g.push_back({"montauk_analysis_dispatch_dark_pct", "", dark_pct});
    g.push_back({"montauk_analysis_dispatch_held_pct", "", held_pct});
    g.push_back({"montauk_analysis_dispatch_worst_dark_ms", "", static_cast<double>(worst_dark) / 1e6});
  }
  g.push_back({"montauk_analysis_dispatch_avg_passovers", "", avg_inter});
  // Lane and class need the native PICK score; reconstructed from SWITCH_IN
  // they would be fabricated, so they are omitted.
  if (!reconstructed) {
    g.push_back({"montauk_analysis_dispatch_passover_mirror_pct", "", pct(po_mirror, po_total)});
    g.push_back({"montauk_analysis_dispatch_served_mirror_pct", "", pct(served_mirror, served_total)});
    g.push_back({"montauk_analysis_dispatch_passover_higher_class_pct", "", pct(cls_higher, cls_total)});
    g.push_back({"montauk_analysis_dispatch_passover_same_class_pct", "", pct(cls_same, cls_total)});
    g.push_back({"montauk_analysis_dispatch_passover_lower_class_pct", "", pct(cls_lower, cls_total)});
    r.detail.emplace_back("class", Detail::object()
        .put("same_class_newer_pct", Detail::of(pct(same_newer, cls_same))));
  }
  g.push_back({"montauk_analysis_dispatch_passover_p99", "", static_cast<double>(p99)});
  // Distinct pass-over tasks over pass-over picks: low is a few hogs re-picked
  // (a fair-share fix), near 1.0 a deep distinct backlog (a deadline fix).
  g.push_back({"montauk_analysis_dispatch_concentration_ratio", "", avg_inter > 0 ? avg_distinct / avg_inter : 0.0});
  // The share of the p99 pass-over depth that survives removing every
  // inversion: what only eligibility or lag can cut.
  g.push_back({"montauk_analysis_dispatch_ceiling_remains_pct", "", ceiling_remains});
  r.detail.emplace_back("ceiling", Detail::object().put("p99_passovers", Detail::count(p99))
                                       .put("p99_legit_only", Detail::count(p99_legit)));
  // CONCENTRATION TRAJECTORY: the ratio by wall-clock window, classified --
  // already low in window 1 is a pattern the boot committed to, ramping down
  // is one it drifted into.
  constexpr size_t kSeg = 8;
  if (conc.size() >= 2 * kSeg) {
    sublimation_order_u64(conc, false, [](const CTL& c) { return c.ts; });
    const uint64_t t0 = conc.front().ts, t1 = conc.back().ts;
    if (t1 > t0) {
      std::vector<uint64_t> seg;
      for (size_t gi = 0; gi < kSeg; ++gi) {
        const uint64_t lo = t0 + (t1 - t0) * gi / kSeg, hi = t0 + (t1 - t0) * (gi + 1) / kSeg;
        uint64_t ds = 0, is = 0;
        for (const auto& c : conc)
          if (c.ts >= lo && (c.ts < hi || (gi + 1 == kSeg && c.ts <= hi))) { ds += c.distinct; is += c.inter; }
        if (is) seg.push_back(ds * 1000 / is);
      }
      if (seg.size() >= 3) {
        const sub_profile_t tp = sublimation_classify_u64(seg.data(), seg.size());
        std::string s;
        for (uint64_t x : seg) s += (s.empty() ? "" : " ") + std::to_string(x);
        r.detail.emplace_back("concentration_trajectory", Detail::object()
            .put("ratio_x1000", Detail::text(s)).put("shape", Detail::text(disorder_name(tp.disorder))));
      }
    }
  }
  auto top3 = [&](const std::unordered_map<uint32_t, uint64_t>& mp, const char* kind, const char* metric, double scale, int sev) {
    if (mp.empty()) return;
    std::vector<std::pair<uint32_t, uint64_t>> vv(mp.begin(), mp.end());
    sublimation_order_u64(vv, true, [](const std::pair<uint32_t, uint64_t>& p) { return p.second; });
    for (size_t i = 0; i < vv.size() && i < 3; ++i)
      r.offenders.push_back({kind, g_sched_holder.name_of(vv[i].first), "", metric, static_cast<double>(vv[i].second) * scale, sev});
  };
  top3(offender, "order-starved", "passover_picks", 1.0, order_pct >= 50.0 ? 2 : 1);
  top3(held_by, "held-cpu", "held_ms", 1e-6, held_pct >= 50.0 ? 2 : 1);
}

const ReportDef kSched = {"sched", {}, false, nullptr, false,
                          [] { return std::unique_ptr<Stream>(new SchedStream); }, derive_sched};
const ReportDef kDispatchStall = {"dispatch-stall", {}, true, nullptr, false,
                                  [] { return std::unique_ptr<Stream>(new DispatchStream); }, derive_dispatch_stall};

// The per-thread ledger costs a lookup on every record, so it is folded only
// when a report that reads it is going to run.
void arm_ledger(const Report* r) {
  if (r->def.ledger) g_threads.on = true;
}

std::vector<std::unique_ptr<Report>> make_reports() {
  std::vector<std::unique_ptr<Report>> reports;
  reports.push_back(std::make_unique<Report>(kIolat));
  reports.push_back(std::make_unique<Report>(kDsqPlacement));
  reports.push_back(std::make_unique<Report>(kClassMix));
  reports.push_back(std::make_unique<Report>(kFieldPersist));
  reports.push_back(std::make_unique<Report>(kLocality));
  reports.push_back(std::make_unique<Report>(kSummary));
  reports.push_back(std::make_unique<Report>(kIowait));
  reports.push_back(std::make_unique<Report>(kSched));
  reports.push_back(std::make_unique<Report>(kWorkConservation));
  reports.push_back(std::make_unique<Report>(kPlacementRace));
  reports.push_back(std::make_unique<Report>(kDispatchStall));
  reports.push_back(std::make_unique<Report>(kKickLatency));
  reports.push_back(std::make_unique<Report>(kKStrand));
  reports.push_back(std::make_unique<Report>(kSlice));
  reports.push_back(std::make_unique<Report>(kStorm));
  reports.push_back(std::make_unique<Report>(kService));
  reports.push_back(std::make_unique<Report>(kWakers));
  reports.push_back(std::make_unique<Report>(kWaits));
  reports.push_back(std::make_unique<Report>(kSpins));
  reports.push_back(std::make_unique<Report>(kPairing));
  reports.push_back(std::make_unique<Report>(kAbortPm));
  reports.push_back(std::make_unique<Report>(kSignals));
  reports.push_back(std::make_unique<Report>(kEndstate));
  reports.push_back(std::make_unique<Report>(kFutex));
  reports.push_back(std::make_unique<Report>(kKeyedEvt));
  reports.push_back(std::make_unique<Report>(kHeapstk));
  reports.push_back(std::make_unique<Report>(kDoubleFree));
  reports.push_back(std::make_unique<Report>(kFractal));
  reports.push_back(std::make_unique<Report>(kSeat));
  reports.push_back(std::make_unique<Report>(kMatrixProfile));
  return reports;
}

// Rank offenders by severity (then value) and print the POORLY-BEHAVING ITEMS
// table, appending the reusable montauk_offender{} family to prom. Shared by
// the full-report main() and the compact digest.
// Split so the --digest --json path can rank offenders the same way the text
// digest does without also writing the "POORLY-BEHAVING ITEMS" text into
// g_out: rank_offenders sorts in place; emit_offenders_text (assumes already
// ranked) writes the text table and folds each offender into `prom`.
// Ranking key: an offender's position WITHIN its own metric, not its raw value.
struct OffKey { size_t idx; double norm; uint64_t sev; };

void rank_offenders(std::vector<Offender>& offs) {
  if (offs.size() < 2) return;
  // Raw `value` is not comparable across reports: bytes against profile_vs_mean
  // against held_ms against waits_per_s against wakes_issued. Ordering by it
  // ranked a 256-byte double-free above a 3x-mean discord purely because 256 >
  // 3. So rank within each METRIC first and use that position as the second
  // key -- "how extreme is this for its own kind".
  //
  // Severity still leads, and stays the contributing report's call: it knows
  // what is bad, the consolidator only orders. This changes ordering within a
  // severity tier, never which tier something lands in.
  std::unordered_map<std::string, std::vector<size_t>> by_metric;
  for (size_t i = 0; i < offs.size(); ++i) by_metric[offs[i].metric].push_back(i);

  std::vector<OffKey> keys(offs.size());
  for (size_t i = 0; i < offs.size(); ++i)
    keys[i] = {i, 1.0, static_cast<uint64_t>(offs[i].sev)};
  for (auto& [metric, idxs] : by_metric) {
    (void)metric;
    if (idxs.size() < 2) continue;   // a lone member of its metric ranks top
    std::vector<std::pair<size_t, double>> v;
    v.reserve(idxs.size());
    for (size_t i : idxs) v.emplace_back(i, offs[i].value);
    sublimation_order_f64(v, false,
                          [](const std::pair<size_t, double>& p) { return p.second; });
    const double denom = static_cast<double>(v.size() - 1);
    for (size_t r = 0; r < v.size(); ++r)
      keys[v[r].first].norm = static_cast<double>(r) / denom;
  }

  // Same LSD composition as before: minor key (normalized rank) first, major
  // key (sev) second, both descending.
  sublimation_order_f64(keys, true, [](const OffKey& k) { return k.norm; });
  sublimation_order_u64(keys, true, [](const OffKey& k) { return k.sev; });

  std::vector<Offender> ranked;
  ranked.reserve(offs.size());
  for (const OffKey& k : keys) ranked.push_back(std::move(offs[k.idx]));
  offs = std::move(ranked);
}

void emit_offenders_text(const std::vector<Offender>& offs,
                          std::vector<PromMetric>& prom) {
  if (offs.empty()) {
    montauk_sink_appendf(&g_out, "\nPOORLY-BEHAVING ITEMS: none detected\n");
    return;
  }
  montauk_sink_appendf(&g_out, "\nPOORLY-BEHAVING ITEMS (ranked)\n");
  montauk_sink_appendf(&g_out, "%-14s %-18s %-16s %14s  sev\n", "kind", "id", "metric", "value");
  for (const Offender& o : offs) {
    std::string idobj = o.obj.empty() ? o.id : (o.id + "/" + o.obj);
    const char* sv = o.sev >= 2 ? "HIGH" : (o.sev == 1 ? "MED" : "LOW");
    montauk_sink_appendf(&g_out, "%-14s %-18s %-16s %14.6g  %s\n", o.kind.c_str(), idobj.c_str(),
                o.metric.c_str(), o.value, sv);
    std::string lab = "kind=\"" + o.kind + "\",id=\"" + o.id + "\"";
    if (!o.obj.empty()) lab += ",obj=\"" + o.obj + "\"";
    lab += ",metric=\"" + o.metric + "\",sev=\"" + std::to_string(o.sev) + "\"";
    prom.push_back({"montauk_offender", lab, o.value});
  }
}

// The JSON envelope for --digest --json: the same data the text digest reads
// (SystemInfo/ScxStability/ThermalPower/HotCpu/Offender/Report::json()), one
// parse per source, two renderings -- same discipline as --report --json.
// The reports whose FULL text leads KEY METRICS. Deliberately a short list and
// not "every report with a finding": the digest is the one-call shareable
// report and is KB-scale by design, so widening it is a product decision rather
// than a cleanup. The name test used to be spelled inline in two places and
// drifting between them was a live hazard; this is the one place to edit.
// The JSON envelope no longer needs it -- it carries EVERY report's conclusion
// compactly instead, which is what retires the hardcoding for a consumer.
constexpr const char* kDigestHeadline[] = {"sched", "dispatch-stall", "kstrand"};
inline bool is_digest_headline(const char* n) {
  for (const char* h : kDigestHeadline) if (std::string(n) == h) return true;
  return false;
}

void emit_digest_json(const std::string& dir, bool have_events,
                       const std::string& events_path, uint64_t events_observed,
                       const std::vector<std::unique_ptr<Report>>& reports,
                       const std::vector<Offender>& offs,
                       const montauk::pop::HotCpu& hot) {
  montauk::pop::SystemInfo sys = montauk::pop::system_info_data(dir);
  montauk::pop::ScxStability stab = montauk::pop::scx_stability_data(dir);
  montauk::pop::ThermalPower tp = montauk::pop::thermal_power_data(dir);

  montauk_json j;
  montauk_json_init(&j, &g_out);
  montauk_json_obj_begin(&j);
    montauk_json_ku64(&j, "schema_version", 1u);
    montauk_json_key(&j, "digest");
    montauk_json_obj_begin(&j);
      montauk_json_kstr(&j, "dir", dir.c_str());
      montauk_json_kbool(&j, "has_events", have_events);
      // Name the layout so a consumer that got has_events:false knows what was
      // looked for -- the <dir>.events sibling or the in-dir events.bin.
      montauk_json_kstr(&j, "events_path", events_path.c_str());
      // Loss beside the data it qualifies, the same numbers the text block
      // prints. Emitted only when a drop snapshot exists: a capture predating
      // drop accounting reports NOTHING here rather than a zero, because absence
      // of the counter is not evidence of a lossless capture and a consumer must
      // be able to tell those apart.
      if (have_events) {
        montauk_json_ku64(&j, "events_observed", events_observed);
        if (g_drop_seen) {
          montauk_json_ku64(&j, "dropped_events", drops_total());
          montauk_json_knum(&j, "capture_completeness",
                            capture_completeness(events_observed));
        }
      }
    montauk_json_obj_end(&j);

    if (sys.found) {
      montauk_json_key(&j, "system");
      montauk_json_obj_begin(&j);
        montauk_json_kstr(&j, "cpu_model", sys.cpu_model.c_str());
        montauk_json_kstr(&j, "physical_cores", sys.physical_cores.c_str());
        montauk_json_kstr(&j, "logical_cpus", sys.logical_cpus.c_str());
        if (!sys.cache_domains.empty()) montauk_json_kstr(&j, "cache_domains", sys.cache_domains.c_str());
        montauk_json_kstr(&j, "mem_total_gib", sys.mem_total_gib.c_str());
        if (!sys.gpu.empty()) montauk_json_kstr(&j, "gpu", sys.gpu.c_str());
        montauk_json_kstr(&j, "kernel", sys.kernel.c_str());
        montauk_json_kstr(&j, "scheduler", sys.sched.c_str());
      montauk_json_obj_end(&j);
    }

    if (!stab.ejections.empty() || !stab.cleanroom_verdict.empty() || stab.watchdog_worst_pct >= 0) {
      montauk_json_key(&j, "stability");
      montauk_json_obj_begin(&j);
        montauk_json_key(&j, "ejections");
        montauk_json_arr_begin(&j);
          for (const auto& e : stab.ejections) {
            montauk_json_obj_begin(&j);
              montauk_json_kstr(&j, "scheduler", e.scheduler.c_str());
              montauk_json_kstr(&j, "reason", e.reason.c_str());
              if (!e.phase.empty()) montauk_json_kstr(&j, "phase", e.phase.c_str());
              if (!e.cores.empty()) montauk_json_kstr(&j, "cores", e.cores.c_str());
            montauk_json_obj_end(&j);
          }
        montauk_json_arr_end(&j);
        if (!stab.cleanroom_verdict.empty()) {
          montauk_json_kstr(&j, "cleanroom_verdict", stab.cleanroom_verdict.c_str());
          if (!stab.cleanroom_detail.empty()) montauk_json_kstr(&j, "cleanroom_detail", stab.cleanroom_detail.c_str());
        }
        if (stab.watchdog_worst_pct >= 0) {
          montauk_json_knum(&j, "watchdog_worst_pct", stab.watchdog_worst_pct);
          if (!stab.watchdog_where.empty()) montauk_json_kstr(&j, "watchdog_where", stab.watchdog_where.c_str());
        }
      montauk_json_obj_end(&j);
    }

    if (tp.temp_n > 0 || tp.power_n > 0 || tp.fan_peak_rpm > 0.0 || tp.freq_n > 0 ||
        tp.ctx_n > 0 || tp.mig_n > 0 || !tp.dominant_cstate.empty() || tp.energy_joules_total >= 0.0) {
      montauk_json_key(&j, "thermal_power");
      montauk_json_obj_begin(&j);
        if (tp.temp_n > 0) { montauk_json_knum(&j, "cpu_temp_peak_c", tp.temp_peak_c); montauk_json_knum(&j, "cpu_temp_avg_c", tp.temp_avg_c); }
        if (tp.fan_peak_rpm > 0.0) montauk_json_knum(&j, "fan_peak_rpm", tp.fan_peak_rpm);
        if (tp.power_n > 0) { montauk_json_knum(&j, "power_avg_w", tp.power_avg_w); montauk_json_knum(&j, "power_peak_w", tp.power_peak_w); }
        if (tp.energy_joules_total >= 0.0) montauk_json_knum(&j, "energy_joules_total", tp.energy_joules_total);
        if (tp.freq_n > 0) { montauk_json_knum(&j, "cpu_clock_avg_mhz", tp.freq_avg_mhz); montauk_json_knum(&j, "cpu_clock_peak_mhz", tp.freq_peak_mhz); }
        if (tp.epi_n > 0) montauk_json_knum(&j, "energy_per_instr_pj", tp.energy_per_instr_pj);
        if (tp.ctx_n > 0) montauk_json_knum(&j, "context_switches_per_sec", tp.ctx_switches_per_sec);
        if (tp.mig_n > 0) montauk_json_knum(&j, "migrations_per_sec", tp.migrations_per_sec);
        if (tp.br_n > 0) montauk_json_knum(&j, "branch_misses_per_sec", tp.branch_misses_per_sec);
        if (!tp.dominant_cstate.empty()) {
          montauk_json_kstr(&j, "dominant_cstate", tp.dominant_cstate.c_str());
          montauk_json_knum(&j, "dominant_cstate_pct", tp.dominant_cstate_pct);
        }
      montauk_json_obj_end(&j);
    }

    if (hot.found) {
      montauk_json_key(&j, "hot_cpu");
      montauk_json_obj_begin(&j);
        montauk_json_ki64(&j, "cpu", hot.cpu);
        montauk_json_knum(&j, "share_pct", hot.share_pct);
        montauk_json_knum(&j, "uniform_pct", hot.uniform_pct);
        montauk_json_ki64(&j, "sev", hot.sev);
      montauk_json_obj_end(&j);
    }

    montauk_json_key(&j, "offenders");
    montauk_json_arr_begin(&j);
      for (const auto& o : offs) {
        montauk_json_obj_begin(&j);
          montauk_json_kstr(&j, "kind", o.kind.c_str());
          montauk_json_kstr(&j, "id", o.id.c_str());
          if (!o.obj.empty()) montauk_json_kstr(&j, "obj", o.obj.c_str());
          montauk_json_kstr(&j, "metric", o.metric.c_str());
          montauk_json_knum(&j, "value", o.value);
          montauk_json_ki64(&j, "sev", o.sev);
        montauk_json_obj_end(&j);
      }
    montauk_json_arr_end(&j);

    if (have_events) {
      montauk_json_key(&j, "reports");
      montauk_json_arr_begin(&j);
        for (auto& r : reports)
          if (is_digest_headline(r->name())) r->json(j);
      montauk_json_arr_end(&j);

      // EVERY report's conclusion, compactly. This is what retires the
      // hardcoded selection for a structured consumer: instead of montauk
      // choosing which three conclusions matter on the caller's behalf, the
      // caller gets all of them as {name, class, verdict} and selects for its
      // own audience. Costs a few hundred bytes against a KB-scale digest.
      montauk_json_key(&j, "conclusions");
      montauk_json_arr_begin(&j);
        for (auto& r : reports) {
          const ReportResult& rr = r->result_base();
          if (rr.klass.empty() && rr.verdict.empty()) continue;
          montauk_json_obj_begin(&j);
          montauk_json_kstr(&j, "name", r->name());
          if (!rr.klass.empty()) montauk_json_kstr(&j, "class", rr.klass.c_str());
          if (!rr.verdict.empty()) montauk_json_kstr(&j, "verdict", rr.verdict.c_str());
          montauk_json_obj_end(&j);
        }
      montauk_json_arr_end(&j);
    }
  montauk_json_obj_end(&j);
  montauk_sink_appendc(&g_out, '\n');
}

// Compact, specs-first report over a montauk --trace RECORDING DIR: SYSTEM
// specs (from the dir's scrapes), POORLY-BEHAVING ITEMS (offenders over the
// sibling .events), then KEY METRICS (the wake2run verdict). The single-call
// shareable digest; the dir is the one input, both halves read from it.
// --json emits the structured envelope (see emit_digest_json) instead of text.
int run_digest(const std::string& dir, bool redact, bool want_json) {
  g_redact_comm = redact;
  std::string base = dir;
  while (!base.empty() && base.back() == '/') base.pop_back();
  std::string events = base + ".events";

  // The per-event stream is optional: a .prom-only recording (e.g. a
  // system-metrics capture with no --trace-out) still has SYSTEM specs and the
  // THERMAL/POWER block worth reporting. Only the offenders and the wake2run
  // verdict need it; degrade gracefully when it is absent. Two layouts carry
  // it: the montauk --trace `<dir>.events` sibling, and the freeze-archive /
  // bare-capture layout that keeps `events.bin` INSIDE the dir. Try both.
  montauk::model::TraceReader reader;
  bool have_events =
      reader.open(events.c_str()) == montauk::model::TraceReadStatus::Ok;
  if (!have_events) {
    std::string inside = base + "/events.bin";
    if (reader.open(inside.c_str()) == montauk::model::TraceReadStatus::Ok) {
      have_events = true;
      events = inside;
    }
  }

  auto reports = make_reports();
  for (const auto& r : reports) arm_ledger(r.get());
  if (have_events) {
    (void)reader.for_each([&](uint32_t t, const uint8_t* d, uint32_t l) {
      // The SAME driver-level fold the --report path runs. The digest used to
      // call only r->fold(), which left both the drop accounting and the shared
      // sched substrate empty -- so it under-reported loss as absent and
      // mis-diagnosed dispatch stalls from a substrate with nothing in it.
      fold_driver_state(t, d, l);
      for (auto& r : reports) r->fold(t, d, l);
    });
    for (auto& r : reports) r->compute();  // finalize typed results once, before any renderer
  }

  std::vector<PromMetric> prom;
  std::vector<Offender> offs;
  if (have_events)
    for (auto& r : reports) r->offenders(offs);
  // The L2 hot-CPU offender is computed from the .prom scrapes, so it ranks even
  // for a .prom-only recording -- a cachyos capture still names its hottest core
  // instead of reporting "not analyzed."
  montauk::pop::HotCpu hot = montauk::pop::l2_hot_cpu(dir);
  if (hot.found)
    offs.push_back({"hot-cpu", std::to_string(hot.cpu), "", "l2_miss_share",
                    hot.share_pct, hot.sev});
  rank_offenders(offs);

  if (want_json) {
    // When nothing opened, report the layouts that were tried, not a bare path.
    std::string events_path = have_events ? events
                                          : (base + ".events | " + base + "/events.bin");
    emit_digest_json(dir, have_events, events_path, reader.events_read(),
                     reports, offs, hot);
    return 0;
  }

  // FRONT AND CENTER: a scheduler that crashed/ejected makes every number below
  // it meaningless, and a NOISY clean-room makes them untrustworthy -- so this
  // leads the digest, above SYSTEM, before the reader sees a single latency.
  std::string stab = montauk::pop::scx_stability_block(dir);
  if (!stab.empty()) montauk_sink_appendf(&g_out, "%s\n", stab.c_str());

  std::string specs = montauk::pop::system_info_block(dir);
  if (!specs.empty()) montauk_sink_appendf(&g_out, "%s", specs.c_str());
  else log_warn("no montauk_system_info in recording (pre-v7.1.0 capture?)");
  std::string tp = montauk::pop::thermal_power_block(dir);
  if (!tp.empty()) montauk_sink_appendf(&g_out, "\n%s", tp.c_str());

  emit_offenders_text(offs, prom);

  if (have_events) {
    // Directly above the quantiles it qualifies: a p99 read off a 5.7%-complete
    // capture is a different claim from one read off a whole stream, and the
    // reader of a shared digest has no other way to know which they hold.
    emit_capture_loss(reader.events_read(), prom);
    montauk_sink_appendf(&g_out, "\nKEY METRICS\n");
    for (auto& r : reports)
      if (is_digest_headline(r->name())) {
        r->emit(reader);
        r->prom(prom);
      }
    if (!prom.empty()) {
      std::string out_path =
          analysis_prom_path(events.c_str(), reader.header().real_anchor_ns);
      if (write_analysis_prom(out_path, prom))
        log_info("digest metrics -> %s", out_path.c_str());
    }
  } else {
    log_warn("no per-event trace at '%s.events' or '%s/events.bin' -- system "
             "metrics + offenders only (wake2run latency needs the event stream, "
             "from a --trace-out capture or a freeze-archive events.bin)",
             base.c_str(), base.c_str());
    montauk_sink_appendf(&g_out, "\nKEY METRICS: not analyzed (no per-event trace; "
             "expected %s.events or %s/events.bin)\n", base.c_str(), base.c_str());
  }
  return 0;
}


// Report selection. `select` is a comma list of report names (empty = all).
// An unknown name is an ERROR: a misspelled name that silently selects nothing
// reads as a report that found nothing.
static bool select_reports(std::vector<Report*>& active, const std::string& select) {
  auto split = [](const std::string& csv, std::vector<std::string>& out) {
    size_t pos = 0;
    while (pos <= csv.size()) {
      size_t c = csv.find(',', pos);
      if (c == std::string::npos) c = csv.size();
      std::string t = csv.substr(pos, c - pos);
      pos = c + 1;
      if (!t.empty()) out.push_back(t);
      if (c == csv.size()) break;
    }
  };
  auto known = [&](const std::string& n) {
    for (Report* r : active) if (n == r->name()) return true;
    return false;
  };
  std::vector<std::string> sel;
  split(select, sel);
  for (const auto& n : sel)
    if (!known(n)) { log_error("unknown report '%s'", n.c_str()); return false; }
  if (!sel.empty()) {
    std::vector<Report*> keep;
    for (const auto& n : sel)
      for (Report* r : active)
        if (n == r->name() &&
            std::find(keep.begin(), keep.end(), r) == keep.end())
          keep.push_back(r);
    active.swap(keep);
  }
  return true;
}

// THE QUERY FACE. A question about a trace as a command line: select events by
// class, op and field, key them, and apply one operator. Everything a report
// computes from the stream is one of these shapes or a composition of them, and
// a question nobody has written a report for is answered here without one.
int run_query(const char* path, int argc, char** argv) {
  namespace q = montauk::query;
  q::Query qy;
  std::string pair_ops, stats, err;
  std::vector<std::string> wheres, pair_wheres, keys;
  std::string value;
  bool want_json = false, have_select = false;
  auto split = [](const std::string& csv) {
    std::vector<std::string> out;
    size_t pos = 0;
    while (pos <= csv.size()) {
      size_t c = csv.find(',', pos);
      if (c == std::string::npos) c = csv.size();
      if (c > pos) out.push_back(csv.substr(pos, c - pos));
      pos = c + 1;
    }
    return out;
  };
  for (int i = 2; i < argc; ++i) {
    const std::string a = argv[i];
    const bool has_val = i + 1 < argc;
    if (a == "--select" && has_val) {
      if (!q::parse_select(argv[++i], qy.a, err)) { log_error("--select: %s", err.c_str()); return 2; }
      have_select = true;
    }
    else if (a == "--where" && has_val) wheres.push_back(argv[++i]);
    else if (a == "--pair-where" && has_val) pair_wheres.push_back(argv[++i]);
    else if (a == "--by" && has_val) keys = split(argv[++i]);
    else if (a == "--value" && has_val) value = argv[++i];
    else if (a == "--count") qy.op = q::Op::Count;
    else if (a == "--gap") qy.op = q::Op::Gap;
    else if (a == "--last") qy.op = q::Op::Last;
    else if (a == "--pair" && has_val) { qy.op = q::Op::Pair; pair_ops = argv[++i]; }
    else if (a == "--between" && has_val) {
      const std::string w = argv[++i];
      const size_t colon = w.find(':');
      if (colon == std::string::npos) { log_error("--between takes START:END seconds"); return 2; }
      if (colon > 0) qy.t0_s = std::strtod(w.c_str(), nullptr);
      if (colon + 1 < w.size()) qy.t1_s = std::strtod(w.c_str() + colon + 1, nullptr);
    }
    else if (a == "--stats" && has_val) stats = argv[++i];
    else if (a == "--json") want_json = true;
    else { log_error("unknown query flag '%s' (see montauk --analyze --help)", a.c_str()); return 2; }
  }
  if (!have_select) { log_error("a query needs --select CLASS[.OP,...]"); return 2; }
  for (const auto& w : wheres)
    if (!q::parse_clause(w, qy.a, err)) { log_error("--where: %s", err.c_str()); return 2; }
  for (const auto& k : keys) {
    const int f = q::field_named(*qy.a.cls, k);
    if (f < 0) { log_error("--by: class '%s' has no field '%s'", qy.a.cls->name, k.c_str()); return 2; }
    qy.key.push_back(f);
  }
  if (!value.empty()) {
    qy.value = q::field_named(*qy.a.cls, value);
    if (qy.value < 0) { log_error("--value: class '%s' has no field '%s'", qy.a.cls->name, value.c_str()); return 2; }
  }
  if (!pair_wheres.empty() && qy.op != q::Op::Pair) {
    log_error("--pair-where qualifies the closing event of --pair; there is no --pair");
    return 2;
  }
  if (qy.op == q::Op::Pair) {
    // The closing op is of the SAME class, so a key field means the same thing
    // at both ends of the pair. Clauses do not carry over: --where qualifies the
    // opener, --pair-where the closer, because a field the opener is filtered
    // on (a kick's flags) is often one the closer never sets.
    if (!q::parse_select(std::string(qy.a.cls->name) + "." + pair_ops, qy.b, err)) {
      log_error("--pair: %s", err.c_str()); return 2;
    }
    for (const auto& w : pair_wheres)
      if (!q::parse_clause(w, qy.b, err)) { log_error("--pair-where: %s", err.c_str()); return 2; }
  }

  montauk::model::TraceReader reader;
  if (reader.open(path) != montauk::model::TraceReadStatus::Ok) {
    log_error("cannot read trace '%s'", path);
    return 1;
  }
  q::Engine eng(qy);
  (void)reader.for_each([&](uint32_t t, const uint8_t* d, uint32_t l) { eng.fold(t, d, l); });
  const q::Table tb = eng.finish();

  // The measure the stats read: what the operator produced, else the value.
  int mcol = -1;
  for (size_t c = 0; c < tb.width(); ++c)
    if (tb.cols[c] == "gap_ns" || tb.cols[c] == "latency_ns" ||
        (!value.empty() && tb.cols[c] == value && !tb.text[c]))
      mcol = static_cast<int>(c);
  std::vector<std::pair<std::string, double>> st;
  if (!stats.empty()) {
    if (mcol < 0) { log_error("--stats needs a measure: --gap, --pair or a numeric --value"); return 2; }
    std::vector<int64_t> v;
    v.reserve(tb.rows());
    for (size_t r = 0; r < tb.rows(); ++r) v.push_back(tb.at(r, static_cast<size_t>(mcol)));
    sublimation_i64(v.data(), v.size());
    for (const auto& s : split(stats)) {
      double x = 0;
      if (s == "n") x = static_cast<double>(v.size());
      else if (s == "min") x = v.empty() ? 0.0 : static_cast<double>(v.front());
      else if (s == "max") x = v.empty() ? 0.0 : static_cast<double>(v.back());
      else if (s == "mean") {
        double sum = 0;
        for (int64_t e : v) sum += static_cast<double>(e);
        x = v.empty() ? 0.0 : sum / static_cast<double>(v.size());
      } else if (s.size() > 1 && s[0] == 'p') {
        // p50, p99, p999: the digits after the first are the fraction.
        x = static_cast<double>(q::quantile_sorted(v, std::strtod(("0." + s.substr(1)).c_str(), nullptr)));
      } else { log_error("--stats: unknown '%s' (n min max mean pNN)", s.c_str()); return 2; }
      st.emplace_back(s, x);
    }
  }

  if (want_json) {
    montauk_json j;
    montauk_json_init(&j, &g_out);
    montauk_json_obj_begin(&j);
    montauk_json_key(&j, "columns");
    montauk_json_arr_begin(&j);
    for (const auto& c : tb.cols) montauk_json_str(&j, c.c_str());
    montauk_json_arr_end(&j);
    if (st.empty()) {
      montauk_json_key(&j, "rows");
      montauk_json_arr_begin(&j);
      for (size_t r = 0; r < tb.rows(); ++r) {
        montauk_json_arr_begin(&j);
        for (size_t c = 0; c < tb.width(); ++c) {
          if (tb.text[c]) montauk_json_str(&j, tb.cell_text(r, c).c_str());
          else montauk_json_i64(&j, tb.at(r, c));
        }
        montauk_json_arr_end(&j);
      }
      montauk_json_arr_end(&j);
    } else {
      montauk_json_key(&j, "stats");
      montauk_json_obj_begin(&j);
      montauk_json_kstr(&j, "of", tb.cols[static_cast<size_t>(mcol)].c_str());
      for (const auto& [k, x] : st) montauk_json_knum(&j, k.c_str(), x);
      montauk_json_obj_end(&j);
    }
    if (qy.op == q::Op::Pair) montauk_json_ku64(&j, "unanswered", eng.misses());
    montauk_json_obj_end(&j);
    montauk_sink_appendc(&g_out, '\n');
    return 0;
  }

  if (!st.empty()) {
    montauk_sink_appendf(&g_out, "%s:", tb.cols[static_cast<size_t>(mcol)].c_str());
    for (const auto& [k, x] : st) montauk_sink_appendf(&g_out, " %s=%.0f", k.c_str(), x);
    montauk_sink_appendc(&g_out, '\n');
  } else {
    std::vector<size_t> w(tb.width());
    for (size_t c = 0; c < tb.width(); ++c) w[c] = tb.cols[c].size();
    for (size_t r = 0; r < tb.rows(); ++r)
      for (size_t c = 0; c < tb.width(); ++c) w[c] = std::max(w[c], tb.cell_text(r, c).size());
    auto line = [&](auto cell) {
      for (size_t c = 0; c + 1 < tb.width(); ++c)
        montauk_sink_appendf(&g_out, "%-*s  ", static_cast<int>(w[c]), cell(c).c_str());
      if (tb.width()) montauk_sink_appendf(&g_out, "%s", cell(tb.width() - 1).c_str());
      montauk_sink_appendc(&g_out, '\n');
    };
    line([&](size_t c) { return tb.cols[c]; });
    for (size_t r = 0; r < tb.rows(); ++r) line([&](size_t c) { return tb.cell_text(r, c); });
  }
  if (qy.op == q::Op::Pair)
    montauk_sink_appendf(&g_out, "unanswered: %" PRIu64 "\n", eng.misses());
  return 0;
}

} // namespace

#include "tools/Entrypoints.hpp"

// THE STATIC ARTIFACT IS A THIRD INPUT SHAPE, beside .events and .prom, and it
// is read here rather than reported by --static because --static is a RECORDER.
// The moment it decides which branches are interesting there are two analyzers,
// which is the redundancy this split exists to prevent.
//
// GUARD DEPTH IS THE FIGURE TO READ. A branch nested six conditions deep is
// reachable only when six things hold at once, which is both harder to exercise
// in a test and likelier to hold a dead arm. The distribution says how much of a
// program sits behind a stack of conditions rather than in its open path.
struct StaticGuard {
  std::string file, func, kind, text;
  uint64_t line = 0;
  int depth = 0;
};

// DECLARED STRUCTURE IS THE OTHER HALF, and the join is performed HERE for the
// same reason the depth distribution is: a function with no branches emits no
// guard at all, so the artifact alone cannot distinguish a symbol nothing
// reaches from one that was never written. D says what exists, R says where it
// is named again, and the difference is the report below.
struct StaticDecl {
  std::string file, kind, name;
  uint64_t line = 0;
};
struct StaticRef {
  std::string file, func, name;
  uint64_t line = 0;
};

// THE GRAPH IS THE THIRD HALF: each function's basic blocks and edges, and
// what they say that nesting cannot -- code nothing flows into, how many paths
// a function has, which loops have a single entry.
struct StaticBlock { std::string kind; uint64_t line = 0; };
struct StaticEdge { uint32_t from = 0, to = 0; std::string kind; };
struct StaticFn {
  size_t file_idx = 0, fn = 0;
  std::string file, func;
  std::vector<StaticBlock> blocks;
  std::vector<StaticEdge> edges;
};

static bool read_guard_artifact(const std::string& path,
                                std::vector<StaticGuard>& out,
                                std::vector<StaticDecl>& decls,
                                std::vector<StaticRef>& refs,
                                std::vector<StaticFn>& fns,
                                std::vector<std::string>& files,
                                std::string& lang) {
  std::FILE* f = std::fopen(path.c_str(), "rb");
  if (!f) { log_error("cannot open '%s'", path.c_str()); return false; }
  char buf[8192];
  int version = 0;
  // Every record is fixed-arity tab-separated fields, the last taken whole: only
  // a guard's or a block's text can hold anything, and only because it is last.
  std::vector<std::string> c;
  auto split = [&](const std::string& line, int fixed) {
    c.clear();
    size_t pos = 0;
    for (int i = 0; i < fixed; ++i) {
      const size_t tab = line.find('\t', pos);
      if (tab == std::string::npos) return false;
      c.push_back(line.substr(pos, tab - pos));
      pos = tab + 1;
    }
    c.push_back(line.substr(pos));
    return true;
  };
  auto file_of = [&](const std::string& idx) {
    const size_t fi = (size_t)std::strtoul(idx.c_str(), nullptr, 10);
    return fi < files.size() ? files[fi] : std::string("?");
  };
  auto num = [](const std::string& s) { return std::strtoull(s.c_str(), nullptr, 10); };
  while (std::fgets(buf, sizeof(buf), f)) {
    std::string line(buf);
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
    if (line.empty() || line[0] == '#') continue;
    if (line.rfind("static_version ", 0) == 0) { version = std::atoi(line.c_str() + 15); continue; }
    if (line.rfind("language ", 0) == 0) { lang = line.substr(9); continue; }
    if (line.rfind("file ", 0) == 0) {
      // file IDX PATH, and from version 2 file IDX DIALECT PATH.
      size_t sp = line.find(' ', 5);
      if (version >= 2 && sp != std::string::npos) sp = line.find(' ', sp + 1);
      if (sp != std::string::npos) files.push_back(line.substr(sp + 1));
      continue;
    }
    if (line.size() < 2 || line[1] != '\t') continue;
    switch (line[0]) {
      case 'D':
        if (split(line, 4)) decls.push_back({file_of(c[1]), c[3], c[4], num(c[2])});
        break;
      case 'R':
        if (split(line, 4)) refs.push_back({file_of(c[1]), c[3], c[4], num(c[2])});
        break;
      case 'G':
        if (split(line, 6)) out.push_back({file_of(c[1]), c[5], c[4], c[6], num(c[2]), std::atoi(c[3].c_str())});
        break;
      case 'B':
      case 'E': {
        if (!split(line, line[0] == 'B' ? 8 : 6)) break;
        const size_t fi = num(c[1]), fn = num(c[2]);
        if (fns.empty() || fns.back().file_idx != fi || fns.back().fn != fn)
          fns.push_back({fi, fn, file_of(c[1]), c[3], {}, {}});
        if (line[0] == 'B') fns.back().blocks.push_back({c[5], num(c[6])});
        else fns.back().edges.push_back({(uint32_t)num(c[4]), (uint32_t)num(c[5]), c[6]});
        break;
      }
    }
  }
  std::fclose(f);
  if (version != 1 && version != 2) {
    log_error("%s: static_version %d, this build reads 1 and 2", path.c_str(), version);
    return false;
  }
  return true;
}

struct CfgStats {
  uint64_t cyclomatic = 1;
  int dom_depth = 0;
  size_t natural = 0, irreducible = 0;
  std::vector<uint32_t> dead;             // blocks nothing reaches from the entry
};

// One function's graph from its entry, block 0. Reachability and the retreating
// edges come from one depth-first pass; immediate dominators from Cooper,
// Harvey and Kennedy, "A Simple, Fast Dominance Algorithm" (2001): iterate over
// reverse postorder until nothing changes, intersecting predecessors by walking
// both up the tree. A retreating edge whose target dominates its source is a
// natural loop's back edge; one whose target does not enters the loop at a
// second place, which is what makes it irreducible.
static CfgStats cfg_stats(const StaticFn& f) {
  CfgStats st;
  const size_t n = f.blocks.size();
  if (n == 0) return st;
  std::vector<std::vector<uint32_t>> succ(n), pred(n);
  for (const StaticEdge& e : f.edges)
    if (e.from < n && e.to < n) { succ[e.from].push_back(e.to); pred[e.to].push_back(e.from); }
  std::vector<uint8_t> state(n, 0);       // 0 unseen, 1 on the path, 2 done
  std::vector<uint32_t> post;
  std::vector<std::pair<uint32_t, uint32_t>> retreat;
  std::vector<std::pair<uint32_t, size_t>> stack{{0, 0}};
  state[0] = 1;
  while (!stack.empty()) {
    const uint32_t v = stack.back().first;
    const size_t k = stack.back().second++;
    if (k < succ[v].size()) {
      const uint32_t w = succ[v][k];
      if (state[w] == 0) { state[w] = 1; stack.push_back({w, 0}); }
      else if (state[w] == 1) retreat.push_back({v, w});
    } else {
      state[v] = 2;
      post.push_back(v);
      stack.pop_back();
    }
  }
  std::vector<size_t> rpo(n, 0);
  for (size_t i = 0; i < post.size(); ++i) rpo[post[i]] = post.size() - 1 - i;
  std::vector<int> idom(n, -1);
  idom[0] = 0;
  auto intersect = [&](int a, int b) {
    while (a != b) {
      while (rpo[a] > rpo[b]) a = idom[a];
      while (rpo[b] > rpo[a]) b = idom[b];
    }
    return a;
  };
  for (bool changed = true; changed;) {
    changed = false;
    for (size_t i = post.size(); i-- > 0;) {
      const uint32_t v = post[i];
      if (v == 0) continue;
      int nd = -1;
      for (uint32_t p : pred[v])
        if (idom[p] >= 0) nd = nd < 0 ? (int)p : intersect((int)p, nd);
      if (nd != idom[v]) { idom[v] = nd; changed = true; }
    }
  }
  std::vector<int> depth(n, 0);
  for (size_t i = post.size(); i-- > 0;) {
    const uint32_t v = post[i];
    if (v != 0) depth[v] = depth[idom[v]] + 1;
    st.dom_depth = std::max(st.dom_depth, depth[v]);
  }
  std::set<uint32_t> heads;
  for (const auto& [u, w] : retreat) {
    int x = (int)u;
    while (x != (int)w && x != 0) x = idom[x];
    if (x == (int)w) heads.insert(w);
    else ++st.irreducible;
  }
  st.natural = heads.size();
  size_t er = 0;
  for (const StaticEdge& e : f.edges)
    if (e.from < n && e.to < n && state[e.from] && state[e.to]) ++er;
  const int64_t m = (int64_t)er - (int64_t)post.size() + 2;
  st.cyclomatic = m > 1 ? (uint64_t)m : 1;
  for (uint32_t b = 0; b < n; ++b)
    if (!state[b] && f.blocks[b].kind != "exit") st.dead.push_back(b);
  return st;
}

static int run_guards(const std::string& path, bool want_json) {
  std::vector<StaticGuard> g;
  std::vector<StaticDecl> decls;
  std::vector<StaticRef> refs;
  std::vector<StaticFn> fns;
  std::vector<std::string> files;
  std::string lang = "?";
  if (!read_guard_artifact(path, g, decls, refs, fns, files, lang)) return 2;
  if (g.empty() && decls.empty() && fns.empty()) {
    log_error("%s: no static records", path.c_str());
    return 2;
  }

  ReportResult guards, declared;
  {
    std::map<std::string, uint64_t> by_kind;
    std::set<std::string> funcs;
    std::vector<uint64_t> depths;
    depths.reserve(g.size());
    int max_depth = 0;
    for (const StaticGuard& x : g) {
      ++by_kind[x.kind];
      funcs.insert(x.func);
      depths.push_back((uint64_t)x.depth);
      if (x.depth > max_depth) max_depth = x.depth;
    }
    sublimation_u64(depths.data(), depths.size());
    // Deepest first: the guards most conditioned on other guards.
    std::vector<const StaticGuard*> deep;
    for (const StaticGuard& x : g) deep.push_back(&x);
    sublimation_order_u64(deep, true,
                          [](const StaticGuard* a) { return static_cast<uint64_t>(a->depth); });

    char v[512];
    std::snprintf(v, sizeof(v),
                  "%zu declared branches over %zu function(s) in %zu file(s), %s; "
                  "depth p50 %llu p99 %llu max %d",
                  g.size(), funcs.size(), files.size(), lang.c_str(),
                  (unsigned long long)q_at(depths, 0.50),
                  (unsigned long long)q_at(depths, 0.99), max_depth);
    guards.verdict = v;
    guards.klass = max_depth >= 6 ? "DEEPLY-NESTED" : max_depth >= 3 ? "NESTED" : "FLAT";
    Detail kinds = Detail::object();
    for (const auto& kv : by_kind) kinds.put(kv.first, Detail::count(kv.second));
    guards.detail.emplace_back("by_kind", std::move(kinds));
    Detail rows = Detail::array();
    for (size_t i = 0; i < deep.size() && i < 5; ++i)
      rows.arr.push_back(Detail::object()
          .put("depth", Detail::count((uint64_t)deep[i]->depth))
          .put("function", Detail::text(deep[i]->func))
          .put("line", Detail::count(deep[i]->line))
          .put("kind", Detail::text(deep[i]->kind))
          .put("guard", Detail::text(deep[i]->text)));
    guards.detail.emplace_back("deepest", std::move(rows));
    guards.gauges.push_back({"montauk_static_guards_total", "", (double)g.size()});
    guards.gauges.push_back({"montauk_static_functions", "", (double)funcs.size()});
    guards.gauges.push_back({"montauk_static_depth_max", "", (double)max_depth});
    for (const auto& kv : by_kind)
      guards.gauges.push_back({"montauk_static_guards_by_kind", "kind=\"" + kv.first + "\"",
                               (double)kv.second});
    push_quantile_gauges(guards.gauges, "montauk_static_guard_depth",
                         {{"0.5", (double)q_at(depths, 0.5)}, {"0.9", (double)q_at(depths, 0.9)},
                          {"0.99", (double)q_at(depths, 0.99)}});
  }

  // UNREFERENCED IS NOT DEAD, and the report says so where it is read. A name
  // dispatched through a table, reached from a translation unit outside the
  // scan, or called by the runtime rather than by us is unreferenced and alive.
  // What the join gives is a SHORT list to look at, out of a corpus too large
  // to read, and the arithmetic behind it is exact even when the conclusion is
  // not.
  {
    std::set<std::string> referenced;
    for (const StaticRef& r : refs) referenced.insert(r.name);
    std::vector<const StaticDecl*> orphans;
    std::map<std::string, uint64_t> orphan_kind;
    for (const StaticDecl& d : decls)
      if (!referenced.count(d.name)) { orphans.push_back(&d); ++orphan_kind[d.kind]; }
    char v[512];
    std::snprintf(v, sizeof(v),
                  "%zu declaration(s), %zu named again elsewhere, %zu reached by "
                  "nothing in the scanned set",
                  decls.size(), decls.size() - orphans.size(), orphans.size());
    declared.verdict = v;
    declared.klass = decls.empty() ? "EMPTY"
                   : orphans.empty() ? "FULLY-REFERENCED"
                   : orphans.size() * 4 > decls.size() ? "SPARSELY-REFERENCED"
                   : "MOSTLY-REFERENCED";
    Detail rows = Detail::array();
    for (size_t i = 0; i < orphans.size() && i < 32; ++i)
      rows.arr.push_back(Detail::object()
          .put("name", Detail::text(orphans[i]->name))
          .put("kind", Detail::text(orphans[i]->kind))
          .put("file", Detail::text(orphans[i]->file))
          .put("line", Detail::count(orphans[i]->line)));
    declared.detail.emplace_back("unreferenced", std::move(rows));
    declared.detail.emplace_back("caveat", Detail::text(
        "unreferenced is not dead: a table dispatch, a caller outside the scanned "
        "files and a runtime entry point all look like this"));
    declared.gauges.push_back({"montauk_static_declarations_total", "", (double)decls.size()});
    declared.gauges.push_back({"montauk_static_references_total", "", (double)refs.size()});
    declared.gauges.push_back({"montauk_static_unreferenced_total", "", (double)orphans.size()});
    for (const auto& kv : orphan_kind)
      declared.gauges.push_back({"montauk_static_unreferenced", "kind=\"" + kv.first + "\"",
                                 (double)kv.second});
  }

  ReportResult cfg;
  size_t nblocks = 0, nedges = 0;
  if (!fns.empty()) {
    std::vector<CfgStats> stats;
    std::vector<uint64_t> cyclo;
    size_t dead = 0, dead_fns = 0, natural = 0, irreducible = 0, macros = 0, handlers = 0, unresolved = 0;
    int dom_depth = 0;
    for (const StaticFn& f : fns) {
      stats.push_back(cfg_stats(f));
      const CfgStats& st = stats.back();
      cyclo.push_back(st.cyclomatic);
      nblocks += f.blocks.size();
      nedges += f.edges.size();
      dead += st.dead.size();
      dead_fns += !st.dead.empty();
      natural += st.natural;
      irreducible += st.irreducible;
      dom_depth = std::max(dom_depth, st.dom_depth);
      for (const StaticBlock& b : f.blocks) macros += b.kind == "macro";
      for (const StaticEdge& e : f.edges) {
        handlers += e.kind == "handler";
        unresolved += e.kind == "goto-unresolved";
      }
    }
    std::vector<uint64_t> sorted = cyclo;
    sublimation_u64(sorted.data(), sorted.size());
    char v[512];
    std::snprintf(v, sizeof(v),
                  "%zu function(s), %zu blocks, %zu edges; cyclomatic p50 %llu p99 %llu max %llu; "
                  "%zu block(s) unreachable from entry in %zu function(s); %zu natural loop(s), "
                  "%zu irreducible edge(s)",
                  fns.size(), nblocks, nedges, (unsigned long long)q_at(sorted, 0.5),
                  (unsigned long long)q_at(sorted, 0.99), (unsigned long long)sorted.back(),
                  dead, dead_fns, natural, irreducible);
    cfg.verdict = v;
    cfg.klass = irreducible ? "IRREDUCIBLE" : dead ? "UNREACHABLE-CODE" : "STRUCTURED";
    std::vector<size_t> by_cyclo(fns.size());
    for (size_t i = 0; i < by_cyclo.size(); ++i) by_cyclo[i] = i;
    sublimation_order_u64(by_cyclo, true, [&](size_t i) { return cyclo[i]; });
    Detail top = Detail::array();
    for (size_t r = 0; r < by_cyclo.size() && r < 10; ++r) {
      const StaticFn& f = fns[by_cyclo[r]];
      top.arr.push_back(Detail::object()
          .put("function", Detail::text(f.func))
          .put("file", Detail::text(f.file))
          .put("line", Detail::count(f.blocks.empty() ? 0 : f.blocks[0].line))
          .put("cyclomatic", Detail::count(cyclo[by_cyclo[r]]))
          .put("blocks", Detail::count(f.blocks.size()))
          .put("dominator_depth", Detail::count((uint64_t)stats[by_cyclo[r]].dom_depth)));
    }
    cfg.detail.emplace_back("most_complex", std::move(top));
    Detail unreach = Detail::array();
    for (size_t i = 0; i < fns.size() && unreach.arr.size() < 32; ++i)
      for (uint32_t b : stats[i].dead) {
        if (unreach.arr.size() == 32) break;
        unreach.arr.push_back(Detail::object()
            .put("function", Detail::text(fns[i].func))
            .put("file", Detail::text(fns[i].file))
            .put("line", Detail::count(fns[i].blocks[b].line))
            .put("kind", Detail::text(fns[i].blocks[b].kind)));
      }
    if (!unreach.arr.empty()) cfg.detail.emplace_back("unreachable", std::move(unreach));
    cfg.detail.emplace_back("limits", Detail::object()
        .put("macro_loops", Detail::count(macros))
        .put("handler_edges", Detail::count(handlers))
        .put("unresolved_gotos", Detail::count(unresolved)));
    cfg.detail.emplace_back("caveat", Detail::text(
        "exceptions, longjmp, computed gotos and calls that never return are edges a "
        "lexer cannot see; a macro that opens a block is drawn as a loop and a catch "
        "as a handler edge from its try, both from their shape"));
    cfg.gauges.push_back({"montauk_static_cfg_functions", "", (double)fns.size()});
    cfg.gauges.push_back({"montauk_static_cfg_blocks", "", (double)nblocks});
    cfg.gauges.push_back({"montauk_static_cfg_edges", "", (double)nedges});
    cfg.gauges.push_back({"montauk_static_cfg_unreachable_blocks", "", (double)dead});
    cfg.gauges.push_back({"montauk_static_cfg_natural_loops", "", (double)natural});
    cfg.gauges.push_back({"montauk_static_cfg_irreducible_edges", "", (double)irreducible});
    cfg.gauges.push_back({"montauk_static_cfg_dominator_depth_max", "", (double)dom_depth});
    push_quantile_gauges(cfg.gauges, "montauk_static_cfg_cyclomatic",
                         {{"0.5", (double)q_at(sorted, 0.5)}, {"0.9", (double)q_at(sorted, 0.9)},
                          {"0.99", (double)q_at(sorted, 0.99)}, {"max", (double)sorted.back()}});
  }

  if (want_json) {
    montauk_json j;
    montauk_json_init(&j, &g_out);
    montauk_json_obj_begin(&j);
    montauk_json_ku64(&j, "schema_version", 1);
    montauk_json_key(&j, "static");
    montauk_json_obj_begin(&j);
    montauk_json_kstr(&j, "path", path.c_str());
    montauk_json_kstr(&j, "language", lang.c_str());
    montauk_json_ku64(&j, "files", files.size());
    montauk_json_ku64(&j, "guards", g.size());
    montauk_json_ku64(&j, "declarations", decls.size());
    montauk_json_ku64(&j, "references", refs.size());
    montauk_json_ku64(&j, "blocks", nblocks);
    montauk_json_ku64(&j, "edges", nedges);
    montauk_json_obj_end(&j);
    montauk_json_key(&j, "reports");
    montauk_json_arr_begin(&j);
    json_result(j, "guards", guards);
    if (!decls.empty()) json_result(j, "declarations", declared);
    if (!fns.empty()) json_result(j, "cfg", cfg);
    montauk_json_arr_end(&j);
    montauk_json_obj_end(&j);
    montauk_sink_appendf(&g_out, "\n");
    return 0;
  }
  montauk_sink_appendf(&g_out, "STATIC %s (%s)\n\n", path.c_str(), lang.c_str());
  text_result("guards", guards);
  if (!decls.empty()) { montauk_sink_appendc(&g_out, '\n'); text_result("declarations", declared); }
  if (!fns.empty()) { montauk_sink_appendc(&g_out, '\n'); text_result("cfg", cfg); }
  return 0;
}

int montauk_analyze_main(int argc, char** argv) {
  // Report stdout buffers into g_out and drains once at exit; set up before any
  // output path (including --version) so every return drains.
  montauk_sink_init(&g_out, 1);
  std::atexit(drain_out);

  // --version: the upgrade detector (bench-enduser / install.py) reads this to
  // decide whether an installed montauk is older than the clone and needs a
  // reinstall. Plain "<n>.<n>.<n>" on stdout, nothing else.
  if (argc >= 2 && std::string(argv[1]) == "--version") {
    montauk_sink_appendf(&g_out, "%s\n", MONTAUK_VERSION);
    return 0;
  }
  bool want_help = argc >= 2 &&
                   (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h");
  if (argc < 2 || want_help) {
    std::fprintf(want_help ? stdout : stderr,
        "usage: montauk --analyze TRACE [--report name[,name...]] [--json]\n"
        "                       [--sig N|NAME] [--comm SUBSTR] [--pid N] [--tid N]\n"
        "                       [--window SECONDS] [--floor-us US]\n"
        "                       (--json emits the structured envelope instead of\n"
        "                        the text report. --pid/--tid narrow to one task's\n"
        "                        events in sched, locality, dispatch-stall, wakers\n"
        "                        and fractal, and to one thread's in signals; --sig\n"
        "                        and --comm remain signals-only (sched events carry\n"
        "                        no signal number or comm). --window bounds the\n"
        "                        trailing capture-teardown split, def 2s)\n"
        "       montauk --analyze TRACE --select CLASS[.OP,...] [--where FIELD<op>V]...\n"
        "                       [--by FIELD[,FIELD]] [--value FIELD]\n"
        "                       [--count | --gap | --pair OP [--pair-where FIELD<op>V]...\n"
        "                        | --last]\n"
        "                       [--between START:END] [--stats n,p50,p99,max,mean]\n"
        "                       [--json]\n"
        "                       (a question as a command line: select events by\n"
        "                        class, op and any field, key them, and apply one\n"
        "                        operator. --pair closes each event at the next OP\n"
        "                        on the same key; --where qualifies the opening\n"
        "                        event only and --pair-where the closing one.\n"
        "                        --stats reduces the operator's\n"
        "                        measure. Classes: sched io ntsync heap signal mmap\n"
        "                        abort heapstk keyedevt kstrand waitstack scx_storm\n"
        "                        provider rawstack fork exec exit comm thread_name)\n"
        "       montauk --analyze DIR|FILE.prom [more.prom...] [--by LABEL]\n"
        "                       [--pairs adjacent|all|vs-best] [--trajectory]\n"
        "                       [--metric substr] [--full] [--higher-better]\n"
        "                       [--alias OLD=NEW] [--alias-axis OLD=NEW]\n"
        "                       [--drop-label L] [--threads n] [--seed n]\n"
        "                       [--perms n] [--alpha a] [--min-effect d]\n"
        "                       [--quantile q] [--no-emit]\n"
        "                       (LABEL: any prom label, plus the synthetic\n"
        "                        version | commit | capture; default scheduler.\n"
        "                        --pairs defaults to adjacent on the ordered\n"
        "                        axes version/capture, all otherwise.\n"
        "                        --trajectory: version-ordered change-point\n"
        "                        scan instead of pairwise comparison)\n"
        "       montauk --analyze RECORDING_DIR --digest [--redact] [--json]\n"
        "                       [--sig N|NAME] [--comm SUBSTR] [--pid N]\n"
        "                       [--tid N] [--window SECONDS]\n"
        "                       (the digest folds the same per-event reports, so\n"
        "                        it takes the same row qualifiers)\n"
        "       montauk --analyze RECORDING_DIR --l2-by-cpu [--json]\n"
        "                       (reads the .prom scrapes; row qualifiers do not\n"
        "                        apply and are rejected rather than ignored)\n");
    return want_help ? 0 : 2;
  }
  const char* path = argv[1];

  {
    std::string gp = path;
    if (gp.size() > 7 && gp.compare(gp.size() - 7, 7, ".guards") == 0) {
      bool gj = false;
      for (int i = 1; i < argc; ++i) if (std::string(argv[i]) == "--json") gj = true;
      return run_guards(gp, gj);
    }
  }

  // Population mode: a directory of bench .prom archives, or .prom file(s).
  // Cross-run / cross-version statistical inference, not single-trace reports.
  {
    struct stat st{};
    bool is_dir = (::stat(path, &st) == 0 && S_ISDIR(st.st_mode));
    std::string p1 = path;
    bool is_prom = p1.size() > 5 && p1.compare(p1.size() - 5, 5, ".prom") == 0;
    bool has_group = false;
    for (int i = 1; i < argc; ++i)
      if (std::string(argv[i]) == "--group") has_group = true;
    // --report is an unambiguous request for single-trace mode, UNLESS an
    // explicit recording-dir verb is also present. Without the first half,
    // is_dir/is_prom always wins for any real montauk capture (every recording
    // is a directory or a .prom file), making --report -- and
    // --sig/--comm/--pid/--tid/--window with it -- permanently unreachable:
    // the flag loop below has no case for it and errors "unknown population
    // flag '--report'" before single-trace mode's own (correct, complete)
    // --report parsing further down is ever reached.
    //
    // WITHOUT THE SECOND HALF, `RECORDING_DIR --digest --report X` would fall
    // into single-trace mode and try to open the DIRECTORY as a trace file,
    // failing with "short read on header" -- which reads like a corrupt capture
    // and is not. A verb naming the mode outranks a flag that merely implies it.
    bool has_report = false, has_dir_verb = false;
    for (int i = 1; i < argc; ++i) {
      std::string a = argv[i];
      if (a == "--report") has_report = true;
      else if (a == "--digest" || a == "--l2-by-cpu")
        has_dir_verb = true;
    }
    if ((!has_report || has_dir_verb) && (is_dir || is_prom || has_group)) {
      // Recording-dir modes (vs cross-run population stats):
      //   --digest    compact specs+offenders+aggregates report
      //   --l2-by-cpu per-CPU cache-miss localization
      bool want_digest = false, want_l2 = false, redact = false, want_digest_json = false;
      // Row qualifiers are honored here too. They used to be read past in this
      // block, so a --window given to --digest silently did nothing; the digest
      // folds the same per-event reports single-trace mode does, so the same
      // narrowing applies to it.
      bool saw_qualifier = false;
      for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--digest") want_digest = true;
        else if (a == "--l2-by-cpu") want_l2 = true;
        else if (a == "--redact") redact = true;
        else if (a == "--json") want_digest_json = true;
        else if (a == "--report") {
          // The digest's headline set is fixed and its JSON carries every
          // report's conclusion; a selection here would be read and ignored.
          log_error("--report selects reports over a single trace; a recording dir's "
                    "--digest runs them all (its --json carries every conclusion)");
          return 2;
        }
        else {
          int used = 0;
          int q = take_row_qualifier(argc, argv, i, &used);
          if (q == 2) return 2;
          if (q == 0) { saw_qualifier = true; i += used; }
        }
      }
      if (want_digest) return run_digest(path, redact, want_digest_json);
      if (want_l2) {
        // The per-CPU L2 localization reads the .prom scrapes, not the event
        // stream, so no row qualifier can narrow it. Say so rather than accept
        // the flag and ignore it.
        if (saw_qualifier) {
          log_error("--l2-by-cpu reads the .prom scrapes, not per-event rows -- "
                    "row qualifiers (--sig/--comm/--pid/--tid/--window) do not "
                    "apply to it");
          return 2;
        }
        return montauk::pop::run_l2_by_cpu(path, want_digest_json);
      }
      montauk::pop::PopOptions opt;
      std::vector<std::string> files;
      // argv[1] is a consumed path only when it is itself a dir/prom; a bare
      // --group invocation leaves it for the flag loop (starting at i=1).
      int argstart = 2;
      if (is_dir) files = montauk::pop::glob_proms(path);
      else if (is_prom) files.push_back(path);
      else argstart = 1;
      for (int i = argstart; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--by" && i + 1 < argc) {
          opt.compare_axis = argv[++i];
          // Any label is a valid axis (the engine is label-generic); `le` is
          // the one structural exception, it is a histogram bucket bound and
          // is always dropped from identity.
          if (opt.compare_axis == "le") {
            log_error("--by le is not comparable (le is a histogram bucket "
                      "bound, not a group identity)");
            return 2;
          }
        }
        else if (a == "--metric" && i + 1 < argc) opt.metric_filter = argv[++i];
        else if (a == "--full") opt.full = true;
        else if (a == "--higher-better") opt.lower_is_better = false;
        else if (a == "--no-emit") opt.emit_prom = false;
        else if (a == "--trajectory") opt.trajectory = true;
        else if (a == "--pairs" && i + 1 < argc) {
          opt.pairs = argv[++i];
          if (opt.pairs != "adjacent" && opt.pairs != "all" &&
              opt.pairs != "vs-best") {
            log_error("--pairs takes adjacent | all | vs-best");
            return 2;
          }
        }
        else if (a == "--threads" && i + 1 < argc)
          opt.threads = static_cast<int>(std::strtol(argv[++i], nullptr, 10));
        else if (a == "--perms" && i + 1 < argc)
          opt.traj_perms = static_cast<int>(std::strtol(argv[++i], nullptr, 10));
        else if (a == "--alpha" && i + 1 < argc)
          opt.traj_alpha = std::strtod(argv[++i], nullptr);
        else if (a == "--min-effect" && i + 1 < argc)
          opt.traj_min_effect = std::strtod(argv[++i], nullptr);
        else if (a == "--alias" && i + 1 < argc) {
          std::string spec = argv[++i];
          size_t eq = spec.find('=');
          if (eq == std::string::npos || eq == 0 || eq + 1 >= spec.size()) {
            log_error("--alias needs OLD=NEW (metric family rename)");
            return 2;
          }
          std::string oldn = spec.substr(0, eq), newn = spec.substr(eq + 1);
          auto it = opt.family_alias.find(oldn);
          if (it != opt.family_alias.end() && it->second != newn) {
            log_error("--alias %s given twice with conflicting targets",
                      oldn.c_str());
            return 2;
          }
          opt.family_alias[oldn] = newn;
        }
        else if (a == "--alias-axis" && i + 1 < argc) {
          std::string spec = argv[++i];
          size_t eq = spec.find('=');
          if (eq == std::string::npos || eq == 0 || eq + 1 >= spec.size()) {
            log_error("--alias-axis needs OLD=NEW (axis display rename)");
            return 2;
          }
          opt.axis_alias[spec.substr(0, eq)] = spec.substr(eq + 1);
        }
        else if (a == "--drop-label" && i + 1 < argc) {
          std::string lbl = argv[++i];
          if (lbl == opt.compare_axis) {
            log_error("--drop-label %s conflicts with the compare axis",
                      lbl.c_str());
            return 2;
          }
          opt.drop_labels.push_back(lbl);
        }
        else if (a == "--seed" && i + 1 < argc)
          opt.seed = std::strtoull(argv[++i], nullptr, 10);
        else if (a == "--quantile" && i + 1 < argc)
          opt.quantile = std::strtod(argv[++i], nullptr);
        else if (a == "--group" && i + 1 < argc) {
          // NAME=PATH: tag every .prom under PATH (dir) or PATH itself (file)
          // with group=NAME and split on it -- the explicit A/B for run-sets
          // whose committed labels (scheduler, version, commit) are identical.
          std::string spec = argv[++i];
          size_t eq = spec.find('=');
          if (eq == std::string::npos) {
            log_error("--group needs NAME=PATH (e.g. --group pre=/runs/old)");
            return 2;
          }
          std::string gname = spec.substr(0, eq), gpath = spec.substr(eq + 1);
          std::vector<std::string> gfiles;
          struct stat gst{};
          if (::stat(gpath.c_str(), &gst) == 0 && S_ISDIR(gst.st_mode))
            gfiles = montauk::pop::glob_proms(gpath);
          else
            gfiles.push_back(gpath);
          for (const auto& gf : gfiles) {
            files.push_back(gf);
            opt.file_group[gf] = gname;
          }
          opt.compare_axis = "group";
        }
        else if (a == "--redact") { /* no comms in population mode */ }
        else if (!a.empty() && a[0] != '-') files.push_back(a);
        else {
          log_error("unknown population flag '%s'", a.c_str());
          return 2;
        }
      }
      return montauk::pop::run_population(files, opt);
    }
  }

  for (int i = 2; i < argc; ++i)
    if (std::strcmp(argv[i], "--select") == 0) return run_query(path, argc, argv);

  auto reports = make_reports();

  std::vector<Report*> active;
  std::string report_list;
  bool want_json = false;
  for (int i = 2; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--redact") {
      g_redact_comm = true;
    } else if (a == "--json") {
      want_json = true;
    } else if (a == "--report" && i + 1 < argc) {
      report_list = argv[++i];
    } else if (int used = 0, q = take_row_qualifier(argc, argv, i, &used);
               q != kQualNotMine) {
      if (q != 0) return q;
      i += used;
    } else if (a == "--digest" || a == "--l2-by-cpu") {
      // THE FLAG IS NOT UNKNOWN, THE TARGET IS THE WRONG SHAPE. These are
      // RECORDING-DIR verbs: the digest joins the dir's .prom scrapes (SYSTEM
      // specs, THERMAL/POWER, the L2 hot CPU) with the optional event stream,
      // and a bare stream has no scrapes to join. Reporting it as an unknown
      // flag sends the reader looking for a missing feature instead of a
      // mismatched argument, which is the more expensive of the two searches.
      log_error("'%s' applies to a RECORDING DIR, not a single trace file. "
                "For a stream use: montauk --analyze %s [--report NAME] [--json]",
                a.c_str(), path);
      return 2;
    } else {
      log_error("unknown flag '%s' (see montauk --analyze --help)", a.c_str());
      return 2;
    }
  }
  for (auto& r : reports) active.push_back(r.get());
  if (!select_reports(active, report_list)) return 2;

  montauk::model::TraceReader reader;
  switch (reader.open(path)) {
    case montauk::model::TraceReadStatus::Ok:
      break;
    case montauk::model::TraceReadStatus::OpenFailed:
      log_error("cannot open '%s'", path);
      return 1;
    case montauk::model::TraceReadStatus::ShortHeader:
      log_error("short read on header");
      return 1;
    case montauk::model::TraceReadStatus::BadMagic:
      log_error("bad magic (not a montauk trace log)");
      return 1;
    default:
      log_error("format version %u, this build expects %u",
                reader.header().version, montauk::model::kTraceFormatVersion);
      return 1;
  }

  // Load any <PID>.maps sidecars beside the trace so the sync reports can
  // resolve a futex uaddr to the module+offset of the contended lock.
  g_maps.load_dir(path);

  for (const Report* r : active) arm_ledger(r);
  const auto t0 = std::chrono::steady_clock::now();
  auto status = reader.for_each([&](uint32_t type, const uint8_t* data, uint32_t len) {
    fold_driver_state(type, data, len);
    for (Report* r : active) r->fold(type, data, len);
  });
  if (status == montauk::model::TraceReadStatus::CorruptLength) {
    log_warn("corrupt record length %u at event %" PRIu64 "; reporting on data read so far",
             reader.corrupt_len(), reader.events_read());
  } else if (status == montauk::model::TraceReadStatus::TruncatedRecord) {
    log_warn("truncated record at event %" PRIu64 "; reporting on data read so far",
             reader.events_read());
  }

  for (Report* r : active) r->compute();  // finalize typed results once, before any renderer

  // --json: the structured surface. Same typed results the text/prom renderers
  // read, wrapped in one envelope: trace context + the reports array. An agent
  // reads this instead of scraping the human report. Pure alternate output --
  // no text report, no .prom write, no offenders block.
  if (want_json) {
    const auto& mh = reader.header();
    char mpat[33];
    std::snprintf(mpat, sizeof mpat, "%.*s",
                  static_cast<int>(sizeof(mh.pattern)), mh.pattern);
    montauk_json j;
    montauk_json_init(&j, &g_out);
    montauk_json_obj_begin(&j);
      montauk_json_ku64(&j, "schema_version", 1u);
      montauk_json_key(&j, "trace");
      montauk_json_obj_begin(&j);
        montauk_json_kstr(&j, "path", path);
        montauk_json_kstr(&j, "pattern", mpat);
        montauk_json_ku64(&j, "format_version", mh.version);
        montauk_json_ku64(&j, "events", reader.events_read());
        montauk_json_ku64(&j, "start_unix_ns", mh.real_anchor_ns);
        // Data-loss provenance: one field answers "is this capture whole."
        // Emitted only when a drop snapshot exists in the trace; absent on
        // captures predating drop accounting (absence of the counter is not
        // evidence of zero loss).
        if (g_drop_seen) {
          const uint64_t dropped = drops_total();
          montauk_json_ku64(&j, "dropped_events", dropped);
          const uint64_t observed = reader.events_read();
          montauk_json_knum(
              &j, "capture_completeness",
              (observed + dropped) > 0
                  ? static_cast<double>(observed) /
                        static_cast<double>(observed + dropped)
                  : 1.0);
        }
        // Qualifier provenance: a gauge computed under --pid/--tid/--comm/
        // --sig is a different population than the whole trace, and without
        // this record the two are indistinguishable downstream (a filtered
        // .prom could silently enter a population comparison against
        // unfiltered runs). Emitted only when a qualifier is active, so
        // unqualified envelopes are byte-stable.
        if (g_qual_pid >= 0 || g_qual_tid >= 0 || !g_qual_comm.empty() ||
            g_qual_sig >= 0) {
          montauk_json_key(&j, "qualifiers");
          montauk_json_obj_begin(&j);
            if (g_qual_pid >= 0)
              montauk_json_ku64(&j, "pid", static_cast<uint64_t>(g_qual_pid));
            if (g_qual_tid >= 0)
              montauk_json_ku64(&j, "tid", static_cast<uint64_t>(g_qual_tid));
            if (!g_qual_comm.empty())
              montauk_json_kstr(&j, "comm", g_qual_comm.c_str());
            if (g_qual_sig >= 0)
              montauk_json_ku64(&j, "sig", static_cast<uint64_t>(g_qual_sig));
          montauk_json_obj_end(&j);
        }
      montauk_json_obj_end(&j);
      montauk_json_key(&j, "reports");
      montauk_json_arr_begin(&j);
        for (Report* r : active) r->json(j);
      montauk_json_arr_end(&j);
    montauk_json_obj_end(&j);
    montauk_sink_appendc(&g_out, '\n');
    return 0;
  }

  bool first = true;
  for (Report* r : active) {
    if (!first) montauk_sink_appendf(&g_out, "\n");
    first = false;
    r->emit(reader);
  }

  // Self-timing: how long this analysis took end to end (fold + sort + emit).
  {
    const double secs = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t0).count();
    const uint64_t nev = reader.events_read();
    log_info("analyzed %s events in %.2fs (%s/s)",
             fmt_count(static_cast<double>(nev)).c_str(), secs,
             fmt_count(secs > 0.0 ? static_cast<double>(nev) / secs : 0.0).c_str());
  }

  std::vector<PromMetric> prom;
  for (Report* r : active) r->prom(prom);

  emit_capture_loss(reader.events_read(), prom);

  // POORLY-BEHAVING ITEMS: consolidate every active report's offenders into one
  // severity-ranked view -- the "what specifically misbehaved" the report leads
  // with. Generic: each report contributed kind/id/metric/value/sev; we only
  // rank and emit the reusable montauk_offender{} family.
  {
    std::vector<Offender> offs;
    for (Report* r : active) r->offenders(offs);
    if (!offs.empty()) {
      rank_offenders(offs);
      emit_offenders_text(offs, prom);
    }
  }

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
    // Qualifier provenance, mirroring the JSON envelope: a filtered .prom
    // must be distinguishable from a whole-trace one.
    if (g_qual_pid >= 0) info += ",qual_pid=\"" + std::to_string(g_qual_pid) + "\"";
    if (g_qual_tid >= 0) info += ",qual_tid=\"" + std::to_string(g_qual_tid) + "\"";
    if (!g_qual_comm.empty()) info += ",qual_comm=\"" + g_qual_comm + "\"";
    if (g_qual_sig >= 0) info += ",qual_sig=\"" + std::to_string(g_qual_sig) + "\"";
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
      log_error("cannot write %s", out_path.c_str());
      return 1;
    }
    log_info("analysis written to %s", out_path.c_str());
  }
  return 0;
}
