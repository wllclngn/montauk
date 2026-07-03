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
#include "prom_population.hpp"
#include "prom_stats.hpp"
#include "util/Log.hpp"

#include <algorithm>
#include <cctype>
#include <cinttypes>
#include <cstdlib>
#include <dirent.h>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

using montauk::util::log_info;
using montauk::util::log_warn;
using montauk::util::log_error;

// ── Address resolution against captured /proc/PID/maps sidecars ──────────────
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
      std::sort(segs.begin(), segs.end(),
                [](const Seg& a, const Seg& b) { return a.start < b.start; });
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
#include "sublimation_pack.h"   // index-by-key sorts (u64/f64) for report rows
#include "sublimation_order.hpp" // sublimation_order_u64/_f64: struct-by-key ordering
#include "sublimation_search.h" // structural locator: where a disorder pattern sits
#include "util/sink.h"          // buffered stdout sink: one drain, not a printf per line

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
    case 7:   return "poll";
    case 271: return "ppoll";
    case 232: return "epoll_wait";
    case 281: return "epoll_pwait";
    case 47:  return "recvmsg";
    case 45:  return "recvfrom";
    case 23:  return "select";
    case 270: return "pselect6";
    case 16:  return "ioctl";
    default:  return "?";
  }
}

// Signal number -> canonical name, nullptr when unnamed. Shared by the
// signals report and the --sig qualifier parser.
const char* signal_name(int32_t n) {
  switch (n) {
    case 1:  return "SIGHUP";  case 2:  return "SIGINT";  case 3:  return "SIGQUIT";
    case 4:  return "SIGILL";  case 5:  return "SIGTRAP"; case 6:  return "SIGABRT";
    case 7:  return "SIGBUS";  case 8:  return "SIGFPE";  case 9:  return "SIGKILL";
    case 10: return "SIGUSR1"; case 11: return "SIGSEGV"; case 12: return "SIGUSR2";
    case 13: return "SIGPIPE"; case 14: return "SIGALRM"; case 15: return "SIGTERM";
    case 17: return "SIGCHLD"; case 19: return "SIGSTOP"; case 24: return "SIGXCPU";
    case 25: return "SIGXFSZ"; case 31: return "SIGSYS";
    default: return nullptr;
  }
}

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

const char* sched_op_name(uint32_t op) {
  switch (op) {
    case SCHED_OP_ENQUEUE:        return "ENQUEUE";
    case SCHED_OP_PICK:           return "PICK";
    case SCHED_OP_PICK_EMPTY:     return "PICK_EMPTY";
    case SCHED_OP_PREEMPT_TICK:   return "PREEMPT_TICK";
    case SCHED_OP_PREEMPT_WAKEUP: return "PREEMPT_WAKEUP";
    case SCHED_OP_WAKEUP:         return "WAKEUP";
    case SCHED_OP_WAKE2RUN:       return "WAKE2RUN";
    case SCHED_OP_CPU_IDLE:       return "CPU_IDLE";
    case SCHED_OP_SWITCH_IN:      return "SWITCH_IN";
    case SCHED_OP_FIELD_GATE:     return "FIELD_GATE";
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
// Wakeup-worthy: ops that can WAKE a waiter. event_reset CLEARS the signal and
// wakes nothing, so a reset-heavy event is not a busy producer. Excluding reset
// is what separates a genuine lost wakeup (a real wake landed after the park)
// from a producer that simply went quiet (its last actual wake was before it).
bool is_wakeup_op(uint8_t op) {
  return op == NTS_EVENT_SET || op == NTS_EVENT_PULSE || op == NTS_SEM_RELEASE ||
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

const char* prom_help(const char* name) {
  static constexpr struct { const char* name; const char* help; } kHelp[] = {
    {"montauk_analysis_events_total",
     "Event count per type+subtype over the whole trace"},
    {"montauk_analysis_dispatches_per_sec",
     "Scheduler dispatch (PICK) rate per second over the trace"},
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
double q_us(const std::vector<uint64_t>& v, double f) {
  if (v.empty()) return 0.0;
  size_t i = static_cast<size_t>(static_cast<double>(v.size()) * f);
  if (i >= v.size()) i = v.size() - 1;
  return us(v[i]);
}
double q_ms(const std::vector<uint64_t>& v, double f) {
  if (v.empty()) return 0.0;
  size_t i = static_cast<size_t>(static_cast<double>(v.size()) * f);
  if (i >= v.size()) i = v.size() - 1;
  return ms(v[i]);
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

struct Report {
  virtual ~Report() = default;
  virtual const char* name() const = 0;
  virtual void fold(uint32_t type, const uint8_t* data, uint32_t len) = 0;
  virtual void emit(const montauk::model::TraceReader& reader) = 0;
  // Called after emit(); appends this report's montauk_analysis_* samples.
  virtual void prom(std::vector<PromMetric>& out) { (void)out; }
  // Called after emit(); contributes this report's misbehaving entities to the
  // consolidated ranked view. Default: none.
  virtual void offenders(std::vector<Offender>& out) { (void)out; }
  // Every report opens with "REPORT <name>". Shared so the 23 emit() bodies do
  // not each hand-roll it (R2 consolidation); name() is the report's identity.
  void header() const { montauk_sink_appendf(&g_out, "REPORT %s\n", name()); }
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
  uint64_t kstrand_ = 0;          // per-CPU kthread dispatch strands
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
      case TRACE_EVT_KSTRAND: {
        if (len < sizeof(montauk_kstrand_event)) break;
        auto* e = reinterpret_cast<const montauk_kstrand_event*>(data);
        note_ts(e->timestamp_ns);
        ++kstrand_;
        break;
      }
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
    row("KSTRAND", "pcpu_kthread", kstrand_);
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
    header();
    if (total_ == 0 || rs.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: empty trace — no events\n");
    } else {
      const Row* dom = &rs[0];
      for (const Row& r : rs)
        if (r.n > dom->n) dom = &r;
      montauk_sink_appendf(&g_out, "VERDICT: %s events in %.1f s (%s/s), dominated by %s %s (%.0f%%)\n",
                  fmt_count(static_cast<double>(total_)).c_str(), dur_s, fmt_count(eps).c_str(),
                  dom->type, dom->sub.c_str(),
                  100.0 * static_cast<double>(dom->n) / static_cast<double>(total_));
    }
    montauk_sink_appendf(&g_out, "pattern         %s\n", pat);
    montauk_sink_appendf(&g_out, "start           %s\n", wall_str(hdr.real_anchor_ns).c_str());
    montauk_sink_appendf(&g_out, "format_version  %u\n", hdr.version);
    montauk_sink_appendf(&g_out, "first_event_ms  %.3f\n", min_ts_ ? reader.elapsed_ms(min_ts_) : 0.0);
    montauk_sink_appendf(&g_out, "duration_s      %.3f\n", dur_s);
    montauk_sink_appendf(&g_out, "events          %" PRIu64 "\n", total_);
    montauk_sink_appendf(&g_out, "events_per_sec  %.0f\n", eps);
    montauk_sink_appendf(&g_out, "type    subtype          count\n");
    for (const Row& r : rs)
      montauk_sink_appendf(&g_out, "%-7s %-16s %12" PRIu64 "\n", r.type, r.sub.c_str(), r.n);
  }

  void prom(std::vector<PromMetric>& out) override {
    for (const Row& r : rows()) {
      char lab[80];
      std::snprintf(lab, sizeof(lab), "type=\"%s\",subtype=\"%s\"", r.type, r.sub.c_str());
      out.push_back({"montauk_analysis_events_total", lab, static_cast<double>(r.n)});
    }
    // Trace-derived scheduler rates -- the dispatches/s and preempts/s the
    // bench suite otherwise text-scrapes from the scheduler's own [TICK] stdout.
    // PICK is a dispatch; preempt is tick + wakeup. Duration is the event-span.
    double dur_s = (max_ts_ > min_ts_) ? static_cast<double>(max_ts_ - min_ts_) / 1e9 : 0.0;
    if (dur_s > 0.0) {
      out.push_back({"montauk_analysis_dispatches_per_sec", "",
                     static_cast<double>(sched_[SCHED_OP_PICK]) / dur_s});
      out.push_back({"montauk_analysis_preempts_per_sec", "",
                     static_cast<double>(sched_[SCHED_OP_PREEMPT_TICK] +
                                         sched_[SCHED_OP_PREEMPT_WAKEUP]) / dur_s});
    }
  }
};

// REPORT waits: per (tid,fd) NTSYNC wait-completion stats.
struct WaitsReport final : Report {
  struct Agg {
    uint32_t tid = 0;
    uint32_t pid = 0;
    bool is_futex = false;
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
    if (a.count == 0) { a.tid = w.tid; a.pid = w.pid; a.is_futex = w.is_futex; a.obj = w.obj; }
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
    header();
    if (aggs_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no sync wait completions in trace (NTSYNC or futex)\n");
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
    std::string topobj = fmt_obj(top->pid, top->obj, top->is_futex);
    if (share >= 50.0)
      montauk_sink_appendf(&g_out, "VERDICT: tid=%u obj=%s dominates — %s of %s wait completions (%.0f%%) across %zu tid/obj pairs\n",
                  top->tid, topobj.c_str(), fmt_count(static_cast<double>(top->count)).c_str(),
                  fmt_count(static_cast<double>(total)).c_str(), share, aggs_.size());
    else
      montauk_sink_appendf(&g_out, "VERDICT: wait load spread across %zu tid/obj pairs — top tid=%u obj=%s holds %.0f%% (%s of %s)\n",
                  aggs_.size(), top->tid, topobj.c_str(), share,
                  fmt_count(static_cast<double>(top->count)).c_str(),
                  fmt_count(static_cast<double>(total)).c_str());
    montauk_sink_appendf(&g_out, "result legend: >=0 signaled object index, %" PRId64 " ETIMEDOUT, other negative -errno\n",
                kEtimedout);
    std::vector<Agg*> rows;
    rows.reserve(aggs_.size());
    for (auto& [k, a] : aggs_) { (void)k; rows.push_back(&a); }
    sublimation_order_u64(rows, true, [](const Agg* p) { return p->count; });
    montauk_sink_appendf(&g_out, "tid      obj                waits      gap_med_ms gap_p99_ms results\n");
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
      std::string oname = sync_obj_name(a->pid, a->obj, a->is_futex);
      montauk_sink_appendf(&g_out, "%-8u 0x%016" PRIx64 " %-10" PRIu64 " %-10s %-10s %s%s%s\n",
                  a->tid, a->obj, a->count, med, p99, res_s.c_str(),
                  oname.empty() ? "" : "  ", oname.c_str());
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
    uint32_t pid = 0;       // owning process, for resolving a futex uaddr
    bool is_futex = false;  // obj is a futex uaddr (resolvable) vs an ntsync fd
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
    uint32_t pid;
    bool is_futex;
  };
  std::unordered_map<uint64_t, RunState> state_;
  std::vector<Run> runs_;
  // Per-object wait/signal totals -- the livelock discriminator. A genuine
  // livelock makes no progress, so its object has no plausible waker (waits far
  // outnumber signals). A healthy partnered ping-pong is woken by its partner on
  // every iteration (waits ~= signals), which looks IDENTICAL to a livelock by
  // gap and result code alone -- both are sub-tick streaks of result>=0 waits.
  // Without this, a high-rate but perfectly healthy futex ping-pong (EEVDF and
  // PANDEMONIUM both produce ~80-170k waits/s on the ipc workload) was ranked a
  // HIGH-severity spin offender purely on rate.
  std::unordered_map<uint64_t, uint64_t> obj_waits_;
  std::unordered_map<uint64_t, uint64_t> obj_signals_;

  const char* name() const override { return "spins"; }

  static void tally(RunState& s, int64_t result) {
    if (result >= 0) ++s.succ;
    else if (result == kEtimedout) ++s.timeo;
    else ++s.other;
  }

  void finalize(uint32_t tid, uint64_t obj, RunState& s, uint64_t end_ts) {
    if (s.iters >= kSpinMinIters)
      runs_.push_back({tid, obj, s.iters, s.start_ts, end_ts, s.succ, s.timeo,
                       s.other, s.pid, s.is_futex});
    s.iters = 0;
    s.succ = s.timeo = s.other = 0;
  }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    // Count signals per object first -- a wake on an object is the evidence that
    // some partner is making progress on it (it is not a stranded livelock).
    SyncSignal sig;
    if (sync_signal(type, data, len, sig)) { ++obj_signals_[sig.obj]; return; }
    SyncWait w;
    if (!sync_wait(type, data, len, w)) return;
    ++obj_waits_[w.obj];
    auto& s = state_[tid_obj_key(w.tid, w.obj)];
    s.tid = w.tid;
    s.pid = w.pid;
    s.is_futex = w.is_futex;
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
    header();
    if (runs_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no spin runs detected\n");
      montauk_sink_appendf(&g_out, "criteria: inter-wait gap < %.1f ms sustained >= %" PRIu64 " iterations\n",
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
    std::string where;
    if (pairs.size() == 1)
      where = "all tid=" + std::to_string(runs_[0].tid) + " obj=" +
              fmt_obj(runs_[0].pid, runs_[0].obj, runs_[0].is_futex);
    else
      where = "across " + std::to_string(pairs.size()) + " tid/obj pairs";
    montauk_sink_appendf(&g_out, "VERDICT: %s — %s, %s, peak %s waits/s\n",
                word, counts, where.c_str(), fmt_count(peak).c_str());
    montauk_sink_appendf(&g_out, "criteria: inter-wait gap < %.1f ms sustained >= %" PRIu64 " iterations\n",
                static_cast<double>(kSpinGapNs) / 1e6, kSpinMinIters);
    sublimation_order_u64(runs_, true, [](const Run& r) { return r.iters; });
    montauk_sink_appendf(&g_out, "tid      obj                iters      start_ms     span_ms    rate_per_s dominant              verdict\n");
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
      std::string oname = sync_obj_name(r.pid, r.obj, r.is_futex);
      montauk_sink_appendf(&g_out, "%-8u 0x%016" PRIx64 " %-10" PRIu64 " %-12.3f %-10.3f %-10.0f %-21s %s%s%s\n",
                  r.tid, r.obj, r.iters, reader.elapsed_ms(r.start_ts), span_ms, rate,
                  dom_s, verdict, oname.empty() ? "" : "  ", oname.c_str());
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

  void offenders(std::vector<Offender>& out) override {
    finalize_all();  // idempotent; drains any open runs
    std::unordered_map<uint64_t, std::pair<const Run*, double>> peaks;
    for (const auto& r : runs_) {
      double rate = run_rate(r);
      auto& p = peaks[tid_obj_key(r.tid, r.obj)];
      if (!p.first || rate > p.second) p = {&r, rate};
    }
    for (const auto& [key, p] : peaks) {
      (void)key;
      const Run& r = *p.first;
      // PROGRESS TEST: is this object actually being woken by a partner? A
      // healthy ping-pong has roughly one signal per wait; a livelock has waits
      // with no plausible waker. Reuse the pairing report's ratio: an object is
      // "partnered" when its signals are within kPairingWaitSignalRatio of its
      // waits (i.e. not signal-starved).
      uint64_t waits = obj_waits_.count(r.obj) ? obj_waits_[r.obj] : r.iters;
      uint64_t sigs = obj_signals_.count(r.obj) ? obj_signals_[r.obj] : 0;
      bool partnered = sigs > 0 && waits <= sigs * kPairingWaitSignalRatio;
      // result-tally dominance: success means each wait returned signaled.
      bool failed_progress = !(r.succ >= r.timeo && r.succ >= r.other);
      // A partnered, cleanly-returning run is a healthy ping-pong, NOT a spin --
      // do not rank it as an offender at all, no matter how high the rate. Only a
      // signal-starved object (real livelock) or a timeout/error-dominant run
      // (starved/failing waiter) is a genuine offender.
      if (partnered && !failed_progress) continue;
      char idb[16];
      std::snprintf(idb, sizeof(idb), "%u", r.tid);
      std::string objs = fmt_obj(r.pid, r.obj, r.is_futex);
      // Failed-progress runs are always HIGH; a signal-starved livelock scales
      // severity by rate, as before.
      int sev = failed_progress ? 2 : (p.second >= 10000.0 ? 2 : 1);
      out.push_back({"spin", idb, objs, "waits_per_s", p.second, sev});
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
    header();
    if (aggs_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no NTSYNC activity in trace\n");
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
      montauk_sink_appendf(&g_out, "VERDICT: all waited fds have plausible signalers\n");
    } else {
      char more[64] = "";
      if (n_flagged > 1)
        std::snprintf(more, sizeof(more), ", +%zu more flagged fds", n_flagged - 1);
      montauk_sink_appendf(&g_out, "VERDICT: fd %d stuck-signaled — %s waits, %s signals%s\n",
                  worst_fd, fmt_count(static_cast<double>(worst->waits)).c_str(),
                  fmt_count(static_cast<double>(signal_total(*worst))).c_str(), more);
    }
    montauk_sink_appendf(&g_out, "flag: waits > %" PRIu64 "x signals (min %" PRIu64 " waits) = waits with no plausible signaler\n",
                kPairingWaitSignalRatio, kPairingMinWaits);
    std::vector<std::pair<int32_t, const Agg*>> rows;
    rows.reserve(aggs_.size());
    for (const auto& [fd, a] : aggs_) rows.emplace_back(fd, &a);
    sublimation_order_u64(rows, true, [](const std::pair<int32_t, const Agg*>& p) { return p.second->waits; });
    montauk_sink_appendf(&g_out, "fd     waits      event_set  event_reset sem_release mutex_unlock signals    flag\n");
    for (const auto& [fd, a] : rows) {
      montauk_sink_appendf(&g_out, "%-6d %-10" PRIu64 " %-10" PRIu64 " %-11" PRIu64 " %-11" PRIu64 " %-12" PRIu64 " %-10" PRIu64 " %s\n",
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

  void offenders(std::vector<Offender>& out) override {
    for (const auto& [fd, a] : aggs_) {
      if (!flagged(a)) continue;
      char idb[24];
      std::snprintf(idb, sizeof(idb), "0x%x", static_cast<unsigned>(fd));
      // Waiters with no plausible signaler -- a lost wakeup / dead producer.
      out.push_back({"unsignaled", idb, "", "waits",
                     static_cast<double>(a.waits), 2});
    }
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
                  "ABORT @%.3fs pid=%u tid=%u comm='%s'\n",
                  a->timestamp_ns / 1e9, a->pid, a->tid, redact_comm(a->comm).c_str());
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
                      "    %s addr=0x%" PRIx64 " size=%-8" PRIu64 " tid=%u comm='%s'%s\n",
                      i == 0 ? "VICTIM?" : "       ",
                      in[i].first, in[i].second->size, in[i].second->tid,
                      redact_comm(in[i].second->comm).c_str(),
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
    header();
    if (findings_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no abort events in trace\n");
      return;
    }
    montauk_sink_appendf(&g_out, "VERDICT: %zu abort(s); victim chunk = highest live allocation in the aborting arena\n",
                findings_.size());
    for (const auto& f : findings_) montauk_sink_appendf(&g_out, "%s", f.c_str());
  }

  void prom(std::vector<PromMetric>& out) override {
    out.push_back({"montauk_analysis_aborts_total", "",
                   static_cast<double>(findings_.size())});
  }
};

// REPORT signals: every TRACE_EVT_SIGNAL decomposed. summary only COUNTS
// deliver/exit_abnormal; this names them: who died or took a signal, which
// signal, from whom, in which syscall and when relative to the trace window,
// with the death stack joined against the maps sidecar. Rows honor the
// generic --sig/--comm/--pid/--tid qualifiers, so any slice of the signal
// stream is a command line. A death inside the trailing --window seconds
// (default 2) is tagged as capture-teardown; one before it is tagged
// MID-TRACE, the deaths that happened while the workload was still running.
struct SignalsReport final : Report {
  struct Ev {
    uint64_t ts = 0;
    uint32_t pid = 0, tid = 0, kind = 0;
    int32_t signal_nr = 0, sender_pid = 0, exit_code = 0;
    int32_t syscall_nr = -1, io_fd = -1;
    uint32_t depth = 0;
    uint64_t frames[8] = {};
    char comm[16] = {};
  };
  struct Tally {
    uint64_t exits = 0, delivers = 0;
    uint64_t first_ts = 0, last_ts = 0;
    std::vector<std::string> sigs;
  };
  std::vector<Ev> evs_;
  uint64_t min_ts_ = 0, max_ts_ = 0;

  const char* name() const override { return "signals"; }

  void note_ts(uint64_t ts) {
    if (ts == 0) return;
    if (min_ts_ == 0 || ts < min_ts_) min_ts_ = ts;
    if (ts > max_ts_) max_ts_ = ts;
  }

  // A fault-class signal names a crash; KILL/TERM name an external hand.
  static bool is_fault(int32_t n) {
    return n == 4 || n == 5 || n == 6 || n == 7 || n == 8 || n == 11 || n == 31;
  }

  bool teardown(const Ev& v) const {
    uint64_t window_ns = static_cast<uint64_t>(g_qual_window_s * 1e9);
    return max_ts_ != 0 && v.ts + window_ns >= max_ts_;
  }

  // Mid-trace signal death: an abnormal exit CARRYING a signal, before the
  // teardown window. exit(N) helpers (status byte, signal 0) are not deaths.
  bool midtrace_death(const Ev& v) const {
    return v.kind == SIGEVT_EXIT_ABNL && v.signal_nr != 0 && !teardown(v);
  }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    // Trace-window bounds from the always-on streams, so a death lands at a
    // position relative to the END of the trace (before_end_s), not just its
    // own timestamp.
    switch (type) {
      case TRACE_EVT_NTSYNC:
        if (len >= sizeof(montauk_ntsync_event))
          note_ts(reinterpret_cast<const montauk_ntsync_event*>(data)->timestamp_ns);
        return;
      case TRACE_EVT_IO:
        if (len >= sizeof(montauk_io_event))
          note_ts(reinterpret_cast<const montauk_io_event*>(data)->timestamp_ns);
        return;
      case TRACE_EVT_SCHED:
        if (len >= sizeof(montauk_sched_event))
          note_ts(reinterpret_cast<const montauk_sched_event*>(data)->timestamp_ns);
        return;
      case TRACE_EVT_HEAP:
        if (len >= sizeof(montauk_heap_event))
          note_ts(reinterpret_cast<const montauk_heap_event*>(data)->timestamp_ns);
        return;
      case TRACE_EVT_SIGNAL:
        break;
      default:
        return;
    }
    if (len < sizeof(montauk_signal_event)) return;
    auto* e = reinterpret_cast<const montauk_signal_event*>(data);
    note_ts(e->timestamp_ns);
    if (!qual_match(e->signal_nr, e->pid, e->tid, e->comm)) return;
    Ev v;
    v.ts = e->timestamp_ns;
    v.pid = e->pid;
    v.tid = e->tid;
    v.kind = e->kind;
    v.signal_nr = e->signal_nr;
    v.sender_pid = e->sender_pid;
    v.exit_code = e->exit_code;
    v.syscall_nr = e->syscall_nr;
    v.io_fd = e->io_fd;
    v.depth = e->stack_depth > 8 ? 8 : e->stack_depth;
    for (uint32_t i = 0; i < v.depth; ++i) v.frames[i] = e->stack_user[i];
    std::memcpy(v.comm, e->comm, sizeof(v.comm));
    evs_.push_back(v);
  }

  void emit(const montauk::model::TraceReader&) override {
    header();
    if (evs_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no signal events in trace%s\n",
                  (g_qual_sig >= 0 || !g_qual_comm.empty() || g_qual_pid >= 0 || g_qual_tid >= 0)
                      ? " matching the given qualifiers" : "");
      return;
    }
    sublimation_order_u64(evs_, false, [](const Ev& v) { return v.ts; });

    uint64_t exits = 0, delivers = 0, deaths = 0;
    std::map<uint32_t, char> tids;
    const Ev* first_death = nullptr;
    std::map<std::string, Tally> by_comm;
    for (const auto& v : evs_) {
      if (v.kind == SIGEVT_EXIT_ABNL) ++exits; else ++delivers;
      tids[v.tid] = 1;
      if (midtrace_death(v)) {
        ++deaths;
        if (!first_death) first_death = &v;
      }
      auto& t = by_comm[redact_comm(v.comm)];
      if (v.kind == SIGEVT_EXIT_ABNL) ++t.exits; else ++t.delivers;
      if (t.first_ts == 0) t.first_ts = v.ts;
      t.last_ts = v.ts;
      std::string lab = signal_label(v.signal_nr);
      if (v.kind == SIGEVT_EXIT_ABNL && v.signal_nr == 0)
        lab = "exit";
      if (std::find(t.sigs.begin(), t.sigs.end(), lab) == t.sigs.end())
        t.sigs.push_back(lab);
    }

    if (deaths > 0 && first_death) {
      montauk_sink_appendf(&g_out,
          "VERDICT: %" PRIu64 " MID-TRACE signal death(s) (>%.1fs before trace end) — earliest '%s' tid=%u %s at +%.3fs, %.3fs before end; "
          "%" PRIu64 " abnormal exit(s) + %" PRIu64 " delivery(ies) across %zu thread(s) total\n",
          deaths, g_qual_window_s,
          redact_comm(first_death->comm).c_str(), first_death->tid,
          signal_label(first_death->signal_nr).c_str(),
          (first_death->ts - min_ts_) / 1e9, (max_ts_ - first_death->ts) / 1e9,
          exits, delivers, tids.size());
    } else {
      montauk_sink_appendf(&g_out,
          "VERDICT: no mid-trace signal deaths — %" PRIu64 " abnormal exit(s) + %" PRIu64 " delivery(ies) across %zu thread(s), all signal deaths inside the trailing %.1fs teardown window\n",
          exits, delivers, tids.size(), g_qual_window_s);
    }

    // Per-comm rollup first: which processes were dying and with what.
    std::vector<std::pair<std::string, const Tally*>> rows;
    for (const auto& [c, t] : by_comm) rows.emplace_back(c, &t);
    sublimation_order_u64(rows, true,
        [](const std::pair<std::string, const Tally*>& p) { return p.second->exits + p.second->delivers; });
    montauk_sink_appendf(&g_out, "comm             exits  delivers first_s   last_s    sigs\n");
    for (const auto& [c, t] : rows) {
      std::string sigs;
      for (size_t i = 0; i < t->sigs.size(); ++i) {
        if (i == 4) { sigs += " +"; break; }
        if (i) sigs += " ";
        sigs += t->sigs[i];
      }
      montauk_sink_appendf(&g_out, "%-16.16s %-6" PRIu64 " %-8" PRIu64 " %-9.3f %-9.3f %s\n",
                  c.c_str(), t->exits, t->delivers,
                  (t->first_ts - min_ts_) / 1e9, (t->last_ts - min_ts_) / 1e9, sigs.c_str());
    }

    // Chronological detail, one line per event; site: the death stack joined
    // against the maps sidecar, when it resolves.
    montauk_sink_appendf(&g_out, "t_s        before_end_s kind    pid      tid      comm             signal     sender   status  state\n");
    for (const auto& v : evs_) {
      char status[12] = "-";
      if (v.kind == SIGEVT_EXIT_ABNL)
        std::snprintf(status, sizeof(status), "%d", (v.exit_code >> 8) & 0xff);
      char sender[12] = "-";
      if (v.sender_pid != 0)
        std::snprintf(sender, sizeof(sender), "%d", v.sender_pid);
      char state[48] = "usermode";
      if (v.syscall_nr >= 0) {
        char nm[20];
        const char* io = io_syscall_name(v.syscall_nr);
        if (io[0] == '?')
          std::snprintf(nm, sizeof(nm), "syscall %d", v.syscall_nr);
        else
          std::snprintf(nm, sizeof(nm), "%s", io);
        if (v.io_fd >= 0)
          std::snprintf(state, sizeof(state), "in %s fd=%d", nm, v.io_fd);
        else
          std::snprintf(state, sizeof(state), "in %s", nm);
      }
      std::string sig = signal_label(v.signal_nr);
      if (v.kind == SIGEVT_EXIT_ABNL && v.signal_nr == 0) sig = "exit";
      montauk_sink_appendf(&g_out, "%-10.3f %-12.3f %-7s %-8u %-8u %-16.16s %-10s %-8s %-7s %s%s\n",
                  (v.ts - min_ts_) / 1e9, (max_ts_ - v.ts) / 1e9,
                  v.kind == SIGEVT_EXIT_ABNL ? "EXIT" : "DELIVER",
                  v.pid, v.tid, redact_comm(v.comm).c_str(), sig.c_str(),
                  sender, status,
                  state, midtrace_death(v) ? "  <- MID-TRACE DEATH" : "");
      if (v.depth > 0) {
        std::string site;
        int shown = 0;
        for (uint32_t i = 0; i < v.depth; ++i) {
          std::string r = g_maps.resolve(v.pid, v.frames[i]);
          if (r.empty() || r == "[anon]") continue;
          if (!site.empty()) site += " <- ";
          site += r;
          if (++shown >= 4) break;
        }
        if (!site.empty())
          montauk_sink_appendf(&g_out, "  site: %s\n", site.c_str());
      }
    }
  }

  void prom(std::vector<PromMetric>& out) override {
    uint64_t exits = 0, delivers = 0, deaths = 0;
    for (const auto& v : evs_) {
      if (v.kind == SIGEVT_EXIT_ABNL) ++exits; else ++delivers;
      if (midtrace_death(v)) ++deaths;
    }
    out.push_back({"montauk_analysis_signal_exits_total", "", static_cast<double>(exits)});
    out.push_back({"montauk_analysis_signal_delivers_total", "", static_cast<double>(delivers)});
    out.push_back({"montauk_analysis_midtrace_signal_deaths_total", "", static_cast<double>(deaths)});
  }

  void offenders(std::vector<Offender>& out) override {
    size_t added = 0;
    for (const auto& v : evs_) {
      if (!midtrace_death(v)) continue;
      if (++added > 16) break;
      out.push_back({"mid-trace-death", redact_comm(v.comm), std::to_string(v.tid),
                     "before_end_s", (max_ts_ - v.ts) / 1e9, is_fault(v.signal_nr) ? 2 : 1});
    }
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
    uint8_t  create_op = 0xFF;   // NTS_CREATE_* when the create was traced, else unknown
  };

  // Object class -- names what a parked thread is starved of (an EVENT nobody
  // sets vs a MUTEX nobody releases). Prefer the traced create op; fall back to
  // the last signal op's family, since an object created before montauk attached
  // has no create event but its signaller still names its class.
  static const char* obj_type_name(uint8_t create_op, uint8_t signal_op = 0xFF) {
    switch (create_op) {
      case NTS_CREATE_SEM:   return "SEM";
      case NTS_CREATE_MUTEX: return "MUTEX";
      case NTS_CREATE_EVENT: return "EVENT";
      default: break;
    }
    switch (signal_op) {
      case NTS_SEM_RELEASE:  return "SEM";
      case NTS_MUTEX_UNLOCK: return "MUTEX";
      case NTS_EVENT_SET: case NTS_EVENT_RESET: case NTS_EVENT_PULSE: return "EVENT";
      default:               return "object";
    }
  }
  std::map<uint32_t, TidState> tids_;
  std::map<uint64_t, ObjSig> objs_;
  uint64_t max_ts_ = 0;
  // tid -> the IPs of its LAST infinite-wait-enter stack. A thread parked at
  // trace end never exits the wait, so this names where in the code it blocked.
  std::map<uint32_t, std::vector<uint64_t>> wait_stack_;
  // tid -> raw stack slice + RIP at its LAST infinite wait (uprobe path). The
  // analyzer scans it for executable return addresses to name the caller a
  // frame-pointer-less bpf_get_stack walk cannot reach.
  struct RawStack { uint32_t pid; uint64_t rip; std::vector<uint8_t> bytes; };
  std::map<uint32_t, RawStack> raw_stack_;

  const char* name() const override { return "endstate"; }

  void touch(uint32_t tid, uint32_t pid, uint64_t ts, const char* comm) {
    auto& t = tids_[tid];
    if (ts > t.last_ts) t.last_ts = ts;
    t.pid = pid;
    if (comm && comm[0]) std::memcpy(t.comm, comm, sizeof(t.comm));
    if (ts > max_ts_) max_ts_ = ts;
  }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type == TRACE_EVT_WAITSTACK && len >= sizeof(montauk_waitstack_event)) {
      auto* e = reinterpret_cast<const montauk_waitstack_event*>(data);
      touch(e->tid, e->pid, e->timestamp_ns, e->comm);
      auto& v = wait_stack_[e->tid];
      v.clear();
      uint32_t n = e->stack_depth;
      if (n > TRACE_STACK_MAX_FRAMES) n = TRACE_STACK_MAX_FRAMES;
      for (uint32_t i = 0; i < n; ++i) v.push_back(e->stack_user[i]);
      return;
    }
    if (type == TRACE_EVT_RAWSTACK && len >= sizeof(montauk_rawstack_event)) {
      auto* e = reinterpret_cast<const montauk_rawstack_event*>(data);
      touch(e->tid, e->pid, e->timestamp_ns, e->comm);
      auto& r = raw_stack_[e->tid];
      r.pid = e->pid;
      r.rip = e->rip;
      uint32_t n = e->stack_len;
      if (n > TRACE_RAWSTACK_BYTES) n = TRACE_RAWSTACK_BYTES;
      r.bytes.assign(e->stack, e->stack + n);
      return;
    }
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
      } else if (is_wakeup_op(e->op)) {
        // Only a WAKEUP-worthy op (set/pulse/release/unlock) counts as a signal
        // for the lost-wakeup vs dead-producer discriminator. event_reset wakes
        // no one, so it must not make a quiet producer look busy or land as a
        // bogus "signaled after park".
        auto& o = objs_[e->obj_ptr];
        ++o.signals;
        o.last_signal_ts = e->timestamp_ns;
        o.last_signal_tid = e->tid;
        o.last_signal_op = static_cast<uint8_t>(e->op);
      } else if (e->op == NTS_CREATE_SEM || e->op == NTS_CREATE_MUTEX ||
                 e->op == NTS_CREATE_EVENT) {
        // The create op names the object class; keyed by the same stable
        // kernel obj_ptr the wait/signal sides use.
        objs_[e->obj_ptr].create_op = static_cast<uint8_t>(e->op);
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
    header();
    if (tids_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no per-thread activity in trace\n");
      return;
    }
    // A stall victim is a thread stuck in an ntsync wait that never completed:
    // either still parked at trace end (wait_open, not exited), OR killed while
    // parked -- a thread that held an open wait for a while and then exited
    // without it ever completing. The killed case matters because the common
    // capture is taken AFTER the user force-quits a wedged game, so by trace end
    // the stalled threads have exited; without this they vanish from the report.
    constexpr uint64_t kParkSlackNs = 1'000'000;           // 1ms
    constexpr uint64_t kKilledStallNs = 2'000'000'000ULL;  // 2s open at kill = stall
    std::vector<std::pair<uint32_t, const TidState*>> blocked;
    for (const auto& [tid, t] : tids_) {
      if (!t.wait_open) continue;
      uint64_t open_ns = (max_ts_ > t.wait_since) ? (max_ts_ - t.wait_since) : 0;
      if (!t.exited || open_ns >= kKilledStallNs) blocked.emplace_back(tid, &t);
    }
    sublimation_order_u64(blocked, false, [](const std::pair<uint32_t, const TidState*>& p) { return p.second->wait_since; });
    if (blocked.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no threads parked or killed-while-parked in this trace\n");
      return;
    }
    // Classify each victim. A non-exited thread is GENUINELY parked only if it
    // executed nothing after its wait entry (any later event means it woke and
    // the completion was lost to the per-CPU ntsync_scratch race). An exited
    // thread that was parked long enough is a KILLED-PARKED stall victim.
    auto status_of = [&](const TidState& t) -> const char* {
      if (t.exited) return "KILLED-PARKED";
      return (t.last_ts <= t.wait_since + kParkSlackNs) ? "PARKED" : "woke(lost-compl)";
    };
    size_t genuine = 0;
    for (const auto& [tid, t] : blocked)
      if (std::string(status_of(*t)) != "woke(lost-compl)") ++genuine;
    const auto& w = *blocked.front().second;
    // Characterize the longest-parked thread's primary wait object so the
    // verdict NAMES what it is starved of, not just that it is parked.
    std::string objdesc;
    if (w.wait_count > 0) {
      auto it = objs_.find(w.wait_objs[0]);
      const char* ty = obj_type_name(
          it != objs_.end() ? it->second.create_op : 0xFF,
          it != objs_.end() ? it->second.last_signal_op : 0xFF);
      if (it == objs_.end() || it->second.signals == 0)
        objdesc = std::string("; ") + ty + " NEVER signaled (dead producer / no signaler)";
      else if (it->second.last_signal_ts > w.wait_since)
        objdesc = std::string("; ") + ty + " signaled AFTER park (lost wakeup)";
      else
        objdesc = std::string("; ") + ty + " last wakeup BEFORE the park — producer went quiet";
    }
    montauk_sink_appendf(&g_out, "VERDICT: %zu thread(s) stuck in an ntsync wait (%zu genuine stall victims, "
                "%zu woke/lost-compl); longest tid=%u '%s' %s %.1fs%s\n",
                blocked.size(), genuine, blocked.size() - genuine,
                blocked.front().first, redact_comm(w.comm).c_str(),
                w.exited ? "killed while parked" : "parked",
                (max_ts_ - w.wait_since) / 1e9, objdesc.c_str());
    montauk_sink_appendf(&g_out, "tid      pid      comm             open_s    act_after_ms  status         objs  timeout_ns\n");
    for (const auto& [tid, t] : blocked) {
      double act_after_ms = (t->last_ts > t->wait_since) ? (t->last_ts - t->wait_since) / 1e6 : 0.0;
      montauk_sink_appendf(&g_out, "%-8u %-8u %-16s %-9.1f %-13.1f %-14s %-5u %" PRIu64 "\n",
                  tid, t->pid, redact_comm(t->comm).c_str(), (max_ts_ - t->wait_since) / 1e9,
                  act_after_ms, status_of(*t),
                  t->wait_count, t->timeout_ns);
    }

    // Per-parked-thread wait-object signal history — the missed-wakeup vs
    // dead-producer discriminator. For each object a parked thread is stuck
    // on: did anything ever signal it, and did that signal land AFTER the
    // park (a real lost wakeup) or never come at all (dead producer / no
    // signaler).
    montauk_sink_appendf(&g_out, "\nparked-thread wait objects (signal history):\n");
    montauk_sink_appendf(&g_out, "tid      obj                  fd     type   signals  waits     verdict\n");
    for (const auto& [tid, t] : blocked) {
      uint32_t n = t->wait_count;
      if (n > NTSYNC_MAX_WAIT_FDS) n = NTSYNC_MAX_WAIT_FDS;
      for (uint32_t i = 0; i < n; ++i) {
        uint64_t ptr = t->wait_objs[i];
        auto it = objs_.find(ptr);
        uint64_t sigs = (it != objs_.end()) ? it->second.signals : 0;
        uint64_t wts  = (it != objs_.end()) ? it->second.waits : 0;
        const char* ty = obj_type_name(
            it != objs_.end() ? it->second.create_op : 0xFF,
            it != objs_.end() ? it->second.last_signal_op : 0xFF);
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
        montauk_sink_appendf(&g_out, "%-8u 0x%016" PRIx64 " %-6u %-6s %-8" PRIu64 " %-9" PRIu64 " %s\n",
                    tid, ptr, t->wait_fds[i], ty, sigs, wts, verdict);
      }
      // Wait-site: the top resolved frames of WHERE this thread is parked in the
      // code (its last infinite-wait stack, joined against the maps sidecar).
      // Turns "in an ntsync wait" into e.g. module.so+0x... -- which names who
      // owns the dead-producer signal and whether the wait is safe to break.
      auto wsit = wait_stack_.find(tid);
      if (wsit != wait_stack_.end() && !wsit->second.empty()) {
        std::string site;
        int shown = 0;
        for (uint64_t ip : wsit->second) {
          std::string r = g_maps.resolve(t->pid, ip);
          if (r.empty() || r == "[anon]") continue;
          if (!site.empty()) site += " <- ";
          site += r;
          if (++shown >= 4) break;
        }
        if (!site.empty())
          montauk_sink_appendf(&g_out, "%-8u parked at: %s\n", tid, site.c_str());
      }
      // Wait-site SCAN: bpf_get_stack cannot walk frame-pointer-less code, so the
      // uprobe captured a raw stack slice. Scan it for words that land in
      // EXECUTABLE code -- the live call chain's return addresses -- which names the
      // caller the FP walk above could not reach. Head is RIP (the wait function);
      // the rest are scanned, deduped, in stack order. A scan is not a precise
      // chain (a stale return address can slip in), but it names the module.
      auto rit = raw_stack_.find(tid);
      if (rit != raw_stack_.end() && !rit->second.bytes.empty()) {
        const RawStack& rs = rit->second;
        std::vector<std::string> sites;
        std::string head = g_maps.resolve(rs.pid, rs.rip);
        if (!head.empty() && head != "[anon]") sites.push_back(head);
        const uint8_t* b = rs.bytes.data();
        size_t words = rs.bytes.size() / 8;
        for (size_t i = 0; i < words && sites.size() < 7; ++i) {
          uint64_t word;
          std::memcpy(&word, b + i * 8, sizeof(word));
          std::string s = g_maps.resolve_exec(rs.pid, word);
          if (s.empty()) continue;
          if (std::find(sites.begin(), sites.end(), s) != sites.end()) continue;
          sites.push_back(s);
        }
        if (!sites.empty()) {
          std::string scan;
          for (auto& s : sites) { if (!scan.empty()) scan += " <- "; scan += s; }
          montauk_sink_appendf(&g_out, "%-8u wait-site scan: %s\n", tid, scan.c_str());
        }
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

// REPORT iowait: who was parked in a blocking I/O-wait syscall (poll/ppoll/
// epoll_wait/select/recvmsg) when the trace ENDED. The I/O-bound analog of
// endstate: a thread asleep in poll() on a socket or fd is parked on its data
// source the way an ntsync waiter is parked on a signaler, but in a syscall
// that may never return -- invisible to the ntsync/futex reports. BPF emits a
// pending (result=-999) enter marker and a completion on return; an enter
// with no completion at trace end is parked.
struct IowaitReport final : Report {
  static bool is_iowait_syscall(int32_t nr) {
    switch (nr) {
      case 7: case 271: case 232: case 281:
      case 47: case 45: case 23: case 270:
      case 16: return true;
      default: return false;
    }
  }
  struct Parked {
    bool open = false;
    uint64_t since = 0;
    int32_t nr = 0;
    int32_t fd = -1;
    uint32_t pid = 0;
    char comm[16] = {};
  };
  std::map<uint32_t, Parked> tids_;
  uint64_t max_ts_ = 0;

  const char* name() const override { return "iowait"; }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type != TRACE_EVT_IO || len < sizeof(montauk_io_event)) return;
    auto* e = reinterpret_cast<const montauk_io_event*>(data);
    if (e->timestamp_ns > max_ts_) max_ts_ = e->timestamp_ns;
    if (!is_iowait_syscall(e->syscall_nr)) return;
    auto& p = tids_[e->tid];
    if (e->result == kWaitEntrySentinel) {        // enter: now parked
      p.open = true;
      p.since = e->timestamp_ns;
      p.nr = e->syscall_nr;
      p.fd = e->fd;
      p.pid = e->pid;
      std::memcpy(p.comm, e->comm, sizeof(p.comm));
    } else {                                       // exit: returned
      p.open = false;
    }
  }

  void emit(const montauk::model::TraceReader&) override {
    std::vector<std::pair<uint32_t, const Parked*>> parked;
    for (const auto& [tid, p] : tids_)
      if (p.open) parked.push_back({tid, &p});
    header();
    if (parked.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no threads parked in a blocking I/O-wait syscall at trace end\n");
      return;
    }
    std::sort(parked.begin(), parked.end(),
              [](const auto& a, const auto& b){ return a.second->since < b.second->since; });
    const auto* lp = parked.front().second;
    montauk_sink_appendf(&g_out, "VERDICT: %zu thread(s) parked in a blocking I/O-wait at trace end "
                "(asleep on its data source -- e.g. poll() on a socket or pipe fd); "
                "longest tid=%u '%s' in %s(fd=%d) %.1fs\n",
                parked.size(), parked.front().first, redact_comm(lp->comm).c_str(),
                io_syscall_name(lp->nr), lp->fd, (max_ts_ - lp->since) / 1e9);
    montauk_sink_appendf(&g_out, "tid      pid      comm             syscall      fd     parked_s\n");
    for (const auto& [tid, p] : parked)
      montauk_sink_appendf(&g_out, "%-8u %-8u %-16s %-12s %-6d %.1f\n",
                  tid, p->pid, redact_comm(p->comm).c_str(),
                  io_syscall_name(p->nr), p->fd, (max_ts_ - p->since) / 1e9);
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
    header();
    if (sites_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no heapstack captures in trace (set MONTAUK_HEAP_STACK_SIZE)\n");
      return;
    }
    std::vector<const Site*> rows;
    for (const auto& [h, s] : sites_) { (void)h; rows.push_back(&s); }
    sublimation_order_u64(rows, true, [](const Site* p) { return p->count; });
    montauk_sink_appendf(&g_out, "VERDICT: %zu unique allocation site(s) for size=%" PRIu64 "\n",
                rows.size(), rows.front()->size);
    for (const Site* s : rows) {
      montauk_sink_appendf(&g_out, "site x%-8" PRIu64 " first_comm='%s'\n", s->count, redact_comm(s->comm).c_str());
      for (uint32_t i = 0; i < s->depth; ++i)
        montauk_sink_appendf(&g_out, "  #%-2u 0x%016" PRIx64 "\n", i, s->frames[i]);
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
    header();
    if (hits_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no double-frees in %" PRIu64 " frees\n", total_frees_);
      return;
    }
    size_t cross = 0;
    for (const auto& h : hits_) if (h.first_tid != h.second_tid) ++cross;
    montauk_sink_appendf(&g_out, "VERDICT: %zu double-free(s) in %" PRIu64 " frees — %zu cross-thread (race), %zu same-thread (logic)\n",
                hits_.size(), total_frees_, cross, hits_.size() - cross);
    montauk_sink_appendf(&g_out, "addr               size     freed_by_1            freed_by_2           kind\n");
    for (const auto& h : hits_) {
      montauk_sink_appendf(&g_out, "0x%016" PRIx64 " %-8" PRIu64 " tid=%-7u %-10.10s tid=%-7u %-10.10s %s\n",
                  h.addr, h.size, h.first_tid, h.first_comm, h.second_tid, h.second_comm,
                  h.first_tid == h.second_tid ? "same-thread(logic)" : "cross-thread(RACE)");
    }
  }
};

// Bump tid's last-activity timestamp (and the running trace-wide max) in a
// per-tid map whose value type has a last_ts field. Shared by any single-key
// wait-flavor report (futex, keyedevt) tracking "was the last thing this
// thread did its wait, or something else" -- both reports' own touch()
// forwards here instead of duplicating the bookkeeping.
template <typename TidMap>
void touch_activity(TidMap& tids, uint64_t& max_ts, uint32_t tid, uint64_t ts) {
  auto& t = tids[tid];
  if (ts > t.last_ts) t.last_ts = ts;
  if (ts > max_ts) max_ts = ts;
}

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

  void touch(uint32_t tid, uint64_t ts) { touch_activity(tids_, max_ts_, tid, ts); }

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
    header();
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
      montauk_sink_appendf(&g_out, "VERDICT: no threads blocked on a futex at trace end\n");
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

    montauk_sink_appendf(&g_out, "VERDICT: %zu threads blocked on futexes (%zu idle-park, %zu spin, %zu wait); "
                "worst uaddr=0x%" PRIx64 " stuck %.1fs\n",
                rows.size(), idle, spin, rows.size() - idle - spin, worst_uaddr, worst_stuck);
    montauk_sink_appendf(&g_out, "(op in fd, uaddr in count; addresses are opaque — join externally for lock identity)\n");

    montauk_sink_appendf(&g_out, "\ncontended addresses (>=2 waiters):\n");
    montauk_sink_appendf(&g_out, "uaddr              waiters  wakes      max_stuck_s\n");
    std::vector<std::pair<uint64_t, const Agg*>> au;
    for (const auto& [u, a] : aggs)
      if (a.waiters >= 2) au.emplace_back(u, &a);
    sublimation_order_f64(au, true, [](const std::pair<uint64_t, const Agg*>& p) { return p.second->max_stuck; });
    for (const auto& [u, a] : au)
      montauk_sink_appendf(&g_out, "0x%016" PRIx64 " %-8d %-10" PRIu64 " %-12.1f\n",
                  u, a->waiters, a->wakes, a->max_stuck);

    montauk_sink_appendf(&g_out, "\nblocked threads (idle-park excluded):\n");
    montauk_sink_appendf(&g_out, "uaddr              tid      comm             stuck_s   retries  s/retry  class\n");
    sublimation_order_f64(rows, true, [](const Row& r) { return r.stuck_s; });
    for (const auto& r : rows) {
      if (!std::strcmp(r.cls, "idle-park")) continue;
      montauk_sink_appendf(&g_out, "0x%016" PRIx64 " %-8u %-16.16s %-9.1f %-8u %-8.2f %s\n",
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
    uint64_t last_wait_ts = 0;  // last keyed-wait entry
    uint64_t wait_key = 0;      // key of that wait
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

  void touch(uint32_t tid, uint64_t ts) { touch_activity(tids_, max_ts_, tid, ts); }

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
    header();
    if (keys_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no keyed-event activity "
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
      montauk_sink_appendf(&g_out, "VERDICT: %zu key(s) seen; no thread wedged entering a keyed wait at trace end\n",
                  keys_.size());
      return;
    }
    uint64_t worst_key = 0, worst_stuck = 0;
    for (const auto& [key, ws] : blocked)
      for (const auto& [tid, t] : ws) { (void)tid;
        uint64_t s = max_ts_ - t->last_wait_ts;
        if (s > worst_stuck) { worst_stuck = s; worst_key = key; }
      }
    montauk_sink_appendf(&g_out, "VERDICT: %zu key(s) have a thread wedged entering them; "
                "worst key=0x%" PRIx64 " stuck %.1fs\n",
                blocked.size(), worst_key, worst_stuck / 1e9);
    montauk_sink_appendf(&g_out, "(no release after the wait => the holder never left the keyed lock)\n");
    montauk_sink_appendf(&g_out, "key                waiters  total_waits  releases  rel_after_wait  note\n");
    for (const auto& [key, ws] : blocked) {
      const auto& k = keys_[key];
      uint64_t latest_wait = 0;
      for (const auto& [tid, t] : ws) { (void)tid; if (t->last_wait_ts > latest_wait) latest_wait = t->last_wait_ts; }
      bool rel_after = k.last_release_ts > latest_wait;
      montauk_sink_appendf(&g_out, "0x%016" PRIx64 " %-8zu %-12" PRIu64 " %-9" PRIu64 " %-15s %s\n",
                  key, ws.size(), k.waits, k.releases, rel_after ? "yes" : "none",
                  rel_after ? "released after wait — waiter should wake"
                            : "NO release after wait — holder wedged");
    }
    montauk_sink_appendf(&g_out, "\nwedged threads (last activity = keyed wait):\n");
    montauk_sink_appendf(&g_out, "key                tid      comm             stuck_s\n");
    std::vector<std::pair<uint32_t, const TidK*>> rows;
    for (const auto& [key, ws] : blocked) for (const auto& [tid, t] : ws) rows.emplace_back(tid, t);
    sublimation_order_u64(rows, true, [mt = max_ts_](const std::pair<uint32_t, const TidK*>& p) {
      return mt - p.second->last_wait_ts;
    });
    for (const auto& [tid, t] : rows)
      montauk_sink_appendf(&g_out, "0x%016" PRIx64 " %-8u %-16.16s %.1f\n",
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
// cross-domain (sub_idx). The report that resolves an IPC p99 sitting on the kernel
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
  std::vector<uint64_t> cross_lat_;  // cross-domain subset (ns)
  sub_profile_t prof_{};             // flow-model profile of lat_ in arrival order
  struct Region { size_t start, end; sub_disorder_t cls; };
  std::vector<Region> regions_;      // where structure sits in the timeline (locator)
  double structured_frac_ = 0.0;     // fraction of windows carrying structure

  // Cold-wake correlation: a wake landing on a core that had been idle a while,
  // tagged with that core's frequency at the wake instant (freq_mhz from the
  // cpu_frequency timeline). Separates a slow wake caused by the core ramping
  // from minimum frequency (governor / architecture) from one caused by dispatch
  // latency (the scheduler wake path) -- the dispatch-vs-ramp discriminator.
  static constexpr uint64_t kColdIdleNs = 20000000ULL;  // 20ms idle = core went cold
  struct ColdWake { uint64_t lat_ns; uint32_t freq_mhz; uint64_t idle_dur_ns; };
  std::unordered_map<uint32_t, uint64_t> cpu_idle_enter_;  // cpu -> ts entered idle
  std::vector<ColdWake> cold_;                             // wakes from a cold core

  const char* name() const override { return "sched"; }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type != TRACE_EVT_SCHED || len < sizeof(montauk_sched_event)) return;
    const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
    // Per-CPU idle boundaries. The CPU_IDLE leave is emitted just AFTER the
    // WAKE2RUN of the task coming on (same sched_switch), so at WAKE2RUN the
    // enter stamp is still live and the idle duration is exact.
    if (s->op == SCHED_OP_CPU_IDLE) {
      if (s->sub_idx == 1) cpu_idle_enter_[s->cpu] = s->timestamp_ns;
      else cpu_idle_enter_.erase(s->cpu);
      return;
    }
    if (s->op != SCHED_OP_WAKE2RUN) return;
    lat_.push_back(s->runtime_ns);
    if (s->sub_idx) cross_lat_.push_back(s->runtime_ns);
    auto it = cpu_idle_enter_.find(s->cpu);
    if (it != cpu_idle_enter_.end() && s->timestamp_ns > it->second &&
        (s->timestamp_ns - it->second) >= kColdIdleNs)
      cold_.push_back({s->runtime_ns, s->freq_mhz, s->timestamp_ns - it->second});
  }

  // v must already be sorted ascending.

  void emit(const montauk::model::TraceReader&) override {
    header();
    if (lat_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no WAKE2RUN events in trace "
                  "(wake-to-run tracepoint not streamed?)\n\n");
      return;
    }
    // Classify the latency sequence in ARRIVAL order first -- the flow-model
    // reads temporal structure the quantiles can't: a mid-trace regime change
    // (PHASED), quantization onto a few tick values (FEW_UNIQUE), or monotonic
    // drift (NEARLY_SORTED). Must run before the in-place sort destroys the
    // timeline. classify is pure (reads, never writes), so lat_ is untouched.
    prof_ = sublimation_classify_u64(lat_.data(), lat_.size());

    // Locate WHERE structure sits in the arrival-order timeline (the third
    // sublimation primitive: search). classify above says WHAT the whole
    // sequence is; the locator slides it across the stream and names the
    // stretches that carry exploitable structure. Also runs before the sort.
    if (lat_.size() >= 1024) {
      const size_t win = std::min<size_t>(512, lat_.size() / 8);
      std::vector<sub_match_t> wins(lat_.size() / win + 2);
      size_t nw = sublimation_profile_u64(lat_.data(), lat_.size(), win, win,
                                          wins.data(), wins.size());
      size_t structured = 0;
      for (size_t i = 0; i < nw; ++i)
        if (wins[i].disorder != SUB_RANDOM) ++structured;
      structured_frac_ = nw ? static_cast<double>(structured) / static_cast<double>(nw) : 0.0;
      // Coalesce adjacent same-class non-random windows into regions.
      for (size_t i = 0; i < nw;) {
        if (wins[i].disorder == SUB_RANDOM) { ++i; continue; }
        sub_disorder_t cls = wins[i].disorder;
        size_t start = wins[i].start, j = i;
        while (j < nw && wins[j].disorder == cls) ++j;
        regions_.push_back({start, wins[j - 1].start + wins[j - 1].len, cls});
        i = j;
      }
    }

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

    montauk_sink_appendf(&g_out, "VERDICT: %s wake2run; p50 %.0fus p99 %.0fus p999 %.0fus "
                "worst %.0fus; %.1f%% fast(<100us) / %.1f%% mid / "
                "%.1f%% tick-floor(>=900us); %.1f%% cross-domain\n",
                fmt_count(dn).c_str(), q_us(lat_, 0.50), q_us(lat_, 0.99),
                q_us(lat_, 0.999), us(lat_.back()), fastpct, midpct, tickpct,
                crosspct);
    if (!cross_lat_.empty())
      montauk_sink_appendf(&g_out, "cross-domain wake2run: %s events; p50 %.0fus p99 %.0fus "
                  "worst %.0fus (high here = scatter feeds the slow mode)\n",
                  fmt_count(static_cast<double>(cross_lat_.size())).c_str(),
                  q_us(cross_lat_, 0.50), q_us(cross_lat_, 0.99),
                  us(cross_lat_.back()));
    // Temporal structure from the flow-model classify (arrival order).
    montauk_sink_appendf(&g_out, "STRUCTURE: latency-over-trace %s", disorder_name(prof_.disorder));
    if (prof_.phase_boundary)
      montauk_sink_appendf(&g_out, " (regime change at ~%.0f%% of trace)",
                  100.0 * static_cast<double>(prof_.phase_boundary) / dn);
    montauk_sink_appendf(&g_out, "; ~%zu distinct values", prof_.distinct_estimate);
    if (prof_.inversion_ratio > 0.0f)
      montauk_sink_appendf(&g_out, "; inversion ratio %.2f",
                  static_cast<double>(prof_.inversion_ratio));
    montauk_sink_appendf(&g_out, "\n");
    // Where that structure sits in the timeline (the locator).
    if (!regions_.empty()) {
      montauk_sink_appendf(&g_out, "LOCATED: %zu structured region(s) —", regions_.size());
      size_t shown = 0;
      for (const auto& r : regions_) {
        if (shown++ >= 5) { montauk_sink_appendf(&g_out, " +%zu more", regions_.size() - 5); break; }
        montauk_sink_appendf(&g_out, " %s[%.0f%%..%.0f%%]", disorder_name(r.cls),
                    100.0 * static_cast<double>(r.start) / dn,
                    100.0 * static_cast<double>(r.end) / dn);
      }
      montauk_sink_appendf(&g_out, "\n");
    }
    // COLD-WAKE: wakes onto a core idle >=20ms, correlated with the core's
    // frequency at the wake. Slow cold-wakes at the minimum frequency seen are
    // the ramp from deep idle (governor / architecture); at nominal frequency
    // they are dispatch (the scheduler wake path). The dispatch-vs-ramp answer.
    if (!cold_.empty()) {
      std::vector<ColdWake> c = cold_;
      std::sort(c.begin(), c.end(),
                [](const ColdWake& a, const ColdWake& b) { return a.lat_ns < b.lat_ns; });
      auto cq = [&](double f) {
        size_t i = std::min(c.size() - 1, static_cast<size_t>(c.size() * f));
        return us(c[i].lat_ns);
      };
      uint32_t fmin = 0;
      bool have_freq = false;
      for (const auto& w : c)
        if (w.freq_mhz) { have_freq = true; if (!fmin || w.freq_mhz < fmin) fmin = w.freq_mhz; }
      uint32_t slowq = 0;  // median freq of the slowest quartile of cold wakes
      if (have_freq && c.size() >= 4) {
        std::vector<uint32_t> sf;
        for (size_t i = c.size() - c.size() / 4; i < c.size(); ++i)
          if (c[i].freq_mhz) sf.push_back(c[i].freq_mhz);
        if (!sf.empty()) { std::sort(sf.begin(), sf.end()); slowq = sf[sf.size() / 2]; }
      }
      montauk_sink_appendf(&g_out, "COLD-WAKE (idle >=20ms): %s wakes; wake2run p50 %.0fus "
                  "p99 %.0fus worst %.0fus\n",
                  fmt_count(static_cast<double>(c.size())).c_str(),
                  cq(0.50), cq(0.99), us(c.back().lat_ns));
      if (have_freq)
        montauk_sink_appendf(&g_out, "  freq-at-wake: min %u MHz seen; slowest-quartile median "
                    "%u MHz -> %s\n", fmin, slowq,
                    (slowq && fmin && slowq <= fmin + fmin / 4)
                        ? "RAMP-BOUND (slow cold-wakes at min freq -- governor/arch, not dispatch)"
                        : (slowq ? "DISPATCH-BOUND (slow cold-wakes at nominal freq -- scheduler wake path)"
                                 : "inconclusive (freq spread too sparse)"));
      else
        montauk_sink_appendf(&g_out, "  freq-at-wake: unavailable (no cpu_frequency transitions in trace)\n");
    }
    montauk_sink_appendf(&g_out, "\n");
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
    // Same bands as the VERDICT line: fast <100us, tick-floor >=900us, mid
    // between. Emitting all three (not just the floor) lets the population pass
    // score the fast-mode share -- the clearest under-load discriminator.
    size_t fast = 0, tick = 0;
    for (uint64_t v : lat_) {
      if (v < 100000) ++fast;
      else if (v >= 900000) ++tick;
    }
    const double fastpct = 100.0 * static_cast<double>(fast) / dn;
    const double tickpct = 100.0 * static_cast<double>(tick) / dn;
    out.push_back({"montauk_analysis_wake2run_fast_pct", "", fastpct});
    out.push_back({"montauk_analysis_wake2run_mid_pct", "",
                   100.0 - fastpct - tickpct});
    out.push_back({"montauk_analysis_wake2run_tickfloor_pct", "", tickpct});
    out.push_back({"montauk_analysis_wake2run_crossdomain_pct", "",
                   100.0 * static_cast<double>(cross_lat_.size()) / dn});
    // Flow-model distinct-value estimate: a low count on a large trace means
    // latency is quantized onto a few values (a fixed timer/quantum).
    out.push_back({"montauk_analysis_wake2run_distinct", "",
                   static_cast<double>(prof_.distinct_estimate)});
    // Locator: fraction of the timeline carrying exploitable structure.
    out.push_back({"montauk_analysis_wake2run_structured_pct", "",
                   100.0 * structured_frac_});
    // COLD-WAKE metrics: count, wake2run quantiles, and the freq discriminator
    // (min freq seen, median freq of the slowest quartile). The bench reads these
    // to score ramp-bound vs dispatch-bound without re-deriving.
    if (!cold_.empty()) {
      std::vector<ColdWake> c = cold_;
      std::sort(c.begin(), c.end(),
                [](const ColdWake& a, const ColdWake& b) { return a.lat_ns < b.lat_ns; });
      auto cq = [&](double f) {
        size_t i = std::min(c.size() - 1, static_cast<size_t>(c.size() * f));
        return us(c[i].lat_ns);
      };
      out.push_back({"montauk_analysis_coldwake_count", "",
                     static_cast<double>(c.size())});
      out.push_back({"montauk_analysis_coldwake_wake2run_us", "quantile=\"0.5\"", cq(0.50)});
      out.push_back({"montauk_analysis_coldwake_wake2run_us", "quantile=\"0.99\"", cq(0.99)});
      out.push_back({"montauk_analysis_coldwake_wake2run_us", "quantile=\"worst\"",
                     us(c.back().lat_ns)});
      uint32_t fmin = 0;
      for (const auto& w : c)
        if (w.freq_mhz && (!fmin || w.freq_mhz < fmin)) fmin = w.freq_mhz;
      out.push_back({"montauk_analysis_coldwake_freq_min_mhz", "",
                     static_cast<double>(fmin)});
      uint32_t slowq = 0;
      if (c.size() >= 4) {
        std::vector<uint32_t> sf;
        for (size_t i = c.size() - c.size() / 4; i < c.size(); ++i)
          if (c[i].freq_mhz) sf.push_back(c[i].freq_mhz);
        if (!sf.empty()) { std::sort(sf.begin(), sf.end()); slowq = sf[sf.size() / 2]; }
      }
      out.push_back({"montauk_analysis_coldwake_freq_slowq_mhz", "",
                     static_cast<double>(slowq)});
    }
  }
};

// REPORT work-conservation: per-CPU idle strands and how each one ENDED.
// A strand = a long gap between dispatches on one CPU (the CPU sat idle while
// runnable work may have existed elsewhere). The strand-close attribution is
// the payload: the gap-ending dispatch is a PULL (work-conservation) if that
// task last ran on a DIFFERENT CPU (it migrated in), or a LOCAL-REWAKE if it
// last ran on THIS CPU (the CPU sat until its own task came back). A high
// local-rewake share means idle CPUs are NOT pulling remote runnable work --
// the work-conservation gap. Pure scheduler analysis over PICK events; reads
// only generic cpu/pid/timestamp from the trace, scheduler-agnostic.
struct WorkConservationReport final : Report {
  static constexpr uint64_t kStrandNs = 50000000ULL;  // 50ms: a strand, not jitter
  std::unordered_map<uint32_t, uint64_t> last_pick_ns_;  // cpu -> last dispatch ts
  std::unordered_map<int, uint32_t> last_cpu_of_;        // pid -> last run cpu
  std::vector<uint64_t> strand_ns_;                      // strand durations (ns)
  uint64_t pulled_ = 0;   // strand ended by a migrated-in task (work-conserved)
  uint64_t local_ = 0;    // strand ended by a task that last ran on this CPU

  const char* name() const override { return "work-conservation"; }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type != TRACE_EVT_SCHED || len < sizeof(montauk_sched_event)) return;
    const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
    if (s->op != SCHED_OP_PICK) return;
    uint32_t cpu = s->cpu;
    int pid = s->pid;
    uint64_t ts = s->timestamp_ns;

    auto it = last_pick_ns_.find(cpu);
    if (it != last_pick_ns_.end() && ts > it->second &&
        (ts - it->second) >= kStrandNs) {
      strand_ns_.push_back(ts - it->second);
      auto pit = last_cpu_of_.find(pid);
      if (pit != last_cpu_of_.end() && pit->second != cpu)
        ++pulled_;
      else
        ++local_;
    }
    last_pick_ns_[cpu] = ts;
    last_cpu_of_[pid] = cpu;
  }


  void emit(const montauk::model::TraceReader&) override {
    header();
    if (strand_ns_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no idle strands >= 50ms "
                  "(work-conserving, or PICK events not streamed)\n\n");
      return;
    }
    sublimation_u64(strand_ns_.data(), strand_ns_.size());
    uint64_t n = pulled_ + local_;
    double pull_pct  = n ? 100.0 * static_cast<double>(pulled_) / static_cast<double>(n) : 0.0;
    double local_pct = n ? 100.0 * static_cast<double>(local_) / static_cast<double>(n) : 0.0;
    montauk_sink_appendf(&g_out, "VERDICT: %s idle strands (>=50ms); p50 %.1fms p99 %.1fms "
                "worst %.1fms; closed by PULL %.0f%% / LOCAL-REWAKE %.0f%%\n",
                fmt_count(static_cast<double>(strand_ns_.size())).c_str(),
                q_ms(strand_ns_, 0.50), q_ms(strand_ns_, 0.99),
                ms(strand_ns_.back()), pull_pct, local_pct);
    montauk_sink_appendf(&g_out, "  (high LOCAL-REWAKE %% = idle CPUs sit on remote runnable "
                "work instead of pulling it -- the work-conservation gap)\n\n");
  }

  void prom(std::vector<PromMetric>& out) override {
    if (strand_ns_.empty()) return;  // already sorted in emit()
    auto push = [&](const char* ql, double v) {
      out.push_back({"montauk_analysis_idle_strand_ms",
                     std::string("quantile=\"") + ql + "\"", v});
    };
    push("0.5", q_ms(strand_ns_, 0.50));
    push("0.99", q_ms(strand_ns_, 0.99));
    push("worst", ms(strand_ns_.back()));
    uint64_t n = pulled_ + local_;
    out.push_back({"montauk_analysis_strand_pull_pct", "",
                   n ? 100.0 * static_cast<double>(pulled_) / static_cast<double>(n) : 0.0});
    out.push_back({"montauk_analysis_strand_count", "",
                   static_cast<double>(strand_ns_.size())});
  }

  void offenders(std::vector<Offender>& out) override {
    if (strand_ns_.empty()) return;
    uint64_t n = pulled_ + local_;
    double local_pct = n ? 100.0 * static_cast<double>(local_) / n : 0.0;
    // Idle strands ended by a task that last ran on THIS cpu = idle cores not
    // pulling remote runnable work. Aggregate (not per-CPU); the hot-cpu
    // offender carries the CPU-specific localization.
    int sev = (strand_ns_.size() >= 10 && local_pct > 50.0) ? 2
              : (strand_ns_.size() >= 3 ? 1 : 0);
    out.push_back({"idle-strand", "-", "", "strand_count",
                   static_cast<double>(strand_ns_.size()), sev});
  }
};

// REPORT placement-race: of the tick-floored wakeups (wake-to-run >= 1 tick),
// how many had an IDLE CPU available at the wake instant? That is the fork the
// sched report's tick-floor% cannot resolve on its own:
//   - idle CPU was available -> placement LOST THE RACE. The wakee queued on a
//     busy CPU while another sat idle; the scheduler's wakeup placement saw a
//     stale (all-busy) occupancy snapshot. Fix is winning the race (kick-on-
//     enqueue / pull-side), not the placement policy (already idle-first).
//   - no CPU idle -> GENUINELY SATURATED. Every CPU was busy at the wake; the
//     wait is unavoidable queueing and the fix is on the busy CPU (pick order /
//     wakeup preempt), not placement.
// Built from SCHED_OP_CPU_IDLE boundaries (per-CPU idle enter/exit, emitted
// unconditionally so swapper is visible) -> an exact per-CPU occupancy timeline,
// queried at each floored wake's became-runnable instant. Requires a trace
// captured by a montauk that streams CPU_IDLE; older traces report it absent.
struct PlacementRaceReport final : Report {
  static constexpr uint64_t kTickFloorNs = 900000ULL;  // >=900us ~ one tick: floored
  // per-CPU idle boundaries: ts (ns) and flag (1=entered idle, 0=left idle)
  std::unordered_map<uint32_t, std::vector<std::pair<uint64_t, uint8_t>>> idle_evt_;
  std::vector<std::pair<uint64_t, uint32_t>> floored_;  // (wake_instant_ns, run_cpu)
  uint64_t w2r_total_ = 0;
  uint32_t max_cpu_ = 0;

  const char* name() const override { return "placement-race"; }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type != TRACE_EVT_SCHED || len < sizeof(montauk_sched_event)) return;
    const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
    if (s->cpu > max_cpu_) max_cpu_ = s->cpu;
    if (s->op == SCHED_OP_CPU_IDLE) {
      idle_evt_[s->cpu].push_back({s->timestamp_ns, (uint8_t)(s->sub_idx ? 1 : 0)});
      return;
    }
    if (s->op != SCHED_OP_WAKE2RUN) return;
    ++w2r_total_;
    uint64_t wait = s->runtime_ns;
    if (wait < kTickFloorNs) return;
    uint64_t run_ts = s->timestamp_ns;
    uint64_t wake_ts = (run_ts > wait) ? (run_ts - wait) : 0;
    floored_.push_back({wake_ts, s->cpu});
  }

  // Was `cpu` idle at time t? State = flag of the last boundary <= t.
  // No boundary <= t -> treat as busy (conservative: don't over-count idle).
  static bool idle_at(const std::vector<std::pair<uint64_t, uint8_t>>& ev, uint64_t t) {
    if (ev.empty() || t < ev.front().first) return false;
    size_t lo = 0, hi = ev.size();  // first index with ts > t
    while (lo < hi) {
      size_t mid = lo + (hi - lo) / 2;
      if (ev[mid].first <= t) lo = mid + 1; else hi = mid;
    }
    return lo > 0 && ev[lo - 1].second == 1;
  }

  void emit(const montauk::model::TraceReader&) override {
    header();
    if (idle_evt_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no CPU_IDLE events -- trace captured by a montauk "
                  "without per-CPU idle streaming; re-capture to resolve\n\n");
      return;
    }
    if (floored_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no tick-floored wakeups (>=900us) -- nothing to "
                  "attribute\n\n");
      return;
    }
    for (auto& kv : idle_evt_)
      sublimation_order_u64(kv.second, false,
                            [](const std::pair<uint64_t, uint8_t>& p) { return p.first; });

    uint64_t miss = 0, saturated = 0, idle_cpu_sum = 0;
    for (auto& fw : floored_) {
      uint64_t wake_ts = fw.first;
      uint32_t run_cpu = fw.second;
      uint32_t idle_n = 0;
      for (uint32_t c = 0; c <= max_cpu_; ++c) {
        if (c == run_cpu) continue;  // count BETTER homes than where it waited
        auto it = idle_evt_.find(c);
        if (it != idle_evt_.end() && idle_at(it->second, wake_ts)) ++idle_n;
      }
      if (idle_n) { ++miss; idle_cpu_sum += idle_n; }
      else ++saturated;
    }
    uint64_t n = miss + saturated;
    double miss_pct = n ? 100.0 * (double)miss / (double)n : 0.0;
    double sat_pct  = n ? 100.0 * (double)saturated / (double)n : 0.0;
    double avg_idle = miss ? (double)idle_cpu_sum / (double)miss : 0.0;
    montauk_sink_appendf(&g_out, "VERDICT: %s tick-floored wakes (>=900us); PLACEMENT-MISS %.0f%% "
                "(idle CPU was free) / SATURATED %.0f%% (all busy); "
                "avg %.1f idle CPUs free at a miss\n",
                fmt_count((double)n).c_str(), miss_pct, sat_pct, avg_idle);
    montauk_sink_appendf(&g_out, "  (high PLACEMENT-MISS %% = wakees queued behind a busy CPU "
                "while idle CPUs sat free -- the wakeup-placement race; "
                "high SATURATED %% = unavoidable queueing, fix the busy CPU)\n");
    montauk_sink_appendf(&g_out, "  REROUTABLE %.1f%% of the floor: that fraction had an idle CPU "
                "and an idle-pull/placement fix could move it; the remaining "
                "%.1f%% is genuine saturation -- only a busy-CPU fix (pick "
                "order / wakeup-preempt / shorter slice) cuts it\n\n",
                miss_pct, sat_pct);
    miss_pct_ = miss_pct; sat_pct_ = sat_pct; avg_idle_ = avg_idle; floored_n_ = n;
  }

  double miss_pct_ = 0, sat_pct_ = 0, avg_idle_ = 0;
  uint64_t floored_n_ = 0;

  void prom(std::vector<PromMetric>& out) override {
    if (!floored_n_) return;
    out.push_back({"montauk_analysis_floored_wakes", "", (double)floored_n_});
    out.push_back({"montauk_analysis_placement_miss_pct", "", miss_pct_});
    out.push_back({"montauk_analysis_reroutable_pct", "", miss_pct_});
    out.push_back({"montauk_analysis_saturated_pct", "", sat_pct_});
    out.push_back({"montauk_analysis_avg_idle_at_miss", "", avg_idle_});
  }
};

// REPORT dispatch-stall: placement-race proved the floored wakes are SATURATED
// (no idle CPU to place onto), so the wait is on the run-CPU itself. This splits
// WHY each floored wakee waited, by counting how many times its run-CPU picked
// OTHER tasks during the wait window [became-runnable, ran):
//   - 0 intervening picks -> PREEMPT-STARVED: one task held the CPU the whole
//     wait; the wakee only ran when the holder yielded. Fix = wakeup preemption
//     (let an urgent wakee evict the running task).
//   - >=1 intervening picks -> ORDER-STARVED: the CPU cycled through OTHER
//     runnable tasks while this wakee sat queued -- the pick kept passing it
//     over. Fix = oldest-first / sojourn-at-dispatch (the journal), not preempt.
// Pure replay of the PICK + WAKE2RUN streams already in the trace -- no capture
// change, no re-run. The avg intervening-pick count sizes how deep the tail's
// pass-over goes (p99 52ms / 3ms quantum ~ 17 pass-overs would read ORDER-heavy).
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
  uint64_t overlap(uint32_t cpu, uint64_t a, uint64_t b) const {
    auto it = iv_.find(cpu);
    if (it == iv_.end() || b <= a) return 0;
    uint64_t acc = 0;
    for (const auto& iv : it->second) {
      uint64_t lo = iv.first > a ? iv.first : a;
      uint64_t hi = iv.second < b ? iv.second : b;
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

  void learn(uint32_t tid, const char* comm) {
    if (!comm || !comm[0]) return;
    if (name_.find(tid) == name_.end()) name_.emplace(tid, redact_comm(comm));
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
      // fork/exec/rename + the deduped THREAD_NAME binding carry the thread's tid
      // (child_pid on fork) + comm -- the system-wide name source for a CPU-bound
      // worker that emits no syscall and predates the trace.
      const auto* e = reinterpret_cast<const montauk_ring_event*>(data);
      learn(e->pid, e->comm);
      if (e->child_pid) learn(e->child_pid, e->comm);
    }
  }

  void finalize() {
    if (sorted_) return;
    sorted_ = true;
    for (auto& kv : own_) std::sort(kv.second.begin(), kv.second.end());
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

struct DispatchStallReport final : Report {
  static constexpr uint64_t kTickFloorNs = 900000ULL;
  // pick on a CPU: timestamp, picked pid, LANE (sub_idx: 0=primary, >0=steal), and
  // the dispatch score. The class occupies the high bits; within a class the
  // oldest waiter sorts highest, so a higher class outranks age. cls = score>>48.
  struct Pk { uint64_t ts; int pid; uint32_t lane; uint64_t score; };
  std::unordered_map<uint32_t, std::vector<Pk>> picks_;  // cpu -> picks
  static uint64_t cls_of(uint64_t score) { return score >> 48; }
  // floored wake: (wake_ts, run_ts, run_cpu, wakee_pid)
  struct FW { uint64_t wake_ts, run_ts; uint32_t cpu; int pid; };
  std::vector<FW> floored_;
  // per floored wake: (wake_ts, distinct pass-over tasks, pass-over picks) for the
  // CONCENTRATION TRAJECTORY -- concentration segmented by wall-clock, to see
  // whether a boot commits to its pick pattern early or drifts into it.
  struct CTL { uint64_t ts; uint32_t distinct; uint32_t inter; };
  std::vector<CTL> conc_tl_;
  // Order-starved offenders: tid -> total pass-over picks it took while a wakee
  // waited. Names WHO the concentration ratio was counting (the re-picked few).
  std::unordered_map<uint32_t, uint64_t> offender_;
  // Per-CPU idle intervals -- see CpuIdleIntervals. Separates a HELD CPU (busy
  // hog, real preempt gap) from a DARK CPU (idle, no tick -- the strand bug)
  // inside PREEMPT-STARVED.
  CpuIdleIntervals idle_;
  CpuHolderLedger holder_;
  std::unordered_map<uint32_t, uint64_t> held_by_;  // tid -> ns held across HELD floored wakes

  const char* name() const override { return "dispatch-stall"; }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    holder_.fold(type, data, len);
    if (type != TRACE_EVT_SCHED || len < sizeof(montauk_sched_event)) return;
    const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
    if (s->op == SCHED_OP_PICK) {
      picks_[s->cpu].push_back({s->timestamp_ns, s->pid, s->sub_idx, s->score});
      return;
    }
    if (s->op == SCHED_OP_CPU_IDLE) {
      idle_.fold(s->cpu, s->sub_idx, s->timestamp_ns);
      return;
    }
    if (s->op != SCHED_OP_WAKE2RUN) return;
    uint64_t wait = s->runtime_ns;
    if (wait < kTickFloorNs) return;
    uint64_t run_ts = s->timestamp_ns;
    floored_.push_back({(run_ts > wait) ? (run_ts - wait) : 0, run_ts, s->cpu, s->pid});
  }

  double preempt_pct_ = 0, order_pct_ = 0, avg_inter_ = 0;
  double po_mirror_pct_ = 0, served_mirror_pct_ = 0;
  double po_higher_pct_ = 0, po_same_pct_ = 0, po_lower_pct_ = 0;
  double same_newer_pct_ = 0, avg_distinct_ = 0;
  double dark_pct_ = 0, held_pct_ = 0;  // of PREEMPT-STARVED: CPU idle vs busy during the wait
  double passover_p99_ = 0;             // p99 pass-overs per floored wake (queue depth)
  double ceiling_remains_pct_ = 0;      // % of p99 pass-overs left after removing inversions (legit-backlog = lag prize)
  uint64_t dark_ = 0, n_dark_idle_ = 0; bool have_idle_ = false;
  uint64_t worst_dark_ns_ = 0;
  uint64_t n_ = 0;

  void emit(const montauk::model::TraceReader&) override {
    header();
    if (floored_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no tick-floored wakes -- nothing to attribute\n\n");
      return;
    }
    for (auto& kv : picks_)
      sublimation_order_u64(kv.second, false, [](const Pk& e) { return e.ts; });
    idle_.finalize();
    have_idle_ = !idle_.empty();
    holder_.finalize();

    uint64_t preempt = 0, order = 0, inter_sum = 0;
    uint64_t held = 0;  // PREEMPT-STARVED with the run-CPU busy through the wait
    uint64_t po_total = 0, po_mirror = 0;        // pass-over picks, of which mirror-lane
    uint64_t served_total = 0, served_mirror = 0; // floored wakees served by which lane
    // pass-over class vs the wakee's own (served) class: HIGHER beats it on the
    // dominant class axis (frozen, no aging); SAME = within-class FIFO failure.
    uint64_t cls_total = 0, cls_higher = 0, cls_same = 0, cls_lower = 0;
    // within SAME class: full score encodes age (higher score = older). A pass-
    // over with a LOWER score than the wakee is NEWER -> served ahead of an older
    // task = real FIFO violation; HIGHER score = older = legitimate FIFO drain.
    uint64_t same_newer = 0, same_older = 0;
    // CONCENTRATION (#3): distinct pass-over pids vs total pass-over picks. Few
    // distinct but many picks -> the same tasks re-picked (hogs cycling/running)
    // -> a fair-share/lag term is the fix. Distinct ~= picks -> a deep distinct
    // backlog -> a deadline is the fix.
    uint64_t distinct_sum = 0;
    std::vector<uint64_t> inter_v;
    // CEILING: per wake, LEGITIMATE pass-overs (HIGHER class, or SAME-class older)
    // -- the ones only eligibility/lag could remove. Illegitimate ones (LOWER
    // class, or SAME-class newer) are what mirror coherence removes. p99 of legit
    // vs p99 of total estimates how far a coherence fix alone can pull the tail.
    std::vector<uint64_t> legit_v;
    inter_v.reserve(floored_.size());
    legit_v.reserve(floored_.size());
    for (auto& fw : floored_) {
      auto it = picks_.find(fw.cpu);
      uint64_t inter = 0, legit = 0;
      std::unordered_set<int> po_pids;
      if (it != picks_.end()) {
        const auto& pv = it->second;
        // the pick that finally served this wakee + its class/score (search first)
        bool have_served = false;
        uint64_t served_cls = 0, served_score = 0;
        for (auto p = std::lower_bound(pv.begin(), pv.end(), fw.run_ts,
                 [](const Pk& e, uint64_t v) { return e.ts < v; });
             p != pv.end() && p->ts <= fw.run_ts + kTickFloorNs; ++p) {
          if (p->pid == fw.pid) {
            ++served_total; if (p->lane == 0) ++served_mirror;
            served_cls = cls_of(p->score); served_score = p->score; have_served = true; break;
          }
        }
        auto lo = std::lower_bound(pv.begin(), pv.end(), fw.wake_ts,
            [](const Pk& e, uint64_t v) { return e.ts < v; });
        // pass-over picks of OTHER pids during [wake_ts, run_ts): count, lane, class
        for (auto p = lo; p != pv.end() && p->ts < fw.run_ts; ++p) {
          if (p->pid == fw.pid) continue;
          ++inter; ++po_total; if (p->lane == 0) ++po_mirror;
          po_pids.insert(p->pid);
          if (have_served) {
            uint64_t c = cls_of(p->score);
            ++cls_total;
            if (c > served_cls) { ++cls_higher; ++legit; }       // higher class: legit
            else if (c < served_cls) ++cls_lower;                // lower class: inversion
            else {
              ++cls_same;
              if (p->score < served_score) ++same_newer;         // newer than wakee -> violation
              else { ++same_older; ++legit; }                    // older -> legit FIFO
            }
          } else {
            ++legit;  // no served class to compare: count conservatively as legit
          }
        }
      }
      if (inter == 0) {
        ++preempt;
        // Split PREEMPT-STARVED: was the run-CPU DARK (idle, no tick -> no
        // rescue) or HELD (a hog ran it the whole wait)? Majority-idle of the
        // wait window = DARK, the tickless strand. Only meaningful with CPU_IDLE.
        if (have_idle_) {
          uint64_t wait_ns = fw.run_ts > fw.wake_ts ? fw.run_ts - fw.wake_ts : 0;
          uint64_t idle_ns = idle_.overlap(fw.cpu, fw.wake_ts, fw.run_ts);
          if (wait_ns && idle_ns * 2 >= wait_ns) {
            ++dark_;
            if (wait_ns > worst_dark_ns_) worst_dark_ns_ = wait_ns;
          } else {
            ++held;
            CpuHolderLedger::Holder hd =
                holder_.dominant(fw.cpu, fw.wake_ts, fw.run_ts);
            if (hd.tid) held_by_[hd.tid] += hd.held_ns;
          }
        }
      } else {
        ++order; inter_sum += inter;
        // ORDER-STARVED: name who the CPU re-picked instead of this wakee.
        CpuHolderLedger::Recip rc =
            holder_.top_picked(fw.cpu, fw.wake_ts, fw.run_ts, fw.pid);
        if (rc.tid) offender_[rc.tid] += rc.count;
      }
      distinct_sum += po_pids.size();
      inter_v.push_back(inter);
      legit_v.push_back(legit);
      conc_tl_.push_back({fw.wake_ts, (uint32_t)po_pids.size(), (uint32_t)inter});
    }
    n_ = preempt + order;
    preempt_pct_ = n_ ? 100.0 * (double)preempt / (double)n_ : 0.0;
    order_pct_   = n_ ? 100.0 * (double)order / (double)n_ : 0.0;
    dark_pct_ = preempt ? 100.0 * (double)dark_ / (double)preempt : 0.0;
    held_pct_ = preempt ? 100.0 * (double)held / (double)preempt : 0.0;
    avg_inter_   = order ? (double)inter_sum / (double)order : 0.0;
    po_mirror_pct_     = po_total ? 100.0 * (double)po_mirror / (double)po_total : 0.0;
    served_mirror_pct_ = served_total ? 100.0 * (double)served_mirror / (double)served_total : 0.0;
    po_higher_pct_ = cls_total ? 100.0 * (double)cls_higher / (double)cls_total : 0.0;
    po_same_pct_   = cls_total ? 100.0 * (double)cls_same / (double)cls_total : 0.0;
    po_lower_pct_  = cls_total ? 100.0 * (double)cls_lower / (double)cls_total : 0.0;
    same_newer_pct_ = cls_same ? 100.0 * (double)same_newer / (double)cls_same : 0.0;
    avg_distinct_ = n_ ? (double)distinct_sum / (double)n_ : 0.0;
    (void)same_older;
    sublimation_u64(inter_v.data(), inter_v.size());
    uint64_t p99 = inter_v[(size_t)((double)inter_v.size() * 0.99)];
    passover_p99_ = (double)p99;
    montauk_sink_appendf(&g_out, "VERDICT: %s saturated floored wakes; PREEMPT-STARVED %.0f%% "
                "(0 intervening picks) / ORDER-STARVED %.0f%% (CPU served others "
                "first); avg %.1f pass-overs, p99 %llu pass-overs\n",
                fmt_count((double)n_).c_str(), preempt_pct_, order_pct_, avg_inter_,
                (unsigned long long)p99);
    if (have_idle_)
      montauk_sink_appendf(&g_out, "  PREEMPT split: %.0f%% DARK (run-CPU IDLE through the wait -- "
                  "tickless, no tick, no rescue scan = the strand; worst %.1fms) / "
                  "%.0f%% HELD (a task ran the CPU the whole wait)\n",
                  dark_pct_, (double)worst_dark_ns_ / 1e6, held_pct_);
    else
      montauk_sink_appendf(&g_out, "  PREEMPT split: no CPU_IDLE events -- cannot separate DARK "
                  "(idle strand) from HELD (busy hog); recapture with a montauk "
                  "that streams CPU_IDLE\n");
    if (!held_by_.empty()) {
      std::vector<std::pair<uint32_t, uint64_t>> hv(held_by_.begin(), held_by_.end());
      std::sort(hv.begin(), hv.end(),
                [](const std::pair<uint32_t, uint64_t>& a,
                   const std::pair<uint32_t, uint64_t>& b) { return a.second > b.second; });
      montauk_sink_appendf(&g_out, "  HELD by:");
      for (size_t i = 0; i < hv.size() && i < 3; ++i)
        montauk_sink_appendf(&g_out, " %s %.1fms", holder_.name_of(hv[i].first).c_str(),
                    (double)hv[i].second / 1e6);
      montauk_sink_appendf(&g_out, "  (the task that ran the CPU through the HELD waits)\n");
    }
    montauk_sink_appendf(&g_out, "  LANE: %.0f%% of pass-over picks via MIRROR / %.0f%% via SUB; "
                "floored wakees finally served %.0f%% MIRROR / %.0f%% SUB\n",
                po_mirror_pct_, 100.0 - po_mirror_pct_,
                served_mirror_pct_, 100.0 - served_mirror_pct_);
    montauk_sink_appendf(&g_out, "  CLASS: pass-over tasks vs the wakee's class -- %.0f%% HIGHER "
                "(cross-class: class beats age) / %.0f%% SAME / %.0f%% LOWER "
                "(priority inversion)\n",
                po_higher_pct_, po_same_pct_, po_lower_pct_);
    montauk_sink_appendf(&g_out, "  SAME-class age: %.0f%% of same-class pass-overs were NEWER than "
                "the wakee (FIFO violation -- newer served ahead of older); rest "
                "older (legit drain)\n", same_newer_pct_);
    montauk_sink_appendf(&g_out, "  (LOWER + SAME-NEWER are the illegitimate pass-overs the score "
                "key should have prevented -- a cache-fragmented dispatch serving "
                "its local best, not the global oldest)\n");
    montauk_sink_appendf(&g_out, "  CONCENTRATION: avg %.1f DISTINCT pass-over tasks per floored "
                "wake vs avg %.1f pass-over PICKS -- ratio %.2f (low = a few hogs "
                "re-picked, fair-share/lag fix; ~1.0 = deep distinct backlog, "
                "deadline fix)\n",
                avg_distinct_, avg_inter_,
                avg_inter_ > 0 ? avg_distinct_ / avg_inter_ : 0.0);
    /* CONCENTRATION TRAJECTORY: the whole-run ratio above cannot say WHEN the
     * pick pattern settled. Segment the floored wakes by wall-clock into 8
     * windows; each window's concentration is sum(distinct)/sum(picks). Read
     * window 1: already low = the boot committed to a concentrated (few-hog
     * re-pick) pattern from the start -- an initial-condition basin, not a drift.
     * A ratio that ramps DOWN over the windows drifted in. Same segmentation as
     * the slice TRAJECTORY; classified by sublimation (ratio x1000 for the
     * integer classifier). This is the per-boot-attractor view -- the scalar
     * adaptive state (codel/regime/service) does not discriminate the modes. */
    {
      static constexpr size_t kCSeg = 8;
      if (conc_tl_.size() >= 2 * kCSeg) {
        std::sort(conc_tl_.begin(), conc_tl_.end(),
                  [](const CTL& a, const CTL& b) { return a.ts < b.ts; });
        uint64_t t0 = conc_tl_.front().ts, t1 = conc_tl_.back().ts;
        if (t1 > t0) {
          uint64_t span = t1 - t0;
          std::vector<uint64_t> seg;  // concentration x1000 per window
          for (size_t g = 0; g < kCSeg; ++g) {
            uint64_t lo = t0 + span * g / kCSeg;
            uint64_t hi = t0 + span * (g + 1) / kCSeg;
            uint64_t ds = 0, is = 0;
            for (const auto& c : conc_tl_)
              if (c.ts >= lo && (c.ts < hi || (g + 1 == kCSeg && c.ts <= hi))) {
                ds += c.distinct; is += c.inter;
              }
            if (is) seg.push_back(ds * 1000 / is);
          }
          if (seg.size() >= 3) {
            sub_profile_t tp = sublimation_classify_u64(seg.data(), seg.size());
            montauk_sink_appendf(&g_out,
                "  CONCENTRATION TRAJECTORY (ratio x1000 over %zu windows):", seg.size());
            for (uint64_t v : seg)
              montauk_sink_appendf(&g_out, " %llu", (unsigned long long)v);
            montauk_sink_appendf(&g_out,
                "; shape=%s (window 1 already low = committed at boot; ramping down "
                "= drifted into it)\n", disorder_name(tp.disorder));
          }
        }
      }
    }
    if (!offender_.empty()) {
      std::vector<std::pair<uint32_t, uint64_t>> off(offender_.begin(), offender_.end());
      std::sort(off.begin(), off.end(),
                [](const std::pair<uint32_t, uint64_t>& a,
                   const std::pair<uint32_t, uint64_t>& b) { return a.second > b.second; });
      montauk_sink_appendf(&g_out,
          "  ORDER-STARVED OFFENDERS (who the CPU re-picked instead of the wakee):");
      for (size_t i = 0; i < off.size() && i < 3; ++i)
        montauk_sink_appendf(&g_out, " %s %llux", holder_.name_of(off[i].first).c_str(),
                    (unsigned long long)off[i].second);
      montauk_sink_appendf(&g_out,
          "  (few names = the re-pick set the concentration ratio counts; many = a "
          "rotating backlog)\n");
    }
    montauk_sink_appendf(&g_out, "\n");
    /* CEILING of a mirror-coherence (inversion-only) fix: remove the
     * illegitimate pass-overs per wake, recompute the pass-over p99. The
     * legit-only p99 is the floor a coherence fix alone could reach; the
     * residual above it is the eligibility/lag (legit-backlog) gap. */
    sublimation_u64(legit_v.data(), legit_v.size());
    uint64_t p99_legit = legit_v[(size_t)((double)legit_v.size() * 0.99)];
    double keep = p99 ? 100.0 * (double)p99_legit / (double)p99 : 0.0;
    ceiling_remains_pct_ = keep;
    montauk_sink_appendf(&g_out, "  CEILING: p99 pass-overs %llu total -> %llu if ALL inversions "
                "removed (%.0f%% remains = LEGIT backlog only eligibility/lag can "
                "cut; %.0f%% is the mirror-coherence headroom)\n\n",
                (unsigned long long)p99, (unsigned long long)p99_legit,
                keep, 100.0 - keep);
  }

  void prom(std::vector<PromMetric>& out) override {
    if (!n_) return;
    out.push_back({"montauk_analysis_dispatch_preempt_pct", "", preempt_pct_});
    out.push_back({"montauk_analysis_dispatch_order_pct", "", order_pct_});
    if (have_idle_) {
      out.push_back({"montauk_analysis_dispatch_dark_pct", "", dark_pct_});
      out.push_back({"montauk_analysis_dispatch_held_pct", "", held_pct_});
      out.push_back({"montauk_analysis_dispatch_worst_dark_ms", "",
                     (double)worst_dark_ns_ / 1e6});
    }
    out.push_back({"montauk_analysis_dispatch_avg_passovers", "", avg_inter_});
    out.push_back({"montauk_analysis_dispatch_passover_mirror_pct", "", po_mirror_pct_});
    out.push_back({"montauk_analysis_dispatch_served_mirror_pct", "", served_mirror_pct_});
    out.push_back({"montauk_analysis_dispatch_passover_higher_class_pct", "", po_higher_pct_});
    out.push_back({"montauk_analysis_dispatch_passover_same_class_pct", "", po_same_pct_});
    out.push_back({"montauk_analysis_dispatch_passover_lower_class_pct", "", po_lower_pct_});
    out.push_back({"montauk_analysis_dispatch_passover_p99", "", passover_p99_});
    // Concentration ratio: distinct pass-over tasks / total pass-over picks. Low
    // (~0.3) = a few hogs re-picked = the fair-share/lag prize; ~1.0 = deep
    // distinct backlog = a deadline prize. The single number that says which
    // lever the saturated floor wants.
    out.push_back({"montauk_analysis_dispatch_concentration_ratio", "",
                   avg_inter_ > 0 ? avg_distinct_ / avg_inter_ : 0.0});
    // Legit-backlog ceiling: % of the p99 pass-over depth that survives removing
    // every ordering inversion. That residual is what only eligibility/lag can
    // cut -- the size of the cliff a stronger service price can still reach.
    out.push_back({"montauk_analysis_dispatch_ceiling_remains_pct", "", ceiling_remains_pct_});
  }
};

// REPORT slice: per-CPU dispatched-slice length = the interval between
// consecutive PICKs on one CPU (how long the picked task ran before the CPU
// picked again). If the saturation tail is "wakee waits behind N tasks each
// running a long slice," this is the per-slice multiplier: tail ~ pass-overs x
// slice. Idle strands (gap > 10ms) are excluded -- those are not slices.
struct SliceReport final : Report {
  std::unordered_map<uint32_t, std::vector<uint64_t>> pick_ts_;    // cpu -> custom PICK ts
  std::unordered_map<uint32_t, std::vector<uint64_t>> switch_ts_;  // cpu -> sched_switch fallback ts
  std::vector<uint64_t> slices_;
  std::vector<std::pair<uint64_t, uint64_t>> tl_;  // (slice start ts, duration) for the wall-clock trajectory
  double traj_inversion_ = 0.0;
  bool traj_ok_ = false;

  const char* name() const override { return "slice"; }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type != TRACE_EVT_SCHED || len < sizeof(montauk_sched_event)) return;
    const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
    if (s->op == SCHED_OP_PICK)           pick_ts_[s->cpu].push_back(s->timestamp_ns);
    else if (s->op == SCHED_OP_SWITCH_IN) switch_ts_[s->cpu].push_back(s->timestamp_ns);
  }


  void emit(const montauk::model::TraceReader&) override {
    header();
    static constexpr uint64_t kStrandNs = 10000000ULL;  // >10ms gap = idle, not a slice
    // Prefer the scheduler's own PICK stream; fall back to the sched_switch-derived
    // SWITCH_IN when no pick tracepoint was bound (EEVDF / scx modes without pick).
    auto& src = !pick_ts_.empty() ? pick_ts_ : switch_ts_;
    for (auto& kv : src) {
      auto& v = kv.second;
      sublimation_u64(v.data(), v.size());
      for (size_t i = 1; i < v.size(); ++i) {
        uint64_t d = v[i] - v[i - 1];
        if (d > 0 && d < kStrandNs) {
          slices_.push_back(d);
          tl_.push_back({v[i - 1], d});
        }
      }
    }
    if (slices_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no slices (PICK stream absent)\n\n");
      return;
    }
    sublimation_u64(slices_.data(), slices_.size());
    double mean = 0;
    for (uint64_t s : slices_) mean += (double)s;
    mean /= (double)slices_.size();
    montauk_sink_appendf(&g_out, "VERDICT: %s dispatched slices; p50 %.1fus p90 %.1fus p99 %.1fus "
                "worst %.1fus; mean %.1fus\n",
                fmt_count((double)slices_.size()).c_str(),
                q_us(slices_, 0.50), q_us(slices_, 0.90), q_us(slices_, 0.99),
                us(slices_.back()), mean / 1000.0);
    montauk_sink_appendf(&g_out, "  (long slices x pass-over depth = the saturation tail; a "
                "shorter effective slice drains a deep runqueue faster)\n");
    // TRAJECTORY: is the dispatched-slice length steady, drifting smoothly, or
    // hunting? Segment the run by wall-clock, take each segment's median slice in
    // TIME order (NOT the quantile sort), and classify the sequence's shape. A
    // scheduler whose effective quantum tracks load coherently reads SORTED /
    // NEARLY_SORTED / PHASED (a settled trajectory); one whose quantum oscillates
    // reads RANDOM -- the control loop hunting rather than converging. Built from
    // the same sched_switch-derived slices, no knowledge of what sets the quantum.
    static constexpr size_t kSegs = 8;
    if (tl_.size() >= 2 * kSegs) {
      std::sort(tl_.begin(), tl_.end(),
                [](const std::pair<uint64_t, uint64_t>& a,
                   const std::pair<uint64_t, uint64_t>& b) { return a.first < b.first; });
      uint64_t t0 = tl_.front().first, t1 = tl_.back().first;
      if (t1 > t0) {
        uint64_t span = t1 - t0;
        std::vector<uint64_t> seg_med, bucket;
        for (size_t g = 0; g < kSegs; ++g) {
          uint64_t lo = t0 + span * g / kSegs;
          uint64_t hi = t0 + span * (g + 1) / kSegs;
          bucket.clear();
          for (const auto& pr : tl_)
            if (pr.first >= lo && (pr.first < hi || (g + 1 == kSegs && pr.first <= hi)))
              bucket.push_back(pr.second);
          if (bucket.empty()) continue;
          sublimation_u64(bucket.data(), bucket.size());
          seg_med.push_back(bucket[bucket.size() / 2]);
        }
        if (seg_med.size() >= 3) {
          sub_profile_t tp = sublimation_classify_u64(seg_med.data(), seg_med.size());
          traj_inversion_ = (double)tp.inversion_ratio;
          traj_ok_ = true;
          montauk_sink_appendf(&g_out, "TRAJECTORY: slice p50 over %zu segments (us):", seg_med.size());
          for (uint64_t m : seg_med) montauk_sink_appendf(&g_out, " %.0f", us(m));
          montauk_sink_appendf(&g_out, "; shape=%s inv=%.2f -- %s\n", disorder_name(tp.disorder),
                      traj_inversion_,
                      tp.disorder != SUB_RANDOM
                          ? "coherent (quantum settles with load)"
                          : "chatter (quantum hunting, not converging)");
        }
      }
    }
    // PER-CPU PREEMPT FAILURE EVIDENCE: with a ~1ms slice quantum the per-CPU tick
    // preempt should chop any slice whose CPU holds a waiter past ~1ms. Slices that
    // ran far past it uninterrupted are hogs the preempt never touched -- the mass
    // of the lat-critical/ctxless preempt-exemption strand. Over the sorted stream.
    auto over = [&](uint64_t ns) {
      size_t k = (size_t)(slices_.end() -
                          std::lower_bound(slices_.begin(), slices_.end(), ns));
      return std::make_pair(k, 100.0 * (double)k / (double)slices_.size());
    };
    auto o2 = over(2000000ULL), o5 = over(5000000ULL), o8 = over(8000000ULL);
    sub_profile_t sp = sublimation_classify_u64(slices_.data(), slices_.size());
    montauk_sink_appendf(&g_out, "PREEMPT-OVERRUN: >2ms %s (%.2f%%)  >5ms %s (%.2f%%)  >8ms %s (%.2f%%)"
                "  -- ~%zu distinct slice lengths\n\n",
                fmt_count((double)o2.first).c_str(), o2.second,
                fmt_count((double)o5.first).c_str(), o5.second,
                fmt_count((double)o8.first).c_str(), o8.second,
                sp.distinct_estimate);
  }

  void prom(std::vector<PromMetric>& out) override {
    if (slices_.empty()) return;
    auto push = [&](const char* ql, double v) {
      out.push_back({"montauk_analysis_slice_us",
                     std::string("quantile=\"") + ql + "\"", v});
    };
    push("0.5", q_us(slices_, 0.50));
    push("0.99", q_us(slices_, 0.99));
    push("worst", us(slices_.back()));
    if (traj_ok_)
      out.push_back({"montauk_analysis_slice_trajectory_inversion", "", traj_inversion_});
  }
};

// REPORT storm: the sched_ext cpu_release kick-storm, from TRACE_EVT_SCX_STORM
// per-interval counters (fentry on scx_bpf_kick_cpu / scx_bpf_reenqueue_local).
// Replaces storm_score's scrape of the scheduler's printed tick log: reenqueue
// rate is the storm intensity; the preempt-kick share splits a REAL IPI storm from
// benign IDLE re-enqueue churn.
struct StormReport final : Report {
  struct Sample { uint64_t kicks, preempt, reenq; uint32_t interval_ms; };
  std::vector<Sample> samples_;
  uint64_t tot_kicks_ = 0, tot_preempt_ = 0, tot_reenq_ = 0, tot_ms_ = 0;
  double storm_pct_ = 0.0, peak_reenq_rate_ = 0.0;

  static constexpr double kStormReenqPerS = 50000.0; // a core reenqueuing this hard is storming
  static constexpr double kHardFrac = 0.5;           // preempt >= frac*reenq => real IPI storm

  const char* name() const override { return "storm"; }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type != TRACE_EVT_SCX_STORM || len < sizeof(montauk_scx_storm_event)) return;
    const auto* s = reinterpret_cast<const montauk_scx_storm_event*>(data);
    samples_.push_back({s->kicks, s->preempt_kicks, s->reenq, s->interval_ms});
    tot_kicks_ += s->kicks; tot_preempt_ += s->preempt_kicks; tot_reenq_ += s->reenq;
    tot_ms_ += s->interval_ms;
  }

  static double reenq_rate(const Sample& s) {
    return s.interval_ms ? (double)s.reenq * 1000.0 / (double)s.interval_ms : 0.0;
  }

  void emit(const montauk::model::TraceReader&) override {
    header();
    if (samples_.empty() || tot_ms_ == 0) {
      montauk_sink_appendf(&g_out, "VERDICT: no sched_ext kick activity captured (non-scx scheduler, "
                  "or no cpu_release storm)\n\n");
      return;
    }
    std::vector<uint64_t> rr;
    rr.reserve(samples_.size());
    size_t storm_intervals = 0;
    for (const auto& s : samples_) {
      double r = reenq_rate(s);
      rr.push_back((uint64_t)r);
      if (r >= kStormReenqPerS) ++storm_intervals;
    }
    storm_pct_ = 100.0 * (double)storm_intervals / (double)samples_.size();
    sublimation_u64(rr.data(), rr.size());
    peak_reenq_rate_ = (double)rr.back();
    double p50 = (double)rr[rr.size() / 2];
    double secs = (double)tot_ms_ / 1000.0;
    bool real_ipi = tot_reenq_ && (double)tot_preempt_ >= kHardFrac * (double)tot_reenq_;
    const char* kind = storm_intervals == 0 ? "clean -- no storm intervals"
                       : real_ipi ? "REAL IPI storm (preempt-kick dominant)"
                                  : "IDLE re-enqueue churn (kicks no-op on busy CPUs)";
    montauk_sink_appendf(&g_out, "VERDICT: %s; storm %zu/%zu intervals (%.1f%%); reenq/s p50=%.0f "
                "peak=%.0f; kick/s=%.0f (preempt %.0f) reenq/s=%.0f\n",
                kind, storm_intervals, samples_.size(), storm_pct_,
                p50, peak_reenq_rate_, (double)tot_kicks_ / secs,
                (double)tot_preempt_ / secs, (double)tot_reenq_ / secs);
    montauk_sink_appendf(&g_out, "  (storm interval = reenqueue rate >= %.0f/s; REAL when preempt-kicks "
                ">= %.0f%% of reenqueues)\n\n", kStormReenqPerS, kHardFrac * 100.0);
  }

  void prom(std::vector<PromMetric>& out) override {
    if (samples_.empty() || tot_ms_ == 0) return;
    double secs = (double)tot_ms_ / 1000.0;
    out.push_back({"montauk_analysis_storm_pct", "", storm_pct_});
    out.push_back({"montauk_analysis_storm_reenq_per_s", "stat=\"peak\"", peak_reenq_rate_});
    out.push_back({"montauk_analysis_storm_kick_per_s", "flag=\"all\"", (double)tot_kicks_ / secs});
    out.push_back({"montauk_analysis_storm_kick_per_s", "flag=\"preempt\"", (double)tot_preempt_ / secs});
  }

  void offenders(std::vector<Offender>& out) override {
    if (peak_reenq_rate_ < kStormReenqPerS) return;
    int sev = peak_reenq_rate_ > 5.0 * kStormReenqPerS ? 2 : 1;
    out.push_back({"scx-storm", "scheduler", "", "reenq_per_s", peak_reenq_rate_, sev});
  }
};

// REPORT service: per-PID CPU service (sum of dispatched slices from the PICK
// stream) and its SKEW. The cliff is the legit backlog -- a wakee waiting behind
// others. The fix is a fair-share / lag term ONLY IF service is skewed (a few
// tasks over-consume, so deprioritizing them frees the starved wakee). If
// service is uniform (every task gets ~equal CPU), a fair-share term has nothing
// to redistribute and won't move the tail. This measures which: top-k share +
// sublimation-sorted per-PID service distribution. Per-PID service = sum of
// (next_pick_ts - this_pick_ts) on the CPU while this PID was the picked task
// (idle strands > 10ms excluded).
struct ServiceReport final : Report {
  std::unordered_map<uint32_t, std::vector<std::pair<uint64_t, int>>> picks_;        // cpu->(ts,pid) custom PICK
  std::unordered_map<uint32_t, std::vector<std::pair<uint64_t, int>>> switch_picks_; // cpu->(ts,pid) fallback
  std::vector<uint64_t> svc_;  // per-pid total service, filled in emit()

  const char* name() const override { return "service"; }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type != TRACE_EVT_SCHED || len < sizeof(montauk_sched_event)) return;
    const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
    if (s->op == SCHED_OP_PICK)           picks_[s->cpu].push_back({s->timestamp_ns, s->pid});
    else if (s->op == SCHED_OP_SWITCH_IN) switch_picks_[s->cpu].push_back({s->timestamp_ns, s->pid});
  }


  void emit(const montauk::model::TraceReader&) override {
    header();
    static constexpr uint64_t kStrandNs = 10000000ULL;
    std::unordered_map<int, uint64_t> by_pid;
    // Prefer the scheduler's own PICK stream; fall back to the sched_switch-derived
    // SWITCH_IN when no pick tracepoint was bound (EEVDF / scx modes without pick).
    auto& src = !picks_.empty() ? picks_ : switch_picks_;
    for (auto& kv : src) {
      auto& v = kv.second;
      sublimation_order_u64(v, false, [](const std::pair<uint64_t, int>& p) { return p.first; });
      for (size_t i = 1; i < v.size(); ++i) {
        uint64_t d = v[i].first - v[i - 1].first;
        if (d > 0 && d < kStrandNs) by_pid[v[i - 1].second] += d;
      }
    }
    if (by_pid.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no service (PICK stream absent)\n\n");
      return;
    }
    uint64_t total = 0;
    for (auto& kv : by_pid) { svc_.push_back(kv.second); total += kv.second; }
    sublimation_u64(svc_.data(), svc_.size());  // ascending
    // Env-gated raw dump: per-PID service in microseconds, one per line, for
    // sublimation classify/locate/quantile over the real distribution shape.
    if (const char* dp = std::getenv("MONTAUK_SVC_DUMP")) {
      if (FILE* df = std::fopen(dp, "w")) {
        for (uint64_t s : svc_) std::fprintf(df, "%llu\n",
                                             (unsigned long long)(s / 1000));
        std::fclose(df);
      }
    }
    size_t np = svc_.size();
    uint64_t top1 = svc_.back();
    uint64_t top5 = 0;
    for (size_t i = 0; i < 5 && i < np; ++i) top5 += svc_[np - 1 - i];
    double top1_pct = total ? 100.0 * (double)top1 / (double)total : 0.0;
    double top5_pct = total ? 100.0 * (double)top5 / (double)total : 0.0;
    // fair share = total / npids; a uniform distribution has every pid ~= fair.
    double fair = np ? (double)total / (double)np : 0.0;
    double p99_over_fair = fair > 0 ? q_ms(svc_, 0.99) * 1e6 / fair : 0.0;
    montauk_sink_appendf(&g_out, "VERDICT: %s PIDs ran; per-PID service p50 %.1fms p99 %.1fms "
                "max %.1fms; fair-share %.1fms\n",
                fmt_count((double)np).c_str(), q_ms(svc_, 0.50), q_ms(svc_, 0.99),
                ms(top1), fair / 1e6);
    montauk_sink_appendf(&g_out, "  SKEW: top-1 PID %.1f%% of all CPU / top-5 %.1f%%; p99 PID ran "
                "%.1fx its fair share\n", top1_pct, top5_pct, p99_over_fair);
    montauk_sink_appendf(&g_out, "  (high skew -> a few tasks over-consume; a fair-share/lag term "
                "frees the starved wakee = the cliff lever. uniform -> symmetric "
                "load, fair-share has nothing to redistribute)\n\n");
  }

  void prom(std::vector<PromMetric>& out) override {
    if (svc_.empty()) return;
    uint64_t total = 0; for (uint64_t s : svc_) total += s;
    out.push_back({"montauk_analysis_service_top1_pct", "",
                   total ? 100.0 * (double)svc_.back() / (double)total : 0.0});
    out.push_back({"montauk_analysis_service_pids", "", (double)svc_.size()});
  }
};

// REPORT wakers (v7.9.0): localize request-level latency to the WAKER critical
// path. schbench's reported latency is a messenger->worker round-trip; per-hop
// wake2run cannot see it, but if the MESSENGER (a hot waker) is itself delayed,
// every worker it wakes inherits that delay in the round-trip. Using the v7.9.0
// waker edge (SCHED_OP_WAKEUP secondary_pid = waker), classify hot wakers
// (messengers, by wake-issue count) and split WAKE2RUN into MESSENGER-dispatch
// vs WORKER-dispatch. If the messenger wake2run tail dwarfs the worker tail,
// the cliff is the waker path, not generic dispatch -- the 54k schbench sees.
struct WakersReport final : Report {
  std::unordered_map<int, uint64_t> wake_count_;   // waker pid -> wakes issued
  std::unordered_map<int, std::vector<uint64_t>> w2r_by_pid_;  // wakee pid -> waits
  uint64_t total_wakes_ = 0;

  const char* name() const override { return "wakers"; }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type != TRACE_EVT_SCHED || len < sizeof(montauk_sched_event)) return;
    const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
    if (s->op == SCHED_OP_WAKEUP) {
      if (s->secondary_pid >= 0) { ++wake_count_[s->secondary_pid]; ++total_wakes_; }
      return;
    }
    if (s->op == SCHED_OP_WAKE2RUN)
      w2r_by_pid_[s->pid].push_back(s->runtime_ns);
  }


  void emit(const montauk::model::TraceReader&) override {
    header();
    if (wake_count_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no waker edges (pre-v7.9.0 trace -- sched_wakeup did "
                  "not stamp the waker); re-capture to resolve\n\n");
      return;
    }
    // Hot waker = messenger: wake-issue count >= 8x the mean waker's count.
    uint64_t sum = 0; for (auto& kv : wake_count_) sum += kv.second;
    double mean = (double)sum / (double)wake_count_.size();
    uint64_t thresh = (uint64_t)(mean * 8.0); if (thresh < 8) thresh = 8;
    std::unordered_set<int> hot;
    for (auto& kv : wake_count_) if (kv.second >= thresh) hot.insert(kv.first);

    std::vector<uint64_t> msg, wrk;
    for (auto& kv : w2r_by_pid_) {
      auto& dst = hot.count(kv.first) ? msg : wrk;
      for (uint64_t v : kv.second) dst.push_back(v);
    }
    // q_us indexes a pre-sorted vector (the shared hoisted helper); sort once
    // here -- the per-class q_us this replaced sorted internally on each call.
    sublimation_u64(msg.data(), msg.size());
    sublimation_u64(wrk.data(), wrk.size());
    montauk_sink_appendf(&g_out, "VERDICT: %s waker pids, %s hot (messengers, >=%llu wakes); "
                "%s total wakes\n",
                fmt_count((double)wake_count_.size()).c_str(),
                fmt_count((double)hot.size()).c_str(),
                (unsigned long long)thresh, fmt_count((double)total_wakes_).c_str());
    montauk_sink_appendf(&g_out, "  MESSENGER wake2run (%s samples): p50 %.0fus p99 %.0fus "
                "p999 %.0fus\n", fmt_count((double)msg.size()).c_str(),
                q_us(msg, 0.50), q_us(msg, 0.99), q_us(msg, 0.999));
    montauk_sink_appendf(&g_out, "  WORKER    wake2run (%s samples): p50 %.0fus p99 %.0fus "
                "p999 %.0fus\n", fmt_count((double)wrk.size()).c_str(),
                q_us(wrk, 0.50), q_us(wrk, 0.99), q_us(wrk, 0.999));
    montauk_sink_appendf(&g_out, "  (messenger tail >> worker tail -> the cliff is the waker "
                "critical path; protect the wakers, don't deprioritize them)\n\n");
  }

  void prom(std::vector<PromMetric>&) override {}
};

// REPORT fractal: self-similarity of the dispatch + migration timeline.
// The old bench-analyze --fractal ran Hurst/DFA on 100ms .prom scrapes (~340
// points, <1 decade of scale -- "INDICATIVE ONLY", its own author's words:
// microsecond dispatch structure is invisible at that cadence). This runs on
// the RAW event stream instead: WAKE2RUN run-events and ENQUEUE migrations,
// binned at microsecond resolution, span many decades -- the rigorous input
// the .prom version never had. DFA Hurst (primary), R/S (cross-check), fractal
// dimension D=2-H, and a migration-avalanche (self-organized-criticality) tail.
struct FractalReport final : Report {
  std::vector<uint64_t> disp_ts_;  // WAKE2RUN run-event timestamps
  std::vector<uint64_t> mig_ts_;   // cross-domain WAKE2RUN timestamps (sub_idx set)
  // Computed in emit(), surfaced in prom().
  struct SeriesOut { const char* name; double h, se, hrs, dim, decades; bool ok; };
  std::vector<SeriesOut> out_;
  int avalanches_ = 0;
  double aval_slope_ = NAN;
  size_t nbins_ = 0;

  const char* name() const override { return "fractal"; }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type != TRACE_EVT_SCHED || len < sizeof(montauk_sched_event)) return;
    const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
    if (s->op == SCHED_OP_WAKE2RUN) {
      disp_ts_.push_back(s->timestamp_ns);
      if (s->sub_idx) mig_ts_.push_back(s->timestamp_ns);  // cross-domain landing
    }
  }

  static std::vector<double> bin_rate(const std::vector<uint64_t>& ts,
                                      uint64_t t0, uint64_t w, size_t nbins) {
    std::vector<double> r(nbins, 0.0);
    for (uint64_t t : ts) {
      size_t i = static_cast<size_t>((t - t0) / w);
      if (i < nbins) r[i] += 1.0;
    }
    return r;
  }

  SeriesOut analyze_series(const char* nm, const std::vector<double>& rate) {
    SeriesOut o{nm, NAN, NAN, NAN, NAN, 0.0, false};
    if (rate.size() < 32) return o;
    o.h = montauk::stats::dfa_hurst(rate, &o.se, &o.decades);
    o.hrs = montauk::stats::rs_hurst(rate);
    o.dim = 2.0 - o.h;
    o.ok = std::isfinite(o.h);
    return o;
  }

  void emit(const montauk::model::TraceReader&) override {
    header();
    if (disp_ts_.empty() && mig_ts_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no SCHED events in trace -- nothing to analyze\n\n");
      return;
    }
    uint64_t t0 = UINT64_MAX, t1 = 0;
    for (uint64_t t : disp_ts_) { t0 = std::min(t0, t); t1 = std::max(t1, t); }
    for (uint64_t t : mig_ts_)  { t0 = std::min(t0, t); t1 = std::max(t1, t); }
    if (t1 <= t0) {
      montauk_sink_appendf(&g_out, "VERDICT: zero-duration timeline -- nothing to analyze\n\n");
      return;
    }
    // Target ~120k bins so the DFA scale range spans ~3-4 decades; clamp the
    // bin width to [10us, 10ms] so neither tiny nor huge traces degenerate.
    const uint64_t span = t1 - t0;
    uint64_t w = span / 120000;
    if (w < 10000) w = 10000;
    if (w > 10000000) w = 10000000;
    nbins_ = static_cast<size_t>(span / w) + 1;
    const double secs = static_cast<double>(span) / 1e9;

    std::vector<double> disp = bin_rate(disp_ts_, t0, w, nbins_);
    std::vector<double> mig = bin_rate(mig_ts_, t0, w, nbins_);
    out_.clear();
    out_.push_back(analyze_series("dispatch-rate", disp));
    out_.push_back(analyze_series("migration-rate", mig));
    avalanches_ = montauk::stats::avalanche_tail(mig, &aval_slope_);

    montauk_sink_appendf(&g_out, "TIMELINE: %s dispatches, %s cross-domain over %.1fs; "
                "bin %.0fus -> %zu bins\n",
                fmt_count(static_cast<double>(disp_ts_.size())).c_str(),
                fmt_count(static_cast<double>(mig_ts_.size())).c_str(), secs,
                static_cast<double>(w) / 1000.0, nbins_);
    montauk_sink_appendf(&g_out, "%-16s %12s %10s %8s %8s  VERDICT\n", "SERIES", "H(DFA)",
                "H(R/S)", "D=2-H", "decades");
    for (const SeriesOut& o : out_) {
      if (!o.ok) {
        montauk_sink_appendf(&g_out, "%-16s %12s\n", o.name, "short/flat");
        continue;
      }
      const char* verdict =
          (o.h - 2 * o.se > 0.5)   ? "persistent (long-range / self-similar)"
          : (o.h + 2 * o.se < 0.5) ? "anti-persistent (mean-reverting)"
                                   : "indistinguishable from uncorrelated";
      montauk_sink_appendf(&g_out, "%-16s %9.3f±%.3f %10.3f %8.3f %8.2f  %s\n", o.name, o.h,
                  o.se, o.hrs, o.dim, o.decades, verdict);
    }
    if (avalanches_ >= 5)
      montauk_sink_appendf(&g_out, "migration avalanches: %d above active-median; "
                  "CCDF log-log slope %+.2f\n", avalanches_, aval_slope_);
    montauk_sink_appendf(&g_out, "NOTE: raw-event timeline spans %.1f decades of scale -- a "
                "rigorous read, not the <1-decade .prom-scrape estimate\n\n",
                out_.empty() || !out_[0].ok ? 0.0 : out_[0].decades);
  }

  void prom(std::vector<PromMetric>& out) override {
    for (const SeriesOut& o : out_) {
      if (!o.ok) continue;
      std::string lab = std::string("series=\"") + o.name + "\"";
      out.push_back({"montauk_fractal_hurst_dfa", lab, o.h});
      out.push_back({"montauk_fractal_hurst_dfa_se", lab, o.se});
      out.push_back({"montauk_fractal_hurst_rs", lab, o.hrs});
      out.push_back({"montauk_fractal_dimension", lab, o.dim});
      out.push_back({"montauk_fractal_decades", lab, o.decades});
    }
    if (avalanches_ >= 5) {
      out.push_back({"montauk_fractal_avalanches", "",
                     static_cast<double>(avalanches_)});
      out.push_back({"montauk_fractal_avalanche_slope", "", aval_slope_});
    }
  }
};

// REPORT kstrand: per-CPU kernel-thread dispatch strands (TRACE_EVT_KSTRAND).
// A per-CPU kthread (ksoftirqd/N, a bound kworker, a btrfs endio worker, the scx
// watchdog workfn) can ONLY run on its single allowed CPU. When the scheduler
// strands it behind a long slice, I/O-completion / writeback work backs up and
// every fsync/fdatasync waiter on the box wedges into D state -- without ever
// tripping the runnable-stall watchdog, because the victims are in D, not R.
// This report ranks the worst-stranded kthreads and splits each strand HELD
// (its CPU was busy through the wait -- a genuine scheduler strand) vs DARK (its
// CPU was idle/tickless -- no rescue scan fired). HELD strands in the 100ms+
// range are the writeback-freeze signature.
struct KStrandReport final : Report {
  struct Agg {
    uint32_t cpu = 0;
    std::vector<uint64_t> lat;  // strand latencies (ns)
    uint64_t held = 0, dark = 0;
    uint64_t max_ns = 0;
    uint64_t worst_run_ts = 0;  // run_ts of the max strand, for holder attribution
  };
  std::unordered_map<std::string, Agg> by_comm_;
  CpuHolderLedger holder_;
  // strands buffered until emit() so CPU_IDLE intervals are complete first.
  struct Ev { uint32_t cpu; uint64_t run_ts, lat; std::string comm; };
  std::vector<Ev> evs_;
  CpuIdleIntervals idle_;
  uint64_t total_ = 0, worst_held_ns_ = 0;

  const char* name() const override { return "kstrand"; }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    holder_.fold(type, data, len);
    if (type == TRACE_EVT_SCHED && len >= sizeof(montauk_sched_event)) {
      const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
      if (s->op != SCHED_OP_CPU_IDLE) return;
      idle_.fold(s->cpu, s->sub_idx, s->timestamp_ns);
      return;
    }
    if (type != TRACE_EVT_KSTRAND || len < sizeof(montauk_kstrand_event)) return;
    const auto* k = reinterpret_cast<const montauk_kstrand_event*>(data);
    evs_.push_back({k->cpu, k->timestamp_ns, k->latency_ns, redact_comm(k->comm)});
    ++total_;
  }

  // Aggregate strands into per-kthread rows with the HELD/DARK split. Built here,
  // NOT in emit(), because the digest path calls offenders()/prom() WITHOUT ever
  // calling emit() for this report -- deferring the aggregation to emit() would
  // hide the strand offenders from the one-file report. Idempotent: safe to call
  // from emit(), offenders() and prom() in any order.
  bool finalized_ = false;
  void finalize() {
    if (finalized_) return;
    finalized_ = true;
    idle_.finalize();
    for (const auto& e : evs_) {
      Agg& a = by_comm_[e.comm];
      a.cpu = e.cpu;
      a.lat.push_back(e.lat);
      if (e.lat > a.max_ns) { a.max_ns = e.lat; a.worst_run_ts = e.run_ts; }
      uint64_t wait_start = (e.run_ts > e.lat) ? (e.run_ts - e.lat) : 0;
      uint64_t idle = idle_.overlap(e.cpu, wait_start, e.run_ts);
      // Majority-idle through the wait => DARK (tickless, no rescue); else HELD.
      if (idle * 2 >= e.lat) a.dark++;
      else { a.held++; if (e.lat > worst_held_ns_) worst_held_ns_ = e.lat; }
    }
    holder_.finalize();
  }

  void emit(const montauk::model::TraceReader&) override {
    header();
    if (evs_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no per-CPU kthread strands over threshold "
                  "(no I/O-completion starvation captured)\n\n");
      return;
    }
    finalize();
    // Rank kthreads by max strand.
    std::vector<std::pair<std::string, Agg*>> rows;
    rows.reserve(by_comm_.size());
    for (auto& kv : by_comm_) rows.push_back({kv.first, &kv.second});
    std::sort(rows.begin(), rows.end(),
              [](const auto& x, const auto& y) { return x.second->max_ns > y.second->max_ns; });

    montauk_sink_appendf(&g_out, "%zu strands across %zu per-CPU kthreads (threshold-crossing dispatch waits)\n",
                static_cast<size_t>(total_), rows.size());
    montauk_sink_appendf(&g_out, "worst HELD strand %.1fms (CPU busy through the wait -- I/O-completion freeze signature)\n",
                ms(worst_held_ns_));
    montauk_sink_appendf(&g_out, "%-18s %-5s %-7s %-9s %-9s %-6s %-6s %s\n",
                "kthread", "cpu", "strands", "max_ms", "p99_ms", "held", "dark", "held_by");
    size_t shown = 0;
    for (auto& [comm, a] : rows) {
      if (shown++ >= 20) break;
      sublimation_u64(a->lat.data(), a->lat.size());
      std::string held_by = "-";
      if (a->held && a->worst_run_ts) {
        uint64_t ws = a->worst_run_ts > a->max_ns ? a->worst_run_ts - a->max_ns : 0;
        CpuHolderLedger::Holder hd = holder_.dominant(a->cpu, ws, a->worst_run_ts);
        if (hd.window_ns) {
          int cov = static_cast<int>(100.0 * (double)hd.held_ns / (double)hd.window_ns);
          held_by = holder_.name_of(hd.tid) + " " + std::to_string(cov) + "%";
        }
      }
      montauk_sink_appendf(&g_out, "%-18s %-5u %-7zu %-9.1f %-9.1f %-6" PRIu64 " %-6" PRIu64 " %s\n",
                  comm.c_str(), a->cpu, a->lat.size(), ms(a->max_ns),
                  q_ms(a->lat, 0.99), a->held, a->dark, held_by.c_str());
    }
    montauk_sink_appendf(&g_out, "\n");
  }

  void prom(std::vector<PromMetric>& out) override {
    finalize();
    out.push_back({"montauk_analysis_kstrand_events_total", "",
                   static_cast<double>(total_)});
    out.push_back({"montauk_analysis_kstrand_worst_held_ms", "", ms(worst_held_ns_)});
  }

  void offenders(std::vector<Offender>& out) override {
    finalize();
    for (auto& [comm, a] : by_comm_) {
      if (a.held == 0) continue;  // DARK-only strands are a tickless-rescue gap, not a held strand
      // sev: 100ms+ held strand wedges fsync/writeback (high); 5-100ms (med).
      int sev = a.max_ns >= 100000000ULL ? 2 : 1;
      out.push_back({"kthread-strand", comm, "", "max_strand_ms",
                     ms(a.max_ns), sev});
    }
  }
};

// REPORT locality: turns each placement migration (WAKE2RUN: prev-run core -> run core) into a
// cache-tier distance (same-L2 / same-L3 / same-socket / cross-socket) and reports
// how migration density decays with distance -- a generic scheduler-analysis lens
// that characterizes any scheduler equally. Topology comes from the trace-embedded
// "cache_topology" snapshot, so it decodes anywhere. montauk measures the
// distribution; the consumer decides what a healthy decay is. Names no scheduler,
// no vendor: a cache tier is hardware, the distance is generic.
class LocalityReport : public Report {
  std::unordered_map<uint32_t, std::array<uint32_t, 3>> topo_;  // cpu -> {l2,l3,socket}
  bool have_topo_ = false;
  std::array<uint64_t, 4> tier_{};  // same-L2, same-L3, same-socket, cross-socket
  uint64_t migrations_ = 0, unmapped_ = 0;
  std::unordered_map<int, uint64_t> last_mig_ts_;  // pid -> ts of its last migration
  // Migration-cause attribution by dispatch lane (PICK sub_idx: 0 = mirror/own STEP-0,
  // >0 = sub/STEP-1 steal). An own-dispatch migration = the task was PLACED on a new CPU
  // (select_cpu/enqueue, incl warm-stay-release) and that CPU drained it; a sub-dispatch
  // migration = a STEAL pulled it cross-CPU. Splits the bounce into placement vs steal and
  // each one's cadence, so the inter-migration period maps to a scheduler clock.
  std::unordered_map<int, uint32_t> last_lane_;  // pid -> last PICK lane
  uint64_t steal_mig_ = 0, place_mig_ = 0;
  std::vector<uint64_t> steal_iv_, place_iv_;
  bool have_lane_ = false;
  std::vector<uint64_t> intervals_;                // inter-migration intervals (ns), all threads
  uint64_t ts_min_ = 0, ts_max_ = 0;               // trace active span (sched events)

  static bool pu(const std::string& line, const char* key, uint32_t& out) {
    std::string pat = std::string(key) + "=\"";
    size_t k = line.find(pat);
    if (k == std::string::npos) return false;
    out = static_cast<uint32_t>(std::strtoul(line.c_str() + k + pat.size(), nullptr, 10));
    return true;
  }
  void parse_topo(const char* p, uint32_t plen) {
    std::string text(p, plen);
    size_t pos = 0;
    while (pos < text.size()) {
      size_t eol = text.find('\n', pos);
      std::string line =
          text.substr(pos, eol == std::string::npos ? std::string::npos : eol - pos);
      pos = (eol == std::string::npos) ? text.size() : eol + 1;
      uint32_t cpu, l2, l3, sock;
      if (pu(line, "cpu", cpu) && pu(line, "l2", l2) && pu(line, "l3", l3) &&
          pu(line, "socket", sock)) {
        topo_[cpu] = {l2, l3, sock};
        have_topo_ = true;
      }
    }
  }
  int tier(uint32_t a, uint32_t b) {
    auto ia = topo_.find(a), ib = topo_.find(b);
    if (ia == topo_.end() || ib == topo_.end()) return -1;
    const auto& A = ia->second;
    const auto& B = ib->second;
    if (A[0] == B[0]) return 0;
    if (A[1] == B[1]) return 1;
    if (A[2] == B[2]) return 2;
    return 3;
  }

 public:
  const char* name() const override { return "locality"; }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type == TRACE_EVT_PROVIDER && len >= sizeof(montauk_provider_event)) {
      const auto* e = reinterpret_cast<const montauk_provider_event*>(data);
      char nm[33];
      std::memcpy(nm, e->name, 32);
      nm[32] = 0;
      if (std::strcmp(nm, "cache_topology") != 0) return;
      uint32_t avail = len - static_cast<uint32_t>(sizeof(montauk_provider_event));
      uint32_t plen = e->payload_len < avail ? e->payload_len : avail;
      parse_topo(reinterpret_cast<const char*>(data + sizeof(montauk_provider_event)), plen);
      return;
    }
    if (type != TRACE_EVT_SCHED || len < sizeof(montauk_sched_event)) return;
    const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
    // Trace active span over ALL sched ops -- the denominator for migrations/s.
    if (ts_min_ == 0 || s->timestamp_ns < ts_min_) ts_min_ = s->timestamp_ns;
    if (s->timestamp_ns > ts_max_) ts_max_ = s->timestamp_ns;
    // WAKE2RUN carries the migration: last_cpu = the core it last ran on (src),
    // cpu = the core it ran on now (dst). last_cpu < 0 = no prior run, == cpu = no
    // migration. (sched_switch is where montauk detects the move.)
    // PICK lane carries the dispatch cause: 0 = own STEP-0 (task ran where it was placed),
    // >0 = STEP-1 steal (a remote CPU pulled it). Track the last lane per pid; the PICK
    // precedes the WAKE2RUN for the same run, so it names this migration's cause.
    if (s->op == SCHED_OP_PICK) { last_lane_[s->pid] = s->sub_idx; have_lane_ = true; return; }
    if (s->op != SCHED_OP_WAKE2RUN) return;
    if (s->last_cpu < 0 || s->last_cpu == static_cast<int32_t>(s->cpu)) return;
    ++migrations_;
    // Attribute: own-dispatch (lane 0) = PLACEMENT (select_cpu/enqueue put it on a new
    // CPU, incl warm-stay-release); sub-dispatch (lane >0) = STEAL.
    bool by_steal = false;
    auto lit = last_lane_.find(s->pid);
    if (lit != last_lane_.end()) by_steal = lit->second > 0;
    (by_steal ? steal_mig_ : place_mig_)++;
    // Inter-migration interval per thread: time since THIS pid last migrated. Tiny
    // intervals = a tight high-frequency bounce; large = sticky. The bounce FREQUENCY
    // the same-L2/L3 tier mix cannot show -- both a pinned and a thrashing pair read local.
    auto mit = last_mig_ts_.find(s->pid);
    if (mit != last_mig_ts_.end() && s->timestamp_ns > mit->second) {
      uint64_t iv = s->timestamp_ns - mit->second;
      intervals_.push_back(iv);
      (by_steal ? steal_iv_ : place_iv_).push_back(iv);
    }
    last_mig_ts_[s->pid] = s->timestamp_ns;
    int t = tier(static_cast<uint32_t>(s->last_cpu), s->cpu);
    if (t < 0) {
      ++unmapped_;
      return;
    }
    ++tier_[t];
  }

  void emit(const montauk::model::TraceReader&) override {
    header();
    if (!have_topo_) {
      montauk_sink_appendf(&g_out, "VERDICT: no cache_topology snapshot in the trace -- cannot map "
                  "migration distance (recapture with montauk >= 7.8.0)\n\n");
      return;
    }
    uint64_t cl = tier_[0] + tier_[1] + tier_[2] + tier_[3];
    if (cl == 0) {
      montauk_sink_appendf(&g_out, "VERDICT: no cross-CPU migrations captured\n\n");
      return;
    }
    montauk_sink_appendf(&g_out, "%" PRIu64 " migrations (%" PRIu64 " unmapped)\n", migrations_, unmapped_);
    const char* nm[4] = {"same-L2", "same-L3", "same-socket", "cross-socket"};
    montauk_sink_appendf(&g_out, "%-14s %-12s %-8s\n", "tier", "moves", "pct");
    for (int t = 0; t < 4; t++)
      montauk_sink_appendf(&g_out, "%-14s %-12" PRIu64 " %6.1f%%\n", nm[t], tier_[t],
                  100.0 * static_cast<double>(tier_[t]) / static_cast<double>(cl));
    montauk_sink_appendf(&g_out, "decay (tier_{k+1}/tier_k):");
    for (int t = 0; t < 3; t++)
      montauk_sink_appendf(&g_out, " %.3f", tier_[t] > 0
                               ? static_cast<double>(tier_[t + 1]) / static_cast<double>(tier_[t])
                               : 0.0);
    montauk_sink_appendf(&g_out, "\n");
    // Migration FREQUENCY -- the bounce rate the tier distribution hides. A pair
    // pinned to one L2 and a pair thrashing between two both read "cache-local";
    // the rate and the inter-migration interval separate them.
    double span_s = (ts_max_ > ts_min_) ? static_cast<double>(ts_max_ - ts_min_) / 1e9 : 0.0;
    if (span_s > 0.0)
      montauk_sink_appendf(&g_out, "rate: %.0f migrations/s over %.2fs\n",
                  static_cast<double>(migrations_) / span_s, span_s);
    if (!intervals_.empty()) {
      std::sort(intervals_.begin(), intervals_.end());
      auto iq = [&](double p) {
        size_t i = static_cast<size_t>(p * static_cast<double>(intervals_.size() - 1));
        return static_cast<double>(intervals_[i]) / 1000.0;  // us
      };
      montauk_sink_appendf(&g_out, "inter-migration interval us: p50=%.1f p99=%.1f min=%.1f (n=%zu)\n",
                  iq(0.50), iq(0.99), static_cast<double>(intervals_.front()) / 1000.0,
                  intervals_.size());
    }
    if (have_lane_) {
      uint64_t a = steal_mig_ + place_mig_;
      auto cad = [](std::vector<uint64_t>& v) {
        if (v.empty()) return 0.0;
        std::sort(v.begin(), v.end());
        return static_cast<double>(v[v.size() / 2]) / 1000.0;  // p50 us
      };
      montauk_sink_appendf(&g_out, "MIGRATION CAUSE (dispatch lane): STEAL (STEP-1) %.0f%% cadence p50 %.0fus  |  "
                  "PLACEMENT (own STEP-0 / select-enqueue) %.0f%% cadence p50 %.0fus\n",
                  a ? 100.0 * static_cast<double>(steal_mig_) / static_cast<double>(a) : 0.0, cad(steal_iv_),
                  a ? 100.0 * static_cast<double>(place_mig_) / static_cast<double>(a) : 0.0, cad(place_iv_));
      montauk_sink_appendf(&g_out, "  (match each cadence to a scheduler clock: ~codel_target -> CoDel relief/steal beat; "
                  "~wake rate -> warm-stay-release fan-out)\n");
    }
    // Monotonic from the first POPULATED tier: a structurally-empty FINER tier
    // (e.g. same-L2 on a no-SMT part, where no two cores share L2) is not scatter
    // -- it just doesn't exist on that hardware. Skip leading empties, then density
    // must be non-increasing with distance.
    bool mono = true;
    uint64_t prev = 0;
    bool seen = false;
    for (int t = 0; t < 4; t++) {
      if (!seen && tier_[t] == 0) continue;
      if (seen && tier_[t] > prev) {
        mono = false;
        break;
      }
      prev = tier_[t];
      seen = true;
    }
    double local_pct =
        100.0 * static_cast<double>(tier_[0] + tier_[1]) / static_cast<double>(cl);
    montauk_sink_appendf(&g_out, "VERDICT: %.1f%% of migrations stay cache-local (same-L2/L3); density %s\n\n",
                local_pct,
                mono ? "decays with distance (locality preserved)"
                     : "does NOT decay with distance (placement scatters across domains)");
  }

  void prom(std::vector<PromMetric>& out) override {
    const char* nm[4] = {"same_l2", "same_l3", "same_socket", "cross_socket"};
    for (int t = 0; t < 4; t++)
      out.push_back({"montauk_analysis_locality_tier_moves",
                     std::string("tier=\"") + nm[t] + "\"", static_cast<double>(tier_[t])});
    uint64_t cl = tier_[0] + tier_[1] + tier_[2] + tier_[3];
    out.push_back({"montauk_analysis_locality_local_pct", "",
                   cl ? 100.0 * static_cast<double>(tier_[0] + tier_[1]) / static_cast<double>(cl)
                      : 0.0});
    double span_s = (ts_max_ > ts_min_) ? static_cast<double>(ts_max_ - ts_min_) / 1e9 : 0.0;
    out.push_back({"montauk_analysis_locality_migration_rate_hz", "",
                   span_s > 0.0 ? static_cast<double>(migrations_) / span_s : 0.0});
    if (!intervals_.empty()) {
      std::sort(intervals_.begin(), intervals_.end());
      auto iq = [&](double p) {
        size_t i = static_cast<size_t>(p * static_cast<double>(intervals_.size() - 1));
        return static_cast<double>(intervals_[i]) / 1000.0;
      };
      out.push_back({"montauk_analysis_locality_intermigration_us", "quantile=\"p50\"", iq(0.50)});
      out.push_back({"montauk_analysis_locality_intermigration_us", "quantile=\"p99\"", iq(0.99)});
    }
  }
};

// REPORT classmix: absolute per-class distribution of ENQUEUEd tasks, from the
// frozen dispatch score (cls_weight in bits 48+). dispatch-stall gives class
// only RELATIVE to the wakee; this gives the absolute mix so "is a uniform
// worker pool getting split across classes" (cross-class starvation the warp
// cannot override, since class sits above it in the key) is answerable from
// data, not assumed. Built from the score montauk already parses; no new capture.
struct ClassMixReport final : Report {
  std::unordered_map<int, uint64_t> pid_cls_;          // pid -> last enqueue cls_weight
  std::unordered_map<uint64_t, uint64_t> enq_per_cls_; // cls_weight -> enqueue count
  const char* name() const override { return "classmix"; }
  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type != TRACE_EVT_SCHED || len < sizeof(montauk_sched_event)) return;
    const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
    if (s->op != SCHED_OP_ENQUEUE) return;
    uint64_t clsw = (uint64_t)s->score >> 48;   // frozen score: cls_weight<<48
    pid_cls_[s->pid] = clsw;
    enq_per_cls_[clsw]++;
  }
  void emit(const montauk::model::TraceReader&) override {
    header();
    if (pid_cls_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no ENQUEUE events\n\n");
      return;
    }
    std::map<uint64_t, uint64_t> distinct;   // cls_weight -> #distinct pids
    for (auto& kv : pid_cls_) distinct[kv.second]++;
    uint64_t tot = 0; for (auto& kv : enq_per_cls_) tot += kv.second;
    auto nm = [](uint64_t w) { return w >= 32 ? "LAT_CRITICAL" : w >= 8 ? "LATENCY"
                                    : w >= 4 ? "INTERACTIVE" : w >= 1 ? "BATCH" : "stalled/other"; };
    montauk_sink_appendf(&g_out,
                "VERDICT: %zu distinct enqueued pids; class mix (cls_weight in score bits 48+):\n",
                pid_cls_.size());
    for (auto& kv : distinct) {
      uint64_t w = kv.first;
      montauk_sink_appendf(&g_out,
                  "  cls_weight %-3llu %-13s : %5llu distinct pids, %8llu enqueues (%.1f%%)\n",
                  (unsigned long long)w, nm(w), (unsigned long long)kv.second,
                  (unsigned long long)enq_per_cls_[w],
                  tot ? 100.0 * (double)enq_per_cls_[w] / (double)tot : 0.0);
    }
    montauk_sink_appendf(&g_out,
                "  (a UNIFORM worker pool should sit in ONE class; many distinct pids "
                "across MULTIPLE classes = mis-classification -> cross-class starvation "
                "no within-class warp/age/svc lever can override)\n\n");
  }
};

// REPORT field-persist: an adaptive scheduler's structural-reclassification gate
// (SCHED_OP_FIELD_GATE) fires each time it re-evaluates its discrete workload
// classification (the "field"). This report answers whether that classification
// MOVES over the capture or is PINNED. A LATCHED classifier -- one signature held
// the whole run, however many times the gate fires -- cannot tell apart two
// operating states it committed between at start; that is the tell of a per-boot
// bistable scheduler whose scalar adaptive state reads identical in both basins.
// The gate's changed flag separates "fired but held" (persisted the prior class)
// from "fired and re-derived". Built purely from the gate stream; absent if the
// scheduler binds no field_gate tracepoint.
struct FieldPersistReport final : Report {
  struct G { uint64_t ts; uint64_t sig; uint32_t changed; };
  std::vector<G> gates_;
  size_t distinct_ = 0;
  uint64_t rederivations_ = 0;
  double dominant_dwell_pct_ = 0.0;

  const char* name() const override { return "field-persist"; }

  void fold(uint32_t type, const uint8_t* data, uint32_t len) override {
    if (type != TRACE_EVT_SCHED || len < sizeof(montauk_sched_event)) return;
    const auto* s = reinterpret_cast<const montauk_sched_event*>(data);
    if (s->op != SCHED_OP_FIELD_GATE) return;
    gates_.push_back({s->timestamp_ns, s->score, s->sub_idx});
  }

  void emit(const montauk::model::TraceReader&) override {
    header();
    if (gates_.empty()) {
      montauk_sink_appendf(&g_out, "VERDICT: no field-gate events (adaptive "
                  "reclassification gate not streamed)\n\n");
      return;
    }
    std::sort(gates_.begin(), gates_.end(),
              [](const G& a, const G& b) { return a.ts < b.ts; });
    // Dwell per signature = time to the next gate tick; distinct signatures and
    // re-derivations (changed flag) come from the same single pass.
    std::unordered_map<uint64_t, uint64_t> dwell, seen;
    uint64_t rederiv = 0;
    for (size_t i = 0; i < gates_.size(); ++i) {
      seen[gates_[i].sig]++;
      if (gates_[i].changed) ++rederiv;
      uint64_t next = (i + 1 < gates_.size()) ? gates_[i + 1].ts : gates_[i].ts;
      dwell[gates_[i].sig] += (next > gates_[i].ts) ? next - gates_[i].ts : 0;
    }
    uint64_t span = gates_.back().ts - gates_.front().ts;
    uint64_t dom_sig = gates_.front().sig, dom_dwell = 0;
    for (const auto& kv : dwell)
      if (kv.second > dom_dwell) { dom_dwell = kv.second; dom_sig = kv.first; }
    distinct_ = seen.size();
    rederivations_ = rederiv;
    dominant_dwell_pct_ = span ? 100.0 * (double)dom_dwell / (double)span : 100.0;
    double dur_s = span / 1e9;
    double rate = dur_s > 0 ? (double)gates_.size() / dur_s : 0.0;

    if (distinct_ <= 1) {
      montauk_sink_appendf(&g_out,
          "VERDICT: LATCHED -- %s gate fires over %.1fs (%.1f/s), signature PINNED at "
          "one value (0x%llx) the entire capture; %llu re-derivations. The gate never "
          "moved: the classifier committed at start and cannot distinguish two operating "
          "states that share this signature (the per-boot bistable tell -- a scalar "
          "regime/target reads identical in both basins).\n\n",
          fmt_count((double)gates_.size()).c_str(), dur_s, rate,
          (unsigned long long)dom_sig, (unsigned long long)rederivations_);
    } else {
      montauk_sink_appendf(&g_out,
          "VERDICT: LIVE -- %s gate fires over %.1fs (%.1f/s); %zu distinct signatures, "
          "%llu re-derivations; dominant signature 0x%llx held %.1f%% of the span\n"
          "  (many distinct + high re-derivation = the classifier tracks the workload; "
          "few distinct + a dominant near 100%% = it barely moves)\n\n",
          fmt_count((double)gates_.size()).c_str(), dur_s, rate, distinct_,
          (unsigned long long)rederivations_, (unsigned long long)dom_sig,
          dominant_dwell_pct_);
    }
  }

  void prom(std::vector<PromMetric>& out) override {
    if (gates_.empty()) return;
    out.push_back({"montauk_analysis_field_gate_fires", "", (double)gates_.size()});
    out.push_back({"montauk_analysis_field_distinct_signatures", "", (double)distinct_});
    out.push_back({"montauk_analysis_field_rederivations", "", (double)rederivations_});
    out.push_back({"montauk_analysis_field_dominant_dwell_pct", "", dominant_dwell_pct_});
  }

  void offenders(std::vector<Offender>& out) override {
    // A gate pinned to a single signature across a non-trivial run is a latched
    // classifier -- diagnostic-worthy on a workload that is not truly stationary.
    if (!gates_.empty() && distinct_ <= 1 && gates_.size() >= 4)
      out.push_back({"field-latched", "-", "", "distinct_signatures",
                     (double)distinct_, 2});
  }
};

std::vector<std::unique_ptr<Report>> make_reports() {
  std::vector<std::unique_ptr<Report>> reports;
  reports.push_back(std::make_unique<ClassMixReport>());
  reports.push_back(std::make_unique<FieldPersistReport>());
  reports.push_back(std::make_unique<LocalityReport>());
  reports.push_back(std::make_unique<SummaryReport>());
  reports.push_back(std::make_unique<IowaitReport>());
  reports.push_back(std::make_unique<SchedLatencyReport>());
  reports.push_back(std::make_unique<WorkConservationReport>());
  reports.push_back(std::make_unique<PlacementRaceReport>());
  reports.push_back(std::make_unique<DispatchStallReport>());
  reports.push_back(std::make_unique<KStrandReport>());
  reports.push_back(std::make_unique<SliceReport>());
  reports.push_back(std::make_unique<StormReport>());
  reports.push_back(std::make_unique<ServiceReport>());
  reports.push_back(std::make_unique<WakersReport>());
  reports.push_back(std::make_unique<WaitsReport>());
  reports.push_back(std::make_unique<SpinsReport>());
  reports.push_back(std::make_unique<PairingReport>());
  reports.push_back(std::make_unique<AbortPostmortemReport>());
  reports.push_back(std::make_unique<SignalsReport>());
  reports.push_back(std::make_unique<EndstateReport>());
  reports.push_back(std::make_unique<FutexReport>());
  reports.push_back(std::make_unique<KeyedEvtReport>());
  reports.push_back(std::make_unique<HeapstkReport>());
  reports.push_back(std::make_unique<DoubleFreeReport>());
  reports.push_back(std::make_unique<FractalReport>());
  return reports;
}

// Rank offenders by severity (then value) and print the POORLY-BEHAVING ITEMS
// table, appending the reusable montauk_offender{} family to prom. Shared by
// the full-report main() and the compact digest.
void rank_and_emit_offenders(std::vector<Offender>& offs,
                             std::vector<PromMetric>& prom) {
  if (offs.empty()) {
    montauk_sink_appendf(&g_out, "\nPOORLY-BEHAVING ITEMS: none detected\n");
    return;
  }
  std::sort(offs.begin(), offs.end(),
            [](const Offender& a, const Offender& b) {
              if (a.sev != b.sev) return a.sev > b.sev;
              return a.value > b.value;
            });
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

// Compact, specs-first report over a montauk --trace RECORDING DIR: SYSTEM
// specs (from the dir's scrapes), POORLY-BEHAVING ITEMS (offenders over the
// sibling .events), then KEY METRICS (the wake2run verdict). The single-call
// shareable digest; the dir is the one input, both halves read from it.
int run_digest(const std::string& dir, bool redact) {
  g_redact_comm = redact;
  std::string base = dir;
  while (!base.empty() && base.back() == '/') base.pop_back();
  std::string events = base + ".events";

  // The per-event .events sibling is optional: a .prom-only recording (e.g. a
  // system-metrics capture with no --trace-out) still has SYSTEM specs and the
  // THERMAL/POWER block worth reporting. Only the offenders and the wake2run
  // verdict need the event stream; degrade gracefully when it is absent.
  montauk::model::TraceReader reader;
  bool have_events =
      reader.open(events.c_str()) == montauk::model::TraceReadStatus::Ok;

  auto reports = make_reports();
  if (have_events) {
    (void)reader.for_each([&](uint32_t t, const uint8_t* d, uint32_t l) {
      for (auto& r : reports) r->fold(t, d, l);
    });
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
  rank_and_emit_offenders(offs, prom);

  if (have_events) {
    montauk_sink_appendf(&g_out, "\nKEY METRICS\n");
    for (auto& r : reports)
      if (std::string(r->name()) == "sched" ||
          std::string(r->name()) == "dispatch-stall" ||
          std::string(r->name()) == "kstrand") {
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
    log_warn("no per-event trace beside '%s' -- system metrics + offenders only "
             "(wake2run latency needs a --trace-out capture)", base.c_str());
    montauk_sink_appendf(&g_out, "\nKEY METRICS: not analyzed (no per-event trace)\n");
  }
  return 0;
}

} // namespace

#ifndef MONTAUK_VERSION
#define MONTAUK_VERSION "unknown"
#endif

int main(int argc, char** argv) {
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
        "usage: montauk_analyze TRACE [--report name[,name...]]\n"
        "                       [--sig N|NAME] [--comm SUBSTR] [--pid N] [--tid N]\n"
        "                       [--window SECONDS]\n"
        "                       (row qualifiers; consumed by per-event reports,\n"
        "                        currently: signals. --window bounds the trailing\n"
        "                        capture-teardown split, default 2s)\n"
        "       montauk_analyze DIR|FILE.prom [more.prom...] [--by axis]\n"
        "                       [--metric substr] [--full] [--higher-better]\n"
        "                       [--seed n] [--quantile q] [--no-emit]\n"
        "                       (axis: scheduler | version | commit | capture)\n"
        "       montauk_analyze RECORDING_DIR --digest [--redact]\n"
        "       montauk_analyze RECORDING_DIR --l2-by-cpu\n");
    return want_help ? 0 : 2;
  }
  const char* path = argv[1];

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
    if (is_dir || is_prom || has_group) {
      // Recording-dir modes (vs cross-run population stats):
      //   --digest    compact specs+offenders+aggregates report
      //   --l2-by-cpu per-CPU cache-miss localization
      bool want_digest = false, want_l2 = false, redact = false;
      for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--digest") want_digest = true;
        else if (a == "--l2-by-cpu") want_l2 = true;
        else if (a == "--redact") redact = true;
      }
      if (want_digest) return run_digest(path, redact);
      if (want_l2) return montauk::pop::run_l2_by_cpu(path);
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
        if (a == "--by" && i + 1 < argc) opt.compare_axis = argv[++i];
        else if (a == "--metric" && i + 1 < argc) opt.metric_filter = argv[++i];
        else if (a == "--full") opt.full = true;
        else if (a == "--higher-better") opt.lower_is_better = false;
        else if (a == "--no-emit") opt.emit_prom = false;
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

  auto reports = make_reports();

  std::vector<Report*> active;
  std::string report_list;
  for (int i = 2; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--redact") {
      g_redact_comm = true;
    } else if (a == "--report" && i + 1 < argc) {
      report_list = argv[++i];
    } else if (a == "--sig" && i + 1 < argc) {
      g_qual_sig = signal_nr_from(argv[++i]);
      if (g_qual_sig < 0) {
        log_error("--sig '%s' names no signal (number, SIGSEGV or SEGV)", argv[i]);
        return 2;
      }
    } else if (a == "--comm" && i + 1 < argc) {
      g_qual_comm = argv[++i];
    } else if (a == "--pid" && i + 1 < argc) {
      g_qual_pid = std::strtol(argv[++i], nullptr, 10);
    } else if (a == "--tid" && i + 1 < argc) {
      g_qual_tid = std::strtol(argv[++i], nullptr, 10);
    } else if (a == "--window" && i + 1 < argc) {
      g_qual_window_s = std::strtod(argv[++i], nullptr);
      if (g_qual_window_s < 0) {
        log_error("--window takes seconds >= 0, got '%s'", argv[i]);
        return 2;
      }
    } else {
      std::fprintf(stderr,
          "usage: montauk_analyze FILE [--report name[,name...]] [--redact]\n"
          "                       [--sig N|NAME] [--comm SUBSTR] [--pid N] [--tid N]\n"
          "                       [--window SECONDS]\n");
      return 2;
    }
  }
  if (report_list.empty()) {
    for (auto& r : reports) active.push_back(r.get());
  } else {
    size_t pos = 0;
    while (pos <= report_list.size()) {
      size_t comma = report_list.find(',', pos);
      if (comma == std::string::npos) comma = report_list.size();
      std::string want = report_list.substr(pos, comma - pos);
      pos = comma + 1;
      if (want.empty()) continue;
      Report* found = nullptr;
      for (auto& r : reports)
        if (want == r->name()) { found = r.get(); break; }
      if (!found) {
        std::string known;
        for (auto& r : reports) { known += " "; known += r->name(); }
        log_error("unknown report '%s' (known:%s)", want.c_str(), known.c_str());
        return 2;
      }
      if (std::find(active.begin(), active.end(), found) == active.end())
        active.push_back(found);
    }
  }

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

  const auto t0 = std::chrono::steady_clock::now();
  auto status = reader.for_each([&](uint32_t type, const uint8_t* data, uint32_t len) {
    for (Report* r : active) r->fold(type, data, len);
  });
  if (status == montauk::model::TraceReadStatus::CorruptLength) {
    log_warn("corrupt record length %u at event %" PRIu64 "; reporting on data read so far",
             reader.corrupt_len(), reader.events_read());
  } else if (status == montauk::model::TraceReadStatus::TruncatedRecord) {
    log_warn("truncated record at event %" PRIu64 "; reporting on data read so far",
             reader.events_read());
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

  // POORLY-BEHAVING ITEMS: consolidate every active report's offenders into one
  // severity-ranked view -- the "what specifically misbehaved" the report leads
  // with. Generic: each report contributed kind/id/metric/value/sev; we only
  // rank and emit the reusable montauk_offender{} family.
  {
    std::vector<Offender> offs;
    for (Report* r : active) r->offenders(offs);
    if (!offs.empty()) {
      std::sort(offs.begin(), offs.end(),
                [](const Offender& a, const Offender& b) {
                  if (a.sev != b.sev) return a.sev > b.sev;
                  return a.value > b.value;
                });
      montauk_sink_appendf(&g_out, "\nPOORLY-BEHAVING ITEMS (ranked)\n");
      montauk_sink_appendf(&g_out, "%-14s %-18s %-16s %14s  sev\n", "kind", "id", "metric", "value");
      for (const Offender& o : offs) {
        std::string idobj = o.obj.empty() ? o.id : (o.id + "/" + o.obj);
        const char* sv = o.sev >= 2 ? "HIGH" : (o.sev == 1 ? "MED" : "LOW");
        montauk_sink_appendf(&g_out, "%-14s %-18s %-16s %14.6g  %s\n", o.kind.c_str(),
                    idobj.c_str(), o.metric.c_str(), o.value, sv);
        std::string lab = "kind=\"" + o.kind + "\",id=\"" + o.id + "\"";
        if (!o.obj.empty()) lab += ",obj=\"" + o.obj + "\"";
        lab += ",metric=\"" + o.metric + "\",sev=\"" + std::to_string(o.sev) + "\"";
        prom.push_back({"montauk_offender", lab, o.value});
      }
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
