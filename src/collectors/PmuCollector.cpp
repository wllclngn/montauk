#include "collectors/PmuCollector.hpp"
#include "util/Log.hpp"
#include "util/Procfs.hpp"

#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace montauk::collectors {

// Raw syscall wrapper: glibc has no perf_event_open() symbol.
static long perf_event_open(struct perf_event_attr* attr, pid_t pid, int cpu,
                            int group_fd, unsigned long flags) {
  return ::syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

// SYSFS HELPERS

static bool read_sysfs_str(const std::string& path, std::string& out) {
  auto s = montauk::util::read_file_string(path);
  if (!s) return false;
  out = *s;
  // sysfs attrs are one line; drop anything past it, then trailing
  // whitespace/newline.
  auto nl = out.find('\n');
  if (nl != std::string::npos) out.erase(nl);
  while (!out.empty() && (out.back() == '\n' || out.back() == '\r' ||
                          out.back() == ' ' || out.back() == '\t'))
    out.pop_back();
  return true;
}

static bool read_sysfs_u32(const std::string& path, uint32_t& out) {
  std::string s;
  if (!read_sysfs_str(path, s) || s.empty()) return false;
  out = static_cast<uint32_t>(std::strtoul(s.c_str(), nullptr, 0));
  return true;
}

// Parse a Linux cpumask/cpu-list string ("0-11" or "0,6" or "0") into ids.
static std::vector<int> parse_cpu_list(const std::string& s) {
  std::vector<int> out;
  size_t i = 0;
  while (i < s.size()) {
    while (i < s.size() && (s[i] == ',' || s[i] == ' ')) ++i;
    if (i >= s.size()) break;
    long a = std::strtol(s.c_str() + i, nullptr, 10);
    while (i < s.size() && s[i] != ',' && s[i] != '-') ++i;
    long b = a;
    if (i < s.size() && s[i] == '-') {
      ++i;
      b = std::strtol(s.c_str() + i, nullptr, 10);
      while (i < s.size() && s[i] != ',') ++i;
    }
    for (long c = a; c <= b; ++c) out.push_back(static_cast<int>(c));
  }
  return out;
}

// AMD_L3 DYNAMIC EVENT ENCODING
//
// The amd_l3 uncore PMU describes its config layout entirely in sysfs and the
// exact event/umask values differ across kernels, so nothing here is
// hardcoded except the documented Zen2 fallback (event=0x04, umask=0xff =
// "all L3 accesses"). We parse:
//   format/<name>  -> "config:LO-HI"  (which bits of attr.config a term sets)
//   events/<name>  -> "term=val,term=val,..." (e.g. "event=0x04,umask=0xff")
// and OR (val << LO) into attr.config for each term.

struct L3Format {
  std::string name; // term name, e.g. "event", "umask"
  int lo{0};
  int hi{0};
};

// List every file under format/ and parse its "config:LO-HI" bitfield spec.
static std::vector<L3Format> read_l3_formats(const std::string& l3_dir) {
  std::vector<L3Format> fmts;
  std::string fmt_dir = l3_dir + "/format";
  for (const auto& name : montauk::util::list_dir(fmt_dir)) {
    std::string spec;
    if (!read_sysfs_str(fmt_dir + "/" + name, spec)) continue;
    // spec looks like "config:0-7" or "config:8" (single bit).
    auto colon = spec.find(':');
    if (colon == std::string::npos) continue;
    // We only handle the "config" word (amd_l3 events live entirely in config).
    if (spec.compare(0, colon, "config") != 0) continue;
    std::string bits = spec.substr(colon + 1);
    int lo = 0, hi = 0;
    auto dash = bits.find('-');
    if (dash == std::string::npos) {
      lo = hi = std::atoi(bits.c_str());
    } else {
      lo = std::atoi(bits.c_str());
      hi = std::atoi(bits.c_str() + dash + 1);
    }
    fmts.push_back(L3Format{name, lo, hi});
  }
  return fmts;
}

// Encode an event spec string ("event=0x04,umask=0xff,...") into attr.config
// by mapping each term name to its format bitfield and OR-ing value<<lo.
static uint64_t encode_l3_event(const std::string& spec,
                                const std::vector<L3Format>& fmts) {
  uint64_t config = 0;
  std::stringstream ss(spec);
  std::string term;
  while (std::getline(ss, term, ',')) {
    auto eq = term.find('=');
    if (eq == std::string::npos) continue;
    std::string name = term.substr(0, eq);
    uint64_t val = std::strtoull(term.c_str() + eq + 1, nullptr, 0);
    for (const auto& f : fmts) {
      if (f.name == name) {
        config |= (val << f.lo);
        break;
      }
    }
  }
  return config;
}

// Enumerate events/ and pick (access, miss) configs by substring match.
// Returns true if at least an access config was resolved.
struct L3Events {
  bool     have_access{false};
  bool     have_miss{false};
  uint64_t access_config{0};
  uint64_t miss_config{0};
};

static L3Events resolve_l3_events(const std::string& l3_dir,
                                  const std::vector<L3Format>& fmts) {
  L3Events ev{};
  std::string ev_dir = l3_dir + "/events";
  for (const auto& name : montauk::util::list_dir(ev_dir)) {
    // amd_l3 typically exposes names like:
    //   "l3_lookup_state.all_l3_req"  (accesses / lookups)
    //   "l3_comb_clstr_state.request_miss" (L3 misses)
    // but exact names vary by kernel, so match by substring.
    std::string lname = name;
    for (auto& ch : lname) ch = static_cast<char>(::tolower(ch));
    std::string spec;
    if (!read_sysfs_str(ev_dir + "/" + name, spec)) continue;
    uint64_t cfg = encode_l3_event(spec, fmts);
    if (lname.find("miss") != std::string::npos) {
      if (!ev.have_miss) { ev.miss_config = cfg; ev.have_miss = true; }
    } else if (lname.find("access") != std::string::npos ||
               lname.find("lookup") != std::string::npos ||
               lname.find("req") != std::string::npos) {
      if (!ev.have_access) { ev.access_config = cfg; ev.have_access = true; }
    }
  }
  // Documented Zen2 fallback for accesses: event=0x04, umask=0xff (all L3
  // requests). Encode it through the same format mapping so bit positions
  // remain correct.
  if (!ev.have_access && !fmts.empty()) {
    ev.access_config = encode_l3_event("event=0x04,umask=0xff", fmts);
    ev.have_access = true;
  }
  return ev;
}

// COLLECTOR

PmuCollector::~PmuCollector() { close_all(); }

int PmuCollector::open_one(uint32_t type, uint64_t config, int cpu) {
  struct perf_event_attr attr{};
  attr.size = sizeof(attr);
  attr.type = type;
  attr.config = config;
  attr.disabled = 1;      // enabled explicitly after all opens
  attr.exclude_hv = 1;
  attr.exclude_idle = 0;
  attr.inherit = 0;       // system-wide per-cpu cannot inherit
  // No PERF_FORMAT_* flags: read() yields a bare u64 count.
  long fd = perf_event_open(&attr, /*pid*/ -1, cpu, /*group_fd*/ -1, /*flags*/ 0);
  if (fd < 0) {
    if (first_open_errno_ == 0) first_open_errno_ = errno;
    return -1;
  }
  return static_cast<int>(fd);
}

// HW_CACHE events pack (cache-id, op, result) into config. dTLB read misses is
// the one that answers "is this workload thrashing address translation", which
// no existing montauk counter could distinguish from "the data is not resident".
static constexpr uint64_t kDtlbLoadMissConfig =
    static_cast<uint64_t>(PERF_COUNT_HW_CACHE_DTLB) |
    (static_cast<uint64_t>(PERF_COUNT_HW_CACHE_OP_READ) << 8) |
    (static_cast<uint64_t>(PERF_COUNT_HW_CACHE_RESULT_MISS) << 16);

int PmuCollector::open_one_proc(uint32_t type, uint64_t config, int pid) {
  struct perf_event_attr attr{};
  attr.size = sizeof(attr);
  attr.type = type;
  attr.config = config;
  attr.disabled = 1;
  attr.exclude_hv = 1;
  attr.exclude_idle = 0;
  // Follow threads and children created after the attach. This is what makes
  // one fd per process sufficient for a thread-pool workload instead of one fd
  // per thread; it does NOT retroactively cover threads that already existed,
  // which is why the attach wants to happen before the pool spawns.
  attr.inherit = 1;
  // Own-process measurement: pid >= 0 with cpu == -1 is the form paranoid 2
  // permits without CAP_PERFMON.
  //
  // TWO ATTEMPTS, AND THE SECOND IS THE ONE THAT WORKS ON A DEFAULT BOX.
  // paranoid 2 forbids KERNEL profiling, so an otherwise-permitted per-process
  // open is still denied with EACCES unless exclude_kernel is set -- which is
  // why the first cut of this looked like a root problem and was not. Try the
  // richer form first so a privileged box counts kernel time too, then fall
  // back to user-space-only. exclude_kernel is recorded on the collector so the
  // renderer can state which one is in force: user-space-only counts are the
  // right measure for a compute kernel and the wrong one for a syscall-bound
  // workload, and a consumer must not have to guess which it is holding.
  long fd = perf_event_open(&attr, pid, /*cpu*/ -1, /*group_fd*/ -1, /*flags*/ 0);
  if (fd < 0 && (errno == EACCES || errno == EPERM)) {
    attr.exclude_kernel = 1;
    fd = perf_event_open(&attr, pid, /*cpu*/ -1, /*group_fd*/ -1, /*flags*/ 0);
    if (fd >= 0) proc_user_only_ = true;
  }
  if (fd < 0) {
    if (first_proc_errno_ == 0) first_proc_errno_ = errno;
    return -1;
  }
  return static_cast<int>(fd);
}

void PmuCollector::set_process_targets(
    const std::vector<std::pair<int, std::string>>& targets) {
  auto cl = [](Counter& c) { if (c.fd >= 0) { ::close(c.fd); c.fd = -1; } };

  // Drop attachments whose pid is no longer selected. Their totals go with
  // them: a total is "since attach", and a pid that left and came back is a
  // different process even if the number is reused.
  for (size_t i = 0; i < procs_.size();) {
    bool keep = false;
    for (const auto& t : targets) if (t.first == procs_[i].pid) { keep = true; break; }
    if (keep) { ++i; continue; }
    cl(procs_[i].instr); cl(procs_[i].cycles);
    cl(procs_[i].dtlb); cl(procs_[i].cachemiss);
    procs_.erase(procs_.begin() + static_cast<long>(i));
  }

  for (const auto& t : targets) {
    bool have = false;
    for (auto& p : procs_) if (p.pid == t.first) { have = true; break; }
    if (have) continue;
    ProcTarget p{};
    p.pid = t.first;
    p.comm = t.second;
    int fi = open_one_proc(PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS, p.pid);
    if (fi < 0) {
      // One line, once. A denied per-process open at paranoid 2 means the pid
      // is not ours (or is gone); spamming it per tick would bury the log.
      if (!proc_warned_) {
        proc_warned_ = true;
        montauk::util::log_warn(
            "per-process perf_event_open failed for pid %d (errno=%d %s); "
            "per-process PMU unavailable for it. Own-user processes need no "
            "privilege; another user's do.",
            p.pid, first_proc_errno_, std::strerror(first_proc_errno_));
      }
      continue;
    }
    p.instr = Counter{fi, -1, 0, false};
    int fc = open_one_proc(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, p.pid);
    if (fc >= 0) p.cycles = Counter{fc, -1, 0, false};
    int fd = open_one_proc(PERF_TYPE_HW_CACHE, kDtlbLoadMissConfig, p.pid);
    if (fd >= 0) p.dtlb = Counter{fd, -1, 0, false};
    int fm = open_one_proc(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES, p.pid);
    if (fm >= 0) p.cachemiss = Counter{fm, -1, 0, false};
    auto enable = [](Counter& c) {
      if (c.fd >= 0) {
        ::ioctl(c.fd, PERF_EVENT_IOC_RESET, 0);
        ::ioctl(c.fd, PERF_EVENT_IOC_ENABLE, 0);
      }
    };
    enable(p.instr); enable(p.cycles); enable(p.dtlb); enable(p.cachemiss);
    procs_.push_back(std::move(p));
    proc_available_ = true;
  }
  if (procs_.empty()) proc_available_ = false;
}

void PmuCollector::init() {
  initialized_ = true;

  // Core PMU: read the dynamic type (4 on x86, but never hardcode).
  uint32_t cpu_type = 0;
  if (!read_sysfs_u32("/sys/bus/event_source/devices/cpu/type", cpu_type)) {
    montauk::util::log_error("core PMU type unavailable; disabling PMU collector");
    available_ = false;
    return;
  }

  // Online logical CPUs.
  std::string online;
  read_sysfs_str("/sys/devices/system/cpu/online", online);
  std::vector<int> cpus = parse_cpu_list(online);
  if (cpus.empty()) {
    available_ = false;
    return;
  }

  // Cache miss/reference event encodings. perf_event_open(PERF_TYPE_RAW)
  // accepts ANY config and silently counts zero on an encoding the running
  // uarch does not implement -- so a hardcoded raw value that is wrong for the
  // hardware (the previous 0x077e/0x077d "L2 raw events" read 0 forever on
  // family 17h) is worse than useless: it looks live but never counts. Resolve
  // the authoritative per-box encoding from sysfs instead, exactly like the
  // amd_l3 path: the kernel publishes events/cache-{misses,references} and the
  // format/ bitfield map. On AMD these aliases ARE the L2-unit events
  // (cache-misses = event=0x64,umask=0x09 = l2_cache_req_stat misses;
  // cache-references = event=0x60,umask=0xff = l2_request_g1 all). Fall back to
  // the family-17h raw encodings only if the sysfs aliases are absent.
  const std::string cpu_dir = "/sys/bus/event_source/devices/cpu";
  std::vector<L3Format> cpu_fmts = read_l3_formats(cpu_dir);
  uint64_t kL2MissConfig = 0x0964;  // event=0x64,umask=0x09
  uint64_t kL2RefConfig  = 0xff60;  // event=0x60,umask=0xff
  std::string miss_spec, ref_spec;
  if (!cpu_fmts.empty()) {
    if (read_sysfs_str(cpu_dir + "/events/cache-misses", miss_spec))
      kL2MissConfig = encode_l3_event(miss_spec, cpu_fmts);
    if (read_sysfs_str(cpu_dir + "/events/cache-references", ref_spec))
      kL2RefConfig = encode_l3_event(ref_spec, cpu_fmts);
  }

  for (int cpu : cpus) {
    int fd_m = open_one(PERF_TYPE_RAW, kL2MissConfig, cpu);
    int fd_r = open_one(PERF_TYPE_RAW, kL2RefConfig, cpu);
    int fd_i = open_one(PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS, cpu);
    int fd_c = open_one(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, cpu);
    // If any of the core opens fails on the very first cpu, bail entirely:
    // it is almost certainly a permission/support problem, not transient.
    if (fd_m < 0 || fd_r < 0 || fd_i < 0 || fd_c < 0) {
      if (fd_m >= 0) ::close(fd_m);
      if (fd_r >= 0) ::close(fd_r);
      if (fd_i >= 0) ::close(fd_i);
      if (fd_c >= 0) ::close(fd_c);
      close_all();
      available_ = false;
      // System-wide per-CPU opens (pid=-1, cpu=N) require paranoid < 1 —
      // i.e. 0 or -1 — or CAP_PERFMON. paranoid=1 only permits own-process
      // measurement and would still fail here.
      montauk::util::log_warn(
                   "perf_event_open denied (errno=%d %s); PMU disabled. "
                   "Need perf_event_paranoid<=0 or CAP_PERFMON.",
                   first_open_errno_, std::strerror(first_open_errno_));
      return;
    }
    l2_miss_.push_back(Counter{fd_m, cpu, 0, false});
    l2_ref_.push_back(Counter{fd_r, cpu, 0, false});
    instr_.push_back(Counter{fd_i, cpu, 0, false});
    cycles_.push_back(Counter{fd_c, cpu, 0, false});
    // Best-effort scheduler counters: do NOT bail the core PMU if these fail
    // (fd -1 just reads 0). SW ctx-switch/migrations always open; HW branch
    // miss is standard on x86.
    ctxsw_.push_back(Counter{
        open_one(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES, cpu),
        cpu, 0, false});
    migr_.push_back(Counter{
        open_one(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_MIGRATIONS, cpu),
        cpu, 0, false});
    branch_.push_back(Counter{
        open_one(PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES, cpu),
        cpu, 0, false});
    dtlb_.push_back(Counter{
        open_one(PERF_TYPE_HW_CACHE, kDtlbLoadMissConfig, cpu), cpu, 0, false});
    cachemiss_.push_back(Counter{
        open_one(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES, cpu),
        cpu, 0, false});
  }
  available_ = true;

  // amd_l3 uncore PMU: optional. Degrade cleanly if the amd_uncore module is
  // not loaded (directory absent).
  const std::string l3_dir = "/sys/bus/event_source/devices/amd_l3";
  uint32_t l3_type = 0;
  if (read_sysfs_u32(l3_dir + "/type", l3_type)) {
    std::vector<L3Format> fmts = read_l3_formats(l3_dir);
    L3Events ev = resolve_l3_events(l3_dir, fmts);
    std::string cpumask;
    read_sysfs_str(l3_dir + "/cpumask", cpumask);
    std::vector<int> l3_cpus = parse_cpu_list(cpumask);
    if (ev.have_access && !l3_cpus.empty()) {
      for (int cpu : l3_cpus) {
        L3Domain dom{};
        dom.domain_cpu = cpu;
        int af = open_one(l3_type, ev.access_config, cpu);
        if (af >= 0) dom.access = Counter{af, cpu, 0, false};
        if (ev.have_miss) {
          int mf = open_one(l3_type, ev.miss_config, cpu);
          if (mf >= 0) dom.miss = Counter{mf, cpu, 0, false};
        }
        if (dom.access.fd >= 0) l3_.push_back(dom);
      }
      l3_available_ = !l3_.empty();
    }
  }
  // amd_l3 absent -> l3_available_ stays false; this is normal & non-fatal.

  // Reset + enable every successfully opened fd.
  auto enable = [](Counter& c) {
    if (c.fd >= 0) {
      ::ioctl(c.fd, PERF_EVENT_IOC_RESET, 0);
      ::ioctl(c.fd, PERF_EVENT_IOC_ENABLE, 0);
    }
  };
  for (auto& c : l2_miss_) enable(c);
  for (auto& c : l2_ref_)  enable(c);
  for (auto& c : instr_)   enable(c);
  for (auto& c : cycles_)  enable(c);
  for (auto& c : ctxsw_)   enable(c);
  for (auto& c : migr_)    enable(c);
  for (auto& c : branch_)  enable(c);
  for (auto& c : dtlb_)    enable(c);
  for (auto& c : cachemiss_) enable(c);
  for (auto& d : l3_) { enable(d.access); enable(d.miss); }
}

void PmuCollector::close_all() {
  auto cl = [](Counter& c) { if (c.fd >= 0) { ::close(c.fd); c.fd = -1; } };
  for (auto& c : l2_miss_) cl(c);
  for (auto& c : l2_ref_)  cl(c);
  for (auto& c : instr_)   cl(c);
  for (auto& c : cycles_)  cl(c);
  for (auto& c : ctxsw_)   cl(c);
  for (auto& c : migr_)    cl(c);
  for (auto& c : branch_)  cl(c);
  for (auto& c : dtlb_)    cl(c);
  for (auto& c : cachemiss_) cl(c);
  for (auto& d : l3_) { cl(d.access); cl(d.miss); }
  for (auto& p : procs_) { cl(p.instr); cl(p.cycles); cl(p.dtlb); cl(p.cachemiss); }
  l2_miss_.clear(); l2_ref_.clear(); instr_.clear(); cycles_.clear();
  ctxsw_.clear(); migr_.clear(); branch_.clear();
  dtlb_.clear(); cachemiss_.clear(); procs_.clear();
  l3_.clear();
}

uint64_t PmuCollector::read_delta(Counter& c) {
  // Reads the raw counter value only (default perf read format). It does NOT
  // request PERF_FORMAT_TOTAL_TIME_ENABLED/RUNNING, so when more events are
  // programmed than the hardware has counters and the kernel multiplexes them,
  // the value is the un-rescaled running count and under-reports by
  // time_running/time_enabled. Correcting it means the scaled read format plus a
  // per-counter rescale; deferred until a consumer needs multiplex-accurate PMU.
  if (c.fd < 0) return 0;
  uint64_t val = 0;
  ssize_t n = ::read(c.fd, &val, sizeof(val));
  if (n != static_cast<ssize_t>(sizeof(val))) return 0;
  uint64_t delta = 0;
  if (c.has_last && val >= c.last) delta = val - c.last;
  c.last = val;
  c.has_last = true;
  return delta;
}

// Per-process fill. Deliberately runs BEFORE the per-CPU availability gate:
// the two paths have different permission requirements, and coupling them is
// what would leave a default box (paranoid 2) with no PMU attribution at all
// even though the per-process form is permitted there.
void PmuCollector::fill_per_process(montauk::model::PmuSnapshot& out) {
  out.per_process.clear();
  out.per_process_available = proc_available_;
  out.per_process_user_only = proc_user_only_;
  if (!proc_available_) return;
  for (auto& p : procs_) {
    montauk::model::PmuSnapshot::ProcCounters c{};
    c.pid = p.pid;
    std::snprintf(c.comm, sizeof c.comm, "%s", p.comm.c_str());
    c.instructions     = read_delta(p.instr);
    c.cycles           = read_delta(p.cycles);
    c.dtlb_load_misses = read_delta(p.dtlb);
    c.cache_misses     = read_delta(p.cachemiss);
    p.total_instr     += c.instructions;
    p.total_cycles    += c.cycles;
    p.total_dtlb      += c.dtlb_load_misses;
    p.total_cachemiss += c.cache_misses;
    c.instructions_total     = p.total_instr;
    c.cycles_total           = p.total_cycles;
    c.dtlb_load_misses_total = p.total_dtlb;
    c.cache_misses_total     = p.total_cachemiss;
    c.ipc = c.cycles > 0 ? (double)c.instructions / (double)c.cycles : 0.0;
    // Per thousand instructions, from the TOTALS rather than the interval:
    // the scale-free form, so a 2-second window and a 40-second run over the
    // same workload are directly comparable, and a quiet interval does not
    // read as a different workload.
    const double ki = (double)p.total_instr / 1000.0;
    c.dtlb_misses_per_kilo_instr =
        ki > 0.0 ? (double)p.total_dtlb / ki : 0.0;
    c.cache_misses_per_kilo_instr =
        ki > 0.0 ? (double)p.total_cachemiss / ki : 0.0;
    out.per_process.push_back(c);
  }
}

bool PmuCollector::sample(montauk::model::PmuSnapshot& out) {
  if (!initialized_) init();
  fill_per_process(out);
  if (!available_) {
    out.available = false;
    out.l3_available = false;
    // Per-process may still have filled above; that is the point of the split.
    return out.per_process_available;
  }

  auto now = std::chrono::steady_clock::now();
  double interval_s = 0.0;
  if (has_last_time_) {
    interval_s = std::chrono::duration<double>(now - last_sample_time_).count();
  }
  last_sample_time_ = now;
  has_last_time_ = true;

  out.available = true;
  out.l3_available = l3_available_;
  out.nr_cpus = static_cast<int>(l2_miss_.size());
  out.interval_s = interval_s;

  const size_t n = l2_miss_.size();
  out.per_cpu_ids.assign(n, 0);
  out.per_cpu_l2_misses.assign(n, 0);
  out.per_cpu_l2_refs.assign(n, 0);
  out.per_cpu_instructions.assign(n, 0);
  out.per_cpu_cycles.assign(n, 0);

  uint64_t agg_miss = 0, agg_ref = 0, agg_instr = 0, agg_cyc = 0;
  uint64_t agg_cs = 0, agg_mig = 0, agg_br = 0, agg_dtlb = 0, agg_cm = 0;
  for (size_t i = 0; i < n; ++i) {
    uint64_t dm = read_delta(l2_miss_[i]);
    uint64_t dr = read_delta(l2_ref_[i]);
    uint64_t di = read_delta(instr_[i]);
    uint64_t dc = read_delta(cycles_[i]);
    out.per_cpu_ids[i]          = l2_miss_[i].cpu;
    out.per_cpu_l2_misses[i]    = dm;
    out.per_cpu_l2_refs[i]      = dr;
    out.per_cpu_instructions[i] = di;
    out.per_cpu_cycles[i]       = dc;
    agg_miss += dm; agg_ref += dr; agg_instr += di; agg_cyc += dc;
    if (i < ctxsw_.size())  agg_cs  += read_delta(ctxsw_[i]);
    if (i < migr_.size())   agg_mig += read_delta(migr_[i]);
    if (i < branch_.size()) agg_br  += read_delta(branch_[i]);
    if (i < dtlb_.size())   agg_dtlb += read_delta(dtlb_[i]);
    if (i < cachemiss_.size()) agg_cm += read_delta(cachemiss_[i]);
  }
  out.l2_misses    = agg_miss;
  out.l2_refs      = agg_ref;
  out.instructions = agg_instr;
  out.cycles       = agg_cyc;
  out.context_switches = agg_cs;
  out.cpu_migrations   = agg_mig;
  out.branch_misses    = agg_br;
  out.dtlb_load_misses = agg_dtlb;
  out.cache_misses     = agg_cm;

  // The cumulative half. read_delta drops the very first sample per counter
  // (nothing to subtract from yet), so these run from montauk's first complete
  // interval rather than from the perf_event_open -- which is the semantic a
  // baseline wants anyway: what happened while montauk was watching.
  total_instructions_     += agg_instr;
  total_cycles_           += agg_cyc;
  total_context_switches_ += agg_cs;
  total_cpu_migrations_   += agg_mig;
  total_branch_misses_    += agg_br;
  total_l2_misses_        += agg_miss;
  total_dtlb_             += agg_dtlb;
  total_cache_misses_     += agg_cm;
  out.instructions_total     = total_instructions_;
  out.cycles_total           = total_cycles_;
  out.context_switches_total = total_context_switches_;
  out.cpu_migrations_total   = total_cpu_migrations_;
  out.branch_misses_total    = total_branch_misses_;
  out.l2_misses_total        = total_l2_misses_;
  out.dtlb_load_misses_total = total_dtlb_;
  out.cache_misses_total     = total_cache_misses_;

  out.ipc = (agg_cyc > 0) ? (double)agg_instr / (double)agg_cyc : 0.0;
  out.l2_miss_pct = (agg_ref > 0)
                        ? 100.0 * (double)agg_miss / (double)agg_ref : 0.0;
  out.cycles_per_l2_miss = (agg_miss > 0)
                        ? (double)agg_cyc / (double)agg_miss : 0.0;

  if (interval_s > 0.0) {
    out.instructions_per_sec = (double)agg_instr / interval_s;
    out.cycles_per_sec       = (double)agg_cyc   / interval_s;
    out.l2_misses_per_sec    = (double)agg_miss  / interval_s;
    out.context_switches_per_sec = (double)agg_cs  / interval_s;
    out.cpu_migrations_per_sec   = (double)agg_mig / interval_s;
    out.branch_misses_per_sec    = (double)agg_br  / interval_s;
  } else {
    out.instructions_per_sec = 0.0;
    out.cycles_per_sec = 0.0;
    out.l2_misses_per_sec = 0.0;
    out.context_switches_per_sec = 0.0;
    out.cpu_migrations_per_sec = 0.0;
    out.branch_misses_per_sec = 0.0;
  }

  // Per-cache domain L3: keep per-domain (do NOT collapse) so cross-domain traffic shows.
  out.l3_per_cache_domain.clear();
  out.l3_accesses_total = 0;
  out.l3_misses_total = 0;
  if (l3_available_) {
    out.l3_per_cache_domain.reserve(l3_.size());
    for (auto& d : l3_) {
      uint64_t da = read_delta(d.access);
      uint64_t dm = (d.miss.fd >= 0) ? read_delta(d.miss) : 0;
      montauk::model::PmuSnapshot::DomainL3 c{};
      c.domain_cpu = d.domain_cpu;
      c.accesses   = da;
      c.misses     = dm;
      c.miss_pct   = (da > 0) ? 100.0 * (double)dm / (double)da : 0.0;
      out.l3_per_cache_domain.push_back(c);
      out.l3_accesses_total += da;
      out.l3_misses_total   += dm;
    }
  }

  return true;
}

} // namespace montauk::collectors
