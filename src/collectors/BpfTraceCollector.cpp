#include "collectors/BpfTraceCollector.hpp"
#include "montauk_trace.h"
#include "model/TraceBinary.hpp"
#include "app/MetricsServer.hpp"
#include "util/Log.hpp"
#include "util/Procfs.hpp"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include "montauk_trace.skel.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <charconv>
#include <ctime>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <cerrno>
#include <filesystem>
#include <string>
#include <map>

namespace {
// Flush the binary trace buffer once it crosses this size — one write()
// per ~256 KB instead of per event.
constexpr size_t kTraceFlushThreshold = 256 * 1024;

// Read a /sys attribute (one line, sysfs-root-aware via util::Procfs) and
// return just its first line, trimmed. Empty string if unreadable.
std::string read_sys_line(const std::string& path) {
  auto s = montauk::util::read_file_string(path);
  if (!s) return {};
  auto nl = s->find('\n');
  if (nl != std::string::npos) s->erase(nl);
  return *s;
}

// Build cpu -> cache domain/L3-domain id from sysfs and push it into the BPF cpu_cache_domain map.
// CPUs sharing an L3 (one cache domain) get the same id; a monolithic single-L3 part maps
// every CPU to 0. Same grouping the scheduler's own topology layer derives, so
// sched_switch can classify each migration as intra- vs cross-domain.
void populate_cache_domain_map(int map_fd) {
  if (map_fd < 0) return;
  int ncpu = libbpf_num_possible_cpus();
  if (ncpu <= 0) ncpu = 1;
  if (ncpu > TRACE_MAX_CPUS) ncpu = TRACE_MAX_CPUS;
  std::map<std::string, uint32_t> list_to_domain;
  uint32_t next_domain = 0;
  for (int cpu = 0; cpu < ncpu; ++cpu) {
    char path[128];
    std::snprintf(path, sizeof(path),
        "/sys/devices/system/cpu/cpu%d/cache/index3/shared_cpu_list", cpu);
    std::string list = read_sys_line(path);
    uint32_t domain;
    if (list.empty()) {
      domain = 0;  // no L3 info (monolithic / offline) -> single domain
    } else {
      auto it = list_to_domain.find(list);
      if (it == list_to_domain.end()) { domain = next_domain++; list_to_domain[list] = domain; }
      else domain = it->second;
    }
    uint32_t key = static_cast<uint32_t>(cpu);
    bpf_map_update_elem(map_fd, &key, &domain, BPF_ANY);
  }
  montauk::util::log_info("cpu_cache_domain populated (%d cpus, %zu cache domains)",
               ncpu, list_to_domain.empty() ? size_t{1} : list_to_domain.size());
}
}

namespace montauk::collectors {

// Syscall decode table (x86_64, curated)
const char* BpfTraceCollector::syscall_name(int nr) {
  switch (nr) {
    case 0:   return "read";
    case 1:   return "write";
    case 2:   return "open";
    case 3:   return "close";
    case 7:   return "poll";
    case 8:   return "lseek";
    case 9:   return "mmap";
    case 10:  return "mprotect";
    case 11:  return "munmap";
    case 16:  return "ioctl";
    case 17:  return "pread64";
    case 18:  return "pwrite64";
    case 23:  return "select";
    case 35:  return "nanosleep";
    case 44:  return "sendto";
    case 45:  return "recvfrom";
    case 46:  return "sendmsg";
    case 47:  return "recvmsg";
    case 48:  return "shutdown";
    case 56:  return "clone";
    case 59:  return "execve";
    case 61:  return "wait4";
    case 62:  return "kill";
    case 202: return "futex";
    case 228: return "clock_nanosleep";
    case 232: return "epoll_wait";
    case 257: return "openat";
    case 270: return "pselect6";
    case 271: return "ppoll";
    case 281: return "epoll_pwait";
    case 290: return "eventfd2";
    case 302: return "prlimit64";
    case 332: return "statx";
    case 426: return "io_uring_enter";
    case 435: return "clone3";
    case 441: return "epoll_pwait2";
    default:  return nullptr;
  }
}

// Constructor / lifecycle
BpfTraceCollector::BpfTraceCollector(montauk::app::TraceBuffers& buffers,
                                     std::string pattern)
    : buffers_(buffers), pattern_(std::move(pattern)) {
  // --trace accepts a comma-separated list of comm substrings (e.g.
  // "gameserver,physicsd") — match if ANY token matches. The first token
  // is the primary: written to the BPF .rodata fast-path for instant exec-time
  // tracking. The rest are matched only by the userspace rescan (sub-second),
  // which is sufficient for long-lived processes already running before
  // montauk attaches (instant exec capture is moot for them).
  size_t start = 0;
  while (start <= pattern_.size()) {
    size_t comma = pattern_.find(',', start);
    if (comma == std::string::npos) comma = pattern_.size();
    std::string tok = pattern_.substr(start, comma - start);
    size_t b = tok.find_first_not_of(" \t");
    size_t e = tok.find_last_not_of(" \t");
    if (b != std::string::npos) {
      tok = tok.substr(b, e - b + 1);
      if (!tok.empty()) {
        if (primary_pattern_.empty()) primary_pattern_ = tok;
        matchers_.emplace_back(tok);
      }
    }
    start = comma + 1;
  }
  if (matchers_.empty()) {  // no usable token — fall back to the whole string
    primary_pattern_ = pattern_;
    matchers_.emplace_back(pattern_);
  }
}

bool BpfTraceCollector::matches_any(const std::string& s) const {
  for (const auto& m : matchers_)
    if (m.search(s) >= 0) return true;
  return false;
}

BpfTraceCollector::~BpfTraceCollector() {
  stop();
  if (rb_)
    ring_buffer__free(rb_);
  if (enroll_iter_link_)
    bpf_link__destroy(enroll_iter_link_);
  if (skel_)
    montauk_trace_bpf__destroy(skel_);
}

void BpfTraceCollector::start() {
  thread_ = std::jthread([this](std::stop_token st) { run(st); });
}

void BpfTraceCollector::stop() {
  if (thread_.joinable()) {
    thread_.request_stop();
    thread_.join();
  }
  // Final flush + close after the collector thread is joined, so no
  // concurrent appends race the close.
  if (trace_fd_ >= 0 || stream_fd_ >= 0) trace_flush();
  if (trace_fd_ >= 0) {
    ::close(trace_fd_);
    trace_fd_ = -1;
  }
  if (stream_fd_ >= 0) {
    ::close(stream_fd_);
    stream_fd_ = -1;
  }
}

void BpfTraceCollector::set_binary_output(const std::string& path) {
  if (path.empty()) return;
  // Create the parent directory if it does not exist -- otherwise open() fails
  // ENOENT and the capture silently writes nothing (e.g. --trace-out
  // /tmp/montauk/x.bin before /tmp/montauk exists).
  std::error_code ec;
  std::filesystem::path parent = std::filesystem::path(path).parent_path();
  if (!parent.empty()) std::filesystem::create_directories(parent, ec);
  trace_dir_ = parent.empty() ? "." : parent.string();
  int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    montauk::util::log_error("--trace-out: cannot open '%s': %s", path.c_str(), std::strerror(errno));
    return;
  }

  // Capture both clocks at the same instant so the decoder can map event
  // timestamps (CLOCK_MONOTONIC, from bpf_ktime_get_ns) to absolute wall
  // time. Read mono first, real second; the tiny skew between them is
  // sub-microsecond and irrelevant at trace granularity.
  timespec mono{}, real{};
  clock_gettime(CLOCK_MONOTONIC, &mono);
  clock_gettime(CLOCK_REALTIME, &real);

  montauk::model::TraceFileHeader hdr{};
  std::memcpy(hdr.magic, montauk::model::kTraceMagic, sizeof(hdr.magic));
  hdr.version        = montauk::model::kTraceFormatVersion;
  hdr.flags          = 0;
  hdr.mono_anchor_ns = static_cast<uint64_t>(mono.tv_sec) * 1000000000ull + mono.tv_nsec;
  hdr.real_anchor_ns = static_cast<uint64_t>(real.tv_sec) * 1000000000ull + real.tv_nsec;
  std::snprintf(hdr.pattern, sizeof(hdr.pattern), "%s", pattern_.c_str());

  size_t off = 0;
  const auto* p = reinterpret_cast<const uint8_t*>(&hdr);
  while (off < sizeof(hdr)) {
    ssize_t n = ::write(fd, p + off, sizeof(hdr) - off);
    if (n <= 0) { ::close(fd); return; }
    off += static_cast<size_t>(n);
  }

  trace_fd_ = fd;
  trace_buf_.reserve(kTraceFlushThreshold + 4096);
}

void BpfTraceCollector::set_stream_output(const std::string& path) {
  if (path.empty()) return;
  // No parent-directory creation, no O_CREAT/O_TRUNC: the target is a
  // character device (a qemu-backed serial port) that already exists, not a
  // regular file on a filesystem this stream exists specifically to not
  // depend on.
  int fd = ::open(path.c_str(), O_WRONLY);
  if (fd < 0) {
    montauk::util::log_error("--stream-out: cannot open '%s': %s", path.c_str(), std::strerror(errno));
    return;
  }

  // If this is a tty (a serial port is one), it defaults to canonical mode:
  // the line discipline echoes, interprets control characters, and can
  // apply XON/XOFF software flow control -- any of which corrupts a raw
  // binary stream (a stray 0x13 in the data can even stall the whole port).
  // Force raw mode before writing a single byte, including the header.
  if (::isatty(fd)) {
    struct termios tio{};
    if (::tcgetattr(fd, &tio) == 0) {
      ::cfmakeraw(&tio);
      ::tcsetattr(fd, TCSANOW, &tio);
    }
  }

  timespec mono{}, real{};
  clock_gettime(CLOCK_MONOTONIC, &mono);
  clock_gettime(CLOCK_REALTIME, &real);

  montauk::model::TraceFileHeader hdr{};
  std::memcpy(hdr.magic, montauk::model::kTraceMagic, sizeof(hdr.magic));
  hdr.version        = montauk::model::kTraceFormatVersion;
  hdr.flags          = 0;
  hdr.mono_anchor_ns = static_cast<uint64_t>(mono.tv_sec) * 1000000000ull + mono.tv_nsec;
  hdr.real_anchor_ns = static_cast<uint64_t>(real.tv_sec) * 1000000000ull + real.tv_nsec;
  std::snprintf(hdr.pattern, sizeof(hdr.pattern), "%s", pattern_.c_str());

  size_t off = 0;
  const auto* p = reinterpret_cast<const uint8_t*>(&hdr);
  while (off < sizeof(hdr)) {
    ssize_t n = ::write(fd, p + off, sizeof(hdr) - off);
    if (n <= 0) { ::close(fd); return; }
    off += static_cast<size_t>(n);
  }

  stream_fd_ = fd;
  stream_buf_.reserve(kTraceFlushThreshold + 4096);
}

void BpfTraceCollector::trace_append(const void* data, size_t len) {
  if (trace_fd_ < 0 && stream_fd_ < 0) return;
  montauk::model::TraceRecordLen l = static_cast<montauk::model::TraceRecordLen>(len);
  const auto* lp = reinterpret_cast<const uint8_t*>(&l);
  const auto* dp = reinterpret_cast<const uint8_t*>(data);
  if (trace_fd_ >= 0) {
    ++writer_attempted_;
    trace_buf_.insert(trace_buf_.end(), lp, lp + sizeof(l));
    trace_buf_.insert(trace_buf_.end(), dp, dp + len);
    if (trace_buf_.size() >= kTraceFlushThreshold) trace_flush();
  }
  if (stream_fd_ >= 0) {
    // Flushed unconditionally on every poll cycle (see run loop), not
    // threshold-gated like trace_buf_: the whole point of this sink is
    // getting bytes out promptly, not batching for efficiency.
    stream_buf_.insert(stream_buf_.end(), lp, lp + sizeof(l));
    stream_buf_.insert(stream_buf_.end(), dp, dp + len);
  }
}

void BpfTraceCollector::trace_flush() {
  if (trace_fd_ >= 0 && !trace_buf_.empty()) {
    size_t off = 0;
    while (off < trace_buf_.size()) {
      ssize_t n = ::write(trace_fd_, trace_buf_.data() + off, trace_buf_.size() - off);
      if (n <= 0) {
        // best-effort: drop on error rather than spin -- but COUNT the drop,
        // so the trace's final snapshot can say its own tail is short.
        ++writer_errors_;
        writer_lost_bytes_ += trace_buf_.size() - off;
        break;
      }
      off += static_cast<size_t>(n);
    }
    trace_buf_.clear();
    // write() only lands data in the page cache; on a journaled filesystem
    // (ext4/xfs) it is not durable on the actual block device until the next
    // journal commit (ext4 default: 5s) or an explicit fsync. This trace log
    // exists specifically to survive a hang, so force the commit every flush
    // rather than trust the periodic one to land before a freeze does. If the
    // freeze itself involves the journal/writeback path, fsync can block too --
    // best-effort, same as the write() above; a stream sink independent of the
    // filesystem is the robust complement, not a substitute.
    ::fsync(trace_fd_);
  }
  if (stream_fd_ >= 0 && !stream_buf_.empty()) {
    size_t off = 0;
    while (off < stream_buf_.size()) {
      ssize_t n = ::write(stream_fd_, stream_buf_.data() + off, stream_buf_.size() - off);
      if (n <= 0) break;  // best-effort: drop on error rather than spin
      off += static_cast<size_t>(n);
    }
    stream_buf_.clear();
    // A character device has no journal to force -- the write() above either
    // reached qemu's host-side backing already or it did not. No fsync here.
  }
}

void BpfTraceCollector::append_provider_snapshots() {
  if (trace_fd_ < 0 && stream_fd_ < 0) return;  // either binary sink accepts these records
  if (!cache_topo_emitted_) {
    append_cache_topology_snapshot();
    cache_topo_emitted_ = true;
  }
  std::vector<montauk::model::Provider> provs;
  if (!providers_.sample(provs) || provs.empty()) return;
  timespec mono{};
  clock_gettime(CLOCK_MONOTONIC, &mono);
  uint64_t now_ns = static_cast<uint64_t>(mono.tv_sec) * 1000000000ull + mono.tv_nsec;
  std::vector<uint8_t> rec;
  for (const auto& p : provs) {
    montauk_provider_event ev{};
    ev.type = TRACE_EVT_PROVIDER;
    ev.timestamp_ns = now_ns;
    std::snprintf(ev.name, sizeof(ev.name), "%s", p.name.c_str());
    ev.payload_len = static_cast<__u32>(p.raw_text.size());
    rec.clear();
    const auto* hp = reinterpret_cast<const uint8_t*>(&ev);
    rec.insert(rec.end(), hp, hp + sizeof(ev));
    const auto* tp = reinterpret_cast<const uint8_t*>(p.raw_text.data());
    rec.insert(rec.end(), tp, tp + p.raw_text.size());
    trace_append(rec.data(), rec.size());
  }
}

// Read the per-CPU scx_storm counters, delta against the previous cycle, and append
// one TRACE_EVT_SCX_STORM sample. The deltas + interval give per-CPU-summed kick /
// preempt-kick / reenqueue rates -- the cpu_release storm, straight from the trace.
void BpfTraceCollector::append_scx_storm_sample() {
  if ((trace_fd_ < 0 && stream_fd_ < 0) || !skel_) return;
  int fd = bpf_map__fd(skel_->maps.scx_storm);
  if (fd < 0) return;
  int ncpu = libbpf_num_possible_cpus();
  if (ncpu <= 0) ncpu = 1;
  std::vector<scx_storm_counters> per(static_cast<size_t>(ncpu));
  uint32_t key = 0;
  if (bpf_map_lookup_elem(fd, &key, per.data()) != 0) return;
  uint64_t kicks = 0, preempt = 0, reenq = 0;
  for (const auto& v : per) { kicks += v.kicks; preempt += v.preempt_kicks; reenq += v.reenq; }

  timespec mono{};
  clock_gettime(CLOCK_MONOTONIC, &mono);
  uint64_t now_ns = static_cast<uint64_t>(mono.tv_sec) * 1000000000ull + mono.tv_nsec;

  // First call seeds the baseline; a delta is only meaningful from the next cycle on.
  if (scx_sample_last_ns_ != 0) {
    montauk_scx_storm_event ev{};
    ev.type = TRACE_EVT_SCX_STORM;
    ev.interval_ms = static_cast<__u32>((now_ns - scx_sample_last_ns_) / 1000000ull);
    ev.kicks = kicks - scx_kicks_last_;
    ev.preempt_kicks = preempt - scx_preempt_last_;
    ev.reenq = reenq - scx_reenq_last_;
    ev.timestamp_ns = now_ns;
    trace_append(reinterpret_cast<const uint8_t*>(&ev), sizeof(ev));
  }
  scx_kicks_last_ = kicks;
  scx_preempt_last_ = preempt;
  scx_reenq_last_ = reenq;
  scx_sample_last_ns_ = now_ns;
}

// Sample the BPF drop_counts map (per-CPU per-event-type reserve failures),
// fold per-CPU values into cumulative per-type totals and append one
// TRACE_EVT_DROPS snapshot when anything moved since the last stamp (plus an
// unconditional final one at teardown, force=true). Totals are FREE-RUNNING,
// never deltas: idempotent across lost snapshots, and the analyzer bounds
// any window's loss by differencing the nearest bracketing pair. Before this
// record existed, every one of the BPF side's reserve failures vanished
// silently and a capture with holes was indistinguishable from a quiet one.
void BpfTraceCollector::append_drop_snapshot(bool force) {
  if ((trace_fd_ < 0 && stream_fd_ < 0) || !skel_) return;
  int fd = bpf_map__fd(skel_->maps.drop_counts);
  if (fd < 0) return;
  int ncpu = libbpf_num_possible_cpus();
  if (ncpu <= 0) ncpu = 1;
  std::vector<uint64_t> per(static_cast<size_t>(ncpu));
  montauk_drop_event ev{};
  ev.type = TRACE_EVT_DROPS;
  uint64_t total = 0;
  for (uint32_t slot = 0; slot < MONTAUK_DROP_SLOTS; ++slot) {
    if (bpf_map_lookup_elem(fd, &slot, per.data()) != 0) continue;
    uint64_t s = 0;
    for (int c = 0; c < ncpu; ++c) s += per[static_cast<size_t>(c)];
    ev.dropped[slot] = s;
    total += s;
  }
  ev.writer_attempted = writer_attempted_;
  ev.writer_errors = writer_errors_;
  ev.writer_lost_bytes = writer_lost_bytes_;
  if (!force && total == drops_last_total_ && writer_errors_ == drops_last_werr_)
    return;  // quiet capture: no snapshot churn
  drops_last_total_ = total;
  drops_last_werr_ = writer_errors_;
  timespec mono{};
  clock_gettime(CLOCK_MONOTONIC, &mono);
  ev.ts_ns = static_cast<uint64_t>(mono.tv_sec) * 1000000000ull +
             static_cast<uint64_t>(mono.tv_nsec);
  trace_append(reinterpret_cast<const uint8_t*>(&ev), sizeof(ev));
}

// Generic cpu -> cache-hierarchy snapshot embedded once in the binary trace.
// Each /sys cache shared_cpu_list maps to a dense id; physical_package_id is the
// socket. The analyzer reads this to give every migration a cache-tier distance
// with no live /sys read. Hardware fact, no scheduler named.
void BpfTraceCollector::append_cache_topology_snapshot() {
  if (trace_fd_ < 0 && stream_fd_ < 0) return;  // either binary sink accepts these records
  int ncpu = libbpf_num_possible_cpus();
  if (ncpu <= 0) ncpu = 1;
  if (ncpu > TRACE_MAX_CPUS) ncpu = TRACE_MAX_CPUS;
  std::map<std::string, uint32_t> l2_id, l3_id;
  uint32_t next_l2 = 0, next_l3 = 0;
  auto group = [](const char* fmt, int cpu, std::map<std::string, uint32_t>& m,
                  uint32_t& next) -> uint32_t {
    char path[160];
    std::snprintf(path, sizeof(path), fmt, cpu);
    std::string s = read_sys_line(path);
    if (s.empty()) return 0;
    auto it = m.find(s);
    if (it != m.end()) return it->second;
    uint32_t id = next++;
    m[s] = id;
    return id;
  };
  std::string text;
  for (int cpu = 0; cpu < ncpu; ++cpu) {
    uint32_t l2 = group("/sys/devices/system/cpu/cpu%d/cache/index2/shared_cpu_list",
                        cpu, l2_id, next_l2);
    uint32_t l3 = group("/sys/devices/system/cpu/cpu%d/cache/index3/shared_cpu_list",
                        cpu, l3_id, next_l3);
    uint32_t sock = 0;
    {
      char path[160];
      std::snprintf(path, sizeof(path),
                    "/sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu);
      std::string s = read_sys_line(path);
      if (!s.empty()) sock = static_cast<uint32_t>(std::strtoul(s.c_str(), nullptr, 10));
    }
    char line[160];
    std::snprintf(line, sizeof(line),
                  "montauk_cache_topology{cpu=\"%d\",l2=\"%u\",l3=\"%u\",socket=\"%u\"} 1\n",
                  cpu, l2, l3, sock);
    text += line;
  }
  montauk_provider_event ev{};
  ev.type = TRACE_EVT_PROVIDER;
  timespec mono{};
  clock_gettime(CLOCK_MONOTONIC, &mono);
  ev.timestamp_ns = static_cast<uint64_t>(mono.tv_sec) * 1000000000ull + mono.tv_nsec;
  std::snprintf(ev.name, sizeof(ev.name), "cache_topology");
  ev.payload_len = static_cast<__u32>(text.size());
  std::vector<uint8_t> rec;
  const auto* hp = reinterpret_cast<const uint8_t*>(&ev);
  rec.insert(rec.end(), hp, hp + sizeof(ev));
  const auto* tp = reinterpret_cast<const uint8_t*>(text.data());
  rec.insert(rec.end(), tp, tp + text.size());
  trace_append(rec.data(), rec.size());
}

// ntsync op name decode
static const char* ntsync_op_name(uint8_t op) {
  switch (op) {
    case 0:  return "create_sem";
    case 1:  return "sem_release";
    case 2:  return "wait_any";
    case 3:  return "wait_all";
    case 4:  return "create_mutex";
    case 5:  return "mutex_unlock";
    case 6:  return "mutex_kill";
    case 7:  return "create_event";
    case 8:  return "event_set";
    case 9:  return "event_reset";
    case 10: return "event_pulse";
    case 11: return "sem_read";
    case 12: return "mutex_read";
    case 13: return "event_read";
    default: return "unknown";
  }
}

// Ring buffer event handler — NO /proc reads

// Per-event stderr printing is a single-app debugging aid (e.g. --trace firefox).
// For a high-rate workload it is a firehose that dominates overhead and slows the
// traced workload itself. Off by default: the periodic snapshot already records
// per-thread syscall / io / state into the .prom flight recorder, which is the
// data path. Set MONTAUK_TRACE_VERBOSE=1 to stream every event to stderr.
static bool trace_event_verbose() {
  static const bool v = [] {
    const char* e = std::getenv("MONTAUK_TRACE_VERBOSE");
    return e && *e && std::strcmp(e, "0") != 0;
  }();
  return v;
}

int BpfTraceCollector::handle_event(void* ctx, void* data, size_t len) {
  auto* self = static_cast<BpfTraceCollector*>(ctx);

  // Binary trace log (--trace-out): append the raw record verbatim before
  // any per-type interpretation. This is the fast path — a memcpy into a
  // batched buffer, no formatting. The verbose-stderr branches below are
  // the orthogonal human-eyeball aid (MONTAUK_TRACE_VERBOSE).
  self->trace_append(data, len);

  // Lazy per-pid maps snapshot. track_pid only fires for pattern-matched
  // ROOTS (a launcher/preloader process); the aborting process itself is a
  // fork-inherited DESCENDANT tracked in-BPF, so it never hit track_pid's
  // snapshot and the death-time snapshot races the reap (empty file). Snapshot
  // on the first HEAP event from any pid — the process is provably alive and
  // allocating, and its module mappings are loaded. Once per pid (cheap set
  // guard).
  if (len >= sizeof(uint32_t)) {
    uint32_t etype = *static_cast<const uint32_t*>(data);
    if (etype == TRACE_EVT_HEAP && len >= sizeof(struct montauk_heap_event)) {
      uint32_t hpid = static_cast<const struct montauk_heap_event*>(data)->pid;
      if (hpid && self->maps_snapshotted_.insert(hpid).second)
        self->snapshot_maps(hpid);
    }
  }

  // ntsync events
  if (len >= sizeof(struct montauk_ntsync_event)) {
    auto* hdr = static_cast<const uint32_t*>(data);
    if (*hdr == TRACE_EVT_NTSYNC) {
      auto* nts = static_cast<const struct montauk_ntsync_event*>(data);

      if (trace_event_verbose()) {
        const char* op = ntsync_op_name(nts->op);
        if (nts->op == NTS_WAIT_ANY || nts->op == NTS_WAIT_ALL) {
          const char* tag = (nts->result == -999) ? "ENTER" : "EXIT";
          std::fprintf(stderr, "montauk: NTSYNC %s pid=%d tid=%d %s(fds=[",
                       tag, nts->pid, nts->tid, op);
          unsigned n = nts->wait_count;
          if (n > NTSYNC_MAX_WAIT_FDS) n = NTSYNC_MAX_WAIT_FDS;
          for (unsigned i = 0; i < n; ++i)
            std::fprintf(stderr, "%s%d", i ? "," : "", nts->wait_fds[i]);
          std::fprintf(stderr, "], count=%u, alert=%u) = %ld idx=%u\n",
                       nts->wait_count, nts->wait_alert,
                       (long)nts->result, nts->wait_index);
        } else {
          std::fprintf(stderr, "montauk: NTSYNC pid=%d tid=%d %s(fd=%d) = %ld arg0=%u arg1=%u\n",
                       nts->pid, nts->tid, op, nts->fd,
                       (long)nts->result, nts->arg0, nts->arg1);
        }
      }

      // Accumulate for snapshot
      if (self->pending_ntsync_.size() <
          static_cast<size_t>(montauk::model::TraceSnapshot::MAX_NTSYNC)) {
        auto& s = self->pending_ntsync_.emplace_back();
        s.pid = static_cast<int32_t>(nts->pid);
        s.tid = static_cast<int32_t>(nts->tid);
        s.op = nts->op;
        s.fd = nts->fd;
        s.result = nts->result;
        s.timestamp_ns = nts->timestamp_ns;
        s.arg0 = nts->arg0;
        s.arg1 = nts->arg1;
        s.timeout_ns = nts->timeout_ns;
        s.wait_count = nts->wait_count;
        s.wait_index = nts->wait_index;
        s.wait_owner = nts->wait_owner;
        s.wait_alert = nts->wait_alert;
        std::memcpy(s.wait_fds, nts->wait_fds, sizeof(s.wait_fds));
        std::memcpy(s.comm, nts->comm, 16);
      }
      return 0;
    }
  }

  // Scheduler-decision events (generic decision tracepoints)
  if (len >= sizeof(struct montauk_sched_event)) {
    auto* hdr = static_cast<const uint32_t*>(data);
    if (*hdr == TRACE_EVT_SCHED) {
      if (trace_event_verbose()) {
        auto* s = static_cast<const struct montauk_sched_event*>(data);
        const char* op = "?";
        switch (s->op) {
          case SCHED_OP_ENQUEUE:        op = "ENQUEUE"; break;
          case SCHED_OP_PICK:           op = "PICK"; break;
          case SCHED_OP_PICK_EMPTY:     op = "PICK_EMPTY"; break;
          case SCHED_OP_PREEMPT_TICK:   op = "PREEMPT_TICK"; break;
          case SCHED_OP_PREEMPT_WAKEUP: op = "PREEMPT_WAKEUP"; break;
          case SCHED_OP_CPU_IDLE:       op = "CPU_IDLE"; break;
          case SCHED_OP_FIELD_GATE:     op = "FIELD_GATE"; break;
        }
        if (s->op == SCHED_OP_ENQUEUE) {
          std::fprintf(stderr, "montauk: SCHED %s pid=%d cpu=%u last_cpu=%d sub=%u score=%llu ts=%llu\n",
                       op, s->pid, s->cpu, s->last_cpu, s->sub_idx,
                       (unsigned long long)s->score, (unsigned long long)s->timestamp_ns);
        } else if (s->op == SCHED_OP_PICK) {
          std::fprintf(stderr, "montauk: SCHED %s pid=%d cpu=%u score=%llu ts=%llu\n",
                       op, s->pid, s->cpu,
                       (unsigned long long)s->score, (unsigned long long)s->timestamp_ns);
        } else if (s->op == SCHED_OP_PICK_EMPTY) {
          std::fprintf(stderr, "montauk: SCHED %s cpu=%u ts=%llu\n",
                       op, s->cpu, (unsigned long long)s->timestamp_ns);
        } else if (s->op == SCHED_OP_PREEMPT_TICK) {
          std::fprintf(stderr, "montauk: SCHED %s pid=%d cpu=%u runtime=%llu budget=%llu ts=%llu\n",
                       op, s->pid, s->cpu,
                       (unsigned long long)s->runtime_ns,
                       (unsigned long long)s->budget_ns,
                       (unsigned long long)s->timestamp_ns);
        } else if (s->op == SCHED_OP_PREEMPT_WAKEUP) {
          std::fprintf(stderr, "montauk: SCHED %s waker=%d wakee=%d cpu=%u ts=%llu\n",
                       op, s->secondary_pid, s->pid, s->cpu,
                       (unsigned long long)s->timestamp_ns);
        } else if (s->op == SCHED_OP_FIELD_GATE) {
          std::fprintf(stderr, "montauk: SCHED %s cpu=%u sig=%llu prev=%llu changed=%u ts=%llu\n",
                       op, s->cpu, (unsigned long long)s->score,
                       (unsigned long long)s->runtime_ns, s->sub_idx,
                       (unsigned long long)s->timestamp_ns);
        }
      }
      return 0;
    }
  }

  // Signal events — fatal signal delivery + abnormal exits, with user-stack
  // snapshot. The actual "what killed this process" record. trace_append above
  // already wrote it to the binary trace log; here we surface it to verbose
  // stderr (always, regardless of trace_event_verbose, since signal events
  // are by definition rare and load-bearing).
  if (len >= sizeof(struct montauk_signal_event)) {
    auto* hdr = static_cast<const uint32_t*>(data);
    if (*hdr == TRACE_EVT_SIGNAL) {
      auto* sig = static_cast<const struct montauk_signal_event*>(data);
      // A clean exit -- WIFEXITED, even with a non-zero status (grep returning 1;
      // a build runs thousands of non-matching greps) -- is NOT abnormal and must
      // not flood stderr with a per-exit stack dump. The binary trace log already
      // recorded it above; only signal-killed exits (WIFSIGNALED, low 7 bits of the
      // exit code set) and delivered signals get the verbose WARN + user-stack here.
      bool signal_killed = (sig->signal_nr != 0) || ((sig->exit_code & 0x7f) != 0);
      if (sig->kind != SIGEVT_DELIVER && !signal_killed) return 0;
      const char* signame;
      switch (sig->signal_nr) {
        case 4:  signame = "SIGILL";  break;
        case 5:  signame = "SIGTRAP"; break;
        case 6:  signame = "SIGABRT"; break;
        case 7:  signame = "SIGBUS";  break;
        case 8:  signame = "SIGFPE";  break;
        case 9:  signame = "SIGKILL"; break;
        case 11: signame = "SIGSEGV"; break;
        case 15: signame = "SIGTERM"; break;
        case 0:  signame = "(none)";  break;
        default: signame = "?";       break;
      }
      const char* kind = (sig->kind == SIGEVT_DELIVER) ? "DELIVER" : "EXIT_ABNL";
      montauk::util::log_warn(
                   "SIGNAL %s pid=%u tid=%u sig=%s(%d) sender=%d "
                   "exit_code=0x%x comm='%.16s' stack_depth=%u",
                   kind, sig->pid, sig->tid, signame, sig->signal_nr,
                   sig->sender_pid, (unsigned)sig->exit_code,
                   sig->comm, sig->stack_depth);
      // Per-thread context at signal time — answers "what syscall was
      // this thread executing when it got killed?" Critical when stack
      // capture is shallow (frame pointer omitted, DWARF unwind fails).
      if (sig->syscall_nr >= 0) {
        montauk::util::log_warn(
                     "  in_syscall=%d fd=%d arg0=0x%016llx arg1=0x%016llx",
                     sig->syscall_nr, sig->io_fd,
                     (unsigned long long)sig->syscall_arg0,
                     (unsigned long long)sig->syscall_arg1);
      }
      // Print up to the first 8 frames inline. The binary trace log has
      // all of them — this is the "eyeball it in stderr" view.
      unsigned n = sig->stack_depth;
      if (n > 8) n = 8;

      // Snapshot /proc/<pid>/maps NOW so we can resolve each stack IP to
      // a loaded module + offset. Race window: the kernel may have already
      // reaped the dying task by the time we get the ringbuf event. For
      // SIGSEGV/SIGABRT the core-dump/exit path usually gives us time;
      // for SIGKILL or fast-exit we'll get ENOENT and just print raw IPs.
      //
      // Also dump the full maps to a sidecar file. A loaded module mapped
      // anonymously (path in /proc/maps empty) resolves to just an offset
      // inline, so the sidecar
      // lets the operator manually correlate after the fact via the maps
      // contents (and via /proc/PID/map_files/ symlinks while the process
      // is still alive).
      struct MapEntry { uint64_t start, end, file_off; std::string path; };
      std::vector<MapEntry> maps;
      {
        char maps_path[64];
        std::snprintf(maps_path, sizeof(maps_path),
                      "/proc/%u/maps", sig->pid);
        FILE* mf = std::fopen(maps_path, "r");
        if (mf) {
          // NOTE: do NOT write the .maps sidecar here. At death the process
          // is being reaped, so this read often comes back empty — and a
          // truncating sidecar write would CLOBBER the good live snapshot the
          // lazy heap-event path already wrote. The sidecar is owned solely
          // by snapshot_maps() (first-HEAP-event, delete-on-empty). This
          // block only reads /proc for the inline stderr resolution below.
          char line[1024];
          while (std::fgets(line, sizeof(line), mf)) {
            MapEntry e{};
            char perms[8];
            char path[768] = {0};
            // Format: addr_start-addr_end perms file_off dev inode path
            int parsed = std::sscanf(line, "%lx-%lx %7s %lx %*s %*s %767[^\n]",
                                     &e.start, &e.end, perms, &e.file_off, path);
            if (parsed >= 4 && perms[2] == 'x') {  // executable only
              // strip leading whitespace from path
              char* p = path;
              while (*p == ' ' || *p == '\t') p++;
              e.path = p;
              // Fallback for anonymous mappings: try /proc/PID/map_files/
              // which has symlinks even when /proc/maps has no path.
              if (e.path.empty()) {
                char link_path[96], target[768];
                std::snprintf(link_path, sizeof(link_path),
                              "/proc/%u/map_files/%lx-%lx",
                              sig->pid, e.start, e.end);
                ssize_t r = readlink(link_path, target, sizeof(target) - 1);
                if (r > 0) {
                  target[r] = '\0';
                  e.path = target;
                }
              }
              maps.push_back(std::move(e));
            }
          }
          std::fclose(mf);
        }
      }

      auto resolve = [&maps](uint64_t ip) -> std::string {
        for (const auto& m : maps) {
          if (ip >= m.start && ip < m.end) {
            const char* base = m.path.c_str();
            const char* slash = std::strrchr(base, '/');
            std::string name = slash ? (slash + 1) : base;
            char buf[128];
            std::snprintf(buf, sizeof(buf), "%s+0x%lx", name.c_str(),
                          (unsigned long)(ip - m.start + m.file_off));
            return buf;
          }
        }
        return "";
      };

      for (unsigned i = 0; i < n; ++i) {
        uint64_t ip = sig->stack_user[i];
        std::string sym = resolve(ip);
        if (!sym.empty()) {
          montauk::util::log_warn("  #%u 0x%016llx  %s",
                       i, (unsigned long long)ip, sym.c_str());
        } else {
          montauk::util::log_warn("  #%u 0x%016llx",
                       i, (unsigned long long)ip);
        }
      }
      return 0;
    }
  }

  // Abort-path events — libc __assert_fail/__libc_message/abort uprobes.
  // Like SIGNAL events: rare, load-bearing, always surfaced to stderr.
  // The abort text otherwise only exists on the dying process's stderr.
  if (len >= sizeof(struct montauk_abort_event)) {
    auto* hdr = static_cast<const uint32_t*>(data);
    if (*hdr == TRACE_EVT_ABORT) {
      auto* ab = static_cast<const struct montauk_abort_event*>(data);
      const char* fn = ab->func == ABORT_FN_ASSERT_FAIL  ? "__assert_fail"
                     : ab->func == ABORT_FN_LIBC_MESSAGE ? "__libc_message"
                     : ab->func == ABORT_FN_ABORT        ? "abort"
                     : "?";
      montauk::util::log_error(
                   "ABORT %s pid=%u tid=%u comm='%.16s' "
                   "msg='%.128s' loc='%.128s' line=%u stack_depth=%u",
                   fn, ab->pid, ab->tid, ab->comm, ab->msg, ab->loc,
                   ab->line, ab->stack_depth);
      unsigned n = ab->stack_depth;
      if (n > 8) n = 8;
      for (unsigned i = 0; i < n; ++i)
        montauk::util::log_error("  #%u 0x%016llx",
                     i, (unsigned long long)ab->stack_user[i]);
      return 0;
    }
  }

  // I/O events have a different struct layout
  if (len >= sizeof(struct montauk_io_event)) {
    auto* hdr = static_cast<const uint32_t*>(data);
    if (*hdr == TRACE_EVT_IO) {
      if (trace_event_verbose()) {
        auto* io = static_cast<struct montauk_io_event*>(data);
        const char* name;
        switch (io->syscall_nr) {
          case 0:  name = "read"; break;
          case 1:  name = "write"; break;
          case 5:  name = "fstat"; break;
          case 8:  name = "lseek"; break;
          case 17: name = "pread64"; break;
          case 257: name = "openat"; break;
          default: name = "?"; break;
        }
        std::fprintf(stderr, "montauk: IO pid=%d tid=%d %s(fd=%d, count=%lu) = %ld whence=%u comm='%.16s'\n",
                     io->pid, io->tid, name, io->fd,
                     (unsigned long)io->count, (long)io->result,
                     io->whence, io->comm);
      }
      return 0;
    }
  }

  if (len < sizeof(struct montauk_ring_event))
    return 0;

  auto* evt = static_cast<struct montauk_ring_event*>(data);
  int32_t pid = static_cast<int32_t>(evt->pid);

  if (evt->type == TRACE_EVT_COMM_CHANGE) {
    montauk::util::log_info("COMM_CHANGE pid=%d comm='%.16s'", pid, evt->comm);
  } else if (evt->type == TRACE_EVT_EXEC) {
    montauk::util::log_info("EXEC pid=%d comm='%.16s' file='%.64s'",
                 pid, evt->comm, evt->filename);
  }

  // Skip our own process chain
  if (self->excluded_pids_.count(pid))
    return 0;

  if (evt->type == TRACE_EVT_EXEC) {
    // Match against filename from tracepoint (extracted in BPF, not /proc)
    bool matched = false;
    if (evt->filename[0] != '\0') {
      std::string fname(evt->filename);
      if (self->matches_any(fname))
        matched = true;
    }
    // Also match against comm
    if (!matched && evt->comm[0] != '\0') {
      std::string comm(evt->comm);
      if (self->matches_any(comm))
        matched = true;
    }
    if (matched) {
      self->track_pid(pid, 0, true, evt->comm);
    }
  } else if (evt->type == TRACE_EVT_COMM_CHANGE) {
    // A process renamed itself via prctl(PR_SET_NAME) — re-evaluate pattern match
    // Read updated comm from BPF proc_map
    if (!self->skel_) return 0;
    uint32_t key = static_cast<uint32_t>(pid);
    struct proc_bpf_info info;
    int proc_fd = bpf_map__fd(self->skel_->maps.proc_map);
    if (bpf_map_lookup_elem(proc_fd, &key, &info) == 0) {
      // Already tracked — comm updated in-kernel
      return 0;
    }
    // Not tracked yet — check if new comm matches pattern
    if (evt->comm[0] != '\0') {
      std::string comm(evt->comm);
      if (self->matches_any(comm)) {
        self->track_pid(pid, 0, true, evt->comm);
      }
    }
  }
  // FORK and EXIT handled entirely in BPF
  return 0;
}

// Track a PID in the BPF proc_map
void BpfTraceCollector::track_pid(int32_t pid, int32_t ppid, bool is_root,
                                   const char* comm) {
  struct proc_bpf_info info = {};
  info.pid = static_cast<uint32_t>(pid);
  info.ppid = static_cast<uint32_t>(ppid);
  info.tracked = 1;
  info.is_root = is_root ? 1 : 0;
  if (comm) {
    auto len = std::strlen(comm);
    if (len > sizeof(info.comm) - 1) len = sizeof(info.comm) - 1;
    std::memcpy(info.comm, comm, len);
  }

  uint32_t key = static_cast<uint32_t>(pid);
  bpf_map__update_elem(skel_->maps.proc_map, &key, sizeof(key),
                        &info, sizeof(info), BPF_ANY);

  // Snapshot /proc/<pid>/maps NOW, while the process is provably alive.
  // The death-time snapshot in handle_event races the reap (fast abort ->
  // SIGABRT -> exit, plus the launcher's SIGKILL backstop) and lands an
  // empty file, leaving heapstack/abort IPs unresolvable. A module's
  // mappings are stable once loaded, so an early snapshot resolves them;
  // refreshed on each (re)track so late dlopens get folded in. Once per
  // pid is enough for the common case, but re-tracking is cheap.
  snapshot_maps(static_cast<uint32_t>(pid));
}

// Snapshot /proc/<pid>/maps to the per-incident sidecar. Called repeatedly
// (first heap event + periodic refresh) so the sidecar tracks the LATEST
// live address space — the game maps DXVK/PE DLLs/late heap arenas well
// after its first allocation, so an early-only snapshot misses the modules
// that own the abort IPs. Writes to a temp and renames over the sidecar
// ONLY when the read was non-empty, so a reap-time empty read can never
// destroy the last good snapshot.
void BpfTraceCollector::snapshot_maps(uint32_t pid) {
  if (trace_dir_.empty()) return;  // no --trace-out: no trace file to correlate against
  char maps_path[64];
  std::snprintf(maps_path, sizeof(maps_path), "/proc/%u/maps", pid);
  FILE* mf = std::fopen(maps_path, "r");
  if (!mf) return;
  std::string sidecar_path = trace_dir_ + "/" + std::to_string(pid) + ".maps";
  std::string tmp_path = trace_dir_ + "/." + std::to_string(pid) + ".maps.tmp";
  FILE* tmp = std::fopen(tmp_path.c_str(), "w");
  if (tmp) {
    char line[1024];
    size_t bytes = 0;
    while (std::fgets(line, sizeof(line), mf))
      bytes += std::fputs(line, tmp) >= 0 ? std::strlen(line) : 0;
    std::fclose(tmp);
    if (bytes > 0)
      ::rename(tmp_path.c_str(), sidecar_path.c_str());  // atomic replace, keeps last-good
    else
      ::remove(tmp_path.c_str());          // empty read: leave existing intact
  }
  std::fclose(mf);
}

// Build self-exclusion set — uses getpid/getppid syscalls, NOT /proc
void BpfTraceCollector::build_self_exclusion() {
  pid_t pid = getpid();
  while (pid > 1) {
    excluded_pids_.insert(static_cast<int32_t>(pid));
    pid = getppid(); // only gets immediate parent
    if (excluded_pids_.count(static_cast<int32_t>(pid)))
      break; // already seen, stop
    excluded_pids_.insert(static_cast<int32_t>(pid));
    // Can't walk further without /proc — but getpid+getppid covers
    // the montauk process and its sudo/shell parent
    break;
  }
}

// Periodic re-scan of BPF proc_map comms for pattern matching
// Catches prctl(PR_SET_NAME) self-renames and delayed comm changes
// All data from BPF maps — zero /proc reads
void BpfTraceCollector::rescan_comms() {
  if (!skel_) return;
  int proc_fd = bpf_map__fd(skel_->maps.proc_map);
  int disc_fd = bpf_map__fd(skel_->maps.discovery_map);

  // Scan discovery_map — every process that made a syscall has an entry.
  // If comm matches our pattern and pid isn't already tracked, promote it.
  uint32_t key = 0, next_key = 0;
  while (bpf_map_get_next_key(disc_fd, &key, &next_key) == 0) {
    struct discovery_entry de;
    if (bpf_map_lookup_elem(disc_fd, &next_key, &de) == 0) {
      uint32_t pid_key = de.pid;
      // Skip if already tracked
      struct proc_bpf_info dummy;
      if (bpf_map_lookup_elem(proc_fd, &pid_key, &dummy) == 0) {
        key = next_key;
        continue;
      }
      // Skip excluded
      if (excluded_pids_.count(static_cast<int32_t>(de.pid))) {
        key = next_key;
        continue;
      }
      // Check comm against pattern
      if (de.comm[0] != '\0') {
        std::string comm(de.comm, strnlen(de.comm, sizeof(de.comm)));
        if (matches_any(comm)) {
          montauk::util::log_info("DISCOVERED pid=%d comm='%s' via discovery_map",
                       de.pid, comm.c_str());
          track_pid(static_cast<int32_t>(de.pid), 0, true, de.comm);
        }
      }
    }
    key = next_key;
  }

  // Refresh the maps sidecar for every pid we have snapshotted, so it tracks
  // the LATEST live address space — the abort IPs live in modules (DXVK, PE
  // DLLs) loaded long after the first-heap-event snapshot. rename-on-non-empty
  // (snapshot_maps) keeps the last good copy when a pid finally dies.
  for (uint32_t pid : maps_snapshotted_)
    snapshot_maps(pid);
}

// Snapshot from BPF maps → TraceSnapshot — zero /proc reads
void BpfTraceCollector::snapshot_from_maps(montauk::model::TraceSnapshot& snap) {
  uint64_t now_ns = 0;
  {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    now_ns = static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL +
             static_cast<uint64_t>(ts.tv_nsec);
  }

  // Read proc_map → TracedProcess array
  snap.procs_count = 0;
  {
    uint32_t key = 0, next_key = 0;
    int map_fd = bpf_map__fd(skel_->maps.proc_map);
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
      if (snap.procs_count >= montauk::model::TraceSnapshot::MAX_PROCS) break;
      struct proc_bpf_info info;
      if (bpf_map_lookup_elem(map_fd, &next_key, &info) == 0) {
        auto& tp = snap.procs[snap.procs_count];
        tp.pid = static_cast<int32_t>(info.pid);
        tp.ppid = static_cast<int32_t>(info.ppid);
        tp.is_root = info.is_root;
        tp.exited = info.exited;
        tp.exit_code = info.exit_code;
        tp.fork_ts = info.fork_ts;
        tp.exec_ts = info.exec_ts;
        tp.exit_ts = info.exit_ts;
        std::memcpy(tp.cmd, info.comm, sizeof(info.comm));
        std::memcpy(tp.exec_file, info.exec_file, sizeof(info.exec_file));
        snap.procs_count++;
      }
      key = next_key;
    }
  }

  // Drive the task iterator first, so every tracked process's threads are
  // enrolled into thread_map before we read it -- complete coverage even for a
  // burst of freshly-spawned threads the reactive path hasn't met yet.
  if (enroll_iter_link_) {
    int it_fd = bpf_iter_create(bpf_link__fd(enroll_iter_link_));
    if (it_fd >= 0) {
      char it_buf[256];
      while (read(it_fd, it_buf, sizeof(it_buf)) > 0) { }
      close(it_fd);
    }
  }

  // Read thread_map → ThreadSample array
  snap.thread_count = 0;
  {
    uint32_t key = 0, next_key = 0;
    int map_fd = bpf_map__fd(skel_->maps.thread_map);
    int proc_fd = bpf_map__fd(skel_->maps.proc_map);
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
      if (snap.thread_count >= montauk::model::TraceSnapshot::MAX_THREADS) break;
      struct thread_bpf_state ts;
      if (bpf_map_lookup_elem(map_fd, &next_key, &ts) == 0) {
        // Only include threads whose pid is tracked
        uint32_t pid_key = ts.pid;
        struct proc_bpf_info pinfo;
        if (bpf_map_lookup_elem(proc_fd, &pid_key, &pinfo) != 0) {
          bpf_map_delete_elem(map_fd, &next_key);
          key = next_key;
          continue;
        }

        auto& th = snap.threads[snap.thread_count];
        th.pid = static_cast<int32_t>(ts.pid);
        th.tid = static_cast<int32_t>(ts.tid);

        const char state_chars[] = "RSDTZ";
        th.state = (ts.state < 5) ? state_chars[ts.state] : '?';

        th.syscall_nr = ts.syscall_nr;
        th.syscall_arg1 = ts.syscall_arg0;
        th.syscall_arg2 = ts.syscall_arg1;
        if (ts.syscall_nr == -1) {
          std::memcpy(th.syscall_name, "running", 8);
        } else {
          const char* name = syscall_name(ts.syscall_nr);
          if (name) {
            auto len = std::strlen(name);
            if (len > sizeof(th.syscall_name) - 1) len = sizeof(th.syscall_name) - 1;
            std::memcpy(th.syscall_name, name, len);
          } else {
            std::snprintf(th.syscall_name, sizeof(th.syscall_name),
                          "sys_%d", ts.syscall_nr);
          }
        }

        th.utime = ts.runtime_ns;
        th.stime = 0;
        th.cpu_pct = 0.0;
        th.cur_cpu = ts.cur_cpu;
        th.migrations = ts.migrations;

        // Comm from BPF thread_map — no /proc
        std::memcpy(th.comm, ts.comm, sizeof(ts.comm));

        // I/O syscall details
        th.io_fd = ts.io_fd;
        th.io_count = ts.io_count;
        th.io_whence = ts.io_whence;
        th.io_result = ts.io_result;
        th.io_timestamp_ns = ts.io_timestamp_ns;

        // Decode ntsync ioctls in thread state display
        if (ts.syscall_nr == 16) {
          uint32_t cmd = static_cast<uint32_t>(ts.syscall_arg1);
          if (((cmd >> 8) & 0xFF) == 0x4E && (cmd & 0xFF) >= 0x80 && (cmd & 0xFF) <= 0x8D) {
            uint8_t nr = cmd & 0xFF;
            const char* nts = nullptr;
            switch (nr) {
              case 0x80: nts = "ntsync:create_sem"; break;
              case 0x82: nts = "ntsync:wait_any"; break;
              case 0x83: nts = "ntsync:wait_all"; break;
              case 0x84: nts = "ntsync:create_mutex"; break;
              case 0x87: nts = "ntsync:create_event"; break;
              case 0x88: nts = "ntsync:event_set"; break;
              case 0x89: nts = "ntsync:event_reset"; break;
              case 0x8a: nts = "ntsync:event_pulse"; break;
              default:   nts = "ntsync:op"; break;
            }
            auto nlen = std::strlen(nts);
            if (nlen > sizeof(th.syscall_name) - 1) nlen = sizeof(th.syscall_name) - 1;
            std::memcpy(th.syscall_name, nts, nlen);
            th.syscall_name[nlen] = '\0';
          }
        }

        // Synthetic wchan from syscall name
        if (th.state != 'R' && ts.syscall_nr >= 0) {
          std::memcpy(th.wchan, th.syscall_name,
                      std::min(sizeof(th.wchan), sizeof(th.syscall_name)));
        }

        snap.thread_count++;
      }
      key = next_key;
    }
  }

  // Read fd_map → FdSample array
  snap.fd_count = 0;
  {
    struct fd_key key = {}, next_key = {};
    int map_fd = bpf_map__fd(skel_->maps.fd_map);
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
      if (snap.fd_count >= montauk::model::TraceSnapshot::MAX_FDS) break;
      struct fd_bpf_entry entry;
      if (bpf_map_lookup_elem(map_fd, &next_key, &entry) == 0) {
        if (entry.type > 0) {
          auto& fs = snap.fds[snap.fd_count];
          fs.pid = static_cast<int32_t>(entry.pid);
          fs.fd_num = entry.fd_num;
          std::memcpy(fs.target, entry.target, sizeof(entry.target));
          snap.fd_count++;
        }
      }
      key = next_key;
    }
  }

  // Drain ntsync events accumulated since last snapshot
  snap.ntsync_count = static_cast<int>(
      std::min(pending_ntsync_.size(),
               static_cast<size_t>(montauk::model::TraceSnapshot::MAX_NTSYNC)));
  for (int i = 0; i < snap.ntsync_count; ++i) {
    snap.ntsync_events[i] = pending_ntsync_[i];
  }
  pending_ntsync_.clear();

  // Scheduler-decision counters: per-CPU array, summed across CPUs. The BPF
  // side only bumps a per-CPU counter per decision, so the hot dispatch path
  // stays near-zero; the cost here is one map lookup of a small per-CPU array.
  if (skel_ && skel_->maps.sched_op_counts) {
    int fd = bpf_map__fd(skel_->maps.sched_op_counts);
    int ncpu = libbpf_num_possible_cpus();
    if (fd >= 0 && ncpu > 0) {
      std::vector<struct sched_op_counters> per(static_cast<size_t>(ncpu));
      uint32_t key = 0;
      if (bpf_map_lookup_elem(fd, &key, per.data()) == 0) {
        for (int o = 0; o < MONTAUK_SCHED_OP_MAX &&
                        o < static_cast<int>(snap.sched_op_total.size()); ++o) {
          uint64_t sum = 0;
          for (int c = 0; c < ncpu; ++c)
            sum += per[static_cast<size_t>(c)].op[o];
          snap.sched_op_total[o] = sum;
        }
      }
    }
  }

  // Migration classification counters (intra/cross/unknown cache domain): same per-CPU
  // array sum pattern. Cumulative since attach — churn-proof globals that a
  // fork-storm's short-lived threads cannot carry off when they exit.
  if (skel_ && skel_->maps.mig_domain_counts) {
    int fd = bpf_map__fd(skel_->maps.mig_domain_counts);
    int ncpu = libbpf_num_possible_cpus();
    if (fd >= 0 && ncpu > 0) {
      std::vector<struct mig_domain_counters> per(static_cast<size_t>(ncpu));
      uint32_t key = 0;
      if (bpf_map_lookup_elem(fd, &key, per.data()) == 0) {
        uint64_t in = 0, cr = 0, un = 0, iw = 0, is = 0, cw = 0, cs = 0;
        for (int c = 0; c < ncpu; ++c) {
          in += per[static_cast<size_t>(c)].intra;
          cr += per[static_cast<size_t>(c)].cross;
          un += per[static_cast<size_t>(c)].unknown;
          iw += per[static_cast<size_t>(c)].intra_wake;
          is += per[static_cast<size_t>(c)].intra_steal;
          cw += per[static_cast<size_t>(c)].cross_wake;
          cs += per[static_cast<size_t>(c)].cross_steal;
        }
        snap.mig_intra_domain = in;
        snap.mig_cross_domain = cr;
        snap.mig_unknown_domain = un;
        snap.mig_intra_wake = iw;
        snap.mig_intra_steal = is;
        snap.mig_cross_wake = cw;
        snap.mig_cross_steal = cs;
      }
    }
  }

  last_snapshot_ns_ = now_ns;
}

// Main run loop — zero /proc reads after BPF attach
void BpfTraceCollector::run(std::stop_token st) {
  skel_ = montauk_trace_bpf__open();
  if (!skel_) {
    montauk::util::log_error("failed to open BPF skeleton");
    load_failed_.store(true);
    return;
  }

  // Write pattern to .rodata BEFORE load — libbpf freezes .rodata at load time.
  // bpf_strncmp requires a readonly (frozen + BPF_F_RDONLY_PROG) map pointer.
  {
    // Only the primary (first) token goes to the BPF fast-path; the remaining
    // tokens are matched by the userspace rescan (see matches_any).
    auto len = primary_pattern_.size();
    if (len > TRACE_PATTERN_MAX - 1) len = TRACE_PATTERN_MAX - 1;
    for (size_t i = 0; i < len; ++i) {
      char c = primary_pattern_[i];
      skel_->rodata->trace_pat.pattern[i] = (c >= 'A' && c <= 'Z') ? c + 32 : c;
    }
    skel_->rodata->trace_pat.len = static_cast<uint8_t>(len);
    montauk::util::log_info("BPF pattern set in .rodata (%zu bytes: %s)",
                 len, pattern_.c_str());
  }

  // Per-event sched streaming to the ringbuf is a firehose on a hot dispatch
  // path; keep it off unless the binary --trace-out log is active. The per-CPU
  // sched_op counters are maintained regardless, so the snapshot always sees
  // the decision rates.
  skel_->rodata->sched_stream = (trace_fd_ >= 0 || stream_fd_ >= 0) ? 1 : 0;
  // --sched-detail: emit the per-CPU idle-boundary firehose only when explicitly
  // asked (off by default, so a generic --trace does not pay the ~6x cost).
  skel_->rodata->sched_detail = sched_detail_ ? 1 : 0;

  // Heap caller-stack capture: MONTAUK_HEAP_STACK_SIZE=<bytes> makes every
  // malloc/calloc of exactly that size emit a TRACE_EVT_HEAPSTACK with the
  // allocator's user stack. Targets the top-chunk/!prev corruption class:
  // once forensics name the victim allocation's size, one run with this set
  // names the allocation site. .rodata, so it must be set before load.
  if (const char* hss = std::getenv("MONTAUK_HEAP_STACK_SIZE")) {
    skel_->rodata->heap_stack_size = std::strtoull(hss, nullptr, 0);
    if (skel_->rodata->heap_stack_size)
      montauk::util::log_info("heap caller-stack capture armed for size=%llu",
                   (unsigned long long)skel_->rodata->heap_stack_size);
  }

  // Per-CPU kthread strand threshold: MONTAUK_KSTRAND_THRESH_NS lowers/raises
  // the became-runnable -> ran wait at which a per-CPU kthread emits a
  // TRACE_EVT_KSTRAND. Default (5ms) lives in the BPF .rodata. .rodata, so set
  // before load.
  if (const char* kt = std::getenv("MONTAUK_KSTRAND_THRESH_NS")) {
    unsigned long long v = std::strtoull(kt, nullptr, 0);
    if (v) {
      skel_->rodata->kstrand_thresh_ns = v;
      montauk::util::log_info("per-CPU kthread strand threshold set to %lluns", v);
    }
  }

  // scx storm probes are fentry/fexit trampolines on sched_ext's OWN kfuncs
  // (scx_bpf_kick_cpu / scx_bpf_reenqueue_local). fentry resolves its BTF
  // target at LOAD time, so on a kernel without sched_ext the missing kfunc
  // fails the ENTIRE skeleton load -- every universal handler dies with it
  // (the silica bench guest: libbpf "failed to find kernel BTF type ID of
  // 'scx_bpf_kick_cpu': -ESRCH" killed the whole capture). Autoload them
  // only when the running kernel's BTF actually carries the kfunc; the
  // attach side already gates them behind MONTAUK_SCX_STORM.
  {
    struct btf* vmlinux_btf = btf__load_vmlinux_btf();
    bool have_scx = vmlinux_btf &&
        btf__find_by_name_kind(vmlinux_btf, "scx_bpf_kick_cpu",
                               BTF_KIND_FUNC) > 0;
    btf__free(vmlinux_btf);
    if (!have_scx) {
      bpf_program__set_autoload(skel_->progs.handle_scx_kick,  false);
      bpf_program__set_autoload(skel_->progs.handle_scx_reenq, false);
      montauk::util::log_info("kernel BTF lacks sched_ext kfuncs; "
                              "scx storm probes disabled for this boot");
    }
  }

  int err = montauk_trace_bpf__load(skel_);
  if (err) {
    montauk::util::log_error("failed to load BPF programs (need root or CAP_BPF)");
    montauk_trace_bpf__destroy(skel_);
    skel_ = nullptr;
    load_failed_.store(true);
    return;
  }

  // Push the cpu->cache domain topology so sched_switch can classify each migration as
  // intra- vs cross-domain (a fork-storm's core-hopping surfaces in mig_domain_counts).
  if (skel_->maps.cpu_cache_domain)
    populate_cache_domain_map(bpf_map__fd(skel_->maps.cpu_cache_domain));

  // Generic scheduler-decision programs, attached at RUNTIME to the active
  // scheduler's tracepoints. The bindings come from MONTAUK_SCHED_TRACEPOINTS as
  // up to 6 comma-separated category:name entries, in role order:
  //   enqueue, pick, pick_empty, preempt_tick, preempt_wakeup, field_gate
  // montauk names no scheduler in source; unset or missing bindings are simply
  // skipped, so the universal sched_switch/fork/exec/syscall trace always
  // attaches regardless of which scheduler (if any) is loaded. System-agnostic.
  struct DecisionProg { bpf_program *prog; bpf_link **link; };
  const DecisionProg decision_progs[] = {
    {skel_->progs.handle_sched_enqueue,        &skel_->links.handle_sched_enqueue},
    {skel_->progs.handle_sched_pick,           &skel_->links.handle_sched_pick},
    {skel_->progs.handle_sched_pick_empty,     &skel_->links.handle_sched_pick_empty},
    {skel_->progs.handle_sched_preempt_tick,   &skel_->links.handle_sched_preempt_tick},
    {skel_->progs.handle_sched_preempt_wakeup, &skel_->links.handle_sched_preempt_wakeup},
    {skel_->progs.handle_sched_field_gate,     &skel_->links.handle_sched_field_gate},
  };
  // Neutral placeholder SECs never auto-attach; we bind them by hand below.
  for (const auto &dp : decision_progs)
    bpf_program__set_autoattach(dp.prog, false);
  // The task iterator is driven on demand from snapshot_from_maps, not auto-attached.
  bpf_program__set_autoattach(skel_->progs.enroll_threads, false);

  // Heap uprobes (libc malloc/free/realloc/calloc) have neutral
  // SEC("uprobe"/"uretprobe") declarations — libbpf can't auto-attach
  // them without knowing the target binary + symbol. We bind them by
  // hand to libc below, after the universal attach succeeds.
  bpf_program__set_autoattach(skel_->progs.uprobe_malloc,    false);
  bpf_program__set_autoattach(skel_->progs.uretprobe_malloc, false);
  bpf_program__set_autoattach(skel_->progs.uprobe_free,      false);
  bpf_program__set_autoattach(skel_->progs.uprobe_realloc,   false);
  bpf_program__set_autoattach(skel_->progs.uretprobe_realloc,false);
  bpf_program__set_autoattach(skel_->progs.uprobe_calloc,    false);
  bpf_program__set_autoattach(skel_->progs.uretprobe_calloc, false);
  bpf_program__set_autoattach(skel_->progs.uprobe_assert_fail,  false);
  bpf_program__set_autoattach(skel_->progs.uprobe_libc_message, false);
  bpf_program__set_autoattach(skel_->progs.uprobe_abort,        false);

  // scx storm probes OFF by default. handle_scx_kick / handle_scx_reenq /
  // handle_resched_curr are the only montauk programs that trampoline a
  // kernel hot path an scx scheduler hammers at storm rates (~100k/s):
  // fentry/scx_bpf_kick_cpu, fexit/scx_bpf_reenqueue_local, and
  // fentry/resched_curr (called from every kick, plus preemption and wakeup
  // paths generally -- hotter than the kick kfunc itself). Attaching a BPF
  // trampoline patches live kernel text, and on 7.1+ that patch cannot
  // synchronize across CPUs while scx saturates them -- a silent box-wide
  // freeze. The pervasive --trace path must never carry any of them; opt in
  // below with MONTAUK_SCX_STORM for a deliberate storm capture. Skip
  // auto-attach here.
  bpf_program__set_autoattach(skel_->progs.handle_scx_kick,    false);
  bpf_program__set_autoattach(skel_->progs.handle_scx_reenq,   false);
  bpf_program__set_autoattach(skel_->progs.handle_resched_curr, false);

  // Atomic skeleton attach now covers only the universal handlers -- always
  // present, so this cannot fail on a missing scheduler tracepoint.
  err = montauk_trace_bpf__attach(skel_);
  if (err) {
    montauk::util::log_error("failed to attach BPF programs: %d", err);
    montauk_trace_bpf__destroy(skel_);
    skel_ = nullptr;
    load_failed_.store(true);
    return;
  }

  // Opt-in scx storm probes (see the OFF-by-default note above). A storm capture
  // sets MONTAUK_SCX_STORM=1; montauk comes up BEFORE the load ramps, so the
  // trampoline patch lands while scx is still quiescent, and detaches after the
  // load drains -- never patched/unpatched mid-storm. Off => the StormReport is
  // simply empty, never a freeze.
  if (const char* sv = std::getenv("MONTAUK_SCX_STORM");
      sv && sv[0] && sv[0] != '0') {
    skel_->links.handle_scx_kick    = bpf_program__attach(skel_->progs.handle_scx_kick);
    skel_->links.handle_scx_reenq   = bpf_program__attach(skel_->progs.handle_scx_reenq);
    skel_->links.handle_resched_curr = bpf_program__attach(skel_->progs.handle_resched_curr);
    if (skel_->links.handle_scx_kick && skel_->links.handle_scx_reenq &&
        skel_->links.handle_resched_curr)
      montauk::util::log_info("scx storm probes attached (MONTAUK_SCX_STORM)");
    else
      montauk::util::log_warn("scx storm probes requested but attach failed -- "
                              "StormReport will be empty");
  }

  // Bind the decision programs to the configured scheduler tracepoints, if any.
  // Each entry is category:name; a tracepoint that doesn't exist is skipped, not
  // fatal -- a scheduler opts in by emitting the generic decision-event layout.
  int sched_tp = 0;
  const char *tp_cfg = std::getenv("MONTAUK_SCHED_TRACEPOINTS");
  if (tp_cfg && *tp_cfg) {
    char buf[256];
    std::strncpy(buf, tp_cfg, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *saveptr = nullptr;
    size_t role = 0;
    for (char *tok = strtok_r(buf, ",", &saveptr);
         tok && role < 6;
         tok = strtok_r(nullptr, ",", &saveptr), ++role) {
      char *colon = std::strchr(tok, ':');
      if (!colon) continue;
      *colon = '\0';
      const char *cat = tok;
      const char *name = colon + 1;
      if (*cat == '\0' || *name == '\0') continue;
      struct bpf_link *link =
          bpf_program__attach_tracepoint(decision_progs[role].prog, cat, name);
      if (link && libbpf_get_error(link) == 0) {
        *decision_progs[role].link = link;
        ++sched_tp;
      }
    }
  }
  if (sched_tp > 0)
    montauk::util::log_info("attached %d scheduler-decision tracepoint(s)", sched_tp);

  // Pick-stream fallback. If no scheduler pick tracepoint bound, tell the BPF to
  // derive picks from the universal sched_switch (SCHED_OP_SWITCH_IN) so the slice/
  // service reports still resolve (EEVDF, or an scx mode that does not export pick).
  // Set post-attach: the link is known only here, and switch_in_fallback lives in
  // .bss (writable), not the load-frozen rodata. Pick present -> stay quiet so the
  // two pick streams never double up.
  if (skel_->bss)
    skel_->bss->switch_in_fallback =
        (skel_->links.handle_sched_pick == nullptr) ? 1 : 0;

  // Task-iterator thread enrollment: attach the iterator once; we drive it each
  // scan (snapshot_from_maps) to enroll every tracked process's threads, however
  // fast they spawn. Non-fatal if it can't attach -- the reactive sys_enter path
  // still covers the common case.
  enroll_iter_link_ = bpf_program__attach_iter(skel_->progs.enroll_threads, nullptr);
  if (!enroll_iter_link_ || libbpf_get_error(enroll_iter_link_)) {
    montauk::util::log_warn("thread-enrollment iterator did not attach (reactive path only)");
    enroll_iter_link_ = nullptr;
  }

  rb_ = ring_buffer__new(bpf_map__fd(skel_->maps.events), handle_event,
                          this, nullptr);
  if (!rb_) {
    montauk::util::log_error("failed to create ring buffer");
    if (enroll_iter_link_) { bpf_link__destroy(enroll_iter_link_); enroll_iter_link_ = nullptr; }
    montauk_trace_bpf__destroy(skel_);
    skel_ = nullptr;
    load_failed_.store(true);
    return;
  }

  // Heap uprobes
  // Attach malloc/free/realloc/calloc uprobes to libc. Without these,
  // syscall-level traces miss ~99% of allocations (libc's arena services
  // most malloc calls without touching the kernel). Best-effort: a libc
  // without these symbols just logs and continues without heap events.
  {
    struct HeapAttach {
      bpf_program *prog;
      bpf_link    **link;
      const char  *func;
      bool         retprobe;
    };
    const HeapAttach attaches[] = {
      { skel_->progs.uprobe_malloc,     &skel_->links.uprobe_malloc,     "malloc",  false },
      { skel_->progs.uretprobe_malloc,  &skel_->links.uretprobe_malloc,  "malloc",  true  },
      { skel_->progs.uprobe_free,       &skel_->links.uprobe_free,       "free",    false },
      { skel_->progs.uprobe_realloc,    &skel_->links.uprobe_realloc,    "realloc", false },
      { skel_->progs.uretprobe_realloc, &skel_->links.uretprobe_realloc, "realloc", true  },
      { skel_->progs.uprobe_calloc,     &skel_->links.uprobe_calloc,     "calloc",  false },
      { skel_->progs.uretprobe_calloc,  &skel_->links.uretprobe_calloc,  "calloc",  true  },
      // Abort-path uprobes: record the abort text + caller stack at the
      // glibc abort site itself. __libc_message is GLIBC-internal (not in
      // .dynsym on a stripped libc) — its attach failing is expected and
      // harmless; abort() covers that path with the caller stack.
      { skel_->progs.uprobe_assert_fail,  &skel_->links.uprobe_assert_fail,  "__assert_fail",  false },
      { skel_->progs.uprobe_libc_message, &skel_->links.uprobe_libc_message, "__libc_message", false },
      { skel_->progs.uprobe_abort,        &skel_->links.uprobe_abort,        "abort",          false },
    };
    // Common libc paths — pick the first that exists.
    const char *libc_candidates[] = {
      "/usr/lib/libc.so.6",
      "/usr/lib64/libc.so.6",
      "/lib/x86_64-linux-gnu/libc.so.6",
      "/lib64/libc.so.6",
      nullptr,
    };
    const char *libc_path = nullptr;
    for (int i = 0; libc_candidates[i]; ++i) {
      if (access(libc_candidates[i], R_OK) == 0) {
        libc_path = libc_candidates[i];
        break;
      }
    }
    int heap_attached = 0;
    if (libc_path) {
      for (const auto &a : attaches) {
        LIBBPF_OPTS(bpf_uprobe_opts, opts,
                    .retprobe  = a.retprobe,
                    .func_name = a.func);
        struct bpf_link *link =
            bpf_program__attach_uprobe_opts(a.prog, /*pid=*/-1,
                                             libc_path, /*func_offset=*/0,
                                             &opts);
        if (link && libbpf_get_error(link) == 0) {
          *a.link = link;
          ++heap_attached;
        }
      }
      montauk::util::log_info(
                   "libc uprobes attached: %d/%zu to %s",
                   heap_attached, sizeof(attaches) / sizeof(attaches[0]),
                   libc_path);
    } else {
      montauk::util::log_warn(
                   "libc not found — heap/abort uprobes disabled");
    }
  }

  // Keyed-event (critical-section) + wait-site uprobes
  // Wine critical sections (loader_section, etc.) wait/wake via
  // NtWaitForKeyedEvent/NtReleaseKeyedEvent in ntdll.so, passing the
  // CRITICAL_SECTION address as the key. Capturing it makes CS contention
  // traceable by lock identity (the layer futex/ntsync capture misses). The
  // ntdll.so path is install-specific (Proton/Wine), so it's provided at
  // runtime via MONTAUK_NTDLL_PATH; unset → silently skipped (best-effort).
  //
  // The wait-site pair (uprobe_wait_single/uprobe_wait_multiple) captures a raw
  // stack + RIP/RSP/RBP for offline unwinding of frame-pointer-less code -- a
  // generic capability (any FP-less binary benefits), so the two function names
  // it attaches to are operator-configurable via MONTAUK_WAITSTACK_FUNC1/2
  // rather than fixed, defaulting to Wine's NtWaitForSingleObject/
  // NtWaitForMultipleObjects since that's the capability's motivating case. A
  // retargeted function must share the hooked slot's calling convention (the
  // BPF side reads a NULL-pointer-as-timeout argument to gate on infinite
  // waits), so this isn't a blind rename -- the operator is on the hook for
  // pointing it at a compatible signature.
  {
    const char *waitstack_func1 = getenv("MONTAUK_WAITSTACK_FUNC1");
    if (!waitstack_func1 || !*waitstack_func1) waitstack_func1 = "NtWaitForSingleObject";
    const char *waitstack_func2 = getenv("MONTAUK_WAITSTACK_FUNC2");
    if (!waitstack_func2 || !*waitstack_func2) waitstack_func2 = "NtWaitForMultipleObjects";

    struct KevtAttach { bpf_program *prog; bpf_link **link; const char *func; };
    const KevtAttach kattaches[] = {
      { skel_->progs.uprobe_keyed_wait,    &skel_->links.uprobe_keyed_wait,    "NtWaitForKeyedEvent" },
      { skel_->progs.uprobe_keyed_release, &skel_->links.uprobe_keyed_release, "NtReleaseKeyedEvent" },
      { skel_->progs.uprobe_wait_single,   &skel_->links.uprobe_wait_single,   waitstack_func1 },
      { skel_->progs.uprobe_wait_multiple, &skel_->links.uprobe_wait_multiple, waitstack_func2 },
    };
    const char *ntdll_path = getenv("MONTAUK_NTDLL_PATH");
    if (ntdll_path && access(ntdll_path, R_OK) == 0) {
      int kattached = 0;
      for (const auto &a : kattaches) {
        LIBBPF_OPTS(bpf_uprobe_opts, opts,
                    .retprobe  = false,
                    .func_name = a.func);
        struct bpf_link *link =
            bpf_program__attach_uprobe_opts(a.prog, /*pid=*/-1,
                                             ntdll_path, /*func_offset=*/0,
                                             &opts);
        if (link && libbpf_get_error(link) == 0) {
          *a.link = link;
          ++kattached;
        }
      }
      montauk::util::log_info(
                   "ntdll keyed-event + wait-site uprobes attached: %d/4 to %s",
                   kattached, ntdll_path);
    } else {
      montauk::util::log_info(
                   "MONTAUK_NTDLL_PATH unset/unreadable — "
                   "keyed-event (critical-section) uprobes disabled");
    }
  }

  montauk::util::log_info("eBPF trace attached (pattern: %s)",
               pattern_.c_str());

  // Pattern already loaded via .rodata before __load() above.

  // Self-exclusion via getpid/getppid — no /proc
  build_self_exclusion();

  // Expose montauk's own state on the provider mesh (montauk.sock), updated
  // each snapshot cycle below. Non-fatal if the bind fails.
  if (!emitter_.start())
    montauk::util::log_warn("provider emitter bind failed (continuing)");

  // Discovery is tracked in-kernel: discovery_map sees every syscalling process,
  // keyed by the group_leader comm so a multi-threaded target's worker threads
  // never mask the process name. No /proc discovery scan.

  while (!st.stop_requested()) {
    ring_buffer__poll(rb_, 100);

    // Latency-bound the binary log: flush whatever the poll drained so a
    // low-rate trace still lands on disk promptly (the size threshold only
    // fires under bursts).
    trace_flush();

    // Periodic re-scan for comm changes (catches prctl PR_SET_NAME self-renames)
    rescan_comms();

    auto& snap = buffers_.back();
    snap = {};

    snapshot_from_maps(snap);

    if (snap.procs_count == 0) {
      snap.waiting_for_match = true;
      if (!printed_waiting_) {
        montauk::util::log_info("waiting for '%s'...",
                     pattern_.c_str());
        printed_waiting_ = true;
      }
    } else {
      printed_waiting_ = false;
      snap.waiting_for_match = false;
    }

    buffers_.publish();

    // Embed provider snapshots into the binary log once per cycle so the
    // trace carries the providers' view of the same time window.
    append_provider_snapshots();
    append_scx_storm_sample();
    append_drop_snapshot();

    // Publish montauk's own state to the provider mesh (montauk.sock).
    emitter_.update(montauk::app::trace_to_prometheus(snap));

    // Drain the event ring DURING the inter-snapshot sleep. Previously this
    // loop slept the full ~400ms with the ring untouched, so the ring filled
    // at the trace's event rate (~290ms to fill the 256KB ring) and dropped a
    // burst every cycle -- the ~390ms holes in the captured stream, identical
    // whether the machine was idle or loaded because the cause was montauk's
    // own nap, not the workload. Consume every 10ms so the ring can never fill
    // between snapshots; trace_flush() lands the drained bytes promptly.
    for (int i = 0; i < 40 && !st.stop_requested(); ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
      ring_buffer__consume(rb_);
      trace_flush();
    }
  }

  // Final drop snapshot at teardown, unconditional: the capture's last bytes
  // state the whole recording's loss totals even if no snapshot fired during
  // the run, then flush so they land before the fd closes.
  append_drop_snapshot(/*force=*/true);
  trace_flush();
}

} // namespace montauk::collectors
