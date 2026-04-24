#include "collectors/BpfTraceCollector.hpp"
#include "montauk_trace.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "montauk_trace.skel.h"
#include <cstdio>
#include <cstring>
#include <charconv>
#include <unistd.h>

namespace montauk::collectors {

// ---------------------------------------------------------------------------
// Syscall decode table (x86_64, curated)
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Constructor / lifecycle
// ---------------------------------------------------------------------------
BpfTraceCollector::BpfTraceCollector(montauk::app::TraceBuffers& buffers,
                                     std::string pattern)
    : buffers_(buffers), pattern_(std::move(pattern)), matcher_(pattern_) {}

BpfTraceCollector::~BpfTraceCollector() {
  stop();
  if (rb_)
    ring_buffer__free(rb_);
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
}

// ---------------------------------------------------------------------------
// ntsync op name decode
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Ring buffer event handler — NO /proc reads
// ---------------------------------------------------------------------------
int BpfTraceCollector::handle_event(void* ctx, void* data, size_t len) {
  auto* self = static_cast<BpfTraceCollector*>(ctx);

  // ntsync events
  if (len >= sizeof(struct montauk_ntsync_event)) {
    auto* hdr = static_cast<const uint32_t*>(data);
    if (*hdr == TRACE_EVT_NTSYNC) {
      auto* nts = static_cast<const struct montauk_ntsync_event*>(data);
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

  // I/O events have a different struct layout
  if (len >= sizeof(struct montauk_io_event)) {
    auto* hdr = static_cast<const uint32_t*>(data);
    if (*hdr == TRACE_EVT_IO) {
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
      return 0;
    }
  }

  if (len < sizeof(struct montauk_ring_event))
    return 0;

  auto* evt = static_cast<struct montauk_ring_event*>(data);
  int32_t pid = static_cast<int32_t>(evt->pid);

  // Debug: log all events to stderr
  if (evt->type == TRACE_EVT_COMM_CHANGE) {
    std::fprintf(stderr, "montauk: COMM_CHANGE pid=%d comm='%.16s'\n", pid, evt->comm);
  } else if (evt->type == TRACE_EVT_EXEC) {
    std::fprintf(stderr, "montauk: EXEC pid=%d comm='%.16s' file='%.64s'\n",
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
      if (self->matcher_.search(fname) >= 0)
        matched = true;
    }
    // Also match against comm
    if (!matched && evt->comm[0] != '\0') {
      std::string comm(evt->comm);
      if (self->matcher_.search(comm) >= 0)
        matched = true;
    }
    if (matched) {
      self->track_pid(pid, 0, true, evt->comm);
    }
  } else if (evt->type == TRACE_EVT_COMM_CHANGE) {
    // Wine prctl(PR_SET_NAME) — re-evaluate pattern match
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
      if (self->matcher_.search(comm) >= 0) {
        self->track_pid(pid, 0, true, evt->comm);
      }
    }
  }
  // FORK and EXIT handled entirely in BPF
  return 0;
}

// ---------------------------------------------------------------------------
// Track a PID in the BPF proc_map
// ---------------------------------------------------------------------------
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
}

// ---------------------------------------------------------------------------
// Build self-exclusion set — uses getpid/getppid syscalls, NOT /proc
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Periodic re-scan of BPF proc_map comms for pattern matching
// Catches Wine prctl(PR_SET_NAME) and delayed comm changes
// All data from BPF maps — zero /proc reads
// ---------------------------------------------------------------------------
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
        if (matcher_.search(comm) >= 0) {
          std::fprintf(stderr, "montauk: DISCOVERED pid=%d comm='%s' via discovery_map\n",
                       de.pid, comm.c_str());
          track_pid(static_cast<int32_t>(de.pid), 0, true, de.comm);
        }
      }
    }
    key = next_key;
  }
}

// ---------------------------------------------------------------------------
// Snapshot from BPF maps → TraceSnapshot — zero /proc reads
// ---------------------------------------------------------------------------
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

  last_snapshot_ns_ = now_ns;
}

// ---------------------------------------------------------------------------
// Main run loop — zero /proc reads after BPF attach
// ---------------------------------------------------------------------------
void BpfTraceCollector::run(std::stop_token st) {
  skel_ = montauk_trace_bpf__open();
  if (!skel_) {
    std::fprintf(stderr, "montauk: failed to open BPF skeleton\n");
    load_failed_.store(true);
    return;
  }

  // Write pattern to .rodata BEFORE load — libbpf freezes .rodata at load time.
  // bpf_strncmp requires a readonly (frozen + BPF_F_RDONLY_PROG) map pointer.
  {
    auto len = pattern_.size();
    if (len > TRACE_PATTERN_MAX - 1) len = TRACE_PATTERN_MAX - 1;
    for (size_t i = 0; i < len; ++i) {
      char c = pattern_[i];
      skel_->rodata->trace_pat.pattern[i] = (c >= 'A' && c <= 'Z') ? c + 32 : c;
    }
    skel_->rodata->trace_pat.len = static_cast<uint8_t>(len);
    std::fprintf(stderr, "montauk: BPF pattern set in .rodata (%zu bytes: %s)\n",
                 len, pattern_.c_str());
  }

  int err = montauk_trace_bpf__load(skel_);
  if (err) {
    std::fprintf(stderr, "montauk: failed to load BPF programs (need root or CAP_BPF)\n");
    montauk_trace_bpf__destroy(skel_);
    skel_ = nullptr;
    load_failed_.store(true);
    return;
  }

  err = montauk_trace_bpf__attach(skel_);
  if (err) {
    std::fprintf(stderr, "montauk: failed to attach BPF programs: %d\n", err);
    montauk_trace_bpf__destroy(skel_);
    skel_ = nullptr;
    load_failed_.store(true);
    return;
  }

  rb_ = ring_buffer__new(bpf_map__fd(skel_->maps.events), handle_event,
                          this, nullptr);
  if (!rb_) {
    std::fprintf(stderr, "montauk: failed to create ring buffer\n");
    montauk_trace_bpf__destroy(skel_);
    skel_ = nullptr;
    load_failed_.store(true);
    return;
  }

  std::fprintf(stderr, "montauk: eBPF trace attached (pattern: %s)\n",
               pattern_.c_str());

  // Pattern already loaded via .rodata before __load() above.

  // Self-exclusion via getpid/getppid — no /proc
  build_self_exclusion();

  // No initial_scan. No /proc reads. BPF tracepoints populate maps
  // as processes fork/exec/syscall/switch. Userspace pattern matching
  // happens in handle_event (exec + comm_change) and rescan_comms.

  while (!st.stop_requested()) {
    ring_buffer__poll(rb_, 100);

    // Periodic re-scan for comm changes (catches Wine prctl PR_SET_NAME)
    rescan_comms();

    auto& snap = buffers_.back();
    snap = {};

    snapshot_from_maps(snap);

    if (snap.procs_count == 0) {
      snap.waiting_for_match = true;
      if (!printed_waiting_) {
        std::fprintf(stderr, "montauk: waiting for '%s'...\n",
                     pattern_.c_str());
        printed_waiting_ = true;
      }
    } else {
      printed_waiting_ = false;
      snap.waiting_for_match = false;
    }

    buffers_.publish();

    for (int i = 0; i < 40 && !st.stop_requested(); ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

} // namespace montauk::collectors
