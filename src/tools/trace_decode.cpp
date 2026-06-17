// montauk_trace_decode — render a binary --trace-out log to text.
//
// The trace collector writes raw ring-buffer event records to a file at
// trace time (no formatting, batched writes, minimal observer effect).
// This tool does all the formatting offline: open/validate/iterate via
// model/TraceReader.hpp and print one human-readable line per event with
// both elapsed and absolute wall-clock timestamps reconstructed from the
// header's clock anchors.
//
// Usage:
//   montauk_trace_decode FILE          # text, all events
//   montauk_trace_decode FILE --csv    # CSV (type,ts_ns,wall_ns,fields...)

#include "model/TraceReader.hpp"
#include "montauk_trace.h"
#include "util/Log.hpp"

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>

namespace {

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

const char* ntsync_op_name(uint8_t op) {
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

} // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: montauk_trace_decode FILE [--csv]\n");
    return 2;
  }
  const char* path = argv[1];
  bool csv = (argc >= 3 && std::strcmp(argv[2], "--csv") == 0);

  montauk::model::TraceReader reader;
  switch (reader.open(path)) {
    case montauk::model::TraceReadStatus::Ok:
      break;
    case montauk::model::TraceReadStatus::OpenFailed:
      montauk::util::log_error("cannot open '%s'", path);
      return 1;
    case montauk::model::TraceReadStatus::ShortHeader:
      montauk::util::log_error("short read on header");
      return 1;
    case montauk::model::TraceReadStatus::BadMagic:
      montauk::util::log_error("bad magic (not a montauk trace log)");
      return 1;
    default:
      montauk::util::log_error("format version %u, this build expects %u",
                               reader.header().version, montauk::model::kTraceFormatVersion);
      return 1;
  }
  const auto& hdr = reader.header();

  auto to_wall = [&](uint64_t ts_ns) { return reader.to_wall_ns(ts_ns); };
  auto elapsed_ms = [&](uint64_t ts_ns) { return reader.elapsed_ms(ts_ns); };

  if (!csv) {
    char pat[33];
    std::snprintf(pat, sizeof(pat), "%.*s", static_cast<int>(sizeof(hdr.pattern)), hdr.pattern);
    std::printf("# montauk trace log  pattern='%s'  start=%s\n", pat, wall_str(hdr.real_anchor_ns).c_str());
  } else {
    std::printf("type,op,elapsed_ms,wall,pid,tid,cpu,detail\n");
  }

  auto status = reader.for_each([&](uint32_t type, const uint8_t* data, uint32_t len) {
    switch (type) {
      case TRACE_EVT_SCHED: {
        if (len < sizeof(montauk_sched_event)) break;
        auto* s = reinterpret_cast<const montauk_sched_event*>(data);
        if (csv) {
          std::printf("SCHED,%s,%.3f,%s,%d,%d,%u,score=%" PRIu64 " last_cpu=%d sub=%u runtime=%" PRIu64 " budget=%" PRIu64 "\n",
                      sched_op_name(s->op), elapsed_ms(s->timestamp_ns), wall_str(to_wall(s->timestamp_ns)).c_str(),
                      s->pid, s->secondary_pid, s->cpu, (uint64_t)s->score, s->last_cpu, s->sub_idx,
                      (uint64_t)s->runtime_ns, (uint64_t)s->budget_ns);
        } else {
          std::printf("[%10.3f] SCHED %-14s cpu=%-3u pid=%-7d", elapsed_ms(s->timestamp_ns),
                      sched_op_name(s->op), s->cpu, s->pid);
          if (s->op == SCHED_OP_ENQUEUE)
            std::printf(" last_cpu=%d sub=%u score=%" PRIu64, s->last_cpu, s->sub_idx, (uint64_t)s->score);
          else if (s->op == SCHED_OP_PICK)
            std::printf(" score=%" PRIu64, (uint64_t)s->score);
          else if (s->op == SCHED_OP_PREEMPT_TICK)
            std::printf(" runtime=%" PRIu64 " budget=%" PRIu64, (uint64_t)s->runtime_ns, (uint64_t)s->budget_ns);
          else if (s->op == SCHED_OP_PREEMPT_WAKEUP)
            std::printf(" waker=%d", s->secondary_pid);
          else if (s->op == SCHED_OP_WAKEUP)
            std::printf(" target_cpu=%u", s->cpu);
          else if (s->op == SCHED_OP_WAKE2RUN)
            std::printf(" wake2run=%" PRIu64 "us%s", (uint64_t)s->runtime_ns / 1000,
                        s->sub_idx ? " CROSS-CCX" : "");
          std::printf("\n");
        }
        break;
      }
      case TRACE_EVT_NTSYNC: {
        if (len < sizeof(montauk_ntsync_event)) break;
        auto* nts = reinterpret_cast<const montauk_ntsync_event*>(data);
        std::printf("[%10.3f] NTSYNC %-13s pid=%-7d tid=%-7d fd=%-4d result=%ld",
                    elapsed_ms(nts->timestamp_ns), ntsync_op_name(nts->op),
                    nts->pid, nts->tid, nts->fd, (long)nts->result);
        if (nts->op == NTS_WAIT_ANY || nts->op == NTS_WAIT_ALL) {
          uint32_t n = nts->wait_count;
          if (n > NTSYNC_MAX_WAIT_FDS) n = NTSYNC_MAX_WAIT_FDS;
          std::printf(" objs=[");
          for (uint32_t i = 0; i < n; ++i)
            std::printf(i ? ",%d" : "%d", static_cast<int32_t>(nts->wait_fds[i]));
          std::printf("]");
          std::printf(" objptrs=[");
          for (uint32_t i = 0; i < n; ++i)
            std::printf(i ? ",0x%llx" : "0x%llx",
                        (unsigned long long)nts->wait_objs[i]);
          std::printf("]");
        } else if (nts->obj_ptr) {
          std::printf(" objptr=0x%llx", (unsigned long long)nts->obj_ptr);
        }
        std::printf("\n");
        break;
      }
      case TRACE_EVT_IO: {
        if (len < sizeof(montauk_io_event)) break;
        auto* io = reinterpret_cast<const montauk_io_event*>(data);
        // For pread64 (17), `whence` carries the offset (BPF stuffs args[3]
        // into it). For lseek (8), `whence` is the actual whence enum. For
        // other syscalls it's unset. Print accordingly so byte-level
        // analysis can correlate pread → file offset.
        if (io->syscall_nr == 17) {
          std::printf("[%10.3f] IO     %-13s pid=%-7d tid=%-7d fd=%-4d count=%" PRIu64 " offset=%u result=%ld comm='%.16s'\n",
                      elapsed_ms(io->timestamp_ns),
                      io_syscall_name(io->syscall_nr), io->pid, io->tid, io->fd,
                      (uint64_t)io->count, io->whence, (long)io->result, io->comm);
        } else {
          std::printf("[%10.3f] IO     %-13s pid=%-7d tid=%-7d fd=%-4d count=%" PRIu64 " result=%ld comm='%.16s'\n",
                      elapsed_ms(io->timestamp_ns),
                      io_syscall_name(io->syscall_nr), io->pid, io->tid, io->fd,
                      (uint64_t)io->count, (long)io->result, io->comm);
        }
        break;
      }
      case TRACE_EVT_MMAP: {
        if (len < sizeof(montauk_mmap_event)) break;
        auto* m = reinterpret_cast<const montauk_mmap_event*>(data);
        // prot/flags decoded inline so grep can find the kind without a
        // lookup table. SHARED vs PRIVATE matters for write-back semantics;
        // PROT_READ/WRITE/EXEC pinpoints whether this is data or code.
        char prot_s[8] = "---";
        if (m->prot & 0x1) prot_s[0] = 'r';
        if (m->prot & 0x2) prot_s[1] = 'w';
        if (m->prot & 0x4) prot_s[2] = 'x';
        const char* share = (m->flags & 0x1) ? "SHARED" : (m->flags & 0x2) ? "PRIVATE" : "?";
        const char* fixed = (m->flags & 0x10) ? " FIXED" : "";
        std::printf("[%10.3f] MMAP   pid=%-7d tid=%-7d fd=%-4d addr=0x%016" PRIx64 " length=%" PRIu64 " offset=%" PRIu64 " prot=%s %s%s comm='%.16s'\n",
                    elapsed_ms(m->timestamp_ns), m->pid, m->tid, m->fd,
                    (uint64_t)m->addr, (uint64_t)m->length, (uint64_t)m->offset,
                    prot_s, share, fixed, m->comm);
        break;
      }
      case TRACE_EVT_HEAP: {
        if (len < sizeof(montauk_heap_event)) break;
        auto* h = reinterpret_cast<const montauk_heap_event*>(data);
        const char* op = h->op == HEAP_OP_MALLOC  ? "malloc"
                       : h->op == HEAP_OP_FREE    ? "free"
                       : h->op == HEAP_OP_REALLOC ? "realloc"
                       : h->op == HEAP_OP_CALLOC  ? "calloc"
                       : "?";
        if (h->op == HEAP_OP_REALLOC) {
          std::printf("[%10.3f] HEAP   %-9s pid=%-7u tid=%-7u "
                      "old=0x%016" PRIx64 " new=0x%016" PRIx64 " size=%" PRIu64
                      " comm='%.16s'\n",
                      elapsed_ms(h->timestamp_ns), op, h->pid, h->tid,
                      (uint64_t)h->addr, (uint64_t)h->new_addr,
                      (uint64_t)h->size, h->comm);
        } else {
          std::printf("[%10.3f] HEAP   %-9s pid=%-7u tid=%-7u "
                      "addr=0x%016" PRIx64 " size=%" PRIu64 " comm='%.16s'\n",
                      elapsed_ms(h->timestamp_ns), op, h->pid, h->tid,
                      (uint64_t)h->addr, (uint64_t)h->size, h->comm);
        }
        break;
      }
      case TRACE_EVT_SIGNAL: {
        if (len < sizeof(montauk_signal_event)) break;
        auto* s = reinterpret_cast<const montauk_signal_event*>(data);
        const char* signame;
        switch (s->signal_nr) {
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
        const char* kind = (s->kind == SIGEVT_DELIVER) ? "DELIVER" : "EXIT_ABNL";
        std::printf("[%10.3f] SIGNAL %s pid=%u tid=%u sig=%s(%d) sender=%d "
                    "exit_code=0x%x comm='%.16s' stack_depth=%u\n",
                    elapsed_ms(s->timestamp_ns), kind, s->pid, s->tid,
                    signame, s->signal_nr, s->sender_pid,
                    (unsigned)s->exit_code, s->comm, s->stack_depth);
        unsigned n = s->stack_depth;
        if (n > TRACE_STACK_MAX_FRAMES) n = TRACE_STACK_MAX_FRAMES;
        for (unsigned i = 0; i < n; ++i) {
          std::printf("              #%-2u 0x%016" PRIx64 "\n",
                      i, (uint64_t)s->stack_user[i]);
        }
        break;
      }
      case TRACE_EVT_ABORT: {
        if (len < sizeof(montauk_abort_event)) break;
        auto* a = reinterpret_cast<const montauk_abort_event*>(data);
        const char* fn = a->func == ABORT_FN_ASSERT_FAIL  ? "__assert_fail"
                       : a->func == ABORT_FN_LIBC_MESSAGE ? "__libc_message"
                       : a->func == ABORT_FN_ABORT        ? "abort"
                       : "?";
        std::printf("[%10.3f] ABORT  %s pid=%u tid=%u comm='%.16s' "
                    "msg='%.128s' loc='%.128s' line=%u stack_depth=%u\n",
                    elapsed_ms(a->timestamp_ns), fn, a->pid, a->tid, a->comm,
                    a->msg, a->loc, a->line, a->stack_depth);
        unsigned an = a->stack_depth;
        if (an > TRACE_STACK_MAX_FRAMES) an = TRACE_STACK_MAX_FRAMES;
        for (unsigned i = 0; i < an; ++i) {
          std::printf("              #%-2u 0x%016" PRIx64 "\n",
                      i, (uint64_t)a->stack_user[i]);
        }
        break;
      }
      case TRACE_EVT_HEAPSTACK: {
        if (len < sizeof(montauk_heapstack_event)) break;
        auto* h = reinterpret_cast<const montauk_heapstack_event*>(data);
        const char* opn = h->op == HEAP_OP_CALLOC ? "calloc" : "malloc";
        std::printf("[%10.3f] HEAPSTK %s pid=%u tid=%u addr=0x%016" PRIx64
                    " size=%" PRIu64 " comm='%.16s' stack_depth=%u\n",
                    elapsed_ms(h->timestamp_ns), opn, h->pid, h->tid,
                    (uint64_t)h->addr, (uint64_t)h->size, h->comm,
                    h->stack_depth);
        unsigned hn = h->stack_depth;
        if (hn > TRACE_STACK_MAX_FRAMES) hn = TRACE_STACK_MAX_FRAMES;
        for (unsigned i = 0; i < hn; ++i) {
          std::printf("              #%-2u 0x%016" PRIx64 "\n",
                      i, (uint64_t)h->stack_user[i]);
        }
        break;
      }
      case TRACE_EVT_KEYEDEVT: {
        if (len < sizeof(montauk_keyedevt_event)) break;
        auto* k = reinterpret_cast<const montauk_keyedevt_event*>(data);
        std::printf("[%10.3f] KEYEDEVT %-7s pid=%-7u tid=%-7u key=0x%016" PRIx64 " comm='%.16s'\n",
                    elapsed_ms(k->timestamp_ns), k->op == KEVT_RELEASE ? "release" : "wait",
                    k->pid, k->tid, (uint64_t)k->key, k->comm);
        break;
      }
      case TRACE_EVT_FORK:
      case TRACE_EVT_EXEC:
      case TRACE_EVT_EXIT:
      case TRACE_EVT_COMM_CHANGE: {
        if (len < sizeof(montauk_ring_event)) break;
        auto* e = reinterpret_cast<const montauk_ring_event*>(data);
        const char* tn = type == TRACE_EVT_FORK ? "FORK"
                       : type == TRACE_EVT_EXEC ? "EXEC"
                       : type == TRACE_EVT_EXIT ? "EXIT" : "COMM";
        std::printf("[          ] %-5s pid=%-7u ppid=%-7u comm='%.16s'", tn, e->pid, e->ppid, e->comm);
        if (type == TRACE_EVT_EXEC) std::printf(" file='%.64s'", e->filename);
        std::printf("\n");
        break;
      }
      case TRACE_EVT_PROVIDER: {
        if (len < sizeof(montauk_provider_event)) break;
        auto* p = reinterpret_cast<const montauk_provider_event*>(data);
        std::printf("[%10.3f] PROVIDER %.32s snapshot bytes=%u\n",
                    elapsed_ms(p->timestamp_ns), p->name, p->payload_len);
        break;
      }
      default:
        // Unknown type — skip silently; the length prefix already advanced us.
        break;
    }
  });

  if (status == montauk::model::TraceReadStatus::CorruptLength) {
    montauk::util::log_error("corrupt record length %u at event %" PRIu64,
                             reader.corrupt_len(), reader.events_read());
  } else if (status == montauk::model::TraceReadStatus::TruncatedRecord) {
    montauk::util::log_error("truncated record at event %" PRIu64, reader.events_read());
  }

  if (!csv) std::printf("# %" PRIu64 " events\n", reader.events_read());
  return 0;
}
