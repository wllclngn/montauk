// montauk --decode — render a binary --trace-out log to text.
//
// The trace collector writes raw ring-buffer event records to a file at
// trace time (no formatting, batched writes, minimal observer effect).
// This tool does all the formatting offline: open/validate/iterate via
// model/TraceReader.hpp and print one human-readable line per event with
// both elapsed and absolute wall-clock timestamps reconstructed from the
// header's clock anchors.
//
// Usage:
//   montauk --decode FILE          # text, all events
//   montauk --decode FILE --csv    # CSV (type,ts_ns,wall_ns,fields...)

#include "model/TraceReader.hpp"
#include "model/TraceEnumNames.hpp"
#include "montauk_trace.h"
#include "trace_query.hpp"
#include "util/Log.hpp"
#include "util/sink.h"

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

namespace {

// Decoded output drains through one buffered sink, drained at exit.
sublimation_sink g_out;

using montauk::model::sched_op_name;
using montauk::model::ntsync_op_name;
using montauk::model::futex_cmd_name;
using montauk::model::io_syscall_name;
using montauk::model::signal_name;
using montauk::model::lifecycle_type_name;

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

#include "tools/Entrypoints.hpp"

int montauk_decode_main(int argc, char** argv) {
  sublimation_sink_init_at_exit(&g_out, 1);
  if (argc < 2) {
    montauk::util::log_error("usage: montauk --decode FILE [--csv]");
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
    sublimation_sink_appendf(&g_out, "# montauk trace log  pattern='%s'  start=%s\n",
                             reader.pattern().c_str(), wall_str(hdr.real_anchor_ns).c_str());
  } else {
    sublimation_sink_appendf(&g_out, "type,op,elapsed_ms,wall,pid,tid,cpu,detail\n");
  }

  std::vector<uint8_t> fitted;
  // A tail of text after a record's fixed part, its NULs (an argument vector's
  // separators) as spaces.
  auto tail_text = [](const uint8_t* p, uint32_t n) {
    std::string t(reinterpret_cast<const char*>(p), n);
    for (char& ch : t) if (ch == '\0') ch = ' ';
    while (!t.empty() && t.back() == ' ') t.pop_back();
    return t;
  };
  auto status = reader.for_each([&](uint32_t type, const uint8_t* data, uint32_t len) {
    // An older capture's shorter records read at today's layout, and a record
    // whose text runs past it is skipped.
    if (!(data = montauk::query::fit(type, data, len, fitted))) return;
    switch (type) {
      case TRACE_EVT_SCHED: {
        if (len < sizeof(montauk_sched_event)) break;
        auto* s = reinterpret_cast<const montauk_sched_event*>(data);
        if (csv) {
          sublimation_sink_appendf(&g_out, "SCHED,%s,%.3f,%s,%d,%d,%u,score=%" PRIu64 " last_cpu=%d sub=%u runtime=%" PRIu64 " budget=%" PRIu64 "\n",
                      sched_op_name(s->op), elapsed_ms(s->timestamp_ns), wall_str(to_wall(s->timestamp_ns)).c_str(),
                      s->pid, s->secondary_pid, s->cpu, (uint64_t)s->score, s->last_cpu, s->sub_idx,
                      (uint64_t)s->runtime_ns, (uint64_t)s->budget_ns);
        } else {
          sublimation_sink_appendf(&g_out, "[%10.3f] SCHED %-14s cpu=%-3u pid=%-7d", elapsed_ms(s->timestamp_ns),
                      sched_op_name(s->op), s->cpu, s->pid);
          if (s->op == SCHED_OP_ENQUEUE)
            sublimation_sink_appendf(&g_out, " last_cpu=%d sub=%u score=%" PRIu64, s->last_cpu, s->sub_idx, (uint64_t)s->score);
          else if (s->op == SCHED_OP_PICK)
            sublimation_sink_appendf(&g_out, " score=%" PRIu64, (uint64_t)s->score);
          else if (s->op == SCHED_OP_PREEMPT_TICK)
            sublimation_sink_appendf(&g_out, " runtime=%" PRIu64 " budget=%" PRIu64, (uint64_t)s->runtime_ns, (uint64_t)s->budget_ns);
          else if (s->op == SCHED_OP_PREEMPT_WAKEUP)
            sublimation_sink_appendf(&g_out, " waker=%d", s->secondary_pid);
          else if (s->op == SCHED_OP_WAKEUP)
            sublimation_sink_appendf(&g_out, " target_cpu=%u", s->cpu);
          else if (s->op == SCHED_OP_WAKE2RUN) {
            sublimation_sink_appendf(&g_out, " wake2run=%" PRIu64 "us%s", (uint64_t)s->runtime_ns / 1000,
                        s->sub_idx ? " CROSS-DOMAIN" : "");
            if (s->freq_mhz) sublimation_sink_appendf(&g_out, " freq=%uMHz", s->freq_mhz);
          } else if (s->op == SCHED_OP_KICK_ISSUE)
            sublimation_sink_appendf(&g_out, " issuing_cpu=%d flags=0x%" PRIx64, s->last_cpu, (uint64_t)s->score);
          else if (s->op == SCHED_OP_RESCHED)
            sublimation_sink_appendf(&g_out, " calling_cpu=%d", s->last_cpu);
          else if (s->op == SCHED_OP_TICK_STOP)
            sublimation_sink_appendf(&g_out, " success=%u dependency=0x%" PRIx64, s->sub_idx, (uint64_t)s->score);
          sublimation_sink_appendf(&g_out, "\n");
        }
        break;
      }
      case TRACE_EVT_KSTRAND: {
        if (len < sizeof(montauk_kstrand_event)) break;
        auto* k = reinterpret_cast<const montauk_kstrand_event*>(data);
        if (csv) {
          sublimation_sink_appendf(&g_out, "KSTRAND,%.3f,%s,%u,%u,%s,lat_us=%" PRIu64 "\n",
                      elapsed_ms(k->timestamp_ns), wall_str(to_wall(k->timestamp_ns)).c_str(),
                      k->tid, k->cpu, k->comm, (uint64_t)k->latency_ns / 1000);
        } else {
          sublimation_sink_appendf(&g_out, "[%10.3f] KSTRAND cpu=%-3u tid=%-7u %-16s strand=%" PRIu64 "us\n",
                      elapsed_ms(k->timestamp_ns), k->cpu, k->tid, k->comm,
                      (uint64_t)k->latency_ns / 1000);
        }
        break;
      }
      case TRACE_EVT_NTSYNC: {
        if (len < sizeof(montauk_ntsync_event)) break;
        auto* nts = reinterpret_cast<const montauk_ntsync_event*>(data);
        sublimation_sink_appendf(&g_out, "[%10.3f] NTSYNC %-13s pid=%-7d tid=%-7d fd=%-4d result=%ld",
                    elapsed_ms(nts->timestamp_ns), ntsync_op_name(nts->op),
                    nts->pid, nts->tid, nts->fd, (long)nts->result);
        if (nts->op == NTS_WAIT_ANY || nts->op == NTS_WAIT_ALL) {
          uint32_t n = nts->wait_count;
          if (n > NTSYNC_MAX_WAIT_FDS) n = NTSYNC_MAX_WAIT_FDS;
          sublimation_sink_appendf(&g_out, " objs=[");
          for (uint32_t i = 0; i < n; ++i)
            sublimation_sink_appendf(&g_out, i ? ",%d" : "%d", static_cast<int32_t>(nts->wait_fds[i]));
          sublimation_sink_appendf(&g_out, "]");
          sublimation_sink_appendf(&g_out, " objptrs=[");
          for (uint32_t i = 0; i < n; ++i)
            sublimation_sink_appendf(&g_out, i ? ",0x%llx" : "0x%llx",
                        (unsigned long long)nts->wait_objs[i]);
          sublimation_sink_appendf(&g_out, "]");
        } else if (nts->obj_ptr) {
          sublimation_sink_appendf(&g_out, " objptr=0x%llx", (unsigned long long)nts->obj_ptr);
        }
        sublimation_sink_appendf(&g_out, "\n");
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
          sublimation_sink_appendf(&g_out, "[%10.3f] IO     %-13s pid=%-7d tid=%-7d fd=%-4d count=%" PRIu64 " offset=%u result=%ld comm='%.16s'\n",
                      elapsed_ms(io->timestamp_ns),
                      io_syscall_name(io->syscall_nr), io->pid, io->tid, io->fd,
                      (uint64_t)io->count, io->whence, (long)io->result, io->comm);
        } else {
          sublimation_sink_appendf(&g_out, "[%10.3f] IO     %-13s pid=%-7d tid=%-7d fd=%-4d count=%" PRIu64 " result=%ld comm='%.16s'\n",
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
        sublimation_sink_appendf(&g_out, "[%10.3f] MMAP   pid=%-7d tid=%-7d fd=%-4d addr=0x%016" PRIx64 " length=%" PRIu64 " offset=%" PRIu64 " prot=%s %s%s comm='%.16s'\n",
                    elapsed_ms(m->timestamp_ns), m->pid, m->tid, m->fd,
                    (uint64_t)m->addr, (uint64_t)m->length, (uint64_t)m->offset,
                    prot_s, share, fixed, m->comm);
        break;
      }
      case TRACE_EVT_HEAP: {
        if (len < sizeof(montauk_heap_event)) break;
        auto* h = reinterpret_cast<const montauk_heap_event*>(data);
        const char* op = montauk::model::heap_op_name(h->op);
        if (montauk::model::heap_op_moves(h->op)) {
          sublimation_sink_appendf(&g_out, "[%10.3f] HEAP   %-9s pid=%-7u tid=%-7u "
                      "old=0x%016" PRIx64 " new=0x%016" PRIx64 " size=%" PRIu64
                      " comm='%.16s'\n",
                      elapsed_ms(h->timestamp_ns), op, h->pid, h->tid,
                      (uint64_t)h->addr, (uint64_t)h->new_addr,
                      (uint64_t)h->size, h->comm);
        } else if (h->op >= HEAP_OP_POSIX_MEMALIGN) {
          sublimation_sink_appendf(&g_out, "[%10.3f] HEAP   %-9s pid=%-7u tid=%-7u "
                      "addr=0x%016" PRIx64 " size=%" PRIu64 " align=%" PRIu64
                      " comm='%.16s'\n",
                      elapsed_ms(h->timestamp_ns), op, h->pid, h->tid,
                      (uint64_t)h->addr, (uint64_t)h->size, (uint64_t)h->align, h->comm);
        } else {
          sublimation_sink_appendf(&g_out, "[%10.3f] HEAP   %-9s pid=%-7u tid=%-7u "
                      "addr=0x%016" PRIx64 " size=%" PRIu64 " comm='%.16s'\n",
                      elapsed_ms(h->timestamp_ns), op, h->pid, h->tid,
                      (uint64_t)h->addr, (uint64_t)h->size, h->comm);
        }
        break;
      }
      case TRACE_EVT_SIGNAL: {
        if (len < sizeof(montauk_signal_event)) break;
        auto* s = reinterpret_cast<const montauk_signal_event*>(data);
        const char* signame = s->signal_nr == 0 ? "(none)" : signal_name(s->signal_nr);
        if (!signame) signame = "?";
        const char* kind = (s->kind == SIGEVT_DELIVER) ? "DELIVER" : "EXIT_ABNL";
        sublimation_sink_appendf(&g_out, "[%10.3f] SIGNAL %s pid=%u tid=%u sig=%s(%d) sender=%d "
                    "disposition=%s exit_code=0x%x comm='%.16s' stack_depth=%u user_stack=%u\n",
                    elapsed_ms(s->timestamp_ns), kind, s->pid, s->tid,
                    signame, s->signal_nr, s->sender_pid,
                    montauk::model::signal_disposition_name(s->disposition),
                    (unsigned)s->exit_code, s->comm, s->stack_depth, s->user_stack_len);
        unsigned n = s->stack_depth;
        if (n > TRACE_STACK_MAX_FRAMES) n = TRACE_STACK_MAX_FRAMES;
        for (unsigned i = 0; i < n; ++i) {
          sublimation_sink_appendf(&g_out, "              #%-2u 0x%016" PRIx64 "\n",
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
        sublimation_sink_appendf(&g_out, "[%10.3f] ABORT  %s pid=%u tid=%u comm='%.16s' "
                    "msg='%.128s' loc='%.128s' line=%u stack_depth=%u\n",
                    elapsed_ms(a->timestamp_ns), fn, a->pid, a->tid, a->comm,
                    a->msg, a->loc, a->line, a->stack_depth);
        unsigned an = a->stack_depth;
        if (an > TRACE_STACK_MAX_FRAMES) an = TRACE_STACK_MAX_FRAMES;
        for (unsigned i = 0; i < an; ++i) {
          sublimation_sink_appendf(&g_out, "              #%-2u 0x%016" PRIx64 "\n",
                      i, (uint64_t)a->stack_user[i]);
        }
        break;
      }
      case TRACE_EVT_HEAPSTACK: {
        if (len < sizeof(montauk_heapstack_event)) break;
        auto* h = reinterpret_cast<const montauk_heapstack_event*>(data);
        const char* opn = montauk::model::heap_op_name(h->op);
        sublimation_sink_appendf(&g_out, "[%10.3f] HEAPSTK %s pid=%u tid=%u addr=0x%016" PRIx64
                    " size=%" PRIu64 " comm='%.16s' stack_depth=%u\n",
                    elapsed_ms(h->timestamp_ns), opn, h->pid, h->tid,
                    (uint64_t)h->addr, (uint64_t)h->size, h->comm,
                    h->stack_depth);
        unsigned hn = h->stack_depth;
        if (hn > TRACE_STACK_MAX_FRAMES) hn = TRACE_STACK_MAX_FRAMES;
        for (unsigned i = 0; i < hn; ++i) {
          sublimation_sink_appendf(&g_out, "              #%-2u 0x%016" PRIx64 "\n",
                      i, (uint64_t)h->stack_user[i]);
        }
        break;
      }
      case TRACE_EVT_WAITSTACK: {
        if (len < sizeof(montauk_waitstack_event)) break;
        auto* w = reinterpret_cast<const montauk_waitstack_event*>(data);
        sublimation_sink_appendf(&g_out, "[%10.3f] WAITSTK pid=%u tid=%u obj=0x%016" PRIx64
                    " comm='%.16s' stack_depth=%u (INFINITE wait)\n",
                    elapsed_ms(w->timestamp_ns), w->pid, w->tid,
                    (uint64_t)w->obj_ptr, w->comm, w->stack_depth);
        unsigned wn = w->stack_depth;
        if (wn > TRACE_STACK_MAX_FRAMES) wn = TRACE_STACK_MAX_FRAMES;
        for (unsigned i = 0; i < wn; ++i) {
          sublimation_sink_appendf(&g_out, "              #%-2u 0x%016" PRIx64 "\n",
                      i, (uint64_t)w->stack_user[i]);
        }
        break;
      }
      case TRACE_EVT_FUTEX: {
        if (len < sizeof(montauk_futex_event)) break;
        auto* f = reinterpret_cast<const montauk_futex_event*>(data);
        sublimation_sink_appendf(&g_out, "[%10.3f] FUTEX  %-13s pid=%-7u tid=%-7u uaddr=0x%016" PRIx64 " val=%" PRIu64,
                    elapsed_ms(f->timestamp_ns), futex_cmd_name(f->op), f->pid, f->tid,
                    (uint64_t)f->uaddr, (uint64_t)f->val);
        if (f->nr_futexes > 1) sublimation_sink_appendf(&g_out, " words=%u", f->nr_futexes);
        if (f->timeout_ns == ~0ULL) sublimation_sink_appendf(&g_out, " timeout=none");
        else sublimation_sink_appendf(&g_out, " timeout=%" PRIu64 "ns", (uint64_t)f->timeout_ns);
        if (f->result == -999) sublimation_sink_appendf(&g_out, " enter");
        else sublimation_sink_appendf(&g_out, " leave result=%ld", (long)f->result);
        sublimation_sink_appendf(&g_out, " comm='%.16s'\n", f->comm);
        break;
      }
      case TRACE_EVT_FUTEXSTACK: {
        if (len < sizeof(montauk_futexstack_event)) break;
        auto* w = reinterpret_cast<const montauk_futexstack_event*>(data);
        sublimation_sink_appendf(&g_out, "[%10.3f] FUTEXSTK pid=%u tid=%u uaddr=0x%016" PRIx64
                    " comm='%.16s' stack_depth=%u (no deadline)\n",
                    elapsed_ms(w->timestamp_ns), w->pid, w->tid,
                    (uint64_t)w->uaddr, w->comm, w->stack_depth);
        unsigned wn = w->stack_depth;
        if (wn > TRACE_STACK_MAX_FRAMES) wn = TRACE_STACK_MAX_FRAMES;
        for (unsigned i = 0; i < wn; ++i) {
          sublimation_sink_appendf(&g_out, "              #%-2u 0x%016" PRIx64 "\n",
                      i, (uint64_t)w->stack_user[i]);
        }
        break;
      }
      case TRACE_EVT_KEYEDEVT: {
        if (len < sizeof(montauk_keyedevt_event)) break;
        auto* k = reinterpret_cast<const montauk_keyedevt_event*>(data);
        sublimation_sink_appendf(&g_out, "[%10.3f] KEYEDEVT %-7s pid=%-7u tid=%-7u key=0x%016" PRIx64 " comm='%.16s'\n",
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
        // A record from before lifecycle records carried their time has none.
        if (e->timestamp_ns)
          sublimation_sink_appendf(&g_out, "[%10.3f] %-5s pid=%-7u ppid=%-7u comm='%.16s'",
                      elapsed_ms(e->timestamp_ns), lifecycle_type_name(type), e->pid, e->ppid, e->comm);
        else
          sublimation_sink_appendf(&g_out, "[          ] %-5s pid=%-7u ppid=%-7u comm='%.16s'",
                      lifecycle_type_name(type), e->pid, e->ppid, e->comm);
        if (type == TRACE_EVT_FORK) sublimation_sink_appendf(&g_out, " child=%u", e->child_pid);
        if (type == TRACE_EVT_EXIT) sublimation_sink_appendf(&g_out, " exit_code=0x%x", static_cast<unsigned>(e->exit_code));
        if (type == TRACE_EVT_EXEC) {
          const uint8_t* tail = data + sizeof(*e);
          if (e->path_len) sublimation_sink_appendf(&g_out, " file='%s'", tail_text(tail, e->path_len).c_str());
          else sublimation_sink_appendf(&g_out, " file='%.64s'", e->filename);
          if (e->argv_len)
            sublimation_sink_appendf(&g_out, " argv='%s'", tail_text(tail + e->path_len, e->argv_len).c_str());
        }
        sublimation_sink_appendf(&g_out, "\n");
        break;
      }
      case TRACE_EVT_SYSCALL: {
        if (len < sizeof(montauk_syscall_event)) break;
        auto* c = reinterpret_cast<const montauk_syscall_event*>(data);
        const char* nm = montauk::model::syscall_name(c->nr);
        sublimation_sink_appendf(&g_out, "[%10.3f] SYSCALL %s(%d) pid=%-7u tid=%-7u args=0x%" PRIx64 ",0x%" PRIx64
                    ",0x%" PRIx64 ",0x%" PRIx64 ",0x%" PRIx64 ",0x%" PRIx64 " = %" PRId64 " dur=%" PRIu64 "ns ip=0x%" PRIx64,
                    elapsed_ms(c->timestamp_ns), nm ? nm : "?", c->nr, c->pid, c->tid,
                    (uint64_t)c->arg0, (uint64_t)c->arg1, (uint64_t)c->arg2, (uint64_t)c->arg3,
                    (uint64_t)c->arg4, (uint64_t)c->arg5, (int64_t)c->result, (uint64_t)c->duration_ns,
                    (uint64_t)c->ip);
        if (c->resolved)
          sublimation_sink_appendf(&g_out, " in=[0x%" PRIx64 "-0x%" PRIx64 ")%s", (uint64_t)c->vma_start,
                      (uint64_t)c->vma_end, c->anon ? " anon" : "");
        const uint8_t* tail = data + sizeof(*c);
        if (c->path_len) sublimation_sink_appendf(&g_out, " path='%s'", tail_text(tail, c->path_len).c_str());
        if (c->path2_len)
          sublimation_sink_appendf(&g_out, " path2='%s'", tail_text(tail + c->path_len, c->path2_len).c_str());
        sublimation_sink_appendf(&g_out, " comm='%.16s'\n", c->comm);
        break;
      }
      case TRACE_EVT_PROVIDER: {
        if (len < sizeof(montauk_provider_event)) break;
        auto* p = reinterpret_cast<const montauk_provider_event*>(data);
        sublimation_sink_appendf(&g_out, "[%10.3f] PROVIDER %.32s snapshot bytes=%u\n",
                    elapsed_ms(p->timestamp_ns), p->name, p->payload_len);
        break;
      }
      case TRACE_EVT_DROPS: {
        montauk_drop_event dr;
        if (!montauk_drop_read(data, len, &dr)) break;
        const montauk_drop_event* d = &dr;
        uint64_t total = 0;
        for (uint32_t i = 0; i < MONTAUK_DROP_SLOTS; ++i) total += d->dropped[i];
        sublimation_sink_appendf(&g_out,
            "[%10.3f] DROPS total=%" PRIu64 " (cumulative) writer_err=%" PRIu64
            " lost_bytes=%" PRIu64 "\n",
            elapsed_ms(d->ts_ns), total,
            static_cast<uint64_t>(d->writer_errors),
            static_cast<uint64_t>(d->writer_lost_bytes));
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

  if (!csv) sublimation_sink_appendf(&g_out, "# %" PRIu64 " events\n", reader.events_read());
  return 0;
}
