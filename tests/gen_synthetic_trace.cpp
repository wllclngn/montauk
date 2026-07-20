// Deterministic synthetic montauk trace generator.
//
// Emits a fixed, reproducible per-event trace (MTKTRACE format) that exercises
// the analyzer's report surfaces -- scheduler latency/slice/locality/wakers,
// ntsync endstate/pairing/handles, io-wait, heap double-free -- so the
// output-unification migration has a byte-identical gate that does not depend
// on a live capture. Same bytes every run: no clocks, no randomness, all
// fields are constants or index-derived.
//
// Build: standalone, only the shared headers.
//   g++ -std=c++23 -I include -I . tests/gen_synthetic_trace.cpp -o gen_synthetic_trace
// Run:  ./gen_synthetic_trace tests/fixtures/synthetic.mtk

#include "model/TraceBinary.hpp"
#include "src/bpf/montauk_trace.h"

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>

namespace {

using montauk::model::TraceFileHeader;
using montauk::model::TraceRecordLen;
using montauk::model::kTraceMagic;
using montauk::model::kTraceFormatVersion;

std::vector<uint8_t> g_buf;

void emit(const void* rec, uint32_t len) {
  TraceRecordLen l = len;
  const auto* lp = reinterpret_cast<const uint8_t*>(&l);
  g_buf.insert(g_buf.end(), lp, lp + sizeof(l));
  const auto* dp = reinterpret_cast<const uint8_t*>(rec);
  g_buf.insert(g_buf.end(), dp, dp + len);
}

// Fixed anchors -- arbitrary but constant, so elapsed math is stable.
constexpr uint64_t kMonoAnchor = 1'000'000'000ull;          // 1s mono
constexpr uint64_t kRealAnchor = 1'750'000'000'000'000'000ull; // fixed epoch ns

void set_comm(char* dst, const char* s) {
  std::memset(dst, 0, 16);
  std::strncpy(dst, s, 15);
}

// A deterministic latency spread (ns) with a heavy tail, so p50/p99/p999 are
// distinct and the quantile-tail emit (R1) is actually exercised.
uint64_t spread_ns(int i) {
  uint64_t base = 2'000 + static_cast<uint64_t>(i % 100) * 300; // 2us..32us body
  if (i % 100 == 99) base = 4'000'000;  // ~1% tail at 4ms
  if (i % 1000 == 999) base = 18'000'000; // ~0.1% tail at 18ms
  return base;
}

void sched_evt(uint32_t op, uint32_t cpu, int32_t pid, int32_t sec_pid,
               uint32_t sub_idx, uint64_t runtime, uint64_t budget, uint64_t ts) {
  montauk_sched_event e{};
  e.type = TRACE_EVT_SCHED;
  e.op = op;
  e.cpu = cpu;
  e.pid = pid;
  e.secondary_pid = sec_pid;
  e.last_cpu = -1;
  e.sub_idx = sub_idx;
  e.freq_mhz = 0;
  e.score = 0;
  e.runtime_ns = runtime;
  e.budget_ns = budget;
  e.timestamp_ns = ts;
  emit(&e, sizeof(e));
}

void thread_name(uint32_t tid, const char* comm) {
  // TRACE_EVT_THREAD_NAME uses the montauk_ring_event payload shape.
  montauk_ring_event e{};
  e.type = TRACE_EVT_THREAD_NAME;
  e.pid = tid;
  set_comm(e.comm, comm);
  emit(&e, sizeof(e));
}

void ntsync_evt(uint8_t op, int32_t fd, uint64_t obj_ptr, int64_t result,
                uint32_t tid, uint64_t ts, uint32_t wait_count = 0,
                uint64_t wait_obj0 = 0) {
  montauk_ntsync_event e{};
  e.type = TRACE_EVT_NTSYNC;
  e.pid = 1000;
  e.tid = tid;
  e.op = op;
  e.fd = fd;
  e.result = result;
  e.timestamp_ns = ts;
  e.obj_ptr = obj_ptr;
  e.wait_count = wait_count;
  if (wait_count) {
    e.wait_fds[0] = static_cast<uint32_t>(fd);
    e.wait_objs[0] = wait_obj0;
  }
  set_comm(e.comm, "worker");
  emit(&e, sizeof(e));
}

void io_evt(int32_t syscall_nr, int32_t fd, int64_t result, uint64_t count,
            uint32_t tid, uint64_t ts) {
  montauk_io_event e{};
  e.type = TRACE_EVT_IO;
  e.pid = 1000;
  e.tid = tid;
  e.syscall_nr = syscall_nr;
  e.fd = fd;
  e.result = result;
  e.count = count;
  set_comm(e.comm, "worker");
  e.timestamp_ns = ts;
  emit(&e, sizeof(e));
}

void heap_evt(uint32_t op, uint64_t addr, uint64_t size, uint32_t tid, uint64_t ts) {
  montauk_heap_event e{};
  e.type = TRACE_EVT_HEAP;
  e.pid = 1000;
  e.tid = tid;
  e.op = op;
  e.addr = addr;
  e.size = size;
  e.timestamp_ns = ts;
  set_comm(e.comm, "worker");
  emit(&e, sizeof(e));
}

} // namespace

int main(int argc, char** argv) {
  const char* out = (argc >= 2) ? argv[1] : "synthetic.mtk";

  // Thread identities first so the holder ledger / wakers can name them.
  thread_name(1000, "messenger");
  thread_name(1001, "worker.A");
  thread_name(1002, "worker.B");
  thread_name(7,    "ksoftirqd/0");

  uint64_t ts = kMonoAnchor;

  // Scheduler body: a messenger waking two workers, each wake-to-run carrying a
  // spread latency; alternating CPUs to drive migration rate; periodic preempt
  // ticks with budget overruns; idle boundaries and switch-in picks for slice.
  for (int i = 0; i < 2000; ++i) {
    ts += 50'000; // 50us between events
    int32_t wakee = (i & 1) ? 1001 : 1002;
    uint32_t cpu = (i % 4);

    sched_evt(SCHED_OP_WAKEUP, cpu, wakee, /*waker*/1000, 0, 0, 0, ts);
    // WAKE2RUN: messenger's own wakes carry a larger tail than the workers',
    // so the wakers report's messenger/worker split is non-degenerate.
    uint64_t lat = spread_ns(i);
    // WAKE2RUN carries the became-runnable -> ran latency in runtime_ns.
    sched_evt(SCHED_OP_WAKE2RUN, cpu, wakee, -1, /*cross_domain*/(i % 3 == 0), lat, 0, ts + lat);

    // Slice: switch-in pick + idle boundary, inter-switch interval spreads.
    sched_evt(SCHED_OP_SWITCH_IN, cpu, wakee, -1, 0, 0, 0, ts + lat + 1000);
    if (i % 7 == 0)
      sched_evt(SCHED_OP_CPU_IDLE, cpu, 0, -1, /*entering*/1, 0, 0, ts + lat + 2000);

    // Preempt tick with occasional long-slice overrun (>2ms/5ms/8ms).
    uint64_t run = 800'000 + static_cast<uint64_t>(i % 50) * 60'000;
    if (i % 37 == 0) run = 9'000'000;
    sched_evt(SCHED_OP_PREEMPT_TICK, cpu, wakee, -1, 0, run, /*budget*/1'000'000, ts + 3000);
  }

  // A stranded per-CPU kthread (kstrand): emitted via the sched stream as a
  // wake2run on its bound CPU with a long latency.
  ts += 100'000;
  sched_evt(SCHED_OP_WAKE2RUN, 0, 7, -1, 0, /*lat*/5'000'000, 0, ts + 5'000'000);

  // ENQUEUE events carrying cls_weight in score bits 48+, to exercise REPORT
  // classmix (added v7.12.0): a spread of classes across distinct pids -- one
  // LAT_CRITICAL, two LATENCY pids, one INTERACTIVE, one BATCH.
  ts += 100'000;
  {
    struct { int32_t pid; uint64_t clsw; } enq[] = {
        {1000, 32}, {1001, 8}, {1002, 8}, {1003, 4}, {1004, 1},
    };
    for (int rep = 0; rep < 20; ++rep)
      for (auto& e : enq) {
        montauk_sched_event ev{};
        ev.type = TRACE_EVT_SCHED;
        ev.op = SCHED_OP_ENQUEUE;
        ev.cpu = 0;
        ev.pid = e.pid;
        ev.secondary_pid = -1;
        ev.last_cpu = -1;
        ev.score = e.clsw << 48;
        ts += 1'000;
        ev.timestamp_ns = ts;
        emit(&ev, sizeof(ev));
      }
  }

  // ntsync: create an event + semaphore + mutex, then a wait left parked at
  // trace end (endstate dead-producer), plus set/reset/release pairings.
  ts += 100'000;
  ntsync_evt(NTS_CREATE_EVENT, 10, 0xE0000, 0, 1001, ts);
  ntsync_evt(NTS_CREATE_SEM,   11, 0x50000, 0, 1001, ts + 1000);
  ntsync_evt(NTS_CREATE_MUTEX, 12, 0xA0000, 0, 1001, ts + 2000);

  for (int i = 0; i < 64; ++i) {
    uint64_t t = ts + 10'000 + static_cast<uint64_t>(i) * 5'000;
    ntsync_evt(NTS_EVENT_SET,   10, 0xE0000, 0, 1001, t);
    ntsync_evt(NTS_EVENT_RESET, 10, 0xE0000, 0, 1001, t + 1000); // reset is NOT a wakeup
    if (i % 4 == 0) ntsync_evt(NTS_SEM_RELEASE, 11, 0x50000, 1, 1001, t + 2000);
  }
  // A worker parked on the event forever (wait enter, no matching signal after):
  ntsync_evt(NTS_WAIT_ANY, 10, 0xE0000, -999, 1002, ts + 500'000, /*count*/1, 0xE0000);

  // io: read/write pairs, then a poll left pending at trace end (iowait).
  ts += 600'000;
  for (int i = 0; i < 32; ++i) {
    io_evt(/*read*/0, 5, 4096, 4096, 1001, ts + static_cast<uint64_t>(i) * 2000);
    io_evt(/*write*/1, 6, 256, 256, 1001, ts + static_cast<uint64_t>(i) * 2000 + 500);
  }
  io_evt(/*ppoll pending*/271, 9, -999, 0, 1002, ts + 100'000); // parked in poll

  // heap: matched malloc/free, then a double free.
  ts += 200'000;
  heap_evt(HEAP_OP_MALLOC, 0xAAAA00, 128, 1001, ts);
  heap_evt(HEAP_OP_FREE,   0xAAAA00, 0,   1001, ts + 1000);
  heap_evt(HEAP_OP_MALLOC, 0xBBBB00, 256, 1001, ts + 2000);
  heap_evt(HEAP_OP_FREE,   0xBBBB00, 0,   1001, ts + 3000);
  heap_evt(HEAP_OP_FREE,   0xBBBB00, 0,   1001, ts + 4000); // double free

  // Write header + records.
  TraceFileHeader hdr{};
  std::memcpy(hdr.magic, kTraceMagic, sizeof(hdr.magic));
  hdr.version = kTraceFormatVersion;
  hdr.flags = 0;
  hdr.mono_anchor_ns = kMonoAnchor;
  hdr.real_anchor_ns = kRealAnchor;
  std::strncpy(hdr.pattern, "synthetic", sizeof(hdr.pattern) - 1);

  std::FILE* f = std::fopen(out, "wb");
  if (!f) { std::fprintf(stderr, "cannot open %s\n", out); return 1; }
  std::fwrite(&hdr, sizeof(hdr), 1, f);
  std::fwrite(g_buf.data(), 1, g_buf.size(), f);
  std::fclose(f);
  std::fprintf(stderr, "wrote %s: header + %zu record bytes\n", out, g_buf.size());
  return 0;
}
