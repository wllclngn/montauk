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
#include <string>
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

void signal_evt(uint32_t kind, int32_t signal_nr, uint32_t tid, uint64_t ts,
                const char* comm, int32_t exit_code = 0) {
  montauk_signal_event e{};
  e.type = TRACE_EVT_SIGNAL;
  e.pid = 1000;
  e.tid = tid;
  e.kind = kind;
  e.signal_nr = signal_nr;
  e.sender_pid = 0;
  e.exit_code = exit_code;
  e.stack_depth = 0;
  e.timestamp_ns = ts;
  e.syscall_nr = -1;
  e.io_fd = -1;
  set_comm(e.comm, comm);
  emit(&e, sizeof(e));
}

void abort_evt(uint32_t func, uint32_t line, uint32_t tid, uint64_t ts,
               const char* comm, const char* msg, const char* loc) {
  montauk_abort_event e{};
  e.type = TRACE_EVT_ABORT;
  e.pid = 1000;
  e.tid = tid;
  e.func = func;
  e.line = line;
  e.stack_depth = 0;
  e.timestamp_ns = ts;
  set_comm(e.comm, comm);
  std::snprintf(e.msg, sizeof(e.msg), "%s", msg);
  std::snprintf(e.loc, sizeof(e.loc), "%s", loc);
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
  // --no-idle omits the CPU_IDLE stream, which makes placement-race report
  // NO-IDLE-STREAM -- a CAPTURE LIMITATION rather than a finding. That is the
  // one thing the golden's freeze path refuses to freeze (it records a
  // `skipped` line instead), and it had no fixture: every capture on hand has
  // the idle stream, so the writer's refusal branch was untested.
  //
  // A real no-sched-detail capture was taken under root on 2026-08-04 to
  // confirm this is the actual mechanism (placement-race = NO-IDLE-STREAM,
  // 10MB) before reproducing it synthetically here. Synthetic is what SHIPS:
  // 600KB, no privileges, and it cannot rot the way a recorded capture does.
  bool no_idle = false;
  for (int i = 2; i < argc; ++i)
    if (std::string(argv[i]) == "--no-idle") no_idle = true;

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
    if (i % 7 == 0 && !no_idle)
      sched_evt(SCHED_OP_CPU_IDLE, cpu, 0, -1, /*entering*/1, 0, 0, ts + lat + 2000);

    // Preempt tick with occasional long-slice overrun (>2ms/5ms/8ms).
    uint64_t run = 800'000 + static_cast<uint64_t>(i % 50) * 60'000;
    if (i % 37 == 0) run = 9'000'000;
    sched_evt(SCHED_OP_PREEMPT_TICK, cpu, wakee, -1, 0, run, /*budget*/1'000'000, ts + 3000);
  }

  // STRANDED PER-CPU KTHREADS (kstrand). These are TRACE_EVT_KSTRAND records,
  // not sched records: KStrandReport::fold() returns immediately on
  // TRACE_EVT_SCHED and only accepts TRACE_EVT_KSTRAND.
  //
  // This used to emit a SCHED wake2run and call it a strand, so the event never
  // reached the report at all -- kstrand ran its EMPTY path on every gate run,
  // and every edit to its aggregation, ranking and quantiles passed by never
  // executing. Two kthreads on different CPUs, with both outcomes represented:
  // two kthreads on different CPUs so the ranking has something to order.
  //
  // Both land HELD (the CPU was busy through the wait), because DARK needs
  // CPU_IDLE intervals overlapping the strand window and this fixture has none
  // there. The DARK branch is therefore still uncovered -- stated rather than
  // implied, since the whole point of this block is that kstrand used to look
  // covered and was not.
  ts += 100'000;
  sched_evt(SCHED_OP_WAKE2RUN, 0, 7, -1, 0, /*lat*/5'000'000, 0, ts + 5'000'000);
  {
    auto kstrand_evt = [&](uint32_t tid, uint32_t cpu, uint64_t lat,
                           uint64_t when, const char* comm) {
      montauk_kstrand_event k{};
      k.type = TRACE_EVT_KSTRAND;
      k.tid = tid;
      k.cpu = cpu;
      k.nr_cpus_allowed = 1;
      k.latency_ns = lat;
      k.timestamp_ns = when;
      std::snprintf(k.comm, sizeof(k.comm), "%s", comm);
      emit(&k, sizeof(k));
    };
    // Timestamps stay INSIDE the existing window: latency_ns is the strand
    // duration and does not have to be spanned by the trace, so placing these
    // milliseconds apart keeps the fixture's duration -- and therefore every
    // rate derived from it -- exactly where it was.
    ts += 100'000;
    kstrand_evt(801, 0,  60'000'000, ts + 1'000'000, "kworker/0:1H");
    kstrand_evt(801, 0,  95'000'000, ts + 2'000'000, "kworker/0:1H");
    kstrand_evt(802, 2, 140'000'000, ts + 3'000'000, "kworker/2:0H");
  }

  // A cache_topology provider snapshot. Without it LocalityReport early-outs
  // with "cannot map migration distance" and its whole interval/quantile path
  // never executes -- so edits to it used to pass the golden gate by never
  // running. 4 CPUs: two L2 pairs sharing one L3 on one socket, which gives
  // same-L2, same-L3 and cross-socket tiers something to land in.
  ts += 100'000;
  {
    // Prometheus exposition, not bare key=value: the analyzer's parser looks
    // for label syntax (key="N"), because a provider snapshot is scraped text.
    const char* topo =
        "montauk_cpu_topology{cpu=\"0\",l2=\"0\",l3=\"0\",socket=\"0\"} 1\n"
        "montauk_cpu_topology{cpu=\"1\",l2=\"0\",l3=\"0\",socket=\"0\"} 1\n"
        "montauk_cpu_topology{cpu=\"2\",l2=\"1\",l3=\"0\",socket=\"0\"} 1\n"
        "montauk_cpu_topology{cpu=\"3\",l2=\"1\",l3=\"1\",socket=\"1\"} 1\n";
    const uint32_t plen = static_cast<uint32_t>(std::strlen(topo));
    std::vector<uint8_t> rec(sizeof(montauk_provider_event) + plen);
    auto* pe = reinterpret_cast<montauk_provider_event*>(rec.data());
    std::memset(pe, 0, sizeof(*pe));
    pe->type = TRACE_EVT_PROVIDER;
    pe->timestamp_ns = ts;
    pe->payload_len = plen;
    std::strncpy(pe->name, "cache_topology", sizeof(pe->name) - 1);
    std::memcpy(rec.data() + sizeof(montauk_provider_event), topo, plen);
    emit(rec.data(), static_cast<uint32_t>(rec.size()));
  }

  // Cross-CPU migrations so locality has tiers and intervals to work with.
  // last_cpu is the migration SOURCE -- the helper above hardcodes -1 (no prior
  // run), which reads as "not a migration", so these are emitted directly.
  // Walk 0->1 (same L2), 1->2 (same L3), 2->3 (cross-socket) and back, with
  // varied gaps so the inter-migration quantiles are not degenerate.
  ts += 10'000;
  {
    const uint32_t path[] = {0, 1, 2, 3, 2, 1};
    uint32_t prev = path[0];
    for (int i = 1; i < 36; ++i) {
      const uint32_t cur = path[static_cast<size_t>(i) % 6];
      ts += 40'000 + static_cast<uint64_t>(i % 5) * 7'000;
      montauk_sched_event ev{};
      ev.type = TRACE_EVT_SCHED;
      ev.op = SCHED_OP_WAKE2RUN;
      ev.cpu = cur;
      ev.pid = 1002;
      ev.secondary_pid = -1;
      ev.last_cpu = static_cast<int32_t>(prev);
      ev.runtime_ns = 12'000;
      ev.timestamp_ns = ts;
      emit(&ev, sizeof(ev));
      prev = cur;
    }
  }

  // Kick/response pairs so KickLatencyReport stops reporting "no kicks
  // captured": a KICK_ISSUE at a target CPU answered by a RESCHED shortly
  // after, plus two deliberately unanswered kicks.
  ts += 100'000;
  for (int i = 0; i < 12; ++i) {
    const uint32_t target = static_cast<uint32_t>(i % 4);
    ts += 50'000;
    sched_evt(SCHED_OP_KICK_ISSUE, target, -1, -1, 0, 0, 0, ts);
    if (i % 5 != 4)  // 2 of 12 go unanswered
      sched_evt(SCHED_OP_RESCHED, target, -1, -1, 0, 0, 0,
                ts + 3'000 + static_cast<uint64_t>(i % 4) * 1'500);
  }

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

  // WAIT COMPLETIONS, which the fixture had none of. result == -999 is the
  // ENTRY sentinel, so every ntsync wait above was an entry and `waits` and
  // `spins` never had a completion to aggregate -- they rendered their empty
  // path on every gate run. A completion carries the signaled object index.
  //
  // Two shapes deliberately: a slow lock, and a TIGHT retry streak on one
  // (tid,obj) pair, which is what `spins` looks for -- consecutive completions
  // with a small inter-wait gap. Without the streak spins stays empty even
  // though waits fills.
  for (int i = 0; i < 24; ++i)
    ntsync_evt(NTS_WAIT_ANY, 11, 0x50000, /*signaled idx*/0, 1001,
               ts + 520'000 + static_cast<uint64_t>(i) * 40'000, 1, 0x50000);
  // The livelock streak has to CLEAR THE DETECTOR, not merely look like one:
  // spins wants kSpinMinIters (1000) consecutive completions on one (tid,fd)
  // with each inter-wait gap under kSpinGapNs (1ms). A 40-iteration streak reads
  // as a spin to a human and to nothing else -- checked, and it left spins on
  // its empty path. 5us apart over 1000 iterations is 5ms of trace.
  for (int i = 0; i < 1200; ++i)
    ntsync_evt(NTS_WAIT_ANY, 12, 0xA0000, 0, 1003,
               ts + 560'000 + static_cast<uint64_t>(i) * 5'000, 1, 0xA0000);

  // FUTEX WAITS reach the same reports by the other door: an IO record whose
  // syscall_nr is futex(202) and whose low fd bits carry a wait op. `futex` had
  // no input at all, so its blocked-thread scan never ran.
  for (int i = 0; i < 12; ++i)
    io_evt(/*futex*/202, /*op FUTEX_WAIT*/0, 0, 0xF00000,
           1004, ts + 600'000 + static_cast<uint64_t>(i) * 30'000);
  // One left open at trace end: a thread still blocked on a futex.
  io_evt(202, 0, -999, 0xF00000, 1005, ts + 980'000);

  // io: read/write pairs, then a poll left pending at trace end (iowait).
  ts += 600'000;
  for (int i = 0; i < 32; ++i) {
    io_evt(/*read*/0, 5, 4096, 4096, 1001, ts + static_cast<uint64_t>(i) * 2000);
    io_evt(/*write*/1, 6, 256, 256, 1001, ts + static_cast<uint64_t>(i) * 2000 + 500);
  }
  io_evt(/*ppoll pending*/271, 9, -999, 0, 1002, ts + 100'000); // parked in poll

  // SIGNALS, which the fixture carried none of -- so `signals` rendered "no
  // signal events in trace" on every gate run and `abortpm`, which correlates a
  // SIGABRT against the aborting thread's live allocations, never correlated
  // anything. Two shapes: deliveries inside the trailing teardown window, and
  // one MID-TRACE death, which is the distinction the report exists to draw.
  ts += 50'000;
  signal_evt(/*SIGEVT_DELIVER*/0, /*SIGSEGV*/11, 1006, ts, "crasher");
  signal_evt(/*SIGEVT_EXIT_ABNL*/1, /*SIGSEGV*/11, 1006, ts + 1'000, "crasher", 139);
  // SIGABRT with live allocations outstanding: the abort-postmortem case.
  heap_evt(HEAP_OP_MALLOC, 0xABC000, 4096, 1007, ts + 2'000);
  heap_evt(HEAP_OP_MALLOC, 0xABD000, 8192, 1007, ts + 3'000);
  signal_evt(/*SIGEVT_DELIVER*/0, /*SIGABRT*/6, 1007, ts + 4'000, "aborter");
  signal_evt(/*SIGEVT_EXIT_ABNL*/1, /*SIGABRT*/6, 1007, ts + 5'000, "aborter", 134);
  // abortpm reads TRACE_EVT_ABORT, a record of its own -- a SIGABRT delivery is
  // NOT one, which is why adding signals alone left it on its empty path. The
  // report correlates the abort against the thread's live allocations, so the
  // two mallocs above are its evidence.
  abort_evt(/*abort_fn*/0, /*line*/42, 1007, ts + 4'500, "aborter",
            "buf != nullptr", "src/render/mesh.c");

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
