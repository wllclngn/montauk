#include "app/TraceRender.hpp"

#include <string>

namespace montauk::app {

namespace {

using montauk::model::TraceSnapshot;

const char* const kSchedOpName[7] = {
    "", "enqueue", "pick", "pick_empty", "preempt_tick", "preempt_wakeup", "wakeup"};

const char* const kNtsyncOps[] = {
    "create_sem", "sem_release", "wait_any", "wait_all",
    "create_mutex", "mutex_unlock", "mutex_kill",
    "create_event", "event_set", "event_reset", "event_pulse",
    "sem_read", "mutex_read", "event_read"};

void render_procs(MetricsSink& sink, const TraceSnapshot& t) {
  sink.collection_begin("procs", Shape::Objects);
  for (int i = 0; i < t.procs_count; ++i) {
    const auto& p = t.procs[i];
    int sig = p.exit_code & 0x7f;
    int status = (p.exit_code >> 8) & 0xff;
    sink.entry_begin();
    sink.i64({"pid", nullptr, nullptr}, p.pid);
    sink.i64({"ppid", nullptr, nullptr}, p.ppid);
    sink.str({"cmd", nullptr, nullptr}, std::string_view(p.cmd));
    sink.boolean({"is_root", nullptr, nullptr}, p.is_root);
    sink.boolean({"exited", nullptr, nullptr}, p.exited);
    sink.i64({"exit_status", nullptr, nullptr}, status);
    sink.i64({"exit_signal", nullptr, nullptr}, sig);
    sink.str({"exec_file", nullptr, nullptr}, std::string_view(p.exec_file));
    sink.u64({"fork_ts", nullptr, nullptr}, p.fork_ts);
    sink.u64({"exec_ts", nullptr, nullptr}, p.exec_ts);
    sink.u64({"exit_ts", nullptr, nullptr}, p.exit_ts);

    std::string pid_s = std::to_string(p.pid), ppid_s = std::to_string(p.ppid);
    std::string exit_s = std::to_string(status), sig_s = std::to_string(sig);
    std::string fork_s = std::to_string(p.fork_ts), exec_s = std::to_string(p.exec_ts);
    std::string exitts_s = std::to_string(p.exit_ts);
    Label l[]{
        {"pid", pid_s}, {"ppid", ppid_s}, {"cmd", std::string_view(p.cmd)},
        {"root", p.is_root ? "1" : "0"}, {"exited", p.exited ? "1" : "0"},
        {"exit_status", exit_s}, {"exit_signal", sig_s},
        {"exec_file", std::string_view(p.exec_file)},
        {"fork_ts", fork_s}, {"exec_ts", exec_s}, {"exit_ts", exitts_s},
    };
    sink.info_line("montauk_trace_process_info", "Traced process group member", l);
    sink.entry_end();
  }
  sink.collection_end();
}

void render_sched_ops(MetricsSink& sink, const TraceSnapshot& t) {
  bool any = false;
  for (int o = 1; o < 7; ++o) if (t.sched_op_total[o]) { any = true; break; }
  if (!any) return;
  sink.collection_begin("sched_op_total", Shape::Objects);
  MetricDesc desc{nullptr, "montauk_sched_op_total",
                  "Scheduler-decision tracepoint counts (per op, summed across CPUs)",
                  MetricKind::Counter};
  for (int o = 1; o < 7; ++o) {
    sink.entry_begin();
    sink.str({"op", nullptr, nullptr}, kSchedOpName[o]);
    sink.u64({"count", nullptr, nullptr}, t.sched_op_total[o]);
    Label l[]{{"op", kSchedOpName[o]}};
    sink.labeled_u64(desc, l, t.sched_op_total[o]);
    sink.entry_end();
  }
  sink.collection_end();
}

void render_threads(MetricsSink& sink, const TraceSnapshot& t) {
  sink.collection_begin("threads", Shape::Objects);
  MetricDesc cpu_pct_desc{nullptr, "montauk_trace_thread_cpu_percent", "Per-thread CPU utilization"};
  MetricDesc cpu_desc{nullptr, "montauk_trace_thread_cpu", "Per-thread current on-CPU core"};
  MetricDesc mig_desc{nullptr, "montauk_trace_thread_migrations", "Per-thread cross-CPU migration count",
                       MetricKind::Counter};
  MetricDesc syscall_desc{nullptr, "montauk_trace_thread_syscall", "Per-thread current syscall"};
  MetricDesc io_desc{nullptr, "montauk_trace_thread_io", "Per-thread last I/O syscall details"};

  for (int i = 0; i < t.thread_count; ++i) {
    const auto& th = t.threads[i];
    sink.entry_begin();
    sink.i64({"pid", nullptr, nullptr}, th.pid);
    sink.i64({"tid", nullptr, nullptr}, th.tid);
    char state_str[2] = {th.state, '\0'};
    sink.str({"state", nullptr, nullptr}, state_str);
    sink.f64({"cpu_pct", nullptr, nullptr}, th.cpu_pct);
    sink.i64({"cur_cpu", nullptr, nullptr}, th.cur_cpu);
    sink.u64({"migrations", nullptr, nullptr}, th.migrations);
    sink.i64({"syscall_nr", nullptr, nullptr}, th.syscall_nr);
    sink.str({"syscall_name", nullptr, nullptr}, std::string_view(th.syscall_name));
    sink.str({"wchan", nullptr, nullptr}, std::string_view(th.wchan));

    std::string pid_s = std::to_string(th.pid), tid_s = std::to_string(th.tid);
    Label pt[]{{"pid", pid_s}, {"tid", tid_s}, {"comm", std::string_view(th.comm)}};
    // montauk_trace_thread_state needs a 4th Prometheus label ("state") that
    // JSON doesn't -- JSON already wrote `state` as its own field above, so
    // this is prom-only (json_key left null) with its own label set.
    {
      Label ptstate[]{{"pid", pid_s}, {"tid", tid_s}, {"comm", std::string_view(th.comm)},
                       {"state", state_str}};
      sink.labeled_i64({nullptr, "montauk_trace_thread_state", "Per-thread state for traced group"}, ptstate, 1);
    }
    sink.labeled_f64(cpu_pct_desc, pt, th.cpu_pct);
    sink.labeled_i64(cpu_desc, pt, th.cur_cpu);
    sink.labeled_u64(mig_desc, pt, th.migrations);

    {
      std::string nr_s = std::to_string(th.syscall_nr);
      Label sc[]{{"pid", pid_s}, {"tid", tid_s}, {"comm", std::string_view(th.comm)},
                 {"syscall", std::string_view(th.syscall_name)}, {"wchan", std::string_view(th.wchan)}};
      sink.labeled_i64(syscall_desc, sc, th.syscall_nr);
    }

    if (th.io_fd >= 0) {
      sink.i64({"io_fd", nullptr, nullptr}, th.io_fd);
      sink.u64({"io_count", nullptr, nullptr}, th.io_count);
      sink.i64({"io_result", nullptr, nullptr}, th.io_result);
      sink.u64({"io_whence", nullptr, nullptr}, th.io_whence);
      sink.u64({"io_timestamp_ns", nullptr, nullptr}, th.io_timestamp_ns);

      std::string fd_s = std::to_string(th.io_fd), count_s = std::to_string(th.io_count),
                  result_s = std::to_string(th.io_result), whence_s = std::to_string(th.io_whence);
      Label io[]{{"pid", pid_s}, {"tid", tid_s}, {"comm", std::string_view(th.comm)},
                 {"syscall", std::string_view(th.syscall_name)}, {"fd", fd_s},
                 {"count", count_s}, {"result", result_s}, {"whence", whence_s}};
      sink.labeled_u64(io_desc, io, th.io_timestamp_ns);
    }
    sink.entry_end();
  }
  sink.collection_end();
}

void render_migrations(MetricsSink& sink, const TraceSnapshot& t) {
  sink.section_begin("migrations");
  sink.u64({"intra_domain", "montauk_trace_migrations_intra_domain",
            "Cross-core migrations within one cache domain/L3 domain", MetricKind::Counter}, t.mig_intra_domain);
  sink.u64({"cross_domain", "montauk_trace_migrations_cross_domain",
            "Cross-core migrations across cache domain/L3 domains (cross-domain interconnect)",
            MetricKind::Counter}, t.mig_cross_domain);
  sink.u64({"unknown_domain", "montauk_trace_migrations_unknown_domain",
            "Cross-core migrations with unmapped cache domain (topology not pushed)",
            MetricKind::Counter}, t.mig_unknown_domain);
  sink.u64({"intra_wake", "montauk_trace_migrations_intra_wake",
            "Intra-domain migrations that placed a woken task (select_cpu / enqueue spill push)",
            MetricKind::Counter}, t.mig_intra_wake);
  sink.u64({"intra_steal", "montauk_trace_migrations_intra_steal",
            "Intra-domain migrations that pulled an already-runnable task at dispatch (steal)",
            MetricKind::Counter}, t.mig_intra_steal);
  sink.u64({"cross_wake", "montauk_trace_migrations_cross_wake",
            "Cross-domain wake-placements (select_cpu / enqueue spill push)", MetricKind::Counter},
           t.mig_cross_wake);
  sink.u64({"cross_steal", "montauk_trace_migrations_cross_steal",
            "Cross-domain dispatch steals (pull)", MetricKind::Counter}, t.mig_cross_steal);
  sink.section_end();
}

void render_ntsync(MetricsSink& sink, const TraceSnapshot& t) {
  sink.collection_begin("ntsync", Shape::Objects);
  MetricDesc desc{nullptr, "montauk_trace_ntsync", "ntsync synchronization operations"};
  for (int i = 0; i < t.ntsync_count; ++i) {
    const auto& ns = t.ntsync_events[i];
    const char* op_str = (ns.op < 14) ? kNtsyncOps[ns.op] : "unknown";
    sink.entry_begin();
    sink.i64({"pid", nullptr, nullptr}, ns.pid);
    sink.i64({"tid", nullptr, nullptr}, ns.tid);
    sink.str({"comm", nullptr, nullptr}, std::string_view(ns.comm));
    sink.str({"op", nullptr, nullptr}, op_str);
    sink.i64({"fd", nullptr, nullptr}, ns.fd);
    sink.i64({"result", nullptr, nullptr}, ns.result);
    sink.u64({"timestamp_ns", nullptr, nullptr}, ns.timestamp_ns);
    sink.u64({"arg0", nullptr, nullptr}, ns.arg0);
    sink.u64({"arg1", nullptr, nullptr}, ns.arg1);
    sink.u64({"wait_owner", nullptr, nullptr}, ns.wait_owner);

    std::string pid_s = std::to_string(ns.pid), tid_s = std::to_string(ns.tid);
    std::string fd_s = std::to_string(ns.fd), result_s = std::to_string(ns.result);
    std::string arg0_s = std::to_string(ns.arg0), arg1_s = std::to_string(ns.arg1);
    std::string owner_s = std::to_string(ns.wait_owner);
    Label l[]{{"pid", pid_s}, {"tid", tid_s}, {"comm", std::string_view(ns.comm)},
              {"op", op_str}, {"fd", fd_s}, {"result", result_s},
              {"arg0", arg0_s}, {"arg1", arg1_s}, {"owner", owner_s}};
    sink.labeled_u64(desc, l, ns.timestamp_ns);
    sink.entry_end();
  }
  sink.collection_end();
}

void render_fds(MetricsSink& sink, const TraceSnapshot& t) {
  sink.collection_begin("fds", Shape::Objects);
  for (int i = 0; i < t.fd_count; ++i) {
    const auto& fd = t.fds[i];
    sink.entry_begin();
    sink.i64({"pid", nullptr, nullptr}, fd.pid);
    sink.i64({"fd", nullptr, nullptr}, fd.fd_num);
    sink.str({"target", nullptr, nullptr}, std::string_view(fd.target));

    std::string pid_s = std::to_string(fd.pid), fd_s = std::to_string(fd.fd_num);
    Label l[]{{"pid", pid_s}, {"fd", fd_s}, {"target", std::string_view(fd.target)}};
    sink.info_line("montauk_trace_fd_target", "Per-process fd targets", l);
    sink.entry_end();
  }
  sink.collection_end();
}

}  // namespace

void render_trace(MetricsSink& sink, const TraceSnapshot& t) {
  sink.raw_comment("\n# Trace\n");
  sink.boolean({"waiting_for_match", "montauk_trace_waiting", "Trace mode waiting for pattern match"},
               t.waiting_for_match);
  sink.i64({"group_size", "montauk_trace_group_size", "Number of processes in traced group"}, t.procs_count);
  sink.i64({"thread_total", "montauk_trace_thread_total", "Total threads across traced group"}, t.thread_count);
  if (t.procs_count == 0) return;

  render_procs(sink, t);
  render_sched_ops(sink, t);
  if (t.thread_count > 0) {
    render_threads(sink, t);
    render_migrations(sink, t);
  }
  if (t.ntsync_count > 0) render_ntsync(sink, t);
  if (t.fd_count > 0) render_fds(sink, t);
}

}  // namespace montauk::app
