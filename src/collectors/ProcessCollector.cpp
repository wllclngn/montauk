#include "collectors/ProcessCollector.hpp"
#include "collectors/ProcessParsing.hpp"
#include "util/Procfs.hpp"
#include <algorithm>
#include <unistd.h>
#include "util/Churn.hpp"

namespace montauk::collectors {

ProcessCollector::ProcessCollector(unsigned min_interval_ms, size_t max_procs, size_t enrich_top_n)
  : min_interval_ms_(min_interval_ms), max_procs_(max_procs), enrich_top_n_(enrich_top_n) {}

bool ProcessCollector::sample(montauk::model::ProcessSnapshot& out) {
  auto now = std::chrono::steady_clock::now();
  if (last_run_.time_since_epoch().count()!=0) {
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_run_).count();
    if (static_cast<unsigned>(elapsed) < min_interval_ms_) {
      return false; // within min interval: snapshot section not refreshed
    }
  }
  last_run_ = now;

  uint64_t cpu_total = read_cpu_total();
  if (ncpu_ == 0) ncpu_ = read_cpu_count();
  const uint64_t page_kb = static_cast<uint64_t>(getpagesize() / 1024);
  out.processes.clear(); out.total_processes=0; out.running_processes=0; out.state_running=0; out.state_sleeping=0; out.state_zombie=0;
  out.total_threads=0;

  for (auto& name : montauk::util::list_dir("/proc")) {
    if (name.empty() || name[0]<'0' || name[0]>'9') continue; // numeric
    int32_t pid = std::strtol(name.c_str(), nullptr, 10);
    auto stat_path = std::string("/proc/")+name+"/stat";
    std::optional<std::string> content_opt;
    try { content_opt = montauk::util::read_file_string(stat_path); }
    catch(...) { content_opt = std::nullopt; }
    if (!content_opt) {
      // Record churn and emit a placeholder row so the user sees it happened
      montauk::util::note_churn(montauk::util::ChurnKind::Proc);
      montauk::model::ProcSample ps; ps.pid = pid; ps.total_time=0; ps.rss_kb=0; ps.cpu_pct=0.0; ps.churn_reason = montauk::model::ChurnReason::ReadFailed; ps.cmd = name;
      out.processes.push_back(std::move(ps));
      continue;
    }
    uint64_t ut=0, st=0; int64_t rssp=0; std::string comm;
    char stch='?';
    if (!parse_stat_line(*content_opt, stch, ut, st, rssp, comm)) {
      montauk::util::note_churn(montauk::util::ChurnKind::Proc);
      montauk::model::ProcSample ps; ps.pid = pid; ps.total_time=0; ps.rss_kb=0; ps.cpu_pct=0.0; ps.churn_reason = montauk::model::ChurnReason::ReadFailed; ps.cmd = comm.empty()? name : comm;
      out.processes.push_back(std::move(ps));
      continue;
    }
    uint64_t total_proc = ut + st;
    double cpu_pct = 0.0;
    if (have_last_) {
      auto it = last_per_proc_.find(pid);
      uint64_t lastp = (it==last_per_proc_.end()) ? total_proc : it->second;
      uint64_t dp = (total_proc > lastp) ? (total_proc - lastp) : 0;
      uint64_t dt = (cpu_total > last_cpu_total_) ? (cpu_total - last_cpu_total_) : 0;
      if (dt>0) cpu_pct = (100.0 * static_cast<double>(dp) / static_cast<double>(dt)) * static_cast<double>(ncpu_);
    }
    montauk::model::ProcSample ps; ps.pid=pid; ps.total_time=total_proc; ps.rss_kb = (rssp>0 ? static_cast<uint64_t>(rssp)*page_kb : 0);
    ps.cpu_pct = cpu_pct; ps.cmd = comm; // exe/command/user enriched after top-K below
    out.processes.push_back(std::move(ps));
    // Count process states
    if (stch == 'R') out.state_running++;
    else if (stch == 'S' || stch == 'D') out.state_sleeping++;
    else if (stch == 'Z') out.state_zombie++;
  }
  out.total_processes = out.processes.size();
  out.running_processes = out.state_running;
  top_k_by_cpu_pct(out.processes, max_procs_);
  // enrich survivors only: exe_path for every kept row (Security scans the
  // whole published set), cmdline/user/threads for the top N
  out.tracked_count = out.processes.size();
  for (auto& ps : out.processes) {
    if (ps.churn_reason == montauk::model::ChurnReason::None)
      ps.exe_path = read_exe_path(ps.pid);
  }
  size_t enrich_n = std::min<size_t>(out.processes.size(), enrich_top_n_);
  out.enriched_count = enrich_n;
  for (size_t i=0;i<enrich_n;i++) {
    auto& ps = out.processes[i];
    auto cmd = read_cmdline(ps.pid);
    if (!cmd.empty()) {
      // Truncate cmdline to 512 bytes (enough for display and security scanning)
      if (cmd.size() > 512) {
        cmd.resize(512);
      }
      ps.cmd = std::move(cmd);
    }
    auto info = info_from_status(ps.pid);
    if (!info.user.empty()) ps.user_name = std::move(info.user);
    out.total_threads += info.thread_count;
  }
  // For non-enriched processes, estimate 1 thread each (conservative)
  if (out.processes.size() > enrich_n) {
    out.total_threads += (out.processes.size() - enrich_n);
  }
  // update last maps
  last_per_proc_.clear(); for (auto& p : out.processes) last_per_proc_[p.pid] = p.total_time;
  last_cpu_total_ = cpu_total; have_last_ = true;
  return true;
}

} // namespace montauk::collectors
