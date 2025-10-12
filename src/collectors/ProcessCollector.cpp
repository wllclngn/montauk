#include "collectors/ProcessCollector.hpp"
#include "util/Procfs.hpp"
#include <filesystem>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include <charconv>
#include "util/Churn.hpp"

namespace fs = std::filesystem;

namespace montauk::collectors {

ProcessCollector::ProcessCollector(unsigned min_interval_ms, size_t max_procs, size_t enrich_top_n)
  : min_interval_ms_(min_interval_ms), max_procs_(max_procs), enrich_top_n_(enrich_top_n) {}

static uint64_t read_cpu_total() {
  auto txt = montauk::util::read_file_string("/proc/stat"); if (!txt) return 0;
  std::istringstream ss(*txt); std::string line; if (!std::getline(ss, line)) return 0;
  // parse after 'cpu '
  size_t pos = line.find(' '); if (pos == std::string::npos) return 0;
  std::string_view rest(line.c_str() + pos + 1);
  uint64_t vals[8]{}; int i=0; size_t start=0;
  while (i<8 && start<rest.size()) {
    while (start<rest.size() && (rest[start]==' '||rest[start]=='\t')) ++start;
    size_t end=start; while (end<rest.size() && rest[end]>='0'&&rest[end]<='9') ++end;
    if (end>start) { std::from_chars(rest.data()+start, rest.data()+end, vals[i++]); }
    start=end+1;
  }
  uint64_t total=0; for (int j=0;j<8;++j) total+=vals[j]; return total;
}

static unsigned read_cpu_count() {
  auto txt = montauk::util::read_file_string("/proc/stat"); if (!txt) return 1;
  std::istringstream ss(*txt); std::string line; unsigned count = 0; bool first = true;
  while (std::getline(ss, line)) {
    if (line.rfind("cpu", 0) == 0) {
      if (first) { first = false; continue; } // skip aggregate 'cpu '
      // per-core lines start with 'cpu' followed by a number
      if (line.size() >= 4 && std::isdigit(static_cast<unsigned char>(line[3]))) count++;
    } else if (!first) {
      break; // stop after cpu block
    }
  }
  if (count == 0) count = 1;
  return count;
}

bool ProcessCollector::parse_stat_line(const std::string& content, char& state, int32_t& ppid, uint64_t& utime, uint64_t& stime, int64_t& rss_pages, std::string& comm) {
  // find parentheses
  auto lp = content.find('('); auto rp = content.rfind(')'); if (lp==std::string::npos||rp==std::string::npos||rp<lp) return false;
  comm = content.substr(lp+1, rp-lp-1);
  std::string rest = content.substr(rp+2);
  std::istringstream ss(rest);
  ss >> state; // state
  ss >> ppid; // ppid
  // skip fields up to utime (9 fields)
  for (int i=0;i<9;i++){ std::string tmp; ss >> tmp; }
  ss >> utime; ss >> stime; // utime, stime
  // Skip: cutime, cstime, priority, nice, num_threads, itrealvalue, starttime (7 fields)
  for (int i=0;i<7;i++){ std::string tmp; ss >> tmp; }
  // Next two fields are vsize (bytes) then rss (pages). Consume vsize, then read rss.
  {
    unsigned long long vsize_bytes = 0;
    ss >> vsize_bytes; // discard vsize
  }
  ss >> rss_pages; // rss (pages)
  return true;
}

std::string ProcessCollector::read_cmdline(int32_t pid) {
  auto path = std::string("/proc/")+std::to_string(pid)+"/cmdline";
  std::optional<std::vector<unsigned char>> bytes;
  try { bytes = montauk::util::read_file_bytes(path); } catch(...) { bytes = std::nullopt; montauk::util::note_churn(montauk::util::ChurnKind::Proc); }
  if (!bytes) return {};
  std::string out; out.reserve(bytes->size()); bool sep=true;
  for (auto b : *bytes) { if (b==0) { if(!sep){ out.push_back(' '); sep=true; } } else { out.push_back(static_cast<char>(b)); sep=false; } }
  if (!out.empty() && out.back()==' ') out.pop_back();
  return out;
}

static std::string read_exe_path(int32_t pid) {
  auto link = montauk::util::read_symlink(std::string("/proc/") + std::to_string(pid) + "/exe");
  if (!link) return {};
  return *link;
}

static std::string user_name_cached(uint32_t uid) {
  static std::unordered_map<uint32_t, std::string> cache;
  auto it = cache.find(uid);
  if (it != cache.end()) return it->second;
  std::ifstream pw("/etc/passwd"); std::string pl;
  while (std::getline(pw, pl)) {
    auto c1 = pl.find(':'); if (c1==std::string::npos) continue;
    auto c2 = pl.find(':', c1+1); if (c2==std::string::npos) continue;
    auto c3 = pl.find(':', c2+1); if (c3==std::string::npos) continue;
    uint32_t fuid = std::strtoul(pl.c_str()+c2+1, nullptr, 10);
    if (fuid==uid) {
      std::string name = pl.substr(0, c1);
      cache.emplace(uid, name);
      return name;
    }
  }
  return std::to_string(uid);
}

StatusInfo ProcessCollector::info_from_status(int32_t pid) {
  StatusInfo info;
  auto path = std::string("/proc/")+std::to_string(pid)+"/status";
  std::optional<std::string> txt;
  try { txt = montauk::util::read_file_string(path); } catch(...) { txt = std::nullopt; montauk::util::note_churn(montauk::util::ChurnKind::Proc); }
  if (!txt) return info;
  std::istringstream ss(*txt); std::string line;
  while (std::getline(ss, line)) {
    if (line.rfind("Uid:",0)==0) {
      std::istringstream ls(line.substr(4));
      uint32_t uid; ls >> uid;
      info.user = user_name_cached(uid);
    }
    else if (line.rfind("Threads:",0)==0) {
      std::istringstream ls(line.substr(8));
      ls >> info.thread_count;
    }
  }
  return info;
}

std::string ProcessCollector::user_from_status(int32_t pid) {
  auto path = std::string("/proc/")+std::to_string(pid)+"/status";
  std::optional<std::string> txt;
  try { txt = montauk::util::read_file_string(path); } catch(...) { txt = std::nullopt; montauk::util::note_churn(montauk::util::ChurnKind::Proc); }
  if (!txt) return {};
  std::istringstream ss(*txt); std::string line;
  while (std::getline(ss, line)) {
    if (line.rfind("Uid:",0)==0) {
      std::istringstream ls(line.substr(4));
      uint32_t uid; ls >> uid;
      return user_name_cached(uid);
    }
  }
  return {};
}

bool ProcessCollector::sample(montauk::model::ProcessSnapshot& out) {
  auto now = std::chrono::steady_clock::now();
  if (last_run_.time_since_epoch().count()!=0) {
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_run_).count();
    if (static_cast<unsigned>(elapsed) < min_interval_ms_) {
      return true; // skip
    }
  }
  last_run_ = now;

  uint64_t cpu_total = read_cpu_total();
  if (ncpu_ == 0) ncpu_ = read_cpu_count();
  out.processes.clear(); out.total_processes=0; out.running_processes=0; out.state_running=0; out.state_sleeping=0; out.state_zombie=0;
  out.total_threads=0; out.threads_max=0;
  
  // Read system thread limit
  auto threads_max_opt = montauk::util::read_file_string("/proc/sys/kernel/threads-max");
  if (threads_max_opt) {
    try { out.threads_max = std::stoull(*threads_max_opt); } catch(...) {}
  }
  
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
      montauk::model::ProcSample ps; ps.pid = pid; ps.ppid = 0; ps.utime=ps.stime=ps.total_time=0; ps.rss_kb=0; ps.cpu_pct=0.0; ps.churn = true; ps.cmd = name;
      out.processes.push_back(std::move(ps));
      continue;
    }
    int32_t ppid=0; uint64_t ut=0, st=0; int64_t rssp=0; std::string comm;
    char stch='?';
    if (!parse_stat_line(*content_opt, stch, ppid, ut, st, rssp, comm)) {
      montauk::util::note_churn(montauk::util::ChurnKind::Proc);
      montauk::model::ProcSample ps; ps.pid = pid; ps.ppid = 0; ps.utime=ps.stime=ps.total_time=0; ps.rss_kb=0; ps.cpu_pct=0.0; ps.churn = true; ps.cmd = comm.empty()? name : comm;
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
    montauk::model::ProcSample ps; ps.pid=pid; ps.ppid=ppid; ps.utime=ut; ps.stime=st; ps.total_time=total_proc; ps.rss_kb = (rssp>0 ? static_cast<uint64_t>(rssp)* (getpagesize()/1024) : 0);
    ps.cpu_pct = cpu_pct; ps.cmd = comm; // will enrich command/user below
    ps.exe_path = read_exe_path(pid);
    out.processes.push_back(std::move(ps));
    // Count process states
    if (stch == 'R') out.state_running++;
    else if (stch == 'S' || stch == 'D') out.state_sleeping++;
    else if (stch == 'Z') out.state_zombie++;
  }
  out.total_processes = out.processes.size();
  out.running_processes = out.state_running;
  // Efficient top-K selection (K = max_procs_): partition then sort top K
  if (out.processes.size() > max_procs_) {
    auto nth = out.processes.begin() + static_cast<std::ptrdiff_t>(max_procs_);
    std::nth_element(out.processes.begin(), nth, out.processes.end(), [](const auto& a, const auto& b){ return a.cpu_pct > b.cpu_pct; });
    out.processes.resize(max_procs_);
  }
  std::sort(out.processes.begin(), out.processes.end(), [](const auto& a, const auto& b){ return a.cpu_pct > b.cpu_pct; });
  // enrich top N (cmdline and user) and accumulate thread counts
  out.tracked_count = out.processes.size();
  size_t enrich_n = std::min<size_t>(out.processes.size(), enrich_top_n_);
  out.enriched_count = enrich_n;
  for (size_t i=0;i<enrich_n;i++) {
    auto& ps = out.processes[i];
    auto cmd = read_cmdline(ps.pid); if (!cmd.empty()) ps.cmd = std::move(cmd);
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
