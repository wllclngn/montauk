#include "collectors/NetlinkProcessCollector.hpp"
#include "collectors/ProcessParsing.hpp"
#include "util/Procfs.hpp"
#include "util/Churn.hpp"

#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <unistd.h>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

namespace montauk::collectors {

NetlinkProcessCollector::NetlinkProcessCollector(size_t max_procs, size_t enrich_top_n)
  : max_procs_(max_procs), enrich_top_n_(enrich_top_n) {}

NetlinkProcessCollector::~NetlinkProcessCollector() { shutdown(); }

bool NetlinkProcessCollector::init() {
  // Create netlink socket
  nl_sock_ = ::socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
  if (nl_sock_ == -1) {
    return false; // permission or not available
  }

  // Bind to process events
  struct sockaddr_nl addr;
  std::memset(&addr, 0, sizeof(addr));
  addr.nl_family = AF_NETLINK;
  addr.nl_groups = CN_IDX_PROC;
  addr.nl_pid = getpid();
  if (::bind(nl_sock_, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    ::close(nl_sock_); nl_sock_ = -1; return false;
  }

  // Subscribe to process events
  send_control_message(PROC_CN_MCAST_LISTEN);

  // CRITICAL: Do an initial /proc scan to populate active_pids_ with existing processes
  // Events only tell us about NEW processes from this point forward!
  {
    std::lock_guard<std::mutex> lk(active_mu_);
    for (auto& name : montauk::util::list_dir("/proc")) {
      if (name.empty() || name[0] < '0' || name[0] > '9') continue;
      int32_t pid = std::strtol(name.c_str(), nullptr, 10);
      if (pid > 0) active_pids_.insert(pid);
    }
  }

  running_ = true;
  event_thread_ = std::thread([this]{ this->event_loop(); });
  return true;
}

void NetlinkProcessCollector::shutdown() {
  if (running_) {
    running_ = false;
    
    // Close socket to wake up blocking recv() in event thread
    if (nl_sock_ != -1) {
      int sock = nl_sock_;
      nl_sock_ = -1;
      // Best-effort unsubscribe before closing
      send_control_message(PROC_CN_MCAST_IGNORE);
      // Shutdown socket for reading to wake up recv()
      ::shutdown(sock, SHUT_RDWR);
      ::close(sock);
    }
    
    // Now thread should wake up and exit
    if (event_thread_.joinable()) event_thread_.join();
  }
}

bool NetlinkProcessCollector::sample(montauk::model::ProcessSnapshot& out) {
  // Snapshot active pids and drain hot set under lock (minimize hold time)
  std::vector<int32_t> all_pids;
  std::vector<int32_t> hot;
  size_t rr = 0;
  {
    std::lock_guard<std::mutex> lk(active_mu_);
    all_pids.reserve(active_pids_.size());
    for (auto pid : active_pids_) all_pids.push_back(pid);
    hot.reserve(hot_pids_.size());
    for (auto pid : hot_pids_) hot.push_back(pid);
    hot_pids_.clear();
    rr = rr_cursor_;
  }

  uint64_t cpu_total = read_cpu_total();
  if (ncpu_ == 0) ncpu_ = read_cpu_count();
  const uint64_t page_kb = static_cast<uint64_t>(getpagesize() / 1024);

  out.processes.clear(); out.total_processes = 0; out.running_processes = 0; out.state_running=0; out.state_sleeping=0; out.state_zombie=0;
  out.total_threads=0;

  std::unordered_map<int32_t, uint64_t> last_snapshot;
  uint64_t last_cpu_total_snapshot = 0;
  bool have_last_snapshot = false;
  {
    std::lock_guard<std::mutex> lk(active_mu_);
    if (have_last_) {
      have_last_snapshot = true;
      last_snapshot = last_per_proc_;
      last_cpu_total_snapshot = last_cpu_total_;
    }
  }

  // Build candidate set within sampling budget: last top-K, hot events, then RR fill
  std::vector<int32_t> candidates; candidates.reserve(std::min(sample_budget_, all_pids.size()));
  std::unordered_set<int32_t> selected;
  selected.reserve(std::min(sample_budget_ * 2, all_pids.size()));
  std::unordered_set<int32_t> active_lookup(all_pids.begin(), all_pids.end());

  auto try_add = [&](int32_t pid){ if (selected.insert(pid).second) candidates.push_back(pid); };
  // 1) Keep last published top-K if still active
  for (int32_t pid : last_top_) { if (active_lookup.count(pid)) try_add(pid); if (candidates.size() >= sample_budget_) break; }
  // 2) Prioritize hot pids (FORK/EXEC)
  for (int32_t pid : hot) { if (active_lookup.count(pid)) try_add(pid); if (candidates.size() >= sample_budget_) break; }
  // 3) Round-robin over remaining actives
  if (!all_pids.empty() && candidates.size() < sample_budget_) {
    size_t need = sample_budget_ - candidates.size();
    size_t total = all_pids.size();
    size_t taken = 0;
    for (; taken < total && taken < need; ++taken) {
      size_t idx = (rr + taken) % total;
      int32_t pid = all_pids[idx];
      if (!selected.count(pid)) candidates.push_back(pid);
    }
    // Update rr cursor under lock
    {
      std::lock_guard<std::mutex> lk(active_mu_);
      rr_cursor_ = all_pids.empty() ? 0 : ((rr + taken) % total);
    }
  }

  // Fallback: if we somehow have no candidates but actives exist, take a small slice
  if (candidates.empty() && !all_pids.empty()) {
    candidates.push_back(all_pids[rr % all_pids.size()]);
    std::lock_guard<std::mutex> lk(active_mu_);
    rr_cursor_ = (rr + 1) % all_pids.size();
  }

  for (int32_t pid : candidates) {
    auto stat_path = std::string("/proc/") + std::to_string(pid) + "/stat";
    auto cached_comm = [&](){
      std::lock_guard<std::mutex> lk(active_mu_);
      auto it = pid_to_comm_.find(pid);
      if (it != pid_to_comm_.end() && !it->second.empty()) return it->second;
      return std::string();
    }();
    auto content_opt = montauk::util::read_file_string(stat_path);
    if (!content_opt) {
      // Likely exited; record churn and surface placeholder row so UI can flag it.
      montauk::util::note_churn(montauk::util::ChurnKind::Proc);
      montauk::model::ProcSample ps;
      ps.pid = pid;
      ps.churn_reason = montauk::model::ChurnReason::ReadFailed;
      ps.cmd = !cached_comm.empty() ? cached_comm : std::to_string(pid);
      out.processes.push_back(std::move(ps));
      continue;
    }

    uint64_t ut=0, st=0; int64_t rssp=0; std::string comm; char stch='?';
    uint64_t minflt=0, majflt=0; int nthreads=1;
    if (!parse_stat_line(*content_opt, stch, ut, st, rssp, comm, minflt, majflt, nthreads)) {
      montauk::util::note_churn(montauk::util::ChurnKind::Proc);
      montauk::model::ProcSample ps;
      ps.pid = pid;
      ps.churn_reason = montauk::model::ChurnReason::ReadFailed;
      ps.cmd = !comm.empty() ? comm : (!cached_comm.empty() ? cached_comm : std::to_string(pid));
      out.processes.push_back(std::move(ps));
      continue;
    }

    const uint64_t total_proc = ut + st;
    double cpu_pct = 0.0;
    if (have_last_snapshot) {
      auto it = last_snapshot.find(pid);
      const uint64_t lastp = (it==last_snapshot.end()) ? total_proc : it->second;
      const uint64_t dp = (total_proc > lastp) ? (total_proc - lastp) : 0;
      const uint64_t dt = (cpu_total > last_cpu_total_snapshot) ? (cpu_total - last_cpu_total_snapshot) : 0;
      if (dt > 0) cpu_pct = (100.0 * static_cast<double>(dp) / static_cast<double>(dt)) * static_cast<double>(ncpu_);
    }

    montauk::model::ProcSample ps; ps.pid = pid;
    ps.total_time = total_proc;
    ps.rss_kb = (rssp > 0 ? static_cast<uint64_t>(rssp) * page_kb : 0);
    ps.cpu_pct = cpu_pct; ps.cmd = comm; // exe/command/user enriched after top-K below
    ps.flt_raw = minflt + majflt; ps.thread_count = nthreads;
    out.processes.push_back(std::move(ps));
    if (stch == 'R') out.state_running++;
    else if (stch == 'S' || stch == 'D') out.state_sleeping++;
    else if (stch == 'Z') out.state_zombie++;
  }

  out.total_processes = out.processes.size();
  out.running_processes = out.state_running;
  top_k_by_cpu_pct(out.processes, max_procs_);

  // Enrich survivors only: exe_path for every kept row (Security scans the
  // whole published set), command/user for the top N
  out.tracked_count = out.processes.size();
  for (auto& ps : out.processes) {
    if (ps.churn_reason == montauk::model::ChurnReason::None)
      ps.exe_path = read_exe_path(ps.pid);
  }
  size_t enrich_n = std::min<size_t>(out.processes.size(), enrich_top_n_);
  out.enriched_count = enrich_n;
  for (size_t i = 0; i < enrich_n; ++i) {
    auto& ps = out.processes[i];
    
    // Try command from EXEC/COMM cache first, fall back to /proc/cmdline
    bool need_cmdline = true;
    {
      std::lock_guard<std::mutex> lk(active_mu_);
      auto it = pid_to_comm_.find(ps.pid);
      if (it != pid_to_comm_.end() && !it->second.empty()) {
        ps.cmd = it->second;
        need_cmdline = false;
      }
    }
    
    if (need_cmdline) {
      auto cmd = read_cmdline(ps.pid);
      if (!cmd.empty()) ps.cmd = std::move(cmd);
    }
    
    // User name and thread count from /proc/[pid]/status
    auto info = info_from_status(ps.pid);
    if (!info.user.empty()) ps.user_name = std::move(info.user);
    out.total_threads += info.thread_count;
  }
  
  // For non-enriched processes, estimate 1 thread each (conservative)
  if (out.processes.size() > enrich_n) {
    out.total_threads += (out.processes.size() - enrich_n);
  }

  // Update last maps for cpu% deltas next cycle and remember the last published top-K
  std::unordered_map<int32_t, uint64_t> next_last;
  next_last.reserve(out.processes.size());
  for (const auto& p : out.processes) next_last[p.pid] = p.total_time;
  std::vector<int32_t> next_top;
  next_top.reserve(out.processes.size());
  for (const auto& p : out.processes) next_top.push_back(p.pid);
  {
    std::lock_guard<std::mutex> lk(active_mu_);
    last_per_proc_ = std::move(next_last);
    last_cpu_total_ = cpu_total;
    have_last_ = true;
    last_top_ = std::move(next_top);
  }
  return true;
}

void NetlinkProcessCollector::event_loop() {
  char buf[4096] __attribute__((aligned(NLMSG_ALIGNTO)));
  while (running_) {
    ssize_t len = ::recv(nl_sock_, buf, sizeof(buf), 0);
    if (len <= 0) {
      // Socket closed or error - exit cleanly
      break;
    }
    // Iterate through netlink messages in buffer
    struct nlmsghdr* nl_hdr = (struct nlmsghdr*)buf;
    while (NLMSG_OK(nl_hdr, len)) {
      if (nl_hdr->nlmsg_type == NLMSG_DONE) {
        void* data = NLMSG_DATA(nl_hdr);
        handle_cn_msg(data, len);
      }
      nl_hdr = NLMSG_NEXT(nl_hdr, len);
    }
  }
}

void NetlinkProcessCollector::handle_cn_msg(void* cn_msg_ptr, ssize_t /*len*/) {
  auto* cn_msg = reinterpret_cast<struct cn_msg*>(cn_msg_ptr);
  if (!cn_msg) return;
  if (cn_msg->id.idx != CN_IDX_PROC || cn_msg->id.val != CN_VAL_PROC) return;

  auto* ev = reinterpret_cast<struct proc_event*>(cn_msg->data);
  if (!ev) return;

  std::lock_guard<std::mutex> lk(active_mu_);
  switch (ev->what) {
    case PROC_EVENT_FORK:
      active_pids_.insert(ev->event_data.fork.child_pid);
      hot_pids_.insert(ev->event_data.fork.child_pid);
      break;
    case PROC_EVENT_EXEC: {
      int32_t pid = ev->event_data.exec.process_pid;
      active_pids_.insert(pid);
      hot_pids_.insert(pid);
      // Update cached command best-effort
      auto cmd = read_cmdline(pid);
      if (cmd.empty()) {
        // Try comm as a fallback (mapped reader honors MONTAUK_PROC_ROOT)
        auto comm = montauk::util::read_file_string("/proc/" + std::to_string(pid) + "/comm");
        if (comm) {
          cmd = *comm;
          if (auto nl = cmd.find('\n'); nl != std::string::npos) cmd.resize(nl);
        }
      }
      if (!cmd.empty()) pid_to_comm_[pid] = std::move(cmd);
      break;
    }
    case PROC_EVENT_EXIT:
      active_pids_.erase(ev->event_data.exit.process_pid);
      pid_to_comm_.erase(ev->event_data.exit.process_pid);
      break;
    case PROC_EVENT_COMM: {
      int32_t pid = ev->event_data.comm.process_pid;
      active_pids_.insert(pid);
      // Update to short name from event (16 chars max)
      std::string name(ev->event_data.comm.comm);
      if (!name.empty()) pid_to_comm_[pid] = std::move(name);
      break;
    }
    default:
      break;
  }
}

void NetlinkProcessCollector::send_control_message(int op) {
  struct cn_msg_mcast {
    struct cb_id id;
    __u32 seq;
    __u32 ack;
    __u16 len;
    __u16 flags;
    enum proc_cn_mcast_op mcast;
  } __attribute__((__packed__));

  struct {
    struct nlmsghdr nl_hdr;
    struct cn_msg_mcast m;
  } msg{};

  std::memset(&msg, 0, sizeof(msg));
  msg.nl_hdr.nlmsg_len = sizeof(msg);
  msg.nl_hdr.nlmsg_pid = getpid();
  msg.nl_hdr.nlmsg_type = NLMSG_DONE;

  msg.m.id.idx = CN_IDX_PROC;
  msg.m.id.val = CN_VAL_PROC;
  msg.m.len = sizeof(enum proc_cn_mcast_op);
  msg.m.mcast = static_cast<proc_cn_mcast_op>(op);

  (void)::send(nl_sock_, &msg, sizeof(msg), 0);
}

} // namespace montauk::collectors
