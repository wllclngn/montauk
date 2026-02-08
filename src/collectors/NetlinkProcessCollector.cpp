#include "collectors/NetlinkProcessCollector.hpp"
#include "util/Procfs.hpp"
#include "util/Churn.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <unistd.h>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>

namespace montauk::collectors {

// Forward declaration of helper struct and function
struct StatusInfoNetlink {
  std::string user;
  int thread_count{1};
};

static StatusInfoNetlink info_from_status_netlink(int32_t pid);
static std::string read_exe_path_netlink(int32_t pid);

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

    int32_t ppid = 0; uint64_t ut=0, st=0; int64_t rssp=0; std::string comm; char stch='?';
    if (!parse_stat_line(*content_opt, stch, ppid, ut, st, rssp, comm)) {
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
    ps.utime = ut; ps.stime = st; ps.total_time = total_proc;
    ps.rss_kb = (rssp > 0 ? static_cast<uint64_t>(rssp) * (getpagesize()/1024) : 0);
    ps.cpu_pct = cpu_pct; ps.cmd = comm;
    ps.exe_path = read_exe_path_netlink(pid);
    out.processes.push_back(std::move(ps));
    if (stch == 'R') out.state_running++;
    else if (stch == 'S' || stch == 'D') out.state_sleeping++;
    else if (stch == 'Z') out.state_zombie++;
  }

  out.total_processes = out.processes.size();
  out.running_processes = out.state_running;
  // Efficient top-K selection (K = max_procs_)
  if (out.processes.size() > max_procs_) {
    auto nth = out.processes.begin() + static_cast<std::ptrdiff_t>(max_procs_);
    std::nth_element(out.processes.begin(), nth, out.processes.end(), [](const auto& a, const auto& b){ return a.cpu_pct > b.cpu_pct; });
    out.processes.resize(max_procs_);
  }
  std::sort(out.processes.begin(), out.processes.end(), [](const auto& a, const auto& b){ return a.cpu_pct > b.cpu_pct; });

  // Enrich top N: command and user
  out.tracked_count = out.processes.size();
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
    auto info = info_from_status_netlink(ps.pid);
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
        // Try comm as a fallback
        std::ifstream f("/proc/" + std::to_string(pid) + "/comm");
        if (f) std::getline(f, cmd);
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

// ===== Helpers replicated from traditional collector (kept local to avoid refactoring now) =====

uint64_t NetlinkProcessCollector::read_cpu_total() {
  auto txt = montauk::util::read_file_string("/proc/stat"); if (!txt) return 0;
  std::istringstream ss(*txt); std::string line; if (!std::getline(ss, line)) return 0;
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

unsigned NetlinkProcessCollector::read_cpu_count() {
  auto txt = montauk::util::read_file_string("/proc/stat"); if (!txt) return 1;
  std::istringstream ss(*txt); std::string line; unsigned count = 0; bool first = true;
  while (std::getline(ss, line)) {
    if (line.rfind("cpu", 0) == 0) {
      if (first) { first = false; continue; }
      if (line.size() >= 4 && std::isdigit(static_cast<unsigned char>(line[3]))) count++;
    } else if (!first) {
      break;
    }
  }
  if (count == 0) count = 1;
  return count;
}

bool NetlinkProcessCollector::parse_stat_line(const std::string& content, char& state, int32_t& ppid, uint64_t& utime, uint64_t& stime, int64_t& rss_pages, std::string& comm) {
  auto lp = content.find('('); auto rp = content.rfind(')'); if (lp==std::string::npos||rp==std::string::npos||rp<lp) return false;
  comm = content.substr(lp+1, rp-lp-1);
  std::string rest = content.substr(rp+2);
  std::istringstream ss(rest);
  ss >> state; // state
  ss >> ppid; // ppid
  for (int i=0;i<9;i++){ std::string tmp; ss >> tmp; }
  ss >> utime; ss >> stime;
  for (int i=0;i<7;i++){ std::string tmp; ss >> tmp; }
  {
    unsigned long long vsize = 0; ss >> vsize;
  }
  ss >> rss_pages;
  return true;
}

std::string NetlinkProcessCollector::read_cmdline(int32_t pid) {
  auto path = std::string("/proc/") + std::to_string(pid) + "/cmdline";
  auto bytes = montauk::util::read_file_bytes(path);
  if (!bytes) return {};
  std::string out; out.reserve(bytes->size()); bool sep = true;
  for (auto b : *bytes) {
    if (b==0) { if (!sep) { out.push_back(' '); sep = true; } }
    else { out.push_back(static_cast<char>(b)); sep = false; }
  }
  if (!out.empty() && out.back()==' ') out.pop_back();
  return out;
}

static std::string read_exe_path_netlink(int32_t pid) {
  auto link = montauk::util::read_symlink(std::string("/proc/") + std::to_string(pid) + "/exe");
  if (!link) return {};
  return *link;
}

static std::string user_name_cached_local(uint32_t uid) {
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

static StatusInfoNetlink info_from_status_netlink(int32_t pid) {
  StatusInfoNetlink info;
  auto path = std::string("/proc/") + std::to_string(pid) + "/status";
  auto txt = montauk::util::read_file_string(path);
  if (!txt) return info;
  std::istringstream ss(*txt); std::string line;
  while (std::getline(ss, line)) {
    if (line.rfind("Uid:", 0) == 0) {
      std::istringstream ls(line.substr(4));
      uint32_t uid; ls >> uid;
      info.user = user_name_cached_local(uid);
    }
    else if (line.rfind("Threads:", 0) == 0) {
      std::istringstream ls(line.substr(8));
      ls >> info.thread_count;
    }
  }
  return info;
}

std::string NetlinkProcessCollector::user_from_status(int32_t pid) {
  auto path = std::string("/proc/") + std::to_string(pid) + "/status";
  auto txt = montauk::util::read_file_string(path);
  if (!txt) return {};
  std::istringstream ss(*txt); std::string line;
  while (std::getline(ss, line)) {
    if (line.rfind("Uid:", 0) == 0) {
      std::istringstream ls(line.substr(4));
      uint32_t uid; ls >> uid;
      return user_name_cached_local(uid);
    }
  }
  return {};
}

} // namespace montauk::collectors
