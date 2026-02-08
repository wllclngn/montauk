// Minimal on-box analyzer: samples /proc and attributes CPU to a process group
// by substring match in cmdline (e.g., "helium"). Classifies Chromium types
// (renderer, gpu-process, utility) and highlights hot threads.

#include "util/Procfs.hpp"
#include "util/AsciiLower.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace std::chrono_literals;
namespace fs = std::filesystem;

static uint64_t read_cpu_total() {
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

static unsigned read_cpu_count() {
  auto txt = montauk::util::read_file_string("/proc/stat"); if (!txt) return 1;
  std::istringstream ss(*txt); std::string line; unsigned count = 0; bool first = true;
  while (std::getline(ss, line)) {
    if (line.rfind("cpu", 0) == 0) {
      if (first) { first = false; continue; }
      if (line.size() >= 4 && std::isdigit(static_cast<unsigned char>(line[3]))) count++;
    } else if (!first) { break; }
  }
  return count ? count : 1;
}

static bool parse_stat_line(const std::string& content, int32_t& ppid, uint64_t& utime, uint64_t& stime, std::string& comm) {
  auto lp = content.find('('); auto rp = content.rfind(')'); if (lp==std::string::npos||rp==std::string::npos||rp<lp) return false;
  comm = content.substr(lp+1, rp-lp-1);
  std::string rest = content.substr(rp+2);
  std::istringstream ss(rest);
  char state; ss >> state; // state
  ss >> ppid; // ppid
  for (int i=0;i<9;i++){ std::string tmp; ss >> tmp; }
  ss >> utime; ss >> stime; // utime, stime
  return true;
}

static std::string read_cmdline(int32_t pid) {
  auto path = std::string("/proc/")+std::to_string(pid)+"/cmdline";
  auto bytes = montauk::util::read_file_bytes(path); if (!bytes) return {};
  std::string out; out.reserve(bytes->size()); bool sep=true;
  for (auto b : *bytes) { if (b==0) { if(!sep){ out.push_back(' '); sep=true; } } else { out.push_back(static_cast<char>(b)); sep=false; } }
  if (!out.empty() && out.back()==' ') out.pop_back();
  return out;
}

static std::string to_lower(std::string s){ for (auto& c : s) c = (char)montauk::util::ascii_lower((unsigned char)c); return s; }

struct ThreadKey { int32_t pid; int32_t tid; };
struct ThreadStats { uint64_t last=0, delta=0; std::string name; };
struct ProcInfo { std::string cmd; std::string type; };

int main(int argc, char** argv) {
  std::string match = (argc>=2? argv[1] : std::string("helium"));
  int seconds = (argc>=3? std::max(1, std::atoi(argv[2])) : 10);
  int interval_ms = (argc>=4? std::max(20, std::atoi(argv[3])) : 100);

  std::cout << "Analyzing processes matching: '" << match << "' for " << seconds << "s (" << interval_ms << "ms interval)\n";

  (void)read_cpu_count(); // ensure /proc layout is sane; suppress unused warning

  // Find candidate PIDs by substring in cmdline or image path
  std::set<int32_t> pids;
  for (auto& name : montauk::util::list_dir("/proc")) {
    if (name.empty() || name[0]<'0' || name[0]>'9') continue;
    int32_t pid = std::strtol(name.c_str(), nullptr, 10);
    auto cmd = read_cmdline(pid);
    auto low = to_lower(cmd);
    if (low.find(to_lower(match)) != std::string::npos || low.find("/opt/helium/")!=std::string::npos) {
      pids.insert(pid);
    }
  }
  if (pids.empty()) {
    std::cout << "No matching processes found.\n";
    return 0;
  }
  std::cout << "Found PIDs:";
  for (auto pid : pids) std::cout << " " << pid;
  std::cout << "\n";

  // Map PID -> info (cmd + chromium type if present)
  std::unordered_map<int32_t, ProcInfo> procinfo;
  for (auto pid : pids) {
    auto cmd = read_cmdline(pid);
    std::string type;
    auto pos = cmd.find("--type="); if (pos != std::string::npos) {
      auto end = cmd.find(' ', pos);
      type = cmd.substr(pos+7, end==std::string::npos? std::string::npos : end-(pos+7));
    }
    procinfo[pid] = ProcInfo{cmd, type};
  }

  // Track per-thread deltas
  std::unordered_map<int32_t, std::unordered_map<int32_t, ThreadStats>> per_pid_threads; // pid -> tid -> stats
  uint64_t last_cpu_total = read_cpu_total();

  auto until = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
  while (std::chrono::steady_clock::now() < until) {
    for (auto pid : std::vector<int32_t>(pids.begin(), pids.end())) {
      // Threads under /proc/pid/task
      auto tdir = std::string("/proc/") + std::to_string(pid) + "/task";
      for (auto& tname : montauk::util::list_dir(tdir)) {
        if (tname.empty() || tname[0]<'0' || tname[0]>'9') continue;
        int32_t tid = std::strtol(tname.c_str(), nullptr, 10);
        auto statp = std::string("/proc/") + std::to_string(pid) + "/task/" + std::to_string(tid) + "/stat";
        auto txt = montauk::util::read_file_string(statp); if (!txt) continue;
        int32_t dummy_ppid=0; uint64_t ut=0, st=0; std::string comm;
        if (!parse_stat_line(*txt, dummy_ppid, ut, st, comm)) continue;
        uint64_t total = ut + st;
        auto& ts = per_pid_threads[pid][tid];
        if (ts.name.empty()) {
          auto commp = std::string("/proc/") + std::to_string(pid) + "/task/" + std::to_string(tid) + "/comm";
          auto n = montauk::util::read_file_string(commp); ts.name = n? *n : comm;
          // Trim trailing newline from comm
          if (!ts.name.empty() && (ts.name.back()=='\n' || ts.name.back()=='\r')) ts.name.pop_back();
        }
        if (ts.last>0 && total>=ts.last) ts.delta += (total - ts.last);
        ts.last = total;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
  }

  uint64_t cpu_total_now = read_cpu_total();
  uint64_t dt_cpu = (cpu_total_now>last_cpu_total) ? (cpu_total_now - last_cpu_total) : 1;

  struct Row { int32_t pid; int32_t tid; double cpu_pct; std::string name; std::string type; std::string cmd; };
  std::vector<Row> rows;
  std::unordered_map<int32_t,double> cpu_by_pid;
  std::unordered_map<std::string,double> cpu_by_type;

  for (auto& [pid, m] : per_pid_threads) {
    for (auto& [tid, ts] : m) {
      double pct = (100.0 * (double)ts.delta / (double)dt_cpu) * (double)read_cpu_count();
      if (pct <= 0.01) continue;
      auto it = procinfo.find(pid);
      std::string type = (it!=procinfo.end()? it->second.type : std::string());
      std::string cmd  = (it!=procinfo.end()? it->second.cmd  : std::string());
      rows.push_back(Row{pid, tid, pct, ts.name, type, cmd});
      cpu_by_pid[pid] += pct;
      cpu_by_type[type.empty()? std::string("(unknown)") : type] += pct;
    }
  }

  std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b){ return a.cpu_pct > b.cpu_pct; });

  double total_pct = 0.0; for (auto& kv : cpu_by_pid) total_pct += kv.second;

  std::cout << "\nSummary CPU across matched processes: " << std::fixed << std::setprecision(1) << total_pct << "% (approx)" << "\n";

  // By Chromium process type
  std::vector<std::pair<std::string,double>> types(cpu_by_type.begin(), cpu_by_type.end());
  std::sort(types.begin(), types.end(), [](auto& a, auto& b){ return a.second > b.second; });
  if (!types.empty()) {
    std::cout << "By process type:" << "\n";
    for (auto& [t, v] : types) {
      std::cout << "  " << std::setw(14) << std::left << t << std::right << std::setw(6) << std::fixed << std::setprecision(1) << v << "%\n";
    }
  }

  // Top processes
  std::vector<std::pair<int32_t,double>> procs(cpu_by_pid.begin(), cpu_by_pid.end());
  std::sort(procs.begin(), procs.end(), [](auto& a, auto& b){ return a.second > b.second; });
  std::cout << "\nTop PIDs:" << "\n";
  int limp = 8; for (auto& [pid, v] : procs) {
    auto cmd = procinfo[pid].cmd; if ((int)cmd.size()>80) cmd = cmd.substr(0,80) + "…";
    std::cout << "  PID " << std::setw(6) << pid << "  " << std::setw(6) << std::fixed << std::setprecision(1) << v << "%  " << cmd << "\n";
    if (--limp==0) break;
  }

  // Top hot threads
  std::cout << "\nHot threads:" << "\n";
  int limt = 12; for (auto& r : rows) {
    std::string label = r.name; if (label.empty()) label = "(anon)";
    std::cout << "  PID " << std::setw(6) << r.pid << " TID " << std::setw(6) << r.tid
              << "  " << std::setw(6) << std::fixed << std::setprecision(1) << r.cpu_pct << "%"
              << "  " << std::setw(12) << std::left << (r.type.empty()? "(unknown)" : r.type) << std::right
              << "  " << label << "\n";
    if (--limt==0) break;
  }

  std::cout << "\nHints:\n";
  std::cout << "- High GPU process CPU% often means the compositor is repainting at a high FPS or busy-waiting for vblank.\n";
  std::cout << "- Renderer spikes usually trace to JS timers, animations, video, or heavy canvas/WebGL.\n";
  std::cout << "- Try disabling extensions, background tabs, or set background throttle to test.\n";
  return 0;
}
