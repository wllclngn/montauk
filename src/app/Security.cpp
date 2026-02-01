#include "app/Security.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <sstream>
#include <unordered_set>

namespace montauk::app {

static std::string to_lower_copy(std::string s, size_t max_len = 512) {
  if (s.size() > max_len) {
    s.resize(max_len);
  }
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
  return s;
}

static std::string to_upper_copy(std::string s, size_t max_len = 512) {
  if (s.size() > max_len) {
    s.resize(max_len);
  }
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(std::toupper(c)); });
  return s;
}

static std::string strip_deleted_suffix(const std::string& path) {
  auto pos = path.find(" (deleted)");
  if (pos != std::string::npos) return path.substr(0, pos);
  return path;
}

static bool has_path_prefix(const std::string& path, const std::string& prefix) {
  if (path.rfind(prefix, 0) == 0) return true;
  if (!prefix.empty() && prefix.back() == '/') {
    std::string trimmed = prefix.substr(0, prefix.size() - 1);
    if (path == trimmed) return true;
  }
  return false;
}

static std::string format_rate_bytes(double bytes_per_sec) {
  if (bytes_per_sec >= 1024.0 * 1024.0) {
    int mb = static_cast<int>(bytes_per_sec / (1024.0 * 1024.0) + 0.5);
    return std::to_string(mb) + "MB/s";
  }
  int kb = static_cast<int>(bytes_per_sec / 1024.0 + 0.5);
  if (kb < 1) kb = 1;
  return std::to_string(kb) + "KB/s";
}

std::vector<SecurityFinding> collect_security_findings(const montauk::model::Snapshot& s) {
  std::vector<SecurityFinding> findings;
  std::unordered_set<int32_t> flagged_pids;
  
  static constexpr size_t MAX_FINDINGS = 100;

  static const std::vector<std::string> writable_prefixes = {
    "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/home/"
  };

  auto make_subject = [](const montauk::model::ProcSample& p, const std::string& extra){
    std::ostringstream os;
    os << "PID " << p.pid << ' ' << (p.user_name.empty() ? "?" : p.user_name) << ' ' << extra;
    return os.str();
  };

  auto add_finding = [&](int severity, const std::string& subject, const std::string& reason){
    if (findings.size() < MAX_FINDINGS) {
      findings.push_back(SecurityFinding{severity, subject, reason});
    }
  };

  for (const auto& p : s.procs.processes) {
    if (flagged_pids.count(p.pid)) continue;
    const std::string exe_clean = strip_deleted_suffix(p.exe_path);
    const bool is_root = (p.user_name == "root");

    if (is_root && !exe_clean.empty()) {
      for (const auto& pref : writable_prefixes) {
        if (has_path_prefix(exe_clean, pref)) {
          std::string reason = "root exec in " + (pref.back() == '/' ? pref.substr(0, pref.size()-1) : pref);
          add_finding(2, make_subject(p, exe_clean), reason);
          flagged_pids.insert(p.pid);
          break;
        }
      }
      if (flagged_pids.count(p.pid)) continue;
    }

    if (!p.cmd.empty() && p.cmd.front() == '[' && p.cmd.back() == ']' && !exe_clean.empty()) {
      add_finding(2, make_subject(p, p.cmd), "fake kernel thread");
      flagged_pids.insert(p.pid);
      continue;
    }

    const std::string cmd_lower = to_lower_copy(p.cmd);
    if (!flagged_pids.count(p.pid)) {
      const bool has_curl = cmd_lower.find("curl") != std::string::npos || cmd_lower.find("wget") != std::string::npos;
      const bool has_pipe_bash = cmd_lower.find("| bash") != std::string::npos || cmd_lower.find("|sh") != std::string::npos;
      if (has_curl && has_pipe_bash) {
        add_finding(1, make_subject(p, p.cmd), "script download");
        flagged_pids.insert(p.pid);
        continue;
      }
    }

    if (!flagged_pids.count(p.pid)) {
      if (cmd_lower.find("python") != std::string::npos && cmd_lower.find(".py") != std::string::npos &&
          (cmd_lower.find("/home/") != std::string::npos || cmd_lower.find("~") != std::string::npos)) {
        add_finding(1, make_subject(p, p.cmd), "home script");
        flagged_pids.insert(p.pid);
        continue;
      }
    }

    if (!flagged_pids.count(p.pid) && !p.cmd.empty()) {
      std::istringstream iss(p.cmd);
      std::string first;
      if (iss >> first) {
        std::string first_lower = to_lower_copy(first);
        auto is_shell = [](const std::string& cmd){
          if (cmd == "sh" || cmd == "/bin/sh" || cmd == "/usr/bin/sh") return true;
          if (cmd == "bash" || cmd == "/bin/bash" || cmd == "/usr/bin/bash") return true;
          if (cmd.size() > 3 && cmd.rfind("/sh") == cmd.size() - 3) return true;
          if (cmd.size() > 5 && cmd.rfind("/bash") == cmd.size() - 5) return true;
          return false;
        };
        if (is_shell(first_lower)) {
          std::string arg;
          while (iss >> arg) {
            std::string clean = arg;
            if (!clean.empty() && (clean.front() == '"' || clean.front() == '\'')) clean.erase(clean.begin());
            if (!clean.empty() && (clean.back() == '"' || clean.back() == '\'')) clean.pop_back();
            for (const auto& pref : writable_prefixes) {
              if (has_path_prefix(clean, pref)) {
                add_finding(2, make_subject(p, p.cmd), "TMP SHELL SCRIPT");
                flagged_pids.insert(p.pid);
                break;
              }
            }
            if (flagged_pids.count(p.pid)) break;
          }
        }
      }
    }
  }

  // Auth crashloop detection: require BOTH sustained high churn AND auth processes affected.
  // This prevents false positives from single transient read failures.
  // Threshold: 3+ churn events in 2s indicates sustained process thrashing, not a one-off.
  static constexpr int CHURN_THRESHOLD = 3;
  if (s.churn.recent_2s_events >= CHURN_THRESHOLD) {
    for (const auto& p : s.procs.processes) {
      // Check if this auth-related process had a read failure during the churn storm
      if (p.churn_reason == montauk::model::ChurnReason::None) continue;
      std::string cmd_lower = to_lower_copy(p.cmd);
      if (cmd_lower.find("ssh") != std::string::npos || cmd_lower.find("sudo") != std::string::npos ||
          cmd_lower.find("login") != std::string::npos || cmd_lower.find("pam") != std::string::npos) {
        std::string reason = "auth crashloop";
        std::ostringstream subj;
        subj << "PID " << p.pid << ' ' << (p.user_name.empty() ? "?" : p.user_name)
             << ' ' << p.cmd << " • " << s.churn.recent_2s_events << " events/2s";
        add_finding(2, subj.str(), reason);
        flagged_pids.insert(p.pid);
      }
    }
  }

  double best_rate = 0.0;
  const montauk::model::NetIf* best_iface = nullptr;
  for (const auto& iface : s.net.interfaces) {
    if (iface.rx_bps > best_rate) { best_rate = iface.rx_bps; best_iface = &iface; }
    if (iface.tx_bps > best_rate) { best_rate = iface.tx_bps; best_iface = &iface; }
  }
  if (best_iface && best_rate > 500.0 * 1024.0) {
    bool has_owner = false;
    size_t check = std::min<size_t>(s.procs.processes.size(), 64);
    for (size_t i=0; i<check; ++i) {
      const auto& p = s.procs.processes[i];
      if (p.churn_reason != montauk::model::ChurnReason::None) continue;
      if (p.cpu_pct >= 2.0) { has_owner = true; break; }
      auto lower = to_lower_copy(p.cmd);
      if (lower.find("ssh") != std::string::npos || lower.find("chrome") != std::string::npos ||
          lower.find("firefox") != std::string::npos || lower.find("rsync") != std::string::npos ||
          lower.find("scp") != std::string::npos || lower.find("curl") != std::string::npos ||
          lower.find("wget") != std::string::npos) {
        has_owner = true;
        break;
      }
    }
    if (!has_owner) {
      std::string subject = "NET " + best_iface->name + ' ' + format_rate_bytes(best_rate) + " no owner";
      add_finding(1, subject, "possible exfil");
    }
  }

  std::stable_sort(findings.begin(), findings.end(), [](const SecurityFinding& a, const SecurityFinding& b){
    return a.severity > b.severity;
  });

  return findings;
}

std::string format_security_line_default(const SecurityFinding& f) {
  std::ostringstream os;
  os << "PROC SECURITY ";
  if (f.severity >= 2) os << "⚠ ";
  else if (f.severity == 1) os << "▴ ";
  else os << "  ";
  os << f.subject;
  if (!f.reason.empty()) os << " [" << f.reason << ']';
  return os.str();
}

std::string format_security_line_system(const SecurityFinding& f) {
  std::ostringstream os;
  os << "PROC SECURITY ";
  if (f.severity >= 2) os << "⚠ ";
  os << f.subject;
  if (!f.reason.empty()) os << " [" << to_upper_copy(f.reason) << ']';
  return os.str();
}

} // namespace montauk::app
