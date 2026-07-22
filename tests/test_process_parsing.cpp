// ProcessParsing: /proc/PID/stat field extraction (comm edge cases, the
// fault/thread counters) and the shared /proc/stat helpers under a
// MONTAUK_PROC_ROOT sandbox.
#include "minitest.hpp"
#include "env_guard.hpp"
#include "collectors/ProcessParsing.hpp"
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <unistd.h>

namespace fs = std::filesystem;

// 52-field stat line builder: pid (comm) state ppid ... utime stime ... rss ...
// with minflt/majflt/num_threads placed at their real field positions (10, 12,
// 20) so the extraction of each is exercised, not just skipped over.
static std::string stat_line(const std::string& comm, char state,
                             uint64_t utime, uint64_t stime, int64_t rss,
                             uint64_t minflt = 0, uint64_t majflt = 0,
                             int num_threads = 0) {
  std::string s = "1234 (" + comm + ") ";
  s += state;
  s += " 1";                                     // ppid
  for (int i = 0; i < 5; ++i) s += " 0";         // pgrp, session, tty, tpgid, flags
  s += " " + std::to_string(minflt);             // minflt (field 10)
  s += " 0";                                     // cminflt
  s += " " + std::to_string(majflt);             // majflt (field 12)
  s += " 0";                                     // cmajflt
  s += " " + std::to_string(utime);
  s += " " + std::to_string(stime);
  for (int i = 0; i < 4; ++i) s += " 0";         // cutime, cstime, priority, nice
  s += " " + std::to_string(num_threads);        // num_threads (field 20)
  s += " 0 0";                                   // itrealvalue, starttime
  s += " 4096";                                  // vsize
  s += " " + std::to_string(rss);
  for (int i = 0; i < 28; ++i) s += " 0";        // trailing fields
  s += "\n";
  return s;
}

TEST(parse_stat_line_simple_comm) {
  char st = '?'; uint64_t ut = 0, stime = 0; int64_t rss = 0; std::string comm;
  uint64_t mf = 0, jf = 0; int nt = 0;
  ASSERT_TRUE(montauk::collectors::parse_stat_line(
      stat_line("bash", 'S', 111, 22, 3300), st, ut, stime, rss, comm,
      mf, jf, nt));
  ASSERT_EQ(comm, std::string("bash"));
  ASSERT_EQ(st, 'S');
  ASSERT_EQ(ut, 111ull);
  ASSERT_EQ(stime, 22ull);
  ASSERT_EQ(rss, 3300ll);
}

TEST(parse_stat_line_comm_with_spaces_and_parens) {
  // Everything between the first '(' and the LAST ')' is the comm, verbatim;
  // internal spaces and parens must not shift the numeric fields.
  char st = '?'; uint64_t ut = 0, stime = 0; int64_t rss = 0; std::string comm;
  uint64_t mf = 0, jf = 0; int nt = 0;
  ASSERT_TRUE(montauk::collectors::parse_stat_line(
      stat_line("Web (Content) x", 'R', 7, 8, 9), st, ut, stime, rss, comm,
      mf, jf, nt));
  ASSERT_EQ(comm, std::string("Web (Content) x"));
  ASSERT_EQ(st, 'R');
  ASSERT_EQ(ut, 7ull);
  ASSERT_EQ(stime, 8ull);
  ASSERT_EQ(rss, 9ll);
}

TEST(parse_stat_line_comm_fully_parenthesized) {
  // systemd's "(sd-pam)" style comm: nested parens resolve exactly.
  char st = '?'; uint64_t ut = 0, stime = 0; int64_t rss = 0; std::string comm;
  uint64_t mf = 0, jf = 0; int nt = 0;
  ASSERT_TRUE(montauk::collectors::parse_stat_line(
      stat_line("(sd-pam)", 'S', 5, 6, 70), st, ut, stime, rss, comm,
      mf, jf, nt));
  ASSERT_EQ(comm, std::string("(sd-pam)"));
  ASSERT_EQ(st, 'S');
  ASSERT_EQ(ut, 5ull);
  ASSERT_EQ(stime, 6ull);
  ASSERT_EQ(rss, 70ll);
}

TEST(parse_stat_line_faults_and_threads) {
  // The fault counters (fields 10, 12) and num_threads (field 20) extract
  // without shifting comm/utime/stime/rss around them.
  char st = '?'; uint64_t ut = 0, stime = 0; int64_t rss = 0; std::string comm;
  uint64_t mf = 0, jf = 0; int nt = 0;
  ASSERT_TRUE(montauk::collectors::parse_stat_line(
      stat_line("app", 'R', 40, 12, 5500, /*minflt=*/900, /*majflt=*/7,
                /*num_threads=*/24),
      st, ut, stime, rss, comm, mf, jf, nt));
  ASSERT_EQ(mf, 900ull);
  ASSERT_EQ(jf, 7ull);
  ASSERT_EQ(nt, 24);
  ASSERT_EQ(ut, 40ull);       // fields around the new ones stay put
  ASSERT_EQ(stime, 12ull);
  ASSERT_EQ(rss, 5500ll);
}

TEST(parse_stat_line_rejects_malformed) {
  char st = '?'; uint64_t ut = 0, stime = 0; int64_t rss = 0; std::string comm;
  uint64_t mf = 0, jf = 0; int nt = 0;
  ASSERT_TRUE(!montauk::collectors::parse_stat_line(
      "garbage without parens", st, ut, stime, rss, comm, mf, jf, nt));
  ASSERT_TRUE(!montauk::collectors::parse_stat_line(
      "1234 )backwards( S", st, ut, stime, rss, comm, mf, jf, nt));
}

TEST(read_cpu_total_and_count_honor_proc_root) {
  auto root = fs::temp_directory_path() / fs::path("montauk_test_procparse_") /
              fs::path(std::to_string(::getpid()));
  fs::create_directories(root / "proc");
  // First line sums to 100+0+100+1000 = 1200; per-core lines cpu0/cpu1.
  std::ofstream(root / "proc/stat") << "cpu  100 0 100 1000 0 0 0 0\n"
                                       "cpu0 50 0 50 500 0 0 0 0\n"
                                       "cpu1 50 0 50 500 0 0 0 0\n"
                                       "intr 12345 0 0\n"
                                       "ctxt 999\n";
  TempRootGuard proc_root("MONTAUK_PROC_ROOT", root.string());
  ASSERT_EQ(montauk::collectors::read_cpu_total(), 1200ull);
  ASSERT_EQ(montauk::collectors::read_cpu_count(), 2u);
}
