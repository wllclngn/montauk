// --trace's name list: every name matches on its own, not only the last.
#include "minitest.hpp"
#include "app/TraceBuffers.hpp"
#if MONTAUK_HAVE_BPF
#include "collectors/BpfTraceCollector.hpp"

#include <string>
#include <vector>

// Names short enough for the small-string buffer are the case that once left
// every matcher comparing against the list's last name, so each name here is,
// and each is matched alone, in other case, inside a longer name, and against
// a prefix of the last one.
TEST(trace_names_each_matches) {
  std::vector<std::string> names;
  std::string list;
  for (int i = 0; i < 3; ++i) {
    names.push_back("name" + std::to_string(i) + "x");
    list += (i ? " , " : "") + names.back();
  }
  montauk::app::TraceBuffers bufs;
  montauk::collectors::BpfTraceCollector c(bufs, list);
  for (const std::string& n : names) {
    std::string upper = n;
    for (char& ch : upper) ch = static_cast<char>(ch >= 'a' && ch <= 'z' ? ch - 32 : ch);
    ASSERT_TRUE(c.matches_any(n));
    ASSERT_TRUE(c.matches_any(upper));
    ASSERT_TRUE(c.matches_any("pre" + n + "post"));
  }
  ASSERT_TRUE(!c.matches_any(names.back().substr(0, names.back().size() - 1)));
  ASSERT_TRUE(!c.matches_any("unrelated"));
}

TEST(trace_names_whole_pattern_without_tokens) {
  montauk::app::TraceBuffers bufs;
  montauk::collectors::BpfTraceCollector c(bufs, " , ");
  ASSERT_TRUE(c.matches_any("a , b"));
  ASSERT_TRUE(!c.matches_any("ab"));
}
#endif
