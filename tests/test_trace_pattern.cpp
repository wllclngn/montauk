// The capture's record of its --trace pattern: whole when the header's field
// cannot hold it, and a capture whose pattern fits read as it always was.
#include "minitest.hpp"
#include "model/TraceReader.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

using namespace montauk::model;

namespace {
struct TempTrace {
  char path[32] = "/tmp/montauk-patternXXXXXX";
  TempTrace() { int fd = mkstemp(path); if (fd >= 0) ::close(fd); }
  ~TempTrace() { std::remove(path); }
};

void write_trace(const char* path, const std::string& pattern, bool record, uint32_t events) {
  TraceFileHeader hdr{};
  std::memcpy(hdr.magic, kTraceMagic, sizeof hdr.magic);
  hdr.version = kTraceFormatVersion;
  std::memcpy(hdr.pattern, pattern.data(), std::min(pattern.size(), sizeof hdr.pattern - 1));
  if (record) hdr.flags |= kTraceFlagPatternRecord;
  FILE* f = std::fopen(path, "wb");
  std::fwrite(&hdr, sizeof hdr, 1, f);
  if (record) {
    const uint32_t type = kTracePatternRecordType;
    const TraceRecordLen len = static_cast<TraceRecordLen>(sizeof type + pattern.size());
    std::fwrite(&len, sizeof len, 1, f);
    std::fwrite(&type, sizeof type, 1, f);
    std::fwrite(pattern.data(), 1, pattern.size(), f);
  }
  for (uint32_t i = 0; i < events; ++i) {
    const uint32_t ev[2] = {1, i};  // a FORK-typed stub record
    const TraceRecordLen len = sizeof ev;
    std::fwrite(&len, sizeof len, 1, f);
    std::fwrite(ev, sizeof ev, 1, f);
  }
  std::fclose(f);
}

uint32_t count_events(TraceReader& r) {
  uint32_t n = 0;
  (void)r.for_each([&](uint32_t, const uint8_t*, uint32_t) { ++n; });
  return n;
}
}  // namespace

TEST(trace_pattern_whole_from_its_record) {
  TempTrace t;
  const std::string longp = "first_long_name_here,second_name,third_name_x";  // 45 bytes
  write_trace(t.path, longp, true, 3);
  TraceReader r;
  ASSERT_TRUE(r.open(t.path) == TraceReadStatus::Ok);
  ASSERT_EQ(r.pattern(), longp);
  ASSERT_EQ(count_events(r), 3u);  // the pattern record is not an event
}

TEST(trace_pattern_fits_the_header) {
  TempTrace t;
  write_trace(t.path, "short,names", false, 2);
  TraceReader r;
  ASSERT_TRUE(r.open(t.path) == TraceReadStatus::Ok);
  ASSERT_EQ(r.pattern(), std::string("short,names"));
  ASSERT_EQ(count_events(r), 2u);
}
