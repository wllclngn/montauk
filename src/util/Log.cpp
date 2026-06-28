#include "util/Log.hpp"
#include "util/sink.h"

#include <cstdio>
#include <cstring>
#include <ctime>

namespace montauk::util {

namespace {
const char* level_str(LogLevel l) {
  switch (l) {
    case LogLevel::Debug: return "DEBUG";
    case LogLevel::Info:  return "INFO";
    case LogLevel::Warn:  return "WARN";
    case LogLevel::Error: return "ERROR";
  }
  return "INFO";
}
} // namespace

void vlog_msg(LogLevel level, const char* fmt, va_list ap) {
  std::tm tm{};
  std::time_t t = std::time(nullptr);
  localtime_r(&t, &tm);
  char buf[1024];
  int n = std::vsnprintf(buf, sizeof(buf), fmt, ap);
  if (n < 0) buf[0] = '\0';
  // Pad so the message column is constant regardless of level width, matching
  // PANDEMONIUM's house format ([INFO]/[WARN] -> 3 spaces, [ERROR]/[DEBUG] -> 2).
  const char* ls = level_str(level);
  int pad = 9 - static_cast<int>(std::strlen(ls) + 2);
  if (pad < 1) pad = 1;
  // Format into a per-call stderr sink and drain immediately: logs stay
  // real-time, and a stack-local sink keeps it thread-safe (no shared buffer).
  // Same bytes as the prior single fprintf.
  montauk_sink s;
  montauk_sink_init(&s, 2);
  montauk_sink_appendf(&s, "[%02d:%02d:%02d] [%s]%*s%s\n",
                       tm.tm_hour, tm.tm_min, tm.tm_sec, ls, pad, "", buf);
  montauk_sink_drain(&s);
  montauk_sink_free(&s);
}

void log_msg(LogLevel level, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vlog_msg(level, fmt, ap);
  va_end(ap);
}

} // namespace montauk::util
