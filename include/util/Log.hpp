#pragma once

#include <cstdarg>

namespace montauk::util {

// House log format, shared across montauk's runtime: "[HH:MM:SS] [LEVEL]   msg".
// Replaces ad-hoc fprintf(stderr, "montauk: ...") so diagnostics are uniform
// and structured (one line per event, scannable). Goes to stderr; the data
// path (binary trace) and montauk's state (provider emitter) are separate.
enum class LogLevel { Debug, Info, Warn, Error };

void log_msg(LogLevel level, const char* fmt, ...) __attribute__((format(printf, 2, 3)));

inline void log_debug(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
inline void log_info(const char* fmt, ...)  __attribute__((format(printf, 1, 2)));
inline void log_warn(const char* fmt, ...)  __attribute__((format(printf, 1, 2)));
inline void log_error(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

// Thin level-specific wrappers. Defined out-of-line forwarding is not possible
// for varargs, so each forwards via the shared vlog entry point.
void vlog_msg(LogLevel level, const char* fmt, va_list ap);

inline void log_debug(const char* fmt, ...) { va_list ap; va_start(ap, fmt); vlog_msg(LogLevel::Debug, fmt, ap); va_end(ap); }
inline void log_info(const char* fmt, ...)  { va_list ap; va_start(ap, fmt); vlog_msg(LogLevel::Info,  fmt, ap); va_end(ap); }
inline void log_warn(const char* fmt, ...)  { va_list ap; va_start(ap, fmt); vlog_msg(LogLevel::Warn,  fmt, ap); va_end(ap); }
inline void log_error(const char* fmt, ...) { va_list ap; va_start(ap, fmt); vlog_msg(LogLevel::Error, fmt, ap); va_end(ap); }

} // namespace montauk::util
