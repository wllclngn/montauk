// Enum-to-string tables shared by trace_decode.cpp and trace_analyze.cpp --
// previously two independent copies each, which had already drifted:
// io_syscall_name carried 6 cases in trace_decode.cpp vs 18 in
// trace_analyze.cpp, and signal_name existed only in trace_analyze.cpp
// (trace_decode.cpp formatted signals ad hoc inline instead of via a table).
// sched_op_name and ntsync_op_name were identical copies, resynced by hand
// once rather than hoisted. One copy here closes the drift class for good.
#pragma once

#include "montauk_trace.h"

#include <cstdint>

namespace montauk::model {

inline const char* sched_op_name(uint32_t op) {
  switch (op) {
    case SCHED_OP_ENQUEUE:        return "ENQUEUE";
    case SCHED_OP_PICK:           return "PICK";
    case SCHED_OP_PICK_EMPTY:     return "PICK_EMPTY";
    case SCHED_OP_PREEMPT_TICK:   return "PREEMPT_TICK";
    case SCHED_OP_PREEMPT_WAKEUP: return "PREEMPT_WAKEUP";
    case SCHED_OP_WAKEUP:         return "WAKEUP";
    case SCHED_OP_WAKE2RUN:       return "WAKE2RUN";
    case SCHED_OP_CPU_IDLE:       return "CPU_IDLE";
    case SCHED_OP_SWITCH_IN:      return "SWITCH_IN";
    case SCHED_OP_FIELD_GATE:     return "FIELD_GATE";
    case SCHED_OP_KICK_ISSUE:     return "KICK_ISSUE";
    case SCHED_OP_RESCHED:        return "RESCHED";
    case SCHED_OP_TICK_STOP:      return "TICK_STOP";
    default:                      return "?";
  }
}

inline const char* ntsync_op_name(uint8_t op) {
  switch (op) {
    case NTS_CREATE_SEM:   return "create_sem";
    case NTS_SEM_RELEASE:  return "sem_release";
    case NTS_WAIT_ANY:     return "wait_any";
    case NTS_WAIT_ALL:     return "wait_all";
    case NTS_CREATE_MUTEX: return "create_mutex";
    case NTS_MUTEX_UNLOCK: return "mutex_unlock";
    case NTS_MUTEX_KILL:   return "mutex_kill";
    case NTS_CREATE_EVENT: return "create_event";
    case NTS_EVENT_SET:    return "event_set";
    case NTS_EVENT_RESET:  return "event_reset";
    case NTS_EVENT_PULSE:  return "event_pulse";
    case NTS_SEM_READ:     return "sem_read";
    case NTS_MUTEX_READ:   return "mutex_read";
    case NTS_EVENT_READ:   return "event_read";
    default:               return "unknown";
  }
}

// Union of both prior copies -- trace_analyze.cpp's was the fuller one (18
// cases vs trace_decode.cpp's 6), confirmed drift before this hoist.
inline const char* io_syscall_name(int32_t nr) {
  switch (nr) {
    case 0:   return "read";
    case 1:   return "write";
    case 5:   return "fstat";
    case 7:   return "poll";
    case 8:   return "lseek";
    case 16:  return "ioctl";
    case 17:  return "pread64";
    case 18:  return "pwrite64";
    case 23:  return "select";
    case 45:  return "recvfrom";
    case 47:  return "recvmsg";
    case 208: return "io_getevents";
    case 209: return "io_submit";
    case 232: return "epoll_wait";
    case 257: return "openat";
    case 270: return "pselect6";
    case 271: return "ppoll";
    case 281: return "epoll_pwait";
    default:  return "?";
  }
}

// Event TYPE -> lowercase name: the analyzer's summary rows and prom labels.
inline const char* evt_type_name(uint32_t t) {
  switch (t) {
    case TRACE_EVT_FORK: return "fork";
    case TRACE_EVT_EXEC: return "exec";
    case TRACE_EVT_EXIT: return "exit";
    case TRACE_EVT_COMM_CHANGE: return "comm";
    case TRACE_EVT_IO: return "io";
    case TRACE_EVT_NTSYNC: return "ntsync";
    case TRACE_EVT_SCHED: return "sched";
    case TRACE_EVT_HEAP: return "heap";
    case TRACE_EVT_SIGNAL: return "signal";
    case TRACE_EVT_MMAP: return "mmap";
    case TRACE_EVT_PROVIDER: return "provider";
    case TRACE_EVT_ABORT: return "abort";
    case TRACE_EVT_HEAPSTACK: return "heapstk";
    case TRACE_EVT_KEYEDEVT: return "keyedevt";
    case TRACE_EVT_KSTRAND: return "kstrand";
    case TRACE_EVT_WAITSTACK: return "waitstack";
    case TRACE_EVT_SCX_STORM: return "scx_storm";
    case TRACE_EVT_THREAD_NAME: return "thread_name";
    case TRACE_EVT_RAWSTACK: return "rawstack";
    case TRACE_EVT_DROPS: return "drops";
    default: return "unknown";
  }
}

// The four lifecycle types as trace_decode.cpp's per-event line prints them
// (caps, COMM for COMM_CHANGE) -- a distinct surface from evt_type_name's
// lowercase naming, kept as its own table so the decode text stays byte-stable.
inline const char* lifecycle_type_name(uint32_t t) {
  switch (t) {
    case TRACE_EVT_FORK: return "FORK";
    case TRACE_EVT_EXEC: return "EXEC";
    case TRACE_EVT_EXIT: return "EXIT";
    default:             return "COMM";
  }
}

// Signal number -> canonical name, nullptr when unnamed. Shared by the
// signals report and the --sig qualifier parser (trace_analyze.cpp) and by
// trace_decode.cpp's per-event signal formatting.
inline const char* signal_name(int32_t n) {
  switch (n) {
    case 1:  return "SIGHUP";  case 2:  return "SIGINT";  case 3:  return "SIGQUIT";
    case 4:  return "SIGILL";  case 5:  return "SIGTRAP"; case 6:  return "SIGABRT";
    case 7:  return "SIGBUS";  case 8:  return "SIGFPE";  case 9:  return "SIGKILL";
    case 10: return "SIGUSR1"; case 11: return "SIGSEGV"; case 12: return "SIGUSR2";
    case 13: return "SIGPIPE"; case 14: return "SIGALRM"; case 15: return "SIGTERM";
    case 17: return "SIGCHLD"; case 19: return "SIGSTOP"; case 24: return "SIGXCPU";
    case 25: return "SIGXFSZ"; case 31: return "SIGSYS";
    default: return nullptr;
  }
}

}  // namespace montauk::model
