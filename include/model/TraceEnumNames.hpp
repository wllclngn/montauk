// Enum-to-string tables shared by trace_decode.cpp and trace_analyze.cpp --
// previously two independent copies each, which had already drifted:
// io_syscall_name carried 6 cases in trace_decode.cpp vs 18 in
// trace_analyze.cpp, and signal_name existed only in trace_analyze.cpp
// (trace_decode.cpp formatted signals ad hoc inline instead of via a table).
// sched_op_name and ntsync_op_name were identical copies, resynced by hand
// once rather than hoisted. One copy here closes the drift class for good, and
// BpfTraceCollector reads its ntsync and syscall names from here too.
#pragma once

#include "montauk_trace.h"
#include "model/SyscallTable.hpp"

#include <cstdint>
#include <string_view>

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
    case SCHED_OP_DSQ_INSERT:     return "DSQ_INSERT";
    case SCHED_OP_DSQ_DRAIN:      return "DSQ_DRAIN";
    case SCHED_OP_MIGRATE:        return "MIGRATE";
    default:                      return "?";
  }
}

inline const char* heap_op_name(uint32_t op) {
  switch (op) {
    case HEAP_OP_MALLOC:         return "malloc";
    case HEAP_OP_FREE:           return "free";
    case HEAP_OP_REALLOC:        return "realloc";
    case HEAP_OP_CALLOC:         return "calloc";
    case HEAP_OP_POSIX_MEMALIGN: return "posix_memalign";
    case HEAP_OP_ALIGNED_ALLOC:  return "aligned_alloc";
    case HEAP_OP_MEMALIGN:       return "memalign";
    case HEAP_OP_VALLOC:         return "valloc";
    case HEAP_OP_PVALLOC:        return "pvalloc";
    default:                     return "?";
  }
}

// A heap op that hands back a fresh block at addr, and one that moves the block
// at addr to new_addr. Every consumer of the heap stream asks one of these
// rather than listing ops, so an allocator added here reaches all of them.
inline bool heap_op_allocates(uint32_t op) {
  return op == HEAP_OP_MALLOC || op == HEAP_OP_CALLOC ||
         (op >= HEAP_OP_POSIX_MEMALIGN && op <= HEAP_OP_PVALLOC);
}
inline bool heap_op_moves(uint32_t op) {
  return op == HEAP_OP_REALLOC;
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

// x86-64 syscall number -> name, nullptr when unnamed: The live thread view's
// current syscall, the syscall class's records and, through io_syscall_name,
// every IO report and decode line. The kernel's whole table, where a hand list
// once named 40 calls and printed the rest as unknown.
inline const char* syscall_name(int32_t nr) {
  constexpr int32_t n = static_cast<int32_t>(sizeof(kSyscallNames) / sizeof(kSyscallNames[0]));
  return nr >= 0 && nr < n ? kSyscallNames[nr] : nullptr;
}

// A syscall's number by its name, -1 when the kernel has no call by that name.
inline int32_t syscall_number(std::string_view name) {
  constexpr int32_t n = static_cast<int32_t>(sizeof(kSyscallNames) / sizeof(kSyscallNames[0]));
  for (int32_t i = 0; i < n; ++i)
    if (kSyscallNames[i] && name == kSyscallNames[i]) return i;
  return -1;
}

// The same name for a report or decode line, "?" when unnamed.
inline const char* io_syscall_name(int32_t nr) {
  const char* n = syscall_name(nr);
  return n ? n : "?";
}

// A futex op's command, its PRIVATE and CLOCK_REALTIME flags masked, as futex(2)
// numbers them; futex_waitv as MONTAUK_FUTEX_CMD_WAITV names it in a
// TRACE_EVT_FUTEX record.
inline const char* futex_cmd_name(uint32_t op) {
  switch (op & 0x7f) {
    case 0:  return "wait";
    case 1:  return "wake";
    case 2:  return "fd";
    case 3:  return "requeue";
    case 4:  return "cmp_requeue";
    case 5:  return "wake_op";
    case 6:  return "lock_pi";
    case 7:  return "unlock_pi";
    case 8:  return "trylock_pi";
    case 9:  return "wait_bitset";
    case 10: return "wake_bitset";
    case 11: return "wait_requeue_pi";
    case 12: return "cmp_requeue_pi";
    case 13: return "lock_pi2";
    case MONTAUK_FUTEX_CMD_WAITV: return "waitv";
    default: return "?";
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
    case TRACE_EVT_FUTEX: return "futex";
    case TRACE_EVT_FUTEXSTACK: return "futexstack";
    case TRACE_EVT_SYSCALL: return "syscall";
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

// What a signal row's disposition did (signal_disposition).
inline const char* signal_disposition_name(uint32_t d) {
  switch (d) {
    case SIGDISP_DEFAULT: return "default";
    case SIGDISP_IGNORED: return "ignored";
    case SIGDISP_CAUGHT:  return "caught";
    default:              return "-";
  }
}

}  // namespace montauk::model
