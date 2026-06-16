#pragma once

#include <cstdint>

// Binary trace-log format shared between the writer (BpfTraceCollector,
// --trace-out FILE) and the reader (montauk_trace_decode).
//
// Rationale: text formatting per event (fprintf to unbuffered stderr) is a
// syscall-per-event firehose that perturbs the very workload being traced —
// fatal for scheduler-decision tracing where event rates run into the
// millions/sec. The binary log writes the raw ring-buffer payloads verbatim,
// batched into ~256 KB writes, so trace-time cost is a memcpy + an
// occasional write(). All formatting moves offline into the decoder.
//
// Layout:
//   [ TraceFileHeader ]
//   [ record ] [ record ] ...
//
// Each record: a little-endian uint32 length, then that many bytes of raw
// ring payload (a montauk_*_event struct). Every event struct begins with a
// uint32 `type` (enum montauk_event_type), so the decoder switches on the
// leading word to interpret the rest. The length prefix is authoritative —
// it comes from the ring callback's `len`, so the decoder never needs a
// type→size table and tolerates struct padding differences across builds.

namespace montauk::model {

// "MTKTRACE" — exactly 8 bytes, no NUL terminator stored.
inline constexpr char kTraceMagic[8] = {'M', 'T', 'K', 'T', 'R', 'A', 'C', 'E'};

// Bump on any incompatible header/record change. The decoder refuses
// mismatched versions rather than emitting garbage.
inline constexpr uint32_t kTraceFormatVersion = 1;

struct TraceFileHeader {
  char     magic[8];        // kTraceMagic (not NUL-terminated)
  uint32_t version;         // kTraceFormatVersion
  uint32_t flags;           // reserved, 0
  uint64_t mono_anchor_ns;  // CLOCK_MONOTONIC at trace start. Event timestamp_ns
                            // fields share this base (bpf_ktime_get_ns), so
                            // (event.timestamp_ns - mono_anchor_ns) is elapsed
                            // time since trace start.
  uint64_t real_anchor_ns;  // CLOCK_REALTIME (ns since epoch) at the same instant
                            // as mono_anchor_ns. Lets the decoder convert any
                            // event to absolute wall-clock:
                            //   wall = real_anchor_ns + (event.ts - mono_anchor_ns)
  char     pattern[32];     // the --trace PATTERN, NUL-padded, for context
};

// Per-record length prefix type. Records are framed as
// [TraceRecordLen][payload bytes].
using TraceRecordLen = uint32_t;

} // namespace montauk::model
