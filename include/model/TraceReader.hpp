#pragma once

// Reusable reader for montauk binary trace logs (--trace-out FILE).
// Owns the open/validate/iterate plumbing shared by montauk_trace_decode
// and montauk_analyze: open the file, check magic+version, then walk the
// length-prefixed records handing each raw event payload to a caller
// visitor. Format details live in model/TraceBinary.hpp.

#include "model/TraceBinary.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace montauk::model {

// Records larger than this are treated as corruption: the largest event
// struct is well under 1 KiB, so a megabyte-plus length prefix means the
// stream is desynchronized, not that the event is big.
inline constexpr uint32_t kTraceMaxRecordLen = 1u << 20;

enum class TraceReadStatus {
  Ok,               // open succeeded / clean EOF
  OpenFailed,
  ShortHeader,
  BadMagic,
  BadVersion,       // header still readable so callers can report hdr.version
  CorruptLength,    // record length 0 or > kTraceMaxRecordLen
  TruncatedRecord,  // EOF mid-record
};

class TraceReader {
public:
  TraceReader() = default;
  ~TraceReader();
  TraceReader(const TraceReader&) = delete;
  TraceReader& operator=(const TraceReader&) = delete;

  [[nodiscard]] TraceReadStatus open(const char* path);
  void close();

  [[nodiscard]] const TraceFileHeader& header() const { return hdr_; }

  // Event timestamps are CLOCK_MONOTONIC; map to wall clock / elapsed time
  // via the anchors captured in the header.
  [[nodiscard]] uint64_t to_wall_ns(uint64_t ts_ns) const {
    return hdr_.real_anchor_ns + (ts_ns - hdr_.mono_anchor_ns);
  }
  [[nodiscard]] double elapsed_ms(uint64_t ts_ns) const {
    return static_cast<double>(ts_ns - hdr_.mono_anchor_ns) / 1e6;
  }

  // Walk every record, invoking visit(type, payload, len) per event. The
  // payload pointer is only valid for the duration of the call; `len` is the
  // authoritative record length (may exceed the struct size the build knows,
  // so visitors must still check len >= sizeof(...)). Returns Ok on clean
  // EOF; on CorruptLength/TruncatedRecord iteration stops and events_read()/
  // corrupt_len() describe where. Templated so the per-event call inlines —
  // traces run to millions of events.
  template <typename Visit>
  [[nodiscard]] TraceReadStatus for_each(Visit&& visit) {
    for (;;) {
      TraceRecordLen len = 0;
      if (std::fread(&len, sizeof(len), 1, f_) != 1) return TraceReadStatus::Ok;
      if (len == 0 || len > kTraceMaxRecordLen) {
        corrupt_len_ = len;
        return TraceReadStatus::CorruptLength;
      }
      rec_.resize(len);
      if (std::fread(rec_.data(), 1, len, f_) != len) return TraceReadStatus::TruncatedRecord;
      ++n_events_;
      uint32_t type = 0;
      std::memcpy(&type, rec_.data(), sizeof(type));
      visit(type, rec_.data(), static_cast<uint32_t>(len));
    }
  }

  // Count of fully-read records (valid during and after for_each).
  [[nodiscard]] uint64_t events_read() const { return n_events_; }
  // The offending length prefix when for_each returned CorruptLength.
  [[nodiscard]] uint32_t corrupt_len() const { return corrupt_len_; }

private:
  FILE* f_ = nullptr;
  TraceFileHeader hdr_{};
  std::vector<uint8_t> rec_;
  uint64_t n_events_ = 0;
  uint32_t corrupt_len_ = 0;
};

} // namespace montauk::model
