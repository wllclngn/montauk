#include "model/TraceReader.hpp"

namespace montauk::model {

TraceReader::~TraceReader() { close(); }

void TraceReader::close() {
  if (f_) {
    std::fclose(f_);
    f_ = nullptr;
  }
}

TraceReadStatus TraceReader::open(const char* path) {
  close();
  n_events_ = 0;
  corrupt_len_ = 0;
  f_ = std::fopen(path, "rb");
  if (!f_) return TraceReadStatus::OpenFailed;
  if (std::fread(&hdr_, sizeof(hdr_), 1, f_) != 1) {
    close();
    return TraceReadStatus::ShortHeader;
  }
  if (std::memcmp(hdr_.magic, kTraceMagic, sizeof(hdr_.magic)) != 0) {
    close();
    return TraceReadStatus::BadMagic;
  }
  if (hdr_.version != kTraceFormatVersion) return TraceReadStatus::BadVersion;
  pattern_.assign(hdr_.pattern, strnlen(hdr_.pattern, sizeof(hdr_.pattern)));
  if (hdr_.flags & kTraceFlagPatternRecord) {
    TraceRecordLen len = 0;
    if (std::fread(&len, sizeof(len), 1, f_) != 1 || len < sizeof(uint32_t) ||
        len > kTraceMaxRecordLen)
      return TraceReadStatus::TruncatedRecord;
    rec_.resize(len);
    if (std::fread(rec_.data(), 1, len, f_) != len) return TraceReadStatus::TruncatedRecord;
    uint32_t type = 0;
    std::memcpy(&type, rec_.data(), sizeof(type));
    if (type == kTracePatternRecordType)
      pattern_.assign(reinterpret_cast<const char*>(rec_.data()) + sizeof(type), len - sizeof(type));
  }
  return TraceReadStatus::Ok;
}

} // namespace montauk::model
