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
  return TraceReadStatus::Ok;
}

} // namespace montauk::model
