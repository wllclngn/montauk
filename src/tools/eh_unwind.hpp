#pragma once
// Offline x86-64 unwinding of a captured user stack by the call frame
// information (.eh_frame) of the files a capture's <pid>.maps names. See
// eh_unwind.cpp.
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace montauk::unwind {

// One line of a <pid>.maps sidecar.
struct Segment {
  uint64_t start = 0, end = 0, file_off = 0, inode = 0;
  bool exec = false;
  std::string path;
};

// The segment holding an address, or nullptr.
using FindSegment = std::function<const Segment*(uint64_t addr)>;

// An interrupted user context: Its registers and the bytes of stack copied
// from its stack pointer up.
struct UserContext {
  uint64_t ip = 0, sp = 0, bp = 0;
  const uint8_t* stack = nullptr;
  size_t stack_len = 0;
};

// The frames the call frame information walks from ctx, innermost first and
// starting with ctx.ip, at most max_frames. The walk stops at the first frame
// it cannot explain: An address no executable file maps, a file that is gone or
// is no longer the inode the capture mapped, no FDE covering the address, a
// rule it does not read, or a slot outside the copied stack.
std::vector<uint64_t> walk(const UserContext& ctx, const FindSegment& find, size_t max_frames);

}  // namespace montauk::unwind
