#include "util/UringDyn.hpp"

#include <dlfcn.h>
#include <cstdlib>

#include "util/Log.hpp"

namespace montauk::util {

UringDyn& UringDyn::instance() {
  static UringDyn inst;
  return inst;
}

bool UringDyn::load_once() {
  if (tried_) return loaded_;
  tried_ = true;

  const char* override_path = std::getenv("MONTAUK_URING_PATH");
  const char* lib = override_path && *override_path ? override_path
                                                    : "liburing.so.2";
  handle_ = ::dlopen(lib, RTLD_LAZY | RTLD_LOCAL);
  if (!handle_) {
    log_info("liburing not available (%s): metrics endpoint disabled", lib);
    return false;
  }

  auto L = [&](const char* sym) { return ::dlsym(handle_, sym); };
  p_queue_init = reinterpret_cast<decltype(p_queue_init)>(L("io_uring_queue_init"));
  p_submit     = reinterpret_cast<decltype(p_submit)>(L("io_uring_submit"));
  p_get_cqe    = reinterpret_cast<decltype(p_get_cqe)>(L("__io_uring_get_cqe"));
  p_queue_exit = reinterpret_cast<decltype(p_queue_exit)>(L("io_uring_queue_exit"));

  if (!p_queue_init || !p_submit || !p_get_cqe || !p_queue_exit) {
    log_warn("liburing loaded but is missing expected symbols: endpoint disabled");
    ::dlclose(handle_);
    handle_ = nullptr;
    return false;
  }
  loaded_ = true;
  return true;
}

int UringDyn::queue_init(unsigned entries, struct io_uring* ring, unsigned flags) {
  return p_queue_init(entries, ring, flags);
}

int UringDyn::submit(struct io_uring* ring) { return p_submit(ring); }

// Reproduces liburing's io_uring_wait_cqe: take the peek fast path when a
// completion is already sitting in the ring (pure user-space, no syscall), and
// only then enter the kernel. Calling __io_uring_get_cqe unconditionally would
// also be correct, but it would change the syscall profile of the endpoint's
// hot loop, which is not a change this refactor is entitled to make.
int UringDyn::wait_cqe(struct io_uring* ring, struct io_uring_cqe** cqe_ptr) {
  if (!__io_uring_peek_cqe(ring, cqe_ptr, nullptr) && *cqe_ptr) return 0;
  return p_get_cqe(ring, cqe_ptr, 0, 1, nullptr);
}

void UringDyn::queue_exit(struct io_uring* ring) { p_queue_exit(ring); }

}  // namespace montauk::util
