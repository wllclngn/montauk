#pragma once
#include <liburing.h>

namespace montauk::util {

// Runtime liburing loader (dlopen/dlsym), mirroring util/NvmlDyn.
//
// liburing was hard-linked, which put it in montauk's DT_NEEDED and made the
// whole binary fail to LOAD on a box without it -- including for flags that
// never touch the metrics endpoint. Only four liburing symbols are real exports;
// everything else the endpoint calls (get_sqe, prep_poll_add, sqe_set_data64,
// cqe_get_data64, cqe_seen, the peek fast path) is a header inline compiled
// into montauk's own objects and needs nothing at run time.
//
// The header is still a BUILD dependency -- `struct io_uring` has to have a
// layout -- but the LINK dependency is gone, which is the property that matters.
class UringDyn {
public:
  static UringDyn& instance();

  // dlopen liburing once (idempotent). Respects MONTAUK_URING_PATH.
  [[nodiscard]] bool load_once();
  [[nodiscard]] bool available() const { return loaded_; }

  int queue_init(unsigned entries, struct io_uring* ring, unsigned flags);
  int submit(struct io_uring* ring);
  int wait_cqe(struct io_uring* ring, struct io_uring_cqe** cqe_ptr);
  void queue_exit(struct io_uring* ring);

private:
  UringDyn() = default;
  UringDyn(const UringDyn&) = delete;
  UringDyn& operator=(const UringDyn&) = delete;

  void* handle_{};
  bool loaded_{false};
  bool tried_{false};

  int (*p_queue_init)(unsigned, struct io_uring*, unsigned){};
  int (*p_submit)(struct io_uring*){};
  int (*p_get_cqe)(struct io_uring*, struct io_uring_cqe**, unsigned, unsigned,
                   sigset_t*){};
  void (*p_queue_exit)(struct io_uring*){};
};

}  // namespace montauk::util
