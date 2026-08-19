#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>

#include "util/BpfDyn.hpp"

#include <cstdlib>

#include "util/Log.hpp"

namespace montauk::util {

const BpfApi& bpf_api() {
  static const BpfApi api = [] {
    BpfApi a{};
    const char* override_path = std::getenv("MONTAUK_LIBBPF_PATH");
    const char* lib = override_path && *override_path ? override_path : "libbpf.so.1";
    void* h = ::dlopen(lib, RTLD_LAZY | RTLD_LOCAL);
    if (!h) {
      log_info("libbpf not available (%s): --trace disabled", lib);
      return a;
    }
    auto L = [&](const char* n) { return ::dlsym(h, n); };
    a.p_bpf_iter_create = reinterpret_cast<decltype(a.p_bpf_iter_create)>(L("bpf_iter_create"));
    a.p_bpf_link__destroy = reinterpret_cast<decltype(a.p_bpf_link__destroy)>(L("bpf_link__destroy"));
    a.p_bpf_link__fd = reinterpret_cast<decltype(a.p_bpf_link__fd)>(L("bpf_link__fd"));
    a.p_bpf_map_delete_elem = reinterpret_cast<decltype(a.p_bpf_map_delete_elem)>(L("bpf_map_delete_elem"));
    a.p_bpf_map__fd = reinterpret_cast<decltype(a.p_bpf_map__fd)>(L("bpf_map__fd"));
    a.p_bpf_map_get_next_key = reinterpret_cast<decltype(a.p_bpf_map_get_next_key)>(L("bpf_map_get_next_key"));
    a.p_bpf_map_lookup_elem = reinterpret_cast<decltype(a.p_bpf_map_lookup_elem)>(L("bpf_map_lookup_elem"));
    a.p_bpf_map__set_max_entries = reinterpret_cast<decltype(a.p_bpf_map__set_max_entries)>(L("bpf_map__set_max_entries"));
    a.p_bpf_map_update_elem = reinterpret_cast<decltype(a.p_bpf_map_update_elem)>(L("bpf_map_update_elem"));
    a.p_bpf_map__update_elem = reinterpret_cast<decltype(a.p_bpf_map__update_elem)>(L("bpf_map__update_elem"));
    a.p_bpf_object__attach_skeleton = reinterpret_cast<decltype(a.p_bpf_object__attach_skeleton)>(L("bpf_object__attach_skeleton"));
    a.p_bpf_object__destroy_skeleton = reinterpret_cast<decltype(a.p_bpf_object__destroy_skeleton)>(L("bpf_object__destroy_skeleton"));
    a.p_bpf_object__load_skeleton = reinterpret_cast<decltype(a.p_bpf_object__load_skeleton)>(L("bpf_object__load_skeleton"));
    a.p_bpf_object__open_skeleton = reinterpret_cast<decltype(a.p_bpf_object__open_skeleton)>(L("bpf_object__open_skeleton"));
    a.p_bpf_program__attach_iter = reinterpret_cast<decltype(a.p_bpf_program__attach_iter)>(L("bpf_program__attach_iter"));
    a.p_bpf_program__attach = reinterpret_cast<decltype(a.p_bpf_program__attach)>(L("bpf_program__attach"));
    a.p_bpf_program__attach_tracepoint = reinterpret_cast<decltype(a.p_bpf_program__attach_tracepoint)>(L("bpf_program__attach_tracepoint"));
    a.p_bpf_program__attach_uprobe_opts = reinterpret_cast<decltype(a.p_bpf_program__attach_uprobe_opts)>(L("bpf_program__attach_uprobe_opts"));
    a.p_bpf_program__set_autoattach = reinterpret_cast<decltype(a.p_bpf_program__set_autoattach)>(L("bpf_program__set_autoattach"));
    a.p_bpf_program__set_autoload = reinterpret_cast<decltype(a.p_bpf_program__set_autoload)>(L("bpf_program__set_autoload"));
    a.p_btf__find_by_name_kind = reinterpret_cast<decltype(a.p_btf__find_by_name_kind)>(L("btf__find_by_name_kind"));
    a.p_btf__free = reinterpret_cast<decltype(a.p_btf__free)>(L("btf__free"));
    a.p_btf__load_vmlinux_btf = reinterpret_cast<decltype(a.p_btf__load_vmlinux_btf)>(L("btf__load_vmlinux_btf"));
    a.p_libbpf_get_error = reinterpret_cast<decltype(a.p_libbpf_get_error)>(L("libbpf_get_error"));
    a.p_libbpf_num_possible_cpus = reinterpret_cast<decltype(a.p_libbpf_num_possible_cpus)>(L("libbpf_num_possible_cpus"));
    a.p_ring_buffer__consume = reinterpret_cast<decltype(a.p_ring_buffer__consume)>(L("ring_buffer__consume"));
    a.p_ring_buffer__free = reinterpret_cast<decltype(a.p_ring_buffer__free)>(L("ring_buffer__free"));
    a.p_ring_buffer__new = reinterpret_cast<decltype(a.p_ring_buffer__new)>(L("ring_buffer__new"));
    a.p_ring_buffer__poll = reinterpret_cast<decltype(a.p_ring_buffer__poll)>(L("ring_buffer__poll"));
    a.ok = a.p_bpf_iter_create
        && a.p_bpf_link__destroy
        && a.p_bpf_link__fd
        && a.p_bpf_map_delete_elem
        && a.p_bpf_map__fd
        && a.p_bpf_map_get_next_key
        && a.p_bpf_map_lookup_elem
        && a.p_bpf_map__set_max_entries
        && a.p_bpf_map_update_elem
        && a.p_bpf_map__update_elem
        && a.p_bpf_object__attach_skeleton
        && a.p_bpf_object__destroy_skeleton
        && a.p_bpf_object__load_skeleton
        && a.p_bpf_object__open_skeleton
        && a.p_bpf_program__attach_iter
        && a.p_bpf_program__attach
        && a.p_bpf_program__attach_tracepoint
        && a.p_bpf_program__attach_uprobe_opts
        && a.p_bpf_program__set_autoattach
        && a.p_bpf_program__set_autoload
        && a.p_btf__find_by_name_kind
        && a.p_btf__free
        && a.p_btf__load_vmlinux_btf
        && a.p_libbpf_get_error
        && a.p_libbpf_num_possible_cpus
        && a.p_ring_buffer__consume
        && a.p_ring_buffer__free
        && a.p_ring_buffer__new
        && a.p_ring_buffer__poll;
    if (!a.ok) {
      log_warn("libbpf loaded but is missing expected symbols: --trace disabled");
      ::dlclose(h);
      return BpfApi{};
    }
    return a;
  }();
  return api;
}

}  // namespace montauk::util
