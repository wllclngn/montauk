#pragma once

// Runtime libbpf loader. Include AFTER <bpf/libbpf.h>, <bpf/bpf.h> and
// <bpf/btf.h> (the pointer types are taken from those declarations) and BEFORE
// the generated skeleton, whose bpf_object__*_skeleton calls this redirects too.
//
// libbpf was hard-linked, which put it in montauk's DT_NEEDED: a box without it
// could not exec montauk AT ALL -- not the TUI, not --analyze, not --decode,
// none of which touch BPF. That was the whole reason the analyzer and decoder
// shipped as separate executables. Late-binding libbpf is what lets montauk be
// one binary and still start on a machine that cannot trace.
//
// Every signature is decltype'd from the real declaration rather than
// transcribed, so a libbpf prototype change is a compile error here instead of a
// silently mismatched call through a wrong pointer type.

#include <dlfcn.h>

namespace montauk::util {

struct BpfApi {
  decltype(&::bpf_iter_create) p_bpf_iter_create{};
  decltype(&::bpf_link__destroy) p_bpf_link__destroy{};
  decltype(&::bpf_link__fd) p_bpf_link__fd{};
  decltype(&::bpf_map_delete_elem) p_bpf_map_delete_elem{};
  decltype(&::bpf_map__fd) p_bpf_map__fd{};
  decltype(&::bpf_map_get_next_key) p_bpf_map_get_next_key{};
  decltype(&::bpf_map_lookup_elem) p_bpf_map_lookup_elem{};
  decltype(&::bpf_map__set_max_entries) p_bpf_map__set_max_entries{};
  decltype(&::bpf_map_update_elem) p_bpf_map_update_elem{};
  decltype(&::bpf_map__update_elem) p_bpf_map__update_elem{};
  decltype(&::bpf_object__attach_skeleton) p_bpf_object__attach_skeleton{};
  decltype(&::bpf_object__destroy_skeleton) p_bpf_object__destroy_skeleton{};
  decltype(&::bpf_object__load_skeleton) p_bpf_object__load_skeleton{};
  decltype(&::bpf_object__open_skeleton) p_bpf_object__open_skeleton{};
  decltype(&::bpf_program__attach_iter) p_bpf_program__attach_iter{};
  decltype(&::bpf_program__attach) p_bpf_program__attach{};
  decltype(&::bpf_program__attach_tracepoint) p_bpf_program__attach_tracepoint{};
  decltype(&::bpf_program__attach_uprobe_opts) p_bpf_program__attach_uprobe_opts{};
  decltype(&::bpf_program__set_autoattach) p_bpf_program__set_autoattach{};
  decltype(&::bpf_program__set_autoload) p_bpf_program__set_autoload{};
  decltype(&::btf__find_by_name_kind) p_btf__find_by_name_kind{};
  decltype(&::btf__free) p_btf__free{};
  decltype(&::btf__load_vmlinux_btf) p_btf__load_vmlinux_btf{};
  decltype(&::libbpf_get_error) p_libbpf_get_error{};
  decltype(&::libbpf_num_possible_cpus) p_libbpf_num_possible_cpus{};
  decltype(&::ring_buffer__consume) p_ring_buffer__consume{};
  decltype(&::ring_buffer__free) p_ring_buffer__free{};
  decltype(&::ring_buffer__new) p_ring_buffer__new{};
  decltype(&::ring_buffer__poll) p_ring_buffer__poll{};
  bool ok{false};
};

// Resolves libbpf once. MONTAUK_LIBBPF_PATH overrides the soname.
const BpfApi& bpf_api();

}  // namespace montauk::util

// Redirect the call sites -- including the generated skeleton's -- through the
// table. Defined after the struct so the decltypes above still see the real
// declarations, and named p_* so an expansion cannot recurse into itself.
#define bpf_iter_create(...) (::montauk::util::bpf_api().p_bpf_iter_create(__VA_ARGS__))
#define bpf_link__destroy(...) (::montauk::util::bpf_api().p_bpf_link__destroy(__VA_ARGS__))
#define bpf_link__fd(...) (::montauk::util::bpf_api().p_bpf_link__fd(__VA_ARGS__))
#define bpf_map_delete_elem(...) (::montauk::util::bpf_api().p_bpf_map_delete_elem(__VA_ARGS__))
#define bpf_map__fd(...) (::montauk::util::bpf_api().p_bpf_map__fd(__VA_ARGS__))
#define bpf_map_get_next_key(...) (::montauk::util::bpf_api().p_bpf_map_get_next_key(__VA_ARGS__))
#define bpf_map_lookup_elem(...) (::montauk::util::bpf_api().p_bpf_map_lookup_elem(__VA_ARGS__))
#define bpf_map__set_max_entries(...) (::montauk::util::bpf_api().p_bpf_map__set_max_entries(__VA_ARGS__))
#define bpf_map_update_elem(...) (::montauk::util::bpf_api().p_bpf_map_update_elem(__VA_ARGS__))
#define bpf_map__update_elem(...) (::montauk::util::bpf_api().p_bpf_map__update_elem(__VA_ARGS__))
#define bpf_object__attach_skeleton(...) (::montauk::util::bpf_api().p_bpf_object__attach_skeleton(__VA_ARGS__))
#define bpf_object__destroy_skeleton(...) (::montauk::util::bpf_api().p_bpf_object__destroy_skeleton(__VA_ARGS__))
#define bpf_object__load_skeleton(...) (::montauk::util::bpf_api().p_bpf_object__load_skeleton(__VA_ARGS__))
#define bpf_object__open_skeleton(...) (::montauk::util::bpf_api().p_bpf_object__open_skeleton(__VA_ARGS__))
#define bpf_program__attach_iter(...) (::montauk::util::bpf_api().p_bpf_program__attach_iter(__VA_ARGS__))
#define bpf_program__attach(...) (::montauk::util::bpf_api().p_bpf_program__attach(__VA_ARGS__))
#define bpf_program__attach_tracepoint(...) (::montauk::util::bpf_api().p_bpf_program__attach_tracepoint(__VA_ARGS__))
#define bpf_program__attach_uprobe_opts(...) (::montauk::util::bpf_api().p_bpf_program__attach_uprobe_opts(__VA_ARGS__))
#define bpf_program__set_autoattach(...) (::montauk::util::bpf_api().p_bpf_program__set_autoattach(__VA_ARGS__))
#define bpf_program__set_autoload(...) (::montauk::util::bpf_api().p_bpf_program__set_autoload(__VA_ARGS__))
#define btf__find_by_name_kind(...) (::montauk::util::bpf_api().p_btf__find_by_name_kind(__VA_ARGS__))
#define btf__free(...) (::montauk::util::bpf_api().p_btf__free(__VA_ARGS__))
#define btf__load_vmlinux_btf(...) (::montauk::util::bpf_api().p_btf__load_vmlinux_btf(__VA_ARGS__))
#define libbpf_get_error(...) (::montauk::util::bpf_api().p_libbpf_get_error(__VA_ARGS__))
#define libbpf_num_possible_cpus(...) (::montauk::util::bpf_api().p_libbpf_num_possible_cpus(__VA_ARGS__))
#define ring_buffer__consume(...) (::montauk::util::bpf_api().p_ring_buffer__consume(__VA_ARGS__))
#define ring_buffer__free(...) (::montauk::util::bpf_api().p_ring_buffer__free(__VA_ARGS__))
#define ring_buffer__new(...) (::montauk::util::bpf_api().p_ring_buffer__new(__VA_ARGS__))
#define ring_buffer__poll(...) (::montauk::util::bpf_api().p_ring_buffer__poll(__VA_ARGS__))
