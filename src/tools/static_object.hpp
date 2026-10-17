#pragma once
// The object lane of montauk --static: what a compiled object declares, read
// from its instructions rather than its source. See static_object.cpp.
#include <cstddef>
#include <string>

struct StaticObjectCounts {
  size_t guards = 0, decls = 0, refs = 0, blocks = 0, edges = 0;
};

enum class ObjectKind { NotElf, Bpf, Aarch64, X86_64, OtherElf };

// What `path` is, from its ELF header alone.
ObjectKind static_object_kind(const std::string& path);

// The dialect name an object kind writes into the artifact ("bpf", "aarch64", "x86-64").
const char* static_object_dialect(ObjectKind k);

// Append an object's records to `body` as file `file_idx`: its file line, then
// D, G, R, B and E rows in the source lane's grammar. False with `err` set when
// the object cannot be read.
bool static_scan_object(const std::string& path, size_t file_idx, std::string& body,
                        StaticObjectCounts& counts, std::string& err);
