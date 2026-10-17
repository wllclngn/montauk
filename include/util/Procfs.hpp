// C++23 utility helpers for reading /proc with optional root remap
#pragma once
#include <string>
#include <vector>
#include <optional>

namespace montauk::util {

// Map an absolute /proc path to an alternate root if MONTAUK_PROC_ROOT is set
[[nodiscard]] auto map_proc_path(const std::string& abs) -> std::string;

// Map an absolute /sys path to an alternate root if MONTAUK_SYS_ROOT is set
[[nodiscard]] auto map_sys_path(const std::string& abs) -> std::string;

// Read entire file as string. Returns std::nullopt on error.
[[nodiscard]] auto read_file_string(const std::string& abs) -> std::optional<std::string>;

// Read entire file as bytes. Returns std::nullopt on error.
[[nodiscard]] auto read_file_bytes(const std::string& abs) -> std::optional<std::vector<unsigned char>>;

// A one-line attribute (sysfs, /proc/sys): its first line, whitespace trimmed
// from both ends. std::nullopt when it cannot be read.
[[nodiscard]] auto read_line(const std::string& abs) -> std::optional<std::string>;

// One number from a file, as strtoll/strtoull/strtod read it in `base` (0
// takes a 0x prefix). False when the file cannot be opened -- errno then says
// why, ENOENT for one that is gone -- or holds no number (errno EINVAL).
[[nodiscard]] bool read_number(const std::string& abs, long long& out, int base = 10);
[[nodiscard]] bool read_number(const std::string& abs, unsigned long long& out, int base = 10);
[[nodiscard]] bool read_number(const std::string& abs, double& out);

// List directory entries (names only). Returns std::nullopt if the directory
// cannot be opened.
[[nodiscard]] auto read_dir(const std::string& abs) -> std::optional<std::vector<std::string>>;

// List directory entries (names only). Returns empty vector on error.
[[nodiscard]] auto list_dir(const std::string& abs) -> std::vector<std::string>;

// A directory entry with the type getdents64 gives it (DT_DIR, DT_REG, DT_LNK,
// ... or DT_UNKNOWN where the filesystem does not say), so a walk needs no stat
// per entry to tell a directory from a file.
struct DirEntry { std::string name; unsigned char type; };
[[nodiscard]] auto read_dir_typed(const std::string& abs) -> std::optional<std::vector<DirEntry>>;

// Read symlink target. Returns std::nullopt on error.
[[nodiscard]] auto read_symlink(const std::string& abs) -> std::optional<std::string>;

} // namespace montauk::util
