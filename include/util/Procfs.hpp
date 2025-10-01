// C++23 utility helpers for reading /proc with optional root remap
#pragma once
#include <string>
#include <vector>
#include <optional>

namespace lsm::util {

// Map an absolute /proc path to an alternate root if LSM_PROC_ROOT is set
auto map_proc_path(const std::string& abs) -> std::string;

// Map an absolute /sys path to an alternate root if LSM_SYS_ROOT is set
auto map_sys_path(const std::string& abs) -> std::string;

// Read entire file as string. Returns std::nullopt on error.
auto read_file_string(const std::string& abs) -> std::optional<std::string>;

// Read entire file as bytes. Returns std::nullopt on error.
auto read_file_bytes(const std::string& abs) -> std::optional<std::vector<unsigned char>>;

// List directory entries (names only). Returns empty vector on error.
auto list_dir(const std::string& abs) -> std::vector<std::string>;

} // namespace lsm::util
