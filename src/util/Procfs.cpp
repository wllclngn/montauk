#include "util/Procfs.hpp"
#include "util/Churn.hpp"

#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>

namespace montauk::util {

static std::string proc_root() {
  const char* env = std::getenv("MONTAUK_PROC_ROOT");
  if (env && *env) return std::string(env);
  return std::string();
}

static std::string sys_root() {
  const char* env = std::getenv("MONTAUK_SYS_ROOT");
  if (env && *env) return std::string(env);
  return std::string();
}

auto map_proc_path(const std::string& abs) -> std::string {
  if (abs.rfind("/proc", 0) != 0) return abs; // not under /proc
  auto root = proc_root();
  if (root.empty()) return abs;
  std::filesystem::path p(root);
  p /= std::filesystem::path(abs.substr(1)); // drop leading '/'
  return p.string();
}

auto map_sys_path(const std::string& abs) -> std::string {
  if (abs.rfind("/sys", 0) != 0) return abs; // not under /sys
  auto root = sys_root();
  if (root.empty()) return abs;
  std::filesystem::path p(root);
  p /= std::filesystem::path(abs.substr(1));
  return p.string();
}

auto read_file_string(const std::string& abs) -> std::optional<std::string> {
  std::ifstream in(map_proc_path(abs));
  if (!in) return std::nullopt;
  try {
    std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return s;
  } catch (...) {
    // File disappeared or became unreadable between open and read
    note_churn(ChurnKind::Proc);
    return std::nullopt;
  }
}

auto read_file_bytes(const std::string& abs) -> std::optional<std::vector<unsigned char>> {
  std::ifstream in(map_proc_path(abs), std::ios::binary);
  if (!in) return std::nullopt;
  try {
    std::vector<unsigned char> buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return buf;
  } catch (...) {
    // File disappeared or became unreadable between open and read
    note_churn(ChurnKind::Proc);
    return std::nullopt;
  }
}

auto list_dir(const std::string& abs) -> std::vector<std::string> {
  std::vector<std::string> out;
  auto path = map_proc_path(abs);
  DIR* d = ::opendir(path.c_str());
  if (!d) return out;
  while (auto* ent = ::readdir(d)) {
    const char* name = ent->d_name;
    if (std::strcmp(name, ".") == 0 || std::strcmp(name, "..") == 0) continue;
    out.emplace_back(name);
  }
  ::closedir(d);
  return out;
}

} // namespace montauk::util
