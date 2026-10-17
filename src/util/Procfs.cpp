#include "util/Procfs.hpp"
#include "util/Churn.hpp"

#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <limits.h>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include "util/Text.hpp"

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

static std::string map_path(const std::string& abs) {
  return map_sys_path(map_proc_path(abs));
}

// THE WHOLE FILE IN READS, NOT A STREAM. procfs and sysfs report a size of
// zero, so a file is read until read() returns nothing, into a buffer that
// doubles; the stream this replaced took one virtual call per character. A
// read that fails after the open (a process exited under its /proc files) is
// churn, not an error.
template <class Buf>
static bool read_whole(const std::string& abs, Buf& out) {
  int fd = ::open(map_path(abs).c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  size_t len = 0;
  out.resize(4096);
  for (;;) {
    if (len == out.size()) out.resize(out.size() * 2);
    const ssize_t n = ::read(fd, out.data() + len, out.size() - len);
    if (n > 0) { len += (size_t)n; continue; }
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) {
      ::close(fd);
      note_churn(ChurnKind::Proc);
      return false;
    }
    break;
  }
  ::close(fd);
  out.resize(len);
  return true;
}

auto read_file_string(const std::string& abs) -> std::optional<std::string> {
  std::string s;
  if (!read_whole(abs, s)) return std::nullopt;
  return s;
}

auto read_file_bytes(const std::string& abs) -> std::optional<std::vector<unsigned char>> {
  std::vector<unsigned char> b;
  if (!read_whole(abs, b)) return std::nullopt;
  return b;
}

auto read_line(const std::string& abs) -> std::optional<std::string> {
  auto s = read_file_string(abs);
  if (!s) return std::nullopt;
  return std::string(trim(std::string_view(*s).substr(0, s->find('\n'))));
}

// A number is short: one read into the stack, no allocation past the path.
static bool read_short(const std::string& abs, char (&buf)[64]) {
  int fd = ::open(map_path(abs).c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  ssize_t n;
  do n = ::read(fd, buf, sizeof buf - 1); while (n < 0 && errno == EINTR);
  ::close(fd);
  if (n <= 0) { errno = n < 0 ? errno : EINVAL; return false; }
  buf[n] = '\0';
  return true;
}

bool read_number(const std::string& abs, long long& out, int base) {
  char buf[64];
  if (!read_short(abs, buf)) return false;
  char* end = nullptr;
  const long long v = std::strtoll(buf, &end, base);
  if (end == buf) { errno = EINVAL; return false; }
  out = v;
  return true;
}

bool read_number(const std::string& abs, unsigned long long& out, int base) {
  char buf[64];
  if (!read_short(abs, buf)) return false;
  char* end = nullptr;
  const unsigned long long v = std::strtoull(buf, &end, base);
  if (end == buf) { errno = EINVAL; return false; }
  out = v;
  return true;
}

bool read_number(const std::string& abs, double& out) {
  char buf[64];
  if (!read_short(abs, buf)) return false;
  char* end = nullptr;
  const double v = std::strtod(buf, &end);
  if (end == buf) { errno = EINVAL; return false; }
  out = v;
  return true;
}

// getdents64 into a caller-owned buffer: Many entries per syscall and no DIR
// allocation, which is the shape a per-frame walk of /proc and of every pid's
// fdinfo wants. readdir is the same syscall behind a heap-allocated stream and
// a call per entry. Every entry but . and .. goes to `f`.
template <class F>
static bool each_dent(const std::string& abs, F&& f) {
  auto path = map_path(abs);
  int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) return false;
  alignas(dirent64) char buf[32768];
  for (;;) {
    ssize_t n = ::getdents64(fd, buf, sizeof buf);
    if (n <= 0) break;
    for (ssize_t off = 0; off < n;) {
      const auto* ent = reinterpret_cast<const dirent64*>(buf + off);
      off += ent->d_reclen;
      const char* name = ent->d_name;
      if (name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'))) continue;
      f(name, ent->d_type);
    }
  }
  ::close(fd);
  return true;
}

auto read_dir(const std::string& abs) -> std::optional<std::vector<std::string>> {
  std::vector<std::string> out;
  if (!each_dent(abs, [&](const char* name, unsigned char) { out.emplace_back(name); })) return std::nullopt;
  return out;
}

auto read_dir_typed(const std::string& abs) -> std::optional<std::vector<DirEntry>> {
  std::vector<DirEntry> out;
  if (!each_dent(abs, [&](const char* name, unsigned char type) { out.push_back({name, type}); })) return std::nullopt;
  return out;
}

auto list_dir(const std::string& abs) -> std::vector<std::string> {
  return read_dir(abs).value_or(std::vector<std::string>{});
}

auto read_symlink(const std::string& abs) -> std::optional<std::string> {
  auto path = map_path(abs);
  char buf[PATH_MAX];
  ssize_t len = ::readlink(path.c_str(), buf, sizeof(buf) - 1);
  if (len < 0) return std::nullopt;
  buf[len] = '\0';
  return std::string(buf);
}

} // namespace montauk::util
