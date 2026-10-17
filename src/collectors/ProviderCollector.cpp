#include "collectors/ProviderCollector.hpp"
#include "app/ProviderEmitter.hpp"
#include "util/Procfs.hpp"
#include "util/Text.hpp"
#include "sublimation_order.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace montauk::collectors {

namespace {

// Per-provider scrape deadline: a provider that can't accept-and-dump its
// snapshot within this window is skipped for the scrape.
constexpr int kScrapeTimeoutMs = 50;


// Connect to a unix socket and read until EOF, bounded by kScrapeTimeoutMs
// total. Returns false on any failure (caller skips the provider silently).
bool read_provider_socket(const std::string& path, std::string& text) {
  sockaddr_un addr{};
  if (path.size() >= sizeof(addr.sun_path)) return false;
  int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) return false;
  addr.sun_family = AF_UNIX;
  std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);

  int rc = ::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
  if (rc < 0 && errno != EINPROGRESS && errno != EAGAIN) { ::close(fd); return false; }

  pollfd pfd{fd, POLLIN, 0};
  if (rc < 0) {
    pfd.events = POLLOUT;
    if (::poll(&pfd, 1, kScrapeTimeoutMs) <= 0) { ::close(fd); return false; }
    int err = 0; socklen_t el = sizeof(err);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err != 0) { ::close(fd); return false; }
    pfd.events = POLLIN;
  }

  text.clear();
  char buf[4096];
  for (;;) {
    ssize_t n = ::read(fd, buf, sizeof(buf));
    if (n > 0) { text.append(buf, static_cast<size_t>(n)); continue; }
    if (n == 0) { ::close(fd); return true; } // EOF: provider closed after the dump
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      if (::poll(&pfd, 1, kScrapeTimeoutMs) <= 0) { ::close(fd); return false; }
      continue;
    }
    if (errno == EINTR) continue;
    ::close(fd);
    return false;
  }
}

// Parse Prometheus text exposition into metrics. Comment/blank/garbled
// lines are skipped; returns the number of samples parsed.
size_t parse_prometheus(const std::string& text, std::vector<montauk::model::ProviderMetric>& out) {
  size_t pos = 0;
  while (pos < text.size()) {
    size_t eol = text.find('\n', pos);
    if (eol == std::string::npos) eol = text.size();
    const std::string_view line = montauk::util::trim(std::string_view(text.data() + pos, eol - pos));
    pos = eol + 1;
    if (line.empty() || line.front() == '#') continue;

    std::string_view name, labels;
    size_t brace = line.find('{');
    size_t name_end;
    if (brace != std::string_view::npos) {
      size_t close = line.find('}', brace);
      if (close == std::string_view::npos) continue;
      name = line.substr(0, brace);
      labels = line.substr(brace + 1, close - brace - 1);
      name_end = close + 1;
    } else {
      name_end = line.find(' ');
      if (name_end == std::string_view::npos) continue;
      name = line.substr(0, name_end);
    }
    if (name.empty()) continue;

    std::string_view rest = line.substr(name_end);
    while (!rest.empty() && (rest.front() == ' ' || rest.front() == '\t')) rest.remove_prefix(1);
    if (rest.empty()) continue;
    // Value field ends at whitespace (an optional timestamp may follow).
    size_t vend = rest.find_first_of(" \t");
    std::string val(rest.substr(0, vend == std::string_view::npos ? rest.size() : vend));
    char* end = nullptr;
    double v = std::strtod(val.c_str(), &end);
    if (end == val.c_str() || *end != '\0') continue;

    out.push_back({std::string(name), std::string(labels), v});
  }
  return out.size();
}

} // namespace

bool ProviderCollector::sample(std::vector<montauk::model::Provider>& out) {
  out.clear();
  std::string dir = montauk::app::providers_dir();
  auto names = montauk::util::read_dir(dir);
  if (!names) return false; // no providers directory: silent no-providers case

  for (const auto& name : *names) {
    std::string_view fname(name);
    constexpr std::string_view suffix = ".sock";
    if (fname.size() <= suffix.size() || !fname.ends_with(suffix)) continue;

    montauk::model::Provider p;
    p.name = std::string(fname.substr(0, fname.size() - suffix.size()));
    // Skip montauk's own emitter socket — montauk must not ingest its own
    // snapshot (self-scrape feedback). See app/ProviderEmitter.
    if (p.name == montauk::app::ProviderEmitter::kSelfName) continue;
    if (!read_provider_socket(dir + "/" + std::string(fname), p.raw_text)) continue;
    if (parse_prometheus(p.raw_text, p.metrics) == 0) continue; // garbled: skip
    out.push_back(std::move(p));
  }

  // Directory order is arbitrary; sort by name (through sublimation) for stable order
  sublimation_order_strings(out, false, [](const auto& p) { return p.name.c_str(); });
  return true;
}

} // namespace montauk::collectors
