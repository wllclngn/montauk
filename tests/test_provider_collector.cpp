// ProviderCollector: scraping third-party Prometheus-text provider sockets.
#include "minitest.hpp"
#include "collectors/ProviderCollector.hpp"

#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {

// Bind a unix listener at `path`, then accept one connection, write `text`,
// and close — the provider protocol. Returns the listening fd (caller closes).
int serve_once(const std::string& path, std::string text, std::thread& th) {
  int lfd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  ASSERT_TRUE(lfd >= 0);
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  ASSERT_TRUE(path.size() < sizeof(addr.sun_path));
  std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path.c_str());
  ::unlink(path.c_str());
  ASSERT_TRUE(::bind(lfd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0);
  ASSERT_TRUE(::listen(lfd, 1) == 0);
  th = std::thread([lfd, text = std::move(text)] {
    int cfd = ::accept(lfd, nullptr, nullptr);
    if (cfd < 0) return;
    size_t off = 0;
    while (off < text.size()) {
      ssize_t n = ::write(cfd, text.data() + off, text.size() - off);
      if (n <= 0) break;
      off += static_cast<size_t>(n);
    }
    ::close(cfd);
  });
  return lfd;
}

fs::path make_runtime_root() {
  auto root = fs::temp_directory_path() / ("montauk_test_provider_" + std::to_string(::getpid()));
  fs::remove_all(root);
  fs::create_directories(root / "montauk/providers");
  setenv("XDG_RUNTIME_DIR", root.c_str(), 1);
  return root;
}

} // namespace

TEST(provider_collector_missing_dir_is_silent) {
  auto root = fs::temp_directory_path() / ("montauk_test_noprov_" + std::to_string(::getpid()));
  fs::remove_all(root);
  setenv("XDG_RUNTIME_DIR", root.c_str(), 1);
  montauk::collectors::ProviderCollector c;
  std::vector<montauk::model::Provider> out;
  ASSERT_TRUE(!c.sample(out));
  ASSERT_TRUE(out.empty());
}

TEST(provider_collector_scrapes_and_parses) {
  auto root = make_runtime_root();
  std::string prom =
      "# HELP acme_widgets_total Widgets produced\n"
      "# TYPE acme_widgets_total counter\n"
      "acme_widgets_total 42\n"
      "acme_queue_depth{queue=\"main\"} 7\n"
      "acme_temperature_celsius 36.5\n";
  std::thread th;
  int lfd = serve_once((root / "montauk/providers/acme.sock").string(), prom, th);

  montauk::collectors::ProviderCollector c;
  std::vector<montauk::model::Provider> out;
  ASSERT_TRUE(c.sample(out));
  th.join();
  ::close(lfd);

  ASSERT_EQ(out.size(), 1u);
  ASSERT_EQ(out[0].name, std::string("acme"));
  ASSERT_EQ(out[0].raw_text, prom);
  ASSERT_EQ(out[0].metrics.size(), 3u);
  ASSERT_EQ(out[0].metrics[0].name, std::string("acme_widgets_total"));
  ASSERT_TRUE(out[0].metrics[0].labels.empty());
  ASSERT_EQ(out[0].metrics[0].value, 42.0);
  ASSERT_EQ(out[0].metrics[1].name, std::string("acme_queue_depth"));
  ASSERT_EQ(out[0].metrics[1].labels, std::string("queue=\"main\""));
  ASSERT_EQ(out[0].metrics[1].value, 7.0);
  ASSERT_EQ(out[0].metrics[2].value, 36.5);

  fs::remove_all(root);
}

TEST(provider_collector_skips_dead_and_garbled_sockets) {
  auto root = make_runtime_root();
  // Dead socket: bound path with no listener behind it
  {
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    auto p = (root / "montauk/providers/dead.sock").string();
    std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", p.c_str());
    ASSERT_TRUE(::bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0);
    ::close(fd); // closed without listen: connects will fail
  }
  // Garbled provider: serves non-Prometheus bytes
  std::thread th;
  int lfd = serve_once((root / "montauk/providers/garbled.sock").string(),
                       "this is not prometheus\n\x01\x02\x03\n", th);

  montauk::collectors::ProviderCollector c;
  std::vector<montauk::model::Provider> out;
  ASSERT_TRUE(c.sample(out));
  th.join();
  ::close(lfd);
  ASSERT_TRUE(out.empty());

  fs::remove_all(root);
}
