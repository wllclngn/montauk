#pragma once

#include <mutex>
#include <string>
#include <thread>

namespace montauk::app {

// Exposes montauk's own state on a unix-socket provider endpoint
// ($XDG_RUNTIME_DIR/montauk/providers/<name>.sock), serving one Prometheus-text
// snapshot per connection — the exact contract montauk's own ProviderCollector
// ingests from other producers. This makes montauk a producer peer in the same
// structured emitter mesh as triskelion, rather than dumping its state to
// stderr. A consumer connects, reads to EOF, and gets the cached snapshot.
//
// The listener thread only reads the cached string under a short lock; the
// producer swaps it via update() on its snapshot tick, so a slow reader never
// stalls the producer.
class ProviderEmitter {
public:
  explicit ProviderEmitter(std::string name);
  ~ProviderEmitter();
  ProviderEmitter(const ProviderEmitter&) = delete;
  ProviderEmitter& operator=(const ProviderEmitter&) = delete;

  // Bind the socket and spawn the listener. Returns false on bind failure
  // (logged by the caller); montauk runs fine without it.
  bool start();

  // Replace the cached snapshot served to subsequent connections.
  void update(std::string payload);

  // Socket filename stem montauk's own ProviderCollector must skip so montauk
  // never ingests its own snapshot (self-scrape).
  static constexpr const char* kSelfName = "montauk";

private:
  void serve(std::stop_token st);

  std::string name_;
  std::string path_;
  int listen_fd_ = -1;
  std::mutex mu_;
  std::string snapshot_;
  std::jthread thread_;
};

} // namespace montauk::app
