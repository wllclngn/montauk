#include "util/Churn.hpp"

#include <deque>
#include <mutex>

namespace montauk::util {

struct ChurnEvent { std::chrono::steady_clock::time_point t; ChurnKind kind; };

static std::mutex g_mu;
static std::deque<ChurnEvent> g_events; // small recent window

static void prune_older_than(std::chrono::steady_clock::time_point cutoff) {
  while (!g_events.empty() && g_events.front().t < cutoff) g_events.pop_front();
}

void note_churn(ChurnKind kind) {
  auto now = std::chrono::steady_clock::now();
  std::lock_guard<std::mutex> lk(g_mu);
  // Keep only ~10s worth to bound memory
  auto cutoff = now - std::chrono::seconds(10);
  prune_older_than(cutoff);
  g_events.push_back(ChurnEvent{now, kind});
}

int count_recent_ms(int ms) {
  auto now = std::chrono::steady_clock::now();
  auto cutoff = now - std::chrono::milliseconds(ms);
  std::lock_guard<std::mutex> lk(g_mu);
  prune_older_than(now - std::chrono::seconds(10));
  int c = 0;
  for (const auto& e : g_events) if (e.t >= cutoff) ++c;
  return c;
}

int count_recent_kind_ms(ChurnKind kind, int ms) {
  auto now = std::chrono::steady_clock::now();
  auto cutoff = now - std::chrono::milliseconds(ms);
  std::lock_guard<std::mutex> lk(g_mu);
  prune_older_than(now - std::chrono::seconds(10));
  int c = 0;
  for (const auto& e : g_events) if (e.t >= cutoff && e.kind == kind) ++c;
  return c;
}

} // namespace montauk::util

