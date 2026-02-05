// Simple shared churn counter for recent /proc and /sysfs read issues
#pragma once

#include <chrono>

namespace montauk::util {

enum class ChurnKind { Proc, Sysfs };

// Record a churn event of a given kind at 'now'.
void note_churn(ChurnKind kind);

// Count events in the last 'ms' milliseconds across all kinds.
[[nodiscard]] int count_recent_ms(int ms);

// Count events in the last 'ms' milliseconds for a specific kind.
[[nodiscard]] int count_recent_kind_ms(ChurnKind kind, int ms);

} // namespace montauk::util

