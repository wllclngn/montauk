// Test-only RAII guard for a single environment variable: saves whatever was
// there (if anything) in the constructor, restores it in the destructor.
// Same shape as the existing hand-rolled guards elsewhere in the codebase
// (RawTermGuard/AltScreenGuard in include/ui/Terminal.hpp, NvmlGuard in
// include/util/NvmlDyn.hpp) -- ctor acquires, dtor releases, non-copyable.
// No generic scope-guard template exists in this codebase to build on, so
// this is a third bespoke guard in the same established style.
//
// Fixes the env leak across the C++ suite: nearly every collector test sets
// MONTAUK_PROC_ROOT/MONTAUK_SYS_ROOT via setenv() and never unsets it,
// leaking a stale sandbox root across the single-process montauk_tests
// binary. Compose multiple instances for tests that need more than one var
// (e.g. TempRootGuard proc("MONTAUK_PROC_ROOT", root); TempRootGuard
// gpu("MONTAUK_GPU_DISABLE_NATIVE", "1");).
#pragma once

#include <cstdlib>
#include <string>

class TempRootGuard {
public:
  TempRootGuard(const char* var, const std::string& value) : var_(var) {
    const char* old = std::getenv(var);
    had_old_ = old != nullptr;
    if (had_old_) old_value_ = old;
    ::setenv(var, value.c_str(), 1);
  }

  ~TempRootGuard() {
    if (had_old_) ::setenv(var_.c_str(), old_value_.c_str(), 1);
    else ::unsetenv(var_.c_str());
  }

  TempRootGuard(const TempRootGuard&) = delete;
  TempRootGuard& operator=(const TempRootGuard&) = delete;

private:
  std::string var_;
  bool had_old_{false};
  std::string old_value_;
};
