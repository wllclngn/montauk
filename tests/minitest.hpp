#pragma once
#include <functional>
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>

namespace mini {

struct TestCase { std::string name; std::function<void()> fn; };
inline std::vector<TestCase>& registry() { static std::vector<TestCase> r; return r; }

struct Registrar {
  Registrar(const std::string& name, std::function<void()> fn) { registry().push_back({name, std::move(fn)}); }
};

inline int run_all() {
  const char* json_env = std::getenv("MONTAUK_TEST_JSON");
  bool json = json_env && (*json_env == '1' || *json_env == 't' || *json_env == 'T' || *json_env == 'y' || *json_env == 'Y');
  int failed = 0; int passed = 0;
  for (auto& t : registry()) {
    try {
      t.fn();
      ++passed;
      if (json) {
        std::cout << "{\"event\":\"test\",\"name\":\"" << t.name << "\",\"status\":\"pass\"}" << "\n";
      } else {
        std::cout << "[PASS] " << t.name << "\n";
      }
    } catch (const std::exception& e) {
      ++failed;
      if (json) {
        std::cout << "{\"event\":\"test\",\"name\":\"" << t.name << "\",\"status\":\"fail\",\"error\":\"";
        // naive JSON string escape for quotes and backslashes
        for (const char c : std::string(e.what())) {
          if (c == '"' || c == '\\') std::cout << '\\' << c; else if (c == '\n') std::cout << "\\n"; else std::cout << c;
        }
        std::cout << "\"}" << "\n";
      } else {
        std::cerr << "[FAIL] " << t.name << ": " << e.what() << "\n";
      }
    } catch (...) {
      ++failed;
      if (json) {
        std::cout << "{\"event\":\"test\",\"name\":\"" << t.name << "\",\"status\":\"fail\",\"error\":\"unknown exception\"}" << "\n";
      } else {
        std::cerr << "[FAIL] " << t.name << ": unknown exception\n";
      }
    }
  }
  if (json) {
    std::cout << "{\"event\":\"summary\",\"passed\":" << passed << ",\"failed\":" << failed << "}" << "\n";
  } else {
    std::cout << "\n" << passed << " passed, " << failed << " failed\n";
  }
  return failed == 0 ? 0 : 1;
}

struct AssertionError : public std::runtime_error { using std::runtime_error::runtime_error; };

} // namespace mini

#define TEST(name) \
  static void name(); \
  static ::mini::Registrar name##_registrar{#name, name}; \
  static void name()

#define ASSERT_TRUE(expr) do { if(!(expr)) throw ::mini::AssertionError(std::string("ASSERT_TRUE failed: ") + #expr); } while(0)
#define ASSERT_EQ(a,b) do { if(!((a)==(b))) { throw ::mini::AssertionError(std::string("ASSERT_EQ failed: ") + #a " == " #b); } } while(0)
#define ASSERT_NE(a,b) do { if(!((a)!=(b))) { throw ::mini::AssertionError(std::string("ASSERT_NE failed: ") + #a " != " #b); } } while(0)
