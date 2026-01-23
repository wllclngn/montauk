// Test Unicode width calculation with wcwidth()
// Build: g++ -std=c++17 -o test_unicode_width test_unicode_width.cpp
// Run: ./test_unicode_width

#include <clocale>
#include <cwchar>
#include <iostream>
#include <string>

// Minimal UTF-8 decoder (same as in Formatting.cpp)
static int utf8_to_wchar(const char* s, size_t len, wchar_t* out) {
  if (len == 0 || !s) return 0;
  unsigned char c = s[0];
  if ((c & 0x80) == 0) { *out = c; return 1; }
  else if ((c & 0xE0) == 0xC0 && len >= 2) {
    *out = ((c & 0x1F) << 6) | (s[1] & 0x3F); return 2;
  } else if ((c & 0xF0) == 0xE0 && len >= 3) {
    *out = ((c & 0x0F) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F); return 3;
  } else if ((c & 0xF8) == 0xF0 && len >= 4) {
    *out = ((c & 0x07) << 18) | ((s[1] & 0x3F) << 12) | ((s[2] & 0x3F) << 6) | (s[3] & 0x3F); return 4;
  }
  return 0;
}

int display_cols(const std::string& s) {
  int cols = 0;
  for (size_t i = 0; i < s.size(); ) {
    wchar_t wc;
    int len = utf8_to_wchar(s.c_str() + i, s.size() - i, &wc);
    if (len > 0) {
      int w = wcwidth(wc);
      cols += (w > 0) ? w : 1;
      i += len;
    } else { cols++; i++; }
  }
  return cols;
}

int main() {
  std::setlocale(LC_ALL, "");  // Required for wcwidth()

  struct TestCase {
    const char* name;
    const char* str;
    int expected_cols;
  };

  TestCase tests[] = {
    // ASCII
    {"ASCII", "hello", 5},
    {"ASCII mixed", "test123", 7},

    // Japanese (each char = 2 columns)
    {"Hiragana", "あいう", 6},           // 3 chars * 2 cols
    {"Katakana", "アイウ", 6},           // 3 chars * 2 cols
    {"Kanji", "日本語", 6},              // 3 chars * 2 cols
    {"Mixed JP", "テスト", 6},           // 3 chars * 2 cols

    // Korean (each char = 2 columns)
    {"Hangul", "한글", 4},               // 2 chars * 2 cols

    // Chinese
    {"Chinese", "中文", 4},              // 2 chars * 2 cols

    // Mixed ASCII + CJK
    {"Mixed", "test日本語", 10},         // "test"=4 + "日本語"=6 = 10
    {"Process name", "テスト_日本語.sh", 16}, // テスト(6) + _(1) + 日本語(6) + .sh(3) = 16

    // Latin with diacritics (1 column each)
    {"Accented", "café", 4},
    {"German", "größe", 5},

    // Box drawing (1 column each)
    {"Box chars", "┌─┐", 3},
    {"Blocks", "█░", 2},
  };

  int passed = 0, failed = 0;

  std::cout << "Unicode Width Tests\n";
  std::cout << "===================\n\n";

  for (const auto& t : tests) {
    int actual = display_cols(t.str);
    bool ok = (actual == t.expected_cols);

    std::cout << (ok ? "PASS" : "FAIL") << ": " << t.name << "\n";
    std::cout << "  String: \"" << t.str << "\"\n";
    std::cout << "  Expected: " << t.expected_cols << " cols, Got: " << actual << " cols\n";

    if (ok) passed++; else failed++;
  }

  std::cout << "\n===================\n";
  std::cout << "Results: " << passed << " passed, " << failed << " failed\n";

  return failed > 0 ? 1 : 0;
}
