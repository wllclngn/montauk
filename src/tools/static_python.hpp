#pragma once
// Python for montauk --static: indentation rewritten into the scanner's brace
// grammar, so one engine reads it. See static_python.cpp.
#include <string>

// The two masks the scanner reads, from Python source: `mask` with comments and
// string contents blanked (a string keeps its quotes), `text` with comments blanked and strings kept, the same
// length as each other and with every newline of `src` in its place, so a line
// number taken from either is the source's.
void python_masks(const std::string& src, std::string& mask, std::string& text);
