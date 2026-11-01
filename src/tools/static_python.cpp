// PYTHON'S BLOCKS ARE INDENTATION, A THIRD BLOCK STRATEGY beside braces and
// keyword-`end`, and the scanner's engine reads braces. So Python is not given a
// second engine: It is rewritten into the first one's grammar, the Rust-shaped
// one (`if c { }`, `for x in y { }`, `pat => { }`) with C's `try { } catch ( ) { }`,
// and every construct the engine already understands reads as itself.
//
// The rewrite is exact about lines and nothing else. Every newline of the source
// stays where it is, so a line number taken from the rewritten text is the
// source's; characters are only ever replaced or inserted within a line. A
// header's `:` becomes `{`, a logical line ends in `;`, and a dedent closes one
// `}` per level it leaves, after the last code of the block it closes. Then the
// rest is spelling:
//
//   elif c:                 else if c {
//   for/while ... else:     a plain block, since the engine's else is an if's
//   try ... else/finally:   else { } / finally { }, which the walker routes
//   except E as e:          catch( E as e){
//   with X as y:            X as y;{  -- the context manager is a statement
//   match s: / case P:      match s {  P => {
//   raise E                 read as return: it leaves the function
//   async                   blanked: async def is a def
//
// and what the engine must not read as structure is blanked in the mask: An
// inline `x if c else y`, a comprehension's `for` and `if`, a dict or set's
// braces (read as parentheses, so a literal is never taken for a body), and a
// class's base list (a metaclass keyword would read as data). Nested functions
// and classes close with `};`, which makes them one statement of the function
// they sit in, as a C++ lambda is.
//
// Code at module level runs too, and branches: `if __name__ == "__main__"`, an
// import tried and caught. A compound statement there, or directly in a class
// body, is wrapped with the clauses that continue it in one more pair of
// braces, which makes it a body the walker reads, filed under <file> as
// top-level code is. And `and` and `or` read as `&&` and `||` in the mask, so a
// condition divides into one block per operand it short-circuits, as C's does.
#include "static_python.hpp"

#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace {

enum Cls : uint8_t { Code, Str, Cmt };

bool ident(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' ||
         (unsigned char)c >= 0x80;
}

struct Lexer {
  const std::string& s;
  std::vector<uint8_t> cls;
  std::vector<int> depth;   // bracket depth before each character
  std::vector<char> paren;  // a mask character standing in for this one, or 0
  int cur = 0;              // bracket depth around the string being lexed
  explicit Lexer(const std::string& src)
      : s(src), cls(src.size(), Code), depth(src.size(), 0), paren(src.size(), 0) {}

  void lit(size_t a, size_t b) {
    for (size_t k = a; k < b && k < s.size(); ++k) { cls[k] = Str; depth[k] = cur; }
  }

  // A string literal starting at its first prefix letter or quote; returns the
  // index past it. An f-string's replacement fields are code: A call made only
  // inside one is a reference like any other. So the mask turns such a string
  // into a parenthesized expression, its quotes and each field's braces into
  // parentheses and its text into blanks, and `f"{stamp()} x"` reads as
  // `((stamp())  )`. A string with no field keeps its quotes.
  size_t string(size_t i) {
    const size_t n = s.size(), start = i;
    bool fmt = false;
    while (i < n && s[i] != '\'' && s[i] != '"') {
      const char c = (char)(s[i] | 0x20);
      fmt |= c == 'f' || c == 't';
      ++i;
    }
    if (i >= n) return i;
    const char q = s[i];
    const size_t open = i;
    const bool triple = i + 2 < n && s[i + 1] == q && s[i + 2] == q;
    const size_t ql = triple ? 3 : 1;
    i += ql;
    size_t close = n;
    bool fields = false;
    while (i < n) {
      const char c = s[i];
      // A raw string keeps its backslashes, but one still stops the next quote
      // ending the string: r"\"" is one string.
      if (c == '\\') { lit(i, i + 2); i += 2; continue; }
      if (fmt && c == '{') {
        if (i + 1 < n && s[i + 1] == '{') { lit(i, i + 2); i += 2; continue; }
        i = field(i + 1);
        fields = true;
        continue;
      }
      if (c == q && (!triple || (i + 2 < n && s[i + 1] == q && s[i + 2] == q))) {
        close = i;
        lit(i, i + ql);
        i += ql;
        break;
      }
      if (c == '\n' && !triple) break;   // unterminated: never swallow the file
      lit(i, i + 1);
      ++i;
    }
    if (i > n) i = n;
    lit(start, open + ql);
    if (fields && close < n) {
      for (size_t k = 0; k < ql; ++k) { paren[open + k] = k ? ' ' : '('; paren[close + k] = k ? ' ' : ')'; }
    } else if (fields) {
      // Unterminated: The whole literal is string, as it was before any field.
      for (size_t k = start; k < i; ++k) paren[k] = 0;
      lit(start, i);
    }
    return i;
  }

  // An f-string replacement field from just past its `{` to just past its `}`.
  // The expression sits one bracket level inside the string, so a `:` in it
  // never reads as a header's and a newline in it never ends a line. Its `!r`
  // conversion, its format spec and a trailing `=` are string.
  size_t field(size_t i) {
    const size_t n = s.size();
    const int base = cur + 1;
    lit(i - 1, i);
    paren[i - 1] = '(';
    int d = 0;
    while (i < n) {
      const char c = s[i];
      if (starts_string(i)) {
        const int save = cur;
        cur = base + d;
        i = string(i);
        cur = save;
        continue;
      }
      if (d == 0 && (c == ':' || (c == '!' && !(i + 1 < n && s[i + 1] == '=')))) return spec(i);
      if (d == 0 && c == '}') { lit(i, i + 1); paren[i] = ')'; return i + 1; }
      depth[i] = base + d;
      if (d == 0 && c == '=' && debug_eq(i)) cls[i] = Str;
      if (c == '(' || c == '[' || c == '{') ++d;
      else if ((c == ')' || c == ']' || c == '}') && d > 0) --d;
      ++i;
    }
    return i;
  }

  // A field's conversion and format spec, to just past the field's `}`. Both
  // are string, but a spec can nest a field of its own (`{x:{w}}`).
  size_t spec(size_t i) {
    const size_t n = s.size();
    while (i < n) {
      const char c = s[i];
      if (c == '{') { i = field(i + 1); continue; }
      lit(i, i + 1);
      if (c == '}') { paren[i] = ')'; return i + 1; }
      ++i;
    }
    return i;
  }

  // `{x=}` and `{x = !r}`: The `=` asks for the expression's text, and is not
  // an assignment.
  bool debug_eq(size_t i) const {
    if (i == 0 || std::strchr("=!<>", s[i - 1]) || (i + 1 < s.size() && s[i + 1] == '=')) return false;
    size_t k = i + 1;
    while (k < s.size() && (s[k] == ' ' || s[k] == '\t')) ++k;
    return k < s.size() && (s[k] == '}' || s[k] == '!' || s[k] == ':');
  }

  bool starts_string(size_t i) const {
    const size_t n = s.size();
    if (i > 0 && ident(s[i - 1])) return false;
    size_t k = i;
    while (k < n && k - i < 2 && std::strchr("rRbBuUfFtT", s[k]) && s[k]) ++k;
    return k < n && (s[k] == '\'' || s[k] == '"');
  }

  void run() {
    const size_t n = s.size();
    int d = 0;
    for (size_t i = 0; i < n;) {
      depth[i] = d;
      const char c = s[i];
      if (c == '#') {
        while (i < n && s[i] != '\n') { cls[i] = Cmt; depth[i] = d; ++i; }
        continue;
      }
      if (starts_string(i)) {
        cur = d;
        i = string(i);
        continue;
      }
      if (c == '(' || c == '[' || c == '{') ++d;
      else if ((c == ')' || c == ']' || c == '}') && d > 0) --d;
      ++i;
    }
  }
};

struct Rep { std::string text, mask; };

}  // namespace

void python_masks(const std::string& src, std::string& mask, std::string& text) {
  const size_t n = src.size();
  Lexer lx(src);
  lx.run();
  std::vector<std::string> pre(n + 1);
  std::map<size_t, Rep> rep;
  std::vector<uint8_t> blank(n, 0);   // mask-only blanking

  auto code_at = [&](size_t i) { return i < n && lx.cls[i] == Code; };
  auto word_at = [&](size_t i) {
    size_t e = i;
    while (e < n && code_at(e) && ident(src[e])) ++e;
    return std::string_view(src).substr(i, e - i);
  };
  auto skip_ws = [&](size_t i, size_t lim) {
    while (i < lim && (src[i] == ' ' || src[i] == '\t' || src[i] == '\f' ||
                       (src[i] == '\\' && i + 1 < n && src[i + 1] == '\n') || src[i] == '\n' ||
                       src[i] == '\r' || lx.cls[i] == Cmt))
      ++i;
    return i;
  };
  auto replace_word = [&](size_t at, std::string_view w, const std::string& with) {
    rep[at] = {with, with};
    for (size_t k = 1; k < w.size(); ++k) rep[at + k] = {"", ""};
  };
  auto blank_word = [&](size_t at, std::string_view w) { for (size_t k = 0; k < w.size(); ++k) blank[at + k] = 1; };
  // Branch words past a statement's leading one are expression syntax, never
  // structure: an inline if/else, a comprehension's for and if.
  auto blank_inline = [&](size_t a, size_t b) {
    for (size_t i = a; i < b; ++i) {
      if (!code_at(i) || !ident(src[i]) || (i > 0 && code_at(i - 1) && ident(src[i - 1]))) continue;
      const std::string_view w = word_at(i);
      if (w == "if" || w == "else" || w == "for" || w == "while" || w == "match" || w == "async")
        blank_word(i, w);
      i += w.size() - 1;
    }
  };
  // `raise` leaves the function: The mask reads it as `return`.
  auto raise_at = [&](size_t i) {
    rep[i + 4] = {"e ", "rn"};
    const char* m = "retu";
    for (int k = 0; k < 4; ++k) rep[i + (size_t)k] = {std::string(1, src[i + (size_t)k]), std::string(1, m[k])};
  };

  // Logical lines: newlines at bracket depth zero, outside strings, not
  // continued by a backslash.
  std::vector<std::pair<size_t, size_t>> lines;
  for (size_t i = 0, ls = 0; i <= n; ++i) {
    if (i < n && !(src[i] == '\n' && lx.cls[i] == Code && lx.depth[i] == 0 &&
                   !(i > 0 && src[i - 1] == '\\') && !(i > 1 && src[i - 1] == '\r' && src[i - 2] == '\\')))
      continue;
    lines.push_back({ls, i});
    ls = i + 1;
  }

  struct Open { int indent, header; std::string close, kind; bool wrapped = false; };
  std::vector<Open> stack{{0, -1, "", "module"}};
  std::map<int, std::string> last_closed;   // header indent -> kind closed there last
  bool pending = false;
  Open pend;
  size_t pend_end = n, last_end = n;
  const auto compound = [](std::string_view w) {
    for (const char* k : {"if", "elif", "else", "while", "for", "try", "except", "finally", "with",
                          "def", "class", "match", "case"})
      if (w == k) return true;
    return false;
  };

  for (const auto& [ls, le] : lines) {
    size_t fc = ls;
    while (fc < le && (src[fc] == ' ' || src[fc] == '\t' || src[fc] == '\f' || src[fc] == '\r' ||
                       lx.cls[fc] == Cmt || (src[fc] == '\\' && fc + 1 < n && src[fc + 1] == '\n') ||
                       src[fc] == '\n'))
      ++fc;
    if (fc >= le) continue;
    size_t pl = src.rfind('\n', fc);
    pl = pl == std::string::npos ? 0 : pl + 1;
    int ind = 0;
    for (size_t k = pl; k < fc; ++k) ind = src[k] == '\t' ? (ind / 8 + 1) * 8 : ind + 1;

    if (pending) {
      if (ind > pend.header) { pend.indent = ind; stack.push_back(pend); }
      else { pre[pend_end] += pend.close; last_closed[pend.header] = pend.kind; }
      pending = false;
    }
    while (stack.size() > 1 && ind < stack.back().indent) {
      if (stack.back().wrapped) pre[last_end] += "}";
      pre[last_end] += stack.back().close;
      last_closed[stack.back().header] = stack.back().kind;
      stack.pop_back();
    }

    size_t kw = fc;
    std::string_view w = code_at(fc) && ident(src[fc]) ? word_at(fc) : std::string_view{};
    if (w == "async") {
      blank_word(fc, w);
      kw = skip_ws(fc + w.size(), le);
      w = word_at(kw);
    }
    if (stack.back().kind == "module" || stack.back().kind == "class") {
      Open& at = stack.back();
      const bool clause = w == "elif" || w == "else" || w == "except" || w == "finally";
      if (at.wrapped && !clause) { pre[last_end] += "}"; at.wrapped = false; }
      if (!at.wrapped && compound(w) && !clause && w != "def" && w != "class") {
        pre[fc] += "{";
        at.wrapped = true;
      }
    }
    // The header's colon: the first at bracket depth zero that is not a walrus.
    size_t colon = std::string::npos;
    if (compound(w)) {
      for (size_t i = kw + w.size(); i < le; ++i)
        if (code_at(i) && src[i] == ':' && lx.depth[i] == 0 && !(i + 1 < n && src[i + 1] == '=')) { colon = i; break; }
      // match and case are soft keywords: Without a colon, or with an
      // assignment before it, the line is a statement about a name.
      if ((w == "match" || w == "case") && colon != std::string::npos)
        for (size_t i = kw + w.size(); i < colon; ++i)
          if (code_at(i) && src[i] == '=' && lx.depth[i] == 0 && !std::strchr("=!<>", src[i - 1]) &&
              !(i + 1 < n && src[i + 1] == '=')) { colon = std::string::npos; break; }
    }
    if (colon == std::string::npos) {
      // A simple statement. A soft keyword leading one is a name
      // (`match = re.match(..)`), and the walker reads `match` wherever it is.
      if (w == "raise") raise_at(kw);
      if (w == "match" || w == "case") blank_word(kw, w);
      blank_inline(kw + w.size(), le);
      pre[le] += ";";
      last_end = le;
      continue;
    }

    const std::string kind(w);
    const std::string& enclosing = stack.back().kind;
    std::string close = "}";
    if ((kind == "def" || kind == "class") && enclosing != "module" && enclosing != "class") close = "};";
    rep[colon] = {"{", "{"};
    if (kind == "elif") replace_word(kw, w, "else if");
    else if (kind == "else") {
      const std::string prev = last_closed.count(ind) ? last_closed[ind] : "";
      if (prev != "if" && prev != "elif" && prev != "except") replace_word(kw, w, std::string(w.size(), ' '));
    } else if (kind == "except") { replace_word(kw, w, "catch("); rep[colon] = {"){", "){"}; }
    else if (kind == "with") { replace_word(kw, w, std::string(w.size(), ' ')); rep[colon] = {";{", ";{"}; }
    else if (kind == "case") { replace_word(kw, w, std::string(w.size(), ' ')); rep[colon] = {"=> {", "=> {"}; }
    else if (kind == "class") {
      const size_t p = skip_ws(kw + 5, colon);
      size_t q = p;
      while (q < colon && ident(src[q])) ++q;
      for (size_t i = q; i < colon; ++i) blank[i] = 1;
    }
    // A def's own name is never expression syntax, whatever it is spelled:
    // `def match(..)` is a function, and only its parameters can hold an
    // inline if.
    size_t from = kw + w.size();
    if (kind == "def") {
      from = skip_ws(from, colon);
      const size_t name = from;
      while (from < colon && ident(src[from])) ++from;
      // A nested def is a statement of the function around it, so its name
      // sits where the walker reads, and a nested `def match` would read as a
      // match. It declares nothing on its own, so the name can go.
      const std::string_view nm = std::string_view(src).substr(name, from - name);
      if (close == "};" && (nm == "match" || nm == "case")) blank_word(name, nm);
    }
    blank_inline(from, colon);

    // A body on the header's own line is one statement, closed with it.
    size_t body = colon + 1;
    while (body < le && (src[body] == ' ' || src[body] == '\t' || lx.cls[body] == Cmt || src[body] == '\r')) ++body;
    if (body < le) {
      const std::string_view bw = code_at(body) && ident(src[body]) ? word_at(body) : std::string_view{};
      if (bw == "raise") raise_at(body);
      blank_inline(body + bw.size(), le);
      pre[le] += ";" + close;
      last_closed[ind] = kind;
      last_end = le;
      continue;
    }
    pending = true;
    pend = {0, ind, close, kind};
    pend_end = le;
    last_end = le;
  }
  if (pending) pre[pend_end] += pend.close;
  while (!stack.empty()) {
    if (stack.back().wrapped) pre[last_end] += "}";
    pre[last_end] += stack.back().close;
    stack.pop_back();
  }

  mask.clear();
  text.clear();
  mask.reserve(n + n / 8);
  text.reserve(n + n / 8);
  for (size_t i = 0; i <= n; ++i) {
    mask += pre[i];
    text += pre[i];
    if (i == n) break;
    const char c = src[i];
    auto r = rep.find(i);
    if (r != rep.end()) {
      text += r->second.text;
      mask += blank[i] ? std::string(r->second.mask.size(), ' ') : r->second.mask;
      continue;
    }
    if (c == '\n') { text += '\n'; mask += '\n'; continue; }
    if (lx.cls[i] == Cmt) { text += ' '; mask += ' '; continue; }
    text += c;
    if (lx.cls[i] == Code && ident(c) && !(i > 0 && lx.cls[i - 1] == Code && ident(src[i - 1]))) {
      const std::string_view wd = word_at(i);
      if ((wd == "and" || wd == "or") && !blank[i]) {
        mask += wd == "and" ? "&& " : "||";
        text += src.substr(i + 1, wd.size() - 1);
        i += wd.size() - 1;
        continue;
      }
    }
    // A string keeps its quotes in the mask, and only its content is blanked:
    // A case arm whose pattern is a string must not read as an empty pattern.
    if (lx.paren[i]) mask += lx.paren[i];
    else if (lx.cls[i] == Str) mask += (c == '\'' || c == '"') && !blank[i] ? c : ' ';
    else if (blank[i]) mask += ' ';
    else if (c == '{') mask += '(';
    else if (c == '}') mask += ')';
    else mask += c;
  }
}
