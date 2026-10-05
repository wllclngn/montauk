// THE STATIC FACE: a fourth producer beside the monitor, the tracer and the
// analyzer's population lane. It reads SOURCE and records what branches a
// program declares -- every condition, and the chain of conditions that must
// hold to reach it. It concludes nothing. That is the analyzer's job, and
// keeping the split is what stops this from becoming a second analyzer.
//
// WHAT IT DECLARES, NOT ONLY WHAT IT BRANCHES ON. A guard line cannot describe
// a function with no branches -- it emits nothing at all -- so an exported
// symbol nothing reaches looks identical to one that was never written. D lines
// record declarations and R lines record every place a declared name is named
// again; the join is "declared, and nothing reaches it". Run over a shell of
// 13,000 lines the first time, it found ten unused inline helpers and three
// enumerators including a public error code no function returns.
//
// AND IT STILL CONCLUDES NOTHING, for a reason the first run demonstrated: the
// join also named `main`, which libc calls and no source in the set does. A
// name dispatched through a table looks the same way. Whether an unreferenced
// declaration is dead is a question for the analyzer with a capture beside it,
// exactly as a never-taken guard is.
//
// WHY THIS PAIRS WITH A CAPTURE AND IS THIN ALONE. The analyzer says what a
// program DID; this says what it COULD do. Neither is scarce on its own. The
// pair answers a question that is otherwise unreachable: which declared branches
// never executed. A classifier that resolves to one value for months leaves its
// other arm dead, the dead arm is invisible in every capture (it emits nothing)
// and invisible in review (it is ordinary, reviewed, commented code), and it
// comes alive the day the classifier is deleted. Recording the branch structure
// is the half nobody had.
//
// WHY A LEXER AND NOT A PARSER. "What had to be true to reach this statement"
// needs paren matching and brace matching, and no types, no name resolution, no
// semantics. Every route that DOES parse costs a dependency this cannot carry:
// clang's JSON AST documents its node fields as changing "in non-additive ways"
// between releases, so a compiler upgrade breaks the reader silently rather than
// loudly, and a translation unit including a kernel's vmlinux.h dumps hundreds
// of megabytes to describe a few thousand lines of the operator's own code.
// debug.DumpCFG is a developer-debug checker printing to stderr under no
// stability contract. libclang is a version pin against the installed LLVM. A
// scanner over the operator's own source depends on nothing and cannot rot.
//
// MACROS ARE NOT EXPANDED, WHICH IS THE POINT. Guards are compared ACROSS
// versions of a file, so `tier == TIER_BATCH` has to stay spelled that way to be
// diffable; an AST hands back `tier == 2` and the comparison is against a
// constant nobody wrote.
//
// THE CONTROL FLOW GRAPH COMES FROM THE SAME LEXER. Nesting says what had to
// hold to reach a statement; it cannot say what a `goto`, an early `return` or
// a `break` does to the rest of the function. B and E records carry the basic
// blocks and the edges between them, built from the statements the scanner
// already finds, so the graph keeps the guards' source spelling and needs no
// compile step. What a lexer cannot see -- exceptions, longjmp, computed gotos,
// a call that never returns -- is left out rather than guessed, and the
// analyzer names it as a limit.

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "sublimation.h"
#include "util/Log.hpp"
#include "util/sink.h"

using montauk::util::log_error;
using montauk::util::log_info;
using montauk::util::log_warn;

namespace {

montauk_sink g_out;
void drain_out() { montauk_sink_drain(&g_out); }

constexpr int kStaticFormat = 2;
constexpr size_t npos = std::string::npos;

bool ident_char(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || c == '_';
}

bool is_space(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

size_t word_end(const std::string& s, size_t i) {
  while (i < s.size() && ident_char(s[i])) ++i;
  return i;
}

// Whether `w` is one of the space-separated words in `list`.
bool in_words(const char* list, std::string_view w) {
  if (!list || w.empty()) return false;
  for (std::string_view l = list; !l.empty();) {
    const size_t sp = l.find(' ');
    if (l.substr(0, sp) == w) return true;
    if (sp == std::string_view::npos) break;
    l.remove_prefix(sp + 1);
  }
  return false;
}

// A DIALECT IS A TABLE ROW. Comment forms, literal forms, how a condition is
// delimited, what names a body and which keywords branch: everything a language
// changes about the scan, and nothing else. A language that needs more than a
// row is engine work and is said to be.
struct Dialect {
  const char* name;
  const char* exts;          // space-separated, with the dot
  bool nested_comments;      // `/* /* */ */` closes twice
  bool lifetimes;            // `'a` is a lifetime or a loop label, not a literal
  bool raw_strings;          // r"..", r#".."#
  bool paren_conds;          // `if (c) S`, against `if c { }`
  bool ternary;              // `?:` branches; otherwise `?` returns early
  const char* fn_word;       // a body is named by the word after this; else by its paren
  const char* containers;    // heads that hold bodies rather than being one
  const char* branches;      // keywords whose condition guards a body
  const char* block_words;   // a word that opens a plain block
};

constexpr Dialect kDialects[] = {
    {"c", ".c .h .cc .cpp .cxx .hh .hpp .hxx .inc", false, false, false, true, true, nullptr,
     "namespace extern struct class union enum", "if while for switch", nullptr},
    {"rust", ".rs", true, true, true, false, false, "fn", "impl mod trait extern",
     "if while for match", "unsafe async"},
};

const Dialect* dialect_named(std::string_view n) {
  if (n == "c" || n == "c++" || n == "cpp") return &kDialects[0];
  if (n == "rust" || n == "rs") return &kDialects[1];
  return nullptr;
}

const Dialect* dialect_for(const std::string& path) {
  const size_t dot = path.rfind('.');
  if (dot == npos || path.find('/', dot) != npos) return nullptr;
  for (const Dialect& d : kDialects)
    if (in_words(d.exts, std::string_view(path).substr(dot))) return &d;
  return nullptr;
}

// TWO MASKS, DIFFERING ONLY IN LITERALS, AND THE SECOND IS NOT OPTIONAL.
// Scanning needs string bodies blanked so brace matching cannot trip over a `}`
// inside a literal. SLICING needs comments blanked but code kept, because guard
// text taken from the raw source drags any comment sitting inside the condition
// along with it -- a real ternary in a real scheduler carried thirty lines of
// prose into its own guard text the first time this ran without it. Every
// replacement is one space per byte and newlines survive, so an offset into
// either mask is the same offset in the source and line numbers stay exact.
//
// `pp`, when given, receives every conditional-compilation directive by offset:
// 'i' #if/#ifdef/#ifndef, 'l' #elif, 'e' #else, 'n' #endif. Only the masker
// knows which `#` lines are directives and which sit inside a comment.
using Directives = std::vector<std::pair<size_t, char>>;

std::string mask_code(const std::string& src, bool keep_strings, const Dialect& d,
                      Directives* pp = nullptr) {
  std::string out = src;
  const size_t n = src.size();
  size_t i = 0;
  bool at_line_start = true;
  while (i < n) {
    const char c = src[i];
    if (c == '\n') { at_line_start = true; ++i; continue; }
    if (at_line_start && (c == ' ' || c == '\t')) { ++i; continue; }
    if (at_line_start && c == '#') {                 // preprocessor line, or an attribute
      if (pp) {
        size_t w = i + 1;
        while (w < n && (src[w] == ' ' || src[w] == '\t')) ++w;
        const std::string word = src.substr(w, word_end(src, w) - w);
        const char k = word == "if" || word == "ifdef" || word == "ifndef" ? 'i'
                     : word == "elif" ? 'l' : word == "else" ? 'e' : word == "endif" ? 'n' : 0;
        if (k) pp->push_back({i, k});
      }
      while (i < n && src[i] != '\n') {
        if (src[i] == '\\' && i + 1 < n && src[i + 1] == '\n') {
          out[i] = ' '; i += 2; continue;            // line continuation
        }
        out[i] = ' '; ++i;
      }
      continue;
    }
    at_line_start = false;
    if (c == '/' && i + 1 < n && src[i + 1] == '/') {
      while (i < n && src[i] != '\n') { out[i] = ' '; ++i; }
      continue;
    }
    if (c == '/' && i + 1 < n && src[i + 1] == '*') {
      out[i] = out[i + 1] = ' ';
      i += 2;
      int depth = 1;
      while (i < n && depth) {
        if (src[i] == '*' && i + 1 < n && src[i + 1] == '/') {
          out[i] = out[i + 1] = ' '; i += 2; --depth; continue;
        }
        if (d.nested_comments && src[i] == '/' && i + 1 < n && src[i + 1] == '*') {
          out[i] = out[i + 1] = ' '; i += 2; ++depth; continue;
        }
        if (src[i] != '\n') out[i] = ' ';
        ++i;
      }
      continue;
    }
    // A DIGIT SEPARATOR IS NOT A QUOTE. C++14 and C23 write `2'000'000'000`, and
    // read as a literal its third quote opens one that blanks everything to the
    // next quote in the file -- on trace_analyze.cpp that hid 82 of 88 functions.
    // A `'` inside a token that starts with a digit is a separator.
    if (c == '\'' && i && ident_char(src[i - 1]) && i + 1 < n && ident_char(src[i + 1])) {
      size_t k = i;
      while (k && ident_char(src[k - 1])) --k;
      if (src[k] >= '0' && src[k] <= '9') { ++i; continue; }
    }
    // r"..", r#".."#, br"..": the body runs to a quote followed by as many `#`.
    if (d.raw_strings && c == 'r' &&
        (i == 0 || !ident_char(src[i - 1]) ||
         (src[i - 1] == 'b' && (i < 2 || !ident_char(src[i - 2]))))) {
      size_t j = i + 1, h = 0;
      while (j < n && src[j] == '#') { ++j; ++h; }
      if (j < n && src[j] == '"') {
        size_t k = j + 1;
        for (; k < n; ++k) {
          if (src[k] != '"') continue;
          size_t m = 0;
          while (m < h && k + 1 + m < n && src[k + 1 + m] == '#') ++m;
          if (m == h) break;
        }
        const size_t stop = k < n ? k + 1 + h : n;
        if (!keep_strings)
          for (size_t q = i + 1; q < stop; ++q) if (src[q] != '\n') out[q] = ' ';
        i = stop;
        continue;
      }
    }
    // `'a` with no closing quote after one character is a lifetime or a label.
    if (d.lifetimes && c == '\'' && i + 1 < n && src[i + 1] != '\\' &&
        static_cast<unsigned char>(src[i + 1]) < 0x80 && !(i + 2 < n && src[i + 2] == '\'')) {
      ++i;
      continue;
    }
    if (c == '"' || c == '\'') {
      const char quote = c;
      if (!keep_strings) out[i] = ' ';
      ++i;
      while (i < n && src[i] != quote) {
        if (src[i] == '\\') {
          if (!keep_strings) {
            out[i] = ' ';
            if (i + 1 < n && src[i + 1] != '\n') out[i + 1] = ' ';
          }
          i += 2;
          continue;
        }
        if (src[i] != '\n' && !keep_strings) out[i] = ' ';
        ++i;
      }
      if (i < n) { if (!keep_strings) out[i] = ' '; ++i; }
      continue;
    }
    ++i;
  }
  return out;
}

// Index just PAST the closer matching the opener at mask[i]; npos if unbalanced.
size_t match_pair(const std::string& mask, size_t i, char opener, char closer) {
  int depth = 0;
  for (; i < mask.size(); ++i) {
    if (mask[i] == opener) ++depth;
    else if (mask[i] == closer && --depth == 0) return i + 1;
  }
  return npos;
}

bool word_at(const std::string& mask, size_t i, const char* word) {
  const size_t len = std::strlen(word);
  if (mask.compare(i, len, word) != 0) return false;
  if (i && ident_char(mask[i - 1])) return false;
  return i + len >= mask.size() || !ident_char(mask[i + len]);
}

size_t skip_space(const std::string& mask, size_t i) {
  while (i < mask.size() && is_space(mask[i])) ++i;
  return i;
}

// The first `tok` in [a, b) outside every (), [] and {}; npos if none.
size_t find_depth0(const std::string& mask, size_t a, size_t b, std::string_view tok) {
  int depth = 0;
  for (size_t i = a; i < b; ++i) {
    const char c = mask[i];
    if (c == '(' || c == '[' || c == '{') ++depth;
    else if (c == ')' || c == ']' || c == '}') --depth;
    else if (depth == 0 && mask.compare(i, tok.size(), tok) == 0) return i;
  }
  return npos;
}

// The body's opening brace for a condition with no parens: the first `{` at
// depth zero, since Rust forbids a struct literal there.
size_t brace_at_depth0(const std::string& mask, size_t a, size_t b) {
  int depth = 0;
  for (size_t i = a; i < b; ++i) {
    const char c = mask[i];
    if (c == '{' && depth == 0) return i;
    if (c == '(' || c == '[') ++depth;
    else if (c == ')' || c == ']') --depth;
  }
  return npos;
}

std::string norm(const std::string& s) {
  std::string out;
  bool space = false;
  for (char c : s) {
    if (is_space(c)) { space = !out.empty(); continue; }
    if (space) { out += ' '; space = false; }
    out += c;
  }
  return out;
}

// A match's arms: the pattern up to `=>`, then a block or one expression.
struct Arm { size_t pat_a, pat_b, body_a, body_b; };

std::vector<Arm> match_arms(const std::string& mask, size_t a, size_t b) {
  std::vector<Arm> arms;
  size_t i = a;
  for (;;) {
    i = skip_space(mask, i);
    while (i < b && mask[i] == ',') i = skip_space(mask, i + 1);
    if (i >= b) break;
    const size_t arrow = find_depth0(mask, i, b, "=>");
    if (arrow == npos) break;
    const size_t body = skip_space(mask, arrow + 2);
    size_t body_end;
    if (body < b && mask[body] == '{') {
      body_end = match_pair(mask, body, '{', '}');
      if (body_end == npos) break;
    } else {
      body_end = find_depth0(mask, body, b, ",");
      if (body_end == npos) body_end = b;
    }
    arms.push_back({i, arrow, body, body_end});
    i = body_end;
  }
  return arms;
}

struct Guard {
  size_t line;
  int depth;
  std::string kind, func, text;
};

struct Scanner {
  const Dialect& d;
  const std::string& src;    // the strings-kept mask; sliced for guard text
  const std::string& mask;   // the full mask; scanned
  const std::vector<size_t>& nl;   // offset of every newline, ascending
  std::vector<Guard>& out;

  size_t line_of(size_t off) const {
    return (size_t)(std::lower_bound(nl.begin(), nl.end(), off) - nl.begin()) + 1;
  }

  // (inner_start, inner_end, resume) for a braced block or a single statement.
  // `resume` is PAST the closer rather than at it, which is what lets the caller
  // look for the `else` that follows.
  void region(size_t after, size_t end, bool at_body,
              size_t* bs, size_t* be, size_t* resume) const {
    size_t j = at_body ? after : skip_space(mask, after);
    if (j < end && mask[j] == '{') {
      size_t close = match_pair(mask, j, '{', '}');
      if (close != npos) {
        *bs = j + 1; *be = close - 1 < end ? close - 1 : end; *resume = close;
        return;
      }
    }
    size_t semi = mask.find(';', j);
    size_t stop = semi == npos ? end : (semi + 1 < end ? semi + 1 : end);
    *bs = j; *be = stop; *resume = stop;
  }

  // The condition after a branch keyword ending at `kw_end`: inside the parens,
  // or up to the body's brace where the dialect has none. 0 when there is no
  // condition here, -1 when its delimiter never closes, 1 with [*a, *b) and the
  // offset the body region starts from.
  int condition(size_t kw_end, size_t end, size_t* a, size_t* b, size_t* body) const {
    if (d.paren_conds) {
      size_t popen = skip_space(mask, kw_end);
      if (popen >= end || mask[popen] != '(') return 0;
      size_t pclose = match_pair(mask, popen, '(', ')');
      if (pclose == npos) return -1;
      *a = popen + 1; *b = pclose - 1; *body = pclose;
      return 1;
    }
    size_t br = brace_at_depth0(mask, kw_end, end);
    if (br == npos) return 0;
    *a = kw_end; *b = br; *body = br;
    return 1;
  }

  // Walk LEFT from `?` to the start of its condition. A ternary is a branch, and
  // enough two-valued decisions are written as one that skipping them drops the
  // guards most worth reading. Stops on a statement or argument boundary at
  // paren depth zero.
  std::string ternary_cond(size_t q) const {
    int depth = 0;
    size_t i = q;
    while (i > 0) {
      --i;
      const char c = mask[i];
      if (c == ')' || c == ']') ++depth;
      else if (c == '(' || c == '[') { if (depth == 0) { ++i; break; } --depth; }
      else if (depth == 0 && (c == ';' || c == '{' || c == '}' || c == ',' ||
                              c == ':' ||
                              (c == '=' && i && !std::strchr("!<>=", mask[i - 1])))) {
        ++i;
        break;
      }
    }
    std::string cond = norm(src.substr(i, q - i));
    for (const char* lead : {"return ", "case "})
      if (cond.rfind(lead, 0) == 0) cond = cond.substr(std::strlen(lead));
    return cond;
  }

  void walk(size_t start, size_t end, const std::string& func,
            std::vector<std::string>& stack) {
    size_t i = start;
    while (i < end) {
      if (d.ternary && mask[i] == '?') {
        std::string cond = ternary_cond(i);
        if (!cond.empty())
          out.push_back({line_of(i), (int)stack.size(), "ternary", func, cond});
        ++i;
        continue;
      }
      if (!ident_char(mask[i]) || (i && ident_char(mask[i - 1]))) { ++i; continue; }
      const size_t we = word_end(mask, i);
      const std::string w = mask.substr(i, we - i);
      if (!in_words(d.branches, w)) { i = we; continue; }
      if (w == "if") { i = walk_if(i, end, func, stack); continue; }
      if (w == "match") { i = walk_match(i, end, func, stack); continue; }
      size_t a, b, body;
      const int st = condition(we, end, &a, &b, &body);
      if (st == 0) { i = we; continue; }
      if (st < 0) break;
      std::string cond = norm(src.substr(a, b - a));
      out.push_back({line_of(i), (int)stack.size(), w, func, cond});
      size_t bs, be, resume;
      region(body, end, false, &bs, &be, &resume);
      stack.push_back(cond);
      walk(bs, be, func, stack);
      stack.pop_back();
      i = resume;
    }
  }

  // One `if`, its body and its whole else chain; returns where to resume. The
  // `else` arm carries the NEGATION as a real guard: for a two-valued classifier
  // that arm is half the behaviour, and an audit recording only the positive
  // test sees half the code.
  size_t walk_if(size_t i, size_t end, const std::string& func,
                 std::vector<std::string>& stack) {
    size_t a, b, body;
    const int st = condition(i + 2, end, &a, &b, &body);
    if (st == 0) return i + 2;
    if (st < 0) return end;
    std::string cond = norm(src.substr(a, b - a));
    out.push_back({line_of(i), (int)stack.size(), "if", func, cond});

    size_t bs, be, resume;
    region(body, end, false, &bs, &be, &resume);
    stack.push_back(cond);
    walk(bs, be, func, stack);
    stack.pop_back();

    size_t j = skip_space(mask, resume);
    if (j >= end || !word_at(mask, j, "else")) return resume;
    std::string neg = "!(" + cond + ")";
    out.push_back({line_of(j), (int)stack.size(), "else", func, neg});
    size_t k = skip_space(mask, j + 4);
    stack.push_back(neg);
    size_t after;
    if (word_at(mask, k, "if")) {
      after = walk_if(k, end, func, stack);
    } else {
      size_t bs2, be2, r2;
      region(k, end, true, &bs2, &be2, &r2);
      walk(bs2, be2, func, stack);
      after = r2;
    }
    stack.pop_back();
    return after;
  }

  // A match is one guard on its scrutinee and one per arm on the arm's pattern,
  // each arm's body nested under both.
  size_t walk_match(size_t i, size_t end, const std::string& func,
                    std::vector<std::string>& stack) {
    size_t a, b, body;
    const int st = condition(i + 5, end, &a, &b, &body);
    if (st == 0) return i + 5;
    if (st < 0) return end;
    const size_t close = match_pair(mask, body, '{', '}');
    if (close == npos) return end;
    std::string scrut = norm(src.substr(a, b - a));
    out.push_back({line_of(i), (int)stack.size(), "match", func, scrut});
    stack.push_back(scrut);
    for (const Arm& arm : match_arms(mask, body + 1, close - 1)) {
      std::string pat = norm(src.substr(arm.pat_a, arm.pat_b - arm.pat_a));
      out.push_back({line_of(arm.pat_a), (int)stack.size(), "arm", func, pat});
      stack.push_back(pat);
      walk(arm.body_a, arm.body_b, func, stack);
      stack.pop_back();
    }
    stack.pop_back();
    return close;
  }
};

// (body_start, body_end, name) for every top-level braced body. An opener with
// no closer ends the scan, and `*unbalanced` names where, so the caller can say
// the rest of the file went unread rather than return a short list as if whole.
struct Func { size_t start, end; std::string name; size_t name_off; };

std::vector<Func> find_functions(const std::string& mask, const Dialect& d, size_t* unbalanced) {
  std::vector<Func> out;
  *unbalanced = npos;
  size_t i = 0;
  while (i < mask.size()) {
    if (mask[i] != '{') { ++i; continue; }
    size_t end = match_pair(mask, i, '{', '}');
    if (end == npos) { *unbalanced = i; break; }
    // The head ends at the last thing that closed: a statement, a body, or an
    // enclosing block's opening brace. Omitting the brace makes the first
    // function inside a namespace inherit the namespace's own head.
    size_t head_start = 0;
    for (char stop : {';', '}', '{'}) {
      size_t p = mask.rfind(stop, i - 1);
      if (p != npos && p + 1 > head_start) head_start = p + 1;
    }
    std::string head = mask.substr(head_start, i - head_start);
    std::string name = "<file>";
    size_t name_off = npos;
    // A CONTAINER IS NOT A BODY. A namespace's brace is the first one in the
    // file, so taking it as one swallows every function inside and files the
    // whole translation unit under <file> -- which is what montauk's own C++
    // sources did. A class, an impl or a mod holds methods the same way. Descend
    // instead. A head with `=` is data, and in C a head with a paren is a
    // function returning one of these.
    bool fn_head = false;
    size_t fn_at = npos;
    if (d.fn_word) {
      for (size_t p = head.find(d.fn_word); p != npos; p = head.find(d.fn_word, p + 1))
        if (word_at(head, p, d.fn_word)) fn_at = p;
      fn_head = fn_at != npos;
    }
    if (!fn_head && head.find('=') == npos && (d.fn_word || head.find(')') == npos)) {
      bool container = false;
      for (size_t p = 0; p < head.size();) {
        if (!ident_char(head[p])) { ++p; continue; }
        const size_t q = word_end(head, p);
        if (in_words(d.containers, std::string_view(head).substr(p, q - p))) container = true;
        p = q;
      }
      if (container) { ++i; continue; }
    }
    if (fn_head) {
      const size_t k = skip_space(head, fn_at + std::strlen(d.fn_word));
      const size_t stop = word_end(head, k);
      if (stop > k) { name = head.substr(k, stop - k); name_off = head_start + k; }
    } else if (!d.fn_word) {
      size_t paren = head.rfind(')');
      if (paren != npos) {
        int depth = 0;
        size_t j = paren + 1;
        while (j > 0) {
          --j;
          if (head[j] == ')') ++depth;
          else if (head[j] == '(' && --depth == 0) break;
        }
        if (j > 0) {
          size_t k = j;
          while (k > 0 && is_space(head[k - 1])) --k;
          size_t stop = k;
          while (k > 0 && ident_char(head[k - 1])) --k;
          if (k < stop) { name = head.substr(k, stop - k); name_off = head_start + k; }
          // A MACRO-DEFINED FUNCTION IS NAMED BY ITS FIRST ARGUMENT. Kernel and
          // BPF sources define whole families as `SEC_MACRO(real_name, ...)`, and
          // taking the identifier before the paren would file every one of them
          // under the macro -- most of a file in one bucket.
          bool upper = !name.empty();
          for (char c : name)
            if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')) upper = false;
          if (upper) {
            std::string args = head.substr(j + 1, paren - j - 1);
            size_t comma = args.find(',');
            std::string first = norm(args.substr(0, comma == npos ? args.size() : comma));
            bool ok = !first.empty();
            for (char c : first) if (!ident_char(c)) ok = false;
            if (ok) name += ":" + first;
          }
        }
      }
    }
    out.push_back({i, end, name, name_off});
    i = end;
  }
  return out;
}

// THE GRAPH OF ONE FUNCTION. Statements are read in order; a straight run of
// them is one block, and every construct that branches closes the block it is
// in and opens new ones. `pend` holds the edges waiting for whatever comes next,
// so a join never needs an empty block of its own, and code with nothing
// flowing into it -- after a return, before a switch's first case -- becomes a
// block with no predecessor, which is how unreachable code shows up at all.
struct Pend { int from; const char* kind; };
struct Block { const char* kind; size_t first, last; std::string text; };
struct Edge { int from, to; const char* kind; };

struct Cfg {
  const Scanner& sc;
  const Dialect& d;
  const std::string& mask;
  const std::string& src;
  const Directives& pp;
  size_t pp_at = 0;
  // An open #if: the flow at its entry, the flow out of each arm so far, and
  // whether an #else means some arm is always compiled.
  struct Alt { std::vector<Pend> entry, outs; bool has_else; };
  std::vector<Alt> alts;
  std::vector<Block> blocks;
  std::vector<Edge> edges;
  int open = -1;
  std::vector<Pend> pend, rets;
  // A loop or a switch: where continue goes (a loop's head), and the break and
  // continue edges collected inside it.
  struct Ctx { int head; bool loop; std::string label; std::vector<Pend> brk, cont; bool saw_default; };
  std::vector<Ctx> ctx;
  std::string label_next;
  std::map<std::string, int> labels;
  std::vector<std::pair<int, std::string>> gotos;

  Cfg(const Scanner& s, const Directives& p) : sc(s), d(s.d), mask(s.mask), src(s.src), pp(p) {}

  int block(const char* kind, size_t off, std::string text = {}) {
    const size_t ln = sc.line_of(off);
    blocks.push_back({kind, ln, ln, std::move(text)});
    return (int)blocks.size() - 1;
  }
  void link(const std::vector<Pend>& from, int to, const char* as = nullptr) {
    for (const Pend& p : from) edges.push_back({p.from, to, as ? as : p.kind});
  }
  void append(std::vector<Pend>& to, const std::vector<Pend>& from) {
    to.insert(to.end(), from.begin(), from.end());
  }
  // Everything that reaches the current point, which is then left empty.
  std::vector<Pend> flow() {
    std::vector<Pend> f = std::move(pend);
    pend.clear();
    if (open >= 0) f.push_back({open, "fall"});
    open = -1;
    return f;
  }
  int node(const char* kind, size_t off, std::string text = {}) {
    std::vector<Pend> f = flow();
    const int id = block(kind, off, std::move(text));
    link(f, id);
    return id;
  }
  // `?` in a dialect without a ternary returns early from the function.
  void try_edge(int id, size_t a, size_t b) {
    if (d.ternary || a >= b || !std::memchr(mask.data() + a, '?', b - a)) return;
    if (rets.empty() || rets.back().from != id) rets.push_back({id, "try"});
  }
  void stmt(size_t a, size_t b) {
    while (b > a && is_space(mask[b - 1])) --b;
    if (open < 0) open = node("stmt", a);
    blocks[open].last = sc.line_of(b > a ? b - 1 : a);
    try_edge(open, a, b);
  }
  void jump(std::vector<Pend>& to, const char* kind) {
    to.push_back({open, kind});
    open = -1;
  }
  std::string take_label() { std::string l = std::move(label_next); label_next.clear(); return l; }
  bool has_code(size_t a, size_t b) const {
    for (; a < b; ++a) if (!is_space(mask[a])) return true;
    return false;
  }

  // A condition: one block per operand of a top-level `||` or `&&`, wired so
  // each short-circuits, since each is a branch the program takes.
  struct Cond { int entry; std::vector<Pend> t, f; };
  Cond cond(size_t a, size_t b) {
    while (a < b && is_space(mask[a])) ++a;
    while (b > a && is_space(mask[b - 1])) --b;
    if (b > a && mask[a] == '(' && match_pair(mask, a, '(', ')') == b) return cond(a + 1, b - 1);
    if (!word_at(mask, a, "let")) {
      for (const char* op : {"||", "&&"}) {
        size_t cut = find_depth0(mask, a, b, op);
        if (cut == npos) continue;
        Cond acc = cond(a, cut);
        while (cut != npos) {
          const size_t next = find_depth0(mask, cut + 2, b, op);
          Cond nx = cond(cut + 2, next == npos ? b : next);
          if (op[0] == '|') { link(acc.f, nx.entry); acc.f = std::move(nx.f); append(acc.t, nx.t); }
          else { link(acc.t, nx.entry); acc.t = std::move(nx.t); append(acc.f, nx.f); }
          cut = next;
        }
        return acc;
      }
    }
    const int id = block("cond", a, norm(src.substr(a, b - a)));
    try_edge(id, a, b);
    return {id, {{id, "true"}}, {{id, "false"}}};
  }

  // Past the `;` that ends a plain statement at depth zero, or `end`. A Rust
  // macro written with braces ends at its own closing brace.
  size_t stmt_end(size_t i, size_t end) const {
    if (!d.paren_conds) {
      const size_t we = word_end(mask, i);
      const size_t bang = skip_space(mask, we);
      const size_t br = bang < end && mask[bang] == '!' ? skip_space(mask, bang + 1) : npos;
      if (we > i && br < end && mask[br] == '{') {
        size_t c = match_pair(mask, br, '{', '}');
        if (c == npos || c > end) return end;
        const size_t s = skip_space(mask, c);
        return s < end && mask[s] == ';' ? s + 1 : c;
      }
    }
    const size_t s = find_depth0(mask, i, end, ";");
    return s == npos ? end : s + 1;
  }
  size_t plain(size_t i, size_t end) {
    const size_t e = stmt_end(i, end);
    stmt(i, e);
    return e;
  }

  // CONDITIONAL COMPILATION IS A BRANCH, between builds rather than at run time.
  // Code under #else or #elif follows the #if's entry, not the arm before it --
  // otherwise the arm after a `return` in the first one reads as unreachable --
  // and an #if with no #else also keeps the path that compiles none of it.
  void directives_before(size_t off) {
    for (; pp_at < pp.size() && pp[pp_at].first < off; ++pp_at) {
      const char k = pp[pp_at].second;
      if (k == 'i') {
        std::vector<Pend> f = flow();
        alts.push_back({f, {}, false});
        pend = std::move(f);
        continue;
      }
      if (alts.empty()) continue;
      Alt& a = alts.back();
      if (k != 'n') {
        append(a.outs, flow());
        a.has_else |= k == 'e';
        pend = a.entry;
        continue;
      }
      std::vector<Pend> f = flow();
      append(f, a.outs);
      if (!a.has_else) append(f, a.entry);
      alts.pop_back();
      for (const Pend& x : f) {
        bool seen = false;
        for (const Pend& y : pend) seen |= y.from == x.from && !std::strcmp(y.kind, x.kind);
        if (!seen) pend.push_back(x);
      }
    }
  }

  void seq(size_t i, size_t end) {
    while ((i = skip_space(mask, i)) < end) {
      directives_before(i);
      i = statement(i, end);
    }
    directives_before(end);
  }

  size_t statement(size_t i, size_t end) {
    if (i >= end) return end;
    const char c = mask[i];
    if (c == '{') {
      const size_t close = match_pair(mask, i, '{', '}');
      if (close == npos || close - 1 > end) { seq(i + 1, end); return end; }
      seq(i + 1, close - 1);
      return close;
    }
    if (c == ';') return i + 1;
    if (d.lifetimes && c == '\'') {                  // 'label: on the loop that follows
      const size_t we = word_end(mask, i + 1);
      const size_t colon = skip_space(mask, we);
      if (we > i + 1 && colon < end && mask[colon] == ':') {
        label_next = mask.substr(i + 1, we - i - 1);
        return colon + 1;
      }
    }
    const size_t we = word_end(mask, i);
    if (we == i) return plain(i, end);
    const std::string w = mask.substr(i, we - i);
    if (w == "if") return parse_if(i, end);
    if (w == "while") return parse_while(i, we, end);
    if (w == "for") return d.paren_conds ? parse_for(i, end) : parse_while(i, we, end);
    if (w == "loop" && !d.paren_conds) return parse_loop(i, we, end);
    if (w == "do" && d.paren_conds) return parse_do(i, end);
    if (w == "switch" && d.paren_conds) return parse_switch(i, end);
    if (w == "match" && !d.paren_conds) return parse_match(i, end);
    if (w == "try" && d.paren_conds) return parse_try(i, end);
    if ((w == "case" || w == "default") && d.paren_conds && switch_ctx())
      return parse_case(i, we, end, w == "default");
    if (w == "return") { const size_t e = plain(i, end); jump(rets, "return"); return e; }
    if (w == "break" || w == "continue") return parse_jump(i, we, end, w == "break");
    if (w == "goto" && d.paren_conds) {
      const size_t e = plain(i, end);
      const size_t a = skip_space(mask, we);
      gotos.push_back({open, mask.substr(a, word_end(mask, a) - a)});
      open = -1;
      return e;
    }
    if (w == "let" && !d.paren_conds) return parse_let(i, end);
    const size_t after = skip_space(mask, we);
    if (in_words(d.block_words, w) && after < end && mask[after] == '{') return statement(after, end);
    if (d.paren_conds && after < end && mask[after] == ':' &&
        !(after + 1 < mask.size() && mask[after + 1] == ':')) {
      open = node("label", i, w);
      labels[w] = open;
      return after + 1;
    }
    // `IDENT(...) {` can only be a macro that opens a block, and every one of
    // them in practice iterates: bpf_for, list_for_each, for_each_cpu.
    if (d.paren_conds && after < end && mask[after] == '(') {
      const size_t pc = match_pair(mask, after, '(', ')');
      const size_t b = pc == npos ? npos : skip_space(mask, pc);
      if (b < end && mask[b] == '{') {
        std::vector<Pend> in = flow();
        const int head = block("macro", i, norm(src.substr(i, pc - i)));
        link(in, head);
        pend = {{head, "true"}};
        ctx.push_back({head, true, take_label(), {}, {}, false});
        const size_t resume = statement(b, end);
        finish_loop(head, {{head, "false"}});
        return resume;
      }
    }
    return plain(i, end);
  }

  Ctx* switch_ctx() {
    for (size_t k = ctx.size(); k-- > 0;) if (!ctx[k].loop) return &ctx[k];
    return nullptr;
  }

  void finish_loop(int head, std::vector<Pend> exits) {
    link(flow(), head, "back");
    Ctx done = std::move(ctx.back());
    ctx.pop_back();
    link(done.cont, head);
    append(exits, done.brk);
    pend = std::move(exits);
  }

  size_t parse_if(size_t i, size_t end) {
    size_t a, b, body;
    if (sc.condition(i + 2, end, &a, &b, &body) != 1) return plain(i, end);
    std::vector<Pend> in = flow();
    Cond c = cond(a, b);
    link(in, c.entry);
    pend = std::move(c.t);
    size_t resume = statement(skip_space(mask, body), end);
    std::vector<Pend> out = flow();
    const size_t j = skip_space(mask, resume);
    if (j < end && word_at(mask, j, "else")) {
      pend = std::move(c.f);
      resume = statement(skip_space(mask, j + 4), end);
      append(out, flow());
    } else {
      append(out, c.f);
    }
    pend = std::move(out);
    return resume;
  }

  size_t parse_while(size_t i, size_t we, size_t end) {
    size_t a, b, body;
    if (sc.condition(we, end, &a, &b, &body) != 1) return plain(i, end);
    std::vector<Pend> in = flow();
    Cond c = cond(a, b);
    link(in, c.entry);
    ctx.push_back({c.entry, true, take_label(), {}, {}, false});
    pend = std::move(c.t);
    const size_t resume = statement(skip_space(mask, body), end);
    finish_loop(c.entry, std::move(c.f));
    return resume;
  }

  size_t parse_for(size_t i, size_t end) {
    const size_t popen = skip_space(mask, i + 3);
    const size_t pclose = popen < end && mask[popen] == '(' ? match_pair(mask, popen, '(', ')') : npos;
    if (pclose == npos) return plain(i, end);
    const size_t s1 = find_depth0(mask, popen + 1, pclose - 1, ";");
    if (s1 == npos) return parse_while(i, i + 3, end);          // range-for
    const size_t s2 = find_depth0(mask, s1 + 1, pclose - 1, ";");
    if (s2 == npos) return plain(i, end);
    if (has_code(popen + 1, s1)) stmt(popen + 1, s1);
    std::vector<Pend> in = flow();
    int head;
    std::vector<Pend> exits;
    if (has_code(s1 + 1, s2)) {
      Cond c = cond(s1 + 1, s2);
      link(in, c.entry);
      head = c.entry;
      pend = std::move(c.t);
      exits = std::move(c.f);
    } else {
      head = block("loop", i);
      link(in, head);
      pend = {{head, "fall"}};
    }
    ctx.push_back({head, true, take_label(), {}, {}, false});
    const size_t resume = statement(skip_space(mask, pclose), end);
    if (has_code(s2 + 1, pclose - 1)) {
      std::vector<Pend> tail = flow();
      append(tail, ctx.back().cont);
      ctx.back().cont.clear();
      open = block("stmt", s2 + 1);
      link(tail, open);
    }
    finish_loop(head, std::move(exits));
    return resume;
  }

  size_t parse_do(size_t i, size_t end) {
    const int head = node("do", i);
    pend = {{head, "fall"}};
    ctx.push_back({head, true, take_label(), {}, {}, false});
    const size_t resume = statement(skip_space(mask, i + 2), end);
    const size_t w = skip_space(mask, resume);
    size_t a, b, body;
    if (w < end && word_at(mask, w, "while") && sc.condition(w + 5, end, &a, &b, &body) == 1) {
      std::vector<Pend> tail = flow();
      Ctx done = std::move(ctx.back());
      ctx.pop_back();
      append(tail, done.cont);
      Cond c = cond(a, b);
      link(tail, c.entry);
      link(c.t, head, "back");
      pend = std::move(c.f);
      append(pend, done.brk);
      const size_t semi = skip_space(mask, body);
      return semi < end && mask[semi] == ';' ? semi + 1 : body;
    }
    finish_loop(head, {});
    return resume;
  }

  size_t parse_loop(size_t i, size_t we, size_t end) {
    const size_t body = skip_space(mask, we);
    if (body >= end || mask[body] != '{') return plain(i, end);
    const int head = node("loop", i);
    pend = {{head, "fall"}};
    ctx.push_back({head, true, take_label(), {}, {}, false});
    const size_t resume = statement(body, end);
    finish_loop(head, {});
    return resume;
  }

  size_t parse_switch(size_t i, size_t end) {
    size_t a, b, body;
    if (sc.condition(i + 6, end, &a, &b, &body) != 1) return plain(i, end);
    const int head = node("switch", i, norm(src.substr(a, b - a)));
    ctx.push_back({head, false, {}, {}, {}, false});
    const size_t resume = statement(skip_space(mask, body), end);
    std::vector<Pend> out = flow();
    Ctx done = std::move(ctx.back());
    ctx.pop_back();
    append(out, done.brk);
    if (!done.saw_default) out.push_back({head, "nomatch"});
    pend = std::move(out);
    return resume;
  }

  size_t parse_case(size_t i, size_t we, size_t end, bool dflt) {
    size_t colon = we;
    for (;;) {
      colon = find_depth0(mask, colon, end, ":");
      if (colon == npos) return plain(i, end);
      if (colon + 1 < mask.size() && mask[colon + 1] == ':') { colon += 2; continue; }
      break;
    }
    Ctx* sw = switch_ctx();
    const int id = node("case", i, dflt ? "default" : norm(src.substr(we, colon - we)));
    edges.push_back({sw->head, id, dflt ? "default" : "case"});
    if (dflt) sw->saw_default = true;
    open = id;
    return colon + 1;
  }

  size_t parse_jump(size_t i, size_t we, size_t end, bool brk) {
    std::string label;
    const size_t a = skip_space(mask, we);
    if (d.lifetimes && a < end && mask[a] == '\'') label = mask.substr(a + 1, word_end(mask, a + 1) - a - 1);
    Ctx* target = nullptr;
    for (size_t k = ctx.size(); k-- > 0;) {
      Ctx& cx = ctx[k];
      if (!label.empty() ? cx.label != label : (!brk && !cx.loop)) continue;
      target = &cx;
      break;
    }
    const size_t e = plain(i, end);
    if (target) jump(brk ? target->brk : target->cont, brk ? "break" : "continue");
    return e;
  }

  size_t parse_match(size_t i, size_t end) {
    size_t a, b, body;
    if (sc.condition(i + 5, end, &a, &b, &body) != 1) return plain(i, end);
    const size_t close = match_pair(mask, body, '{', '}');
    if (close == npos) return plain(i, end);
    const int head = node("match", i, norm(src.substr(a, b - a)));
    try_edge(head, a, b);
    std::vector<Pend> out;
    const std::vector<Arm> arms = match_arms(mask, body + 1, close - 1);
    for (const Arm& arm : arms) {
      open = block("arm", arm.pat_a, norm(src.substr(arm.pat_a, arm.pat_b - arm.pat_a)));
      edges.push_back({head, open, "arm"});
      statement(arm.body_a, arm.body_b);
      append(out, flow());
    }
    if (arms.empty()) out.push_back({head, "fall"});
    pend = std::move(out);
    return close;
  }

  // `let x = if ..`, `let x = match ..`: the binding is a statement and its
  // value is a construct. `let PAT = e else { .. }` is a test whose else must
  // diverge.
  size_t parse_let(size_t i, size_t end) {
    const size_t e = stmt_end(i, end);
    size_t eq = i;
    for (;;) {
      eq = find_depth0(mask, eq, e, "=");
      if (eq == npos) return plain(i, end);
      const char prev = eq ? mask[eq - 1] : ' ', next = eq + 1 < mask.size() ? mask[eq + 1] : ' ';
      if (std::strchr("=<>!", prev) || next == '=' || next == '>') { ++eq; continue; }
      break;
    }
    const size_t r = skip_space(mask, eq + 1);
    const std::string rw = mask.substr(r, word_end(mask, r) - r);
    if (rw == "if" || rw == "match" || rw == "loop" || rw == "unsafe") {
      stmt(i, eq + 1);
      statement(r, e);
      return e;
    }
    for (size_t p = eq + 1; (p = find_depth0(mask, p, e, "else")) != npos; ++p) {
      if (!word_at(mask, p, "else")) continue;
      std::vector<Pend> in = flow();
      Cond c = cond(i, p);
      link(in, c.entry);
      pend = std::move(c.f);
      statement(skip_space(mask, p + 4), e);
      std::vector<Pend> out = flow();
      pend = std::move(c.t);
      append(pend, out);
      return e;
    }
    return plain(i, end);
  }

  size_t parse_try(size_t i, size_t end) {
    const size_t b = skip_space(mask, i + 3);
    if (b >= end || mask[b] != '{') return plain(i, end);
    const int head = node("try", i);
    pend = {{head, "fall"}};
    size_t resume = statement(b, end);
    std::vector<Pend> out = flow();
    for (;;) {
      const size_t k = skip_space(mask, resume);
      if (k >= end || !word_at(mask, k, "catch")) break;
      const size_t p = skip_space(mask, k + 5);
      const size_t pc = p < end && mask[p] == '(' ? match_pair(mask, p, '(', ')') : npos;
      if (pc == npos) break;
      open = block("handler", k, norm(src.substr(p + 1, pc - p - 2)));
      edges.push_back({head, open, "handler"});
      resume = statement(skip_space(mask, pc), end);
      append(out, flow());
    }
    pend = std::move(out);
    return resume;
  }

  void build(const Func& f) {
    pp_at = (size_t)(std::lower_bound(pp.begin(), pp.end(), std::make_pair(f.start, '\0')) - pp.begin());
    block("entry", f.start);
    block("exit", f.end - 1);
    pend = {{0, "fall"}};
    seq(f.start + 1, f.end - 1);
    link(flow(), 1);
    link(rets, 1);
    for (const auto& [from, name] : gotos) {
      const auto it = labels.find(name);
      edges.push_back({from, it == labels.end() ? 1 : it->second,
                       it == labels.end() ? "goto-unresolved" : "goto"});
    }
  }
};

// DECLARED STRUCTURE, which is the half the guard lines cannot carry.
//
// A guard says what a branch is conditioned on. It cannot say what EXISTS: a
// function with no branches emits no G line at all, so an exported symbol that
// nothing reaches is indistinguishable from one that was never written. That
// gap is not hypothetical -- a split fold shipped in a sibling tree with no
// caller reachable, because the dispatch compared a different name, and it was
// found by noticing an output was suspiciously identical rather than by any
// tool.
//
// So: D records what a file declares, R records where a declared name is named
// again, and the pair answers "declared, and nothing reaches it".
//
// THIS STILL CONCLUDES NOTHING. A name dispatched through a table looks
// unreferenced, and a macro-built family looks like one symbol. Whether an
// unreferenced declaration is dead is a question for the analyzer with a
// capture beside it, exactly as a never-taken guard is. Emitting the join here
// would make this a second analyzer, which the split above exists to prevent.
struct Decl { size_t line; std::string kind, name; size_t off; };
struct Ref  { size_t line; std::string func, name; };

// Enumerators are declarations a lexer can see without types: the body of an
// `enum { ... }` is a comma-separated identifier list, and the initialiser of
// each is skipped rather than parsed.
void find_enumerators(const std::string& mask, const Scanner& sc,
                      std::vector<Decl>& out) {
  size_t i = 0;
  while (i + 4 < mask.size()) {
    if (!word_at(mask, i, "enum")) { ++i; continue; }
    size_t b = mask.find('{', i);
    if (b == npos) break;
    // A brace far from the keyword belongs to something else entirely.
    if (mask.find(';', i) < b) { i += 4; continue; }
    size_t e = match_pair(mask, b, '{', '}');
    if (e == npos) break;
    size_t j = b + 1;
    bool expect_name = true;
    while (j < e) {
      char c = mask[j];
      if (c == ',') { expect_name = true; ++j; continue; }
      if (c == '=') {                       // skip an initialiser wholesale
        while (j < e && mask[j] != ',') ++j;
        continue;
      }
      if (expect_name && (ident_char(c) && !(c >= '0' && c <= '9'))) {
        size_t k = j;
        while (k < e && ident_char(mask[k])) ++k;
        out.push_back({sc.line_of(j), "enumerator", mask.substr(j, k - j), j});
        expect_name = false;
        j = k;
        continue;
      }
      ++j;
    }
    i = e;
  }
}

// Every place a KNOWN name is named again, with the function it was named from.
// Restricted to names the scan already declared, because recording every
// identifier would bury the signal in locals and keywords -- and because a
// reference to something outside the scanned set says nothing about whether
// what IS in the set is reachable.
void find_references(const std::string& mask, const Scanner& sc,
                     const std::vector<Func>& funcs,
                     const std::set<std::string>& known,
                     const std::set<size_t>& decl_offsets,
                     std::vector<Ref>& out) {
  size_t fi = 0;
  size_t i = 0;
  while (i < mask.size()) {
    if (!ident_char(mask[i]) || (mask[i] >= '0' && mask[i] <= '9')) { ++i; continue; }
    if (i > 0 && ident_char(mask[i - 1])) { ++i; continue; }
    size_t k = i;
    while (k < mask.size() && ident_char(mask[k])) ++k;
    std::string name = mask.substr(i, k - i);
    // A declaration is not a reference to itself, and the offset says which
    // this is without having to guess from the text.
    if (known.count(name) && !decl_offsets.count(i)) {
      while (fi < funcs.size() && funcs[fi].end < i) ++fi;
      const bool inside = fi < funcs.size() && i >= funcs[fi].start && i <= funcs[fi].end;
      out.push_back({sc.line_of(i), inside ? funcs[fi].name : "<file>", name});
    }
    i = k;
  }
}

bool read_file(const std::string& path, std::string& out) {
  FILE* f = std::fopen(path.c_str(), "rb");
  if (!f) { log_error("cannot open '%s'", path.c_str()); return false; }
  char buf[65536];
  size_t n;
  while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) out.append(buf, n);
  std::fclose(f);
  return true;
}
void usage() {
  montauk_sink_appendf(&g_out,
      "usage: montauk --static FILE|DIR... [-o OUT.guards] [--lang c|rust]\n"
      "                       (records every branch each FILE declares and the\n"
      "                        chain of conditions that must hold to reach it,\n"
      "                        each function's basic blocks and the edges between\n"
      "                        them, what each file DECLARES and every place a\n"
      "                        declared name is named again. Writes an artifact;\n"
      "                        it concludes nothing. Read it with `montauk\n"
      "                        --analyze OUT.guards`. Without -o the artifact goes\n"
      "                        to stdout. A DIR is walked for every file a dialect\n"
      "                        claims by extension, skipping hidden directories\n"
      "                        and any holding a CACHEDIR.TAG. --lang forces one\n"
      "                        dialect on every FILE and limits a DIR to its own\n"
      "                        extensions; c covers C and C++)\n");
}

}  // namespace

#include "tools/Entrypoints.hpp"

int montauk_static_main(int argc, char** argv) {
  montauk_sink_init(&g_out, 1);
  std::atexit(drain_out);

  std::vector<std::string> args;
  std::string out_path;
  const Dialect* forced = nullptr;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--help" || a == "-h") { usage(); return 0; }
    else if ((a == "-o" || a == "--output") && i + 1 < argc) out_path = argv[++i];
    else if (a == "--lang" && i + 1 < argc) {
      forced = dialect_named(argv[++i]);
      if (!forced) {
        log_error("--lang %s: the dialects are c (C and C++) and rust", argv[i]);
        return 2;
      }
    } else if (!a.empty() && a[0] == '-') {
      log_error("unknown flag '%s' (see montauk --static --help)", a.c_str());
      return 2;
    } else args.push_back(a);
  }
  if (args.empty()) { usage(); return 2; }

  // Every input with its dialect. A DIR contributes the files a dialect claims,
  // in byte order of path, so two runs over one tree write one artifact.
  std::vector<std::string> files;
  std::vector<const Dialect*> dialects;
  for (const std::string& a : args) {
    std::error_code ec;
    if (!std::filesystem::is_directory(a, ec)) {
      const Dialect* d = forced ? forced : dialect_for(a);
      files.push_back(a);
      dialects.push_back(d ? d : &kDialects[0]);
      continue;
    }
    std::vector<std::string> found;
    namespace fs = std::filesystem;
    fs::recursive_directory_iterator it(a, fs::directory_options::skip_permission_denied, ec), stop;
    for (; !ec && it != stop; it.increment(ec)) {
      std::error_code q;
      const fs::path& p = it->path();
      if (it->is_directory(q)) {
        const std::string name = p.filename().string();
        if ((!name.empty() && name[0] == '.') || fs::exists(p / "CACHEDIR.TAG", q))
          it.disable_recursion_pending();
        continue;
      }
      if (!it->is_regular_file(q)) continue;
      const Dialect* d = dialect_for(p.string());
      if (d && (!forced || d == forced)) found.push_back(p.string());
    }
    if (ec) { log_error("cannot walk '%s': %s", a.c_str(), ec.message().c_str()); return 2; }
    std::vector<const char*> order;
    for (const std::string& f : found) order.push_back(f.c_str());
    sublimation_strings(order.data(), order.size());
    for (const char* f : order) { files.push_back(f); dialects.push_back(dialect_for(f)); }
  }
  if (files.empty()) { log_error("no source files a dialect claims"); return 2; }

  // TWO PASSES, because a reference can precede its declaration and can live in
  // a different file. The first pass learns every name the scan declares; only
  // then can the second say which of them anything reaches.
  struct Scanned {
    const Dialect* d;
    std::string mask, text;
    std::vector<size_t> nl;
    Directives pp;
    std::vector<Func> funcs;
    std::vector<Decl> decls;
    std::set<size_t> decl_offsets;
  };
  std::vector<Scanned> scanned(files.size());
  std::set<std::string> known;

  for (size_t fi = 0; fi < files.size(); ++fi) {
    std::string src;
    if (!read_file(files[fi], src)) return 2;
    Scanned& s = scanned[fi];
    s.d = dialects[fi];
    s.mask = mask_code(src, false, *s.d, &s.pp);
    s.text = mask_code(src, true, *s.d);
    for (size_t i = 0; i < src.size(); ++i)
      if (src[i] == '\n') s.nl.push_back(i);
    std::vector<Guard> unused;
    Scanner sc{*s.d, s.text, s.mask, s.nl, unused};
    size_t unbalanced;
    s.funcs = find_functions(s.mask, *s.d, &unbalanced);
    if (unbalanced != npos)
      log_warn("%s:%zu: '{' with no matching '}'; the scan of this file stops here",
               files[fi].c_str(), sc.line_of(unbalanced));
    for (const Func& f : s.funcs) {
      if (f.name == "<file>") continue;
      s.decls.push_back({sc.line_of(f.name_off == npos ? f.start : f.name_off),
                         "function", f.name, f.name_off});
      if (f.name_off != npos) s.decl_offsets.insert(f.name_off);
      known.insert(f.name);
    }
    find_enumerators(s.mask, sc, s.decls);
    for (const Decl& d : s.decls) {
      if (d.kind != "enumerator") continue;
      s.decl_offsets.insert(d.off);
      known.insert(d.name);
    }
  }

  std::string body;
  body += "# montauk static guard artifact.\n";
  body += "# G <file_idx> <line> <depth> <kind> <function> <guard>\n";
  body += "# D <file_idx> <line> <kind> <name>          -- what the file declares\n";
  body += "# R <file_idx> <line> <function> <name>      -- where a declared name is named again\n";
  body += "# B <file_idx> <fn_idx> <function> <block> <kind> <first_line> <last_line> <text>\n";
  body += "# E <file_idx> <fn_idx> <function> <from_block> <to_block> <kind>\n";
  body += "static_version " + std::to_string(kStaticFormat) + "\n";
  std::string langs;
  for (const Dialect& d : kDialects)
    if (std::find(dialects.begin(), dialects.end(), &d) != dialects.end())
      langs += (langs.empty() ? "" : ",") + std::string(d.name);
  body += "language " + langs + "\n";

  size_t total = 0, ndecl = 0, nref = 0, nblock = 0, nedge = 0;
  for (size_t fi = 0; fi < files.size(); ++fi) {
    Scanned& s = scanned[fi];
    std::vector<Guard> guards;
    Scanner sc{*s.d, s.text, s.mask, s.nl, guards};
    for (const Func& f : s.funcs) {
      std::vector<std::string> stack;
      sc.walk(f.start + 1, f.end - 1, f.name, stack);
    }
    std::vector<Ref> refs;
    find_references(s.mask, sc, s.funcs, known, s.decl_offsets, refs);

    const std::string fs = std::to_string(fi);
    body += "file " + fs + " " + s.d->name + " " + files[fi] + "\n";
    for (const Decl& d : s.decls)
      body += "D\t" + fs + "\t" + std::to_string(d.line) + "\t" + d.kind + "\t" + d.name + "\n";
    for (const Guard& g : guards)
      body += "G\t" + fs + "\t" + std::to_string(g.line) + "\t" + std::to_string(g.depth) +
              "\t" + g.kind + "\t" + g.func + "\t" + g.text + "\n";
    for (const Ref& rf : refs)
      body += "R\t" + fs + "\t" + std::to_string(rf.line) + "\t" + rf.func + "\t" + rf.name + "\n";
    for (size_t k = 0; k < s.funcs.size(); ++k) {
      const Func& f = s.funcs[k];
      if (f.name == "<file>") continue;
      Cfg g(sc, s.pp);
      g.build(f);
      const std::string head = fs + "\t" + std::to_string(k) + "\t" + f.name + "\t";
      for (size_t b = 0; b < g.blocks.size(); ++b)
        body += "B\t" + head + std::to_string(b) + "\t" + g.blocks[b].kind + "\t" +
                std::to_string(g.blocks[b].first) + "\t" + std::to_string(g.blocks[b].last) +
                "\t" + g.blocks[b].text + "\n";
      for (const Edge& e : g.edges)
        body += "E\t" + head + std::to_string(e.from) + "\t" + std::to_string(e.to) + "\t" +
                e.kind + "\n";
      nblock += g.blocks.size();
      nedge += g.edges.size();
    }
    total += guards.size();
    ndecl += s.decls.size();
    nref += refs.size();
  }

  if (out_path.empty()) {
    montauk_sink_appendf(&g_out, "%s", body.c_str());
    return 0;
  }
  FILE* out = std::fopen(out_path.c_str(), "wb");
  if (!out) { log_error("cannot write '%s'", out_path.c_str()); return 2; }
  const bool ok = std::fwrite(body.data(), 1, body.size(), out) == body.size();
  std::fclose(out);
  if (!ok) { log_error("short write on '%s'", out_path.c_str()); return 2; }
  log_info("%zu guard(s), %zu declaration(s), %zu reference(s), %zu block(s), %zu edge(s) "
           "from %zu file(s) -> %s",
           total, ndecl, nref, nblock, nedge, files.size(), out_path.c_str());
  return 0;
}
