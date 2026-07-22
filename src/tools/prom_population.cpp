// prom_population — implementation. See prom_population.hpp.
#include "prom_population.hpp"
#include "sublimation.h"
#include "sublimation_order.hpp"

#include "prom_stats.hpp"
#include "util/Log.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <dirent.h>
#include <sys/stat.h>

#include "util/sink.h"

#ifndef MONTAUK_VERSION
#define MONTAUK_VERSION "unknown"
#endif

namespace montauk::pop {

namespace {

// Population / l2-by-cpu stdout drains through one buffered sink, lazily set up
// on first use (these paths run from montauk_analyze's main) and drained at exit.
montauk_sink g_pop_out;
bool g_pop_out_init = false;
void drain_pop_out() { montauk_sink_drain(&g_pop_out); }
void ensure_pop_out() {
  if (!g_pop_out_init) {
    montauk_sink_init(&g_pop_out, 1);
    std::atexit(drain_pop_out);
    g_pop_out_init = true;
  }
}

using LabelVec = std::vector<std::pair<std::string, std::string>>;

// Fragmenting-label diagnostic accumulator: label name -> file -> value set.
using DiagLabelValues =
    std::map<std::string, std::map<std::string, std::set<std::string>>>;

// One reconstructed-sample pool plus the per-run scalar vector, per group.
struct Cell {
  LabelVec display;  // cell labels (sans compare axis), for the report header
  std::map<std::string, std::vector<double>> runs;  // axis value -> per-run scalar
  std::map<std::string, std::vector<double>> samp;  // axis value -> pooled within-run
};

struct Family {
  std::map<std::string, Cell> cells;  // cell key -> cell
};

// Prometheus text parsing

std::string strip(const std::string& s) {
  size_t a = 0, b = s.size();
  while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
  while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
  return s.substr(a, b - a);
}

// Parse `key="value",key="value"` (values may contain spaces/parens, and
// per the Prometheus text format may contain escaped quotes and backslashes;
// the closing-quote scan honors the escapes). Values keep their raw escaped
// bytes: identity only needs consistency, not unescaping.
LabelVec parse_labels(const std::string& in) {
  LabelVec out;
  size_t i = 0;
  while (i < in.size()) {
    size_t eq = in.find('=', i);
    if (eq == std::string::npos) break;
    std::string key = strip(in.substr(i, eq - i));
    size_t q1 = in.find('"', eq);
    if (q1 == std::string::npos) break;
    size_t q2 = std::string::npos;
    for (size_t j = q1 + 1; j < in.size(); ++j) {
      if (in[j] == '\\') {
        ++j;
        continue;
      }
      if (in[j] == '"') {
        q2 = j;
        break;
      }
    }
    if (q2 == std::string::npos) break;
    std::string val = in.substr(q1 + 1, q2 - q1 - 1);
    if (!key.empty()) out.emplace_back(key, val);
    i = in.find(',', q2);
    if (i == std::string::npos) break;
    ++i;
  }
  return out;
}

std::string label_get(const LabelVec& labels, const std::string& key) {
  for (const auto& kv : labels)
    if (kv.first == key) return kv.second;
  return std::string();
}

// Canonical key of the labels excluding `drop` keys (sorted for stability).
std::string cell_key(const LabelVec& labels,
                     const std::set<std::string>& drop) {
  std::vector<std::string> parts;
  for (const auto& kv : labels)
    if (!drop.count(kv.first)) parts.push_back(kv.first + "=" + kv.second);
  sublimation_order_strings(parts, false, [](const std::string& s){ return s.c_str(); });
  std::string s;
  for (const auto& p : parts) {
    if (!s.empty()) s += ",";
    s += p;
  }
  return s;
}

LabelVec cell_display(const LabelVec& labels,
                      const std::set<std::string>& drop) {
  LabelVec out;
  for (const auto& kv : labels)
    if (!drop.count(kv.first)) out.push_back(kv);
  // Whole-pair lexicographic order (key, then value) as one byte-key string
  // sort: key + NUL + value compares exactly like std::pair<string,string>
  // (label text never contains NUL), via the length-explicit index sort.
  const size_t n = out.size();
  if (n > 1) {
    std::vector<std::string> keys(n);
    std::vector<const char*> ptrs(n);
    std::vector<size_t> lens(n);
    std::vector<uint32_t> idx(n);
    for (size_t i = 0; i < n; ++i) {
      keys[i] = out[i].first;
      keys[i].push_back('\0');
      keys[i] += out[i].second;
      ptrs[i] = keys[i].data();
      lens[i] = keys[i].size();
    }
    sublimation_strings_indices_len(ptrs.data(), lens.data(), idx.data(), n);
    LabelVec sorted;
    sorted.reserve(n);
    for (size_t i = 0; i < n; ++i) sorted.push_back(std::move(out[idx[i]]));
    out = std::move(sorted);
  }
  return out;
}

double le_value(const std::string& le) {
  if (le == "+Inf") return INFINITY;
  return std::strtod(le.c_str(), nullptr);
}

// Natural-version ordering for --pairs adjacent and the trajectory view.
// Tokenize into numeric and non-numeric runs (one leading v/V stripped);
// numeric runs compare as integers, non-numeric lexicographically, numeric
// before non-numeric at a mixed position. When one string is a prefix of the
// other, the longer sorts FIRST only if it continues into a pre-release run
// (a dash, tilde or letter: 7.13.0-rc1 before 7.13.0), otherwise the shorter
// sorts first (1.2 before 1.2.1). Heuristic by design; callers break full
// ties by first-seen order via stable sort.
bool natural_version_less(const std::string& a, const std::string& b) {
  auto is_d = [](char c) { return c >= '0' && c <= '9'; };
  auto prerelease_start = [](char c) {
    return c == '-' || c == '~' || (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z');
  };
  size_t i = 0, j = 0;
  if (i < a.size() && (a[i] == 'v' || a[i] == 'V') && a.size() > 1) ++i;
  if (j < b.size() && (b[j] == 'v' || b[j] == 'V') && b.size() > 1) ++j;
  while (i < a.size() && j < b.size()) {
    if (is_d(a[i]) && is_d(b[j])) {
      size_t ie = i, je = j;
      while (ie < a.size() && is_d(a[ie])) ++ie;
      while (je < b.size() && is_d(b[je])) ++je;
      size_t ia = i, jb = j;
      while (ia + 1 < ie && a[ia] == '0') ++ia;
      while (jb + 1 < je && b[jb] == '0') ++jb;
      size_t la = ie - ia, lb = je - jb;
      if (la != lb) return la < lb;
      int c = a.compare(ia, la, b, jb, lb);
      if (c != 0) return c < 0;
      i = ie;
      j = je;
    } else if (is_d(a[i]) != is_d(b[j])) {
      return is_d(a[i]);
    } else {
      if (a[i] != b[j]) return a[i] < b[j];
      ++i;
      ++j;
    }
  }
  if (i >= a.size() && j >= b.size()) return false;
  if (i >= a.size()) return !prerelease_start(b[j]);
  return prerelease_start(a[i]);
}

// Stable natural-version ordering through sublimation: derive each string's
// rank under the comparator (how many others sort strictly before it), then a
// stable pack index sort by rank. On any input set where natural_version_less
// is a strict weak order this reproduces a stable sort exactly -- equal ranks
// are exactly the comparator's ties and the pack sort's index tiebreak keeps
// their first-seen order. The comparator's heuristic corner cases (its
// prerelease/end/digit rules are cyclic on adversarial mixes) get a
// deterministic total completion instead of unspecified merge behavior.
// O(n^2) comparator calls; n is a version-axis value count (tens).
void natural_version_sort(std::vector<std::string>& v) {
  const size_t n = v.size();
  if (n < 2) return;
  std::vector<uint64_t> rank(n, 0);
  for (size_t x = 0; x < n; ++x)
    for (size_t y = 0; y < n; ++y)
      if (y != x && natural_version_less(v[y], v[x])) ++rank[x];
  std::vector<uint32_t> idx(n);
  for (size_t i = 0; i < n; ++i) idx[i] = static_cast<uint32_t>(i);
  sublimation_pack_sort_u64(rank.data(), idx.data(), n, false);
  std::vector<std::string> out;
  out.reserve(n);
  for (size_t i = 0; i < n; ++i) out.push_back(std::move(v[idx[i]]));
  v = std::move(out);
}

// Metric-family aliasing (--alias OLD=NEW): exact match, no chaining.
const std::string& alias_family(const std::string& n, const PopOptions& opt) {
  auto it = opt.family_alias.find(n);
  return it == opt.family_alias.end() ? n : it->second;
}

// Per-file parse accounting, so --by LABEL failures diagnose themselves
// instead of reporting "no usable gauges."
struct ParseStats {
  size_t samples = 0;             // gauge/bucket samples that reached routing
  size_t no_axis = 0;             // skipped: series carries no compare-axis label
  size_t files_with_version = 0;  // files whose *_info yielded a version
};

// printf-append into a std::string; the per-cell workers build their report
// text privately, so the shared sink is only touched by the ordered emit.
void sappendf(std::string& out, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  va_list ap2;
  va_copy(ap2, ap);
  int need = std::vsnprintf(nullptr, 0, fmt, ap);
  va_end(ap);
  if (need > 0) {
    size_t at = out.size();
    out.resize(at + static_cast<size_t>(need) + 1);
    std::vsnprintf(out.data() + at, static_cast<size_t>(need) + 1, fmt, ap2);
    out.resize(at + static_cast<size_t>(need));
  }
  va_end(ap2);
}

// FNV-1a over a string, chained; feeds the per-cell Rng seed so results are
// deterministic for a given --seed regardless of thread count or schedule.
uint64_t fnv1a(uint64_t h, const std::string& s) {
  for (unsigned char c : s) {
    h ^= c;
    h *= 1099511628211ull;
  }
  return h;
}

// Per-(family,labels) histogram accumulator (for the within-run reconstruction).
struct Hist {
  std::map<double, long long> buckets;  // le -> cumulative count
};

}  // namespace

std::vector<std::string> glob_proms(const std::string& dir) {
  std::vector<std::string> out;
  DIR* d = ::opendir(dir.c_str());
  if (!d) return out;
  for (dirent* e; (e = ::readdir(d)) != nullptr;) {
    std::string name = e->d_name;
    if (name.size() < 6 || name.compare(name.size() - 5, 5, ".prom") != 0)
      continue;
    if (name.rfind("analysis-", 0) == 0) continue;  // our own outputs
    out.push_back(dir + "/" + name);
  }
  ::closedir(d);
  sublimation_order_strings(out, false, [](const std::string& s){ return s.c_str(); });
  return out;
}

namespace {

// Reconstruct representative samples from a cumulative-bucket histogram
// (geometric-midpoint placement; +Inf overflow at the largest finite bound).
void reconstruct(const Hist& h, std::vector<double>& out) {
  double prev_le = 0.0;
  long long prev_cum = 0;
  for (const auto& kv : h.buckets) {  // std::map iterates le ascending
    double le = kv.first;
    long long cum = kv.second;
    long long n = cum - prev_cum;
    if (n > 0) {
      double rep;
      if (std::isinf(le))
        rep = prev_le > 0.0 ? prev_le : 1.0;
      else
        rep = prev_le <= 0.0 ? le : std::sqrt(prev_le * le);
      out.insert(out.end(), static_cast<size_t>(n), rep);
    }
    prev_cum = cum;
    if (!std::isinf(le)) prev_le = le;
  }
}

// Synthetic `capture` axis: the run's identity for population splits when the
// committed labels collide -- an uncommitted A/B where version, commit and
// scheduler are all identical and `--by commit` folds both runs into one cell.
// Each .prom is one run, so we key it by the YYYYMMDD-HHMMSS stamp in its
// filename (the last such stamp; bench .prom names end in it), falling back to
// the basename so every file still maps to a distinct group.
std::string capture_key_from_path(const std::string& path) {
  size_t slash = path.find_last_of('/');
  std::string base = (slash == std::string::npos) ? path : path.substr(slash + 1);
  if (base.size() >= 5 && base.compare(base.size() - 5, 5, ".prom") == 0)
    base.resize(base.size() - 5);
  std::string found;
  for (size_t i = 0; i + 15 <= base.size(); ++i) {
    bool ok = base[i + 8] == '-';
    for (size_t k = 0; ok && k < 15; ++k)
      if (k != 8 && !std::isdigit(static_cast<unsigned char>(base[i + k]))) ok = false;
    if (ok) found = base.substr(i, 15);  // keep the last match
  }
  return found.empty() ? base : found;
}

// Parse one file: inject `version` into every sample's labels; route gauges to
// the run vectors and histogram parts to the per-cell pools.
void parse_file(const std::string& path, const PopOptions& opt,
                std::map<std::string, Family>& data, ParseStats& ps,
                DiagLabelValues& diag) {
  FILE* f = std::fopen(path.c_str(), "r");
  if (!f) {
    util::log_error("cannot open %s", path.c_str());
    return;
  }
  std::set<std::string> hist_families;
  std::string version = "unknown";
  std::string commit = "unknown";
  const std::string capture = capture_key_from_path(path);
  // Explicit A/B group for this file (--group NAME=path), injected as `group`.
  std::string group;
  {
    auto git = opt.file_group.find(path);
    if (git != opt.file_group.end()) group = git->second;
  }
  // TYPE lines precede their series in the bench .prom, so a single pass works.
  // family -> cellkey -> axis value -> cumulative-bucket histogram.
  std::map<std::string, std::map<std::string, std::map<std::string, Hist>>> file_hist;
  std::map<std::string, LabelVec> file_hist_disp;  // cellkey -> display

  // `capture` is always dropped from the cell identity: it is a per-run key that
  // exists only to BE a compare axis. Left in the key it would fragment every
  // cell by run even under --by commit/version/scheduler. When compare_axis ==
  // "capture" it is the axis (label_get still finds it) and splits the cell.
  std::set<std::string> drop_for_cell = {opt.compare_axis, "le", "capture"};
  // version and commit are one identity axis at two granularities, injected
  // per file rather than emitted per series. Comparing by either must drop the
  // other from the cell key: in a real archive they move 1:1, so a retained
  // commit fragments every --by version cell (and vice versa) and versions
  // that never shared a commit label silently never get compared at all.
  if (opt.compare_axis == "version") drop_for_cell.insert("commit");
  if (opt.compare_axis == "commit") drop_for_cell.insert("version");
  // Histogram processing drops `le` (all buckets of one series form one
  // cell). Plain gauges must NOT: a `_bucket` series whose TYPE line is
  // missing in this file falls through to the gauge path, and dropping `le`
  // there collapses every bucket of the series into one cell as fake runs.
  // An `le` label is histogram evidence on its own; keeping it in the gauge
  // identity turns that misparse into inert per-bucket singleton cells.
  std::set<std::string> drop_for_gauge = drop_for_cell;
  drop_for_gauge.erase("le");
  // Operator-supplied identity reduction (--drop-label), the generic answer
  // to high-cardinality foreign labels and co-moving pairs beyond the
  // built-in version/commit rule. Applies to both identity sets.
  for (const auto& l : opt.drop_labels) {
    drop_for_cell.insert(l);
    drop_for_gauge.insert(l);
  }

  char* line = nullptr;
  size_t cap = 0;
  ssize_t len;
  while ((len = ::getline(&line, &cap, f)) != -1) {
    std::string s = strip(std::string(line, len > 0 ? len : 0));
    if (s.empty()) continue;
    if (s[0] == '#') {
      // "# TYPE <name> histogram"
      if (s.rfind("# TYPE", 0) == 0) {
        std::vector<std::string> tok;
        size_t i = 0;
        while (i < s.size()) {
          while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
          size_t j = i;
          while (j < s.size() && !std::isspace(static_cast<unsigned char>(s[j]))) ++j;
          if (j > i) tok.push_back(s.substr(i, j - i));
          i = j;
        }
        if (tok.size() >= 4 && tok[3] == "histogram")
          hist_families.insert(alias_family(tok[2], opt));
      }
      continue;
    }
    // name[{labels}] value [timestamp]. The value is the FIRST token after
    // the name or label set; a trailing Prometheus timestamp is tolerated
    // and ignored on both paths (the braceless path used to take the LAST
    // whitespace field, so `up 1 1720000000000` parsed as value 1.72e12).
    // strtod stops at the space, so first-token semantics fall out of the
    // parse itself once the split points are right.
    size_t brace = s.find('{');
    std::string name, labelstr, valstr;
    if (brace != std::string::npos) {
      name = s.substr(0, brace);
      // Quote-aware close scan: a '}' inside a quoted label value is legal
      // Prometheus text and must not terminate the label set.
      size_t close = std::string::npos;
      bool in_quote = false;
      for (size_t j = brace + 1; j < s.size(); ++j) {
        char c = s[j];
        if (in_quote) {
          if (c == '\\') {
            ++j;
            continue;
          }
          if (c == '"') in_quote = false;
        } else if (c == '"') {
          in_quote = true;
        } else if (c == '}') {
          close = j;
          break;
        }
      }
      if (close == std::string::npos) continue;
      labelstr = s.substr(brace + 1, close - brace - 1);
      valstr = strip(s.substr(close + 1));
    } else {
      size_t sp = s.find_first_of(" \t");
      if (sp == std::string::npos) continue;
      name = strip(s.substr(0, sp));
      valstr = strip(s.substr(sp + 1));
    }
    char* end = nullptr;
    double val = std::strtod(valstr.c_str(), &end);
    if (end == valstr.c_str() || !std::isfinite(val)) continue;

    LabelVec labels = parse_labels(labelstr);

    // version/commit: any *_info family carrying the label.
    if (name.size() > 5 && name.compare(name.size() - 5, 5, "_info") == 0) {
      std::string v = label_get(labels, "version");
      if (!v.empty()) version = v;
      std::string c = label_get(labels, "git_commit");
      if (!c.empty()) commit = c;
      continue;
    }

    // Fragmenting-label diagnostic: record each raw label's value per file. A
    // label constant within a file but distinct across files is a per-run key
    // that fragments every cell to N=1; the post-parse scan names it and the
    // exact --drop-label that unfragments the run.
    for (const auto& kv : labels) {
      if (kv.first == opt.compare_axis || kv.first == "le" ||
          kv.first == "capture")
        continue;
      bool dropped = false;
      for (const auto& d : opt.drop_labels)
        if (d == kv.first) { dropped = true; break; }
      if (!dropped) diag[kv.first][path].insert(kv.second);
    }

    // Histogram component? The base is aliased before the lookup, so a
    // renamed histogram family's buckets land under the new name alongside
    // the TYPE line's own aliased insert.
    auto is_hist_part = [&](const std::string& suffix) {
      if (name.size() <= suffix.size()) return std::string();
      if (name.compare(name.size() - suffix.size(), suffix.size(), suffix) != 0)
        return std::string();
      std::string base =
          alias_family(name.substr(0, name.size() - suffix.size()), opt);
      return hist_families.count(base) ? base : std::string();
    };
    std::string hb = is_hist_part("_bucket");
    bool is_sum = !is_hist_part("_sum").empty();
    bool is_count = !is_hist_part("_count").empty();
    if (!hb.empty()) {
      labels.emplace_back("version", version);
      labels.emplace_back("commit", commit);
      labels.emplace_back("capture", capture);
      if (!group.empty()) labels.emplace_back("group", group);
      ++ps.samples;
      std::string axv = label_get(labels, opt.compare_axis);
      if (axv.empty()) {
        ++ps.no_axis;
        continue;
      }
      std::string ck = cell_key(labels, drop_for_cell);  // drops le + axis
      file_hist[hb][ck][axv].buckets[le_value(label_get(labels, "le"))] =
          static_cast<long long>(val);
      if (!file_hist_disp.count(ck))
        file_hist_disp[ck] = cell_display(labels, drop_for_cell);
      continue;
    }
    if (is_sum || is_count) continue;  // histogram scalars: ignore

    // Plain gauge: one per-run scalar for (family, full labels).
    labels.emplace_back("version", version);
    labels.emplace_back("commit", commit);
    labels.emplace_back("capture", capture);
    if (!group.empty()) labels.emplace_back("group", group);
    ++ps.samples;
    std::string axis = label_get(labels, opt.compare_axis);
    if (axis.empty()) {
      ++ps.no_axis;
      continue;  // cannot place without the compare axis
    }
    std::string ck = cell_key(labels, drop_for_gauge);
    Family& fam = data[alias_family(name, opt)];
    Cell& cell = fam.cells[ck];
    if (cell.display.empty()) cell.display = cell_display(labels, drop_for_gauge);
    cell.runs[axis].push_back(val);
  }
  std::free(line);
  std::fclose(f);
  if (version != "unknown") ++ps.files_with_version;

  // Fold this file's reconstructed histograms into the population pools,
  // pooled per (cell, axis value) across the run's buckets.
  for (auto& fam_kv : file_hist) {
    Family& fam = data[fam_kv.first];
    for (auto& cell_kv : fam_kv.second) {
      Cell& cell = fam.cells[cell_kv.first];
      if (cell.display.empty() && file_hist_disp.count(cell_kv.first))
        cell.display = file_hist_disp[cell_kv.first];
      for (auto& ax_kv : cell_kv.second) {
        std::vector<double> samples;
        reconstruct(ax_kv.second, samples);
        auto& dst = cell.samp[ax_kv.first];
        dst.insert(dst.end(), samples.begin(), samples.end());
      }
    }
  }
}

// report + prom

// Axis-value display: operator-supplied --alias-axis mapping first, else the
// lowercased value verbatim. The previous hardcoded scheduler-name
// compression table was project-specific text inside a general instrument
// and is retired in favor of the generic mechanism.
std::string display_axis(const std::string& v, const PopOptions& opt) {
  auto it = opt.axis_alias.find(v);
  if (it != opt.axis_alias.end()) return it->second;
  std::string n;
  for (char c : v) n += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return n;
}

std::string cell_label_str(const LabelVec& d) {
  std::string s;
  for (const auto& kv : d) {
    if (!s.empty()) s += " ";
    s += kv.first + "=" + kv.second;
  }
  return s.empty() ? "(no labels)" : s;
}

struct PromLine {
  std::string name, labels;
  double value;
};

// Real HELP text per emitted family, replacing the former placeholder. Each
// line states the aggregation, the scope and the range or unit, so neither a
// human nor an agent has to guess what a value means. tests/semantic_check.py
// fails any emitted family that falls through to the placeholder.
const char* pop_help(const std::string& name) {
  if (name == "montauk_pop_info")
    return "Analysis metadata: montauk version, compare axis, file count";
  if (name == "montauk_pop_cliff")
    return "Cliff's delta effect size for the labeled pair, P(a>b)-P(a<b) "
           "over per-run value pairs, dimensionless in [-1, 1]";
  if (name == "montauk_pop_perm_p")
    return "Permutation p-value for the labeled pair's mean difference, in "
           "(0, 1]; Monte Carlo floor is 1/(n_perm+1)";
  if (name == "montauk_pop_power_n")
    return "Smallest per-group run count reaching 80% Welch power for the "
           "labeled pair, RIGHT-CENSORED at the sweep cap; when the paired "
           "montauk_pop_power_censored is 1 the true value exceeds this bound";
  if (name == "montauk_pop_power_censored")
    return "1 when the paired montauk_pop_power_n hit its sweep cap (true "
           "requirement exceeds the reported bound), else 0";
  if (name == "montauk_pop_mcb_is_best")
    return "Hsu MCB verdict for the labeled group: 1 best, 0 tied-for-best, "
           "-1 not best (direction per lower/higher-is-better)";
  if (name == "montauk_pop_mean")
    return "Mean of the labeled group's per-run values, in the labeled "
           "metric's own unit";
  if (name == "montauk_pop_n")
    return "Run count (files contributing a value) in the labeled group";
  if (name == "montauk_pop_gameshowell_p")
    return "Games-Howell pairwise p-value on within-run distributions "
           "(--full path), in (0, 1]";
  if (name == "montauk_pop_traj_p_dense")
    return "Trajectory joint permutation p for the labeled boundary, dense "
           "aggregate (sum of squared per-cell rank statistics; many cells "
           "moving a little)";
  if (name == "montauk_pop_traj_p_sparse")
    return "Trajectory joint permutation p for the labeled boundary, sparse "
           "aggregate (max absolute per-cell rank statistic; few cells "
           "moving a lot)";
  if (name == "montauk_pop_traj_cells_moved")
    return "Cells whose standardized rank statistic exceeds 1.96 at the "
           "labeled boundary (normal-approximation flag), count";
  if (name == "montauk_pop_traj_cells_total")
    return "Cells of the labeled family carrying runs on both sides of the "
           "boundary, count";
  if (name == "montauk_pop_traj_effect")
    return "Median absolute per-cell Cliff's delta across the labeled "
           "boundary, dimensionless in [0, 1]";
  if (name == "montauk_pop_traj_class")
    return "Structure classification of a single-cell family's run sequence "
           "in axis order (value 1; the class label names the shape)";
  return "population analysis";
}

void emit_prom(const std::vector<PromLine>& lines, const PopOptions& opt) {
  ensure_pop_out();
  const char* xdg = std::getenv("XDG_CACHE_HOME");
  std::string dir = (xdg && *xdg)
                        ? std::string(xdg)
                        : std::string(std::getenv("HOME") ? std::getenv("HOME") : ".") + "/.cache";
  ::mkdir(dir.c_str(), 0755);
  dir += "/montauk";
  ::mkdir(dir.c_str(), 0755);
  std::string tag = opt.metric_filter.empty() ? "all" : opt.metric_filter;
  for (char& c : tag)
    if (!std::isalnum(static_cast<unsigned char>(c))) c = '_';
  std::string path = dir + "/analysis-pop-" + opt.compare_axis + "-" + tag + ".prom";
  FILE* f = std::fopen(path.c_str(), "w");
  if (!f) {
    util::log_error("cannot write %s", path.c_str());
    return;
  }
  std::set<std::string> emitted;
  for (const PromLine& m : lines) {
    if (emitted.insert(m.name).second)
      std::fprintf(f, "# HELP %s %s\n# TYPE %s gauge\n",
                   m.name.c_str(), pop_help(m.name), m.name.c_str());
    char num[32];
    if (m.value == std::floor(m.value) && std::fabs(m.value) < 1e15)
      std::snprintf(num, sizeof(num), "%.0f", m.value);
    else
      std::snprintf(num, sizeof(num), "%.6g", m.value);
    if (m.labels.empty())
      std::fprintf(f, "%s %s\n", m.name.c_str(), num);
    else
      std::fprintf(f, "%s{%s} %s\n", m.name.c_str(), m.labels.c_str(), num);
  }
  std::fclose(f);
  util::log_info("population analysis written to %s", path.c_str());
}

// The trajectory engine (--trajectory): version-ordered change-point scan
// over the archive, per metric family. Inference is a run-aware rank scan:
// midrank every run in the window, at each version boundary form the
// standardized Mann-Whitney statistic of runs-before vs runs-after
// (segments, never adjacent pairs, so N=1 per version still tests), take
// the max over boundaries and calibrate it by permuting whole version
// blocks with the max recomputed each time, so the selection lives inside
// the null (Pettitt's construction, finite-sample valid at any n). Cells of
// one family are scanned JOINTLY: a single permutation applied to every
// cell preserves cross-cell dependence exactly in the null. Two aggregates
// share the alpha budget: dense (sum of squared per-cell statistics, many
// cells moving a little) and sparse (max absolute, few cells moving a lot).
// Deterministic under --seed; below 8 versions the permutation space is
// enumerated fully and the p-value is exact and seed-free. Multiple jumps
// via binary-segmentation recursion, gated by the joint p AND an
// operator-supplied Cliff's-delta magnitude floor.

double rank_T(double R, uint32_t m, uint32_t n, double tie3) {
  if (m == 0 || m >= n || n < 2) return 0.0;
  double mu = static_cast<double>(m) * (n + 1) / 2.0;
  double var = static_cast<double>(m) * (n - m) * (n + 1) / 12.0 -
               static_cast<double>(m) * (n - m) * tie3 /
                   (12.0 * static_cast<double>(n) * (n - 1.0));
  if (var <= 0.0) return 0.0;
  return (R - mu) / std::sqrt(var);
}

struct TrajPrep {
  std::vector<std::vector<uint32_t>> cnt;    // [cell][rel version] run count
  std::vector<std::vector<double>> ranksum;  // [cell][rel version] midrank sum
  std::vector<double> tie3;                  // [cell] sum(t^3 - t) over ties
  std::vector<uint32_t> total;               // [cell] runs in window
};

// Midrank preparation for one cell over vers[lo..hi).
void traj_prep_cell(const Cell& cell, const std::vector<std::string>& vers,
                    size_t lo, size_t hi, std::vector<uint32_t>& cnt,
                    std::vector<double>& ranksum, double& tie3,
                    uint32_t& total) {
  size_t W = hi - lo;
  cnt.assign(W, 0);
  ranksum.assign(W, 0.0);
  tie3 = 0.0;
  total = 0;
  std::vector<std::pair<double, uint32_t>> vals;
  for (size_t v = lo; v < hi; ++v) {
    auto it = cell.runs.find(vers[v]);
    if (it == cell.runs.end()) continue;
    for (double x : it->second)
      vals.push_back({x, static_cast<uint32_t>(v - lo)});
  }
  total = static_cast<uint32_t>(vals.size());
  if (total == 0) return;
  sublimation_order_f64(vals, false,
                        [](const std::pair<double, uint32_t>& p) { return p.first; });
  size_t i = 0;
  while (i < vals.size()) {
    size_t j = i;
    while (j < vals.size() && vals[j].first == vals[i].first) ++j;
    double mid = (static_cast<double>(i + 1) + static_cast<double>(j)) / 2.0;
    double t = static_cast<double>(j - i);
    if (t > 1.0) tie3 += t * t * t - t;
    for (size_t k = i; k < j; ++k) {
      cnt[vals[k].second] += 1;
      ranksum[vals[k].second] += mid;
    }
    i = j;
  }
}

// One scan under version-order permutation p (relative indices): fills the
// per-boundary dense and sparse aggregates. Boundary k means "the first k
// versions of the permuted order vs the rest," k in 1..W-1.
void traj_scan(const TrajPrep& tp, const std::vector<uint32_t>& p,
               std::vector<double>& dense, std::vector<double>& sparse) {
  const size_t J = tp.cnt.size();
  const size_t W = p.size();
  dense.assign(W, 0.0);
  sparse.assign(W, 0.0);
  for (size_t j = 0; j < J; ++j) {
    if (tp.total[j] < 2) continue;
    double R = 0.0;
    uint32_t m = 0;
    for (size_t k = 1; k < W; ++k) {
      R += tp.ranksum[j][p[k - 1]];
      m += tp.cnt[j][p[k - 1]];
      double T = rank_T(R, m, tp.total[j], tp.tie3[j]);
      dense[k] += T * T;
      double a = std::fabs(T);
      if (a > sparse[k]) sparse[k] = a;
    }
  }
}

const char* traj_class_name(sub_disorder_t d) {
  switch (d) {
    case SUB_SORTED: return "sorted";
    case SUB_REVERSED: return "reversed";
    case SUB_NEARLY_SORTED: return "nearly-sorted";
    case SUB_FEW_UNIQUE: return "few-unique";
    case SUB_PHASED: return "phased";
    case SUB_SPECTRAL: return "spectral";
    case SUB_RANDOM: default: return "random";
  }
}

int run_trajectory(std::map<std::string, Family>& data, size_t files_n,
                   const PopOptions& opt) {
  std::vector<PromLine> prom;
  util::log_info(
      "trajectory: %zu file(s), axis '%s', alpha %.3g, min effect %.3g",
      files_n, opt.compare_axis.c_str(), opt.traj_alpha, opt.traj_min_effect);
  for (auto& fam_kv : data) {
    const std::string& metric = fam_kv.first;
    if (!opt.metric_filter.empty() &&
        metric.find(opt.metric_filter) == std::string::npos)
      continue;
    Family& fam = fam_kv.second;
    std::set<std::string> vset;
    for (auto& c : fam.cells)
      for (auto& r : c.second.runs)
        if (!r.second.empty()) vset.insert(r.first);
    std::vector<std::string> vers(vset.begin(), vset.end());
    if (opt.compare_axis == "version") natural_version_sort(vers);
    if (vers.size() < 2) continue;
    std::vector<std::pair<const std::string*, const Cell*>> cells;
    for (auto& c : fam.cells) cells.push_back({&c.first, &c.second});
    montauk_sink_appendf(&g_pop_out, "\nTRAJECTORY %s (%zu %s values, %zu cells)\n",
                         metric.c_str(), vers.size(), opt.compare_axis.c_str(),
                         cells.size());

    // Descriptive shape layer for single-cell families: the classifier names
    // the run sequence's structure in axis order; inference stays with the
    // rank scan below.
    if (cells.size() == 1) {
      std::vector<double> seq;
      for (const auto& v : vers) {
        auto it = cells[0].second->runs.find(v);
        if (it == cells[0].second->runs.end()) continue;
        seq.insert(seq.end(), it->second.begin(), it->second.end());
      }
      if (seq.size() >= 4) {
        sub_profile_t prof = sublimation_classify_f64(seq.data(), seq.size());
        montauk_sink_appendf(&g_pop_out, "  shape: %s\n",
                             traj_class_name(prof.disorder));
        prom.push_back({"montauk_pop_traj_class",
                        "metric=\"" + metric + "\",class=\"" +
                            traj_class_name(prof.disorder) + "\"",
                        1.0});
      }
    }

    size_t findings = 0;
    std::vector<std::pair<size_t, size_t>> stack;
    stack.push_back({0, vers.size()});
    while (!stack.empty()) {
      size_t lo = stack.back().first, hi = stack.back().second;
      stack.pop_back();
      size_t W = hi - lo;
      if (W < 2) continue;

      TrajPrep tp;
      tp.cnt.resize(cells.size());
      tp.ranksum.resize(cells.size());
      tp.tie3.resize(cells.size());
      tp.total.resize(cells.size());
      for (size_t j = 0; j < cells.size(); ++j)
        traj_prep_cell(*cells[j].second, vers, lo, hi, tp.cnt[j],
                       tp.ranksum[j], tp.tie3[j], tp.total[j]);

      std::vector<uint32_t> ident(W);
      for (size_t k = 0; k < W; ++k) ident[k] = static_cast<uint32_t>(k);
      std::vector<double> dob, sob;
      traj_scan(tp, ident, dob, sob);
      double Md = 0.0, Ms = 0.0;
      size_t Kd = 0, Ks = 0;
      for (size_t k = 1; k < W; ++k) {
        if (dob[k] > Md) { Md = dob[k]; Kd = k; }
        if (sob[k] > Ms) { Ms = sob[k]; Ks = k; }
      }
      if (Kd == 0 && Ks == 0) continue;  // no cell spans any boundary

      size_t cnt_d = 0, cnt_s = 0, ntot = 0;
      double sum_md = 0.0, sum_md2 = 0.0, sum_ms = 0.0, sum_ms2 = 0.0;
      std::vector<double> dtmp, stmp;
      auto tally = [&](const std::vector<uint32_t>& p) {
        traj_scan(tp, p, dtmp, stmp);
        double md = 0.0, ms = 0.0;
        for (size_t k = 1; k < W; ++k) {
          if (dtmp[k] > md) md = dtmp[k];
          if (stmp[k] > ms) ms = stmp[k];
        }
        if (md >= Md - 1e-12) ++cnt_d;
        if (ms >= Ms - 1e-12) ++cnt_s;
        sum_md += md;
        sum_md2 += md * md;
        sum_ms += ms;
        sum_ms2 += ms * ms;
        ++ntot;
      };
      double pd = 1.0, psp = 1.0;
      if (W <= 7) {
        // Full enumeration of version orders: exact p, seed-free, and the
        // identity order is one of the enumerated arrangements.
        std::vector<uint32_t> p = ident;
        do {
          tally(p);
        } while (std::next_permutation(p.begin(), p.end()));
        pd = static_cast<double>(cnt_d) / static_cast<double>(ntot);
        psp = static_cast<double>(cnt_s) / static_cast<double>(ntot);
      } else {
        stats::Rng rng(fnv1a(
            fnv1a(opt.seed ^ 1469598103934665603ull, metric) ^
                (0x9e3779b97f4a7c15ull + lo * 131 + hi),
            std::string("trajectory")));
        int B = opt.traj_perms > 0 ? opt.traj_perms : 999;
        std::vector<uint32_t> p = ident;
        for (int b = 0; b < B; ++b) {
          for (size_t k = W; k > 1; --k)
            std::swap(p[k - 1], p[rng.below(k)]);
          tally(p);
        }
        pd = static_cast<double>(cnt_d + 1) / (B + 1.0);
        psp = static_cast<double>(cnt_s + 1) / (B + 1.0);
      }
      if (std::min(pd, psp) * 2.0 > opt.traj_alpha) continue;

      const bool use_dense = pd <= psp;
      const size_t K = use_dense ? Kd : Ks;
      const std::vector<double>& S = use_dense ? dob : sob;
      const double M = use_dense ? Md : Ms;
      double mean_max = (use_dense ? sum_md : sum_ms) / ntot;
      double var_max =
          (use_dense ? sum_md2 : sum_ms2) / ntot - mean_max * mean_max;
      double sd = var_max > 0.0 ? std::sqrt(var_max) : 0.0;
      size_t rlo = K, rhi = K;
      for (size_t k = 1; k < W; ++k)
        if (S[k] >= M - sd) {
          if (k < rlo) rlo = k;
          if (k > rhi) rhi = k;
        }

      // Effect and attribution at K: per-cell Cliff's delta on the two
      // segments plus the normal-approximation moved flag on |T|.
      struct CellHit {
        size_t j;
        double delta;
        double absT;
      };
      std::vector<CellHit> hits;
      std::vector<double> abs_deltas;
      size_t eligible = 0, moved = 0;
      for (size_t j = 0; j < cells.size(); ++j) {
        if (tp.total[j] < 2) continue;
        double R = 0.0;
        uint32_t m = 0;
        for (size_t k = 0; k < K; ++k) {
          R += tp.ranksum[j][k];
          m += tp.cnt[j][k];
        }
        if (m == 0 || m >= tp.total[j]) continue;
        ++eligible;
        double T = rank_T(R, m, tp.total[j], tp.tie3[j]);
        std::vector<double> before, after;
        for (size_t v = lo; v < hi; ++v) {
          auto it = cells[j].second->runs.find(vers[v]);
          if (it == cells[j].second->runs.end()) continue;
          auto& dst = (v < lo + K) ? before : after;
          dst.insert(dst.end(), it->second.begin(), it->second.end());
        }
        double cd = stats::cliffs_delta(before, after);
        abs_deltas.push_back(std::fabs(cd));
        if (std::fabs(T) >= 1.96) ++moved;
        hits.push_back({j, cd, std::fabs(T)});
      }
      if (abs_deltas.empty()) continue;
      double fam_eff = stats::percentile(abs_deltas, 50.0);
      if (fam_eff < opt.traj_min_effect) continue;

      const std::string& va = vers[lo + K - 1];
      const std::string& vb = vers[lo + K];
      std::string at = display_axis(va, opt) + "__" + display_axis(vb, opt);
      if (rlo != rhi)
        montauk_sink_appendf(
            &g_pop_out,
            "  jump %s -> %s [range %s..%s]: p_dense=%.4g p_sparse=%.4g, "
            "cells moved %zu/%zu, median |delta| %.2f\n",
            display_axis(va, opt).c_str(), display_axis(vb, opt).c_str(),
            display_axis(vers[lo + rlo - 1], opt).c_str(),
            display_axis(vers[lo + rhi], opt).c_str(), pd, psp, moved,
            eligible, fam_eff);
      else
        montauk_sink_appendf(
            &g_pop_out,
            "  jump %s -> %s: p_dense=%.4g p_sparse=%.4g, cells moved "
            "%zu/%zu, median |delta| %.2f\n",
            display_axis(va, opt).c_str(), display_axis(vb, opt).c_str(), pd,
            psp, moved, eligible, fam_eff);
      sublimation_order_f64(hits, true, [](const CellHit& h) { return h.absT; });
      for (size_t t = 0; t < hits.size() && t < 3; ++t)
        montauk_sink_appendf(
            &g_pop_out, "    top: [%s] delta %+.2f\n",
            cell_label_str(cells[hits[t].j].second->display).c_str(),
            hits[t].delta);
      std::string lab = "metric=\"" + metric + "\",at=\"" + at + "\"";
      prom.push_back({"montauk_pop_traj_p_dense", lab, pd});
      prom.push_back({"montauk_pop_traj_p_sparse", lab, psp});
      prom.push_back({"montauk_pop_traj_cells_moved", lab,
                      static_cast<double>(moved)});
      prom.push_back({"montauk_pop_traj_cells_total", lab,
                      static_cast<double>(eligible)});
      prom.push_back({"montauk_pop_traj_effect", lab, fam_eff});
      ++findings;
      stack.push_back({lo, lo + K});
      stack.push_back({lo + K, hi});
    }
    if (findings == 0)
      montauk_sink_appendf(&g_pop_out, "  no change point at alpha %.3g\n",
                           opt.traj_alpha);
  }
  if (opt.emit_prom && !prom.empty()) {
    std::vector<PromLine> header;
    std::string info = std::string("montauk_version=\"") + MONTAUK_VERSION +
                       "\",compare_axis=\"" + opt.compare_axis +
                       "\",files=\"" + std::to_string(files_n) + "\"";
    header.push_back({"montauk_pop_info", info, 1.0});
    prom.insert(prom.begin(), header.begin(), header.end());
    emit_prom(prom, opt);
  }
  montauk_sink_drain(&g_pop_out);
  return 0;
}

}  // namespace

int run_population(const std::vector<std::string>& files, const PopOptions& opt) {
  // Initialize the report sink FIRST. Every append below lands in g_pop_out;
  // without this call the zero-initialized sink accumulated via realloc(NULL)
  // and emit_prom's own ensure_pop_out() then RESET the buffer, destroying
  // the entire report before the atexit drain was even registered. That is
  // why the population text report never reached stdout.
  ensure_pop_out();
  if (files.empty()) {
    util::log_error("no .prom files to analyze");
    return 1;
  }
  std::map<std::string, Family> data;
  ParseStats ps;
  DiagLabelValues diag;
  for (const auto& f : files) parse_file(f, opt, data, ps, diag);
  if (ps.no_axis > 0)
    util::log_info("series skipped: %zu (no label '%s')", ps.no_axis,
                   opt.compare_axis.c_str());
  if (data.empty()) {
    if (ps.no_axis > 0 && ps.samples == ps.no_axis)
      util::log_error("no series carried label '%s' in %zu file(s)",
                      opt.compare_axis.c_str(), files.size());
    else
      util::log_error("no usable gauges in %zu file(s)", files.size());
    return 1;
  }
  if (opt.compare_axis == "version" && ps.files_with_version == 0)
    util::log_warn("no file carried a version (montauk *_info label); every "
                   "sample lands in one 'unknown' group");

  // Associate each histogram family with the summary-gauge families it backs
  // (PANDEMONIUM bench: histogram `<wl>` + gauge `<wl>_p99_us` are separate
  // metric names for the same workload), so a gauge family's run-level cell
  // also carries the within-run distribution for Path A. Match by name prefix
  // at a `_` boundary; longest histogram prefix wins.
  std::vector<std::string> hist_fams;
  for (auto& kv : data)
    for (auto& c : kv.second.cells)
      if (!c.second.samp.empty()) { hist_fams.push_back(kv.first); break; }
  for (auto& g : data) {
    const std::string* best = nullptr;
    for (const auto& h : hist_fams) {
      if (g.first.size() > h.size() + 1 && g.first.compare(0, h.size(), h) == 0 &&
          g.first[h.size()] == '_' && (!best || h.size() > best->size()))
        best = &h;
    }
    if (!best) continue;
    Family& H = data[*best];
    for (auto& c : g.second.cells) {
      auto it = H.cells.find(c.first);
      if (it == H.cells.end()) continue;
      for (auto& s : it->second.samp) {
        auto& dst = c.second.samp[s.first];
        dst.insert(dst.end(), s.second.begin(), s.second.end());
      }
    }
  }

  // Trajectory mode replaces the pairwise engine outright: same parse and
  // histogram association, different inference.
  if (opt.trajectory) return run_trajectory(data, files.size(), opt);

  std::vector<PromLine> prom;
  const char* better = opt.lower_is_better ? "lower=better" : "higher=better";

  util::log_info("population: %zu file(s), compare by '%s', %s",
                 files.size(), opt.compare_axis.c_str(), better);

  // Underpowered guard: the inferential unit is one run. If no cell has more
  // than one run per axis value, every comparison is single-shot -- say so
  // loudly once, before the numbers tempt a verdict they cannot support.
  int max_group_n = 0;
  for (auto& fam_kv : data)
    for (auto& cell_kv : fam_kv.second.cells)
      for (auto& g : cell_kv.second.runs)
        max_group_n = std::max(max_group_n, static_cast<int>(g.second.size()));
  if (max_group_n <= 1) {
    util::log_warn("N=1 per group -- inference underpowered; collect >=3 runs "
                   "per '%s' value for a verdict", opt.compare_axis.c_str());
    // Name the fragmenting culprits: a label whose value is unique per file
    // (constant within, distinct across) is what split every cell to N=1.
    for (const auto& [name, per_file] : diag) {
      const size_t nfiles = per_file.size();
      if (nfiles < 2) continue;
      bool constant_within = true;
      std::set<std::string> distinct;
      for (const auto& [file, vals] : per_file) {
        (void)file;
        if (vals.size() != 1) { constant_within = false; break; }
        distinct.insert(*vals.begin());
      }
      if (constant_within && distinct.size() == nfiles)
        util::log_warn("label '%s' is unique per file (%zu files, %zu distinct "
                       "values) -- it fragments every cell; re-run with "
                       "--drop-label %s", name.c_str(), nfiles,
                       distinct.size(), name.c_str());
    }
  }

  // Every (family, cell) is statistically independent of every other, so the
  // resampling work fans out across a thread pool. Each item derives its Rng
  // seed from (--seed, metric, cell key), never from a shared stream, so a
  // given seed reproduces the same numbers at any thread count and schedule.
  // Text and prom lines are built privately per item and emitted serially in
  // the original map order below, keeping output ordering byte-stable.
  struct WorkItem {
    const std::string* metric;
    const std::string* ckey;
    Cell* cell;
    std::string text;
    std::vector<PromLine> out;
  };
  std::vector<WorkItem> work;
  for (auto& fam_kv : data) {
    if (!opt.metric_filter.empty() &&
        fam_kv.first.find(opt.metric_filter) == std::string::npos)
      continue;
    for (auto& cell_kv : fam_kv.second.cells)
      work.push_back({&fam_kv.first, &cell_kv.first, &cell_kv.second, {}, {}});
  }

  auto process_cell = [&](WorkItem& w) {
    const std::string& metric = *w.metric;
    Cell& cell = *w.cell;
    stats::Rng rng(fnv1a(fnv1a(opt.seed ^ 1469598103934665603ull, metric) ^
                             0x9e3779b97f4a7c15ull,
                         *w.ckey));
    std::vector<std::string> groups;
    for (auto& g : cell.runs)
      if (!g.second.empty()) groups.push_back(g.first);
    // Ordered axes get natural-version order (stable, so full ties keep the
    // deterministic map order); categorical axes keep map order as before.
    const bool ordered_axis =
        opt.compare_axis == "version" || opt.compare_axis == "capture";
    if (opt.compare_axis == "version") natural_version_sort(groups);
    sappendf(w.text, "  [%s]\n", cell_label_str(cell.display).c_str());
    if (groups.size() < 2) {
      sappendf(w.text, "    only %s -- no comparison\n",
               groups.empty() ? "(none)" : display_axis(groups[0], opt).c_str());
      return;
    }
    std::string clabel = cell_label_str(cell.display);

    // Bootstrap Hsu-MCB across ALL groups, regardless of the pair selector
    // (best-overall must survive pair pruning), and first, so vs-best can key
    // its pairs off the winner.
    std::vector<std::vector<double>> g;
    std::vector<std::string> gn;
    for (const auto& s : groups) {
      g.push_back(cell.runs[s]);
      gn.push_back(display_axis(s, opt));
    }
    auto mcb = stats::bootstrap_mcb(g, opt.lower_is_better, rng);

    // Pair selection: operator choice, else adjacent on ordered axes (linear
    // in axis values, the archive default) and all-pairs on categorical ones.
    std::string mode = !opt.pairs.empty() ? opt.pairs
                       : (ordered_axis ? "adjacent" : "all");
    std::vector<std::pair<size_t, size_t>> prs;
    if (mode == "adjacent") {
      for (size_t k = 0; k + 1 < groups.size(); ++k) prs.push_back({k, k + 1});
    } else if (mode == "vs-best") {
      size_t best = 0;
      bool found = false;
      for (size_t k = 0; k < groups.size() && !found; ++k)
        if (mcb[k].verdict == 1) { best = k; found = true; }
      for (size_t k = 0; k < groups.size() && !found; ++k)
        if (mcb[k].verdict == 0) { best = k; found = true; }
      for (size_t k = 0; k < groups.size(); ++k)
        if (k != best) prs.push_back({best, k});
    } else {
      for (size_t i = 0; i < groups.size(); ++i)
        for (size_t j = i + 1; j < groups.size(); ++j) prs.push_back({i, j});
    }

    // Pairwise run-level inference over the selected pairs.
    for (const auto& pr : prs) {
      const size_t i = pr.first, j = pr.second;
      auto& va = cell.runs[groups[i]];
      auto& vb = cell.runs[groups[j]];
      double ma = stats::mean(va), mb = stats::mean(vb);
      double mnA = *std::min_element(va.begin(), va.end());
      double mxA = *std::max_element(va.begin(), va.end());
      double mnB = *std::min_element(vb.begin(), vb.end());
      double mxB = *std::max_element(vb.begin(), vb.end());
      double cd = stats::cliffs_delta(va, vb);
      double pp = stats::perm_test(va, vb, stats::Stat::Mean, 0.0, rng);
      int npow = stats::mc_power(va, vb, rng);
      const std::string& sa = gn[i];
      const std::string& sb = gn[j];
      sappendf(w.text,
          "    %s vs %s [N=%zu/%zu]: mean %.6g (%.4g..%.4g) vs %.6g (%.4g..%.4g) | "
          "cliff %+.2f (%s) | perm p=%.3f | power %s\n",
          sa.c_str(), sb.c_str(), va.size(), vb.size(), ma, mnA, mxA, mb,
          mnB, mxB, cd, stats::cliff_magnitude(cd), pp,
          npow ? std::to_string(npow).c_str() : ">20");
      std::string lab = "metric=\"" + metric + "\",cell=\"" + clabel +
                        "\",pair=\"" + sa + "__" + sb + "\"";
      w.out.push_back({"montauk_pop_cliff", lab, cd});
      w.out.push_back({"montauk_pop_perm_p", lab, pp});
      // power_n is right-censored at the sweep cap: 0 from mc_power means
      // "did not reach the target within nmax," never "zero runs needed."
      // Encode the censoring explicitly (bound as the value, companion flag)
      // instead of a 0 that aliases a real answer.
      w.out.push_back({"montauk_pop_power_n", lab,
                       npow ? static_cast<double>(npow) : 20.0});
      w.out.push_back({"montauk_pop_power_censored", lab,
                       npow ? 0.0 : 1.0});
    }

    sappendf(w.text, "    MCB (%s):", better);
    for (size_t k = 0; k < gn.size(); ++k) {
      const char* v = mcb[k].verdict == 1 ? "best"
                      : mcb[k].verdict == -1 ? "not-best"
                                             : "tied";
      sappendf(w.text, " %s=%s", gn[k].c_str(), v);
      std::string lab = "metric=\"" + metric + "\",cell=\"" + clabel +
                        "\",group=\"" + gn[k] + "\"";
      w.out.push_back({"montauk_pop_mcb_is_best", lab,
                       static_cast<double>(mcb[k].verdict)});
      w.out.push_back({"montauk_pop_mean", lab, stats::mean(g[k])});
      w.out.push_back({"montauk_pop_n", lab,
                       static_cast<double>(g[k].size())});
    }
    sappendf(w.text, "\n");

    // Path A: Games-Howell + within-run quantile permutation on the
    // reconstructed histogram distributions, when present and --full was set.
    // Falls back to the run-level vectors when a cell carries no histograms,
    // so --full always emits a parametric p (at lower n).
    if (opt.full) {
      bool have_hist = true;
      for (const auto& s : groups)
        if (cell.samp.find(s) == cell.samp.end() || cell.samp[s].size() < 2)
          have_hist = false;
      std::vector<std::vector<double>> hs;
      std::vector<std::string> hn;
      for (const auto& s : groups) {
        hs.push_back(have_hist ? cell.samp[s] : cell.runs[s]);
        hn.push_back(display_axis(s, opt));
      }
      if (have_hist) {
        for (size_t i = 0; i < groups.size(); ++i)
          for (size_t j = i + 1; j < groups.size(); ++j) {
            double qp = stats::perm_test(hs[i], hs[j], stats::Stat::Percentile,
                                         opt.quantile, rng);
            sappendf(w.text, "      within-run q%.0f perm p=%.3f (%s vs %s)\n",
                     opt.quantile, qp, hn[i].c_str(), hn[j].c_str());
          }
      }
      auto gh = stats::games_howell(hs);
      for (const auto& pr : gh) {
        sappendf(w.text, "      games-howell %s vs %s: p=%.3f%s\n",
                 hn[pr.i].c_str(), hn[pr.j].c_str(), pr.p,
                 have_hist ? "" : " [run-level]");
        std::string lab = "metric=\"" + metric + "\",cell=\"" + clabel +
                          "\",pair=\"" + hn[pr.i] + "__" + hn[pr.j] + "\"";
        w.out.push_back({"montauk_pop_gameshowell_p", lab, pr.p});
      }
    }
  };

  std::atomic<size_t> next_item{0};
  auto pump = [&]() {
    for (;;) {
      size_t i = next_item.fetch_add(1);
      if (i >= work.size()) return;
      process_cell(work[i]);
    }
  };
  // Pool size: --threads, else MONTAUK_POP_THREADS, else all cores. Results
  // are identical at any thread count by the per-cell seeding contract; the
  // control exists so the determinism gate can PIN that invariance and so an
  // operator can bound the analyzer's own footprint.
  size_t want = opt.threads > 0 ? static_cast<size_t>(opt.threads) : 0;
  if (want == 0) {
    const char* e = std::getenv("MONTAUK_POP_THREADS");
    if (e && *e) {
      long v = std::strtol(e, nullptr, 10);
      if (v > 0) want = static_cast<size_t>(v);
    }
  }
  if (want == 0) {
    unsigned hw = std::thread::hardware_concurrency();
    want = hw ? hw : 1;
  }
  size_t nthreads = std::min<size_t>(want, work.size());
  if (nthreads > 1) {
    std::vector<std::thread> pool;
    pool.reserve(nthreads);
    for (size_t t = 0; t < nthreads; ++t) pool.emplace_back(pump);
    for (auto& t : pool) t.join();
  } else {
    pump();
  }

  // Ordered emit: family headers and cell blocks in the same map order the
  // serial loop produced, with each item's prom lines appended in place.
  const std::string* cur_metric = nullptr;
  for (auto& w : work) {
    if (!cur_metric || *cur_metric != *w.metric) {
      montauk_sink_appendf(&g_pop_out, "\nMETRIC %s\n", w.metric->c_str());
      cur_metric = w.metric;
    }
    montauk_sink_append(&g_pop_out, w.text.data(), w.text.size());
    prom.insert(prom.end(), w.out.begin(), w.out.end());
  }

  if (opt.emit_prom && !prom.empty()) {
    // House-style metadata header first.
    std::vector<PromLine> header;
    std::string info = std::string("montauk_version=\"") + MONTAUK_VERSION +
                       "\",compare_axis=\"" + opt.compare_axis + "\",files=\"" +
                       std::to_string(files.size()) + "\"";
    header.push_back({"montauk_pop_info", info, 1.0});
    prom.insert(prom.begin(), header.begin(), header.end());
    emit_prom(prom, opt);
  }
  // Drain the report explicitly rather than relying on atexit alone, so the
  // full text is on stdout before the caller sees this function return.
  montauk_sink_drain(&g_pop_out);
  return 0;
}

SystemInfo system_info_data(const std::string& dir) {
  std::string labels;  // last montauk_system_info{...} wins
  for (const auto& path : glob_proms(dir)) {
    FILE* fp = std::fopen(path.c_str(), "r");
    if (!fp) continue;
    char* line = nullptr;
    size_t cap = 0;
    ssize_t len;
    while ((len = ::getline(&line, &cap, fp)) != -1) {
      std::string ln(line, len > 0 ? static_cast<size_t>(len) : 0);
      if (ln.rfind("montauk_system_info{", 0) != 0) continue;
      size_t br = ln.find('{'), cb = ln.find('}', br);
      if (cb != std::string::npos) labels = ln.substr(br + 1, cb - br - 1);
    }
    std::free(line);
    std::fclose(fp);
  }
  SystemInfo info;
  if (labels.empty()) return info;
  LabelVec L = parse_labels(labels);
  auto g = [&](const char* k) { return label_get(L, k); };
  info.found = true;
  info.cpu_model = g("cpu_model");
  info.physical_cores = g("physical_cores");
  info.logical_cpus = g("logical_cpus");
  info.cache_domains = g("cache_domains");
  info.mem_total_gib = g("mem_total_gib");
  info.gpu = g("gpu");
  info.kernel = g("kernel");
  info.sched = g("sched");
  return info;
}

std::string system_info_block(const std::string& dir) {
  SystemInfo info = system_info_data(dir);
  if (!info.found) return "";
  std::string out = "SYSTEM\n";
  out += "  cpu        " + info.cpu_model + " (" + info.physical_cores + "c/" +
         info.logical_cpus + "t";
  if (!info.cache_domains.empty()) out += ", " + info.cache_domains + " cache domains";
  out += ")\n";
  out += "  memory     " + info.mem_total_gib + " GiB\n";
  if (!info.gpu.empty()) out += "  gpu        " + info.gpu + "\n";
  out += "  kernel     " + info.kernel + "\n";
  out += "  scheduler  " + info.sched + "\n";
  return out;
}

namespace {
std::string format_ejection(const ScxEjection& e) {
  std::string out = e.scheduler + " -- \"" + e.reason + "\"";
  if (!e.phase.empty() || !e.cores.empty()) {
    out += "  (during " + e.phase;
    if (!e.cores.empty()) out += (e.phase.empty() ? "" : ", ") + e.cores + "c";
    out += ")";
  }
  return out;
}
}  // namespace

ScxStability scx_stability_data(const std::string& dir) {
  // CRASH / EJECTION first, because a scheduler that got ejected makes every
  // latency number below it meaningless -- the reader needs to see it before
  // anything else. bench-enduser writes these markers into the recording .prom:
  //   montauk_scx_ejected{scheduler,reason,phase,cores} 1   (one per ejection)
  //   montauk_cleanroom{verdict,detail} 1                   (CLEAN | NOISY)
  //   montauk_watchdog_proximity_pct{phase,cores} <pct>     (worst sojourn / 30s)
  ScxStability s;
  std::vector<std::string> seen;  // dedup key: the formatted line, as before
  for (const auto& path : glob_proms(dir)) {
    FILE* fp = std::fopen(path.c_str(), "r");
    if (!fp) continue;
    char* line = nullptr;
    size_t cap = 0;
    ssize_t len;
    while ((len = ::getline(&line, &cap, fp)) != -1) {
      std::string ln = strip(std::string(line, len > 0 ? static_cast<size_t>(len) : 0));
      if (ln.rfind("montauk_scx_ejected{", 0) == 0) {
        size_t br = ln.find('{'), cb = ln.find('}', br);
        if (cb == std::string::npos) continue;
        LabelVec L = parse_labels(ln.substr(br + 1, cb - br - 1));
        ScxEjection e{label_get(L, "scheduler"), label_get(L, "reason"),
                      label_get(L, "phase"), label_get(L, "cores")};
        std::string key = format_ejection(e);
        if (std::find(seen.begin(), seen.end(), key) == seen.end()) {
          seen.push_back(key);
          s.ejections.push_back(std::move(e));
        }
      } else if (ln.rfind("montauk_cleanroom{", 0) == 0) {
        size_t br = ln.find('{'), cb = ln.find('}', br);
        if (cb == std::string::npos) continue;
        LabelVec L = parse_labels(ln.substr(br + 1, cb - br - 1));
        s.cleanroom_verdict = label_get(L, "verdict");
        s.cleanroom_detail = label_get(L, "detail");
      } else if (ln.rfind("montauk_watchdog_proximity_pct", 0) == 0) {
        size_t sp = ln.rfind(' ');
        double v = sp != std::string::npos ? std::atof(ln.c_str() + sp + 1) : 0;
        std::string where;
        size_t br = ln.find('{'), cb = ln.find('}', br);
        if (cb != std::string::npos && br != std::string::npos) {
          LabelVec L = parse_labels(ln.substr(br + 1, cb - br - 1));
          std::string ph = label_get(L, "phase"), co = label_get(L, "cores");
          where = ph + (co.empty() ? "" : (ph.empty() ? "" : " ") + co + "c");
        }
        if (v > s.watchdog_worst_pct) { s.watchdog_worst_pct = v; s.watchdog_where = where; }
      }
    }
    std::free(line);
    std::fclose(fp);
  }
  return s;
}

std::string scx_stability_block(const std::string& dir) {
  ScxStability s = scx_stability_data(dir);
  if (s.ejections.empty() && s.cleanroom_verdict.empty() && s.watchdog_worst_pct < 0) return "";
  std::string out = "SCHEDULER STABILITY\n";
  if (!s.ejections.empty())
    for (const auto& e : s.ejections) out += "  EJECTED      " + format_ejection(e) + "\n";
  else
    out += "  no ejection -- scheduler ran clean\n";
  if (s.watchdog_worst_pct >= 0) {
    char num[64];
    std::snprintf(num, sizeof num, "%.0f%%", s.watchdog_worst_pct);
    out += std::string("  watchdog     worst sojourn ") + num +
           " of the 30s sched_ext limit";
    if (!s.watchdog_where.empty()) out += "  (" + s.watchdog_where + ")";
    if (s.watchdog_worst_pct >= 50) out += "  [NEAR-EJECTION]";
    out += "\n";
  }
  if (!s.cleanroom_verdict.empty()) {
    out += "\nCLEAN-ROOM\n  state        " + s.cleanroom_verdict;
    if (!s.cleanroom_detail.empty()) out += " -- " + s.cleanroom_detail;
    out += "\n";
  }
  return out;
}


ThermalPower thermal_power_data(const std::string& dir) {
  double temp_peak = 0, temp_sum = 0;
  int temp_n = 0;
  double fan_peak = 0;
  double pw_peak = 0, pw_sum = 0;
  int pw_n = 0;
  double fq_peak = 0, fq_sum = 0; int fq_n = 0;
  double epi_sum = 0; int epi_n = 0;
  double ctx_sum = 0; int ctx_n = 0;
  double mig_sum = 0; int mig_n = 0;
  double br_sum = 0; int br_n = 0;
  double e_min = -1.0, e_max = -1.0; int e_n = 0;  // package energy counter -> integral
  std::map<std::string, std::pair<double, int>> cstate;  // name -> (sum%, n)
  const std::string kTemp = "montauk_thermal_cpu_temperature_celsius ";
  const std::string kFan = "montauk_thermal_fan_speed_rpm ";
  const std::string kPow = "montauk_power_watts ";
  const std::string kFreq = "montauk_cpu_frequency_mhz_avg ";
  const std::string kEpi = "montauk_energy_per_instruction_pj ";
  const std::string kCtx = "montauk_pmu_context_switches_per_second ";
  const std::string kMig = "montauk_pmu_cpu_migrations_per_second ";
  const std::string kBr = "montauk_pmu_branch_misses_per_second ";
  const std::string kCst = "montauk_cstate_residency_percent{state=\"";
  const std::string kEnergy = "montauk_package_energy_joules_total ";
  for (const auto& path : glob_proms(dir)) {
    FILE* fp = std::fopen(path.c_str(), "r");
    if (!fp) continue;
    char* line = nullptr;
    size_t cap = 0;
    ssize_t len;
    while ((len = ::getline(&line, &cap, fp)) != -1) {
      std::string ln = strip(std::string(line, len > 0 ? static_cast<size_t>(len) : 0));
      if (ln.rfind(kTemp, 0) == 0) {
        double v = std::strtod(ln.c_str() + kTemp.size(), nullptr);
        temp_peak = std::max(temp_peak, v);
        temp_sum += v;
        ++temp_n;
      } else if (ln.rfind(kFan, 0) == 0) {
        fan_peak = std::max(fan_peak, std::strtod(ln.c_str() + kFan.size(), nullptr));
      } else if (ln.rfind(kPow, 0) == 0) {
        double v = std::strtod(ln.c_str() + kPow.size(), nullptr);
        if (v > 0.0) { pw_peak = std::max(pw_peak, v); pw_sum += v; ++pw_n; }
      } else if (ln.rfind(kFreq, 0) == 0) {
        double v = std::strtod(ln.c_str() + kFreq.size(), nullptr);
        if (v > 0.0) { fq_peak = std::max(fq_peak, v); fq_sum += v; ++fq_n; }
      } else if (ln.rfind(kEpi, 0) == 0) {
        double v = std::strtod(ln.c_str() + kEpi.size(), nullptr);
        if (v > 0.0) { epi_sum += v; ++epi_n; }
      } else if (ln.rfind(kCtx, 0) == 0) {
        ctx_sum += std::strtod(ln.c_str() + kCtx.size(), nullptr); ++ctx_n;
      } else if (ln.rfind(kMig, 0) == 0) {
        mig_sum += std::strtod(ln.c_str() + kMig.size(), nullptr); ++mig_n;
      } else if (ln.rfind(kBr, 0) == 0) {
        br_sum += std::strtod(ln.c_str() + kBr.size(), nullptr); ++br_n;
      } else if (ln.rfind(kEnergy, 0) == 0) {
        double v = std::strtod(ln.c_str() + kEnergy.size(), nullptr);
        if (e_min < 0.0 || v < e_min) e_min = v;
        if (v > e_max) e_max = v;
        ++e_n;
      } else if (ln.rfind(kCst, 0) == 0) {
        size_t q = ln.find('"', kCst.size());
        size_t b = ln.find("} ", kCst.size());
        if (q != std::string::npos && b != std::string::npos) {
          std::string name = ln.substr(kCst.size(), q - kCst.size());
          double v = std::strtod(ln.c_str() + b + 2, nullptr);
          auto& e = cstate[name];
          e.first += v; e.second += 1;
        }
      }
    }
    std::free(line);
    std::fclose(fp);
  }
  ThermalPower t;
  t.temp_peak_c = temp_peak; t.temp_avg_c = temp_n > 0 ? temp_sum / temp_n : 0.0; t.temp_n = temp_n;
  t.fan_peak_rpm = fan_peak;
  t.power_avg_w = pw_n > 0 ? pw_sum / pw_n : 0.0; t.power_peak_w = pw_peak; t.power_n = pw_n;
  t.energy_joules_total = (e_n > 0 && e_max > e_min) ? (e_max - e_min) : -1.0;
  t.freq_avg_mhz = fq_n > 0 ? fq_sum / fq_n : 0.0; t.freq_peak_mhz = fq_peak; t.freq_n = fq_n;
  t.energy_per_instr_pj = epi_n > 0 ? epi_sum / epi_n : 0.0; t.epi_n = epi_n;
  t.ctx_switches_per_sec = ctx_n > 0 ? ctx_sum / ctx_n : 0.0; t.ctx_n = ctx_n;
  t.migrations_per_sec = mig_n > 0 ? mig_sum / mig_n : 0.0; t.mig_n = mig_n;
  t.branch_misses_per_sec = br_n > 0 ? br_sum / br_n : 0.0; t.br_n = br_n;
  if (!cstate.empty()) {
    // Report the idle state the CPUs spent the most time in (deepest dominant).
    std::string top; double top_pct = -1.0;
    for (const auto& [name, e] : cstate) {
      double avg = e.second > 0 ? e.first / e.second : 0.0;
      if (avg > top_pct) { top_pct = avg; top = name; }
    }
    if (top_pct >= 0.0) { t.dominant_cstate = top; t.dominant_cstate_pct = top_pct; }
  }
  return t;
}

std::string thermal_power_block(const std::string& dir) {
  ThermalPower t = thermal_power_data(dir);
  if (t.temp_n == 0 && t.power_n == 0 && t.fan_peak_rpm == 0.0 && t.freq_n == 0 &&
      t.ctx_n == 0 && t.mig_n == 0 && t.dominant_cstate.empty())
    return "";
  char buf[160];
  std::string out = "THERMAL/POWER\n";
  if (t.temp_n > 0) {
    std::snprintf(buf, sizeof(buf), "  cpu temp   peak %.1f C  avg %.1f C\n",
                  t.temp_peak_c, t.temp_avg_c);
    out += buf;
  }
  if (t.fan_peak_rpm > 0.0) {
    std::snprintf(buf, sizeof(buf), "  fan        peak %.0f rpm\n", t.fan_peak_rpm);
    out += buf;
  }
  if (t.power_n > 0) {
    std::snprintf(buf, sizeof(buf), "  power      avg %.1f W  peak %.1f W\n",
                  t.power_avg_w, t.power_peak_w);
    out += buf;
  }
  if (t.energy_joules_total >= 0.0) {
    std::snprintf(buf, sizeof(buf), "  energy-tot %.1f J integral over recording\n",
                  t.energy_joules_total);
    out += buf;
  }
  if (t.freq_n > 0) {
    std::snprintf(buf, sizeof(buf), "  cpu clock  avg %.0f MHz  peak %.0f MHz\n",
                  t.freq_avg_mhz, t.freq_peak_mhz);
    out += buf;
  }
  if (t.epi_n > 0) {
    std::snprintf(buf, sizeof(buf), "  energy     avg %.1f pJ/instr\n",
                  t.energy_per_instr_pj);
    out += buf;
  }
  if (t.ctx_n > 0) {
    std::snprintf(buf, sizeof(buf), "  ctx-sw     avg %.0f /s\n", t.ctx_switches_per_sec);
    out += buf;
  }
  if (t.mig_n > 0) {
    std::snprintf(buf, sizeof(buf), "  migrations avg %.0f /s\n", t.migrations_per_sec);
    out += buf;
  }
  if (t.br_n > 0) {
    std::snprintf(buf, sizeof(buf), "  branch-mis avg %.0f /s\n", t.branch_misses_per_sec);
    out += buf;
  }
  if (!t.dominant_cstate.empty()) {
    std::snprintf(buf, sizeof(buf), "  idle       %s avg %.1f%% (dominant)\n",
                  t.dominant_cstate.c_str(), t.dominant_cstate_pct);
    out += buf;
  }
  return out;
}

// Shared L2-by-CPU computation: sum montauk_pmu_l2_misses_per_cpu over the busy
// (storm) scrapes and return the per-CPU rows sorted by misses (desc). Used by
// both the full l2-by-cpu report and the digest's hot-cpu offender fold.
namespace {
struct L2Shares {
  bool ok{false};
  std::vector<std::pair<int, double>> rows;  // (cpu, misses), desc
  double grand{0.0};
  int busy{0};
  size_t scrapes{0};
};

L2Shares compute_l2_shares(const std::string& dir) {
  L2Shares r;
  std::vector<std::string> files = glob_proms(dir);
  if (files.empty()) return r;

  // A montauk recording is a concatenation of per-scrape expositions; one
  // "# HELP montauk_cpu_usage_percent" opens each scrape. Per scrape we keep the
  // aggregate L2 (to find the busy/storm window) and the per-CPU breakdown.
  struct Scrape { double total = 0.0; std::map<int, double> per_cpu; };
  std::vector<Scrape> scrapes;
  Scrape cur;
  bool open = false;
  const std::string kDelim = "# HELP montauk_cpu_usage_percent";
  const std::string kIval  = "montauk_pmu_l2_misses_interval ";
  const std::string kPer   = "montauk_pmu_l2_misses_per_cpu{";

  for (const auto& path : files) {
    FILE* fp = std::fopen(path.c_str(), "r");
    if (!fp) continue;
    char* line = nullptr;
    size_t cap = 0;
    ssize_t len;
    while ((len = ::getline(&line, &cap, fp)) != -1) {
      std::string ln = strip(std::string(line, len > 0 ? static_cast<size_t>(len) : 0));
      if (ln.rfind(kDelim, 0) == 0) {
        if (open) scrapes.push_back(cur);
        cur = Scrape{};
        open = true;
        continue;
      }
      open = true;
      if (ln.rfind(kIval, 0) == 0) {
        cur.total = std::strtod(ln.c_str() + kIval.size(), nullptr);
      } else if (ln.rfind(kPer, 0) == 0) {
        size_t br = ln.find('{'), cb = ln.find('}', br);
        if (cb == std::string::npos) continue;
        LabelVec labels = parse_labels(ln.substr(br + 1, cb - br - 1));
        std::string cpu = label_get(labels, "cpu");
        if (cpu.empty()) continue;
        cur.per_cpu[std::atoi(cpu.c_str())] +=
            std::strtod(strip(ln.substr(cb + 1)).c_str(), nullptr);
      }
    }
    std::free(line);
    std::fclose(fp);
  }
  if (open) scrapes.push_back(cur);
  r.scrapes = scrapes.size();

  // Busy window: scrapes whose aggregate L2 clears 0.3*peak -- the storm, where
  // the misses that matter happen (excludes the quiet idle baseline).
  double peak = 0.0;
  for (const auto& s : scrapes) peak = std::max(peak, s.total);
  std::map<int, double> per_cpu;
  for (const auto& s : scrapes) {
    if (peak > 0.0 && s.total <= 0.3 * peak) continue;
    ++r.busy;
    for (const auto& kv : s.per_cpu) {
      per_cpu[kv.first] += kv.second;
      r.grand += kv.second;
    }
  }
  if (per_cpu.empty() || r.grand <= 0.0) return r;

  r.rows.assign(per_cpu.begin(), per_cpu.end());
  sublimation_order_f64(r.rows, true, [](const std::pair<int, double>& p) { return p.second; });
  r.ok = true;
  return r;
}

// Concentration severity from the top CPU's share vs. the even-spread baseline.
int l2_severity(double top_pct, double uniform_pct) {
  return top_pct > 3.0 * uniform_pct ? 2 : (top_pct > 1.5 * uniform_pct ? 1 : 0);
}
}  // namespace

int run_l2_by_cpu(const std::string& dir) {
  ensure_pop_out();
  std::vector<std::string> files = glob_proms(dir);
  if (files.empty()) {
    util::log_error("no montauk_*.prom in %s", dir.c_str());
    return 1;
  }
  util::log_info("l2-by-cpu: %zu scrape file(s) in %s", files.size(), dir.c_str());

  L2Shares s = compute_l2_shares(dir);
  if (!s.ok) {
    util::log_warn("no per-CPU L2 in recording -- recapture with the per-CPU "
                   "emission build (montauk_pmu_l2_misses_per_cpu)");
    return 1;
  }

  montauk_sink_appendf(&g_pop_out, "\nREPORT l2-by-cpu  (%d busy of %zu scrapes)\n", s.busy, s.scrapes);
  montauk_sink_appendf(&g_pop_out, "%-6s %18s %9s\n", "CPU", "L2-misses", "share");
  for (const auto& r : s.rows)
    montauk_sink_appendf(&g_pop_out, "%-6d %18.0f %8.1f%%\n", r.first, r.second,
                100.0 * r.second / s.grand);
  double top = 100.0 * s.rows.front().second / s.grand;
  double uniform = 100.0 / static_cast<double>(s.rows.size());
  int sev = l2_severity(top, uniform);
  const char* verdict = sev == 2 ? "CONCENTRATED (hotspot)"
                        : sev == 1 ? "skewed" : "spread";
  montauk_sink_appendf(&g_pop_out, "top CPU %d holds %.1f%% (uniform = %.1f%%) -- %s\n",
              s.rows.front().first, top, uniform, verdict);
  // Join the offender family so the hot core sits alongside the trace-side
  // offenders in the report's machine-readable list (one montauk_offender{}).
  montauk_sink_appendf(&g_pop_out, "montauk_offender{kind=\"hot-cpu\",id=\"%d\",metric=\"l2_miss_share\",sev=\"%d\"} %.1f\n",
              s.rows.front().first, sev, top);
  return 0;
}

HotCpu l2_hot_cpu(const std::string& dir) {
  HotCpu h;
  L2Shares s = compute_l2_shares(dir);
  if (!s.ok) return h;
  h.found = true;
  h.cpu = s.rows.front().first;
  h.share_pct = 100.0 * s.rows.front().second / s.grand;
  h.uniform_pct = 100.0 / static_cast<double>(s.rows.size());
  h.sev = l2_severity(h.share_pct, h.uniform_pct);
  return h;
}

}  // namespace montauk::pop
