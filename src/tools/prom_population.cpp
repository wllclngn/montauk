// prom_population — implementation. See prom_population.hpp.
#include "prom_population.hpp"
#include "sublimation_order.hpp"

#include "prom_stats.hpp"
#include "util/Log.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <dirent.h>
#include <sys/stat.h>

#ifndef MONTAUK_VERSION
#define MONTAUK_VERSION "unknown"
#endif

namespace montauk::pop {

namespace {

using LabelVec = std::vector<std::pair<std::string, std::string>>;

// One reconstructed-sample pool plus the per-run scalar vector, per group.
struct Cell {
  LabelVec display;  // cell labels (sans compare axis), for the report header
  std::map<std::string, std::vector<double>> runs;  // axis value -> per-run scalar
  std::map<std::string, std::vector<double>> samp;  // axis value -> pooled within-run
};

struct Family {
  std::map<std::string, Cell> cells;  // cell key -> cell
};

// ---- Prometheus text parsing -------------------------------------------------

std::string strip(const std::string& s) {
  size_t a = 0, b = s.size();
  while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
  while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
  return s.substr(a, b - a);
}

// Parse `key="value",key="value"` (values may contain spaces/parens).
LabelVec parse_labels(const std::string& in) {
  LabelVec out;
  size_t i = 0;
  while (i < in.size()) {
    size_t eq = in.find('=', i);
    if (eq == std::string::npos) break;
    std::string key = strip(in.substr(i, eq - i));
    size_t q1 = in.find('"', eq);
    if (q1 == std::string::npos) break;
    size_t q2 = in.find('"', q1 + 1);
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
  std::sort(out.begin(), out.end());
  return out;
}

double le_value(const std::string& le) {
  if (le == "+Inf") return INFINITY;
  return std::strtod(le.c_str(), nullptr);
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

// Parse one file: inject `version` into every sample's labels; route gauges to
// the run vectors and histogram parts to the per-cell pools.
void parse_file(const std::string& path, const PopOptions& opt,
                std::map<std::string, Family>& data) {
  FILE* f = std::fopen(path.c_str(), "r");
  if (!f) {
    util::log_error("cannot open %s", path.c_str());
    return;
  }
  std::set<std::string> hist_families;
  std::string version = "unknown";
  std::string commit = "unknown";
  // TYPE lines precede their series in the bench .prom, so a single pass works.
  // family -> cellkey -> axis value -> cumulative-bucket histogram.
  std::map<std::string, std::map<std::string, std::map<std::string, Hist>>> file_hist;
  std::map<std::string, LabelVec> file_hist_disp;  // cellkey -> display

  const std::set<std::string> drop_for_cell = {opt.compare_axis, "le"};

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
        if (tok.size() >= 4 && tok[3] == "histogram") hist_families.insert(tok[2]);
      }
      continue;
    }
    // name[{labels}] value
    size_t brace = s.find('{');
    std::string name, labelstr, valstr;
    if (brace != std::string::npos) {
      name = s.substr(0, brace);
      size_t close = s.find('}', brace);
      if (close == std::string::npos) continue;
      labelstr = s.substr(brace + 1, close - brace - 1);
      valstr = strip(s.substr(close + 1));
    } else {
      size_t sp = s.find_last_of(" \t");
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

    // Histogram component?
    auto is_hist_part = [&](const std::string& suffix) {
      if (name.size() <= suffix.size()) return std::string();
      if (name.compare(name.size() - suffix.size(), suffix.size(), suffix) != 0)
        return std::string();
      std::string base = name.substr(0, name.size() - suffix.size());
      return hist_families.count(base) ? base : std::string();
    };
    std::string hb = is_hist_part("_bucket");
    bool is_sum = !is_hist_part("_sum").empty();
    bool is_count = !is_hist_part("_count").empty();
    if (!hb.empty()) {
      labels.emplace_back("version", version);
      labels.emplace_back("commit", commit);
      std::string axv = label_get(labels, opt.compare_axis);
      if (axv.empty()) continue;
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
    std::string axis = label_get(labels, opt.compare_axis);
    if (axis.empty()) continue;  // cannot place without the compare axis
    std::string ck = cell_key(labels, drop_for_cell);
    Family& fam = data[name];
    Cell& cell = fam.cells[ck];
    if (cell.display.empty()) cell.display = cell_display(labels, drop_for_cell);
    cell.runs[axis].push_back(val);
  }
  std::free(line);
  std::fclose(f);

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

// ---- report + prom ----------------------------------------------------------

std::string short_axis(const std::string& v) {
  std::string n;
  for (char c : v) n += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  if (n.find("pandemonium") != std::string::npos && n.find("bpf") != std::string::npos)
    return "bpf";
  if (n.find("pandemonium") != std::string::npos && n.find("adaptive") != std::string::npos)
    return "adaptive";
  if (n.find("eevdf") != std::string::npos) return "eevdf";
  return v;
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

void emit_prom(const std::vector<PromLine>& lines, const PopOptions& opt) {
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
      std::fprintf(f, "# HELP %s population analysis\n# TYPE %s gauge\n",
                   m.name.c_str(), m.name.c_str());
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

}  // namespace

int run_population(const std::vector<std::string>& files, const PopOptions& opt) {
  if (files.empty()) {
    util::log_error("no .prom files to analyze");
    return 1;
  }
  std::map<std::string, Family> data;
  for (const auto& f : files) parse_file(f, opt, data);
  if (data.empty()) {
    util::log_error("no usable gauges in %zu file(s)", files.size());
    return 1;
  }

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

  stats::Rng rng(opt.seed);
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
  if (max_group_n <= 1)
    util::log_warn("N=1 per group -- inference underpowered; collect >=3 runs "
                   "per '%s' value for a verdict", opt.compare_axis.c_str());

  for (auto& fam_kv : data) {
    const std::string& metric = fam_kv.first;
    if (!opt.metric_filter.empty() &&
        metric.find(opt.metric_filter) == std::string::npos)
      continue;
    std::printf("\nMETRIC %s\n", metric.c_str());
    for (auto& cell_kv : fam_kv.second.cells) {
      Cell& cell = cell_kv.second;
      std::vector<std::string> groups;
      for (auto& g : cell.runs)
        if (!g.second.empty()) groups.push_back(g.first);
      std::printf("  [%s]\n", cell_label_str(cell.display).c_str());
      if (groups.size() < 2) {
        std::printf("    only %s -- no comparison\n",
                    groups.empty() ? "(none)" : short_axis(groups[0]).c_str());
        continue;
      }
      std::string clabel = cell_label_str(cell.display);

      // Pairwise run-level inference.
      for (size_t i = 0; i < groups.size(); ++i) {
        for (size_t j = i + 1; j < groups.size(); ++j) {
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
          std::string sa = short_axis(groups[i]), sb = short_axis(groups[j]);
          std::printf(
              "    %s vs %s [N=%zu/%zu]: mean %.6g (%.4g..%.4g) vs %.6g (%.4g..%.4g) | "
              "cliff %+.2f (%s) | perm p=%.3f | power %s\n",
              sa.c_str(), sb.c_str(), va.size(), vb.size(), ma, mnA, mxA, mb,
              mnB, mxB, cd, stats::cliff_magnitude(cd), pp,
              npow ? std::to_string(npow).c_str() : ">20");
          std::string lab = "metric=\"" + metric + "\",cell=\"" + clabel +
                            "\",pair=\"" + sa + "__" + sb + "\"";
          prom.push_back({"montauk_pop_cliff", lab, cd});
          prom.push_back({"montauk_pop_perm_p", lab, pp});
          prom.push_back({"montauk_pop_power_n", lab,
                          static_cast<double>(npow)});
        }
      }

      // Bootstrap Hsu-MCB across all groups in the cell.
      std::vector<std::vector<double>> g;
      std::vector<std::string> gn;
      for (const auto& s : groups) {
        g.push_back(cell.runs[s]);
        gn.push_back(short_axis(s));
      }
      auto mcb = stats::bootstrap_mcb(g, opt.lower_is_better, rng);
      std::printf("    MCB (%s):", better);
      for (size_t k = 0; k < gn.size(); ++k) {
        const char* v = mcb[k].verdict == 1 ? "best"
                        : mcb[k].verdict == -1 ? "not-best"
                                               : "tied";
        std::printf(" %s=%s", gn[k].c_str(), v);
        std::string lab = "metric=\"" + metric + "\",cell=\"" + clabel +
                          "\",group=\"" + gn[k] + "\"";
        prom.push_back({"montauk_pop_mcb_is_best", lab,
                        static_cast<double>(mcb[k].verdict)});
        prom.push_back({"montauk_pop_mean", lab, stats::mean(g[k])});
        prom.push_back({"montauk_pop_n", lab,
                        static_cast<double>(g[k].size())});
      }
      std::printf("\n");

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
          hn.push_back(short_axis(s));
        }
        if (have_hist) {
          for (size_t i = 0; i < groups.size(); ++i)
            for (size_t j = i + 1; j < groups.size(); ++j) {
              double qp = stats::perm_test(hs[i], hs[j], stats::Stat::Percentile,
                                           opt.quantile, rng);
              std::printf("      within-run q%.0f perm p=%.3f (%s vs %s)\n",
                          opt.quantile, qp, hn[i].c_str(), hn[j].c_str());
            }
        }
        auto gh = stats::games_howell(hs);
        for (const auto& pr : gh) {
          std::printf("      games-howell %s vs %s: p=%.3f%s\n",
                      hn[pr.i].c_str(), hn[pr.j].c_str(), pr.p,
                      have_hist ? "" : " [run-level]");
          std::string lab = "metric=\"" + metric + "\",cell=\"" + clabel +
                            "\",pair=\"" + hn[pr.i] + "__" + hn[pr.j] + "\"";
          prom.push_back({"montauk_pop_gameshowell_p", lab, pr.p});
        }
      }
    }
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
  return 0;
}

std::string system_info_block(const std::string& dir) {
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
  if (labels.empty()) return "";
  LabelVec L = parse_labels(labels);
  auto g = [&](const char* k) { return label_get(L, k); };
  std::string out = "SYSTEM\n";
  out += "  cpu        " + g("cpu_model") + " (" + g("physical_cores") + "c/" +
         g("logical_cpus") + "t";
  std::string domain = g("cache_domains");
  if (!domain.empty()) out += ", " + domain + " cache domains";
  out += ")\n";
  out += "  memory     " + g("mem_total_gib") + " GiB\n";
  std::string gpu = g("gpu");
  if (!gpu.empty()) out += "  gpu        " + gpu + "\n";
  out += "  kernel     " + g("kernel") + "\n";
  out += "  scheduler  " + g("sched") + "\n";
  return out;
}

std::string scx_stability_block(const std::string& dir) {
  // CRASH / EJECTION first, because a scheduler that got ejected makes every
  // latency number below it meaningless -- the reader needs to see it before
  // anything else. bench-enduser writes these markers into the recording .prom:
  //   montauk_scx_ejected{scheduler,reason,phase,cores} 1   (one per ejection)
  //   montauk_cleanroom{verdict,detail} 1                   (CLEAN | NOISY)
  //   montauk_watchdog_proximity_pct{phase,cores} <pct>     (worst sojourn / 30s)
  std::vector<std::string> ejections;
  std::string cr_verdict, cr_detail;
  double wd_worst = -1;
  std::string wd_where;
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
        std::string e = label_get(L, "scheduler") + " -- \"" +
                        label_get(L, "reason") + "\"";
        std::string ph = label_get(L, "phase"), co = label_get(L, "cores");
        if (!ph.empty() || !co.empty()) {
          e += "  (during " + ph;
          if (!co.empty()) e += (ph.empty() ? "" : ", ") + co + "c";
          e += ")";
        }
        if (std::find(ejections.begin(), ejections.end(), e) == ejections.end())
          ejections.push_back(e);
      } else if (ln.rfind("montauk_cleanroom{", 0) == 0) {
        size_t br = ln.find('{'), cb = ln.find('}', br);
        if (cb == std::string::npos) continue;
        LabelVec L = parse_labels(ln.substr(br + 1, cb - br - 1));
        cr_verdict = label_get(L, "verdict");
        cr_detail = label_get(L, "detail");
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
        if (v > wd_worst) { wd_worst = v; wd_where = where; }
      }
    }
    std::free(line);
    std::fclose(fp);
  }
  if (ejections.empty() && cr_verdict.empty() && wd_worst < 0) return "";
  std::string out = "SCHEDULER STABILITY\n";
  if (!ejections.empty())
    for (const auto& e : ejections) out += "  EJECTED      " + e + "\n";
  else
    out += "  no ejection -- scheduler ran clean\n";
  if (wd_worst >= 0) {
    char num[64];
    std::snprintf(num, sizeof num, "%.0f%%", wd_worst);
    out += std::string("  watchdog     worst sojourn ") + num +
           " of the 30s sched_ext limit";
    if (!wd_where.empty()) out += "  (" + wd_where + ")";
    if (wd_worst >= 50) out += "  [NEAR-EJECTION]";
    out += "\n";
  }
  if (!cr_verdict.empty()) {
    out += "\nCLEAN-ROOM\n  state        " + cr_verdict;
    if (!cr_detail.empty()) out += " -- " + cr_detail;
    out += "\n";
  }
  return out;
}


std::string thermal_power_block(const std::string& dir) {
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
  if (temp_n == 0 && pw_n == 0 && fan_peak == 0.0 && fq_n == 0 &&
      ctx_n == 0 && mig_n == 0 && cstate.empty())
    return "";
  char buf[160];
  std::string out = "THERMAL/POWER\n";
  if (temp_n > 0) {
    std::snprintf(buf, sizeof(buf), "  cpu temp   peak %.1f C  avg %.1f C\n",
                  temp_peak, temp_sum / temp_n);
    out += buf;
  }
  if (fan_peak > 0.0) {
    std::snprintf(buf, sizeof(buf), "  fan        peak %.0f rpm\n", fan_peak);
    out += buf;
  }
  if (pw_n > 0) {
    std::snprintf(buf, sizeof(buf), "  power      avg %.1f W  peak %.1f W\n",
                  pw_sum / pw_n, pw_peak);
    out += buf;
  }
  if (e_n > 0 && e_max > e_min) {
    std::snprintf(buf, sizeof(buf), "  energy-tot %.1f J integral over recording\n",
                  e_max - e_min);
    out += buf;
  }
  if (fq_n > 0) {
    std::snprintf(buf, sizeof(buf), "  cpu clock  avg %.0f MHz  peak %.0f MHz\n",
                  fq_sum / fq_n, fq_peak);
    out += buf;
  }
  if (epi_n > 0) {
    std::snprintf(buf, sizeof(buf), "  energy     avg %.1f pJ/instr\n",
                  epi_sum / epi_n);
    out += buf;
  }
  if (ctx_n > 0) {
    std::snprintf(buf, sizeof(buf), "  ctx-sw     avg %.0f /s\n", ctx_sum / ctx_n);
    out += buf;
  }
  if (mig_n > 0) {
    std::snprintf(buf, sizeof(buf), "  migrations avg %.0f /s\n", mig_sum / mig_n);
    out += buf;
  }
  if (br_n > 0) {
    std::snprintf(buf, sizeof(buf), "  branch-mis avg %.0f /s\n", br_sum / br_n);
    out += buf;
  }
  if (!cstate.empty()) {
    // Report the idle state the CPUs spent the most time in (deepest dominant).
    std::string top; double top_pct = -1.0;
    for (const auto& [name, e] : cstate) {
      double avg = e.second > 0 ? e.first / e.second : 0.0;
      if (avg > top_pct) { top_pct = avg; top = name; }
    }
    if (top_pct >= 0.0) {
      std::snprintf(buf, sizeof(buf), "  idle       %s avg %.1f%% (dominant)\n",
                    top.c_str(), top_pct);
      out += buf;
    }
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

  std::printf("\nREPORT l2-by-cpu  (%d busy of %zu scrapes)\n", s.busy, s.scrapes);
  std::printf("%-6s %18s %9s\n", "CPU", "L2-misses", "share");
  for (const auto& r : s.rows)
    std::printf("%-6d %18.0f %8.1f%%\n", r.first, r.second,
                100.0 * r.second / s.grand);
  double top = 100.0 * s.rows.front().second / s.grand;
  double uniform = 100.0 / static_cast<double>(s.rows.size());
  int sev = l2_severity(top, uniform);
  const char* verdict = sev == 2 ? "CONCENTRATED (hotspot)"
                        : sev == 1 ? "skewed" : "spread";
  std::printf("top CPU %d holds %.1f%% (uniform = %.1f%%) -- %s\n",
              s.rows.front().first, top, uniform, verdict);
  // Join the offender family so the hot core sits alongside the trace-side
  // offenders in the report's machine-readable list (one montauk_offender{}).
  std::printf("montauk_offender{kind=\"hot-cpu\",id=\"%d\",metric=\"l2_miss_share\",sev=\"%d\"} %.1f\n",
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
