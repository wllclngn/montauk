#include "collectors/FdinfoProcessCollector.hpp"
#include "util/Procfs.hpp"

#include <string>
#include <sstream>
#include <cctype>

using namespace std::chrono;

namespace montauk::collectors {

static bool is_number(const std::string& s) {
  if (s.empty()) return false;
  for (char c : s) if (!std::isdigit((unsigned char)c)) return false;
  return true;
}

// Parse a single fdinfo content. Fills partial intel/amd counters and vram_kb if present.
static void parse_fdinfo_text(const std::string& txt, FdinfoProcessCollector::IntelCycles& intel,
                              FdinfoProcessCollector::AmdEngines& amd, uint64_t& vram_kb) {
  std::istringstream ss(txt);
  std::string line;
  auto starts_with = [](const std::string& s, const char* p){ return s.rfind(p, 0) == 0; };
  while (std::getline(ss, line)) {
    // Strip trailing CR
    if (!line.empty() && (line.back()=='\r' || line.back()=='\n')) line.pop_back();
    // split at ':'
    auto colon = line.find(':');
    if (colon == std::string::npos) continue;
    std::string key = line.substr(0, colon);
    std::string val = line.substr(colon + 1);
    auto ltrim = [](std::string& s){ while(!s.empty() && (s.front()==' '||s.front()=='\t')) s.erase(s.begin()); };
    auto rtrim = [](std::string& s){ while(!s.empty() && (s.back()==' '||s.back()=='\t')) s.pop_back(); };
    ltrim(key); rtrim(key); ltrim(val); rtrim(val);

    // Intel XE cycles
    if (starts_with(key, "drm-cycles-")) {
      uint64_t v = 0; try { v = std::stoull(val); } catch (...) { continue; }
      if (key == "drm-cycles-rcs") intel.cycles_rcs = v;
      else if (key == "drm-cycles-ccs") intel.cycles_ccs = v;
      else if (key == "drm-cycles-vcs") intel.cycles_vcs = v;
    } else if (starts_with(key, "drm-total-cycles-")) {
      uint64_t v = 0; try { v = std::stoull(val); } catch (...) { continue; }
      if (key == "drm-total-cycles-rcs") intel.total_rcs = v;
      else if (key == "drm-total-cycles-ccs") intel.total_ccs = v;
      else if (key == "drm-total-cycles-vcs") intel.total_vcs = v;
    }
    // AMD new engines (nanoseconds busy time)
    else if (key == "drm-engine-gfx" || key == "gfx") {
      uint64_t v = 0; try { v = std::stoull(val); } catch (...) { continue; } amd.gfx_ns = v; }
    else if (key == "drm-engine-compute" || key == "compute") {
      uint64_t v = 0; try { v = std::stoull(val); } catch (...) { continue; } amd.compute_ns = v; }
    else if (key == "drm-engine-enc" || key == "enc") {
      uint64_t v = 0; try { v = std::stoull(val); } catch (...) { continue; } amd.enc_ns = v; }
    else if (key == "drm-engine-dec" || key == "dec") {
      uint64_t v = 0; try { v = std::stoull(val); } catch (...) { continue; } amd.dec_ns = v; }
    // Per-process VRAM (KiB)
    else if (key == "drm-memory-vram" || key == "vram mem") {
      // Expect "<num> kB|KiB"
      // Extract leading integer
      size_t pos = 0; while (pos < val.size() && std::isspace((unsigned char)val[pos])) ++pos;
      size_t end = pos; while (end < val.size() && std::isdigit((unsigned char)val[end])) ++end;
      if (end > pos) {
        try {
          uint64_t kib = std::stoull(val.substr(pos, end-pos));
          vram_kb = kib;
        } catch (...) { /* ignore */ }
      }
    }
  }
}

bool FdinfoProcessCollector::sample(std::unordered_map<int,int>& pid_to_gpu,
                                    std::unordered_map<int, uint64_t>& pid_to_gpu_mem_kb,
                                    std::unordered_set<int>& running_pids) {
  pid_to_gpu.clear(); pid_to_gpu_mem_kb.clear(); running_pids.clear();
  bool any = false;
  auto now = Clock::now();
  for (const auto& pd : montauk::util::list_dir("/proc")) {
    if (!is_number(pd)) continue;
    int pid = std::strtol(pd.c_str(), nullptr, 10);
    // Enumerate fdinfo files
    std::string fdinfo_dir = std::string("/proc/") + pd + "/fdinfo";
    auto fds = montauk::util::list_dir(fdinfo_dir);
    if (fds.empty()) continue;
    IntelCycles intel_acc{}; AmdEngines amd_acc{}; uint64_t vram_kb = 0;
    bool saw_drm = false;
    for (const auto& fn : fds) {
      if (!is_number(fn)) continue;
      auto content_opt = montauk::util::read_file_string(fdinfo_dir + "/" + fn);
      if (!content_opt) continue;
      const auto& txt = *content_opt;
      // Quick filter: skip if no DRM keys
      if (txt.find("drm-") == std::string::npos && txt.find("gfx") == std::string::npos && txt.find("compute") == std::string::npos)
        continue;
      saw_drm = true; any = true;
      IntelCycles intel_part{}; AmdEngines amd_part{}; uint64_t vram_kb_part = 0;
      parse_fdinfo_text(txt, intel_part, amd_part, vram_kb_part);
      // Accumulate per-pid (dedup best-effort)
      intel_acc.cycles_rcs = std::max(intel_acc.cycles_rcs, intel_part.cycles_rcs);
      intel_acc.total_rcs  = std::max(intel_acc.total_rcs,  intel_part.total_rcs);
      intel_acc.cycles_ccs = std::max(intel_acc.cycles_ccs, intel_part.cycles_ccs);
      intel_acc.total_ccs  = std::max(intel_acc.total_ccs,  intel_part.total_ccs);
      intel_acc.cycles_vcs = std::max(intel_acc.cycles_vcs, intel_part.cycles_vcs);
      intel_acc.total_vcs  = std::max(intel_acc.total_vcs,  intel_part.total_vcs);
      amd_acc.gfx_ns      = std::max(amd_acc.gfx_ns,     amd_part.gfx_ns);
      amd_acc.compute_ns  = std::max(amd_acc.compute_ns, amd_part.compute_ns);
      amd_acc.enc_ns      = std::max(amd_acc.enc_ns,     amd_part.enc_ns);
      amd_acc.dec_ns      = std::max(amd_acc.dec_ns,     amd_part.dec_ns);
      if (vram_kb_part > 0) vram_kb = vram_kb_part;
    }
    if (!saw_drm) continue;
    running_pids.insert(pid);
    if (vram_kb > 0) pid_to_gpu_mem_kb[pid] = vram_kb;
    // Compute utilization using deltas vs last
    auto itlast = last_.find(pid);
    if (itlast == last_.end()) {
      // Store baseline
      last_[pid] = LastSample{intel_acc, amd_acc, now};
      continue;
    }
    auto last = itlast->second;
    int util_pct = 0;
    // Intel path: use cycles delta / total delta per engine; combine by max.
    auto pct_from = [](uint64_t num_d, uint64_t den_d)->int{
      if (den_d == 0) return 0;
      long double r = ((long double)num_d * 100.0L) / (long double)den_d;
      if (r < 0) r = 0;
      if (r > 100) r = 100;
      return (int)(r + 0.5L);
    };
    int rcs = 0, ccs = 0, vcs = 0;
    if (intel_acc.total_rcs && last.intel.total_rcs && intel_acc.total_rcs >= last.intel.total_rcs && intel_acc.cycles_rcs >= last.intel.cycles_rcs) {
      rcs = pct_from(intel_acc.cycles_rcs - last.intel.cycles_rcs, intel_acc.total_rcs - last.intel.total_rcs);
    }
    if (intel_acc.total_ccs && last.intel.total_ccs && intel_acc.total_ccs >= last.intel.total_ccs && intel_acc.cycles_ccs >= last.intel.cycles_ccs) {
      ccs = pct_from(intel_acc.cycles_ccs - last.intel.cycles_ccs, intel_acc.total_ccs - last.intel.total_ccs);
    }
    if (intel_acc.total_vcs && last.intel.total_vcs && intel_acc.total_vcs >= last.intel.total_vcs && intel_acc.cycles_vcs >= last.intel.cycles_vcs) {
      vcs = pct_from(intel_acc.cycles_vcs - last.intel.cycles_vcs, intel_acc.total_vcs - last.intel.total_vcs);
    }
    util_pct = std::max({util_pct, rcs, ccs, vcs});
    // AMD path: use busy nanoseconds delta / wall time delta in ns
    auto dt_ns = duration_cast<nanoseconds>(now - last.tp).count();
    if (dt_ns > 0) {
      auto pct_from_busy = [&](uint64_t cur, uint64_t prev)->int{
        if (cur >= prev) {
          uint64_t d = cur - prev;
          long double r = ((long double)d * 100.0L) / (long double)dt_ns;
          if (r < 0) r = 0;
          if (r > 100) r = 100;
          return (int)(r + 0.5L);
        }
        return 0;
      };
      int gfx = pct_from_busy(amd_acc.gfx_ns, last.amd.gfx_ns);
      int cmp = pct_from_busy(amd_acc.compute_ns, last.amd.compute_ns);
      int enc = pct_from_busy(amd_acc.enc_ns, last.amd.enc_ns);
      int dec = pct_from_busy(amd_acc.dec_ns, last.amd.dec_ns);
      util_pct = std::max({util_pct, gfx, cmp, enc, dec});
    }
    if (util_pct > 0) pid_to_gpu[pid] = util_pct;
    // Update baseline
    itlast->second = LastSample{intel_acc, amd_acc, now};
  }
  // Prune stale
  for (auto it = last_.begin(); it != last_.end(); ) {
    if (running_pids.find(it->first) == running_pids.end()) it = last_.erase(it); else ++it;
  }
  return any;
}

} // namespace montauk::collectors
