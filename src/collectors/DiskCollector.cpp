#include "collectors/DiskCollector.hpp"
#include "collectors/ProcessParsing.hpp"
#include "util/Procfs.hpp"
#include <charconv>
#include <string_view>

namespace montauk::collectors {

bool DiskCollector::sample(montauk::model::DiskSnapshot& out) {
  auto txt_opt = montauk::util::read_file_string("/proc/diskstats");
  if (!txt_opt) return false;
  const std::string& txt = *txt_opt; out.devices.clear(); out.total_read_bps = out.total_write_bps = 0.0;
  double ts = now_secs();
  size_t start = 0;
  while (start < txt.size()) {
    size_t lend = txt.find('\n', start);
    if (lend == std::string::npos) lend = txt.size();
    std::string_view line(txt.data() + start, lend - start);
    start = lend + 1;
    // fields: major minor name rd rdmerge rdsec rdtm wr wrmerge wrsec wrtm inprog tios wtm
    std::string_view tok[14];
    size_t pos = 0; int n = 0;
    while (pos < line.size() && n < 14) {
      while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) ++pos;
      size_t fend = pos;
      while (fend < line.size() && line[fend] != ' ' && line[fend] != '\t') ++fend;
      if (fend > pos) tok[n++] = line.substr(pos, fend - pos);
      pos = fend;
    }
    if (n < 14) continue;
    auto parse_u64 = [](std::string_view t, uint64_t& v) {
      auto [p, ec] = std::from_chars(t.data(), t.data() + t.size(), v);
      return ec == std::errc{} && p == t.data() + t.size();
    };
    uint64_t majmin = 0, nums[11]{};
    if (!parse_u64(tok[0], majmin) || !parse_u64(tok[1], majmin)) continue; // major/minor must be numeric
    bool ok = true;
    for (int i = 0; i < 11; ++i) {
      if (!parse_u64(tok[i + 3], nums[i])) { ok = false; break; }
    }
    if (!ok) continue;
    std::string_view name = tok[2];
    if (name.starts_with("loop") || name.starts_with("ram")) continue; // skip virtual
    uint64_t rdsec = nums[2], wrsec = nums[6], tios = nums[9];
    montauk::model::DiskDev d; d.name = std::string(name);
    auto it = last_.find(d.name);
    if (it != last_.end()) {
      auto& p = it->second; double dt = ts - p.ts; if (dt<=0.0) dt=1.0;
      // Guard against counter reset/wrap (device re-plug, stats reset): a
      // backwards counter yields a zero-rate frame, not an astronomical spike.
      if (rdsec >= p.rdsec) d.read_bps = static_cast<double>((rdsec - p.rdsec) * kSectorSize) / dt;
      if (wrsec >= p.wrsec) d.write_bps = static_cast<double>((wrsec - p.wrsec) * kSectorSize) / dt;
      if (tios >= p.tios) {
        double dioms = static_cast<double>(tios - p.tios); // time spent doing I/O during interval (ms)
        d.util_pct = std::min(100.0, (dioms / (dt * 1000.0)) * 100.0);
      }
      out.total_read_bps += d.read_bps; out.total_write_bps += d.write_bps;
    }
    last_[d.name] = Prev{rdsec, wrsec, tios, ts};
    out.devices.push_back(std::move(d));
  }
  return true;
}

} // namespace montauk::collectors
