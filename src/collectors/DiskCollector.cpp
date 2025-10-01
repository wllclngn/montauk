#include "collectors/DiskCollector.hpp"
#include "util/Procfs.hpp"
#include <chrono>
#include <sstream>

using namespace std::chrono;

namespace lsm::collectors {

static double now_secs() {
  return duration_cast<duration<double>>(steady_clock::now().time_since_epoch()).count();
}

bool DiskCollector::sample(lsm::model::DiskSnapshot& out) {
  auto txt_opt = lsm::util::read_file_string("/proc/diskstats");
  if (!txt_opt) return false;
  const std::string& txt = *txt_opt; out.devices.clear(); out.total_read_bps = out.total_write_bps = 0.0;
  std::istringstream ss(txt); std::string line; double ts = now_secs();
  while (std::getline(ss, line)) {
    std::istringstream ls(line);
    unsigned major=0, minor=0; std::string name;
    uint64_t rd=0, rdmerge=0, rdsec=0, rdtm=0, wr=0, wrmerge=0, wrsec=0, wrtm=0, inprog=0, tios=0, wtm=0;
    if (!(ls>>major>>minor>>name>>rd>>rdmerge>>rdsec>>rdtm>>wr>>wrmerge>>wrsec>>wrtm>>inprog>>tios>>wtm)) continue;
    if (name.rfind("loop",0)==0 || name.rfind("ram",0)==0) continue; // skip virtual
    lsm::model::DiskDev d; d.name=name; d.reads_completed=rd; d.writes_completed=wr; d.sectors_read=rdsec; d.sectors_written=wrsec; d.time_in_io_ms=tios;
    auto it = last_.find(name);
    if (it != last_.end()) {
      auto& p = it->second; double dt = ts - p.ts; if (dt<=0.0) dt=1.0;
      double rbytes = static_cast<double>((rdsec - p.rdsec) * kSectorSize);
      double wbytes = static_cast<double>((wrsec - p.wrsec) * kSectorSize);
      d.read_bps = rbytes / dt; d.write_bps = wbytes / dt;
      double dioms = static_cast<double>(tios - p.tios); // time spent doing I/O during interval (ms)
      d.util_pct = std::min(100.0, (dioms / (dt * 1000.0)) * 100.0);
      out.total_read_bps += d.read_bps; out.total_write_bps += d.write_bps;
    }
    last_[name] = Prev{rd,wr,rdsec,wrsec,tios,wtm,ts};
    out.devices.push_back(d);
  }
  return true;
}

} // namespace lsm::collectors
