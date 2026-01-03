#include "collectors/NetCollector.hpp"
#include "util/Procfs.hpp"
#include <chrono>
#include <sstream>

using namespace std::chrono;

namespace montauk::collectors {

static double now_secs() {
  return duration_cast<duration<double>>(steady_clock::now().time_since_epoch()).count();
}

bool NetCollector::sample(montauk::model::NetSnapshot& out) {
  auto txt_opt = montauk::util::read_file_string("/proc/net/dev");
  if (!txt_opt) return false;
  const std::string& txt = *txt_opt;
  out.interfaces.clear(); out.agg_rx_bps = out.agg_tx_bps = 0.0;
  std::istringstream ss(txt);
  std::string line; int line_no = 0; double ts = now_secs();
  while (std::getline(ss, line)) {
    ++line_no; if (line_no <= 2) continue; // headers
    // format: iface: rx_bytes ... tx_bytes ...
    auto colon = line.find(':'); if (colon == std::string::npos) continue;
    std::string name = line.substr(0, colon);
    // trim spaces
    while (!name.empty() && name.front() == ' ') name.erase(name.begin());
    if (name.rfind("lo",0)==0 || name.rfind("veth",0)==0 || name.rfind("docker",0)==0 || name.rfind("br-",0)==0 || name.rfind("virbr",0)==0)
      continue;
    std::istringstream ns(line.substr(colon+1));
    uint64_t rx_bytes=0, tx_bytes=0; // positions: 1st and 9th numbers
    ns >> rx_bytes; // rx bytes
    for (int i=0;i<7;i++){ uint64_t tmp; ns >> tmp; }
    ns >> tx_bytes; // tx bytes
    montauk::model::NetIf nif; nif.name = name; nif.rx_bytes = rx_bytes; nif.tx_bytes = tx_bytes; nif.last_ts = ts;
    // find previous
    for (auto& p: last_) {
      if (p.name == name) {
        double dt = ts - p.last_ts; if (dt <= 0.0) dt = 1.0;
        double dr = static_cast<double>(rx_bytes - p.rx_bytes);
        double dtb= static_cast<double>(tx_bytes - p.tx_bytes);
        nif.rx_bps = dr / dt; nif.tx_bps = dtb / dt; break;
      }
    }
    out.agg_rx_bps += nif.rx_bps; out.agg_tx_bps += nif.tx_bps;
    out.interfaces.push_back(nif);
  }
  last_ = out.interfaces;
  return true;
}

} // namespace montauk::collectors

