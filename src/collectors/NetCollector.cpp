#include "collectors/NetCollector.hpp"
#include "collectors/ProcessParsing.hpp"
#include "util/Procfs.hpp"
#include <charconv>
#include <string_view>

namespace montauk::collectors {

bool NetCollector::sample(montauk::model::NetSnapshot& out) {
  auto txt_opt = montauk::util::read_file_string("/proc/net/dev");
  if (!txt_opt) return false;
  const std::string& txt = *txt_opt;
  out.interfaces.clear(); out.agg_rx_bps = out.agg_tx_bps = 0.0;
  int line_no = 0; double ts = now_secs();
  size_t start = 0;
  while (start < txt.size()) {
    size_t end = txt.find('\n', start);
    if (end == std::string::npos) end = txt.size();
    std::string_view line(txt.data() + start, end - start);
    start = end + 1;
    ++line_no; if (line_no <= 2) continue; // headers
    // format: iface: rx_bytes ... tx_bytes ...
    auto colon = line.find(':'); if (colon == std::string_view::npos) continue;
    std::string_view name_sv = line.substr(0, colon);
    while (!name_sv.empty() && name_sv.front() == ' ') name_sv.remove_prefix(1);
    if (name_sv.starts_with("lo") || name_sv.starts_with("veth") || name_sv.starts_with("docker") || name_sv.starts_with("br-") || name_sv.starts_with("virbr"))
      continue;
    // rx bytes is the 1st number after ':', tx bytes the 9th
    std::string_view rest = line.substr(colon + 1);
    uint64_t rx_bytes = 0, tx_bytes = 0;
    size_t pos = 0; int field = 0;
    while (pos < rest.size() && field < 9) {
      while (pos < rest.size() && (rest[pos] == ' ' || rest[pos] == '\t')) ++pos;
      size_t fend = pos;
      while (fend < rest.size() && rest[fend] != ' ' && rest[fend] != '\t') ++fend;
      if (fend > pos) {
        if (field == 0) std::from_chars(rest.data() + pos, rest.data() + fend, rx_bytes);
        else if (field == 8) std::from_chars(rest.data() + pos, rest.data() + fend, tx_bytes);
        ++field;
      }
      pos = fend;
    }
    montauk::model::NetIf nif; nif.name = std::string(name_sv); nif.rx_bytes = rx_bytes; nif.tx_bytes = tx_bytes; nif.last_ts = ts;
    if (auto it = last_.find(nif.name); it != last_.end()) {
      const auto& p = it->second;
      double dt = ts - p.last_ts; if (dt <= 0.0) dt = 1.0;
      // Guard against counter reset/wrap (interface re-created, driver reload):
      // a backwards counter yields a zero-rate frame, not an astronomical spike.
      if (rx_bytes >= p.rx_bytes) nif.rx_bps = static_cast<double>(rx_bytes - p.rx_bytes) / dt;
      if (tx_bytes >= p.tx_bytes) nif.tx_bps = static_cast<double>(tx_bytes - p.tx_bytes) / dt;
    }
    out.agg_rx_bps += nif.rx_bps; out.agg_tx_bps += nif.tx_bps;
    out.interfaces.push_back(nif);
  }
  last_.clear();
  for (const auto& nif : out.interfaces) last_.emplace(nif.name, nif);
  return true;
}

} // namespace montauk::collectors
