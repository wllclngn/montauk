#include "collectors/KernelProcessCollector.hpp"
#include "util/Procfs.hpp"

#include <cstring>
#include <cstdio>
#include <fstream>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <pwd.h>

namespace montauk::collectors {

// Mirror definitions from kernel module's montauk.h
#define MONTAUK_GENL_NAME       "MONTAUK"
#define MONTAUK_GENL_VERSION    1

enum montauk_cmd {
    MONTAUK_CMD_UNSPEC = 0,
    MONTAUK_CMD_GET_SNAPSHOT,
    MONTAUK_CMD_GET_STATS,
};

enum montauk_attr {
    MONTAUK_ATTR_UNSPEC = 0,
    MONTAUK_ATTR_PID,
    MONTAUK_ATTR_PPID,
    MONTAUK_ATTR_COMM,
    MONTAUK_ATTR_STATE,
    MONTAUK_ATTR_UTIME,
    MONTAUK_ATTR_STIME,
    MONTAUK_ATTR_RSS_PAGES,
    MONTAUK_ATTR_UID,
    MONTAUK_ATTR_THREADS,
    MONTAUK_ATTR_EXE_PATH,
    MONTAUK_ATTR_START_TIME,
    MONTAUK_ATTR_CMDLINE,
    MONTAUK_ATTR_PROC_ENTRY,
    MONTAUK_ATTR_PROC_COUNT,
};

// Netlink helpers
#define NLMSG_ALIGN_SIZE(len) (((len) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1))
#define NLA_ALIGN_SIZE(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
// NLA_HDRLEN and NLA_TYPE_MASK are defined in linux/netlink.h

struct genlmsghdr {
    uint8_t cmd;
    uint8_t version;
    uint16_t reserved;
};

KernelProcessCollector::KernelProcessCollector() = default;

KernelProcessCollector::~KernelProcessCollector() {
    shutdown();
}

bool KernelProcessCollector::init() {
    // Create netlink socket
    nl_sock_ = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (nl_sock_ < 0) {
        return false;
    }

    // Bind to local address
    struct sockaddr_nl addr{};
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = 0;

    if (bind(nl_sock_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(nl_sock_);
        nl_sock_ = -1;
        return false;
    }

    // Resolve the MONTAUK genetlink family ID
    if (!resolve_family()) {
        close(nl_sock_);
        nl_sock_ = -1;
        return false;
    }

    ncpu_ = read_cpu_count();
    return true;
}

void KernelProcessCollector::shutdown() {
    if (nl_sock_ >= 0) {
        close(nl_sock_);
        nl_sock_ = -1;
    }
    family_id_ = -1;
}

bool KernelProcessCollector::resolve_family() {
    // Build CTRL_CMD_GETFAMILY request
    char buf[256];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr));
    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = ++seq_;
    nlh->nlmsg_pid = getpid();

    struct genlmsghdr* ghdr = (struct genlmsghdr*)NLMSG_DATA(nlh);
    ghdr->cmd = CTRL_CMD_GETFAMILY;
    ghdr->version = 1;

    // Add family name attribute
    struct nlattr* nla = (struct nlattr*)((char*)ghdr + NLMSG_ALIGN_SIZE(sizeof(struct genlmsghdr)));
    nla->nla_type = CTRL_ATTR_FAMILY_NAME;
    nla->nla_len = NLA_HDRLEN + strlen(MONTAUK_GENL_NAME) + 1;
    memcpy((char*)nla + NLA_HDRLEN, MONTAUK_GENL_NAME, strlen(MONTAUK_GENL_NAME) + 1);

    nlh->nlmsg_len = NLMSG_ALIGN_SIZE(nlh->nlmsg_len) + NLA_ALIGN_SIZE(nla->nla_len);

    // Send request
    struct sockaddr_nl dest{};
    dest.nl_family = AF_NETLINK;
    dest.nl_pid = 0;  // Kernel

    if (sendto(nl_sock_, buf, nlh->nlmsg_len, 0,
               (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        return false;
    }

    // Receive response
    char rbuf[4096];
    ssize_t len = recv(nl_sock_, rbuf, sizeof(rbuf), 0);
    if (len < 0) {
        return false;
    }

    // Parse response to find family ID
    nlh = (struct nlmsghdr*)rbuf;
    if (!NLMSG_OK(nlh, (size_t)len) || nlh->nlmsg_type == NLMSG_ERROR) {
        return false;
    }

    ghdr = (struct genlmsghdr*)NLMSG_DATA(nlh);
    int attr_len = nlh->nlmsg_len - NLMSG_HDRLEN - sizeof(struct genlmsghdr);
    nla = (struct nlattr*)((char*)ghdr + sizeof(struct genlmsghdr));

    while (attr_len >= NLA_HDRLEN) {
        int nla_len = NLA_ALIGN_SIZE(nla->nla_len);
        if (nla->nla_type == CTRL_ATTR_FAMILY_ID) {
            family_id_ = *(uint16_t*)((char*)nla + NLA_HDRLEN);
            return true;
        }
        attr_len -= nla_len;
        nla = (struct nlattr*)((char*)nla + nla_len);
    }

    return false;
}

bool KernelProcessCollector::send_get_snapshot() {
    char buf[256];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr));
    nlh->nlmsg_type = family_id_;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = ++seq_;
    nlh->nlmsg_pid = getpid();

    struct genlmsghdr* ghdr = (struct genlmsghdr*)NLMSG_DATA(nlh);
    ghdr->cmd = MONTAUK_CMD_GET_SNAPSHOT;
    ghdr->version = MONTAUK_GENL_VERSION;

    struct sockaddr_nl dest{};
    dest.nl_family = AF_NETLINK;
    dest.nl_pid = 0;

    return sendto(nl_sock_, buf, nlh->nlmsg_len, 0,
                  (struct sockaddr*)&dest, sizeof(dest)) >= 0;
}

bool KernelProcessCollector::recv_snapshot(montauk::model::ProcessSnapshot& out) {
    // Large buffer for process list
    static char buf[1024 * 1024];  // 1MB should be enough
    ssize_t len = recv(nl_sock_, buf, sizeof(buf), 0);
    if (len < 0) {
        return false;
    }

    struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
    if (!NLMSG_OK(nlh, (size_t)len)) {
        return false;
    }

    if (nlh->nlmsg_type == NLMSG_ERROR) {
        return false;
    }

    struct genlmsghdr* ghdr = (struct genlmsghdr*)NLMSG_DATA(nlh);
    int attr_len = nlh->nlmsg_len - NLMSG_HDRLEN - sizeof(struct genlmsghdr);
    struct nlattr* nla = (struct nlattr*)((char*)ghdr + sizeof(struct genlmsghdr));

    uint64_t cpu_total = read_cpu_total();
    long page_size = sysconf(_SC_PAGESIZE);

    // Parse attributes
    while (attr_len >= NLA_HDRLEN) {
        if (nla->nla_len < NLA_HDRLEN || nla->nla_len > attr_len) {
            break;  // Invalid attribute length
        }
        int nla_payload = nla->nla_len - NLA_HDRLEN;
        int nla_len = NLA_ALIGN_SIZE(nla->nla_len);
        if (nla_len <= 0 || nla_len > attr_len) {
            break;  // Prevent infinite loop or buffer overrun
        }

        int attr_type = nla->nla_type & NLA_TYPE_MASK;
        if (attr_type == MONTAUK_ATTR_PROC_ENTRY && nla_payload > 0) {
            // Parse nested process entry
            montauk::model::ProcSample ps{};
            struct nlattr* inner = (struct nlattr*)((char*)nla + NLA_HDRLEN);
            int inner_len = nla_payload;

            while (inner_len >= NLA_HDRLEN) {
                if (inner->nla_len < NLA_HDRLEN || inner->nla_len > inner_len) {
                    break;  // Invalid inner attribute
                }
                int inner_nla_len = NLA_ALIGN_SIZE(inner->nla_len);
                if (inner_nla_len <= 0 || inner_nla_len > inner_len) {
                    break;  // Prevent infinite loop
                }
                char* data = (char*)inner + NLA_HDRLEN;

                switch (inner->nla_type) {
                case MONTAUK_ATTR_PID:
                    ps.pid = *(uint32_t*)data;
                    break;
                case MONTAUK_ATTR_PPID:
                    break;
                case MONTAUK_ATTR_COMM:
                    ps.cmd = std::string(data);
                    break;
                case MONTAUK_ATTR_STATE:
                    // State char stored for potential future use
                    break;
                case MONTAUK_ATTR_UTIME:
                    ps.utime = *(uint64_t*)data;
                    break;
                case MONTAUK_ATTR_STIME:
                    ps.stime = *(uint64_t*)data;
                    break;
                case MONTAUK_ATTR_RSS_PAGES:
                    ps.rss_kb = (*(uint64_t*)data) * (page_size / 1024);
                    break;
                case MONTAUK_ATTR_UID: {
                    uid_t uid = *(uint32_t*)data;
                    struct passwd* pw = getpwuid(uid);
                    if (pw && pw->pw_name) {
                        ps.user_name = pw->pw_name;
                    } else {
                        ps.user_name = std::to_string(uid);
                    }
                    break;
                }
                case MONTAUK_ATTR_THREADS:
                    // Thread count available for future use
                    break;
                case MONTAUK_ATTR_EXE_PATH:
                    ps.exe_path = std::string(data);
                    break;
                case MONTAUK_ATTR_START_TIME:
                    // Start time available for future use
                    break;
                case MONTAUK_ATTR_CMDLINE:
                    // Full command line overrides the short comm
                    ps.cmd = std::string(data);
                    break;
                }

                inner_len -= inner_nla_len;
                inner = (struct nlattr*)((char*)inner + inner_nla_len);
            }

            // Calculate CPU%
            ps.total_time = ps.utime + ps.stime;
            if (have_last_) {
                auto it = last_per_proc_.find(ps.pid);
                uint64_t last_proc = (it != last_per_proc_.end()) ? it->second : ps.total_time;
                uint64_t dp = (ps.total_time > last_proc) ? (ps.total_time - last_proc) : 0;
                uint64_t dt = (cpu_total > last_cpu_total_) ? (cpu_total - last_cpu_total_) : 0;
                if (dt > 0) {
                    ps.cpu_pct = (100.0 * (double)dp / (double)dt) * (double)ncpu_;
                }
            }

            out.processes.push_back(std::move(ps));
        } else if (attr_type == MONTAUK_ATTR_PROC_COUNT) {
            out.total_processes = *(uint32_t*)((char*)nla + NLA_HDRLEN);
        }

        attr_len -= nla_len;
        nla = (struct nlattr*)((char*)nla + nla_len);
    }

    // Update state for next delta calculation
    std::unordered_map<int32_t, uint64_t> next_last;
    for (const auto& p : out.processes) {
        next_last[p.pid] = p.total_time;
    }
    last_per_proc_ = std::move(next_last);
    last_cpu_total_ = cpu_total;
    have_last_ = true;

    // Sort by CPU%
    std::sort(out.processes.begin(), out.processes.end(),
              [](const auto& a, const auto& b) { return a.cpu_pct > b.cpu_pct; });

    out.tracked_count = out.processes.size();
    out.enriched_count = out.processes.size();  // All processes are "enriched" from kernel

    return true;
}

bool KernelProcessCollector::sample(montauk::model::ProcessSnapshot& out) {
    out = {};

    if (nl_sock_ < 0 || family_id_ < 0) {
        return false;
    }

    if (!send_get_snapshot()) {
        return false;
    }

    return recv_snapshot(out);
}

uint64_t KernelProcessCollector::read_cpu_total() {
    auto content = montauk::util::read_file_string("/proc/stat");
    if (!content) return 0;

    // Parse first line: cpu user nice system idle iowait irq softirq steal guest guest_nice
    uint64_t user=0, nice=0, system=0, idle=0, iowait=0, irq=0, softirq=0, steal=0;
    if (std::sscanf(content->c_str(), "cpu %lu %lu %lu %lu %lu %lu %lu %lu",
                    &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal) < 4) {
        return 0;
    }
    return user + nice + system + idle + iowait + irq + softirq + steal;
}

int KernelProcessCollector::read_cpu_count() {
    int count = 0;
    std::ifstream f("/proc/stat");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("cpu", 0) == 0 && line.size() > 3 && line[3] >= '0' && line[3] <= '9') {
            count++;
        }
    }
    return count > 0 ? count : 1;
}

} // namespace montauk::collectors
