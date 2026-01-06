# montauk-kernel

A Linux kernel module that provides real-time process telemetry for [montauk](https://github.com/wllclngn/montauk), the high-performance system monitor.

## Overview

montauk-kernel moves process data collection from userspace into the kernel, eliminating `/proc` parsing overhead and providing sub-millisecond event detection. When loaded and montauk is built with `-DMONTAUK_KERNEL=ON`, it automatically detects and uses the kernel backend.

### Why a Kernel Module?

Traditional process monitors work by:
1. Scanning `/proc` for PID directories
2. Reading `/proc/[pid]/stat`, `/proc/[pid]/status`, `/proc/[pid]/cmdline`
3. Parsing text output into structured data
4. Repeating every refresh cycle

This approach has fundamental limitations:
- **Race conditions**: Processes can exit between discovery and stat reading
- **Text parsing overhead**: The kernel formats data as text, userspace parses it back
- **Polling inefficiency**: Must re-scan even when nothing changed
- **Missing events**: Short-lived processes can spawn and exit between polls

montauk-kernel solves these by:
- Hooking directly into kernel process lifecycle events via kprobes (fork/exec/exit)
- Reading `task_struct` fields directly—no text formatting or parsing
- Maintaining an in-kernel process table (rhashtable) updated in real-time
- Background workqueue refreshes CPU times every 1 second
- Exporting structured binary data via Generic Netlink (genetlink)

### Performance Comparison

| Metric | /proc Polling | Netlink proc_connector | montauk-kernel |
|--------|---------------|------------------------|--------------|
| Event detection latency | 250-1000ms | <1ms | <1ms |
| Syscalls per refresh | ~3 per process | ~1 + events | 1 total |
| CPU overhead (1000 procs) | ~2-5% | ~0.5-1% | ~0.1-0.2% |
| Short-lived process capture | Often missed | Captured | Captured |
| Data accuracy | Race-prone | Event-accurate | Event-accurate |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           USERSPACE                                 │
│                                                                     │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │                        montauk                              │   │
│   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │   │
│   │  │   TUI       │  │  Sorting    │  │  Other Collectors   │  │   │
│   │  │  Renderer   │  │  Filtering  │  │  (CPU, Mem, GPU...) │  │   │
│   │  └─────────────┘  └─────────────┘  └─────────────────────┘  │   │
│   │                           │                                 │   │
│   │              ┌────────────┴────────────┐                    │   │
│   │              │   IProcessCollector     │                    │   │
│   │              └────────────┬────────────┘                    │   │
│   │                           │                                 │   │
│   │   ┌───────────────────────┼───────────────────────┐         │   │
│   │   │                       │                       │         │   │
│   │   ▼                       ▼                       ▼         │   │
│   │ ┌─────────────┐   ┌──────────────┐   ┌─────────────────┐    │   │
│   │ │ KernelProc  │   │ NetlinkProc  │   │ ProcessCollector│    │   │
│   │ │ Collector   │   │ Collector    │   │ (/proc scanner) │    │   │
│   │ │ [preferred] │   │ [fallback 1] │   │ [fallback 2]    │    │   │
│   │ └──────┬──────┘   └──────────────┘   └─────────────────┘    │   │
│   │        │                                                    │   │
│   └────────┼────────────────────────────────────────────────────┘   │
│            │                                                        │
│            │ Genetlink socket (AF_NETLINK + NETLINK_GENERIC)        │
│            │                                                        │
└────────────┼────────────────────────────────────────────────────────┘
             │
═════════════╪════════════════════════════════════════════════════════
   KERNEL    │
═════════════╪════════════════════════════════════════════════════════
             │
┌────────────┼────────────────────────────────────────────────────────┐
│            ▼                                                        │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │                     montauk-kernel                          │   │
│   │                                                             │   │
│   │   ┌─────────────────┐    ┌────────────────────────────┐     │   │
│   │   │  Genetlink      │    │     Process Table          │     │   │
│   │   │  Interface      │◄───│     (rhashtable)           │     │   │
│   │   │                 │    │                            │     │   │
│   │   │  MONTAUK_CMD_*  │    │  ┌──────────────────────┐  │     │   │
│   │   └─────────────────┘    │  │ struct montauk_proc  │  │     │   │
│   │                          │  │ - pid, ppid, comm    │  │     │   │
│   │                          │  │ - utime, stime       │  │     │   │
│   │                          │  │ - rss, state         │  │     │   │
│   │                          │  └──────────────────────┘  │     │   │
│   │                          └─────────────▲──────────────┘     │   │
│   │                                        │                    │   │
│   │   ┌────────────────────────────────────┴────────────────┐   │   │
│   │   │                   Kprobe Hooks                      │   │   │
│   │   │  wake_up_new_task ────── begin_new_exec             │   │   │
│   │   │  do_exit ────────────── (workqueue refresh @1Hz)    │   │   │
│   │   └─────────────────────────────────────────────────────┘   │   │
│   │                              │                              │   │
│   └──────────────────────────────┼──────────────────────────────┘   │
│                                  │                                  │
│                                  ▼                                  │
│   ┌──────────────────────────────────────────────────────────────┐  │
│   │                     Linux Scheduler                          │  │
│   │                     (task_struct)                            │  │
│   └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Installation

### Prerequisites

- Linux kernel 5.10 or later (tested up to 6.12)
- Kernel headers for your running kernel
- Build essentials (gcc, make)
- Optional: DKMS for automatic rebuilds on kernel upgrades

### Option A: DKMS (Recommended)

DKMS automatically rebuilds the module when you upgrade your kernel.

**Arch Linux:**
```bash
yay -S montauk-kernel-dkms
sudo systemctl enable montauk-kernel
sudo systemctl start montauk-kernel
```

**Debian/Ubuntu:**
```bash
sudo apt install montauk-kernel-dkms
sudo modprobe montauk
echo "montauk" | sudo tee /etc/modules-load.d/montauk.conf
```

**Fedora:**
```bash
sudo dnf install montauk-kernel-dkms
sudo modprobe montauk
```

### Option B: Manual Build

```bash
# Clone the repository
git clone https://github.com/wllclngn/montauk-kernel
cd montauk-kernel

# Build against running kernel
make

# Load the module (temporary, until reboot)
sudo insmod montauk.ko

# Or install persistently
sudo make install
sudo depmod -a
sudo modprobe montauk

# Auto-load at boot
echo "montauk" | sudo tee /etc/modules-load.d/montauk.conf
```

### Option C: Building for a Specific Kernel

```bash
# Build for a different kernel version
make KDIR=/lib/modules/6.12.0-arch1-1/build

# Cross-compile for another architecture
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- KDIR=/path/to/kernel
```

### Verifying Installation

```bash
# Check if module is loaded
lsmod | grep montauk

# Check module info
modinfo montauk

# Check dmesg for load messages
dmesg | grep montauk

# Verify montauk detects it
montauk --collector-info
```

Expected output:
```
$ lsmod | grep montauk
montauk                20480  0

$ dmesg | grep montauk
[  123.456789] montauk: initializing
[  123.456790] montauk: process tracepoints registered
[  123.456791] montauk: genetlink family registered
[  123.456792] montauk: loaded successfully (tracking 847 processes)

$ montauk --collector-info
Available collectors:
  [active] Kernel Module (montauk-kernel 0.1.0)
           Event-Driven Netlink
           Traditional /proc Scanner
```

---

## Usage

Once installed, **no configuration is required**. montauk automatically detects and uses the kernel module when available.

### Forcing a Specific Backend

For testing or debugging, you can force montauk to use a specific collector:

```bash
# Force kernel module (fail if unavailable; requires -DMONTAUK_KERNEL=ON build)
MONTAUK_COLLECTOR=kernel montauk

# Force netlink proc_connector
MONTAUK_COLLECTOR=netlink montauk

# Force traditional /proc scanning
MONTAUK_COLLECTOR=traditional montauk
```

### Module Parameters

```bash
# Load with custom parameters
sudo modprobe montauk max_procs=4096 debug=1

# Or set in /etc/modprobe.d/montauk.conf
echo "options montauk max_procs=4096" | sudo tee /etc/modprobe.d/montauk.conf
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_procs` | int | 8192 | Maximum processes to track |
| `debug` | bool | 0 | Enable verbose debug logging (to dmesg) |

Note: CPU times are refreshed by a kernel workqueue at 1Hz (once per second). This is not configurable as it provides optimal balance between accuracy and overhead.

### Runtime Information

Check module status via standard kernel interfaces:

```bash
# Module info
modinfo montauk

# Check if loaded
lsmod | grep montauk

# View kernel messages
dmesg | grep montauk

# Statistics via genetlink (use montauk or custom client)
# The module provides MONTAUK_CMD_GET_STATS command
```

---

## Protocol Specification

montauk-kernel communicates with userspace via Generic Netlink (genetlink). This section documents the protocol for developers who want to build alternative clients.

### Family Registration

- **Family Name**: `MONTAUK`
- **Version**: 1
- **Multicast Group**: `events` (for real-time subscriptions)

### Commands

#### MONTAUK_CMD_GET_SNAPSHOT (1)

Request a snapshot of all tracked processes.

**Request**: Empty payload

**Response**:
```
MONTAUK_ATTR_PROC_COUNT: u32        # Total processes in snapshot
MONTAUK_ATTR_PROC_ENTRY: nested[]   # Array of process entries (repeated)
    MONTAUK_ATTR_PID: u32
    MONTAUK_ATTR_PPID: u32
    MONTAUK_ATTR_COMM: string       # Command name (max 16 chars)
    MONTAUK_ATTR_STATE: u8          # Process state (R/S/D/Z/T)
    MONTAUK_ATTR_UTIME: u64         # User time in USER_HZ ticks
    MONTAUK_ATTR_STIME: u64         # System time in USER_HZ ticks
    MONTAUK_ATTR_RSS_PAGES: u64     # Resident set size in pages
    MONTAUK_ATTR_UID: u32           # User ID
    MONTAUK_ATTR_THREADS: u32       # Thread count
    MONTAUK_ATTR_START_TIME: u64    # Start time (ticks since boot)
    MONTAUK_ATTR_EXE_PATH: string   # Executable path (optional)
    MONTAUK_ATTR_CMDLINE: string    # Full command line (optional)
```

#### MONTAUK_CMD_GET_STATS (2)

Get module statistics.

**Response**:
```
MONTAUK_ATTR_STAT_TRACKED: u32      # Currently tracked processes
MONTAUK_ATTR_STAT_EVENTS_FORK: u64  # Total fork events since load
MONTAUK_ATTR_STAT_EVENTS_EXEC: u64  # Total exec events
MONTAUK_ATTR_STAT_EVENTS_EXIT: u64  # Total exit events
MONTAUK_ATTR_STAT_OVERFLOWS: u64    # Times max_procs limit was hit
MONTAUK_ATTR_STAT_UPTIME_SEC: u64   # Seconds since module load
```

### Attribute Types

| ID | Name | Type | Description |
|----|------|------|-------------|
| 1 | MONTAUK_ATTR_PID | NLA_U32 | Process ID |
| 2 | MONTAUK_ATTR_PPID | NLA_U32 | Parent process ID |
| 3 | MONTAUK_ATTR_COMM | NLA_NUL_STRING | Command name (max 16 bytes) |
| 4 | MONTAUK_ATTR_STATE | NLA_U8 | Process state character (R/S/D/Z/T) |
| 5 | MONTAUK_ATTR_UTIME | NLA_U64 | User CPU time (USER_HZ ticks) |
| 6 | MONTAUK_ATTR_STIME | NLA_U64 | System CPU time (USER_HZ ticks) |
| 7 | MONTAUK_ATTR_RSS_PAGES | NLA_U64 | Resident set size (pages) |
| 8 | MONTAUK_ATTR_UID | NLA_U32 | User ID |
| 9 | MONTAUK_ATTR_THREADS | NLA_U32 | Thread count |
| 10 | MONTAUK_ATTR_EXE_PATH | NLA_NUL_STRING | Executable path (max 256 bytes) |
| 11 | MONTAUK_ATTR_START_TIME | NLA_U64 | Process start time (ticks since boot) |
| 12 | MONTAUK_ATTR_CMDLINE | NLA_NUL_STRING | Full command line (max 256 bytes) |
| 13 | MONTAUK_ATTR_PROC_ENTRY | NLA_NESTED | Container for process attrs |
| 14 | MONTAUK_ATTR_PROC_COUNT | NLA_U32 | Total process count |
| 15 | MONTAUK_ATTR_STAT_TRACKED | NLA_U32 | Currently tracked processes |
| 16 | MONTAUK_ATTR_STAT_FORKS | NLA_U64 | Total fork events since load |
| 17 | MONTAUK_ATTR_STAT_EXECS | NLA_U64 | Total exec events |
| 18 | MONTAUK_ATTR_STAT_EXITS | NLA_U64 | Total exit events |
| 19 | MONTAUK_ATTR_STAT_OVERFLOWS | NLA_U64 | Times max_procs limit hit |
| 20 | MONTAUK_ATTR_STAT_UPTIME_SEC | NLA_U64 | Seconds since module load |

### Example Client (C with libnl)

```c
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#define MONTAUK_GENL_NAME "MONTAUK"
#define MONTAUK_CMD_GET_SNAPSHOT 1

int main(void)
{
    struct nl_sock *sock;
    struct nl_msg *msg;
    int family_id;
    
    // Connect
    sock = nl_socket_alloc();
    genl_connect(sock);
    
    // Resolve family
    family_id = genl_ctrl_resolve(sock, MONTAUK_GENL_NAME);
    if (family_id < 0) {
        fprintf(stderr, "montauk module not loaded\n");
        return 1;
    }
    
    // Build request
    msg = nlmsg_alloc();
    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0, 0,
                MONTAUK_CMD_GET_SNAPSHOT, 1);
    
    // Send and receive
    nl_send_auto(sock, msg);
    nl_recvmsgs_default(sock);  // Calls your callback
    
    nlmsg_free(msg);
    nl_socket_free(sock);
    return 0;
}
```

---

## Internals

### Process Table Implementation

The module maintains a resizable hashtable (`rhashtable`) keyed by PID:

```c
struct montauk_proc {
    struct rhash_head   node;       // Hash linkage
    refcount_t          refcnt;     // Reference count
    
    pid_t               pid;
    pid_t               ppid;
    char                comm[16];
    u64                 utime;
    u64                 stime;
    u64                 start_time;
    unsigned long       rss_pages;
    char                state;
    
    struct rcu_head     rcu;        // RCU callback head
};
```

### Concurrency Model

- **Read path** (snapshot export): RCU read-side lock, no blocking
- **Write path** (fork/exec/exit): Spinlock per-bucket via rhashtable
- **Memory reclamation**: RCU callback (`kfree_rcu`)

This allows snapshot requests to proceed concurrently with high-frequency process events without blocking.

### Kprobe Hooks

The module uses kprobes (not tracepoints) because scheduler tracepoints aren't exported for out-of-tree modules:

| Kprobe Symbol | Trigger | Action |
|---------------|---------|--------|
| `wake_up_new_task` | After fork(), when new task is scheduled | Insert child into table |
| `begin_new_exec` | During execve() | Update comm, clear exe_path |
| `do_exit` | Process termination | Remove from table |

**Why kprobes instead of tracepoints?**

Tracepoints like `sched_process_fork` exist but their registration symbols (`__tracepoint_sched_process_fork`) aren't exported to modules. Kprobes attach to any non-inlined kernel function without requiring symbol exports.

### Background Refresh

A kernel workqueue runs every 1 second (HZ jiffies) to refresh:
- `utime` / `stime` (CPU times)
- `state` (R/S/D/Z/T)
- `nr_threads` (thread count)
- `rss_pages` (memory usage)

This decouples data freshness from userspace snapshot requests—snapshots just dump cached data with zero lookups.

### Memory Limits

To prevent unbounded growth:
- Default limit: 8192 tracked processes (`max_procs` parameter)
- When limit is reached: New processes are not tracked (overflow counter incremented)
- Existing processes continue to be tracked normally
- Check overflow count via `MONTAUK_CMD_GET_STATS` to detect if limit is being hit

### CPU Time Export

The kernel module exports raw CPU times in USER_HZ ticks (typically 100 ticks/second):
- `utime`: User-mode CPU time
- `stime`: Kernel-mode CPU time

Userspace (montauk) calculates CPU percentages by:
1. Recording times at snapshot N
2. Recording times at snapshot N+1
3. Computing delta: `(utime_delta + stime_delta) / elapsed_ticks * 100`

This matches htop/top methodology. The kernel refreshes these values every 1 second via the background workqueue.

---

## Troubleshooting

### Module Won't Load

**Symptom**: `insmod: ERROR: could not insert module`

**Common causes**:

1. **Kernel version mismatch**
   ```bash
   # Check if module was built for this kernel
   modinfo montauk.ko | grep vermagic
   uname -r
   # If different, rebuild: make clean && make
   ```

2. **Secure Boot enabled**
   ```bash
   # Check secure boot status
   mokutil --sb-state
   # Either disable secure boot or sign the module
   ```

3. **Missing kernel headers**
   ```bash
   # Install headers
   sudo apt install linux-headers-$(uname -r)  # Debian/Ubuntu
   sudo dnf install kernel-devel               # Fedora
   sudo pacman -S linux-headers                # Arch
   ```

### Module Loads but montauk Doesn't Use It

**Symptom**: montauk shows `[collector: Event-Driven Netlink]` instead of `[collector: Kernel Module]`

**Check**:
```bash
# Is the module actually loaded?
lsmod | grep montauk

# Is genetlink family registered?
cat /sys/kernel/debug/netlink/genl_family | grep MONTAUK

# Try forcing kernel backend to see error
MONTAUK_COLLECTOR=kernel montauk
```

### High CPU Usage from Module

**Symptom**: `ksoftirqd` or module itself using significant CPU

**Likely cause**: Fork bomb or very high process churn

**Solution**:
```bash
# Check event rate
cat /sys/kernel/montauk/stats | grep events

# If very high, you may have a fork bomb
# The module is working correctly, just busy

# Reduce tracked process limit if needed
sudo rmmod montauk
sudo modprobe montauk max_procs=1024
```

### Kernel Oops/Panic

**If the module causes a kernel crash**:

1. Capture the oops message from dmesg or serial console
2. Note the kernel version and module version
3. File a bug report with the stack trace
4. Reboot without the module: add `module_blacklist=montauk` to kernel cmdline

---

## Development

### Building with Debug Symbols

```bash
make DEBUG=1
```

### Running Tests

```bash
# Load module and run test suite
sudo insmod montauk.ko debug=1
make test
sudo rmmod montauk
```

### Code Style

The module follows Linux kernel coding style:
- Tabs for indentation (8 spaces wide)
- 80-column limit (soft)
- `/* C89 comments */`
- See `Documentation/process/coding-style.rst` in kernel source

### Submitting Patches

1. Fork the repository
2. Create a feature branch
3. Make changes with clear commit messages
4. Run the test suite
5. Submit a pull request

---

## FAQ

**Q: Does this require root to use montauk?**

A: No. The kernel module runs as root, but montauk connects via Netlink which is available to unprivileged users. However, loading/unloading the module requires root.

**Q: Will this work in a container?**

A: The module must be loaded on the host. Containers can use montauk with the kernel backend if the host has it loaded, but they cannot load modules themselves (unless privileged).

**Q: What about WSL2?**

A: WSL2 uses a real Linux kernel, so montauk-kernel can work if you build a custom WSL kernel with module support. The default WSL kernel doesn't allow loading external modules.

**Q: Is this safe for production?**

A: The module is designed to be safe and minimally invasive. It only reads data and doesn't modify kernel behavior. However, any kernel module carries inherent risk—test thoroughly in your environment first.

**Q: How does this compare to eBPF-based tools?**

A: eBPF tools like `bpftrace` or BCC are more flexible but require runtime compilation or CO-RE support. montauk-kernel is a single compiled module with no runtime dependencies beyond the kernel itself. It uses kprobes (the same mechanism eBPF uses for kprobe programs) but without the eBPF verifier overhead.

**Q: Can I use this on embedded systems?**

A: Yes, if the system runs a compatible Linux kernel. Cross-compile with appropriate `ARCH` and `CROSS_COMPILE` settings.

---

## License

montauk-kernel is licensed under the GNU General Public License v2 (GPL-2.0).

This is required because the module uses kernel APIs that are marked GPL-only (tracepoints, genetlink, rhashtable).

---

## Acknowledgments

- The Linux kernel community for excellent documentation
- Linus Torvalds for Linux
- The htop/btop projects for inspiration

---

## Links

- [montauk (userspace)](https://github.com/wllclngn/montauk)
- [montauk-kernel (kernel module)](https://github.com/wllclngn/montauk-kernel)
- [Linux Kernel Documentation](https://www.kernel.org/doc/html/latest/)
- [Generic Netlink HOWTO](https://wiki.linuxfoundation.org/networking/generic_netlink_howto)
