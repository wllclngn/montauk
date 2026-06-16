```
███╗   ███╗  ██████╗  ███╗   ██╗ ████████╗  █████╗  ██╗   ██╗ ██╗  ██╗
████╗ ████║ ██╔═══██╗ ████╗  ██║ ╚══██╔══╝ ██╔══██╗ ██║   ██║ ██║ ██╔╝
██╔████╔██║ ██║   ██║ ██╔██╗ ██║    ██║    ███████║ ██║   ██║ █████╔╝ 
██║╚██╔╝██║ ██║   ██║ ██║╚██╗██║    ██║    ██╔══██║ ██║   ██║ ██╔═██╗ 
██║ ╚═╝ ██║ ╚██████╔╝ ██║ ╚████║    ██║    ██║  ██║ ╚██████╔╝ ██║  ██╗
╚═╝     ╚═╝  ╚═════╝  ╚═╝  ╚═══╝    ╚═╝    ╚═╝  ╚═╝  ╚═════╝  ╚═╝  ╚═╝
```

## Overview

A standalone, offline-friendly C++23 system monitor for Linux with comprehensive GPU support, event-driven process monitoring, and Prometheus metrics export. sublimation — montauk's sort algorithm — is an in-tree sub-system (`montauk/sublimation/`), built with montauk; NVML and liburing are auto-detected and optional.

**Key Features:**
- **Event-Driven Monitoring**: Kernel-based process event tracking with 90%+ reduction in system overhead
- **Deep GPU Integration**: Per-process GPU utilization and memory tracking with intelligent attribution
- **Multi-vendor Support**: NVIDIA (NVML + fallbacks), AMD (sysfs), Intel (fdinfo)
- **Sophisticated Attribution**: Multiple fallback mechanisms for GPU metrics when vendor APIs are unavailable
- **Prometheus Metrics Endpoint**: Optional HTTP `/metrics` endpoint serving Prometheus exposition format over io_uring, enabling integration with Prometheus, Grafana, and Kubernetes monitoring stacks
- **eBPF Process Group Tracing**: `--trace PATTERN` attaches eBPF programs to kernel tracepoints and libc uprobes for real-time per-thread syscall, scheduler state and decision, fd tracking, file I/O, heap allocation, mmap, and signal/abort capture across an entire process tree — event-driven, non-invasive, no ptrace, with continuous flight recording via Prometheus logs
- **Hardware Performance Counters**: Trace mode samples per-CPU L2 cache misses/references, instructions, cycles (IPC), and per-CCX L3 access/miss via `perf_event_open`, exported as `montauk_pmu_*` gauges for cache-placement analysis. Trace-gated — the plain monitor never opens a counter and needs no perf permissions
- **External Metrics Providers**: Scrapes Prometheus-text from external programs over unix sockets in `$XDG_RUNTIME_DIR/montauk/providers/` — their self-reported internals pass through montauk's own exposition and embed inline in trace captures, correlating an app's own view against the kernel events montauk observes
- **Binary Trace Log + Analysis Suite**: `--trace-out FILE` records raw events with near-zero observer effect (batched writes, no per-event formatting); `montauk_trace_decode` renders them to text/CSV and `montauk_analyze` runs single-pass diagnostic reports — heap double-free, livelock/spin, abort post-mortem, end-state stall — over captures reaching 450 MB+
- **Headless Daemon Mode**: Run without TUI as a pure metrics exporter (`--headless --metrics PORT`)
- **Structured Logging**: Timestamped Prometheus exposition snapshots to disk (`--log DIR`)
- **Live Process Search**: Boyer-Moore-Horspool substring search with branchless ASCII lowercasing via `/` or `Ctrl+F`
- **Thompson NFA Regex Engine**: RE2-style regex with UTF-8 byte lowering for pattern-based process classification
- **Thermal Monitoring**: Multi-sensor temperature tracking (edge, hotspot, memory) with vendor-specific thresholds
- **Process Tracking**: Up to 256 processes with full command-line enrichment for accurate identification
- **Atomic Snapshots**: Minimal CPU overhead with lock-free snapshot publication
- **Lean Dependencies**: sublimation (montauk's sort algorithm) is an in-tree sub-system, built with montauk — no fetch, no system package; NVML and liburing auto-detected and optional
- **Churn Resilient**: Real-time churn detection and dynamic display during heavy system activity
- **ANSI Color Support**: Intelligent escape sequence handling with full truecolor support
- **TOML Configuration**: Unified `~/.config/montauk/config.toml` with palette detection, configurable keybindings, and env var fallback
- **Dynamic Layout**: All panels fill available vertical space automatically
- **Security Monitoring**: Process security analysis with severity-based highlighting
- **Three Display Modes**: Default (pixel-rendered area-chart right column over PROCESS MONITOR), SYSTEM focus (text-detail panel replacing the chart stack), and CPU TOPOLOGY (per-core mini-chart grid replacing PROCESS MONITOR) — each toggle-driven, mutually exclusive in their respective columns, no flicker on switch
- **Cell-Based UI Architecture**: OUROBOROS-derived Canvas/Component/FlexLayout pipeline — every cell is structurally clipped, no padded-string rendering, no rubberbanding on resize
- **Pixel-Rendered Charts**: Monotone cubic Hermite area charts with anti-aliased line + fill, transmitted via Kitty `t=t` /dev/shm temp-file (no PTY saturation) or Sixel fallback
- **Per-Core Topology View**: Shift+C replaces PROCESS MONITOR with a dynamic grid of bordered boxes — one per logical CPU — each rendering a pixel-rasterized area chart of that core's last-N-seconds utilization (with live util% in every box title). Grid geometry auto-fills both axes; high-core-count systems fall into a scrollable layout at minimum cell height. Same Kitty/Sixel substrate as the right-column charts.

## Kernel Module (Optional)

For maximum efficiency, montauk includes an optional kernel module (`montauk-kernel`) that eliminates all `/proc` parsing overhead. When loaded, montauk automatically detects and uses it.

**Benefits over userspace collectors:**
- Zero `/proc` reads as data comes directly from kernel `task_struct`
- Zero proc_connector via Netlink traffic event stream as kprobes update the table directly
- Single genetlink call per snapshot; subverts ~3 syscalls per process with /proc, or 1 + N events with proc_connector
- Sub-millisecond process event detection via kprobes
- Background CPU time refresh via kernel workqueue (1Hz)
- ~0.1-0.2% CPU overhead via kernel utilization; ~0.5-1% via proc_connector, ~2-5% via /proc polling

## Screenshots

### Main Interface
![Main](screenshot-default.png)

Default view. PROCESS MONITOR on the left; pixel-rendered area charts (PROCESSOR, GPU, VRAM, GPU MEM, ENC, DEC, MEMORY, NETWORK) stacked on the right. Charts emit through Kitty's `t=t` /dev/shm transport (Sixel fallback) and update at 1 Hz over a 60-second rolling window.

### SYSTEM Focus (`s`)
![SYSTEM](screenshot-system.png)

`s` swaps the right-column chart stack for a comprehensive text panel: identity (hostname, kernel, uptime), runtime (collector, scheduler, process states), CPU (model, threads, freq/governor, load avg, ctxt-sw rate), GPU (model, util, NVML, power, p-state), memory, disk I/O, network, thermal margins, and process-security findings — severity-coloured in place.

### CPU Topology (`Shift+C`)
![Topology](screenshot-topology.png)

`Shift+C` swaps PROCESS MONITOR for a dynamic grid of bordered boxes — one per logical CPU. Each box renders a pixel-rasterized area chart of that core's last-N-seconds utilization (60s default, configurable via `[chart] history_seconds`), with live util% centered on the top border. Grid columns auto-fit to the rect (target ~2.5:1 cell aspect); high-core-count systems fall into scroll mode at minimum cell height. Same monotone-cubic AA rasterizer and Kitty/Sixel emit path as the right-column charts. Right column (charts or SYSTEM focus) is unaffected by the toggle.

## Installation

### Simple Install

```bash
./install.py
```

### Advanced Install (CMake)

```bash
# Configure
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build -j$(nproc)

# Install (optional)
sudo cmake --install build
```

liburing is auto-detected at configure time. If present, the Prometheus metrics endpoint is enabled. If absent, montauk builds without it (no functional impact on the TUI).

### Other Commands

```bash
./install.py build      # Build only, don't install
./install.py clean      # Clean build directory
./install.py uninstall  # Remove installed binary
./install.py test       # Run tests
./install.py --kernel   # Build with kernel module support
./install.py --debug    # Debug build
```

### Arch Linux Package

```bash
makepkg -si   # From PKGBUILD in pkg/ directory
```

**Process Collection Modes:**

montauk supports three collection backends (auto-detected in this priority):

1. **Kernel Module** — Best. Zero /proc reads, zero proc_connector traffic. Requires `montauk.ko` loaded.
2. **Netlink proc_connector** — Good. Receives fork/exec/exit events from kernel, but still reads `/proc/[pid]/*` for process details. Requires `CAP_NET_ADMIN`.
3. **Traditional /proc polling** — Fallback. Scans `/proc` directory each cycle.

To enable netlink proc_connector (when kernel module isn't loaded):
```bash
sudo setcap cap_net_admin=ep /usr/local/bin/montauk
```

Without this capability (and without the kernel module), montauk falls back to traditional /proc scanning.

**Force collector mode** (for testing):
```bash
MONTAUK_COLLECTOR=kernel ./montauk      # Force kernel module (requires montauk.ko)
MONTAUK_COLLECTOR=netlink ./montauk     # Force event-driven (requires capability)
MONTAUK_COLLECTOR=traditional ./montauk  # Force traditional polling
```

**Quick Start:**
```bash
cd montauk-kernel
./install.py
```

This builds the kernel module, installs it, sets up auto-load at boot, and rebuilds montauk with kernel support.

**Verify:**
```bash
lsmod | grep montauk
sudo dmesg | grep montauk
```

**Module Parameters:**
```bash
# Custom settings
sudo modprobe montauk max_procs=4096 debug=1

# Persistent config
echo "options montauk max_procs=4096" | sudo tee /etc/modprobe.d/montauk.conf
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_procs` | 8192 | Maximum processes to track |
| `debug` | false | Enable verbose kernel logging |

**Unload:**
```bash
sudo rmmod montauk
```

See `montauk-kernel/README.md` for full documentation including architecture, protocol specification, and troubleshooting.

## Operating Modes

montauk supports four operating modes via composable CLI flags:

```bash
montauk                                # TUI only (default)
montauk --metrics 9101                 # TUI + Prometheus endpoint on :9101
montauk --log /var/log/montauk         # TUI + Prometheus-format log files
montauk --log /var/log/montauk --log-interval-ms 5000  # Custom write interval (default: 1000ms)
montauk --headless --metrics 9101      # Daemon mode: Prometheus only, no TUI
montauk --headless --log /var/log/montauk              # Daemon mode: logging only
montauk --headless --metrics 9101 --log /var/log/montauk  # Daemon mode: both
montauk --headless                     # Error: requires --metrics or --log
montauk --trace firefox                # Trace mode: per-thread diagnostics for process group
montauk --trace myapp --metrics 9101   # Trace mode + Prometheus endpoint
montauk --trace myapp --log /tmp/trace # Trace mode + flight recorder
montauk --trace myapp --trace-out t.bin # Trace mode + raw binary event log
montauk_trace_decode t.bin             # Decode a binary log to text (--csv for CSV)
montauk_analyze t.bin --report waits   # Run an analysis report over a binary log
montauk --init-theme                   # Detect terminal palette, write config.toml
```

**Prometheus Metrics Endpoint:**

When `--metrics PORT` is specified, montauk serves Prometheus exposition format (text/plain; version=0.0.4) at `http://localhost:PORT/metrics`. The endpoint reads from the same lock-free SnapshotBuffers the TUI uses -- no mutexes, no additional overhead. All socket I/O is driven by io_uring.

Exported metric families (~55 gauges, all prefixed `montauk_`):
- CPU: aggregate, per-core, user/system/iowait/irq/steal breakdown, context switches, interrupts
- Memory: total/used/available/cached/buffers/swap (bytes), utilization percent
- Network: per-interface and aggregate rx/tx bytes/sec
- Disk: per-device read/write bytes/sec, utilization percent, aggregate totals
- Filesystem: per-mount total/used/available bytes, utilization percent
- Processes: total/running/sleeping/zombie counts, thread count
- Per-process top-N: CPU%, resident memory, GPU utilization, GPU memory (labeled by PID and command)
- GPU: per-device VRAM, temperatures, fan speed; aggregate VRAM, utilization, encoder/decoder, power

Requires liburing at build time. Without liburing, montauk compiles normally with the metrics endpoint disabled.

**Log Writer:**

When `--log DIR` is specified, montauk writes timestamped Prometheus exposition snapshots to disk. Files rotate hourly with the naming convention `montauk_YYYY-MM-DD_HH.prom`. Each block is prefixed with a `# montauk_scrape_timestamp_ms` comment for replay and analysis. The LogWriter reads from the same SnapshotBuffers as the TUI and metrics endpoint.

No additional dependencies required. Works independently of or alongside `--metrics`.

**Trace Mode (eBPF):**

When `--trace PATTERN` is specified, montauk enters headless trace mode powered by eBPF. It attaches BPF programs to kernel tracepoints (`sched_process_fork`, `sched_process_exec`, `sched_process_exit`, `raw_syscalls/sys_enter`, `raw_syscalls/sys_exit`, `sched_switch`, `sched_wakeup`, `signal_deliver`, scheduler-decision tracepoints, and syscall-specific tracepoints for fd/mmap tracking) and to libc uprobes (heap allocation, abort path) for real-time, event-driven instrumentation. No `/proc` scanning, no text parsing, no TOCTOU races.

montauk discovers and tracks processes through a four-layer approach, all event-driven with zero userspace roundtrip for the critical path:

1. **BPF-side exec matching** (v5.2.0): Pattern stored in a BPF array map, matched DIRECTLY in the `sched_process_exec` handler against both the exec'd filename and `task->comm`. Process is added to `proc_map` atomically in kernel — no ringbuf, no userspace delay. Children forked afterward are auto-tracked immediately via `sched_process_fork`.
2. **BPF-side first-syscall matching** (v5.2.0): On a process's first syscall, BPF checks `comm` against the pattern and auto-tracks on match. Catches `clone()` without `exec()` — the process is tracked before its second syscall.
3. **BPF-side prctl(PR_SET_NAME) matching** (v5.2.0): When any process renames itself, BPF re-checks the new name against the pattern and auto-tracks on match. Catches processes that set their identity after startup.
4. **Fork auto-tracking**: Once a root process is tracked, all children are automatically tracked via BPF `sched_process_fork` handler. The parent is tracked before it can fork, so children are never missed.

Userspace `rescan_comms` and `handle_event` remain as fallback paths for edge cases, but the primary discovery is entirely BPF-side. The pattern match uses a bounded case-insensitive substring search that is BPF-verifier-safe (fixed iteration count, no unbounded loops).

Pattern matching is case-insensitive on both the exec filename and the kernel `task->comm`. If no matching processes are running, montauk waits until they appear. montauk automatically excludes its own process chain from tracing.

This works for any process — standard applications, `clone()` without `exec()`, processes that rename themselves via `prctl(PR_SET_NAME)`, thread pools, container runtimes, any process model on Linux. No `/proc` reads at any point. No timing-based polling for discovery — every match is event-driven.

Per-thread data collected via eBPF:
- Thread state (R/S/D/T/Z) from `sched_switch` tracepoint (real-time state transitions)
- Current syscall number and arguments from `raw_syscalls/sys_enter` (decoded: futex, ioctl, epoll_wait, io_uring_enter, etc.)
- Per-thread CPU time via `sched_switch` on-CPU duration tracking
- Open file descriptors tracked via `sys_enter_openat`, `sys_enter_close`, `sys_exit_socket`, `sys_exit_eventfd2` tracepoints
- **File I/O details** (v5.1.0): per-thread `read`, `write`, `lseek`, `pread64`, and `fstat` tracking with full argument capture (fd, byte count, seek offset/whence) and return values. Enables diagnosing file I/O divergences between implementations — e.g., comparing a custom wineserver against stock to find exactly where file operations differ
- **futex** (v6.5.0): `futex` (202) captured through the I/O event — op (WAIT/WAKE plus PRIVATE/CLOCK flags), val, and uaddr — so a trace shows a `FUTEX_WAKE` against a waiter and the op/uaddr to correlate wait/wake pairs
- **Heap allocation** (v6.5.0): `malloc`/`free`/`realloc`/`calloc` via libc uprobes, pairing size with returned address per-thread; realloc moves tracked. The event stream the heap-corruption reports fold over — no debugger attached to the workload
- **Signals and aborts** (v6.5.0): `tp/signal/signal_deliver` with a user-mode stack snapshot, abnormal-exit (`exit_code != 0`) postmortem stacks, and libc abort-path uprobes (`__assert_fail`/`__libc_message`/`abort`) marking the point a glibc consistency check fires
- **File-backed mmap** (v6.5.0): `mmap` (anonymous mappings filtered) to distinguish arena growth from file mapping
- **Scheduler decisions** (v6.5.0): enqueue / pick / preempt / wakeup / wake-to-run latency, bound by generic role to whatever decision tracepoints the active scheduler exposes — montauk names no scheduler in source. Aggregated per-CPU by default (one counter increment, near-zero overhead); full per-event streaming is opt-in via `--trace-out`
- **On-CPU and migrations** (v6.5.0): current core per thread and a cross-core migration count, bucketed intra / cross / unknown-CCX against a sysfs-derived L3-domain map — cross-CCX moves (the L3-refill penalty) separated from cheap within-CCX shuffling, no PMU required
- **ntsync** (v6.5.0): Wine/Proton NT synchronization ioctls (semaphore/mutex/event create, signal, wait) with the waited-on object fds — the substrate for the sync-contention reports

Requires root at runtime (kernel tracepoint attachment requires `CAP_SYS_ADMIN` on most configurations). Build requires `libbpf`, `bpftool`, and `clang` (BPF target). Auto-detected by CMake; if unavailable, `--trace` prints an error.

Trace mode composes with `--metrics` and `--log`. When combined with `--metrics PORT`, the Prometheus endpoint appends `montauk_trace_*` metrics alongside the standard system metrics:
- `montauk_trace_process_info{pid,ppid,cmd,root}` — process group membership
- `montauk_trace_thread_state{pid,tid,comm,state}` — per-thread state
- `montauk_trace_thread_cpu_percent{pid,tid,comm}` — per-thread CPU utilization
- `montauk_trace_thread_syscall{pid,tid,comm,syscall,wchan}` — current syscall and wait channel
- `montauk_trace_thread_io{pid,tid,comm,syscall,fd,count,result,whence}` — file I/O details: last read/write/lseek/pread64/fstat per thread with fd, byte count or seek offset, return value, and seek whence. Correlate with `fd_target` to see full file I/O sequences per file
- `montauk_trace_fd_target{pid,fd,target}` — open file descriptors (pipes, devices, sockets)
- `montauk_trace_thread_cpu{pid,tid,comm}` — core a thread currently runs on
- `montauk_trace_thread_migrations{pid,tid,comm}` — cumulative cross-core moves per thread
- `montauk_trace_migrations_intra_ccx` / `_cross_ccx` / `_unknown_ccx` — migration totals bucketed by L3/CCX locality
- `montauk_trace_ntsync{...}` — ntsync ioctl operations from traced processes
- `montauk_sched_op_total{op}` — scheduler decision counts (enqueue, pick, pick_empty, preempt_tick, preempt_wakeup, wakeup, wake2run), aggregated per-CPU in BPF
- `montauk_pmu_*` — hardware counter gauges (see Hardware Performance Counters below)
- `montauk_trace_group_size`, `montauk_trace_thread_total`, `montauk_trace_waiting` — group metadata

When combined with `--log DIR`, trace metrics are written alongside standard metrics in the hourly `.prom` files, creating a flight recorder for post-mortem analysis.

The trace subsystem runs as a parallel pipeline with its own lock-free seqlock double buffer, independent of the main monitoring pipeline. BPF programs maintain per-thread state maps and a global discovery map in the kernel; userspace reads these maps every 500ms to publish snapshots. Zero `/proc` reads after eBPF attach — all data comes from BPF maps and ring buffer events. No impact on existing TUI or system-wide metrics when `--trace` is not used.

**Binary Event Log (`--trace-out`):**

The periodic Prometheus snapshot is the data path for aggregate per-thread state. For high-rate event streams — scheduler decisions, heap traffic — formatting each event to text at trace time is a syscall-per-event firehose that perturbs the very workload being measured. `--trace-out FILE` writes the raw ring records verbatim to a binary log, batched into ~256 KB writes (one syscall per batch, not per event); trace-time cost per event drops to a memcpy. The header captures `CLOCK_MONOTONIC` and `CLOCK_REALTIME` anchors at trace start, so the readers reconstruct absolute wall-clock per event and correlate against external traces (schbench output, scheduler logs, the embedded provider snapshots). It is independent of `MONTAUK_TRACE_VERBOSE` (the per-event stderr aid) and `--log` (the Prometheus flight recorder) — three orthogonal output paths.

Two tools read the binary log offline, sharing one record-walk (validate magic+version, length-authoritative iteration so an older decoder skips newer event types cleanly), with no `montauk_core` or BPF link:

- `montauk_trace_decode FILE [--csv]` — renders one line per event with elapsed and absolute timestamps. Text by default, CSV for tooling.
- `montauk_analyze FILE [--report name[,name...]]` — single-pass diagnostic reports (default: all). Each folds events once over the file:
  - `summary` — header, duration, throughput, per type+subtype counts
  - `waits` — per `(tid,fd)` NTSYNC wait-completion stats
  - `spins` — livelock detector: streaks of sub-tick wait completions on one `(tid,fd)` sustained past a threshold, with a verdict
  - `pairing` — per object fd, waits vs signal-side ops, to find a signal that never reaches a waiter
  - `abortpm` — per-abort arena post-mortem: replays the heap stream up to each abort and names the glibc top-chunk overrun victim allocation, plus the aborting thread's last events
  - `endstate` — who was parked in what wait when the trace ended, and for how long, to name a wedge/stall
  - `heapstk` — unique allocation sites of a size-filtered `malloc`/`calloc` (`MONTAUK_HEAP_STACK_SIZE`), ranked by count
  - `doublefree` — an address freed while not live, with the last size and both freeing tids/comms (same tid = logic double-destroy; two tids = concurrent free race); realloc moves tracked so a moved chunk isn't mis-flagged
  - `futex` — per-uaddr futex wait/wake stats: which threads block on which futex and whether a wake ever reached a waiter
  - `keyedevt` — ntdll keyed-event (critical-section) waits vs releases, keyed on the critical-section address, to spot a section a holder never released
  - `sched` — wake-to-run (runqueue) latency distribution with percentiles, plus a flow-model classification of the latency sequence (a mid-trace regime change, quantization onto a few values) sorted and classified through sublimation

**Hardware Performance Counters (PMU):**

Trace mode additionally samples hardware counters via `perf_event_open`: per-CPU L2 cache misses/references (AMD Zen raw events), instructions, cycles, and — where the `amd_uncore` module exposes the `amd_l3` PMU — per-CCX L3 accesses/misses. Derived rates (IPC, L2 miss percent, cycles-per-L2-miss, misses/sec) export as the `montauk_pmu_*` gauge families. The `amd_l3` event encoding is read entirely from sysfs, nothing hardcoded but the documented Zen2 fallback. This is the cache-placement signal that pairs with the CCX-migration counters: misses explain why cross-CCX moves hurt.

PMU sampling requires `kernel.perf_event_paranoid <= 0` or `CAP_PERFMON`, and is exclusive to trace mode by design — the plain monitor never calls `perf_event_open` and never requires elevated perf permissions. If the permission check fails in trace mode, PMU is disabled with a one-line notice and tracing continues without counter data.

**External Metrics Providers:**

montauk ingests external programs' own metrics. `ProviderCollector` scrapes unix sockets named `<name>.sock` in `$XDG_RUNTIME_DIR/montauk/providers/` (fallback `/run/montauk/providers/`): connect, read one full Prometheus-text snapshot to EOF. Providers self-identify by socket filename; montauk names none in source. A missing directory or unreachable/garbled provider is a silent per-scrape no-op — providers come and go at runtime.

Provider text passes through montauk's own Prometheus exposition verbatim (so a scheduler or application exporting its internals appears alongside `montauk_*` in `--metrics`/`--log`), and is embedded into the binary trace stream as provider-snapshot records, so a capture carries the external program's self-reported state inline with the kernel events — correlate an app's own counters against the migrations montauk observed, in one file. Export-only: not shown in the TUI.

## UI Controls

**Navigation:**
- `q` — Quit
- `↑/↓` — Scroll process list
- `PgUp/PgDn` — Page up/down

**Search/Filter:**
- `/` or `Ctrl+F` — Enter search mode (live case-insensitive substring filter)
- `Enter` — Confirm filter and return to normal mode
- `Esc` — Exit search mode (or clear active filter from normal mode)
- `Backspace` — Delete last character (empty backspace exits search mode)

**Sorting:**
- `c` — Sort by CPU%
- `m` — Sort by Memory
- `g` — Sort by GPU%
- `v` — Sort by GPU Memory (GMEM)
- `p` — Sort by PID
- `n` — Sort by Name

**Display Toggles:**
- `G` — Toggle GPU charts (util / VRAM / GPU MEM / ENC / DEC)
- `t` — Toggle Thermal section inside SYSTEM focus

**Help Overlay:**
- `?` or `h` — Toggle the in-app help overlay
- The overlay loads `man montauk` at runtime and renders it inside the PROCESS MONITOR column (right column stays visible). Content reflows to the available width on resize / split-screen via `MANWIDTH`. Single source of truth: edit `montauk.1`, the overlay updates on next open.
- While open: `j`/`k` scroll one line, `d`/`Space` page down, `u` page up, `g`/`G` jump to top/bottom, `q`/`?`/`Esc` close

**Modes:**
- `s` — Toggle SYSTEM focus mode (right column: chart stack ↔ text-detail panel)
- `C` (Shift+C) — Toggle CPU TOPOLOGY view (left column: PROCESS MONITOR ↔ per-core grid; arrows + PageUp/PageDown scroll on high-core systems; Esc or `C` again returns)
- `i` — Toggle CPU scale (machine-share ↔ per-core)
- `u` — Toggle GPU scale (capacity ↔ utilization)
- `R` — Reset UI to defaults
- `+/-` — Increase/decrease refresh rate

**Note:** Three views, each on its own column. Default — pixel-rendered area charts (PROCESSOR, GPU, VRAM, GPU MEM, ENC, DEC, MEMORY, NETWORK) on the right, PROCESS MONITOR on the left — both via the terminal graphics protocol (Kitty primary, Sixel fallback). `s` swaps the right column to a comprehensive text panel covering identity, runtime, CPU, GPU, memory, disk, network, thermal, and process statistics. `Shift+C` swaps the left column to a per-core CPU TOPOLOGY grid, one mini area-chart per logical CPU, with auto-fit geometry and scroll fallback for high-core systems. The two toggles are orthogonal — left and right column states are independent.

## Configuration

montauk uses a unified TOML configuration file at `~/.config/montauk/config.toml`. Every value follows a three-tier resolution chain: **TOML -> environment variable -> compiled default**. If no config file exists, compiled defaults apply with zero overhead.

### Quick Start

Generate a config file with your terminal's palette auto-detected:
```bash
montauk --init-theme
```

This writes `~/.config/montauk/config.toml` with all defaults and your terminal's 16 ANSI colors.

### TOML Schema

```toml
[palette]
color0  = "#2E2E2E"
color1  = "#CC0000"
# ... color2-color15 (populated by --init-theme)

[roles]
# Integer = palette index, string "#RRGGBB" = hex override
accent  = 11
caution = 9
warning = 1
normal  = 2
muted   = "#787878"
border  = "#383838"
binary  = "#8F00FF"

[thresholds]
proc_caution_pct = 60
proc_warning_pct = 80
cpu_temp_warning_c = 90
temp_caution_delta_c = 10
gpu_temp_warning_c = 90
alert_frames = 5

[ui]
alt_screen = true
system_focus = false
cpu_scale = "total"
gpu_scale = "utilization"
time_format = ""

[process]
max_procs = 256
enrich_top_n = 256
collector = "auto"

[nvidia]
smi_path = "auto"
smi_dev = true
smi_min_interval_ms = 0
pmon = true
mem = true
log_nvml = false
gpu_debug = false
disable_nvml = false
nvml_path = ""

[keybinds]
quit = "q"
help = "h"
fps_up = "+"
fps_down = "-"
sort_cpu = "c"
sort_mem = "m"
sort_pid = "p"
sort_name = "n"
sort_gpu = "g"
sort_gmem = "v"
toggle_gpu = "G"
toggle_thermal = "t"
toggle_disk = "d"
toggle_net = "N"
toggle_cpu_scale = "i"
toggle_gpu_scale = "u"
toggle_system_focus = "s"
reset_ui = "R"
search = "/"
```

### Process Settings

- `max_procs` — Maximum processes tracked and rendered (default: `256`, range: `32–4096`).
- `enrich_top_n` — Processes enriched with full command line (default: `256`, up to `max_procs`).
- `collector` — Collection backend: `"auto"`, `"kernel"`, `"netlink"`, or `"traditional"`.

With the kernel module, enrichment has zero /proc overhead (cmdline comes from kernel). With userspace collectors, enrichment reads `/proc/[pid]/cmdline` and `/proc/[pid]/status`. Reduce `enrich_top_n` below `max_procs` for lower-powered systems without the kernel module.

### Environment Variable Fallback

All settings accept `MONTAUK_*` or `montauk_*` environment variables as a fallback when not set in TOML. For example, `MONTAUK_MAX_PROCS=1024` works if `[process] max_procs` is absent from the TOML.

## CPU Scale Modes

**Machine-share (default):**
- 100% = entire machine's CPU capacity
- Processes sum naturally toward total system usage
- Best for understanding system-wide resource consumption

**Per-core (IRIX-style):**
- 100% = one full CPU core
- Multi-threaded apps can exceed 100%
- Toggle with `i` key

## GPU Support

### NVIDIA

**Full NVML Integration** (recommended):
- Per-process GPU utilization (SM, encoder, decoder)
- Per-process VRAM usage
- Device-level metrics (util, power, temps, clocks)
- MIG mode detection
- PRIME render offload support

**Requirements:**
- Runtime: `nvidia-utils` (provides `libnvidia-ml.so.1`). montauk now loads NVML dynamically and does not require dev headers.
- Optional build: `cuda` headers if you opt-in to static NVML linkage via CMake.

**Fallback Chain** (when NVML unavailable or insufficient):
0. NVML (runtime loader) — Preferred when available
1. Device-level via `nvidia-smi --query-gpu=…` — Name, VRAM, GPU/MEM util, temp, pstate, power
2. `nvidia-smi pmon` — Per-process utilization sampling
3. `nvidia-smi --query-compute-apps` — Compute context memory
4. `/proc/driver/nvidia/gpus/*/fb_memory_usage` — Device VRAM
5. Heuristic distribution based on device-level metrics

### AMD/Intel

- `/sys/class/drm` — VRAM usage, temperatures, power
- `/proc/*/fdinfo` — Per-process GPU utilization (DRM)
- `gpu_busy_percent` — Device utilization

### Browser GPU Process Detection

montauk automatically identifies browser GPU processes (Chrome, Chromium, Helium, etc.) by:
- Scanning for `--type=gpu-process` in command lines
- Enriching up to 256 processes with full cmdline data
- Applying intelligent fallback attribution when processes use minimal CPU
- Using `/proc/*/fd` device file inspection for decode-only workloads

### GPU Configuration

All GPU settings live under `[nvidia]` in TOML (see schema above). Env var fallbacks:

```bash
MONTAUK_NVIDIA_PMON=0     # [nvidia] pmon = false
MONTAUK_NVIDIA_MEM=0      # [nvidia] mem = false
MONTAUK_LOG_NVML=1        # [nvidia] log_nvml = true
MONTAUK_NVIDIA_SMI_DEV=0  # [nvidia] smi_dev = false
MONTAUK_NVIDIA_SMI_PATH=… # [nvidia] smi_path = "…"
MONTAUK_SMI_MIN_INTERVAL_MS=1000  # [nvidia] smi_min_interval_ms = 1000
MONTAUK_GPU_DEBUG=1       # [nvidia] gpu_debug = true
MONTAUK_DISABLE_NVML=1    # [nvidia] disable_nvml = true
MONTAUK_NVML_PATH=…       # [nvidia] nvml_path = "…"
```

## Display Details

**Process Columns:**
- **PID** — Process ID
- **USER** — Owner username
- **CPU%** — CPU utilization (0-100% in machine-share, 0-N×100% in per-core)
- **GPU%** — GPU SM/compute utilization
- **GMEM** — GPU memory (VRAM) usage
- **MEM** — System RAM usage
- **COMMAND** — Process name or full command line

**Minimum Display Values:**
- CPU% and GPU% show **0.1%, 0.2%, etc.** for sub-1% activity
- Values 1% and above shown as integers
- This ensures low-activity processes remain visible without inflating their usage

**UI Layout:**

**Default Mode:**
Left column: PROCESS MONITOR (dynamically fills available height)
Right column (top to bottom):
- PROCESSOR (CPU utilization bar)
- GPU (multi-metric bars: GPU util, VRAM, MEM util, ENC, DEC)
- MEMORY (RAM utilization bar)
- DISK I/O (throughput and device stats)
- NETWORK (throughput and interface stats)
- SYSTEM (detailed system information)

**SYSTEM Focus Mode (press 's'):**
Left column: PROCESS MONITOR
Right column: Comprehensive SYSTEM box showing:
- Host/kernel/date/time/uptime (when in SYSTEM focus)
- CPU details (model, threads, frequency, governor, turbo, utilization breakdown)
- Load averages
- Context switches and interrupts per second
- GPU info (model, utilization, NVML status, power, power limit, P-state)
- Memory (available, used, cache/buffers)
- Disk I/O (aggregate and per-device)
- Network (aggregate and per-interface)
- Filesystem usage
- CPU and GPU temperatures with margin-to-warning calculations
- Collector type (Kernel Module, Netlink proc_connector, or Traditional)
- Process counts (enriched vs total)
- System threads statistics
- Process states (Running, Sleeping, Zombie)
- **PROC CHURN** (when active) or **PROC SECURITY** (when no churn)

**Color Coding:**
- Normal text: Default terminal color
- Bars: Green (healthy) → Yellow (caution) → Red (warning) based on utilization
- CAUTION severity: Yellow/orange highlighting (60-80% default)
- WARNING severity: Red highlighting (80%+ default)
- PROC CHURN: CAUTION severity (yellow/orange)
- PROC SECURITY warnings: Severity-based coloring (INFO/CAUTION/WARNING)
- Titles: Accent color
- Borders: Distinct border color for all box-drawing characters
- COMMAND column: Binary name highlighted, path prefixes and arguments muted, kernel threads fully muted (classified via Thompson NFA)
- GPU%: Severity coloring mirroring CPU% thresholds

## Churn Handling

During heavy system activity (builds, installs, rapid process creation), `/proc` and `/sys` entries can vanish between directory scans and file reads. This affects userspace collectors (netlink proc_connector and traditional /proc polling). The kernel module is immune to /proc churn since it reads `task_struct` directly.

montauk handles churn gracefully with dynamic visual feedback:

**PROC CHURN Display:**

When active churn is detected, the SYSTEM box shows:
- Summary line: `PROC CHURN  N events [LAST 2s]` (colored as CAUTION - yellow/orange)
- Event breakdown: `PROC:X  SYSFS:Y` showing source of churn events
- Currently affected processes with PIDs (processes may have exited by display time)

**Display Behavior:**
- PROC CHURN and PROC SECURITY are mutually exclusive
- When churn is active: PROC CHURN replaces PROC SECURITY display
- When churn subsides: PROC SECURITY returns automatically
- In SYSTEM focus mode: Churn details dynamically fill available vertical space

**Process Table:**
- Churned processes may show partial metrics during read failures
- Clears on next successful sample
- System remains responsive throughout churn events

Example SYSTEM box during churn:
```
PROC CHURN                                  8 events [LAST 2s]
PROC:8  SYSFS:0
PID:12345 cc1plus
PID:12346 ld
PID:12347 as
```

The event count (8) may exceed visible PIDs (3) because some processes exit before display update.

## Environment Variable Reference

All settings below are env var fallbacks for when a TOML key is absent. Prefer `~/.config/montauk/config.toml` (see Configuration above).

### UI/Terminal
```bash
MONTAUK_ALT_SCREEN=0           # [ui] alt_screen = false
MONTAUK_PROC_CPU_SCALE=total   # [ui] cpu_scale = "total" | "core"
```

Seven semantic color roles (configured via `[roles]` in TOML): accent, caution, warning, normal, muted, border, binary.

### Thresholds
```bash
MONTAUK_PROC_CAUTION_PCT=60    # [thresholds] proc_caution_pct = 60
MONTAUK_PROC_WARNING_PCT=80    # [thresholds] proc_warning_pct = 80
MONTAUK_TOPPROC_ALERT_FRAMES=5 # [thresholds] alert_frames = 5
```

### Thermal Thresholds

**Dynamic (preferred):**
- NVIDIA: Auto-discovered via NVML (slowdown, mem_max)
- AMD/Intel: Auto-discovered via sysfs hwmon (crit, max, emergency)

**Overrides (TOML `[thresholds]` or env vars):**
```bash
MONTAUK_CPU_TEMP_WARNING_C=90       # cpu_temp_warning_c
MONTAUK_CPU_TEMP_CAUTION_C=80       # cpu_temp_caution_c
MONTAUK_GPU_TEMP_WARNING_C=90       # gpu_temp_warning_c
MONTAUK_TEMP_CAUTION_DELTA_C=10     # temp_caution_delta_c
MONTAUK_GPU_TEMP_EDGE_WARNING_C=85  # gpu_temp_edge_warning_c
MONTAUK_GPU_TEMP_HOT_WARNING_C=95   # gpu_temp_hot_warning_c
MONTAUK_GPU_TEMP_MEM_WARNING_C=95   # gpu_temp_mem_warning_c
```

### Testing/Development
```bash
MONTAUK_PROC_ROOT=/custom/proc    # Remap /proc paths (userspace collectors only)
MONTAUK_SYS_ROOT=/custom/sys      # Remap /sys paths
MONTAUK_COLLECTOR=kernel          # [process] collector = "kernel"
MONTAUK_COLLECTOR=netlink         # [process] collector = "netlink"
MONTAUK_COLLECTOR=traditional     # [process] collector = "traditional"
```

## Testing

**Build with tests:**
```bash
cmake -S . -B build -DMONTAUK_BUILD_TESTS=ON
cmake --build build -j
./build/montauk_tests
```

When built with liburing, this includes Prometheus serializer tests (CPU gauge, memory byte conversion, per-core labels, top-N process output, empty snapshot safety).

**Self-test mode:**
```bash
./build/montauk --self-test-seconds 5
```

**Stress Testing:**

montauk includes stress test scripts in the companion `stress-tests/` directory for validating monitoring accuracy and churn detection:

**GPU Stress Test:**
```bash
cd ../stress-tests
./stress_test 60        # 60-second GPU + CPU stress test
```
- Tests GPU utilization tracking (compute + memory)
- Multi-threaded CPU load (OpenMP)
- VRAM allocation monitoring
- Power and thermal tracking

**PROC CHURN Test:**
```bash
./proc_churn.sh 30 100  # 30 seconds, 100 processes/second
```
- Rapidly spawns and destroys processes
- Triggers PROC CHURN detection (userspace collectors only; kernel module is immune)
- Tests /proc resilience during heavy activity
- Validates collector behavior differences

Monitor with montauk while running stress tests (press 's' for SYSTEM focus to see detailed churn metrics).

**Note:** Tests are disabled by default in packaging builds.

## Trace Analysis Tools

Two standalone tools consume a binary trace log (`--trace-out`) offline — no privileges, no live target, no external dependencies. Both share one length-authoritative record walk and build without a `montauk_core` or BPF link, so they decode a capture anywhere. They are installed alongside `montauk` and must track its version: a newer `montauk` emits event types an older decoder would silently drop.

**`montauk_trace_decode`** — render a log to a human-readable event stream:

```bash
montauk_trace_decode trace.bin          # one line per event, elapsed + wall timestamps
montauk_trace_decode trace.bin --csv    # CSV for tooling
```

**`montauk_analyze`** — run single-pass diagnostic reports over a log:

```bash
montauk_analyze trace.bin                       # all reports
montauk_analyze trace.bin --report doublefree   # one report
montauk_analyze trace.bin --report waits,spins  # several
```

The report suite (`summary`, `waits`, `spins`, `pairing`, `abortpm`, `endstate`, `heapstk`, `doublefree`, `futex`, `keyedevt`, `sched`) is described under **Trace Mode → Binary Event Log** above. Each report folds the file in a single pass, so analysis scales to captures of 450 MB+. These answer the questions that come up debugging sync contention and heap corruption — a wedged thread, a livelock spin, a double-free race, a glibc abort's victim allocation — post-hoc from one capture, no rerun.

> The old live `/proc` CPU-attribution analyzer was removed in v6.5.0; `montauk_analyze` is now trace-only.

## Uninstall (CMake)

```bash
sudo xargs rm -v < build/install_manifest.txt
```

## Packaging (Arch Linux)

- PKGBUILD provided in `pkg/` directory
- NVML auto-detected at build time
- Build deps: `cmake`, `gcc`, `make`
- Optional build: `liburing` (enables Prometheus metrics endpoint)
- Optional runtime: `nvidia-utils`
- Tests disabled by default: `MONTAUK_BUILD_TESTS=OFF`

**Install:**
```bash
makepkg -si
```

**Result:** `/usr/bin/montauk`

## Architecture

**Collectors:**
- `CpuCollector` — Per-core usage, freq, model, governor, turbo status
- `MemoryCollector` — RAM, swap, buffers, cache, available memory
- `KernelProcessCollector` — Kernel module backend via genetlink (preferred)
- `NetlinkProcessCollector` — Event-driven via proc_connector + /proc reads (fallback 1)
- `ProcessCollector` — Traditional /proc scanning (fallback 2)
- `GpuCollector` — VRAM, temps, power, utilization (multi-vendor)
- `GpuAttributor` — Per-process GPU util/mem with fallback chains
- `NetCollector` — Interface stats, throughput (down/up per interface)
- `DiskCollector` — I/O stats, throughput, per-device utilization
- `ThermalCollector` — Multi-sensor temps with vendor thresholds
- `FsCollector` — Filesystem usage (mountpoint, used, total)
- `FdinfoProcessCollector` — Per-process GPU metrics via /proc/*/fdinfo (DRM)
- `PmuCollector` — Hardware PMU counters via perf_event_open: per-CPU L2 miss/ref, IPC, per-CCX L3 (trace-gated)
- `ProviderCollector` — Scrapes external programs' Prometheus-text over unix sockets in `$XDG_RUNTIME_DIR/montauk/providers/`
- `BpfTraceCollector` — eBPF tracepoint/uprobe instrumentation for `--trace`: per-thread state, syscalls, heap, signals, scheduler decisions, ntsync

**Core Components:**
- `Security` — Process security analysis (privilege escalation, suspicious patterns)
- `Churn` — Real-time /proc and /sysfs churn event tracking
- `Alerts` — Process-based alerting system
- `SnapshotBuffers` — Lock-free snapshot management
- `Producer` — Coordinated data collection pipeline
- `Filter` — Process filtering and sorting
- `ThompsonNFA` — RE2-style Thompson NFA regex engine with UTF-8 byte lowering (Parser → Lowering → Builder → Simulator); 256-bit bitmask character classes, shunting-yard construction, zero-allocation simulation
- `BoyerMoore` — Boyer-Moore-Horspool substring search with 256-byte bad character table
- `AsciiLower` — Constexpr 256-byte ASCII lowercase lookup table (branchless, no locale)
- `SortDispatch` — typed adapters onto sublimation (montauk's sort algorithm): pack-key index sort for numerics, hybrid prefix-pack + MSD radix for strings
- `LogWriter` — Prometheus exposition snapshot logging with hourly file rotation
- `MetricsServer` — io_uring HTTP server for Prometheus endpoint (optional, requires liburing)
- `PrometheusSerializer` — Serializes MetricsSnapshot to Prometheus text exposition format via `std::to_chars()` (system + trace + PMU families, with provider passthrough)
- `TraceReader` — Shared open/validate/iterate over a binary `--trace-out` log; linked by `montauk_trace_decode` and `montauk_analyze` with no BPF dependency

**UI Components (cell-based, OUROBOROS-derived):**
- `widget::Canvas` — Cell-grid rendering surface with structural clipping and image-mask support for pixel blits
- `widget::Component` — Base class for every widget; subclasses implement `render` and `handle_input`
- `widget::FlexLayout` — Flexbox-style constraint solver for hierarchical layout (no manual `cols * 2 / 3` math)
- `widget::Panel` — Bordered panel that draws structured `Row`s (label/value pairs, headers, blanks) cell-by-cell
- `widget::Chart` — Monotone cubic Hermite area-chart rasterizer with anti-aliased line + fill
- `widget::GraphicsEmitter` — Kitty (`a=T,t=t` /dev/shm) and Sixel emit paths for pixel charts
- `widget::InputEvent` + `parse_input_bytes` — stdin → typed key events (Char / Enter / Esc / arrows / page keys)
- `widgets::ProcessTable` — Left-column PROCESS MONITOR; owns sort/scroll/filter/search/columns/scale state
- `widgets::ChartPanel` — One pixel-rendered area chart per metric (PROCESSOR, GPU, VRAM, GPU MEM, ENC, DEC, MEMORY, NETWORK)
- `Panels` — Builds the right-column SYSTEM panel as `vector<Row>` (identity / runtime / CPU / GPU / memory / disk / network / thermal / security)
- `HelpOverlay` — Manpage-driven scrollable help with its own input handler
- `Renderer` — Owns ProcessTable + HelpOverlay + RightColumnState; runs the input dispatch and frame composition
- `Terminal` — TTY detection, color support, cursor control
- `Formatting` — Domain helpers (`smooth_value`, hostname/kernel/freq readers, `format_size`, severity helper)
- `Config` — Unified TOML configuration (TOML → env var → compiled default)
- `TomlReader` — Header-only TOML subset parser (portable across sibling projects)

**Process Collection:**

montauk supports three collection backends (auto-selected by availability):

**Kernel Module — Preferred:**
- All data from kernel `task_struct` via genetlink
- Kprobes hook fork/exec/exit directly
- Background workqueue refreshes CPU times at 1Hz
- Zero /proc reads, zero proc_connector overhead
- Requires `montauk.ko` loaded

**Netlink proc_connector — Fallback 1:**
- Subscribes to kernel process events (fork, exec, exit) via proc_connector
- Still reads `/proc/[pid]/stat`, `/proc/[pid]/cmdline`, etc. for process details
- Sub-millisecond event detection, but /proc reads add overhead
- Requires `CAP_NET_ADMIN` capability

**Traditional /proc polling — Fallback 2:**
- Scans `/proc` directory every sample interval
- Maintains compatibility when neither kernel module nor netlink available
- Identical functionality and UI to other modes

**Snapshot Pipeline:**
1. Collectors sample independently
2. Atomic snapshot publication via lock-free double buffer
3. GpuAttributor enriches with per-process GPU data
4. TUI renders from stable snapshot (seqlock copy for concurrency)
5. MetricsServer reads from the same SnapshotBuffers via selective seqlock (bounded, fixed-size copy)
6. LogWriter reads via seqlock and writes Prometheus exposition snapshots to disk

**GPU Attribution Logic:**
1. NVML per-process queries (preferred)
2. `nvidia-smi pmon` parsing
3. `/proc/*/fdinfo` DRM stats
4. Heuristic distribution from device metrics
5. Residual VRAM attribution to clear GPU processes
6. `/proc/*/fd` device inspection for decode workloads

## Performance

- **Overhead:** ~0.1-0.2% CPU with kernel module, ~0.5-1% with netlink proc_connector, ~2-5% with /proc polling
- **Sampling:** 250ms default (adjustable with +/-)
- **Process limit:** 256 default, configurable up to 4096 (top by CPU usage)
- **Process detection:** Sub-millisecond with kernel module or netlink, ~1 second with /proc polling
- **System calls:** 1 per snapshot (kernel module), ~1 + N events (netlink), ~3 per process (/proc polling)
- **Cmdline enrichment:** All tracked processes up to 4096 (full command lines for accurate GPU detection)
- **Memory:** ~10MB resident

**Technical Implementation:**

**ANSI Escape Sequence Handling:**
- Display width calculations skip escape codes (don't count as visible characters)
- String truncation preserves embedded ANSI codes
- Prevents double-coloring and escape sequence corruption
- Full truecolor (24-bit) support with 256-color fallback

**Dynamic Layout:**
- All panels calculate available vertical space dynamically
- PROCESS MONITOR fills to match terminal height
- SYSTEM box expands to fill remaining space
- PROC CHURN and PROC SECURITY details fill all available lines
- No hardcoded row limits

**Churn Detection:**
- Tracks /proc and /sysfs read failures in sliding 2-second window
- Event counts tracked separately by source (PROC vs SYSFS)
- Per-process churn flag for processes with read failures
- Auto-clears when churn subsides
- Zero performance impact when no churn active

**Sort (sublimation):**

sublimation IS montauk's sort algorithm — the flow-model adaptive sort, linked unconditionally (no runtime backend choice and no fallback). The process table and **every ordering the analyzer emits** — latency quantiles and report rows alike — sort through it; the analyzer no longer falls back to `std::sort` anywhere.

- **Pack-key index sort** for numeric keys (CPU%, memory, PID, GPU%, GMEM): keys pack with their index and sort as a unit, so montauk permutes a `uint32_t` index array rather than moving rows. Stable for equal keys — the packed index, initialized from input order, is the tiebreak, which keeps the UI from reshuffling rows that share a CPU%. 32-bit keys pack into one `uint64_t`; 64-bit keys (timestamps, addresses) use a stable LSD radix carrying the index as a satellite.
- **Hybrid string sort** (prefix-pack + MSD radix) for the name column.
- **Disorder classifier** — the same flow-model front end that picks the sort path also profiles a sequence's structure (Young-tableau shape, longest increasing subsequence, inversion ratio, phase boundary). The analyzer's `sched` report reads this to label a latency sequence's temporal structure.
- **In-tree sub-system:** sublimation lives at `montauk/sublimation/` and CMake builds it as a static library, linked into montauk and the analyzer — no system package, no fetch step. Requires a Haswell-or-newer CPU (BMI2 + AVX2) and gcc 13+ (C23).

> montauk's prior C++23 TimSort/Powersort implementation is retired and preserved under `[0] ARCHIVE/montauk-timsort-cpp/`.

## Policy

**sublimation is an in-tree sub-system:** montauk's sort algorithm lives at `montauk/sublimation/` and is compiled into the montauk build — no system package, no fetch, no runtime fallback. NVML and liburing are auto-detected and gracefully disabled when unavailable. No FetchContent, no ExternalProject — the sublimation source is vendored in the tree, not pulled at build time.

## License

GPL-2.0. See LICENSE file in repository.
