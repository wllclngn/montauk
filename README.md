```
███╗   ███╗  ██████╗  ███╗   ██╗ ████████╗  █████╗  ██╗   ██╗ ██╗  ██╗
████╗ ████║ ██╔═══██╗ ████╗  ██║ ╚══██╔══╝ ██╔══██╗ ██║   ██║ ██║ ██╔╝
██╔████╔██║ ██║   ██║ ██╔██╗ ██║    ██║    ███████║ ██║   ██║ █████╔╝ 
██║╚██╔╝██║ ██║   ██║ ██║╚██╗██║    ██║    ██╔══██║ ██║   ██║ ██╔═██╗ 
██║ ╚═╝ ██║ ╚██████╔╝ ██║ ╚████║    ██║    ██║  ██║ ╚██████╔╝ ██║  ██╗
╚═╝     ╚═╝  ╚═════╝  ╚═╝  ╚═══╝    ╚═╝    ╚═╝  ╚═╝  ╚═════╝  ╚═╝  ╚═╝
```

**montauk · sublimation** — a Linux system monitor, metrics generator, tracer and analyzer, built on sublimation, its in-tree flow-model sort and search/match core.

## Overview

montauk is a Linux **system monitor, metrics generator, tracer and analyzer** — three tools in one offline-friendly C++23 binary — built on **sublimation**, its in-tree flow-model sort and search/match core: the ordering, the disorder classification, the entropy detection and every substring and regex match montauk makes. The monitor (plain `montauk`) is an event-driven TUI with deep GPU attribution and Prometheus export. The tracer (`--trace`) is an eBPF flight recorder over a whole process tree — sync objects, heap, signals, scheduler decisions, hardware counters. The analyzer (`montauk_analyze` / `montauk_trace_decode`) folds a capture once into diagnostic reports.

sublimation is a **sub-system montauk builds**, vendored in `montauk/sublimation/`, and it is montauk's search and sort *everywhere*: the process table, every ordering the analyzer emits, the latency-structure classification the reports read and the kernel-thread, `/`-search and `--trace` text matching. Two systems, one tree. No system packages, no fetch step — NVML and liburing are auto-detected and optional; everything else lives in the repo.

```
montauk — one C++23 binary, three tools, one in-tree sort
  ├─ monitor  (plain `montauk`)
  │    ├─ collectors — CPU, memory, GPU (NVML / AMD sysfs / Intel fdinfo), disk, net, thermal, process
  │    ├─ UI — OUROBOROS-derived Canvas / Component / FlexLayout, cell-clipped, no rubberbanding
  │    ├─ charts — pixel-rendered area charts (Kitty t=t /dev/shm transport, Sixel fallback)
  │    └─ /metrics — Prometheus endpoint over io_uring (optional)
  ├─ tracer  (`--trace PATTERN`)
  │    ├─ eBPF on kernel tracepoints + libc/ntdll uprobes — no ptrace
  │    ├─ capture — ntsync / keyed-event / futex sync, heap, signal, abort, mmap
  │    ├─ scheduler decisions + wake-to-run latency, hardware PMU (perf_event_open)
  │    └─ binary trace log (`--trace-out`) — batched writes, near-zero observer effect
  ├─ analyzer  (`montauk_analyze`, `montauk_trace_decode`)
  │    └─ single-pass reports — waits, spins, pairing, abortpm, endstate,
  │       heapstk, doublefree, futex, keyedevt, sched (wake-to-run latency + structure),
  │       slice (per-CPU dispatched-slice length)
  └─ sublimation  (in-tree search / sort / match core)
       ├─ disorder classifier — builds a level graph, routes the sort; the analyzer reads its verdict
       ├─ index sorts (32-bit pack / 64-bit LSD radix) + hybrid prefix-pack / MSD-radix string sort
       ├─ randomness battery — six orthogonal entropy lenses → a single max-entropy confidence
       └─ text engines — Boyer-Moore-Horspool substring + Thompson NFA (RE2-lineage) regex; value search (select, searchsorted)
```

## Components

montauk is one binary that wears three faces, plus the sort beneath them. Each face is reached by how you invoke it; sublimation is compiled in under all three.

| Tool | Invocation | Role |
|---|---|---|
| **monitor** | `montauk` | Event-driven TUI. Per-process CPU and multi-vendor GPU attribution (NVIDIA NVML + `nvidia-smi` fallbacks, AMD sysfs, Intel fdinfo), thermal margins, security findings, live Boyer-Moore-Horspool search and Thompson-NFA classification. OUROBOROS-derived cell-clipped UI, pixel-rendered area charts (Kitty `t=t` /dev/shm transport, Sixel fallback), three column-swappable views. Optional Prometheus `/metrics` over io_uring and hourly `.prom` logging. |
| **tracer** | `montauk --trace PATTERN` | eBPF flight recorder over a whole process tree — event-driven discovery, no ptrace, no `/proc`. Per-thread state and syscalls, ntsync / futex / keyed-event sync, heap traffic, signals and aborts, file I/O, file-backed mmap, scheduler decisions with wake-to-run latency, CCX-bucketed migrations and hardware PMU counters via `perf_event_open`. Composes with `--metrics`, `--log` and a near-zero-overhead binary log (`--trace-out`). |
| **analyzer** | `montauk_analyze`, `montauk_trace_decode` | Folds a capture once into single-pass diagnostic reports — `waits`, `spins`, `pairing`, `abortpm`, `endstate`, `heapstk`, `doublefree`, `futex`, `keyedevt`, `sched`, `slice` — over logs reaching 450 MB+, plus recording-directory digests and cross-run population statistics. No live target, no privileges. |
| **sublimation** | in-tree sub-system + `sublimation` CLI | montauk's search, sort and match core, used everywhere: the process table, every ordering the analyzer emits, the disorder classification its reports read and all of montauk's text matching. It sorts, classifies, locates structure and greps text (Boyer-Moore-Horspool substring + Thompson NFA / RE2-lineage regex); the `sublimation` CLI exposes all of them (sort / quantile / select / searchsorted / sum / mean / stdev / min / max / count / classify / characterize / locate / rand / grep / contains / field / where), with grep exit codes and `-i`/`-o`/`-v`/`-c`/`-n`. See the dedicated section below. |

An optional kernel module (`montauk-kernel`) and the external-metrics provider sockets are the only seams to the outside; everything else is one statically-linked C++23 binary. sublimation is vendored under `montauk/sublimation/` with its own tests — one license, one tree, one README for both. NVML and liburing are auto-detected and optional; no system packages, no fetch step.

## sublimation — a flow-model sort that routes by disorder

sublimation is **a flow-model sort that routes by disorder**, vendored in-tree under `montauk/sublimation/` (source, the `sublimation` CLI, tests) and used as montauk's order / search / match core everywhere. It measures how disordered an input already is — sorted, reversed, nearly-sorted, few-unique, phased, random — then routes it to the cheapest path for that structure. The **flow model** is the router: a level graph over the data (the maximum-flow machinery the family is named for), with disorder priced as effective resistance on the run-boundary Laplacian. The payoff: **100 million random int64, sorted flat at ~17 ns/element, under the AVX2 comparison-sort floor.** Structured input is detected and exploited; equal keys stay stable by construction through a packed-index tiebreak; the classifier's verdict — Young-tableau shape, longest increasing subsequence, inversion ratio, phase boundary — montauk reads straight. Order and structure come from the flow model; text from the engines beside it — **Boyer-Moore-Horspool** substring search and a **Thompson NFA** regex (RE2-lineage). One core for everything montauk sorts, searches or measures.

| component | what it is |
|---|---|
| **disorder classifier** | one O(n) pass → the verdict: `sorted` / `reversed` / `nearly-sorted` / `few-unique` / `phased` / `random` / `spectral`. The analyzer's `sched` report reads it to label a latency timeline's structure. |
| **R_eff merge tree** | the flow-model router — effective resistance on the run-boundary Laplacian picks the merge path for structured runs |
| **index sorts** | order a `uint32_t` index array by a numeric key without moving rows (32-bit key packed with its index into one `uint64_t`; 64-bit key carried as a stable LSD-radix satellite) |
| **string sort** | prefix-pack + MSD-radix, for the process-name column |
| **structural locator** | slides the classifier across a stream to find *where* a disorder pattern sits (`locate`) |
| **randomness battery** | six orthogonal entropy lenses (hook-length entropy, LIS vs `2√n`, inversion ratio, distinct ratio, horizontal-visibility degree, ordinal permutation entropy) fused into one max-entropy confidence (`rand`) |
| **Thompson NFA** | UTF-8-aware leftmost-longest regex — RE2-lineage: linear-time NFA simulation, no catastrophic backtracking. Backs `grep` and montauk's regex matching. |
| **Boyer-Moore-Horspool** | literal substring search. Backs `contains` and montauk's substring matching. |
| **value search** | `select` (quickselect, replacing `std::nth_element`) and `searchsorted` (binary, lower/upper bound) |
| **field** | N-th delimited column projection — awk's `{print $N}` |

The text engines are 1:1 C23 ports of montauk's C++ `BoyerMooreSearch` and `ThompsonNFA`, verified byte-identical across 403 + 1748 cases — every regex and substring match montauk makes runs through them.

**On the command line.** The `sublimation` CLI puts the engine a shell pipe away — a flow-model sort with a full set of modern stream utilities. Numeric commands read a value stream (`--field N` pulls a delimited column, folding in awk's extraction): order and quantiles, k-th selection and value lookup, the **reductions** (`sum`/`mean`/`min`/`max`/`count`, `stdev`/`variance`) for awk's `{s+=$N}` family and `wc -l`, disorder classification, a randomness verdict, and `characterize` — the structural verdict that names a stream's disorder class, how random it is and how much exploitable structure it carries, the same shape the flow model measures to route its own sort, surfaced to the pipe. `grep`, `contains`, `field` and `where` are line tools: `grep`/`contains` return grep's exit status (0 matched, 1 none) and take `-v`/`-c`/`-n` (`grep -i` case-insensitive, `-o` for the match only); `field` is awk's `{print $N}` and `{print $1,$3}`; `where 'N OP V'` is awk's numeric `$N OP V` row filter.

| command | does |
|---|---|
| `sublimation sort [--desc]` | order ascending / descending |
| `sublimation quantile Q [--nearest]` | the Q-quantile (Q in 0..1); `--nearest` for the nearest-rank order statistic |
| `sublimation select K` | the K-th smallest (0-based) |
| `sublimation searchsorted V` | insertion index of V in the sorted input |
| `sublimation sum \| mean \| min \| max` | reductions over the value stream — awk's `{s+=$N}` family |
| `sublimation stdev \| variance` | sample (n-1) standard deviation / variance |
| `sublimation count` | number of input lines — `wc -l` |
| `sublimation classify` | disorder class + profile of the stream |
| `sublimation locate CLASS` | the windows where a disorder pattern sits |
| `sublimation rand` | max-entropy randomness confidence |
| `sublimation characterize` | the structural verdict — disorder class, randomness confidence, sort efficiency |
| `sublimation grep PATTERN [-i\|-o\|-v\|-c\|-n]` | lines matching the regex — **Thompson NFA** (RE2-lineage, linear-time); `-i` case-insensitive, `-o` prints only the match |
| `sublimation contains STR [-v\|-c\|-n]` | lines containing STR — **Boyer-Moore-Horspool**, case-insensitive |
| `sublimation field N,M [--delim D]` | the N-th column, or a comma-list — awk's `{print $N}` and `{print $1,$3}` |
| `sublimation where 'N OP V'` | lines whose field N satisfies the numeric predicate — awk's `$N OP V` |

e.g. `cat dump | sublimation quantile 0.99 --field 2` for a column's 99th percentile, `ps aux | sublimation where '6 > 100000'` to keep the heavy processes, `seq 1 1000 | shuf | sublimation characterize` to name a stream's shape. Order, percentile, selection, value lookup, the awk-style column / filter / reduce idioms, regex/substring matching and the structural verdict from one tool — the same engines montauk runs internally, on the command line. The division is by **target**: sublimation owns the **stream** — the column, filter, reduce, order and structure idioms — while `grep`, `find` and `awk` keep their own ground, filesystem traversal and the awk language itself.

**On the shell.** Nothing requires the pipe to name `sublimation` outright — a few `~/.bashrc` wrapper functions can route the stream forms of `grep`, `sort`, `wc` and `awk` to it, so `awk '{print $1,$3}'`, `awk '$2 > 100'` or `awk '/re/'` resolve to `field`, `where` or `grep`. The awk language proper (`BEGIN`/`END`, `NF`/`NR`, variables, `printf`, control flow) stays awk's. Route only the byte-for-byte idioms; leave the rest where it belongs.

**How it works.** Classification is one O(n) pass (run count, monotone runs, max descent gap); only ambiguous inputs pay for sampled inversions, distinct-value estimation and the full Young-tableau shape via patience sorting. The hook-length formula (Frame-Robinson-Thrall) gives the information-theoretic comparison bound, and the tableau shape routes: counting sort for few-unique (k ≤ 64), an R_eff merge tree (effective resistance on the run-boundary Laplacian) for structured runs, an O(n) rotation fix for rotated-sorted, binary insertion for low-displacement nearly-sorted and for random data a four-layer pipeline — PCF bucketing → AVX2/BMI2 block quicksort → pdqsort fat-pivot → AVX2 sorting networks at the leaves. A Jacobi-eigendecomposition spectral fallback (Fiedler seriation) catches partition degradation, gated by a CUSUM whose threshold rides a critically-damped oscillator. Type-generic across i32/i64/u32/u64/f32/f64; IPS4o-style parallel sort at n ≥ 250K.

**Performance** (AMD Ryzen 5 3600, Zen 2, `-O2 -march=native`, powersave governor, ns/element at 100K, best of 5):

| pattern | sublimation | introsort | qsort | Rust ipnsort |
|---|--:|--:|--:|--:|
| sorted | 0.2 | 6.1 | 25.3 | 0.3 |
| pipe_organ | 3.4 | 55.1 | 28.7 | 17.0 |
| few_unique | 14.5 | 18.6 | 54.8 | 2.7 |
| phased | 23.9 | 52.3 | 102.9 | 15.9 |
| random | 23.7 | 51.6 | 102.4 | 19.4 |

Beats libstdc++ introsort on 7/8 patterns and glibc qsort on 8/8 (1.3–65×); trails Rust ipnsort (the AVX2 comparison-sort floor) on uniform random by only ~1.2× on this Zen 2 part, ahead of it on sorted / equal / pipe-organ / nearly-sorted. The same AVX2+BMI2 paths the Zen 3 reference runs — no AVX-512 on either. String sort runs 2.0–4.5× over `qsort + strcmp`.

**Random-data size sweep** (same machine, ns/element, best of 5; 100M best of 3, sortedness-validated): the comparison sorts pay an O(n log n) tax at every step while the learned PCF pipeline stays ~flat. The gap to Rust ipnsort closes through 100K, **crosses ahead at 1M and holds the lead clear out to 100 million** — no L2 cliff, the dynamic-B bucketing stays flat across a 100× range.

| n | sublimation | introsort | qsort | Rust ipnsort |
|---|--:|--:|--:|--:|
| 1K | 24.9 | 30.7 | 62.7 | 8.4 |
| 10K | 21.7 | 41.2 | 83.5 | 11.8 |
| 100K | 23.1 | 51.4 | 102.4 | 14.6 |
| 1M | **15.6** | 61.3 | 123.7 | 17.5 |
| 10M | 16.6 | 71.2 | 143.2 | 20.1 |
| 100M | **17.6** | 80.8 | 163.7 | 21.8 |

From 1M to 100M sublimation holds ~16–18 ns/element while Rust ipnsort rises 17.5 → 21.8 and introsort and qsort rise faster still — the linear PCF pipeline pulling away from the O(n log n) comparison floor as n grows. At **100 million** random int64, sublimation sorts **1.24× faster than Rust ipnsort** (the AVX2 comparison-sort floor), **4.6× over introsort** and **9.3× over glibc qsort**.

**Lineage.** Robinson-Schensted correspondence (sorting ↔ Young tableaux), Dinic / Kyng maximum flow (the level-graph model), Fiedler spectral seriation (Atkins-Boman-Hendrickson), CoDel + damped-oscillator adaptive control and AlphaDev-shaped AVX2 sorting networks.

**Build.** Compiled as a static library with montauk — no system package, no fetch step. Requires a Haswell-or-newer CPU (BMI2 + AVX2) and gcc 13+ (C23). The prior C++23 TimSort/Powersort sort is retired (archived under `[0] ARCHIVE/montauk-timsort-cpp/`).

**Where montauk uses it:** the process-table sort and **the analyzer's orderings** (latency quantiles, report rows, struct-by-key sorts via `sublimation_order_*`, value lookups via `searchsorted`); the `sched` report's structure classification (`STRUCTURE`) and locator (`LOCATED`); and **all of montauk's text matching** — kernel-thread classification, the live `/`-search, the `--regex` filter and `--trace` token matching, on the in-house substring and regex engines. A handful of multi-key and hot-path partial-selection sorts stay on `std::` by design, where no single-key sublimation primitive fits.

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

`s` swaps the right-column chart stack for a comprehensive text panel: identity (hostname, kernel, uptime), runtime (collector, scheduler, process states), CPU (model, threads, freq/governor, load avg, ctxt-sw rate), GPU (model, util, NVML, power, p-state), memory, disk I/O, network, thermal margins and process-security findings — severity-coloured in place.

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

This builds the kernel module, installs it, sets up auto-load at boot and rebuilds montauk with kernel support.

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

See `montauk-kernel/README.md` for full documentation including architecture, protocol specification and troubleshooting.

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

When `--trace PATTERN` is specified, montauk enters headless trace mode powered by eBPF. It attaches BPF programs to kernel tracepoints (`sched_process_fork`, `sched_process_exec`, `sched_process_exit`, `raw_syscalls/sys_enter`, `raw_syscalls/sys_exit`, `sched_switch`, `sched_wakeup`, `signal_deliver`, scheduler-decision tracepoints and syscall-specific tracepoints for fd/mmap tracking) and to libc uprobes (heap allocation, abort path) for real-time, event-driven instrumentation. No `/proc` scanning, no text parsing, no TOCTOU races.

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
- **File I/O details** (v5.1.0): per-thread `read`, `write`, `lseek`, `pread64` and `fstat` tracking with full argument capture (fd, byte count, seek offset/whence) and return values. Enables diagnosing file I/O divergences between implementations — e.g., comparing a custom wineserver against stock to find exactly where file operations differ
- **futex** (v6.5.0): `futex` (202) captured through the I/O event — op (WAIT/WAKE plus PRIVATE/CLOCK flags), val and uaddr — so a trace shows a `FUTEX_WAKE` against a waiter and the op/uaddr to correlate wait/wake pairs
- **Heap allocation** (v6.5.0): `malloc`/`free`/`realloc`/`calloc` via libc uprobes, pairing size with returned address per-thread; realloc moves tracked. The event stream the heap-corruption reports fold over — no debugger attached to the workload
- **Signals and aborts** (v6.5.0): `tp/signal/signal_deliver` with a user-mode stack snapshot, abnormal-exit (`exit_code != 0`) postmortem stacks and libc abort-path uprobes (`__assert_fail`/`__libc_message`/`abort`) marking the point a glibc consistency check fires
- **File-backed mmap** (v6.5.0): `mmap` (anonymous mappings filtered) to distinguish arena growth from file mapping
- **Scheduler decisions** (v6.5.0): enqueue / pick / preempt / wakeup / wake-to-run latency, bound by generic role to whatever decision tracepoints the active scheduler exposes — montauk names no scheduler in source. Aggregated per-CPU by default (one counter increment, near-zero overhead); full per-event streaming is opt-in via `--trace-out`
- **On-CPU and migrations** (v6.5.0): current core per thread and a cross-core migration count, bucketed intra / cross / unknown-CCX against a sysfs-derived L3-domain map — cross-CCX moves (the L3-refill penalty) separated from cheap within-CCX shuffling, no PMU required
- **ntsync** (v6.5.0): Wine/Proton NT synchronization ioctls (semaphore/mutex/event create, signal, wait) with the waited-on object fds — the substrate for the sync-contention reports

Requires root at runtime (kernel tracepoint attachment requires `CAP_SYS_ADMIN` on most configurations). Build requires `libbpf`, `bpftool` and `clang` (BPF target). Auto-detected by CMake; if unavailable, `--trace` prints an error.

Trace mode composes with `--metrics` and `--log`. When combined with `--metrics PORT`, the Prometheus endpoint appends `montauk_trace_*` metrics alongside the standard system metrics:
- `montauk_trace_process_info{pid,ppid,cmd,root}` — process group membership
- `montauk_trace_thread_state{pid,tid,comm,state}` — per-thread state
- `montauk_trace_thread_cpu_percent{pid,tid,comm}` — per-thread CPU utilization
- `montauk_trace_thread_syscall{pid,tid,comm,syscall,wchan}` — current syscall and wait channel
- `montauk_trace_thread_io{pid,tid,comm,syscall,fd,count,result,whence}` — file I/O details: last read/write/lseek/pread64/fstat per thread with fd, byte count or seek offset, return value and seek whence. Correlate with `fd_target` to see full file I/O sequences per file
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
- `montauk_analyze FILE [--report name[,name...]]` — single-pass diagnostic reports (default: all). Each folds events once over the file (`montauk_analyze --version` prints the version and exits, so a consumer can tell a current install from a stale one):
  - `summary` — header, duration, throughput, per type+subtype counts, and the trace-derived scheduler rates `montauk_analysis_dispatches_per_sec` / `montauk_analysis_preempts_per_sec`
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
  - `slice` — per-CPU dispatched-slice length: the interval between consecutive PICKs on one CPU (how long the picked task ran before that CPU picked again), with p50/p90/p99/worst/mean; idle strands (gaps over 10ms) excluded. The per-slice multiplier behind a saturation tail (tail ≈ pass-over depth × slice)

**Over a recording directory.** Beyond a single binary log, `montauk_analyze` reads a whole `--trace` recording — the `montauk_*.prom` scrapes beside the sibling `.events`:

- `RECORDING_DIR --digest [--redact]` — the one-call shareable report. A `SCHEDULER STABILITY` block (ejection and clean-room state — what invalidates every number under it) leads **above** `SYSTEM` specs, then the ranked `POORLY-BEHAVING ITEMS` (a consolidated `montauk_offender{}` view over the spin / pairing / idle-strand detectors and the L2 hot-CPU), a `CROSS-CCX PLACEMENT` block (per-path scatter attribution), a `THERMAL/POWER` block (temp, fan, package power and the window-integral energy, clock, idle-state residency, scheduler churn), then `KEY METRICS` (the wake-to-run verdict and the dispatch-stall mechanism). Stability-first, specs early and KB-scale; `--redact` swaps process comms for stable FNV-1a hash handles for public sharing. With no `.events` present it still reports stability, specs, thermal/power and the offenders derivable from the scrapes.
- `RECORDING_DIR --l2-by-cpu` — per-CPU L2-miss localization over the busy (storm) window: which cores eat the misses, and how concentrated.
- `DIR | *.prom [--by version|scheduler] [--metric SUBSTR] [--full]` — population statistics across many runs: cross-version / cross-scheduler inference (Cliff's delta, permutation test, Monte-Carlo power) over the `.prom` archives, the inferential unit being one run.

**Hardware Performance Counters (PMU):**

Trace mode additionally samples hardware counters via `perf_event_open`: per-CPU L2 cache misses/references (AMD Zen raw events), instructions, cycles, context-switches, CPU-migrations, branch-misses and — where the `amd_uncore` module exposes the `amd_l3` PMU — per-CCX L3 accesses/misses. Derived rates (IPC, L2 miss percent, cycles-per-L2-miss, misses/sec, per-second context-switch/migration/branch-miss rates) export as the `montauk_pmu_*` gauge families. The `amd_l3` event encoding is read entirely from sysfs, nothing hardcoded but the documented Zen2 fallback. This is the cache-placement signal that pairs with the CCX-migration counters: misses explain why cross-CCX moves hurt.

Alongside the counters, montauk derives the efficiency picture from sysfs on the same recording stream: package power from the powercap RAPL energy counters (`montauk_power_watts`) plus a wrap-safe cumulative package energy (`montauk_package_energy_joules_total`, a counter whose delta is the window-integral energy over a recording — the digest's `energy-tot J`), average CPU frequency across online cores (`montauk_cpu_frequency_mhz_avg`), per-state idle residency (`montauk_cstate_residency_percent{state}`) and energy-per-instruction (`montauk_energy_per_instruction_pj`, power over the instruction rate). One capture carries temperature, power, clock, idle depth, scheduler churn and the efficiency they imply.

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

**Note:** Three views, each on its own column. Default — pixel-rendered area charts (PROCESSOR, GPU, VRAM, GPU MEM, ENC, DEC, MEMORY, NETWORK) on the right, PROCESS MONITOR on the left — both via the terminal graphics protocol (Kitty primary, Sixel fallback). `s` swaps the right column to a comprehensive text panel covering identity, runtime, CPU, GPU, memory, disk, network, thermal and process statistics. `Shift+C` swaps the left column to a per-core CPU TOPOLOGY grid, one mini area-chart per logical CPU, with auto-fit geometry and scroll fallback for high-core systems. The two toggles are orthogonal — left and right column states are independent.

## Configuration

montauk reads a unified TOML file at `~/.config/montauk/config.toml`, resolving each value **TOML → `MONTAUK_*` environment variable → compiled default** — no file means compiled defaults at zero overhead. `montauk --init-theme` writes a starter with your terminal's 16-color palette detected. The full schema (`[palette]`, `[roles]`, `[thresholds]`, `[ui]`, `[process]`, `[nvidia]`, `[keybinds]`), the process-collector settings and the complete `MONTAUK_*` environment-variable reference live in [`CONFIG.md`](CONFIG.md).

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

## Display

The process columns (PID / USER / CPU% / GPU% / GMEM / MEM / COMMAND), the two-column layout, the SYSTEM-focus box and the severity color coding are documented in [`CONFIG.md`](CONFIG.md#display-details).

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
montauk_analyze RECORDING_DIR --digest          # one-call shareable digest
montauk_analyze --version                       # print version, exit
```

The report suite (`summary`, `waits`, `spins`, `pairing`, `abortpm`, `endstate`, `heapstk`, `doublefree`, `futex`, `keyedevt`, `sched`, `slice`) is described under **Trace Mode → Binary Event Log** above. Each report folds the file in a single pass, so analysis scales to captures of 450 MB+. These answer the questions that come up debugging sync contention and heap corruption — a wedged thread, a livelock spin, a double-free race, a glibc abort's victim allocation — post-hoc from one capture, no rerun.

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
- `sublimation::NFA` / `sublimation::BMH` — montauk's regex and substring search are sublimation primitives: the Thompson NFA (RE2-style, UTF-8 byte lowering, 256-bit class bitmasks, shunting-yard build, zero-allocation simulation) in `sublimation/src/text/nfa.c` and Boyer-Moore-Horspool in `bmh.c`, reached through header-only C++ wrappers. The former `util::ThompsonNFA` / `util::BoyerMoore` are retired (1:1-ported into sublimation)
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

## Runtime Cost

montauk's own footprint, by collection backend (the sort benchmarks are in the [sublimation](#sublimation--montauks-search-sort-and-match-core) section):

- **CPU:** ~0.1–0.2% with the kernel module, ~0.5–1% with netlink `proc_connector`, ~2–5% with `/proc` polling.
- **Process detection:** sub-millisecond (kernel module / netlink), ~1s (`/proc` polling).
- **Syscalls:** 1 per snapshot (kernel module), ~1 + N events (netlink), ~3 per process (`/proc`).
- **Sampling:** 250ms default (`+`/`-` to adjust).
- **Process table:** 256 default, up to 4096 (top by CPU), all cmdline-enriched for GPU attribution.
- **Memory:** ~10MB resident.

## Policy

**sublimation is an in-tree sub-system:** montauk's search/sort/match core lives at `montauk/sublimation/`, vendored in the tree and compiled into the montauk build — no system package, no fetch, no runtime fallback. NVML and liburing are auto-detected and gracefully disabled when unavailable.

## License

GPL-2.0 — see the [`LICENSE`](LICENSE) file. sublimation, montauk's in-tree search/sort/match core, is covered by the same license. One license, one tree.
