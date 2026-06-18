# montauk — Configuration & Display Reference

The lookup material for montauk: the TOML configuration schema, the `MONTAUK_*` environment-variable fallbacks, and the display/column reference. The [README](README.md) carries the narrative; this is what you reach for to tune montauk or read its screen.

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
- COMMAND column: Binary name highlighted, path prefixes and arguments muted, kernel threads fully muted (classified via sublimation's Thompson NFA)
- GPU%: Severity coloring mirroring CPU% thresholds
