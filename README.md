```
███╗   ███╗  ██████╗  ███╗   ██╗ ████████╗  █████╗  ██╗   ██╗ ██╗  ██╗
████╗ ████║ ██╔═══██╗ ████╗  ██║ ╚══██╔══╝ ██╔══██╗ ██║   ██║ ██║ ██╔╝
██╔████╔██║ ██║   ██║ ██╔██╗ ██║    ██║    ███████║ ██║   ██║ █████╔╝ 
██║╚██╔╝██║ ██║   ██║ ██║╚██╗██║    ██║    ██╔══██║ ██║   ██║ ██╔═██╗ 
██║ ╚═╝ ██║ ╚██████╔╝ ██║ ╚████║    ██║    ██║  ██║ ╚██████╔╝ ██║  ██╗
╚═╝     ╚═╝  ╚═════╝  ╚═╝  ╚═══╝    ╚═╝    ╚═╝  ╚═╝  ╚═════╝  ╚═╝  ╚═╝
```

## Overview

A standalone, offline‑friendly C++23 system monitor for Linux with comprehensive GPU support. No external dependencies required for the default build.

**Key Features:**
- **Deep GPU Integration**: Per-process GPU utilization and memory tracking with intelligent attribution
- **Multi-vendor Support**: NVIDIA (NVML + fallbacks), AMD (sysfs), Intel (fdinfo)
- **Sophisticated Attribution**: Multiple fallback mechanisms for GPU metrics when vendor APIs are unavailable
- **Thermal Monitoring**: Multi-sensor temperature tracking (edge, hotspot, memory) with vendor-specific thresholds
- **Process Tracking**: Up to 256 processes with full command-line enrichment for accurate identification
- **Atomic Snapshots**: Minimal CPU overhead with lock-free snapshot publication
- **Zero Dependencies**: Builds with standard library only; NVML auto-detected and optional
- **Churn Resilient**: Handles /proc and /sysfs transients gracefully during heavy system activity

## Build

```bash
make build    # Release build
make debug    # Debug build with symbols
make clean    # Clean build artifacts
```

## Installation

**Local build:**
```bash
./build/montauk
```

**System install (Arch Linux):**
```bash
makepkg -si   # From PKGBUILD in pkg/ directory
```

**CMake install:**
```bash
cmake --install build --prefix /usr/local
```

## UI Controls

**Navigation:**
- `q` — Quit
- `↑/↓` — Scroll process list
- `PgUp/PgDn` — Page up/down

**Sorting:**
- `c` — Sort by CPU%
- `m` — Sort by Memory
- `g` — Sort by GPU%
- `v` — Sort by GPU Memory (GMEM)
- `p` — Sort by PID
- `n` — Sort by Name

**Display Toggles:**
- `G` — Toggle GPU panel
- `t` — Toggle Thermal panel
- `d` — Toggle Disk panel
- `N` — Toggle Network panel
- `h` — Toggle help line

**Modes:**
- `i` — Toggle CPU scale (machine-share ↔ per-core)
- `u` — Toggle GPU scale (reserved for future modes)
- `+/-` — Increase/decrease refresh rate

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
- Runtime: `nvidia-utils` (provides `libnvidia-ml.so`)
- Build: `cuda` package (provides `/opt/cuda/include/nvml.h`)

**Fallback Chain** (when NVML unavailable or insufficient):
1. `nvidia-smi pmon` — Per-process utilization sampling
2. `nvidia-smi --query-compute-apps` — Compute context memory
3. `/proc/driver/nvidia/gpus/*/fb_memory_usage` — Device VRAM
4. Heuristic distribution based on device-level metrics

### AMD/Intel

- `/sys/class/drm` — VRAM usage, temperatures, power
- `/proc/*/fdinfo` — Per-process GPU utilization (DRM)
- `gpu_busy_percent` — Device utilization

### Browser GPU Process Detection

Montauk automatically identifies browser GPU processes (Chrome, Chromium, Helium, etc.) by:
- Scanning for `--type=gpu-process` in command lines
- Enriching up to 256 processes with full cmdline data
- Applying intelligent fallback attribution when processes use minimal CPU
- Using `/proc/*/fd` device file inspection for decode-only workloads

### GPU Environment Variables

```bash
MONTAUK_NVIDIA_PMON=0     # Disable nvidia-smi pmon fallback (default: 1)
MONTAUK_NVIDIA_MEM=0      # Disable nvidia-smi memory query (default: 1)
MONTAUK_LOG_NVML=1        # Enable NVML debug logging
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
- CPU% and GPU% show **1%** for any non-zero activity (0.01%-0.49%)
- This makes low-activity processes clearly visible instead of appearing idle

## Churn Handling

During heavy system activity (builds, installs), `/proc` and `/sys` entries can vanish between directory scans and file reads. Montauk handles this gracefully:

**Per-process signal:**
- Churned processes show `PROC CHURN DETECTED` in place of metrics
- Colored as WARNING
- Clears on next successful sample

**System summary:**
- Sticky banner: `PROC CHURN  N events [LAST 2s]`
- Auto-hides when churn subsides

Example:
```
  PID     USER      CPU%  GPU%  GMEM   MEM    COMMAND
103923  mod       38.4    0     0M   350M   cc1plus -quiet...
103981  mod       PROC CHURN DETECTED       cc1plus -quiet...  ⚠
103931  mod       21.4    0     0M   441M   cc1plus -quiet...
```

## Configuration (Environment Variables)

### UI/Terminal
```bash
MONTAUK_ALT_SCREEN=0           # Disable alt screen (default: 1)
MONTAUK_TITLE_HEX=#FFB000      # Title color (hex)
MONTAUK_TITLE_IDX=214          # Title color (palette index)
```

### Colors/Thresholds
```bash
MONTAUK_ACCENT_IDX=39          # Accent color
MONTAUK_CAUTION_IDX=220        # Caution color  
MONTAUK_WARNING_IDX=196        # Warning color
MONTAUK_PROC_CAUTION_PCT=50    # Process caution threshold
MONTAUK_PROC_WARNING_PCT=80    # Process warning threshold
```

### Alerts
```bash
MONTAUK_TOPPROC_ALERT_FRAMES=5  # Frames before top-proc alert (default: 5)
                                 # Lower = more sensitive, higher = sustained load only
```

### Process Display
```bash
MONTAUK_PROC_CPU_SCALE=total   # Default CPU scale: total|core
MONTAUK_COPY_FRONT=1           # Snapshot copy for concurrency safety (default: 1)
```

### Thermal Thresholds

**Dynamic (preferred):**
- NVIDIA: Auto-discovered via NVML (slowdown, mem_max)
- AMD/Intel: Auto-discovered via sysfs hwmon (crit, max, emergency)

**Overrides:**
```bash
# Generic CPU/GPU
MONTAUK_CPU_TEMP_WARNING_C=90
MONTAUK_CPU_TEMP_CAUTION_C=80
MONTAUK_GPU_TEMP_WARNING_C=90
MONTAUK_GPU_TEMP_CAUTION_C=80
MONTAUK_TEMP_CAUTION_DELTA_C=10   # Default offset when only warning known

# GPU per-sensor overrides
MONTAUK_GPU_TEMP_EDGE_WARNING_C=85
MONTAUK_GPU_TEMP_EDGE_CAUTION_C=75
MONTAUK_GPU_TEMP_HOT_WARNING_C=95
MONTAUK_GPU_TEMP_HOT_CAUTION_C=85
MONTAUK_GPU_TEMP_MEM_WARNING_C=95
MONTAUK_GPU_TEMP_MEM_CAUTION_C=85

# Display thresholds inline
MONTAUK_SHOW_TEMP_WARN=1          # Show warning temps on thermal lines
```

### Testing/Development
```bash
MONTAUK_PROC_ROOT=/custom/proc    # Remap /proc paths
MONTAUK_SYS_ROOT=/custom/sys      # Remap /sys paths
```

## Testing

**Build with tests:**
```bash
cmake -S . -B build -DMONTAUK_BUILD_TESTS=ON
cmake --build build -j
./build/montauk_tests
```

**Self-test mode:**
```bash
./build/montauk --self-test-seconds 5
```

**Note:** Tests are disabled by default in packaging builds.

## Uninstall (CMake)

```bash
sudo xargs rm -v < build/install_manifest.txt
```

## Packaging (Arch Linux)

- PKGBUILD provided in `pkg/` directory
- NVML auto-detected at build time
- Build deps: `cmake`, `gcc`, `make`
- Optional runtime: `nvidia-utils`
- Tests disabled by default: `MONTAUK_BUILD_TESTS=OFF`

**Install:**
```bash
makepkg -si
```

**Result:** `/usr/bin/montauk`

## Architecture

**Collectors:**
- `CpuCollector` — Per-core usage, freq, model
- `MemoryCollector` — RAM, swap, buffers, cache
- `ProcessCollector` — Top 256 processes by CPU, full cmdline enrichment
- `GpuCollector` — VRAM, temps, power (multi-vendor)
- `GpuAttributor` — Per-process GPU util/mem with fallback chains
- `NetCollector` — Interface stats, throughput
- `DiskCollector` — I/O stats, throughput  
- `ThermalCollector` — Multi-sensor temps with vendor thresholds

**Snapshot Pipeline:**
1. Collectors sample independently
2. Atomic snapshot publication
3. GpuAttributor enriches with per-process GPU data
4. UI renders from stable snapshot (optional copy for concurrency)

**GPU Attribution Logic:**
1. NVML per-process queries (preferred)
2. `nvidia-smi pmon` parsing
3. `/proc/*/fdinfo` DRM stats
4. Heuristic distribution from device metrics
5. Residual VRAM attribution to clear GPU processes
6. `/proc/*/fd` device inspection for decode workloads

## Performance

- **Overhead:** <1% CPU on typical systems
- **Sampling:** 500ms default (adjustable with +/-)
- **Process limit:** 256 (top by CPU usage)
- **Cmdline enrichment:** All 256 processes (full command lines for accurate GPU detection)
- **Memory:** ~10MB resident

## Policy

**No external dependencies** for default build. NVML is auto-detected and gracefully disabled when unavailable. No vendoring, no FetchContent, no ExternalProject.

## License

MIT License. See LICENSE file in repository.
