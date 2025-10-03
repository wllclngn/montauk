```
███╗   ███╗  ██████╗  ███╗   ██╗ ████████╗  █████╗  ██╗   ██╗ ██╗  ██╗
████╗ ████║ ██╔═══██╗ ████╗  ██║ ╚══██╔══╝ ██╔══██╗ ██║   ██║ ██║ ██╔╝
██╔████╔██║ ██║   ██║ ██╔██╗ ██║    ██║    ███████║ ██║   ██║ █████╔╝ 
██║╚██╔╝██║ ██║   ██║ ██║╚██╗██║    ██║    ██╔══██║ ██║   ██║ ██╔═██╗ 
██║ ╚═╝ ██║ ╚██████╔╝ ██║ ╚████║    ██║    ██║  ██║ ╚██████╔╝ ██║  ██╗
╚═╝     ╚═╝  ╚═════╝  ╚═╝  ╚═══╝    ╚═╝    ╚═╝  ╚═╝  ╚═════╝  ╚═╝  ╚═╝
```

Overview
- Standalone, offline‑friendly C++23 system monitor for Linux. No external libraries or packages are required to build and run the default text mode.
- Collectors: CPU, Memory, Net, Disk, Processes, GPU VRAM (proc/sysfs), Thermal.
- Atomic snapshot publication; minimal CPU overhead.
- NVIDIA support via NVML is auto-detected at build; recommended for reliable VRAM/power on NVIDIA.
 - HOT start pre‑warm: first visible frame has real deltas (no startup flicker).
 - Robust to /proc and /sysfs churn: transient disappearances are handled and surfaced as warnings (see below).

Build
- Release: `make build`
- Debug: `make debug`
- Clean: `make clean` / `make distclean`
- One-shot install: `./scripts/auto_install.sh` (to `/usr/local`)

Run
- Text mode (default): `./build/montauk [--iterations N] [--sleep-ms MS]`
- Self test: `./build/montauk --self-test-seconds 5`
- System install path: `/usr/local/bin/montauk` (via CMake install)

UI Controls
- q: quit
- c/m/p/n: sort by CPU/MEM/PID/NAME
- +/-: increase/decrease refresh rate (FPS)
- ↑/↓/PgUp/PgDn: scroll process table
- g/t/d/N: toggle GPU/Thermal/Disk/Net panels
- i: toggle process CPU scale (total machine‑share vs per‑core)
- h: show/hide help line

CPU Scale (Processes)
- Default = total/machine‑share. A process at 100% means it uses the entire machine’s CPU capacity; multiple processes sum sensibly toward the big CPU bar.
- Toggle to per‑core scale with `i` (IRIX‑style: one full core = 100%, two cores = 200%, etc.).

Quick Tips
- Prefer machine‑share CPU (default). Press `i` to flip to per‑core if you want IRIX‑style numbers.
- Want a gentler or stricter top‑proc alert? Set `MONTAUK_TOPPROC_ALERT_FRAMES` (e.g., `2` for sensitive, `12` for sustained).
- Avoid alt screen if you plan to copy/paste terminal contents: `MONTAUK_ALT_SCREEN=0 ./build/montauk`.
- Concurrency‑safe rendering is enabled by default by copying each snapshot at frame start. Disable for maximal throughput: `MONTAUK_COPY_FRONT=0`.

Proc/Sysfs Churn Warnings
- Context: On busy systems (e.g., during package installs or large builds), entries under `/proc` and `/sys` can appear and disappear between directory iteration and file reads. Previously, this could surface as a C++ iostream failure. Montauk now treats these as transient “churn” and reports them without crashing.
- Process row signal (per‑row): when a process churns during sampling, its row is colored as a WARNING and the numeric columns are replaced by the message below. It sorts like `0%` CPU and clears on the next clean sample.
  - Display: `PROC CHURN DETECTED` (replaces `CPU%  GPU%  GMEM  MEM`)
- System sticky summary: a short‑lived line appears under the TEMP entries counting churn events in the recent window across both `/proc` and `/sys`.
  - Display: `PROC CHURN  N events [LAST 2s]` (WARNING/red). Auto‑hides when churn subsides.
- Example (rows shown inline with a churned process):
  
      PID     USER      CPU%  GPU%  GMEM   MEM    NAME
      103923  mod       38.4    0     0M   350M   cc1plus -quiet -I ext/…
      103981  mod       PROC CHURN DETECTED       cc1plus -quiet -I ext/…    (warning/red line)
      103931  mod       21.4    0     0M   441M   cc1plus -quiet -I ext/…
  
  SYSTEM (excerpt)
  
      CPU TEMP                                             57°C
      GPU TEMP                                             E:57°C
      
      PROC CHURN                              3 events [LAST 2s]         (warning/red)

 

NVIDIA (NVML)
- NVML is auto-detected; no flags required. If found, per-process GPU% and additional device metrics are enabled. If not found, the build continues without NVML.
  - Runtime: ensure `nvidia-utils` is installed (provides `libnvidia-ml.so`).
  - Headers: ensure `cuda` is installed (provides `/opt/cuda/include/nvml.h`).

Policy: No Secondary Dependencies
- The default build uses only the C++ standard library and Linux kernel interfaces (/proc, /sys). NVML (for NVIDIA GPU metrics) is attempted automatically and gracefully disabled when not found.

Packaging (Arch Linux)
- A PKGBUILD is provided. NVML is auto‑detected. The UI is text‑only.
- Build deps: `cmake`, `gcc`, `make`. Optional runtime: `nvidia-utils`.
- Tests are disabled by default for packaging: `MONTAUK_BUILD_TESTS=OFF`.
- Install: `makepkg -si`
- Result: `/usr/bin/montauk` (text UI).

Notes
- Paths with spaces: PKGBUILD mitigates Arch’s `-ffile-prefix-map` issue; if you still encounter it, use the helper: `./scripts/system_install.sh --aur`.
- Direct CMake install: `./scripts/system_install.sh --cmake` (installs to `/usr/local`).

Tests
- Enable in CMake: `cmake -S . -B build -DMONTAUK_BUILD_TESTS=ON && cmake --build build -j && ./build/montauk_tests`
- The `Makefile` target `make test` assumes tests are built already.
- Packaging disables tests by default.

Uninstall (CMake installs)
- `sudo xargs rm -v < build/install_manifest.txt`

Configuration (Environment Variables)
- UI/Terminal
  - `MONTAUK_ALT_SCREEN`=1|0: use alt screen (default 1).
  - `MONTAUK_TITLE_IDX` (palette index) or `MONTAUK_TITLE_HEX` (e.g., `#FFB000`) for title color.
- Colors/Thresholds
  - `MONTAUK_ACCENT_IDX`, `MONTAUK_CAUTION_IDX`, `MONTAUK_WARNING_IDX`: palette indices for accent/caution/warning.
  - `MONTAUK_PROC_CAUTION_PCT`, `MONTAUK_PROC_WARNING_PCT`: process CPU% color thresholds.
- Alerts
  - `MONTAUK_TOPPROC_ALERT_FRAMES`: consecutive frames above warning required to show the top‑proc banner (default 5). Respects current CPU scale.
- Processes
  - `MONTAUK_PROC_CPU_SCALE`=total|core: default process CPU scale (total = machine‑share, core = per‑core).
  - `MONTAUK_COPY_FRONT`=1|0: copy the live snapshot at frame start to avoid read/write overlap (default 1).
 - Thermals
   - Dynamic thresholds are discovered from vendor APIs where possible:
     - NVIDIA (NVML): slowdown (warning) for GPU edge; memory max for VRAM temp when available.
     - AMD/Intel (sysfs/hwmon): per‑sensor crit/max/emergency files (edge/junction/hotspot/mem) used as warning.
   - Fallback and overrides:
     - Shared delta: `MONTAUK_TEMP_CAUTION_DELTA_C` (default 10°C) when only a warning is known.
     - CPU: `MONTAUK_CPU_TEMP_WARNING_C` (default 90), `MONTAUK_CPU_TEMP_CAUTION_C` (default warning − delta).
     - GPU generic: `MONTAUK_GPU_TEMP_WARNING_C` (default 90), `MONTAUK_GPU_TEMP_CAUTION_C` (default warning − delta).
     - GPU per‑sensor warning/ca ution overrides:
       - Edge: `MONTAUK_GPU_TEMP_EDGE_WARNING_C`, `MONTAUK_GPU_TEMP_EDGE_CAUTION_C`
       - Hotspot: `MONTAUK_GPU_TEMP_HOT_WARNING_C`, `MONTAUK_GPU_TEMP_HOT_CAUTION_C`
       - Memory: `MONTAUK_GPU_TEMP_MEM_WARNING_C`, `MONTAUK_GPU_TEMP_MEM_CAUTION_C`
   - Show resolved warning thresholds inline on THERMALS lines: `MONTAUK_SHOW_TEMP_WARN`=1|0 (default 0).
- Testing/Dev
  - `MONTAUK_PROC_ROOT` remaps absolute `/proc` paths.
  - `MONTAUK_SYS_ROOT` remaps absolute `/sys` paths.
