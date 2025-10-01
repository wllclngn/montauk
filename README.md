Legendary Linux Terminal System Monitor (C++23)

Overview
- Standalone, offline‑friendly C++23 system monitor for Linux. No external libraries or packages are required to build and run the default text mode.
- Collectors: CPU, Memory, Net, Disk, Processes, GPU VRAM (proc/sysfs), Thermal.
- Atomic snapshot publication; minimal CPU overhead.
- NVIDIA support via NVML is auto-detected at build; recommended for reliable VRAM/power on NVIDIA.
 - HOT start pre‑warm: first visible frame has real deltas (no startup flicker).

Build
- Release: `make build`
- Debug: `make debug`
- Clean: `make clean` / `make distclean`

Run
- Text mode (default): `./build/lsmcpp [--iterations N] [--sleep-ms MS]`
- Self test: `./build/lsmcpp --self-test-seconds 5`

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
- Want a gentler or stricter top‑proc alert? Set `LSM_TOPPROC_ALERT_FRAMES` (e.g., `2` for sensitive, `12` for sustained).
- Avoid alt screen if you plan to copy/paste terminal contents: `LSM_ALT_SCREEN=0 ./build/lsmcpp`.
- Concurrency‑safe rendering is enabled by default by copying each snapshot at frame start. Disable for maximal throughput: `LSM_COPY_FRONT=0`.

 

NVIDIA (NVML)
- NVML is auto-detected; no flags required. If found, per-process GPU% and additional device metrics are enabled. If not found, the build continues without NVML.
  - Runtime: ensure `nvidia-utils` is installed (provides `libnvidia-ml.so`).
  - Headers: ensure `cuda` is installed (provides `/opt/cuda/include/nvml.h`).

Policy: No Secondary Dependencies
- The default build uses only the C++ standard library and Linux kernel interfaces (/proc, /sys). NVML (for NVIDIA GPU metrics) is attempted automatically and gracefully disabled when not found.

Packaging (Arch Linux)
- A `PKGBUILD` is provided. NVML is auto-detected. The UI is text‑only.
- Dependencies: `nvidia-utils` (runtime), build deps: `cmake`, `cuda`.
- Install: `makepkg -si`
- Result: `/usr/bin/lsmcpp` (text UI).

Tests
- `make test` runs a lightweight test suite (no external framework) writing temporary fixtures under `/tmp`.

Configuration (Environment Variables)
- UI/Terminal
  - `LSM_ALT_SCREEN`=1|0: use alt screen (default 1).
  - `LSM_TITLE_IDX` (palette index) or `LSM_TITLE_HEX` (e.g., `#FFB000`) for title color.
- Colors/Thresholds
  - `LSM_ACCENT_IDX`, `LSM_CAUTION_IDX`, `LSM_WARNING_IDX`: palette indices for accent/caution/warning.
  - `LSM_PROC_CAUTION_PCT`, `LSM_PROC_WARNING_PCT`: process CPU% color thresholds.
- Alerts
  - `LSM_TOPPROC_ALERT_FRAMES`: consecutive frames above warning required to show the top‑proc banner (default 5). Respects current CPU scale.
- Processes
  - `LSM_PROC_CPU_SCALE`=total|core: default process CPU scale (total = machine‑share, core = per‑core).
  - `LSM_COPY_FRONT`=1|0: copy the live snapshot at frame start to avoid read/write overlap (default 1).
 - Thermals
   - Dynamic thresholds are discovered from vendor APIs where possible:
     - NVIDIA (NVML): slowdown (warning) for GPU edge; memory max for VRAM temp when available.
     - AMD/Intel (sysfs/hwmon): per‑sensor crit/max/emergency files (edge/junction/hotspot/mem) used as warning.
   - Fallback and overrides:
     - Shared delta: `LSM_TEMP_CAUTION_DELTA_C` (default 10°C) when only a warning is known.
     - CPU: `LSM_CPU_TEMP_WARNING_C` (default 90), `LSM_CPU_TEMP_CAUTION_C` (default warning − delta).
     - GPU generic: `LSM_GPU_TEMP_WARNING_C` (default 90), `LSM_GPU_TEMP_CAUTION_C` (default warning − delta).
     - GPU per‑sensor warning/ca ution overrides:
       - Edge: `LSM_GPU_TEMP_EDGE_WARNING_C`, `LSM_GPU_TEMP_EDGE_CAUTION_C`
       - Hotspot: `LSM_GPU_TEMP_HOT_WARNING_C`, `LSM_GPU_TEMP_HOT_CAUTION_C`
       - Memory: `LSM_GPU_TEMP_MEM_WARNING_C`, `LSM_GPU_TEMP_MEM_CAUTION_C`
   - Show resolved warning thresholds inline on THERMALS lines: `LSM_SHOW_TEMP_WARN`=1|0 (default 0).
- Testing/Dev
  - `LSM_PROC_ROOT` remaps absolute `/proc` paths.
  - `LSM_SYS_ROOT` remaps absolute `/sys` paths.
