GPU% Tracking Improvements — Notes & Next Steps

Context
- Symptom: Per‑process GPU% sparsity/zeros (esp. decode‑heavy apps like Helium), “window closing” between polls, occasional UI stalls.
- Goal: Default, no‑flags, steady and honest per‑process GPU% that reflects compute (SM) and video engines (ENC/DEC), with a responsive UI.

What’s Implemented
- NVML usage (always on by default)
  - Auto‑detect + link NVML in CMake.
  - Persistent NVML session (init once, shutdown at exit).
  - Per‑device last utilization timestamps; query since last ts (with a small timestamp fudge −200ms to avoid edge misses).
  - Throttled NVML per‑process sampling (~1 Hz) to keep the UI instantaneous.
  - MIG detection; per‑process GPU% disabled when MIG is enabled.

- Per‑process attribution
  - Combine engines: per‑PID GPU% = max(SM, ENC, DEC) per NVML sample.
  - Presence‑aware smoothing: EMA + 3s hold; decay to 0 over 3s (6s if still “running”); fast exit fade (0.5s).
  - “Running” PIDs gathered via NVML (graphics+compute) each tick.
  - Fallbacks when samples are missing:
    - If exactly one running PID: attribute device engine util (max of G/ENC/DEC) to that PID.
    - If multiple running PIDs and no samples: distribute device util proportionally to per‑PID GPU memory (if available), else equal split (ensure ≥1%).

- Diagnostics & UI controls
  - Always show NVML line when available: OK/OFF, dev, run, samp, age(ms), mig:on|off.
  - Keyboard ‘u’: toggle GPU% display Raw vs Smooth (no envs).
  - Tests: added gpu_cache_persists_between_samples; all tests pass.

Current Behavior (observed)
- “Window closing” fixed: values persist while NVML lists the PID as running, and decoders are counted (ENC/DEC) via max(SM,ENC,DEC).
- For some drivers/workloads, run>0 but samp=0 intermittently; fallbacks kick in so decode‑heavy apps don’t sit at 0, but mixed workloads can still be imperfect.

Known Gaps / Edge Cases
- NVML may not return per‑process samples for some decode‑only workloads (driver dependent). Device‑level util shows activity; per‑PID may be missing.
- Heuristics (single PID, mem‑weighted, equal split) can misattribute when multiple GPU processes are active with similar footprints.
- MIG: per‑process util unsupported; we skip.
- Non‑NVIDIA (Intel/AMD) decode activity is invisible to NVML; only device‑level appears.

Next Steps (targeted)
1) Show per‑process GPU memory (GMEM) column in PROCESS MONITOR (optional toggle) to make attribution heuristics visible while debugging.
2) Add a tiny marker when a row’s GPU% is attributed via fallback (vs. sampled) to aid validation.
3) Consider sampling NVML in a background task to fully isolate any driver hiccups from the UI loop.
4) Investigate NVML accounting APIs (where supported) as a secondary source when process utilization samples are sparse.
5) For AMD/Intel, optionally parse DRM fdinfo (nvtop approach) to attribute GPU engine usage per process on non‑NVIDIA systems.
6) Tune smoothing windows dynamically based on sample age (shorten hold when fresh; lengthen decay when presence persists).

What To Capture During Debugging
- NVML line (OK/OFF dev:X run:Y samp:Z age:Nms mig:off|on) while the app is active.
- The app’s PID(s) and whether Raw (‘u’ once) shows any blips.
- Whether per‑process GPU memory is non‑zero for the target PID.

Rollback / Safeguards
- Smoothing can be toggled via ‘u’ (Raw/Smooth).
- All fallbacks are disabled under MIG.

