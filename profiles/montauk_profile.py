#!/usr/bin/env python3
"""montauk_profile: generic capture -> analyze -> report harness.

montauk measures; this orchestrates and assembles, nothing more. An application
describes a Profile -- what to trace, which montauk_analyze reports to run, an
optional producer-marker hook for internal state the trace cannot see, and an
optional report assembler -- and calls run_profile(). Generic applications need
no code: the CLI builds a Profile from flags (command / attach / trace).

The division of labour, by design:
  - generic capture/analyze/assemble lives HERE (a montauk feature any app uses);
  - application-specific report content (quark's heap/object/window analysis)
    lives in the application's own harness via the assemble hook. Anything an app
    finds it is hand-rolling that is actually generic belongs back in here.

This is MontaukTrace (formerly duplicated in PANDEMONIUM's pandemonium_common)
generalised out so it is no longer copied per project. montauk is the only
tracer -- no ftrace/perf/strace anywhere.
"""

import argparse
import os
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional


# montauk binary discovery: installed location first, then a sibling source
# build (montauk/build/), then PATH. Overridable via env for unusual layouts.
def _find_bin(name: str, env_key: str) -> str:
    override = os.environ.get(env_key)
    if override and Path(override).exists():
        return override
    here = Path(__file__).resolve()
    candidates = [
        Path("/usr/local/bin") / name,
        Path("/usr/bin") / name,
        here.parent.parent / "build" / name,   # montauk/build/<name>
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
    found = subprocess.run(["bash", "-lc", f"command -v {name}"],
                           capture_output=True, text=True)
    return found.stdout.strip() or name


MONTAUK = _find_bin("montauk", "MONTAUK_BIN")
MONTAUK_ANALYZE = _find_bin("montauk_analyze", "MONTAUK_ANALYZE_BIN")

ATTACH_TIMEOUT = 10.0
LOG_INTERVAL_MS = 100


def _ts() -> str:
    return datetime.now().strftime("[%H:%M:%S]")


def log_info(m: str) -> None:
    print(f"{_ts()} [INFO]   {str(m).lstrip()}", flush=True)


def log_warn(m: str) -> None:
    print(f"{_ts()} [WARN]   {str(m).lstrip()}", flush=True)


def log_error(m: str) -> None:
    print(f"{_ts()} [ERROR]  {str(m).lstrip()}", flush=True)


def montauk_available() -> bool:
    return Path(MONTAUK).exists() and Path(MONTAUK_ANALYZE).exists()


def _chown_to_invoking_user(*paths) -> None:
    """Hand root-owned recordings back to the sudo invoker so they are readable
    without sudo. No-op when not under sudo."""
    user = os.environ.get("SUDO_USER")
    if not user or os.geteuid() != 0:
        return
    for p in paths:
        if p is not None and Path(p).exists():
            subprocess.run(["chown", "-R", f"{user}:", str(p)],
                           capture_output=True)


# CAPTURE
#
# Three modes cover every application:
#   launch  -- run a command and trace it until it exits (or `duration`)
#   attach  -- trace an already-running program by comm for `duration`
#   trace   -- no capture; analyse an existing recording (dir or .bin/.events)
#              that something else already produced (e.g. quark's observer).

@dataclass
class CaptureSpec:
    mode: str                                  # "launch" | "attach" | "trace"
    pattern: str = ""                          # montauk --trace comm (launch/attach)
    command: Optional[list] = None             # launch: argv
    comm: str = ""                             # attach: comm to match
    duration: float = 0.0                      # launch cap / attach window (s)
    env: Optional[dict] = None                 # extra env for a launched command
    trace_path: str = ""                       # trace mode: existing recording
    events: bool = True                        # raw per-event log (--trace-out)
    pin_cpu: Optional[int] = None              # taskset montauk to a drain core
    log_dir: str = "/tmp/montauk-profile"      # where launch/attach recordings land


class MontaukCapture:
    """Context manager driving one montauk recording. __enter__ launches
    `montauk --trace PATTERN --log DIR [--trace-out EVENTS]`, waits for attach,
    and yields self with `.dir`/`.events_path` set. __exit__ stops montauk the
    way Ctrl+C would (SIGINT -> TERM -> KILL) and chowns the recording back.

    The caller owns the workload; this owns only montauk.
    """

    def __init__(self, spec: CaptureSpec, label: str, stamp: str):
        self.spec = spec
        d = Path(spec.log_dir)
        self.dir = d / f"montauk-{label}-{stamp}"
        self.stdout_path = d / f"montauk-{label}-{stamp}.stdout"
        self.events_path = (d / f"montauk-{label}-{stamp}.events"
                            if spec.events else None)
        self.proc = None
        self._out = None

    def __enter__(self) -> "MontaukCapture":
        self.dir.mkdir(parents=True, exist_ok=True)
        self._out = open(self.stdout_path, "w")
        cmd = [MONTAUK, "--trace", self.spec.pattern, "--log", str(self.dir),
               "--log-interval-ms", str(LOG_INTERVAL_MS)]
        if self.events_path is not None:
            cmd += ["--trace-out", str(self.events_path)]
        if self.spec.pin_cpu is not None:
            cmd = ["taskset", "-c", str(self.spec.pin_cpu)] + cmd
        self.proc = subprocess.Popen(cmd, stdout=self._out,
                                     stderr=subprocess.STDOUT)
        if not self._wait_for_attach():
            log_warn(f"montauk slow to attach (see {self.stdout_path})")
        return self

    def _wait_for_attach(self) -> bool:
        deadline = time.time() + ATTACH_TIMEOUT
        while time.time() < deadline:
            if any(self.dir.glob("montauk_*.prom")):
                return True
            if self.proc.poll() is not None:
                return False
            time.sleep(0.2)
        return False

    def stop(self) -> None:
        if self.proc is not None:
            for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
                if self.proc.poll() is not None:
                    break
                self.proc.send_signal(sig)
                try:
                    self.proc.wait(timeout=8)
                    break
                except subprocess.TimeoutExpired:
                    continue
            self.proc = None
        if self._out is not None:
            self._out.close()
            self._out = None
        _chown_to_invoking_user(self.dir, self.stdout_path, self.events_path)

    def __exit__(self, *exc) -> bool:
        self.stop()
        return False


# PROFILE

@dataclass
class Profile:
    """A declarative capture+report spec. `markers` and `assemble` are the two
    application hooks; everything else is generic."""
    name: str
    capture: CaptureSpec
    reports: list = field(default_factory=list)   # montauk_analyze --report names
    digest: bool = True                           # also run --digest (dir traces)
    redact: bool = True                           # hash process names in the digest
    # hook(record_path: Path) -> None: write producer-marker .prom into the
    # recording for state the trace cannot see (object identities, opcode stats).
    markers: Optional[Callable[[Path], None]] = None
    # hook(profile, trace, blocks) -> str: build the final report. None = default.
    # `blocks` is an ordered dict {section_title: text} of digest + each report.
    assemble: Optional[Callable] = None
    report_dir: str = ""                          # default: ~/.cache/<name>/


# ANALYZE

def run_analyze(trace: str, report: Optional[str] = None,
                digest: bool = False, redact: bool = False) -> str:
    """Run montauk_analyze over a trace (recording dir or .bin/.events) and
    return stdout. Either a single --report, or --digest. montauk owns the
    analysis; this only shells out and captures."""
    cmd = [MONTAUK_ANALYZE, str(trace)]
    if digest:
        cmd.append("--digest")
        if redact:
            cmd.append("--redact")
    elif report:
        cmd += ["--report", report]
    r = subprocess.run(cmd, capture_output=True, text=True)
    out = r.stdout
    # montauk_analyze logs two INFO lines (analyzed/written) to stdout before the
    # report; drop them so an assembled report carries data, not run chatter.
    keep = [ln for ln in out.splitlines()
            if not ln.lstrip().startswith(("[")) or "analy" not in ln]
    text = "\n".join(keep).strip()
    # For a single report the caller titles the block "REPORT <name>"; drop
    # montauk's identical leading echo so the section header is not doubled.
    if report and text.startswith(f"REPORT {report}"):
        text = text.split("\n", 1)[1].strip() if "\n" in text else ""
    return text


def _is_dir_recording(trace: str) -> bool:
    return Path(trace).is_dir()


def default_assemble(profile: Profile, trace: str, blocks: dict) -> str:
    """Generic report: a header, then each block (digest first, then reports)
    verbatim. Apps with a richer layout supply their own assemble hook."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out = [f"{profile.name} report",
           f"trace:    {trace}",
           f"captured: {stamp}",
           ""]
    for title, text in blocks.items():
        out.append(title)
        out.append(text.rstrip() if text.strip() else "  (no data)")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def _report_dir(profile: Profile) -> Path:
    if profile.report_dir:
        return Path(profile.report_dir)
    home = Path(os.environ.get("SUDO_USER") and
                f"/home/{os.environ['SUDO_USER']}" or Path.home())
    return home / ".cache" / profile.name


def run_profile(profile: Profile) -> Optional[Path]:
    """Capture per the profile (or use an existing trace), run the producer
    markers hook, run the digest + each report, assemble, and write one report
    file. Returns the report path, or None on a hard failure."""
    if not montauk_available():
        log_error(f"montauk not found (montauk={MONTAUK}, "
                  f"montauk_analyze={MONTAUK_ANALYZE})")
        return None

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    spec = profile.capture

    # 1. Obtain a trace: capture it, or point at an existing recording.
    if spec.mode == "trace":
        trace = spec.trace_path
        if not trace or not Path(trace).exists():
            log_error(f"trace not found: {trace}")
            return None
        return _finish(profile, trace, stamp)

    if spec.mode in ("launch", "attach"):
        with MontaukCapture(spec, profile.name, stamp) as cap:
            if spec.mode == "launch":
                _drive_launch(spec, cap)
            else:
                _drive_attach(spec)
        trace = str(cap.events_path if (spec.events and cap.events_path and
                    cap.events_path.exists()) else cap.dir)
        return _finish(profile, trace, stamp)

    log_error(f"unknown capture mode: {spec.mode}")
    return None


def _drive_launch(spec: CaptureSpec, cap: MontaukCapture) -> None:
    env = {**os.environ, **(spec.env or {})}
    log_info(f"launching: {' '.join(spec.command)}")
    try:
        proc = subprocess.Popen(spec.command, env=env)
    except (OSError, ValueError) as e:
        log_error(f"could not launch: {e}")
        return
    try:
        if spec.duration > 0:
            try:
                proc.wait(timeout=spec.duration)
            except subprocess.TimeoutExpired:
                log_info(f"duration {spec.duration:.0f}s reached -- stopping")
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        else:
            proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        raise


def _drive_attach(spec: CaptureSpec) -> None:
    dur = spec.duration if spec.duration > 0 else 20.0
    log_info(f"tracing running '{spec.comm}' for {dur:.0f}s ...")
    time.sleep(dur)


def _finish(profile: Profile, trace: str, stamp: str) -> Optional[Path]:
    # 2. Producer markers: let the app write .prom into the recording for state
    #    the trace cannot see. Markers only make sense for a dir recording (the
    #    digest scrapes .prom there); for a bare .bin the app surfaces the same
    #    state through its assembler instead.
    if profile.markers is not None:
        try:
            profile.markers(Path(trace))
        except Exception as e:        # a marker hook must never sink the report
            log_warn(f"markers hook failed: {e}")

    # 3. Run the digest (dir recordings) and each requested report.
    blocks: dict = {}
    if profile.digest and _is_dir_recording(trace):
        d = run_analyze(trace, digest=True, redact=profile.redact)
        if d.strip():
            blocks["DIGEST"] = d
    for rep in profile.reports:
        log_info(f"montauk_analyze --report {rep}")
        blocks[f"REPORT {rep}"] = run_analyze(trace, report=rep)

    # 4. Assemble (app hook or generic default) and write.
    builder = profile.assemble or default_assemble
    text = builder(profile, trace, blocks)
    rd = _report_dir(profile)
    rd.mkdir(parents=True, exist_ok=True)
    path = rd / f"{profile.name}-report-{stamp}.txt"
    path.write_text(text)
    _chown_to_invoking_user(path)
    log_info(f"REPORT: {path}")
    return path


# GENERIC CLI
#
# For applications that need no custom assembly: build a Profile from flags.
# Rich applications (quark) write their own harness importing run_profile.

def _cli_profile(args) -> Profile:
    reports = [r.strip() for r in (args.reports or "").split(",") if r.strip()]
    if args.cmd == "command":
        argv = shlex.split(args.command)
        spec = CaptureSpec(mode="launch", pattern=(args.pattern or
                           os.path.basename(argv[0])[:15]),
                           command=argv, duration=args.duration,
                           events=not args.no_events, pin_cpu=args.pin_cpu)
        name = args.name or os.path.basename(argv[0])[:15]
    elif args.cmd == "attach":
        spec = CaptureSpec(mode="attach", pattern=args.comm[:15],
                           comm=args.comm[:15], duration=args.duration or 20.0,
                           events=not args.no_events, pin_cpu=args.pin_cpu)
        name = args.name or args.comm[:15]
    else:  # trace
        spec = CaptureSpec(mode="trace", trace_path=args.path)
        name = args.name or "montauk-profile"
    return Profile(name=name, capture=spec, reports=reports,
                   digest=not args.no_digest, redact=not args.no_redact)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="montauk-profile",
        description="Generic montauk capture -> analyze -> report harness.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--name", help="profile/report name")
        p.add_argument("--reports", default="",
                       help="comma-separated montauk_analyze --report names")
        p.add_argument("--no-digest", action="store_true")
        p.add_argument("--no-redact", action="store_true")

    pc = sub.add_parser("command", help="launch a command and report on it")
    pc.add_argument("command", help="the command to run (quoted)")
    pc.add_argument("--pattern", help="montauk --trace comm (default: argv0)")
    pc.add_argument("--duration", type=float, default=0.0)
    pc.add_argument("--no-events", action="store_true")
    pc.add_argument("--pin-cpu", type=int)
    common(pc)

    pa = sub.add_parser("attach", help="trace a running program and report")
    pa.add_argument("comm", help="comm name to trace")
    pa.add_argument("--duration", type=float, default=20.0)
    pa.add_argument("--no-events", action="store_true")
    pa.add_argument("--pin-cpu", type=int)
    common(pa)

    pt = sub.add_parser("trace", help="report on an existing recording")
    pt.add_argument("path", help="recording dir or .bin/.events file")
    common(pt)

    args = ap.parse_args(argv)
    profile = _cli_profile(args)
    return 0 if run_profile(profile) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log_warn("interrupted")
        sys.exit(130)
