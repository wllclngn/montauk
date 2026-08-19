#!/usr/bin/env python3
"""
montauk installer

Builds and installs montauk system monitor, with kernel module and eBPF
trace support built by default.

The kernel module and eBPF trace build unless opted out (--no-kernel,
--no-bpf). When a feature is requested its prereqs are mandatory: kernel
headers for the module, the eBPF toolchain (clang, bpftool, libbpf, kernel
BTF) for trace; a missing prereq aborts the install with the fix to run.

Usage:
    ./install.py              # Build and install (kernel module + eBPF trace by default)
    ./install.py --no-bpf     # Build without eBPF trace (-DMONTAUK_NO_BPF=ON)
    ./install.py --no-kernel  # Build without the kernel module
    ./install.py --debug      # Debug build
    ./install.py --prefix /usr # Install to /usr instead of /usr/local
    ./install.py build        # Build only, don't install
    ./install.py clean        # Clean build directory
    ./install.py uninstall    # Remove installed files and kernel module
    ./install.py test         # Run the full test suite (python3 tests/run.py)
"""

import argparse
import os
import sys
import shutil
import subprocess
import multiprocessing
import tempfile
from pathlib import Path
from datetime import datetime


# =============================================================================
# LOGGING
# =============================================================================

def _timestamp() -> str:
    return datetime.now().strftime("[%H:%M:%S]")


def log_info(msg: str) -> None:
    print(f"{_timestamp()} [INFO]   {msg}")


def log_warn(msg: str) -> None:
    print(f"{_timestamp()} [WARN]   {msg}")


def log_error(msg: str) -> None:
    print(f"{_timestamp()} [ERROR]  {msg}")


# =============================================================================
# COMMAND EXECUTION
# =============================================================================

def run_cmd(cmd: list, cwd: Path | None = None) -> int:
    print(f">>> {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd)
    return result.returncode


def run_cmd_capture(cmd: list, cwd: Path | None = None) -> tuple[int, str, str]:
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    return result.returncode, result.stdout, result.stderr


def run_cmd_sudo(cmd: list, cwd: Path | None = None) -> int:
    return run_cmd(["sudo"] + cmd, cwd=cwd)


def run_cmd_sudo_capture(cmd: list, cwd: Path | None = None) -> tuple[int, str, str]:
    return run_cmd_capture(["sudo"] + cmd, cwd=cwd)


# =============================================================================
# DEPENDENCY CHECKS
# =============================================================================

def check_cmake() -> bool:
    ret, _, _ = run_cmd_capture(["which", "cmake"])
    return ret == 0


def check_compiler() -> bool:
    for compiler in ["g++", "clang++"]:
        ret, _, _ = run_cmd_capture(["which", compiler])
        if ret == 0:
            return True
    return False


# =============================================================================
# KMOD UTILITIES
# =============================================================================

def find_kmod_tool(name: str) -> str:
    path = shutil.which(name)
    if path:
        return path
    for sbin in ["/usr/sbin", "/sbin"]:
        candidate = os.path.join(sbin, name)
        if os.path.isfile(candidate):
            return candidate
    return name


def get_kernel_version() -> str:
    return os.uname().release


def get_module_vermagic(ko_path: Path) -> str | None:
    ret, stdout, _ = run_cmd_capture([find_kmod_tool("modinfo"), str(ko_path)])
    if ret != 0:
        return None
    for line in stdout.splitlines():
        if line.startswith("vermagic:"):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]
    return None


def check_kernel_headers(kver: str) -> bool:
    return Path(f"/lib/modules/{kver}/build").exists()


def detect_kernel_compiler(kver: str) -> list:
    """Return extra make args (e.g. ['LLVM=1']) if the kernel was built with LLVM."""
    auto_conf = Path(f"/lib/modules/{kver}/build/include/config/auto.conf")
    if auto_conf.exists():
        try:
            text = auto_conf.read_text()
            if "CONFIG_CC_IS_CLANG=y" in text:
                return ["LLVM=1"]
        except OSError:
            pass
    return []


# =============================================================================
# THEME
# =============================================================================

def get_config_dir() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "montauk"
    return Path.home() / ".config" / "montauk"


def init_theme(install_path: Path) -> bool:
    config_file = get_config_dir() / "config.toml"
    if config_file.exists():
        return False
    log_info("Detecting terminal palette...")
    ret = run_cmd([str(install_path), "--init-theme"])
    return ret == 0


# =============================================================================
# KERNEL MODULE
# =============================================================================

def build_and_install_kernel_module(source_dir: Path) -> bool:
    """Build, install, and load the montauk kernel module."""
    kernel_dir = source_dir / "components" / "kernel"
    if not kernel_dir.exists():
        log_error(f"Kernel module source not found at {kernel_dir}")
        return False

    kver = get_kernel_version()
    kbuild = f"/lib/modules/{kver}/build"
    tmp_build = Path("/tmp/montauk-kernel")

    log_info("BUILDING KERNEL MODULE")
    log_info(f"Kernel version: {kver}")

    # Handle spaces in path (kernel build system limitation)
    if " " in str(kernel_dir):
        log_info(f"Source path has spaces, staging to {tmp_build}")
        if tmp_build.exists():
            shutil.rmtree(tmp_build)
        shutil.copytree(kernel_dir, tmp_build,
                        ignore=shutil.ignore_patterns(
                            '*.pyc', '__pycache__', '*.ko', '*.o',
                            '*.mod*', '.tmp*', 'Module.symvers',
                            'modules.order'))
        build_src = tmp_build
    else:
        build_src = kernel_dir

    # Clean + build (match the kernel's compiler)
    cc_args = detect_kernel_compiler(kver)
    if cc_args:
        log_info(f"Kernel was built with LLVM toolchain, using {cc_args[0]}")
    run_cmd_capture(["make", "-C", kbuild, f"M={build_src}", "clean"] + cc_args)
    ret, _, stderr = run_cmd_capture(["make", "-C", kbuild, f"M={build_src}", "modules"] + cc_args)
    if ret != 0:
        log_error("Kernel module build failed!")
        print(stderr)
        return False

    ko_file = build_src / "montauk.ko"
    if not ko_file.exists():
        log_error("montauk.ko not found after build!")
        return False
    log_info(f"Built {ko_file}")

    # Verify vermagic
    module_kver = get_module_vermagic(ko_file)
    if module_kver is None:
        log_error("Could not read module vermagic")
        return False
    if module_kver != kver:
        log_error(f"Module built for {module_kver}, but running {kver}")
        log_info("Make sure you have the correct kernel headers installed:")
        print(f"         Running kernel: {kver}")
        print(f"         Headers at:     /lib/modules/{kver}/build")
        return False
    log_info(f"Module vermagic matches running kernel ({module_kver})")
    print()

    # Install .ko
    log_info("INSTALLING KERNEL MODULE")
    dest_dir = Path(f"/lib/modules/{kver}/extra")
    dest_file = dest_dir / "montauk.ko"

    run_cmd_sudo(["mkdir", "-p", str(dest_dir)])
    ret = run_cmd_sudo(["cp", str(ko_file), str(dest_file)])
    if ret != 0:
        log_error("Failed to copy module")
        return False

    ret = run_cmd_sudo([find_kmod_tool("depmod"), "-a"])
    if ret != 0:
        log_error("depmod failed!")
        return False
    log_info(f"Installed to {dest_file}")

    # Auto-load on boot
    modules_conf = Path("/etc/modules-load.d/montauk.conf")
    proc = subprocess.Popen(
        ["sudo", "tee", str(modules_conf)],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL)
    proc.communicate(input=b"montauk\n")
    if proc.returncode == 0:
        log_info(f"Created {modules_conf}")
    else:
        log_warn("Could not set up auto-load")
    print()

    # Load module
    log_info("LOADING KERNEL MODULE")
    ret, stdout, _ = run_cmd_capture([find_kmod_tool("lsmod")])
    if "montauk" in stdout:
        log_info("Unloading existing module...")
        run_cmd_sudo([find_kmod_tool("rmmod"), "montauk"])

    ret, _, stderr = run_cmd_sudo_capture([find_kmod_tool("modprobe"), "montauk"])
    if ret != 0:
        log_error(f"Failed to load module: {stderr}")
        return False

    ret, stdout, _ = run_cmd_capture([find_kmod_tool("lsmod")])
    if "montauk" not in stdout:
        log_error("Module not showing in lsmod!")
        return False
    log_info("Module loaded")
    print()

    return True


def uninstall_kernel_module() -> bool:
    """Unload and remove the montauk kernel module."""
    kver = get_kernel_version()
    ko_path = Path(f"/lib/modules/{kver}/extra/montauk.ko")
    conf_path = Path("/etc/modules-load.d/montauk.conf")

    # Unload if loaded
    ret, stdout, _ = run_cmd_capture([find_kmod_tool("lsmod")])
    if "montauk" in stdout:
        log_info("Unloading kernel module...")
        run_cmd_sudo([find_kmod_tool("rmmod"), "montauk"])

    # Report what actually happened. These used to log "Removed" and set the flag
    # without looking at the return code, so a failed rm -- the ordinary case when
    # the sudo is refused -- printed success and returned True.
    removed = False
    for path in (ko_path, conf_path):
        if not path.exists():
            continue
        if run_cmd_sudo(["rm", str(path)]) == 0:
            log_info(f"Removed {path}")
            removed = True
        else:
            log_error(f"Failed to remove {path}")

    if removed:
        run_cmd_sudo([find_kmod_tool("depmod"), "-a"])

    return True


# =============================================================================
# EBPF TRACE SUPPORT
# =============================================================================

def check_bpf_deps() -> dict:
    """Check for eBPF trace dependencies. Returns dict of tool -> path or None."""
    deps = {}
    for tool in ["clang", "bpftool"]:
        ret, stdout, _ = run_cmd_capture(["which", tool])
        deps[tool] = stdout.strip() if ret == 0 else None

    # Check libbpf
    ret, _, _ = run_cmd_capture(["pkg-config", "--exists", "libbpf"])
    deps["libbpf"] = ret == 0

    # Check kernel BTF
    deps["btf"] = Path("/sys/kernel/btf/vmlinux").exists()

    return deps


def resolve_bpf(args) -> bool:
    """eBPF trace support is on by default -- montauk IS its tracer. When it
    is requested (no --no-bpf), verify the toolchain (clang, bpftool, libbpf,
    kernel BTF) and fail with the install command if any piece is missing.
    Callers skip this entirely under --no-bpf."""
    deps = check_bpf_deps()
    missing = [name for name, ok in (
        ("clang", deps["clang"]),
        ("bpftool", deps["bpftool"]),
        ("libbpf", deps["libbpf"]),
        ("kernel BTF (/sys/kernel/btf/vmlinux)", deps["btf"]),
    ) if not ok]
    if missing:
        log_error("eBPF dependencies not found: " + ", ".join(missing))
        print()
        log_info("montauk requires them. Install, then re-run:")
        print("         Arch Linux:    sudo pacman -S libbpf bpf clang")
        print("         Debian/Ubuntu: sudo apt install libbpf-dev bpftool clang linux-tools-$(uname -r)")
        print("         Fedora:        sudo dnf install libbpf-devel bpftool clang")
        print()
        return False
    return True


# =============================================================================
# COMMANDS
# =============================================================================

def resolve_kernel(args, source_dir: Path) -> bool:
    """The kernel module is on by default. When it is requested (no
    --no-kernel), verify the running kernel's headers and fail with the
    install command if they're missing. Callers skip this entirely under
    --no-kernel."""
    kver = get_kernel_version()
    kernel_src = source_dir / "components" / "kernel"
    if not kernel_src.exists():
        log_error(f"kernel module source missing at {kernel_src}")
        return False
    if not check_kernel_headers(kver):
        log_error("Kernel headers not found -- montauk's kernel module needs them.")
        print()
        log_info("montauk requires them. Install, then re-run:")
        print(f"         Arch Linux:    sudo pacman -S linux-headers  (kernel {kver})")
        print(f"         Debian/Ubuntu: sudo apt install linux-headers-{kver}")
        print("         Fedora:        sudo dnf install kernel-devel")
        print()
        return False
    return True


def cmd_build(args, source_dir: Path) -> bool:
    """Build montauk (and by default the kernel module, eBPF trace)."""
    build_dir = source_dir / "build"
    # Kernel module and eBPF trace default ON; --no-kernel / --no-bpf opt out.
    # For a requested feature, resolve_* verify the prereqs and print the
    # exact fix; a miss aborts here rather than silently building a lesser
    # montauk. An opted-out feature skips its resolve entirely.
    use_kernel = not getattr(args, "no_kernel", False)
    use_bpf = not getattr(args, "no_bpf", False)
    if use_kernel and not resolve_kernel(args, source_dir):
        return False
    if use_bpf and not resolve_bpf(args):
        return False

    # Build the kernel module first (when requested).
    if use_kernel:
        if not build_and_install_kernel_module(source_dir):
            return False
    else:
        log_info("Kernel module: skipped (--no-kernel)")

    # sublimation (montauk's adaptive sort and search core) is an in-tree
    # sub-system at montauk/sublimation/. CMake builds it with the montauk build.
    # No fetch, no system install. It needs a Haswell-or-newer CPU
    # (BMI2 + AVX2); the C23 compile will fail on older hardware.

    log_info("CONFIGURING BUILD")

    cmake_args = ["cmake", "-S", str(source_dir), "-B", str(build_dir)]

    if args.debug:
        cmake_args.append("-DCMAKE_BUILD_TYPE=Debug")
        log_info("Build type: Debug")
    else:
        cmake_args.append("-DCMAKE_BUILD_TYPE=Release")
        log_info("Build type: Release")

    # Both switches are passed explicitly so a stale CMakeCache from a prior
    # configure can't leak the opposite setting into this build (same reason
    # MONTAUK_BUILD_TESTS below is always passed).
    if use_kernel:
        cmake_args.append("-DMONTAUK_KERNEL=ON")
        log_info("Kernel collector: enabled")
    else:
        cmake_args.append("-DMONTAUK_KERNEL=OFF")
        log_info("Kernel collector: disabled (--no-kernel)")

    if not use_bpf:
        cmake_args.append("-DMONTAUK_NO_BPF=ON")
        log_info("eBPF trace: disabled (--no-bpf)")
    else:
        cmake_args.append("-DMONTAUK_NO_BPF=OFF")
        log_info("eBPF trace: enabled (--trace mode)")

    log_info("sublimation: in-tree sub-system (montauk/sublimation), built with montauk")

    # Test binary (montauk_tests) is opt-in. The --test flag on install/build
    # adds it; otherwise we explicitly pass OFF so any stale CMakeCache from
    # a prior `./install.py test` run doesn't leak test sources into a normal
    # install.
    if args.test:
        cmake_args.append("-DMONTAUK_BUILD_TESTS=ON")
        log_info("Test binary: enabled (--test)")
    else:
        cmake_args.append("-DMONTAUK_BUILD_TESTS=OFF")

    if args.prefix:
        cmake_args.append(f"-DCMAKE_INSTALL_PREFIX={args.prefix}")
        log_info(f"Install prefix: {args.prefix}")

    ret = run_cmd(cmake_args)
    if ret != 0:
        log_error("cmake configure failed!")
        return False
    log_info("Configuration complete")

    # Build
    jobs = multiprocessing.cpu_count()

    log_info("BUILDING")
    log_info(f"Using {jobs} parallel jobs")

    build_cmd = ["cmake", "--build", str(build_dir), f"-j{jobs}"]
    if args.command == "install":
        build_cmd.insert(3, "--clean-first")
        log_info("Clean build enabled")

    ret = run_cmd(build_cmd)
    if ret != 0:
        log_error("Build failed!")
        return False

    binary = build_dir / "montauk"
    if not binary.exists():
        log_error("montauk binary not found after build!")
        return False

    size = binary.stat().st_size
    log_info(f"Built {binary} ({size} bytes)")

    # Stash decisions for cmd_install to use
    args._use_kernel = use_kernel
    return True


def install_atomic(src: Path, dst: Path) -> int:
    """Install src -> dst atomically. Copy to a temp name in dst's directory,
    then rename over dst. rename(2) swaps the directory entry without touching
    the old inode, so it succeeds even while the old binary is still running --
    a plain `cp` over a live executable fails with ETXTBSY ("text file busy").
    The temp lives in the same directory as dst so the rename stays on one
    filesystem (atomic, not a cross-device copy). Returns 0 on success."""
    tmp = dst.with_name(dst.name + ".new")
    if run_cmd_sudo(["cp", str(src), str(tmp)]) != 0:
        return 1
    return run_cmd_sudo(["mv", "-f", str(tmp), str(dst)])


# THE MANIFEST. cmd_uninstall used to carry its own hardcoded list of targets,
# and a second list of the same thing drifts -- provably: a live install here
# carried an orphaned bin/montauk-mcp from the retired MCP server, a
# share/montauk/ this installer never creates, and the manpage at BOTH
# share/man/man1/ and man/man1/. Every one of them survived an uninstall that
# reported success. The same root cause shipped in PANDEMONIUM (Issue #17) and
# PRISM, so this is a family bug, not a montauk one.
#
# The fix is derivation, not three more entries: install RECORDS each path it
# places, uninstall reads that record back. A list that is written by the code
# that does the placing cannot disagree with it.
MANIFEST_REL = Path("lib") / "montauk" / "install_manifest.txt"

# Paths older installers placed that the manifest cannot know about, since they
# predate it. Swept on uninstall so an upgrade-in-place still cleans up after its
# ancestors; each is a path THIS installer no longer writes.
LEGACY_TARGETS = [
    Path("bin") / "montauk_analyze",      # folded into `montauk --analyze`
    Path("bin") / "montauk_trace_decode", # folded into `montauk --decode`
    Path("bin") / "montauk-mcp",          # the retired MCP server, pre-rename
    Path("bin") / "vector",               # the retired MCP server
    Path("man") / "man1" / "montauk.1",   # moved under share/
    Path("share") / "montauk",            # logo dir, no longer installed
]


def manifest_record(prefix: Path, placed: list) -> None:
    """Write the list of installed paths so uninstall can derive its targets."""
    dest = prefix / MANIFEST_REL
    body = "".join(f"{p}\n" for p in placed)
    tmp = Path(tempfile.gettempdir()) / "montauk_install_manifest"
    tmp.write_text(body)
    if run_cmd_sudo(["install", "-Dm644", str(tmp), str(dest)]) == 0:
        log_info(f"Recorded {len(placed)} installed paths in {dest}")
    else:
        log_warn("Failed to record the install manifest -- uninstall will fall "
                 "back to scanning known paths")
    tmp.unlink(missing_ok=True)


def manifest_read(prefix: Path) -> list | None:
    """Read back what install placed. None when no manifest exists (an install
    predating it), which is the caller's cue to fall back rather than to treat
    the install as empty."""
    src = prefix / MANIFEST_REL
    if not src.exists():
        return None
    return [Path(line) for line in src.read_text().split("\n") if line.strip()]


def cmd_install(args, source_dir: Path) -> bool:
    """Build and install montauk."""
    if not cmd_build(args, source_dir):
        return False

    build_dir = source_dir / "build"
    binary = build_dir / "montauk"
    prefix = Path(args.prefix) if args.prefix else Path("/usr/local")
    install_path = prefix / "bin" / "montauk"
    placed = []  # every path this run writes, recorded for uninstall

    log_info("INSTALLING")
    log_info(f"Destination: {install_path}")

    run_cmd_sudo(["mkdir", "-p", str(prefix / "bin")])

    ret = install_atomic(binary, install_path)
    if ret != 0:
        log_error("Failed to install binary!")
        return False

    size = binary.stat().st_size
    log_info(f"Installed {install_path} ({size} bytes)")
    placed.append(install_path.relative_to(prefix))

    # `sublimation` is the CLI front door to the in-tree sort sub-system and is
    # its own binary -- it ships beside montauk.
    tool_bin = binary.parent / "sublimation"
    if tool_bin.exists():
        if install_atomic(tool_bin, prefix / "bin" / "sublimation") == 0:
            log_info(f"Installed {prefix / 'bin' / 'sublimation'}")
            placed.append(Path("bin") / "sublimation")
        else:
            log_warn("Failed to install sublimation")
    else:
        log_warn("sublimation missing from build dir — not installed")

    # The generic profile harness (montauk_profile): a montauk feature any
    # application uses to turn a montauk capture into a `montauk --analyze` report --
    # capture (launch/attach/existing trace), run the reports, assemble. Installed
    # importable as a module (apps add this dir to sys.path for their own diagnose
    # script) plus a `montauk-profile` CLI shim for the generic command/attach/
    # trace path.
    profile_src = source_dir / "components" / "profile" / "montauk_profile.py"
    if profile_src.exists():
        lib_dest = prefix / "lib" / "montauk" / "montauk_profile.py"
        cli_dest = prefix / "bin" / "montauk-profile"
        if run_cmd_sudo(["install", "-Dm755", str(profile_src), str(lib_dest)]) == 0:
            run_cmd_sudo(["ln", "-sf", str(lib_dest), str(cli_dest)])
            log_info(f"Installed {cli_dest} (importable: {lib_dest})")
            placed.append(lib_dest.relative_to(prefix))
            placed.append(cli_dest.relative_to(prefix))
        else:
            log_warn("Failed to install montauk-profile")

    # Apply file capabilities so `montauk --trace` (eBPF) works without sudo.
    # A plain cp clears whatever caps the previous binary had, so this MUST run
    # on EVERY install — otherwise the next --trace fails with "need root or
    # CAP_BPF" on a locked-down kernel (unprivileged_bpf_disabled=2). The set:
    # cap_bpf/cap_perfmon (load+attach BPF, perf_event_open), cap_sys_admin
    # (tracepoint attach), cap_sys_resource (RLIMIT_MEMLOCK), and
    # cap_dac_read_search (read root-only tracefs tracepoint ids).
    trace_caps = "cap_sys_admin,cap_bpf,cap_perfmon,cap_sys_resource,cap_dac_read_search+ep"
    ret = run_cmd_sudo(["setcap", trace_caps, str(install_path)])
    if ret == 0:
        log_info("Applied trace capabilities (montauk --trace works without sudo)")
    else:
        log_warn("setcap failed — run manually or --trace needs sudo:")
        log_warn(f"  sudo setcap {trace_caps} {install_path}")

    # Install the manpage so `man montauk` works (and the in-app help overlay
    # can read it via popen).
    manpage_src = source_dir / "montauk.1"
    if manpage_src.exists():
        manpage_dest = prefix / "share" / "man" / "man1" / "montauk.1"
        ret = run_cmd_sudo(["install", "-Dm644", str(manpage_src), str(manpage_dest)])
        if ret == 0:
            log_info(f"Installed manpage to {manpage_dest}")
            placed.append(manpage_dest.relative_to(prefix))
            run_cmd_sudo(["mandb", "-q"])  # refresh man index, best-effort
        else:
            log_warn("Failed to install manpage (in-app help overlay will be empty)")

    manifest_record(prefix, placed)

    # Detect terminal palette and write config.toml on first install
    if init_theme(install_path):
        log_info(f"Wrote config to {get_config_dir()}/config.toml")

    use_kernel = getattr(args, '_use_kernel', False)
    if use_kernel:
        ret, stdout, _ = run_cmd_capture(["strings", str(install_path)])
        if "KernelProcessCollector" in stdout:
            log_info("Kernel collector support verified")
        else:
            log_warn("Kernel collector may not be compiled in")

    print()
    log_info("SUCCESS. Installation complete.")
    log_info("RUN COMMAND: montauk")

    if use_kernel:
        log_info("Kernel module is loaded and will auto-load on boot.")
        log_warn("Re-run this installer after kernel upgrades!")

    log_info("sublimation is montauk's adaptive sort and search core, built in-tree (montauk/sublimation).")

    return True


def cmd_clean(args, source_dir: Path) -> bool:
    """Clean build directory."""
    build_dir = source_dir / "build"

    log_info("CLEANING")

    if build_dir.exists():
        log_info(f"Removing {build_dir}")
        shutil.rmtree(build_dir)
        log_info("Clean complete")
    else:
        log_info("Nothing to clean")

    return True


def cmd_uninstall(args, source_dir: Path) -> bool:
    """Remove everything install placed, read back from the manifest install
    wrote -- plus the paths older installers placed, and the kernel module."""
    prefix = Path(args.prefix) if args.prefix else Path("/usr/local")

    log_info("UNINSTALLING")

    rel = manifest_read(prefix)
    if rel is None:
        # An install predating the manifest. Fall back to the paths this
        # installer is known to have placed across its history -- stated once,
        # here, and reachable only on this path.
        log_warn("No install manifest found (installed by an older montauk); "
                 "falling back to the historical path set")
        rel = [Path("bin") / n for n in ("montauk", "sublimation",
                                         "montauk-profile")]
        rel += [Path("lib") / "montauk" / "montauk_profile.py",
                Path("share") / "man" / "man1" / "montauk.1"]
    else:
        log_info(f"Manifest lists {len(rel)} installed paths")
        rel = rel + [MANIFEST_REL]  # the manifest goes last, with everything else

    targets = [prefix / r for r in rel + LEGACY_TARGETS]

    removed = 0
    for t in targets:
        if not t.exists() and not t.is_symlink():
            continue
        cmd = ["rm", "-r", str(t)] if t.is_dir() else ["rm", str(t)]
        if run_cmd_sudo(cmd) == 0:
            log_info(f"Removed {t}")
            removed += 1
        else:
            log_error(f"Failed to remove {t}")
            return False

    # Prune the directories install created, but only when they are empty --
    # lib/montauk and share/man/man1 are shared with other software on a real
    # prefix, so rmdir (which refuses a non-empty directory) is the safe verb.
    for d in (prefix / "lib" / "montauk", prefix / "share" / "montauk"):
        if d.is_dir():
            run_cmd_sudo(["rmdir", str(d)])  # best-effort; non-empty is fine

    if removed:
        run_cmd_sudo(["mandb", "-q"])  # refresh man index after dropping the page
    else:
        log_warn(f"nothing to remove under {prefix} (montauk not installed?)")

    # Check for kernel module
    kver = get_kernel_version()
    ko_path = Path(f"/lib/modules/{kver}/extra/montauk.ko")
    conf_path = Path("/etc/modules-load.d/montauk.conf")
    if ko_path.exists() or conf_path.exists():
        log_info("Removing kernel module...")
        uninstall_kernel_module()

    log_info("Uninstall complete")
    return True


def cmd_test(args, source_dir: Path) -> bool:
    """Run the full suite via tests/run.py -- all five layers (unit, gate,
    perf, trace), not just the test binary. run.py does its
    own configure-and-build of the test targets."""
    log_info("RUNNING TESTS")

    runner = source_dir / "tests" / "run.py"
    if not runner.exists():
        log_error(f"Test runner missing at {runner}")
        return False

    log_info(f"Executing {sys.executable} {runner}")
    ret = run_cmd([sys.executable, str(runner)])

    if ret == 0:
        log_info("All tests passed")
    else:
        log_error("Some tests failed")

    return ret == 0


# =============================================================================
# MAIN
# =============================================================================

def main() -> int:
    if os.geteuid() == 0:
        log_error("Do not run this script as root or with sudo.")
        log_error("The installer uses sudo internally only where needed (kernel module install).")
        log_error("Running as root poisons the build directory with root-owned files.")
        return 1

    parser = argparse.ArgumentParser(
        description="Build and install montauk system monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  (default)   Build and install
  build       Build only
  clean       Remove build directory
  uninstall   Remove installed binary and kernel module
  test        Run the full test suite (python3 tests/run.py: unit, gate,
              perf, trace layers)

Examples:
  ./install.py                    # Build and install (kernel module + eBPF trace by default)
  ./install.py --no-bpf           # Build without eBPF trace (-DMONTAUK_NO_BPF=ON)
  ./install.py --test             # Also build montauk_tests alongside
  ./install.py --prefix /usr      # Install to /usr/bin
  ./install.py build              # Build only
  ./install.py clean              # Clean build

The kernel module and eBPF trace build by default; --no-kernel / --no-bpf
opt out.
"""
    )

    parser.add_argument("command", nargs="?", default="install",
                       choices=["install", "build", "clean", "uninstall", "test"],
                       help="Command to run (default: install)")
    # Kernel module and eBPF trace default ON; the --no-* flags opt out and
    # also skip the corresponding prereq check (headers / eBPF toolchain).
    kernel_group = parser.add_mutually_exclusive_group()
    kernel_group.add_argument("--kernel", action="store_true",
                              help="(default) build the kernel module")
    kernel_group.add_argument("--no-kernel", action="store_true",
                              help="skip the kernel module (headers not required)")
    bpf_group = parser.add_mutually_exclusive_group()
    bpf_group.add_argument("--bpf", action="store_true",
                            help="(default) build eBPF trace support")
    bpf_group.add_argument("--no-bpf", action="store_true",
                            help="build without eBPF trace (-DMONTAUK_NO_BPF=ON; "
                                 "eBPF toolchain not required)")
    parser.add_argument("--debug", action="store_true",
                       help="Build with debug symbols")
    parser.add_argument("--test", action="store_true",
                       help="Also build montauk_tests (default: off)")
    parser.add_argument("--prefix", type=str, default=None,
                       help="Installation prefix (default: /usr/local)")

    args = parser.parse_args()

    source_dir = Path(__file__).parent.resolve()

    print()
    log_info("montauk installer")
    log_info(f"Source: {source_dir}")
    print()

    # Check dependencies
    if args.command in ["install", "build", "test"]:
        log_info("CHECKING DEPENDENCIES")

        if not check_cmake():
            log_error("cmake not found!")
            print()
            log_info("Install it first:")
            print("         Arch Linux:    sudo pacman -S cmake")
            print("         Debian/Ubuntu: sudo apt install cmake build-essential")
            print("         Fedora:        sudo dnf install cmake gcc-c++")
            print()
            return 1
        log_info("cmake found")

        if not check_compiler():
            log_error("C++ compiler not found!")
            print()
            log_info("Install it first:")
            print("         Arch Linux:    sudo pacman -S gcc")
            print("         Debian/Ubuntu: sudo apt install build-essential")
            print("         Fedora:        sudo dnf install gcc-c++")
            print()
            return 1
        log_info("C++ compiler found")
        print()

    # Run command
    commands = {
        "install": cmd_install,
        "build": cmd_build,
        "clean": cmd_clean,
        "uninstall": cmd_uninstall,
        "test": cmd_test,
    }

    success = commands[args.command](args, source_dir)
    return 0 if success else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)
