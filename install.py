#!/usr/bin/env python3
"""
montauk installer

Builds and installs montauk system monitor, optionally with kernel module
and/or eBPF trace support.

Usage:
    ./install.py              # Build and install (prompts for kernel/bpf if deps found)
    ./install.py --kernel     # Build with kernel module (no prompt)
    ./install.py --no-kernel  # Skip kernel module (no prompt)
    ./install.py --bpf        # Build with eBPF trace support (no prompt)
    ./install.py --no-bpf     # Skip eBPF trace support (no prompt)
    ./install.py --debug      # Debug build
    ./install.py --prefix /usr # Install to /usr instead of /usr/local
    ./install.py build        # Build only, don't install
    ./install.py clean        # Clean build directory
    ./install.py uninstall    # Remove installed files and kernel module
    ./install.py test         # Run tests
"""

import argparse
import os
import sys
import shutil
import subprocess
import multiprocessing
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
    kernel_dir = source_dir / "montauk-kernel"
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

    removed = False
    if ko_path.exists():
        run_cmd_sudo(["rm", str(ko_path)])
        log_info(f"Removed {ko_path}")
        removed = True

    if conf_path.exists():
        run_cmd_sudo(["rm", str(conf_path)])
        log_info(f"Removed {conf_path}")
        removed = True

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


def prompt_bpf() -> bool:
    """Prompt user for eBPF trace support. Returns True if yes."""
    log_info("eBPF tracing dependencies found.")
    log_info("montauk can build with eBPF support for --trace mode:")
    log_info("  - Real-time per-thread syscall/state tracking via kernel tracepoints")
    log_info("  - Event-driven process tree discovery (no /proc polling)")
    log_info("  - Per-thread CPU%, wait channel, fd targets — all from eBPF maps")
    log_info("  - Requires root or CAP_BPF + CAP_PERFMON at runtime")
    print()
    try:
        while True:
            response = input(
                "Build with eBPF trace support? [Y/N]: "
            ).strip().lower()
            if response in ("y", "yes"):
                return True
            elif response in ("n", "no"):
                return False
    except EOFError:
        print()
        log_info("No input (non-interactive). Skipping eBPF trace support.")
        return False


def resolve_bpf(args) -> bool:
    """Determine whether to build with eBPF trace support.
    --bpf: yes, no prompt.
    --no-bpf: no, no prompt.
    Neither: check for deps, prompt if found.
    """
    if args.bpf:
        deps = check_bpf_deps()
        missing = []
        if not deps["clang"]:
            missing.append("clang")
        if not deps["bpftool"]:
            missing.append("bpftool")
        if not deps["libbpf"]:
            missing.append("libbpf")
        if not deps["btf"]:
            missing.append("kernel BTF (/sys/kernel/btf/vmlinux)")
        if missing:
            log_error("eBPF dependencies not found: " + ", ".join(missing))
            print()
            log_info("Install them first:")
            print("         Arch Linux:    sudo pacman -S libbpf bpf clang")
            print("         Debian/Ubuntu: sudo apt install libbpf-dev bpftool clang linux-tools-$(uname -r)")
            print("         Fedora:        sudo dnf install libbpf-devel bpftool clang")
            print()
            return False
        return True

    if args.no_bpf:
        return False

    # Auto-detect
    deps = check_bpf_deps()
    if deps["clang"] and deps["bpftool"] and deps["libbpf"] and deps["btf"]:
        return prompt_bpf()

    # Some deps missing -- mention it
    log_info("eBPF trace support (--trace mode) is available but requires:")
    log_info("  clang, bpftool, libbpf, kernel BTF")
    missing = [k for k in ["clang", "bpftool", "libbpf", "btf"] if not deps.get(k)]
    log_info(f"  Missing: {', '.join(missing)}")
    print()
    log_info("To enable:  sudo pacman -S libbpf bpf clang  (Arch)")
    log_info("Then re-run:  ./install.py --bpf")
    print()
    log_info("Continuing without eBPF trace support...")
    print()
    return False


# =============================================================================
# SUBLIMATION SORT BACKEND
# =============================================================================

SUBLIMATION_REPO = "https://github.com/wllclngn/sublimation.git"
SUBLIMATION_BUILD_DIR = Path("/tmp/sublimation")


def check_sublimation_deps() -> dict:
    """Check for sublimation build dependencies."""
    deps = {}

    # git for clone
    ret, stdout, _ = run_cmd_capture(["which", "git"])
    deps["git"] = stdout.strip() if ret == 0 else None

    # gcc 13+ for C23 (sublimation needs -std=c2x)
    ret, stdout, _ = run_cmd_capture(["gcc", "-dumpversion"])
    if ret == 0:
        try:
            major = int(stdout.strip().split(".")[0])
            deps["gcc_c23"] = major >= 13
            deps["gcc_version"] = stdout.strip()
        except (ValueError, IndexError):
            deps["gcc_c23"] = False
            deps["gcc_version"] = None
    else:
        deps["gcc_c23"] = False
        deps["gcc_version"] = None

    # CPU features: BMI2 (PEXT) and AVX2 for the random-data fast path
    bmi2 = False
    avx2 = False
    try:
        with open("/proc/cpuinfo", "r") as f:
            for line in f:
                if line.startswith("flags"):
                    flags = line.split(":", 1)[1].split()
                    bmi2 = "bmi2" in flags
                    avx2 = "avx2" in flags
                    break
    except OSError:
        pass
    deps["bmi2"] = bmi2
    deps["avx2"] = avx2

    # Already installed system-wide? Check pkg-config first, then fall back to
    # the CMake config file (some distros don't have /usr/local/lib/pkgconfig
    # on PKG_CONFIG_PATH by default).
    ret, _, _ = run_cmd_capture(["pkg-config", "--exists", "sublimation"])
    if ret == 0:
        deps["installed"] = True
    else:
        deps["installed"] = Path("/usr/local/lib/cmake/Sublimation/SublimationConfig.cmake").exists()

    return deps


def prompt_sublimation() -> bool:
    """Prompt user for sublimation sort backend. Returns True if yes."""
    log_info("sublimation build dependencies found.")
    log_info("montauk can ship with sublimation as an opt-in alternative sort backend:")
    log_info("  - C23 adaptive sort, flow-model architecture (Young tableau classifier)")
    log_info("  - 2-3x speedup on string sort vs qsort+strcmp; pack-key index sort for numerics")
    log_info("  - Installed system-wide; runtime default stays TimSort")
    log_info("  - Activate per-user via MONTAUK_SORT_BACKEND=sublimation env / config")
    log_info(f"  - Fetched from {SUBLIMATION_REPO}")
    print()
    try:
        while True:
            response = input(
                "Build with sublimation sort backend? [Y/N]: "
            ).strip().lower()
            if response in ("y", "yes"):
                return True
            elif response in ("n", "no"):
                return False
    except EOFError:
        print()
        log_info("No input (non-interactive). Skipping sublimation backend.")
        return False


def resolve_sublimation(args) -> bool:
    """Determine whether to build with sublimation sort backend.
    --sublimation: yes, no prompt.
    --no-sublimation: no, no prompt.
    Neither: check for deps, prompt if found.
    """
    if args.sublimation:
        deps = check_sublimation_deps()
        missing = []
        if not deps["git"]:
            missing.append("git")
        if not deps["gcc_c23"]:
            missing.append(f"gcc 13+ (found {deps['gcc_version'] or 'none'}; need 13+ for C23)")
        if not deps["bmi2"]:
            missing.append("CPU BMI2 (PEXT)")
        if not deps["avx2"]:
            missing.append("CPU AVX2")
        if missing:
            log_error("sublimation dependencies not met: " + ", ".join(missing))
            print()
            log_info("BMI2/AVX2 require Haswell-or-newer CPU. On older hardware, re-run")
            log_info("with --no-sublimation; the TimSort backend works on any CPU.")
            print()
            return False
        return True

    if args.no_sublimation:
        return False

    # Auto-detect
    deps = check_sublimation_deps()
    if deps["git"] and deps["gcc_c23"] and deps["bmi2"] and deps["avx2"]:
        return prompt_sublimation()

    # Some deps missing -- mention what's needed
    log_info("sublimation sort backend (opt-in alternative) is available but requires:")
    log_info("  git, gcc 13+ (C23), CPU BMI2 + AVX2")
    missing = []
    if not deps["git"]:
        missing.append("git")
    if not deps["gcc_c23"]:
        missing.append(f"gcc 13+ (have {deps['gcc_version'] or 'none'})")
    if not deps["bmi2"]:
        missing.append("BMI2")
    if not deps["avx2"]:
        missing.append("AVX2")
    log_info(f"  Missing: {', '.join(missing)}")
    print()
    log_info("Continuing without sublimation backend...")
    print()
    return False


def fetch_and_install_sublimation() -> bool:
    """Clone sublimation to /tmp, run its install.py to build + install system-wide.

    Skips if libsublimation is already detected by pkg-config.
    """
    deps = check_sublimation_deps()
    if deps["installed"]:
        log_info("sublimation already installed system-wide (pkg-config detected)")
        return True

    log_info("FETCHING SUBLIMATION")
    log_info(f"Repo:  {SUBLIMATION_REPO}")
    log_info(f"Stage: {SUBLIMATION_BUILD_DIR}")

    # Clean stale stage
    if SUBLIMATION_BUILD_DIR.exists():
        shutil.rmtree(SUBLIMATION_BUILD_DIR)

    ret = run_cmd(["git", "clone", "--depth", "1", SUBLIMATION_REPO, str(SUBLIMATION_BUILD_DIR)])
    if ret != 0:
        log_error("git clone failed")
        log_info("Re-run with --no-sublimation to skip the sublimation backend.")
        return False

    sub_installer = SUBLIMATION_BUILD_DIR / "install.py"
    if not sub_installer.exists():
        log_error(f"sublimation install.py not found at {sub_installer}")
        return False

    print()
    log_info("BUILDING + INSTALLING SUBLIMATION")
    ret = run_cmd(["python3", str(sub_installer)], cwd=SUBLIMATION_BUILD_DIR)
    if ret != 0:
        log_error("sublimation install failed")
        log_info(f"Check {SUBLIMATION_BUILD_DIR} for details, or re-run with --no-sublimation.")
        return False

    # Verify pkg-config now finds it
    ret, _, _ = run_cmd_capture(["pkg-config", "--exists", "sublimation"])
    if ret != 0:
        log_warn("sublimation installed but pkg-config doesn't find it.")
        log_warn("You may need to set PKG_CONFIG_PATH=/usr/local/lib/pkgconfig.")
    else:
        ret, ver, _ = run_cmd_capture(["pkg-config", "--modversion", "sublimation"])
        log_info(f"sublimation installed (version {ver.strip()})")

    print()
    return True


def prompt_kernel() -> bool:
    """Prompt user for kernel module support. Returns True if yes."""
    kver = get_kernel_version()
    log_info(f"Linux kernel headers found (kernel {kver}).")
    log_info("montauk can install an optional kernel module for best performance:")
    log_info("  - ~0.1% CPU overhead (vs ~2-5% without)")
    log_info("  - Zero /proc reads (data comes directly from the kernel)")
    log_info("  - Sub-millisecond process detection")
    print()
    try:
        while True:
            response = input(
                "Install the montauk kernel module? [Y/N]: "
            ).strip().lower()
            if response in ("y", "yes"):
                return True
            elif response in ("n", "no"):
                return False
    except EOFError:
        print()
        log_info("No input (non-interactive). Skipping kernel module.")
        return False


# =============================================================================
# COMMANDS
# =============================================================================

def resolve_kernel(args, source_dir: Path) -> bool:
    """Determine whether to build with kernel support.
    --kernel: yes, no prompt.
    --no-kernel: no, no prompt.
    Neither: check for headers, prompt if found.
    """
    if args.kernel:
        kver = get_kernel_version()
        if not check_kernel_headers(kver):
            log_error("Kernel headers not found!")
            print()
            log_info("Install them first:")
            print("         Arch Linux:    sudo pacman -S linux-headers")
            print("         Debian/Ubuntu: sudo apt install linux-headers-$(uname -r)")
            print("         Fedora:        sudo dnf install kernel-devel")
            print()
            return False
        return True

    if args.no_kernel:
        return False

    # Auto-detect
    kver = get_kernel_version()
    kernel_src = source_dir / "montauk-kernel"

    if not kernel_src.exists():
        return False

    if check_kernel_headers(kver):
        return prompt_kernel()

    # Headers missing but kernel source exists -- tell them about it
    log_info("montauk includes an optional Linux kernel module for best performance")
    log_info("(~0.1% CPU, zero /proc reads, sub-millisecond process detection).")
    print()
    log_info("To enable it, install your Linux kernel's development headers:")
    print(f"         Arch Linux:    sudo pacman -S linux-headers  (kernel {kver})")
    print(f"         Debian/Ubuntu: sudo apt install linux-headers-{kver}")
    print(f"         Fedora:        sudo dnf install kernel-devel")
    print()
    log_info("Then re-run:  ./install.py --kernel")
    print()
    log_info("Continuing without kernel module support...")
    print()
    return False


def cmd_build(args, source_dir: Path) -> bool:
    """Build montauk (and optionally the kernel module, eBPF trace, sublimation)."""
    build_dir = source_dir / "build"
    use_kernel = resolve_kernel(args, source_dir)
    use_bpf = resolve_bpf(args)
    use_sublimation = resolve_sublimation(args)

    # Build kernel module first if requested
    if use_kernel:
        if not build_and_install_kernel_module(source_dir):
            return False

    # Fetch + install sublimation before configuring CMake (find_package needs it).
    if use_sublimation:
        if not fetch_and_install_sublimation():
            return False

    log_info("CONFIGURING BUILD")

    cmake_args = ["cmake", "-S", str(source_dir), "-B", str(build_dir)]

    if args.debug:
        cmake_args.append("-DCMAKE_BUILD_TYPE=Debug")
        log_info("Build type: Debug")
    else:
        cmake_args.append("-DCMAKE_BUILD_TYPE=Release")
        log_info("Build type: Release")

    if use_kernel:
        cmake_args.append("-DMONTAUK_KERNEL=ON")
        log_info("Kernel collector: enabled")

    if not use_bpf:
        cmake_args.append("-DMONTAUK_NO_BPF=ON")
        log_info("eBPF trace: disabled")
    else:
        log_info("eBPF trace: enabled (--trace mode)")

    if use_sublimation:
        cmake_args.append("-DUSE_SUBLIMATION=ON")
        log_info("Sublimation backend: enabled and active by default")
    else:
        log_info("Sublimation backend: disabled (TimSort only)")

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
    args._use_sublimation = use_sublimation
    return True


def cmd_install(args, source_dir: Path) -> bool:
    """Build and install montauk."""
    if not cmd_build(args, source_dir):
        return False

    build_dir = source_dir / "build"
    binary = build_dir / "montauk"
    prefix = Path(args.prefix) if args.prefix else Path("/usr/local")
    install_path = prefix / "bin" / "montauk"

    log_info("INSTALLING")
    log_info(f"Destination: {install_path}")

    run_cmd_sudo(["mkdir", "-p", str(prefix / "bin")])

    ret = run_cmd_sudo(["cp", str(binary), str(install_path)])
    if ret != 0:
        log_error("Failed to install binary!")
        return False

    size = binary.stat().st_size
    log_info(f"Installed {install_path} ({size} bytes)")

    # Install the manpage so `man montauk` works (and the in-app help overlay
    # can read it via popen).
    manpage_src = source_dir / "montauk.1"
    if manpage_src.exists():
        manpage_dest = prefix / "share" / "man" / "man1" / "montauk.1"
        ret = run_cmd_sudo(["install", "-Dm644", str(manpage_src), str(manpage_dest)])
        if ret == 0:
            log_info(f"Installed manpage to {manpage_dest}")
            run_cmd_sudo(["mandb", "-q"])  # refresh man index, best-effort
        else:
            log_warn("Failed to install manpage (in-app help overlay will be empty)")

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

    if getattr(args, '_use_sublimation', False):
        log_info("Sublimation backend compiled in and ACTIVE by default.")
        log_info("To opt back out to TimSort: MONTAUK_SORT_BACKEND=timsort montauk")

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
    """Remove installed binary and kernel module."""
    prefix = Path(args.prefix) if args.prefix else Path("/usr/local")
    install_path = prefix / "bin" / "montauk"

    log_info("UNINSTALLING")

    if install_path.exists():
        log_info(f"Removing {install_path}")
        ret = run_cmd_sudo(["rm", str(install_path)])
        if ret != 0:
            log_error("Failed to remove binary")
            return False
        log_info("Binary removed")
    else:
        log_warn(f"{install_path} not found")

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
    """Run tests."""
    build_dir = source_dir / "build"
    test_binary = build_dir / "montauk_tests"

    log_info("RUNNING TESTS")

    if not test_binary.exists():
        log_info("Tests not built, building with tests enabled...")

        cmake_args = ["cmake", "-S", str(source_dir), "-B", str(build_dir),
                       "-DMONTAUK_BUILD_TESTS=ON"]
        ret = run_cmd(cmake_args)
        if ret != 0:
            log_error("Configure failed")
            return False

        ret = run_cmd(["cmake", "--build", str(build_dir),
                        f"-j{multiprocessing.cpu_count()}"])
        if ret != 0:
            log_error("Build failed")
            return False

    log_info(f"Executing {test_binary}")
    ret = run_cmd([str(test_binary)])

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
  test        Run tests

Examples:
  ./install.py                    # Build and install (prompts for kernel/bpf if available)
  ./install.py --kernel           # Build with kernel module support (no prompt)
  ./install.py --no-kernel        # Build without kernel module (no prompt)
  ./install.py --bpf              # Build with eBPF trace support (no prompt)
  ./install.py --no-bpf           # Build without eBPF trace support (no prompt)
  ./install.py --sublimation      # Build with sublimation sort backend (no prompt)
  ./install.py --no-sublimation   # Skip sublimation sort backend (no prompt)
  ./install.py --test             # Also build montauk_tests alongside
  ./install.py --prefix /usr      # Install to /usr/bin
  ./install.py build              # Build only
  ./install.py clean              # Clean build
"""
    )

    parser.add_argument("command", nargs="?", default="install",
                       choices=["install", "build", "clean", "uninstall", "test"],
                       help="Command to run (default: install)")
    kernel_group = parser.add_mutually_exclusive_group()
    kernel_group.add_argument("--kernel", action="store_true",
                              help="Build and install kernel module (no prompt)")
    kernel_group.add_argument("--no-kernel", action="store_true",
                              help="Skip kernel module (no prompt)")
    bpf_group = parser.add_mutually_exclusive_group()
    bpf_group.add_argument("--bpf", action="store_true",
                            help="Build with eBPF trace support (no prompt)")
    bpf_group.add_argument("--no-bpf", action="store_true",
                            help="Skip eBPF trace support (no prompt)")
    sublimation_group = parser.add_mutually_exclusive_group()
    sublimation_group.add_argument("--sublimation", action="store_true",
                                   help="Build with sublimation sort backend (no prompt)")
    sublimation_group.add_argument("--no-sublimation", action="store_true",
                                   help="Skip sublimation sort backend (no prompt)")
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
