#!/usr/bin/env python3
"""
montauk installer

Builds and installs montauk system monitor, optionally with kernel module support.

Usage:
    ./install.py              # Build and install (prompts for kernel if headers found)
    ./install.py --kernel     # Build and install with kernel module (no prompt)
    ./install.py --no-kernel  # Build and install without kernel module (no prompt)
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

    # Clean + build
    run_cmd_capture(["make", "-C", kbuild, f"M={build_src}", "clean"])
    ret, _, stderr = run_cmd_capture(["make", "-C", kbuild, f"M={build_src}", "modules"])
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
    """Build montauk (and optionally the kernel module)."""
    build_dir = source_dir / "build"
    use_kernel = resolve_kernel(args, source_dir)

    # Build kernel module first if requested
    if use_kernel:
        if not build_and_install_kernel_module(source_dir):
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

    # Stash kernel decision for cmd_install to use
    args._use_kernel = use_kernel
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
  ./install.py                    # Build and install (prompts for kernel if available)
  ./install.py --kernel           # Build with kernel module support (no prompt)
  ./install.py --no-kernel        # Build without kernel module (no prompt)
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
    parser.add_argument("--debug", action="store_true",
                       help="Build with debug symbols")
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
