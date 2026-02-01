#!/usr/bin/env python3
"""
montauk-kernel installer

Builds and installs everything needed for kernel module support:
1. Checks for kernel headers
2. Builds the kernel module
3. Installs and loads the module
4. Rebuilds montauk userspace with kernel collector enabled
5. Installs montauk binary to /usr/local/bin

Handles common issues like:
- Missing kernel headers
- Spaces in paths (kernel build system doesn't support them)
- Module/kernel version mismatches
- Module installation and auto-load setup
"""

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
    """Get current timestamp in [HH:MM:SS] format."""
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
    """Run a command with real-time output. Returns exit code."""
    print(f">>> {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd)
    return result.returncode


def run_cmd_capture(cmd: list, cwd: Path | None = None) -> tuple[int, str, str]:
    """Run a command and capture output."""
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    return result.returncode, result.stdout, result.stderr


def run_cmd_sudo(cmd: list, cwd: Path | None = None) -> int:
    """Run a command with sudo."""
    return run_cmd(["sudo"] + cmd, cwd=cwd)


def run_cmd_sudo_capture(cmd: list, cwd: Path | None = None) -> tuple[int, str, str]:
    """Run a command with sudo and capture output."""
    return run_cmd_capture(["sudo"] + cmd, cwd=cwd)


# =============================================================================
# KMOD UTILITIES
# =============================================================================

def find_kmod_tool(name: str) -> str:
    """Find a kmod tool (modinfo, modprobe, etc.) accounting for Debian's /usr/sbin PATH."""
    path = shutil.which(name)
    if path:
        return path
    for sbin in ["/usr/sbin", "/sbin"]:
        candidate = os.path.join(sbin, name)
        if os.path.isfile(candidate):
            return candidate
    return name


def get_kernel_version() -> str:
    """Get running kernel version."""
    return os.uname().release


def get_module_vermagic(ko_path: Path) -> str | None:
    """Extract vermagic from a .ko file to check kernel version compatibility."""
    ret, stdout, _ = run_cmd_capture([find_kmod_tool("modinfo"), str(ko_path)])
    if ret != 0:
        return None
    for line in stdout.splitlines():
        if line.startswith("vermagic:"):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]
    return None


# =============================================================================
# DEPENDENCY CHECKS
# =============================================================================

def check_kernel_headers(kver: str) -> bool:
    """Check if kernel headers are installed."""
    build_dir = Path(f"/lib/modules/{kver}/build")
    return build_dir.exists()


def check_cmake() -> bool:
    """Check if cmake is available."""
    ret, _, _ = run_cmd_capture(["which", "cmake"])
    return ret == 0


# =============================================================================
# MAIN
# =============================================================================

def main() -> int:
    script_dir = Path(__file__).parent.resolve()
    montauk_root = script_dir.parent
    kver = get_kernel_version()
    tmp_build = Path("/tmp/montauk-kernel")

    print()
    log_info("montauk-kernel installer")
    log_info(f"Kernel version: {kver}")
    log_info(f"Kernel module source: {script_dir}")
    log_info(f"Montauk root: {montauk_root}")
    print()

    # Check dependencies
    log_info("CHECKING DEPENDENCIES")

    if not check_kernel_headers(kver):
        log_error("Kernel headers not found!")
        print()
        log_info("Install them first:")
        print("         Arch Linux:    sudo pacman -S linux-headers")
        print("         Debian/Ubuntu: sudo apt install linux-headers-$(uname -r)")
        print("         Fedora:        sudo dnf install kernel-devel")
        print()
        return 1
    log_info(f"Kernel headers found at /lib/modules/{kver}/build")

    if not check_cmake():
        log_error("cmake not found!")
        print()
        log_info("Install it first:")
        print("         Arch Linux:    sudo pacman -S cmake")
        print("         Debian/Ubuntu: sudo apt install cmake")
        print("         Fedora:        sudo dnf install cmake")
        print()
        return 1
    log_info("cmake found")
    print()

    # Prepare build directory
    log_info("PREPARING BUILD DIRECTORY")

    if " " in str(script_dir):
        log_info(f"Source path has spaces, copying to {tmp_build}")
        if tmp_build.exists():
            shutil.rmtree(tmp_build)
        shutil.copytree(script_dir, tmp_build,
                       ignore=shutil.ignore_patterns('*.pyc', '__pycache__', '*.ko', '*.o', '*.mod*', '.tmp*', 'Module.symvers', 'modules.order'))
    else:
        tmp_build = script_dir
    log_info(f"Building in {tmp_build}")
    print()

    # Build kernel module
    log_info("BUILDING KERNEL MODULE")

    kdir = f"/lib/modules/{kver}/build"

    # Clean first
    run_cmd_capture(["make", "-C", kdir, f"M={tmp_build}", "clean"])

    # Build
    ret, stdout, stderr = run_cmd_capture(["make", "-C", kdir, f"M={tmp_build}", "modules"])
    if ret != 0:
        log_error("Build failed!")
        print(stderr)
        return 1

    ko_file = tmp_build / "montauk.ko"
    if not ko_file.exists():
        log_error("montauk.ko not found after build!")
        return 1
    log_info(f"Built {ko_file}")

    # Verify module version
    module_kver = get_module_vermagic(ko_file)
    if module_kver is None:
        log_error("Could not read module vermagic")
        return 1
    if module_kver != kver:
        log_error(f"Module built for {module_kver}, but running {kver}")
        print()
        log_info("Make sure you have the correct kernel headers installed:")
        print(f"         Running kernel: {kver}")
        print(f"         Headers should be at: /lib/modules/{kver}/build")
        print()
        return 1
    log_info(f"Module vermagic matches running kernel ({module_kver})")
    print()

    # Install kernel module
    log_info("INSTALLING KERNEL MODULE")

    dest_dir = Path(f"/lib/modules/{kver}/extra")
    dest_file = dest_dir / "montauk.ko"

    run_cmd_sudo(["mkdir", "-p", str(dest_dir)])
    ret = run_cmd_sudo(["cp", str(ko_file), str(dest_file)])
    if ret != 0:
        log_error("Failed to copy module (need sudo?)")
        return 1

    ret = run_cmd_sudo([find_kmod_tool("depmod"), "-a"])
    if ret != 0:
        log_error("depmod failed!")
        return 1
    log_info(f"Installed to {dest_file}")

    # Setup auto-load
    modules_conf = Path("/etc/modules-load.d/montauk.conf")
    proc = subprocess.Popen(
        ["sudo", "tee", str(modules_conf)],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL
    )
    proc.communicate(input=b"montauk\n")

    if proc.returncode != 0:
        log_warn("Could not set up auto-load")
    else:
        log_info(f"Created {modules_conf}")
    print()

    # Load kernel module
    log_info("LOADING KERNEL MODULE")

    ret, stdout, _ = run_cmd_capture([find_kmod_tool("lsmod")])
    if "montauk" in stdout:
        log_info("Unloading existing module...")
        run_cmd_sudo([find_kmod_tool("rmmod"), "montauk"])

    ret, _, stderr = run_cmd_sudo_capture([find_kmod_tool("modprobe"), "montauk"])
    if ret != 0:
        log_error(f"Failed to load module: {stderr}")
        return 1

    ret, stdout, _ = run_cmd_capture([find_kmod_tool("lsmod")])
    if "montauk" not in stdout:
        log_error("Module not showing in lsmod!")
        return 1
    log_info("Module loaded")
    print()

    # Rebuild montauk userspace
    log_info("REBUILDING MONTAUK WITH KERNEL SUPPORT")

    build_dir = montauk_root / "build"
    jobs = multiprocessing.cpu_count()

    ret, stdout, stderr = run_cmd_capture(
        ["cmake", "-B", str(build_dir), "-DMONTAUK_KERNEL=ON"],
        cwd=montauk_root
    )
    if ret != 0:
        log_error("cmake configure failed!")
        print(stderr)
        return 1
    log_info("Configuration complete")

    ret, stdout, stderr = run_cmd_capture(
        ["cmake", "--build", str(build_dir), "--clean-first", f"-j{jobs}"]
    )
    if ret != 0:
        log_error("cmake build failed!")
        print(stderr)
        return 1

    montauk_bin = build_dir / "montauk"
    if not montauk_bin.exists():
        log_error("montauk binary not found after build!")
        return 1

    size = montauk_bin.stat().st_size
    log_info(f"Built {montauk_bin} ({size} bytes)")

    # Install binary
    log_info("Installing to /usr/local/bin...")
    ret, _, stderr = run_cmd_sudo_capture(["cp", str(montauk_bin), "/usr/local/bin/montauk"])
    if ret != 0:
        log_error(f"Could not install to /usr/local/bin: {stderr}")
        return 1
    log_info(f"Installed /usr/local/bin/montauk ({size} bytes)")

    ret, stdout, _ = run_cmd_capture(["strings", "/usr/local/bin/montauk"])
    if "KernelProcessCollector" not in stdout:
        log_warn("Installed binary may not have kernel support compiled in!")
    else:
        log_info("Kernel collector verified in installed binary")
    print()

    # Done
    log_info("SUCCESS. montauk-kernel is fully installed.")
    log_info(f"Kernel version: {kver}")
    log_info("The kernel module is loaded and will auto-load on boot.")
    print()
    log_info("RUN COMMAND: montauk")
    log_info("You should see 'Kernel Module' as the collector type in the UI.")
    print()
    log_info("Verify kernel module:")
    print("         lsmod | grep montauk")
    print("         sudo dmesg | grep montauk")
    print()
    log_warn("If you update your system kernel, you MUST re-run this installer!")
    print(f"         cd {script_dir}")
    print("         ./install.py")
    print()
    log_info("To uninstall:")
    print("         sudo rmmod montauk")
    print(f"         sudo rm /lib/modules/{kver}/extra/montauk.ko")
    print("         sudo rm /etc/modules-load.d/montauk.conf")
    print("         sudo depmod -a")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)
