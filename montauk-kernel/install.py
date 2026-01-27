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
import re
from pathlib import Path

def run(cmd, check=True, capture=False, sudo=False, cwd=None):
    """Run a command, optionally with sudo."""
    if sudo:
        cmd = ["sudo"] + cmd
    if capture:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
        return result.returncode, result.stdout, result.stderr
    else:
        result = subprocess.run(cmd, cwd=cwd)
        return result.returncode, None, None

def find_kmod_tool(name):
    """Find a kmod tool (modinfo, modprobe, etc.) accounting for Debian's /usr/sbin PATH."""
    path = shutil.which(name)
    if path:
        return path
    for sbin in ["/usr/sbin", "/sbin"]:
        candidate = os.path.join(sbin, name)
        if os.path.isfile(candidate):
            return candidate
    return name  # fallback to bare name, let subprocess raise

def get_kernel_version():
    """Get running kernel version."""
    return os.uname().release

def check_kernel_headers():
    """Check if kernel headers are installed."""
    kver = get_kernel_version()
    build_dir = Path(f"/lib/modules/{kver}/build")
    return build_dir.exists()

def check_cmake():
    """Check if cmake is available."""
    ret, _, _ = run(["which", "cmake"], capture=True)
    return ret == 0

def get_module_vermagic(ko_path):
    """Extract vermagic from a .ko file to check kernel version compatibility."""
    ret, stdout, _ = run([find_kmod_tool("modinfo"), str(ko_path)], capture=True)
    if ret != 0:
        return None
    for line in stdout.splitlines():
        if line.startswith("vermagic:"):
            # vermagic: 6.18.3-arch1-1 SMP preempt mod_unload
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]  # kernel version
    return None

def verify_module_version(ko_path, expected_kver):
    """Verify the module was built for the expected kernel version."""
    module_kver = get_module_vermagic(ko_path)
    if module_kver is None:
        return False, "Could not read module vermagic"
    if module_kver != expected_kver:
        return False, f"Module built for {module_kver}, but running {expected_kver}"
    return True, module_kver

def main():
    script_dir = Path(__file__).parent.resolve()
    montauk_root = script_dir.parent  # Parent of montauk-kernel is montauk root
    kver = get_kernel_version()
    tmp_build = Path("/tmp/montauk-kernel")

    print("montauk-kernel installer")
    print("========================")
    print(f"Kernel version: {kver}")
    print(f"Kernel module source: {script_dir}")
    print(f"Montauk root: {montauk_root}")
    print()

    # Step 1: Check kernel headers
    print("[1/9] Checking kernel headers...")
    if not check_kernel_headers():
        print()
        print("ERROR: Kernel headers not found!")
        print()
        print("Install them first:")
        print("  Arch Linux:    sudo pacman -S linux-headers")
        print("  Debian/Ubuntu: sudo apt install linux-headers-$(uname -r)")
        print("  Fedora:        sudo dnf install kernel-devel")
        print()
        sys.exit(1)
    print(f"  OK: Headers found at /lib/modules/{kver}/build")

    # Step 2: Check cmake
    print("[2/9] Checking build tools...")
    if not check_cmake():
        print()
        print("ERROR: cmake not found!")
        print()
        print("Install it first:")
        print("  Arch Linux:    sudo pacman -S cmake")
        print("  Debian/Ubuntu: sudo apt install cmake")
        print("  Fedora:        sudo dnf install cmake")
        print()
        sys.exit(1)
    print("  OK: cmake found")

    # Step 3: Copy to /tmp (avoid spaces in path)
    print("[3/9] Preparing kernel module build directory...")
    if " " in str(script_dir):
        print(f"  Source path has spaces, copying to {tmp_build}")
        if tmp_build.exists():
            shutil.rmtree(tmp_build)
        # Copy only the kernel module files, not the whole tree
        shutil.copytree(script_dir, tmp_build,
                       ignore=shutil.ignore_patterns('*.pyc', '__pycache__', '*.ko', '*.o', '*.mod*', '.tmp*', 'Module.symvers', 'modules.order'))
    else:
        tmp_build = script_dir
    print(f"  OK: Building in {tmp_build}")

    # Step 4: Build kernel module
    print("[4/9] Building kernel module...")
    kdir = f"/lib/modules/{kver}/build"

    # Clean first
    ret, _, _ = run(["make", "-C", kdir, f"M={tmp_build}", "clean"])

    # Build
    ret, stdout, stderr = run(["make", "-C", kdir, f"M={tmp_build}", "modules"], capture=True)
    if ret != 0:
        print(f"ERROR: Build failed!")
        print(stderr)
        sys.exit(1)

    ko_file = tmp_build / "montauk.ko"
    if not ko_file.exists():
        print("ERROR: montauk.ko not found after build!")
        sys.exit(1)
    print(f"  OK: Built {ko_file}")

    # Step 5: Verify module version matches running kernel
    print("[5/9] Verifying module/kernel version match...")
    ok, msg = verify_module_version(ko_file, kver)
    if not ok:
        print(f"ERROR: {msg}")
        print()
        print("The module was built for a different kernel version.")
        print("Make sure you have the correct kernel headers installed:")
        print(f"  Running kernel: {kver}")
        print(f"  Headers should be at: /lib/modules/{kver}/build")
        print()
        sys.exit(1)
    print(f"  OK: Module vermagic matches running kernel ({msg})")

    # Step 6: Install kernel module (needs root)
    print("[6/9] Installing kernel module...")
    dest_dir = Path(f"/lib/modules/{kver}/extra")
    dest_file = dest_dir / "montauk.ko"

    ret, _, _ = run(["mkdir", "-p", str(dest_dir)], sudo=True)
    ret, _, _ = run(["cp", str(ko_file), str(dest_file)], sudo=True)
    if ret != 0:
        print("ERROR: Failed to copy module (need sudo?)")
        sys.exit(1)

    ret, _, _ = run([find_kmod_tool("depmod"), "-a"], sudo=True)
    if ret != 0:
        print("ERROR: depmod failed!")
        sys.exit(1)
    print(f"  OK: Installed to {dest_file}")

    # Step 7: Setup auto-load (with version safety note)
    print("[7/9] Setting up auto-load at boot...")
    modules_conf = Path("/etc/modules-load.d/montauk.conf")

    proc = subprocess.Popen(
        ["sudo", "tee", str(modules_conf)],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL
    )
    proc.communicate(input=b"montauk\n")

    if proc.returncode != 0:
        print("  WARNING: Could not set up auto-load")
    else:
        print(f"  OK: Created {modules_conf}")

    # Step 8: Load kernel module now
    print("[8/9] Loading kernel module...")

    # Unload if already loaded
    ret, stdout, _ = run([find_kmod_tool("lsmod")], capture=True)
    if "montauk" in stdout:
        print("  Unloading existing module...")
        run([find_kmod_tool("rmmod"), "montauk"], sudo=True, check=False)

    ret, _, stderr = run([find_kmod_tool("modprobe"), "montauk"], sudo=True, capture=True)
    if ret != 0:
        print(f"ERROR: Failed to load module: {stderr}")
        sys.exit(1)

    # Verify
    ret, stdout, _ = run([find_kmod_tool("lsmod")], capture=True)
    if "montauk" not in stdout:
        print("ERROR: Module not showing in lsmod!")
        sys.exit(1)
    print("  OK: Module loaded")

    # Step 9: Rebuild montauk userspace with kernel support and install
    print("[9/9] Rebuilding montauk with kernel collector support...")

    build_dir = montauk_root / "build"

    # Configure with MONTAUK_KERNEL=ON
    ret, stdout, stderr = run(
        ["cmake", "-B", str(build_dir), "-DMONTAUK_KERNEL=ON"],
        cwd=str(montauk_root),
        capture=True
    )
    if ret != 0:
        print(f"ERROR: cmake configure failed!")
        print(stderr)
        sys.exit(1)

    # Build (--clean-first ensures fresh binaries)
    import multiprocessing
    jobs = multiprocessing.cpu_count()
    ret, stdout, stderr = run(
        ["cmake", "--build", str(build_dir), "--clean-first", f"-j{jobs}"],
        capture=True
    )
    if ret != 0:
        print(f"ERROR: cmake build failed!")
        print(stderr)
        sys.exit(1)

    montauk_bin = build_dir / "montauk"
    if not montauk_bin.exists():
        print("ERROR: montauk binary not found after build!")
        sys.exit(1)
    print(f"  OK: Built {montauk_bin}")

    # Install to /usr/local/bin
    print("  Installing to /usr/local/bin...")
    ret, _, stderr = run(["cp", str(montauk_bin), "/usr/local/bin/montauk"], sudo=True, capture=True)
    if ret != 0:
        print(f"  ERROR: Could not install to /usr/local/bin: {stderr}")
        sys.exit(1)

    # Verify the install worked
    ret, stdout, _ = run(["ls", "-la", "/usr/local/bin/montauk"], capture=True)
    installed_size = montauk_bin.stat().st_size
    print(f"  OK: Installed to /usr/local/bin/montauk ({installed_size} bytes)")

    # Verify the installed binary has kernel support
    ret, stdout, _ = run(["strings", "/usr/local/bin/montauk"], capture=True)
    if "KernelProcessCollector" not in stdout:
        print("  WARNING: Installed binary may not have kernel support compiled in!")
    else:
        print("  OK: Kernel collector verified in installed binary")

    print()
    print("=" * 60)
    print("SUCCESS! montauk-kernel is fully installed.")
    print("=" * 60)
    print()
    print(f"Kernel version: {kver}")
    print("The kernel module is loaded and will auto-load on boot.")
    print()
    print("Run:")
    print("  montauk")
    print()
    print("You should see 'Kernel Module' as the collector type in the UI.")
    print()
    print("Verify kernel module:")
    print("  lsmod | grep montauk")
    print("  sudo dmesg | grep montauk")
    print()
    print("*" * 60)
    print("WARNING: If you update your system kernel, you MUST re-run")
    print("         this installer to rebuild the module!")
    print()
    print(f"         cd {script_dir}")
    print("         ./install.py")
    print("*" * 60)
    print()
    print("To uninstall:")
    print("  sudo rmmod montauk")
    print(f"  sudo rm /lib/modules/{kver}/extra/montauk.ko")
    print("  sudo rm /etc/modules-load.d/montauk.conf")
    print("  sudo depmod -a")

if __name__ == "__main__":
    main()
