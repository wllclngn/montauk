#!/usr/bin/env python3
"""
montauk installer

Builds and installs montauk system monitor.

Usage:
    ./install.py              # Build and install (default)
    ./install.py --kernel     # Build with kernel module collector support
    ./install.py --debug      # Debug build
    ./install.py --prefix /usr # Install to /usr instead of /usr/local
    ./install.py build        # Build only, don't install
    ./install.py clean        # Clean build directory
    ./install.py uninstall    # Remove installed files
"""

import argparse
import os
import sys
import shutil
import subprocess
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

def check_cmake():
    """Check if cmake is available."""
    ret, _, _ = run(["which", "cmake"], capture=True)
    return ret == 0

def check_compiler():
    """Check if a C++ compiler is available."""
    for compiler in ["g++", "clang++"]:
        ret, _, _ = run(["which", compiler], capture=True)
        if ret == 0:
            return True
    return False

def get_config_dir():
    """Get the user's config directory."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "montauk"
    return Path.home() / ".config" / "montauk"

def install_themes(source_dir):
    """Install theme files to user config directory."""
    config_dir = get_config_dir()
    theme_src = source_dir / "src" / "util" / "theme.env"

    if not theme_src.exists():
        return False

    config_dir.mkdir(parents=True, exist_ok=True)
    theme_dst = config_dir / "theme.env"

    # Don't overwrite existing theme
    if not theme_dst.exists():
        shutil.copy(theme_src, theme_dst)
        return True
    return False

def cmd_build(args, source_dir):
    """Build montauk."""
    build_dir = source_dir / "build"

    # Configure
    cmake_args = ["cmake", "-S", str(source_dir), "-B", str(build_dir)]

    if args.debug:
        cmake_args.append("-DCMAKE_BUILD_TYPE=Debug")
    else:
        cmake_args.append("-DCMAKE_BUILD_TYPE=Release")

    if args.kernel:
        cmake_args.append("-DMONTAUK_KERNEL=ON")

    if args.prefix:
        cmake_args.append(f"-DCMAKE_INSTALL_PREFIX={args.prefix}")

    print("Configuring...")
    ret, _, stderr = run(cmake_args, capture=True)
    if ret != 0:
        print(f"ERROR: cmake configure failed!")
        print(stderr)
        return False

    # Build
    import multiprocessing
    jobs = multiprocessing.cpu_count()

    print(f"Building (using {jobs} jobs)...")
    # Use --clean-first for install to ensure fresh binaries
    build_cmd = ["cmake", "--build", str(build_dir), f"-j{jobs}"]
    if args.command == "install":
        build_cmd.insert(3, "--clean-first")
    ret, _, stderr = run(build_cmd, capture=True)
    if ret != 0:
        print(f"ERROR: Build failed!")
        print(stderr)
        return False

    binary = build_dir / "montauk"
    if not binary.exists():
        print("ERROR: montauk binary not found after build!")
        return False

    print(f"  OK: Built {binary}")

    # Install themes
    if install_themes(source_dir):
        print(f"  OK: Installed theme to {get_config_dir()}/theme.env")

    return True

def cmd_install(args, source_dir):
    """Build and install montauk."""
    if not cmd_build(args, source_dir):
        return False

    build_dir = source_dir / "build"
    binary = build_dir / "montauk"
    prefix = Path(args.prefix) if args.prefix else Path("/usr/local")
    install_path = prefix / "bin" / "montauk"

    print(f"Installing to {install_path}...")

    # Create bin directory if needed
    ret, _, _ = run(["mkdir", "-p", str(prefix / "bin")], sudo=True)

    # Copy binary
    ret, _, stderr = run(["cp", str(binary), str(install_path)], sudo=True, capture=True)
    if ret != 0:
        print(f"ERROR: Failed to install: {stderr}")
        return False

    print(f"  OK: Installed to {install_path}")

    # Verify
    ret, stdout, _ = run(["ls", "-la", str(install_path)], capture=True)
    size = binary.stat().st_size
    print(f"  OK: {size} bytes")

    if args.kernel:
        ret, stdout, _ = run(["strings", str(install_path)], capture=True)
        if "KernelProcessCollector" in stdout:
            print("  OK: Kernel collector support enabled")
        else:
            print("  WARNING: Kernel collector may not be compiled in")

    print()
    print("=" * 50)
    print("SUCCESS!")
    print("=" * 50)
    print()
    print("Run:")
    print("  montauk")
    print()

    if args.kernel:
        print("NOTE: For kernel module support, also run:")
        print("  cd montauk-kernel && ./install.py")
        print()

    return True

def cmd_clean(args, source_dir):
    """Clean build directory."""
    build_dir = source_dir / "build"

    if build_dir.exists():
        print(f"Removing {build_dir}...")
        shutil.rmtree(build_dir)
        print("  OK: Cleaned")
    else:
        print("Nothing to clean")

    return True

def cmd_uninstall(args, source_dir):
    """Remove installed files."""
    prefix = Path(args.prefix) if args.prefix else Path("/usr/local")
    install_path = prefix / "bin" / "montauk"

    if install_path.exists():
        print(f"Removing {install_path}...")
        ret, _, _ = run(["rm", str(install_path)], sudo=True)
        if ret == 0:
            print("  OK: Removed")
        else:
            print("  ERROR: Failed to remove")
            return False
    else:
        print(f"{install_path} not found")

    return True

def cmd_test(args, source_dir):
    """Run tests."""
    build_dir = source_dir / "build"
    test_binary = build_dir / "montauk_tests"

    if not test_binary.exists():
        print("Tests not built. Building with tests enabled...")
        cmake_args = ["cmake", "-S", str(source_dir), "-B", str(build_dir), "-DMONTAUK_BUILD_TESTS=ON"]
        ret, _, _ = run(cmake_args, capture=True)
        if ret != 0:
            print("ERROR: Configure failed")
            return False

        import multiprocessing
        ret, _, _ = run(["cmake", "--build", str(build_dir), f"-j{multiprocessing.cpu_count()}"], capture=True)
        if ret != 0:
            print("ERROR: Build failed")
            return False

    print("Running tests...")
    ret, _, _ = run([str(test_binary)])
    return ret == 0

def main():
    parser = argparse.ArgumentParser(
        description="Build and install montauk system monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  (default)   Build and install
  build       Build only
  clean       Remove build directory
  uninstall   Remove installed binary
  test        Run tests

Examples:
  ./install.py                    # Build and install to /usr/local/bin
  ./install.py --kernel           # Build with kernel module support
  ./install.py --prefix /usr      # Install to /usr/bin
  ./install.py build              # Build only
  ./install.py clean              # Clean build
"""
    )

    parser.add_argument("command", nargs="?", default="install",
                       choices=["install", "build", "clean", "uninstall", "test"],
                       help="Command to run (default: install)")
    parser.add_argument("--kernel", action="store_true",
                       help="Enable kernel module collector support")
    parser.add_argument("--debug", action="store_true",
                       help="Build with debug symbols")
    parser.add_argument("--prefix", type=str, default=None,
                       help="Installation prefix (default: /usr/local)")

    args = parser.parse_args()

    source_dir = Path(__file__).parent.resolve()

    print("montauk installer")
    print("=================")
    print(f"Source: {source_dir}")
    print()

    # Check dependencies
    if args.command in ["install", "build", "test"]:
        print("Checking dependencies...")

        if not check_cmake():
            print()
            print("ERROR: cmake not found!")
            print()
            print("Install it first:")
            print("  Arch Linux:    sudo pacman -S cmake")
            print("  Debian/Ubuntu: sudo apt install cmake build-essential")
            print("  Fedora:        sudo dnf install cmake gcc-c++")
            print()
            sys.exit(1)
        print("  OK: cmake found")

        if not check_compiler():
            print()
            print("ERROR: C++ compiler not found!")
            print()
            print("Install it first:")
            print("  Arch Linux:    sudo pacman -S gcc")
            print("  Debian/Ubuntu: sudo apt install build-essential")
            print("  Fedora:        sudo dnf install gcc-c++")
            print()
            sys.exit(1)
        print("  OK: C++ compiler found")
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
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
