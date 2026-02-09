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
    """
    Run a command with real-time output to terminal.
    Returns the exit code.
    """
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


# =============================================================================
# DEPENDENCY CHECKS
# =============================================================================

def check_cmake() -> bool:
    """Check if cmake is available."""
    ret, _, _ = run_cmd_capture(["which", "cmake"])
    return ret == 0


def check_compiler() -> bool:
    """Check if a C++ compiler is available."""
    for compiler in ["g++", "clang++"]:
        ret, _, _ = run_cmd_capture(["which", compiler])
        if ret == 0:
            return True
    return False


# =============================================================================
# THEME INSTALLATION
# =============================================================================

def get_config_dir() -> Path:
    """Get the user's config directory."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "montauk"
    return Path.home() / ".config" / "montauk"


def init_theme(install_path: Path) -> bool:
    """Run --init-theme to detect terminal palette and write config.toml."""
    config_file = get_config_dir() / "config.toml"
    if config_file.exists():
        return False
    log_info("Detecting terminal palette...")
    ret = run_cmd([str(install_path), "--init-theme"])
    return ret == 0


# =============================================================================
# COMMANDS
# =============================================================================

def cmd_build(args, source_dir: Path) -> bool:
    """Build montauk."""
    build_dir = source_dir / "build"

    log_info("CONFIGURING BUILD")

    cmake_args = ["cmake", "-S", str(source_dir), "-B", str(build_dir)]

    if args.debug:
        cmake_args.append("-DCMAKE_BUILD_TYPE=Debug")
        log_info("Build type: Debug")
    else:
        cmake_args.append("-DCMAKE_BUILD_TYPE=Release")
        log_info("Build type: Release")

    if args.kernel:
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
    import multiprocessing
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

    # Create bin directory if needed
    run_cmd_sudo(["mkdir", "-p", str(prefix / "bin")])

    # Copy binary
    ret = run_cmd_sudo(["cp", str(binary), str(install_path)])
    if ret != 0:
        log_error("Failed to install binary!")
        return False

    size = binary.stat().st_size
    log_info(f"Installed {install_path} ({size} bytes)")

    # Detect terminal palette and write config.toml on first install
    if init_theme(install_path):
        log_info(f"Wrote config to {get_config_dir()}/config.toml")

    if args.kernel:
        ret, stdout, _ = run_cmd_capture(["strings", str(install_path)])
        if "KernelProcessCollector" in stdout:
            log_info("Kernel collector support verified")
        else:
            log_warn("Kernel collector may not be compiled in")

    print()
    log_info("SUCCESS. Installation complete.")
    log_info("RUN COMMAND: montauk")

    if args.kernel:
        log_info("For kernel module support: cd montauk-kernel && ./install.py")

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
    """Remove installed files."""
    prefix = Path(args.prefix) if args.prefix else Path("/usr/local")
    install_path = prefix / "bin" / "montauk"

    log_info("UNINSTALLING")

    if install_path.exists():
        log_info(f"Removing {install_path}")
        ret = run_cmd_sudo(["rm", str(install_path)])
        if ret == 0:
            log_info("Uninstall complete")
        else:
            log_error("Failed to remove binary")
            return False
    else:
        log_warn(f"{install_path} not found")

    return True


def cmd_test(args, source_dir: Path) -> bool:
    """Run tests."""
    build_dir = source_dir / "build"
    test_binary = build_dir / "montauk_tests"

    log_info("RUNNING TESTS")

    if not test_binary.exists():
        log_info("Tests not built, building with tests enabled...")

        cmake_args = ["cmake", "-S", str(source_dir), "-B", str(build_dir), "-DMONTAUK_BUILD_TESTS=ON"]
        ret = run_cmd(cmake_args)
        if ret != 0:
            log_error("Configure failed")
            return False

        import multiprocessing
        ret = run_cmd(["cmake", "--build", str(build_dir), f"-j{multiprocessing.cpu_count()}"])
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
