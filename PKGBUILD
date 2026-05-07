# Maintainer: Will C.
#
# This is a VCS package that automatically tracks the latest commit on the main branch.
# You do not need to manually update pkgver or sha256sums; makepkg handles it dynamically.

# Base name of the upstream repository
_pkgname=montauk
# Arch package name (suffixed with -git as per VCS guidelines)
pkgname="${_pkgname}-git"
pkgver=6.3.0.r69.ga46bd8db
pkgrel=1
pkgdesc='High-performance Linux system monitor with kernel module, eBPF tracing, GPU attribution, and pixel-rendered area charts'
arch=('x86_64')
url='https://github.com/wllclngn/montauk'
license=('GPL-2.0-only')
depends=(
    'glibc'
    'gcc-libs'
    'libbpf'
    'liburing'
)
makedepends=(
    'git'
    'cmake'
    'gcc'
    'clang'
)
optdepends=(
    'nvidia-utils: NVML-based per-process GPU attribution'
    'linux-headers: build the optional kernel module via ./install.py --kernel'
    'sublimation: opt-in C23 sort backend (run ./install.py --sublimation to fetch and install before makepkg)'
)
# Explicitly provide and conflict with the stable release name
provides=("$_pkgname")
conflicts=("$_pkgname")
source=("$_pkgname::git+$url.git")
# SKIP is used because git branches are dynamic and checksums change with every commit
sha256sums=('SKIP')

pkgver() {
    cd "$srcdir/$_pkgname"
    
    local _cmake_ver _commits _short
    
    # Dynamically extract the base version (X.Y.Z) directly from CMakeLists.txt.
    # This ensures the PKGBUILD is always in sync with the upstream build system.
    _cmake_ver=$(sed -nE 's/^project\(montauk VERSION ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' \
                CMakeLists.txt | head -n1)
                
    # Append the total commit count and the short hash to create a unique, sequential Arch version string.
    _commits=$(git rev-list --count HEAD)
    _short=$(git rev-parse --short=8 HEAD)
    printf '%s.r%s.g%s' "${_cmake_ver:-0.0.0}" "$_commits" "$_short"
}

build() {
    cd "$srcdir/$_pkgname"

    # Check if the optional 'sublimation' package is installed on the build system.
    # If not found, gracefully fall back to the built-in TimSort implementation.
    local _use_sublimation=OFF
    if pkg-config --exists sublimation 2>/dev/null; then
        _use_sublimation=ON
    fi

    # Configure the build via CMake
    cmake -B build -S . \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DUSE_SUBLIMATION="$_use_sublimation" \
        -DMONTAUK_KERNEL=OFF \
        -DMONTAUK_BUILD_TESTS=OFF
        
    # Compile the project. 
    # Note: makepkg automatically injects the user's MAKEFLAGS (e.g., -j16) here.
    cmake --build build
}

package() {
    cd "$srcdir/$_pkgname"

    # Install main executables
    install -Dm755 build/montauk             "$pkgdir/usr/bin/montauk"
    install -Dm755 build/montauk_analyze     "$pkgdir/usr/bin/montauk_analyze"

    # Install the manpage (required for Montauk's in-app help overlay to function)
    install -Dm644 montauk.1                 "$pkgdir/usr/share/man/man1/montauk.1"

    # Install standard documentation and licensing
    install -Dm644 LICENSE                   "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
    install -Dm644 README.md                 "$pkgdir/usr/share/doc/$pkgname/README.md"
    
    # Conditionally install DEPLOYMENT.md only if it exists in the currently checked-out commit
    if [ -f DEPLOYMENT.md ]; then
        install -Dm644 DEPLOYMENT.md "$pkgdir/usr/share/doc/$pkgname/DEPLOYMENT.md"
    fi
}
