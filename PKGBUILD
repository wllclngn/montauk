# Maintainer: Will C.
#
# VCS-tracked package: pulls the latest commit from main on every makepkg.
# pkgver() derives the version automatically from CMakeLists.txt's
# `project(montauk VERSION X.Y.Z)` line, so bumping the version in the
# build system is the only source of truth. No git tags required, no
# sha256 updates, no pkgver edits in this file. Commit, push, makepkg -si.
pkgname=montauk
pkgver=6.0.0
pkgrel=1
pkgdesc='High-performance Linux system monitor with kernel module, eBPF tracing, GPU attribution, and pixel-rendered area charts'
arch=('x86_64')
url='https://github.com/wllclngn/montauk'
license=('GPL-2.0-only')
depends=(
    'glibc'
    'gcc-libs'
    'sublimation>=1.2.0'
    'libbpf'
    'liburing'
)
makedepends=(
    'git'
    'cmake'
    'gcc'
    'clang'
    'bpf'
)
optdepends=(
    'nvidia-utils: NVML-based per-process GPU attribution'
    'linux-headers: build the optional kernel module via ./install.py --kernel'
)
source=("$pkgname::git+$url.git")
sha256sums=('SKIP')

pkgver() {
    cd "$srcdir/$pkgname"
    # Read VERSION from `project(montauk VERSION X.Y.Z LANGUAGES CXX)`
    local cmake_ver
    cmake_ver=$(awk -F'[ )]' '/^project\(montauk VERSION/ {print $4; exit}' CMakeLists.txt)
    # Append a short commit suffix so reinstalling unchanged HEAD is a no-op
    # but every new commit produces a new pkgver pacman will accept.
    local commits short
    commits=$(git rev-list --count HEAD)
    short=$(git rev-parse --short=8 HEAD)
    printf '%s.r%s.g%s' "${cmake_ver:-0.0.0}" "$commits" "$short"
}

build() {
    cd "$srcdir/$pkgname"
    cmake -B build -S . \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DUSE_SUBLIMATION=ON \
        -DMONTAUK_KERNEL=OFF \
        -DMONTAUK_BUILD_TESTS=OFF
    cmake --build build -j"$(nproc)"
}

package() {
    cd "$srcdir/$pkgname"

    # Binaries
    install -Dm755 build/montauk             "$pkgdir/usr/bin/montauk"
    install -Dm755 build/montauk_analyze     "$pkgdir/usr/bin/montauk_analyze"

    # Manpage (read at runtime by the in-app help overlay via `man montauk`)
    install -Dm644 montauk.1                 "$pkgdir/usr/share/man/man1/montauk.1"

    # License
    install -Dm644 LICENSE                   "$pkgdir/usr/share/licenses/$pkgname/LICENSE"

    # Documentation
    install -Dm644 README.md                 "$pkgdir/usr/share/doc/$pkgname/README.md"
    [ -f DEPLOYMENT.md ]    && install -Dm644 DEPLOYMENT.md    "$pkgdir/usr/share/doc/$pkgname/DEPLOYMENT.md"
    [ -f UI_TRANSITION.md ] && install -Dm644 UI_TRANSITION.md "$pkgdir/usr/share/doc/$pkgname/UI_TRANSITION.md"
}
