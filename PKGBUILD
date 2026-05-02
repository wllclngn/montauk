# Maintainer: Will C.
#
# VCS-tracked package: pulls the latest commit from main on every makepkg.
# pkgver() derives the version automatically from CMakeLists.txt's
# `project(montauk VERSION X.Y.Z)` line, so bumping the version in the
# build system is the only source of truth. No git tags required, no
# sha256 updates, no pkgver edits in this file. Commit, push, makepkg -si.
pkgname=montauk

# Auto-relocate BUILDDIR off any path containing spaces. CMake's
# try_compile, makepkg's CFLAGS expansion (-ffile-prefix-map,
# -fdiagnostics-color), and the kernel-module build all word-split on
# spaces and fail.
#
# Mechanism: by the time this PKGBUILD is sourced, makepkg has already
# canonicalized BUILDDIR to either the user's explicit value (from env
# or ~/.makepkg.conf) or to $startdir as the fallback. We mirror
# makepkg's own `-ef` test against $startdir to detect the fallback
# case — same file/inode means the user set nothing — and only override
# when the fallback path also contains spaces. Explicit user overrides
# are honored unchanged.
#
# srcdir/pkgdir are derived from BUILDDIR *after* PKGBUILD source
# (makepkg.sh line ~1295), so a direct assignment here propagates.
if [[ $BUILDDIR -ef "$startdir" && "$startdir" == *" "* ]]; then
    BUILDDIR=/tmp/makepkg-$pkgname
fi

pkgver=6.3.0.r69.ga0338b15
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
source=("$pkgname::git+$url.git")
sha256sums=('SKIP')

pkgver() {
    cd "$srcdir/$pkgname"
    # Read VERSION from `project(montauk VERSION X.Y.Z LANGUAGES CXX)`.
    # Capture the X.Y.Z digits explicitly — splitting on whitespace would
    # land on "LANGUAGES" because that's $4 in field-split land.
    local cmake_ver
    cmake_ver=$(sed -nE 's/^project\(montauk VERSION ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' \
                CMakeLists.txt | head -n1)
    # Append a short commit suffix so reinstalling unchanged HEAD is a no-op
    # but every new commit produces a new pkgver pacman will accept.
    local commits short
    commits=$(git rev-list --count HEAD)
    short=$(git rev-parse --short=8 HEAD)
    printf '%s.r%s.g%s' "${cmake_ver:-0.0.0}" "$commits" "$short"
}

build() {
    cd "$srcdir/$pkgname"

    # Sublimation is only available via the upstream GitHub repo (no pacman
    # provider); install.py fetches and installs it system-wide on demand.
    # If pkg-config sees it already installed, link it in; otherwise build
    # the TimSort-only path so makepkg works on any Arch box without
    # requiring users to run install.py first.
    local use_sublimation=OFF
    if pkg-config --exists sublimation 2>/dev/null; then
        use_sublimation=ON
    fi

    cmake -B build -S . \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DUSE_SUBLIMATION="$use_sublimation" \
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
    [ -f DEPLOYMENT.md ] && install -Dm644 DEPLOYMENT.md "$pkgdir/usr/share/doc/$pkgname/DEPLOYMENT.md"
}
