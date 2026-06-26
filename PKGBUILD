# Maintainer: Will C.
# Contributor: SoongVilda <https://github.com/SoongVilda>
#
# VCS-tracked package: pulls the latest commit from main on every makepkg.
# pkgver() derives the version automatically from CMakeLists.txt's
# `project(montauk VERSION X.Y.Z)` line, so bumping the version in the
# build system is the only source of truth. No git tags required, no
# sha256 updates, no pkgver edits in this file. Commit, push, makepkg -si.

# Upstream project name; pkgname is suffixed `-git` per Arch VCS guidelines
# so this can coexist with a future stable `montauk` AUR package via
# provides/conflicts. Internal references (srcdir, source array, install
# paths under /usr/share/{licenses,doc}/) all use $_pkgname so the layout
# matches what the stable package would produce.
_pkgname=montauk
pkgname="${_pkgname}-git"

# Auto-relocate BUILDDIR off any path containing spaces. CMake's
# try_compile, makepkg's CFLAGS expansion (-ffile-prefix-map,
# -fdiagnostics-color), and the kernel-module build all word-split on
# spaces and fail. By the time this PKGBUILD is sourced, makepkg has
# already canonicalized BUILDDIR to the user's explicit value (env or
# ~/.makepkg.conf) or to $startdir as fallback. We mirror makepkg's own
# `-ef` test to detect the fallback case and only override when the
# fallback path also contains spaces — explicit user overrides are
# honored unchanged. srcdir/pkgdir are derived from BUILDDIR *after*
# PKGBUILD source (makepkg.sh line ~1295), so a direct assignment here
# propagates.
if [[ $BUILDDIR -ef "$startdir" && "$startdir" == *" "* ]]; then
    BUILDDIR=/tmp/makepkg-$pkgname
fi

pkgver=7.8.0.r79.g4fd29ea0
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
)

# Coexistence with a future stable AUR `montauk` package.
provides=("$_pkgname")
conflicts=("$_pkgname")

# Rename hygiene. This PKGBUILD was once named `montauk` and its debug split
# was `montauk-debug`. After the `-git` rename, provides/conflicts swapped the
# main package but left `montauk-debug` installed, orphaned and still owning the
# /usr/lib/debug/.build-id/* files -- which then collide with montauk-git-debug
# ("exists in filesystem, owned by montauk-debug") and fail the install commit.
# replaces= supersedes the orphan on install so the debug files transfer cleanly.
replaces=("$_pkgname-debug")

source=("$_pkgname::git+$url.git")
# git branches are dynamic — checksums change every commit. SKIP is correct
# for a -git VCS package; integrity is the source URL itself.
sha256sums=('SKIP')

pkgver() {
    cd "$srcdir/$_pkgname"

    # Locals are underscore-prefixed to keep them out of any namespace
    # makepkg internals might touch.
    local _cmake_ver _commits _short

    # Capture X.Y.Z directly from `project(montauk VERSION X.Y.Z LANGUAGES CXX)`.
    # Field-splitting on whitespace would land on "LANGUAGES" — that's $4
    # in awk-field land — so we use an explicit sed regex.
    _cmake_ver=$(sed -nE 's/^project\(montauk VERSION ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' \
                 CMakeLists.txt | head -n1)

    # Append the total commit count + short hash so every push produces
    # a unique sequential Arch version string. Reinstalling unchanged
    # HEAD is a no-op.
    _commits=$(git rev-list --count HEAD)
    _short=$(git rev-parse --short=8 HEAD)
    printf '%s.r%s.g%s' "${_cmake_ver:-0.0.0}" "$_commits" "$_short"
}

build() {
    cd "$srcdir/$_pkgname"

    # sublimation is montauk's sort algorithm — an in-tree sub-system at
    # montauk/sublimation/. CMake builds it as a static library and links it
    # into montauk; there is no fallback and no build-time toggle.
    cmake -B build -S . \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DMONTAUK_KERNEL=OFF \
        -DMONTAUK_BUILD_TESTS=OFF

    # No -j flag — makepkg injects MAKEFLAGS from /etc/makepkg.conf, which
    # is where parallelism belongs.
    cmake --build build
}

package() {
    cd "$srcdir/$_pkgname"

    # Binaries.
    install -Dm755 build/montauk              "$pkgdir/usr/bin/montauk"
    install -Dm755 build/montauk_analyze      "$pkgdir/usr/bin/montauk_analyze"
    install -Dm755 build/montauk_trace_decode "$pkgdir/usr/bin/montauk_trace_decode"
    install -Dm755 build/sublimation          "$pkgdir/usr/bin/sublimation"

    # Manpage — the in-app help overlay loads it at runtime via `man montauk`.
    install -Dm644 montauk.1                 "$pkgdir/usr/share/man/man1/montauk.1"

    # License + docs under the upstream name so users can `pacman -Ql montauk`
    # equivalently whether they installed -git or stable.
    install -Dm644 LICENSE                   "$pkgdir/usr/share/licenses/$_pkgname/LICENSE"
    install -Dm644 README.md                 "$pkgdir/usr/share/doc/$_pkgname/README.md"

    # Optional supplementary doc — only present in some commits. Wrap in
    # a real `if` so a missing file doesn't make package() return non-zero
    # from the trailing test (which makepkg would treat as build failure).
    if [ -f DEPLOYMENT.md ]; then
        install -Dm644 DEPLOYMENT.md "$pkgdir/usr/share/doc/$_pkgname/DEPLOYMENT.md"
    fi
}
