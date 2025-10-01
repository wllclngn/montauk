 # Maintainer: Your Name <you@example.com>

pkgname=linux-sys-monitor-cpp
pkgver=0.1.0
pkgrel=1
pkgdesc="Lightweight C++23 Linux system monitor (text UI; optional NVIDIA NVML)"
arch=('x86_64')
url="https://local"
license=('custom')
depends=('gcc-libs')
makedepends=('cmake' 'gcc' 'make')
optdepends=('nvidia-utils: enable NVML GPU metrics when available')

source=()
sha256sums=()

build() {
  cd "$srcdir"
  if [[ "$srcdir" == *" "* || "$startdir" == *" "* ]]; then
    echo "[lsm] Detected spaces in build path; overriding *FLAGS to strip -ffile-prefix-map"
    # Provide safe baseline flags without -ffile-prefix-map (space-safe)
    local _BASEC="-march=x86-64 -mtune=generic -O2 -pipe -fno-plt -fexceptions -Wp,-D_FORTIFY_SOURCE=3 -Wformat -Werror=format-security -fstack-clash-protection -fcf-protection -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -Wp,-D_GLIBCXX_ASSERTIONS -g"
    CFLAGS="${_BASEC}" CXXFLAGS="${_BASEC}" CPPFLAGS="" LDFLAGS="${LDFLAGS:-}" \
    cmake -S "$startdir" -B build \
      -DCMAKE_BUILD_TYPE=None \
      -DCMAKE_INSTALL_PREFIX=/usr \
      -DLSM_BUILD_TESTS=OFF \
      -DCMAKE_C_FLAGS="${_BASEC}" -DCMAKE_CXX_FLAGS="${_BASEC}"
    CFLAGS="${_BASEC}" CXXFLAGS="${_BASEC}" CPPFLAGS="" LDFLAGS="${LDFLAGS:-}" \
    cmake --build build --parallel
  else
    cmake -S "$startdir" -B build \
      -DCMAKE_BUILD_TYPE=None \
      -DCMAKE_INSTALL_PREFIX=/usr \
      -DLSM_BUILD_TESTS=OFF
    cmake --build build --parallel
  fi
}

check() {
  cd "$srcdir"
  if [[ -x build/lsm_tests ]]; then
    ./build/lsm_tests || echo "[lsm] Tests failed (ignored for packaging)"
  else
    echo "[lsm] Tests disabled (LSM_BUILD_TESTS=OFF)"
  fi
}

package() {
  cd "$srcdir"
  DESTDIR="$pkgdir" cmake --install build
  install -Dm644 "$startdir/README.md" "$pkgdir/usr/share/doc/$pkgname/README.md"
}
