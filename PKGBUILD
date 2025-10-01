# Maintainer: Your Name <you@example.com>

pkgname=linux-sys-monitor-cpp
pkgver=0.1.0
pkgrel=1
pkgdesc="Lightweight C++23 Linux system monitor (text UI, NVML-enabled for NVIDIA)"
arch=('x86_64')
url="https://local"
license=('custom')
# Build with NVML auto-detected.
depends=('nvidia-utils')
makedepends=('cmake' 'cuda')

source=()
sha256sums=()

build() {
  cd "$srcdir"
  cmake -S "$startdir" -B build \
    -DCMAKE_BUILD_TYPE=Release \
    
  cmake --build build -j$(nproc)
}

check() {
  cd "$srcdir"
  if [[ -x build/lsm_tests ]]; then
    ./build/lsm_tests
  fi
}

package() {
  cd "$srcdir"
  install -Dm755 build/lsmcpp "$pkgdir/usr/bin/lsmcpp"
  # Optional docs
  install -Dm644 "$startdir/README.md" "$pkgdir/usr/share/doc/$pkgname/README.md"
}
