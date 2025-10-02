.PHONY: all build debug run test clean distclean nvml

all: build

build:
	@cmake -S . -B build >/dev/null || true
	@cmake --build build -j

debug:
	@cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug >/dev/null || true
	@cmake --build build -j

run: build
	@./build/montauk || true

test: build
	@./build/montauk_tests

clean:
	@cmake --build build --target clean >/dev/null 2>&1 || true

distclean:
	@rm -rf build

# Build with NVML (text mode only)
nvml:
	@cmake -S . -B build >/dev/null || true
	@cmake --build build -j
