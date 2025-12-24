.PHONY: all build debug run test clean distclean nvml install install-themes

CONFIG_DIR := $(if $(XDG_CONFIG_HOME),$(XDG_CONFIG_HOME)/montauk,$(HOME)/.config/montauk)

all: build

build: install-themes
	@cmake -S . -B build >/dev/null
	@cmake --build build -j

debug: install-themes
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

install: build
	@cmake --install build

# Build with NVML (text mode only)
nvml: install-themes
	@cmake -S . -B build >/dev/null || true
	@cmake --build build -j

install-themes:
	@mkdir -p "$(CONFIG_DIR)"
	@cp -n src/util/theme.env "$(CONFIG_DIR)/theme.env" 2>/dev/null || true
