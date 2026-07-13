cmake_minimum_required(VERSION 3.20)
# C is enabled for the in-tree sublimation sort sub-system (C23); CXX for
# montauk itself.
project(montauk VERSION 7.14.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

 
# Forbid vendoring: prevent any attempt to fetch external projects during configure/build.
# If someone tries to introduce FetchContent or ExternalProject, fail fast at configure time.
macro(FetchContent_Declare)
  message(FATAL_ERROR "Vendoring is disabled in this project. Do not use FetchContent.")
endmacro()
macro(ExternalProject_Add)
  message(FATAL_ERROR "Vendoring is disabled in this project. Do not use ExternalProject.")
endmacro()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Build options
option(MONTAUK_BUILD_TESTS "Build unit tests" OFF)
option(MONTAUK_KERNEL "Build with kernel module collector support (requires montauk-kernel loaded)" OFF)

# ── sublimation ─────────────────────────────────────────────────────────────
# montauk's sort algorithm, now an in-tree sub-system (sublimation/). Built
# as a C23 static library from its own sources with its own flags — NOT
# montauk's -Werror/-Wshadow (third-party warnings must not fail montauk's
# build). No system install, no find_package, no fetch: the code lives here.
add_library(sublimation STATIC
    sublimation/src/classify.c
    sublimation/src/merge.c
    sublimation/src/pack.c
    sublimation/src/randomness.c
    sublimation/src/search.c
    sublimation/src/select.c
    sublimation/src/small.c
    sublimation/src/sort.c
    sublimation/src/spectral.c
    sublimation/src/text/bmh.c
    sublimation/src/text/nfa.c
    sublimation/src/parallel/pool.c
    sublimation/src/strings/msd_radix.c
    sublimation/src/strings/sort_strings.c
)
set_target_properties(sublimation PROPERTIES
    C_STANDARD 23
    C_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON)
# Public headers (sublimation.h / _pack.h / _strings.h) on the include path
# for consumers; src/ is private for the implementation's internal includes.
target_include_directories(sublimation
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/sublimation/src/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/sublimation/src)
target_compile_options(sublimation PRIVATE
    -O2 -march=native -fvisibility=hidden
    -fstack-protector-strong -fstack-clash-protection -fcf-protection)
target_link_libraries(sublimation PUBLIC pthread m)

add_library(montauk_core
    src/util/Procfs.cpp
    src/util/Churn.cpp
    src/util/SortDispatch.cpp
    src/util/Log.cpp
    src/util/NvmlDyn.cpp
    src/model/TraceReader.cpp
    src/ui/Terminal.cpp
    src/ui/Config.cpp
    src/ui/Formatting.cpp
    src/ui/Renderer.cpp
    src/ui/HelpOverlay.cpp
    src/app/ChartHistories.cpp
    src/app/GpuAttributor.cpp
    src/app/Producer.cpp
    src/app/Security.cpp
    src/app/Alerts.cpp
    src/app/Filter.cpp
    src/app/PrometheusSerializer.cpp
    src/app/JsonSerializer.cpp
    src/app/PrometheusSink.cpp
    src/app/JsonSink.cpp
    src/app/MetricsRender.cpp
    src/app/TraceRender.cpp
    src/app/ProviderEmitter.cpp
    src/app/LogWriter.cpp
    src/collectors/MemoryCollector.cpp
    src/collectors/GpuCollector.cpp
    src/collectors/FdinfoProcessCollector.cpp
    src/collectors/CpuCollector.cpp
    src/collectors/PmuCollector.cpp
    src/collectors/NetCollector.cpp
    src/collectors/DiskCollector.cpp
    src/collectors/FsCollector.cpp
    src/collectors/ProviderCollector.cpp
    src/collectors/ProcessCollector.cpp
    src/collectors/NetlinkProcessCollector.cpp
    src/collectors/ThermalCollector.cpp
    src/ui/widget/Canvas.cpp
    src/ui/widget/Chart.cpp
    src/ui/widget/Component.cpp
    src/ui/widget/FlexLayout.cpp
    src/ui/widget/GraphicsProtocol.cpp
    src/ui/widget/InputEvent.cpp
    src/ui/widget/Panel.cpp
    src/ui/widgets/ChartPanel.cpp
    src/ui/widgets/CpuGrid.cpp
    src/ui/widgets/ProcessTable.cpp
    src/ui/widgets/RightColumn.cpp
    src/ui/widgets/SystemPanel.cpp
)
target_include_directories(montauk_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_definitions(montauk_core PUBLIC _GNU_SOURCE)
target_compile_options(montauk_core PRIVATE -Wall -Wextra -Werror -Wshadow)

# Always attempt NVML (NVIDIA) support by default; if not found, build continues without it.
# Try common locations for NVML headers. On Arch/others, CUDA installs nvml.h under /opt/cuda/include.
find_path(NVML_INCLUDE_DIR nvml.h PATHS /usr/include /usr/local/include /usr/include/nvidia /opt/cuda/include)
find_library(NVML_LIBRARY nvidia-ml PATHS /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64)
if(NVML_INCLUDE_DIR AND NVML_LIBRARY)
  target_compile_definitions(montauk_core PUBLIC MONTAUK_HAVE_NVML=1)
  target_include_directories(montauk_core PUBLIC ${NVML_INCLUDE_DIR})
  target_link_libraries(montauk_core PUBLIC ${NVML_LIBRARY})
  message(STATUS "NVML detected: enabling per-process and device GPU metrics")
else()
  message(STATUS "NVML not found: building without NVML (device VRAM/util via sysfs if available)")
endif()

# io_uring support (Prometheus metrics endpoint)
find_library(URING_LIBRARY uring)
if(URING_LIBRARY)
  target_sources(montauk_core PRIVATE src/app/MetricsServer.cpp)
  target_link_libraries(montauk_core PUBLIC ${URING_LIBRARY})
  target_compile_definitions(montauk_core PUBLIC MONTAUK_HAVE_URING=1)
  message(STATUS "liburing detected: enabling Prometheus metrics endpoint")
else()
  target_sources(montauk_core PRIVATE src/app/MetricsServerStub.cpp)
  message(STATUS "liburing not found: building without metrics endpoint")
endif()

# Kernel module collector support (opt-in)
if(MONTAUK_KERNEL)
  target_compile_definitions(montauk_core PUBLIC MONTAUK_HAVE_KERNEL=1)
  target_sources(montauk_core PRIVATE src/collectors/KernelProcessCollector.cpp)
  message(STATUS "Kernel module support enabled: MONTAUK_COLLECTOR=kernel available")
endif()

# eBPF trace support (--trace mode)
option(MONTAUK_NO_BPF "Disable eBPF trace support even if libbpf is available" OFF)
if(NOT MONTAUK_NO_BPF)
find_library(LIBBPF_LIBRARY bpf)
find_path(LIBBPF_INCLUDE bpf/libbpf.h)
find_program(BPFTOOL bpftool)
find_program(CLANG_BPF clang)
if(LIBBPF_LIBRARY AND LIBBPF_INCLUDE AND BPFTOOL AND CLANG_BPF)
  # Generate vmlinux.h from kernel BTF.
  # Strip bpf_stream_vprintk: kernel BTF declares the older 4-arg signature,
  # but libbpf's bpf_helpers.h declares the newer 5-arg form (with aux__prog).
  # Both visible in the same TU = clang conflicting-types error. Drop the BTF
  # copy; bpf_helpers.h's declaration is the authoritative one.
  add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/vmlinux.h
    COMMAND ${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c
            | sed "/^extern int bpf_stream_vprintk/d"
            > ${CMAKE_BINARY_DIR}/vmlinux.h
    COMMENT "Generating vmlinux.h from kernel BTF"
  )
  # Compile BPF program
  add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/montauk_trace.bpf.o
    COMMAND ${CLANG_BPF} -target bpf -g -O2
      -I${CMAKE_BINARY_DIR}
      -I${CMAKE_SOURCE_DIR}/bpf
      -D__TARGET_ARCH_x86
      -Wno-missing-declarations
      -c ${CMAKE_SOURCE_DIR}/bpf/montauk_trace.bpf.c
      -o ${CMAKE_BINARY_DIR}/montauk_trace.bpf.o
    DEPENDS ${CMAKE_SOURCE_DIR}/bpf/montauk_trace.bpf.c
            ${CMAKE_SOURCE_DIR}/bpf/montauk_trace.h
            ${CMAKE_BINARY_DIR}/vmlinux.h
    COMMENT "Compiling BPF program"
  )
  # Generate skeleton header
  add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/montauk_trace.skel.h
    COMMAND ${BPFTOOL} gen skeleton ${CMAKE_BINARY_DIR}/montauk_trace.bpf.o
            > ${CMAKE_BINARY_DIR}/montauk_trace.skel.h
    DEPENDS ${CMAKE_BINARY_DIR}/montauk_trace.bpf.o
    COMMENT "Generating BPF skeleton"
  )
  add_custom_target(bpf_skel DEPENDS ${CMAKE_BINARY_DIR}/montauk_trace.skel.h)

  target_sources(montauk_core PRIVATE src/collectors/BpfTraceCollector.cpp)
  target_include_directories(montauk_core PUBLIC ${CMAKE_BINARY_DIR} ${LIBBPF_INCLUDE} ${CMAKE_SOURCE_DIR}/bpf)
  target_link_libraries(montauk_core PUBLIC ${LIBBPF_LIBRARY} elf z)
  target_compile_definitions(montauk_core PUBLIC MONTAUK_HAVE_BPF=1)
  add_dependencies(montauk_core bpf_skel)
  message(STATUS "libbpf detected: enabling eBPF trace mode (--trace)")
else()
  message(STATUS "libbpf/bpftool/clang not found: --trace disabled")
endif()
else()
  message(STATUS "eBPF trace disabled by MONTAUK_NO_BPF")
endif()

# Link the in-tree sublimation sort sub-system into montauk_core (built
# above). PUBLIC so its include dir propagates to montauk_core's consumers
# (e.g. the trace tools' sched-latency percentile sort).
target_link_libraries(montauk_core PUBLIC sublimation)
message(STATUS "Sublimation: in-tree sub-system (montauk/sublimation)")

add_executable(montauk src/main.cpp)
target_link_libraries(montauk PRIVATE montauk_core)
target_compile_options(montauk PRIVATE -Wall -Wextra -Werror -Wshadow)
set_target_properties(montauk PROPERTIES OUTPUT_NAME montauk)


install(TARGETS montauk RUNTIME DESTINATION bin)

# Trace-analysis report suite (trace-only; the old live /proc analyzer is
# gone). Same dependency footprint as the decoder: event headers + the
# TraceReader record walk, no montauk_core link, no BPF.
add_executable(montauk_analyze
    src/tools/trace_analyze.cpp
    src/tools/prom_stats.cpp
    src/tools/prom_population.cpp
    src/model/TraceReader.cpp
    src/util/Log.cpp)
target_include_directories(montauk_analyze PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf)
# sublimation is montauk's sort -- the sched report sorts wake2run latencies
# through its direct u64 entry. Links the in-tree sub-system.
target_link_libraries(montauk_analyze PRIVATE sublimation)
# Stamp the project version into the analysis .prom _info metric (house style).
target_compile_definitions(montauk_analyze PRIVATE MONTAUK_VERSION="${PROJECT_VERSION}")
target_compile_options(montauk_analyze PRIVATE -Wall -Wextra -Werror -Wshadow)
set_target_properties(montauk_analyze PROPERTIES OUTPUT_NAME montauk_analyze)

# Binary trace-log decoder (no external deps, no BPF link). Reads --trace-out
# files and renders them to text/CSV. Pure struct decoding — only needs the
# shared event headers (model/TraceBinary.hpp + bpf/montauk_trace.h) and the
# TraceReader record walk, so it builds even when BPF tracing isn't compiled
# into montauk itself.
add_executable(montauk_trace_decode src/tools/trace_decode.cpp src/model/TraceReader.cpp src/util/Log.cpp)
target_include_directories(montauk_trace_decode PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf)
target_compile_options(montauk_trace_decode PRIVATE -Wall -Wextra -Werror -Wshadow)

# ── sublimation CLI ─────────────────────────────────────────────────────────
# The command-line front door to the sort sub-system: pipe a numeric stream in,
# get sort / quantile / select / searchsorted / classify / locate / rand out.
# Output name is `sublimation` (the static lib is libsublimation.a -- no clash).
add_executable(sublimation_cli sublimation/cli.c)
set_target_properties(sublimation_cli PROPERTIES
    OUTPUT_NAME sublimation
    C_STANDARD 23 C_STANDARD_REQUIRED ON)
# montauk's include/ for the shared output sink (util/sink.h); the CLI's data
# output drains through it like the rest of montauk.
target_include_directories(sublimation_cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(sublimation_cli PRIVATE sublimation)

if(MONTAUK_BUILD_TESTS)
  # Lightweight unit tests without external deps
  add_executable(montauk_tests
    tests/test_main.cpp
    tests/test_memory.cpp
    tests/test_cpu.cpp
    tests/test_net.cpp
    tests/test_disk.cpp
    tests/test_gpu_fallback.cpp
    tests/test_gpu_cache.cpp
    tests/test_fdinfo_collector.cpp
    tests/test_snapshot_buffers.cpp
    tests/test_trace_buffers.cpp
    tests/test_producer_basic.cpp
    tests/test_stress.cpp
    tests/test_filters.cpp
    tests/test_alerts.cpp
    tests/test_thermal.cpp
    tests/test_netlink_smoke.cpp
    tests/test_prometheus.cpp
    tests/test_json_snapshot.cpp
    tests/test_logwriter.cpp
    tests/test_security.cpp
    tests/test_gpu_smi_device.cpp
    tests/test_thompson_nfa.cpp
    tests/test_toml_reader.cpp
    tests/test_canvas.cpp
    tests/test_provider_collector.cpp
    tests/test_sink.cpp
  )
  target_include_directories(montauk_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/tests)
  target_link_libraries(montauk_tests PRIVATE montauk_core)
  target_compile_options(montauk_tests PRIVATE -Wall -Wextra -Werror -Wshadow)
  target_compile_definitions(montauk_tests PRIVATE MONTAUK_TESTING=1)

  # The output sink (include/util/sink.h) is a shared C23/C++23 header. The C++
  # front-end is covered above; this target proves the same header compiles and
  # runs as C23 -- the shared-header property the whole unification rests on.
  add_executable(montauk_sink_c_test tests/test_sink_c.c)
  set_target_properties(montauk_sink_c_test PROPERTIES C_STANDARD 23 C_STANDARD_REQUIRED ON)
  target_include_directories(montauk_sink_c_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
  target_compile_options(montauk_sink_c_test PRIVATE -Wall -Wextra -Werror -Wshadow)

  add_executable(montauk_json_test tests/test_json.c)
  set_target_properties(montauk_json_test PROPERTIES C_STANDARD 23 C_STANDARD_REQUIRED ON)
  target_include_directories(montauk_json_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
  target_compile_options(montauk_json_test PRIVATE -Wall -Wextra -Werror -Wshadow)

  # One entry point for the whole suite -- tests/run.py orchestrates the unit
  # (C++ montauk_tests + C23 sink test), gate (Python byte-identical) and trace
  # (root-gated, skipped without root) layers. --no-build because the DEPENDS
  # below already builds the binaries run.py invokes.
  add_custom_target(check
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tests/run.py --no-build
    DEPENDS montauk_tests montauk_sink_c_test montauk_json_test montauk_analyze montauk_trace_decode sublimation_cli)
endif()
