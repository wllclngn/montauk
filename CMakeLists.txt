cmake_minimum_required(VERSION 3.20)
project(montauk VERSION 4.9.0 LANGUAGES CXX)

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

add_library(montauk_core
    src/util/Procfs.cpp
    src/util/Churn.cpp
    src/util/Retro.cpp
    src/util/TimSort.cpp
    src/util/BoyerMoore.cpp
    src/util/ThompsonNFA.cpp
    src/util/NvmlDyn.cpp
    src/ui/Terminal.cpp
    src/ui/Config.cpp
    src/ui/Formatting.cpp
    src/ui/Renderer.cpp
    src/ui/Panels.cpp
    src/ui/ProcessTable.cpp
    src/app/SnapshotBuffers.cpp
    src/app/GpuAttributor.cpp
    src/app/Producer.cpp
    src/app/Security.cpp
    src/app/Alerts.cpp
    src/app/Filter.cpp
    src/app/PrometheusSerializer.cpp
    src/app/LogWriter.cpp
    src/collectors/MemoryCollector.cpp
    src/collectors/GpuCollector.cpp
    src/collectors/FdinfoProcessCollector.cpp
    src/collectors/CpuCollector.cpp
    src/collectors/NetCollector.cpp
    src/collectors/DiskCollector.cpp
    src/collectors/FsCollector.cpp
    src/collectors/ProcessCollector.cpp
    src/collectors/NetlinkProcessCollector.cpp
    src/collectors/ThermalCollector.cpp
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

add_executable(montauk src/main.cpp)
target_link_libraries(montauk PRIVATE montauk_core)
target_compile_options(montauk PRIVATE -Wall -Wextra -Werror -Wshadow)
set_target_properties(montauk PROPERTIES OUTPUT_NAME montauk)


install(TARGETS montauk RUNTIME DESTINATION bin)

# Lightweight on-box process analyzer (no external deps)
add_executable(montauk_analyze src/tools/analyze_proc.cpp)
target_include_directories(montauk_analyze PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(montauk_analyze PRIVATE montauk_core)
target_compile_options(montauk_analyze PRIVATE -Wall -Wextra -Werror -Wshadow)
set_target_properties(montauk_analyze PROPERTIES OUTPUT_NAME montauk_analyze)

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
    tests/test_producer_basic.cpp
    tests/test_stress.cpp
    tests/test_filters.cpp
    tests/test_alerts.cpp
    tests/test_thermal.cpp
    tests/test_netlink_smoke.cpp
    tests/test_timsort.cpp
    tests/test_prometheus.cpp
    tests/test_logwriter.cpp
    tests/test_security.cpp
    tests/test_gpu_smi_device.cpp
    tests/test_thompson_nfa.cpp
    tests/test_toml_reader.cpp
  )
  target_include_directories(montauk_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/tests)
  target_link_libraries(montauk_tests PRIVATE montauk_core)
  target_compile_options(montauk_tests PRIVATE -Wall -Wextra -Werror -Wshadow)
  target_compile_definitions(montauk_tests PRIVATE MONTAUK_TESTING=1)

  add_custom_target(check COMMAND montauk_tests DEPENDS montauk_tests)
endif()
