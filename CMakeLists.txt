cmake_minimum_required(VERSION 3.20)
project(rusttop_cpp LANGUAGES CXX)

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

add_library(montauk_core
    src/util/Procfs.cpp
    src/util/Churn.cpp
    src/util/Retro.cpp
    src/util/AdaptiveSort.cpp
    src/app/SnapshotBuffers.cpp
    src/app/GpuAttributor.cpp
    src/app/Producer.cpp
    src/app/Alerts.cpp
    src/app/Filter.cpp
    src/collectors/MemoryCollector.cpp
    src/collectors/GpuCollector.cpp
    src/collectors/FdinfoProcessCollector.cpp
    src/collectors/CpuCollector.cpp
    src/collectors/NetCollector.cpp
    src/collectors/DiskCollector.cpp
    src/collectors/ProcessCollector.cpp
    src/collectors/NetlinkProcessCollector.cpp
    src/collectors/ThermalCollector.cpp
)
target_include_directories(montauk_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(montauk_core PRIVATE -Wall -Wextra -Werror)

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

add_executable(montauk src/main.cpp)
target_link_libraries(montauk PRIVATE montauk_core)
target_compile_options(montauk PRIVATE -Wall -Wextra -Werror)
set_target_properties(montauk PROPERTIES OUTPUT_NAME montauk)


install(TARGETS montauk RUNTIME DESTINATION bin)

# Lightweight on-box process analyzer (no external deps)
add_executable(montauk_analyze src/tools/analyze_proc.cpp)
target_include_directories(montauk_analyze PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(montauk_analyze PRIVATE montauk_core)
target_compile_options(montauk_analyze PRIVATE -Wall -Wextra -Werror)
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
  )
  target_include_directories(montauk_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/tests)
  target_link_libraries(montauk_tests PRIVATE montauk_core)
  target_compile_options(montauk_tests PRIVATE -Wall -Wextra -Werror)
  target_compile_definitions(montauk_tests PRIVATE MONTAUK_TESTING=1)

  add_custom_target(check COMMAND montauk_tests DEPENDS montauk_tests)
endif()
