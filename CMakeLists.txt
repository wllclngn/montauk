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
option(LSM_BUILD_TESTS "Build unit tests" OFF)

add_library(lsm_core
    src/util/Procfs.cpp
    src/util/Retro.cpp
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
    src/collectors/ThermalCollector.cpp
)
target_include_directories(lsm_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(lsm_core PRIVATE -Wall -Wextra -Werror)

# Always attempt NVML (NVIDIA) support by default; if not found, build continues without it.
# Try common locations for NVML headers. On Arch/others, CUDA installs nvml.h under /opt/cuda/include.
find_path(NVML_INCLUDE_DIR nvml.h PATHS /usr/include /usr/local/include /usr/include/nvidia /opt/cuda/include)
find_library(NVML_LIBRARY nvidia-ml PATHS /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64)
if(NVML_INCLUDE_DIR AND NVML_LIBRARY)
  target_compile_definitions(lsm_core PUBLIC LSM_HAVE_NVML=1)
  target_include_directories(lsm_core PUBLIC ${NVML_INCLUDE_DIR})
  target_link_libraries(lsm_core PUBLIC ${NVML_LIBRARY})
  message(STATUS "NVML detected: enabling per-process and device GPU metrics")
else()
  message(STATUS "NVML not found: building without NVML (device VRAM/util via sysfs if available)")
endif()

add_executable(lsm src/main.cpp)
target_link_libraries(lsm PRIVATE lsm_core)
target_compile_options(lsm PRIVATE -Wall -Wextra -Werror)


install(TARGETS lsm RUNTIME DESTINATION bin)

# Lightweight on-box process analyzer (no external deps)
add_executable(lsm_analyze src/tools/analyze_proc.cpp)
target_include_directories(lsm_analyze PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(lsm_analyze PRIVATE lsm_core)
target_compile_options(lsm_analyze PRIVATE -Wall -Wextra -Werror)

if(LSM_BUILD_TESTS)
  # Lightweight unit tests without external deps
  add_executable(lsm_tests
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
  target_include_directories(lsm_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/tests)
  target_link_libraries(lsm_tests PRIVATE lsm_core)
  target_compile_options(lsm_tests PRIVATE -Wall -Wextra -Werror)
  target_compile_definitions(lsm_tests PRIVATE LSM_TESTING=1)

  add_custom_target(check COMMAND lsm_tests DEPENDS lsm_tests)
endif()
