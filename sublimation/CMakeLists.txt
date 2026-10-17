# sublimation -- montauk's adaptive sort, search and learn core.
#
# THE TARGET IS DEFINED ONCE, HERE, because it is consumed from more than one
# tree. montauk and OUROBOROS both build these sources in-tree, and for as long
# as the recipe lived inline in montauk's CMakeLists.txt every consumer owned a
# copy of it. Both build defects found in OUROBOROS on 2026-08-10 were that copy
# going stale: its source list had frozen at 16 of 21 files (a pre-radix-split
# snapshot), and it still carried the -O2-after--O3 flag-ordering bug montauk had
# ALREADY found, fixed and written a comment about. A fix that lives next to a
# copy does not reach the copy. Add a file here and it reaches every consumer on
# the next pull instead of on the next manual audit.
#
# Consume it with add_subdirectory(<path>/sublimation); link `sublimation`.
# No system install, no find_package, no fetch: The code lives here. It also
# configures alone (cmake -S sublimation -B ...), and needs nothing outside
# this directory to build, test or run its CLI.
#
# The CLI and the test suite are OPT-IN, so a consumer that only links the
# library builds exactly what it did before: SUBLIMATION_BUILD_CLI builds the
# `sublimation` binary and SUBLIMATION_BUILD_TESTS the suite, each landing in
# the top-level build directory. Both default ON when this is the top-level
# project.
cmake_minimum_required(VERSION 3.20)
project(sublimation LANGUAGES C)
set(SUB_TOP_LEVEL OFF)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(SUB_TOP_LEVEL ON)
endif()
option(SUBLIMATION_BUILD_CLI "Build the sublimation command-line tool" ${SUB_TOP_LEVEL})
option(SUBLIMATION_BUILD_TESTS "Build sublimation's test suite" ${SUB_TOP_LEVEL})

add_library(sublimation STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/classify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/merge.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kmerge.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pack.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radix.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/randomness.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/search.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/select.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/small.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sort.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/spectral_kernel.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/spectral_typed.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/stats.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/text/diff.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/text/fmt_double.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/text/match.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/parallel/wsdeque.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/parallel/dfspool.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/parallel/radix_par.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/strings/kmerge_strings.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/strings/msd_radix.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/strings/sort_strings.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/learn/detect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/learn/signal.c
)

set_target_properties(sublimation PROPERTIES
    C_STANDARD 23
    C_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON)

# Public headers on the include path for consumers; src/ is private for the
# implementation's own internal includes.
target_include_directories(sublimation
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/src/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# NO OPTIMIZATION LEVEL HERE: the build type's own -O stands. This is the whole
# of the second OUROBOROS defect -- an -O2 in this list came AFTER Release's -O3
# on the command line and silently won, leaving the hottest code in the tree
# built at the lowest optimization level by flag-ordering accident.
#
# The warning wall is deliberately NON-FATAL (no -Werror): the library carries
# its own C23 flags, so a new toolchain's fresh warnings must degrade loudly
# rather than break every consumer at once.
target_compile_options(sublimation PRIVATE
    -march=native -fvisibility=hidden -Wall -Wextra
    -fstack-protector-strong -fstack-clash-protection -fcf-protection)

target_link_libraries(sublimation PUBLIC pthread m)

if(NOT SUBLIMATION_BUILD_CLI AND NOT SUBLIMATION_BUILD_TESTS)
  return()
endif()

# THE CLI AND THE TESTS CARRY THE FATAL WALL the library deliberately does not:
# They are first-party, hot-edited code that no outside consumer compiles, so a
# new warning there is a defect to fix rather than a consumer to protect.
# -Warray-bounds=2 and -Wrestrict are GCC spellings that clang rejects.
add_library(sublimation_warnings INTERFACE)
target_compile_options(sublimation_warnings INTERFACE
    -Wall -Wextra -Werror -Wshadow -Wformat-security
    $<$<COMPILE_LANG_AND_ID:C,GNU>:-Warray-bounds=2>
    $<$<COMPILE_LANG_AND_ID:C,GNU>:-Wrestrict>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU>:-Warray-bounds=2>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU>:-Wrestrict>)

# Link-time hardening for the binaries (the library carries the codegen set
# above). _FORTIFY_SOURCE needs -O1+, so it is Release-gated; -U guards a
# toolchain that predefines it.
add_library(sublimation_hardening INTERFACE)
target_compile_options(sublimation_hardening INTERFACE
    -fstack-protector-strong -fstack-clash-protection -fcf-protection
    $<$<CONFIG:Release>:-U_FORTIFY_SOURCE>
    $<$<CONFIG:Release>:-D_FORTIFY_SOURCE=3>)
target_link_options(sublimation_hardening INTERFACE
    -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)

if(SUBLIMATION_BUILD_CLI)
  # The front door: Pipe a stream in, get one primitive's answer out. Named
  # `sublimation` beside libsublimation.a, which is why a consumer gives this
  # directory an explicit binary dir of its own.
  add_executable(sublimation_cli ${CMAKE_CURRENT_SOURCE_DIR}/cli.c)
  set_target_properties(sublimation_cli PROPERTIES
      OUTPUT_NAME sublimation
      C_STANDARD 23 C_STANDARD_REQUIRED ON
      RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
  target_link_libraries(sublimation_cli PRIVATE
      sublimation_warnings sublimation_hardening sublimation)
endif()

if(SUBLIMATION_BUILD_TESTS)
  enable_language(CXX)
  set(SUB_INC ${CMAKE_CURRENT_SOURCE_DIR}/src/include)
  set(SUB_TESTS ${CMAKE_CURRENT_SOURCE_DIR}/tests)

  # Seeded differential fuzzer for the sort core: Multiset preservation and
  # order against std::sort across every shipped type, heavy on the few-unique,
  # NaN and signed-zero region a value-corruption bug once lived in.
  add_executable(sublimation_fuzz_diff ${SUB_TESTS}/fuzz_sort_diff.cpp)
  # The double formatter against std::to_chars, byte for byte.
  add_executable(test_fmt_double ${SUB_TESTS}/test_fmt_double.cpp)
  foreach(t sublimation_fuzz_diff test_fmt_double)
    set_target_properties(${t} PROPERTIES
        CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    target_link_libraries(${t} PRIVATE sublimation_warnings sublimation)
  endforeach()

  # The sort, search and core C tests, each a single .c linking the library,
  # plus the sink and the JSON writer, which are header-only and proven as C23
  # here.
  foreach(t
      test_wsdeque test_dfspool test_radix test_radix_par test_smerge_par test_pack
      test_kmerge
      test_basic test_tier1 test_tier2 test_tier4 test_tier5
      test_adversarial test_adversarial_types test_bentley_mcilroy test_antiqsort
      test_types test_sorted_perturbed test_zipfian test_saw_mixed
      test_strings test_randomness test_profile_contract test_search test_affinity
      test_diff test_sink test_json)
    add_executable(${t} ${SUB_TESTS}/${t}.c)
    set_target_properties(${t} PROPERTIES
        C_STANDARD 23 C_STANDARD_REQUIRED ON
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    target_include_directories(${t} PRIVATE ${SUB_INC})
    target_link_libraries(${t} PRIVATE sublimation)
  endforeach()
  target_link_libraries(test_sink PRIVATE sublimation_warnings)
  target_link_libraries(test_json PRIVATE sublimation_warnings)

  # The sort core under AddressSanitizer and UBSan. They COMPILE the library
  # sources directly so the sanitizer instruments sublimation itself, not just
  # the test. test_types (all six types, every disorder class) and test_tier5
  # (the parallel path and spectral allocations) are the broadest-coverage
  # cores; test_diff joins them because diff.c is the one place doing manual
  # allocation and index arithmetic over a computed path.
  file(GLOB_RECURSE SUB_LIB_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)
  foreach(t test_types test_tier5 test_diff)
    add_executable(${t}_asan ${SUB_TESTS}/${t}.c ${SUB_LIB_SRCS})
    set_target_properties(${t}_asan PROPERTIES
        C_STANDARD 23 C_STANDARD_REQUIRED ON
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    target_include_directories(${t}_asan PRIVATE ${SUB_INC} ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_options(${t}_asan PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -pthread)
    target_link_options(${t}_asan PRIVATE -fsanitize=address,undefined -pthread)
    target_link_libraries(${t}_asan PRIVATE m)
  endforeach()

  # The work-stealing engine under ThreadSanitizer, compiling the engine sources
  # directly so TSan sees the deque and pool atomics.
  set(PAR ${CMAKE_CURRENT_SOURCE_DIR}/src/parallel)
  add_executable(test_wsdeque_tsan ${SUB_TESTS}/test_wsdeque.c ${PAR}/wsdeque.c)
  add_executable(test_dfspool_tsan ${SUB_TESTS}/test_dfspool.c ${PAR}/wsdeque.c ${PAR}/dfspool.c)
  add_executable(test_radix_par_tsan ${SUB_TESTS}/test_radix_par.c
      ${PAR}/wsdeque.c ${PAR}/dfspool.c ${PAR}/radix_par.c)
  foreach(t test_wsdeque_tsan test_dfspool_tsan test_radix_par_tsan)
    set_target_properties(${t} PROPERTIES
        C_STANDARD 23 C_STANDARD_REQUIRED ON
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    target_include_directories(${t} PRIVATE ${SUB_INC})
    target_compile_options(${t} PRIVATE -fsanitize=thread -g -O1 -pthread)
    target_link_options(${t} PRIVATE -fsanitize=thread -pthread)
  endforeach()
endif()
