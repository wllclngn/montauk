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
# No system install, no find_package, no fetch: the code lives here.

add_library(sublimation STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/classify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/merge.c
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
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tally.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/text/match.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/parallel/wsdeque.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/parallel/dfspool.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/parallel/radix_par.c
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
