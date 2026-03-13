# deps/yara/CMakeLists.txt
# Build libyara as a static library from YARA v4.5.2 source.
#
# This is a custom CMake build for libyara. The official YARA project uses
# autotools (Linux) and Visual Studio solution files (Windows). We build
# from source here for consistent /MT static CRT linking and to avoid
# NuGet/vcpkg dependencies.
#
# Modules enabled: PE, math, time, console, string, elf, tests (base set)
# Modules disabled: cuckoo, hash, dotnet, magic, macho, dex (require
#   OpenSSL/Jansson or aren't needed)
#
# P8-T1: YARA Scanner Integration.

cmake_minimum_required(VERSION 3.20)

# Path to cloned YARA source (sibling to claude-edr)
set(YARA_SRC "C:/Users/derek/Desktop/Projects/yara-build")

# ── Collect source files ────────────────────────────────────────────────────

# Core libyara sources
file(GLOB LIBYARA_CORE_SRCS "${YARA_SRC}/libyara/*.c")

# Platform-specific process iterator (Windows)
set(LIBYARA_PROC_SRCS "${YARA_SRC}/libyara/proc/windows.c")

# TLSH (Trend Micro Locality Sensitive Hashing) — required by ELF module
set(LIBYARA_TLSH_SRCS
    ${YARA_SRC}/libyara/tlshc/tlsh.c
    ${YARA_SRC}/libyara/tlshc/tlsh_impl.c
    ${YARA_SRC}/libyara/tlshc/tlsh_util.c
)

# Module sources (only the ones in module_list without #ifdef guards)
set(LIBYARA_MODULE_SRCS
    ${YARA_SRC}/libyara/modules/pe/pe.c
    ${YARA_SRC}/libyara/modules/pe/pe_utils.c
    ${YARA_SRC}/libyara/modules/elf/elf.c
    ${YARA_SRC}/libyara/modules/math/math.c
    ${YARA_SRC}/libyara/modules/time/time.c
    ${YARA_SRC}/libyara/modules/console/console.c
    ${YARA_SRC}/libyara/modules/string/string.c
    ${YARA_SRC}/libyara/modules/tests/tests.c
)

# ── Static library target ───────────────────────────────────────────────────

add_library(libyara STATIC
    ${LIBYARA_CORE_SRCS}
    ${LIBYARA_PROC_SRCS}
    ${LIBYARA_TLSH_SRCS}
    ${LIBYARA_MODULE_SRCS}
)

target_include_directories(libyara PRIVATE
    ${YARA_SRC}/libyara
    ${YARA_SRC}/libyara/include
    ${YARA_SRC}/libyara/include/tlshc    # TLSH headers
    ${YARA_SRC}                          # For config.h if present
)

# Public headers for consumers
target_include_directories(libyara PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include  # deps/yara/include (copied headers)
)

target_compile_definitions(libyara PRIVATE
    _CRT_SECURE_NO_WARNINGS
    USE_WINDOWS_PROC                     # Windows process memory iteration
    YR_BUILDING_STATIC_LIB               # Building as static .lib
    BUCKETS_128                           # Hash table bucket count
    CHECKSUM_1B                           # 1-byte checksum
    HAVE_WINCRYPT_H                       # Use Windows CryptoAPI for PE hashing
    # NOT defined: HAVE_LIBCRYPTO, HASH_MODULE, CUCKOO_MODULE, DOTNET_MODULE,
    #              MAGIC_MODULE, MACHO_MODULE, DEX_MODULE, PB_TESTS_MODULE
)

# Suppress YARA build warnings (third-party code)
if(MSVC)
    target_compile_options(libyara PRIVATE
        /W0                               # Suppress all warnings for third-party code
        /wd4996                           # Deprecated CRT functions
    )
endif()

# Static CRT (/MT for Release, /MTd for Debug)
set_target_properties(libyara PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

# System libraries needed by libyara on Windows
target_link_libraries(libyara PUBLIC
    crypt32.lib                           # CryptoAPI (PE hash via wincrypt)
)

message(STATUS "libyara: Building from source (${YARA_SRC})")
