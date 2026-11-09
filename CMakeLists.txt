cmake_minimum_required(VERSION 3.22)
project(RePeer VERSION 13.34 LANGUAGES CXX C)

string(REPLACE "-DNDEBUG" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
string(REPLACE "-DNDEBUG" "" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --- Feature options (replaces AC_ARG_ENABLE / AC_ARG_WITH) ---
option(ENABLE_MULTIPROCESS "Enable multiprocess" OFF)
option(ENABLE_ASM "Enable assembly routines" ON)
option(ENABLE_SSE42 "Enable SSE4.2" OFF)
option(ENABLE_SSE41 "Enable SSE4.1" OFF)
option(ENABLE_AVX2 "Enable AVX2" OFF)
option(ENABLE_X86_SHANI "Enable x86 SHA-NI" OFF)
option(ENABLE_ARM_CRC "Enable ARM CRC" OFF)
option(ENABLE_ARM_SHANI "Enable ARM SHA-NI" OFF)
option(ENABLE_CLMUL "Enable CLMUL" OFF)
option(ENABLE_CLZ "Enable CLZ" OFF)
option(ENABLE_SYSCALL_SANDBOX "Enable seccomp sandbox" OFF)
option(ENABLE_TRACING "Enable USDT tracing" OFF)
option(USE_QRCODE "Use QR code support" OFF)
option(ENABLE_DEBUG "Debug build" OFF)
option(ENABLE_LTO "Link-time optimization" OFF)
option(ENABLE_GPROF "gprof profiling" OFF)
option(ENABLE_HARDENING "Security hardening" ON)
option(ENABLE_REDUCE_EXPORTS "Reduce exported symbols" OFF)
option(ENABLE_FUZZ_BINARY "Build fuzz binary" ON)
option(BUILD_BITCOIN_KERNEL_LIB "Build kernel library" OFF)
option(BUILD_BITCOIN_GUI "Build GUI" OFF)
option(BUILD_BITCOIN_NODE "Build node" OFF)

# --- Compiler checks (replaces AX_CHECK_COMPILE_FLAG) ---
include(CheckCXXCompilerFlag)
include(CheckCXXSourceCompiles)
include(CheckCXXSourceRuns)
include(CheckIncludeFile)
include(CheckFunctionExists)
include(CheckCXXSymbolExists)
include(CheckTypeSize)
include(GNUInstallDirs)

# Warnings
check_cxx_compiler_flag("-Wall" COMPILER_SUPPORTS_WALL)
check_cxx_compiler_flag("-Wextra" COMPILER_SUPPORTS_WEXTRA)
check_cxx_compiler_flag("-Werror" COMPILER_SUPPORTS_WERROR)
check_cxx_compiler_flag("-fPIC" COMPILER_SUPPORTS_FPIC)
check_cxx_compiler_flag("-fPIE -pie" COMPILER_SUPPORTS_PIE)
check_cxx_compiler_flag("-fstack-protector-all" COMPILER_SUPPORTS_STACK_PROTECTOR)
check_cxx_compiler_flag("-fstack-clash-protection" COMPILER_SUPPORTS_STACK_CLASH)
check_cxx_compiler_flag("-fcf-protection=full" COMPILER_SUPPORTS_CFI)
check_cxx_compiler_flag("-fno-extended-identifiers" COMPILER_SUPPORTS_NO_EXT_ID)
check_cxx_compiler_flag("-fstack-reuse=none" COMPILER_SUPPORTS_STACK_REUSE)
check_cxx_compiler_flag("-flto" COMPILER_SUPPORTS_LTO)

# Debug flags
if(ENABLE_DEBUG)
  check_cxx_compiler_flag("-O0" COMPILER_SUPPORTS_O0)
  check_cxx_compiler_flag("-g3" COMPILER_SUPPORTS_G3)
  check_cxx_compiler_flag("-ftrapv" COMPILER_SUPPORTS_TRAPV)
endif()

# --- Endianness (replaces AC_C_BIGENDIAN) ---
include(TestBigEndian)
test_big_endian(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
  set(WORDS_BIGENDIAN ON)
endif()

# --- Platform checks (replaces AC_CHECK_DECLS / AC_CHECK_FUNCS) ---
check_include_file("endian.h" HAVE_ENDIAN_H)
check_include_file("sys/endian.h" HAVE_SYS_ENDIAN_H)
check_include_file("byteswap.h" HAVE_BYTESWAP_H)
check_include_file("sys/select.h" HAVE_SYS_SELECT_H)
check_include_file("sys/prctl.h" HAVE_SYS_PRCTL_H)
check_include_file("sys/sysctl.h" HAVE_SYS_SYSCTL_H)

check_cxx_symbol_exists(bswap_16 "byteswap.h" HAVE_DECL_BSWAP_16)
check_cxx_symbol_exists(bswap_32 "byteswap.h" HAVE_DECL_BSWAP_32)
check_cxx_symbol_exists(bswap_64 "byteswap.h" HAVE_DECL_BSWAP_64)
check_cxx_symbol_exists(le16toh "endian.h" HAVE_DECL_LE16TOH)
# ... etc for all endian functions

check_cxx_symbol_exists(fdatasync "unistd.h" HAVE_FDATASYNC)
check_cxx_symbol_exists(posix_fallocate "fcntl.h" HAVE_POSIX_FALLOCATE)
check_cxx_symbol_exists(getentropy "unistd.h" HAVE_GETENTROPY)
check_cxx_symbol_exists(mallopt "malloc.h" HAVE_MALLOPT)
check_cxx_symbol_exists(malloc_info "malloc.h" HAVE_MALLOC_INFO)
check_cxx_symbol_exists(timingsafe_bcmp "string.h" HAVE_TIMINGSAFE_BCMP)

# __builtin_clzl / clzll
check_cxx_source_compiles("
  int main() { (void)__builtin_clzl(0); return 0; }
" HAVE_BUILTIN_CLZL)
check_cxx_source_compiles("
  int main() { (void)__builtin_clzll(0); return 0; }
" HAVE_BUILTIN_CLZLL)

# __builtin_prefetch / _mm_prefetch
check_cxx_source_compiles("
  int main() { char d=0; __builtin_prefetch(&d,0,0); return 0; }
" HAVE_BUILTIN_PREFETCH)
check_cxx_source_compiles("
  #include <xmmintrin.h>
  int main() { char d=0; _mm_prefetch(&d, _MM_HINT_NTA); return 0; }
" HAVE_MM_PREFETCH)

# thread_local
check_cxx_source_compiles("
  #include <thread>
  static thread_local int foo = 0;
  int main(){ std::thread([](){ foo++; }).detach(); return foo; }
" HAVE_THREAD_LOCAL)

# visibility attribute
check_cxx_source_compiles("
  int foo(void) __attribute__((visibility(\"default\")));
  int main(){}
" HAVE_DEFAULT_VISIBILITY_ATTRIBUTE)

# --- External dependencies (replaces PKG_CHECK_MODULES) ---
find_package(PkgConfig REQUIRED)
pkg_check_modules(SSL REQUIRED libssl)
pkg_check_modules(CRYPTO REQUIRED libcrypto)

pkg_check_modules(QRENCODE libqrencode)
pkg_check_modules(LIBMULTIPROCESS libmultiprocess)

# SQLite3
find_package(SQLite3 REQUIRED)

# Threads
find_package(Threads REQUIRED)

# Boost
find_package(Boost CONFIG REQUIRED)

# Qt5 (replaces BITCOIN_QT_CONFIGURE)
find_package(Qt5 5.11.3 REQUIRED COMPONENTS Core Gui Widgets Network)
find_package(Qt5LinguistTools REQUIRED)
# D-Bus
find_package(Qt5DBus REQUIRED)

# --- Generate config header (replaces AC_CONFIG_HEADERS) ---
configure_file(
  "${CMAKE_SOURCE_DIR}/src/config/bitcoin-config.h.in"
  "${CMAKE_BINARY_DIR}/src/config/bitcoin-config.h"
)

# --- Subdirectories ---
add_subdirectory(src)