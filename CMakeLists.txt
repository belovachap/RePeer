cmake_minimum_required(VERSION 3.22)
project(RePeer VERSION 13.37 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Tell CMake to default to static for internal submodules/dependencies.
set(BUILD_SHARED_LIBS OFF)

# Place binary executables in the build/bin directory.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# The C/C++ assert() macro is disabled when NDEBUG is defined.
# These lines allow runtime assertions to remain active even when compiling a high-performance Release build.
string(REPLACE "-DNDEBUG" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
string(REPLACE "-DNDEBUG" "" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")

# Configuration file
configure_file(
  "${CMAKE_SOURCE_DIR}/src/config/bitcoin-config.h.in"
  "${CMAKE_BINARY_DIR}/src/config/bitcoin-config.h"
)

# External dependencies

find_package(PkgConfig REQUIRED)
pkg_check_modules(CRYPTO REQUIRED libcrypto)
pkg_check_modules(SSL REQUIRED libssl)
find_package(Boost CONFIG REQUIRED)
find_package(Qt6 REQUIRED COMPONENTS Core DBus Gui Widgets Network)
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)

# Submodules

## crc32c
set(CRC32C_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CRC32C_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(CRC32C_USE_GLOG OFF CACHE BOOL "" FORCE)
set(CRC32C_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory(src/crc32c)

## leveldb
set(LEVELDB_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LEVELDB_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(LEVELDB_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory(src/leveldb)
### leveldb turns off RTTI by default and that breaks our build, so turn it back on.
target_compile_options(leveldb PRIVATE -frtti)

## minisketch
set(MINISKETCH_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(src/minisketch)

## secp256k1
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE BOOL "" FORCE)
add_subdirectory(src/secp256k1)

## univalue
add_subdirectory(src/univalue)

# repeerd executable

set(REPEERD_SOURCE_FILES
  src/bitcoind.cpp
  src/chainparamsbase.cpp
  src/chainparamsbase.h
  src/clientversion.cpp
  src/clientversion.h
  src/coins.cpp
  src/coins.h
  src/init.cpp
  src/init.h
  src/key.cpp
  src/key.h
  src/key_io.cpp
  src/key_io.h
  src/logging.cpp
  src/logging.h
  src/pubkey.cpp
  src/pubkey.h
  src/random.cpp
  src/random.h
  src/shutdown.cpp
  src/shutdown.h
  src/uint256.cpp
  src/uint256.h

  src/config/bitcoin-config.h

  src/crypto/sha256.cpp
  src/crypto/sha256.h
  src/crypto/siphash.cpp
  src/crypto/siphash.h

  src/init/bitcoind.cpp

  src/interfaces/chain.h
  src/interfaces/node.h
  src/interfaces/wallet.h

  src/node/interfaces.cpp

  src/primitives/transaction.cpp
  src/primitives/transaction.h

  src/script/descriptor.cpp
  src/script/descriptor.h
  src/script/signingprovider.cpp
  src/script/signingprovider.h
  src/script/standard.cpp
  src/script/standard.h

  src/support/cleanse.cpp
  src/support/cleanse.h
  src/support/lockedpool.cpp
  src/support/lockedpool.h

  src/util/bip32.cpp
  src/util/bip32.h
  src/util/check.cpp
  src/util/check.h
  src/util/fs.cpp
  src/util/fs.h
  src/util/hasher.cpp
  src/util/hasher.h
  src/util/strencodings.cpp
  src/util/strencodings.h
  src/util/system.cpp
  src/util/system.h
  src/util/time.cpp
  src/util/time.h
  src/util/threadnames.cpp
  src/util/threadnames.h
  src/util/tokenpipe.cpp
  src/util/tokenpipe.h

  src/wallet/db.cpp
  src/wallet/db.h
  src/wallet/interfaces.cpp
  src/wallet/scriptpubkeyman.cpp
  src/wallet/scriptpubkeyman.h
  src/wallet/sqlite.cpp
  src/wallet/sqlite.h
  src/wallet/wallet.cpp
  src/wallet/wallet.h
  src/wallet/walletdb.cpp
  src/wallet/walletdb.h
  src/wallet/walletutil.cpp
  src/wallet/walletutil.h
)

add_executable(repeerd ${REPEERD_SOURCE_FILES})
target_include_directories(repeerd PUBLIC ${CMAKE_SOURCE_DIR}/src ${CMAKE_BINARY_DIR}/src)
target_link_libraries(repeerd PUBLIC crypto leveldb secp256k1 univalue)