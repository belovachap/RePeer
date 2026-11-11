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
  src/addrdb.cpp
  src/addrdb.h
  src/addrman.cpp
  src/addrman.h
  src/arith_uint256.cpp
  src/arith_uint256.h
  src/banman.cpp
  src/banman.h
  src/base58.cpp
  src/base58.h
  src/bech32.cpp
  src/bech32.h
  src/bitcoind.cpp
  src/blockencodings.cpp
  src/blockencodings.h
  src/blockfilter.cpp
  src/blockfilter.h
  src/chain.cpp
  src/chain.h
  src/chainparams.cpp
  src/chainparams.h
  src/chainparamsbase.cpp
  src/chainparamsbase.h
  src/clientversion.cpp
  src/clientversion.h
  src/coins.cpp
  src/coins.h
  src/compressor.cpp
  src/compressor.h
  src/dbwrapper.cpp
  src/dbwrapper.h
  src/deploymentinfo.cpp
  src/deploymentinfo.h
  src/flatfile.cpp
  src/flatfile.h
  src/hash.cpp
  src/hash.h
  src/headerssync.cpp
  src/headerssync.h
  src/i2p.cpp
  src/i2p.h
  src/init.cpp
  src/init.h
  src/kernel.cpp
  src/kernel.h
  src/key.cpp
  src/key.h
  src/key_io.cpp
  src/key_io.h
  src/logging.cpp
  src/logging.h
  src/merkleblock.cpp
  src/merkleblock.h
  src/net_permissions.cpp
  src/net_permissions.h
  src/net_processing.cpp
  src/net_processing.h
  src/net_types.cpp
  src/net_types.h
  src/net.cpp
  src/net.h
  src/netaddress.cpp
  src/netaddress.h
  src/netbase.cpp
  src/netbase.h
  src/netgroup.cpp
  src/netgroup.h
  src/noui.cpp
  src/noui.h
  src/outputtype.cpp
  src/outputtype.h
  src/pow.cpp
  src/pow.h
  src/protocol.cpp
  src/protocol.h
  src/psbt.cpp
  src/psbt.h
  src/pubkey.cpp
  src/pubkey.h
  src/random.cpp
  src/random.h
  src/randomenv.cpp
  src/randomenv.h
  src/scheduler.cpp
  src/scheduler.h
  src/shutdown.cpp
  src/shutdown.h
  src/signet.cpp
  src/signet.h
  src/timedata.cpp
  src/timedata.h
  src/txdb.cpp
  src/txdb.h
  src/txmempool.cpp
  src/txmempool.h
  src/txorphanage.cpp
  src/txorphanage.h
  src/txrequest.cpp
  src/txrequest.h
  src/uint256.cpp
  src/uint256.h
  src/validation.cpp
  src/validation.h
  src/validationinterface.cpp
  src/validationinterface.h
  src/warnings.cpp
  src/warnings.h

  src/config/bitcoin-config.h

  src/consensus/merkle.cpp
  src/consensus/merkle.h
  src/consensus/tx_check.cpp
  src/consensus/tx_check.h
  src/consensus/tx_verify.cpp
  src/consensus/tx_verify.h

  src/common/bloom.cpp
  src/common/bloom.h
  src/common/init.cpp
  src/common/init.h
  src/common/interfaces.cpp

  src/crypto/aes.cpp
  src/crypto/aes.h
  src/crypto/chacha20.cpp
  src/crypto/chacha20.h
  src/crypto/hmac_sha512.cpp
  src/crypto/hmac_sha512.h
  src/crypto/muhash.cpp
  src/crypto/muhash.h
  src/crypto/ripemd160.cpp
  src/crypto/ripemd160.h
  src/crypto/sha1.cpp
  src/crypto/sha1.h
  src/crypto/sha256.cpp
  src/crypto/sha256.h
  src/crypto/sha512.cpp
  src/crypto/sha512.h
  src/crypto/siphash.cpp
  src/crypto/siphash.h

  src/index/base.cpp
  src/index/base.h
  src/index/blockfilterindex.cpp
  src/index/blockfilterindex.h
  src/index/coinstatsindex.cpp
  src/index/coinstatsindex.h
  src/index/txindex.cpp
  src/index/txindex.h

  src/init/bitcoind.cpp
  src/init/common.cpp
  src/init/common.h

  src/interfaces/chain.h
  src/interfaces/handler.h
  src/interfaces/node.h
  src/interfaces/wallet.h

  src/kernel/chain.cpp
  src/kernel/chain.h
  src/kernel/chainparams.cpp
  src/kernel/chainparams.h
  src/kernel/checks.cpp
  src/kernel/checks.h
  src/kernel/coinstats.cpp
  src/kernel/coinstats.h
  src/kernel/context.cpp
  src/kernel/context.h
  src/kernel/cs_main.cpp
  src/kernel/cs_main.h
  src/kernel/mempool_persist.cpp
  src/kernel/mempool_persist.h

  src/node/blockmanager_args.cpp
  src/node/blockmanager_args.h
  src/node/blockstorage.cpp
  src/node/blockstorage.h
  src/node/caches.cpp
  src/node/caches.h
  src/node/chainstate.cpp
  src/node/chainstate.h
  src/node/chainstatemanager_args.cpp
  src/node/chainstatemanager_args.h
  src/node/coin.cpp
  src/node/coin.h
  src/node/coins_view_args.cpp
  src/node/coins_view_args.h
  src/node/connection_types.cpp
  src/node/connection_types.h
  src/node/context.cpp
  src/node/context.h
  src/node/database_args.cpp
  src/node/database_args.h
  src/node/eviction.cpp
  src/node/eviction.h
  src/node/interface_ui.cpp
  src/node/interface_ui.h
  src/node/interfaces.cpp
  src/node/mempool_args.cpp
  src/node/mempool_args.h
  src/node/mempool_persist_args.cpp
  src/node/mempool_persist_args.h
  src/node/miner.cpp
  src/node/miner.h
  src/node/transaction.cpp
  src/node/transaction.h
  src/node/txreconciliation.cpp
  src/node/txreconciliation.h
  src/node/utxo_snapshot.cpp
  src/node/utxo_snapshot.h
  src/node/validation_cache_args.cpp
  src/node/validation_cache_args.h

  src/policy/packages.cpp
  src/policy/packages.h
  src/policy/policy.cpp
  src/policy/policy.h
  src/policy/settings.cpp
  src/policy/settings.h

  src/primitives/block.cpp
  src/primitives/block.h
  src/primitives/transaction.cpp
  src/primitives/transaction.h

  src/script/descriptor.cpp
  src/script/descriptor.h
  src/script/interpreter.cpp
  src/script/interpreter.h
  src/script/miniscript.cpp
  src/script/miniscript.h
  src/script/script.cpp
  src/script/script.h
  src/script/script_error.cpp
  src/script/script_error.h
  src/script/sigcache.cpp
  src/script/sigcache.h
  src/script/sign.cpp
  src/script/sign.h
  src/script/signingprovider.cpp
  src/script/signingprovider.h
  src/script/standard.cpp
  src/script/standard.h

  src/support/cleanse.cpp
  src/support/cleanse.h
  src/support/lockedpool.cpp
  src/support/lockedpool.h

  src/util/asmap.cpp
  src/util/asmap.h
  src/util/bip32.cpp
  src/util/bip32.h
  src/util/bytevectorhash.cpp
  src/util/bytevectorhash.h
  src/util/check.cpp
  src/util/check.h
  src/util/error.cpp
  src/util/error.h
  src/util/exception.cpp
  src/util/exception.h
  src/util/fs.cpp
  src/util/fs.h
  src/util/fs_helpers.cpp
  src/util/fs_helpers.h
  src/util/getuniquepath.cpp
  src/util/getuniquepath.h
  src/util/hasher.cpp
  src/util/hasher.h
  src/util/message.cpp
  src/util/message.h
  src/util/moneystr.cpp
  src/util/moneystr.h
  src/util/readwritefile.cpp
  src/util/readwritefile.h
  src/util/settings.cpp
  src/util/settings.h
  src/util/sock.cpp
  src/util/sock.h
  src/util/spanparsing.cpp
  src/util/spanparsing.h
  src/util/strencodings.cpp
  src/util/strencodings.h
  src/util/string.cpp
  src/util/string.h
  src/util/syscall_sandbox.cpp
  src/util/syscall_sandbox.h
  src/util/syserror.cpp
  src/util/syserror.h
  src/util/system.cpp
  src/util/system.h
  src/util/thread.cpp
  src/util/thread.h
  src/util/threadinterrupt.cpp
  src/util/threadinterrupt.h
  src/util/time.cpp
  src/util/time.h
  src/util/threadnames.cpp
  src/util/threadnames.h
  src/util/tokenpipe.cpp
  src/util/tokenpipe.h

  src/wallet/coincontrol.cpp
  src/wallet/coincontrol.h
  src/wallet/coinselection.cpp
  src/wallet/coinselection.h
  src/wallet/context.cpp
  src/wallet/context.h
  src/wallet/crypter.cpp
  src/wallet/crypter.h
  src/wallet/db.cpp
  src/wallet/db.h
  src/wallet/init.cpp
  src/wallet/interfaces.cpp
  src/wallet/load.cpp
  src/wallet/load.h
  src/wallet/receive.cpp
  src/wallet/receive.h
  src/wallet/scriptpubkeyman.cpp
  src/wallet/scriptpubkeyman.h
  src/wallet/spend.cpp
  src/wallet/spend.h
  src/wallet/sqlite.cpp
  src/wallet/sqlite.h
  src/wallet/transaction.cpp
  src/wallet/transaction.h
  src/wallet/wallet.cpp
  src/wallet/wallet.h
  src/wallet/walletdb.cpp
  src/wallet/walletdb.h
  src/wallet/walletutil.cpp
  src/wallet/walletutil.h
)

add_executable(repeerd ${REPEERD_SOURCE_FILES})
target_include_directories(repeerd PUBLIC ${CMAKE_SOURCE_DIR}/src ${CMAKE_BINARY_DIR}/src)
target_link_libraries(repeerd PUBLIC crypto leveldb minisketch secp256k1 sqlite3 univalue)