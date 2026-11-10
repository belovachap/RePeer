# Place binary executables in the build/bin directory.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Submodules

## crc32c
set(CRC32C_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CRC32C_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(CRC32C_USE_GLOG OFF CACHE BOOL "" FORCE)
set(CRC32C_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory(crc32c)

## leveldb
set(LEVELDB_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LEVELDB_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(LEVELDB_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory(leveldb)
### leveldb turns off RTTI by default and that breaks our build, so turn it back on.
target_compile_options(leveldb PRIVATE -frtti)

## minisketch
set(MINISKETCH_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(minisketch)

## secp256k1
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE BOOL "" FORCE)
add_subdirectory(secp256k1)

## univalue
add_subdirectory(univalue)

# --- Crypto library ---
add_library(bitcoin_crypto_base STATIC
  crypto/aes.cpp
  crypto/chacha_poly_aead.cpp
  crypto/chacha20.cpp
  crypto/hkdf_sha256_32.cpp
  crypto/hmac_sha256.cpp
  crypto/hmac_sha512.cpp
  crypto/poly1305.cpp
  crypto/muhash.cpp
  crypto/ripemd160.cpp
  crypto/sha1.cpp
  crypto/sha256.cpp
  crypto/sha3.cpp
  crypto/sha512.cpp
  crypto/siphash.cpp
)
target_include_directories(bitcoin_crypto_base PUBLIC ${CMAKE_SOURCE_DIR}/src)

if(ENABLE_SSE41)
  add_library(bitcoin_crypto_sse41 STATIC crypto/sha256_sse41.cpp)
  target_compile_options(bitcoin_crypto_sse41 PUBLIC ${SSE41_CXXFLAGS})
  target_compile_definitions(bitcoin_crypto_sse41 PUBLIC ENABLE_SSE41)
  list(APPEND CRYPTO_LIBS bitcoin_crypto_sse41)
endif()
# ... similar for AVX2, X86_SHANI, ARM_SHANI

set(LIBBITCOIN_CRYPTO bitcoin_crypto_base ${CRYPTO_LIBS})

# --- Consensus library ---
add_library(bitcoin_consensus STATIC
  arith_uint256.cpp
  consensus/merkle.cpp
  consensus/tx_check.cpp
  hash.cpp
  primitives/block.cpp
  primitives/transaction.cpp
  pubkey.cpp
  script/bitcoinconsensus.cpp
  script/descriptor.cpp
  script/interpreter.cpp
  script/miniscript.cpp
  script/script.cpp
  script/script_error.cpp
  script/sign.cpp
  script/signingprovider.cpp
  script/standard.cpp
  uint256.cpp
  util/strencodings.cpp
)
target_link_libraries(bitcoin_consensus PUBLIC bitcoin_util)
target_include_directories(bitcoin_consensus PUBLIC
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/src/secp256k1/include)

# --- Common library ---
add_library(bitcoin_common STATIC
  base58.cpp
  bech32.cpp
  chainparams.cpp
  coins.cpp
  common/bloom.cpp
  common/init.cpp
  common/interfaces.cpp
  compressor.cpp
  core_read.cpp
  core_write.cpp
  deploymentinfo.cpp
  init/common.cpp
  kernel/chainparams.cpp
  key.cpp
  key_io.cpp
  merkleblock.cpp
  net_types.cpp
  netaddress.cpp
  netbase.cpp
  net_permissions.cpp
  outputtype.cpp
  policy/policy.cpp
  protocol.cpp
  psbt.cpp
  scheduler.cpp
)
target_link_libraries(bitcoin_common PUBLIC univalue secp256k1 bitcoin_util bitcoin_consensus)
target_include_directories(bitcoin_common PUBLIC ${CMAKE_SOURCE_DIR}/src ${CMAKE_BINARY_DIR}/src)

# --- Util library ---
add_library(bitcoin_util STATIC
  support/lockedpool.cpp
  chainparamsbase.cpp
  clientversion.cpp
  logging.cpp
  random.cpp
  randomenv.cpp
  support/cleanse.cpp
  sync.cpp
  util/asmap.cpp
  util/bip32.cpp
  util/bytevectorhash.cpp
  util/check.cpp
  util/error.cpp
  util/exception.cpp
  util/fs.cpp
  util/fs_helpers.cpp
  util/getuniquepath.cpp
  util/hasher.cpp
  util/sock.cpp
  util/syserror.cpp
  util/system.cpp
  util/message.cpp
  util/moneystr.cpp
  util/readwritefile.cpp
  util/settings.cpp
  util/syscall_sandbox.cpp
  util/thread.cpp
  util/threadinterrupt.cpp
  util/threadnames.cpp
  util/serfloat.cpp
  util/spanparsing.cpp
  util/strencodings.cpp
  util/string.cpp
  util/time.cpp
  util/tokenpipe.cpp
)
target_link_libraries(bitcoin_util PUBLIC univalue)
target_include_directories(bitcoin_util PUBLIC ${CMAKE_SOURCE_DIR}/src ${CMAKE_BINARY_DIR}/src)

# --- Node library ---
add_library(bitcoin_node STATIC
  addrdb.cpp
  addrman.cpp
  banman.cpp
  blockencodings.cpp
  blockfilter.cpp
  chain.cpp
  consensus/tx_verify.cpp
  dbwrapper.cpp
  deploymentstatus.cpp
  flatfile.cpp
  headerssync.cpp
  i2p.cpp
  index/base.cpp
  index/blockfilterindex.cpp
  index/coinstatsindex.cpp
  index/txindex.cpp
  init.cpp
  kernel/chain.cpp
  kernel/checks.cpp
  kernel/coinstats.cpp
  kernel/context.cpp
  kernel/cs_main.cpp
  kernel/mempool_persist.cpp
  net.cpp
  net_processing.cpp
  netgroup.cpp
  node/blockmanager_args.cpp
  node/blockstorage.cpp
  node/caches.cpp
  node/chainstate.cpp
  node/chainstatemanager_args.cpp
  node/coin.cpp
  node/coins_view_args.cpp
  node/connection_types.cpp
  node/context.cpp
  node/database_args.cpp
  node/eviction.cpp
  node/interface_ui.cpp
  node/interfaces.cpp
  node/mempool_args.cpp
  node/mempool_persist_args.cpp
  node/miner.cpp
  node/minisketchwrapper.cpp
  node/psbt.cpp
  node/transaction.cpp
  node/txreconciliation.cpp
  node/utxo_snapshot.cpp
  node/validation_cache_args.cpp
  noui.cpp
  policy/packages.cpp
  policy/settings.cpp
  pow.cpp
  script/sigcache.cpp
  shutdown.cpp
  signet.cpp
  timedata.cpp
  txdb.cpp
  txmempool.cpp
  txorphanage.cpp
  txrequest.cpp
  util/syscall_sandbox.cpp
  validation.cpp
  validationinterface.cpp
  wallet/init.cpp
  warnings.cpp
  kernel.cpp
)
target_link_libraries(bitcoin_node PUBLIC leveldb minisketch univalue)
target_include_directories(bitcoin_node PUBLIC ${CMAKE_SOURCE_DIR}/src ${CMAKE_BINARY_DIR}/src)

# --- Wallet library ---
add_library(bitcoin_wallet STATIC
  kernelrecord.cpp
  key_io.cpp
  psbt.cpp
  script/descriptor.cpp
  util/spanparsing.cpp
  wallet/coincontrol.cpp
  wallet/context.cpp
  wallet/crypter.cpp
  wallet/db.cpp
  wallet/dump.cpp
  wallet/interfaces.cpp
  wallet/load.cpp
  wallet/receive.cpp
  wallet/scriptpubkeyman.cpp
  wallet/spend.cpp
  wallet/sqlite.cpp
  wallet/transaction.cpp
  wallet/wallet.cpp
  wallet/walletdb.cpp
  wallet/walletutil.cpp
  wallet/coinselection.cpp
)
target_include_directories(bitcoin_wallet PUBLIC ${CMAKE_SOURCE_DIR}/src ${CMAKE_BINARY_DIR}/src)
target_link_libraries(bitcoin_wallet PUBLIC leveldb sqlite3 univalue bitcoin_common)

# --- Main daemon binary ---
add_executable(repeerd
  bitcoind.cpp
  init/bitcoind.cpp
)
target_link_libraries(repeerd PUBLIC
  bitcoin_node
  bitcoin_common
  bitcoin_util
  bitcoin_consensus
  bitcoin_wallet
  ${LIBBITCOIN_CRYPTO}
  ${SSL_LIBRARIES}
  ${CRYPTO_LIBRARIES}
  Threads::Threads
)

# --- Qt GUI (replaces Makefile.qt.include) ---
 add_subdirectory(qt)

# --- Kernel library ---
if(BUILD_BITCOIN_KERNEL_LIB)
  add_library(peercoinkernel SHARED
    kernel/bitcoinkernel.cpp
    # ... same source list as in Makefile.am
  )
  target_include_directories(peercoinkernel PUBLIC ${CMAKE_SOURCE_DIR}/src)
  target_link_libraries(peercoinkernel PUBLIC
    ${LIBBITCOIN_CRYPTO} ${LIBLEVELDB} ${LIBMEMENV} ${LIBSECP256K1}
  )
  set_target_properties(peercoinkernel PROPERTIES
    CXX_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
  )
endif()

# --- IPC / Multiprocess ---
if(ENABLE_MULTIPROCESS)
  # Use libmultiprocess's own CMake integration or custom commands
  # to generate capnp files
endif()