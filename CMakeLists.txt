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
find_package(Qt6 REQUIRED COMPONENTS Core DBus Widgets Network)
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
  src/addrman_impl.h
  src/addrman.cpp
  src/addrman.h
  src/arith_uint256.cpp
  src/arith_uint256.h
  src/attributes.h
  src/banman.cpp
  src/banman.h
  src/base58.cpp
  src/base58.h
  src/bech32.cpp
  src/bech32.h
  src/bignum.h
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
  src/checkqueue.h
  src/clientversion.cpp
  src/clientversion.h
  src/coins.cpp
  src/coins.h
  src/compressor.cpp
  src/compressor.h
  src/core_io.h
  src/core_memusage.h
  src/cuckoocache.h
  src/dbwrapper.cpp
  src/dbwrapper.h
  src/deploymentinfo.cpp
  src/deploymentinfo.h
  src/deploymentstatus.h
  src/flatfile.cpp
  src/flatfile.h
  src/hash.cpp
  src/hash.h
  src/headerssync.cpp
  src/headerssync.h
  src/i2p.cpp
  src/i2p.h
  src/indirectmap.h
  src/init.cpp
  src/init.h
  src/kernel.cpp
  src/kernel.h
  src/key_io.cpp
  src/key_io.h
  src/key.cpp
  src/key.h
  src/logging.cpp
  src/logging.h
  src/memusage.h
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
  src/netmessagemaker.h
  src/noui.cpp
  src/noui.h
  src/outputtype.cpp
  src/outputtype.h
  src/pow.cpp
  src/pow.h
  src/prevector.h
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
  src/reverse_iterator.h
  src/scheduler.cpp
  src/scheduler.h
  src/serialize.h
  src/shutdown.cpp
  src/shutdown.h
  src/signet.cpp
  src/signet.h
  src/span.h
  src/streams.h
  src/sync.h
  src/threadsafety.h
  src/timedata.cpp
  src/timedata.h
  src/tinyformat.h
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
  src/undo.h
  src/validation.cpp
  src/validation.h
  src/validationinterface.cpp
  src/validationinterface.h
  src/version.h
  src/versionbits.h
  src/walletinitinterface.h
  src/warnings.cpp
  src/warnings.h

  src/common/bloom.cpp
  src/common/bloom.h
  src/common/init.cpp
  src/common/init.h
  src/common/interfaces.cpp

  src/compat/assumptions.h
  src/compat/compat.h
  src/compat/cpuid.h

  src/config/bitcoin-config.h

  src/consensus/amount.h
  src/consensus/consensus.h
  src/consensus/merkle.cpp
  src/consensus/merkle.h
  src/consensus/params.h
  src/consensus/tx_check.cpp
  src/consensus/tx_check.h
  src/consensus/tx_verify.cpp
  src/consensus/tx_verify.h
  src/consensus/validation.h

  src/crypto/aes.cpp
  src/crypto/aes.h
  src/crypto/chacha20.cpp
  src/crypto/chacha20.h
  src/crypto/common.h
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
  src/index/disktxpos.h
  src/index/txindex.cpp
  src/index/txindex.h

  src/init/bitcoind.cpp
  src/init/common.cpp
  src/init/common.h

  src/interfaces/chain.h
  src/interfaces/handler.h
  src/interfaces/init.h
  src/interfaces/node.h
  src/interfaces/wallet.h

  src/kernel/blockmanager_opts.h
  src/kernel/chain.cpp
  src/kernel/chain.h
  src/kernel/chainparams.cpp
  src/kernel/chainparams.h
  src/kernel/chainstatemanager_opts.h
  src/kernel/checks.cpp
  src/kernel/checks.h
  src/kernel/coinstats.cpp
  src/kernel/coinstats.h
  src/kernel/context.cpp
  src/kernel/context.h
  src/kernel/cs_main.cpp
  src/kernel/cs_main.h
  src/kernel/mempool_entry.h
  src/kernel/mempool_limits.h
  src/kernel/mempool_options.h
  src/kernel/mempool_persist.cpp
  src/kernel/mempool_persist.h
  src/kernel/validation_cache_sizes.h

  src/logging/timer.h

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

  src/policy/feerate.h
  src/policy/fees.h
  src/policy/packages.cpp
  src/policy/packages.h
  src/policy/policy.cpp
  src/policy/policy.h
  src/policy/rbf.h
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
  src/script/keyorigin.h
  src/script/miniscript.cpp
  src/script/miniscript.h
  src/script/script_error.cpp
  src/script/script_error.h
  src/script/script.cpp
  src/script/script.h
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

  src/support/allocators/secure.h
  src/support/allocators/zeroafterfree.h

  src/util/asmap.cpp
  src/util/asmap.h
  src/util/bip32.cpp
  src/util/bip32.h
  src/util/bitdeque.h
  src/util/bytevectorhash.cpp
  src/util/bytevectorhash.h
  src/util/check.cpp
  src/util/check.h
  src/util/epochguard.h
  src/util/error.cpp
  src/util/error.h
  src/util/exception.cpp
  src/util/exception.h
  src/util/fastrange.h
  src/util/fees.h
  src/util/fs_helpers.cpp
  src/util/fs_helpers.h
  src/util/fs.cpp
  src/util/fs.h
  src/util/getuniquepath.cpp
  src/util/getuniquepath.h
  src/util/golombrice.h
  src/util/hash_type.h
  src/util/hasher.cpp
  src/util/hasher.h
  src/util/macros.h
  src/util/message.cpp
  src/util/message.h
  src/util/moneystr.cpp
  src/util/moneystr.h
  src/util/overflow.h
  src/util/overloaded.h
  src/util/rbf.h
  src/util/readwritefile.cpp
  src/util/readwritefile.h
  src/util/result.h
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
  src/util/threadnames.cpp
  src/util/threadnames.h
  src/util/time.cpp
  src/util/time.h
  src/util/tokenpipe.cpp
  src/util/tokenpipe.h
  src/util/translation.h
  src/util/types.h
  src/util/ui_change_type.h
  src/util/vector.h

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
  src/wallet/fees.h
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
  src/wallet/types.h
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

# repeer-qt executable

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOUIC_SEARCH_PATHS "src/qt/forms")
set(CMAKE_AUTORCC ON)

set(REPEER-QT_SOURCE_FILES
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
  src/core_write.cpp # unique to repeer-qt?
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
  src/kernelrecord.cpp # unique to repeer-qt?
  src/kernelrecord.h # unique to repeer-qt?
  src/key_io.cpp
  src/key_io.h
  src/key.cpp
  src/key.h
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
  src/signet.cpp
  src/signet.h
  src/shutdown.cpp
  src/shutdown.h
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

  src/common/bloom.cpp
  src/common/bloom.h
  src/common/interfaces.cpp
  src/common/init.cpp
  src/common/init.h

  src/consensus/merkle.cpp
  src/consensus/merkle.h
  src/consensus/tx_check.cpp
  src/consensus/tx_check.h
  src/consensus/tx_verify.cpp
  src/consensus/tx_verify.h

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

  src/init/bitcoin-qt.cpp
  src/init/common.cpp
  src/init/common.h

  src/interfaces/handler.h

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

  src/qt/addressbookpage.cpp
  src/qt/addressbookpage.h
  src/qt/addresstablemodel.cpp
  src/qt/addresstablemodel.h
  src/qt/askpassphrasedialog.cpp
  src/qt/askpassphrasedialog.h
  src/qt/bitcoin.cpp
  src/qt/bitcoin.h
  src/qt/bitcoin.qrc
  src/qt/bitcoinaddressvalidator.cpp
  src/qt/bitcoinaddressvalidator.h
  src/qt/bitcoinamountfield.cpp
  src/qt/bitcoinamountfield.h
  src/qt/bitcoingui.cpp
  src/qt/bitcoingui.h
  src/qt/bitcoinunits.cpp
  src/qt/bitcoinunits.h
  src/qt/clientmodel.cpp
  src/qt/clientmodel.h
  src/qt/coincontroldialog.cpp
  src/qt/coincontroldialog.h
  src/qt/coincontroltreewidget.cpp
  src/qt/coincontroltreewidget.h
  src/qt/createwalletdialog.cpp
  src/qt/createwalletdialog.h
  src/qt/csvmodelwriter.cpp
  src/qt/csvmodelwriter.h
  src/qt/editaddressdialog.cpp
  src/qt/editaddressdialog.h
  src/qt/guiutil.cpp
  src/qt/guiutil.h
  src/qt/informationwindow.h
  src/qt/informationwindow.cpp
  src/qt/initexecutor.cpp
  src/qt/initexecutor.h
  src/qt/intro.cpp
  src/qt/intro.h
  src/qt/main.cpp
  src/qt/mintingfilterproxy.cpp
  src/qt/mintingfilterproxy.h
  src/qt/mintingtablemodel.cpp
  src/qt/mintingtablemodel.h
  src/qt/mintingview.cpp
  src/qt/mintingview.h
  src/qt/modaloverlay.cpp
  src/qt/modaloverlay.h
  src/qt/networkstyle.cpp
  src/qt/networkstyle.h
  src/qt/notificator.cpp
  src/qt/notificator.h
  src/qt/optionsdialog.cpp
  src/qt/optionsdialog.h
  src/qt/optionsmodel.cpp
  src/qt/optionsmodel.h
  src/qt/overviewpage.cpp
  src/qt/overviewpage.h
  src/qt/platformstyle.cpp
  src/qt/platformstyle.h
  src/qt/qvalidatedlineedit.cpp
  src/qt/qvalidatedlineedit.h
  src/qt/qvaluecombobox.cpp
  src/qt/qvaluecombobox.h
  src/qt/receivecoinsdialog.cpp
  src/qt/receivecoinsdialog.h
  src/qt/receiverequestdialog.cpp
  src/qt/receiverequestdialog.h
  src/qt/recentrequeststablemodel.cpp
  src/qt/recentrequeststablemodel.h
  src/qt/sendcoinsdialog.cpp
  src/qt/sendcoinsdialog.h
  src/qt/sendcoinsentry.cpp
  src/qt/sendcoinsentry.h
  src/qt/splashscreen.cpp
  src/qt/splashscreen.h
  src/qt/transactiondesc.cpp
  src/qt/transactiondesc.h
  src/qt/transactiondescdialog.cpp
  src/qt/transactiondescdialog.h
  src/qt/transactionfilterproxy.cpp
  src/qt/transactionfilterproxy.h
  src/qt/transactionoverviewwidget.cpp
  src/qt/transactionoverviewwidget.h
  src/qt/transactiontablemodel.cpp
  src/qt/transactiontablemodel.h
  src/qt/transactionrecord.cpp
  src/qt/transactionrecord.h
  src/qt/transactionview.cpp
  src/qt/transactionview.h
  src/qt/utilitydialog.cpp
  src/qt/utilitydialog.h
  src/qt/walletcontroller.cpp
  src/qt/walletcontroller.h
  src/qt/walletframe.cpp
  src/qt/walletframe.h
  src/qt/walletmodel.cpp
  src/qt/walletmodel.h
  src/qt/walletmodeltransaction.cpp
  src/qt/walletmodeltransaction.h
  src/qt/walletview.cpp
  src/qt/walletview.h

  src/script/descriptor.cpp
  src/script/descriptor.h
  src/script/interpreter.cpp
  src/script/interpreter.h
  src/script/miniscript.cpp
  src/script/miniscript.h
  src/script/script_error.cpp
  src/script/script_error.h
  src/script/script.cpp
  src/script/script.h
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
  src/util/fs_helpers.cpp
  src/util/fs_helpers.h
  src/util/fs.cpp
  src/util/fs.h
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
  src/util/threadnames.cpp
  src/util/threadnames.h
  src/util/threadinterrupt.cpp
  src/util/threadinterrupt.h
  src/util/time.cpp
  src/util/time.h
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
  src/wallet/walletutil.cpp
)

set_source_files_properties(src/node/interface_ui.h PROPERTIES SKIP_AUTOUIC ON)
set_source_files_properties(src/wallet/interfaces.cpp PROPERTIES SKIP_AUTOUIC ON)
set_source_files_properties(src/wallet/wallet.h PROPERTIES SKIP_AUTOUIC ON)

add_executable(repeer-qt ${REPEER-QT_SOURCE_FILES})
target_include_directories(repeer-qt PUBLIC
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_BINARY_DIR}/src
  ${CMAKE_BINARY_DIR}/repeer-qt_autogen/include
)
target_link_libraries(repeer-qt PUBLIC
  crypto
  leveldb
  Qt::Core Qt::DBus Qt::Network Qt::Widgets
  secp256k1
  sqlite3
  univalue
)