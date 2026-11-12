#include <test/util/setup_common.h>
#include <validation.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <pubkey.h>
#include <key.h>
#include <key_io.h>
#include <uint256.h>
#include <wallet/wallet.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/sqlite.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(validation_signblock_tests, TestingSetup)

static CBlock MakePoWBlock(const CScript& scriptPubKey, const CScriptWitness& witness = CScriptWitness())
{
    CBlock block;
    CMutableTransaction mtx;
    mtx.nVersion = 1;
    mtx.nLockTime = 0;

    CTxIn txin;
    txin.prevout.SetNull();
    txin.scriptSig << 0;
    txin.scriptWitness = witness;
    mtx.vin.push_back(txin);

    CTxOut txout;
    txout.nValue = 50 * COIN;
    txout.scriptPubKey = scriptPubKey;
    mtx.vout.push_back(txout);

    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));
    block.nBits = 0x1d00ffff;
    block.nTime = 1231006505;
    block.nNonce = 0;
    return block;
}

static CBlock MakePoSBlock(const CScript& scriptPubKey, const CScriptWitness& witness = CScriptWitness())
{
    CBlock block;

    CMutableTransaction cb;
    cb.nVersion = 1;
    cb.nLockTime = 0;
    CTxIn cb_in;
    cb_in.prevout.SetNull();
    cb_in.scriptSig << 0;
    cb.vin.push_back(cb_in);
    CTxOut cb_out;
    cb_out.SetEmpty();
    cb.vout.push_back(cb_out);
    block.vtx.push_back(MakeTransactionRef(std::move(cb)));

    CMutableTransaction cs;
    cs.nVersion = 1;
    cs.nLockTime = 0;
    CTxIn cs_in;
    cs_in.prevout = COutPoint(uint256::ONE, 0);
    cs_in.scriptWitness = witness;
    cs.vin.push_back(cs_in);
    CTxOut cs_out0;
    cs_out0.SetEmpty();
    cs.vout.push_back(cs_out0);
    CTxOut cs_out1;
    cs_out1.nValue = 1 * COIN;
    cs_out1.scriptPubKey = scriptPubKey;
    cs.vout.push_back(cs_out1);
    block.vtx.push_back(MakeTransactionRef(std::move(cs)));

    block.nBits = 0x1d00ffff;
    block.nTime = 1231006505;
    block.nNonce = 0;
    return block;
}

static std::shared_ptr<wallet::CWallet> MakeTestWallet(const CKey& key, interfaces::Chain* chain)
{
    wallet::DatabaseOptions options;
    wallet::DatabaseStatus status;
    bilingual_str error_string;
    auto wallet = std::make_shared<wallet::CWallet>(
        chain, "test", wallet::MakeSQLiteDatabase("sqlite_testing.db", options, status, error_string));
    LOCK(wallet->cs_wallet);
    wallet->SetupLegacyScriptPubKeyMan();
    wallet->GetLegacyScriptPubKeyMan()->AddKey(key);
    return wallet;
}

// Helper for taproot tests: creates a descriptor-based wallet with a tr() descriptor.
static std::shared_ptr<wallet::CWallet> MakeTestTaprootWallet(interfaces::Chain* chain)
{
    wallet::DatabaseOptions options;
    wallet::DatabaseStatus status;
    bilingual_str error_string;
    auto wallet = std::make_shared<wallet::CWallet>(chain, "test", wallet::MakeSQLiteDatabase("sqlite_testing.db", options, status, error_string));
    LOCK(wallet->cs_wallet);
    wallet->SetWalletFlag(wallet::WALLET_FLAG_DESCRIPTORS);
    wallet->SetupDescriptorScriptPubKeyMans();

    return wallet;
}

// --- PUBKEY path, legacy keystore, key found, pubkey matches → success ---

BOOST_AUTO_TEST_CASE(SignBlock_pubkey_legacy_success)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << OP_CHECKSIG;

    CBlock block = MakePoWBlock(scriptPubKey);
    auto wallet = MakeTestWallet(key, m_node.chain.get());

    BOOST_CHECK(SignBlock(block, *wallet));
    BOOST_CHECK(!block.vchBlockSig.empty());
    BOOST_CHECK(pubkey.Verify(block.GetHash(), block.vchBlockSig));
}

// --- PUBKEY path, legacy keystore, key NOT found → false ---

BOOST_AUTO_TEST_CASE(SignBlock_pubkey_legacy_key_not_found)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << OP_CHECKSIG;

    CBlock block = MakePoWBlock(scriptPubKey);

    CKey other_key;
    other_key.MakeNewKey(true);
    auto wallet = MakeTestWallet(other_key, m_node.chain.get());

    BOOST_CHECK(!SignBlock(block, *wallet));
}

// --- WITNESS_V0_KEYHASH path, valid witness → success ---

BOOST_AUTO_TEST_CASE(SignBlock_witness_v0_keyhash_success)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << OP_0 << ToByteVector(pubkey.GetID());

    CScriptWitness witness;
    witness.stack.push_back(std::vector<unsigned char>());
    witness.stack.push_back(std::vector<unsigned char>(pubkey.begin(), pubkey.end()));

    CBlock block = MakePoWBlock(scriptPubKey, witness);
    auto wallet = MakeTestWallet(key, m_node.chain.get());

    BOOST_CHECK(SignBlock(block, *wallet));
    BOOST_CHECK(!block.vchBlockSig.empty());
    BOOST_CHECK(pubkey.Verify(block.GetHash(), block.vchBlockSig));
}

// --- WITNESS_V0_KEYHASH path, empty witness → false ---

BOOST_AUTO_TEST_CASE(SignBlock_witness_v0_keyhash_empty_witness)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << OP_0 << ToByteVector(pubkey.GetID());

    CScriptWitness witness; // empty

    CBlock block = MakePoWBlock(scriptPubKey, witness);
    auto wallet = MakeTestWallet(key, m_node.chain.get());

    BOOST_CHECK(!SignBlock(block, *wallet));
}

// --- WITNESS_V0_KEYHASH path, null witness → false ---

BOOST_AUTO_TEST_CASE(SignBlock_witness_v0_keyhash_null_witness)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << OP_0 << ToByteVector(pubkey.GetID());

    CBlock block = MakePoWBlock(scriptPubKey); // no witness
    auto wallet = MakeTestWallet(key, m_node.chain.get());

    BOOST_CHECK(!SignBlock(block, *wallet));
}

// --- WITNESS_V0_KEYHASH path, invalid pubkey in witness → false ---

BOOST_AUTO_TEST_CASE(SignBlock_witness_v0_keyhash_invalid_pubkey)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << OP_0 << ToByteVector(pubkey.GetID());

    CScriptWitness witness;
    witness.stack.push_back(std::vector<unsigned char>());
    witness.stack.push_back(std::vector<unsigned char>(10, 0x00)); // invalid pubkey

    CBlock block = MakePoWBlock(scriptPubKey, witness);
    auto wallet = MakeTestWallet(key, m_node.chain.get());

    BOOST_CHECK(!SignBlock(block, *wallet));
}

// --- Unsupported script type → false ---

BOOST_AUTO_TEST_CASE(SignBlock_unsupported_script_type)
{
    CKey key;
    key.MakeNewKey(true);

    CScript scriptPubKey;
    scriptPubKey << OP_HASH160 << std::vector<unsigned char>(20, 0x00) << OP_EQUAL;

    CBlock block = MakePoWBlock(scriptPubKey);
    auto wallet = MakeTestWallet(key, m_node.chain.get());

    BOOST_CHECK(!SignBlock(block, *wallet));
}

BOOST_AUTO_TEST_CASE(SignBlock_nonstandard_script)
{
    CKey key;
    key.MakeNewKey(true);

    CScript scriptPubKey;
    scriptPubKey << OP_RETURN << std::vector<unsigned char>(4, 0x00);

    CBlock block = MakePoWBlock(scriptPubKey);
    auto wallet = MakeTestWallet(key, m_node.chain.get());

    BOOST_CHECK(!SignBlock(block, *wallet));
}

// --- PoS block path (uses vtx[1]->vout[1]) ---

BOOST_AUTO_TEST_CASE(SignBlock_pos_block_pubkey_success)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << OP_CHECKSIG;

    CBlock block = MakePoSBlock(scriptPubKey);
    auto wallet = MakeTestWallet(key, m_node.chain.get());

    BOOST_CHECK(SignBlock(block, *wallet));
    BOOST_CHECK(!block.vchBlockSig.empty());
    BOOST_CHECK(pubkey.Verify(block.GetHash(), block.vchBlockSig));
}

BOOST_AUTO_TEST_CASE(SignBlock_pos_block_witness_v0_keyhash_success)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << OP_0 << ToByteVector(pubkey.GetID());

    CScriptWitness witness;
    witness.stack.push_back(std::vector<unsigned char>());
    witness.stack.push_back(std::vector<unsigned char>(pubkey.begin(), pubkey.end()));

    CBlock block = MakePoSBlock(scriptPubKey, witness);
    auto wallet = MakeTestWallet(key, m_node.chain.get());

    BOOST_CHECK(SignBlock(block, *wallet));
    BOOST_CHECK(!block.vchBlockSig.empty());
    BOOST_CHECK(pubkey.Verify(block.GetHash(), block.vchBlockSig));
}

BOOST_AUTO_TEST_CASE(SignBlock_pos_block_unsupported_type)
{
    CKey key;
    key.MakeNewKey(true);

    CScript scriptPubKey;
    scriptPubKey << OP_HASH160 << std::vector<unsigned char>(20, 0x00) << OP_EQUAL;

    CBlock block = MakePoSBlock(scriptPubKey);
    auto wallet = MakeTestWallet(key, m_node.chain.get());

    BOOST_CHECK(!SignBlock(block, *wallet));
}

// --- Edge case: empty vin in witness path ---

BOOST_AUTO_TEST_CASE(SignBlock_witness_v0_keyhash_empty_vin)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << OP_0 << ToByteVector(pubkey.GetID());

    CBlock block;
    CMutableTransaction mtx;
    mtx.nVersion = 1;
    mtx.nLockTime = 0;
    CTxOut txout;
    txout.nValue = 50 * COIN;
    txout.scriptPubKey = scriptPubKey;
    mtx.vout.push_back(txout);
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));
    block.nBits = 0x1d00ffff;
    block.nTime = 1231006505;
    block.nNonce = 0;

    auto wallet = MakeTestWallet(key, m_node.chain.get());
    BOOST_CHECK(!SignBlock(block, *wallet));
}

// --- WITNESS_V1_TAPROOT path, valid x-only pubkey → should succeed (currently fails) ---

BOOST_AUTO_TEST_CASE(SignBlock_witness_v1_taproot_success)
{
    auto wallet = MakeTestTaprootWallet(m_node.chain.get());
    util::Result<CTxDestination> result = wallet->GetNewDestination(OutputType::BECH32M, "Test Signing");
    BOOST_REQUIRE(result);
    CTxDestination dest = *result;

    // Get the scriptPubKey and use it to get the signing provider
    CScript script_pub_key = GetScriptForDestination(dest);
    auto provider = wallet->GetSolvingProvider(script_pub_key);
    BOOST_REQUIRE(provider);

    // For taproot, get the pubkey from the descriptor SPK manager's signing provider
    auto* spk_man = wallet->GetScriptPubKeyMan(OutputType::BECH32M, false);
    BOOST_REQUIRE(spk_man);
    auto* desc_spk_man = dynamic_cast<wallet::DescriptorScriptPubKeyMan*>(spk_man);
    BOOST_REQUIRE(desc_spk_man);

    auto keys = desc_spk_man->GetSigningProvider(script_pub_key, true);
    BOOST_REQUIRE(keys);
    BOOST_REQUIRE(!keys->keys.empty());
    CPubKey pubkey = keys->keys.begin()->second.GetPubKey();

    CScript block_script;
    block_script << OP_1 << ToByteVector(XOnlyPubKey{pubkey});

    CBlock block = MakePoWBlock(block_script);

    BOOST_REQUIRE(SignBlock(block, *wallet));
}

// --- WITNESS_V1_TAPROOT path, key NOT in wallet → false ---

BOOST_AUTO_TEST_CASE(SignBlock_witness_v1_taproot_key_not_found)
{
    auto wallet = MakeTestTaprootWallet(m_node.chain.get());

    // Use a scriptPubKey the wallet doesn't watch (different key)
    CKey key;
    key.MakeNewKey(true);
    CScript wrong_spk;
    wrong_spk << OP_1 << ToByteVector(XOnlyPubKey{key.GetPubKey()});

    CBlock block = MakePoWBlock(wrong_spk);

    BOOST_REQUIRE(!SignBlock(block, *wallet));
}

// --- WITNESS_V1_TAPROOT path, invalid x-only pubkey in script → false ---

BOOST_AUTO_TEST_CASE(SignBlock_witness_v1_taproot_invalid_pubkey)
{
    auto wallet = MakeTestTaprootWallet(m_node.chain.get());

    // 32 bytes of zeros is not a valid x-only pubkey (not on curve)
    CScript invalid_spk;
    invalid_spk << OP_1 << std::vector<unsigned char>(32, 0x00);

    CBlock block = MakePoWBlock(invalid_spk);

    BOOST_REQUIRE(!SignBlock(block, *wallet));
}

BOOST_AUTO_TEST_SUITE_END()