#include <test/util/setup_common.h>
#include <validation.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <pubkey.h>
#include <key.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(validation_block_tests, TestingSetup)

static CBlock MakeBlockWithCoinbase(const CScript& scriptPubKey, const CScriptWitness& witness = CScriptWitness())
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

static CBlock MakePoSBlockWithCoinstake(const CScript& scriptPubKey, const CScriptWitness& witness = CScriptWitness())
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

// --- Genesis block path ---

BOOST_AUTO_TEST_CASE(CheckBlockSignature_genesis_empty_sig)
{
    CBlock genesis = m_node.chainman->GetParams().GenesisBlock();
    BOOST_CHECK(CheckBlockSignature(genesis));
}

BOOST_AUTO_TEST_CASE(CheckBlockSignature_genesis_nonempty_sig)
{
    CBlock genesis = m_node.chainman->GetParams().GenesisBlock();
    genesis.vchBlockSig = std::vector<unsigned char>(1, 0x01);
    BOOST_CHECK(!CheckBlockSignature(genesis));
}

// --- PUBKEY path ---

BOOST_AUTO_TEST_CASE(CheckBlockSignature_pubkey_valid)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << OP_CHECKSIG;

    CBlock block = MakeBlockWithCoinbase(scriptPubKey);

    uint256 hash = block.GetHash();
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(hash, sig));
    block.vchBlockSig = sig;

    BOOST_CHECK(CheckBlockSignature(block));
}

BOOST_AUTO_TEST_CASE(CheckBlockSignature_pubkey_invalid_sig)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << OP_CHECKSIG;

    CBlock block = MakeBlockWithCoinbase(scriptPubKey);

    CKey wrong_key;
    wrong_key.MakeNewKey(true);
    uint256 hash = block.GetHash();
    std::vector<unsigned char> sig;
    BOOST_CHECK(wrong_key.Sign(hash, sig));
    block.vchBlockSig = sig;

    BOOST_CHECK(!CheckBlockSignature(block));
}

BOOST_AUTO_TEST_CASE(CheckBlockSignature_pubkey_empty_sig)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << OP_CHECKSIG;

    CBlock block = MakeBlockWithCoinbase(scriptPubKey);
    block.vchBlockSig.clear();

    BOOST_CHECK(!CheckBlockSignature(block));
}

// --- WITNESS_V0_KEYHASH (P2WPKH / bech32) path ---

BOOST_AUTO_TEST_CASE(CheckBlockSignature_witness_v0_keyhash_valid)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << OP_0 << ToByteVector(pubkey.GetID());

    CScriptWitness witness;
    witness.stack.push_back(std::vector<unsigned char>());
    witness.stack.push_back(std::vector<unsigned char>(pubkey.begin(), pubkey.end()));

    CBlock block = MakeBlockWithCoinbase(scriptPubKey, witness);

    uint256 hash = block.GetHash();
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(hash, sig));
    block.vchBlockSig = sig;

    BOOST_CHECK(CheckBlockSignature(block));
}

BOOST_AUTO_TEST_CASE(CheckBlockSignature_witness_v0_keyhash_hash_mismatch)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CKey other_key;
    other_key.MakeNewKey(true);
    CPubKey other_pubkey = other_key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << OP_0 << ToByteVector(other_pubkey.GetID());

    CScriptWitness witness;
    witness.stack.push_back(std::vector<unsigned char>());
    witness.stack.push_back(std::vector<unsigned char>(pubkey.begin(), pubkey.end()));

    CBlock block = MakeBlockWithCoinbase(scriptPubKey, witness);

    uint256 hash = block.GetHash();
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(hash, sig));
    block.vchBlockSig = sig;

    BOOST_CHECK(!CheckBlockSignature(block));
}

BOOST_AUTO_TEST_CASE(CheckBlockSignature_witness_v0_keyhash_empty_witness)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << OP_0 << ToByteVector(pubkey.GetID());

    CScriptWitness witness; // empty

    CBlock block = MakeBlockWithCoinbase(scriptPubKey, witness);
    block.vchBlockSig = std::vector<unsigned char>(1, 0x01);

    BOOST_CHECK(!CheckBlockSignature(block));
}

BOOST_AUTO_TEST_CASE(CheckBlockSignature_witness_v0_keyhash_invalid_pubkey)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << OP_0 << ToByteVector(pubkey.GetID());

    CScriptWitness witness;
    witness.stack.push_back(std::vector<unsigned char>());
    witness.stack.push_back(std::vector<unsigned char>(10, 0x00)); // invalid pubkey

    CBlock block = MakeBlockWithCoinbase(scriptPubKey, witness);
    block.vchBlockSig = std::vector<unsigned char>(1, 0x01);

    BOOST_CHECK(!CheckBlockSignature(block));
}

// --- WITNESS_V1_TAPROOT (bech32m) path ---

BOOST_AUTO_TEST_CASE(CheckBlockSignature_taproot_valid)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    XOnlyPubKey xonly(pubkey);

    CScript scriptPubKey;
    scriptPubKey << OP_1 << ToByteVector(xonly);

    CBlock block = MakeBlockWithCoinbase(scriptPubKey);

    uint256 hash = block.GetHash();
    std::vector<unsigned char> sig(64);
    BOOST_CHECK(key.SignSchnorr(hash, Span<unsigned char>(sig), nullptr, uint256()));
    block.vchBlockSig = sig;

    BOOST_CHECK(CheckBlockSignature(block));
}

BOOST_AUTO_TEST_CASE(CheckBlockSignature_taproot_invalid_sig)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    XOnlyPubKey xonly(pubkey);

    CScript scriptPubKey;
    scriptPubKey << OP_1 << ToByteVector(xonly);

    CBlock block = MakeBlockWithCoinbase(scriptPubKey);

    CKey wrong_key;
    wrong_key.MakeNewKey(true);
    uint256 hash = block.GetHash();
    std::vector<unsigned char> sig(64);
    BOOST_CHECK(wrong_key.SignSchnorr(hash, Span<unsigned char>(sig), nullptr, uint256()));
    block.vchBlockSig = sig;

    BOOST_CHECK(!CheckBlockSignature(block));
}

BOOST_AUTO_TEST_CASE(CheckBlockSignature_taproot_empty_sig)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    XOnlyPubKey xonly(pubkey);

    CScript scriptPubKey;
    scriptPubKey << OP_1 << ToByteVector(xonly);

    CBlock block = MakeBlockWithCoinbase(scriptPubKey);
    block.vchBlockSig.clear();

    BOOST_CHECK(!CheckBlockSignature(block));
}

// --- Unsupported script type path ---

BOOST_AUTO_TEST_CASE(CheckBlockSignature_unsupported_script_type)
{
    CScript scriptPubKey;
    scriptPubKey << OP_HASH160 << std::vector<unsigned char>(20, 0x00) << OP_EQUAL;

    CBlock block = MakeBlockWithCoinbase(scriptPubKey);
    block.vchBlockSig = std::vector<unsigned char>(1, 0x01);

    BOOST_CHECK(!CheckBlockSignature(block));
}

BOOST_AUTO_TEST_CASE(CheckBlockSignature_nonstandard_script)
{
    CScript scriptPubKey;
    scriptPubKey << OP_RETURN << std::vector<unsigned char>(4, 0x00);

    CBlock block = MakeBlockWithCoinbase(scriptPubKey);
    block.vchBlockSig = std::vector<unsigned char>(1, 0x01);

    BOOST_CHECK(!CheckBlockSignature(block));
}

// --- PoS block paths (coinstake vout[1]) ---

BOOST_AUTO_TEST_CASE(CheckBlockSignature_pos_pubkey_valid)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << OP_CHECKSIG;

    CBlock block = MakePoSBlockWithCoinstake(scriptPubKey);

    uint256 hash = block.GetHash();
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(hash, sig));
    block.vchBlockSig = sig;

    BOOST_CHECK(CheckBlockSignature(block));
}

BOOST_AUTO_TEST_CASE(CheckBlockSignature_pos_witness_v0_keyhash_valid)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << OP_0 << ToByteVector(pubkey.GetID());

    CScriptWitness witness;
    witness.stack.push_back(std::vector<unsigned char>());
    witness.stack.push_back(std::vector<unsigned char>(pubkey.begin(), pubkey.end()));

    CBlock block = MakePoSBlockWithCoinstake(scriptPubKey, witness);

    uint256 hash = block.GetHash();
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(hash, sig));
    block.vchBlockSig = sig;

    BOOST_CHECK(CheckBlockSignature(block));
}

BOOST_AUTO_TEST_CASE(CheckBlockSignature_pos_taproot_valid)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    XOnlyPubKey xonly(pubkey);

    CScript scriptPubKey;
    scriptPubKey << OP_1 << ToByteVector(xonly);

    CBlock block = MakePoSBlockWithCoinstake(scriptPubKey);

    uint256 hash = block.GetHash();
    std::vector<unsigned char> sig(64);
    BOOST_CHECK(key.SignSchnorr(hash, Span<unsigned char>(sig), nullptr, uint256()));
    block.vchBlockSig = sig;

    BOOST_CHECK(CheckBlockSignature(block));
}

BOOST_AUTO_TEST_SUITE_END()