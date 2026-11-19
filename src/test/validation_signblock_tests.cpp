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

static CBlock MakePoWBlock(const CScript& scriptPubKey)
{
    CBlock block;
    CMutableTransaction mtx;
    mtx.nVersion = 1;
    mtx.nLockTime = 0;

    CTxIn txin;
    txin.prevout.SetNull();
    txin.scriptSig << 0;
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

static std::shared_ptr<wallet::CWallet> MakeTestTaprootWallet(interfaces::Chain* chain)
{
    wallet::DatabaseOptions options;
    wallet::DatabaseStatus status;
    bilingual_str error_string;
    auto wallet = std::make_shared<wallet::CWallet>(chain, "test", wallet::MakeSQLiteDatabase("sqlite_testing.db", options, status, error_string, /*mock=*/true));
    LOCK(wallet->cs_wallet);
    wallet->SetupDescriptorScriptPubKeyMans();

    return wallet;
}

BOOST_AUTO_TEST_CASE(SignBlock_witness_v1_taproot_success)
{
    auto wallet = MakeTestTaprootWallet(m_node.chain.get());
    util::Result<CTxDestination> result = wallet->GetNewDestination(OutputType::BECH32M, "Test Signing");
    BOOST_REQUIRE(result);
    CTxDestination dest = *result;

    // Extract the x-only pubkey directly from the taproot destination
    auto* taproot_dest = std::get_if<WitnessV1Taproot>(&dest);
    BOOST_REQUIRE(taproot_dest);
    XOnlyPubKey xonly_pubkey = *taproot_dest;

    CScript block_script;
    block_script << OP_1 << ToByteVector(xonly_pubkey);

    CBlock block = MakePoWBlock(block_script);

    BOOST_REQUIRE(SignBlock(block, *wallet));
}

BOOST_AUTO_TEST_CASE(SignBlock_witness_v1_taproot_key_not_found)
{
    auto wallet = MakeTestTaprootWallet(m_node.chain.get());

    CKey key;
    key.MakeNewKey(true);
    CScript wrong_spk;
    wrong_spk << OP_1 << ToByteVector(XOnlyPubKey{key.GetPubKey()});

    CBlock block = MakePoWBlock(wrong_spk);

    BOOST_REQUIRE(!SignBlock(block, *wallet));
}

BOOST_AUTO_TEST_CASE(SignBlock_witness_v1_taproot_invalid_pubkey)
{
    auto wallet = MakeTestTaprootWallet(m_node.chain.get());

    CScript invalid_spk;
    invalid_spk << OP_1 << std::vector<unsigned char>(32, 0x00);

    CBlock block = MakePoWBlock(invalid_spk);

    BOOST_REQUIRE(!SignBlock(block, *wallet));
}

BOOST_AUTO_TEST_SUITE_END()
