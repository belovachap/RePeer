// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <interfaces/chain.h>
#include <wallet/context.h>
#include <wallet/sqlite.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

using namespace wallet;

BOOST_FIXTURE_TEST_SUITE(wallet_create_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(create_wallet_no_keys_when_will_encrypt)
{
    // Create a WalletContext with a mock chain
    WalletContext context;
    context.args = m_node.args;
    bilingual_str error;
    std::vector<bilingual_str> warnings;

    // Create wallet with will_encrypt_wallet = true
    // This should NOT call SetupDescriptorScriptPubKeyMans(), so no keys are created
    std::shared_ptr<CWallet> wallet = CWallet::Create(context, "test_wallet_encrypt",
                                                      std::move(m_sqlite_db),
                                                      /*will_encrypt_wallet=*/true, error, warnings);
    BOOST_REQUIRE(wallet != nullptr);
    BOOST_REQUIRE(error.empty());

    // Verify that no ScriptPubKeyManagers (and thus no keys) were created
    // because SetupDescriptorScriptPubKeyMans was skipped
    BOOST_REQUIRE(wallet->GetAllScriptPubKeyMans().empty());
    BOOST_REQUIRE(wallet->GetActiveScriptPubKeyMans().empty());

    // Verify the wallet is not yet encrypted (no master keys yet)
    BOOST_REQUIRE(!wallet->IsCrypted());
}

BOOST_AUTO_TEST_CASE(create_wallet_creates_keys_when_not_will_encrypt)
{
    // Create a WalletContext with a mock chain
    WalletContext context;
    context.args = m_node.args;
    bilingual_str error;
    std::vector<bilingual_str> warnings;

    // Create wallet with will_encrypt_wallet = false
    // This SHOULD call SetupDescriptorScriptPubKeyMans(), so keys ARE created
    std::shared_ptr<CWallet> wallet = CWallet::Create(context, "test_wallet_no_encrypt",
                                                      std::move(m_sqlite_db),
                                                      /*will_encrypt_wallet=*/false, error, warnings);
    BOOST_REQUIRE(wallet != nullptr);
    BOOST_REQUIRE(error.empty());

    // Verify that ScriptPubKeyManagers WERE created (keys were generated)
    BOOST_REQUIRE(!wallet->GetAllScriptPubKeyMans().empty());
    BOOST_REQUIRE(!wallet->GetActiveScriptPubKeyMans().empty());
}

BOOST_AUTO_TEST_CASE(create_wallet_encrypt_then_encrypt_creates_keys)
{
    // Verify that after calling EncryptWallet on a wallet created with will_encrypt_wallet=true,
    // keys are then set up via SetupDescriptorScriptPubKeyMans inside EncryptWallet
    WalletContext context;
    context.args = m_node.args;
    bilingual_str error;
    std::vector<bilingual_str> warnings;

    // Create wallet with will_encrypt_wallet = true (no keys yet)
    std::shared_ptr<CWallet> wallet = CWallet::Create(context, "test_wallet_encrypt_then",
                                                      std::move(m_sqlite_db),
                                                      /*will_encrypt_wallet=*/true, error, warnings);
    BOOST_REQUIRE(wallet != nullptr);
    BOOST_REQUIRE(wallet->GetAllScriptPubKeyMans().empty());

    // Now encrypt the wallet - this should call SetupDescriptorScriptPubKeyMans internally
    BOOST_REQUIRE(wallet->EncryptWallet("testpassphrase"));

    // After encryption, keys should now exist
    BOOST_REQUIRE(!wallet->GetAllScriptPubKeyMans().empty());
    BOOST_REQUIRE(wallet->IsCrypted());
}

BOOST_AUTO_TEST_SUITE_END()
