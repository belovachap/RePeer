// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/wallet.h>
#include <test/util/setup_common.h>
#include <wallet/context.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(wallet_unlocking_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(mint_only_unlock_is_per_wallet)
{
    // Create two encrypted wallets
    WalletContext context;
    context.chain = m_node.chain.get();
    context.args = m_node.args;

    DatabaseOptions options;
    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;

    SecureString passphrase{"testpassphrase"};

    // Create wallet A
    options.require_create = true;
    options.create_passphrase = passphrase;
    std::shared_ptr<CWallet> wallet_a = CreateWallet(context, "wallet_a", /*load_on_start=*/false, options, status, error, warnings);
    BOOST_REQUIRE(wallet_a != nullptr);
    BOOST_REQUIRE(wallet_a->IsCrypted());
    BOOST_REQUIRE(wallet_a->IsLocked());

    // Create wallet B
    options.create_passphrase = passphrase;
    std::shared_ptr<CWallet> wallet_b = CreateWallet(context, "wallet_b", /*load_on_start=*/false, options, status, error, warnings);
    BOOST_REQUIRE(wallet_b != nullptr);
    BOOST_REQUIRE(wallet_b->IsCrypted());
    BOOST_REQUIRE(wallet_b->IsLocked());

    // Unlock wallet A in mint-only mode
    BOOST_REQUIRE(wallet_a->Unlock(passphrase));
    {
        LOCK(wallet_a->cs_wallet);
        wallet_a->m_mint_only_unlocked = true;
    }

    // Assert wallet A is unlocked in mint-only mode
    BOOST_REQUIRE(!wallet_a->IsLocked());
    {
        LOCK(wallet_a->cs_wallet);
        BOOST_REQUIRE(wallet_a->m_mint_only_unlocked);
    }

    // Assert wallet B is still locked and NOT mint-only unlocked
    BOOST_REQUIRE(wallet_b->IsLocked());
    {
        LOCK(wallet_b->cs_wallet);
        BOOST_REQUIRE(!wallet_b->m_mint_only_unlocked);
    }

    // Clean up
    wallet_a->Lock();
    wallet_b->Lock();
}

BOOST_AUTO_TEST_CASE(lock_resets_mint_only_unlocked)
{
    WalletContext context;
    context.chain = m_node.chain.get();
    context.args = m_node.args;

    DatabaseOptions options;
    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;

    SecureString passphrase{"testpassphrase"};
    options.require_create = true;
    options.create_passphrase = passphrase;

    std::shared_ptr<CWallet> wallet = CreateWallet(context, "test_wallet", /*load_on_start=*/false, options, status, error, warnings);
    BOOST_REQUIRE(wallet != nullptr);
    BOOST_REQUIRE(wallet->IsCrypted());
    BOOST_REQUIRE(wallet->IsLocked());

    // Unlock in mint-only mode
    BOOST_REQUIRE(wallet->Unlock(passphrase));
    {
        LOCK(wallet->cs_wallet);
        wallet->m_mint_only_unlocked = true;
    }
    BOOST_REQUIRE(!wallet->IsLocked());
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->m_mint_only_unlocked);
    }

    // Lock the wallet
    BOOST_REQUIRE(wallet->Lock());
    BOOST_REQUIRE(wallet->IsLocked());
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(!wallet->m_mint_only_unlocked);
    }
}

BOOST_AUTO_TEST_CASE(unencrypted_wallet_not_mint_only_unlocked)
{
    WalletContext context;
    context.chain = m_node.chain.get();
    context.args = m_node.args;

    DatabaseOptions options;
    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;

    // Create an unencrypted wallet
    options.require_create = true;
    options.create_passphrase = SecureString{};
    std::shared_ptr<CWallet> wallet = CreateWallet(context, "unencrypted_wallet", /*load_on_start=*/false, options, status, error, warnings);
    BOOST_REQUIRE(wallet != nullptr);
    BOOST_REQUIRE(!wallet->IsCrypted());
    BOOST_REQUIRE(!wallet->IsLocked());

    // m_mint_only_unlocked should remain false for unencrypted wallets
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(!wallet->m_mint_only_unlocked);
    }
}

BOOST_AUTO_TEST_CASE(mint_only_unlock_survives_relock_cycle)
{
    WalletContext context;
    context.chain = m_node.chain.get();
    context.args = m_node.args;

    DatabaseOptions options;
    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;

    SecureString passphrase{"testpassphrase"};
    options.require_create = true;
    options.create_passphrase = passphrase;

    std::shared_ptr<CWallet> wallet = CreateWallet(context, "cycle_wallet", /*load_on_start=*/false, options, status, error, warnings);
    BOOST_REQUIRE(wallet != nullptr);

    // Unlock in mint-only mode
    BOOST_REQUIRE(wallet->Unlock(passphrase));
    {
        LOCK(wallet->cs_wallet);
        wallet->m_mint_only_unlocked = true;
    }
    BOOST_REQUIRE(!wallet->IsLocked());
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->m_mint_only_unlocked);
    }

    // Lock
    BOOST_REQUIRE(wallet->Lock());
    BOOST_REQUIRE(wallet->IsLocked());
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(!wallet->m_mint_only_unlocked);
    }

    // Unlock again in mint-only mode
    BOOST_REQUIRE(wallet->Unlock(passphrase));
    {
        LOCK(wallet->cs_wallet);
        wallet->m_mint_only_unlocked = true;
    }
    BOOST_REQUIRE(!wallet->IsLocked());
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->m_mint_only_unlocked);
    }

    // Unlock again in full mode (not mint-only)
    BOOST_REQUIRE(wallet->Lock());
    BOOST_REQUIRE(wallet->Unlock(passphrase));
    {
        LOCK(wallet->cs_wallet);
        wallet->m_mint_only_unlocked = false;
    }
    BOOST_REQUIRE(!wallet->IsLocked());
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(!wallet->m_mint_only_unlocked);
    }

    wallet->Lock();
}

BOOST_AUTO_TEST_SUITE_END()
