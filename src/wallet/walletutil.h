// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_WALLETUTIL_H
#define BITCOIN_WALLET_WALLETUTIL_H

#include <script/descriptor.h>
#include <util/fs.h>

#include <vector>

namespace wallet {
//! Get the path of the wallet directory.
fs::path GetWalletDir();

/** Descriptor with some wallet metadata */
class WalletDescriptor
{
public:
    std::shared_ptr<Descriptor> descriptor;
    uint64_t creation_time = 0;
    int32_t range_start = 0; // First item in range; start of range, inclusive, i.e. [range_start, range_end). This never changes.
    int32_t range_end = 0; // Item after the last; end of range, exclusive, i.e. [range_start, range_end). This will increment with each TopUp()
    int32_t next_index = 0; // Position of the next item to generate
    DescriptorCache cache;

    void DeserializeDescriptor(const std::string& str)
    {
        std::string error;
        FlatSigningProvider keys;
        descriptor = Parse(str, keys, error, true);
        if (!descriptor) {
            throw std::ios_base::failure("Invalid descriptor: " + error);
        }
    }

    SERIALIZE_METHODS(WalletDescriptor, obj)
    {
        std::string descriptor_str;
        SER_WRITE(obj, descriptor_str = obj.descriptor->ToString());
        READWRITE(descriptor_str, obj.creation_time, obj.next_index, obj.range_start, obj.range_end);
        SER_READ(obj, obj.DeserializeDescriptor(descriptor_str));
    }

    WalletDescriptor() {}
    WalletDescriptor(std::shared_ptr<Descriptor> descriptor, uint64_t creation_time, int32_t range_start, int32_t range_end, int32_t next_index) : descriptor(descriptor), creation_time(creation_time), range_start(range_start), range_end(range_end), next_index(next_index) {}
};

class CWallet;
class DescriptorScriptPubKeyMan;

/** struct containing information needed for migrating legacy wallets to descriptor wallets */
struct MigrationData
{
    CExtKey master_key;
    std::vector<std::pair<std::string, int64_t>> watch_descs;
    std::vector<std::pair<std::string, int64_t>> solvable_descs;
    std::vector<std::unique_ptr<DescriptorScriptPubKeyMan>> desc_spkms;
    std::shared_ptr<CWallet> watchonly_wallet{nullptr};
    std::shared_ptr<CWallet> solvable_wallet{nullptr};
};
} // namespace wallet

#endif // BITCOIN_WALLET_WALLETUTIL_H
