#include <test/util/wallet.h>

namespace wallet {

std::unique_ptr<WalletDatabase> CreateMockableWalletDatabase()
{
    return std::make_unique<MockableDatabase>();
}

} // namespace wallet
