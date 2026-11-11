#ifndef TEST_UTIL_SETUP_COMMON_H
#define TEST_UTIL_SETUP_COMMON_H

#include <chainparamsbase.h>
#include <key.h>
#include <node/caches.h>
#include <node/context.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <random.h>
#include <stdexcept>
#include <util/check.h>
#include <util/fs.h>
#include <util/string.h>
#include <util/system.h>
#include <util/vector.h>

#include <functional>
#include <type_traits>
#include <vector>

class Chainstate;

// Enable BOOST_CHECK_EQUAL for enum class types
namespace std {
template <typename T>
std::ostream& operator<<(typename std::enable_if<std::is_enum<T>::value, std::ostream>::type& stream, const T& e)
{
    return stream << static_cast<typename std::underlying_type<T>::type>(e);
}
} // namespace std

/**
 * This global and the helpers that use it are not thread-safe.
 *
 * If thread-safety is needed, the global could be made thread_local (given
 * that thread_local is supported on all architectures we support) or a
 * per-thread instance could be used in the multi-threaded test.
 */
extern FastRandomContext g_insecure_rand_ctx;

/**
 * Flag to make GetRand in random.h return the same number
 */
extern bool g_mock_deterministic_tests;

enum class SeedRand {
    ZEROS, //!< Seed with a compile time constant of zeros
    SEED,  //!< Call the Seed() helper
};

/** Seed the given random ctx or use the seed passed in via an environment var */
void Seed(FastRandomContext& ctx);

static inline void SeedInsecureRand(SeedRand seed = SeedRand::SEED)
{
    if (seed == SeedRand::ZEROS) {
        g_insecure_rand_ctx = FastRandomContext(/*fDeterministic=*/true);
    } else {
        Seed(g_insecure_rand_ctx);
    }
}

//static constexpr CAmount CENT{10000};

/** Basic testing setup.
 * This just configures logging, data dir and chain parameters.
 */
struct BasicTestingSetup {
    node::NodeContext m_node; // keep as first member to be destructed last

    explicit BasicTestingSetup(const std::string& chainName = CBaseChainParams::MAIN, const std::vector<const char*>& extra_args = {});
    ~BasicTestingSetup();

    const fs::path m_path_root;
    ArgsManager m_args;
};

/** Testing setup that performs all steps up until right before
 * ChainstateManager gets initialized. Meant for testing ChainstateManager
 * initialization behaviour.
 */
struct ChainTestingSetup : public BasicTestingSetup {
    node::CacheSizes m_cache_sizes{};

    explicit ChainTestingSetup(const std::string& chainName = CBaseChainParams::MAIN, const std::vector<const char*>& extra_args = {});
    ~ChainTestingSetup();
};

/** Testing setup that configures a complete environment.
 */
struct TestingSetup : public ChainTestingSetup {
    bool m_coins_db_in_memory{true};
    bool m_block_tree_db_in_memory{true};

    void LoadVerifyActivateChainstate();

    explicit TestingSetup(
        const std::string& chainName = CBaseChainParams::MAIN,
        const std::vector<const char*>& extra_args = {},
        const bool coins_db_in_memory = true,
        const bool block_tree_db_in_memory = true);
};

#endif // TEST_UTIL_SETUP_COMMON_H
