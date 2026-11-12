#include <test/util/setup_common.h>

#include <kernel/validation_cache_sizes.h>

#include <addrman.h>
#include <banman.h>
#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <init.h>
#include <init/common.h>
#include <interfaces/chain.h>
#include <kernel/mempool_entry.h>
#include <net.h>
#include <net_processing.h>
#include <node/blockstorage.h>
#include <node/chainstate.h>
#include <node/context.h>
#include <node/mempool_args.h>
#include <node/miner.h>
#include <node/validation_cache_args.h>
#include <noui.h>
#include <policy/fees.h>
#include <policy/fees_args.h>
#include <pow.h>
#include <scheduler.h>
#include <script/sigcache.h>
#include <shutdown.h>
#include <streams.h>
#include <timedata.h>
#include <txdb.h>
#include <txmempool.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/thread.h>
#include <util/threadnames.h>
#include <util/time.h>
#include <util/translation.h>
#include <util/vector.h>
#include <validation.h>
#include <validationinterface.h>
#include <walletinitinterface.h>

#include <algorithm>
#include <functional>
#include <stdexcept>

using kernel::ValidationCacheSizes;
using node::ApplyArgsManOptions;
using node::BlockAssembler;
using node::CalculateCacheSizes;
using node::LoadChainstate;
using node::RegenerateCommitments;
using node::VerifyLoadedChainstate;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

FastRandomContext g_insecure_rand_ctx;
/** Random context to get unique temp data dirs. Separate from g_insecure_rand_ctx, which can be seeded from a const env var */
static FastRandomContext g_insecure_rand_ctx_temp_path;

/** Return the unsigned from the environment var if available, otherwise 0 */
static uint256 GetUintFromEnv(const std::string& env_name)
{
    const char* num = std::getenv(env_name.c_str());
    if (!num) return {};
    return uint256S(num);
}

void Seed(FastRandomContext& ctx)
{
    // Should be enough to get the seed once for the process
    static uint256 seed{};
    static const std::string RANDOM_CTX_SEED{"RANDOM_CTX_SEED"};
    if (seed.IsNull()) seed = GetUintFromEnv(RANDOM_CTX_SEED);
    if (seed.IsNull()) seed = GetRandHash();
    LogPrintf("%s: Setting random seed for current tests to %s=%s\n", __func__, RANDOM_CTX_SEED, seed.GetHex());
    ctx = FastRandomContext(seed);
}

std::ostream& operator<<(std::ostream& os, const uint256& num)
{
    os << num.ToString();
    return os;
}

BasicTestingSetup::BasicTestingSetup(const std::string& chainName, const std::vector<const char*>& extra_args)
    : m_path_root{fs::temp_directory_path() / "test_common_" PACKAGE_NAME / g_insecure_rand_ctx_temp_path.rand256().ToString()},
      m_args{}
{
    m_node.args = &gArgs;
    std::vector<const char*> arguments = Cat(
        {
            "dummy",
            "-printtoconsole=0",
            "-logsourcelocations",
            "-logtimemicros",
            "-logthreadnames",
            "-loglevel=trace",
            "-debug",
            "-debugexclude=leveldb",
        },
        extra_args);
    util::ThreadRename("test");
    fs::create_directories(m_path_root);
    m_args.ForceSetArg("-datadir", fs::PathToString(m_path_root));
    gArgs.ForceSetArg("-datadir", fs::PathToString(m_path_root));
    gArgs.ClearPathCache();
    {
        SetupServerArgs(*m_node.args);
        std::string error;
        if (!m_node.args->ParseParameters(arguments.size(), arguments.data(), error)) {
            m_node.args->ClearArgs();
            throw std::runtime_error{error};
        }
    }
    SelectParams(chainName);
    SeedInsecureRand();
    InitLogging(*m_node.args);
    AppInitParameterInteraction(*m_node.args);
    LogInstance().StartLogging();
    m_node.kernel = std::make_unique<kernel::Context>();
    SetupEnvironment();
    SetupNetworking();

    ValidationCacheSizes validation_cache_sizes{};
    ApplyArgsManOptions(*m_node.args, validation_cache_sizes);
    Assert(InitSignatureCache(validation_cache_sizes.signature_cache_bytes));
    Assert(InitScriptExecutionCache(validation_cache_sizes.script_execution_cache_bytes));

    m_node.chain = interfaces::MakeChain(m_node);
    static bool noui_connected = false;
    if (!noui_connected) {
        noui_connect();
        noui_connected = true;
    }
}

BasicTestingSetup::~BasicTestingSetup()
{
    SetMockTime(0s); // Reset mocktime for following tests
    LogInstance().DisconnectTestLogger();
    fs::remove_all(m_path_root);
    gArgs.ClearArgs();
}

ChainTestingSetup::ChainTestingSetup(const std::string& chainName, const std::vector<const char*>& extra_args)
    : BasicTestingSetup(chainName, extra_args)
{
    const CChainParams& chainparams = Params();

    // We have to run a scheduler thread to prevent ActivateBestChain
    // from blocking due to queue overrun.
    m_node.scheduler = std::make_unique<CScheduler>();
    m_node.scheduler->m_service_thread = std::thread(util::TraceThread, "scheduler", [&] { m_node.scheduler->serviceQueue(); });
    GetMainSignals().RegisterBackgroundSignalScheduler(*m_node.scheduler);

    {
        CTxMemPool::Options opts;
        opts.max_size_bytes = 300000000;
        opts.expiry = std::chrono::hours{24};
        opts.require_standard = true;
        opts.permit_bare_multisig = false;
        opts.max_datacarrier_bytes = 80;
        m_node.mempool = std::make_unique<CTxMemPool>(opts);
    }

    m_cache_sizes = CalculateCacheSizes(m_args);

    const ChainstateManager::Options chainman_opts{
        .chainparams = chainparams,
        .datadir = m_args.GetDataDirNet(),
        .adjusted_time_callback = GetAdjustedTime,
        .check_block_index = true,
    };
    m_node.chainman = std::make_unique<ChainstateManager>(chainman_opts, node::BlockManager::Options{});
    m_node.chainman->m_blockman.m_block_tree_db = std::make_unique<CBlockTreeDB>(DBParams{
        .path = m_args.GetDataDirNet() / "blocks" / "index",
        .cache_bytes = static_cast<size_t>(m_cache_sizes.block_tree_db),
        .memory_only = true});

    constexpr int script_check_threads = 2;
    StartScriptCheckWorkerThreads(script_check_threads);
}

ChainTestingSetup::~ChainTestingSetup()
{
    if (m_node.scheduler) m_node.scheduler->stop();
    StopScriptCheckWorkerThreads();
    GetMainSignals().FlushBackgroundCallbacks();
    GetMainSignals().UnregisterBackgroundSignalScheduler();
    m_node.connman.reset();
    m_node.banman.reset();
    m_node.addrman.reset();
    m_node.netgroupman.reset();
    m_node.args = nullptr;
    m_node.mempool.reset();
    m_node.scheduler.reset();
    m_node.chainman.reset();
}

void TestingSetup::LoadVerifyActivateChainstate()
{
    auto& chainman{*Assert(m_node.chainman)};
    node::ChainstateLoadOptions options;
    options.mempool = Assert(m_node.mempool.get());
    options.block_tree_db_in_memory = m_block_tree_db_in_memory;
    options.coins_db_in_memory = m_coins_db_in_memory;
    options.reindex = node::fReindex;
    options.reindex_chainstate = m_args.GetBoolArg("-reindex-chainstate", false);
    options.prune = chainman.m_blockman.IsPruneMode();
    options.check_blocks = m_args.GetIntArg("-checkblocks", DEFAULT_CHECKBLOCKS);
    options.check_level = m_args.GetIntArg("-checklevel", DEFAULT_CHECKLEVEL);
    options.require_full_verification = m_args.IsArgSet("-checkblocks") || m_args.IsArgSet("-checklevel");
    auto [status, error] = LoadChainstate(chainman, m_cache_sizes, options);
    assert(status == node::ChainstateLoadStatus::SUCCESS);

    std::tie(status, error) = VerifyLoadedChainstate(chainman, options);
    assert(status == node::ChainstateLoadStatus::SUCCESS);

    BlockValidationState state;
    if (!chainman.ActiveChainstate().ActivateBestChain(state)) {
        throw std::runtime_error(strprintf("ActivateBestChain failed. (%s)", state.ToString()));
    }
}

TestingSetup::TestingSetup(
    const std::string& chainName,
    const std::vector<const char*>& extra_args,
    const bool coins_db_in_memory,
    const bool block_tree_db_in_memory)
    : ChainTestingSetup(chainName, extra_args),
      m_coins_db_in_memory(coins_db_in_memory),
      m_block_tree_db_in_memory(block_tree_db_in_memory)
{
    LoadVerifyActivateChainstate();

    m_node.netgroupman = std::make_unique<NetGroupManager>(/*asmap=*/std::vector<bool>());
    m_node.addrman = std::make_unique<AddrMan>(*m_node.netgroupman,
                                               /*deterministic=*/false,
                                               m_node.args->GetIntArg("-checkaddrman", 0));
    m_node.banman = std::make_unique<BanMan>(m_args.GetDataDirBase() / "banlist", nullptr, DEFAULT_MISBEHAVING_BANTIME);
    m_node.connman = std::make_unique<CConnman>(0x1337, 0x1337, *m_node.addrman, *m_node.netgroupman);
    m_node.peerman = PeerManager::make(*m_node.connman, *m_node.addrman,
                                       m_node.banman.get(), *m_node.chainman,
                                       *m_node.mempool, false);
    {
        CConnman::Options options;
        options.m_msgproc = m_node.peerman.get();
        m_node.connman->Init(options);
    }
}
