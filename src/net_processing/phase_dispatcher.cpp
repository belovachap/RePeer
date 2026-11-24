// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing/peer_manager_impl.h>
#include <net_processing/constants.h>
#include <kernel.h>
#include <policy/settings.h>

using node::ReadBlockFromDisk;
using node::ReadRawBlockFromDisk;

namespace {
static bool PeerHasHeader(CNodeState *state, const CBlockIndex *pindex) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (state->pindexBestKnownBlock && pindex == state->pindexBestKnownBlock->GetAncestor(pindex->nHeight))
        return true;
    if (state->pindexBestHeaderSent && pindex == state->pindexBestHeaderSent->GetAncestor(pindex->nHeight))
        return true;
    return false;
}

class CompareInvMempoolOrder
{
    CTxMemPool* mp;
    bool m_wtxid_relay;
public:
    explicit CompareInvMempoolOrder(CTxMemPool *_mempool, bool use_wtxid)
    {
        mp = _mempool;
        m_wtxid_relay = use_wtxid;
    }
    bool operator()(std::set<uint256>::iterator a, std::set<uint256>::iterator b)
    {
        return mp->CompareDepthAndScore(*b, *a, m_wtxid_relay);
    }
};
} // namespace

// ============================================================================
// PHASE DISPATCHER
//
// Routes incoming and outgoing messages to the appropriate phase handler.
//
// Phase 1: PRESYNC  - Anti-DoS for low-work headers chains
// Phase 2: HEADERS  - Initial headers sync (getheaders exchange)
// Phase 3: IBD      - Initial block download (full block fetching)
// Phase 4: NORMAL   - Steady-state operation (tx relay, addr relay, etc.)
//
// The dispatcher determines the current phase and routes messages accordingly.
// ============================================================================

arith_uint256 PeerManagerImpl::GetAntiDoSWorkThreshold()
{
    arith_uint256 near_chaintip_work = 0;
    LOCK(cs_main);
    if (m_chainman.ActiveChain().Tip() != nullptr) {
        const CBlockIndex *tip = m_chainman.ActiveChain().Tip();
        near_chaintip_work = tip->nChainTrust - std::min<arith_uint256>(144*GetBlockTrust(*tip), tip->nChainTrust);
    }
    return std::max(near_chaintip_work, m_chainman.MinimumChainWork());
}

PeerManagerImpl::Phase PeerManagerImpl::GetCurrentPhase()
{
    // Phase 4: Normal operations (post-IBD)
    if (!m_chainman.ActiveChainstate().IsInitialBlockDownload()) {
        return Phase::NORMAL;
    }

    // Phase 3: IBD (headers near tip, downloading blocks)
    if (WITH_LOCK(cs_main, return CanDirectFetch())) {
        return Phase::IBD;
    }

    // Phase 2: Headers sync (have headers with sufficient work, but not close to tip)
    if (WITH_LOCK(cs_main, return m_chainman.m_best_header != nullptr &&
        m_chainman.m_best_header->nChainTrust >= m_chainman.MinimumChainWork())) {
        return Phase::HEADERS_SYNC;
    }

    // Phase 1: Presync (no headers with sufficient work yet)
    return Phase::PRESYNC;
}

void PeerManagerImpl::UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload)
{
    SetBestHeight(pindexNew->nHeight);
    SetServiceFlagsIBDCache(!fInitialDownload);

    if (fInitialDownload) return;

    std::vector<uint256> vHashes;
    const CBlockIndex *pindexToAnnounce = pindexNew;
    while (pindexToAnnounce != pindexFork) {
        vHashes.push_back(pindexToAnnounce->GetBlockHash());
        pindexToAnnounce = pindexToAnnounce->pprev;
        if (vHashes.size() == MAX_BLOCKS_TO_ANNOUNCE) {
            break;
        }
    }

    {
        LOCK(m_peer_mutex);
        for (auto& it : m_peer_map) {
            Peer& peer = *it.second;
            LOCK(peer.m_block_inv_mutex);
            for (const uint256& hash : reverse_iterate(vHashes)) {
                peer.m_blocks_for_headers_relay.push_back(hash);
            }
        }
    }

    m_connman.WakeMessageHandler();
}

void PeerManagerImpl::SendPings()
{
    LOCK(m_peer_mutex);
    for(auto& it : m_peer_map) it.second->m_ping_queued = true;
}

bool PeerManagerImpl::ProcessMessages(CNode* pfrom, std::atomic<bool>& interruptMsgProc)
{
    AssertLockHeld(g_msgproc_mutex);

    PeerRef peer = GetPeerRef(pfrom->GetId());
    if (peer == nullptr) return false;

    {
        LOCK(peer->m_getdata_requests_mutex);
        if (!peer->m_getdata_requests.empty()) {
            ProcessGetData(*pfrom, *peer, interruptMsgProc);
        }
    }

    const bool processed_orphan = ProcessOrphanTx(*peer);

    if (pfrom->fDisconnect)
        return false;

    if (processed_orphan) return true;

    {
        LOCK(peer->m_getdata_requests_mutex);
        if (!peer->m_getdata_requests.empty()) return true;
    }

    if (pfrom->fPauseSend) return false;

    auto poll_result{pfrom->PollMessage()};
    if (!poll_result) {
        return false;
    }

    CNetMessage& msg{poll_result->first};
    bool fMoreWork = poll_result->second;

    if (gArgs.GetBoolArg("-capturemessages", false)) {
        CaptureMessage(pfrom->addr, msg.m_type, MakeUCharSpan(msg.m_recv), /*is_incoming=*/true);
    }

    msg.SetVersion(pfrom->GetCommonVersion());

    try {
        ProcessMessage(*pfrom, msg.m_type, msg.m_recv, msg.m_time, interruptMsgProc);
        if (interruptMsgProc) return false;
        {
            LOCK(peer->m_getdata_requests_mutex);
            if (!peer->m_getdata_requests.empty()) fMoreWork = true;
        }
        if (m_orphanage.HaveTxToReconsider(peer->m_id)) fMoreWork = true;
    } catch (const std::exception& e) {
        LogPrint(BCLog::NET, "%s(%s, %u bytes): Exception '%s' (%s) caught\n", __func__, SanitizeString(msg.m_type), msg.m_message_size, e.what(), typeid(e).name());
    } catch (...) {
        LogPrint(BCLog::NET, "%s(%s, %u bytes): Unknown exception caught\n", __func__, SanitizeString(msg.m_type), msg.m_message_size);
    }

    return fMoreWork;
}

void PeerManagerImpl::ProcessMessage(CNode& pfrom, const std::string& msg_type, CDataStream& vRecv,
                                     const std::chrono::microseconds time_received,
                                     const std::atomic<bool>& interruptMsgProc)
{
    AssertLockHeld(g_msgproc_mutex);

    LogPrint(BCLog::NET, "received: %s (%u bytes) peer=%d\n", SanitizeString(msg_type), vRecv.size(), pfrom.GetId());

    PeerRef peer = GetPeerRef(pfrom.GetId());
    if (peer == nullptr) return;

    // set deserialization mode to read PoS flag in headers
    vRecv.SetType(vRecv.GetType() | SER_POSMARKER);

    // --- Handshake messages (phase-independent) ---
    if (msg_type == NetMsgType::VERSION) {
        ProcessVersionMessage(pfrom, *peer, vRecv);
        return;
    }

    if (pfrom.nVersion == 0) {
        LogPrint(BCLog::NET, "non-version message before version handshake. Message \"%s\" from peer=%d\n", SanitizeString(msg_type), pfrom.GetId());
        return;
    }

    if (msg_type == NetMsgType::VERACK) {
        ProcessVerackMessage(pfrom, *peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::WTXIDRELAY) {
        ProcessWtxidRelay(pfrom, *peer);
        return;
    }

    if (msg_type == NetMsgType::SENDADDRV2) {
        ProcessSendAddrV2(pfrom, *peer);
        return;
    }

    if (msg_type == NetMsgType::SENDTXRCNCL) {
        ProcessSendTxRcncl(pfrom, *peer, vRecv);
        return;
    }

    if (!pfrom.fSuccessfullyConnected) {
        LogPrint(BCLog::NET, "Unsupported message \"%s\" prior to verack from peer=%d\n", SanitizeString(msg_type), pfrom.GetId());
        return;
    }

    // --- Phase-dependent message routing ---
    const Phase phase = GetCurrentPhase();

    switch (phase) {
    case Phase::PRESYNC:
        DispatchPresync(pfrom, *peer, msg_type, vRecv, time_received, interruptMsgProc);
        break;
    case Phase::HEADERS_SYNC:
        DispatchHeadersSync(pfrom, *peer, msg_type, vRecv, time_received, interruptMsgProc);
        break;
    case Phase::IBD:
        DispatchIBD(pfrom, *peer, msg_type, vRecv, time_received, interruptMsgProc);
        break;
    case Phase::NORMAL:
        DispatchNormal(pfrom, *peer, msg_type, vRecv, time_received, interruptMsgProc);
        break;
    }
}

void PeerManagerImpl::ProcessVersionMessage(CNode& pfrom, Peer& peer, CDataStream& vRecv)
{
    auto it = mapPoSTemperature.find(pfrom.addr);
    if (it == mapPoSTemperature.end())
        mapPoSTemperature[pfrom.addr] = MAX_CONSECUTIVE_POS_HEADERS/4;
    if (pfrom.nVersion != 0)
    {
        LogPrint(BCLog::NET, "redundant version message from peer=%d\n", pfrom.GetId());
        return;
    }

    int64_t nTime;
    CService addrMe;
    uint64_t nNonce = 1;
    ServiceFlags nServices;
    int nVersion;
    std::string cleanSubVer;
    int starting_height = -1;
    bool fRelay = true;

    vRecv >> nVersion >> Using<CustomUintFormatter<8>>(nServices) >> nTime;
    if (nTime < 0) {
        nTime = 0;
    }
    vRecv.ignore(8);
    vRecv >> addrMe;
    if (!pfrom.IsInboundConn())
    {
        m_addrman.SetServices(pfrom.addr, nServices);
    }
    if (pfrom.ExpectServicesFromConn() && !HasAllDesirableServiceFlags(nServices))
    {
        LogPrint(BCLog::NET, "peer=%d does not offer the expected services (%08x offered, %08x expected); disconnecting\n", pfrom.GetId(), nServices, GetDesirableServiceFlags(nServices));
        pfrom.fDisconnect = true;
        return;
    }

    if (nVersion < MIN_PEER_PROTO_VERSION) {
        LogPrint(BCLog::NET, "peer=%d using obsolete version %i; disconnecting\n", pfrom.GetId(), nVersion);
        pfrom.fDisconnect = true;
        return;
    }

    if (!vRecv.empty()) {
        vRecv.ignore(26);
        vRecv >> nNonce;
    }
    if (!vRecv.empty()) {
        std::string strSubVer;
        vRecv >> LIMITED_STRING(strSubVer, MAX_SUBVERSION_LENGTH);
        cleanSubVer = SanitizeString(strSubVer);
    }
    if (!vRecv.empty()) {
        vRecv >> starting_height;
    }
    if (!vRecv.empty())
        vRecv >> fRelay;
    if (pfrom.IsInboundConn() && !m_connman.CheckIncomingNonce(nNonce))
    {
        LogPrintf("connected to self at %s, disconnecting\n", pfrom.addr.ToStringAddrPort());
        pfrom.fDisconnect = true;
        return;
    }

    if (pfrom.IsInboundConn() && addrMe.IsRoutable())
    {
        SeenLocal(addrMe);
    }

    if (pfrom.IsInboundConn()) {
        PushNodeVersion(pfrom, peer);
    }

    const int greatest_common_version = std::min(nVersion, PROTOCOL_VERSION);
    pfrom.SetCommonVersion(greatest_common_version);
    pfrom.nVersion = nVersion;

    const CNetMsgMaker msg_maker(greatest_common_version);

    if (greatest_common_version >= WTXID_RELAY_VERSION) {
        m_connman.PushMessage(&pfrom, msg_maker.Make(NetMsgType::WTXIDRELAY));
    }

    if (greatest_common_version >= 70016) {
        m_connman.PushMessage(&pfrom, msg_maker.Make(NetMsgType::SENDADDRV2));
    }

    pfrom.m_has_all_wanted_services = HasAllDesirableServiceFlags(nServices);
    peer.m_their_services = nServices;
    pfrom.SetAddrLocal(addrMe);
    {
        LOCK(pfrom.m_subver_mutex);
        pfrom.cleanSubVer = cleanSubVer;
    }
    peer.m_starting_height = starting_height;

    if (!pfrom.IsBlockOnlyConn() &&
        !pfrom.IsFeelerConn() &&
        (fRelay || (peer.m_our_services & NODE_BLOOM))) {
        auto* const tx_relay = peer.SetTxRelay();
        {
            LOCK(tx_relay->m_bloom_filter_mutex);
            tx_relay->m_relay_txs = fRelay;
        }
        if (fRelay) pfrom.m_relays_txs = true;
    }

    if (greatest_common_version >= WTXID_RELAY_VERSION && m_txreconciliation) {
        const auto* tx_relay = peer.GetTxRelay();
        if (tx_relay && WITH_LOCK(tx_relay->m_bloom_filter_mutex, return tx_relay->m_relay_txs) &&
            !pfrom.IsAddrFetchConn() && !m_ignore_incoming_txs) {
            const uint64_t recon_salt = m_txreconciliation->PreRegisterPeer(pfrom.GetId());
            m_connman.PushMessage(&pfrom, msg_maker.Make(NetMsgType::SENDTXRCNCL,
                                                         TXRECONCILIATION_VERSION, recon_salt));
        }
    }

    m_connman.PushMessage(&pfrom, msg_maker.Make(NetMsgType::VERACK));

    {
        LOCK(cs_main);
        CNodeState* state = State(pfrom.GetId());
        state->fPreferredDownload = (!pfrom.IsInboundConn() || pfrom.HasPermission(NetPermissionFlags::NoBan)) && !pfrom.IsAddrFetchConn() && CanServeBlocks(peer);
        m_num_preferred_download_peers += state->fPreferredDownload;
    }

    bool send_getaddr{false};
    if (!pfrom.IsInboundConn()) {
        send_getaddr = SetupAddressRelay(pfrom, peer);
    }
    if (send_getaddr) {
        m_connman.PushMessage(&pfrom, CNetMsgMaker(greatest_common_version).Make(NetMsgType::GETADDR));
        peer.m_getaddr_sent = true;
        peer.m_addr_token_bucket += MAX_ADDR_TO_SEND;
    }

    if (!pfrom.IsInboundConn()) {
        m_addrman.Good(pfrom.addr);
    }

    std::string remoteAddr;
    if (fLogIPs)
        remoteAddr = ", peeraddr=" + pfrom.addr.ToStringAddrPort();

    LogPrint(BCLog::NET, "receive version message: %s: version %d, blocks=%d, us=%s, txrelay=%d, peer=%d%s\n",
              cleanSubVer, pfrom.nVersion,
              peer.m_starting_height, addrMe.ToStringAddrPort(), fRelay, pfrom.GetId(),
              remoteAddr);

    int64_t nTimeOffset = nTime - GetTime();
    pfrom.nTimeOffset = nTimeOffset;
    if (!pfrom.IsInboundConn()) {
        AddTimeData(pfrom.addr, nTimeOffset);
    }

    if (greatest_common_version <= 70012) {
        DataStream finalAlert{ParseHex("60010000000000000000000000ffffff7f0000000ffffff7ffeffff7f01ffffff7f00000000ffffff7f00ffffff7f002f555247454e543a20416c657274206b657920636f6d70726f6d697365642c2075706772616465207265717569726564004630440220653febd6410f470f6bae11cad19c48413becb1ac2c17f908fd0fd53bdc3abd5202206d0e9c96fe88d4a0f01ed9dedae2b6f9e00da94cad0fecaae66ecf689bf71b50")};
        m_connman.PushMessage(&pfrom, CNetMsgMaker(greatest_common_version).Make("alert", finalAlert));
    }

    if (pfrom.IsFeelerConn()) {
        LogPrint(BCLog::NET, "feeler connection completed peer=%d; disconnecting\n", pfrom.GetId());
        pfrom.fDisconnect = true;
    }
}

void PeerManagerImpl::ProcessVerackMessage(CNode& pfrom, Peer& peer, CDataStream& vRecv)
{
    if (pfrom.fSuccessfullyConnected) {
        LogPrint(BCLog::NET, "ignoring redundant verack message from peer=%d\n", pfrom.GetId());
        return;
    }

    if (!pfrom.IsInboundConn()) {
        LogPrintf("New outbound peer connected: version: %d, blocks=%d, peer=%d%s (%s)\n",
                  pfrom.nVersion.load(), peer.m_starting_height,
                  pfrom.GetId(), (fLogIPs ? strprintf(", peeraddr=%s", pfrom.addr.ToStringAddrPort()) : ""),
                  pfrom.ConnectionTypeAsString());
    }

    if (pfrom.GetCommonVersion() >= SHORT_IDS_BLOCKS_VERSION) {
        m_connman.PushMessage(&pfrom, CNetMsgMaker(pfrom.GetCommonVersion()).Make(NetMsgType::SENDCMPCT,
            /*high_bandwidth=*/false, /*version=*/CMPCTBLOCKS_VERSION));
    }

    if (m_txreconciliation) {
        if (!peer.m_wtxid_relay || !m_txreconciliation->IsPeerRegistered(pfrom.GetId())) {
            m_txreconciliation->ForgetPeer(pfrom.GetId());
        }
    }

    if (auto tx_relay = peer.GetTxRelay()) {
        Assume(WITH_LOCK(
            tx_relay->m_tx_inventory_mutex,
            return tx_relay->m_tx_inventory_to_send.empty() &&
                   tx_relay->m_next_inv_send_time == 0s));
    }

    pfrom.fSuccessfullyConnected = true;
}

void PeerManagerImpl::ProcessWtxidRelay(CNode& pfrom, Peer& peer)
{
    if (pfrom.fSuccessfullyConnected) {
        LogPrint(BCLog::NET, "wtxidrelay received after verack from peer=%d; disconnecting\n", pfrom.GetId());
        pfrom.fDisconnect = true;
        return;
    }
    if (pfrom.GetCommonVersion() >= WTXID_RELAY_VERSION) {
        if (!peer.m_wtxid_relay) {
            peer.m_wtxid_relay = true;
            m_wtxid_relay_peers++;
        } else {
            LogPrint(BCLog::NET, "ignoring duplicate wtxidrelay from peer=%d\n", pfrom.GetId());
        }
    } else {
        LogPrint(BCLog::NET, "ignoring wtxidrelay due to old common version=%d from peer=%d\n", pfrom.GetCommonVersion(), pfrom.GetId());
    }
}

void PeerManagerImpl::ProcessSendAddrV2(CNode& pfrom, Peer& peer)
{
    if (pfrom.fSuccessfullyConnected) {
        LogPrint(BCLog::NET, "sendaddrv2 received after verack from peer=%d; disconnecting\n", pfrom.GetId());
        pfrom.fDisconnect = true;
        return;
    }
    peer.m_wants_addrv2 = true;
}

void PeerManagerImpl::ProcessSendTxRcncl(CNode& pfrom, Peer& peer, CDataStream& vRecv)
{
    if (!m_txreconciliation) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "sendtxrcncl from peer=%d ignored, as our node does not have txreconciliation enabled\n", pfrom.GetId());
        return;
    }

    if (pfrom.fSuccessfullyConnected) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "sendtxrcncl received after verack from peer=%d; disconnecting\n", pfrom.GetId());
        pfrom.fDisconnect = true;
        return;
    }

    if (RejectIncomingTxs(pfrom)) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "sendtxrcncl received from peer=%d to which we indicated no tx relay; disconnecting\n", pfrom.GetId());
        pfrom.fDisconnect = true;
        return;
    }

    const auto* tx_relay = peer.GetTxRelay();
    if (!tx_relay || !WITH_LOCK(tx_relay->m_bloom_filter_mutex, return tx_relay->m_relay_txs)) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "sendtxrcncl received from peer=%d which indicated no tx relay to us; disconnecting\n", pfrom.GetId());
        pfrom.fDisconnect = true;
        return;
    }

    uint32_t peer_txreconcl_version;
    uint64_t remote_salt;
    vRecv >> peer_txreconcl_version >> remote_salt;

    const ReconciliationRegisterResult result = m_txreconciliation->RegisterPeer(pfrom.GetId(), pfrom.IsInboundConn(),
                                                                               peer_txreconcl_version, remote_salt);
    switch (result) {
    case ReconciliationRegisterResult::NOT_FOUND:
        LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "Ignore unexpected txreconciliation signal from peer=%d\n", pfrom.GetId());
        break;
    case ReconciliationRegisterResult::SUCCESS:
        break;
    case ReconciliationRegisterResult::ALREADY_REGISTERED:
        LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "txreconciliation protocol violation from peer=%d (sendtxrcncl received from already registered peer); disconnecting\n", pfrom.GetId());
        pfrom.fDisconnect = true;
        return;
    case ReconciliationRegisterResult::PROTOCOL_VIOLATION:
        LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "txreconciliation protocol violation from peer=%d; disconnecting\n", pfrom.GetId());
        pfrom.fDisconnect = true;
        return;
    }
}

void PeerManagerImpl::ProcessGetHeaders(CNode& pfrom, Peer& peer, CDataStream& vRecv)
{
    CBlockLocator locator;
    uint256 hashStop;
    vRecv >> locator >> hashStop;

    if (locator.vHave.size() > MAX_LOCATOR_SZ) {
        LogPrint(BCLog::NET, "getheaders locator size %lld > %d, disconnect peer=%d\n", locator.vHave.size(), MAX_LOCATOR_SZ, pfrom.GetId());
        pfrom.fDisconnect = true;
        return;
    }

    if (m_chainman.m_blockman.LoadingBlocks()) {
        LogPrint(BCLog::NET, "Ignoring getheaders from peer=%d while importing/reindexing\n", pfrom.GetId());
        return;
    }

    LOCK(cs_main);

    if (m_chainman.ActiveTip() == nullptr ||
            (m_chainman.ActiveTip()->nChainTrust < m_chainman.MinimumChainWork() && !pfrom.HasPermission(NetPermissionFlags::Download))) {
        LogPrint(BCLog::NET, "Ignoring getheaders from peer=%d because active chain has too little work; sending empty response\n", pfrom.GetId());
        m_connman.PushMessage(&pfrom, CNetMsgMaker(pfrom.GetCommonVersion()).Make(NetMsgType::HEADERS, std::vector<CBlock>()));
        return;
    }

    CNodeState *nodestate = State(pfrom.GetId());
    const CBlockIndex* pindex = nullptr;
    if (locator.IsNull())
    {
        pindex = m_chainman.m_blockman.LookupBlockIndex(hashStop);
        if (!pindex) {
            return;
        }

        if (!BlockRequestAllowed(pindex)) {
            LogPrint(BCLog::NET, "%s: ignoring request from peer=%i for old block header that isn't in the main chain\n", __func__, pfrom.GetId());
            return;
        }
    }
    else
    {
        pindex = m_chainman.ActiveChainstate().FindForkInGlobalIndex(locator);
        if (pindex)
            pindex = m_chainman.ActiveChain().Next(pindex);
    }

    std::vector<CBlock> vHeaders;
    int nLimit = MAX_HEADERS_RESULTS;
    LogPrint(BCLog::NET, "getheaders %d to %s from peer=%d\n", (pindex ? pindex->nHeight : -1), hashStop.IsNull() ? "end" : hashStop.ToString(), pfrom.GetId());
    for (; pindex; pindex = m_chainman.ActiveChain().Next(pindex))
    {
        vHeaders.push_back(pindex->GetBlockHeader());
        if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
            break;
    }
    nodestate->pindexBestHeaderSent = pindex ? pindex : m_chainman.ActiveChain().Tip();
    m_connman.PushMessage(&pfrom, CNetMsgMaker(pfrom.GetCommonVersion()).Make(NetMsgType::HEADERS, vHeaders));
}

void PeerManagerImpl::ProcessGetBlocks(CNode& pfrom, Peer& peer, CDataStream& vRecv)
{
    CBlockLocator locator;
    uint256 hashStop;
    vRecv >> locator >> hashStop;

    if (locator.vHave.size() > MAX_LOCATOR_SZ) {
        LogPrint(BCLog::NET, "getblocks locator size %lld > %d, disconnect peer=%d\n", locator.vHave.size(), MAX_LOCATOR_SZ, pfrom.GetId());
        pfrom.fDisconnect = true;
        return;
    }

    {
        std::shared_ptr<const CBlock> a_recent_block;
        {
            LOCK(m_most_recent_block_mutex);
            a_recent_block = m_most_recent_block;
        }
        BlockValidationState state;
        if (!m_chainman.ActiveChainstate().ActivateBestChain(state, a_recent_block)) {
            LogPrint(BCLog::NET, "failed to activate chain (%s)\n", state.ToString());
        }
    }

    LOCK(cs_main);

    const CBlockIndex* pindex = m_chainman.ActiveChainstate().FindForkInGlobalIndex(locator);

    if (pindex)
        pindex = m_chainman.ActiveChain().Next(pindex);
    int nLimit = 500;
    LogPrint(BCLog::NET, "getblocks %d to %s limit %d from peer=%d\n", (pindex ? pindex->nHeight : -1), hashStop.IsNull() ? "end" : hashStop.ToString(), nLimit, pfrom.GetId());
    for (; pindex; pindex = m_chainman.ActiveChain().Next(pindex))
    {
        if (pindex->GetBlockHash() == hashStop)
        {
            LogPrint(BCLog::NET, "  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
            if (hashStop != m_chainman.ActiveChain().Tip()->GetBlockHash() && pindex->GetBlockTime() + Params().GetConsensus().nStakeMinAge > m_chainman.ActiveChain().Tip()->GetBlockTime())
                WITH_LOCK(peer.m_block_inv_mutex, peer.m_blocks_for_inv_relay.push_back(pindex->GetBlockHash()));
            break;
        }
        WITH_LOCK(peer.m_block_inv_mutex, peer.m_blocks_for_inv_relay.push_back(pindex->GetBlockHash()));
        if (--nLimit <= 0) {
            LogPrint(BCLog::NET, "  getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
            WITH_LOCK(peer.m_block_inv_mutex, {peer.m_continuation_block = pindex->GetBlockHash();});
            break;
        }
    }
}

void PeerManagerImpl::ProcessInvMessage(CNode& pfrom, Peer& peer, CDataStream& vRecv, const std::atomic<bool>& interruptMsgProc)
{
    std::vector<CInv> vInv;
    vRecv >> vInv;
    if (vInv.size() > MAX_INV_SZ)
    {
        Misbehaving(peer, 20, strprintf("inv message size = %u", vInv.size()));
        return;
    }

    const bool reject_tx_invs{RejectIncomingTxs(pfrom)};

    LOCK(cs_main);

    const auto current_time{GetTime<std::chrono::microseconds>()};
    uint256* best_block{nullptr};

    for (CInv& inv : vInv) {
        if (interruptMsgProc) return;

        if (peer.m_wtxid_relay) {
            if (inv.IsMsgTx()) continue;
        } else {
            if (inv.IsMsgWtx()) continue;
        }

        if (inv.IsMsgBlk()) {
            const bool fAlreadyHave = AlreadyHaveBlock(inv.hash);
            LogPrint(BCLog::NET, "got inv: %s  %s peer=%d\n", inv.ToString(), fAlreadyHave ? "have" : "new", pfrom.GetId());

            UpdateBlockAvailability(pfrom.GetId(), inv.hash);
            if (!fAlreadyHave && !m_chainman.m_blockman.LoadingBlocks() && !IsBlockRequested(inv.hash)) {
                best_block = &inv.hash;
            }
        } else if (inv.IsGenTxMsg()) {
            if (reject_tx_invs) {
                LogPrint(BCLog::NET, "transaction (%s) inv sent in violation of protocol, disconnecting peer=%d\n", inv.hash.ToString(), pfrom.GetId());
                pfrom.fDisconnect = true;
                return;
            }
            const GenTxid gtxid = ToGenTxid(inv);
            const bool fAlreadyHave = AlreadyHaveTx(gtxid);
            LogPrint(BCLog::NET, "got inv: %s  %s peer=%d\n", inv.ToString(), fAlreadyHave ? "have" : "new", pfrom.GetId());

            {
                auto tx_relay = peer.GetTxRelay();
                if (tx_relay) {
                    LOCK(tx_relay->m_tx_inventory_mutex);
                    tx_relay->m_tx_inventory_known_filter.insert(inv.hash);
                }
            }
            if (!fAlreadyHave && !m_chainman.ActiveChainstate().IsInitialBlockDownload()) {
                AddTxAnnouncement(pfrom, gtxid, current_time);
            }
        } else {
            LogPrint(BCLog::NET, "Unknown inv type \"%s\" received from peer=%d\n", inv.ToString(), pfrom.GetId());
        }
    }

    if (best_block != nullptr) {
        CNodeState& state{*Assert(State(pfrom.GetId()))};
        if (state.fSyncStarted || (!peer.m_inv_triggered_getheaders_before_sync && *best_block != m_last_block_inv_triggering_headers_sync)) {
            if (MaybeSendGetHeaders(pfrom, GetLocator(m_chainman.m_best_header), peer)) {
                LogPrint(BCLog::NET, "getheaders (%d) %s to peer=%d\n",
                        m_chainman.m_best_header->nHeight, best_block->ToString(),
                        pfrom.GetId());
            }
            if (!state.fSyncStarted) {
                peer.m_inv_triggered_getheaders_before_sync = true;
                m_last_block_inv_triggering_headers_sync = *best_block;
            }
        }
    }
}

void PeerManagerImpl::ProcessGetDataMessage(CNode& pfrom, Peer& peer, CDataStream& vRecv, const std::atomic<bool>& interruptMsgProc)
{
    std::vector<CInv> vInv;
    vRecv >> vInv;
    if (vInv.size() > MAX_INV_SZ)
    {
        Misbehaving(peer, 20, strprintf("getdata message size = %u", vInv.size()));
        return;
    }

    LogPrint(BCLog::NET, "received getdata (%u invsz) peer=%d\n", vInv.size(), pfrom.GetId());

    if (vInv.size() > 0) {
        LogPrint(BCLog::NET, "received getdata for: %s peer=%d\n", vInv[0].ToString(), pfrom.GetId());
    }

    {
        LOCK(peer.m_getdata_requests_mutex);
        peer.m_getdata_requests.insert(peer.m_getdata_requests.end(), vInv.begin(), vInv.end());
        ProcessGetData(pfrom, peer, interruptMsgProc);
    }
}

void PeerManagerImpl::ProcessTxMessage(CNode& pfrom, Peer& peer, CDataStream& vRecv)
{
    if (RejectIncomingTxs(pfrom)) {
        LogPrint(BCLog::NET, "transaction sent in violation of protocol peer=%d\n", pfrom.GetId());
        pfrom.fDisconnect = true;
        return;
    }

    if (m_chainman.ActiveChainstate().IsInitialBlockDownload()) return;

    CTransactionRef ptx;
    vRecv >> ptx;
    const CTransaction& tx = *ptx;

    const uint256& txid = ptx->GetHash();
    const uint256& wtxid = ptx->GetWitnessHash();

    const uint256& hash = peer.m_wtxid_relay ? wtxid : txid;
    {
        auto tx_relay = peer.GetTxRelay();
        if (tx_relay) {
            LOCK(tx_relay->m_tx_inventory_mutex);
            tx_relay->m_tx_inventory_known_filter.insert(hash);
            if (peer.m_wtxid_relay && txid != wtxid) {
                tx_relay->m_tx_inventory_known_filter.insert(txid);
            }
        }
    }

    LOCK(cs_main);

    m_txrequest.ReceivedResponse(pfrom.GetId(), txid);
    if (tx.HasWitness()) m_txrequest.ReceivedResponse(pfrom.GetId(), wtxid);

    if (AlreadyHaveTx(GenTxid::Wtxid(wtxid))) {
        if (pfrom.HasPermission(NetPermissionFlags::ForceRelay)) {
            if (!m_mempool.exists(GenTxid::Txid(tx.GetHash()))) {
                LogPrintf("Not relaying non-mempool transaction %s from forcerelay peer=%d\n", tx.GetHash().ToString(), pfrom.GetId());
            } else {
                LogPrintf("Force relaying tx %s from peer=%d\n", tx.GetHash().ToString(), pfrom.GetId());
                RelayTransaction(tx.GetHash(), tx.GetWitnessHash());
            }
        }
        return;
    }

    const MempoolAcceptResult result = m_chainman.ProcessTransaction(ptx);
    const TxValidationState& state = result.m_state;

    if (result.m_result_type == MempoolAcceptResult::ResultType::VALID) {
        m_txrequest.ForgetTxHash(tx.GetHash());
        m_txrequest.ForgetTxHash(tx.GetWitnessHash());
        RelayTransaction(tx.GetHash(), tx.GetWitnessHash());
        m_orphanage.AddChildrenToWorkSet(tx);

        pfrom.m_last_tx_time = GetTime<std::chrono::seconds>();

        LogPrint(BCLog::MEMPOOL, "AcceptToMemoryPool: peer=%d: accepted %s (poolsz %u txn, %u kB)\n",
            pfrom.GetId(),
            tx.GetHash().ToString(),
            m_mempool.size(), m_mempool.DynamicMemoryUsage() / 1000);

        for (const CTransactionRef& removedTx : result.m_replaced_transactions.value()) {
            AddToCompactExtraTransactions(removedTx);
        }
    }
    else if (state.GetResult() == TxValidationResult::TX_MISSING_INPUTS)
    {
        bool fRejectedParents = false;

        std::vector<uint256> unique_parents;
        unique_parents.reserve(tx.vin.size());
        for (const CTxIn& txin : tx.vin) {
            unique_parents.push_back(txin.prevout.hash);
        }
        std::sort(unique_parents.begin(), unique_parents.end());
        unique_parents.erase(std::unique(unique_parents.begin(), unique_parents.end()), unique_parents.end());
        for (const uint256& parent_txid : unique_parents) {
            if (m_recent_rejects.contains(parent_txid)) {
                fRejectedParents = true;
                break;
            }
        }
        if (!fRejectedParents) {
            const auto current_time{GetTime<std::chrono::microseconds>()};

            for (const uint256& parent_txid : unique_parents) {
                const auto gtxid{GenTxid::Txid(parent_txid)};
                {
                    auto tx_relay = peer.GetTxRelay();
                    if (tx_relay) {
                        LOCK(tx_relay->m_tx_inventory_mutex);
                        tx_relay->m_tx_inventory_known_filter.insert(parent_txid);
                    }
                }
                if (!AlreadyHaveTx(gtxid)) AddTxAnnouncement(pfrom, gtxid, current_time);
            }

            if (m_orphanage.AddTx(ptx, pfrom.GetId())) {
                AddToCompactExtraTransactions(ptx);
            }

            m_txrequest.ForgetTxHash(tx.GetHash());
            m_txrequest.ForgetTxHash(tx.GetWitnessHash());

            unsigned int nMaxOrphanTx = (unsigned int)std::max((int64_t)0, gArgs.GetIntArg("-maxorphantx", DEFAULT_MAX_ORPHAN_TRANSACTIONS));
            m_orphanage.LimitOrphans(nMaxOrphanTx);
        } else {
            LogPrint(BCLog::MEMPOOL, "not keeping orphan with rejected parents %s\n",tx.GetHash().ToString());
            m_recent_rejects.insert(tx.GetHash());
            m_recent_rejects.insert(tx.GetWitnessHash());
            m_txrequest.ForgetTxHash(tx.GetHash());
            m_txrequest.ForgetTxHash(tx.GetWitnessHash());
        }
    } else {
        if (state.GetResult() != TxValidationResult::TX_WITNESS_STRIPPED) {
            m_recent_rejects.insert(tx.GetWitnessHash());
            m_txrequest.ForgetTxHash(tx.GetWitnessHash());
            if (state.GetResult() == TxValidationResult::TX_INPUTS_NOT_STANDARD && tx.GetWitnessHash() != tx.GetHash()) {
                m_recent_rejects.insert(tx.GetHash());
                m_txrequest.ForgetTxHash(tx.GetHash());
            }
            if (RecursiveDynamicUsage(*ptx) < 100000) {
                AddToCompactExtraTransactions(ptx);
            }
        }
    }

    if (state.IsInvalid()) {
        LogPrint(BCLog::MEMPOOLREJ, "%s from peer=%d was not accepted: %s\n", tx.GetHash().ToString(),
            pfrom.GetId(),
            state.ToString());
        MaybePunishNodeForTx(pfrom.GetId(), state);
    }
}

void PeerManagerImpl::ProcessGetBlockTxn(CNode& pfrom, Peer& peer, CDataStream& vRecv)
{
    BlockTransactionsRequest req;
    vRecv >> req;

    std::shared_ptr<const CBlock> recent_block;
    {
        LOCK(m_most_recent_block_mutex);
        if (m_most_recent_block_hash == req.blockhash)
            recent_block = m_most_recent_block;
    }
    if (recent_block) {
        SendBlockTransactions(pfrom, peer, *recent_block, req);
        return;
    }

    {
        LOCK(cs_main);

        const CBlockIndex* pindex = m_chainman.m_blockman.LookupBlockIndex(req.blockhash);
        if (!pindex || !(pindex->nStatus & BLOCK_HAVE_DATA)) {
            LogPrint(BCLog::NET, "Peer %d sent us a getblocktxn for a block we don't have\n", pfrom.GetId());
            return;
        }

        if (pindex->nHeight >= m_chainman.ActiveChain().Height() - MAX_BLOCKTXN_DEPTH) {
            CBlock block;
            bool ret = ReadBlockFromDisk(block, pindex, m_chainparams.GetConsensus());
            assert(ret);

            SendBlockTransactions(pfrom, peer, block, req);
            return;
        }
    }

    LogPrint(BCLog::NET, "Peer %d sent us a getblocktxn for a block > %i deep\n", pfrom.GetId(), MAX_BLOCKTXN_DEPTH);
    CInv inv{MSG_WITNESS_BLOCK, req.blockhash};
    WITH_LOCK(peer.m_getdata_requests_mutex, peer.m_getdata_requests.push_back(inv));
}

void PeerManagerImpl::ProcessMempool(CNode& pfrom, Peer& peer)
{
    if (!(peer.m_our_services & NODE_BLOOM) && !pfrom.HasPermission(NetPermissionFlags::Mempool))
    {
        if (!pfrom.HasPermission(NetPermissionFlags::NoBan))
        {
            LogPrint(BCLog::NET, "mempool request with bloom filters disabled, disconnect peer=%d\n", pfrom.GetId());
            pfrom.fDisconnect = true;
        }
        return;
    }

    if (m_connman.OutboundTargetReached(false) && !pfrom.HasPermission(NetPermissionFlags::Mempool))
    {
        if (!pfrom.HasPermission(NetPermissionFlags::NoBan))
        {
            LogPrint(BCLog::NET, "mempool request with bandwidth limit reached, disconnect peer=%d\n", pfrom.GetId());
            pfrom.fDisconnect = true;
        }
        return;
    }

    if (auto tx_relay = peer.GetTxRelay(); tx_relay != nullptr) {
        LOCK(tx_relay->m_tx_inventory_mutex);
        tx_relay->m_send_mempool = true;
    }
}

void PeerManagerImpl::ProcessPing(CNode& pfrom, Peer& peer, CDataStream& vRecv)
{
    if (pfrom.GetCommonVersion() > BIP0031_VERSION) {
        uint64_t nonce = 0;
        vRecv >> nonce;
        m_connman.PushMessage(&pfrom, CNetMsgMaker(pfrom.GetCommonVersion()).Make(NetMsgType::PONG, nonce));
    }
}

void PeerManagerImpl::ProcessPong(CNode& pfrom, Peer& peer, CDataStream& vRecv, const std::chrono::microseconds time_received)
{
    const auto ping_end = time_received;
    uint64_t nonce = 0;
    size_t nAvail = vRecv.in_avail();
    bool bPingFinished = false;
    std::string sProblem;

    if (nAvail >= sizeof(nonce)) {
        vRecv >> nonce;

        if (peer.m_ping_nonce_sent != 0) {
            if (nonce == peer.m_ping_nonce_sent) {
                bPingFinished = true;
                const auto ping_time = ping_end - peer.m_ping_start.load();
                if (ping_time.count() >= 0) {
                    pfrom.PongReceived(ping_time);
                } else {
                    sProblem = "Timing mishap";
                }
            } else {
                sProblem = "Nonce mismatch";
                if (nonce == 0) {
                    bPingFinished = true;
                    sProblem = "Nonce zero";
                }
            }
        } else {
            sProblem = "Unsolicited pong without ping";
        }
    } else {
        bPingFinished = true;
        sProblem = "Short payload";
    }

    if (!(sProblem.empty())) {
        LogPrint(BCLog::NET, "pong peer=%d: %s, %x expected, %x received, %u bytes\n",
            pfrom.GetId(),
            sProblem,
            peer.m_ping_nonce_sent,
            nonce,
            nAvail);
    }
    if (bPingFinished) {
        peer.m_ping_nonce_sent = 0;
    }
}

void PeerManagerImpl::ProcessAddrMessage(CNode& pfrom, Peer& peer, CDataStream& vRecv, const std::atomic<bool>& interruptMsgProc, const std::string& msg_type)
{
    int stream_version = vRecv.GetVersion();
    if (msg_type == NetMsgType::ADDRV2) {
        stream_version |= ADDRV2_FORMAT;
    }

    OverrideStream<CDataStream> s(&vRecv, vRecv.GetType(), stream_version);
    std::vector<CAddress> vAddr;

    s >> vAddr;

    if (!SetupAddressRelay(pfrom, peer)) {
        LogPrint(BCLog::NET, "ignoring %s message from %s peer=%d\n", "addr", pfrom.ConnectionTypeAsString(), pfrom.GetId());
        return;
    }

    if (vAddr.size() > MAX_ADDR_TO_SEND)
    {
        Misbehaving(peer, 20, strprintf("addr message size = %u", vAddr.size()));
        return;
    }

    std::vector<CAddress> vAddrOk;
    const auto current_a_time{Now<NodeSeconds>()};

    const auto current_time{GetTime<std::chrono::microseconds>()};
    if (peer.m_addr_token_bucket < MAX_ADDR_PROCESSING_TOKEN_BUCKET) {
        const auto time_diff = std::max(current_time - peer.m_addr_token_timestamp, 0us);
        const double increment = Ticks<SecondsDouble>(time_diff) * MAX_ADDR_RATE_PER_SECOND;
        peer.m_addr_token_bucket = std::min<double>(peer.m_addr_token_bucket + increment, MAX_ADDR_PROCESSING_TOKEN_BUCKET);
    }
    peer.m_addr_token_timestamp = current_time;

    const bool rate_limited = !pfrom.HasPermission(NetPermissionFlags::Addr);
    uint64_t num_proc = 0;
    uint64_t num_rate_limit = 0;
    Shuffle(vAddr.begin(), vAddr.end(), FastRandomContext());
    for (CAddress& addr : vAddr)
    {
        if (interruptMsgProc)
            return;

        if (peer.m_addr_token_bucket < 1.0) {
            if (rate_limited) {
                ++num_rate_limit;
                continue;
            }
        } else {
            peer.m_addr_token_bucket -= 1.0;
        }
        if (!MayHaveUsefulAddressDB(addr.nServices) && !HasAllDesirableServiceFlags(addr.nServices))
            continue;

        if (addr.nTime <= NodeSeconds{100000000s} || addr.nTime > current_a_time + 10min) {
            addr.nTime = current_a_time - 5 * 24h;
        }
        AddAddressKnown(peer, addr);
        if (m_banman && (m_banman->IsDiscouraged(addr) || m_banman->IsBanned(addr))) {
            continue;
        }
        ++num_proc;
        bool fReachable = IsReachable(addr);
        if (addr.nTime > current_a_time - 10min && !peer.m_getaddr_sent && vAddr.size() <= 10 && addr.IsRoutable()) {
            RelayAddress(pfrom.GetId(), addr, fReachable);
        }
        if (fReachable)
            vAddrOk.push_back(addr);
    }
    peer.m_addr_processed += num_proc;
    peer.m_addr_rate_limited += num_rate_limit;
    LogPrint(BCLog::NET, "Received addr: %u addresses (%u processed, %u rate-limited) from peer=%d\n",
             vAddr.size(), num_proc, num_rate_limit, pfrom.GetId());

    m_addrman.Add(vAddrOk, pfrom.addr, 2h);
    if (vAddr.size() < 1000) peer.m_getaddr_sent = false;

    if (pfrom.IsAddrFetchConn() && vAddr.size() > 1) {
        LogPrint(BCLog::NET, "addrfetch connection completed peer=%d; disconnecting\n", pfrom.GetId());
        pfrom.fDisconnect = true;
    }
}

void PeerManagerImpl::ProcessFeeFilter(CNode& pfrom, Peer& peer, CDataStream& vRecv)
{
    CAmount newFeeFilter = 0;
    vRecv >> newFeeFilter;
    if (MoneyRange(newFeeFilter)) {
        if (auto tx_relay = peer.GetTxRelay(); tx_relay != nullptr) {
            tx_relay->m_fee_filter_received = newFeeFilter;
        }
        LogPrint(BCLog::NET, "received: feefilter of %d satoshi from peer=%d\n", newFeeFilter, pfrom.GetId());
    }
}

void PeerManagerImpl::ProcessFilterLoad(CNode& pfrom, Peer& peer, CDataStream& vRecv)
{
    if (!(peer.m_our_services & NODE_BLOOM)) {
        LogPrint(BCLog::NET, "filterload received despite not offering bloom services from peer=%d; disconnecting\n", pfrom.GetId());
        pfrom.fDisconnect = true;
        return;
    }
    CBloomFilter filter;
    vRecv >> filter;

    if (!filter.IsWithinSizeConstraints())
    {
        Misbehaving(peer, 100, "too-large bloom filter");
    } else if (auto tx_relay = peer.GetTxRelay(); tx_relay != nullptr) {
        {
            LOCK(tx_relay->m_bloom_filter_mutex);
            tx_relay->m_bloom_filter.reset(new CBloomFilter(filter));
            tx_relay->m_relay_txs = true;
        }
        pfrom.m_bloom_filter_loaded = true;
        pfrom.m_relays_txs = true;
    }
}

void PeerManagerImpl::ProcessFilterAdd(CNode& pfrom, Peer& peer, CDataStream& vRecv)
{
    if (!(peer.m_our_services & NODE_BLOOM)) {
        LogPrint(BCLog::NET, "filteradd received despite not offering bloom services from peer=%d; disconnecting\n", pfrom.GetId());
        pfrom.fDisconnect = true;
        return;
    }
    std::vector<unsigned char> vData;
    vRecv >> vData;

    bool bad = false;
    if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE) {
        bad = true;
    } else if (auto tx_relay = peer.GetTxRelay(); tx_relay != nullptr) {
        LOCK(tx_relay->m_bloom_filter_mutex);
        if (tx_relay->m_bloom_filter) {
            tx_relay->m_bloom_filter->insert(vData);
        } else {
            bad = true;
        }
    }
    if (bad) {
        Misbehaving(peer, 100, "bad filteradd message");
    }
}

void PeerManagerImpl::ProcessFilterClear(CNode& pfrom, Peer& peer)
{
    if (!(peer.m_our_services & NODE_BLOOM)) {
        LogPrint(BCLog::NET, "filterclear received despite not offering bloom services from peer=%d; disconnecting\n", pfrom.GetId());
        pfrom.fDisconnect = true;
        return;
    }
    auto tx_relay = peer.GetTxRelay();
    if (!tx_relay) return;

    {
        LOCK(tx_relay->m_bloom_filter_mutex);
        tx_relay->m_bloom_filter = nullptr;
        tx_relay->m_relay_txs = true;
    }
    pfrom.m_bloom_filter_loaded = false;
    pfrom.m_relays_txs = true;
}

void PeerManagerImpl::ProcessNotFound(CNode& pfrom, Peer& peer, CDataStream& vRecv)
{
    std::vector<CInv> vInv;
    vRecv >> vInv;
    if (vInv.size() <= MAX_PEER_TX_ANNOUNCEMENTS + MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
        LOCK(::cs_main);
        for (CInv &inv : vInv) {
            if (inv.IsGenTxMsg()) {
                m_txrequest.ReceivedResponse(pfrom.GetId(), inv.hash);
            }
        }
    }
}

void PeerManagerImpl::ProcessSendCmpct(CNode& pfrom, Peer& peer, CDataStream& vRecv)
{
    bool sendcmpct_hb{false};
    uint64_t sendcmpct_version{0};
    vRecv >> sendcmpct_hb >> sendcmpct_version;

    if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;

    LOCK(cs_main);
    CNodeState* nodestate = State(pfrom.GetId());
    nodestate->m_provides_cmpctblocks = true;
    nodestate->m_requested_hb_cmpctblocks = sendcmpct_hb;
    pfrom.m_bip152_highbandwidth_from = sendcmpct_hb;
}

void PeerManagerImpl::DispatchPresync(CNode& pfrom, Peer& peer, const std::string& msg_type,
                                       CDataStream& vRecv, const std::chrono::microseconds time_received,
                                       const std::atomic<bool>& interruptMsgProc)
{
    // Phase 1: Only handle headers and basic protocol messages
    if (msg_type == NetMsgType::HEADERS) {
        std::vector<CBlockHeader> headers;
        unsigned int nCount = ReadCompactSize(vRecv);
        if (nCount > MAX_HEADERS_RESULTS) {
            Misbehaving(peer, 20, strprintf("headers message size = %u", nCount));
            return;
        }
        headers.resize(nCount);
        {
            LOCK(cs_main);
            int32_t& nPoSTemperature = mapPoSTemperature[pfrom.addr];
            int nTmpPoSTemperature = nPoSTemperature;
            for (unsigned int n = 0; n < nCount; n++) {
                vRecv >> headers[n];
                ReadCompactSize(vRecv); // ignore tx count
                ReadCompactSize(vRecv); // vchBlockSig
                bool fPoS = headers[n].nFlags & CBlockIndex::BLOCK_PROOF_OF_STAKE;
                nTmpPoSTemperature += fPoS ? 1 : -POW_HEADER_COOLING;
                if (n == 0 && !fPoS && headers[n].hashPrevBlock != pfrom.lastAcceptedHeader)
                    nTmpPoSTemperature += POW_HEADER_COOLING;
                nTmpPoSTemperature = std::max(nTmpPoSTemperature, 0);
                if (nTmpPoSTemperature >= MAX_CONSECUTIVE_POS_HEADERS) {
                    nPoSTemperature = (MAX_CONSECUTIVE_POS_HEADERS*3)/4;
                    if (Params().NetworkIDString() != "test") {
                        Misbehaving(peer, 100, "too many consecutive pos headers");
                        return;
                    }
                }
            }
        }
        ProcessHeadersMessage(pfrom, peer, std::move(headers), /*via_compact_block=*/false);
        return;
    }

    if (msg_type == NetMsgType::GETHEADERS) {
        ProcessGetHeaders(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::GETBLOCKS) {
        ProcessGetBlocks(pfrom, peer, vRecv);
        return;
    }

    // Ignore all other messages during presync
    LogPrint(BCLog::NET, "Ignoring message \"%s\" during presync from peer=%d\n", SanitizeString(msg_type), pfrom.GetId());
}

void PeerManagerImpl::DispatchHeadersSync(CNode& pfrom, Peer& peer, const std::string& msg_type,
                                           CDataStream& vRecv, const std::chrono::microseconds time_received,
                                           const std::atomic<bool>& interruptMsgProc)
{
    // Phase 2: Handle headers and basic block requests
    if (msg_type == NetMsgType::HEADERS) {
        peer.m_last_getheaders_timestamp = {};
        std::vector<CBlockHeader> headers;
        unsigned int nCount = ReadCompactSize(vRecv);
        if (nCount > MAX_HEADERS_RESULTS) {
            Misbehaving(peer, 20, strprintf("headers message size = %u", nCount));
            return;
        }
        headers.resize(nCount);
        {
            LOCK(cs_main);
            int32_t& nPoSTemperature = mapPoSTemperature[pfrom.addr];
            int nTmpPoSTemperature = nPoSTemperature;
            for (unsigned int n = 0; n < nCount; n++) {
                vRecv >> headers[n];
                ReadCompactSize(vRecv);
                ReadCompactSize(vRecv);
                bool fPoS = headers[n].nFlags & CBlockIndex::BLOCK_PROOF_OF_STAKE;
                nTmpPoSTemperature += fPoS ? 1 : -POW_HEADER_COOLING;
                if (n == 0 && !fPoS && headers[n].hashPrevBlock != pfrom.lastAcceptedHeader)
                    nTmpPoSTemperature += POW_HEADER_COOLING;
                nTmpPoSTemperature = std::max(nTmpPoSTemperature, 0);
                if (nTmpPoSTemperature >= MAX_CONSECUTIVE_POS_HEADERS) {
                    nPoSTemperature = (MAX_CONSECUTIVE_POS_HEADERS*3)/4;
                    if (Params().NetworkIDString() != "test") {
                        Misbehaving(peer, 100, "too many consecutive pos headers");
                        return;
                    }
                }
            }
        }
        ProcessHeadersMessage(pfrom, peer, std::move(headers), /*via_compact_block=*/false);
        return;
    }

    if (msg_type == NetMsgType::GETHEADERS) {
        ProcessGetHeaders(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::GETBLOCKS) {
        ProcessGetBlocks(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::INV) {
        ProcessInvMessage(pfrom, peer, vRecv, interruptMsgProc);
        return;
    }

    if (msg_type == NetMsgType::GETDATA) {
        ProcessGetDataMessage(pfrom, peer, vRecv, interruptMsgProc);
        return;
    }

    if (msg_type == NetMsgType::PING) {
        ProcessPing(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::PONG) {
        ProcessPong(pfrom, peer, vRecv, time_received);
        return;
    }

    if (msg_type == NetMsgType::ADDR || msg_type == NetMsgType::ADDRV2) {
        ProcessAddrMessage(pfrom, peer, vRecv, interruptMsgProc, msg_type);
        return;
    }

    LogPrint(BCLog::NET, "Ignoring message \"%s\" during headers sync from peer=%d\n", SanitizeString(msg_type), pfrom.GetId());
}

void PeerManagerImpl::DispatchIBD(CNode& pfrom, Peer& peer, const std::string& msg_type,
                                    CDataStream& vRecv, const std::chrono::microseconds time_received,
                                    const std::atomic<bool>& interruptMsgProc)
{
    // Phase 3: Handle blocks and block-related messages during IBD
    if (msg_type == NetMsgType::HEADERS) {
        peer.m_last_getheaders_timestamp = {};
        std::vector<CBlockHeader> headers;
        unsigned int nCount = ReadCompactSize(vRecv);
        if (nCount > MAX_HEADERS_RESULTS) {
            Misbehaving(peer, 20, strprintf("headers message size = %u", nCount));
            return;
        }
        headers.resize(nCount);
        {
            LOCK(cs_main);
            int32_t& nPoSTemperature = mapPoSTemperature[pfrom.addr];
            int nTmpPoSTemperature = nPoSTemperature;
            for (unsigned int n = 0; n < nCount; n++) {
                vRecv >> headers[n];
                ReadCompactSize(vRecv);
                ReadCompactSize(vRecv);
                bool fPoS = headers[n].nFlags & CBlockIndex::BLOCK_PROOF_OF_STAKE;
                nTmpPoSTemperature += fPoS ? 1 : -POW_HEADER_COOLING;
                if (n == 0 && !fPoS && headers[n].hashPrevBlock != pfrom.lastAcceptedHeader)
                    nTmpPoSTemperature += POW_HEADER_COOLING;
                nTmpPoSTemperature = std::max(nTmpPoSTemperature, 0);
                if (nTmpPoSTemperature >= MAX_CONSECUTIVE_POS_HEADERS) {
                    nPoSTemperature = (MAX_CONSECUTIVE_POS_HEADERS*3)/4;
                    if (Params().NetworkIDString() != "test") {
                        Misbehaving(peer, 100, "too many consecutive pos headers");
                        return;
                    }
                }
            }
        }
        ProcessHeadersMessage(pfrom, peer, std::move(headers), /*via_compact_block=*/false);
        return;
    }

    if (msg_type == NetMsgType::BLOCK) {
        ProcessPhase3Block(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::CMPCTBLOCK) {
        ProcessPhase3CMPCTBlock(pfrom, peer, vRecv, time_received, interruptMsgProc);
        return;
    }

    if (msg_type == NetMsgType::GETDATA) {
        std::vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ) {
            Misbehaving(peer, 20, strprintf("getdata message size = %u", vInv.size()));
            return;
        }
        for (const CInv& inv : vInv) {
            if (inv.IsGenBlkMsg()) {
                ProcessPhase3GetData(pfrom, peer, inv);
            }
            // Ignore tx getdata during IBD
        }
        return;
    }

    if (msg_type == NetMsgType::GETHEADERS) {
        ProcessGetHeaders(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::GETBLOCKS) {
        ProcessGetBlocks(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::INV) {
        ProcessInvMessage(pfrom, peer, vRecv, interruptMsgProc);
        return;
    }

    if (msg_type == NetMsgType::PING) {
        ProcessPing(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::PONG) {
        ProcessPong(pfrom, peer, vRecv, time_received);
        return;
    }

    if (msg_type == NetMsgType::ADDR || msg_type == NetMsgType::ADDRV2) {
        ProcessAddrMessage(pfrom, peer, vRecv, interruptMsgProc, msg_type);
        return;
    }

    LogPrint(BCLog::NET, "Ignoring message \"%s\" during IBD from peer=%d\n", SanitizeString(msg_type), pfrom.GetId());
}

void PeerManagerImpl::DispatchNormal(CNode& pfrom, Peer& peer, const std::string& msg_type,
                                      CDataStream& vRecv, const std::chrono::microseconds time_received,
                                      const std::atomic<bool>& interruptMsgProc)
{
    // Phase 4: Full message handling for normal operations
    if (msg_type == NetMsgType::HEADERS) {
        peer.m_last_getheaders_timestamp = {};
        std::vector<CBlockHeader> headers;
        unsigned int nCount = ReadCompactSize(vRecv);
        if (nCount > MAX_HEADERS_RESULTS) {
            Misbehaving(peer, 20, strprintf("headers message size = %u", nCount));
            return;
        }
        headers.resize(nCount);
        {
            LOCK(cs_main);
            int32_t& nPoSTemperature = mapPoSTemperature[pfrom.addr];
            int nTmpPoSTemperature = nPoSTemperature;
            for (unsigned int n = 0; n < nCount; n++) {
                vRecv >> headers[n];
                ReadCompactSize(vRecv);
                ReadCompactSize(vRecv);
                bool fPoS = headers[n].nFlags & CBlockIndex::BLOCK_PROOF_OF_STAKE;
                nTmpPoSTemperature += fPoS ? 1 : -POW_HEADER_COOLING;
                if (n == 0 && !fPoS && headers[n].hashPrevBlock != pfrom.lastAcceptedHeader)
                    nTmpPoSTemperature += POW_HEADER_COOLING;
                nTmpPoSTemperature = std::max(nTmpPoSTemperature, 0);
                if (nTmpPoSTemperature >= MAX_CONSECUTIVE_POS_HEADERS) {
                    nPoSTemperature = (MAX_CONSECUTIVE_POS_HEADERS*3)/4;
                    if (Params().NetworkIDString() != "test") {
                        Misbehaving(peer, 100, "too many consecutive pos headers");
                        return;
                    }
                }
            }
        }
        ProcessHeadersMessage(pfrom, peer, std::move(headers), /*via_compact_block=*/false);
        return;
    }

    if (msg_type == NetMsgType::CMPCTBLOCK) {
        ProcessCMPCTBlock(pfrom, peer, vRecv, time_received, interruptMsgProc);
        return;
    }

    if (msg_type == NetMsgType::BLOCKTXN) {
        ProcessBLOCKTXN(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::TX) {
        ProcessTxMessage(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::INV) {
        ProcessInvMessage(pfrom, peer, vRecv, interruptMsgProc);
        return;
    }

    if (msg_type == NetMsgType::GETDATA) {
        ProcessGetDataMessage(pfrom, peer, vRecv, interruptMsgProc);
        return;
    }

    if (msg_type == NetMsgType::GETBLOCKTXN) {
        ProcessGetBlockTxn(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::GETHEADERS) {
        ProcessGetHeaders(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::GETBLOCKS) {
        ProcessGetBlocks(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::GETCFILTERS) {
        ProcessGetCFilters(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::GETCFHEADERS) {
        ProcessGetCFHeaders(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::GETCFCHECKPT) {
        ProcessGetCFCheckPt(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::ADDR || msg_type == NetMsgType::ADDRV2) {
        ProcessAddrMessage(pfrom, peer, vRecv, interruptMsgProc, msg_type);
        return;
    }

    if (msg_type == NetMsgType::MEMPOOL) {
        ProcessMempool(pfrom, peer);
        return;
    }

    if (msg_type == NetMsgType::PING) {
        ProcessPing(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::PONG) {
        ProcessPong(pfrom, peer, vRecv, time_received);
        return;
    }

    if (msg_type == NetMsgType::FEEFILTER) {
        ProcessFeeFilter(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::FILTERLOAD) {
        ProcessFilterLoad(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::FILTERADD) {
        ProcessFilterAdd(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::FILTERCLEAR) {
        ProcessFilterClear(pfrom, peer);
        return;
    }

    if (msg_type == NetMsgType::NOTFOUND) {
        ProcessNotFound(pfrom, peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::SENDHEADERS) {
        peer.m_prefers_headers = true;
        return;
    }

    if (msg_type == NetMsgType::SENDCMPCT) {
        ProcessSendCmpct(pfrom, peer, vRecv);
        return;
    }

    // Ignore unknown commands for extensibility
    LogPrint(BCLog::NET, "Unknown command \"%s\" from peer=%d\n", SanitizeString(msg_type), pfrom.GetId());
}

bool PeerManagerImpl::SendMessages(CNode* pto)
{
    AssertLockHeld(g_msgproc_mutex);

    PeerRef peer = GetPeerRef(pto->GetId());
    if (!peer) return false;

    // Always check for disconnection first
    if (MaybeDiscourageAndDisconnect(*pto, *peer)) return true;

    if (!pto->fSuccessfullyConnected || pto->fDisconnect)
        return true;

    const auto current_time{GetTime<std::chrono::microseconds>()};

    // Ping handling is phase-independent
    MaybeSendPing(*pto, *peer, current_time);
    if (pto->fDisconnect) return true;
    if (pto->IsAddrFetchConn() && current_time - pto->m_connected > 10 * AVG_ADDRESS_BROADCAST_INTERVAL) {
        LogPrint(BCLog::NET, "addrfetch connection timeout; disconnecting peer=%d\n", pto->GetId());
        pto->fDisconnect = true;
        return true;
    }

    const Phase phase = GetCurrentPhase();

    switch (phase) {
    case Phase::PRESYNC:
    case Phase::HEADERS_SYNC:
        // During presync/headers-sync, only send getheaders
        SendHeadersSyncMessages(pto, *peer, current_time);
        break;
    case Phase::IBD:
        // During IBD, only send block getdata
        Phase3SendMessages(pto);
        break;
    case Phase::NORMAL:
        // Full message sending in normal phase
        SendNormalMessages(pto, *peer, current_time);
        break;
    }

    return true;
}

void PeerManagerImpl::MaybeSendPing(CNode& node_to, Peer& peer, std::chrono::microseconds now)
{
    if (m_connman.ShouldRunInactivityChecks(node_to, std::chrono::duration_cast<std::chrono::seconds>(now)) &&
        peer.m_ping_nonce_sent &&
        now > peer.m_ping_start.load() + TIMEOUT_INTERVAL)
    {
        LogPrint(BCLog::NET, "ping timeout: %fs peer=%d\n", 0.000001 * count_microseconds(now - peer.m_ping_start.load()), peer.m_id);
        node_to.fDisconnect = true;
        return;
    }

    const CNetMsgMaker msgMaker(node_to.GetCommonVersion());
    bool pingSend = false;

    if (peer.m_ping_queued) {
        pingSend = true;
    }

    if (peer.m_ping_nonce_sent == 0 && now > peer.m_ping_start.load() + PING_INTERVAL) {
        pingSend = true;
    }

    if (pingSend) {
        uint64_t nonce;
        do {
            nonce = GetRand<uint64_t>();
        } while (nonce == 0);
        peer.m_ping_queued = false;
        peer.m_ping_start = now;
        if (node_to.GetCommonVersion() > BIP0031_VERSION) {
            peer.m_ping_nonce_sent = nonce;
            m_connman.PushMessage(&node_to, msgMaker.Make(NetMsgType::PING, nonce));
        } else {
            peer.m_ping_nonce_sent = 0;
            m_connman.PushMessage(&node_to, msgMaker.Make(NetMsgType::PING));
        }
    }
}

void PeerManagerImpl::MaybeSendSendHeaders(CNode& node, Peer& peer)
{
    if (!peer.m_sent_sendheaders && node.GetCommonVersion() >= SENDHEADERS_VERSION) {
        LOCK(cs_main);
        CNodeState &state = *State(node.GetId());
        if (state.pindexBestKnownBlock != nullptr &&
                state.pindexBestKnownBlock->nChainTrust > m_chainman.MinimumChainWork()) {
            m_connman.PushMessage(&node, CNetMsgMaker(node.GetCommonVersion()).Make(NetMsgType::SENDHEADERS));
            peer.m_sent_sendheaders = true;
        }
    }
}

std::chrono::microseconds PeerManagerImpl::NextInvToInbounds(std::chrono::microseconds now,
                                                             std::chrono::seconds average_interval)
{
    if (m_next_inv_to_inbounds.load() < now) {
        m_next_inv_to_inbounds = GetExponentialRand(now, average_interval);
    }
    return m_next_inv_to_inbounds;
}

void PeerManagerImpl::SendHeadersSyncMessages(CNode* pto, Peer& peer, std::chrono::microseconds current_time)
{
    const CNetMsgMaker msgMaker(pto->GetCommonVersion());

    LOCK(cs_main);
    CNodeState& state = *State(pto->GetId());

    // Start block sync
    if (m_chainman.m_best_header == nullptr) {
        m_chainman.m_best_header = m_chainman.ActiveChain().Tip();
    }

    bool sync_blocks_and_headers_from_peer = false;
    if (state.fPreferredDownload) {
        sync_blocks_and_headers_from_peer = true;
    } else if (CanServeBlocks(peer) && !pto->IsAddrFetchConn()) {
        if (m_num_preferred_download_peers == 0 || mapBlocksInFlight.empty()) {
            sync_blocks_and_headers_from_peer = true;
        }
    }

    if (!state.fSyncStarted && CanServeBlocks(peer) && !m_chainman.m_blockman.LoadingBlocks()) {
        if ((nSyncStarted == 0 && sync_blocks_and_headers_from_peer) || m_chainman.m_best_header->Time() > GetAdjustedTime() - 24h) {
            const CBlockIndex* pindexStart = m_chainman.m_best_header;
            if (pindexStart->pprev)
                pindexStart = pindexStart->pprev;
            if (MaybeSendGetHeaders(*pto, GetLocator(pindexStart), peer)) {
                LogPrint(BCLog::NET, "initial getheaders (%d) to peer=%d (startheight:%d)\n", pindexStart->nHeight, pto->GetId(), peer.m_starting_height);
                state.fSyncStarted = true;
                peer.m_headers_sync_timeout = current_time + HEADERS_DOWNLOAD_TIMEOUT_BASE +
                    std::chrono::microseconds{HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER} *
                    Ticks<std::chrono::seconds>(GetAdjustedTime() - m_chainman.m_best_header->Time()) / m_chainparams.GetConsensus().nPowTargetSpacing;
                nSyncStarted++;
            }
        }
    }

    // Headers sync timeout check
    if (state.fSyncStarted && peer.m_headers_sync_timeout < std::chrono::microseconds::max()) {
        if (m_chainman.m_best_header->Time() <= GetAdjustedTime() - 24h) {
            if (current_time > peer.m_headers_sync_timeout && nSyncStarted == 1 && (m_num_preferred_download_peers - state.fPreferredDownload >= 1)) {
                if (!pto->HasPermission(NetPermissionFlags::NoBan)) {
                    LogPrintf("Timeout downloading headers from peer=%d, disconnecting\n", pto->GetId());
                    pto->fDisconnect = true;
                } else {
                    LogPrintf("Timeout downloading headers from noban peer=%d, not disconnecting\n", pto->GetId());
                    state.fSyncStarted = false;
                    nSyncStarted--;
                    peer.m_headers_sync_timeout = 0us;
                }
            }
        } else {
            peer.m_headers_sync_timeout = std::chrono::microseconds::max();
        }
    }

    ConsiderEviction(*pto, peer, GetTime<std::chrono::seconds>());
}

void PeerManagerImpl::SendNormalMessages(CNode* pto, Peer& peer, std::chrono::microseconds current_time)
{
    const Consensus::Params& consensusParams = m_chainparams.GetConsensus();
    const CNetMsgMaker msgMaker(pto->GetCommonVersion());

    MaybeSendAddr(*pto, peer, current_time);
    MaybeSendSendHeaders(*pto, peer);

    {
        LOCK(cs_main);
        CNodeState& state = *State(pto->GetId());

        // Try sending block announcements via headers
        {
            LOCK(peer.m_block_inv_mutex);
            std::vector<CBlock> vHeaders;
            bool fRevertToInv = ((!peer.m_prefers_headers &&
                                 (!state.m_requested_hb_cmpctblocks || peer.m_blocks_for_headers_relay.size() > 1)) ||
                                 peer.m_blocks_for_headers_relay.size() > MAX_BLOCKS_TO_ANNOUNCE);
            const CBlockIndex* pBestIndex = nullptr;
            ProcessBlockAvailability(pto->GetId());

            if (!fRevertToInv) {
                bool fFoundStartingHeader = false;
                for (const uint256& hash : peer.m_blocks_for_headers_relay) {
                    const CBlockIndex* pindex = m_chainman.m_blockman.LookupBlockIndex(hash);
                    assert(pindex);
                    if (m_chainman.ActiveChain()[pindex->nHeight] != pindex) {
                        fRevertToInv = true;
                        break;
                    }
                    if (pBestIndex != nullptr && pindex->pprev != pBestIndex) {
                        fRevertToInv = true;
                        break;
                    }
                    pBestIndex = pindex;
                    if (fFoundStartingHeader) {
                        vHeaders.push_back(pindex->GetBlockHeader());
                    } else if (PeerHasHeader(&state, pindex)) {
                        continue;
                    } else if (pindex->pprev == nullptr || PeerHasHeader(&state, pindex->pprev)) {
                        fFoundStartingHeader = true;
                        vHeaders.push_back(pindex->GetBlockHeader());
                    } else {
                        fRevertToInv = true;
                        break;
                    }
                }
            }
            if (!fRevertToInv && !vHeaders.empty()) {
                if (vHeaders.size() == 1 && state.m_requested_hb_cmpctblocks) {
                    LogPrint(BCLog::NET, "%s sending header-and-ids %s to peer=%d\n", __func__,
                            vHeaders.front().GetHash().ToString(), pto->GetId());
                    std::optional<CSerializedNetMsg> cached_cmpctblock_msg;
                    {
                        LOCK(m_most_recent_block_mutex);
                        if (m_most_recent_block_hash == pBestIndex->GetBlockHash()) {
                            cached_cmpctblock_msg = msgMaker.Make(NetMsgType::CMPCTBLOCK, *m_most_recent_compact_block);
                        }
                    }
                    if (cached_cmpctblock_msg.has_value()) {
                        m_connman.PushMessage(pto, std::move(cached_cmpctblock_msg.value()));
                    } else {
                        CBlock block;
                        bool ret = ReadBlockFromDisk(block, pBestIndex, consensusParams);
                        assert(ret);
                        CBlockHeaderAndShortTxIDs cmpctblock{block};
                        m_connman.PushMessage(pto, msgMaker.Make(NetMsgType::CMPCTBLOCK, cmpctblock));
                    }
                    state.pindexBestHeaderSent = pBestIndex;
                } else if (peer.m_prefers_headers) {
                    m_connman.PushMessage(pto, msgMaker.Make(NetMsgType::HEADERS, vHeaders));
                    state.pindexBestHeaderSent = pBestIndex;
                } else {
                    fRevertToInv = true;
                }
            }
            if (fRevertToInv) {
                if (!peer.m_blocks_for_headers_relay.empty()) {
                    const uint256& hashToAnnounce = peer.m_blocks_for_headers_relay.back();
                    const CBlockIndex* pindex = m_chainman.m_blockman.LookupBlockIndex(hashToAnnounce);
                    assert(pindex);
                    if (m_chainman.ActiveChain()[pindex->nHeight] != pindex) {
                        LogPrint(BCLog::NET, "Announcing block %s not on main chain (tip=%s)\n",
                            hashToAnnounce.ToString(), m_chainman.ActiveChain().Tip()->GetBlockHash().ToString());
                    }
                    if (!PeerHasHeader(&state, pindex)) {
                        peer.m_blocks_for_inv_relay.push_back(hashToAnnounce);
                        LogPrint(BCLog::NET, "%s: sending inv peer=%d hash=%s\n", __func__,
                            pto->GetId(), hashToAnnounce.ToString());
                    }
                }
            }
            peer.m_blocks_for_headers_relay.clear();
        }

        // Message: inventory
        std::vector<CInv> vInv;
        {
            LOCK(peer.m_block_inv_mutex);
            vInv.reserve(std::max<size_t>(peer.m_blocks_for_inv_relay.size(), INVENTORY_BROADCAST_MAX));
            for (const uint256& hash : peer.m_blocks_for_inv_relay) {
                vInv.push_back(CInv(MSG_BLOCK, hash));
                if (vInv.size() == MAX_INV_SZ) {
                    m_connman.PushMessage(pto, msgMaker.Make(NetMsgType::INV, vInv));
                    vInv.clear();
                }
            }
            peer.m_blocks_for_inv_relay.clear();
        }

        if (auto tx_relay = peer.GetTxRelay(); tx_relay != nullptr) {
            LOCK(tx_relay->m_tx_inventory_mutex);
            bool fSendTrickle = pto->HasPermission(NetPermissionFlags::NoBan);
            if (tx_relay->m_next_inv_send_time < current_time) {
                fSendTrickle = true;
                if (pto->IsInboundConn()) {
                    tx_relay->m_next_inv_send_time = NextInvToInbounds(current_time, INBOUND_INVENTORY_BROADCAST_INTERVAL);
                } else {
                    tx_relay->m_next_inv_send_time = GetExponentialRand(current_time, OUTBOUND_INVENTORY_BROADCAST_INTERVAL);
                }
            }
            if (fSendTrickle) {
                LOCK(tx_relay->m_bloom_filter_mutex);
                if (!tx_relay->m_relay_txs) tx_relay->m_tx_inventory_to_send.clear();
            }
            if (fSendTrickle && tx_relay->m_send_mempool) {
                auto vtxinfo = m_mempool.infoAll();
                tx_relay->m_send_mempool = false;
                CAmount filterrate = 0;
                LOCK(tx_relay->m_bloom_filter_mutex);
                for (const auto& txinfo : vtxinfo) {
                    const uint256& hash = peer.m_wtxid_relay ? txinfo.tx->GetWitnessHash() : txinfo.tx->GetHash();
                    CInv inv(peer.m_wtxid_relay ? MSG_WTX : MSG_TX, hash);
                    tx_relay->m_tx_inventory_to_send.erase(hash);
                    if (filterrate && txinfo.fee < filterrate) continue;
                    if (tx_relay->m_bloom_filter) {
                        if (!tx_relay->m_bloom_filter->IsRelevantAndUpdate(*txinfo.tx)) continue;
                    }
                    tx_relay->m_tx_inventory_known_filter.insert(hash);
                    vInv.push_back(inv);
                    if (vInv.size() == MAX_INV_SZ) {
                        m_connman.PushMessage(pto, msgMaker.Make(NetMsgType::INV, vInv));
                        vInv.clear();
                    }
                }
                tx_relay->m_last_mempool_req = std::chrono::duration_cast<std::chrono::seconds>(current_time);
            }
            if (fSendTrickle) {
                std::vector<std::set<uint256>::iterator> vInvTx;
                vInvTx.reserve(tx_relay->m_tx_inventory_to_send.size());
                for (std::set<uint256>::iterator it = tx_relay->m_tx_inventory_to_send.begin(); it != tx_relay->m_tx_inventory_to_send.end(); it++) {
                    vInvTx.push_back(it);
                }
                CAmount filterrate = 0;
                CompareInvMempoolOrder compareInvMempoolOrder(&m_mempool, peer.m_wtxid_relay);
                std::make_heap(vInvTx.begin(), vInvTx.end(), compareInvMempoolOrder);
                unsigned int nRelayedTransactions = 0;
                LOCK(tx_relay->m_bloom_filter_mutex);
                size_t broadcast_max{INVENTORY_BROADCAST_MAX + (tx_relay->m_tx_inventory_to_send.size()/1000)*5};
                broadcast_max = std::min<size_t>(1000, broadcast_max);
                while (!vInvTx.empty() && nRelayedTransactions < broadcast_max) {
                    std::pop_heap(vInvTx.begin(), vInvTx.end(), compareInvMempoolOrder);
                    std::set<uint256>::iterator it = vInvTx.back();
                    vInvTx.pop_back();
                    uint256 hash = *it;
                    CInv inv(peer.m_wtxid_relay ? MSG_WTX : MSG_TX, hash);
                    tx_relay->m_tx_inventory_to_send.erase(it);
                    if (tx_relay->m_tx_inventory_known_filter.contains(hash)) continue;
                    auto txinfo = m_mempool.info(ToGenTxid(inv));
                    if (!txinfo.tx) continue;
                    auto txid = txinfo.tx->GetHash();
                    auto wtxid = txinfo.tx->GetWitnessHash();
                    if (filterrate && txinfo.fee < filterrate) continue;
                    if (tx_relay->m_bloom_filter && !tx_relay->m_bloom_filter->IsRelevantAndUpdate(*txinfo.tx)) continue;
                    tx_relay->m_recently_announced_invs.insert(hash);
                    vInv.push_back(inv);
                    nRelayedTransactions++;
                    {
                        while (!g_relay_expiration.empty() && g_relay_expiration.front().first < current_time) {
                            mapRelay.erase(g_relay_expiration.front().second);
                            g_relay_expiration.pop_front();
                        }
                        auto ret = mapRelay.emplace(txid, std::move(txinfo.tx));
                        if (ret.second) {
                            g_relay_expiration.emplace_back(current_time + RELAY_TX_CACHE_TIME, ret.first);
                        }
                        auto ret2 = mapRelay.emplace(wtxid, ret.first->second);
                        if (ret2.second) {
                            g_relay_expiration.emplace_back(current_time + RELAY_TX_CACHE_TIME, ret2.first);
                        }
                    }
                    if (vInv.size() == MAX_INV_SZ) {
                        m_connman.PushMessage(pto, msgMaker.Make(NetMsgType::INV, vInv));
                        vInv.clear();
                    }
                    tx_relay->m_tx_inventory_known_filter.insert(hash);
                    if (hash != txid) {
                        tx_relay->m_tx_inventory_known_filter.insert(txid);
                    }
                }
            }
        }
        if (!vInv.empty())
            m_connman.PushMessage(pto, msgMaker.Make(NetMsgType::INV, vInv));

        // Detect whether we're stalling
        auto stalling_timeout = m_block_stalling_timeout.load();
        if (state.m_stalling_since.count() && state.m_stalling_since < current_time - stalling_timeout) {
            LogPrintf("Peer=%d is stalling block download, disconnecting\n", pto->GetId());
            pto->fDisconnect = true;
            const auto new_timeout = std::min(2 * stalling_timeout, BLOCK_STALLING_TIMEOUT_MAX);
            if (stalling_timeout != new_timeout && m_block_stalling_timeout.compare_exchange_strong(stalling_timeout, new_timeout)) {
                LogPrint(BCLog::NET, "Increased stalling timeout temporarily to %d seconds\n", count_seconds(new_timeout));
            }
            return;
        }
        if (state.vBlocksInFlight.size() > 0) {
            QueuedBlock& queuedBlock = state.vBlocksInFlight.front();
            int nOtherPeersWithValidatedDownloads = m_peers_downloading_from - 1;
            if (current_time > state.m_downloading_since + std::chrono::seconds{consensusParams.nPowTargetSpacing} * (BLOCK_DOWNLOAD_TIMEOUT_BASE + BLOCK_DOWNLOAD_TIMEOUT_PER_PEER * nOtherPeersWithValidatedDownloads)) {
                LogPrintf("Timeout downloading block %s from peer=%d, disconnecting\n", queuedBlock.pindex->GetBlockHash().ToString(), pto->GetId());
                pto->fDisconnect = true;
                return;
            }
        }

        // Check for headers sync timeouts
        if (state.fSyncStarted && peer.m_headers_sync_timeout < std::chrono::microseconds::max()) {
            if (m_chainman.m_best_header->Time() <= GetAdjustedTime() - 24h) {
                if (current_time > peer.m_headers_sync_timeout && nSyncStarted == 1 && (m_num_preferred_download_peers - state.fPreferredDownload >= 1)) {
                    if (!pto->HasPermission(NetPermissionFlags::NoBan)) {
                        LogPrintf("Timeout downloading headers from peer=%d, disconnecting\n", pto->GetId());
                        pto->fDisconnect = true;
                        return;
                    } else {
                        LogPrintf("Timeout downloading headers from noban peer=%d, not disconnecting\n", pto->GetId());
                        state.fSyncStarted = false;
                        nSyncStarted--;
                        peer.m_headers_sync_timeout = 0us;
                    }
                }
            } else {
                peer.m_headers_sync_timeout = std::chrono::microseconds::max();
            }
        }

        ConsiderEviction(*pto, peer, GetTime<std::chrono::seconds>());

        // Message: getdata (blocks)
        std::vector<CInv> vGetData;
        bool sync_blocks_and_headers_from_peer = state.fPreferredDownload ||
            (CanServeBlocks(peer) && !pto->IsAddrFetchConn() &&
             (m_num_preferred_download_peers == 0 || mapBlocksInFlight.empty()));
        if (CanServeBlocks(peer) && ((sync_blocks_and_headers_from_peer && !IsLimitedPeer(peer)) || !m_chainman.ActiveChainstate().IsInitialBlockDownload()) && state.vBlocksInFlight.size() < MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
            std::vector<const CBlockIndex*> vToDownload;
            NodeId staller = -1;
            FindNextBlocksToDownload(peer, MAX_BLOCKS_IN_TRANSIT_PER_PEER - state.vBlocksInFlight.size(), vToDownload, staller);
            for (const CBlockIndex* pindex : vToDownload) {
                uint32_t nFetchFlags = IsBTC16BIPsEnabled(pindex->nTime) ? GetFetchFlags(peer) : false;
                vGetData.push_back(CInv(MSG_BLOCK | nFetchFlags, pindex->GetBlockHash()));
                BlockRequested(pto->GetId(), *pindex);
                LogPrint(BCLog::NET, "Requesting block %s (%d) peer=%d\n", pindex->GetBlockHash().ToString(),
                    pindex->nHeight, pto->GetId());
            }
            if (state.vBlocksInFlight.empty() && staller != -1) {
                if (State(staller)->m_stalling_since == 0us) {
                    State(staller)->m_stalling_since = current_time;
                    LogPrint(BCLog::NET, "Stall started peer=%d\n", staller);
                }
            }
        }

        // Message: getdata (transactions)
        std::vector<std::pair<NodeId, GenTxid>> expired;
        auto requestable = m_txrequest.GetRequestable(pto->GetId(), current_time, &expired);
        for (const auto& entry : expired) {
            LogPrint(BCLog::NET, "timeout of inflight %s %s from peer=%d\n", entry.second.IsWtxid() ? "wtx" : "tx",
                entry.second.GetHash().ToString(), entry.first);
        }
        for (const GenTxid& gtxid : requestable) {
            if (!AlreadyHaveTx(gtxid)) {
                LogPrint(BCLog::NET, "Requesting %s %s peer=%d\n", gtxid.IsWtxid() ? "wtx" : "tx",
                    gtxid.GetHash().ToString(), pto->GetId());
                vGetData.emplace_back(gtxid.IsWtxid() ? MSG_WTX : (MSG_TX | GetFetchFlags(peer)), gtxid.GetHash());
                if (vGetData.size() >= MAX_GETDATA_SZ) {
                    m_connman.PushMessage(pto, msgMaker.Make(NetMsgType::GETDATA, vGetData));
                    vGetData.clear();
                }
                m_txrequest.RequestedTx(pto->GetId(), gtxid.GetHash(), current_time + GETDATA_TX_INTERVAL);
            } else {
                m_txrequest.ForgetTxHash(gtxid.GetHash());
            }
        }

        if (!vGetData.empty())
            m_connman.PushMessage(pto, msgMaker.Make(NetMsgType::GETDATA, vGetData));
    } // release cs_main
}
