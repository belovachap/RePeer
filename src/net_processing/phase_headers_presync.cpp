// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing/peer_manager_impl.h>
#include <net_processing/constants.h>

// ============================================================================
// PHASE 1: PRESYNC BLOCKHEADERS (PARALLEL MULTI-PEER)
//
// Purpose: Download ALL block headers from peers all the way to the tip.
// Entry:   Always the first phase. Headers are downloaded until the peer
//          signals they have no more (sends < MAX_HEADERS_RESULTS).
// Exit:    When the peer has sent all their headers (indicated by a
//          non-full batch), meaning we've reached the tip.
//
// This phase is completely isolated from all other phases. It coordinates
// header downloads across ALL connected peers simultaneously, tracking
// in-flight requests and retrying failures. Each peer is assigned a
// distinct contiguous range of headers to fetch in parallel.
// ============================================================================

// --- Global presync completion signal ---
// Set to true once we have downloaded all headers to the tip.
// All other phases check this before processing headers normally.
std::atomic<bool> g_headers_presync_complete{false};

// --- Shared presync coordination state (protected by m_headers_presync_mutex) ---

/**
 * Represents a contiguous range of headers that a peer is responsible for
 * downloading. Each peer gets a distinct range so that all peers work in
 * parallel on non-overlapping segments of the header chain.
 */
struct PresyncHeaderRange {
    uint64_t start_height;   // first header height in this range (exclusive of locator)
    uint64_t end_height;     // last header height in this range (inclusive)
    uint256  locator_hash;   // hash of the block just before start_height (used as getheaders locator)
    bool     completed{false};
    bool     failed{false};
};

struct PresyncInFlightRequest {
    NodeId peer_id;
    CBlockLocator locator;       // where we asked them to start
    uint64_t expected_height;    // height of first expected header
    uint64_t expected_count;     // how many headers we expect back
    std::chrono::steady_clock::time_point request_time;
    int retry_count{0};
    bool failed{false};
};

struct PresyncState {
    bool active{false};
    const CBlockIndex* chain_start_header{nullptr};
    arith_uint256 minimum_chain_work;
    arith_uint256 accumulated_work;          // validated work so far
    uint64_t next_expected_height{0};        // next header height we need
    uint64_t target_height{0};               // height we need to reach for sufficient work
    std::vector<PresyncInFlightRequest> in_flight;
    std::vector<PresyncHeaderRange> pending_ranges;  // ranges not yet assigned to a peer
    std::map<NodeId, int> peer_retry_counts; // per-peer failure count
    static constexpr int MAX_RETRIES_PER_PEER = 3;
    static constexpr std::chrono::seconds REQUEST_TIMEOUT{30};
};

// Global shared presync state (guarded by m_headers_presync_mutex)
static PresyncState g_presync_state;

bool PeerManagerImpl::IsPresyncPhase(const CNode& pfrom) const
{
    // Check global completion flag first
    if (g_headers_presync_complete.load(std::memory_order_acquire)) {
        return false;
    }
    LOCK(m_headers_presync_mutex);
    return g_presync_state.active;
}

bool PeerManagerImpl::ProcessPresyncHeaders(CNode& pfrom, Peer& peer,
                                             const std::vector<CBlockHeader>& headers)
{
    std::cout << "[DEBUG] ProcessPresyncHeaders: called with " << headers.size() << " headers peer=" << pfrom.GetId() << " g_headers_presync_complete=" << g_headers_presync_complete.load(std::memory_order_acquire) << std::endl;
    // If presync is already globally complete, caller should transition to Phase 2.
    if (g_headers_presync_complete.load(std::memory_order_acquire)) {
        return false;
    }

    if (headers.empty()) {
        // Peer sent empty headers — they have nothing more to give.
        // Mark presync complete.
        g_headers_presync_complete.store(true, std::memory_order_release);
        std::cout << "[DEBUG] ProcessPresyncHeaders: empty headers, marking presync complete peer=" << pfrom.GetId() << std::endl;
        return false;
    }

    if (!CheckHeadersPoW(headers, m_chainparams.GetConsensus(), peer)) {
        std::cout << "[DEBUG] ProcessPresyncHeaders: CheckHeadersPoW FAILED peer=" << pfrom.GetId() << std::endl;
        return true;
    }

    if (!CheckHeadersAreContinuous(headers)) {
        std::cout << "[DEBUG] ProcessPresyncHeaders: CheckHeadersAreContinuous FAILED peer=" << pfrom.GetId() << std::endl;
        return true;
    }

    const CBlockIndex* chain_start_header{WITH_LOCK(cs_main, return m_chainman.m_blockman.LookupBlockIndex(headers[0].hashPrevBlock))};
    if (!chain_start_header) {
        std::cout << "[DEBUG] ProcessPresyncHeaders: chain_start_header is NULL (prev block not found) peer=" << pfrom.GetId() << " hashPrevBlock=" << headers[0].hashPrevBlock.ToString().substr(0,16) << "..." << std::endl;
        HandleFewUnconnectingHeaders(pfrom, peer, headers);
        return true;
    }

    // Always process the headers into the block index so m_best_header advances.
    // We do NOT gate on work — we download all headers to the tip.
    ProcessPresyncValidatedHeaders(pfrom, peer, headers);

    // Check if the peer has more headers to give us.
    // If they sent a full batch (MAX_HEADERS_RESULTS), they likely have more.
    // If they sent fewer, they claim to be at their tip. However, we cannot
    // trust a single peer's claim that they are at the tip — they could be on
    // a different fork or maliciously truncating. Only mark presync complete
    // if the peer's tip actually matches our m_best_header, confirming we have
    // genuinely reached the tip of the chain we are syncing.
    if (headers.size() < MAX_HEADERS_RESULTS) {
        const CBlockIndex* peer_tip = WITH_LOCK(cs_main, return m_chainman.m_blockman.LookupBlockIndex(headers.back().GetHash()));
        if (peer_tip && peer_tip == m_chainman.m_best_header) {
            // Peer's tip matches our best header — we have all headers to the tip.
            g_headers_presync_complete.store(true, std::memory_order_release);
            std::cout << "[DEBUG] ProcessPresyncHeaders: peer tip matches m_best_header (height=" << peer_tip->nHeight << "), marking presync complete peer=" << pfrom.GetId() << std::endl;
        } else {
            std::cout << "[DEBUG] ProcessPresyncHeaders: peer sent non-full batch but tip does NOT match m_best_header, NOT marking complete peer=" << pfrom.GetId() << std::endl;
        }
        return false;
    }

    // Peer sent a full batch — they likely have more headers.
    // Request the next batch.
    {
        LOCK(cs_main);
        const CBlockIndex* best = m_chainman.m_best_header;
        if (best) {
            CBlockLocator locator;
            locator.vHave.push_back(best->GetBlockHash());
            MaybeSendGetHeaders(pfrom, locator, peer);
            std::cout << "[DEBUG] ProcessPresyncHeaders: full batch received, requesting more headers from peer=" << pfrom.GetId() << " at height=" << best->nHeight << std::endl;
        }
    }

    // Still in presync — return true to indicate headers were handled here
    // and should NOT be processed again by the caller.
    return true;
}

void PeerManagerImpl::ProcessPresyncValidatedHeaders(CNode& pfrom, Peer& peer,
                                                      const std::vector<CBlockHeader>& headers)
{
    std::cout << "[DEBUG] ProcessPresyncValidatedHeaders: called with " << headers.size() << " headers peer=" << pfrom.GetId() << std::endl;
    // Actually process the headers into the block index so m_best_header advances
    BlockValidationState state;
    const CBlockIndex* pindexLast = nullptr;
    int32_t& nPoSTemperature = mapPoSTemperature[pfrom.addr];
    if (!m_chainman.ProcessNewBlockHeaders(nPoSTemperature, pfrom.lastAcceptedHeader, headers,
                                          /*min_pow_checked=*/true, state, m_chainparams, &pindexLast)) {
        if (state.IsInvalid()) {
            MaybePunishNodeForBlock(pfrom.GetId(), state, /*via_compact_block=*/false, "invalid header in presync");
            return;
        }
    }
    assert(pindexLast);

    // Update peer state with the last received header
    WITH_LOCK(cs_main, UpdateBlockAvailability(pfrom.GetId(), pindexLast->GetBlockHash()));

    // Update accumulated work (informational, not used as a stopping condition anymore)
    {
        LOCK(cs_main);
        std::cout << "[DEBUG] ProcessPresyncValidatedHeaders: m_best_header=" << (m_chainman.m_best_header ? std::to_string(m_chainman.m_best_header->nHeight) : "null") << " MinimumChainWork=" << m_chainman.MinimumChainWork().ToString().substr(0,20) << "..." << std::endl;
    }
}

void PeerManagerImpl::CheckPresyncCompletion(CNode& pfrom, Peer& peer)
{
    // Must be called with m_headers_presync_mutex held
    if (!g_presync_state.active) return;

    // Presync is complete when we've downloaded all headers to the tip.
    // This is signaled by g_headers_presync_complete being set in ProcessPresyncHeaders.
    if (g_headers_presync_complete.load(std::memory_order_acquire)) {
        g_presync_state.active = false;
        g_presync_state.in_flight.clear();
        g_presync_state.pending_ranges.clear();
        LogPrint(BCLog::NET, "Presync complete: reached tip (peer=%d)\n", pfrom.GetId());
        return;
    }

    // Check if all peers are exhausted (all in-flight failed or no more peers)
    bool all_exhausted = true;
    for (const auto& req : g_presync_state.in_flight) {
        if (!req.failed) {
            all_exhausted = false;
            break;
        }
    }
    if (all_exhausted && g_presync_state.in_flight.empty() && g_presync_state.pending_ranges.empty()) {
        // No more peers to request from — treat as complete (we have what we can get)
        LogPrint(BCLog::NET, "Presync exhausted: no more peers (peer=%d)\n",
                 pfrom.GetId());
        g_presync_state.active = false;
        g_headers_presync_complete.store(true, std::memory_order_release);
    }
}

void PeerManagerImpl::HandlePresyncFailure(CNode& pfrom, Peer& peer, const std::string& reason)
{
    // Must be called with m_headers_presync_mutex held
    if (!g_presync_state.active) return;

    int& retries = g_presync_state.peer_retry_counts[pfrom.GetId()];
    retries++;

    if (retries >= PresyncState::MAX_RETRIES_PER_PEER) {
        // Peer exhausted retries - mark all its in-flight requests as failed
        for (auto& req : g_presync_state.in_flight) {
            if (req.peer_id == pfrom.GetId()) {
                req.failed = true;
            }
        }
        LogPrint(BCLog::NET, "Presync peer %d exhausted retries (%s), reassigning\n",
                 pfrom.GetId(), reason);
        // Reassign the failed range to other peers
        ReassignFailedRequests(pfrom, peer);
    } else {
        // Retry: re-request from same peer with backoff
        LogPrint(BCLog::NET, "Presync retry %d/%d for peer=%d (%s)\n",
                 retries, PresyncState::MAX_RETRIES_PER_PEER, pfrom.GetId(), reason);
        // The retry will be handled by the periodic retry timer
    }
}

void PeerManagerImpl::ReassignFailedRequests(CNode& pfrom, Peer& peer)
{
    // Must be called with m_headers_presync_mutex held
    // Find failed requests and reassign to other connected peers
    std::vector<PresyncInFlightRequest> failed_requests;
    for (const auto& req : g_presync_state.in_flight) {
        if (req.failed) {
            failed_requests.push_back(req);
        }
    }

    // Remove failed entries
    g_presync_state.in_flight.erase(
        std::remove_if(g_presync_state.in_flight.begin(), g_presync_state.in_flight.end(),
            [](const PresyncInFlightRequest& r) { return r.failed; }),
        g_presync_state.in_flight.end());

    // Reassign to other peers that haven't exhausted retries
    for (const auto& failed_req : failed_requests) {
        bool reassigned = false;
        for (const auto& [other_peer_id, retry_count] : g_presync_state.peer_retry_counts) {
            if (other_peer_id != pfrom.GetId() && retry_count < PresyncState::MAX_RETRIES_PER_PEER) {
                // Send getheaders to this peer for the failed range
                CBlockLocator locator;
                locator.vHave.push_back(failed_req.locator.vHave.front());
                // Will be sent on next tick
                PresyncInFlightRequest new_req;
                new_req.peer_id = other_peer_id;
                new_req.locator = locator;
                new_req.expected_height = failed_req.expected_height;
                new_req.expected_count = failed_req.expected_count;
                new_req.request_time = std::chrono::steady_clock::now();
                g_presync_state.in_flight.push_back(new_req);
                reassigned = true;
                break;
            }
        }
        if (!reassigned) {
            LogPrint(BCLog::NET, "Presync: could not reassign headers at height %d\n",
                     failed_req.expected_height);
        }
    }
}

void PeerManagerImpl::DistributePresyncRequests(CNode& pfrom, Peer& peer)
{
    // Fan out header requests to all connected peers in parallel.
    // Each peer gets a DISTINCT contiguous range of headers to fetch,
    // so that all peers work on non-overlapping segments simultaneously.
    // NOTE: m_headers_presync_mutex is already held by caller (TryLowWorkHeadersSync)
    if (!g_presync_state.active) return;

    // Build locator from the current best header so peers send headers after our tip
    CBlockLocator locator;
    {
        LOCK(cs_main);
        if (m_chainman.m_best_header) {
            locator.vHave.push_back(m_chainman.m_best_header->GetBlockHash());
        }
    }

    if (locator.vHave.empty()) {
        LogPrint(BCLog::NET, "Presync: no best_header available for locator\n");
        return;
    }

    // Collect all connected peers that can serve headers
    std::vector<NodeId> connected_peers;
    m_connman.ForEachNode([&](CNode* node) {
        if (node->fSuccessfullyConnected && CanServeBlocks(*GetPeerRef(node->GetId()))) {
            connected_peers.push_back(node->GetId());
        }
    });

    if (connected_peers.empty()) {
        LogPrint(BCLog::NET, "Presync: no peers to distribute requests to\n");
        return;
    }

    // Calculate the total range of headers we need to fetch.
    // We need headers from next_expected_height up to target_height.
    uint64_t start = g_presync_state.next_expected_height;
    uint64_t end = g_presync_state.target_height;
    if (end <= start) {
        // Already have enough headers
        return;
    }

    uint64_t total_headers_needed = end - start;
    uint64_t num_peers = connected_peers.size();

    // Divide the total range into non-overlapping segments, one per peer.
    // Each peer gets ceil(total_headers_needed / num_peers) headers,
    // except possibly the last peer which gets the remainder.
    uint64_t range_size = (total_headers_needed + num_peers - 1) / num_peers;

    // Clear old in-flight and pending ranges, we are redistributing
    g_presync_state.in_flight.clear();
    g_presync_state.pending_ranges.clear();

    uint64_t range_start = start;
    for (size_t i = 0; i < num_peers && range_start < end; i++) {
        uint64_t range_end = std::min(range_start + range_size, end);

        PresyncHeaderRange range;
        range.start_height = range_start;
        range.end_height = range_end;
        range.locator_hash = locator.vHave.front();
        range.completed = false;
        range.failed = false;
        g_presync_state.pending_ranges.push_back(range);

        // Create in-flight entry for this peer with its specific range
        PresyncInFlightRequest req;
        req.peer_id = connected_peers[i];
        req.locator = locator;
        req.expected_height = range_start;
        req.expected_count = range_end - range_start;
        req.request_time = std::chrono::steady_clock::now();
        req.retry_count = 0;
        req.failed = false;

        g_presync_state.in_flight.push_back(req);
        range_start = range_end;
    }

    // Send getheaders to each peer for their assigned range
    for (const auto& req : g_presync_state.in_flight) {
        m_connman.ForNode(req.peer_id, [&](CNode* node) {
            PeerRef target_peer = GetPeerRef(req.peer_id);
            if (target_peer) {
                target_peer->m_last_getheaders_timestamp = {};
                MaybeSendGetHeaders(*node, req.locator, *target_peer);
            }
            return true;
        });
    }

    LogPrint(BCLog::NET, "Presync: distributed %d headers across %d peers (range %d-%d)\n",
             total_headers_needed, num_peers, start, end);
}

void PeerManagerImpl::HandleFewUnconnectingHeaders(CNode& pfrom, Peer& peer,
                                                    const std::vector<CBlockHeader>& headers)
{
    peer.m_num_unconnecting_headers_msgs++;
    const CBlockIndex* best_header{WITH_LOCK(cs_main, return m_chainman.m_best_header)};
    if (MaybeSendGetHeaders(pfrom, GetLocator(best_header), peer)) {
        LogPrint(BCLog::NET, "received header %s: missing prev block %s, sending getheaders (%d) to end (peer=%d, m_num_unconnecting_headers_msgs=%d)\n",
            headers[0].GetHash().ToString(),
            headers[0].hashPrevBlock.ToString(),
            best_header->nHeight,
            pfrom.GetId(), peer.m_num_unconnecting_headers_msgs);
    }
    WITH_LOCK(cs_main, UpdateBlockAvailability(pfrom.GetId(), headers.back().GetHash()));
    if (peer.m_num_unconnecting_headers_msgs % MAX_NUM_UNCONNECTING_HEADERS_MSGS == 0) {
        Misbehaving(peer, 20, strprintf("%d non-connecting headers", peer.m_num_unconnecting_headers_msgs));
    }
}

bool PeerManagerImpl::IsContinuationOfLowWorkHeadersSync(Peer& peer, CNode& pfrom, std::vector<CBlockHeader>& headers)
{
    // In the parallel model, continuation is handled by ProcessPresyncValidatedHeaders.
    // This function is retained for compatibility but delegates to the shared state.
    LOCK(m_headers_presync_mutex);
    if (!g_presync_state.active) return false;

    // Check if headers continue from our expected position
    if (!headers.empty()) {
        const CBlockIndex* prev = m_chainman.m_blockman.LookupBlockIndex(headers[0].hashPrevBlock);
        if (prev && prev->nHeight + 1 == g_presync_state.next_expected_height) {
            return true;
        }
    }
    return false;
}

bool PeerManagerImpl::TryLowWorkHeadersSync(Peer& peer, CNode& pfrom,
                                              const CBlockIndex* chain_start_header,
                                              std::vector<CBlockHeader>& headers)
{
    std::cout << "[DEBUG] TryLowWorkHeadersSync: called peer=" << pfrom.GetId() << " chain_start_header height=" << chain_start_header->nHeight << " headers.size=" << headers.size() << std::endl;

    // Always activate presync — we always want to download headers to the tip.
    // The work check is no longer a gate; we process all headers regardless.
    if (headers.size() == MAX_HEADERS_RESULTS) {
        std::cout << "[DEBUG] TryLowWorkHeadersSync: headers.size()==MAX_HEADERS_RESULTS, activating presync state peer=" << pfrom.GetId() << std::endl;
        LOCK(m_headers_presync_mutex);
        if (!g_presync_state.active) {
            g_presync_state.active = true;
            g_presync_state.chain_start_header = const_cast<CBlockIndex*>(chain_start_header);
            g_presync_state.minimum_chain_work = GetAntiDoSWorkThreshold();
            g_presync_state.accumulated_work = chain_start_header->nChainTrust;
            g_presync_state.next_expected_height = chain_start_header->nHeight + 1;
            // Use a generous upper bound for target height.
            // The actual completion is determined by the peer sending < MAX_HEADERS_RESULTS.
            g_presync_state.target_height = chain_start_header->nHeight + MAX_HEADERS_RESULTS * 10;
        }
        // Process and distribute
        ProcessPresyncValidatedHeaders(pfrom, peer, headers);
        DistributePresyncRequests(pfrom, peer);
    } else {
        // Non-full batch: peer claims to be at their tip. Only mark presync
        // complete if their tip matches our m_best_header — we cannot trust
        // a single peer's claim that they are at the tip.
        const CBlockIndex* peer_tip = WITH_LOCK(cs_main, return m_chainman.m_blockman.LookupBlockIndex(headers.back().GetHash()));
        if (peer_tip && peer_tip == m_chainman.m_best_header) {
            g_headers_presync_complete.store(true, std::memory_order_release);
            std::cout << "[DEBUG] TryLowWorkHeadersSync: non-full batch AND tip matches m_best_header, marking presync complete peer=" << pfrom.GetId() << std::endl;
        } else {
            std::cout << "[DEBUG] TryLowWorkHeadersSync: non-full batch but tip does NOT match m_best_header, NOT marking complete peer=" << pfrom.GetId() << std::endl;
        }
    }
    headers = {};
    return true;
}

bool PeerManagerImpl::CheckHeadersPoW(const std::vector<CBlockHeader>& headers, const Consensus::Params& consensusParams, Peer& peer)
{
    if (!HasValidProofOfWork(headers, consensusParams)) {
        Misbehaving(peer, 100, "header with invalid proof of work");
        return false;
    }
    if (!CheckHeadersAreContinuous(headers)) {
        Misbehaving(peer, 20, "non-continuous headers sequence");
        return false;
    }
    return true;
}

bool PeerManagerImpl::CheckHeadersAreContinuous(const std::vector<CBlockHeader>& headers) const
{
    uint256 hashLastBlock;
    for (const CBlockHeader& header : headers) {
        if (!hashLastBlock.IsNull() && header.hashPrevBlock != hashLastBlock) {
            return false;
        }
        hashLastBlock = header.GetHash();
    }
    return true;
}

// --- Periodic retry timer (called from the main event loop) ---
void PeerManagerImpl::CheckPresyncRetries()
{
    LOCK(m_headers_presync_mutex);
    if (!g_presync_state.active) return;

    auto now = std::chrono::steady_clock::now();
    std::vector<PresyncInFlightRequest> timed_out;

    for (auto& req : g_presync_state.in_flight) {
        if (!req.failed && (now - req.request_time) > PresyncState::REQUEST_TIMEOUT) {
            req.failed = true;
            timed_out.push_back(req);
            LogPrint(BCLog::NET, "Presync: request to peer=%d timed out at height %d\n",
                     req.peer_id, req.expected_height);
        }
    }

    if (!timed_out.empty()) {
        // Remove timed-out entries and reassign
        g_presync_state.in_flight.erase(
            std::remove_if(g_presync_state.in_flight.begin(), g_presync_state.in_flight.end(),
                [](const PresyncInFlightRequest& r) { return r.failed; }),
            g_presync_state.in_flight.end());

        for (const auto& failed_req : timed_out) {
            int& retries = g_presync_state.peer_retry_counts[failed_req.peer_id];
            retries++;
            if (retries < PresyncState::MAX_RETRIES_PER_PEER) {
                // Retry with same peer
                PresyncInFlightRequest retry_req = failed_req;
                retry_req.failed = false;
                retry_req.request_time = now;
                retry_req.retry_count = retries;
                g_presync_state.in_flight.push_back(retry_req);
                LogPrint(BCLog::NET, "Presync: retrying peer=%d (attempt %d)\n",
                         failed_req.peer_id, retries);
            } else {
                LogPrint(BCLog::NET, "Presync: peer=%d exhausted all retries\n", failed_req.peer_id);
            }
        }

        // Reassign any permanently-failed ranges to other peers
        // (simplified: just re-distribute remaining gaps)
        if (!g_presync_state.in_flight.empty() || !timed_out.empty()) {
            // Signal that more headers are needed
            m_headers_presync_should_signal = true;
        }
    }
}
