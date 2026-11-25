// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing/peer_manager_impl.h>
#include <net_processing/constants.h>
#include <random.h>

// Set to true once headers sync is complete (all peers have sent their full
// header chains to the tip). Block downloading is gated on this flag.
std::atomic<bool> g_headers_sync_complete{false};

// ============================================================================
// PHASE 1: SYNC BLOCKHEADERS (3-of-3 CONSENSUS VERIFICATION)
//
// Purpose: Download each block header from 3 independent peers and confirm
//          they all agree before connecting it to the chain. If peers disagree,
//          the header is returned to the pool for 3 new random peers to retry.
// Entry:   Always the first phase.
// Exit:    When all headers are verified and CanDirectFetch() becomes true.
//
// This phase does NOT download blocks. It does NOT relay transactions.
// Each header must be confirmed by HEADER_VERIFY_QUORUM peers before acceptance.
// ============================================================================

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

bool PeerManagerImpl::IsAncestorOfBestHeaderOrTip(const CBlockIndex* header)
{
    if (header == nullptr) {
        return false;
    } else if (m_chainman.m_best_header != nullptr && header == m_chainman.m_best_header->GetAncestor(header->nHeight)) {
        return true;
    } else if (m_chainman.ActiveChain().Contains(header)) {
        return true;
    }
    return false;
}

bool PeerManagerImpl::MaybeSendGetHeaders(CNode& pfrom, const CBlockLocator& locator, Peer& peer)
{
    const CNetMsgMaker msgMaker(pfrom.GetCommonVersion());

    const auto current_time = NodeClock::now();

    // Only allow a new getheaders message to go out if we don't have a recent
    // one already in-flight
    if (current_time - peer.m_last_getheaders_timestamp > HEADERS_RESPONSE_TIME) {
        m_connman.PushMessage(&pfrom, msgMaker.Make(NetMsgType::GETHEADERS, locator, uint256()));
        peer.m_last_getheaders_timestamp = current_time;
        return true;
    }
    return false;
}

/*
 * Given a new headers tip ending in last_header, potentially request blocks towards that tip.
 * We require that the given tip have at least as much work as our tip, and for
 * our current tip to be "close to synced" (see CanDirectFetch()).
 */
void PeerManagerImpl::HeadersDirectFetchBlocks(CNode& pfrom, const Peer& peer, const CBlockIndex& last_header)
{
    const CNetMsgMaker msgMaker(pfrom.GetCommonVersion());

    LOCK(cs_main);
    CNodeState *nodestate = State(pfrom.GetId());

    if (CanDirectFetch() && last_header.IsValid(BLOCK_VALID_TREE) && m_chainman.ActiveChain().Tip()->nChainTrust <= last_header.nChainTrust) {
        std::vector<const CBlockIndex*> vToFetch;
        const CBlockIndex* pindexWalk{&last_header};
        // Calculate all the blocks we'd need to switch to last_header, up to a limit.
        while (pindexWalk && !m_chainman.ActiveChain().Contains(pindexWalk) && vToFetch.size() <= MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
            if (!(pindexWalk->nStatus & BLOCK_HAVE_DATA) &&
                    !IsBlockRequested(pindexWalk->GetBlockHash()) &&
                    (!DeploymentActiveAt(*pindexWalk, m_chainman, Consensus::DEPLOYMENT_SEGWIT) || CanServeWitnesses(peer))) {
                // We don't have this block, and it's not yet in flight.
                vToFetch.push_back(pindexWalk);
            }
            pindexWalk = pindexWalk->pprev;
        }
        // If pindexWalk still isn't on our main chain, we're looking at a
        // very large reorg at a time we think we're close to caught up to
        // the main chain -- this shouldn't really happen.  Bail out on the
        // direct fetch and rely on parallel download instead.
        if (!m_chainman.ActiveChain().Contains(pindexWalk)) {
            LogPrint(BCLog::NET, "Large reorg, won't direct fetch to %s (%d)\n",
                     last_header.GetBlockHash().ToString(),
                     last_header.nHeight);
        } else {
            std::vector<CInv> vGetData;
            // Download as much as possible, from earliest to latest.
            for (const CBlockIndex *pindex : reverse_iterate(vToFetch)) {
                if (nodestate->vBlocksInFlight.size() >= MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
                    // Can't download any more from this peer
                    break;
                }
                uint32_t nFetchFlags = GetFetchFlags(peer);
                vGetData.push_back(CInv(MSG_BLOCK | nFetchFlags, pindex->GetBlockHash()));
                BlockRequested(pfrom.GetId(), *pindex);
                LogPrint(BCLog::NET, "Requesting block %s from  peer=%d\n",
                        pindex->GetBlockHash().ToString(), pfrom.GetId());
            }
            if (vGetData.size() > 1) {
                LogPrint(BCLog::NET, "Downloading blocks toward %s (%d) via headers direct fetch\n",
                         last_header.GetBlockHash().ToString(),
                         last_header.nHeight);
            }
            if (vGetData.size() > 0) {
                if (!m_ignore_incoming_txs &&
                        nodestate->m_provides_cmpctblocks &&
                        vGetData.size() == 1 &&
                        mapBlocksInFlight.size() == 1 &&
                        last_header.pprev->IsValid(BLOCK_VALID_CHAIN)) {
                    // In any case, we want to download using a compact block, not a regular one
                    vGetData[0] = CInv(MSG_CMPCT_BLOCK, vGetData[0].hash);
                }
                m_connman.PushMessage(&pfrom, msgMaker.Make(NetMsgType::GETDATA, vGetData));
            }
        }
    }
}

/**
 * Given receipt of headers from a peer ending in last_header, along with
 * whether that header was new and whether the headers message was full,
 * update the state we keep for the peer.
 */
void PeerManagerImpl::UpdatePeerStateForReceivedHeaders(CNode& pfrom, Peer& peer,
        const CBlockIndex& last_header, bool received_new_header, bool may_have_more_headers)
{
    if (peer.m_num_unconnecting_headers_msgs > 0) {
        LogPrint(BCLog::NET, "peer=%d: resetting m_num_unconnecting_headers_msgs (%d -> 0)\n", pfrom.GetId(), peer.m_num_unconnecting_headers_msgs);
    }
    peer.m_num_unconnecting_headers_msgs = 0;

    LOCK(cs_main);
    CNodeState *nodestate = State(pfrom.GetId());

    UpdateBlockAvailability(pfrom.GetId(), last_header.GetBlockHash());

    // From here, pindexBestKnownBlock should be guaranteed to be non-null,
    // because it is set in UpdateBlockAvailability. Some nullptr checks
    // are still present, however, as belt-and-suspenders.

    if (received_new_header && last_header.nChainTrust > m_chainman.ActiveChain().Tip()->nChainTrust) {
        nodestate->m_last_block_announcement = GetTime();
    }

    // If we're in IBD, we want outbound peers that will serve us a useful
    // chain. Disconnect peers that are on chains with insufficient work.
    if (m_chainman.ActiveChainstate().IsInitialBlockDownload() && !may_have_more_headers) {
        // If the peer has no more headers to give us, then we know we have
        // their tip.
        if (nodestate->pindexBestKnownBlock && nodestate->pindexBestKnownBlock->nChainTrust < m_chainman.MinimumChainWork()) {
            // This peer has too little work on their headers chain to help
            // us sync -- disconnect if it is an outbound disconnection
            // candidate.
            // Note: We compare their tip to the minimum chain work (rather than
            // m_chainman.ActiveChain().Tip()) because we won't start block download
            // until we have a headers chain that has at least
            // the minimum chain work, even if a peer has a chain past our tip,
            // as an anti-DoS measure.
            if (pfrom.IsOutboundOrBlockRelayConn()) {
                LogPrintf("Disconnecting outbound peer %d -- headers chain has insufficient work\n", pfrom.GetId());
                pfrom.fDisconnect = true;
            }
        }
    }

    // If this is an outbound full-relay peer, check to see if we should protect
    // it from the bad/lagging chain logic.
    // Note that outbound block-relay peers are excluded from this protection, and
    // thus always subject to eviction under the bad/lagging chain logic.
    // See ChainSyncTimeoutState.
    if (!pfrom.fDisconnect && pfrom.IsFullOutboundConn() && nodestate->pindexBestKnownBlock != nullptr) {
        if (m_outbound_peers_with_protect_from_disconnect < MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT && nodestate->pindexBestKnownBlock->nChainTrust >= m_chainman.ActiveChain().Tip()->nChainTrust && !nodestate->m_chain_sync.m_protect) {
            LogPrint(BCLog::NET, "Protecting outbound peer=%d from eviction\n", pfrom.GetId());
            nodestate->m_chain_sync.m_protect = true;
            ++m_outbound_peers_with_protect_from_disconnect;
        }
    }
}

// ============================================================================
// 3-of-3 HEADER VERIFICATION LOGIC
// ============================================================================

void PeerManagerImpl::AssignHeadersForVerification(uint64_t start_height, uint64_t end_height)
{
    // Must be called with m_header_verify_mutex held
    // Collect all connected peers that can serve headers
    std::vector<NodeId> connected_peers;
    m_connman.ForEachNode([&](CNode* node) {
        if (node->fSuccessfullyConnected && CanServeBlocks(*GetPeerRef(node->GetId()))) {
            connected_peers.push_back(node->GetId());
        }
    });

    if (connected_peers.size() < HEADER_VERIFY_QUORUM) {
        LogPrint(BCLog::NET, "Header verification: not enough peers (%zu < %d)\n",
                 connected_peers.size(), HEADER_VERIFY_QUORUM);
        return;
    }

    // For each height in the range, assign HEADER_VERIFY_QUORUM random peers
    for (uint64_t height = start_height; height <= end_height; height++) {
        HeaderVerification hv;
        hv.height = height;
        hv.verified = false;
        hv.failed = false;
        hv.retry_count = 0;

        // Pick HEADER_VERIFY_QUORUM random distinct peers
        std::vector<NodeId> shuffled = connected_peers;
        Shuffle(shuffled.begin(), shuffled.end(), FastRandomContext());
        for (int i = 0; i < HEADER_VERIFY_QUORUM && i < (int)shuffled.size(); i++) {
            hv.assigned_peers.push_back(shuffled[i]);
            m_peer_assigned_heights[shuffled[i]].insert(height);
        }

        m_header_verifications[height] = std::move(hv);
        m_header_verify_queue.push_back(height);
    }

    m_next_header_to_assign = end_height + 1;

    // Send getheaders to each assigned peer for their assigned ranges
    std::map<NodeId, std::vector<uint64_t>> peer_heights;
    for (const auto& [height, hv] : m_header_verifications) {
        if (!hv.verified && !hv.failed) {
            for (NodeId pid : hv.assigned_peers) {
                peer_heights[pid].push_back(height);
            }
        }
    }

    for (const auto& [peer_id, heights] : peer_heights) {
        if (heights.empty()) continue;
        m_connman.ForNode(peer_id, [&](CNode* node) {
            PeerRef target_peer = GetPeerRef(peer_id);
            if (target_peer) {
                CBlockLocator locator;
                {
                    LOCK(cs_main);
                    if (m_chainman.m_best_header) {
                        locator.vHave.push_back(m_chainman.m_best_header->GetBlockHash());
                    }
                }
                target_peer->m_last_getheaders_timestamp = {};
                MaybeSendGetHeaders(*node, locator, *target_peer);
            }
            return true;
        });
    }

    LogPrint(BCLog::NET, "Header verification: assigned heights %d-%d to %zu peers\n",
             start_height, end_height, connected_peers.size());
}

void PeerManagerImpl::ProcessHeaderVerificationResponse(NodeId peer_id, const CBlockHeader& header, uint64_t height)
{
    LOCK(m_header_verify_mutex);

    auto it = m_header_verifications.find(height);
    if (it == m_header_verifications.end()) {
        return;
    }

    HeaderVerification& hv = it->second;

    // Check if this peer was assigned to this height
    bool assigned = false;
    for (NodeId pid : hv.assigned_peers) {
        if (pid == peer_id) {
            assigned = true;
            break;
        }
    }
    if (!assigned) {
        LogPrint(BCLog::NET, "Header verification: peer=%d sent header for height %d but wasn't assigned\n",
                 peer_id, height);
        return;
    }

    // Record the response
    hv.responses.push_back(header);

    // Remove from peer's assigned set
    m_peer_assigned_heights[peer_id].erase(height);

    // Check if we have enough responses
    if ((int)hv.responses.size() < HEADER_VERIFY_QUORUM) {
        return;
    }

    // Compare all responses
    bool all_match = true;
    for (size_t i = 1; i < hv.responses.size(); i++) {
        if (hv.responses[i].GetHash() != hv.responses[0].GetHash()) {
            all_match = false;
            break;
        }
    }

    if (all_match) {
        // All peers agree — accept this header
        hv.verified = true;
        LogPrint(BCLog::NET, "Header verification: height %d verified by %d peers (hash=%s)\n",
                 height, HEADER_VERIFY_QUORUM, hv.responses[0].GetHash().ToString().substr(0, 16));

        // Process the verified header into the block index
        BlockValidationState state;
        const CBlockIndex* pindexLast = nullptr;
        int32_t& nPoSTemperature = mapPoSTemperature[m_connman.GetNodeAddr(peer_id)];
        if (!m_chainman.ProcessNewBlockHeaders(nPoSTemperature, pindexLast ? pindexLast->GetBlockHash() : uint256::ZERO,
                                              {hv.responses[0]}, /*min_pow_checked=*/true, state, m_chainparams, &pindexLast)) {
            if (state.IsInvalid()) {
                LogPrint(BCLog::NET, "Header verification: invalid header at height %d from peer=%d\n",
                         height, peer_id);
                hv.failed = true;
            }
        }

        // Remove from queue
        auto qit = std::find(m_header_verify_queue.begin(), m_header_verify_queue.end(), height);
        if (qit != m_header_verify_queue.end()) {
            m_header_verify_queue.erase(qit);
        }

        CheckHeaderVerificationComplete();
    } else {
        // Peers disagree — retry with 3 new random peers
        hv.retry_count++;
        hv.responses.clear();

        if (hv.retry_count >= MAX_HEADER_VERIFY_RETRIES) {
            hv.failed = true;
            LogPrint(BCLog::NET, "Header verification: height %d failed after %d retries, giving up\n",
                     height, MAX_HEADER_VERIFY_RETRIES);
            auto qit = std::find(m_header_verify_queue.begin(), m_header_verify_queue.end(), height);
            if (qit != m_header_verify_queue.end()) {
                m_header_verify_queue.erase(qit);
            }
            CheckHeaderVerificationComplete();
        } else {
            // Reassign to 3 new random peers
            std::vector<NodeId> connected_peers;
            m_connman.ForEachNode([&](CNode* node) {
                if (node->fSuccessfullyConnected && CanServeBlocks(*GetPeerRef(node->GetId()))) {
                    connected_peers.push_back(node->GetId());
                }
            });

            // Remove old assignments
            for (NodeId pid : hv.assigned_peers) {
                m_peer_assigned_heights[pid].erase(height);
            }
            hv.assigned_peers.clear();

            Shuffle(connected_peers.begin(), connected_peers.end(), FastRandomContext());
            for (int i = 0; i < HEADER_VERIFY_QUORUM && i < (int)connected_peers.size(); i++) {
                hv.assigned_peers.push_back(connected_peers[i]);
                m_peer_assigned_heights[connected_peers[i]].insert(height);
            }

            LogPrint(BCLog::NET, "Header verification: height %d mismatch, retry %d/%d with new peers\n",
                     height, hv.retry_count, MAX_HEADER_VERIFY_RETRIES);

            for (NodeId pid : hv.assigned_peers) {
                m_connman.ForNode(pid, [&](CNode* node) {
                    PeerRef target_peer = GetPeerRef(pid);
                    if (target_peer) {
                        CBlockLocator locator;
                        {
                            LOCK(cs_main);
                            if (m_chainman.m_best_header) {
                                locator.vHave.push_back(m_chainman.m_best_header->GetBlockHash());
                            }
                        }
                        target_peer->m_last_getheaders_timestamp = {};
                        MaybeSendGetHeaders(*node, locator, *target_peer);
                    }
                    return true;
                });
            }
        }
    }
}

void PeerManagerImpl::CheckHeaderVerificationComplete()
{
    // Must be called with m_header_verify_mutex held
    if (!m_header_verify_queue.empty()) {
        return;
    }

    for (const auto& [height, hv] : m_header_verifications) {
        if (!hv.verified && !hv.failed) {
            return;
        }
    }

    g_headers_sync_complete.store(true, std::memory_order_release);
    LogPrint(BCLog::NET, "Header verification complete: all headers verified or failed\n");
}

void PeerManagerImpl::ProcessPhase1Headers(CNode& pfrom, Peer& peer, const std::vector<CBlockHeader>& headers)
{
    if (headers.empty()) {
        return;
    }

    // Validate PoW and continuity
    if (!CheckHeadersPoW(headers, m_chainparams.GetConsensus(), peer)) {
        return;
    }

    // For each header in the batch, process it through the verification system
    for (const CBlockHeader& header : headers) {
        uint64_t height = 0;
        {
            LOCK(cs_main);
            const CBlockIndex* prev = m_chainman.m_blockman.LookupBlockIndex(header.hashPrevBlock);
            if (prev) {
                height = prev->nHeight + 1;
            } else {
                continue;
            }
        }
        ProcessHeaderVerificationResponse(pfrom.GetId(), header, height);
    }

    // If we received a full batch, request more from this peer
    if (headers.size() == MAX_HEADERS_RESULTS) {
        CBlockLocator locator;
        {
            LOCK(cs_main);
            if (m_chainman.m_best_header) {
                locator.vHave.push_back(m_chainman.m_best_header->GetBlockHash());
            }
        }
        MaybeSendGetHeaders(pfrom, locator, peer);
    }
}

void PeerManagerImpl::ProcessHeadersMessage(CNode& pfrom, Peer& peer,
                                            std::vector<CBlockHeader>&& headers,
                                            bool via_compact_block)
{
    size_t nCount = headers.size();

    if (nCount == 0) {
        // Nothing interesting. Stop asking this peers for more headers.
        return;
    }

    // Before we do any processing, make sure these pass basic sanity checks.
    // We'll rely on headers having valid proof-of-work further down, as an
    // anti-DoS criteria (note: this check is required before passing any
    // headers into HeadersSyncState).
    if (!CheckHeadersPoW(headers, m_chainparams.GetConsensus(), peer)) {
        // Misbehaving() calls are handled within CheckHeadersPoW(), so we can
        // just return. (Note that even if a header is announced via compact
        // block, the header itself should be valid, so this type of error can
        // always be punished.)
        return;
    }

    // Do these headers connect to something in our block index?
    const CBlockIndex *chain_start_header{WITH_LOCK(::cs_main, return m_chainman.m_blockman.LookupBlockIndex(headers[0].hashPrevBlock))};
    if (!chain_start_header) {
        if (nCount <= MAX_BLOCKS_TO_ANNOUNCE) {
            // If this looks like it could be a BIP 130 block announcement, use
            // special logic for handling headers that don't connect, as this
            // could be benign.
            HandleFewUnconnectingHeaders(pfrom, peer, headers);
        } else {
            Misbehaving(peer, 10, "invalid header received");
        }
        return;
    }

    // Route through the 3-of-3 verification system
    ProcessPhase1Headers(pfrom, peer, headers);
}
