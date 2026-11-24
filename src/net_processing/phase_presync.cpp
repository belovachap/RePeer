// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing/peer_manager_impl.h>
#include <net_processing/constants.h>

// ============================================================================
// PHASE 1: PRESYNC BLOCKHEADERS
//
// Purpose: Anti-DoS protection for low-work headers chains.
// Entry:   When headers arrive with insufficient work to meet our threshold.
// Exit:    When a chain with sufficient work is found, or peer is disconnected.
//
// This phase is completely isolated from all other phases. It handles the
// HeadersSyncState mechanism that prevents low-difficulty header chains from
// consuming resources.
// ============================================================================

bool PeerManagerImpl::IsPresyncPhase(const CNode& pfrom) const
{
    PeerRef peer = GetPeerRef(pfrom.GetId());
    if (!peer) return false;
    LOCK(peer->m_headers_sync_mutex);
    return peer->m_headers_sync != nullptr;
}

bool PeerManagerImpl::ProcessPresyncHeaders(CNode& pfrom, Peer& peer,
                                             std::vector<CBlockHeader>&& headers)
{
    // This is the ONLY code path that handles presync.
    // If we are in presync, no other phase processes headers.

    if (headers.empty()) {
        // Empty headers message during presync means peer has nothing more.
        LOCK(peer.m_headers_sync_mutex);
        if (peer.m_headers_sync) {
            peer.m_headers_sync.reset(nullptr);
            LOCK(m_headers_presync_mutex);
            m_headers_presync_stats.erase(pfrom.GetId());
        }
        return true; // handled
    }

    // Verify PoW and continuity (presync-specific validation)
    if (!CheckHeadersPoW(headers, m_chainparams.GetConsensus(), peer)) {
        return true; // handled (misbehaving called internally)
    }

    // Check if this is a continuation of an existing presync
    bool already_validated_work = false;
    {
        LOCK(peer.m_headers_sync_mutex);
        already_validated_work = IsContinuationOfLowWorkHeadersSync(peer, pfrom, headers);
        if (headers.empty()) {
            return true; // presync consumed all headers
        }
    }

    if (already_validated_work) {
        // Headers were processed by presync mechanism; update peer state
        const CBlockIndex* last_received_header{nullptr};
        {
            LOCK(cs_main);
            last_received_header = m_chainman.m_blockman.LookupBlockIndex(headers.back().GetHash());
        }
        if (last_received_header) {
            UpdatePeerStateForReceivedHeaders(pfrom, peer, *last_received_header, true, false);
        }
        return true;
    }

    // Check if these headers have sufficient work to exit presync
    const CBlockIndex* chain_start_header{WITH_LOCK(cs_main, return m_chainman.m_blockman.LookupBlockIndex(headers[0].hashPrevBlock))};
    if (!chain_start_header) {
        // Doesn't connect - handle as unconnecting (presync-specific)
        HandleFewUnconnectingHeaders(pfrom, peer, headers);
        return true;
    }

    arith_uint256 total_work = chain_start_header->nChainTrust + CalculateHeadersWork(headers);
    arith_uint256 minimum_chain_work = GetAntiDoSWorkThreshold();

    if (total_work < minimum_chain_work) {
        // Still in presync - start or continue low-work sync
        if (headers.size() == MAX_HEADERS_RESULTS) {
            LOCK(peer.m_headers_sync_mutex);
            peer.m_headers_sync.reset(new HeadersSyncState(peer.m_id, m_chainparams.GetConsensus(),
                chain_start_header, minimum_chain_work));
            (void)IsContinuationOfLowWorkHeadersSync(peer, pfrom, headers);
        } else {
            LogPrint(BCLog::NET, "Ignoring low-work chain (height=%u) from peer=%d\n",
                     chain_start_header->nHeight + headers.size(), pfrom.GetId());
        }
        return true; // still in presync, no further processing
    }

    // Work is sufficient - EXIT presync, transition to Phase 2
    {
        LOCK(peer.m_headers_sync_mutex);
        if (peer.m_headers_sync) {
            peer.m_headers_sync.reset(nullptr);
            LOCK(m_headers_presync_mutex);
            m_headers_presync_stats.erase(pfrom.GetId());
        }
    }
    return false; // NOT handled by presync - caller should transition to Phase 2
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
    if (peer.m_headers_sync) {
        auto result = peer.m_headers_sync->ProcessNextHeaders(headers, headers.size() == MAX_HEADERS_RESULTS);
        if (result.request_more) {
            auto locator = peer.m_headers_sync->NextHeadersRequestLocator();
            Assume(!locator.vHave.empty());
            if (!locator.vHave.empty()) {
                bool sent_getheaders = MaybeSendGetHeaders(pfrom, locator, peer);
                if (sent_getheaders) {
                    LogPrint(BCLog::NET, "more getheaders (from %s) to peer=%d\n",
                            locator.vHave.front().ToString(), pfrom.GetId());
                } else {
                    LogPrint(BCLog::NET, "error sending next getheaders (from %s) to continue sync with peer=%d\n",
                            locator.vHave.front().ToString(), pfrom.GetId());
                }
            }
        }

        if (peer.m_headers_sync->GetState() == HeadersSyncState::State::FINAL) {
            peer.m_headers_sync.reset(nullptr);
            LOCK(m_headers_presync_mutex);
            m_headers_presync_stats.erase(pfrom.GetId());
        } else {
            HeadersPresyncStats stats;
            stats.first = peer.m_headers_sync->GetPresyncWork();
            if (peer.m_headers_sync->GetState() == HeadersSyncState::State::PRESYNC) {
                stats.second = {peer.m_headers_sync->GetPresyncHeight(),
                                peer.m_headers_sync->GetPresyncTime()};
            }

            LOCK(m_headers_presync_mutex);
            m_headers_presync_stats[pfrom.GetId()] = stats;
            auto best_it = m_headers_presync_stats.find(m_headers_presync_bestpeer);
            bool best_updated = false;
            if (best_it == m_headers_presync_stats.end()) {
                NodeId peer_best{-1};
                const HeadersPresyncStats* stat_best{nullptr};
                for (const auto& [peer_id, stat] : m_headers_presync_stats) {
                    if (!stat_best || stat > *stat_best) {
                        peer_best = peer_id;
                        stat_best = &stat;
                    }
                }
                m_headers_presync_bestpeer = peer_best;
                best_updated = (peer_best == pfrom.GetId());
            } else if (best_it->first == pfrom.GetId() || stats > best_it->second) {
                m_headers_presync_bestpeer = pfrom.GetId();
                best_updated = true;
            }
            if (best_updated && stats.second.has_value()) {
                m_headers_presync_should_signal = true;
            }
        }

        if (result.success) {
            headers.swap(result.pow_validated_headers);
        }
        return result.success;
    }
    return false;
}

bool PeerManagerImpl::TryLowWorkHeadersSync(Peer& peer, CNode& pfrom,
                                              const CBlockIndex* chain_start_header,
                                              std::vector<CBlockHeader>& headers)
{
    arith_uint256 total_work = chain_start_header->nChainTrust + CalculateHeadersWork(headers);
    arith_uint256 minimum_chain_work = GetAntiDoSWorkThreshold();

    if (total_work < minimum_chain_work) {
        if (headers.size() == MAX_HEADERS_RESULTS) {
            LOCK(peer.m_headers_sync_mutex);
            peer.m_headers_sync.reset(new HeadersSyncState(peer.m_id, m_chainparams.GetConsensus(),
                chain_start_header, minimum_chain_work));
            (void)IsContinuationOfLowWorkHeadersSync(peer, pfrom, headers);
        } else {
            LogPrint(BCLog::NET, "Ignoring low-work chain (height=%u) from peer=%d\n",
                     chain_start_header->nHeight + headers.size(), pfrom.GetId());
        }
        headers = {};
        return true;
    }
    return false;
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
