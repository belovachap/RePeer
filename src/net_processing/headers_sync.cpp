// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing/peer_manager_impl.h>
#include <net_processing/constants.h>

bool PeerManagerImpl::CheckHeadersPoW(const std::vector<CBlockHeader>& headers, const Consensus::Params& consensusParams, Peer& peer)
{
    // Do these headers have proof-of-work matching what's claimed?
    if (!HasValidProofOfWork(headers, consensusParams)) {
        Misbehaving(peer, 100, "header with invalid proof of work");
        return false;
    }

    // Are these headers connected to each other?
    if (!CheckHeadersAreContinuous(headers)) {
        Misbehaving(peer, 20, "non-continuous headers sequence");
        return false;
    }
    return true;
}

arith_uint256 PeerManagerImpl::GetAntiDoSWorkThreshold()
{
    arith_uint256 near_chaintip_work = 0;
    LOCK(cs_main);
    if (m_chainman.ActiveChain().Tip() != nullptr) {
        const CBlockIndex *tip = m_chainman.ActiveChain().Tip();
        // Use a 144 block buffer, so that we'll accept headers that fork from
        // near our tip.
        near_chaintip_work = tip->nChainTrust - std::min<arith_uint256>(144*GetBlockTrust(*tip), tip->nChainTrust);
    }
    return std::max(near_chaintip_work, m_chainman.MinimumChainWork());
}

/**
 * Special handling for unconnecting headers that might be part of a block
 * announcement.
 *
 * We'll send a getheaders message in response to try to connect the chain.
 *
 * The peer can send up to MAX_NUM_UNCONNECTING_HEADERS_MSGS in a row that
 * don't connect before given DoS points.
 *
 * Once a headers message is received that is valid and does connect,
 * m_num_unconnecting_headers_msgs gets reset back to 0.
 */
void PeerManagerImpl::HandleFewUnconnectingHeaders(CNode& pfrom, Peer& peer,
        const std::vector<CBlockHeader>& headers)
{
    peer.m_num_unconnecting_headers_msgs++;
    // Try to fill in the missing headers.
    const CBlockIndex* best_header{WITH_LOCK(cs_main, return m_chainman.m_best_header)};
    if (MaybeSendGetHeaders(pfrom, GetLocator(best_header), peer)) {
        LogPrint(BCLog::NET, "received header %s: missing prev block %s, sending getheaders (%d) to end (peer=%d, m_num_unconnecting_headers_msgs=%d)\n",
            headers[0].GetHash().ToString(),
            headers[0].hashPrevBlock.ToString(),
            best_header->nHeight,
            pfrom.GetId(), peer.m_num_unconnecting_headers_msgs);
    }

    // Set hashLastUnknownBlock for this peer, so that if we
    // eventually get the headers - even from a different peer -
    // we can use this peer to download.
    WITH_LOCK(cs_main, UpdateBlockAvailability(pfrom.GetId(), headers.back().GetHash()));

    // The peer may just be broken, so periodically assign DoS points if this
    // condition persists.
    if (peer.m_num_unconnecting_headers_msgs % MAX_NUM_UNCONNECTING_HEADERS_MSGS == 0) {
        Misbehaving(peer, 20, strprintf("%d non-connecting headers", peer.m_num_unconnecting_headers_msgs));
    }
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

bool PeerManagerImpl::IsContinuationOfLowWorkHeadersSync(Peer& peer, CNode& pfrom, std::vector<CBlockHeader>& headers)
{
    if (peer.m_headers_sync) {
        auto result = peer.m_headers_sync->ProcessNextHeaders(headers, headers.size() == MAX_HEADERS_RESULTS);
        if (result.request_more) {
            auto locator = peer.m_headers_sync->NextHeadersRequestLocator();
            // If we were instructed to ask for a locator, it should not be empty.
            Assume(!locator.vHave.empty());
            if (!locator.vHave.empty()) {
                // It should be impossible for the getheaders request to fail,
                // because we should have cleared the last getheaders timestamp
                // when processing the headers that triggered this call. But
                // it may be possible to bypass this via compactblock
                // processing, so check the result before logging just to be
                // safe.
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

            // Delete this peer's entry in m_headers_presync_stats.
            // If this is m_headers_presync_bestpeer, it will be replaced later
            // by the next peer that triggers the else{} branch below.
            LOCK(m_headers_presync_mutex);
            m_headers_presync_stats.erase(pfrom.GetId());
        } else {
            // Build statistics for this peer's sync.
            HeadersPresyncStats stats;
            stats.first = peer.m_headers_sync->GetPresyncWork();
            if (peer.m_headers_sync->GetState() == HeadersSyncState::State::PRESYNC) {
                stats.second = {peer.m_headers_sync->GetPresyncHeight(),
                                peer.m_headers_sync->GetPresyncTime()};
            }

            // Update statistics in stats.
            LOCK(m_headers_presync_mutex);
            m_headers_presync_stats[pfrom.GetId()] = stats;
            auto best_it = m_headers_presync_stats.find(m_headers_presync_bestpeer);
            bool best_updated = false;
            if (best_it == m_headers_presync_stats.end()) {
                // If the cached best peer is outdated, iterate over all remaining ones (including
                // newly updated one) to find the best one.
                NodeId peer_best{-1};
                const HeadersPresyncStats* stat_best{nullptr};
                for (const auto& [peer, stat] : m_headers_presync_stats) {
                    if (!stat_best || stat > *stat_best) {
                        peer_best = peer;
                        stat_best = &stat;
                    }
                }
                m_headers_presync_bestpeer = peer_best;
                best_updated = (peer_best == pfrom.GetId());
            } else if (best_it->first == pfrom.GetId() || stats > best_it->second) {
                // pfrom was and remains the best peer, or pfrom just became best.
                m_headers_presync_bestpeer = pfrom.GetId();
                best_updated = true;
            }
            if (best_updated && stats.second.has_value()) {
                // If the best peer updated, and it is in its first phase, signal.
                m_headers_presync_should_signal = true;
            }
        }

        if (result.success) {
            // We only overwrite the headers passed in if processing was
            // successful.
            headers.swap(result.pow_validated_headers);
        }

        return result.success;
    }
    // Either we didn't have a sync in progress, or something went wrong
    // processing these headers, or we are returning headers to the caller to
    // process.
    return false;
}

bool PeerManagerImpl::TryLowWorkHeadersSync(Peer& peer, CNode& pfrom, const CBlockIndex* chain_start_header, std::vector<CBlockHeader>& headers)
{
    // Calculate the total work on this chain.
    arith_uint256 total_work = chain_start_header->nChainTrust + CalculateHeadersWork(headers);

    // Our dynamic anti-DoS threshold (minimum work required on a headers chain
    // before we'll store it)
    arith_uint256 minimum_chain_work = GetAntiDoSWorkThreshold();

    // Avoid DoS via low-difficulty-headers by only processing if the headers
    // are part of a chain with sufficient work.
    if (total_work < minimum_chain_work) {
        // Only try to sync with this peer if their headers message was full;
        // otherwise they don't have more headers after this so no point in
        // trying to sync their too-little-work chain.
        if (headers.size() == MAX_HEADERS_RESULTS) {
            // Note: we could advance to the last header in this set that is
            // known to us, rather than starting at the first header (which we
            // may already have); however this is unlikely to matter much since
            // ProcessHeadersMessage() already handles the case where all
            // headers in a received message are already known and are
            // ancestors of m_best_header or chainActive.Tip(), by skipping
            // this logic in that case. So even if the first header in this set
            // of headers is known, some header in this set must be new, so
            // advancing to the first unknown header would be a small effect.
            LOCK(peer.m_headers_sync_mutex);
            peer.m_headers_sync.reset(new HeadersSyncState(peer.m_id, m_chainparams.GetConsensus(),
                chain_start_header, minimum_chain_work));

            // Now a HeadersSyncState object for tracking this synchronization
            // is created, process the headers using it as normal. Failures are
            // handled inside of IsContinuationOfLowWorkHeadersSync.
            (void)IsContinuationOfLowWorkHeadersSync(peer, pfrom, headers);
        } else {
            LogPrint(BCLog::NET, "Ignoring low-work chain (height=%u) from peer=%d\n", chain_start_header->nHeight + headers.size(), pfrom.GetId());
        }

        // The peer has not yet given us a chain that meets our work threshold,
        // so we want to prevent further processing of the headers in any case.
        headers = {};
        return true;
    }

    return false;
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

void PeerManagerImpl::ProcessHeadersMessage(CNode& pfrom, Peer& peer,
                                            std::vector<CBlockHeader>&& headers,
                                            bool via_compact_block)
{
    size_t nCount = headers.size();

    if (nCount == 0) {
        // Nothing interesting. Stop asking this peers for more headers.
        // If we were in the middle of headers sync, receiving an empty headers
        // message suggests that the peer suddenly has nothing to give us
        // (perhaps it reorged to our chain). Clear download state for this peer.
        LOCK(peer.m_headers_sync_mutex);
        if (peer.m_headers_sync) {
            peer.m_headers_sync.reset(nullptr);
            LOCK(m_headers_presync_mutex);
            m_headers_presync_stats.erase(pfrom.GetId());
        }
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

    const CBlockIndex *pindexLast = nullptr;

    // We'll set already_validated_work to true if these headers are
    // successfully processed as part of a low-work headers sync in progress
    // (either in PRESYNC or REDOWNLOAD phase).
    // If true, this will mean that any headers returned to us (ie during
    // REDOWNLOAD) can be validated without further anti-DoS checks.
    bool already_validated_work = false;

    // If we're in the middle of headers sync, let it do its magic.
    bool have_headers_sync = false;
    {
        LOCK(peer.m_headers_sync_mutex);

        already_validated_work = IsContinuationOfLowWorkHeadersSync(peer, pfrom, headers);

        // The headers we passed in may have been:
        // - untouched, perhaps if no headers-sync was in progress, or some
        //   failure occurred
        // - erased, such as if the headers were successfully processed and no
        //   additional headers processing needs to take place (such as if we
        //   are still in PRESYNC)
        // - replaced with headers that are now ready for validation, such as
        //   during the REDOWNLOAD phase of a low-work headers sync.
        // So just check whether we still have headers that we need to process,
        // or not.
        if (headers.empty()) {
            return;
        }

        have_headers_sync = !!peer.m_headers_sync;
    }

    // Do these headers connect to something in our block index?
    const CBlockIndex *chain_start_header{WITH_LOCK(::cs_main, return m_chainman.m_blockman.LookupBlockIndex(headers[0].hashPrevBlock))};
    bool headers_connect_blockindex{chain_start_header != nullptr};

    if (!headers_connect_blockindex) {
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

    // If the headers we received are already in memory and an ancestor of
    // m_best_header or our tip, skip anti-DoS checks. These headers will not
    // use any more memory (and we are not leaking information that could be
    // used to fingerprint us).
    const CBlockIndex *last_received_header{nullptr};
    {
        LOCK(cs_main);
        last_received_header = m_chainman.m_blockman.LookupBlockIndex(headers.back().GetHash());
        if (IsAncestorOfBestHeaderOrTip(last_received_header)) {
            already_validated_work = true;
        }
    }

    // If our peer has NetPermissionFlags::NoBan privileges, then bypass our
    // anti-DoS logic (this saves bandwidth when we connect to a trusted peer
    // on startup).
    if (pfrom.HasPermission(NetPermissionFlags::NoBan)) {
        already_validated_work = true;
    }

    // At this point, the headers connect to something in our block index.
    // Do anti-DoS checks to determine if we should process or store for later
    // processing.
    if (!already_validated_work && TryLowWorkHeadersSync(peer, pfrom,
                chain_start_header, headers)) {
        // If we successfully started a low-work headers sync, then there
        // should be no headers to process any further.
        Assume(headers.empty());
        return;
    }

    // At this point, we have a set of headers with sufficient work on them
    // which can be processed.

    // If we don't have the last header, then this peer will have given us
    // something new (if these headers are valid).
    bool received_new_header{last_received_header == nullptr};

    // Now process all the headers.
    BlockValidationState state;

    int32_t& nPoSTemperature = mapPoSTemperature[pfrom.addr];
    if (!m_chainman.ProcessNewBlockHeaders(nPoSTemperature, pfrom.lastAcceptedHeader, headers, /*min_pow_checked=*/true, state, m_chainparams, &pindexLast)) {
        if (state.IsInvalid()) {
            MaybePunishNodeForBlock(pfrom.GetId(), state, via_compact_block, "invalid header received");
            return;
        }
    }
    assert(pindexLast);

    // Consider fetching more headers if we are not using our headers-sync mechanism.
    if (nCount == MAX_HEADERS_RESULTS && !have_headers_sync) {
        // Headers message had its maximum size; the peer may have more headers.
        if (MaybeSendGetHeaders(pfrom, GetLocator(pindexLast), peer)) {
            LogPrint(BCLog::NET, "more getheaders (%d) to end to peer=%d (startheight:%d)\n",
                    pindexLast->nHeight, pfrom.GetId(), peer.m_starting_height);
        }
    }

    UpdatePeerStateForReceivedHeaders(pfrom, peer, *pindexLast, received_new_header, nCount == MAX_HEADERS_RESULTS);

    // Consider immediately downloading blocks.
    HeadersDirectFetchBlocks(pfrom, peer, *pindexLast);

    return;
}
