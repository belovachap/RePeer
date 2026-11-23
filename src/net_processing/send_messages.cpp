// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing/peer_manager_impl.h>
#include <net_processing/constants.h>
#include <kernel.h>

using node::ReadBlockFromDisk;

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
        /* As std::make_heap produces a max-heap, we want the entries with the
         * fewest ancestors/highest fee to sort later. */
        return mp->CompareDepthAndScore(*b, *a, m_wtxid_relay);
    }
};
} // namespace

void PeerManagerImpl::MaybeSendPing(CNode& node_to, Peer& peer, std::chrono::microseconds now)
{
    if (m_connman.ShouldRunInactivityChecks(node_to, std::chrono::duration_cast<std::chrono::seconds>(now)) &&
        peer.m_ping_nonce_sent &&
        now > peer.m_ping_start.load() + TIMEOUT_INTERVAL)
    {
        // The ping timeout is using mocktime. To disable the check during
        // testing, increase -peertimeout.
        LogPrint(BCLog::NET, "ping timeout: %fs peer=%d\n", 0.000001 * count_microseconds(now - peer.m_ping_start.load()), peer.m_id);
        node_to.fDisconnect = true;
        return;
    }

    const CNetMsgMaker msgMaker(node_to.GetCommonVersion());
    bool pingSend = false;

    if (peer.m_ping_queued) {
        // RPC ping request by user
        pingSend = true;
    }

    if (peer.m_ping_nonce_sent == 0 && now > peer.m_ping_start.load() + PING_INTERVAL) {
        // Ping automatically sent as a latency probe & keepalive.
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
            // Peer is too old to support ping command with nonce, pong will never arrive.
            peer.m_ping_nonce_sent = 0;
            m_connman.PushMessage(&node_to, msgMaker.Make(NetMsgType::PING));
        }
    }
}

void PeerManagerImpl::MaybeSendSendHeaders(CNode& node, Peer& peer)
{
    // Delay sending SENDHEADERS (BIP 130) until we're done with an
    // initial-headers-sync with this peer. Receiving headers announcements for
    // new blocks while trying to sync their headers chain is problematic,
    // because of the state tracking done.
    if (!peer.m_sent_sendheaders && node.GetCommonVersion() >= SENDHEADERS_VERSION) {
        LOCK(cs_main);
        CNodeState &state = *State(node.GetId());
        if (state.pindexBestKnownBlock != nullptr &&
                state.pindexBestKnownBlock->nChainTrust > m_chainman.MinimumChainWork()) {
            // Tell our peer we prefer to receive headers rather than inv's
            // We send this to non-NODE NETWORK peers as well, because even
            // non-NODE NETWORK peers can announce blocks (such as pruning
            // nodes)
            m_connman.PushMessage(&node, CNetMsgMaker(node.GetCommonVersion()).Make(NetMsgType::SENDHEADERS));
            peer.m_sent_sendheaders = true;
        }
    }
}

bool PeerManagerImpl::SendMessages(CNode* pto)
{
    AssertLockHeld(g_msgproc_mutex);

    PeerRef peer = GetPeerRef(pto->GetId());
    if (!peer) return false;
    const Consensus::Params& consensusParams = m_chainparams.GetConsensus();

    // We must call MaybeDiscourageAndDisconnect first, to ensure that we'll
    // disconnect misbehaving peers even before the version handshake is complete.
    if (MaybeDiscourageAndDisconnect(*pto, *peer)) return true;

    // Don't send anything until the version handshake is complete
    if (!pto->fSuccessfullyConnected || pto->fDisconnect)
        return true;

    // If we get here, the outgoing message serialization version is set and can't change.
    const CNetMsgMaker msgMaker(pto->GetCommonVersion());

    const auto current_time{GetTime<std::chrono::microseconds>()};

    if (pto->IsAddrFetchConn() && current_time - pto->m_connected > 10 * AVG_ADDRESS_BROADCAST_INTERVAL) {
        LogPrint(BCLog::NET, "addrfetch connection timeout; disconnecting peer=%d\n", pto->GetId());
        pto->fDisconnect = true;
        return true;
    }

    MaybeSendPing(*pto, *peer, current_time);

    // MaybeSendPing may have marked peer for disconnection
    if (pto->fDisconnect) return true;

    MaybeSendAddr(*pto, *peer, current_time);

    MaybeSendSendHeaders(*pto, *peer);

    {
        LOCK(cs_main);

        CNodeState &state = *State(pto->GetId());

        // Start block sync
        if (m_chainman.m_best_header == nullptr) {
            m_chainman.m_best_header = m_chainman.ActiveChain().Tip();
        }

        // Determine whether we might try initial headers sync or parallel
        // block download from this peer -- this mostly affects behavior while
        // in IBD (once out of IBD, we sync from all peers).
        bool sync_blocks_and_headers_from_peer = false;
        if (state.fPreferredDownload) {
            sync_blocks_and_headers_from_peer = true;
        } else if (CanServeBlocks(*peer) && !pto->IsAddrFetchConn()) {
            // Typically this is an inbound peer. If we don't have any outbound
            // peers, or if we aren't downloading any blocks from such peers,
            // then allow block downloads from this peer, too.
            // We prefer downloading blocks from outbound peers to avoid
            // putting undue load on (say) some home user who is just making
            // outbound connections to the network, but if our only source of
            // the latest blocks is from an inbound peer, we have to be sure to
            // eventually download it (and not just wait indefinitely for an
            // outbound peer to have it).
            if (m_num_preferred_download_peers == 0 || mapBlocksInFlight.empty()) {
                sync_blocks_and_headers_from_peer = true;
            }
        }

        if (!state.fSyncStarted && CanServeBlocks(*peer) && !m_chainman.m_blockman.LoadingBlocks()) {
            // Only actively request headers from a single peer, unless we're close to today.
            if ((nSyncStarted == 0 && sync_blocks_and_headers_from_peer) || m_chainman.m_best_header->Time() > GetAdjustedTime() - 24h) {
                const CBlockIndex* pindexStart = m_chainman.m_best_header;
                /* If possible, start at the block preceding the currently
                   best known header.  This ensures that we always get a
                   non-empty list of headers back as long as the peer
                   is up-to-date.  With a non-empty response, we can initialise
                   the peer's known best block.  This wouldn't be possible
                   if we requested starting at m_chainman.m_best_header and
                   got back an empty response.  */
                if (pindexStart->pprev)
                    pindexStart = pindexStart->pprev;
                if (MaybeSendGetHeaders(*pto, GetLocator(pindexStart), *peer)) {
                    LogPrint(BCLog::NET, "initial getheaders (%d) to peer=%d (startheight:%d)\n", pindexStart->nHeight, pto->GetId(), peer->m_starting_height);

                    state.fSyncStarted = true;
                    peer->m_headers_sync_timeout = current_time + HEADERS_DOWNLOAD_TIMEOUT_BASE +
                        (
                         // Convert HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER to microseconds before scaling
                         // to maintain precision
                         std::chrono::microseconds{HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER} *
                         Ticks<std::chrono::seconds>(GetAdjustedTime() - m_chainman.m_best_header->Time()) / consensusParams.nPowTargetSpacing
                        );
                    nSyncStarted++;
                }
            }
        }

        //
        // Try sending block announcements via headers
        //
        {
            // If we have no more than MAX_BLOCKS_TO_ANNOUNCE in our
            // list of block hashes we're relaying, and our peer wants
            // headers announcements, then find the first header
            // not yet known to our peer but would connect, and send.
            // If no header would connect, or if we have too many
            // blocks, or if the peer doesn't want headers, just
            // add all to the inv queue.
            LOCK(peer->m_block_inv_mutex);
            std::vector<CBlock> vHeaders;
            bool fRevertToInv = ((!peer->m_prefers_headers &&
                                 (!state.m_requested_hb_cmpctblocks || peer->m_blocks_for_headers_relay.size() > 1)) ||
                                 peer->m_blocks_for_headers_relay.size() > MAX_BLOCKS_TO_ANNOUNCE);
            const CBlockIndex *pBestIndex = nullptr; // last header queued for delivery
            ProcessBlockAvailability(pto->GetId()); // ensure pindexBestKnownBlock is up-to-date

            if (!fRevertToInv) {
                bool fFoundStartingHeader = false;
                // Try to find first header that our peer doesn't have, and
                // then send all headers past that one.  If we come across any
                // headers that aren't on m_chainman.ActiveChain(), give up.
                for (const uint256& hash : peer->m_blocks_for_headers_relay) {
                    const CBlockIndex* pindex = m_chainman.m_blockman.LookupBlockIndex(hash);
                    assert(pindex);
                    if (m_chainman.ActiveChain()[pindex->nHeight] != pindex) {
                        // Bail out if we reorged away from this block
                        fRevertToInv = true;
                        break;
                    }
                    if (pBestIndex != nullptr && pindex->pprev != pBestIndex) {
                        // This means that the list of blocks to announce don't
                        // connect to each other.
                        // This shouldn't really be possible to hit during
                        // regular operation (because reorgs should take us to
                        // a chain that has some block not on the prior chain,
                        // which should be caught by the prior check), but one
                        // way this could happen is by using invalidateblock /
                        // reconsiderblock repeatedly on the tip, causing it to
                        // be added multiple times to m_blocks_for_headers_relay.
                        // Robustly deal with this rare situation by reverting
                        // to an inv.
                        fRevertToInv = true;
                        break;
                    }
                    pBestIndex = pindex;
                    if (fFoundStartingHeader) {
                        // add this to the headers message
                        vHeaders.push_back(pindex->GetBlockHeader());
                    } else if (PeerHasHeader(&state, pindex)) {
                        continue; // keep looking for the first new block
                    } else if (pindex->pprev == nullptr || PeerHasHeader(&state, pindex->pprev)) {
                        // Peer doesn't have this header but they do have the prior one.
                        // Start sending headers.
                        fFoundStartingHeader = true;
                        vHeaders.push_back(pindex->GetBlockHeader());
                    } else {
                        // Peer doesn't have this header or the prior one -- nothing will
                        // connect, so bail out.
                        fRevertToInv = true;
                        break;
                    }
                }
            }
            if (!fRevertToInv && !vHeaders.empty()) {
                if (vHeaders.size() == 1 && state.m_requested_hb_cmpctblocks) {
                    // We only send up to 1 block as header-and-ids, as otherwise
                    // probably means we're doing an initial-ish-sync or they're slow
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
                } else if (peer->m_prefers_headers) {
                    if (vHeaders.size() > 1) {
                        LogPrint(BCLog::NET, "%s: %u headers, range (%s, %s), to peer=%d\n", __func__,
                                vHeaders.size(),
                                vHeaders.front().GetHash().ToString(),
                                vHeaders.back().GetHash().ToString(), pto->GetId());
                    } else {
                        LogPrint(BCLog::NET, "%s: sending header %s to peer=%d\n", __func__,
                                vHeaders.front().GetHash().ToString(), pto->GetId());
                    }
                    m_connman.PushMessage(pto, msgMaker.Make(NetMsgType::HEADERS, vHeaders));
                    state.pindexBestHeaderSent = pBestIndex;
                } else
                    fRevertToInv = true;
            }
            if (fRevertToInv) {
                // If falling back to using an inv, just try to inv the tip.
                // The last entry in m_blocks_for_headers_relay was our tip at some point
                // in the past.
                if (!peer->m_blocks_for_headers_relay.empty()) {
                    const uint256& hashToAnnounce = peer->m_blocks_for_headers_relay.back();
                    const CBlockIndex* pindex = m_chainman.m_blockman.LookupBlockIndex(hashToAnnounce);
                    assert(pindex);

                    // Warn if we're announcing a block that is not on the main chain.
                    // This should be very rare and could be optimized out.
                    // Just log for now.
                    if (m_chainman.ActiveChain()[pindex->nHeight] != pindex) {
                        LogPrint(BCLog::NET, "Announcing block %s not on main chain (tip=%s)\n",
                            hashToAnnounce.ToString(), m_chainman.ActiveChain().Tip()->GetBlockHash().ToString());
                    }

                    // If the peer's chain has this block, don't inv it back.
                    if (!PeerHasHeader(&state, pindex)) {
                        peer->m_blocks_for_inv_relay.push_back(hashToAnnounce);
                        LogPrint(BCLog::NET, "%s: sending inv peer=%d hash=%s\n", __func__,
                            pto->GetId(), hashToAnnounce.ToString());
                    }
                }
            }
            peer->m_blocks_for_headers_relay.clear();
        }

        //
        // Message: inventory
        //
        std::vector<CInv> vInv;
        {
            LOCK(peer->m_block_inv_mutex);
            vInv.reserve(std::max<size_t>(peer->m_blocks_for_inv_relay.size(), INVENTORY_BROADCAST_MAX));

            // Add blocks
            for (const uint256& hash : peer->m_blocks_for_inv_relay) {
                vInv.push_back(CInv(MSG_BLOCK, hash));
                if (vInv.size() == MAX_INV_SZ) {
                    m_connman.PushMessage(pto, msgMaker.Make(NetMsgType::INV, vInv));
                    vInv.clear();
                }
            }
            peer->m_blocks_for_inv_relay.clear();
        }

        if (auto tx_relay = peer->GetTxRelay(); tx_relay != nullptr) {
                LOCK(tx_relay->m_tx_inventory_mutex);
                // Check whether periodic sends should happen
                bool fSendTrickle = pto->HasPermission(NetPermissionFlags::NoBan);
                if (tx_relay->m_next_inv_send_time < current_time) {
                    fSendTrickle = true;
                    if (pto->IsInboundConn()) {
                        tx_relay->m_next_inv_send_time = NextInvToInbounds(current_time, INBOUND_INVENTORY_BROADCAST_INTERVAL);
                    } else {
                        tx_relay->m_next_inv_send_time = GetExponentialRand(current_time, OUTBOUND_INVENTORY_BROADCAST_INTERVAL);
                    }
                }

                // Time to send but the peer has requested we not relay transactions.
                if (fSendTrickle) {
                    LOCK(tx_relay->m_bloom_filter_mutex);
                    if (!tx_relay->m_relay_txs) tx_relay->m_tx_inventory_to_send.clear();
                }

                // Respond to BIP35 mempool requests
                if (fSendTrickle && tx_relay->m_send_mempool) {
                    auto vtxinfo = m_mempool.infoAll();
                    tx_relay->m_send_mempool = false;
                    CAmount filterrate = 0;

                    LOCK(tx_relay->m_bloom_filter_mutex);

                    for (const auto& txinfo : vtxinfo) {
                        const uint256& hash = peer->m_wtxid_relay ? txinfo.tx->GetWitnessHash() : txinfo.tx->GetHash();
                        CInv inv(peer->m_wtxid_relay ? MSG_WTX : MSG_TX, hash);
                        tx_relay->m_tx_inventory_to_send.erase(hash);
                        if (filterrate) {
                            if (txinfo.fee < filterrate)
                                continue;
                        }
                        if (tx_relay->m_bloom_filter) {
                            if (!tx_relay->m_bloom_filter->IsRelevantAndUpdate(*txinfo.tx)) continue;
                        }
                        tx_relay->m_tx_inventory_known_filter.insert(hash);
                        // Responses to MEMPOOL requests bypass the m_recently_announced_invs filter.
                        vInv.push_back(inv);
                        if (vInv.size() == MAX_INV_SZ) {
                            m_connman.PushMessage(pto, msgMaker.Make(NetMsgType::INV, vInv));
                            vInv.clear();
                        }
                    }
                    tx_relay->m_last_mempool_req = std::chrono::duration_cast<std::chrono::seconds>(current_time);
                }

                // Determine transactions to relay
                if (fSendTrickle) {
                    // Produce a vector with all candidates for sending
                    std::vector<std::set<uint256>::iterator> vInvTx;
                    vInvTx.reserve(tx_relay->m_tx_inventory_to_send.size());
                    for (std::set<uint256>::iterator it = tx_relay->m_tx_inventory_to_send.begin(); it != tx_relay->m_tx_inventory_to_send.end(); it++) {
                        vInvTx.push_back(it);
                    }
                    CAmount filterrate = 0;
                    // Topologically and fee-rate sort the inventory we send for privacy and priority reasons.
                    // A heap is used so that not all items need sorting if only a few are being sent.
                    CompareInvMempoolOrder compareInvMempoolOrder(&m_mempool, peer->m_wtxid_relay);
                    std::make_heap(vInvTx.begin(), vInvTx.end(), compareInvMempoolOrder);
                    // No reason to drain out at many times the network's capacity,
                    // especially since we have many peers and some will draw much shorter delays.
                    unsigned int nRelayedTransactions = 0;
                    LOCK(tx_relay->m_bloom_filter_mutex);
                    size_t broadcast_max{INVENTORY_BROADCAST_MAX + (tx_relay->m_tx_inventory_to_send.size()/1000)*5};
                    broadcast_max = std::min<size_t>(1000, broadcast_max);
                    while (!vInvTx.empty() && nRelayedTransactions < broadcast_max) {
                        // Fetch the top element from the heap
                        std::pop_heap(vInvTx.begin(), vInvTx.end(), compareInvMempoolOrder);
                        std::set<uint256>::iterator it = vInvTx.back();
                        vInvTx.pop_back();
                        uint256 hash = *it;
                        CInv inv(peer->m_wtxid_relay ? MSG_WTX : MSG_TX, hash);
                        // Remove it from the to-be-sent set
                        tx_relay->m_tx_inventory_to_send.erase(it);
                        // Check if not in the filter already
                        if (tx_relay->m_tx_inventory_known_filter.contains(hash)) {
                            continue;
                        }
                        // Not in the mempool anymore? don't bother sending it.
                        auto txinfo = m_mempool.info(ToGenTxid(inv));
                        if (!txinfo.tx) {
                            continue;
                        }
                        auto txid = txinfo.tx->GetHash();
                        auto wtxid = txinfo.tx->GetWitnessHash();
                        // Peer told you to not send transactions at that feerate? Don't bother sending it.
                        if (filterrate && txinfo.fee < filterrate) {
                            continue;
                        }
                        if (tx_relay->m_bloom_filter && !tx_relay->m_bloom_filter->IsRelevantAndUpdate(*txinfo.tx)) continue;
                        // Send
                        tx_relay->m_recently_announced_invs.insert(hash);
                        vInv.push_back(inv);
                        nRelayedTransactions++;
                        {
                            // Expire old relay messages
                            while (!g_relay_expiration.empty() && g_relay_expiration.front().first < current_time)
                            {
                                mapRelay.erase(g_relay_expiration.front().second);
                                g_relay_expiration.pop_front();
                            }

                            auto ret = mapRelay.emplace(txid, std::move(txinfo.tx));
                            if (ret.second) {
                                g_relay_expiration.emplace_back(current_time + RELAY_TX_CACHE_TIME, ret.first);
                            }
                            // Add wtxid-based lookup into mapRelay as well, so that peers can request by wtxid
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
                            // Insert txid into m_tx_inventory_known_filter, even for
                            // wtxidrelay peers. This prevents re-adding of
                            // unconfirmed parents to the recently_announced
                            // filter, when a child tx is requested. See
                            // ProcessGetData().
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
            // Stalling only triggers when the block download window cannot move. During normal steady state,
            // the download window should be much larger than the to-be-downloaded set of blocks, so disconnection
            // should only happen during initial block download.
            LogPrintf("Peer=%d is stalling block download, disconnecting\n", pto->GetId());
            pto->fDisconnect = true;
            // Increase timeout for the next peer so that we don't disconnect multiple peers if our own
            // bandwidth is insufficient.
            const auto new_timeout = std::min(2 * stalling_timeout, BLOCK_STALLING_TIMEOUT_MAX);
            if (stalling_timeout != new_timeout && m_block_stalling_timeout.compare_exchange_strong(stalling_timeout, new_timeout)) {
                LogPrint(BCLog::NET, "Increased stalling timeout temporarily to %d seconds\n", count_seconds(new_timeout));
            }
            return true;
        }
        // In case there is a block that has been in flight from this peer for block_interval * (1 + 0.5 * N)
        // (with N the number of peers from which we're downloading validated blocks), disconnect due to timeout.
        // We compensate for other peers to prevent killing off peers due to our own downstream link
        // being saturated. We only count validated in-flight blocks so peers can't advertise non-existing block hashes
        // to unreasonably increase our timeout.
        if (state.vBlocksInFlight.size() > 0) {
            QueuedBlock &queuedBlock = state.vBlocksInFlight.front();
            int nOtherPeersWithValidatedDownloads = m_peers_downloading_from - 1;
            if (current_time > state.m_downloading_since + std::chrono::seconds{consensusParams.nPowTargetSpacing} * (BLOCK_DOWNLOAD_TIMEOUT_BASE + BLOCK_DOWNLOAD_TIMEOUT_PER_PEER * nOtherPeersWithValidatedDownloads)) {
                LogPrintf("Timeout downloading block %s from peer=%d, disconnecting\n", queuedBlock.pindex->GetBlockHash().ToString(), pto->GetId());
                pto->fDisconnect = true;
                return true;
            }
        }
        // Check for headers sync timeouts
        if (state.fSyncStarted && peer->m_headers_sync_timeout < std::chrono::microseconds::max()) {
            // Detect whether this is a stalling initial-headers-sync peer
            if (m_chainman.m_best_header->Time() <= GetAdjustedTime() - 24h) {
                if (current_time > peer->m_headers_sync_timeout && nSyncStarted == 1 && (m_num_preferred_download_peers - state.fPreferredDownload >= 1)) {
                    // Disconnect a peer (without NetPermissionFlags::NoBan permission) if it is our only sync peer,
                    // and we have others we could be using instead.
                    // Note: If all our peers are inbound, then we won't
                    // disconnect our sync peer for stalling; we have bigger
                    // problems if we can't get any outbound peers.
                    if (!pto->HasPermission(NetPermissionFlags::NoBan)) {
                        LogPrintf("Timeout downloading headers from peer=%d, disconnecting\n", pto->GetId());
                        pto->fDisconnect = true;
                        return true;
                    } else {
                        LogPrintf("Timeout downloading headers from noban peer=%d, not disconnecting\n", pto->GetId());
                        // Reset the headers sync state so that we have a
                        // chance to try downloading from a different peer.
                        // Note: this will also result in at least one more
                        // getheaders message to be sent to
                        // this peer (eventually).
                        state.fSyncStarted = false;
                        nSyncStarted--;
                        peer->m_headers_sync_timeout = 0us;
                    }
                }
            } else {
                // After we've caught up once, reset the timeout so we can't trigger
                // disconnect later.
                peer->m_headers_sync_timeout = std::chrono::microseconds::max();
            }
        }

        // Check that outbound peers have reasonable chains
        // GetTime() is used by this anti-DoS logic so we can test this using mocktime
        ConsiderEviction(*pto, *peer, GetTime<std::chrono::seconds>());

        //
        // Message: getdata (blocks)
        //
        std::vector<CInv> vGetData;
        if (CanServeBlocks(*peer) && ((sync_blocks_and_headers_from_peer && !IsLimitedPeer(*peer)) || !m_chainman.ActiveChainstate().IsInitialBlockDownload()) && state.vBlocksInFlight.size() < MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
            std::vector<const CBlockIndex*> vToDownload;
            NodeId staller = -1;
            FindNextBlocksToDownload(*peer, MAX_BLOCKS_IN_TRANSIT_PER_PEER - state.vBlocksInFlight.size(), vToDownload, staller);
            for (const CBlockIndex *pindex : vToDownload) {
                uint32_t nFetchFlags = IsBTC16BIPsEnabled(pindex->nTime) ? GetFetchFlags(*peer) : false;
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

        //
        // Message: getdata (transactions)
        //
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
                vGetData.emplace_back(gtxid.IsWtxid() ? MSG_WTX : (MSG_TX | GetFetchFlags(*peer)), gtxid.GetHash());
                if (vGetData.size() >= MAX_GETDATA_SZ) {
                    m_connman.PushMessage(pto, msgMaker.Make(NetMsgType::GETDATA, vGetData));
                    vGetData.clear();
                }
                m_txrequest.RequestedTx(pto->GetId(), gtxid.GetHash(), current_time + GETDATA_TX_INTERVAL);
            } else {
                // We have already seen this transaction, no need to download. This is just a belt-and-suspenders, as
                // this should already be called whenever a transaction becomes AlreadyHaveTx().
                m_txrequest.ForgetTxHash(gtxid.GetHash());
            }
        }

        if (!vGetData.empty())
            m_connman.PushMessage(pto, msgMaker.Make(NetMsgType::GETDATA, vGetData));
    } // release cs_main
    return true;
}
