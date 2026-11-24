// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing/peer_manager_impl.h>
#include <net_processing/constants.h>
#include <kernel.h>

using node::ReadBlockFromDisk;

// ============================================================================
// PHASE 4: NORMAL OPERATIONS
//
// Purpose: Transaction relay, address relay, compact blocks, pings,
//          feefilter, and all steady-state peer interactions.
// Entry:   When IsInitialBlockDownload() returns false.
// Exit:    Never (steady state).
//
// This phase handles ALL post-IBD operations. No block download windowing.
// No headers sync. No presync. Transaction and address relay are fully active.
// ============================================================================

bool PeerManagerImpl::IsNormalPhase() const
{
    return !m_chainman.ActiveChainstate().IsInitialBlockDownload();
}

bool PeerManagerImpl::RejectIncomingTxs(const CNode& peer) const
{
    // block-relay-only peers may never send txs to us
    if (peer.IsBlockOnlyConn()) return true;
    if (peer.IsFeelerConn()) return true;
    // In -blocksonly mode, peers need the 'relay' permission to send txs to us
    if (m_ignore_incoming_txs && !peer.HasPermission(NetPermissionFlags::Relay)) return true;
    return false;
}

bool PeerManagerImpl::AlreadyHaveTx(const GenTxid& gtxid)
{
    if (m_chainman.ActiveChain().Tip()->GetBlockHash() != hashRecentRejectsChainTip) {
        // If the chain tip has changed previously rejected transactions
        // might be now valid, e.g. due to a nLockTime'd tx becoming valid,
        // or a double-spend. Reset the rejects filter and give those
        // txs a second chance.
        hashRecentRejectsChainTip = m_chainman.ActiveChain().Tip()->GetBlockHash();
        m_recent_rejects.reset();
    }

    const uint256& hash = gtxid.GetHash();

    if (m_orphanage.HaveTx(gtxid)) return true;

    {
        LOCK(m_recent_confirmed_transactions_mutex);
        if (m_recent_confirmed_transactions.contains(hash)) return true;
    }

    return m_recent_rejects.contains(hash) || m_mempool.exists(gtxid);
}

void PeerManagerImpl::RelayTransaction(const uint256& txid, const uint256& wtxid)
{
    LOCK(m_peer_mutex);
    for(auto& it : m_peer_map) {
        Peer& peer = *it.second;
        auto tx_relay = peer.GetTxRelay();
        if (!tx_relay) continue;

        LOCK(tx_relay->m_tx_inventory_mutex);
        // Only queue transactions for announcement once the version handshake
        // is completed. The time of arrival for these transactions is
        // otherwise at risk of leaking to a spy, if the spy is able to
        // distinguish transactions received during the handshake from the rest
        // in the announcement.
        if (tx_relay->m_next_inv_send_time == 0s) continue;

        const uint256& hash{peer.m_wtxid_relay ? wtxid : txid};
        if (!tx_relay->m_tx_inventory_known_filter.contains(hash)) {
            tx_relay->m_tx_inventory_to_send.insert(hash);
        }
    };
}

void PeerManagerImpl::AddTxAnnouncement(const CNode& node, const GenTxid& gtxid, std::chrono::microseconds current_time)
{
    AssertLockHeld(::cs_main); // For m_txrequest
    NodeId nodeid = node.GetId();
    if (!node.HasPermission(NetPermissionFlags::Relay) && m_txrequest.Count(nodeid) >= MAX_PEER_TX_ANNOUNCEMENTS) {
        // Too many queued announcements from this peer
        return;
    }
    const CNodeState* state = State(nodeid);

    // Decide the TxRequestTracker parameters for this announcement:
    // - "preferred": if fPreferredDownload is set (= outbound, or NetPermissionFlags::NoBan permission)
    // - "reqtime": current time plus delays for:
    //   - NONPREF_PEER_TX_DELAY for announcements from non-preferred connections
    //   - TXID_RELAY_DELAY for txid announcements while wtxid peers are available
    //   - OVERLOADED_PEER_TX_DELAY for announcements from peers which have at least
    //     MAX_PEER_TX_REQUEST_IN_FLIGHT requests in flight (and don't have NetPermissionFlags::Relay).
    auto delay{0us};
    const bool preferred = state->fPreferredDownload;
    if (!preferred) delay += NONPREF_PEER_TX_DELAY;
    if (!gtxid.IsWtxid() && m_wtxid_relay_peers > 0) delay += TXID_RELAY_DELAY;
    const bool overloaded = !node.HasPermission(NetPermissionFlags::Relay) &&
        m_txrequest.CountInFlight(nodeid) >= MAX_PEER_TX_REQUEST_IN_FLIGHT;
    if (overloaded) delay += OVERLOADED_PEER_TX_DELAY;
    m_txrequest.ReceivedInv(nodeid, gtxid, preferred, current_time + delay);
}

void PeerManagerImpl::AddToCompactExtraTransactions(const CTransactionRef& tx)
{
    size_t max_extra_txn = gArgs.GetIntArg("-blockreconstructionextratxn", DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN);
    if (max_extra_txn <= 0)
        return;
    if (!vExtraTxnForCompact.size())
        vExtraTxnForCompact.resize(max_extra_txn);
    vExtraTxnForCompact[vExtraTxnForCompactIt] = std::make_pair(tx->GetWitnessHash(), tx);
    vExtraTxnForCompactIt = (vExtraTxnForCompactIt + 1) % max_extra_txn;
}

CTransactionRef PeerManagerImpl::FindTxForGetData(const Peer::TxRelay& tx_relay, const GenTxid& gtxid, const std::chrono::seconds mempool_req, const std::chrono::seconds now)
{
    auto txinfo = m_mempool.info(gtxid);
    if (txinfo.tx) {
        // If a TX could have been INVed in reply to a MEMPOOL request,
        // or is older than UNCONDITIONAL_RELAY_DELAY, permit the request
        // unconditionally.
        if ((mempool_req.count() && txinfo.m_time <= mempool_req) || txinfo.m_time <= now - UNCONDITIONAL_RELAY_DELAY) {
            return std::move(txinfo.tx);
        }
    }

    // Otherwise, the transaction must have been announced recently.
    if (tx_relay.m_recently_announced_invs.contains(gtxid.GetHash())) {
        // If it was, it can be relayed from either the mempool...
        if (txinfo.tx) return std::move(txinfo.tx);
        // ... or the relay pool.
        auto mi = mapRelay.find(gtxid.GetHash());
        if (mi != mapRelay.end()) return mi->second;
    }

    return {};
}

void PeerManagerImpl::ProcessGetData(CNode& pfrom, Peer& peer, const std::atomic<bool>& interruptMsgProc)
{
    AssertLockNotHeld(cs_main);

    auto tx_relay = peer.GetTxRelay();

    std::deque<CInv>::iterator it = peer.m_getdata_requests.begin();
    std::vector<CInv> vNotFound;
    const CNetMsgMaker msgMaker(pfrom.GetCommonVersion());

    const auto now{GetTime<std::chrono::seconds>()};
    // Get last mempool request time
    const auto mempool_req = tx_relay != nullptr ? tx_relay->m_last_mempool_req.load() : std::chrono::seconds::min();

    // Process as many TX items from the front of the getdata queue as
    // possible, since they're common and it's efficient to batch process
    // them.
    while (it != peer.m_getdata_requests.end() && it->IsGenTxMsg()) {
        if (interruptMsgProc) return;
        // The send buffer provides backpressure. If there's no space in
        // the buffer, pause processing until the next call.
        if (pfrom.fPauseSend) break;

        const CInv &inv = *it++;

        if (tx_relay == nullptr) {
            // Ignore GETDATA requests for transactions from block-relay-only
            // peers and peers that asked us not to announce transactions.
            continue;
        }

        CTransactionRef tx = FindTxForGetData(*tx_relay, ToGenTxid(inv), mempool_req, now);
        if (tx) {
            // WTX and WITNESS_TX imply we serialize with witness
            int nSendFlags = (inv.IsMsgTx() ? SERIALIZE_TRANSACTION_NO_WITNESS : 0);
            m_connman.PushMessage(&pfrom, msgMaker.Make(nSendFlags, NetMsgType::TX, *tx));
            m_mempool.RemoveUnbroadcastTx(tx->GetHash());
            // As we're going to send tx, make sure its unconfirmed parents are made requestable.
            std::vector<uint256> parent_ids_to_add;
            {
                LOCK(m_mempool.cs);
                auto tx_iter = m_mempool.GetIter(tx->GetHash());
                if (tx_iter) {
                    const CTxMemPoolEntry::Parents& parents = (*tx_iter)->GetMemPoolParentsConst();
                    parent_ids_to_add.reserve(parents.size());
                    for (const CTxMemPoolEntry& parent : parents) {
                        if (parent.GetTime() > now - UNCONDITIONAL_RELAY_DELAY) {
                            parent_ids_to_add.push_back(parent.GetTx().GetHash());
                        }
                    }
                }
            }
            for (const uint256& parent_txid : parent_ids_to_add) {
                // Relaying a transaction with a recent but unconfirmed parent.
                if (WITH_LOCK(tx_relay->m_tx_inventory_mutex, return !tx_relay->m_tx_inventory_known_filter.contains(parent_txid))) {
                    tx_relay->m_recently_announced_invs.insert(parent_txid);
                }
            }
        } else {
            vNotFound.push_back(inv);
        }
    }

    // Only process one BLOCK item per call, since they're uncommon and can be
    // expensive to process.
    if (it != peer.m_getdata_requests.end() && !pfrom.fPauseSend) {
        const CInv &inv = *it++;
        if (inv.IsGenBlkMsg()) {
            ProcessGetBlockData(pfrom, peer, inv);
        }
        // else: If the first item on the queue is an unknown type, we erase it
        // and continue processing the queue on the next call.
    }

    peer.m_getdata_requests.erase(peer.m_getdata_requests.begin(), it);

    if (!vNotFound.empty()) {
        // Let the peer know that we didn't find what it asked for, so it doesn't
        // have to wait around forever.
        // SPV clients care about this message: it's needed when they are
        // recursively walking the dependencies of relevant unconfirmed
        // transactions. SPV clients want to do that because they want to know
        // about (and store and rebroadcast and risk analyze) the dependencies
        // of transactions relevant to them, without having to download the
        // entire memory pool.
        // Also, other nodes can use these messages to automatically request a
        // transaction from some other peer that annnounced it, and stop
        // waiting for us to respond.
        // In normal operation, we often send NOTFOUND messages for parents of
        // transactions that we relay; if a peer is missing a parent, they may
        // assume we have them and request the parents from us.
        m_connman.PushMessage(&pfrom, msgMaker.Make(NetMsgType::NOTFOUND, vNotFound));
    }
}

bool PeerManagerImpl::ProcessOrphanTx(Peer& peer)
{
    AssertLockHeld(g_msgproc_mutex);
    LOCK(cs_main);

    CTransactionRef porphanTx = nullptr;

    while (CTransactionRef porphanTx = m_orphanage.GetTxToReconsider(peer.m_id)) {
        const MempoolAcceptResult result = m_chainman.ProcessTransaction(porphanTx);
        const TxValidationState& state = result.m_state;
        const uint256& orphanHash = porphanTx->GetHash();

        if (result.m_result_type == MempoolAcceptResult::ResultType::VALID) {
            LogPrint(BCLog::MEMPOOL, "   accepted orphan tx %s\n", orphanHash.ToString());
            RelayTransaction(orphanHash, porphanTx->GetWitnessHash());
            m_orphanage.AddChildrenToWorkSet(*porphanTx);
            m_orphanage.EraseTx(orphanHash);
            for (const CTransactionRef& removedTx : result.m_replaced_transactions.value()) {
                AddToCompactExtraTransactions(removedTx);
            }
            return true;
        } else if (state.GetResult() != TxValidationResult::TX_MISSING_INPUTS) {
            if (state.IsInvalid()) {
                LogPrint(BCLog::MEMPOOL, "   invalid orphan tx %s from peer=%d. %s\n",
                    orphanHash.ToString(),
                    peer.m_id,
                    state.ToString());
                // Maybe punish peer that gave us an invalid orphan tx
                MaybePunishNodeForTx(peer.m_id, state);
            }
            // Has inputs but not accepted to mempool
            // Probably non-standard or insufficient fee
            LogPrint(BCLog::MEMPOOL, "   removed orphan tx %s\n", orphanHash.ToString());
            if (state.GetResult() != TxValidationResult::TX_WITNESS_STRIPPED) {
                // We can add the wtxid of this transaction to our reject filter.
                // Do not add txids of witness transactions or witness-stripped
                // transactions to the filter, as they can have been malleated;
                // adding such txids to the reject filter would potentially
                // interfere with relay of valid transactions from peers that
                // do not support wtxid-based relay. See
                // https://github.com/bitcoin/bitcoin/issues/8279 for details.
                // We can remove this restriction (and always add wtxids to
                // the filter even for witness stripped transactions) once
                // wtxid-based relay is broadly deployed.
                // See also comments in https://github.com/bitcoin/bitcoin/pull/18044#discussion_r443419034
                // for concerns around weakening security of unupgraded nodes
                // if we start doing this too early.
                m_recent_rejects.insert(porphanTx->GetWitnessHash());
                // If the transaction failed for TX_INPUTS_NOT_STANDARD,
                // then we know that the witness was irrelevant to the policy
                // failure, since this check depends only on the txid
                // (the scriptPubKey being spent is covered by the txid).
                // Add the txid to the reject filter to prevent repeated
                // processing of this transaction in the event that child
                // transactions are later received (resulting in
                // parent-fetching by txid via the orphan-handling logic).
                if (state.GetResult() == TxValidationResult::TX_INPUTS_NOT_STANDARD && porphanTx->GetWitnessHash() != porphanTx->GetHash()) {
                    // We only add the txid if it differs from the wtxid, to
                    // avoid wasting entries in the rolling bloom filter.
                    m_recent_rejects.insert(porphanTx->GetHash());
                }
            }
            m_orphanage.EraseTx(orphanHash);
            return true;
        }
    }

    return false;
}

void PeerManagerImpl::SendBlockTransactions(CNode& pfrom, Peer& peer, const CBlock& block, const BlockTransactionsRequest& req)
{
    BlockTransactions resp(req);
    for (size_t i = 0; i < req.indexes.size(); i++) {
        if (req.indexes[i] >= block.vtx.size()) {
            Misbehaving(peer, 100, "getblocktxn with out-of-bounds tx indices");
            return;
        }
        resp.txn[i] = block.vtx[req.indexes[i]];
    }

    const CNetMsgMaker msgMaker(pfrom.GetCommonVersion());
    m_connman.PushMessage(&pfrom, msgMaker.Make(NetMsgType::BLOCKTXN, resp));
}

void PeerManagerImpl::ProcessCMPCTBlock(CNode& pfrom, Peer& peer, CDataStream& vRecv,
                                         const std::chrono::microseconds time_received,
                                         const std::atomic<bool>& interruptMsgProc)
{
    // Ignore cmpctblock received while importing
    if (m_chainman.m_blockman.LoadingBlocks()) {
        LogPrint(BCLog::NET, "Unexpected cmpctblock message received from peer %d\n", pfrom.GetId());
        return;
    }

    CBlockHeaderAndShortTxIDs cmpctblock;
    vRecv >> cmpctblock;

    bool received_new_header = false;
    const auto blockhash = cmpctblock.header.GetHash();
    CBlockIndex* tip;
    {
        LOCK(cs_main);

        tip = m_chainman.ActiveChain().Tip();

        const CBlockIndex* prev_block = m_chainman.m_blockman.LookupBlockIndex(cmpctblock.header.hashPrevBlock);
        if (!prev_block) {
            // Doesn't connect (or is genesis), instead of DoSing in AcceptBlockHeader, request deeper headers
            if (!m_chainman.ActiveChainstate().IsInitialBlockDownload()) {
                MaybeSendGetHeaders(pfrom, GetLocator(m_chainman.m_best_header), peer);
            }
            return;
        } else if (prev_block->nChainTrust + CalculateHeadersWork({cmpctblock.header}) < GetAntiDoSWorkThreshold()) {
            // If we get a low-work header in a compact block, we can ignore it.
            LogPrint(BCLog::NET, "Ignoring low-work compact block from peer %d\n", pfrom.GetId());
            return;
        }

        if (!m_chainman.m_blockman.LookupBlockIndex(blockhash)) {
            received_new_header = true;
        }
    }

    int32_t& nPoSTemperature = mapPoSTemperature[pfrom.addr];
    const CBlockIndex *pindex = nullptr;
    BlockValidationState state;
    if (!m_chainman.ProcessNewBlockHeaders(nPoSTemperature, tip->GetBlockHash(), {cmpctblock.header}, /*min_pow_checked=*/true, state, m_chainparams, &pindex)) {
        if (state.IsInvalid()) {
            MaybePunishNodeForBlock(pfrom.GetId(), state, /*via_compact_block=*/true, "invalid header via cmpctblock");
            return;
        }
    }

    if (nPoSTemperature >= MAX_CONSECUTIVE_POS_HEADERS) {
        nPoSTemperature = (MAX_CONSECUTIVE_POS_HEADERS*3)/4;
        if (Params().NetworkIDString() != "test") {
            Misbehaving(peer, 100, "too many consecutive pos headers");
            return;
        }
    }

    // When we succeed in decoding a block's txids from a cmpctblock
    // message we typically jump to the BLOCKTXN handling code, with a
    // dummy (empty) BLOCKTXN message, to re-use the logic there in
    // completing processing of the putative block (without cs_main).
    bool fProcessBLOCKTXN = false;
    CDataStream blockTxnMsg(SER_NETWORK, PROTOCOL_VERSION);

    // If we end up treating this as a plain headers message, call that as well
    // without cs_main.
    bool fRevertToHeaderProcessing = false;

    // Keep a CBlock for "optimistic" compactblock reconstructions (see
    // below)
    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
    bool fBlockReconstructed = false;

    {
    LOCK(cs_main);
    // If AcceptBlockHeader returned true, it set pindex
    assert(pindex);
    UpdateBlockAvailability(pfrom.GetId(), pindex->GetBlockHash());

    CNodeState *nodestate = State(pfrom.GetId());

    // If this was a new header with more work than our tip, update the
    // peer's last block announcement time
    if (received_new_header && pindex->nChainTrust > tip->nChainTrust) {
        nodestate->m_last_block_announcement = GetTime();
    }

    if (pindex->nStatus & BLOCK_HAVE_DATA) // Nothing to do here
        return;

    auto range_flight = mapBlocksInFlight.equal_range(pindex->GetBlockHash());
    size_t already_in_flight = std::distance(range_flight.first, range_flight.second);
    bool requested_block_from_this_peer{false};

    // Multimap ensures ordering of outstanding requests. It's either empty or first in line.
    bool first_in_flight = already_in_flight == 0 || (range_flight.first->second.first == pfrom.GetId());

    while (range_flight.first != range_flight.second) {
        if (range_flight.first->second.first == pfrom.GetId()) {
            requested_block_from_this_peer = true;
            break;
        }
        range_flight.first++;
    }

    if (pindex->nChainTrust <= m_chainman.ActiveChain().Tip()->nChainTrust) { // We know something better
        if (requested_block_from_this_peer) {
            // We requested this block for some reason, but our mempool will probably be useless
            // so we just grab the block via normal getdata
            std::vector<CInv> vInv(1);
            vInv[0] = CInv(MSG_BLOCK | GetFetchFlags(peer), blockhash);
            m_connman.PushMessage(&pfrom, CNetMsgMaker(pfrom.GetCommonVersion()).Make(NetMsgType::GETDATA, vInv));
        }
        return;
    }

    // If we're not close to tip yet, give up and let parallel block fetch work its magic
    if (!already_in_flight && !CanDirectFetch()) {
        return;
    }

    // We want to be a bit conservative just to be extra careful about DoS
    // possibilities in compact block processing...
    if (pindex->nHeight <= m_chainman.ActiveChain().Height() + 2) {
        if ((already_in_flight < MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK && nodestate->vBlocksInFlight.size() < MAX_BLOCKS_IN_TRANSIT_PER_PEER) ||
             requested_block_from_this_peer) {
            std::list<QueuedBlock>::iterator* queuedBlockIt = nullptr;
            if (!BlockRequested(pfrom.GetId(), *pindex, &queuedBlockIt)) {
                if (!(*queuedBlockIt)->partialBlock)
                    (*queuedBlockIt)->partialBlock.reset(new PartiallyDownloadedBlock(&m_mempool));
                else {
                    // The block was already in flight using compact blocks from the same peer
                    LogPrint(BCLog::NET, "Peer sent us compact block we were already syncing!\n");
                    return;
                }
            }

            PartiallyDownloadedBlock& partialBlock = *(*queuedBlockIt)->partialBlock;
            ReadStatus status = partialBlock.InitData(cmpctblock, vExtraTxnForCompact);
            if (status == READ_STATUS_INVALID) {
                RemoveBlockRequest(pindex->GetBlockHash(), pfrom.GetId()); // Reset in-flight state in case Misbehaving does not result in a disconnect
                Misbehaving(peer, 100, "invalid compact block");
                return;
            } else if (status == READ_STATUS_FAILED) {
                if (first_in_flight)  {
                    // Duplicate txindexes, the block is now in-flight, so just request it
                    std::vector<CInv> vInv(1);
                    vInv[0] = CInv(MSG_BLOCK | GetFetchFlags(peer), blockhash);
                    m_connman.PushMessage(&pfrom, CNetMsgMaker(pfrom.GetCommonVersion()).Make(NetMsgType::GETDATA, vInv));
                } else {
                    // Give up for this peer and wait for other peer(s)
                    RemoveBlockRequest(pindex->GetBlockHash(), pfrom.GetId());
                }
                return;
            }

            BlockTransactionsRequest req;
            for (size_t i = 0; i < cmpctblock.BlockTxCount(); i++) {
                if (!partialBlock.IsTxAvailable(i))
                    req.indexes.push_back(i);
            }
            if (req.indexes.empty()) {
                // Dirty hack to jump to BLOCKTXN code (TODO: move message handling into their own functions)
                BlockTransactions txn;
                txn.blockhash = blockhash;
                blockTxnMsg << txn;
                fProcessBLOCKTXN = true;
            } else if (first_in_flight) {
                // We will try to round-trip any compact blocks we get on failure,
                // as long as it's first...
                req.blockhash = pindex->GetBlockHash();
                m_connman.PushMessage(&pfrom, CNetMsgMaker(pfrom.GetCommonVersion()).Make(NetMsgType::GETBLOCKTXN, req));
            } else if (pfrom.m_bip152_highbandwidth_to &&
                (!pfrom.IsInboundConn() ||
                IsBlockRequestedFromOutbound(blockhash) ||
                already_in_flight < MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK - 1)) {
                // ... or it's a hb relay peer and:
                // - peer is outbound, or
                // - we already have an outbound attempt in flight(so we'll take what we can get), or
                // - it's not the final parallel download slot (which we may reserve for first outbound)
                req.blockhash = pindex->GetBlockHash();
                m_connman.PushMessage(&pfrom, CNetMsgMaker(pfrom.GetCommonVersion()).Make(NetMsgType::GETBLOCKTXN, req));
            } else {
                // Give up for this peer and wait for other peer(s)
                RemoveBlockRequest(pindex->GetBlockHash(), pfrom.GetId());
            }
        } else {
            // This block is either already in flight from a different
            // peer, or this peer has too many blocks outstanding to
            // download from.
            // Optimistically try to reconstruct anyway since we might be
            // able to without any round trips.
            PartiallyDownloadedBlock tempBlock(&m_mempool);
            ReadStatus status = tempBlock.InitData(cmpctblock, vExtraTxnForCompact);
            if (status != READ_STATUS_OK) {
                // TODO: don't ignore failures
                return;
            }
            std::vector<CTransactionRef> dummy;
            status = tempBlock.FillBlock(*pblock, dummy);
            if (status == READ_STATUS_OK) {
                fBlockReconstructed = true;
            }
        }
    } else {
        if (requested_block_from_this_peer) {
            // We requested this block, but its far into the future, so our
            // mempool will probably be useless - request the block normally
            std::vector<CInv> vInv(1);
            vInv[0] = CInv(MSG_BLOCK | GetFetchFlags(peer), blockhash);
            m_connman.PushMessage(&pfrom, CNetMsgMaker(pfrom.GetCommonVersion()).Make(NetMsgType::GETDATA, vInv));
            return;
        } else {
            // If this was an announce-cmpctblock, we want the same treatment as a header message
            fRevertToHeaderProcessing = true;
        }
    }
    } // cs_main

    if (fProcessBLOCKTXN) {
        ProcessMessage(pfrom, NetMsgType::BLOCKTXN, blockTxnMsg, time_received, interruptMsgProc);
        return;
    }

    if (fRevertToHeaderProcessing) {
        // Headers received from HB compact block peers are permitted to be
        // relayed before full validation (see BIP 152), so we don't want to disconnect
        // the peer if the header turns out to be for an invalid block.
        // Note that if a peer tries to build on an invalid chain, that
        // will be detected and the peer will be disconnected/discouraged.
        ProcessHeadersMessage(pfrom, peer, {cmpctblock.header}, /*via_compact_block=*/true);
        return;
    }

    if (fBlockReconstructed) {
        // If we got here, we were able to optimistically reconstruct a
        // block that is in flight from some other peer.
        {
            LOCK(cs_main);
            mapBlockSource.emplace(pblock->GetHash(), std::make_pair(pfrom.GetId(), false));
        }
        // Setting force_processing to true means that we bypass some of
        // our anti-DoS protections in AcceptBlock, which filters
        // unrequested blocks that might be trying to waste our resources
        // (eg disk space). Because we only try to reconstruct blocks when
        // we're close to caught up (via the CanDirectFetch() requirement
        // above, combined with the behavior of not requesting blocks until
        // we have a chain with at least the minimum chain work), and we ignore
        // compact blocks with less work than our tip, it is safe to treat
        // reconstructed compact blocks as having been requested.
        ProcessBlock(pfrom, pblock, /*force_processing=*/true, /*min_pow_checked=*/true);
        LOCK(cs_main); // hold cs_main for CBlockIndex::IsValid()
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS)) {
            // Clear download state for this block, which is in
            // process from some other peer.  We do this after calling
            // ProcessNewBlock so that a malleated cmpctblock announcement
            // can't be used to interfere with block relay.
            RemoveBlockRequest(pblock->GetHash(), std::nullopt);
        }
    }
}

void PeerManagerImpl::ProcessBLOCKTXN(CNode& pfrom, Peer& peer, CDataStream& vRecv)
{
    // Ignore blocktxn received while importing
    if (m_chainman.m_blockman.LoadingBlocks()) {
        LogPrint(BCLog::NET, "Unexpected blocktxn message received from peer %d\n", pfrom.GetId());
        return;
    }

    BlockTransactions resp;
    vRecv >> resp;

    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
    bool fBlockRead = false;
    {
        LOCK(cs_main);

        auto range_flight = mapBlocksInFlight.equal_range(resp.blockhash);
        size_t already_in_flight = std::distance(range_flight.first, range_flight.second);
        bool requested_block_from_this_peer{false};

        // Multimap ensures ordering of outstanding requests. It's either empty or first in line.
        bool first_in_flight = already_in_flight == 0 || (range_flight.first->second.first == pfrom.GetId());

        while (range_flight.first != range_flight.second) {
            auto [node_id, block_it] = range_flight.first->second;
            if (node_id == pfrom.GetId() && block_it->partialBlock) {
                requested_block_from_this_peer = true;
                break;
            }
            range_flight.first++;
        }

        if (!requested_block_from_this_peer) {
            LogPrint(BCLog::NET, "Peer %d sent us block transactions for block we weren't expecting\n", pfrom.GetId());
            return;
        }

        PartiallyDownloadedBlock& partialBlock = *range_flight.first->second.second->partialBlock;
        ReadStatus status = partialBlock.FillBlock(*pblock, resp.txn);
        if (status == READ_STATUS_INVALID) {
            RemoveBlockRequest(resp.blockhash, pfrom.GetId()); // Reset in-flight state in case Misbehaving does not result in a disconnect
            Misbehaving(peer, 100, "invalid compact block/non-matching block transactions");
            return;
        } else if (status == READ_STATUS_FAILED) {
            if (first_in_flight) {
                // Might have collided, fall back to getdata now :(
                std::vector<CInv> invs;
                invs.push_back(CInv(MSG_BLOCK | GetFetchFlags(peer), resp.blockhash));
                m_connman.PushMessage(&pfrom, CNetMsgMaker(pfrom.GetCommonVersion()).Make(NetMsgType::GETDATA, invs));
            } else {
                RemoveBlockRequest(resp.blockhash, pfrom.GetId());
                LogPrint(BCLog::NET, "Peer %d sent us a compact block but it failed to reconstruct, waiting on first download to complete\n", pfrom.GetId());
                return;
            }
        } else {
            // Block is either okay, or possibly we received
            // READ_STATUS_CHECKBLOCK_FAILED.
            // Note that CheckBlock can only fail for one of a few reasons:
            // 1. bad-proof-of-work (impossible here, because we've already
            //    accepted the header)
            // 2. merkleroot doesn't match the transactions given (already
            //    caught in FillBlock with READ_STATUS_FAILED, so
            //    impossible here)
            // 3. the block is otherwise invalid (eg invalid coinbase,
            //    block is too big, too many legacy sigops, etc).
            // So if CheckBlock failed, #3 is the only possibility.
            // Under BIP 152, we don't discourage the peer unless proof of work is
            // invalid (we don't require all the stateless checks to have
            // been run).  This is handled below, so just treat this as
            // though the block was successfully read, and rely on the
            // handling in ProcessNewBlock to ensure the block index is
            // updated, etc.
            RemoveBlockRequest(resp.blockhash, pfrom.GetId()); // it is now an empty pointer
            fBlockRead = true;
            // mapBlockSource is used for potentially punishing peers and
            // updating which peers send us compact blocks, so the race
            // between here and cs_main in ProcessNewBlock is fine.
            // BIP 152 permits peers to relay compact blocks after validating
            // the header only; we should not punish peers if the block turns
            // out to be invalid.
            mapBlockSource.emplace(resp.blockhash, std::make_pair(pfrom.GetId(), false));
        }
    } // Don't hold cs_main when we call into ProcessNewBlock
    if (fBlockRead) {
        // Since we requested this block (it was in mapBlocksInFlight), force it to be processed,
        // even if it would not be a candidate for new tip (missing previous block, chain not long enough, etc)
        // This bypasses some anti-DoS logic in AcceptBlock (eg to prevent
        // disk-space attacks), but this should be safe due to the
        // protections in the compact block handler -- see related comment
        // in compact block optimistic reconstruction handling.
        ProcessBlock(pfrom, pblock, /*force_processing=*/true, /*min_pow_checked=*/true);
    }
}
