// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing/peer_manager_impl.h>
#include <net_processing/constants.h>

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
