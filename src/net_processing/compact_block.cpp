// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing/peer_manager_impl.h>
#include <net_processing/constants.h>

using node::ReadBlockFromDisk;

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
