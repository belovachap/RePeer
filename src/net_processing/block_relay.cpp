// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing/peer_manager_impl.h>
#include <net_processing/constants.h>
#include <merkleblock.h>
#include <kernel.h>
#include <primitives/block.h>

using node::ReadBlockFromDisk;
using node::ReadRawBlockFromDisk;

bool PeerManagerImpl::IsBlockRequested(const uint256& hash)
{
    return mapBlocksInFlight.count(hash);
}

bool PeerManagerImpl::IsBlockRequestedFromOutbound(const uint256& hash)
{
    for (auto range = mapBlocksInFlight.equal_range(hash); range.first != range.second; range.first++) {
        auto [nodeid, block_it] = range.first->second;
        CNodeState& nodestate = *Assert(State(nodeid));
        if (!nodestate.m_is_inbound) return true;
    }

    return false;
}

void PeerManagerImpl::RemoveBlockRequest(const uint256& hash, std::optional<NodeId> from_peer)
{
    auto range = mapBlocksInFlight.equal_range(hash);
    if (range.first == range.second) {
        // Block was not requested from any peer
        return;
    }

    // We should not have requested too many of this block
    Assume(mapBlocksInFlight.count(hash) <= MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK);

    while (range.first != range.second) {
        auto [node_id, list_it] = range.first->second;

        if (from_peer && *from_peer != node_id) {
            range.first++;
            continue;
        }

        CNodeState& state = *Assert(State(node_id));

        if (state.vBlocksInFlight.begin() == list_it) {
            // First block on the queue was received, update the start download time for the next one
            state.m_downloading_since = std::max(state.m_downloading_since, GetTime<std::chrono::microseconds>());
        }
        state.vBlocksInFlight.erase(list_it);

        if (state.vBlocksInFlight.empty()) {
            // Last validated block on the queue for this peer was received.
            m_peers_downloading_from--;
        }
        state.m_stalling_since = 0us;

        range.first = mapBlocksInFlight.erase(range.first);
    }
}

bool PeerManagerImpl::BlockRequested(NodeId nodeid, const CBlockIndex& block, std::list<QueuedBlock>::iterator** pit)
{
    const uint256& hash{block.GetBlockHash()};

    CNodeState *state = State(nodeid);
    assert(state != nullptr);

    Assume(mapBlocksInFlight.count(hash) <= MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK);

    // Short-circuit most stuff in case it is from the same node
    for (auto range = mapBlocksInFlight.equal_range(hash); range.first != range.second; range.first++) {
        if (range.first->second.first == nodeid) {
            if (pit) {
                *pit = &range.first->second.second;
            }
            return false;
        }
    }

    // Make sure it's not being fetched already from same peer.
    RemoveBlockRequest(hash, nodeid);

    std::list<QueuedBlock>::iterator it = state->vBlocksInFlight.insert(state->vBlocksInFlight.end(),
            {&block, std::unique_ptr<PartiallyDownloadedBlock>(pit ? new PartiallyDownloadedBlock(&m_mempool) : nullptr)});
    if (state->vBlocksInFlight.size() == 1) {
        // We're starting a block download (batch) from this peer.
        state->m_downloading_since = GetTime<std::chrono::microseconds>();
        m_peers_downloading_from++;
    }
    auto itInFlight = mapBlocksInFlight.insert(std::make_pair(hash, std::make_pair(nodeid, it)));
    if (pit) {
        *pit = &itInFlight->second.second;
    }
    return true;
}

void PeerManagerImpl::MaybeSetPeerAsAnnouncingHeaderAndIDs(NodeId nodeid)
{
    AssertLockHeld(cs_main);

    // When in -blocksonly mode, never request high-bandwidth mode from peers. Our
    // mempool will not contain the transactions necessary to reconstruct the
    // compact block.
    if (m_ignore_incoming_txs) return;

    CNodeState* nodestate = State(nodeid);
    if (!nodestate || !nodestate->m_provides_cmpctblocks) {
        // Don't request compact blocks if the peer has not signalled support
        return;
    }

    int num_outbound_hb_peers = 0;
    for (std::list<NodeId>::iterator it = lNodesAnnouncingHeaderAndIDs.begin(); it != lNodesAnnouncingHeaderAndIDs.end(); it++) {
        if (*it == nodeid) {
            lNodesAnnouncingHeaderAndIDs.erase(it);
            lNodesAnnouncingHeaderAndIDs.push_back(nodeid);
            return;
        }
        CNodeState *state = State(*it);
        if (state != nullptr && !state->m_is_inbound) ++num_outbound_hb_peers;
    }
    if (nodestate->m_is_inbound) {
        // If we're adding an inbound HB peer, make sure we're not removing
        // our last outbound HB peer in the process.
        if (lNodesAnnouncingHeaderAndIDs.size() >= 3 && num_outbound_hb_peers == 1) {
            CNodeState *remove_node = State(lNodesAnnouncingHeaderAndIDs.front());
            if (remove_node != nullptr && !remove_node->m_is_inbound) {
                // Put the HB outbound peer in the second slot, so that it
                // doesn't get removed.
                std::swap(lNodesAnnouncingHeaderAndIDs.front(), *std::next(lNodesAnnouncingHeaderAndIDs.begin()));
            }
        }
    }
    m_connman.ForNode(nodeid, [this](CNode* pfrom) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        AssertLockHeld(::cs_main);
        if (lNodesAnnouncingHeaderAndIDs.size() >= 3) {
            // As per BIP152, we only get 3 of our peers to announce
            // blocks using compact encodings.
            m_connman.ForNode(lNodesAnnouncingHeaderAndIDs.front(), [this](CNode* pnodeStop){
                m_connman.PushMessage(pnodeStop, CNetMsgMaker(pnodeStop->GetCommonVersion()).Make(NetMsgType::SENDCMPCT, /*high_bandwidth=*/false, /*version=*/CMPCTBLOCKS_VERSION));
                // save BIP152 bandwidth state: we select peer to be low-bandwidth
                pnodeStop->m_bip152_highbandwidth_to = false;
                return true;
            });
            lNodesAnnouncingHeaderAndIDs.pop_front();
        }
        m_connman.PushMessage(pfrom, CNetMsgMaker(pfrom->GetCommonVersion()).Make(NetMsgType::SENDCMPCT, /*high_bandwidth=*/true, /*version=*/CMPCTBLOCKS_VERSION));
        // save BIP152 bandwidth state: we select peer to be high-bandwidth
        pfrom->m_bip152_highbandwidth_to = true;
        lNodesAnnouncingHeaderAndIDs.push_back(pfrom->GetId());
        return true;
    });
}

static bool PeerHasHeader(CNodeState *state, const CBlockIndex *pindex) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (state->pindexBestKnownBlock && pindex == state->pindexBestKnownBlock->GetAncestor(pindex->nHeight))
        return true;
    if (state->pindexBestHeaderSent && pindex == state->pindexBestHeaderSent->GetAncestor(pindex->nHeight))
        return true;
    return false;
}

void PeerManagerImpl::ProcessBlockAvailability(NodeId nodeid) {
    CNodeState *state = State(nodeid);
    assert(state != nullptr);

    if (!state->hashLastUnknownBlock.IsNull()) {
        const CBlockIndex* pindex = m_chainman.m_blockman.LookupBlockIndex(state->hashLastUnknownBlock);
        if (pindex && pindex->nChainTrust > 0) {
            if (state->pindexBestKnownBlock == nullptr || pindex->nChainTrust >= state->pindexBestKnownBlock->nChainTrust) {
                state->pindexBestKnownBlock = pindex;
            }
            state->hashLastUnknownBlock.SetNull();
        }
    }
}

void PeerManagerImpl::UpdateBlockAvailability(NodeId nodeid, const uint256 &hash) {
    CNodeState *state = State(nodeid);
    assert(state != nullptr);

    ProcessBlockAvailability(nodeid);

    const CBlockIndex* pindex = m_chainman.m_blockman.LookupBlockIndex(hash);
    if (pindex && pindex->nChainTrust > 0) {
        // An actually better block was announced.
        if (state->pindexBestKnownBlock == nullptr || pindex->nChainTrust >= state->pindexBestKnownBlock->nChainTrust) {
            state->pindexBestKnownBlock = pindex;
        }
    } else {
        // An unknown block was announced; just assume that the latest one is the best one.
        state->hashLastUnknownBlock = hash;
    }
}

void PeerManagerImpl::FindNextBlocksToDownload(const Peer& peer, unsigned int count, std::vector<const CBlockIndex*>& vBlocks, NodeId& nodeStaller)
{
    if (count == 0)
        return;

    vBlocks.reserve(vBlocks.size() + count);
    CNodeState *state = State(peer.m_id);
    assert(state != nullptr);

    // Make sure pindexBestKnownBlock is up to date, we'll need it.
    ProcessBlockAvailability(peer.m_id);

    if (state->pindexBestKnownBlock == nullptr || state->pindexBestKnownBlock->nChainTrust < m_chainman.ActiveChain().Tip()->nChainTrust || state->pindexBestKnownBlock->nChainTrust < m_chainman.MinimumChainWork()) {
        // This peer has nothing interesting.
        return;
    }

    if (state->pindexLastCommonBlock == nullptr) {
        // Bootstrap quickly by guessing a parent of our best tip is the forking point.
        // Guessing wrong in either direction is not a problem.
        state->pindexLastCommonBlock = m_chainman.ActiveChain()[std::min(state->pindexBestKnownBlock->nHeight, m_chainman.ActiveChain().Height())];
    }

    // If the peer reorganized, our previous pindexLastCommonBlock may not be an ancestor
    // of its current tip anymore. Go back enough to fix that.
    state->pindexLastCommonBlock = LastCommonAncestor(state->pindexLastCommonBlock, state->pindexBestKnownBlock);
    if (state->pindexLastCommonBlock == state->pindexBestKnownBlock)
        return;

    std::vector<const CBlockIndex*> vToFetch;
    const CBlockIndex *pindexWalk = state->pindexLastCommonBlock;
    // Never fetch further than the best block we know the peer has, or more than BLOCK_DOWNLOAD_WINDOW + 1 beyond the last
    // linked block we have in common with this peer. The +1 is so we can detect stalling, namely if we would be able to
    // download that next block if the window were 1 larger.
    int nWindowEnd = state->pindexLastCommonBlock->nHeight + BLOCK_DOWNLOAD_WINDOW;
    int nMaxHeight = std::min<int>(state->pindexBestKnownBlock->nHeight, nWindowEnd + 1);
    NodeId waitingfor = -1;
    while (pindexWalk->nHeight < nMaxHeight) {
        // Read up to 128 (or more, if more blocks than that are needed) successors of pindexWalk (towards
        // pindexBestKnownBlock) into vToFetch. We fetch 128, because CBlockIndex::GetAncestor may be as expensive
        // as iterating over ~100 CBlockIndex* entries anyway.
        int nToFetch = std::min(nMaxHeight - pindexWalk->nHeight, std::max<int>(count - vBlocks.size(), 128));
        vToFetch.resize(nToFetch);
        pindexWalk = state->pindexBestKnownBlock->GetAncestor(pindexWalk->nHeight + nToFetch);
        vToFetch[nToFetch - 1] = pindexWalk;
        for (unsigned int i = nToFetch - 1; i > 0; i--) {
            vToFetch[i - 1] = vToFetch[i]->pprev;
        }

        // Iterate over those blocks in vToFetch (in forward direction), adding the ones that
        // are not yet downloaded and not in flight to vBlocks. In the meantime, update
        // pindexLastCommonBlock as long as all ancestors are already downloaded, or if it's
        // already part of our chain.
        for (const CBlockIndex* pindex : vToFetch) {
            if (!pindex->IsValid(BLOCK_VALID_TREE)) {
                // We consider the chain that this peer is on invalid.
                return;
            }
            if (!CanServeWitnesses(peer) && IsBTC16BIPsEnabled(pindex->nTime)) {
                // We wouldn't download this block or its descendants from this peer.
                return;
            }
            if (pindex->nStatus & BLOCK_HAVE_DATA || m_chainman.ActiveChain().Contains(pindex)) {
                if (pindex->HaveTxsDownloaded())
                    state->pindexLastCommonBlock = pindex;
            } else if (!IsBlockRequested(pindex->GetBlockHash())) {
                // The block is not already downloaded, and not yet in flight.
                if (pindex->nHeight > nWindowEnd) {
                    // We reached the end of the window.
                    if (vBlocks.size() == 0 && waitingfor != peer.m_id) {
                        // We aren't able to fetch anything, but we would be if the download window was one larger.
                        nodeStaller = waitingfor;
                    }
                    return;
                }
                vBlocks.push_back(pindex);
                if (vBlocks.size() == count) {
                    return;
                }
            } else if (waitingfor == -1) {
                // This is the first already-in-flight block.
                waitingfor = mapBlocksInFlight.lower_bound(pindex->GetBlockHash())->second.first;
            }
        }
    }
}

void PeerManagerImpl::ProcessGetBlockData(CNode& pfrom, Peer& peer, const CInv& inv)
{
    std::shared_ptr<const CBlock> a_recent_block;
    std::shared_ptr<const CBlockHeaderAndShortTxIDs> a_recent_compact_block;
    {
        LOCK(m_most_recent_block_mutex);
        a_recent_block = m_most_recent_block;
        a_recent_compact_block = m_most_recent_compact_block;
    }

    bool need_activate_chain = false;
    {
        LOCK(cs_main);
        const CBlockIndex* pindex = m_chainman.m_blockman.LookupBlockIndex(inv.hash);
        if (pindex) {
            if (pindex->HaveTxsDownloaded() && !pindex->IsValid(BLOCK_VALID_SCRIPTS) &&
                    pindex->IsValid(BLOCK_VALID_TREE)) {
                // If we have the block and all of its parents, but have not yet validated it,
                // we might be in the middle of connecting it (ie in the unlock of cs_main
                // before ActivateBestChain but after AcceptBlock).
                // In this case, we need to run ActivateBestChain prior to checking the relay
                // conditions below.
                need_activate_chain = true;
            }
        }
    } // release cs_main before calling ActivateBestChain
    if (need_activate_chain) {
        BlockValidationState state;
        if (!m_chainman.ActiveChainstate().ActivateBestChain(state, a_recent_block)) {
            LogPrint(BCLog::NET, "failed to activate chain (%s)\n", state.ToString());
        }
    }

    LOCK(cs_main);
    const CBlockIndex* pindex = m_chainman.m_blockman.LookupBlockIndex(inv.hash);
    if (!pindex) {
        return;
    }
    if (!BlockRequestAllowed(pindex)) {
        LogPrint(BCLog::NET, "%s: ignoring request from peer=%i for old block that isn't in the main chain\n", __func__, pfrom.GetId());
        return;
    }
    const CNetMsgMaker msgMaker(pfrom.GetCommonVersion());
    // disconnect node in case we have reached the outbound limit for serving historical blocks
    if (m_connman.OutboundTargetReached(true) &&
        (((m_chainman.m_best_header != nullptr) && (m_chainman.m_best_header->GetBlockTime() - pindex->GetBlockTime() > HISTORICAL_BLOCK_AGE)) || inv.IsMsgFilteredBlk()) &&
        !pfrom.HasPermission(NetPermissionFlags::Download) // nodes with the download permission may exceed target
    ) {
        LogPrint(BCLog::NET, "historical block serving limit reached, disconnect peer=%d\n", pfrom.GetId());
        pfrom.fDisconnect = true;
        return;
    }
    // Avoid leaking prune-height by never sending blocks below the NODE_NETWORK_LIMITED threshold
    if (!pfrom.HasPermission(NetPermissionFlags::NoBan) && (
            (((peer.m_our_services & NODE_NETWORK_LIMITED) == NODE_NETWORK_LIMITED) && ((peer.m_our_services & NODE_NETWORK) != NODE_NETWORK) && (m_chainman.ActiveChain().Tip()->nHeight - pindex->nHeight > (int)NODE_NETWORK_LIMITED_MIN_BLOCKS + 2 /* add two blocks buffer extension for possible races */) )
       )) {
        LogPrint(BCLog::NET, "Ignore block request below NODE_NETWORK_LIMITED threshold, disconnect peer=%d\n", pfrom.GetId());
        //disconnect node and prevent it from stalling (would otherwise wait for the missing block)
        pfrom.fDisconnect = true;
        return;
    }
    // Check whether the block is available before trying to send.
    if (!(pindex->nStatus & BLOCK_HAVE_DATA)) {
        return;
    }
    std::shared_ptr<const CBlock> pblock;
    if (a_recent_block && a_recent_block->GetHash() == pindex->GetBlockHash()) {
        pblock = a_recent_block;
    } else {
        // Send block from disk
        std::shared_ptr<CBlock> pblockRead = std::make_shared<CBlock>();
        if (!ReadBlockFromDisk(*pblockRead, pindex, m_chainparams.GetConsensus())) {
            assert(!"cannot load block from disk");
        }
        pblock = pblockRead;
    }
    if (pblock) {
        if (inv.IsMsgBlk()) {
            m_connman.PushMessage(&pfrom, msgMaker.Make(SERIALIZE_TRANSACTION_NO_WITNESS, NetMsgType::BLOCK, *pblock));
        } else if (inv.IsMsgWitnessBlk()) {
            m_connman.PushMessage(&pfrom, msgMaker.Make(NetMsgType::BLOCK, *pblock));
        } else if (inv.IsMsgFilteredBlk()) {
            bool sendMerkleBlock = false;
            CMerkleBlock merkleBlock;
            if (auto tx_relay = peer.GetTxRelay(); tx_relay != nullptr) {
                LOCK(tx_relay->m_bloom_filter_mutex);
                if (tx_relay->m_bloom_filter) {
                    sendMerkleBlock = true;
                    merkleBlock = CMerkleBlock(*pblock, *tx_relay->m_bloom_filter);
                }
            }
            if (sendMerkleBlock) {
                m_connman.PushMessage(&pfrom, msgMaker.Make(NetMsgType::MERKLEBLOCK, merkleBlock));
                // CMerkleBlock just contains hashes, so also push any transactions in the block the client did not see
                // This avoids hurting performance by pointlessly requiring a round-trip
                // Note that there is currently no way for a node to request any single transactions we didn't send here -
                // they must either disconnect and retry or request the full block.
                // Thus, the protocol spec specified allows for us to provide duplicate txn here,
                // however we MUST always provide at least what the remote peer needs
                typedef std::pair<unsigned int, uint256> PairType;
                for (PairType& pair : merkleBlock.vMatchedTxn)
                    m_connman.PushMessage(&pfrom, msgMaker.Make(SERIALIZE_TRANSACTION_NO_WITNESS, NetMsgType::TX, *pblock->vtx[pair.first]));
            }
            // else
            // no response
        } else if (inv.IsMsgCmpctBlk()) {
            // If a peer is asking for old blocks, we're almost guaranteed
            // they won't have a useful mempool to match against a compact block,
            // and we don't feel like constructing the object for them, so
            // instead we respond with the full, non-compact block.
            if (CanDirectFetch() && pindex->nHeight >= m_chainman.ActiveChain().Height() - MAX_CMPCTBLOCK_DEPTH) {
                if (a_recent_compact_block && a_recent_compact_block->header.GetHash() == pindex->GetBlockHash()) {
                    m_connman.PushMessage(&pfrom, msgMaker.Make(NetMsgType::CMPCTBLOCK, *a_recent_compact_block));
                } else {
                    CBlockHeaderAndShortTxIDs cmpctblock{*pblock};
                    m_connman.PushMessage(&pfrom, msgMaker.Make(NetMsgType::CMPCTBLOCK, cmpctblock));
                }
            } else {
                m_connman.PushMessage(&pfrom, msgMaker.Make(NetMsgType::BLOCK, *pblock));
            }
        }
    }

    {
        LOCK(peer.m_block_inv_mutex);
        // Trigger the peer node to send a getblocks request for the next batch of inventory
        if (inv.hash == peer.m_continuation_block) {
            // Send immediately. This must send even if redundant,
            // and we want it right after the last block so they don't
            // wait for other stuff first.
            // peercoin: send latest proof-of-work block to allow the
            // download node to accept as orphan (proof-of-stake
            // block might be rejected by stake connection check)
            std::vector<CInv> vInv;
            vInv.push_back(CInv(MSG_BLOCK, GetLastBlockIndex(m_chainman.ActiveChain().Tip(), false)->GetBlockHash()));
            m_connman.PushMessage(&pfrom, msgMaker.Make(NetMsgType::INV, vInv));
            peer.m_continuation_block.SetNull();
        }
    }
}

void PeerManagerImpl::ProcessBlock(CNode& node, const std::shared_ptr<const CBlock>& block, bool force_processing, bool min_pow_checked)
{
    bool new_block{false};
    m_chainman.ProcessNewBlock(block, force_processing, min_pow_checked, &new_block);
    if (new_block) {
        node.m_last_block_time = GetTime<std::chrono::seconds>();
        // In case this block came from a different peer than we requested
        // from, we can erase the block request now anyway (as we just stored
        // this block to disk).
        LOCK(cs_main);
        RemoveBlockRequest(block->GetHash(), std::nullopt);
    } else {
        LOCK(cs_main);
        mapBlockSource.erase(block->GetHash());
    }
}

/**
 * Evict orphan txn pool entries based on a newly connected
 * block, remember the recently confirmed transactions, and delete tracked
 * announcements for them. Also save the time of the last tip update and
 * possibly reduce dynamic block stalling timeout.
 */
void PeerManagerImpl::BlockConnected(const std::shared_ptr<const CBlock>& pblock, const CBlockIndex* pindex)
{
    m_orphanage.EraseForBlock(*pblock);
    m_last_tip_update = GetTime<std::chrono::seconds>();

    {
        LOCK(m_recent_confirmed_transactions_mutex);
        for (const auto& ptx : pblock->vtx) {
            m_recent_confirmed_transactions.insert(ptx->GetHash());
            if (ptx->GetHash() != ptx->GetWitnessHash()) {
                m_recent_confirmed_transactions.insert(ptx->GetWitnessHash());
            }
        }
    }
    {
        LOCK(cs_main);
        for (const auto& ptx : pblock->vtx) {
            m_txrequest.ForgetTxHash(ptx->GetHash());
            m_txrequest.ForgetTxHash(ptx->GetWitnessHash());
        }
    }
}

void PeerManagerImpl::BlockDisconnected(const std::shared_ptr<const CBlock> &block, const CBlockIndex* pindex)
{
    // To avoid relay problems with transactions that were previously
    // confirmed, clear our filter of recently confirmed transactions whenever
    // there's a reorg.
    // This means that in a 1-block reorg (where 1 block is disconnected and
    // then another block reconnected), our filter will drop to having only one
    // block's worth of transactions in it, but that should be fine, since
    // presumably the most common case of relaying a confirmed transaction
    // should be just after a new block containing it is found.
    LOCK(m_recent_confirmed_transactions_mutex);
    m_recent_confirmed_transactions.reset();
}

/**
 * Maintain state about the best-seen block and fast-announce a compact block
 * to compatible peers.
 */
void PeerManagerImpl::NewPoWValidBlock(const CBlockIndex *pindex, const std::shared_ptr<const CBlock>& pblock)
{
    auto pcmpctblock = std::make_shared<const CBlockHeaderAndShortTxIDs>(*pblock);
    const CNetMsgMaker msgMaker(PROTOCOL_VERSION);

    LOCK(cs_main);

    if (pindex->nHeight <= m_highest_fast_announce)
        return;
    m_highest_fast_announce = pindex->nHeight;

    if (!IsBTC16BIPsEnabled(pindex->nTime)) return;

    uint256 hashBlock(pblock->GetHash());
    const std::shared_future<CSerializedNetMsg> lazy_ser{
        std::async(std::launch::deferred, [&] { return msgMaker.Make(NetMsgType::CMPCTBLOCK, *pcmpctblock); })};

    {
        LOCK(m_most_recent_block_mutex);
        m_most_recent_block_hash = hashBlock;
        m_most_recent_block = pblock;
        m_most_recent_compact_block = pcmpctblock;
    }

    m_connman.ForEachNode([this, pindex, &lazy_ser, &hashBlock](CNode* pnode) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        AssertLockHeld(::cs_main);

        if (pnode->GetCommonVersion() < INVALID_CB_NO_BAN_VERSION || pnode->fDisconnect)
            return;
        ProcessBlockAvailability(pnode->GetId());
        CNodeState &state = *State(pnode->GetId());
        // If the peer has, or we announced to them the previous block already,
        // but we don't think they have this one, go ahead and announce it
        if (state.m_requested_hb_cmpctblocks && !PeerHasHeader(&state, pindex) && PeerHasHeader(&state, pindex->pprev)) {

            LogPrint(BCLog::NET, "%s sending header-and-ids %s to peer=%d\n", "PeerManager::NewPoWValidBlock",
                    hashBlock.ToString(), pnode->GetId());

            const CSerializedNetMsg& ser_cmpctblock{lazy_ser.get()};
            m_connman.PushMessage(pnode, ser_cmpctblock.Copy());
            state.pindexBestHeaderSent = pindex;
        }
    });
}

/**
 * Handle invalid block rejection and consequent peer discouragement, maintain which
 * peers announce compact blocks.
 */
void PeerManagerImpl::BlockChecked(const CBlock& block, const BlockValidationState& state)
{
    LOCK(cs_main);

    const uint256 hash(block.GetHash());
    std::map<uint256, std::pair<NodeId, bool>>::iterator it = mapBlockSource.find(hash);

    // If the block failed validation, we know where it came from and we're still connected
    // to that peer, maybe punish.
    if (state.IsInvalid() &&
        it != mapBlockSource.end() &&
        State(it->second.first)) {
            MaybePunishNodeForBlock(/*nodeid=*/ it->second.first, state, /*via_compact_block=*/ !it->second.second);
    }
    // Check that:
    // 1. The block is valid
    // 2. We're not in initial block download
    // 3. This is currently the best block we're aware of. We haven't updated
    //    the tip yet so we have no way to check this directly here. Instead we
    //    just check that there are currently no other blocks in flight.
    else if (state.IsValid() &&
             !m_chainman.ActiveChainstate().IsInitialBlockDownload() &&
             mapBlocksInFlight.count(hash) == mapBlocksInFlight.size()) {
        if (it != mapBlockSource.end()) {
            MaybeSetPeerAsAnnouncingHeaderAndIDs(it->second.first);
        }
    }
    if (it != mapBlockSource.end())
        mapBlockSource.erase(it);
}

bool PeerManagerImpl::BlockRequestAllowed(const CBlockIndex* pindex)
{
    AssertLockHeld(cs_main);
    if (m_chainman.ActiveChain().Contains(pindex)) return true;
    return pindex->IsValid(BLOCK_VALID_SCRIPTS) && (m_chainman.m_best_header != nullptr) &&
           (m_chainman.m_best_header->GetBlockTime() - pindex->GetBlockTime() < STALE_RELAY_AGE_LIMIT) &&
           (GetBlockProofEquivalentTime(*m_chainman.m_best_header, *pindex, *m_chainman.m_best_header, m_chainparams.GetConsensus()) < STALE_RELAY_AGE_LIMIT);
}

bool PeerManagerImpl::AlreadyHaveBlock(const uint256& block_hash)
{
    return m_chainman.m_blockman.LookupBlockIndex(block_hash) != nullptr;
}

uint32_t PeerManagerImpl::GetFetchFlags(const Peer& peer) const
{
    uint32_t nFetchFlags = 0;
    if (CanServeWitnesses(peer)) {
        nFetchFlags |= MSG_WITNESS_FLAG;
    }
    return nFetchFlags;
}

std::optional<std::string> PeerManagerImpl::FetchBlock(NodeId peer_id, const CBlockIndex& block_index)
{
    if (m_chainman.m_blockman.LoadingBlocks()) return "Loading blocks ...";

    // Ensure this peer exists and hasn't been disconnected
    PeerRef peer = GetPeerRef(peer_id);
    if (peer == nullptr) return "Peer does not exist";

    // Ignore pre-segwit peers
    if (!CanServeWitnesses(*peer)) return "Pre-SegWit peer";

    LOCK(cs_main);

    // Forget about all prior requests
    RemoveBlockRequest(block_index.GetBlockHash(), std::nullopt);

    // Mark block as in-flight
    if (!BlockRequested(peer_id, block_index)) return "Already requested from this peer";

    // Construct message to request the block
    const uint256& hash{block_index.GetBlockHash()};
    std::vector<CInv> invs{CInv(MSG_BLOCK | MSG_WITNESS_FLAG, hash)};

    // Send block request message to the peer
    bool success = m_connman.ForNode(peer_id, [this, &invs](CNode* node) {
        const CNetMsgMaker msgMaker(node->GetCommonVersion());
        this->m_connman.PushMessage(node, msgMaker.Make(NetMsgType::GETDATA, invs));
        return true;
    });

    if (!success) return "Peer not fully connected";

    LogPrint(BCLog::NET, "Requesting block %s from peer=%d\n",
                 hash.ToString(), peer_id);
    return std::nullopt;
}
