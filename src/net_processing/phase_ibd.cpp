// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing/peer_manager_impl.h>
#include <net_processing/constants.h>
#include <kernel.h>

using node::ReadBlockFromDisk;

// ============================================================================
// PHASE 3: INITIAL BLOCK DOWNLOAD
//
// Purpose: Download and validate full blocks from peers.
// Entry:   When CanDirectFetch() becomes true (headers near tip).
// Exit:    When IsInitialBlockDownload() returns false.
//
// This phase handles block download windowing, stalling detection,
// and block validation. It does NOT relay transactions or addresses.
// ============================================================================

bool PeerManagerImpl::IsIBDPhase() const
{
    return m_chainman.ActiveChainstate().IsInitialBlockDownload();
}

void PeerManagerImpl::ProcessPhase3Block(CNode& pfrom, Peer& peer, CDataStream& vRecv)
{
    // Only called during IBD. Handles BLOCK messages.
    // No transaction relay, no address relay, no compact block announcements.

    if (m_chainman.m_blockman.LoadingBlocks()) {
        LogPrint(BCLog::NET, "Unexpected block message received from peer %d during IBD\n", pfrom.GetId());
        return;
    }

    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
    vRecv >> *pblock;

    LogPrint(BCLog::NET, "received block %s peer=%d (IBD)\n", pblock->GetHash().ToString(), pfrom.GetId());

    CBlockIndex* prev_block{WITH_LOCK(cs_main, return m_chainman.m_blockman.LookupBlockIndex(pblock->hashPrevBlock))};

    // Check for mutation
    if (prev_block && IsBlockMutated(*pblock, IsBTC16BIPsEnabled(prev_block->nTime))) {
        LogPrint(BCLog::NET, "Received mutated block from peer=%d\n", peer.m_id);
        Misbehaving(peer, 100, "mutated block");
        WITH_LOCK(cs_main, RemoveBlockRequest(pblock->GetHash(), peer.m_id));
        return;
    }

    bool min_pow_checked = false;
    {
        LOCK(cs_main);
        if (prev_block && prev_block->nChainTrust + CalculateHeadersWork({pblock->GetBlockHeader()}) >= GetAntiDoSWorkThreshold()) {
            min_pow_checked = true;
        }
    }

    ProcessBlock(pfrom, pblock, /*force_processing=*/true, min_pow_checked);
}

void PeerManagerImpl::ProcessPhase3CMPCTBlock(CNode& pfrom, Peer& peer, CDataStream& vRecv,
                                                const std::chrono::microseconds time_received,
                                                const std::atomic<bool>& interruptMsgProc)
{
    // Compact block handling during IBD - simplified, no high-bandwidth announcements
    if (m_chainman.m_blockman.LoadingBlocks()) {
        LogPrint(BCLog::NET, "Unexpected cmpctblock message received from peer %d during IBD\n", pfrom.GetId());
        return;
    }

    CBlockHeaderAndShortTxIDs cmpctblock;
    vRecv >> cmpctblock;

    const auto blockhash = cmpctblock.header.GetHash();
    CBlockIndex* tip;
    {
        LOCK(cs_main);
        tip = m_chainman.ActiveChain().Tip();
        const CBlockIndex* prev_block = m_chainman.m_blockman.LookupBlockIndex(cmpctblock.header.hashPrevBlock);
        if (!prev_block) {
            return; // doesn't connect, ignore during IBD
        }
        if (prev_block->nChainTrust + CalculateHeadersWork({cmpctblock.header}) < GetAntiDoSWorkThreshold()) {
            return; // low work, ignore
        }
    }

    int32_t& nPoSTemperature = mapPoSTemperature[pfrom.addr];
    const CBlockIndex* pindex = nullptr;
    BlockValidationState state;
    if (!m_chainman.ProcessNewBlockHeaders(nPoSTemperature, tip->GetBlockHash(), {cmpctblock.header},
                                            /*min_pow_checked=*/true, state, m_chainparams, &pindex)) {
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

    // During IBD, just request the full block via getdata
    {
        LOCK(cs_main);
        UpdateBlockAvailability(pfrom.GetId(), pindex->GetBlockHash());
        std::vector<CInv> vInv(1);
        vInv[0] = CInv(MSG_BLOCK | GetFetchFlags(peer), blockhash);
        m_connman.PushMessage(&pfrom, CNetMsgMaker(pfrom.GetCommonVersion()).Make(NetMsgType::GETDATA, vInv));
    }
}

void PeerManagerImpl::ProcessPhase3GetData(CNode& pfrom, Peer& peer, const CInv& inv)
{
    // During IBD, only serve blocks, never transactions
    if (!inv.IsGenBlkMsg()) {
        // Ignore tx getdata during IBD
        return;
    }

    std::shared_ptr<const CBlock> a_recent_block;
    {
        LOCK(m_most_recent_block_mutex);
        a_recent_block = m_most_recent_block;
    }

    LOCK(cs_main);
    const CBlockIndex* pindex = m_chainman.m_blockman.LookupBlockIndex(inv.hash);
    if (!pindex) return;
    if (!BlockRequestAllowed(pindex)) return;

    if (!(pindex->nStatus & BLOCK_HAVE_DATA)) return;

    std::shared_ptr<const CBlock> pblock;
    if (a_recent_block && a_recent_block->GetHash() == pindex->GetBlockHash()) {
        pblock = a_recent_block;
    } else {
        std::shared_ptr<CBlock> pblockRead = std::make_shared<CBlock>();
        if (!ReadBlockFromDisk(*pblockRead, pindex, m_chainparams.GetConsensus())) {
            assert(!"cannot load block from disk");
        }
        pblock = pblockRead;
    }

    const CNetMsgMaker msgMaker(pfrom.GetCommonVersion());
    if (inv.IsMsgBlk()) {
        m_connman.PushMessage(&pfrom, msgMaker.Make(SERIALIZE_TRANSACTION_NO_WITNESS, NetMsgType::BLOCK, *pblock));
    } else if (inv.IsMsgWitnessBlk()) {
        m_connman.PushMessage(&pfrom, msgMaker.Make(NetMsgType::BLOCK, *pblock));
    }
}

void PeerManagerImpl::Phase3SendMessages(CNode* pto)
{
    // During IBD: only send getdata for blocks, no tx relay, no addr relay
    AssertLockHeld(g_msgproc_mutex);
    PeerRef peer = GetPeerRef(pto->GetId());
    if (!peer) return;

    const CNetMsgMaker msgMaker(pto->GetCommonVersion());
    const auto current_time{GetTime<std::chrono::microseconds>()};

    LOCK(cs_main);
    CNodeState& state = *State(pto->GetId());

    // Request blocks to download
    std::vector<CInv> vGetData;
    if (state.vBlocksInFlight.size() < MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
        std::vector<const CBlockIndex*> vToDownload;
        NodeId staller = -1;
        FindNextBlocksToDownload(*peer, MAX_BLOCKS_IN_TRANSIT_PER_PEER - state.vBlocksInFlight.size(), vToDownload, staller);
        for (const CBlockIndex* pindex : vToDownload) {
            uint32_t nFetchFlags = IsBTC16BIPsEnabled(pindex->nTime) ? GetFetchFlags(*peer) : false;
            vGetData.push_back(CInv(MSG_BLOCK | nFetchFlags, pindex->GetBlockHash()));
            BlockRequested(pto->GetId(), *pindex);
            LogPrint(BCLog::NET, "Requesting block %s (%d) peer=%d\n",
                     pindex->GetBlockHash().ToString(), pindex->nHeight, pto->GetId());
        }
        if (state.vBlocksInFlight.empty() && staller != -1) {
            if (State(staller)->m_stalling_since == 0us) {
                State(staller)->m_stalling_since = current_time;
                LogPrint(BCLog::NET, "Stall started peer=%d\n", staller);
            }
        }
    }

    if (!vGetData.empty()) {
        m_connman.PushMessage(pto, msgMaker.Make(NetMsgType::GETDATA, vGetData));
    }

    // Stalling detection
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

    // Block download timeout
    if (state.vBlocksInFlight.size() > 0) {
        QueuedBlock& queuedBlock = state.vBlocksInFlight.front();
        int nOtherPeersWithValidatedDownloads = m_peers_downloading_from - 1;
        if (current_time > state.m_downloading_since +
            std::chrono::seconds{m_chainparams.GetConsensus().nPowTargetSpacing} *
            (BLOCK_DOWNLOAD_TIMEOUT_BASE + BLOCK_DOWNLOAD_TIMEOUT_PER_PEER * nOtherPeersWithValidatedDownloads)) {
            LogPrintf("Timeout downloading block %s from peer=%d, disconnecting\n",
                      queuedBlock.pindex->GetBlockHash().ToString(), pto->GetId());
            pto->fDisconnect = true;
        }
    }
}
