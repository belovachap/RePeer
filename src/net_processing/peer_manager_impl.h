// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_PROCESSING_PEER_MANAGER_IMPL_H
#define BITCOIN_NET_PROCESSING_PEER_MANAGER_IMPL_H

#include <net_processing/peer.h>
#include <net_processing/node_state.h>
#include <net_processing/peer_manager.h>

#include <addrman.h>
#include <banman.h>
#include <blockencodings.h>
#include <blockfilter.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <headerssync.h>
#include <index/blockfilterindex.h>
#include <kernel/mempool_entry.h>
#include <net.h>
#include <netmessagemaker.h>
#include <node/blockstorage.h>
#include <node/txreconciliation.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <reverse_iterator.h>
#include <scheduler.h>
#include <streams.h>
#include <sync.h>
#include <timedata.h>
#include <tinyformat.h>
#include <txmempool.h>
#include <txorphanage.h>
#include <txrequest.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <validation.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <future>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <typeinfo>
#include <vector>

class PeerManagerImpl final : public PeerManager
{
public:
    PeerManagerImpl(CConnman& connman, AddrMan& addrman,
                    BanMan* banman, ChainstateManager& chainman,
                    CTxMemPool& pool, bool ignore_incoming_txs);

    /** Overridden from CValidationInterface. */
    void BlockConnected(const std::shared_ptr<const CBlock>& pblock, const CBlockIndex* pindexConnected) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_recent_confirmed_transactions_mutex);
    void BlockDisconnected(const std::shared_ptr<const CBlock> &block, const CBlockIndex* pindex) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_recent_confirmed_transactions_mutex);
    void UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);
    void BlockChecked(const CBlock& block, const BlockValidationState& state) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);
    void NewPoWValidBlock(const CBlockIndex *pindex, const std::shared_ptr<const CBlock>& pblock) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_most_recent_block_mutex);

    /** Implement NetEventsInterface */
    void InitializeNode(CNode& node, ServiceFlags our_services) override EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);
    void FinalizeNode(const CNode& node) override EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex, !m_headers_presync_mutex);
    bool ProcessMessages(CNode* pfrom, std::atomic<bool>& interrupt) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex, !m_recent_confirmed_transactions_mutex, !m_most_recent_block_mutex, !m_headers_presync_mutex, g_msgproc_mutex);
    bool SendMessages(CNode* pto) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex, !m_recent_confirmed_transactions_mutex, !m_most_recent_block_mutex, g_msgproc_mutex);

    /** Implement PeerManager */
    void StartScheduledTasks(CScheduler& scheduler) override;
    void CheckForStaleTipAndEvictPeers() override;
    std::optional<std::string> FetchBlock(NodeId peer_id, const CBlockIndex& block_index) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);
    bool GetNodeStateStats(NodeId nodeid, CNodeStateStats& stats) const override EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);
    bool IgnoresIncomingTxs() override { return m_ignore_incoming_txs; }
    void SendPings() override EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);
    void RelayTransaction(const uint256& txid, const uint256& wtxid) override EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);
    void SetBestHeight(int height) override { m_best_height = height; };
    void UnitTestMisbehaving(NodeId peer_id, int howmuch) override EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex) { Misbehaving(*Assert(GetPeerRef(peer_id)), howmuch, ""); };
    void ProcessMessage(CNode& pfrom, const std::string& msg_type, CDataStream& vRecv,
                        const std::chrono::microseconds time_received, const std::atomic<bool>& interruptMsgProc) override
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex, !m_recent_confirmed_transactions_mutex, !m_most_recent_block_mutex, !m_headers_presync_mutex, g_msgproc_mutex);
    void UpdateLastBlockAnnounceTime(NodeId node, int64_t time_in_seconds) override;

private:
    /** Consider evicting an outbound peer based on the amount of time they've been behind our tip */
    void ConsiderEviction(CNode& pto, Peer& peer, std::chrono::seconds time_in_seconds) EXCLUSIVE_LOCKS_REQUIRED(cs_main, g_msgproc_mutex);

    /** If we have extra outbound peers, try to disconnect the one with the oldest block announcement */
    void EvictExtraOutboundPeers(std::chrono::seconds now) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /** Retrieve unbroadcast transactions from the mempool and reattempt sending to peers */
    void ReattemptInitialBroadcast(CScheduler& scheduler) EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);

    /** Get a shared pointer to the Peer object.
     *  May return an empty shared_ptr if the Peer object can't be found. */
    PeerRef GetPeerRef(NodeId id) const EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);

    /** Get a shared pointer to the Peer object and remove it from m_peer_map.
     *  May return an empty shared_ptr if the Peer object can't be found. */
    PeerRef RemovePeer(NodeId id) EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);

    /**
     * Increment peer's misbehavior score. If the new value >= DISCOURAGEMENT_THRESHOLD, mark the node
     * to be discouraged, meaning the peer might be disconnected and added to the discouragement filter.
     */
    void Misbehaving(Peer& peer, int howmuch, const std::string& message);

    /**
     * Potentially mark a node discouraged based on the contents of a BlockValidationState object
     *
     * @param[in] via_compact_block this bool is passed in because net_processing should
     * punish peers differently depending on whether the data was provided in a compact
     * block message or not. If the compact block had a valid header, but contained invalid
     * txs, the peer should not be punished. See BIP 152.
     *
     * @return Returns true if the peer was punished (probably disconnected)
     */
    bool MaybePunishNodeForBlock(NodeId nodeid, const BlockValidationState& state,
                                 bool via_compact_block, const std::string& message = "")
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);

    /**
     * Potentially disconnect and discourage a node based on the contents of a TxValidationState object
     *
     * @return Returns true if the peer was punished (probably disconnected)
     */
    bool MaybePunishNodeForTx(NodeId nodeid, const TxValidationState& state, const std::string& message = "")
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex);

    /** Maybe disconnect a peer and discourage future connections from its address.
     *
     * @param[in]   pnode     The node to check.
     * @param[in]   peer      The peer object to check.
     * @return                True if the peer was marked for disconnection in this function
     */
    bool MaybeDiscourageAndDisconnect(CNode& pnode, Peer& peer);

    /**
     * Reconsider orphan transactions after a parent has been accepted to the mempool.
     *
     * @peer[in]  peer     The peer whose orphan transactions we will reconsider. Generally only
     *                     one orphan will be reconsidered on each call of this function. If an
     *                     accepted orphan has orphaned children, those will need to be
     *                     reconsidered, creating more work, possibly for other peers.
     * @return             True if meaningful work was done (an orphan was accepted/rejected).
     *                     If no meaningful work was done, then the work set for this peer
     *                     will be empty.
     */
    bool ProcessOrphanTx(Peer& peer)
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex, g_msgproc_mutex);

    /** Process a single headers message from a peer.
     *
     * @param[in]   pfrom     CNode of the peer
     * @param[in]   peer      The peer sending us the headers
     * @param[in]   headers   The headers received. Note that this may be modified within ProcessHeadersMessage.
     * @param[in]   via_compact_block   Whether this header came in via compact block handling.
    */
    void ProcessHeadersMessage(CNode& pfrom, Peer& peer,
                               std::vector<CBlockHeader>&& headers,
                               bool via_compact_block)
        EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex, !m_headers_presync_mutex, g_msgproc_mutex);
    /** Various helpers for headers processing, invoked by ProcessHeadersMessage() */
    /** Return true if headers are continuous and have valid proof-of-work (DoS points assigned on failure) */
    bool CheckHeadersPoW(const std::vector<CBlockHeader>& headers, const Consensus::Params& consensusParams, Peer& peer);
    /** Calculate an anti-DoS work threshold for headers chains */
    arith_uint256 GetAntiDoSWorkThreshold();
    /** Deal with state tracking and headers sync for peers that send the
     * occasional non-connecting header (this can happen due to BIP 130 headers
     * announcements for blocks interacting with the 2hr (MAX_FUTURE_BLOCK_TIME) rule). */
    void HandleFewUnconnectingHeaders(CNode& pfrom, Peer& peer, const std::vector<CBlockHeader>& headers) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);
    /** Return true if the headers connect to each other, false otherwise */
    bool CheckHeadersAreContinuous(const std::vector<CBlockHeader>& headers) const;
    /** Try to continue a low-work headers sync that has already begun.
     * Assumes the caller has already verified the headers connect, and has
     * checked that each header satisfies the proof-of-work target included in
     * the header.
     *  @param[in]  peer                            The peer we're syncing with.
     *  @param[in]  pfrom                           CNode of the peer
     *  @param[in,out] headers                      The headers to be processed.
     *  @return     True if the passed in headers were successfully processed
     *              as the continuation of a low-work headers sync in progress;
     *              false otherwise.
     *              If false, the passed in headers will be returned back to
     *              the caller.
     *              If true, the returned headers may be empty, indicating
     *              there is no more work for the caller to do; or the headers
     *              may be populated with entries that have passed anti-DoS
     *              checks (and therefore may be validated for block index
     *              acceptance by the caller).
     */
    bool IsContinuationOfLowWorkHeadersSync(Peer& peer, CNode& pfrom,
            std::vector<CBlockHeader>& headers)
        EXCLUSIVE_LOCKS_REQUIRED(peer.m_headers_sync_mutex, !m_headers_presync_mutex, g_msgproc_mutex);
    /** Check work on a headers chain to be processed, and if insufficient,
     * initiate our anti-DoS headers sync mechanism.
     *
     * @param[in]   peer                The peer whose headers we're processing.
     * @param[in]   pfrom               CNode of the peer
     * @param[in]   chain_start_header  Where these headers connect in our index.
     * @param[in,out]   headers             The headers to be processed.
     *
     * @return      True if chain was low work (headers will be empty after
     *              calling); false otherwise.
     */
    bool TryLowWorkHeadersSync(Peer& peer, CNode& pfrom,
                                  const CBlockIndex* chain_start_header,
                                  std::vector<CBlockHeader>& headers)
        EXCLUSIVE_LOCKS_REQUIRED(!peer.m_headers_sync_mutex, !m_peer_mutex, !m_headers_presync_mutex, g_msgproc_mutex);

    /** Return true if the given header is an ancestor of
     *  m_chainman.m_best_header or our current tip */
    bool IsAncestorOfBestHeaderOrTip(const CBlockIndex* header) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /** Request further headers from this peer with a given locator.
     * We don't issue a getheaders message if we have a recent one outstanding.
     * This returns true if a getheaders is actually sent, and false otherwise.
     */
    bool MaybeSendGetHeaders(CNode& pfrom, const CBlockLocator& locator, Peer& peer) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);
    /** Potentially fetch blocks from this peer upon receipt of a new headers tip */
    void HeadersDirectFetchBlocks(CNode& pfrom, const Peer& peer, const CBlockIndex& last_header);
    /** Update peer state based on received headers message */
    void UpdatePeerStateForReceivedHeaders(CNode& pfrom, Peer& peer, const CBlockIndex& last_header, bool received_new_header, bool may_have_more_headers)
        EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);

    void SendBlockTransactions(CNode& pfrom, Peer& peer, const CBlock& block, const BlockTransactionsRequest& req);

    /** Register with TxRequestTracker that an INV has been received from a
     *  peer. The announcement parameters are decided in PeerManager and then
     *  passed to TxRequestTracker. */
    void AddTxAnnouncement(const CNode& node, const GenTxid& gtxid, std::chrono::microseconds current_time)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Send a version message to a peer */
    void PushNodeVersion(CNode& pnode, const Peer& peer);

    /** Send a ping message every PING_INTERVAL or if requested via RPC. May
     *  mark the peer to be disconnected if a ping has timed out.
     *  We use mockable time for ping timeouts, so setmocktime may cause pings
     *  to time out. */
    void MaybeSendPing(CNode& node_to, Peer& peer, std::chrono::microseconds now);

    /** Send `addr` messages on a regular schedule. */
    void MaybeSendAddr(CNode& node, Peer& peer, std::chrono::microseconds current_time) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);

    /** Send a single `sendheaders` message, after we have completed headers sync with a peer. */
    void MaybeSendSendHeaders(CNode& node, Peer& peer) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);

    /** Relay (gossip) an address to a few randomly chosen nodes.
     *
     * @param[in] originator   The id of the peer that sent us the address. We don't want to relay it back.
     * @param[in] addr         Address to relay.
     * @param[in] fReachable   Whether the address' network is reachable. We relay unreachable
     *                         addresses less.
     */
    void RelayAddress(NodeId originator, const CAddress& addr, bool fReachable) EXCLUSIVE_LOCKS_REQUIRED(!m_peer_mutex, g_msgproc_mutex);

    const CChainParams& m_chainparams;
    CConnman& m_connman;
    AddrMan& m_addrman;
    /** Pointer to this node's banman. May be nullptr - check existence before dereferencing. */
    BanMan* const m_banman;
    ChainstateManager& m_chainman;
    CTxMemPool& m_mempool;
    TxRequestTracker m_txrequest GUARDED_BY(::cs_main);
    std::unique_ptr<TxReconciliationTracker> m_txreconciliation;

    /** The height of the best chain */
    std::atomic<int> m_best_height{-1};

    /** Next time to check for stale tip */
    std::chrono::seconds m_stale_tip_check_time GUARDED_BY(cs_main){0s};

    /** Whether this node is running in -blocksonly mode */
    const bool m_ignore_incoming_txs;

    bool RejectIncomingTxs(const CNode& peer) const;

    /** Whether we've completed initial sync yet, for determining when to turn
      * on extra block-relay-only peers. */
    bool m_initial_sync_finished GUARDED_BY(cs_main){false};

    /** Protects m_peer_map. This mutex must not be locked while holding a lock
     *  on any of the mutexes inside a Peer object. */
    mutable Mutex m_peer_mutex;
    /**
     * Map of all Peer objects, keyed by peer id. This map is protected
     * by the m_peer_mutex. Once a shared pointer reference is
     * taken, the lock may be released. Individual fields are protected by
     * their own locks.
     */
    std::map<NodeId, PeerRef> m_peer_map GUARDED_BY(m_peer_mutex);

    /** Map maintaining per-node state. */
    std::map<NodeId, CNodeState> m_node_states GUARDED_BY(cs_main);

    /** Get a pointer to a const CNodeState, used when not mutating the CNodeState object. */
    const CNodeState* State(NodeId pnode) const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    /** Get a pointer to a mutable CNodeState. */
    CNodeState* State(NodeId pnode) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    uint32_t GetFetchFlags(const Peer& peer) const;

    std::atomic<std::chrono::microseconds> m_next_inv_to_inbounds{0us};

    /** Number of nodes with fSyncStarted. */
    int nSyncStarted GUARDED_BY(cs_main) = 0;

    /** Hash of the last block we received via INV */
    uint256 m_last_block_inv_triggering_headers_sync GUARDED_BY(g_msgproc_mutex){};

    /**
     * Sources of received blocks, saved to be able punish them when processing
     * happens afterwards.
     * Set mapBlockSource[hash].second to false if the node should not be
     * punished if the block is invalid.
     */
    std::map<uint256, std::pair<NodeId, bool>> mapBlockSource GUARDED_BY(cs_main);

    /** Number of peers with wtxid relay. */
    std::atomic<int> m_wtxid_relay_peers{0};

    /** Number of outbound peers with m_chain_sync.m_protect. */
    int m_outbound_peers_with_protect_from_disconnect GUARDED_BY(cs_main) = 0;

    /** Number of preferable block download peers. */
    int m_num_preferred_download_peers GUARDED_BY(cs_main){0};

    /** Stalling timeout for blocks in IBD */
    std::atomic<std::chrono::seconds> m_block_stalling_timeout{BLOCK_STALLING_TIMEOUT_DEFAULT};

    bool AlreadyHaveTx(const GenTxid& gtxid)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_recent_confirmed_transactions_mutex);

    /**
     * Filter for transactions that were recently rejected by the mempool.
     * These are not rerequested until the chain tip changes, at which point
     * the entire filter is reset.
     *
     * Without this filter we'd be re-requesting txs from each of our peers,
     * increasing bandwidth consumption considerably. For instance, with 100
     * peers, half of which relay a tx we don't accept, that might be a 50x
     * bandwidth increase. A flooding attacker attempting to roll-over the
     * filter using minimum-sized, 60byte, transactions might manage to send
     * 1000/sec if we have fast peers, so we pick 120,000 to give our peers a
     * two minute window to send invs to us.
     *
     * Decreasing the false positive rate is fairly cheap, so we pick one in a
     * million to make it highly unlikely for users to have issues with this
     * filter.
     *
     * We typically only add wtxids to this filter. For non-segwit
     * transactions, the txid == wtxid, so this only prevents us from
     * re-downloading non-segwit transactions when communicating with
     * non-wtxidrelay peers -- which is important for avoiding malleation
     * attacks that could otherwise interfere with transaction relay from
     * non-wtxidrelay peers. For communicating with wtxidrelay peers, having
     * the reject filter store wtxids is exactly what we want to avoid
     * redownload of a rejected transaction.
     *
     * In cases where we can tell that a segwit transaction will fail
     * validation no matter the witness, we may add the txid of such
     * transaction to the filter as well. This can be helpful when
     * communicating with txid-relay peers or if we were to otherwise fetch a
     * transaction via txid (eg in our orphan handling).
     *
     * Memory used: 1.3 MB
     */
    CRollingBloomFilter m_recent_rejects GUARDED_BY(::cs_main){120'000, 0.000'001};
    uint256 hashRecentRejectsChainTip GUARDED_BY(cs_main);

    /*
     * Filter for transactions that have been recently confirmed.
     * We use this to avoid requesting transactions that have already been
     * confirnmed.
     *
     * Blocks don't typically have more than 4000 transactions, so this should
     * be at least six blocks (~1 hr) worth of transactions that we can store,
     * inserting both a txid and wtxid for every observed transaction.
     * If the number of transactions appearing in a block goes up, or if we are
     * seeing getdata requests more than an hour after initial announcement, we
     * can increase this number.
     * The false positive rate of 1/1M should come out to less than 1
     * transaction per day that would be inadvertently ignored (which is the
     * same probability that we have in the reject filter).
     */
    Mutex m_recent_confirmed_transactions_mutex;
    CRollingBloomFilter m_recent_confirmed_transactions GUARDED_BY(m_recent_confirmed_transactions_mutex){48'000, 0.000'001};

    /**
     * For sending `inv`s to inbound peers, we use a single (exponentially
     * distributed) timer for all peers. If we used a separate timer for each
     * peer, a spy node could make multiple inbound connections to us to
     * accurately determine when we received the transaction (and potentially
     * determine the transaction's origin). */
    std::chrono::microseconds NextInvToInbounds(std::chrono::microseconds now,
                                                std::chrono::seconds average_interval);


    // All of the following cache a recent block, and are protected by m_most_recent_block_mutex
    Mutex m_most_recent_block_mutex;
    std::shared_ptr<const CBlock> m_most_recent_block GUARDED_BY(m_most_recent_block_mutex);
    std::shared_ptr<const CBlockHeaderAndShortTxIDs> m_most_recent_compact_block GUARDED_BY(m_most_recent_block_mutex);
    uint256 m_most_recent_block_hash GUARDED_BY(m_most_recent_block_mutex);

    // Data about the low-work headers synchronization, aggregated from all peers' HeadersSyncStates.
    /** Mutex guarding the other m_headers_presync_* variables. */
    Mutex m_headers_presync_mutex;
    /** A type to represent statistics about a peer's low-work headers sync.
     *
     * - The first field is the total verified amount of work in that synchronization.
     * - The second is:
     *   - nullopt: the sync is in REDOWNLOAD phase (phase 2).
     *   - {height, timestamp}: the sync has the specified tip height and block timestamp (phase 1).
     */
    using HeadersPresyncStats = std::pair<arith_uint256, std::optional<std::pair<int64_t, uint32_t>>>;
    /** Statistics for all peers in low-work headers sync. */
    std::map<NodeId, HeadersPresyncStats> m_headers_presync_stats GUARDED_BY(m_headers_presync_mutex) {};
    /** The peer with the most-work entry in m_headers_presync_stats. */
    NodeId m_headers_presync_bestpeer GUARDED_BY(m_headers_presync_mutex) {-1};
    /** The m_headers_presync_stats improved, and needs signalling. */
    std::atomic_bool m_headers_presync_should_signal{false};

    /** Height of the highest block announced using BIP 152 high-bandwidth mode. */
    int m_highest_fast_announce GUARDED_BY(::cs_main){0};

    /** Have we requested this block from a peer */
    bool IsBlockRequested(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /** Have we requested this block from an outbound peer */
    bool IsBlockRequestedFromOutbound(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /** Remove this block from our tracked requested blocks. Called if:
     *  - the block has been received from a peer
     *  - the request for the block has timed out
     * If "from_peer" is specified, then only remove the block if it is in
     * flight from that peer (to avoid one peer's network traffic from
     * affecting another's state).
     */
    void RemoveBlockRequest(const uint256& hash, std::optional<NodeId> from_peer) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /* Mark a block as in flight
     * Returns false, still setting pit, if the block was already in flight from the same peer
     * pit will only be valid as long as the same cs_main lock is being held
     */
    bool BlockRequested(NodeId nodeid, const CBlockIndex& block, std::list<QueuedBlock>::iterator** pit = nullptr) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    bool TipMayBeStale() EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /** Update pindexLastCommonBlock and add not-in-flight missing successors to vBlocks, until it has
     *  at most count entries.
     */
    void FindNextBlocksToDownload(const Peer& peer, unsigned int count, std::vector<const CBlockIndex*>& vBlocks, NodeId& nodeStaller) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /* Multimap used to preserve insertion order */
    typedef std::multimap<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator>> BlockDownloadMap;
    BlockDownloadMap mapBlocksInFlight GUARDED_BY(cs_main);

    /** When our tip was last updated. */
    std::atomic<std::chrono::seconds> m_last_tip_update{0s};

    /** Determine whether or not a peer can request a transaction, and return it (or nullptr if not found or not allowed). */
    CTransactionRef FindTxForGetData(const Peer::TxRelay& tx_relay, const GenTxid& gtxid, const std::chrono::seconds mempool_req, const std::chrono::seconds now)
        EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex);

    void ProcessGetData(CNode& pfrom, Peer& peer, const std::atomic<bool>& interruptMsgProc)
        EXCLUSIVE_LOCKS_REQUIRED(!m_most_recent_block_mutex, peer.m_getdata_requests_mutex, NetEventsInterface::g_msgproc_mutex)
        LOCKS_EXCLUDED(::cs_main);
    void ProcessCMPCTBlock(CNode& pfrom, Peer& peer, CDataStream& vRecv,
                           const std::chrono::microseconds time_received,
                           const std::atomic<bool>& interruptMsgProc)
        EXCLUSIVE_LOCKS_REQUIRED(!m_most_recent_block_mutex, !m_peer_mutex, g_msgproc_mutex);
    void ProcessBLOCKTXN(CNode& pfrom, Peer& peer, CDataStream& vRecv)
        EXCLUSIVE_LOCKS_REQUIRED(!m_most_recent_block_mutex, g_msgproc_mutex);

    /** Process a new block. Perform any post-processing housekeeping */
    void ProcessBlock(CNode& node, const std::shared_ptr<const CBlock>& block, bool force_processing, bool min_pow_checked);

    /** Relay map (txid or wtxid -> CTransactionRef) */
    typedef std::map<uint256, CTransactionRef> MapRelay;
    MapRelay mapRelay GUARDED_BY(NetEventsInterface::g_msgproc_mutex);
    /** Expiration-time ordered list of (expire time, relay map entry) pairs. */
    std::deque<std::pair<std::chrono::microseconds, MapRelay::iterator>> g_relay_expiration GUARDED_BY(NetEventsInterface::g_msgproc_mutex);

    /**
     * When a peer sends us a valid block, instruct it to announce blocks to us
     * using CMPCTBLOCK if possible by adding its nodeid to the end of
     * lNodesAnnouncingHeaderAndIDs, and keeping that list under a certain size by
     * removing the first element if necessary.
     */
    void MaybeSetPeerAsAnnouncingHeaderAndIDs(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /** Stack of nodes which we have set to announce using compact blocks */
    std::list<NodeId> lNodesAnnouncingHeaderAndIDs GUARDED_BY(cs_main);

    /** Number of peers from which we're downloading blocks. */
    int m_peers_downloading_from GUARDED_BY(cs_main) = 0;

    /** Storage for orphan information */
    TxOrphanage m_orphanage;

    void AddToCompactExtraTransactions(const CTransactionRef& tx) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);
    /** peercoin: blocks that are waiting to be processed, the key points to previous CBlockIndex entry */
    struct WaitElement {
        std::shared_ptr<CBlock> pblock;
            int64_t time;
    };
    std::map<CBlockIndex*, WaitElement> mapBlocksWait;


    /** Orphan/conflicted/etc transactions that are kept for compact block reconstruction.
     *  The last -blockreconstructionextratxn/DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN of
     *  these are kept in a ring buffer */
    std::vector<std::pair<uint256, CTransactionRef>> vExtraTxnForCompact GUARDED_BY(g_msgproc_mutex);
    /** Offset into vExtraTxnForCompact to insert the next tx */
    size_t vExtraTxnForCompactIt GUARDED_BY(g_msgproc_mutex) = 0;

    /** Check whether the last unknown block a peer advertised is not yet known. */
    void ProcessBlockAvailability(NodeId nodeid) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    /** Update tracking information about which blocks a peer is assumed to have. */
    void UpdateBlockAvailability(NodeId nodeid, const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool CanDirectFetch() EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /**
     * To prevent fingerprinting attacks, only send blocks/headers outside of
     * the active chain if they are no more than a month older (both in time,
     * and in best equivalent proof of work) than the best header chain we know
     * about and we fully-validated them at some point.
     */
    bool BlockRequestAllowed(const CBlockIndex* pindex) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool AlreadyHaveBlock(const uint256& block_hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void ProcessGetBlockData(CNode& pfrom, Peer& peer, const CInv& inv)
        EXCLUSIVE_LOCKS_REQUIRED(!m_most_recent_block_mutex);

    /**
     * Validation logic for compact filters request handling.
     *
     * May disconnect from the peer in the case of a bad request.
     *
     * @param[in]   node            The node that we received the request from
     * @param[in]   peer            The peer that we received the request from
     * @param[in]   filter_type     The filter type the request is for. Must be basic filters.
     * @param[in]   start_height    The start height for the request
     * @param[in]   stop_hash       The stop_hash for the request
     * @param[in]   max_height_diff The maximum number of items permitted to request, as specified in BIP 157
     * @param[out]  stop_index      The CBlockIndex for the stop_hash block, if the request can be serviced.
     * @param[out]  filter_index    The filter index, if the request can be serviced.
     * @return                      True if the request can be serviced.
     */
    bool PrepareBlockFilterRequest(CNode& node, Peer& peer,
                                   BlockFilterType filter_type, uint32_t start_height,
                                   const uint256& stop_hash, uint32_t max_height_diff,
                                   const CBlockIndex*& stop_index,
                                   BlockFilterIndex*& filter_index);

    /**
     * Handle a cfilters request.
     *
     * May disconnect from the peer in the case of a bad request.
     *
     * @param[in]   node            The node that we received the request from
     * @param[in]   peer            The peer that we received the request from
     * @param[in]   vRecv           The raw message received
     */
    void ProcessGetCFilters(CNode& node, Peer& peer, CDataStream& vRecv);

    /**
     * Handle a cfheaders request.
     *
     * May disconnect from the peer in the case of a bad request.
     *
     * @param[in]   node            The node that we received the request from
     * @param[in]   peer            The peer that we received the request from
     * @param[in]   vRecv           The raw message received
     */
    void ProcessGetCFHeaders(CNode& node, Peer& peer, CDataStream& vRecv);

    /**
     * Handle a getcfcheckpt request.
     *
     * May disconnect from the peer in the case of a bad request.
     *
     * @param[in]   node            The node that we received the request from
     * @param[in]   peer            The peer that we received the request from
     * @param[in]   vRecv           The raw message received
     */
    void ProcessGetCFCheckPt(CNode& node, Peer& peer, CDataStream& vRecv);

    /** Checks if address relay is permitted with peer. If needed, initializes
     * the m_addr_known bloom filter and sets m_addr_relay_enabled to true.
     *
     *  @return   True if address relay is enabled with peer
     *            False if address relay is disallowed
     */
    bool SetupAddressRelay(const CNode& node, Peer& peer) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);

    void AddAddressKnown(Peer& peer, const CAddress& addr) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);
    void PushAddress(Peer& peer, const CAddress& addr, FastRandomContext& insecure_rand) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex);
};

#endif // BITCOIN_NET_PROCESSING_PEER_MANAGER_IMPL_H
