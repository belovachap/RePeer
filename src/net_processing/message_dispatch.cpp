// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing/peer_manager_impl.h>
#include <net_processing/constants.h>
#include <policy/settings.h>
#include <kernel.h>

using node::ReadBlockFromDisk;
using node::ReadRawBlockFromDisk;

namespace {
static void AddKnownTx(Peer& peer, const uint256& hash)
{
    auto tx_relay = peer.GetTxRelay();
    if (!tx_relay) return;

    LOCK(tx_relay->m_tx_inventory_mutex);
    tx_relay->m_tx_inventory_known_filter.insert(hash);
}
} // namespace

std::chrono::microseconds PeerManagerImpl::NextInvToInbounds(std::chrono::microseconds now,
                                                             std::chrono::seconds average_interval)
{
    if (m_next_inv_to_inbounds.load() < now) {
        // If this function were called from multiple threads simultaneously
        // it would possible that both update the next send variable, and return a different result to their caller.
        // This is not possible in practice as only the net processing thread invokes this function.
        m_next_inv_to_inbounds = GetExponentialRand(now, average_interval);
    }
    return m_next_inv_to_inbounds;
}

void PeerManagerImpl::SendPings()
{
    LOCK(m_peer_mutex);
    for(auto& it : m_peer_map) it.second->m_ping_queued = true;
}

/**
 * Update our best height and announce any block hashes which weren't previously
 * in m_chainman.ActiveChain() to our peers.
 */
void PeerManagerImpl::UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload)
{
    SetBestHeight(pindexNew->nHeight);
    SetServiceFlagsIBDCache(!fInitialDownload);

    // Don't relay inventory during initial block download.
    if (fInitialDownload) return;

    // Find the hashes of all blocks that weren't previously in the best chain.
    std::vector<uint256> vHashes;
    const CBlockIndex *pindexToAnnounce = pindexNew;
    while (pindexToAnnounce != pindexFork) {
        vHashes.push_back(pindexToAnnounce->GetBlockHash());
        pindexToAnnounce = pindexToAnnounce->pprev;
        if (vHashes.size() == MAX_BLOCKS_TO_ANNOUNCE) {
            // Limit announcements in case of a huge reorganization.
            // Rely on the peer's synchronization mechanism in that case.
            break;
        }
    }

    {
        LOCK(m_peer_mutex);
        for (auto& it : m_peer_map) {
            Peer& peer = *it.second;
            LOCK(peer.m_block_inv_mutex);
            for (const uint256& hash : reverse_iterate(vHashes)) {
                peer.m_blocks_for_headers_relay.push_back(hash);
            }
        }
    }

    m_connman.WakeMessageHandler();
}

void PeerManagerImpl::ProcessMessage(CNode& pfrom, const std::string& msg_type, CDataStream& vRecv,
                                     const std::chrono::microseconds time_received,
                                     const std::atomic<bool>& interruptMsgProc)
{
    AssertLockHeld(g_msgproc_mutex);

    LogPrint(BCLog::NET, "received: %s (%u bytes) peer=%d\n", SanitizeString(msg_type), vRecv.size(), pfrom.GetId());

    PeerRef peer = GetPeerRef(pfrom.GetId());
    if (peer == nullptr) return;

    // set deserialization mode to read PoS flag in headers
    vRecv.SetType(vRecv.GetType() | SER_POSMARKER);

    if (msg_type == NetMsgType::VERSION) {
        auto it = mapPoSTemperature.find(pfrom.addr);
        if (it == mapPoSTemperature.end())
            mapPoSTemperature[pfrom.addr] = MAX_CONSECUTIVE_POS_HEADERS/4;
        // Each connection can only send one version message
        if (pfrom.nVersion != 0)
        {
            LogPrint(BCLog::NET, "redundant version message from peer=%d\n", pfrom.GetId());
            return;
        }

        int64_t nTime;
        CService addrMe;
        uint64_t nNonce = 1;
        ServiceFlags nServices;
        int nVersion;
        std::string cleanSubVer;
        int starting_height = -1;
        bool fRelay = true;

        vRecv >> nVersion >> Using<CustomUintFormatter<8>>(nServices) >> nTime;
        if (nTime < 0) {
            nTime = 0;
        }
        vRecv.ignore(8); // Ignore the addrMe service bits sent by the peer
        vRecv >> addrMe;
        if (!pfrom.IsInboundConn())
        {
            m_addrman.SetServices(pfrom.addr, nServices);
        }
        if (pfrom.ExpectServicesFromConn() && !HasAllDesirableServiceFlags(nServices))
        {
            LogPrint(BCLog::NET, "peer=%d does not offer the expected services (%08x offered, %08x expected); disconnecting\n", pfrom.GetId(), nServices, GetDesirableServiceFlags(nServices));
            pfrom.fDisconnect = true;
            return;
        }

        if (nVersion < MIN_PEER_PROTO_VERSION) {
            // disconnect from peers older than this proto version
            LogPrint(BCLog::NET, "peer=%d using obsolete version %i; disconnecting\n", pfrom.GetId(), nVersion);
            pfrom.fDisconnect = true;
            return;
        }

        if (!vRecv.empty()) {
            // The version message includes information about the sending node which we don't use:
            //   - 8 bytes (service bits)
            //   - 16 bytes (ipv6 address)
            //   - 2 bytes (port)
            vRecv.ignore(26);
            vRecv >> nNonce;
        }
        if (!vRecv.empty()) {
            std::string strSubVer;
            vRecv >> LIMITED_STRING(strSubVer, MAX_SUBVERSION_LENGTH);
            cleanSubVer = SanitizeString(strSubVer);
        }
        if (!vRecv.empty()) {
            vRecv >> starting_height;
        }
        if (!vRecv.empty())
            vRecv >> fRelay;
        // Disconnect if we connected to ourself
        if (pfrom.IsInboundConn() && !m_connman.CheckIncomingNonce(nNonce))
        {
            LogPrintf("connected to self at %s, disconnecting\n", pfrom.addr.ToStringAddrPort());
            pfrom.fDisconnect = true;
            return;
        }

        if (pfrom.IsInboundConn() && addrMe.IsRoutable())
        {
            SeenLocal(addrMe);
        }

        // Inbound peers send us their version message when they connect.
        // We send our version message in response.
        if (pfrom.IsInboundConn()) {
            PushNodeVersion(pfrom, *peer);
        }

        // Change version
        const int greatest_common_version = std::min(nVersion, PROTOCOL_VERSION);
        pfrom.SetCommonVersion(greatest_common_version);
        pfrom.nVersion = nVersion;

        const CNetMsgMaker msg_maker(greatest_common_version);

        if (greatest_common_version >= WTXID_RELAY_VERSION) {
            m_connman.PushMessage(&pfrom, msg_maker.Make(NetMsgType::WTXIDRELAY));
        }

        // Signal ADDRv2 support (BIP155).
        if (greatest_common_version >= 70016) {
            // BIP155 defines addrv2 and sendaddrv2 for all protocol versions, but some
            // implementations reject messages they don't know. As a courtesy, don't send
            // it to nodes with a version before 70016, as no software is known to support
            // BIP155 that doesn't announce at least that protocol version number.
            m_connman.PushMessage(&pfrom, msg_maker.Make(NetMsgType::SENDADDRV2));
        }

        pfrom.m_has_all_wanted_services = HasAllDesirableServiceFlags(nServices);
        peer->m_their_services = nServices;
        pfrom.SetAddrLocal(addrMe);
        {
            LOCK(pfrom.m_subver_mutex);
            pfrom.cleanSubVer = cleanSubVer;
        }
        peer->m_starting_height = starting_height;

        // Only initialize the Peer::TxRelay m_relay_txs data structure if:
        // - this isn't an outbound block-relay-only connection, and
        // - this isn't an outbound feeler connection, and
        // - fRelay=true (the peer wishes to receive transaction announcements)
        //   or we're offering NODE_BLOOM to this peer. NODE_BLOOM means that
        //   the peer may turn on transaction relay later.
        if (!pfrom.IsBlockOnlyConn() &&
            !pfrom.IsFeelerConn() &&
            (fRelay || (peer->m_our_services & NODE_BLOOM))) {
            auto* const tx_relay = peer->SetTxRelay();
            {
                LOCK(tx_relay->m_bloom_filter_mutex);
                tx_relay->m_relay_txs = fRelay; // set to true after we get the first filter* message
            }
            if (fRelay) pfrom.m_relays_txs = true;
        }

        if (greatest_common_version >= WTXID_RELAY_VERSION && m_txreconciliation) {
            // Per BIP-330, we announce txreconciliation support if:
            // - protocol version per the peer's VERSION message supports WTXID_RELAY;
            // - transaction relay is supported per the peer's VERSION message
            // - this is not a block-relay-only connection and not a feeler
            // - this is not an addr fetch connection;
            // - we are not in -blocksonly mode.
            const auto* tx_relay = peer->GetTxRelay();
            if (tx_relay && WITH_LOCK(tx_relay->m_bloom_filter_mutex, return tx_relay->m_relay_txs) &&
                !pfrom.IsAddrFetchConn() && !m_ignore_incoming_txs) {
                const uint64_t recon_salt = m_txreconciliation->PreRegisterPeer(pfrom.GetId());
                m_connman.PushMessage(&pfrom, msg_maker.Make(NetMsgType::SENDTXRCNCL,
                                                             TXRECONCILIATION_VERSION, recon_salt));
            }
        }

        m_connman.PushMessage(&pfrom, msg_maker.Make(NetMsgType::VERACK));

        // Potentially mark this peer as a preferred download peer.
        {
            LOCK(cs_main);
            CNodeState* state = State(pfrom.GetId());
            state->fPreferredDownload = (!pfrom.IsInboundConn() || pfrom.HasPermission(NetPermissionFlags::NoBan)) && !pfrom.IsAddrFetchConn() && CanServeBlocks(*peer);
            m_num_preferred_download_peers += state->fPreferredDownload;
        }

        // Attempt to initialize address relay for outbound peers and use result
        // to decide whether to send GETADDR, so that we don't send it to
        // inbound or outbound block-relay-only peers.
        bool send_getaddr{false};
        if (!pfrom.IsInboundConn()) {
            send_getaddr = SetupAddressRelay(pfrom, *peer);
        }
        if (send_getaddr) {
            // Do a one-time address fetch to help populate/update our addrman.
            // If we're starting up for the first time, our addrman may be pretty
            // empty, so this mechanism is important to help us connect to the network.
            // We skip this for block-relay-only peers. We want to avoid
            // potentially leaking addr information and we do not want to
            // indicate to the peer that we will participate in addr relay.
            m_connman.PushMessage(&pfrom, CNetMsgMaker(greatest_common_version).Make(NetMsgType::GETADDR));
            peer->m_getaddr_sent = true;
            // When requesting a getaddr, accept an additional MAX_ADDR_TO_SEND addresses in response
            // (bypassing the MAX_ADDR_PROCESSING_TOKEN_BUCKET limit).
            peer->m_addr_token_bucket += MAX_ADDR_TO_SEND;
        }

        if (!pfrom.IsInboundConn()) {
            // For non-inbound connections, we update the addrman to record
            // connection success so that addrman will have an up-to-date
            // notion of which peers are online and available.
            //
            // While we strive to not leak information about block-relay-only
            // connections via the addrman, not moving an address to the tried
            // table is also potentially detrimental because new-table entries
            // are subject to eviction in the event of addrman collisions.  We
            // mitigate the information-leak by never calling
            // AddrMan::Connected() on block-relay-only peers; see
            // FinalizeNode().
            //
            // This moves an address from New to Tried table in Addrman,
            // resolves tried-table collisions, etc.
            m_addrman.Good(pfrom.addr);
        }

        std::string remoteAddr;
        if (fLogIPs)
            remoteAddr = ", peeraddr=" + pfrom.addr.ToStringAddrPort();

        LogPrint(BCLog::NET, "receive version message: %s: version %d, blocks=%d, us=%s, txrelay=%d, peer=%d%s\n",
                  cleanSubVer, pfrom.nVersion,
                  peer->m_starting_height, addrMe.ToStringAddrPort(), fRelay, pfrom.GetId(),
                  remoteAddr);

        int64_t nTimeOffset = nTime - GetTime();
        pfrom.nTimeOffset = nTimeOffset;
        if (!pfrom.IsInboundConn()) {
            // Don't use timedata samples from inbound peers to make it
            // harder for others to tamper with our adjusted time.
            AddTimeData(pfrom.addr, nTimeOffset);
        }

        // If the peer is old enough to have the old alert system, send it the final alert.
        if (greatest_common_version <= 70012) {
            DataStream finalAlert{ParseHex("60010000000000000000000000ffffff7f00000000ffffff7ffeffff7f01ffffff7f00000000ffffff7f00ffffff7f002f555247454e543a20416c657274206b657920636f6d70726f6d697365642c2075706772616465207265717569726564004630440220653febd6410f470f6bae11cad19c48413becb1ac2c17f908fd0fd53bdc3abd5202206d0e9c96fe88d4a0f01ed9dedae2b6f9e00da94cad0fecaae66ecf689bf71b50")};
            m_connman.PushMessage(&pfrom, CNetMsgMaker(greatest_common_version).Make("alert", finalAlert));
        }

        // Feeler connections exist only to verify if address is online.
        if (pfrom.IsFeelerConn()) {
            LogPrint(BCLog::NET, "feeler connection completed peer=%d; disconnecting\n", pfrom.GetId());
            pfrom.fDisconnect = true;
        }
        return;
    }

    if (pfrom.nVersion == 0) {
        // Must have a version message before anything else
        LogPrint(BCLog::NET, "non-version message before version handshake. Message \"%s\" from peer=%d\n", SanitizeString(msg_type), pfrom.GetId());
        return;
    }

    // At this point, the outgoing message serialization version can't change.
    const CNetMsgMaker msgMaker(pfrom.GetCommonVersion());

    if (msg_type == NetMsgType::VERACK) {
        if (pfrom.fSuccessfullyConnected) {
            LogPrint(BCLog::NET, "ignoring redundant verack message from peer=%d\n", pfrom.GetId());
            return;
        }

        if (!pfrom.IsInboundConn()) {
            LogPrintf("New outbound peer connected: version: %d, blocks=%d, peer=%d%s (%s)\n",
                      pfrom.nVersion.load(), peer->m_starting_height,
                      pfrom.GetId(), (fLogIPs ? strprintf(", peeraddr=%s", pfrom.addr.ToStringAddrPort()) : ""),
                      pfrom.ConnectionTypeAsString());
        }

        if (pfrom.GetCommonVersion() >= SHORT_IDS_BLOCKS_VERSION) {
            // Tell our peer we are willing to provide version 2 cmpctblocks.
            // However, we do not request new block announcements using
            // cmpctblock messages.
            // We send this to non-NODE NETWORK peers as well, because
            // they may wish to request compact blocks from us
            m_connman.PushMessage(&pfrom, msgMaker.Make(NetMsgType::SENDCMPCT, /*high_bandwidth=*/false, /*version=*/CMPCTBLOCKS_VERSION));
        }

        if (m_txreconciliation) {
            if (!peer->m_wtxid_relay || !m_txreconciliation->IsPeerRegistered(pfrom.GetId())) {
                // We could have optimistically pre-registered/registered the peer. In that case,
                // we should forget about the reconciliation state here if this wasn't followed
                // by WTXIDRELAY (since WTXIDRELAY can't be announced later).
                m_txreconciliation->ForgetPeer(pfrom.GetId());
            }
        }

        if (auto tx_relay = peer->GetTxRelay()) {
            // `TxRelay::m_tx_inventory_to_send` must be empty before the
            // version handshake is completed as
            // `TxRelay::m_next_inv_send_time` is first initialised in
            // `SendMessages` after the verack is received. Any transactions
            // received during the version handshake would otherwise
            // immediately be advertised without random delay, potentially
            // leaking the time of arrival to a spy.
            Assume(WITH_LOCK(
                tx_relay->m_tx_inventory_mutex,
                return tx_relay->m_tx_inventory_to_send.empty() &&
                       tx_relay->m_next_inv_send_time == 0s));
        }

        pfrom.fSuccessfullyConnected = true;
        return;
    }

    if (msg_type == NetMsgType::SENDHEADERS) {
        peer->m_prefers_headers = true;
        return;
    }

    if (msg_type == NetMsgType::SENDCMPCT) {
        bool sendcmpct_hb{false};
        uint64_t sendcmpct_version{0};
        vRecv >> sendcmpct_hb >> sendcmpct_version;

        // Only support compact block relay with witnesses
        if (sendcmpct_version != CMPCTBLOCKS_VERSION) return;

        LOCK(cs_main);
        CNodeState* nodestate = State(pfrom.GetId());
        nodestate->m_provides_cmpctblocks = true;
        nodestate->m_requested_hb_cmpctblocks = sendcmpct_hb;
        // save whether peer selects us as BIP152 high-bandwidth peer
        // (receiving sendcmpct(1) signals high-bandwidth, sendcmpct(0) low-bandwidth)
        pfrom.m_bip152_highbandwidth_from = sendcmpct_hb;
        return;
    }

    // BIP339 defines feature negotiation of wtxidrelay, which must happen between
    // VERSION and VERACK to avoid relay problems from switching after a connection is up.
    if (msg_type == NetMsgType::WTXIDRELAY) {
        if (pfrom.fSuccessfullyConnected) {
            // Disconnect peers that send a wtxidrelay message after VERACK.
            LogPrint(BCLog::NET, "wtxidrelay received after verack from peer=%d; disconnecting\n", pfrom.GetId());
            pfrom.fDisconnect = true;
            return;
        }
        if (pfrom.GetCommonVersion() >= WTXID_RELAY_VERSION) {
            if (!peer->m_wtxid_relay) {
                peer->m_wtxid_relay = true;
                m_wtxid_relay_peers++;
            } else {
                LogPrint(BCLog::NET, "ignoring duplicate wtxidrelay from peer=%d\n", pfrom.GetId());
            }
        } else {
            LogPrint(BCLog::NET, "ignoring wtxidrelay due to old common version=%d from peer=%d\n", pfrom.GetCommonVersion(), pfrom.GetId());
        }
        return;
    }

    // BIP155 defines feature negotiation of addrv2 and sendaddrv2, which must happen
    // between VERSION and VERACK.
    if (msg_type == NetMsgType::SENDADDRV2) {
        if (pfrom.fSuccessfullyConnected) {
            // Disconnect peers that send a SENDADDRV2 message after VERACK.
            LogPrint(BCLog::NET, "sendaddrv2 received after verack from peer=%d; disconnecting\n", pfrom.GetId());
            pfrom.fDisconnect = true;
            return;
        }
        peer->m_wants_addrv2 = true;
        return;
    }

    // Received from a peer demonstrating readiness to announce transactions via reconciliations.
    // This feature negotiation must happen between VERSION and VERACK to avoid relay problems
    // from switching announcement protocols after the connection is up.
    if (msg_type == NetMsgType::SENDTXRCNCL) {
        if (!m_txreconciliation) {
            LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "sendtxrcncl from peer=%d ignored, as our node does not have txreconciliation enabled\n", pfrom.GetId());
            return;
        }

        if (pfrom.fSuccessfullyConnected) {
            LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "sendtxrcncl received after verack from peer=%d; disconnecting\n", pfrom.GetId());
            pfrom.fDisconnect = true;
            return;
        }

        // Peer must not offer us reconciliations if we specified no tx relay support in VERSION.
        if (RejectIncomingTxs(pfrom)) {
            LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "sendtxrcncl received from peer=%d to which we indicated no tx relay; disconnecting\n", pfrom.GetId());
            pfrom.fDisconnect = true;
            return;
        }

        // Peer must not offer us reconciliations if they specified no tx relay support in VERSION.
        // This flag might also be false in other cases, but the RejectIncomingTxs check above
        // eliminates them, so that this flag fully represents what we are looking for.
        const auto* tx_relay = peer->GetTxRelay();
        if (!tx_relay || !WITH_LOCK(tx_relay->m_bloom_filter_mutex, return tx_relay->m_relay_txs)) {
            LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "sendtxrcncl received from peer=%d which indicated no tx relay to us; disconnecting\n", pfrom.GetId());
            pfrom.fDisconnect = true;
            return;
        }

        uint32_t peer_txreconcl_version;
        uint64_t remote_salt;
        vRecv >> peer_txreconcl_version >> remote_salt;

        const ReconciliationRegisterResult result = m_txreconciliation->RegisterPeer(pfrom.GetId(), pfrom.IsInboundConn(),
                                                                                     peer_txreconcl_version, remote_salt);
        switch (result) {
        case ReconciliationRegisterResult::NOT_FOUND:
            LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "Ignore unexpected txreconciliation signal from peer=%d\n", pfrom.GetId());
            break;
        case ReconciliationRegisterResult::SUCCESS:
            break;
        case ReconciliationRegisterResult::ALREADY_REGISTERED:
            LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "txreconciliation protocol violation from peer=%d (sendtxrcncl received from already registered peer); disconnecting\n", pfrom.GetId());
            pfrom.fDisconnect = true;
            return;
        case ReconciliationRegisterResult::PROTOCOL_VIOLATION:
            LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "txreconciliation protocol violation from peer=%d; disconnecting\n", pfrom.GetId());
            pfrom.fDisconnect = true;
            return;
        }
        return;
    }

    if (!pfrom.fSuccessfullyConnected) {
        LogPrint(BCLog::NET, "Unsupported message \"%s\" prior to verack from peer=%d\n", SanitizeString(msg_type), pfrom.GetId());
        return;
    }

    if (msg_type == NetMsgType::ADDR || msg_type == NetMsgType::ADDRV2) {
        int stream_version = vRecv.GetVersion();
        if (msg_type == NetMsgType::ADDRV2) {
            // Add ADDRV2_FORMAT to the version so that the CNetAddr and CAddress
            // unserialize methods know that an address in v2 format is coming.
            stream_version |= ADDRV2_FORMAT;
        }

        OverrideStream<CDataStream> s(&vRecv, vRecv.GetType(), stream_version);
        std::vector<CAddress> vAddr;

        s >> vAddr;

        if (!SetupAddressRelay(pfrom, *peer)) {
            LogPrint(BCLog::NET, "ignoring %s message from %s peer=%d\n", msg_type, pfrom.ConnectionTypeAsString(), pfrom.GetId());
            return;
        }

        if (vAddr.size() > MAX_ADDR_TO_SEND)
        {
            Misbehaving(*peer, 20, strprintf("%s message size = %u", msg_type, vAddr.size()));
            return;
        }

        // Store the new addresses
        std::vector<CAddress> vAddrOk;
        const auto current_a_time{Now<NodeSeconds>()};

        // Update/increment addr rate limiting bucket.
        const auto current_time{GetTime<std::chrono::microseconds>()};
        if (peer->m_addr_token_bucket < MAX_ADDR_PROCESSING_TOKEN_BUCKET) {
            // Don't increment bucket if it's already full
            const auto time_diff = std::max(current_time - peer->m_addr_token_timestamp, 0us);
            const double increment = Ticks<SecondsDouble>(time_diff) * MAX_ADDR_RATE_PER_SECOND;
            peer->m_addr_token_bucket = std::min<double>(peer->m_addr_token_bucket + increment, MAX_ADDR_PROCESSING_TOKEN_BUCKET);
        }
        peer->m_addr_token_timestamp = current_time;

        const bool rate_limited = !pfrom.HasPermission(NetPermissionFlags::Addr);
        uint64_t num_proc = 0;
        uint64_t num_rate_limit = 0;
        Shuffle(vAddr.begin(), vAddr.end(), FastRandomContext());
        for (CAddress& addr : vAddr)
        {
            if (interruptMsgProc)
                return;

            // Apply rate limiting.
            if (peer->m_addr_token_bucket < 1.0) {
                if (rate_limited) {
                    ++num_rate_limit;
                    continue;
                }
            } else {
                peer->m_addr_token_bucket -= 1.0;
            }
            // We only bother storing full nodes, though this may include
            // things which we would not make an outbound connection to, in
            // part because we may make feeler connections to them.
            if (!MayHaveUsefulAddressDB(addr.nServices) && !HasAllDesirableServiceFlags(addr.nServices))
                continue;

            if (addr.nTime <= NodeSeconds{100000000s} || addr.nTime > current_a_time + 10min) {
                addr.nTime = current_a_time - 5 * 24h;
            }
            AddAddressKnown(*peer, addr);
            if (m_banman && (m_banman->IsDiscouraged(addr) || m_banman->IsBanned(addr))) {
                // Do not process banned/discouraged addresses beyond remembering we received them
                continue;
            }
            ++num_proc;
            bool fReachable = IsReachable(addr);
            if (addr.nTime > current_a_time - 10min && !peer->m_getaddr_sent && vAddr.size() <= 10 && addr.IsRoutable()) {
                // Relay to a limited number of other nodes
                RelayAddress(pfrom.GetId(), addr, fReachable);
            }
            // Do not store addresses outside our network
            if (fReachable)
                vAddrOk.push_back(addr);
        }
        peer->m_addr_processed += num_proc;
        peer->m_addr_rate_limited += num_rate_limit;
        LogPrint(BCLog::NET, "Received addr: %u addresses (%u processed, %u rate-limited) from peer=%d\n",
                 vAddr.size(), num_proc, num_rate_limit, pfrom.GetId());

        m_addrman.Add(vAddrOk, pfrom.addr, 2h);
        if (vAddr.size() < 1000) peer->m_getaddr_sent = false;

        // AddrFetch: Require multiple addresses to avoid disconnecting on self-announcements
        if (pfrom.IsAddrFetchConn() && vAddr.size() > 1) {
            LogPrint(BCLog::NET, "addrfetch connection completed peer=%d; disconnecting\n", pfrom.GetId());
            pfrom.fDisconnect = true;
        }
        return;
    }

    if (msg_type == NetMsgType::INV) {
        std::vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            Misbehaving(*peer, 20, strprintf("inv message size = %u", vInv.size()));
            return;
        }

        const bool reject_tx_invs{RejectIncomingTxs(pfrom)};

        LOCK(cs_main);

        const auto current_time{GetTime<std::chrono::microseconds>()};
        uint256* best_block{nullptr};

        for (CInv& inv : vInv) {
            if (interruptMsgProc) return;

            // Ignore INVs that don't match wtxidrelay setting.
            // Note that orphan parent fetching always uses MSG_TX GETDATAs regardless of the wtxidrelay setting.
            // This is fine as no INV messages are involved in that process.
            if (peer->m_wtxid_relay) {
                if (inv.IsMsgTx()) continue;
            } else {
                if (inv.IsMsgWtx()) continue;
            }

            if (inv.IsMsgBlk()) {
                const bool fAlreadyHave = AlreadyHaveBlock(inv.hash);
                LogPrint(BCLog::NET, "got inv: %s  %s peer=%d\n", inv.ToString(), fAlreadyHave ? "have" : "new", pfrom.GetId());

                UpdateBlockAvailability(pfrom.GetId(), inv.hash);
                if (!fAlreadyHave && !m_chainman.m_blockman.LoadingBlocks() && !IsBlockRequested(inv.hash)) {
                    // Headers-first is the primary method of announcement on
                    // the network. If a node fell back to sending blocks by
                    // inv, it may be for a re-org, or because we haven't
                    // completed initial headers sync. The final block hash
                    // provided should be the highest, so send a getheaders and
                    // then fetch the blocks we need to catch up.
                    best_block = &inv.hash;
                }
            } else if (inv.IsGenTxMsg()) {
                if (reject_tx_invs) {
                    LogPrint(BCLog::NET, "transaction (%s) inv sent in violation of protocol, disconnecting peer=%d\n", inv.hash.ToString(), pfrom.GetId());
                    pfrom.fDisconnect = true;
                    return;
                }
                const GenTxid gtxid = ToGenTxid(inv);
                const bool fAlreadyHave = AlreadyHaveTx(gtxid);
                LogPrint(BCLog::NET, "got inv: %s  %s peer=%d\n", inv.ToString(), fAlreadyHave ? "have" : "new", pfrom.GetId());

                AddKnownTx(*peer, inv.hash);
                if (!fAlreadyHave && !m_chainman.ActiveChainstate().IsInitialBlockDownload()) {
                    AddTxAnnouncement(pfrom, gtxid, current_time);
                }
            } else {
                LogPrint(BCLog::NET, "Unknown inv type \"%s\" received from peer=%d\n", inv.ToString(), pfrom.GetId());
            }
        }

        if (best_block != nullptr) {
            // If we haven't started initial headers-sync with this peer, then
            // consider sending a getheaders now. On initial startup, there's a
            // reliability vs bandwidth tradeoff, where we are only trying to do
            // initial headers sync with one peer at a time, with a long
            // timeout (at which point, if the sync hasn't completed, we will
            // disconnect the peer and then choose another). In the meantime,
            // as new blocks are found, we are willing to add one new peer per
            // block to sync with as well, to sync quicker in the case where
            // our initial peer is unresponsive (but less bandwidth than we'd
            // use if we turned on sync with all peers).
            CNodeState& state{*Assert(State(pfrom.GetId()))};
            if (state.fSyncStarted || (!peer->m_inv_triggered_getheaders_before_sync && *best_block != m_last_block_inv_triggering_headers_sync)) {
                if (MaybeSendGetHeaders(pfrom, GetLocator(m_chainman.m_best_header), *peer)) {
                    LogPrint(BCLog::NET, "getheaders (%d) %s to peer=%d\n",
                            m_chainman.m_best_header->nHeight, best_block->ToString(),
                            pfrom.GetId());
                }
                if (!state.fSyncStarted) {
                    peer->m_inv_triggered_getheaders_before_sync = true;
                    // Update the last block hash that triggered a new headers
                    // sync, so that we don't turn on headers sync with more
                    // than 1 new peer every new block.
                    m_last_block_inv_triggering_headers_sync = *best_block;
                }
            }
        }

        return;
    }

    if (msg_type == NetMsgType::GETDATA) {
        std::vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            Misbehaving(*peer, 20, strprintf("getdata message size = %u", vInv.size()));
            return;
        }

        LogPrint(BCLog::NET, "received getdata (%u invsz) peer=%d\n", vInv.size(), pfrom.GetId());

        if (vInv.size() > 0) {
            LogPrint(BCLog::NET, "received getdata for: %s peer=%d\n", vInv[0].ToString(), pfrom.GetId());
        }

        {
            LOCK(peer->m_getdata_requests_mutex);
            peer->m_getdata_requests.insert(peer->m_getdata_requests.end(), vInv.begin(), vInv.end());
            ProcessGetData(pfrom, *peer, interruptMsgProc);
        }

        return;
    }

    if (msg_type == NetMsgType::GETBLOCKS) {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        if (locator.vHave.size() > MAX_LOCATOR_SZ) {
            LogPrint(BCLog::NET, "getblocks locator size %lld > %d, disconnect peer=%d\n", locator.vHave.size(), MAX_LOCATOR_SZ, pfrom.GetId());
            pfrom.fDisconnect = true;
            return;
        }

        // We might have announced the currently-being-connected tip using a
        // compact block, which resulted in the peer sending a getblocks
        // request, which we would otherwise respond to without the new block.
        // To avoid this situation we simply verify that we are on our best
        // known chain now. This is super overkill, but we handle it better
        // for getheaders requests, and there are no known nodes which support
        // compact blocks but still use getblocks to request blocks.
        {
            std::shared_ptr<const CBlock> a_recent_block;
            {
                LOCK(m_most_recent_block_mutex);
                a_recent_block = m_most_recent_block;
            }
            BlockValidationState state;
            if (!m_chainman.ActiveChainstate().ActivateBestChain(state, a_recent_block)) {
                LogPrint(BCLog::NET, "failed to activate chain (%s)\n", state.ToString());
            }
        }

        LOCK(cs_main);

        // Find the last block the caller has in the main chain
        const CBlockIndex* pindex = m_chainman.ActiveChainstate().FindForkInGlobalIndex(locator);

        // Send the rest of the chain
        if (pindex)
            pindex = m_chainman.ActiveChain().Next(pindex);
        int nLimit = 500;
        LogPrint(BCLog::NET, "getblocks %d to %s limit %d from peer=%d\n", (pindex ? pindex->nHeight : -1), hashStop.IsNull() ? "end" : hashStop.ToString(), nLimit, pfrom.GetId());
        for (; pindex; pindex = m_chainman.ActiveChain().Next(pindex))
        {
            if (pindex->GetBlockHash() == hashStop)
            {
                LogPrint(BCLog::NET, "  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                // peercoin: tell downloading node about the latest block if it's
                // without risk being rejected due to stake connection check
                if (hashStop != m_chainman.ActiveChain().Tip()->GetBlockHash() && pindex->GetBlockTime() + Params().GetConsensus().nStakeMinAge > m_chainman.ActiveChain().Tip()->GetBlockTime())
                    WITH_LOCK(peer->m_block_inv_mutex, peer->m_blocks_for_inv_relay.push_back(pindex->GetBlockHash()));
                break;
            }
            WITH_LOCK(peer->m_block_inv_mutex, peer->m_blocks_for_inv_relay.push_back(pindex->GetBlockHash()));
            if (--nLimit <= 0) {
                // When this block is requested, we'll send an inv that'll
                // trigger the peer to getblocks the next batch of inventory.
                LogPrint(BCLog::NET, "  getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                WITH_LOCK(peer->m_block_inv_mutex, {peer->m_continuation_block = pindex->GetBlockHash();});
                break;
            }
        }
        return;
    }

    if (msg_type == NetMsgType::GETBLOCKTXN) {
        BlockTransactionsRequest req;
        vRecv >> req;

        std::shared_ptr<const CBlock> recent_block;
        {
            LOCK(m_most_recent_block_mutex);
            if (m_most_recent_block_hash == req.blockhash)
                recent_block = m_most_recent_block;
            // Unlock m_most_recent_block_mutex to avoid cs_main lock inversion
        }
        if (recent_block) {
            SendBlockTransactions(pfrom, *peer, *recent_block, req);
            return;
        }

        {
            LOCK(cs_main);

            const CBlockIndex* pindex = m_chainman.m_blockman.LookupBlockIndex(req.blockhash);
            if (!pindex || !(pindex->nStatus & BLOCK_HAVE_DATA)) {
                LogPrint(BCLog::NET, "Peer %d sent us a getblocktxn for a block we don't have\n", pfrom.GetId());
                return;
            }

            if (pindex->nHeight >= m_chainman.ActiveChain().Height() - MAX_BLOCKTXN_DEPTH) {
                CBlock block;
                bool ret = ReadBlockFromDisk(block, pindex, m_chainparams.GetConsensus());
                assert(ret);

                SendBlockTransactions(pfrom, *peer, block, req);
                return;
            }
        }

        // If an older block is requested (should never happen in practice,
        // but can happen in tests) send a block response instead of a
        // blocktxn response. Sending a full block response instead of a
        // small blocktxn response is preferable in the case where a peer
        // might maliciously send lots of getblocktxn requests to trigger
        // expensive disk reads, because it will require the peer to
        // actually receive all the data read from disk over the network.
        LogPrint(BCLog::NET, "Peer %d sent us a getblocktxn for a block > %i deep\n", pfrom.GetId(), MAX_BLOCKTXN_DEPTH);
        CInv inv{MSG_WITNESS_BLOCK, req.blockhash};
        WITH_LOCK(peer->m_getdata_requests_mutex, peer->m_getdata_requests.push_back(inv));
        // The message processing loop will go around again (without pausing) and we'll respond then
        return;
    }

    if (msg_type == NetMsgType::GETHEADERS) {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        if (locator.vHave.size() > MAX_LOCATOR_SZ) {
            LogPrint(BCLog::NET, "getheaders locator size %lld > %d, disconnect peer=%d\n", locator.vHave.size(), MAX_LOCATOR_SZ, pfrom.GetId());
            pfrom.fDisconnect = true;
            return;
        }

        if (m_chainman.m_blockman.LoadingBlocks()) {
            LogPrint(BCLog::NET, "Ignoring getheaders from peer=%d while importing/reindexing\n", pfrom.GetId());
            return;
        }

        LOCK(cs_main);

        // Note that if we were to be on a chain that forks from the checkpointed
        // chain, then serving those headers to a peer that has seen the
        // checkpointed chain would cause that peer to disconnect us. Requiring
        // that our chainwork exceed the minimum chain work is a protection against
        // being fed a bogus chain when we started up for the first time and
        // getting partitioned off the honest network for serving that chain to
        // others.
        if (m_chainman.ActiveTip() == nullptr ||
                (m_chainman.ActiveTip()->nChainTrust < m_chainman.MinimumChainWork() && !pfrom.HasPermission(NetPermissionFlags::Download))) {
            LogPrint(BCLog::NET, "Ignoring getheaders from peer=%d because active chain has too little work; sending empty response\n", pfrom.GetId());
            // Just respond with an empty headers message, to tell the peer to
            // go away but not treat us as unresponsive.
            m_connman.PushMessage(&pfrom, msgMaker.Make(NetMsgType::HEADERS, std::vector<CBlock>()));
            return;
        }

        CNodeState *nodestate = State(pfrom.GetId());
        const CBlockIndex* pindex = nullptr;
        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            pindex = m_chainman.m_blockman.LookupBlockIndex(hashStop);
            if (!pindex) {
                return;
            }

            if (!BlockRequestAllowed(pindex)) {
                LogPrint(BCLog::NET, "%s: ignoring request from peer=%i for old block header that isn't in the main chain\n", __func__, pfrom.GetId());
                return;
            }
        }
        else
        {
            // Find the last block the caller has in the main chain
            pindex = m_chainman.ActiveChainstate().FindForkInGlobalIndex(locator);
            if (pindex)
                pindex = m_chainman.ActiveChain().Next(pindex);
        }

        // we must use CBlocks, as CBlockHeaders won't include the 0x00 nTx count at the end
        std::vector<CBlock> vHeaders;
        int nLimit = MAX_HEADERS_RESULTS;
        LogPrint(BCLog::NET, "getheaders %d to %s from peer=%d\n", (pindex ? pindex->nHeight : -1), hashStop.IsNull() ? "end" : hashStop.ToString(), pfrom.GetId());
        for (; pindex; pindex = m_chainman.ActiveChain().Next(pindex))
        {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                break;
        }
        // pindex can be nullptr either if we sent m_chainman.ActiveChain().Tip() OR
        // if our peer has m_chainman.ActiveChain().Tip() (and thus we are sending an empty
        // headers message). In both cases it's safe to update
        // pindexBestHeaderSent to be our tip.
        //
        // It is important that we simply reset the BestHeaderSent value here,
        // and not max(BestHeaderSent, newHeaderSent). We might have announced
        // the currently-being-connected tip using a compact block, which
        // resulted in the peer sending a headers request, which we respond to
        // without the new block. By resetting the BestHeaderSent, we ensure we
        // will re-announce the new block via headers (or compact blocks again)
        // in the SendMessages logic.
        nodestate->pindexBestHeaderSent = pindex ? pindex : m_chainman.ActiveChain().Tip();
        m_connman.PushMessage(&pfrom, msgMaker.Make(NetMsgType::HEADERS, vHeaders));
        return;
    }

    if (msg_type == NetMsgType::TX) {
        if (RejectIncomingTxs(pfrom)) {
            LogPrint(BCLog::NET, "transaction sent in violation of protocol peer=%d\n", pfrom.GetId());
            pfrom.fDisconnect = true;
            return;
        }

        // Stop processing the transaction early if we are still in IBD since we don't
        // have enough information to validate it yet. Sending unsolicited transactions
        // is not considered a protocol violation, so don't punish the peer.
        if (m_chainman.ActiveChainstate().IsInitialBlockDownload()) return;

        CTransactionRef ptx;
        vRecv >> ptx;
        const CTransaction& tx = *ptx;

        const uint256& txid = ptx->GetHash();
        const uint256& wtxid = ptx->GetWitnessHash();

        const uint256& hash = peer->m_wtxid_relay ? wtxid : txid;
        AddKnownTx(*peer, hash);
        if (peer->m_wtxid_relay && txid != wtxid) {
            // Insert txid into m_tx_inventory_known_filter, even for
            // wtxidrelay peers. This prevents re-adding of
            // unconfirmed parents to the recently_announced
            // filter, when a child tx is requested. See
            // ProcessGetData().
            AddKnownTx(*peer, txid);
        }

        LOCK(cs_main);

        m_txrequest.ReceivedResponse(pfrom.GetId(), txid);
        if (tx.HasWitness()) m_txrequest.ReceivedResponse(pfrom.GetId(), wtxid);

        // We do the AlreadyHaveTx() check using wtxid, rather than txid - in the
        // absence of witness malleation, this is strictly better, because the
        // recent rejects filter may contain the wtxid but rarely contains
        // the txid of a segwit transaction that has been rejected.
        // In the presence of witness malleation, it's possible that by only
        // doing the check with wtxid, we could overlook a transaction which
        // was confirmed with a different witness, or exists in our mempool
        // with a different witness, but this has limited downside:
        // mempool validation does its own lookup of whether we have the txid
        // already; and an adversary can already relay us old transactions
        // (older than our recency filter) if trying to DoS us, without any need
        // for witness malleation.
        if (AlreadyHaveTx(GenTxid::Wtxid(wtxid))) {
            if (pfrom.HasPermission(NetPermissionFlags::ForceRelay)) {
                // Always relay transactions received from peers with forcerelay
                // permission, even if they were already in the mempool, allowing
                // the node to function as a gateway for nodes hidden behind it.
                if (!m_mempool.exists(GenTxid::Txid(tx.GetHash()))) {
                    LogPrintf("Not relaying non-mempool transaction %s from forcerelay peer=%d\n", tx.GetHash().ToString(), pfrom.GetId());
                } else {
                    LogPrintf("Force relaying tx %s from peer=%d\n", tx.GetHash().ToString(), pfrom.GetId());
                    RelayTransaction(tx.GetHash(), tx.GetWitnessHash());
                }
            }
            return;
        }

        const MempoolAcceptResult result = m_chainman.ProcessTransaction(ptx);
        const TxValidationState& state = result.m_state;

        if (result.m_result_type == MempoolAcceptResult::ResultType::VALID) {
            // As this version of the transaction was acceptable, we can forget about any
            // requests for it.
            m_txrequest.ForgetTxHash(tx.GetHash());
            m_txrequest.ForgetTxHash(tx.GetWitnessHash());
            RelayTransaction(tx.GetHash(), tx.GetWitnessHash());
            m_orphanage.AddChildrenToWorkSet(tx);

            pfrom.m_last_tx_time = GetTime<std::chrono::seconds>();

            LogPrint(BCLog::MEMPOOL, "AcceptToMemoryPool: peer=%d: accepted %s (poolsz %u txn, %u kB)\n",
                pfrom.GetId(),
                tx.GetHash().ToString(),
                m_mempool.size(), m_mempool.DynamicMemoryUsage() / 1000);

            for (const CTransactionRef& removedTx : result.m_replaced_transactions.value()) {
                AddToCompactExtraTransactions(removedTx);
            }
        }
        else if (state.GetResult() == TxValidationResult::TX_MISSING_INPUTS)
        {
            bool fRejectedParents = false; // It may be the case that the orphans parents have all been rejected

            // Deduplicate parent txids, so that we don't have to loop over
            // the same parent txid more than once down below.
            std::vector<uint256> unique_parents;
            unique_parents.reserve(tx.vin.size());
            for (const CTxIn& txin : tx.vin) {
                // We start with all parents, and then remove duplicates below.
                unique_parents.push_back(txin.prevout.hash);
            }
            std::sort(unique_parents.begin(), unique_parents.end());
            unique_parents.erase(std::unique(unique_parents.begin(), unique_parents.end()), unique_parents.end());
            for (const uint256& parent_txid : unique_parents) {
                if (m_recent_rejects.contains(parent_txid)) {
                    fRejectedParents = true;
                    break;
                }
            }
            if (!fRejectedParents) {
                const auto current_time{GetTime<std::chrono::microseconds>()};

                for (const uint256& parent_txid : unique_parents) {
                    // Here, we only have the txid (and not wtxid) of the
                    // inputs, so we only request in txid mode, even for
                    // wtxidrelay peers.
                    // Eventually we should replace this with an improved
                    // protocol for getting all unconfirmed parents.
                    const auto gtxid{GenTxid::Txid(parent_txid)};
                    AddKnownTx(*peer, parent_txid);
                    if (!AlreadyHaveTx(gtxid)) AddTxAnnouncement(pfrom, gtxid, current_time);
                }

                if (m_orphanage.AddTx(ptx, pfrom.GetId())) {
                    AddToCompactExtraTransactions(ptx);
                }

                // Once added to the orphan pool, a tx is considered AlreadyHave, and we shouldn't request it anymore.
                m_txrequest.ForgetTxHash(tx.GetHash());
                m_txrequest.ForgetTxHash(tx.GetWitnessHash());

                // DoS prevention: do not allow m_orphanage to grow unbounded (see CVE-2012-3789)
                unsigned int nMaxOrphanTx = (unsigned int)std::max((int64_t)0, gArgs.GetIntArg("-maxorphantx", DEFAULT_MAX_ORPHAN_TRANSACTIONS));
                m_orphanage.LimitOrphans(nMaxOrphanTx);
            } else {
                LogPrint(BCLog::MEMPOOL, "not keeping orphan with rejected parents %s\n",tx.GetHash().ToString());
                // We will continue to reject this tx since it has rejected
                // parents so avoid re-requesting it from other peers.
                // Here we add both the txid and the wtxid, as we know that
                // regardless of what witness is provided, we will not accept
                // this, so we don't need to allow for redownload of this txid
                // from any of our non-wtxidrelay peers.
                m_recent_rejects.insert(tx.GetHash());
                m_recent_rejects.insert(tx.GetWitnessHash());
                m_txrequest.ForgetTxHash(tx.GetHash());
                m_txrequest.ForgetTxHash(tx.GetWitnessHash());
            }
        } else {
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
                m_recent_rejects.insert(tx.GetWitnessHash());
                m_txrequest.ForgetTxHash(tx.GetWitnessHash());
                // If the transaction failed for TX_INPUTS_NOT_STANDARD,
                // then we know that the witness was irrelevant to the policy
                // failure, since this check depends only on the txid
                // (the scriptPubKey being spent is covered by the txid).
                // Add the txid to the reject filter to prevent repeated
                // processing of this transaction in the event that child
                // transactions are later received (resulting in
                // parent-fetching by txid via the orphan-handling logic).
                if (state.GetResult() == TxValidationResult::TX_INPUTS_NOT_STANDARD && tx.GetWitnessHash() != tx.GetHash()) {
                    m_recent_rejects.insert(tx.GetHash());
                    m_txrequest.ForgetTxHash(tx.GetHash());
                }
                if (RecursiveDynamicUsage(*ptx) < 100000) {
                    AddToCompactExtraTransactions(ptx);
                }
            }
        }

        // If a tx has been detected by m_recent_rejects, we will have reached
        // this point and the tx will have been ignored. Because we haven't
        // submitted the tx to our mempool, we won't have computed a DoS
        // score for it or determined exactly why we consider it invalid.
        //
        // This means we won't penalize any peer subsequently relaying a DoSy
        // tx (even if we penalized the first peer who gave it to us) because
        // we have to account for m_recent_rejects showing false positives. In
        // other words, we shouldn't penalize a peer if we aren't *sure* they
        // submitted a DoSy tx.
        //
        // Note that m_recent_rejects doesn't just record DoSy or invalid
        // transactions, but any tx not accepted by the mempool, which may be
        // due to node policy (vs. consensus). So we can't blanket penalize a
        // peer simply for relaying a tx that our m_recent_rejects has caught,
        // regardless of false positives.

        if (state.IsInvalid()) {
            LogPrint(BCLog::MEMPOOLREJ, "%s from peer=%d was not accepted: %s\n", tx.GetHash().ToString(),
                pfrom.GetId(),
                state.ToString());
            MaybePunishNodeForTx(pfrom.GetId(), state);
        }
        return;
    }

    if (msg_type == NetMsgType::CMPCTBLOCK)
    {
        ProcessCMPCTBlock(pfrom, *peer, vRecv, time_received, interruptMsgProc);
        return;
    }

    if (msg_type == NetMsgType::BLOCKTXN)
    {
        ProcessBLOCKTXN(pfrom, *peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::HEADERS)
    {
        // Ignore headers received while importing
        if (m_chainman.m_blockman.LoadingBlocks()) {
            LogPrint(BCLog::NET, "Unexpected headers message received from peer %d\n", pfrom.GetId());
            return;
        }

        // Assume that this is in response to any outstanding getheaders
        // request we may have sent, and clear out the time of our last request
        peer->m_last_getheaders_timestamp = {};

        std::vector<CBlockHeader> headers;

        // Bypass the normal CBlock deserialization, as we don't want to risk deserializing 2000 full blocks.
        unsigned int nCount = ReadCompactSize(vRecv);
        if (nCount > MAX_HEADERS_RESULTS) {
            Misbehaving(*peer, 20, strprintf("headers message size = %u", nCount));
            return;
        }
        headers.resize(nCount);
        {
            LOCK(cs_main);
            int32_t& nPoSTemperature = mapPoSTemperature[pfrom.addr];
            int nTmpPoSTemperature = nPoSTemperature;
            for (unsigned int n = 0; n < nCount; n++) {
                vRecv >> headers[n];
                ReadCompactSize(vRecv); // ignore tx count; assume it is 0.
                ReadCompactSize(vRecv); // needed for vchBlockSig.

                // peercoin: quick check to see if we should ban peers for PoS spam
                // note: at this point we don't know if PoW headers are valid - we just assume they are
                // so we need to update pfrom->nPoSTemperature once we actualy check them
                bool fPoS = headers[n].nFlags & CBlockIndex::BLOCK_PROOF_OF_STAKE;
                nTmpPoSTemperature += fPoS ? 1 : -POW_HEADER_COOLING;
                // peer cannot cool himself by PoW headers from other branches
                if (n == 0 && !fPoS && headers[n].hashPrevBlock != pfrom.lastAcceptedHeader)
                    nTmpPoSTemperature += POW_HEADER_COOLING;
                nTmpPoSTemperature = std::max(nTmpPoSTemperature, 0);
                if (nTmpPoSTemperature >= MAX_CONSECUTIVE_POS_HEADERS) {
                    nPoSTemperature = (MAX_CONSECUTIVE_POS_HEADERS*3)/4;
                    if (Params().NetworkIDString() != "test") {
                        Misbehaving(*peer, 100, "too many consecutive pos headers");
                        return;
                    }
                }
            }
        }

        ProcessHeadersMessage(pfrom, *peer, std::move(headers), /*via_compact_block=*/false);

        // Check if the headers presync progress needs to be reported to validation.
        // This needs to be done without holding the m_headers_presync_mutex lock.
        if (m_headers_presync_should_signal.exchange(false)) {
            HeadersPresyncStats stats;
            {
                LOCK(m_headers_presync_mutex);
                auto it = m_headers_presync_stats.find(m_headers_presync_bestpeer);
                if (it != m_headers_presync_stats.end()) stats = it->second;
            }
            if (stats.second) {
                m_chainman.ReportHeadersPresync(stats.first, stats.second->first, stats.second->second);
            }
        }

        return;
    }

    if (msg_type == NetMsgType::BLOCK)
    {
        // Ignore block received while importing
        if (m_chainman.m_blockman.LoadingBlocks()) {
            LogPrint(BCLog::NET, "Unexpected block message received from peer %d\n", pfrom.GetId());
            return;
        }

        std::shared_ptr<CBlock> pblock2 = std::make_shared<CBlock>();
        vRecv >> *pblock2;
        int64_t nTimeNow = GetTime();

        LogPrint(BCLog::NET, "received block %s peer=%d\n", pblock2->GetHash().ToString(), pfrom.GetId());

        CBlockIndex* tip;
        CBlockIndex* prev_block{WITH_LOCK(m_chainman.GetMutex(), return m_chainman.m_blockman.LookupBlockIndex(pblock2->hashPrevBlock))};
        // Check for possible mutation if it connects to something we know so we can check for DEPLOYMENT_SEGWIT being active
        if (prev_block && IsBlockMutated(/*block=*/*pblock2,
                           /*check_witness_root=*/IsBTC16BIPsEnabled(prev_block->nTime))) {
            LogPrint(BCLog::NET, "Received mutated block from peer=%d\n", peer->m_id);
            Misbehaving(*peer, 100, "mutated block");
            WITH_LOCK(cs_main, RemoveBlockRequest(pblock2->GetHash(), peer->m_id));
            return;
        }

        bool min_pow_checked = false;
        {
            const uint256 hash2(pblock2->GetHash());
            LOCK(cs_main);
            bool fRequested = mapBlocksInFlight.count(hash2);

            // Check work on this block against our anti-dos thresholds.
            if (prev_block && prev_block->nChainTrust + CalculateHeadersWork({pblock2->GetBlockHeader()}) >= GetAntiDoSWorkThreshold()) {
                min_pow_checked = true;
            }

            if (!fRequested) {
                int32_t& nPoSTemperature = mapPoSTemperature[pfrom.addr];
                if (nPoSTemperature >= MAX_CONSECUTIVE_POS_HEADERS) {
                    nPoSTemperature = (MAX_CONSECUTIVE_POS_HEADERS*3)/4;
                    if (Params().NetworkIDString() != "test") {
                        Misbehaving(*peer, 100, "too many consecutive pos headers");
                        return;
                    }
                }

                if (pblock2->IsProofOfStake() && !m_chainman.ActiveChainstate().IsInitialBlockDownload())
                    nPoSTemperature += 1;

                if (!prev_block->IsValid(BLOCK_VALID_TRANSACTIONS)) {
                    RemoveBlockRequest(hash2, std::nullopt);
                    LogPrint(BCLog::NET, "this block does not connect to any valid known blocks");
                    return;
                }
            }
            // peercoin: store in memory until we can connect it to some chain
            WaitElement we; we.pblock = pblock2; we.time = nTimeNow;
            mapBlocksWait[prev_block] = we;
            tip = m_chainman.ActiveChain().Tip();
        }

        static CBlockIndex* pindexLastAccepted = nullptr;
        if (pindexLastAccepted == nullptr)
            pindexLastAccepted = tip;
        bool fContinue = true;

        // peercoin: accept as many blocks as we possibly can from mapBlocksWait
        while (fContinue) {
            fContinue = false;
            bool fSelected = false;
            bool forceProcessing = false;
            CBlockIndex* pindexPrev;
            std::shared_ptr<CBlock> pblock;

            {
                LOCK(cs_main);
                // peercoin: try to select next block in a constant time
                std::map<CBlockIndex*, WaitElement>::iterator it = mapBlocksWait.find(pindexLastAccepted);
                if (it != mapBlocksWait.end() && pindexLastAccepted != nullptr) {
                    pindexPrev = it->first;
                    pblock = it->second.pblock;
                    mapBlocksWait.erase(pindexPrev);
                    fContinue = true;
                    fSelected = true;
                } else
                // otherwise: try to scan for it
                for (auto& pair : mapBlocksWait) {
                    pindexPrev = pair.first;
                    pblock = pair.second.pblock;
                    const uint256 hash(pblock->GetHash());
                    // remove blocks that were not connected in 60 seconds
                    if (nTimeNow > pair.second.time + 60) {
                        mapBlocksWait.erase(pindexPrev);
                        fContinue = true;
                        RemoveBlockRequest(hash, std::nullopt);
                        break;
                    }
                    if (!pindexPrev->IsValid(BLOCK_VALID_TRANSACTIONS)) {
                        if (pindexPrev->nStatus & BLOCK_FAILED_MASK) {
                            mapBlocksWait.erase(pindexPrev);  // prev block was rejected
                            fContinue = true;
                            RemoveBlockRequest(hash, pfrom.GetId());
                            break;
                        }
                        continue;   // prev block was not (yet) accepted on disk, skip to next one
                    }

                    mapBlocksWait.erase(pindexPrev);
                    fContinue = true;
                    fSelected = true;
                    break;
                }
                if (!fSelected)
                    continue;

                const uint256 hash(pblock->GetHash());
                // Always process the block if we requested it, since we may
                // need it even when it's not a candidate for new tip.
                forceProcessing = IsBlockRequested(hash);
                RemoveBlockRequest(hash, pfrom.GetId());
                // mapBlockSource is only used for punishing peers and setting
                // which peers send us compact blocks, so the race between here and
                // cs_main in ProcessNewBlock is fine.
                mapBlockSource.emplace(hash, std::make_pair(pfrom.GetId(), true));
            }

            ProcessBlock(pfrom, pblock, forceProcessing, min_pow_checked);
        }
        return;
    }

    if (msg_type == NetMsgType::GETADDR) {
        // This asymmetric behavior for inbound and outbound connections was introduced
        // to prevent a fingerprinting attack: an attacker can send specific fake addresses
        // to users' AddrMan and later request them by sending getaddr messages.
        // Making nodes which are behind NAT and can only make outgoing connections ignore
        // the getaddr message mitigates the attack.
        if (!pfrom.IsInboundConn()) {
            LogPrint(BCLog::NET, "Ignoring \"getaddr\" from %s connection. peer=%d\n", pfrom.ConnectionTypeAsString(), pfrom.GetId());
            return;
        }

        // Since this must be an inbound connection, SetupAddressRelay will
        // never fail.
        Assume(SetupAddressRelay(pfrom, *peer));

        // Only send one GetAddr response per connection to reduce resource waste
        // and discourage addr stamping of INV announcements.
        if (peer->m_getaddr_recvd) {
            LogPrint(BCLog::NET, "Ignoring repeated \"getaddr\". peer=%d\n", pfrom.GetId());
            return;
        }
        peer->m_getaddr_recvd = true;

        peer->m_addrs_to_send.clear();
        std::vector<CAddress> vAddr;
        if (pfrom.HasPermission(NetPermissionFlags::Addr)) {
            vAddr = m_connman.GetAddresses(MAX_ADDR_TO_SEND, MAX_PCT_ADDR_TO_SEND, /*network=*/std::nullopt);
        } else {
            vAddr = m_connman.GetAddresses(pfrom, MAX_ADDR_TO_SEND, MAX_PCT_ADDR_TO_SEND);
        }
        FastRandomContext insecure_rand;
        for (const CAddress &addr : vAddr) {
            PushAddress(*peer, addr, insecure_rand);
        }
        return;
    }

    if (msg_type == NetMsgType::MEMPOOL) {
        if (!(peer->m_our_services & NODE_BLOOM) && !pfrom.HasPermission(NetPermissionFlags::Mempool))
        {
            if (!pfrom.HasPermission(NetPermissionFlags::NoBan))
            {
                LogPrint(BCLog::NET, "mempool request with bloom filters disabled, disconnect peer=%d\n", pfrom.GetId());
                pfrom.fDisconnect = true;
            }
            return;
        }

        if (m_connman.OutboundTargetReached(false) && !pfrom.HasPermission(NetPermissionFlags::Mempool))
        {
            if (!pfrom.HasPermission(NetPermissionFlags::NoBan))
            {
                LogPrint(BCLog::NET, "mempool request with bandwidth limit reached, disconnect peer=%d\n", pfrom.GetId());
                pfrom.fDisconnect = true;
            }
            return;
        }

        if (auto tx_relay = peer->GetTxRelay(); tx_relay != nullptr) {
            LOCK(tx_relay->m_tx_inventory_mutex);
            tx_relay->m_send_mempool = true;
        }
        return;
    }

    if (msg_type == NetMsgType::PING) {
        if (pfrom.GetCommonVersion() > BIP0031_VERSION) {
            uint64_t nonce = 0;
            vRecv >> nonce;
            // Echo the message back with the nonce. This allows for two useful features:
            //
            // 1) A remote node can quickly check if the connection is operational
            // 2) Remote nodes can measure the latency of the network thread. If this node
            //    is overloaded it won't respond to pings quickly and the remote node can
            //    avoid sending us more work, like chain download requests.
            //
            // The nonce stops the remote getting confused between different pings: without
            // it, if the remote node sends a ping once per second and this node takes 5
            // seconds to respond to each, the 5th ping the remote sends would appear to
            // return very quickly.
            m_connman.PushMessage(&pfrom, msgMaker.Make(NetMsgType::PONG, nonce));
        }
        return;
    }

    if (msg_type == NetMsgType::PONG) {
        const auto ping_end = time_received;
        uint64_t nonce = 0;
        size_t nAvail = vRecv.in_avail();
        bool bPingFinished = false;
        std::string sProblem;

        if (nAvail >= sizeof(nonce)) {
            vRecv >> nonce;

            // Only process pong message if there is an outstanding ping (old ping without nonce should never pong)
            if (peer->m_ping_nonce_sent != 0) {
                if (nonce == peer->m_ping_nonce_sent) {
                    // Matching pong received, this ping is no longer outstanding
                    bPingFinished = true;
                    const auto ping_time = ping_end - peer->m_ping_start.load();
                    if (ping_time.count() >= 0) {
                        // Let connman know about this successful ping-pong
                        pfrom.PongReceived(ping_time);
                    } else {
                        // This should never happen
                        sProblem = "Timing mishap";
                    }
                } else {
                    // Nonce mismatches are normal when pings are overlapping
                    sProblem = "Nonce mismatch";
                    if (nonce == 0) {
                        // This is most likely a bug in another implementation somewhere; cancel this ping
                        bPingFinished = true;
                        sProblem = "Nonce zero";
                    }
                }
            } else {
                sProblem = "Unsolicited pong without ping";
            }
        } else {
            // This is most likely a bug in another implementation somewhere; cancel this ping
            bPingFinished = true;
            sProblem = "Short payload";
        }

        if (!(sProblem.empty())) {
            LogPrint(BCLog::NET, "pong peer=%d: %s, %x expected, %x received, %u bytes\n",
                pfrom.GetId(),
                sProblem,
                peer->m_ping_nonce_sent,
                nonce,
                nAvail);
        }
        if (bPingFinished) {
            peer->m_ping_nonce_sent = 0;
        }
        return;
    }

    if (msg_type == NetMsgType::FILTERLOAD) {
        if (!(peer->m_our_services & NODE_BLOOM)) {
            LogPrint(BCLog::NET, "filterload received despite not offering bloom services from peer=%d; disconnecting\n", pfrom.GetId());
            pfrom.fDisconnect = true;
            return;
        }
        CBloomFilter filter;
        vRecv >> filter;

        if (!filter.IsWithinSizeConstraints())
        {
            // There is no excuse for sending a too-large filter
            Misbehaving(*peer, 100, "too-large bloom filter");
        } else if (auto tx_relay = peer->GetTxRelay(); tx_relay != nullptr) {
            {
                LOCK(tx_relay->m_bloom_filter_mutex);
                tx_relay->m_bloom_filter.reset(new CBloomFilter(filter));
                tx_relay->m_relay_txs = true;
            }
            pfrom.m_bloom_filter_loaded = true;
            pfrom.m_relays_txs = true;
        }
        return;
    }

    if (msg_type == NetMsgType::FILTERADD) {
        if (!(peer->m_our_services & NODE_BLOOM)) {
            LogPrint(BCLog::NET, "filteradd received despite not offering bloom services from peer=%d; disconnecting\n", pfrom.GetId());
            pfrom.fDisconnect = true;
            return;
        }
        std::vector<unsigned char> vData;
        vRecv >> vData;

        // Nodes must NEVER send a data item > 520 bytes (the max size for a script data object,
        // and thus, the maximum size any matched object can have) in a filteradd message
        bool bad = false;
        if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE) {
            bad = true;
        } else if (auto tx_relay = peer->GetTxRelay(); tx_relay != nullptr) {
            LOCK(tx_relay->m_bloom_filter_mutex);
            if (tx_relay->m_bloom_filter) {
                tx_relay->m_bloom_filter->insert(vData);
            } else {
                bad = true;
            }
        }
        if (bad) {
            Misbehaving(*peer, 100, "bad filteradd message");
        }
        return;
    }

    if (msg_type == NetMsgType::FILTERCLEAR) {
        if (!(peer->m_our_services & NODE_BLOOM)) {
            LogPrint(BCLog::NET, "filterclear received despite not offering bloom services from peer=%d; disconnecting\n", pfrom.GetId());
            pfrom.fDisconnect = true;
            return;
        }
        auto tx_relay = peer->GetTxRelay();
        if (!tx_relay) return;

        {
            LOCK(tx_relay->m_bloom_filter_mutex);
            tx_relay->m_bloom_filter = nullptr;
            tx_relay->m_relay_txs = true;
        }
        pfrom.m_bloom_filter_loaded = false;
        pfrom.m_relays_txs = true;
        return;
    }

    if (msg_type == NetMsgType::FEEFILTER) {
        CAmount newFeeFilter = 0;
        vRecv >> newFeeFilter;
        if (MoneyRange(newFeeFilter)) {
            if (auto tx_relay = peer->GetTxRelay(); tx_relay != nullptr) {
                tx_relay->m_fee_filter_received = newFeeFilter;
            }
            LogPrint(BCLog::NET, "received: feefilter of %d satoshi from peer=%d\n", newFeeFilter, pfrom.GetId());
        }
        return;
    }

    if (msg_type == NetMsgType::GETCFILTERS) {
        ProcessGetCFilters(pfrom, *peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::GETCFHEADERS) {
        ProcessGetCFHeaders(pfrom, *peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::GETCFCHECKPT) {
        ProcessGetCFCheckPt(pfrom, *peer, vRecv);
        return;
    }

    if (msg_type == NetMsgType::NOTFOUND) {
        std::vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() <= MAX_PEER_TX_ANNOUNCEMENTS + MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
            LOCK(::cs_main);
            for (CInv &inv : vInv) {
                if (inv.IsGenTxMsg()) {
                    // If we receive a NOTFOUND message for a tx we requested, mark the announcement for it as
                    // completed in TxRequestTracker.
                    m_txrequest.ReceivedResponse(pfrom.GetId(), inv.hash);
                }
            }
        }
        return;
    }
    // Ignore unknown commands for extensibility
    LogPrint(BCLog::NET, "Unknown command \"%s\" from peer=%d\n", SanitizeString(msg_type), pfrom.GetId());
    return;
}

bool PeerManagerImpl::ProcessMessages(CNode* pfrom, std::atomic<bool>& interruptMsgProc)
{
    AssertLockHeld(g_msgproc_mutex);

    PeerRef peer = GetPeerRef(pfrom->GetId());
    if (peer == nullptr) return false;

    {
        LOCK(peer->m_getdata_requests_mutex);
        if (!peer->m_getdata_requests.empty()) {
            ProcessGetData(*pfrom, *peer, interruptMsgProc);
        }
    }

    const bool processed_orphan = ProcessOrphanTx(*peer);

    if (pfrom->fDisconnect)
        return false;

    if (processed_orphan) return true;

    // this maintains the order of responses
    // and prevents m_getdata_requests to grow unbounded
    {
        LOCK(peer->m_getdata_requests_mutex);
        if (!peer->m_getdata_requests.empty()) return true;
    }

    // Don't bother if send buffer is too full to respond anyway
    if (pfrom->fPauseSend) return false;

    auto poll_result{pfrom->PollMessage()};
    if (!poll_result) {
        // No message to process
        return false;
    }

    CNetMessage& msg{poll_result->first};
    bool fMoreWork = poll_result->second;

    if (gArgs.GetBoolArg("-capturemessages", false)) {
        CaptureMessage(pfrom->addr, msg.m_type, MakeUCharSpan(msg.m_recv), /*is_incoming=*/true);
    }

    msg.SetVersion(pfrom->GetCommonVersion());

    try {
        ProcessMessage(*pfrom, msg.m_type, msg.m_recv, msg.m_time, interruptMsgProc);
        if (interruptMsgProc) return false;
        {
            LOCK(peer->m_getdata_requests_mutex);
            if (!peer->m_getdata_requests.empty()) fMoreWork = true;
        }
        // Does this peer has an orphan ready to reconsider?
        // (Note: we may have provided a parent for an orphan provided
        //  by another peer that was already processed; in that case,
        //  the extra work may not be noticed, possibly resulting in an
        //  unnecessary 100ms delay)
        if (m_orphanage.HaveTxToReconsider(peer->m_id)) fMoreWork = true;
    } catch (const std::exception& e) {
        LogPrint(BCLog::NET, "%s(%s, %u bytes): Exception '%s' (%s) caught\n", __func__, SanitizeString(msg.m_type), msg.m_message_size, e.what(), typeid(e).name());
    } catch (...) {
        LogPrint(BCLog::NET, "%s(%s, %u bytes): Unknown exception caught\n", __func__, SanitizeString(msg.m_type), msg.m_message_size);
    }

    return fMoreWork;
}
