// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing/peer_manager_impl.h>
#include <net_processing/constants.h>

/**
 * Whether the peer supports the address.
 */
static bool IsAddrCompatible(const Peer& peer, const CAddress& addr)
{
    return peer.m_wants_addrv2 || addr.IsAddrV1Compatible();
}

void PeerManagerImpl::AddAddressKnown(Peer& peer, const CAddress& addr)
{
    assert(peer.m_addr_known);
    peer.m_addr_known->insert(addr.GetKey());
}

void PeerManagerImpl::PushAddress(Peer& peer, const CAddress& addr, FastRandomContext& insecure_rand)
{
    // Known checking here is only to save space from duplicates.
    // Before sending, we'll filter it again for known addresses that were
    // added after addresses were pushed.
    assert(peer.m_addr_known);
    if (addr.IsValid() && !peer.m_addr_known->contains(addr.GetKey()) && IsAddrCompatible(peer, addr)) {
        if (peer.m_addrs_to_send.size() >= MAX_ADDR_TO_SEND) {
            peer.m_addrs_to_send[insecure_rand.randrange(peer.m_addrs_to_send.size())] = addr;
        } else {
            peer.m_addrs_to_send.push_back(addr);
        }
    }
}

void PeerManagerImpl::RelayAddress(NodeId originator,
                                   const CAddress& addr,
                                   bool fReachable)
{
    // We choose the same nodes within a given 24h window (if the list of connected
    // nodes does not change) and we don't relay to nodes that already know an
    // address. So within 24h we will likely relay a given address once. This is to
    // prevent a peer from unjustly giving their address better propagation by sending
    // it to us repeatedly.

    if (!fReachable && !addr.IsRelayable()) return;

    // Relay to a limited number of other nodes
    // Use deterministic randomness to send to the same nodes for 24 hours
    // at a time so the m_addr_knowns of the chosen nodes prevent repeats
    const uint64_t hash_addr{CServiceHash(0, 0)(addr)};
    const auto current_time{GetTime<std::chrono::seconds>()};
    // Adding address hash makes exact rotation time different per address, while preserving periodicity.
    const uint64_t time_addr{(static_cast<uint64_t>(count_seconds(current_time)) + hash_addr) / count_seconds(ROTATE_ADDR_RELAY_DEST_INTERVAL)};
    const CSipHasher hasher{m_connman.GetDeterministicRandomizer(RANDOMIZER_ID_ADDRESS_RELAY)
                                .Write(hash_addr)
                                .Write(time_addr)};
    FastRandomContext insecure_rand;

    // Relay reachable addresses to 2 peers. Unreachable addresses are relayed randomly to 1 or 2 peers.
    unsigned int nRelayNodes = (fReachable || (hasher.Finalize() & 1)) ? 2 : 1;

    std::array<std::pair<uint64_t, Peer*>, 2> best{{{0, nullptr}, {0, nullptr}}};
    assert(nRelayNodes <= best.size());

    LOCK(m_peer_mutex);

    for (auto& [id, peer] : m_peer_map) {
        if (peer->m_addr_relay_enabled && id != originator && IsAddrCompatible(*peer, addr)) {
            uint64_t hashKey = CSipHasher(hasher).Write(id).Finalize();
            for (unsigned int i = 0; i < nRelayNodes; i++) {
                 if (hashKey > best[i].first) {
                     std::copy(best.begin() + i, best.begin() + nRelayNodes - 1, best.begin() + i + 1);
                     best[i] = std::make_pair(hashKey, peer.get());
                     break;
                 }
            }
        }
    };

    for (unsigned int i = 0; i < nRelayNodes && best[i].first != 0; i++) {
        PushAddress(*best[i].second, addr, insecure_rand);
    }
}

bool PeerManagerImpl::SetupAddressRelay(const CNode& node, Peer& peer)
{
    // We don't participate in addr relay with outbound block-relay-only
    // connections to prevent providing adversaries with the additional
    // information of addr traffic to infer the link.
    if (node.IsBlockOnlyConn()) return false;

    if (!peer.m_addr_relay_enabled.exchange(true)) {
        // During version message processing (non-block-relay-only outbound peers)
        // or on first addr-related message we have received (inbound peers), initialize
        // m_addr_known.
        peer.m_addr_known = std::make_unique<CRollingBloomFilter>(5000, 0.001);
    }

    return true;
}

void PeerManagerImpl::MaybeSendAddr(CNode& node, Peer& peer, std::chrono::microseconds current_time)
{
    // Nothing to do for non-address-relay peers
    if (!peer.m_addr_relay_enabled) return;

    LOCK(peer.m_addr_send_times_mutex);
    // Periodically advertise our local address to the peer.
    if (fListen && !m_chainman.ActiveChainstate().IsInitialBlockDownload() &&
        peer.m_next_local_addr_send < current_time) {
        // If we've sent before, clear the bloom filter for the peer, so that our
        // self-announcement will actually go out.
        // This might be unnecessary if the bloom filter has already rolled
        // over since our last self-announcement, but there is only a small
        // bandwidth cost that we can incur by doing this (which happens
        // once a day on average).
        if (peer.m_next_local_addr_send != 0us) {
            peer.m_addr_known->reset();
        }
        if (std::optional<CService> local_service = GetLocalAddrForPeer(node)) {
            CAddress local_addr{*local_service, peer.m_our_services, Now<NodeSeconds>()};
            FastRandomContext insecure_rand;
            PushAddress(peer, local_addr, insecure_rand);
        }
        peer.m_next_local_addr_send = GetExponentialRand(current_time, AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL);
    }

    // We sent an `addr` message to this peer recently. Nothing more to do.
    if (current_time <= peer.m_next_addr_send) return;

    peer.m_next_addr_send = GetExponentialRand(current_time, AVG_ADDRESS_BROADCAST_INTERVAL);

    if (!Assume(peer.m_addrs_to_send.size() <= MAX_ADDR_TO_SEND)) {
        // Should be impossible since we always check size before adding to
        // m_addrs_to_send. Recover by trimming the vector.
        peer.m_addrs_to_send.resize(MAX_ADDR_TO_SEND);
    }

    // Remove addr records that the peer already knows about, and add new
    // addrs to the m_addr_known filter on the same pass.
    auto addr_already_known = [&peer](const CAddress& addr) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex) {
        bool ret = peer.m_addr_known->contains(addr.GetKey());
        if (!ret) peer.m_addr_known->insert(addr.GetKey());
        return ret;
    };
    peer.m_addrs_to_send.erase(std::remove_if(peer.m_addrs_to_send.begin(), peer.m_addrs_to_send.end(), addr_already_known),
                           peer.m_addrs_to_send.end());

    // No addr messages to send
    if (peer.m_addrs_to_send.empty()) return;

    const char* msg_type;
    int make_flags;
    if (peer.m_wants_addrv2) {
        msg_type = NetMsgType::ADDRV2;
        make_flags = ADDRV2_FORMAT;
    } else {
        msg_type = NetMsgType::ADDR;
        make_flags = 0;
    }
    m_connman.PushMessage(&node, CNetMsgMaker(node.GetCommonVersion()).Make(make_flags, msg_type, peer.m_addrs_to_send));
    peer.m_addrs_to_send.clear();

    // we only send the big addr message once
    if (peer.m_addrs_to_send.capacity() > 40) {
        peer.m_addrs_to_send.shrink_to_fit();
    }
}
