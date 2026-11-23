// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_processing/peer_manager_impl.h>
#include <net_processing/constants.h>

void PeerManagerImpl::PushNodeVersion(CNode& pnode, const Peer& peer)
{
    uint64_t my_services{peer.m_our_services};
    const int64_t nTime{count_seconds(GetTime<std::chrono::seconds>())};
    uint64_t nonce = pnode.GetLocalNonce();
    const int nNodeStartingHeight{m_best_height};
    NodeId nodeid = pnode.GetId();
    CAddress addr = pnode.addr;

    CService addr_you = addr.IsRoutable() && !IsProxy(addr) && addr.IsAddrV1Compatible() ? addr : CService();
    uint64_t your_services{addr.nServices};

    const bool tx_relay{!RejectIncomingTxs(pnode)};
    m_connman.PushMessage(&pnode, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERSION, PROTOCOL_VERSION, my_services, nTime,
            your_services, addr_you, // Together the pre-version-31402 serialization of CAddress "addrYou" (without nTime)
            my_services, CService(), // Together the pre-version-31402 serialization of CAddress "addrMe" (without nTime)
            nonce, strSubVersion, nNodeStartingHeight, tx_relay));

    if (fLogIPs) {
        LogPrint(BCLog::NET, "send version message: version %d, blocks=%d, them=%s, txrelay=%d, peer=%d\n", PROTOCOL_VERSION, nNodeStartingHeight, addr_you.ToStringAddrPort(), tx_relay, nodeid);
    } else {
        LogPrint(BCLog::NET, "send version message: version %d, blocks=%d, txrelay=%d, peer=%d\n", PROTOCOL_VERSION, nNodeStartingHeight, tx_relay, nodeid);
    }
}
