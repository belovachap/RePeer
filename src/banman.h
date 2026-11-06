// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_BANMAN_H
#define BITCOIN_BANMAN_H

#include <addrdb.h>
#include <common/bloom.h>
#include <net_types.h> // For banmap_t
#include <sync.h>
#include <util/fs.h>

#include <chrono>
#include <cstdint>
#include <memory>

static constexpr unsigned int DEFAULT_MISBEHAVING_BANTIME = 60 * 60 * 24; // Default 24-hour ban

/// How often to dump banned addresses/subnets to disk.
static constexpr std::chrono::minutes DUMP_BANS_INTERVAL{15};

class CClientUIInterface;
class CNetAddr;
class CSubNet;

class BanMan
{
public:
    ~BanMan();
    BanMan(fs::path ban_file, CClientUIInterface* client_interface, int64_t default_ban_time);
    void Ban(const CNetAddr& net_addr, int64_t ban_time_offset = 0, bool since_unix_epoch = false);
    void Ban(const CSubNet& sub_net, int64_t ban_time_offset = 0, bool since_unix_epoch = false);
    void Discourage(const CNetAddr& net_addr);
    void ClearBanned();

    //! Return whether net_addr is banned
    bool IsBanned(const CNetAddr& net_addr);

    //! Return whether sub_net is exactly banned
    bool IsBanned(const CSubNet& sub_net);

    //! Return whether net_addr is discouraged.
    bool IsDiscouraged(const CNetAddr& net_addr);

    bool Unban(const CNetAddr& net_addr);
    bool Unban(const CSubNet& sub_net);
    void GetBanned(banmap_t& banmap);
    void DumpBanlist();

private:
    void LoadBanlist() EXCLUSIVE_LOCKS_REQUIRED(!m_cs_banned);
    bool BannedSetIsDirty();
    //!set the "dirty" flag for the banlist
    void SetBannedSetDirty(bool dirty = true);
    //!clean unused entries (if bantime has expired)
    void SweepBanned() EXCLUSIVE_LOCKS_REQUIRED(m_cs_banned);

    RecursiveMutex m_cs_banned;
    banmap_t m_banned GUARDED_BY(m_cs_banned);
    bool m_is_dirty GUARDED_BY(m_cs_banned){false};
    CClientUIInterface* m_client_interface = nullptr;
    CBanDB m_ban_db;
    const int64_t m_default_ban_time;
    CRollingBloomFilter m_discouraged GUARDED_BY(m_cs_banned) {50000, 0.000001};
};

#endif // BITCOIN_BANMAN_H
