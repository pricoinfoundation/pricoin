// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pricoin_broadcasted_kis.h>

#include <logging.h>
#include <sync.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <map>
#include <mutex>

namespace wallet::pricoin_broadcasted_kis {

namespace {

// Per-wallet cache. Keyed by CWallet pointer because individual
// wallets have independent keyimage sets. Lock order: g_mutex
// around the cache; per-wallet WalletBatch handles its own locking.
Mutex g_mutex;
std::map<::wallet::CWallet*,
         std::map<std::array<unsigned char, 33>, uint256>>
    g_cache GUARDED_BY(g_mutex);
std::set<::wallet::CWallet*> g_loaded GUARDED_BY(g_mutex);

std::map<std::array<unsigned char, 33>, uint256>& EnsureLoadedLocked(
    ::wallet::CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    auto& entry = g_cache[&wallet];
    if (g_loaded.contains(&wallet)) return entry;
    g_loaded.insert(&wallet);
    std::map<std::array<unsigned char, 33>, uint256> loaded;
    {
        WalletBatch batch(wallet.GetDatabase());
        if (!batch.ReadAllPricoinBroadcastedKis(loaded)) {
            LogInfo("Pricoin broadcasted-KI store: lazy-load read failed\n");
            return entry;
        }
    }
    entry = std::move(loaded);
    LogInfo("Pricoin broadcasted-KI store: lazy-loaded %u entries\n",
            (unsigned)entry.size());
    return entry;
}

}  // namespace

bool LoadFromDB(::wallet::CWallet& wallet)
{
    LOCK(g_mutex);
    EnsureLoadedLocked(wallet);
    return true;
}

bool Add(::wallet::CWallet& wallet,
          const std::array<unsigned char, 33>& key_image,
          const uint256& txid)
{
    {
        LOCK(g_mutex);
        auto& s = EnsureLoadedLocked(wallet);
        auto existing = s.find(key_image);
        if (existing != s.end() && existing->second == txid) {
            return true;
        }
        s[key_image] = txid;
    }
    WalletBatch batch(wallet.GetDatabase());
    if (!batch.WritePricoinBroadcastedKi(key_image, txid)) {
        LOCK(g_mutex);
        g_cache[&wallet].erase(key_image);
        return false;
    }
    return true;
}

std::optional<uint256> Lookup(::wallet::CWallet& wallet,
                                const std::array<unsigned char, 33>& key_image)
{
    LOCK(g_mutex);
    const auto& s = EnsureLoadedLocked(wallet);
    auto it = s.find(key_image);
    if (it == s.end()) return std::nullopt;
    return it->second;
}

}  // namespace wallet::pricoin_broadcasted_kis
