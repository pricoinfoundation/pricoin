// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pricoin_clsag_nonce_records.h>

#include <pricoin/clsag_nonce_policy.h>
#include <streams.h>
#include <sync.h>
#include <util/time.h>
#include <wallet/pricoin_stealth.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <map>
#include <memory>

namespace wallet::pricoin_clsag_nonce_records {

namespace policy = ::pricoin::clsag_nonce_policy;

namespace {

struct WalletCache {
    policy::Store store;
    bool loaded{false};
};

Mutex g_mutex;
std::map<CWallet*, std::unique_ptr<WalletCache>> g_caches GUARDED_BY(g_mutex);

WalletCache& EnsureCache(CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    auto it = g_caches.find(&wallet);
    if (it == g_caches.end()) {
        it = g_caches.emplace(&wallet, std::make_unique<WalletCache>()).first;
    }
    return *it->second;
}

bool RequireUnlocked(CWallet& wallet)
{
    return !(wallet.HasEncryptionKeys() && wallet.IsLocked());
}

bool LoadFromDBLocked(CWallet& wallet, WalletCache& cache)
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    std::map<uint256, std::vector<unsigned char>> blobs;
    {
        WalletBatch batch(wallet.GetDatabase());
        if (!batch.ReadAllPricoinClsagNonces(blobs)) return false;
    }
    for (auto& [digest, blob] : blobs) {
        std::vector<unsigned char> plain;
        if (!::wallet::pricoin_stealth::DecryptWalletBlob(wallet, blob, plain)) {
            return false;
        }
        DataStream ds{std::span<const unsigned char>{plain}};
        policy::NonceRecord rec;
        try {
            ds >> rec;
        } catch (const std::exception&) {
            return false;
        }
        // Recompute the digest from the loaded record's key and check it
        // matches the DB row key. Defense against quietly-corrupt or
        // copy-pasted records.
        if (policy::RecordDigest(rec.key) != digest) return false;
        cache.store.Replay(std::move(rec));
    }
    return true;
}

bool EnsureLoadedLocked(CWallet& wallet, WalletCache& cache)
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    if (cache.loaded) return true;
    if (!LoadFromDBLocked(wallet, cache)) return false;
    cache.loaded = true;
    return true;
}

bool WriteRecordToDB(CWallet& wallet, const policy::NonceRecord& rec)
{
    DataStream ds;
    ds << rec;
    std::vector<unsigned char> plain(
        UCharCast(ds.data()),
        UCharCast(ds.data()) + ds.size());

    std::vector<unsigned char> enc;
    if (!::wallet::pricoin_stealth::EncryptWalletBlob(wallet, plain, enc)) {
        return false;
    }
    WalletBatch batch(wallet.GetDatabase());
    return batch.WritePricoinClsagNonce(policy::RecordDigest(rec.key), enc);
}

} // namespace

BeginResult Begin(
    CWallet& wallet,
    const RecordKey& key,
    const uint256& session_id,
    const policy::Scalar& alpha,
    const uint256& commitment,
    NonceRecord& out)
{
    if (key.joint_output_id.empty() || session_id.IsNull()) {
        return BeginResult::InvalidInput;
    }
    if (!RequireUnlocked(wallet)) return BeginResult::Locked;

    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return BeginResult::WriteFailed;

    NonceRecord rec;
    rec.key = key;
    rec.session_id = session_id;
    rec.alpha = alpha;
    rec.commitment = commitment;
    rec.t_published = false;
    const int64_t now = GetTime<std::chrono::seconds>().count();
    rec.created_time = now;
    rec.updated_time = now;

    // Snapshot the prior record (if any) so we can roll back the
    // in-memory mutation if the DB write fails.
    const NonceRecord* existing = cache.store.Get(rec.key);
    std::optional<NonceRecord> prior =
        existing ? std::optional<NonceRecord>{*existing} : std::nullopt;

    policy::Decision d = cache.store.TryCreate(rec);
    switch (d) {
    case policy::Decision::Ok:
        break;
    case policy::Decision::ConflictDifferentSession:
        return BeginResult::ConflictDifferentSession;
    case policy::Decision::ConflictSameSessionInFlight:
        return BeginResult::ConflictSameSessionInFlight;
    }

    if (!WriteRecordToDB(wallet, rec)) {
        // Roll back the in-memory store to keep it consistent with disk.
        if (prior) {
            cache.store.Replay(*prior);
        } else {
            cache.store.Erase(rec.key);
        }
        return BeginResult::WriteFailed;
    }
    out = rec;
    return BeginResult::Ok;
}

MutateResult MarkTPublished(CWallet& wallet, const RecordKey& key)
{
    if (!RequireUnlocked(wallet)) return MutateResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return MutateResult::WriteFailed;

    const NonceRecord* existing = cache.store.Get(key);
    if (!existing) return MutateResult::NotFound;
    NonceRecord prior = *existing;

    if (!cache.store.MarkTPublished(key)) return MutateResult::NotFound;
    const NonceRecord* updated = cache.store.Get(key);
    if (!updated || !WriteRecordToDB(wallet, *updated)) {
        cache.store.Replay(prior);
        return MutateResult::WriteFailed;
    }
    return MutateResult::Ok;
}

MutateResult Erase(CWallet& wallet, const RecordKey& key)
{
    if (!RequireUnlocked(wallet)) return MutateResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return MutateResult::WriteFailed;

    const NonceRecord* existing = cache.store.Get(key);
    if (!existing) return MutateResult::NotFound;

    WalletBatch batch(wallet.GetDatabase());
    if (!batch.ErasePricoinClsagNonce(policy::RecordDigest(key))) {
        return MutateResult::WriteFailed;
    }
    cache.store.Erase(key);
    return MutateResult::Ok;
}

LookupResult Get(CWallet& wallet, const RecordKey& key, NonceRecord& out)
{
    if (!RequireUnlocked(wallet)) return LookupResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return LookupResult::NotFound;
    const NonceRecord* rec = cache.store.Get(key);
    if (!rec) return LookupResult::NotFound;
    out = *rec;
    return LookupResult::Ok;
}

LookupResult List(CWallet& wallet, std::vector<NonceRecord>& out)
{
    if (!RequireUnlocked(wallet)) return LookupResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return LookupResult::NotFound;
    out.clear();
    cache.store.ForEach([&](const NonceRecord& rec) { out.push_back(rec); });
    return LookupResult::Ok;
}

bool LoadFromDB(CWallet& wallet)
{
    if (!RequireUnlocked(wallet)) {
        // Defer until first authenticated access.
        return true;
    }
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (cache.loaded) return true;
    if (!LoadFromDBLocked(wallet, cache)) return false;
    cache.loaded = true;
    return true;
}

void Shutdown()
{
    LOCK(g_mutex);
    g_caches.clear();
}

} // namespace wallet::pricoin_clsag_nonce_records
