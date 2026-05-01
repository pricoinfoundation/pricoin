// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pricoin_swap_session.h>

#include <crypto/hmac_sha256.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <random.h>
#include <streams.h>
#include <sync.h>
#include <util/time.h>
#include <wallet/pricoin_stealth.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <cstring>
#include <map>
#include <memory>

namespace wallet::pricoin_swap_session {

namespace {

// In-memory cache, keyed on (wallet*, session_id). Sessions are
// loaded lazily on first call per wallet.
struct WalletCache {
    std::map<uint256, SwapSession> by_id;
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

// Forward declaration; defined after EncryptWalletBlob inversion below.
bool LoadFromDBLocked(CWallet& wallet, WalletCache& cache)
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex);

// Lazy-load the cache on first access. Mirrors pricoin_stealth's
// GetOrCreate pattern. Returns false on a corrupt-record load
// failure; the caller should fail the operation with an error.
bool EnsureLoadedLocked(CWallet& wallet, WalletCache& cache)
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    if (cache.loaded) return true;
    if (!LoadFromDBLocked(wallet, cache)) return false;
    cache.loaded = true;
    return true;
}

// Stable per-wallet swap-identity key derivation.
//   key = HMAC-SHA256(stealth_spend_priv, "pricoin/swap/identity-v1" || ctr)
// where ctr is incremented on the (negligible-probability) chance
// the resulting scalar isn't a valid secp256k1 seckey. The same
// pubkey is reused across all of this wallet's swap sessions, so
// it can be safely advertised once in an order book.
bool DeriveSwapIdentityPriv(
    const CKey& spend_priv,
    CKey& out)
{
    if (!spend_priv.IsValid()) return false;
    constexpr const char* kTag = "pricoin/swap/identity-v1";
    uint8_t counter = 0;
    while (counter < 16) {
        CHMAC_SHA256 hmac(UCharCast(spend_priv.data()), 32);
        hmac.Write(reinterpret_cast<const unsigned char*>(kTag), std::strlen(kTag));
        hmac.Write(&counter, 1);
        unsigned char raw[32];
        hmac.Finalize(raw);
        out.Set(raw, raw + 32, /*compressed=*/true);
        if (out.IsValid()) return true;
        ++counter;
    }
    return false;
}

bool RequireUnlocked(CWallet& wallet)
{
    return !(wallet.HasEncryptionKeys() && wallet.IsLocked());
}

// Persist or remove a session record. The wallet's at-rest
// encryption posture is applied via EncryptWalletBlob — same as the
// other Pricoin records (stealth seed, recovery cache).
bool WriteSessionToDB(CWallet& wallet, const SwapSession& s)
{
    DataStream ds;
    ds << s;
    std::vector<unsigned char> blob(
        UCharCast(ds.data()),
        UCharCast(ds.data()) + ds.size());

    std::vector<unsigned char> enc;
    if (!::wallet::pricoin_stealth::EncryptWalletBlob(wallet, blob, enc)) {
        return false;
    }
    WalletBatch batch(wallet.GetDatabase());
    return batch.WritePricoinSwapSession(s.session_id, enc);
}

// Currently unused — kept for the session-deletion API we'll add when
// we wire long-running session pruning. Suppress the warning.
[[maybe_unused]] bool EraseSessionFromDB(CWallet& wallet, const uint256& session_id)
{
    WalletBatch batch(wallet.GetDatabase());
    return batch.ErasePricoinSwapSession(session_id);
}

// Verify ECDSA-DER signature of `payload` against `pub`. Wraps the
// conventional sig-checks-on-payload-hash pattern.
bool VerifyPayloadSig(
    const CPubKey& pub,
    std::span<const unsigned char> payload,
    std::span<const unsigned char> sig)
{
    if (!pub.IsValid()) return false;
    HashWriter h{};
    h.write(MakeByteSpan(payload));
    const uint256 msg = h.GetSHA256();
    return pub.Verify(msg,
        std::vector<unsigned char>{sig.begin(), sig.end()});
}

bool SignPayloadEcdsa(
    const CKey& priv,
    std::span<const unsigned char> payload,
    std::vector<unsigned char>& sig_out)
{
    HashWriter h{};
    h.write(MakeByteSpan(payload));
    const uint256 msg = h.GetSHA256();
    return priv.Sign(msg, sig_out);
}

} // namespace

std::optional<CPubKey> GetSwapIdentityPubkey(CWallet& wallet)
{
    if (!RequireUnlocked(wallet)) return std::nullopt;
    const auto& id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
    if (!id.spend.IsValid()) return std::nullopt;
    CKey priv;
    if (!DeriveSwapIdentityPriv(id.spend, priv)) return std::nullopt;
    return priv.GetPubKey();
}

CreateResult Create(
    CWallet& wallet,
    const CPubKey& counterparty_pub,
    const std::string& memo,
    SwapSession& out)
{
    if (!counterparty_pub.IsValid() || !counterparty_pub.IsCompressed()) {
        return CreateResult::InvalidCounterpartyPubkey;
    }
    if (!RequireUnlocked(wallet)) return CreateResult::Locked;

    const auto& id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
    if (!id.spend.IsValid()) return CreateResult::DerivationFailed;

    // Generate a fresh session id. Retry on the (impossible) all-zero case.
    uint256 sid{};
    for (int i = 0; i < 8; ++i) {
        GetRandBytes(sid);
        if (!sid.IsNull()) break;
    }
    if (sid.IsNull()) return CreateResult::DerivationFailed;

    SwapSession s;
    s.session_id = sid;
    if (!DeriveSwapIdentityPriv(id.spend, s.my_priv)) {
        return CreateResult::DerivationFailed;
    }
    s.my_pub = s.my_priv.GetPubKey();
    s.counterparty_pub = counterparty_pub;
    s.role = Role::Initiator;
    s.state = State::Active;
    const auto now = GetTime<std::chrono::seconds>().count();
    s.created_time = static_cast<int64_t>(now);
    s.updated_time = s.created_time;
    s.memo = memo;

    {
        LOCK(g_mutex);
        auto& cache = EnsureCache(wallet);
        if (!EnsureLoadedLocked(wallet, cache)) return CreateResult::WriteFailed;
        if (!WriteSessionToDB(wallet, s)) return CreateResult::WriteFailed;
        cache.by_id[sid] = s;
    }

    out = std::move(s);
    return CreateResult::Ok;
}

CreateResult Attach(
    CWallet& wallet,
    const uint256& session_id,
    const CPubKey& counterparty_pub,
    const std::string& memo,
    SwapSession& out)
{
    if (!counterparty_pub.IsValid() || !counterparty_pub.IsCompressed()) {
        return CreateResult::InvalidCounterpartyPubkey;
    }
    if (session_id.IsNull()) {
        return CreateResult::DerivationFailed;
    }
    if (!RequireUnlocked(wallet)) return CreateResult::Locked;

    {
        LOCK(g_mutex);
        auto& cache = EnsureCache(wallet);
        if (cache.loaded && cache.by_id.contains(session_id)) {
            return CreateResult::DuplicateSessionId;
        }
    }

    const auto& id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
    if (!id.spend.IsValid()) return CreateResult::DerivationFailed;

    SwapSession s;
    s.session_id = session_id;
    if (!DeriveSwapIdentityPriv(id.spend, s.my_priv)) {
        return CreateResult::DerivationFailed;
    }
    s.my_pub = s.my_priv.GetPubKey();
    s.counterparty_pub = counterparty_pub;
    s.role = Role::Responder;
    s.state = State::Active;
    const auto now = GetTime<std::chrono::seconds>().count();
    s.created_time = static_cast<int64_t>(now);
    s.updated_time = s.created_time;
    s.memo = memo;

    {
        LOCK(g_mutex);
        auto& cache = EnsureCache(wallet);
        if (!EnsureLoadedLocked(wallet, cache)) return CreateResult::WriteFailed;
        if (!WriteSessionToDB(wallet, s)) return CreateResult::WriteFailed;
        cache.by_id[session_id] = s;
    }

    out = std::move(s);
    return CreateResult::Ok;
}

bool Sign(
    CWallet& wallet,
    const uint256& session_id,
    std::span<const unsigned char> payload,
    std::vector<unsigned char>& sig_out)
{
    if (!RequireUnlocked(wallet)) return false;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return false;
    auto it = cache.by_id.find(session_id);
    if (it == cache.by_id.end()) return false;
    return SignPayloadEcdsa(it->second.my_priv, payload, sig_out);
}

bool Verify(
    CWallet& wallet,
    const uint256& session_id,
    std::span<const unsigned char> payload,
    std::span<const unsigned char> sig)
{
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return false;
    auto it = cache.by_id.find(session_id);
    if (it == cache.by_id.end()) return false;
    return VerifyPayloadSig(it->second.counterparty_pub, payload, sig);
}

LookupResult Get(CWallet& wallet, const uint256& session_id, SwapSession& out)
{
    if (!RequireUnlocked(wallet)) return LookupResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return LookupResult::NotFound;
    auto it = cache.by_id.find(session_id);
    if (it == cache.by_id.end()) return LookupResult::NotFound;
    out = it->second;
    return LookupResult::Ok;
}

LookupResult List(CWallet& wallet, std::vector<SwapSession>& out)
{
    if (!RequireUnlocked(wallet)) return LookupResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return LookupResult::NotFound;
    out.clear();
    out.reserve(cache.by_id.size());
    for (const auto& [_, s] : cache.by_id) out.push_back(s);
    return LookupResult::Ok;
}

TransitionResult Complete(
    CWallet& wallet,
    const uint256& session_id,
    const uint256& spend_txid)
{
    if (!RequireUnlocked(wallet)) return TransitionResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return TransitionResult::WriteFailed;
    auto it = cache.by_id.find(session_id);
    if (it == cache.by_id.end()) return TransitionResult::NotFound;
    if (it->second.state != State::Active) return TransitionResult::InvalidState;

    it->second.state = State::Complete;
    it->second.spend_txid = spend_txid;
    it->second.updated_time = static_cast<int64_t>(
        GetTime<std::chrono::seconds>().count());

    if (!WriteSessionToDB(wallet, it->second)) {
        // Roll back the in-memory mutation so the cache stays
        // consistent with the DB.
        it->second.state = State::Active;
        it->second.spend_txid = uint256{};
        return TransitionResult::WriteFailed;
    }
    return TransitionResult::Ok;
}

TransitionResult Abort(
    CWallet& wallet,
    const uint256& session_id,
    std::optional<BlameTicket> blame)
{
    if (!RequireUnlocked(wallet)) return TransitionResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return TransitionResult::WriteFailed;
    auto it = cache.by_id.find(session_id);
    if (it == cache.by_id.end()) return TransitionResult::NotFound;
    if (it->second.state != State::Active) return TransitionResult::InvalidState;

    if (blame) {
        // Blame's signature MUST verify against the counterparty's
        // session pubkey — that's the entire point of identifiable
        // abort. A ticket that doesn't verify is just hearsay.
        if (!VerifyPayloadSig(
                it->second.counterparty_pub,
                std::span<const unsigned char>{blame->payload},
                std::span<const unsigned char>{blame->signature})) {
            return TransitionResult::InvalidBlame;
        }
        it->second.blame = *blame;
    }
    it->second.state = State::Aborted;
    it->second.updated_time = static_cast<int64_t>(
        GetTime<std::chrono::seconds>().count());

    if (!WriteSessionToDB(wallet, it->second)) {
        it->second.state = State::Active;
        it->second.blame = BlameTicket{};
        return TransitionResult::WriteFailed;
    }
    return TransitionResult::Ok;
}

namespace {
bool LoadFromDBLocked(CWallet& wallet, WalletCache& cache)
{
    std::map<uint256, std::vector<unsigned char>> blobs;
    {
        WalletBatch batch(wallet.GetDatabase());
        if (!batch.ReadAllPricoinSwapSessions(blobs)) return false;
    }
    for (auto& [sid, blob] : blobs) {
        std::vector<unsigned char> plain;
        if (!::wallet::pricoin_stealth::DecryptWalletBlob(wallet, blob, plain)) {
            return false;
        }
        DataStream ds{std::span<const unsigned char>{plain}};
        SwapSession s;
        try {
            ds >> s;
        } catch (const std::exception&) {
            return false;
        }
        if (s.session_id != sid) return false;
        cache.by_id[sid] = std::move(s);
    }
    return true;
}
} // namespace

bool LoadFromDB(CWallet& wallet)
{
    if (!RequireUnlocked(wallet)) {
        // Defer until first authenticated call — same posture as
        // pricoin_stealth, which can't decrypt while locked.
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

} // namespace wallet::pricoin_swap_session
