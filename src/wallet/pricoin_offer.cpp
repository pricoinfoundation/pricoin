// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pricoin_offer.h>

#include <crypto/hmac_sha256.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <key.h>
#include <logging.h>
#include <random.h>
#include <streams.h>
#include <sync.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <wallet/pricoin_stealth.h>
#include <wallet/pricoin_swap_session.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <memory>
#include <stdexcept>

namespace wallet::pricoin_offer {

constexpr const char* kUriScheme = "pricoffer:v1/";

// ─────────────────────────────────────────────────────────────────
// URI codec
// ─────────────────────────────────────────────────────────────────

namespace {

std::vector<unsigned char> SerializePayload(const OfferPayload& p)
{
    DataStream ds;
    ds << p;
    return std::vector<unsigned char>(UCharCast(ds.data()),
                                       UCharCast(ds.data()) + ds.size());
}

std::optional<OfferPayload> DeserializePayload(std::span<const unsigned char> bytes)
{
    DataStream ds{bytes};
    OfferPayload p;
    try {
        ds >> p;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    return p;
}

} // namespace

std::string EncodeUri(const OfferPayload& p)
{
    auto bytes = SerializePayload(p);
    return std::string(kUriScheme) + EncodeBase64(bytes);
}

std::optional<OfferPayload> DecodeUri(const std::string& uri)
{
    const std::string scheme(kUriScheme);
    if (uri.size() <= scheme.size()) return std::nullopt;
    if (uri.compare(0, scheme.size(), scheme) != 0) return std::nullopt;
    const std::string body = uri.substr(scheme.size());
    auto bytes = DecodeBase64(body);
    if (!bytes) return std::nullopt;
    return DeserializePayload(*bytes);
}

// ─────────────────────────────────────────────────────────────────
// Signing & verification
// ─────────────────────────────────────────────────────────────────

uint256 SigningHash(const OfferPayload& p)
{
    // Hash all fields EXCEPT the signature. Recompute the payload bytes
    // with an empty signature, then SHA256d.
    OfferPayload tmp = p;
    tmp.signature.clear();
    auto bytes = SerializePayload(tmp);
    HashWriter hw;
    static constexpr char kTag[] = "pricoin/offer-v1";
    hw.write(MakeByteSpan(kTag).first(sizeof(kTag) - 1));
    hw.write(MakeByteSpan(bytes));
    return hw.GetHash();
}

bool SignPayload(OfferPayload& payload, const CKey& priv)
{
    if (!priv.IsValid()) return false;
    payload.maker_pubkey = priv.GetPubKey();
    payload.signature.clear();
    const uint256 h = SigningHash(payload);
    return priv.Sign(h, payload.signature);
}

bool VerifySignedPayload(const OfferPayload& p)
{
    if (!p.maker_pubkey.IsValid() || !p.maker_pubkey.IsCompressed()) return false;
    if (p.signature.empty()) return false;
    const uint256 h = SigningHash(p);
    return p.maker_pubkey.Verify(h, p.signature);
}

// ─────────────────────────────────────────────────────────────────
// Matching logic
// ─────────────────────────────────────────────────────────────────

std::optional<int64_t> ProRateForeign(
    int64_t pric_amount_sat,
    int64_t ask_max_pric_sat,
    int64_t ask_foreign_at_max_sat)
{
    if (pric_amount_sat < 0 || ask_max_pric_sat <= 0 || ask_foreign_at_max_sat < 0) {
        return std::nullopt;
    }
    if (pric_amount_sat > ask_max_pric_sat) return std::nullopt;
    // Use __int128 for the intermediate to avoid 64-bit overflow.
    __int128 prod = static_cast<__int128>(pric_amount_sat) *
                    static_cast<__int128>(ask_foreign_at_max_sat);
    __int128 result = prod / ask_max_pric_sat;
    if (result > static_cast<__int128>(std::numeric_limits<int64_t>::max())) {
        return std::nullopt;
    }
    return static_cast<int64_t>(result);
}

namespace {

bool IsTradeable(const Order& o, int64_t now)
{
    if (o.status != Status::Active) return false;
    if (o.pric_remaining_sat <= 0) return false;
    if (o.payload.expiry_unix_sec > 0 && o.payload.expiry_unix_sec <= now) return false;
    return true;
}

// rate = foreign_at_max / max_pric. Compare two rates without floats:
//   a >= b  ⇔  a_foreign * b_pric >= b_foreign * a_pric
bool BidRateAtLeastAskRate(const Order& bid, const Order& ask)
{
    __int128 lhs = static_cast<__int128>(bid.payload.foreign_amount_at_max_sat) *
                   static_cast<__int128>(ask.payload.max_pric_amount_sat);
    __int128 rhs = static_cast<__int128>(ask.payload.foreign_amount_at_max_sat) *
                   static_cast<__int128>(bid.payload.max_pric_amount_sat);
    return lhs >= rhs;
}

} // namespace

std::optional<MatchProposal> EvaluateMatch(
    const Order& mine, const Order& theirs,
    int64_t actual_pric_amount_sat, int64_t now_unix_sec)
{
    if (!IsTradeable(mine, now_unix_sec) || !IsTradeable(theirs, now_unix_sec)) {
        return std::nullopt;
    }
    if (mine.payload.foreign_chain != theirs.payload.foreign_chain) return std::nullopt;
    if (mine.payload.side == theirs.payload.side) return std::nullopt;
    if (actual_pric_amount_sat <= 0) return std::nullopt;
    if (actual_pric_amount_sat > mine.pric_remaining_sat) return std::nullopt;
    if (actual_pric_amount_sat > theirs.pric_remaining_sat) return std::nullopt;

    // Identify bid (BuyPric) and ask (SellPric).
    const Order& bid = (mine.payload.side == Side::BuyPric) ? mine : theirs;
    const Order& ask = (mine.payload.side == Side::SellPric) ? mine : theirs;

    if (!BidRateAtLeastAskRate(bid, ask)) return std::nullopt;

    auto foreign_opt = ProRateForeign(
        actual_pric_amount_sat,
        ask.payload.max_pric_amount_sat,
        ask.payload.foreign_amount_at_max_sat);
    if (!foreign_opt) return std::nullopt;

    MatchProposal mp;
    mp.actual_pric_amount_sat = actual_pric_amount_sat;
    mp.actual_foreign_amount_sat = *foreign_opt;
    mp.bid_is_us = (mine.payload.side == Side::BuyPric);
    return mp;
}

// ─────────────────────────────────────────────────────────────────
// Persistence
// ─────────────────────────────────────────────────────────────────

namespace {

struct WalletCache {
    std::map<uint256, Order> by_id;
    bool loaded{false};
};

Mutex g_mutex;

// Re-derive the maker priv that backs an order's signature. Mirrors
// the HMAC chain swap_session::GetSwapIdentityPubkey uses. Returns
// false if the wallet's stealth identity is unavailable or no valid
// scalar is found in the 16-counter search window (cryptographically
// implausible). Pulled out of `Create` so `RepublishUri` can re-sign
// without duplicating the derivation.
bool DeriveMakerPriv(const ::wallet::pricoin_stealth::Identity& id,
                      CKey& out)
{
    if (!id.spend.IsValid()) return false;
    constexpr const char* kTag = "pricoin/swap/identity-v1";
    uint8_t counter = 0;
    while (counter < 16) {
        CHMAC_SHA256 hmac(UCharCast(id.spend.data()), 32);
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

bool WriteOrderToDB(CWallet& wallet, const Order& o)
{
    DataStream ds;
    ds << o;
    std::vector<unsigned char> blob(
        UCharCast(ds.data()), UCharCast(ds.data()) + ds.size());
    std::vector<unsigned char> enc;
    if (!::wallet::pricoin_stealth::EncryptWalletBlob(wallet, blob, enc)) return false;
    WalletBatch batch(wallet.GetDatabase());
    return batch.WritePricoinOffer(o.payload.order_id, enc);
}

bool LoadFromDBLocked(CWallet& wallet, WalletCache& cache)
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    std::map<uint256, std::vector<unsigned char>> blobs;
    {
        WalletBatch batch(wallet.GetDatabase());
        if (!batch.ReadAllPricoinOffers(blobs)) return false;
    }
    int dropped = 0;
    for (auto& [oid, blob] : blobs) {
        std::vector<unsigned char> plain;
        if (!::wallet::pricoin_stealth::DecryptWalletBlob(wallet, blob, plain)) return false;
        DataStream ds{std::span<const unsigned char>{plain}};
        Order o;
        try {
            ds >> o;
        } catch (const std::exception&) {
            // Tail-truncated record: rewind and parse without the
            // appended fields (linked_swap_id and any future addition).
            // The serialized layout up to and including `updated_time`
            // is stable; pre-format records lack the bytes after it.
            // Treat as a pre-format record and decode best-effort: the
            // partial parse may have advanced — discard and use the
            // default-constructed `o` to consume the original blob
            // again, this time tolerating a short read by catching at
            // each field. Simpler heuristic: attempt a manual parse
            // matching the pre-2026-05-16 layout, then keep the
            // resulting `o` with `linked_swap_id` defaulted to null.
            ds = DataStream{std::span<const unsigned char>{plain}};
            o = Order{};
            try {
                ds >> o.payload;
                uint8_t origin_byte = 0;
                ds >> origin_byte;
                o.origin = static_cast<Origin>(origin_byte);
                uint8_t status_byte = 0;
                ds >> status_byte;
                o.status = static_cast<Status>(status_byte);
                ds >> o.pric_remaining_sat;
                ds >> o.pric_in_flight_sat;
                ds >> o.matched_with_order_id;
                ds >> o.notes;
                ds >> o.created_time;
                ds >> o.updated_time;
                // linked_swap_id stays default (null) for old records.
            } catch (const std::exception&) {
                ++dropped;
                continue;
            }
        }
        if (o.payload.order_id != oid) {
            ++dropped;
            continue;
        }
        cache.by_id[oid] = std::move(o);
    }
    if (dropped > 0) {
        LogInfo("Pricoin offer cache: dropped %d unparseable record(s) "
                "(likely older serialization layout); %d valid loaded\n",
                dropped, (int)cache.by_id.size());
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

int64_t NowSec() { return GetTime<std::chrono::seconds>().count(); }

void SweepExpiredLocked(WalletCache& cache, CWallet& wallet, int64_t now)
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    for (auto& [_, o] : cache.by_id) {
        if (o.status != Status::Active) continue;
        if (o.payload.expiry_unix_sec <= 0) continue;
        if (o.payload.expiry_unix_sec > now) continue;
        o.status = Status::Expired;
        o.updated_time = now;
        // Best-effort persist; if it fails the record stays expired in
        // memory and we'll retry next sweep.
        (void)WriteOrderToDB(wallet, o);
    }
}

} // namespace

CreateResult Create(CWallet& wallet, const CreateParams& params, Order& out)
{
    if (params.max_pric_amount_sat <= 0) return CreateResult::InvalidInput;
    if (params.foreign_amount_at_max_sat <= 0) return CreateResult::InvalidInput;
    if (params.expiry_unix_sec <= 0) return CreateResult::InvalidInput;
    if (!RequireUnlocked(wallet)) return CreateResult::Locked;

    // Derive the maker priv from the wallet's swap-identity key.
    auto pub_opt = ::wallet::pricoin_swap_session::GetSwapIdentityPubkey(wallet);
    if (!pub_opt) return CreateResult::DerivationFailed;
    // Sign via a freshly-derived priv. We can't easily get the raw
    // CKey from the swap-session module — so we re-derive via the
    // same path as that module uses, exposed via Sign helper there.
    // For simplicity (and to match the swap_session API), we sign by
    // calling the swap_session module's Sign helper… but that helper
    // signs an arbitrary payload, not an offer. We instead derive
    // the priv directly here by replicating the swap-identity HMAC.
    // (The swap_session module exposes only pubkey + Sign; we need
    // the raw priv for ECDSA-Sign on our SigningHash.)
    //
    // Cleanest path: extend swap_session with a Sign-with-identity
    // helper. For now, mirror the derivation: HMAC-SHA256 over the
    // stealth spend priv with the swap-identity tag. This duplicates
    // a few lines but avoids reshaping the swap_session public API.
    const auto& id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
    if (!id.spend.IsValid()) return CreateResult::DerivationFailed;

    // Re-derive the same key as swap_session::GetSwapIdentityPubkey.
    CKey maker_priv;
    if (!DeriveMakerPriv(id, maker_priv)) return CreateResult::DerivationFailed;

    Order o;
    o.payload.version = 1;
    GetStrongRandBytes(o.payload.order_id);
    o.payload.side = params.side;
    o.payload.foreign_chain = params.foreign_chain;
    o.payload.max_pric_amount_sat = params.max_pric_amount_sat;
    o.payload.foreign_amount_at_max_sat = params.foreign_amount_at_max_sat;
    o.payload.expiry_unix_sec = params.expiry_unix_sec;

    if (!SignPayload(o.payload, maker_priv)) return CreateResult::DerivationFailed;
    // Sanity: signature must verify against the freshly-derived pubkey.
    if (!VerifySignedPayload(o.payload)) return CreateResult::DerivationFailed;

    o.origin = Origin::Local;
    o.status = Status::Active;
    o.pric_remaining_sat = o.payload.max_pric_amount_sat;
    o.pric_in_flight_sat = 0;
    o.notes = params.notes;
    o.created_time = NowSec();
    o.updated_time = o.created_time;

    {
        LOCK(g_mutex);
        auto& cache = EnsureCache(wallet);
        if (!EnsureLoadedLocked(wallet, cache)) return CreateResult::WriteFailed;
        if (!WriteOrderToDB(wallet, o)) return CreateResult::WriteFailed;
        cache.by_id[o.payload.order_id] = o;
    }
    out = std::move(o);
    return CreateResult::Ok;
}

ImportResult Import(CWallet& wallet, const std::string& uri, Order& out)
{
    auto payload = DecodeUri(uri);
    if (!payload) return ImportResult::InvalidUri;
    if (!VerifySignedPayload(*payload)) return ImportResult::InvalidSignature;
    if (payload->max_pric_amount_sat <= 0 ||
        payload->foreign_amount_at_max_sat <= 0 ||
        payload->expiry_unix_sec <= 0) {
        return ImportResult::InvalidUri;
    }
    const int64_t now = NowSec();
    if (payload->expiry_unix_sec <= now) return ImportResult::AlreadyExpired;
    if (!RequireUnlocked(wallet)) return ImportResult::Locked;

    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return ImportResult::WriteFailed;
    if (cache.by_id.contains(payload->order_id)) return ImportResult::Duplicate;

    Order o;
    o.payload = *payload;
    o.origin = Origin::Imported;
    o.status = Status::Active;
    o.pric_remaining_sat = payload->max_pric_amount_sat;
    o.pric_in_flight_sat = 0;
    o.created_time = now;
    o.updated_time = now;

    if (!WriteOrderToDB(wallet, o)) return ImportResult::WriteFailed;
    cache.by_id[o.payload.order_id] = o;
    out = std::move(o);
    return ImportResult::Ok;
}

std::string RepublishUri(CWallet& wallet, const uint256& order_id)
{
    if (!RequireUnlocked(wallet)) return std::string{};
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return std::string{};
    auto it = cache.by_id.find(order_id);
    if (it == cache.by_id.end()) return std::string{};
    const Order& o = it->second;
    if (o.origin != Origin::Local) return std::string{};
    if (o.pric_remaining_sat <= 0) return std::string{};
    // No-op when nothing has changed since publish — the original
    // signature is still authoritative.
    if (o.pric_remaining_sat == o.payload.max_pric_amount_sat) {
        return EncodeUri(o.payload);
    }

    const auto& id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
    CKey maker_priv;
    if (!DeriveMakerPriv(id, maker_priv)) return std::string{};

    // Scale the foreign max to preserve the original rate. Use 128-bit
    // intermediate to avoid overflow on large amounts (any int64 input
    // pair stays within int128 product range).
    OfferPayload p = o.payload;
    p.max_pric_amount_sat = o.pric_remaining_sat;
    {
        const __int128 num =
            static_cast<__int128>(o.payload.foreign_amount_at_max_sat) *
            static_cast<__int128>(o.pric_remaining_sat);
        const __int128 den =
            static_cast<__int128>(o.payload.max_pric_amount_sat);
        if (den <= 0) return std::string{};
        const __int128 q = num / den;
        p.foreign_amount_at_max_sat = static_cast<int64_t>(q);
    }
    if (p.foreign_amount_at_max_sat <= 0) return std::string{};

    if (!SignPayload(p, maker_priv)) return std::string{};
    if (!VerifySignedPayload(p)) return std::string{};
    return EncodeUri(p);
}

MutateResult ApplyImportedUpdate(CWallet& wallet, const std::string& uri)
{
    auto payload = DecodeUri(uri);
    if (!payload) return MutateResult::InvalidInput;
    if (!VerifySignedPayload(*payload)) return MutateResult::InvalidInput;
    if (payload->max_pric_amount_sat <= 0
        || payload->foreign_amount_at_max_sat <= 0) {
        return MutateResult::InvalidInput;
    }
    if (!RequireUnlocked(wallet)) return MutateResult::Locked;

    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return MutateResult::WriteFailed;
    auto it = cache.by_id.find(payload->order_id);
    if (it == cache.by_id.end()) return MutateResult::NotFound;

    Order& o = it->second;
    if (o.origin != Origin::Imported) return MutateResult::InvalidState;
    // Same maker — the update must come from the original author.
    if (o.payload.maker_pubkey != payload->maker_pubkey) {
        return MutateResult::InvalidInput;
    }
    // Same side + chain — peers don't get to flip those mid-life.
    if (o.payload.side != payload->side
        || o.payload.foreign_chain != payload->foreign_chain) {
        return MutateResult::InvalidInput;
    }
    // Same expiry — re-extending an expired offer is a separate
    // operation (would be a new order from the maker's perspective).
    if (o.payload.expiry_unix_sec != payload->expiry_unix_sec) {
        return MutateResult::InvalidInput;
    }
    // Monotonic shrink: peers can only reduce. Equal is a no-op.
    if (payload->max_pric_amount_sat > o.payload.max_pric_amount_sat) {
        return MutateResult::InvalidInput;
    }
    if (payload->max_pric_amount_sat == o.payload.max_pric_amount_sat) {
        return MutateResult::Ok;  // idempotent
    }
    // Terminal-state imports stay as-is. An updated payload to a
    // Cancelled / Expired import is a stale rebroadcast.
    if (o.status == Status::Cancelled
        || o.status == Status::Expired) {
        return MutateResult::InvalidState;
    }

    Order snap = o;
    o.payload = *payload;
    // Clamp remaining + in_flight to the new ceiling.
    if (o.pric_remaining_sat > payload->max_pric_amount_sat) {
        o.pric_remaining_sat = payload->max_pric_amount_sat;
    }
    if (o.pric_in_flight_sat > o.pric_remaining_sat) {
        o.pric_in_flight_sat = o.pric_remaining_sat;
    }
    o.updated_time = NowSec();
    if (!WriteOrderToDB(wallet, o)) {
        o = snap;
        return MutateResult::WriteFailed;
    }
    return MutateResult::Ok;
}

namespace {

template <typename Mutate>
MutateResult MutateAndPersist(
    CWallet& wallet, const uint256& order_id, Mutate mutate)
{
    if (!RequireUnlocked(wallet)) return MutateResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return MutateResult::WriteFailed;
    auto it = cache.by_id.find(order_id);
    if (it == cache.by_id.end()) return MutateResult::NotFound;
    Order snapshot = it->second;
    MutateResult r = mutate(it->second);
    if (r != MutateResult::Ok) {
        it->second = snapshot;
        return r;
    }
    it->second.updated_time = NowSec();
    if (!WriteOrderToDB(wallet, it->second)) {
        it->second = snapshot;
        return MutateResult::WriteFailed;
    }
    return MutateResult::Ok;
}

} // namespace

MutateResult Cancel(CWallet& wallet, const uint256& order_id)
{
    if (!RequireUnlocked(wallet)) return MutateResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return MutateResult::WriteFailed;
    auto it = cache.by_id.find(order_id);
    if (it == cache.by_id.end()) return MutateResult::NotFound;

    Order& target = it->second;
    if (target.status == Status::Cancelled || target.status == Status::Filled
        || target.status == Status::Expired) {
        return MutateResult::InvalidState;
    }
    Order target_snap = target;
    Order* peer = nullptr;
    Order peer_snap;
    if (target.status == Status::Matched && !target.matched_with_order_id.IsNull()) {
        auto pit = cache.by_id.find(target.matched_with_order_id);
        if (pit != cache.by_id.end()) {
            peer = &pit->second;
            peer_snap = *peer;
        }
    }

    target.pric_in_flight_sat = 0;
    target.matched_with_order_id = uint256{};
    target.status = Status::Cancelled;
    target.updated_time = NowSec();
    if (peer && peer->status == Status::Matched) {
        // Cancelling one side breaks the lock — peer goes back to Active
        // with no consumption (cancellation is non-consumptive).
        peer->pric_in_flight_sat = 0;
        peer->matched_with_order_id = uint256{};
        peer->status = Status::Active;
        peer->updated_time = NowSec();
    }

    if (!WriteOrderToDB(wallet, target) ||
        (peer && !WriteOrderToDB(wallet, *peer))) {
        target = target_snap;
        if (peer) *peer = peer_snap;
        return MutateResult::WriteFailed;
    }
    return MutateResult::Ok;
}

MutateResult Match(
    CWallet& wallet,
    const uint256& my_order_id,
    const uint256& their_order_id,
    int64_t actual_pric_amount_sat)
{
    if (my_order_id == their_order_id) return MutateResult::InvalidInput;
    if (actual_pric_amount_sat <= 0) return MutateResult::InvalidInput;
    if (!RequireUnlocked(wallet)) return MutateResult::Locked;

    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return MutateResult::WriteFailed;
    SweepExpiredLocked(cache, wallet, NowSec());

    auto mit = cache.by_id.find(my_order_id);
    auto tit = cache.by_id.find(their_order_id);
    if (mit == cache.by_id.end() || tit == cache.by_id.end()) return MutateResult::NotFound;
    Order m_snap = mit->second;
    Order t_snap = tit->second;

    auto proposal = EvaluateMatch(mit->second, tit->second,
                                   actual_pric_amount_sat, NowSec());
    if (!proposal) return MutateResult::PriceCrossFailed;

    mit->second.status = Status::Matched;
    mit->second.pric_in_flight_sat = actual_pric_amount_sat;
    mit->second.matched_with_order_id = their_order_id;
    mit->second.updated_time = NowSec();

    tit->second.status = Status::Matched;
    tit->second.pric_in_flight_sat = actual_pric_amount_sat;
    tit->second.matched_with_order_id = my_order_id;
    tit->second.updated_time = NowSec();

    if (!WriteOrderToDB(wallet, mit->second) || !WriteOrderToDB(wallet, tit->second)) {
        mit->second = m_snap;
        tit->second = t_snap;
        return MutateResult::WriteFailed;
    }
    return MutateResult::Ok;
}

namespace {

// Helper: apply a closure to a Matched order and (if present) its peer,
// rolling back on DB failure. The closure receives both orders by ref;
// peer may be nullptr if the matched_with target isn't in this wallet.
template <typename Apply>
MutateResult MutateMatchedPair(
    CWallet& wallet, const uint256& order_id, Apply apply)
{
    if (!RequireUnlocked(wallet)) return MutateResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return MutateResult::WriteFailed;
    auto it = cache.by_id.find(order_id);
    if (it == cache.by_id.end()) return MutateResult::NotFound;

    Order& target = it->second;
    if (target.status != Status::Matched) return MutateResult::InvalidState;

    Order target_snap = target;
    Order* peer = nullptr;
    Order peer_snap;
    if (!target.matched_with_order_id.IsNull()) {
        auto pit = cache.by_id.find(target.matched_with_order_id);
        if (pit != cache.by_id.end()) {
            peer = &pit->second;
            peer_snap = *peer;
        }
    }

    MutateResult r = apply(target, peer);
    if (r != MutateResult::Ok) {
        target = target_snap;
        if (peer) *peer = peer_snap;
        return r;
    }
    target.updated_time = NowSec();
    if (peer) peer->updated_time = NowSec();

    if (!WriteOrderToDB(wallet, target) ||
        (peer && !WriteOrderToDB(wallet, *peer))) {
        target = target_snap;
        if (peer) *peer = peer_snap;
        return MutateResult::WriteFailed;
    }
    return MutateResult::Ok;
}

} // namespace

// Dust threshold for post-fill remainder. PRIC v4 CT txs are ~3KB
// with rangeproofs; at typical fee markets a transparent dust amount
// like 546 sats is well under the cost of broadcasting a CT tx, so
// any sub-10000-sat remainder is effectively unspendable as a swap
// leg. Auto-Filled rather than left Active to avoid 0.00000001-PRIC
// remainders surviving as "open orders" in the UI.
//
// Adjustable if needed; chosen conservatively rather than tied to
// the current minrelayfee since per-broadcast economics change.
static constexpr int64_t kOrderDustRemainderSat = 10'000;  // 0.0001 PRIC

MutateResult Fill(CWallet& wallet, const uint256& order_id)
{
    return MutateMatchedPair(wallet, order_id,
        [](Order& target, Order* peer) -> MutateResult {
            if (target.pric_in_flight_sat <= 0) return MutateResult::InvalidState;
            if (target.pric_in_flight_sat > target.pric_remaining_sat) return MutateResult::InvalidState;
            const int64_t consumed = target.pric_in_flight_sat;
            target.pric_remaining_sat -= consumed;
            target.pric_in_flight_sat = 0;
            target.matched_with_order_id = uint256{};
            target.linked_swap_id = uint256{};   // linkage consumed
            target.status = (target.pric_remaining_sat <= kOrderDustRemainderSat)
                ? Status::Filled : Status::Active;
            if (peer && peer->status == Status::Matched) {
                if (peer->pric_in_flight_sat != consumed) {
                    return MutateResult::InvalidState;
                }
                peer->pric_remaining_sat -= consumed;
                peer->pric_in_flight_sat = 0;
                peer->matched_with_order_id = uint256{};
                peer->linked_swap_id = uint256{};   // linkage consumed
                peer->status = (peer->pric_remaining_sat <= kOrderDustRemainderSat)
                    ? Status::Filled : Status::Active;
            }
            return MutateResult::Ok;
        });
}

MutateResult LinkSwap(
    CWallet& wallet, const uint256& order_id, const uint256& swap_id)
{
    if (swap_id.IsNull()) return MutateResult::InvalidInput;
    if (!RequireUnlocked(wallet)) return MutateResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return MutateResult::WriteFailed;
    auto it = cache.by_id.find(order_id);
    if (it == cache.by_id.end()) return MutateResult::NotFound;
    Order& o = it->second;
    if (!o.linked_swap_id.IsNull() && o.linked_swap_id != swap_id) {
        return MutateResult::InvalidState;  // refuse to clobber an existing link
    }
    if (o.linked_swap_id == swap_id) {
        return MutateResult::Ok;            // idempotent
    }
    Order snap = o;
    o.linked_swap_id = swap_id;
    o.updated_time = NowSec();
    if (!WriteOrderToDB(wallet, o)) {
        o = snap;
        return MutateResult::WriteFailed;
    }
    return MutateResult::Ok;
}

MutateResult FillFromLinkedSwap(
    CWallet& wallet, const uint256& order_id, int64_t consumed_sat)
{
    if (consumed_sat <= 0) return MutateResult::InvalidInput;
    if (!RequireUnlocked(wallet)) return MutateResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return MutateResult::WriteFailed;
    auto it = cache.by_id.find(order_id);
    if (it == cache.by_id.end()) return MutateResult::NotFound;
    Order& o = it->second;
    // Terminal states already settled — no-op.
    if (o.status == Status::Filled
        || o.status == Status::Cancelled
        || o.status == Status::Expired) {
        return MutateResult::Ok;
    }
    if (consumed_sat > o.pric_remaining_sat) {
        // Already applied (e.g. the standard Fill path ran first).
        // Treat as idempotent success.
        return MutateResult::Ok;
    }
    Order snap = o;
    o.pric_remaining_sat -= consumed_sat;
    o.pric_in_flight_sat = 0;
    o.matched_with_order_id = uint256{};
    o.linked_swap_id = uint256{};
    o.status = (o.pric_remaining_sat <= kOrderDustRemainderSat)
        ? Status::Filled : Status::Active;
    o.updated_time = NowSec();
    if (!WriteOrderToDB(wallet, o)) {
        o = snap;
        return MutateResult::WriteFailed;
    }
    return MutateResult::Ok;
}

MutateResult Unmatch(CWallet& wallet, const uint256& order_id)
{
    return MutateMatchedPair(wallet, order_id,
        [](Order& target, Order* peer) -> MutateResult {
            target.pric_in_flight_sat = 0;
            target.matched_with_order_id = uint256{};
            target.status = Status::Active;
            if (peer && peer->status == Status::Matched) {
                peer->pric_in_flight_sat = 0;
                peer->matched_with_order_id = uint256{};
                peer->status = Status::Active;
            }
            return MutateResult::Ok;
        });
}

void SweepExpired(CWallet& wallet, int64_t now_unix_sec)
{
    if (!RequireUnlocked(wallet)) return;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return;
    SweepExpiredLocked(cache, wallet, now_unix_sec);
}

LookupResult Get(CWallet& wallet, const uint256& order_id, Order& out)
{
    if (!RequireUnlocked(wallet)) return LookupResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return LookupResult::NotFound;
    SweepExpiredLocked(cache, wallet, NowSec());
    auto it = cache.by_id.find(order_id);
    if (it == cache.by_id.end()) return LookupResult::NotFound;
    out = it->second;
    return LookupResult::Ok;
}

LookupResult List(CWallet& wallet, std::vector<Order>& out)
{
    if (!RequireUnlocked(wallet)) return LookupResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return LookupResult::NotFound;
    SweepExpiredLocked(cache, wallet, NowSec());
    out.clear();
    out.reserve(cache.by_id.size());
    for (const auto& [_, o] : cache.by_id) out.push_back(o);
    return LookupResult::Ok;
}

LookupResult FindMatches(
    CWallet& wallet,
    const uint256& my_order_id,
    std::vector<MatchCandidate>& out)
{
    if (!RequireUnlocked(wallet)) return LookupResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return LookupResult::NotFound;
    const int64_t now = NowSec();
    SweepExpiredLocked(cache, wallet, now);

    auto mit = cache.by_id.find(my_order_id);
    if (mit == cache.by_id.end()) return LookupResult::NotFound;
    const Order& mine = mit->second;
    if (!IsTradeable(mine, now)) {
        out.clear();
        return LookupResult::Ok;
    }

    out.clear();
    for (const auto& [oid, o] : cache.by_id) {
        if (oid == my_order_id) continue;
        if (!IsTradeable(o, now)) continue;
        if (o.payload.foreign_chain != mine.payload.foreign_chain) continue;
        if (o.payload.side == mine.payload.side) continue;
        const int64_t max_actual = std::min(mine.pric_remaining_sat, o.pric_remaining_sat);
        if (max_actual <= 0) continue;
        auto proposal = EvaluateMatch(mine, o, max_actual, now);
        if (!proposal) continue;

        MatchCandidate c;
        c.their_order_id = oid;
        c.their_max_pric_sat = o.payload.max_pric_amount_sat;
        c.their_foreign_at_max_sat = o.payload.foreign_amount_at_max_sat;
        c.max_actual_pric_sat = max_actual;
        // Price advantage: how much my rate "beats" theirs, as
        // foreign-per-PRIC delta * 1000 / mine.pric_max — sign-consistent
        // for sorting (bigger = better for me).
        // For a Bid: better when ask's rate is well below mine.
        // For an Ask: better when bid's rate is well above mine.
        // Both reduce to |mine.rate - their.rate| * sign.
        const Order& bid = (mine.payload.side == Side::BuyPric) ? mine : o;
        const Order& ask = (mine.payload.side == Side::SellPric) ? mine : o;
        __int128 diff = static_cast<__int128>(bid.payload.foreign_amount_at_max_sat) *
                        static_cast<__int128>(ask.payload.max_pric_amount_sat)
                      - static_cast<__int128>(ask.payload.foreign_amount_at_max_sat) *
                        static_cast<__int128>(bid.payload.max_pric_amount_sat);
        // Normalize a touch: scale to an int64-sized "advantage score".
        // The exact value isn't load-bearing; only the ordering is.
        if (diff < 0) diff = -diff;  // shouldn't happen given EvaluateMatch passed
        // Avoid overflow when squeezing into int64 by clamping.
        if (diff > static_cast<__int128>(std::numeric_limits<int64_t>::max())) {
            c.price_advantage_milli = std::numeric_limits<int64_t>::max();
        } else {
            c.price_advantage_milli = static_cast<int64_t>(diff);
        }
        out.push_back(c);
    }
    std::sort(out.begin(), out.end(),
              [](const MatchCandidate& a, const MatchCandidate& b) {
                  return a.price_advantage_milli > b.price_advantage_milli;
              });
    return LookupResult::Ok;
}

LookupResult ExportUri(CWallet& wallet, const uint256& order_id, std::string& uri_out)
{
    Order o;
    auto r = Get(wallet, order_id, o);
    if (r != LookupResult::Ok) return r;
    if (o.origin != Origin::Local) {
        uri_out.clear();
        return LookupResult::Ok;  // imported orders have no exportable URI of ours
    }
    uri_out = EncodeUri(o.payload);
    return LookupResult::Ok;
}

bool LoadFromDB(CWallet& wallet)
{
    if (!RequireUnlocked(wallet)) return true;
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

// ─────────────────────────────────────────────────────────────────
// Self-test (URI codec + matching, no wallet required)
// ─────────────────────────────────────────────────────────────────

namespace {

void Check(bool cond, const char* what)
{
    if (!cond) throw std::runtime_error(std::string("offer self-test failed: ") + what);
}

OfferPayload MakeUnsigned(Side side, ForeignChain chain,
                           int64_t pric_max, int64_t foreign_max, int64_t expiry)
{
    OfferPayload p;
    p.version = 1;
    GetStrongRandBytes(p.order_id);
    p.side = side;
    p.foreign_chain = chain;
    p.max_pric_amount_sat = pric_max;
    p.foreign_amount_at_max_sat = foreign_max;
    p.expiry_unix_sec = expiry;
    return p;
}

Order MakeOrder(Side side, ForeignChain chain,
                int64_t pric_max, int64_t foreign_max, int64_t expiry,
                const CKey& priv)
{
    Order o;
    o.payload = MakeUnsigned(side, chain, pric_max, foreign_max, expiry);
    Check(SignPayload(o.payload, priv), "sign");
    Check(VerifySignedPayload(o.payload), "verify");
    o.origin = Origin::Local;
    o.status = Status::Active;
    o.pric_remaining_sat = pric_max;
    o.pric_in_flight_sat = 0;
    return o;
}

} // namespace

void RunSelfTest()
{
    CKey priv_a; priv_a.MakeNewKey(true);
    CKey priv_b; priv_b.MakeNewKey(true);
    const int64_t now = 1700000000;
    const int64_t expiry = now + 86400;

    // ─── URI codec round-trip ───
    {
        OfferPayload p = MakeUnsigned(Side::SellPric, ForeignChain::Btc,
                                       100'000'000, 50'000'000, expiry);
        Check(SignPayload(p, priv_a), "sign for codec");
        const std::string uri = EncodeUri(p);
        auto rt = DecodeUri(uri);
        Check(rt.has_value(), "decode round-trip");
        Check(*rt == p, "round-trip equal");
        Check(VerifySignedPayload(*rt), "round-trip sig still verifies");

        // Bad scheme rejected.
        Check(!DecodeUri("notpricoffer:abc").has_value(), "bad scheme");
        // Bad base64 rejected.
        Check(!DecodeUri(std::string(kUriScheme) + "***").has_value(), "bad base64");
        // Tampered base64 → either decode fails or signature fails.
        std::string tampered = uri;
        tampered.back() = (tampered.back() == 'A' ? 'B' : 'A');
        auto td = DecodeUri(tampered);
        Check(!td || !VerifySignedPayload(*td), "tamper rejected");
    }

    // ─── ProRate ───
    {
        // 3 PRIC at rate 1 BTC = 3 PRIC → 1 BTC for 3 PRIC partial
        auto r = ProRateForeign(2, 3, 1'000'000);
        Check(r.has_value(), "prorate");
        Check(*r == 666'666, "prorate floor");
        // Edge: pric=0 valid, returns 0
        auto r0 = ProRateForeign(0, 100, 50);
        Check(r0.has_value() && *r0 == 0, "prorate zero pric");
        // Edge: ask_max=0 invalid
        Check(!ProRateForeign(1, 0, 1).has_value(), "prorate divide-by-zero");
    }

    // ─── Match logic ───
    {
        // Bid at 0.6 BTC/PRIC, ask at 0.5 BTC/PRIC, both 100 PRIC max,
        // BTC chain. Price-cross holds; trade at ask's rate.
        Order ask = MakeOrder(Side::SellPric, ForeignChain::Btc,
                               100'000'000, 50'000'000, expiry, priv_a);
        Order bid = MakeOrder(Side::BuyPric, ForeignChain::Btc,
                               100'000'000, 60'000'000, expiry, priv_b);
        // Match for full 100 PRIC. Foreign at ask's rate = 50M sat.
        auto m = EvaluateMatch(bid, ask, 100'000'000, now);
        Check(m.has_value(), "full match");
        Check(m->actual_pric_amount_sat == 100'000'000, "full pric");
        Check(m->actual_foreign_amount_sat == 50'000'000, "full foreign at ask rate");
        Check(m->bid_is_us == true, "bid_is_us when bid is mine");

        // Partial: take 30 PRIC at ask's rate → 30 * 50M / 100M = 15M.
        auto m2 = EvaluateMatch(bid, ask, 30'000'000, now);
        Check(m2.has_value(), "partial");
        Check(m2->actual_foreign_amount_sat == 15'000'000, "partial foreign");

        // Same side → no match.
        Order ask2 = MakeOrder(Side::SellPric, ForeignChain::Btc,
                                50'000'000, 25'000'000, expiry, priv_b);
        Check(!EvaluateMatch(ask, ask2, 1, now).has_value(), "same side rejects");

        // Different chain → no match.
        Order bid_ltc = MakeOrder(Side::BuyPric, ForeignChain::Ltc,
                                   100'000'000, 60'000'000, expiry, priv_b);
        Check(!EvaluateMatch(bid_ltc, ask, 1, now).has_value(), "chain mismatch rejects");

        // Price-cross fails: bid below ask.
        Order bid_low = MakeOrder(Side::BuyPric, ForeignChain::Btc,
                                   100'000'000, 40'000'000, expiry, priv_b);
        Check(!EvaluateMatch(bid_low, ask, 1, now).has_value(), "price-cross fails");

        // Expired order → no match.
        Order ask_old = MakeOrder(Side::SellPric, ForeignChain::Btc,
                                   100'000'000, 50'000'000, now - 1, priv_a);
        Check(!EvaluateMatch(bid, ask_old, 1, now).has_value(), "expired ask");

        // Asking for more than remaining → no match.
        Check(!EvaluateMatch(bid, ask, 200'000'000, now).has_value(),
              "request > remaining");
    }

    // ─── Signature tamper ───
    {
        Order o = MakeOrder(Side::BuyPric, ForeignChain::Btc,
                             1, 1, expiry, priv_a);
        Check(VerifySignedPayload(o.payload), "verify sig pre-tamper");
        Order tampered = o;
        tampered.payload.max_pric_amount_sat += 1;
        Check(!VerifySignedPayload(tampered.payload),
              "tampered payload fails verify");
    }
}

} // namespace wallet::pricoin_offer
