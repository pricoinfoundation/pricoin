// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pricoin_adaptor_swap.h>

#include <random.h>
#include <streams.h>
#include <swap/refund.h>
#include <sync.h>
#include <util/time.h>
#include <wallet/pricoin_stealth.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <cstring>
#include <map>
#include <memory>

namespace wallet::pricoin_adaptor_swap {

namespace {

struct WalletCache {
    std::map<uint256, AdaptorSwap> by_id;
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
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex);

bool EnsureLoadedLocked(CWallet& wallet, WalletCache& cache)
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    if (cache.loaded) return true;
    if (!LoadFromDBLocked(wallet, cache)) return false;
    cache.loaded = true;
    return true;
}

bool WriteToDB(CWallet& wallet, const AdaptorSwap& s)
{
    DataStream ds;
    ds << s;
    std::vector<unsigned char> blob(
        UCharCast(ds.data()), UCharCast(ds.data()) + ds.size());

    std::vector<unsigned char> enc;
    if (!::wallet::pricoin_stealth::EncryptWalletBlob(wallet, blob, enc)) {
        return false;
    }
    WalletBatch batch(wallet.GetDatabase());
    return batch.WritePricoinAdaptorSwap(s.swap_id, enc);
}

bool LoadFromDBLocked(CWallet& wallet, WalletCache& cache)
{
    std::map<uint256, std::vector<unsigned char>> blobs;
    {
        WalletBatch batch(wallet.GetDatabase());
        if (!batch.ReadAllPricoinAdaptorSwaps(blobs)) return false;
    }
    int dropped = 0;
    for (auto& [sid, blob] : blobs) {
        std::vector<unsigned char> plain;
        if (!::wallet::pricoin_stealth::DecryptWalletBlob(wallet, blob, plain)) {
            // Wallet locked, MAC mismatch, or wrong-key. The latter
            // shouldn't happen on a non-tampered wallet; the former
            // (locked) just means we can't see swap state right now,
            // and we should fail the whole load so the caller can
            // retry once unlocked. So return false here, NOT skip.
            return false;
        }
        DataStream ds{std::span<const unsigned char>{plain}};
        AdaptorSwap s;
        try {
            ds >> s;
        } catch (const std::exception&) {
            // Pre-format record (older serialization layout) — the
            // appended-field convention means new code can fail to
            // deserialize an old record. Skip it instead of failing
            // the entire cache load: stale records (typically aborted
            // from prior test sessions) shouldn't block creation of
            // new swaps. The user can purge them via a wallet sweep
            // if they want a clean state.
            ++dropped;
            continue;
        }
        if (s.swap_id != sid) {
            // Sid mismatch is a corruption indicator — drop, don't fail.
            ++dropped;
            continue;
        }
        cache.by_id[sid] = std::move(s);
    }
    if (dropped > 0) {
        LogInfo("Pricoin adaptor_swap: dropped %d stale/unparseable record(s) "
                "during cache load (likely from older serialization layout); "
                "%d valid record(s) loaded\n",
                dropped, (int)cache.by_id.size());
    }
    return true;
}

bool ValidForeignChain(const std::string& chain)
{
    // Conservative whitelist for now. The chainwatch backend has a
    // larger registry; for swap creation we only care about chains
    // we can actually drive end-to-end in this commit's scope.
    return chain == "btc" || chain == "ltc" || chain == "regtest";
}

bool ValidJointStealthAddr(const std::string& addr)
{
    // Minimal sanity check — we don't decode the address here (the
    // existing pricoin_buildjointstealthaddress RPC produces it; the
    // check is whether the field is present in the right shape).
    return addr.size() >= 16 && addr.size() <= 256;
}

int64_t NowSec()
{
    return GetTime<std::chrono::seconds>().count();
}

bool RecomputeAdaptorReady(AdaptorSwap& s)
{
    // Setup → AdaptorReady gate: both adaptor materials AND timelocks
    // must be set, AND the timelocks must validate against the spec.
    if (s.state != State::Setup) return false;
    if (!s.adaptor_set) return false;
    if (!s.timelocks_set) return false;
    auto v = ::pricoin::swap::refund::ValidateRefundTimelocks(
        {s.pric_refund_height, s.foreign_refund_height, s.delta_min_blocks});
    if (v != ::pricoin::swap::refund::TimelockCheck::Ok) return false;
    s.state = State::AdaptorReady;
    return true;
}

} // namespace

CreateResult Create(
    CWallet& wallet,
    Role role,
    const CPubKey& counterparty_pub,
    const std::string& foreign_chain,
    int64_t foreign_amount_sat,
    const std::string& pric_joint_stealth_address,
    int64_t pric_amount_sat,
    const std::string& memo,
    const std::string& btc_alice_recipient_xonly_hex,
    const std::string& btc_bob_recipient_xonly_hex,
    const std::string& pric_alice_recipient_stealth,
    const std::string& pric_bob_recipient_stealth,
    AdaptorSwap& out,
    const uint256* swap_id_pinned)
{
    if (!counterparty_pub.IsValid() || !counterparty_pub.IsCompressed()) {
        return CreateResult::InvalidCounterpartyPubkey;
    }
    if (!ValidForeignChain(foreign_chain) || foreign_amount_sat <= 0) {
        return CreateResult::InvalidForeignLeg;
    }
    if (!ValidJointStealthAddr(pric_joint_stealth_address) || pric_amount_sat <= 0) {
        return CreateResult::InvalidPricLeg;
    }
    if (!RequireUnlocked(wallet)) return CreateResult::Locked;

    AdaptorSwap s;
    if (swap_id_pinned && !swap_id_pinned->IsNull()) {
        s.swap_id = *swap_id_pinned;
    } else {
        GetStrongRandBytes(s.swap_id);
    }
    s.role = role;
    s.state = State::Setup;
    s.counterparty_pub = counterparty_pub;
    s.foreign_chain = foreign_chain;
    s.foreign_amount_sat = foreign_amount_sat;
    s.pric_joint_stealth_address = pric_joint_stealth_address;
    s.pric_amount_sat = pric_amount_sat;
    s.memo = memo;
    // Destination addresses — the dialogs prefill recipient/dest
    // fields off these. Passed verbatim here; format validation is
    // a UX concern up the stack (the create dialog already filters).
    s.btc_alice_recipient_xonly_hex = btc_alice_recipient_xonly_hex;
    s.btc_bob_recipient_xonly_hex   = btc_bob_recipient_xonly_hex;
    s.pric_alice_recipient_stealth  = pric_alice_recipient_stealth;
    s.pric_bob_recipient_stealth    = pric_bob_recipient_stealth;
    s.created_time = NowSec();
    s.updated_time = s.created_time;

    {
        LOCK(g_mutex);
        auto& cache = EnsureCache(wallet);
        if (!EnsureLoadedLocked(wallet, cache)) return CreateResult::WriteFailed;
        if (!WriteToDB(wallet, s)) return CreateResult::WriteFailed;
        cache.by_id[s.swap_id] = s;
    }
    out = std::move(s);
    return CreateResult::Ok;
}

namespace {

// Helper: lookup + state-precondition check, then call mutator + persist.
template <typename Mutate>
TransitionResult MutateAndPersist(
    CWallet& wallet,
    const uint256& swap_id,
    Mutate mutate)
{
    if (!RequireUnlocked(wallet)) return TransitionResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return TransitionResult::WriteFailed;
    auto it = cache.by_id.find(swap_id);
    if (it == cache.by_id.end()) return TransitionResult::NotFound;

    AdaptorSwap snapshot = it->second;
    TransitionResult r = mutate(it->second);
    if (r != TransitionResult::Ok) {
        // Rollback in-memory mutation on validation failure.
        it->second = snapshot;
        return r;
    }
    it->second.updated_time = NowSec();
    if (!WriteToDB(wallet, it->second)) {
        it->second = snapshot;
        return TransitionResult::WriteFailed;
    }
    return TransitionResult::Ok;
}

} // namespace

TransitionResult SetAdaptorMaterials(
    CWallet& wallet,
    const uint256& swap_id,
    const std::array<unsigned char, 33>& T_G,
    const std::array<unsigned char, 33>& T_H,
    const std::vector<unsigned char>& dleq_proof_blob,
    const std::optional<std::array<unsigned char, 32>>& t_secret_for_bob)
{
    if (dleq_proof_blob.empty()) return TransitionResult::InvalidInput;
    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        if (s.state != State::Setup) return TransitionResult::InvalidState;
        s.T_G = T_G;
        s.T_H = T_H;
        s.dleq_proof_blob = dleq_proof_blob;
        s.adaptor_set = true;
        if (s.role == Role::Bob) {
            if (!t_secret_for_bob) return TransitionResult::InvalidInput;
            s.t_secret = *t_secret_for_bob;
            s.has_t = true;
        } else {
            // Alice: t_secret_for_bob must NOT be supplied.
            if (t_secret_for_bob) return TransitionResult::InvalidInput;
        }
        // Maybe advance to AdaptorReady if timelocks already set.
        RecomputeAdaptorReady(s);
        return TransitionResult::Ok;
    });
}

TransitionResult SetPricEphemeralR(
    CWallet& wallet,
    const uint256& swap_id,
    const std::array<unsigned char, 32>& r)
{
    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        // Bob persists r at adaptor-setup time for himself; Alice
        // receives it via DM. Either way no state transition — just
        // a stash. Allowed pre-AdaptorReady (Bob's case) and post-
        // AdaptorReady (Alice's case if her DM lands after the
        // SetAdaptorMaterials transition).
        if (s.state == State::Complete || s.state == State::Refunded ||
            s.state == State::Aborted) {
            return TransitionResult::InvalidState;
        }
        s.pric_ephemeral_r = r;
        s.has_pric_ephemeral_r = true;
        return TransitionResult::Ok;
    });
}

TransitionResult SetRefundTimelocks(
    CWallet& wallet,
    const uint256& swap_id,
    int32_t pric_refund_height,
    int32_t foreign_refund_height,
    int32_t delta_min_blocks)
{
    namespace rfn = ::pricoin::swap::refund;
    auto v = rfn::ValidateRefundTimelocks(
        {pric_refund_height, foreign_refund_height, delta_min_blocks});
    if (v != rfn::TimelockCheck::Ok) return TransitionResult::InvalidTimelocks;

    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        if (s.state != State::Setup) return TransitionResult::InvalidState;
        s.pric_refund_height = pric_refund_height;
        s.foreign_refund_height = foreign_refund_height;
        s.delta_min_blocks = delta_min_blocks;
        s.timelocks_set = true;
        RecomputeAdaptorReady(s);
        return TransitionResult::Ok;
    });
}

TransitionResult SetBtcFunded(
    CWallet& wallet,
    const uint256& swap_id,
    const std::string& foreign_funding_txid,
    int32_t foreign_funding_vout,
    int32_t foreign_funding_height)
{
    if (foreign_funding_txid.empty() || foreign_funding_vout < 0
        || foreign_funding_height <= 0) {
        return TransitionResult::InvalidInput;
    }
    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        if (s.state != State::AdaptorReady) return TransitionResult::InvalidState;
        s.foreign_funding_txid    = foreign_funding_txid;
        s.foreign_funding_vout    = foreign_funding_vout;
        s.foreign_funding_height  = foreign_funding_height;
        s.state = State::BtcFunded;
        return TransitionResult::Ok;
    });
}

TransitionResult SetPricFunded(
    CWallet& wallet,
    const uint256& swap_id,
    const uint256& pric_funding_txid,
    int32_t pric_funding_vout,
    int32_t pric_funding_height)
{
    if (pric_funding_txid.IsNull() || pric_funding_vout < 0
        || pric_funding_height <= 0) {
        return TransitionResult::InvalidInput;
    }
    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        if (s.state != State::BtcFunded) return TransitionResult::InvalidState;
        s.pric_funding_txid   = pric_funding_txid;
        s.pric_funding_vout   = pric_funding_vout;
        s.pric_funding_height = pric_funding_height;
        s.state = State::BothFunded;
        return TransitionResult::Ok;
    });
}

TransitionResult SetPreSigned(
    CWallet& wallet,
    const uint256& swap_id,
    const AdaptorSwapPreSigs& presigs)
{
    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        if (s.state != State::BothFunded) return TransitionResult::InvalidState;
        if (!presigs.IsComplete(s.foreign_chain)) return TransitionResult::InvalidInput;
        // Chain-specific size invariants. LTC HTLC swaps don't use
        // the BTC-side MuSig2 / Schnorr-adaptor fields at all, so
        // we skip those size checks for LTC.
        if (s.foreign_chain != "ltc") {
            if (presigs.btc_claim_presig.size() != 64) return TransitionResult::InvalidInput;
            if (presigs.btc_claim_session.size() != 133) return TransitionResult::InvalidInput;
            if (presigs.btc_refund_sig.size() != 64) return TransitionResult::InvalidInput;
        }
        s.presigs = presigs;
        s.state = State::PreSigned;
        return TransitionResult::Ok;
    });
}

TransitionResult SetPricClaimed(
    CWallet& wallet,
    const uint256& swap_id,
    const uint256& pric_claim_txid)
{
    if (pric_claim_txid.IsNull()) return TransitionResult::InvalidInput;
    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        if (s.state != State::PreSigned) return TransitionResult::InvalidState;
        s.pric_claim_txid = pric_claim_txid;
        // Bob: t was published on-chain, so the in-wallet copy is no
        // longer secret. Wipe it so backups don't carry an obsolete
        // long-term secret.
        if (s.role == Role::Bob) {
            std::memset(s.t_secret.data(), 0, s.t_secret.size());
            s.has_t = false;
        }
        s.state = State::PricClaimed;
        return TransitionResult::Ok;
    });
}

TransitionResult SetTSecret(
    CWallet& wallet,
    const uint256& swap_id,
    const std::array<unsigned char, 32>& t)
{
    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        if (s.has_t) {
            // Idempotent if same t; reject if caller is trying to
            // overwrite with a different scalar (programmer error).
            if (s.t_secret == t) return TransitionResult::Ok;
            return TransitionResult::InvalidInput;
        }
        s.t_secret = t;
        s.has_t = true;
        return TransitionResult::Ok;
    });
}

TransitionResult SetPricClaimRing(
    CWallet& wallet,
    const uint256& swap_id,
    const std::vector<std::array<unsigned char, 33>>& ring)
{
    if (ring.empty()) return TransitionResult::InvalidInput;
    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        if (!s.pric_claim_ring.empty()) {
            if (s.pric_claim_ring == ring) return TransitionResult::Ok;
            return TransitionResult::InvalidInput;
        }
        s.pric_claim_ring = ring;
        return TransitionResult::Ok;
    });
}

TransitionResult SetComplete(
    CWallet& wallet,
    const uint256& swap_id,
    const std::string& foreign_claim_txid)
{
    if (foreign_claim_txid.empty()) return TransitionResult::InvalidInput;
    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        if (s.state != State::PricClaimed) return TransitionResult::InvalidState;
        s.foreign_claim_txid = foreign_claim_txid;
        s.state = State::Complete;
        return TransitionResult::Ok;
    });
}

TransitionResult SetRefunded(
    CWallet& wallet,
    const uint256& swap_id,
    const uint256& pric_refund_txid_or_empty,
    const std::string& foreign_refund_txid_or_empty)
{
    if (pric_refund_txid_or_empty.IsNull() && foreign_refund_txid_or_empty.empty()) {
        return TransitionResult::InvalidInput;
    }
    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        // Refund is allowed once at least one funding has confirmed.
        // Concretely: BothFunded, PreSigned, PricClaimed.
        if (s.state != State::BothFunded
            && s.state != State::PreSigned
            && s.state != State::PricClaimed) {
            return TransitionResult::InvalidState;
        }
        if (!pric_refund_txid_or_empty.IsNull()) {
            s.pric_refund_txid = pric_refund_txid_or_empty;
        }
        if (!foreign_refund_txid_or_empty.empty()) {
            s.foreign_refund_txid = foreign_refund_txid_or_empty;
        }
        s.state = State::Refunded;
        return TransitionResult::Ok;
    });
}

TransitionResult Abort(
    CWallet& wallet,
    const uint256& swap_id,
    const std::string& reason)
{
    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        if (s.state == State::Complete
            || s.state == State::Refunded
            || s.state == State::Aborted) {
            return TransitionResult::InvalidState;
        }
        s.abort_reason = reason;
        // Best-effort wipe of secret material on abort.
        if (s.has_t) {
            std::memset(s.t_secret.data(), 0, s.t_secret.size());
            s.has_t = false;
        }
        s.state = State::Aborted;
        return TransitionResult::Ok;
    });
}

LookupResult Get(CWallet& wallet, const uint256& swap_id, AdaptorSwap& out)
{
    if (!RequireUnlocked(wallet)) return LookupResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return LookupResult::NotFound;
    auto it = cache.by_id.find(swap_id);
    if (it == cache.by_id.end()) return LookupResult::NotFound;
    out = it->second;
    return LookupResult::Ok;
}

LookupResult List(CWallet& wallet, std::vector<AdaptorSwap>& out)
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

std::string NextActionHint(const AdaptorSwap& s)
{
    const bool is_alice = (s.role == Role::Alice);
    switch (s.state) {
    case State::Setup:
        if (!s.adaptor_set && !s.timelocks_set) {
            return is_alice
                ? "Receive T_G + DLEQ proof + refund timelocks from Bob; verify, then SetAdaptorMaterials + SetRefundTimelocks"
                : "Pick t, compute T_G + DLEQ; agree refund timelocks; call SetAdaptorMaterials + SetRefundTimelocks";
        }
        if (!s.adaptor_set) return "SetAdaptorMaterials still pending";
        if (!s.timelocks_set) return "SetRefundTimelocks still pending";
        return "Setup partial — recompute or abort";
    case State::AdaptorReady:
        return is_alice
            ? "Wait for Bob to fund foreign 2-of-2; on confirmation call SetBtcFunded"
            : "Fund foreign 2-of-2; on confirmation call SetBtcFunded";
    case State::BtcFunded:
        return is_alice
            ? "Lock PRIC into joint stealth output; on confirmation call SetPricFunded"
            : "Wait for Alice to lock PRIC; on confirmation call SetPricFunded";
    case State::BothFunded:
        return "Run cooperative pre-sign protocol (4 signatures: 2 claim adaptor + 2 refund non-adaptor); call SetPreSigned with the resulting blobs";
    case State::PreSigned:
        return is_alice
            ? "Watch PRIC chain for Bob's claim spending the joint output; on confirmation call SetPricClaimed (you'll Extract t at that point)"
            : "Adapt the PRIC claim presig with t and broadcast tx_pric_claim; on confirmation call SetPricClaimed";
    case State::PricClaimed:
        return is_alice
            ? "Extract t from on-chain PRIC sig, Adapt foreign claim presig, broadcast tx_foreign_claim; on confirmation call SetComplete"
            : "Wait for Alice's foreign claim (or call SetRefunded after T_foreign_refund if she stalls)";
    case State::Complete:
        return "Done";
    case State::Refunded:
        return "Refund executed; swap terminated";
    case State::Aborted:
        return "Aborted";
    }
    return "";
}

bool LoadFromDB(CWallet& wallet)
{
    if (!RequireUnlocked(wallet)) return true;  // defer; lazy on first auth call
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

} // namespace wallet::pricoin_adaptor_swap
