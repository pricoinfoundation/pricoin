// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pricoin_adaptor_swap.h>

#include <core_io.h>
#include <primitives/transaction.h>
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
        // Back-fill: pre-2026-05-15 builds wrote `pric_funding_unsigned_tx_hex`
        // and `pric_funding_planned_vout` without pinning the deterministic
        // `pric_funding_txid` derived from the hex. The cooperative-sign
        // dialog reads pric_funding_txid via the snapshot prefill, so an
        // empty value blocks buildtx. Decode the hex here once on load
        // and pin both fields if the record predates the pinning fix.
        // Idempotent: skip if either the hex is empty or the txid is
        // already set.
        if (!s.pric_funding_unsigned_tx_hex.empty()
            && s.pric_funding_txid.IsNull()) {
            CMutableTransaction back_mtx;
            if (DecodeHexTx(back_mtx, s.pric_funding_unsigned_tx_hex,
                             /*try_no_witness=*/true, /*try_witness=*/true)) {
                s.pric_funding_txid = back_mtx.GetHash().ToUint256();
                if (s.pric_funding_vout < 0 && s.pric_funding_planned_vout >= 0) {
                    s.pric_funding_vout = s.pric_funding_planned_vout;
                }
            }
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
        // Idempotent re-create guard. A pinned swap_id can be triggered
        // by a replayed swap_start DM on relay reconnect; without this,
        // Create would clobber a live swap's state (funding metadata,
        // adaptor secret t, presigs) back to Setup. If a record already
        // exists for this swap_id, return the existing record unchanged.
        auto existing = cache.by_id.find(s.swap_id);
        if (existing != cache.by_id.end()) {
            out = existing->second;
            return CreateResult::Ok;
        }
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
        // Post-2026-05-15 protocol ordering: presigs are gathered
        // BEFORE the foreign-chain funding so Alice has Bob's PRIC
        // refund presig in hand before any of her PRIC is locked.
        // Bob's LTC funding therefore advances from AdaptorReady; for
        // safety, we still accept the same transition if the swap is
        // already past PreSigned (rare race: Alice's coopsign ack
        // arrives milliseconds before Bob's chainwatch event).
        if (s.state != State::AdaptorReady
            && s.state != State::PreSigned) {
            return TransitionResult::InvalidState;
        }
        // Enforce the core funds-safety invariant: presigs (incl. the
        // refund presig that auto-refund depends on) MUST be complete and
        // persisted before any funding is recorded. The AdaptorReady source
        // is only meant to cover the millisecond race where funding confirms
        // just before SetPreSigned runs — but if presigs aren't actually in
        // hand, advancing would strand the swap with no refund path (and
        // SetPreSigned can no longer run once we leave AdaptorReady).
        if (!s.presigs.IsComplete(s.foreign_chain)) {
            return TransitionResult::InvalidState;
        }
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
        // Post-2026-05-15 protocol ordering: presigs are gathered
        // before any on-chain funding, so the source state is now
        // AdaptorReady (not BothFunded). Removes the legacy
        // "I ACCEPT" gate at btc_funded — once we're in PreSigned,
        // Alice already holds Bob's PRIC refund presig and can
        // safely broadcast her funding.
        if (s.state != State::AdaptorReady) return TransitionResult::InvalidState;
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
        // Post-2026-05-15: PRIC claim happens once both legs are
        // funded (and the presigs were already gathered earlier).
        if (s.state != State::BothFunded) return TransitionResult::InvalidState;
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
    const std::vector<std::array<unsigned char, 33>>& ring,
    const std::vector<std::array<unsigned char, 33>>& ring_w,
    const std::string& msg_hex,
    int32_t pi,
    const std::string& unsigned_tx_hex)
{
    if (ring.empty()) return TransitionResult::InvalidInput;
    // ring_w may be empty (legacy callers / pre-ML path), but if
    // supplied it must align with the P ring 1:1.
    if (!ring_w.empty() && ring_w.size() != ring.size()) {
        return TransitionResult::InvalidInput;
    }
    // msg_hex when supplied must be 32 bytes (64 hex chars).
    if (!msg_hex.empty() && msg_hex.size() != 64) {
        return TransitionResult::InvalidInput;
    }
    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        const bool ring_clash =
            (!s.pric_claim_ring.empty() && s.pric_claim_ring != ring);
        if (ring_clash) return TransitionResult::InvalidInput;
        s.pric_claim_ring = ring;
        // Back-fill / set W. Idempotent on equal; conflicting re-set
        // rejected (don't clobber a real W with a different one).
        if (!ring_w.empty()) {
            if (!s.pric_claim_ring_w.empty() && s.pric_claim_ring_w != ring_w) {
                return TransitionResult::InvalidInput;
            }
            s.pric_claim_ring_w = ring_w;
        }
        // Back-fill / set (msg, pi, tx_hex). Same conflict policy.
        if (!msg_hex.empty()) {
            if (!s.pric_claim_msg_hex.empty() && s.pric_claim_msg_hex != msg_hex) {
                return TransitionResult::InvalidInput;
            }
            s.pric_claim_msg_hex = msg_hex;
        }
        if (pi >= 0) {
            if (s.pric_claim_pi >= 0 && s.pric_claim_pi != pi) {
                return TransitionResult::InvalidInput;
            }
            s.pric_claim_pi = pi;
        }
        if (!unsigned_tx_hex.empty()) {
            if (!s.pric_claim_unsigned_tx_hex.empty()
                && s.pric_claim_unsigned_tx_hex != unsigned_tx_hex) {
                return TransitionResult::InvalidInput;
            }
            s.pric_claim_unsigned_tx_hex = unsigned_tx_hex;
        }
        return TransitionResult::Ok;
    });
}

TransitionResult SetPricRefundTx(
    CWallet& wallet,
    const uint256& swap_id,
    const std::string& unsigned_tx_hex)
{
    if (unsigned_tx_hex.empty()) return TransitionResult::InvalidInput;
    // Be liberal in what we accept here — the buildtx output is the
    // authoritative source. Just sanity-check it's hex-shaped and
    // non-tiny.
    if (unsigned_tx_hex.size() < 20) return TransitionResult::InvalidInput;
    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        if (s.state == State::Setup) return TransitionResult::InvalidState;
        if (s.state == State::Complete || s.state == State::Refunded
            || s.state == State::Aborted) {
            return TransitionResult::InvalidState;
        }
        if (!s.pric_refund_unsigned_tx_hex.empty()) {
            // Idempotent re-set with same value is OK; re-set with
            // different value isn't (don't clobber a captured refund).
            if (s.pric_refund_unsigned_tx_hex == unsigned_tx_hex) {
                return TransitionResult::Ok;
            }
            return TransitionResult::InvalidInput;
        }
        s.pric_refund_unsigned_tx_hex = unsigned_tx_hex;
        return TransitionResult::Ok;
    });
}

TransitionResult SetCoopsignSession(
    CWallet& wallet,
    const uint256& swap_id,
    CoopsignLeg leg,
    const std::string& session_json)
{
    // Empty JSON is allowed — used to clear/reset a session.
    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        if (s.state == State::Complete || s.state == State::Refunded
            || s.state == State::Aborted) {
            return TransitionResult::InvalidState;
        }
        switch (leg) {
        case CoopsignLeg::PricClaimAdaptor:
            s.pric_claim_adaptor_session_json = session_json; break;
        case CoopsignLeg::PricRefund:
            s.pric_refund_session_json = session_json; break;
        case CoopsignLeg::BtcClaimAdaptor:
            s.btc_claim_adaptor_session_json = session_json; break;
        case CoopsignLeg::BtcRefund:
            s.btc_refund_session_json = session_json; break;
        }
        return TransitionResult::Ok;
    });
}

TransitionResult SetBtcRefundTx(
    CWallet& wallet,
    const uint256& swap_id,
    const std::string& unsigned_tx_hex)
{
    if (unsigned_tx_hex.empty()) return TransitionResult::InvalidInput;
    if (unsigned_tx_hex.size() < 20) return TransitionResult::InvalidInput;
    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        if (s.state == State::Setup) return TransitionResult::InvalidState;
        if (s.state == State::Complete || s.state == State::Refunded
            || s.state == State::Aborted) {
            return TransitionResult::InvalidState;
        }
        if (!s.btc_refund_unsigned_tx_hex.empty()) {
            if (s.btc_refund_unsigned_tx_hex == unsigned_tx_hex) {
                return TransitionResult::Ok;
            }
            return TransitionResult::InvalidInput;
        }
        s.btc_refund_unsigned_tx_hex = unsigned_tx_hex;
        return TransitionResult::Ok;
    });
}

TransitionResult SetBtcClaimTx(
    CWallet& wallet,
    const uint256& swap_id,
    const std::string& unsigned_tx_hex)
{
    if (unsigned_tx_hex.empty()) return TransitionResult::InvalidInput;
    if (unsigned_tx_hex.size() < 20) return TransitionResult::InvalidInput;
    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        if (s.state == State::Setup) return TransitionResult::InvalidState;
        if (s.state == State::Complete || s.state == State::Refunded
            || s.state == State::Aborted) {
            return TransitionResult::InvalidState;
        }
        if (!s.btc_claim_unsigned_tx_hex.empty()) {
            if (s.btc_claim_unsigned_tx_hex == unsigned_tx_hex) {
                return TransitionResult::Ok;
            }
            return TransitionResult::InvalidInput;
        }
        s.btc_claim_unsigned_tx_hex = unsigned_tx_hex;
        return TransitionResult::Ok;
    });
}

TransitionResult SetPricFundingPlanned(
    CWallet& wallet,
    const uint256& swap_id,
    const std::string& unsigned_tx_hex,
    int32_t planned_vout)
{
    if (unsigned_tx_hex.empty() || unsigned_tx_hex.size() < 20) {
        return TransitionResult::InvalidInput;
    }
    if (planned_vout < 0) return TransitionResult::InvalidInput;
    // Compute the deterministic txid from the signed hex up front so
    // the dialog + watcher can reference the funding output by txid
    // before broadcast. PRIC ringsig CT txs have no signature
    // malleability once signed, so this txid is final.
    uint256 planned_txid;
    {
        CMutableTransaction mtx;
        if (!DecodeHexTx(mtx, unsigned_tx_hex,
                         /*try_no_witness=*/true, /*try_witness=*/true)) {
            return TransitionResult::InvalidInput;
        }
        planned_txid = mtx.GetHash().ToUint256();
    }
    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        // Pre-funding states only — once the swap is past funding the
        // hex on disk is moot (the on-chain tx is authoritative).
        if (s.state != State::Setup
            && s.state != State::AdaptorReady
            && s.state != State::PreSigned
            && s.state != State::BtcFunded) {
            return TransitionResult::InvalidState;
        }
        if (!s.pric_funding_unsigned_tx_hex.empty()) {
            // Idempotent re-set with same value is OK. Reject only
            // when a conflicting hex/vout is offered (don't clobber
            // a value already committed).
            if (s.pric_funding_unsigned_tx_hex != unsigned_tx_hex
                || s.pric_funding_planned_vout != planned_vout) {
                return TransitionResult::InvalidInput;
            }
            // Fall through: even when the hex matches, we may still
            // need to back-fill pric_funding_txid for swap records
            // written by an earlier code path that didn't pin it.
        } else {
            s.pric_funding_unsigned_tx_hex = unsigned_tx_hex;
            s.pric_funding_planned_vout    = planned_vout;
        }
        // Pin the funding txid + vout so existing buildtx / dialog
        // prefill paths (which read pric_funding_txid_hex) work for
        // the pre-broadcast ceremony. pric_funding_height stays 0
        // until the tx confirms on chain. Idempotent: if already
        // pinned (and to the same value), this is a no-op.
        if (s.pric_funding_txid.IsNull()) {
            s.pric_funding_txid = planned_txid;
            s.pric_funding_vout = planned_vout;
        }
        return TransitionResult::Ok;
    });
}

TransitionResult SetBtcFundingPlanned(
    CWallet& wallet,
    const uint256& swap_id,
    const std::string& signed_tx_hex,
    const std::string& planned_txid_hex,
    int32_t planned_vout)
{
    // BTC analogue of SetPricFundingPlanned: persist the planned BTC
    // funding outpoint (txid:vout) so both parties' cooperative ceremonies
    // sign over the same funding output BEFORE it is broadcast.
    //   * Bob (the funder) passes the fully-signed tx hex too; it's
    //     replayed at the funding step.
    //   * Alice (cosigner) receives only the outpoint over DM and passes
    //     an EMPTY signed_tx_hex — she just needs the outpoint for her
    //     ceremony, not the funding tx.
    // Does NOT touch foreign_funding_* (the post-broadcast, state-
    // advancing path) — these are separate "planned" fields.
    if (!signed_tx_hex.empty() && signed_tx_hex.size() < 20) {
        return TransitionResult::InvalidInput;
    }
    if (planned_txid_hex.size() != 64) return TransitionResult::InvalidInput;
    if (planned_vout < 0) return TransitionResult::InvalidInput;
    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        if (s.foreign_chain != "btc") return TransitionResult::InvalidInput;
        // Pre-funding states only.
        if (s.state != State::Setup
            && s.state != State::AdaptorReady
            && s.state != State::PreSigned) {
            return TransitionResult::InvalidState;
        }
        // Outpoint is write-once: reject a conflicting re-set (don't let a
        // late/duplicate DM repoint the ceremony).
        if (!s.btc_funding_planned_txid.empty()
            && (s.btc_funding_planned_txid != planned_txid_hex
                || s.btc_funding_planned_vout != planned_vout)) {
            return TransitionResult::InvalidInput;
        }
        s.btc_funding_planned_txid = planned_txid_hex;
        s.btc_funding_planned_vout = planned_vout;
        // Only the funder holds the signed tx; back-fill it idempotently.
        if (!signed_tx_hex.empty()) {
            if (!s.btc_funding_unsigned_tx_hex.empty()
                && s.btc_funding_unsigned_tx_hex != signed_tx_hex) {
                return TransitionResult::InvalidInput;
            }
            s.btc_funding_unsigned_tx_hex = signed_tx_hex;
        }
        return TransitionResult::Ok;
    });
}

TransitionResult SetPeerStealthPubkeys(
    CWallet& wallet,
    const uint256& swap_id,
    const std::string& view_hex,
    const std::string& spend_hex)
{
    if (view_hex.size() != 66 || spend_hex.size() != 66) {
        return TransitionResult::InvalidInput;
    }
    return MutateAndPersist(wallet, swap_id, [&](AdaptorSwap& s) -> TransitionResult {
        if (s.state == State::Complete || s.state == State::Refunded
            || s.state == State::Aborted) {
            return TransitionResult::InvalidState;
        }
        if (!s.peer_view_pubkey_hex.empty() || !s.peer_spend_pubkey_hex.empty()) {
            if (s.peer_view_pubkey_hex == view_hex
                && s.peer_spend_pubkey_hex == spend_hex) {
                return TransitionResult::Ok;
            }
            return TransitionResult::InvalidInput;
        }
        s.peer_view_pubkey_hex = view_hex;
        s.peer_spend_pubkey_hex = spend_hex;
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
        // Post-2026-05-15 ordering, the funded states are:
        //   BtcFunded   — Bob funded LTC, Alice not yet.
        //   BothFunded  — both legs funded.
        //   PricClaimed — Bob claimed; Alice may still need to claim/refund.
        // PreSigned in the new ordering precedes any funding, so it is
        // NOT a valid refund-source state.
        if (s.state != State::BtcFunded
            && s.state != State::BothFunded
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
