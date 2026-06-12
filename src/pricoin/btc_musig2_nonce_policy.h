// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRICOIN_BTC_MUSIG2_NONCE_POLICY_H
#define BITCOIN_PRICOIN_BTC_MUSIG2_NONCE_POLICY_H

#include <serialize.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <vector>

// BTC-side §4.1a — MuSig2 nonce-reuse defence (the foreign-leg analog
// of doc/adaptor-clsag.md §4.1a, which targets the PRIC-side
// cooperative adaptor-CLSAG flow).
//
// PROBLEM
//   BIP327 MuSig2 round 1 produces a secret nonce + public nonce.
//   The pubnonce is sent to the counterparty; the secnonce is held
//   in volatile process memory (libsecp256k1 deliberately resists
//   serialization to deter persistent leakage).
//
//   If a wallet calls round 1 — sends the pubnonce — and then crashes
//   before reaching partial_sign, the secnonce is destroyed. On
//   restart, the wallet has no way to complete that signing session.
//   So far so good.
//
//   The danger: a naive wallet might try to "resume" by calling round
//   1 again with the same signing context. That generates a FRESH
//   secnonce + pubnonce. The counterparty now holds two pubnonces
//   from the same wallet for the same signing context. The classic
//   MuSig2 nonce-reuse attack lets the counterparty extract this
//   wallet's contributing key from the two partial signatures'
//   linear-system collapse:
//
//     s = α + e·d  ;  s' = α' + e'·d   (different α, different e)
//   →  d = (s − s') / (e − e')
//
//   Catastrophic: foreign-chain priv leaks.
//
// REQUIREMENT
//   Before publishing any round-1 pubnonce, the wallet MUST persist
//   a record keyed by (agg_xonly_pubkey, msg, role). On every
//   subsequent round-1 attempt the wallet MUST reject if a record
//   exists for the same key with a different session_id, OR with
//   the same session_id but `finalized == false`.
//
//   `finalized` flips true once the corresponding BTC tx is broadcast
//   and the spent output is no longer signable (no longer at risk).
//
// THIS MODULE
//   * Defines the BTC nonce record + record-digest derivation.
//   * Implements the allow/reject policy as a pure function over
//     (existing record opt, new record).
//   * Provides an in-memory `Store` used by the wallet wrapper to
//     enforce the policy.
//
//   Persistence (wallet DB integration) lives in a separate
//   wallet-tier module; this module is wallet-agnostic so the
//   daemon-startup self-test exercises the policy without a wallet.
//
// NOTE on field shapes
//   The PRIC analog persists alpha (the secret round-1 nonce) per
//   spec §4.1a — there alpha is just a 32-byte scalar. For BTC,
//   the secnonce is libsecp256k1's opaque 132-byte buffer that
//   we deliberately DO NOT persist (per libsecp256k1 docs). We
//   persist only the public commitment (the 66-byte pubnonce) plus
//   the record-key fields. On crash, the secnonce is gone; the
//   record's purpose is purely the reject-on-conflict guard, NOT
//   resumption of the in-flight session.

namespace pricoin::btc_musig2_nonce_policy {

enum class Role : uint8_t {
    Initiator = 0,
    Responder = 1,
};

// Per-spec key components. The `agg_xonly` pubkey + `msg` together
// uniquely identify a MuSig2 signing context; `role` distinguishes
// the wallet's contributions on either side of a 2-of-2 (e.g., when
// a single wallet contributes both Alice and Bob in tests).
struct RecordKey {
    uint256 agg_xonly;   // 32-byte BIP340 aggregate x-only pubkey
    uint256 msg;         // 32-byte sighash being signed
    Role    role{Role::Initiator};

    bool operator<(const RecordKey& o) const {
        if (agg_xonly != o.agg_xonly) return agg_xonly < o.agg_xonly;
        if (msg != o.msg) return msg < o.msg;
        return role < o.role;
    }
    bool operator==(const RecordKey&) const = default;

    SERIALIZE_METHODS(RecordKey, obj) {
        READWRITE(obj.agg_xonly);
        READWRITE(obj.msg);
        uint8_t role_byte = static_cast<uint8_t>(obj.role);
        READWRITE(role_byte);
        SER_READ(obj, obj.role = static_cast<Role>(role_byte));
    }
};

// SHA256(tag || agg_xonly || msg || role). Used as the DB row key.
uint256 RecordDigest(const RecordKey& k);

// 66-byte BIP327 serialized pubnonce.
using PubNonce66 = std::array<unsigned char, 66>;

struct NonceRecord {
    RecordKey key;

    // Wallet-supplied session id. Binds the record to a specific
    // logical signing intent (e.g., a swap session). A re-attempt
    // under the SAME session_id with finalized=false is rejected
    // (the wallet committed to a pubnonce already; using a fresh
    // secnonce would risk reuse). A re-attempt under a DIFFERENT
    // session_id is also rejected (concurrent-session attack).
    uint256 session_id;

    // The committed pubnonce. Public (already sent to counterparty
    // by the time this record is written), but persisted to detect
    // bit-rot or to identify which session a record belongs to in
    // an audit log.
    PubNonce66 pubnonce{};

    // Becomes true once the corresponding BTC tx is broadcast and
    // confirmed (the spent output is no longer signable; nonce-reuse
    // is no longer a concern). Until then the slot is "in flight"
    // and the policy rejects re-signing.
    bool finalized{false};

    int64_t created_time{0};
    int64_t updated_time{0};

    // CRITICAL nonce-reuse guard for the DETERMINISTIC round1_safe path.
    // round1_safe re-derives the SAME secnonce k for the same record key
    // (priv, agg_xonly, msg, role) so a crashed ceremony can resume — but
    // that means two partial_sign calls could produce s = k + e·d and
    // s' = k + e'·d with DIFFERENT challenges e (because the peer supplied
    // a different aggregate nonce the second time), collapsing to
    // d = (s − s')/(e − e') and leaking the key. To prevent it we bind the
    // secnonce to exactly ONE aggregate nonce: the first partial_sign
    // records SHA256(session) here; a later partial_sign over the same
    // record with a different session is rejected, and an identical one is
    // idempotent. Null until the first partial is produced.
    uint256 signed_agg_hash{};

    bool operator==(const NonceRecord&) const = default;

    SERIALIZE_METHODS(NonceRecord, obj) {
        READWRITE(obj.key);
        READWRITE(obj.session_id);
        READWRITE(obj.pubnonce);
        uint8_t fin_byte = obj.finalized ? 1 : 0;
        READWRITE(fin_byte);
        SER_READ(obj, obj.finalized = (fin_byte != 0));
        READWRITE(obj.created_time);
        READWRITE(obj.updated_time);
        READWRITE(obj.signed_agg_hash);
    }
};

enum class Decision {
    Ok,
    ConflictDifferentSession,    // existing record under different session_id
    ConflictSameSessionInFlight, // existing record under same session_id, finalized=false
};

// Pure decision function. Same shape as clsag_nonce_policy but for
// the BTC record types.
Decision EvaluateCreate(
    const std::optional<NonceRecord>& existing,
    const NonceRecord& proposed);

// In-memory store. Wallet-tier wrappers own a Store instance and
// mirror it to disk on every mutation.
class Store {
public:
    Store() = default;

    void Replay(NonceRecord rec);
    Decision TryCreate(NonceRecord rec);
    bool MarkFinalized(const RecordKey& k);
    const NonceRecord* Get(const RecordKey& k) const;
    bool Erase(const RecordKey& k);
    void ForEach(const std::function<void(const NonceRecord&)>& f) const;
    size_t Size() const { return m_records.size(); }
    void Clear() { m_records.clear(); }

private:
    std::map<RecordKey, NonceRecord> m_records;
};

// Self-test. Exercises the policy decision function + Store
// invariants. Throws on failure.
void RunSelfTest();

} // namespace pricoin::btc_musig2_nonce_policy

#endif // BITCOIN_PRICOIN_BTC_MUSIG2_NONCE_POLICY_H
