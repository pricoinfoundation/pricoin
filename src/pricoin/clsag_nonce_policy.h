// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRICOIN_CLSAG_NONCE_POLICY_H
#define BITCOIN_PRICOIN_CLSAG_NONCE_POLICY_H

#include <pricoin/ringsig.h>  // Scalar
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <vector>

// §4.1a — cooperative-CLSAG nonce-reuse defence.
//
// PROBLEM (per spec doc/adaptor-clsag.md §4.1a):
//   Cooperative adaptor-CLSAG round-1 publishes a hiding commitment
//   to a private nonce alpha. If the wallet later re-signs the SAME
//   joint output under a SECOND session — for any reason: crash,
//   forced restart, malicious counterparty re-prompting — with a
//   fresh alpha, the resulting two signatures over the same key with
//   different challenges leak the spend share via:
//
//       x_X = (ŝ_share_X − ŝ_share_X') / (c_pi' − c_pi)
//
//   This is the standard "ECDSA-with-reused-nonce" leak generalized
//   to CLSAG. Catastrophic.
//
// REQUIREMENT:
//   Before publishing any round-1 commitment, the wallet MUST persist
//   a record keyed by (joint_output_id, ring_hash, role). On every
//   subsequent round-1 attempt, the wallet MUST reject if a record
//   exists for the same key with a different session_id, OR with the
//   same session_id but with `t_published == false`.
//
//   `t_published` flips true once the adaptor secret t becomes public
//   on-chain (extracted from the BTC-side adapted Schnorr signature
//   and observed in PRIC mempool / blocks). At that point the swap is
//   logically resolved and a future signing of the same joint output
//   under a fresh session is permitted (the joint output was spent).
//
// THIS MODULE:
//   * Defines the record struct and DB-record key derivation.
//   * Implements the *policy* (allow/reject decision) as a pure
//     function over (existing record opt, new record).
//   * Provides an in-memory `Store` that enforces the policy.
//
//   Persistence (wallet DB integration) lives in a separate
//   wallet-tier module; this module is wallet-agnostic so it can be
//   exercised by the daemon-startup self-test.

namespace pricoin::clsag_nonce_policy {

using Scalar = ::pricoin::ringsig::Scalar;

enum class Role : uint8_t {
    Initiator = 0,
    Responder = 1,
};

// Per-spec key components. `joint_output_id` is chain-specific bytes
// — for PRIC it's the canonical txid:vout encoding; the policy module
// treats it as opaque. `ring_hash` is the canonical hash of the ring
// being signed over (`ringsig::RingHash` style).
struct RecordKey {
    std::vector<unsigned char> joint_output_id;
    uint256 ring_hash;
    Role    role{Role::Initiator};

    bool operator<(const RecordKey& o) const {
        if (joint_output_id != o.joint_output_id) return joint_output_id < o.joint_output_id;
        if (ring_hash != o.ring_hash) return ring_hash < o.ring_hash;
        return role < o.role;
    }
    bool operator==(const RecordKey&) const = default;

    SERIALIZE_METHODS(RecordKey, obj) {
        READWRITE(obj.joint_output_id);
        READWRITE(obj.ring_hash);
        uint8_t role_byte = static_cast<uint8_t>(obj.role);
        READWRITE(role_byte);
        SER_READ(obj, obj.role = static_cast<Role>(role_byte));
    }
};

// DB-record digest. SHA256(tag || joint_output_id || ring_hash || role).
// Used as a stable lookup key and (in the wallet-tier follow-up) the
// DB row key.
uint256 RecordDigest(const RecordKey& k);

struct NonceRecord {
    RecordKey key;

    // Session the record was originally created under.
    uint256 session_id;

    // Secret round-1 nonce. Must NEVER leak to a counterparty before
    // round 3. Persisted only because the spec demands it (so a
    // wallet that crashes mid-flight cannot re-sign with a fresh
    // alpha and leak the spend share).
    Scalar alpha;

    // Public hiding commitment (sent in round 1).
    uint256 commitment;

    // Becomes true when the adaptor secret t for this swap is
    // observed on-chain (PRIC side), at which point the joint output
    // is logically spent and a future signing under a fresh session
    // for the same key is permitted.
    bool t_published{false};

    // Unix seconds.
    int64_t created_time{0};
    int64_t updated_time{0};

    bool operator==(const NonceRecord&) const = default;

    SERIALIZE_METHODS(NonceRecord, obj) {
        READWRITE(obj.key);
        READWRITE(obj.session_id);
        READWRITE(obj.alpha);
        READWRITE(obj.commitment);
        uint8_t t_pub_byte = obj.t_published ? 1 : 0;
        READWRITE(t_pub_byte);
        SER_READ(obj, obj.t_published = (t_pub_byte != 0));
        READWRITE(obj.created_time);
        READWRITE(obj.updated_time);
    }
};

// Outcome of a Create / Update attempt.
enum class Decision {
    Ok,
    ConflictDifferentSession,  // record exists with different session_id
    ConflictSameSessionInFlight, // record exists with same session_id, t_published==false
};

// Pure decision function. Given a possibly-existing record and a
// proposed new one (with the same RecordKey), decide whether the new
// one may be written.
Decision EvaluateCreate(
    const std::optional<NonceRecord>& existing,
    const NonceRecord& proposed);

// In-memory store. Wallet-tier wrappers will own a Store instance and
// mirror it to disk on every mutation; the in-memory side serves
// reads and enforces the policy.
class Store {
public:
    Store() = default;

    // Replay a record loaded from durable storage. Used during wallet
    // open to rebuild the cache. No policy check is applied — the
    // record was previously approved.
    void Replay(NonceRecord rec);

    // Try to insert a new record. Returns Ok on success and assigns
    // `created_time`/`updated_time` if they were zero. On a conflict,
    // the existing record is left untouched.
    Decision TryCreate(NonceRecord rec);

    // Flip the `t_published` flag on an existing record. Returns
    // false if no record exists for the given key.
    bool MarkTPublished(const RecordKey& k);

    // Lookup. Returns nullptr if no record exists.
    const NonceRecord* Get(const RecordKey& k) const;

    // Erase a record from the in-memory store. Returns true if a
    // record was removed. Used by the wallet wrapper to roll back
    // the in-memory state when a DB write fails (the policy itself
    // would never erase records).
    bool Erase(const RecordKey& k);

    // Iterate every record in the store. The callback receives a
    // const ref; Iterate() does NOT permit mutation — that goes
    // through TryCreate / MarkTPublished / Erase.
    void ForEach(const std::function<void(const NonceRecord&)>& f) const;

    // Number of records currently in the store. For tests.
    size_t Size() const { return m_records.size(); }

    // Drop everything. For tests / wallet shutdown.
    void Clear() { m_records.clear(); }

private:
    std::map<RecordKey, NonceRecord> m_records;
};

// Self-test. Throws on failure; called from the daemon-startup
// self-test runner in pricoin/ct.cpp.
void RunSelfTest();

} // namespace pricoin::clsag_nonce_policy

#endif // BITCOIN_PRICOIN_CLSAG_NONCE_POLICY_H
