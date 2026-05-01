// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRICOIN_CLSAG_NONCE_RECORDS_H
#define BITCOIN_WALLET_PRICOIN_CLSAG_NONCE_RECORDS_H

#include <pricoin/clsag_nonce_policy.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace wallet {
class CWallet;
} // namespace wallet

// Wallet-tier wrapper around `pricoin::clsag_nonce_policy::Store`.
// Implements §4.1a (see doc/adaptor-clsag.md): durably persists each
// cooperative-CLSAG round-1 nonce record to disk *before* the
// commitment is broadcast, and enforces the reject-on-conflict policy
// across crashes.
//
// Records are encrypted at rest via the EncryptWalletBlob pattern
// (the record carries the secret round-1 nonce alpha — same secrecy
// posture as the wallet's stealth seed). On wallet open, lazy-loaded
// on first authenticated access (mirrors pricoin_swap_session).

namespace wallet::pricoin_clsag_nonce_records {

using ::pricoin::clsag_nonce_policy::RecordKey;
using ::pricoin::clsag_nonce_policy::NonceRecord;
using ::pricoin::clsag_nonce_policy::Role;

// Outcome of a Begin(...) call.
enum class BeginResult {
    Ok,
    InvalidInput,                 // empty key components
    Locked,                       // wallet encrypted-but-locked
    ConflictDifferentSession,     // §4.1a violation: different session_id under same key
    ConflictSameSessionInFlight,  // §4.1a violation: same session, t_published==false
    WriteFailed,                  // DB or encryption error
};

// Atomically check-and-write a new round-1 record. The wallet MUST
// call this before sending the round-1 commitment to the
// counterparty; on success the record is durably persisted and the
// in-memory store is updated. On any non-Ok return, the caller MUST
// abort the signing flow (no commitment leaves the wallet).
//
// `alpha` is the secret round-1 nonce; `commitment` is its public
// hiding hash. `session_id`, `joint_output_id`, `ring_hash`, `role`
// uniquely identify the signing context per §4.1a.
BeginResult Begin(
    CWallet& wallet,
    const RecordKey& key,
    const uint256& session_id,
    const ::pricoin::clsag_nonce_policy::Scalar& alpha,
    const uint256& commitment,
    NonceRecord& out);

// Outcome of a state-mutation (Mark / Erase) call.
enum class MutateResult {
    Ok,
    NotFound,
    Locked,
    WriteFailed,
};

// Mark the record for `key` as t_published=true. Called when the
// adaptor secret t for this swap becomes public on-chain (PRIC side).
//
// After this call, a future Begin under the SAME session_id is
// permitted; under a different session_id the policy continues to
// reject (strict reading of §4.1a).
MutateResult MarkTPublished(CWallet& wallet, const RecordKey& key);

// Hard-erase a record. Use only when the user has explicitly decided
// the joint output is permanently retired and the record is no longer
// needed for safety. Audit-logged at the call site.
MutateResult Erase(CWallet& wallet, const RecordKey& key);

// Read.
enum class LookupResult { Ok, NotFound, Locked };
LookupResult Get(CWallet& wallet, const RecordKey& key, NonceRecord& out);
LookupResult List(CWallet& wallet, std::vector<NonceRecord>& out);

// Lazy-load all records for `wallet` from the wallet DB on first
// authenticated access. Idempotent. Returns false on a corrupt
// record, which the caller treats as a load error.
bool LoadFromDB(CWallet& wallet);

// Drop all in-memory caches. Called from the daemon's Shutdown path.
void Shutdown();

} // namespace wallet::pricoin_clsag_nonce_records

#endif // BITCOIN_WALLET_PRICOIN_CLSAG_NONCE_RECORDS_H
