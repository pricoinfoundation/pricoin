// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRICOIN_BTC_MUSIG2_NONCE_RECORDS_H
#define BITCOIN_WALLET_PRICOIN_BTC_MUSIG2_NONCE_RECORDS_H

#include <pricoin/btc_musig2_nonce_policy.h>
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

// Wallet-tier wrapper around `pricoin::btc_musig2_nonce_policy::Store`.
// Implements the BTC-side §4.1a defence: durably persists each
// MuSig2 round-1 commitment to disk *before* the pubnonce is sent to
// the counterparty, and enforces the reject-on-conflict policy across
// crashes.
//
// Records carry no secret material — the libsecp256k1 secnonce is in
// volatile process memory only. The persisted commitment exists
// purely as the reject-on-conflict guard. On crash + restart, an
// in-flight record blocks any new round 1 for the same signing
// context until the operator explicitly Erases it (or MarkFinalized
// is called when the corresponding BTC tx confirms on-chain).
//
// At-rest encryption uses the same EncryptWalletBlob pattern as the
// other Pricoin wallet records — even though the contents aren't
// secret, the at-rest envelope keeps the wallet's full posture
// uniform and ties the records to the wallet's encryption state.

namespace wallet::pricoin_btc_musig2_nonce_records {

using ::pricoin::btc_musig2_nonce_policy::RecordKey;
using ::pricoin::btc_musig2_nonce_policy::NonceRecord;
using ::pricoin::btc_musig2_nonce_policy::Role;
using ::pricoin::btc_musig2_nonce_policy::PubNonce66;

enum class BeginResult {
    Ok,
    InvalidInput,
    Locked,
    ConflictDifferentSession,
    ConflictSameSessionInFlight,
    WriteFailed,
};

// Atomically check-and-write a new MuSig2 round-1 commitment record.
// MUST be called BEFORE the pubnonce is sent to the counterparty —
// on any non-Ok return, the caller MUST abort the signing flow.
BeginResult Begin(
    CWallet& wallet,
    const RecordKey& key,
    const uint256& session_id,
    const PubNonce66& pubnonce,
    NonceRecord& out);

enum class MutateResult {
    Ok,
    NotFound,
    Locked,
    WriteFailed,
};

// Mark the record for `key` as finalized=true. Called when the
// corresponding BTC tx is confirmed on-chain; the slot becomes
// re-usable for the same session_id (different sessions still
// rejected per the strict §4.1a reading).
MutateResult MarkFinalized(CWallet& wallet, const RecordKey& key);

enum class BindResult {
    Ok,                       // bound (or idempotent re-bind to same agg nonce)
    InvalidInput,
    NotFound,
    Locked,
    WriteFailed,
    ConflictDifferentAggNonce, // SECOND partial over same secnonce, different
                               // aggregate nonce — the key-extraction attack
};

// Bind the record for `key` to a single aggregate nonce (identified by
// `agg_hash`) at partial-sign time, and reject a second partial over the
// same deterministic secnonce against a DIFFERENT aggregate nonce. MUST be
// called by partial_sign BEFORE producing the partial signature for any
// nonce that came from the deterministic round1_safe path; on a non-Ok
// return (other than idempotent Ok) the caller MUST NOT sign.
BindResult BindAggNonceAndCheck(
    CWallet& wallet, const RecordKey& key, const uint256& agg_hash);

// Hard-erase a record. Use only when the wallet has decided the
// in-flight signing session is permanently aborted and the slot
// needs to be reset. Audit-logged at the call site.
MutateResult Erase(CWallet& wallet, const RecordKey& key);

enum class LookupResult { Ok, NotFound, Locked };

LookupResult Get(CWallet& wallet, const RecordKey& key, NonceRecord& out);
LookupResult List(CWallet& wallet, std::vector<NonceRecord>& out);

bool LoadFromDB(CWallet& wallet);
void Shutdown();

} // namespace wallet::pricoin_btc_musig2_nonce_records

#endif // BITCOIN_WALLET_PRICOIN_BTC_MUSIG2_NONCE_RECORDS_H
