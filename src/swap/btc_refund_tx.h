// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SWAP_BTC_REFUND_TX_H
#define BITCOIN_SWAP_BTC_REFUND_TX_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

// BTC-side refund-tx skeleton + BIP341 sighash + post-signing
// witness assembly.
//
// CONTEXT
//   The cooperative MuSig2 + non-adaptor primitives produce a 64-byte
//   BIP340 signature. To turn that into a broadcastable refund tx,
//   we need:
//     1.  A correctly-shaped tx (one input spending the 2-of-2 P2TR
//         funding output, one output paying the refund recipient,
//         nLockTime ≥ T_foreign_refund).
//     2.  The BIP341 key-path-spend sighash for that tx.
//     3.  A witness assembled from the cooperative signature.
//
//   The cooperative-signing flow signs the sighash from step (2);
//   step (3) attaches the resulting sig to the tx producing the
//   final broadcastable bytes.
//
//   The CLAIM-tx flow is identical except that the signature is
//   adapted (Adapt(presig, t)) before attachment, AND nLockTime is
//   typically not set (the claim is broadcastable as soon as the
//   funding confirms). This module covers refund only — the claim
//   side will be a thin reuse in a follow-up.
//
// SCOPE
//   Single-input single-output refund. Real production refunds may
//   want a change output (if fee math leaves dust) or fee-bumping
//   (CPFP) flexibility — those are out of scope for this commit's
//   research surface.

namespace pricoin::swap::btc_refund_tx {

struct BtcRefundTxParams {
    // Funding outpoint — the 2-of-2 P2TR output being refunded.
    uint256 funding_txid{};
    uint32_t funding_vout{0};

    // Funding amount (smallest unit; "satoshi"). Required for the
    // BIP341 sighash, which commits to the spent input's amount.
    int64_t funding_amount_sat{0};

    // 32-byte aggregate x-only pubkey of the 2-of-2 (output of
    // pricoin_btc_musig2_keyagg). Defines the funding output's
    // scriptPubKey: OP_1 <agg_xonly>.
    std::array<unsigned char, 32> agg_xonly{};

    // Refund recipient's scriptPubKey (raw bytes). The caller owns
    // its construction — a typical refund pays the lock-side party's
    // own P2TR or P2WPKH address. Pass GetScriptForDestination(...)
    // bytes verbatim.
    std::vector<unsigned char> recipient_script_pubkey;

    // Refund amount (= funding_amount_sat - fee). Caller computes
    // fees externally; this field is the on-the-wire output value.
    int64_t refund_amount_sat{0};

    // Absolute block height at which the refund becomes spendable
    // (CHECKLOCKTIMEVERIFY semantics — tx's nLockTime field). Must
    // match the value validated by `swap::refund::ValidateRefundTimelocks`.
    int32_t nlocktime{0};
};

struct BtcRefundTxBuilt {
    // Unsigned transaction. Input 0's witness is empty; sequence is
    // 0xfffffffe (enables nLockTime per BIP65 semantics).
    CMutableTransaction tx;

    // 32-byte BIP341 key-path-spend sighash for input 0. The
    // cooperative MuSig2 signing flow signs this — the resulting
    // 64-byte sig goes back through `Finalize` to produce the
    // broadcastable tx.
    uint256 sighash;
};

// Build the refund-tx skeleton + sighash. Returns nullopt if any
// param is invalid (zero amounts, malformed agg_xonly, etc.).
std::optional<BtcRefundTxBuilt> Build(const BtcRefundTxParams& params);

// Attach the cooperative MuSig2 64-byte BIP340 signature to input 0's
// witness and return the immutable broadcastable transaction. Fails
// if `sig64.size() != 64` or the underlying tx looks malformed.
//
// The resulting CTransaction is what a real bitcoind would accept on
// `sendrawtransaction` — verify-via-XOnlyPubKey::VerifySchnorr is
// guaranteed to pass against the same sighash that came out of Build.
std::optional<CTransaction> Finalize(
    const BtcRefundTxBuilt& built,
    std::span<const unsigned char> sig64);

// Self-test: in-process happy path — build → cooperative MuSig2
// sign (no adaptor) → finalize → witness-sig verifies under the
// agg_xonly. Plus length-validation negatives. Throws on failure.
void RunSelfTest();

} // namespace pricoin::swap::btc_refund_tx

#endif // BITCOIN_SWAP_BTC_REFUND_TX_H
