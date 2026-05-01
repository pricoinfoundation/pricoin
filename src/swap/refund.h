// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SWAP_REFUND_H
#define BITCOIN_SWAP_REFUND_H

#include <cstdint>

// Refund-tx pre-signing for atomic swaps (spec §6.2 step 7).
//
// CONTEXT
//   On the happy path, two adapted signatures (one per chain)
//   complete the swap. If a counterparty stalls, neither party
//   should be strictly worse off than their starting position.
//   The mechanism: BEFORE either funding tx is broadcast, both
//   parties cooperatively pre-sign a pair of timelocked refund txs
//   that revert each leg to its original owner.
//
//     tx_pric_refund    : PRIC joint output → Alice
//                         nLockTime ≥ T_pric_refund
//     tx_foreign_refund : foreign 2-of-2     → Bob
//                         nLockTime ≥ T_foreign_refund
//
// SAFETY CONSTRAINT (rev 2 of doc/adaptor-clsag.md, reversed from rev 1)
//
//   T_foreign_refund > T_pric_refund + δ
//
// where δ is calibrated to give Alice enough wall-clock time to
// (i) detect Bob's PRIC claim and extract t, and (ii) confirm her
// foreign-chain claim, after Bob reveals t. Without this buffer,
// Bob could publish his PRIC claim immediately before T_pric_refund
// expires, leaving Alice without enough time to broadcast +
// confirm her foreign claim before T_foreign_refund kicks in — at
// which point Bob can refund his foreign coin AND he already has
// her PRIC. Catastrophic.
//
// CRYPTOGRAPHY
//   Refund signatures are NON-adaptor cooperative signatures:
//     * PRIC leg: cooperative CLSAG (joint_ringsig — already in
//       this codebase). Plain non-adaptor: t isn't involved here,
//       only the joint spend secret split between Alice and Bob.
//     * Foreign leg: cooperative MuSig2 with adaptor=null
//       (btc_musig2_adaptor::ProcessNonces with adaptor_T_G=nullopt).
//
// THIS MODULE
//   Provides a small public surface for the orchestration layer:
//     * RefundTimelocks struct + ValidateRefundTimelocks(...)
//     * RunSelfTest exercising both legs' non-adaptor cooperative
//       refund signing AND the timelock-constraint validator.
//
//   The actual transaction construction (sighash bytes, witness
//   wiring, watcher logic) lives in the orchestration commit; this
//   module is the policy layer + crypto-validation harness.

namespace pricoin::swap::refund {

// All values in BLOCK HEIGHTS. The spec's "T_pric_refund" / "T_foreign_refund"
// notation is interpreted here as the absolute height at which the refund
// path becomes spendable on each chain (CHECKLOCKTIMEVERIFY semantics).
struct RefundTimelocks {
    // PRIC-side absolute block height for the refund. After this
    // height the joint output becomes spendable solely by Alice
    // (via the cooperatively pre-signed tx_pric_refund).
    int32_t pric_refund_height{0};
    // Foreign-chain absolute block height for the refund. After this
    // height the foreign 2-of-2 becomes spendable solely by Bob.
    int32_t foreign_refund_height{0};
    // Minimum required δ (in foreign-chain blocks) between the two
    // timelocks. Calibrated to the foreign chain's expected reorg
    // depth + worst-case fee-bumping window. The spec suggests
    // 24 hours = ~144 BTC blocks at 10-min targets.
    int32_t delta_min_blocks{0};
};

enum class TimelockCheck : uint8_t {
    Ok = 0,
    PricNotPositive       = 1,  // pric_refund_height ≤ 0
    ForeignNotPositive    = 2,  // foreign_refund_height ≤ 0
    DeltaMinNotPositive   = 3,  // delta_min_blocks ≤ 0 — caller error
    OrderingViolation     = 4,  // foreign_refund_height ≤ pric_refund_height
    DeltaTooSmall         = 5,  // 0 < (foreign − pric) < delta_min_blocks
};

// Pure decision function over `t`. Returns Ok when the spec
// constraint is satisfied.
TimelockCheck ValidateRefundTimelocks(const RefundTimelocks& t);

// Human-readable explanation for telemetry / RPC errors.
const char* ExplainTimelockCheck(TimelockCheck c);

// Daemon-startup self-test: validator boundary cases + non-adaptor
// cooperative refund signing for both legs. Throws on failure.
void RunSelfTest();

} // namespace pricoin::swap::refund

#endif // BITCOIN_SWAP_REFUND_H
