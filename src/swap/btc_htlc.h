// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SWAP_BTC_HTLC_H
#define BITCOIN_SWAP_BTC_HTLC_H

#include <consensus/amount.h>
#include <key.h>
#include <pubkey.h>
#include <script/script.h>

#include <array>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

// Phase-3 atomic-swap plumbing — Bitcoin-style hash-time-locked
// contracts (HTLCs) for the foreign-chain leg of a BTC ↔ PRIC swap
// (and, by extension, LTC, DOGE, BCH, etc., which share the same
// script semantics).
//
// IMPORTANT — this module deliberately does NOT make a swap atomic.
// Atomicity in a BTC ↔ PRIC swap requires linking the BTC preimage
// reveal to a PRIC-side spend, which on a confidential chain like
// Pricoin requires adaptor signatures (adaptor-CLSAG). Adaptor-CLSAG
// is gated on external cryptographic review (see
// doc/atomic-swap-protocol.md, Q5), and is not implemented in this
// commit. Without it, the party who finalizes the swap second can
// always stall, leaving the counterparty either (a) stuck waiting
// for a refund timelock or (b) at the mercy of cooperative refund.
//
// What this module IS useful for, today:
//   * Constructing a real BTC HTLC for the foreign-chain leg.
//   * Building the claim tx (with preimage reveal) for the receiver.
//   * Building the refund tx (with timelock) for the sender.
// And it's a stepping stone — phase 5 (adaptor-CLSAG) will add the
// PRIC-side cryptographic linkage that completes the atomicity.
//
// API posture: stateless / pure-construction. Takes WIF-encoded
// privkeys, raw outpoints, values, redeem scripts as params; the
// caller manages BTC-side keys and chain state via their own tools
// (or via the chainwatch backend in src/swap/chain_backend.h).

namespace pricoin::swap::btc_htlc {

class HTLCError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Network selector for address encoding. The redeem script is
// chain-neutral — only the bech32 HRP changes between
// {bitcoin, litecoin} × {mainnet, testnet, regtest, signet}.
enum class Network : uint8_t {
    BitcoinMainnet,    // bc
    BitcoinTestnet,    // tb (testnet3 + testnet4 + signet)
    BitcoinRegtest,    // bcrt
    LitecoinMainnet,   // ltc
    LitecoinTestnet,   // tltc
    LitecoinRegtest,   // rltc
    PricoinRegtest,    // pricrt — used in functional tests as a script playground
    PricoinMainnet,    // pric
};

// HTLC redeem script:
//   OP_IF
//     OP_SHA256 <hash>  OP_EQUALVERIFY  <recipient_pub> OP_CHECKSIG
//   OP_ELSE
//     <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <sender_pub> OP_CHECKSIG
//   OP_ENDIF
//
//   recipient claims with: <sig_recipient> <preimage> 1
//   sender refunds with:   <sig_sender>             0    (with nLockTime ≥ timeout)
//
// `preimage_hash` is SHA-256 of the 32-byte preimage. We use plain
// SHA-256 (not HASH160 / RIPEMD-160) because Lightning-network HTLCs
// also use SHA-256 and we may want to bridge later — keeping the hash
// function aligned simplifies cross-protocol reuse.
//
// `timeout` is an absolute block-height or a Unix time, per
// CHECKLOCKTIMEVERIFY semantics. Values < 500_000_000 are heights;
// ≥ 500_000_000 are unix seconds. Caller chooses; we just emit the
// number into the script.
CScript BuildHTLCScript(
    std::span<const unsigned char> preimage_hash, // 32 bytes
    const CPubKey& recipient_pub,
    const CPubKey& sender_pub,
    int64_t timeout);

// Bech32 P2WSH address for the given redeem script + network.
// Throws HTLCError on encoding failure.
std::string BuildHTLCBech32Address(const CScript& script, Network net);

// scriptPubKey for the P2WSH wrapping: OP_0 <32-byte-script-hash>.
// Useful when constructing the funding tx by hand or extracting the
// expected scriptPubKey for verification.
CScript BuildHTLCScriptPubKey(const CScript& redeem_script);

// Information that the claim/refund builders need about the prev
// output being spent. The caller learns these via their funding tx
// and the chainwatch backend (or by self-inspection).
struct HTLCFunding {
    uint256   prev_txid;
    uint32_t  prev_vout{0};
    CAmount   prev_value{0};
    CScript   redeem_script;        // returned by BuildHTLCScript
};

// Build a claim tx that spends an HTLC funding to `dest_script`.
// `preimage` is the 32-byte secret. `recipient_priv` is the WIF-
// decoded recipient privkey. The witness is fully filled in; the
// returned tx is ready to broadcast.
//
// `fee` is the transparent miner fee in satoshis. The single output
// gets `prev_value - fee`. Caller is responsible for fee selection.
//
// `dest_script` is the scriptPubKey to pay (typically a P2WPKH the
// recipient already controls, but any valid scriptPubKey works).
//
// Throws HTLCError on signing or encoding failure.
std::vector<unsigned char> BuildClaimTx(
    const HTLCFunding& funding,
    std::span<const unsigned char> preimage, // 32 bytes
    const CKey& recipient_priv,
    const CScript& dest_script,
    CAmount fee);

// Build a refund tx. Sets `nLockTime` to the redeem-script's timeout
// so the tx becomes valid only after the timeout. Sets vin[0].nSequence
// to enable CLTV (anything < 0xfffffffe). Otherwise mirrors BuildClaimTx.
std::vector<unsigned char> BuildRefundTx(
    const HTLCFunding& funding,
    int64_t timeout,
    const CKey& sender_priv,
    const CScript& dest_script,
    CAmount fee);

// Helper: given a 32-byte preimage, return its SHA-256 hash. Useful
// for callers building the redeem script.
std::array<unsigned char, 32> Sha256Preimage(std::span<const unsigned char> preimage);

// End-to-end correctness self-test for the discrete-log-bound HTLC.
// Builds the redeem script, a fake funding tx, the claim tx, and the
// refund tx; runs the script interpreter on each witness to confirm
// the script accepts the honest paths and rejects:
//   * a claim with the wrong t (knowledge of dlog of T_G failure)
//   * a refund before the timelock height
// Throws on any mismatch — wired into Pricoin's startup self-test
// gauntlet so a regression fails the daemon at boot.
void RunDLHTLCSelfTest();

// ─── Discrete-log-bound HTLC ─────────────────────────────────────
//
// Variant of the HTLC above where the claim path is bound to
// knowledge of the discrete log of an "adaptor point" T_G = t·G,
// instead of to a SHA-256 preimage. Used by Pricoin's BTC↔PRIC
// atomic swap when the foreign chain doesn't have Taproot (i.e. LTC).
//
// Why discrete-log binding rather than SHA-256: the swap protocol
// commits Bob to a specific T_G via the PRIC-side adaptor pre-sig
// + DLEQ proof. If we use SHA-256 instead (H_t = SHA256(t)), Bob
// can lie about H_t at setup, claim PRIC to reveal the real t,
// and Alice cannot satisfy the LTC HTLC because SHA256(t) ≠ H_t —
// breaking atomicity. Binding directly to T_G eliminates this
// griefing path because the LTC script verifier cryptographically
// enforces "knowledge of dlog(T_G)" via OP_CHECKSIG under T_G.
//
// Redeem script:
//   OP_IF
//     <recipient_pub> OP_CHECKSIGVERIFY
//     <T_G_compressed> OP_CHECKSIG
//   OP_ELSE
//     <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <sender_pub> OP_CHECKSIG
//   OP_ENDIF
//
//   recipient claims with: <T_G_sig> <recipient_sig> 1
//                          (recipient must hold both the dlog of
//                          recipient_pub AND the dlog of T_G — i.e.
//                          have extracted t from the foreign chain)
//   sender refunds with:   <sender_sig> 0  (with nLockTime ≥ timeout)
//
// `adaptor_T_G_compressed` MUST be a valid, non-identity 33-byte
// secp256k1 point. Both x-only forms (BIP340) and full compressed
// forms work in ECDSA (the y-parity byte just selects which point
// to verify against). We require the full compressed form so the
// script unambiguously identifies the point.
//
// `BuildDLRefundTx` is intentionally absent: the refund witness
// shape is identical to the SHA-256 HTLC's refund (`[sig, empty,
// redeem_script]`), only the redeem_script changes — and that's
// already plumbed via `HTLCFunding::redeem_script`. Use the
// existing `BuildRefundTx` with a DL-HTLC `redeem_script`.
CScript BuildDLHTLCScript(
    std::span<const unsigned char> adaptor_T_G_compressed, // 33 bytes
    const CPubKey& recipient_pub,
    const CPubKey& sender_pub,
    int64_t timeout);

// Build a DL-HTLC claim tx. `t_scalar` is the 32-byte scalar
// extracted from the foreign chain's adaptor reveal (= dlog of T_G).
// We sign the spending tx twice — once under `recipient_priv` and
// once under `t_scalar` (which is the privkey for T_G).
//
// Throws HTLCError on invalid t_scalar (zero, out of range, or
// doesn't match the redeem-script's T_G — caller is responsible
// for passing the right scalar).
std::vector<unsigned char> BuildDLClaimTx(
    const HTLCFunding& funding,
    std::span<const unsigned char> t_scalar, // 32 bytes
    const CKey& recipient_priv,
    const CScript& dest_script,
    CAmount fee);

} // namespace pricoin::swap::btc_htlc

#endif // BITCOIN_SWAP_BTC_HTLC_H
