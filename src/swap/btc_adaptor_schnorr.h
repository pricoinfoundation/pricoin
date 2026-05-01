// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SWAP_BTC_ADAPTOR_SCHNORR_H
#define BITCOIN_SWAP_BTC_ADAPTOR_SCHNORR_H

#include <uint256.h>

#include <array>
#include <cstdint>
#include <optional>

// Single-party BIP340-compatible adaptor-Schnorr signatures, for the
// foreign-chain leg of a cross-chain atomic swap.
//
// SECURITY POSTURE: experimental research code. Reviewed by AI
// models, not by a human cryptographer. Suitable for testnet
// research only. Do not deploy with non-trivial value without
// external review. See `doc/adaptor-clsag.md` rev 4 §6.1 for the
// protocol-level context.
//
// COMPATIBILITY: adapted signatures verify under the deployed
// `CPubKey::VerifySchnorr` (= libsecp256k1 BIP340), which is what
// real BTC and LTC nodes use. Self-test feeds every output through
// VerifySchnorr — divergence fails the daemon at startup.
//
// CROSS-CHAIN BYTE EQUALITY: T_G is encoded as a 33-byte compressed
// pubkey, byte-identical to PRIC's adaptor T_G (per
// `doc/adaptor-clsag.md` rev 4 §6.0a). Both chains use secp256k1
// generator G; byte-equality is the verification mechanism.
//
// Math (per BIP340 + adaptor extension):
//
//   * Signing key d. Pubkey P = d·G; effective signing key
//     d_eff = d if has_even_y(P) else n-d.
//   * Random k. Then R_pub = k·G + T_G  (where T_G = t·G).
//   * Retry on odd-y R_pub: BIP340 requires R to be even-y for
//     verification, and we can't manipulate T_G's parity, so we
//     just rerandomise k. Probability 1/2 per attempt.
//   * e = tagged_hash("BIP0340/challenge", R_pub.x ‖ P.x ‖ msg) mod n.
//   * Pre-signature scalar: s' = k + e·d_eff (mod n).
//   * Pre-signature on the wire: R_pub.x ‖ s'  (64 bytes).
//
// Adapt:  s = s' + t (mod n). Result on the wire: R_pub.x ‖ s.
// Standard BIP340 verifier sees:
//   s·G ?= lift_x(R_pub.x) + e·lift_x_evenY(P.x).
//   (s' + t)·G = (k + e·d + t)·G = (k·G + T_G) + e·d_eff·G
//              = R_pub + e·P_eff. ✓
//
// Extract: t = sig.s - presig.s' (mod n). Verify t·G == T_G.
//
// What's NOT in this commit:
//   * 2-of-2 cooperative MuSig2 + adaptor. Required for actual
//     atomic swaps where the BTC output is co-locked. Follow-up.
//   * Wallet RPCs to drive a swap end-to-end. Follow-up.

namespace pricoin::swap::btc_adaptor_schnorr {

// 32-byte scalar (priv key, adaptor secret t, signature s/s' field).
using Scalar = std::array<unsigned char, 32>;

// 32-byte x-only pubkey (BIP340 standard).
using XOnlyPubKey = std::array<unsigned char, 32>;

// 33-byte compressed pubkey (adaptor T_G — byte-identical to
// PRIC's adaptor T_G; allows cross-chain byte-equality check per
// spec §6.0a).
using AdaptorPointCompressed = std::array<unsigned char, 33>;

// 64-byte BIP340 signature (or pre-signature; same bytes shape).
using SignatureBytes = std::array<unsigned char, 64>;

// Construct an adaptor pre-signature.
//
// `priv`        — 32-byte signing key (must be a valid secp256k1
//                 scalar; caller's responsibility).
// `msg`         — 32-byte sighash to sign over (typically a BIP143
//                 or BIP341 sighash from the spending tx).
// `adaptor_T_G` — 33-byte compressed adaptor point. Must be a
//                 valid curve point and not the identity.
//
// Internally retries (with fresh nonce) when R_pub has odd y or
// the resulting scalar arithmetic produces an invalid scalar.
// Bounded to 32 attempts; throws on exhaustion (only fires if the
// CSPRNG is broken).
//
// Returns nullopt on cryptographic failure (invalid priv, malformed
// adaptor point, etc.).
std::optional<SignatureBytes> MakeAdaptorPreSig(
    const Scalar& priv,
    const uint256& msg,
    const AdaptorPointCompressed& adaptor_T_G);

// Verify a pre-signature off-chain. Equation:
//
//   s'·G + T_G == lift_x(R_pub.x) + e·lift_x_evenY(P.x)
//
// where e is the BIP340 challenge hash. Returns false on any
// failure (malformed inputs, equation doesn't close).
bool VerifyAdaptorPreSig(
    const XOnlyPubKey& pub_x,
    const uint256& msg,
    const AdaptorPointCompressed& adaptor_T_G,
    const SignatureBytes& presig);

// Adapt the pre-signature with held secret `t`. Verifies
// `t·G == adaptor_T_G` before producing the result, so a
// mismatched t fails fast.
//
// The result is byte-shape identical to a normal BIP340 signature
// and verifies under `CPubKey::VerifySchnorr`. Self-test confirms.
//
// Returns nullopt if t doesn't match the adaptor point, or scalar
// arithmetic produces an invalid result (negligible probability).
std::optional<SignatureBytes> Adapt(
    const SignatureBytes& presig,
    const Scalar& t,
    const AdaptorPointCompressed& adaptor_T_G);

// Extract `t` from a published BIP340 signature given the held
// pre-signature. Verifies `t·G == adaptor_T_G`.
//
// `sig` and `presig` must have the same `R_pub.x` (first 32 bytes)
// — if they differ, the published signature wasn't produced by
// adapting this pre-sig. We don't enforce that here; caller can
// check separately if needed.
//
// Returns nullopt if t doesn't reconstruct the adaptor point.
std::optional<Scalar> Extract(
    const SignatureBytes& presig,
    const SignatureBytes& sig,
    const AdaptorPointCompressed& adaptor_T_G);

// Self-test: honest round-trip + standard-BIP340-verify
// compatibility + extract round-trip + adversarial cases (wrong
// t, tampered sig, non-matching adaptor point). Throws on
// failure.
void RunSelfTest();

} // namespace pricoin::swap::btc_adaptor_schnorr

#endif // BITCOIN_SWAP_BTC_ADAPTOR_SCHNORR_H
