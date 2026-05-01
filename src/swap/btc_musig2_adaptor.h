// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SWAP_BTC_MUSIG2_ADAPTOR_H
#define BITCOIN_SWAP_BTC_MUSIG2_ADAPTOR_H

#include <musig.h>
#include <pubkey.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

// Cooperative 2-of-N MuSig2 + Schnorr adaptor wrapper around
// libsecp256k1-zkp's musig module (BIP327). Used for the foreign-chain
// leg of a cross-chain atomic swap when the BTC output is co-locked
// between two participants.
//
// This is the cooperative cousin of `btc_adaptor_schnorr.{h,cpp}`,
// which handles the single-signer case. Output sigs verify under the
// deployed `XOnlyPubKey::VerifySchnorr` (= libsecp256k1 BIP340), which
// is what real BTC and LTC nodes run.
//
// SECURITY POSTURE: experimental research code. Reviewed by AI
// models, not by a human cryptographer. Suitable for testnet
// research only. Do not deploy with non-trivial value without
// external review. See `doc/adaptor-clsag.md` rev 4 §6.1 for the
// protocol-level context.
//
// NONCE-REUSE WARNING: each party's secret nonce (`MuSig2SecNonce`)
// MUST NOT be reused across signing sessions. libsecp256k1 enforces
// this by invalidating the secnonce buffer inside `partial_sign`, but
// the caller must also not persist or copy the secnonce object.
// `MuSig2SecNonce` is non-copyable for that reason.
//
// FLOW (2-party, generalises to N):
//
//   1. Both parties: AggregatePubkeys(pubkeys) → KeyAggCache + agg X.
//   2. Each party:   NonceGen(...) → PubNonce + (secret) MuSig2SecNonce.
//   3. Exchange pubnonces.
//   4. Both parties: AggregateNonces([pn_A, pn_B]) → AggNonce.
//   5. Both parties: ProcessNonces(aggnonce, msg, cache, T_G) → Session
//                    (also captures nonce_parity needed for Adapt/Extract).
//   6. Each party:   PartialSign(secnonce, priv, cache, session) → PartialSig.
//   7. Exchange partial sigs.
//   8. Either party: AggregatePartials(session, [ps_A, ps_B]) → 64-byte
//                    pre-signature R.x ‖ s' (NOT a BIP340 sig until adapted).
//   9. Adapt(presig, t, nonce_parity) → BIP340 sig (verifiable under
//      the aggregate XOnlyPubKey).
//  10. Extract(presig, sig, nonce_parity) → t (used to claim the PRIC
//      side once the BTC sig is observed on-chain).
//
// The adaptor T_G is the same 33-byte compressed point used by PRIC's
// adaptor-CLSAG (`doc/adaptor-clsag.md` rev 4 §6.0a) — byte-equality
// across chains is the cross-chain binding mechanism.

namespace pricoin::swap::btc_musig2_adaptor {

// 32-byte scalar (priv key, adaptor secret t).
using Scalar = std::array<unsigned char, 32>;

// 32-byte BIP340 x-only aggregate pubkey.
using XOnlyPubKeyBytes = std::array<unsigned char, 32>;

// 33-byte compressed adaptor point T_G = t·G. Cross-chain
// byte-identical to PRIC's adaptor T_G.
using AdaptorPointCompressed = std::array<unsigned char, 33>;

// 64-byte BIP340 signature (or pre-signature; same byte shape).
using SignatureBytes = std::array<unsigned char, 64>;

// 66-byte serialized public nonce (BIP327).
using PubNonce66 = std::array<unsigned char, 66>;

// 66-byte serialized aggregate public nonce (BIP327).
using AggNonce66 = std::array<unsigned char, 66>;

// 32-byte serialized partial signature.
using PartialSig32 = std::array<unsigned char, 32>;

// Opaque keyagg cache. Wire size matches libsecp256k1's
// secp256k1_musig_keyagg_cache (197 bytes) — checked at compile time
// in the .cpp via static_assert.
struct KeyAggCache {
    std::array<unsigned char, 197> data;
};

// Opaque session, plus the nonce_parity captured at process-time.
// Parity is needed to Adapt/Extract correctly per BIP327's adaptor
// extension: see libsecp256k1 musig/adaptor_impl.h.
struct Session {
    std::array<unsigned char, 133> data;
    int nonce_parity{0};
};

// Step 1: aggregate participant pubkeys into a single x-only pubkey
// and produce the keyagg_cache shared by all subsequent steps.
//
// `pubkeys` ordering must be identical across all parties (musig
// pubkey aggregation is order-sensitive). Returns nullopt if any
// pubkey is malformed.
std::optional<XOnlyPubKeyBytes> AggregatePubkeys(
    const std::vector<CPubKey>& pubkeys,
    KeyAggCache& cache_out);

// Step 2: per-party nonce generation. Outputs a public nonce (to send
// to other parties) and writes the secret nonce into `secnonce_out`,
// which the caller must own and protect like a private key.
//
// `session_seed` must be uniformly random and unique per call —
// libsecp256k1 invalidates the buffer internally to deter reuse. The
// caller can cheaply derive it from `MuSig2SessionID(...)` defined in
// `<musig.h>`, optionally mixed with fresh randomness from
// `GetStrongRandBytes`.
//
// `self_priv` and `msg` are optional inputs (nullopt → not bound at
// nonce-gen time) but binding them improves nonce-misuse resistance
// per BIP327. Pass them when known.
std::optional<PubNonce66> NonceGen(
    MuSig2SecNonce& secnonce_out,
    const std::optional<Scalar>& self_priv,
    const CPubKey& self_pub,
    const std::optional<uint256>& msg,
    const KeyAggCache& cache,
    const uint256& session_seed);

// Step 4: aggregate all participants' public nonces into a single
// 66-byte aggregate nonce. Order-independent (musig nonce aggregation
// is commutative).
std::optional<AggNonce66> AggregateNonces(const std::vector<PubNonce66>& pubnonces);

// Step 5: bind `aggnonce` + `msg` + `cache` (+ optional adaptor T_G)
// into a session. The session also captures `nonce_parity`, needed
// later for Adapt/Extract.
//
// If `adaptor_T_G` is provided, the resulting aggregated signature
// will be a pre-signature (must be Adapted with t = dlog(T_G) before
// it verifies as BIP340). If nullopt, the resulting aggregated
// signature is a normal BIP340 sig.
std::optional<Session> ProcessNonces(
    const AggNonce66& aggnonce,
    const uint256& msg,
    const KeyAggCache& cache,
    const std::optional<AdaptorPointCompressed>& adaptor_T_G);

// Step 6: per-party partial signing. Consumes (and invalidates) the
// secret nonce via libsecp256k1. Returns nullopt on internal
// failure (e.g., session/cache mismatch, invalid priv key).
std::optional<PartialSig32> PartialSign(
    MuSig2SecNonce& secnonce,
    const Scalar& self_priv,
    const CPubKey& self_pub,
    const KeyAggCache& cache,
    const Session& session);

// Step 8: aggregate all parties' partial sigs into a 64-byte
// signature (or pre-signature, if the session was built with an
// adaptor). Byte shape matches BIP340.
std::optional<SignatureBytes> AggregatePartials(
    const Session& session,
    const std::vector<PartialSig32>& partials);

// Step 9: Adapt(presig, t, nonce_parity) → 64-byte BIP340 sig.
// Verifies under the aggregate x-only pubkey via the deployed
// `XOnlyPubKey::VerifySchnorr`.
//
// `nonce_parity` must be the value captured in `Session.nonce_parity`
// when the pre-sig was produced.
std::optional<SignatureBytes> Adapt(
    const SignatureBytes& presig,
    const Scalar& t,
    int nonce_parity);

// Step 10: Extract(presig, sig, nonce_parity) → t.
//
// Caller must independently verify that `sig` is the published BIP340
// signature corresponding to `presig` (e.g., observed on-chain). This
// function does NOT validate the signature; if `sig` is invalid, the
// extracted scalar is nonsense per libsecp256k1's API contract.
std::optional<Scalar> Extract(
    const SignatureBytes& presig,
    const SignatureBytes& sig,
    int nonce_parity);

// Self-test: 2-party in-process honest flow → AggregatePartials →
// pre-sig → Adapt → standard BIP340 verify under aggregate
// XOnlyPubKey → Extract round-trip → t matches the original adaptor
// secret. Throws on any mismatch.
void RunSelfTest();

} // namespace pricoin::swap::btc_musig2_adaptor

#endif // BITCOIN_SWAP_BTC_MUSIG2_ADAPTOR_H
