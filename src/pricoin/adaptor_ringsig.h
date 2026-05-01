// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRICOIN_ADAPTOR_RINGSIG_H
#define BITCOIN_PRICOIN_ADAPTOR_RINGSIG_H

#include <pricoin/ringsig.h>

#include <optional>
#include <span>

// Adaptor-signature variant of CLSAG. Implements the math from
// `doc/adaptor-clsag.md` revision 4. Single-party path only in this
// commit; cooperative + multi-layer extensions land separately.
//
// SECURITY POSTURE: experimental research code. The construction
// has been reviewed by AI models (3 rounds, see
// `doc/adaptor-clsag-review-responses.md`) but NOT by a human
// cryptographer. Suitable for testnet research only. Do not deploy
// with non-trivial value without external review.
//
// Notation (per spec §2):
//   * `t`         — adaptor secret (scalar in [1, n-1]). Held by
//                   one party only (Bob in atomic-swap terminology).
//   * `T_G = t·G` — adaptor point on the standard generator.
//   * `T_H = t·H_p(P_pi)` — adaptor point on the H_p(P_pi)
//                   generator. Same scalar t. **Must be byte-
//                   identical between PRIC and BTC sides** (§6.0a).
//   * DLEQ `π_t`  — Chaum-Pedersen proof binding (T_G, T_H) to
//                   the same scalar t.
//   * Pre-sig `ŝ_pi = α - c_pi · x_pi` — same as a normal CLSAG
//                   close, BUT the ring walk uses shifted anchors
//                   `L'_pi = α·G + T_G`, `R'_pi = α·H_p(P_pi) + T_H`.
//   * Adapt: `s_pi = ŝ_pi + t`. The result is byte-identical in
//                   shape to a normal CLSAG and verifies under
//                   `pricoin::ringsig::Verify(ring, sig, msg)`
//                   unchanged.
//   * Extract: `t = s_pi - ŝ_pi`. Anyone holding the pre-sig can
//                   extract t from the on-chain signature.
//
// The session-binding requirement from §2.1 lives entirely
// off-chain: every DLEQ challenge and (in the cooperative variant,
// later) every nonce commitment hashes the SESSION payload.
// Callers supply session_label + session_payload; the math
// primitives fold them into the relevant Fiat-Shamir transcripts.

namespace pricoin::adaptor_ringsig {

using ::pricoin::ringsig::Point;
using ::pricoin::ringsig::Scalar;
using ::pricoin::ringsig::Signature;

// Public adaptor points. Both must be on the curve and non-
// infinity. `T_H = t · H_p(P_pi)` for the SAME scalar `t` as in
// `T_G = t · G` — bound by the DLEQ proof.
struct AdaptorPoints {
    Point T_G{};
    Point T_H{};
    bool operator==(const AdaptorPoints&) const = default;
};

// Chaum-Pedersen DLEQ proof. Per spec §3.0a:
//   A_G = r·G,  A_H = r·H_p(P_pi),  z = r + e·t
//   e = H_session("dleq-challenge-v1", encode(G,H_p,T_G,T_H,A_G,A_H))
struct DLEQProof {
    Point  A_G{};
    Point  A_H{};
    Scalar z{};

    SERIALIZE_METHODS(DLEQProof, obj) {
        READWRITE(obj.A_G);
        READWRITE(obj.A_H);
        READWRITE(obj.z);
    }
    bool operator==(const DLEQProof&) const = default;
};

// Pre-signature object. Off-chain only — the SESSION fields and
// adaptor data must NEVER be exposed to a third-party verifier.
// pi-leakage to the off-chain receiver is acceptable in the
// cooperative-spend setting (both parties already know pi).
struct AdaptorPreSignature {
    // CLSAG-shaped fields (s[pi] holds ŝ_pi until Adapt).
    Point  key_image{};
    Point  commitment_image{};   // zero for single-layer
    Scalar c0{};
    std::vector<Scalar> s{};

    // Adaptor-specific (off-chain) fields:
    AdaptorPoints adaptor{};
    DLEQProof     dleq{};
    uint32_t      pi{0};         // signer index in the ring

    SERIALIZE_METHODS(AdaptorPreSignature, obj) {
        READWRITE(obj.key_image);
        READWRITE(obj.commitment_image);
        READWRITE(obj.c0);
        READWRITE(obj.s);
        READWRITE(obj.adaptor.T_G);
        READWRITE(obj.adaptor.T_H);
        READWRITE(obj.dleq);
        READWRITE(obj.pi);
    }
    bool operator==(const AdaptorPreSignature&) const = default;
};

// ─────────────────────────────────────────────────────────────────
// DLEQ helpers.
// ─────────────────────────────────────────────────────────────────

// Compute (T_G, T_H) from secret t and the signer's pubkey P_pi.
// T_H is on generator H_p(P_pi); both points use the SAME t.
// Returns nullopt on cryptographic failure (invalid t, etc.).
std::optional<AdaptorPoints> ComputeAdaptorPoints(
    const Scalar& t, const Point& P_pi);

// Construct a Chaum-Pedersen DLEQ proof binding (T_G, T_H) to the
// same scalar t over generators (G, H_p(P_pi)).
//
// `session_label` is a per-call domain tag (e.g.,
// `"pricoin/adaptor-clsag/dleq-v1"`); `session_payload` is the
// SESSION transcript bytes per spec §2.1 — the caller assembles it.
// Both feed into the Fiat-Shamir challenge.
std::optional<DLEQProof> MakeDLEQProof(
    const Scalar& t,
    const Point& P_pi,
    const AdaptorPoints& adaptor,
    std::span<const unsigned char> session_label,
    std::span<const unsigned char> session_payload);

// Verify a DLEQ proof. Caller passes the same session_label /
// session_payload the prover used. Returns false on any failure.
bool VerifyDLEQProof(
    const Point& P_pi,
    const AdaptorPoints& adaptor,
    const DLEQProof& proof,
    std::span<const unsigned char> session_label,
    std::span<const unsigned char> session_payload);

// ─────────────────────────────────────────────────────────────────
// Pre-signature, Adapt, Extract.
// ─────────────────────────────────────────────────────────────────

// Construct an adaptor pre-signature.
//
// The signer knows `x_pi` such that `ring[pi] = x_pi · G`. The
// adaptor party (the counterparty, holding `t`) supplies
// `(adaptor, dleq, session_label, session_payload)`.
//
// We verify the DLEQ before producing the pre-sig; if it doesn't
// verify, abort. (Spec §3.1 step 1.)
std::optional<AdaptorPreSignature> MakePreSignature(
    std::span<const Point> ring,
    size_t pi,
    const Scalar& x_pi,
    const uint256& msg,
    const AdaptorPoints& adaptor,
    const DLEQProof& dleq,
    std::span<const unsigned char> session_label,
    std::span<const unsigned char> session_payload);

// Verify a pre-signature. Walks the ring with shifted anchors at
// `pi` (per spec §3.2). Off-chain operation.
bool VerifyPreSignature(
    std::span<const Point> ring,
    const AdaptorPreSignature& presig,
    const uint256& msg,
    std::span<const unsigned char> session_label,
    std::span<const unsigned char> session_payload);

// Adapt the pre-signature using the held secret `t`. Produces a
// standard CLSAG `Signature` byte-identical in shape to one
// produced by `pricoin::ringsig::Sign`.
//
// MUST verify before returning (per spec §3.3):
//   * `t · G == T_G`,
//   * `s_pi != 0` (mod n; restart on the negligible-probability
//     case),
//   * the resulting signature passes `pricoin::ringsig::Verify`
//     against the same `msg`.
//
// Returns nullopt on any check failure.
std::optional<Signature> Adapt(
    const AdaptorPreSignature& presig,
    const Scalar& t,
    std::span<const Point> ring,
    const uint256& msg);

// Extract `t` from an on-chain signature given the pre-sig that
// produced it. `t = sig.s[pi] - presig.s[pi]`.
//
// MUST verify (per spec §3.5):
//   * `t · G == T_G`,
//   * `t · H_p(P_pi) == T_H` (where P_pi = ring[presig.pi]).
//
// Returns nullopt on either check failure.
std::optional<Scalar> Extract(
    std::span<const Point> ring,
    const AdaptorPreSignature& presig,
    const Signature& sig);

// Self-test: exercises all happy paths + sign-flip detection +
// wrong-T_H detection + DLEQ replay rejection. Throws on failure.
// Called from `pricoin::ct::RunSelfTest`.
void RunSelfTest();

} // namespace pricoin::adaptor_ringsig

#endif // BITCOIN_PRICOIN_ADAPTOR_RINGSIG_H
