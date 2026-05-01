// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRICOIN_ADAPTOR_JOINT_RINGSIG_H
#define BITCOIN_PRICOIN_ADAPTOR_JOINT_RINGSIG_H

#include <pricoin/adaptor_ringsig.h>
#include <pricoin/ringsig.h>

#include <optional>
#include <span>

// Cooperative single-layer adaptor-CLSAG. Implements the protocol
// from `doc/adaptor-clsag.md` rev 4 §4.1 / §4.2: multi-party
// adaptor-CLSAG signing with mandatory share-consistency DLEQs and
// hash-bound nonce commitments.
//
// SECURITY POSTURE: experimental research code (same as
// `adaptor_ringsig.h`). Reviewed by AI models, not by a human
// cryptographer. Suitable for testnet research only.
//
// Compared to the non-adaptor cooperative module
// (`pricoin/joint_ringsig.h`), this module:
//   * Uses **shifted anchors** at the signer's index in the ring
//     walk: `L'_pi = (Σ α_X) · G + T_G`, `R'_pi = (Σ α_X) · H_p(P_pi) + T_H`.
//   * Requires **mandatory** share-consistency DLEQ proofs from
//     every party (DLEQ-1 binds α_X across G + H_p(P_pi); DLEQ-2
//     binds x_X across G + H_p(P_pi)). These eliminate the
//     adversarial-share-grinding surface flagged by round-3 review.
//   * Binds **adaptor data** (T_G, T_H) into nonce commitments so
//     SESSION mutation after round 1 is detectable.
//   * Derives `s_others` deterministically from SESSION, not from
//     any one party's randomness.
//
// The output is an `adaptor_ringsig::AdaptorPreSignature` —
// structurally identical to the single-party version, so
// `adaptor_ringsig::Adapt` and `Extract` work on it unchanged.

namespace pricoin::adaptor_joint_ringsig {

using ::pricoin::ringsig::Point;
using ::pricoin::ringsig::Scalar;
using ::pricoin::ringsig::Signature;
using ::pricoin::adaptor_ringsig::AdaptorPoints;
using ::pricoin::adaptor_ringsig::AdaptorPreSignature;
using ::pricoin::adaptor_ringsig::DLEQProof;

// One party's round-1 contribution to a cooperative adaptor pre-
// signing. The `commitment` is a hiding hash of all the public
// fields plus the SESSION; in a real distributed protocol parties
// exchange commitments first, then reveal the underlying share
// data in round 2.
//
// `alpha` is PRIVATE — it must never leave the originating party
// before round 3 closes. Disclosing it lets a counterparty derive
// the spend-secret share via `x_X = (α_X − ŝ_share_X) / c_pi`.
struct AdaptorNonceShare {
    Scalar    alpha;        // PRIVATE
    Point     L_share;      // α_X · G                   (public)
    Point     R_share;      // α_X · H_p(P_pi)           (public)
    Point     KI_share;     // x_X · H_p(P_pi)           (public)
    DLEQProof dleq_alpha;   // DLEQ-1: L_share/R_share share α_X
    DLEQProof dleq_x;       // DLEQ-2: X_pub_X / KI_share share x_X
    Scalar    commitment;   // hash binding all public fields above
                            // + adaptor (T_G, T_H) + SESSION

    SERIALIZE_METHODS(AdaptorNonceShare, obj) {
        READWRITE(obj.alpha);
        READWRITE(obj.L_share);
        READWRITE(obj.R_share);
        READWRITE(obj.KI_share);
        READWRITE(obj.dleq_alpha);
        READWRITE(obj.dleq_x);
        READWRITE(obj.commitment);
    }
};

// Output of the combine + walk step. All parties run `CombineAndWalk`
// independently with identical inputs and obtain the same output.
struct AdaptorCombineOutput {
    Point KI;            // Σ KI_share_X  (= x_pi · H_p(P_pi))
    Point L_pi;          // Σ L_share_X   (= α · G)
    Point R_pi;          // Σ R_share_X   (= α · H_p(P_pi))
    Point L_prime;       // L_pi + T_G  (shifted anchor)
    Point R_prime;       // R_pi + T_H  (shifted anchor)
    Scalar c_pi;         // closing challenge at signer's index
    Scalar c0;           // initial challenge (becomes Signature.c0)
    std::vector<Scalar> s_others; // deterministic per-index, length N
};

// ─────────────────────────────────────────────────────────────────
// Round 1 — per party.
// ─────────────────────────────────────────────────────────────────

// Generate this party's adaptor nonce share.
//
// `P_pi`     — joint pubkey at the signer's ring index (=Σ X_pub_X).
// `X_pub_X`  — this party's pre-committed public spend share.
// `x_X`      — this party's spend-secret share. PRIVATE.
// `adaptor`  — (T_G, T_H) from the adaptor party (Bob in atomic-swap
//              terminology). Already verified via DLEQ-t in the
//              setup phase.
// `session_label` / `session_payload` — SESSION binding per spec §2.1.
//
// Returns nullopt on any cryptographic failure (invalid scalar,
// degenerate point, etc.).
std::optional<AdaptorNonceShare> NonceGenAdaptor(
    const Point& P_pi,
    const Point& X_pub_X,
    const Scalar& x_X,
    const AdaptorPoints& adaptor,
    std::span<const unsigned char> session_label,
    std::span<const unsigned char> session_payload);

// Verify a counterparty's adaptor nonce share. Checks DLEQ-1,
// DLEQ-2, and that the commitment hash matches the recomputation
// with the supplied public fields.
bool VerifyAdaptorNonceShare(
    const Point& P_pi,
    const Point& X_pub_X,
    const AdaptorNonceShare& share,
    const AdaptorPoints& adaptor,
    std::span<const unsigned char> session_label,
    std::span<const unsigned char> session_payload);

// ─────────────────────────────────────────────────────────────────
// Round 2 — combine + walk (any party runs this with identical
//                            inputs, gets identical outputs).
// ─────────────────────────────────────────────────────────────────

// Verify all parties' shares, sum them, apply the adaptor shift,
// derive `s_others` deterministically from SESSION (closes the
// grinding vector flagged by round-3 review), and walk the ring.
//
// `dleq_t`        — Bob's DLEQ-t binding T_G, T_H to the adaptor
//                   secret t. Must already be verified by the caller
//                   (we re-verify here as belt-and-braces).
// `X_pub_shares`  — public spend shares, one per party, parallel to
//                   `shares`. Required for DLEQ-2 verification.
// `shares`        — round-1 outputs from each party.
//
// Returns nullopt if any share fails verification or any combine
// produces a degenerate point.
std::optional<AdaptorCombineOutput> CombineAndWalk(
    std::span<const Point> ring,
    size_t pi,
    const uint256& msg,
    const AdaptorPoints& adaptor,
    const DLEQProof& dleq_t,
    std::span<const Point> X_pub_shares,
    std::span<const AdaptorNonceShare> shares,
    std::span<const unsigned char> session_label,
    std::span<const unsigned char> session_payload);

// ─────────────────────────────────────────────────────────────────
// Round 3 — per-party close, then assemble.
// ─────────────────────────────────────────────────────────────────

// `ŝ_share_X = α_X − c_pi · x_X (mod n)`. Same math as the non-
// adaptor cooperative protocol.
std::optional<Scalar> CooperativeCloseShareAdaptor(
    const Scalar& alpha_X,
    const Scalar& c_pi,
    const Scalar& x_X);

// Combine all parties' close shares into the final pre-signature.
// `close_shares.size()` must equal the number of parties.
//
// Returns nullopt if any close share is invalid or the combined
// signature is degenerate.
std::optional<AdaptorPreSignature> AssembleAdaptorPreSig(
    const AdaptorCombineOutput& combined,
    std::span<const Scalar> close_shares,
    size_t pi,
    const AdaptorPoints& adaptor,
    const DLEQProof& dleq_t);

// Self-test: 2-party in-process honest happy path + adversarial
// rejection cases (malformed KI_share rejected by DLEQ-2,
// malformed R_share rejected by DLEQ-1, tampered commitment
// rejected). Throws on failure. Called from
// `pricoin::ct::RunSelfTest`.
void RunSelfTest();

} // namespace pricoin::adaptor_joint_ringsig

#endif // BITCOIN_PRICOIN_ADAPTOR_JOINT_RINGSIG_H
