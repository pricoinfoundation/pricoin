// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRICOIN_JOINT_RINGSIG_H
#define BITCOIN_PRICOIN_JOINT_RINGSIG_H

#include <pricoin/ringsig.h>

#include <optional>
#include <span>

// Cooperative CLSAG signing for two (or more) parties holding additive
// shares of a single spend key.
//
// Setup:
//   - The signer's pubkey at ring[pi] is the SUM of N parties' shares:
//        ring[pi] = (x_1 + x_2 + ... + x_N) · G
//     For atomic-swap stage 2b this is the joint stealth one-time pubkey:
//        x_total = b_A + b_B + shared_secret
//     The wallet code is responsible for absorbing `shared_secret` into
//     one party's share (e.g., x_A_eff = b_A + shared_secret); this
//     module just sees additive shares with no further structure.
//   - All parties have agreed (off-band) on `ring`, `pi`, and `msg`.
//
// Protocol (3 rounds of communication for the strict cooperative case;
// rounds can be collapsed for the optimistic-honest case):
//
//   Round 1 — commit:
//     Each party X picks a random α_X (NoncePartial.alpha), computes
//     L_share_X = α_X · G, R_share_X = α_X · H_p(P_pi), and broadcasts
//     a hiding commitment to (L_share_X, R_share_X). KI_share_X = x_X
//     · H_p(P_pi) is also broadcast in this round.
//
//   Round 2 — open:
//     Each party reveals (L_share_X, R_share_X). Counterparties verify
//     the round-1 commitment opens to the revealed values. (Without
//     the commitment binding, a malicious party could choose their
//     L/R after seeing the others — a Wagner-style attack on nonces.)
//
//     The combiner computes:
//        KI    = sum(KI_share_X)
//        L_pi  = sum(L_share_X)
//        R_pi  = sum(R_share_X)
//
//     A designated party generates `s_others` (one fresh random scalar
//     per ring index ≠ pi) and broadcasts. All parties run WalkRing on
//     identical inputs to obtain the same c_pi.
//
//   Round 3 — close:
//     Each party computes s_share_X = α_X − c_pi · x_X (mod n) and
//     broadcasts. The combiner sums to get s_pi and assembles the final
//     Signature (which is byte-identical in shape to a single-party
//     CLSAG and verifiable with pricoin::ringsig::Verify).
//
// Open questions for external cryptographic review (recorded for the
// reviewer artifact in docs/atomic-swap-protocol.md):
//
//   - Wagner k-sum attacks: does the round-1 commit-reveal binding
//     suffice, or do we need MuSig2-style two-nonce per party?
//   - Rogue-key resistance: when ring[pi] = sum(x_X · G), a party
//     could publish x_X' = x_X − sum(others) and "steal" the joint
//     position. Our defense is that the joint stealth address is
//     derived from each party's stealth ADDRESS (committed to before
//     the swap), not from raw shares — so each x_X · G is observable
//     and pinned. Reviewer should confirm.
//   - Nonce reuse across sessions: catastrophic for any party. We
//     require fresh randomness per session and document this in the
//     callers; we don't currently bind α_X to session_id internally.
//   - Single-layer vs multi-layer: this module covers single-layer
//     CLSAG only. v4 transactions use multi-layer; the cooperative
//     multi-layer extension is a follow-up commit and needs a similar
//     review.
//   - Identifiable abort: the protocol does NOT currently identify
//     which party caused a failure (e.g., bad commitment open). For
//     atomic swaps this matters — a malicious counterparty can stall
//     us with no on-chain evidence. Future commit can add it.

namespace pricoin::joint_ringsig {

using ::pricoin::ringsig::Point;
using ::pricoin::ringsig::Scalar;
using ::pricoin::ringsig::Signature;

// Output of a party's nonce-generation step. `alpha` MUST be kept
// secret until the round-3 close share is computed; revealing it
// before round 3 would let a counterparty unilaterally derive this
// party's spend key share via x_X = (α_X − s_share_X) / c_pi.
struct NoncePartial {
    Scalar alpha;       // PRIVATE — never share before round 3
    Point  L_share;     // public: α · G
    Point  R_share;     // public: α · H_p(P_pi)
};

// Round 1a — generate this party's nonce partial. Returns nullopt if
// P_pi fails to parse or random generation produced an unusable α.
std::optional<NoncePartial> NonceGen(const Point& P_pi);

// Round 1b — compute this party's share of the joint key image
// KI_share_X = x_X · H_p(P_pi). Returns nullopt on cryptographic
// failure (invalid x_X, etc.).
std::optional<Point> KeyImageShare(const Point& P_pi, const Scalar& x_X);

// Round 1c (optional) — commit to this party's nonce partial. The
// commitment is a tagged hash over (session_id || L_share || R_share
// || KI_share). Counterparties verify this in round 2 before using
// the revealed L/R. Pass `session_id` chosen from a value that pins
// the signing session (e.g., the spend tx's hash-prefix or a fresh
// random nonce agreed in setup) — reusing session_id across distinct
// signing attempts re-enables Wagner attacks.
//
// Return value: 32-byte commitment (uint256-shaped).
Scalar NonceCommit(
    std::span<const unsigned char> session_id,
    const Point& L_share,
    const Point& R_share,
    const Point& KI_share);

// Combine a list of point shares into one (point-addition). Returns
// nullopt if any input fails to parse, the sum is the point at
// infinity (degenerate), or the list is empty.
std::optional<Point> CombinePoints(std::span<const Point> shares);

// Combine a list of scalar shares mod n. Returns nullopt if the sum
// is zero or the result fails secp256k1's seckey_verify.
std::optional<Scalar> CombineScalars(std::span<const Scalar> shares);

// Run the deterministic ring walk to obtain the c_pi closing
// challenge. All parties call this with identical inputs; each gets
// the same c_pi (so each can compute their close share). Also returns
// c0 (which the combiner needs for the final signature).
//
// `s_others` is parallel to `ring`; entries at indices ≠ pi are the
// pre-agreed random closing scalars for the non-signer ring members.
// The entry at pi is ignored (it's the slot that gets filled with
// the combined s_pi).
struct WalkOutput {
    Scalar c_pi;  // closing challenge at the signer's index
    Scalar c0;    // first challenge (goes into the published signature)
};
std::optional<WalkOutput> WalkRing(
    std::span<const Point> ring,
    size_t pi,
    const uint256& msg,
    const Point& key_image,
    const Point& L_pi,
    const Point& R_pi,
    std::span<const Scalar> s_others);

// Round 3 — compute this party's closing share s_share_X = α_X − c_pi
// · x_X (mod n). Returns nullopt on cryptographic failure.
std::optional<Scalar> CloseShare(
    const Scalar& alpha,
    const Scalar& c_pi,
    const Scalar& x_X);

// ─────────────────────────────────────────────────────────────────
// Multi-layer (RingCT) cooperative signing primitives.
// ─────────────────────────────────────────────────────────────────
//
// v4 transactions use multi-layer CLSAG: the signer proves knowledge
// of (x_pi, z_pi) at ring[pi] where z_pi = b_prev − b_pseudo (the
// commitment-offset secret). For cooperative signing each party
// holds an additive share of BOTH x_pi and z_pi:
//
//     ring[pi].P = (x_A + x_B) · G                 (joint spend pub)
//     ring[pi].W = (z_A + z_B) · G                 (joint offset pub)
//
// In the atomic-swap context z is shared in the clear between the
// two parties (both know it from the joint scan + the agreed-upon
// pseudo-blind), but the protocol still treats it as additively
// split for symmetry with x. Callers are responsible for picking a
// non-zero per-party z_X (e.g., one party picks r, the other uses
// z − r); this avoids point-at-infinity edge cases.

using ::pricoin::ringsig::MultiLayerMember;

// One party's per-position images: KI_share = x_X · H_p(P_pi),
// D_share = z_X · H_p(P_pi). Combiners sum across parties to obtain
// the published (KI, D).
struct MultiLayerImageShares {
    Point KI_share;
    Point D_share;
};
std::optional<MultiLayerImageShares> KICommitImageShare(
    const Point& P_pi,
    const Scalar& x_X,
    const Scalar& z_X);

// μ_P, μ_C from (ring, KI, D) — public, deterministic. Once the
// combiner has the joint (KI, D) every party computes the same
// μ values and uses them to derive their aggregated priv share.
struct MultiLayerMu {
    Scalar mu_P;
    Scalar mu_C;
};
std::optional<MultiLayerMu> ComputeMu(
    std::span<const MultiLayerMember> ring,
    const Point& KI,
    const Point& D);

// One party's aggregated priv share at the signer's index:
//     a_share = μ_P · x_X + μ_C · z_X (mod n)
// Sum across parties gives the aggregated priv `a` used in the
// closing scalar. Returns nullopt on cryptographic failure.
std::optional<Scalar> AggregateShare(
    const MultiLayerMu& mu,
    const Scalar& x_X,
    const Scalar& z_X);

// Multi-layer ring walk. Mirrors WalkRing but uses the multi-layer
// step challenge (binds to KI + D) and walks the µ-aggregated ring
// T_i = μ_P · P_i + μ_C · W_i with anchor I_agg = μ_P·KI + μ_C·D.
// All parties run this with identical inputs.
std::optional<WalkOutput> WalkRingMultiLayer(
    std::span<const MultiLayerMember> ring,
    size_t pi,
    const uint256& msg,
    const Point& KI,
    const Point& D,
    const Point& L_pi,
    const Point& R_pi,
    std::span<const Scalar> s_others);

// Self-test: in-process two-party single-layer AND multi-layer
// cooperative signing flows. Builds rings containing the joint
// pubkeys, runs the full protocol, and feeds the results through
// pricoin::ringsig::Verify and pricoin::ringsig::VerifyMultiLayer.
// Throws on failure. Called from pricoin::ct::RunSelfTest.
void RunSelfTest();

} // namespace pricoin::joint_ringsig

#endif // BITCOIN_PRICOIN_JOINT_RINGSIG_H
