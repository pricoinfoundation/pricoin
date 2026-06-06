// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRICOIN_RINGSIG_H
#define BITCOIN_PRICOIN_RINGSIG_H

#include <pubkey.h>
#include <serialize.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace pricoin::ringsig {

// CLSAG ring signature, single-layer (signer proves knowledge of x such
// that ring[pi] == x*G, without revealing pi). The signature also publishes
// a key image I = x * H_p(ring[pi]) so a network can detect double-spends
// via a global key-image set.
//
// Phase 4a scope: just the pubkey row. Phase 4b will add the
// commitment-offset row that makes it RingCT (signer also proves the
// commitment-balance ring).

constexpr size_t kPointBytes = 33;
constexpr size_t kScalarBytes = 32;

using Point = std::array<unsigned char, kPointBytes>;   // compressed pubkey
using Scalar = std::array<unsigned char, kScalarBytes>; // 32-byte scalar mod n

struct Signature {
    // Standard CLSAG key image: I = x_pi · H_p(P_pi). This is what consensus
    // checks against the global KI set for double-spend prevention. It is
    // *tx-invariant* — the same (P, x) signed under any ring/msg/pseudo
    // produces the same KI.
    Point key_image{};
    // Multi-layer commitment image: D = z_pi · H_p(P_pi). Required for
    // multi-layer CLSAG verification (binds the chosen ring member's
    // commitment to the pseudo). All-zero for single-layer signatures —
    // verifiers infer the layer from this field.
    Point commitment_image{};
    Scalar c0{};                          // initial challenge (closes the ring)
    std::vector<Scalar> s;                // s_0 .. s_{N-1}, parallel to ring

    SERIALIZE_METHODS(Signature, obj) {
        READWRITE(obj.key_image);
        READWRITE(obj.commitment_image);
        READWRITE(obj.c0);
        READWRITE(obj.s);
    }
    bool operator==(const Signature&) const = default;
};

// Sign a message under a ring. Returns nullopt on cryptographic failure
// (e.g., signing key doesn't match ring[pi]).
//
// `ring`: list of compressed pubkeys (33 bytes each). All must be valid
//         secp256k1 points.
// `pi`:   index of the signer in the ring.
// `x_pi`: 32-byte private key matching ring[pi] (i.e., x_pi * G == ring[pi]).
// `msg`:  message to sign (typically a sighash).
std::optional<Signature> Sign(
    std::span<const Point> ring,
    size_t pi,
    const Scalar& x_pi,
    const uint256& msg);

// Verify a signature against a ring + message. Returns true iff valid.
bool Verify(
    std::span<const Point> ring,
    const Signature& sig,
    const uint256& msg);

// Tagged hash-to-point: return a point on secp256k1 deterministically
// derived from the input bytes. Used internally as H_p; exposed for tests.
Point HashToPoint(std::span<const unsigned char> seed);

// Compute the key image I = x · H_p(P) for a (P, x) keypair. Used by
// wallet-side bookkeeping to determine whether one of our recovered
// outputs has been spent on chain (its KI would appear in the global
// committed-KI set). Returns nullopt on cryptographic failure.
std::optional<Point> ComputeKeyImage(const Point& P, const Scalar& x);

// Multi-layer (RingCT-style) ring with commitment-offset row.
// Each ring member has a spend pubkey P_i and a commitment-offset W_i.
// W_i = C_i − C_pseudo where C_i is the prev output's commitment and
// C_pseudo is the sender's rerandomized input commitment. The signer at
// position pi knows x_pi such that P_pi = x_pi·G AND z_pi such that
// W_pi = z_pi·G (i.e., z_pi = b_prev − b_pseudo, with values canceling).
struct MultiLayerMember {
    Point P; // spend pubkey
    Point W; // C_prev − C_pseudo
};

// Sign with two-row CLSAG via μ-weighted aggregation. The signer proves
// knowledge of (x_pi, z_pi) for ring[pi] without revealing pi. Key image is
// I = x_pi · H_p(P_pi) — same as single-layer.
std::optional<Signature> SignMultiLayer(
    std::span<const MultiLayerMember> ring,
    size_t pi,
    const Scalar& x_pi,
    const Scalar& z_pi,
    const uint256& msg);

bool VerifyMultiLayer(
    std::span<const MultiLayerMember> ring,
    const Signature& sig,
    const uint256& msg);

// Multi-layer ADAPTOR pre-signature verifier (no adaptor secret t needed).
// Like VerifyMultiLayer but at index `pi` it adds the adaptor anchors
// T_G (to L) and T_H (to R) — so it verifies that the pre-signature's
// ring closes BEFORE adapting. This is the t-free check both swap parties
// can run at ceremony time to catch a cooperative round-1 desync, instead
// of discovering it only at claim time after funds are locked.
bool VerifyMultiLayerPreSig(
    std::span<const MultiLayerMember> ring,
    const Signature& sig,        // pre-adaptor: c0, s[], key_image, commitment_image
    const uint256& msg,
    size_t pi,
    const Point& T_G,
    const Point& T_H);

// out = (a + b) mod n. Both inputs and the result must be valid
// (non-zero, in range) secp256k1 scalars; returns nullopt otherwise.
// Used to reconstruct a joint spend/commitment secret from its two
// cooperative shares (x = x_A + x_B, z = z_A + z_B) for single-party
// recovery signing of a stuck swap output.
std::optional<Scalar> AddScalars(const Scalar& a, const Scalar& b);

// Phase 4a self-test: builds a small ring, signs, verifies, mutates,
// expects rejection. Throws on failure. Called from init.
void RunSelfTest();

} // namespace pricoin::ringsig

#endif // BITCOIN_PRICOIN_RINGSIG_H
