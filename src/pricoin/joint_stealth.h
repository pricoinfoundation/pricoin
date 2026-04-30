// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRICOIN_JOINT_STEALTH_H
#define BITCOIN_PRICOIN_JOINT_STEALTH_H

#include <pricoin/stealth.h>

#include <array>
#include <optional>
#include <span>

// Two-party joint stealth addresses for cooperative receive (and, in a
// follow-up commit, cooperative spend). The on-chain output is
// indistinguishable from a single-party stealth output — what changes is
// that neither party alone can scan or spend.
//
// Atomic-swap context: Alice (PRIC side, sending) locks PRIC into a joint
// (Alice, Bob) output; Bob can only claim it via a cooperative protocol
// keyed on a secret that Alice releases when she claims her counter-asset
// on the other chain. Stage 2 (this file) covers the receive primitives.
// Stage 3 will add cooperative CLSAG signing for the spend side.
//
// Math:
//   Alice keys: (a_A, b_A), pubkeys (A_A, B_A).
//   Bob   keys: (a_B, b_B), pubkeys (A_B, B_B).
//   Joint pubkeys: A_J = A_A + A_B, B_J = B_A + B_B.
//                  (Equivalently, A_J = (a_A + a_B) * G; neither party
//                  knows the joint privkey individually.)
//   Sender's tx output: standard stealth send to (A_J, B_J).
//     R = r * G, shared = r * A_J = a_A * R + a_B * R.
//   Cooperative scan:
//     Alice computes partial_A = a_A * R, Bob computes partial_B = a_B * R.
//     Either party (with both partials) reconstructs `shared = partial_A
//     + partial_B`, then runs the standard DeriveSharedSecret /
//     DeriveOneTimePubkey / RewindRangeProof flow.
//
// Trust posture: sharing a partial does NOT leak the party's view priv
// (partial = priv * R is a one-way operation under the secp256k1 DL
// assumption; recovering priv from the partial requires solving DL).
// Both parties learn the joint output's value once they exchange.
namespace pricoin::joint_stealth {

// Build the joint stealth address (A_A + A_B, B_A + B_B). Returns nullopt
// if either input address is invalid or if any sum is the point at
// infinity (negligible probability for legitimate inputs).
std::optional<::pricoin::stealth::StealthAddress> Combine(
    const ::pricoin::stealth::StealthAddress& a,
    const ::pricoin::stealth::StealthAddress& b);

// Compute this party's contribution to the cooperative ECDH:
// (self_view_priv * R), serialised as a 33-byte compressed point.
// The other party computes their partial; either party combines them
// via CombinePartials.
std::optional<::pricoin::stealth::PointBytes> ScanPartial(
    const CKey& self_view_priv,
    std::span<const unsigned char> tx_pubkey_R_33);

// Add two partials to obtain the full ECDH shared point R * (a_A + a_B)
// = R * a_J. Order doesn't matter (point addition is commutative).
// Returns nullopt if either partial fails to parse or the sum is the
// point at infinity (which would indicate a degenerate input pair).
std::optional<::pricoin::stealth::PointBytes> CombinePartials(
    std::span<const unsigned char> partial_a_33,
    std::span<const unsigned char> partial_b_33);

} // namespace pricoin::joint_stealth

#endif // BITCOIN_PRICOIN_JOINT_STEALTH_H
