// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRICOIN_JOINT_STEALTH_H
#define BITCOIN_PRICOIN_JOINT_STEALTH_H

#include <key.h>
#include <pricoin/stealth.h>
#include <uint256.h>

#include <array>
#include <optional>
#include <span>
#include <vector>

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

// ─────────────────────────────────────────────────────────────────
// Proof-of-possession (rogue-key defense for atomic-swap setup).
//
// The plain additive joint-key construction `B_J = B_A + B_B` is
// vulnerable to a rogue-key attack: after seeing Alice's `B_A`, a
// malicious Bob can pick `B_B' = B_B - B_A` so that `B_J = B_B'`
// and Bob alone controls the joint key. For atomic swaps, this
// breaks atomicity entirely.
//
// Defense (per `doc/adaptor-clsag.md` rev 4 §6.0): each party
// publishes a signature on a tagged challenge under their spend
// privkey, proving knowledge of that privkey. The challenge binds:
//
//   * a fixed protocol tag ("pricoin/joint-stealth/PoP-v1"),
//   * a session_id (32 bytes; agreed between parties off-band, or
//     derived from the swap ceremony's session id),
//   * the counterparty's spend pubkey.
//
// Binding the counterparty's pubkey forces each party to commit
// to the OTHER side's pubkey before producing a valid PoP — so a
// rogue-key choice would invalidate the signature.
//
// We use ECDSA (compatible with our existing key infrastructure;
// no x-only-pubkey complications). The signature is unforgeable
// under standard ECDSA assumptions in the random-oracle model;
// for the rogue-key defense argument we just need
// existential-unforgeability, which both ECDSA and Schnorr provide.
//
// PoP is REQUIRED for atomic-swap joint stealth setup. The
// non-PoP `Combine(...)` path remains in place for the existing
// stage-2a receive flow which doesn't need rogue-key protection
// (cooperative-only output that neither party can spend alone
// regardless of how the public key was constructed).

// Compute the canonical PoP challenge digest (32 bytes).
// `session_id` and `counterparty_spend_pubkey` differentiate
// otherwise-equivalent challenges across sessions and counterparties,
// so a PoP can never be replayed across sessions or partners.
uint256 PoPChallenge(
    const uint256& session_id,
    const CPubKey& counterparty_spend_pubkey);

// Sign the PoP challenge under `self_spend_priv`. Returns the
// ECDSA-DER signature, or nullopt on signing failure (invalid
// privkey).
std::optional<std::vector<unsigned char>> ProvePossession(
    const CKey& self_spend_priv,
    const uint256& session_id,
    const CPubKey& counterparty_spend_pubkey);

// Verify a PoP signature. Returns false if the signature is
// malformed or doesn't verify against `self_spend_pubkey` over
// the canonical challenge.
bool VerifyPossession(
    const CPubKey& self_spend_pubkey,
    const uint256& session_id,
    const CPubKey& counterparty_spend_pubkey,
    std::span<const unsigned char> sig);

// Combine two stealth addresses with mutual proof-of-possession.
// Each PoP must verify under the corresponding party's spend
// pubkey + session_id + the OTHER party's pubkey (so the PoP is
// session- and partner-bound).
//
// Returns nullopt if any PoP fails verification, any input
// address is invalid, or the combined point is the identity
// (degenerate input pair).
std::optional<::pricoin::stealth::StealthAddress> CombineWithPoP(
    const ::pricoin::stealth::StealthAddress& a,
    const ::pricoin::stealth::StealthAddress& b,
    std::span<const unsigned char> a_pop,
    std::span<const unsigned char> b_pop,
    const uint256& session_id);

// Self-test: PoP honest round-trip + rogue-key attack rejection +
// session/counterparty replay rejection. Throws on failure.
// Called from `pricoin::ct::RunSelfTest`.
void RunPoPSelfTest();

} // namespace pricoin::joint_stealth

#endif // BITCOIN_PRICOIN_JOINT_STEALTH_H
