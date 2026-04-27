// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRICOIN_CTTX_H
#define BITCOIN_PRICOIN_CTTX_H

#include <pricoin/ct.h>
#include <pricoin/ringsig.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

namespace pricoin::ct {

// One confidential output: commitment to value + rangeproof binding the
// commitment to a specific scriptPubKey + per-output tx pubkey R = rG used
// by the recipient (with their view key) to ECDH-derive the rangeproof's
// rewind nonce and recognise outputs paid to their stealth address.
//
// For non-stealth flows (Phase 2d-5/6a), tx_pubkey is the all-zero point
// — the recipient cannot scan but the bundle is otherwise well-formed.
using SerializedPubKey33 = std::array<unsigned char, 33>;

struct CTOutput {
    Commitment commitment{};
    RangeProof rangeproof{};
    std::vector<unsigned char> script_pubkey{};
    SerializedPubKey33 tx_pubkey{};
    // Phase 4b: store the full one-time recipient pubkey P (33 bytes)
    // alongside the P2WPKH script. Future ring-sig verifiers need P
    // explicitly because the script only stores hash160(P). All-zero for
    // outputs that don't intend to be ring-signed against (those still work
    // as direct-spend prevouts).
    SerializedPubKey33 one_time_pubkey{};

    SERIALIZE_METHODS(CTOutput, obj) {
        READWRITE(obj.commitment.bytes);
        READWRITE(obj.rangeproof);
        READWRITE(obj.script_pubkey);
        READWRITE(obj.tx_pubkey);
        READWRITE(obj.one_time_pubkey);
    }

    bool operator==(const CTOutput&) const = default;
};

// Reference to a previous output, by (txid, vout-index). Same wire layout
// as COutPoint — duplicated here to avoid a circular dependency with
// primitives/transaction.h (which already includes cttx.h via CTransaction).
struct PrevoutRef {
    uint256 hash{};
    uint32_t n{0};

    SERIALIZE_METHODS(PrevoutRef, obj) { READWRITE(obj.hash); READWRITE(obj.n); }
    bool operator==(const PrevoutRef&) const = default;
};

// Phase 4b — RingCT input. Each one hides the spent prev output among N
// candidates via a multi-layer CLSAG signature over (P_i, W_i) where
// W_i = C_i - pseudo_commitment. The sender chooses pseudo_commitment so
// that pseudo blinds sum to output blinds (same balance math as without
// rings). The signature also publishes a key image for double-spend
// detection.
struct CTRingInput {
    std::vector<PrevoutRef> ring{};       // N candidate prevouts
    Commitment pseudo_commitment{};        // C_pseudo_in (used in tally)
    pricoin::ringsig::Signature sig{};     // CLSAG; key image is sig.key_image

    SERIALIZE_METHODS(CTRingInput, obj) {
        READWRITE(obj.ring);
        READWRITE(obj.pseudo_commitment.bytes);
        READWRITE(obj.sig);
    }
    bool operator==(const CTRingInput&) const = default;
};

// In-memory + serializable shape of a confidential-amount transaction.
// Two ways to fund inputs:
//   - input_commitments[] — direct mode (Phase 2d). Each tx.vin[i].prevout
//     points to the actual prev output; its commitment is recomputed from
//     the chainstate. No sender privacy.
//   - ring_inputs[] — RingCT mode (Phase 4b). Each tx.vin[i].prevout is a
//     placeholder; the real input is hidden among N candidates in the ring.
// A v4 tx uses one or the other (verifier picks based on which is
// non-empty for that input index).
struct CTBundle {
    std::vector<Commitment> input_commitments{};
    std::vector<CTRingInput> ring_inputs{};
    std::vector<CTOutput> outputs{};
    uint64_t transparent_fee{0};

    SERIALIZE_METHODS(CTBundle, obj) {
        READWRITE(obj.input_commitments);
        READWRITE(obj.ring_inputs);
        READWRITE(obj.outputs);
        READWRITE(obj.transparent_fee);
    }

    bool operator==(const CTBundle&) const = default;

    // Total serialized size, useful for fee/weight accounting.
    size_t SerializedSize() const;
};

// Constructed bundle plus the secret blinds (sender-side state).
struct CTBuildResult {
    CTBundle bundle;
    std::vector<BlindingFactor> output_blinds; // parallel to bundle.outputs
};

// Build a balanced CT bundle.
//   in_values_blinds:  (value, blind) for each input that funds the tx
//   out_values_scripts: (value, scriptPubKey) for each output
//   transparent_fee:   the cleartext fee
//   nonce_seed:        sender-chosen 32 bytes; per-output nonces are derived
//                      deterministically by hashing (nonce_seed || index)
// Returns std::nullopt on cryptographic failure (probability ~2^-100).
std::optional<CTBuildResult> BuildBundle(
    std::span<const std::pair<uint64_t, BlindingFactor>> in_values_blinds,
    std::span<const std::pair<uint64_t, std::vector<unsigned char>>> out_values_scripts,
    uint64_t transparent_fee,
    const BlindingFactor& nonce_seed);

// Verify a bundle: each rangeproof must validate against its commitment +
// scriptPubKey, and the Pedersen tally must balance with the transparent
// fee. Returns true iff all checks pass.
bool VerifyBundle(const CTBundle& bundle);

// Deterministic 32-byte digest of a CTBundle. Used by signature hashing on
// v4 transactions so a signature commits to the bundle (preventing an
// attacker from swapping the bundle while keeping the signature intact).
// Plain SHA-256 of the bundle's standard serialization.
uint256 HashBundle(const CTBundle& bundle);

// Subtract two Pedersen commitments as elliptic-curve points and return the
// result as a compressed 33-byte pubkey. Used by ring-signature verifiers
// to compute W_i = C_i - C_pseudo for each ring member. Returns nullopt on
// any cryptographic parse failure.
//
// Implementation note: serializes each commitment, swaps prefix 8↔2 / 9↔3,
// parses as pubkey. The resulting pubkey may be at +y or -y of the actual
// commitment point (parity depends on point's is_square vs is_even — these
// are independent on secp256k1). Both sender and verifier use this function,
// so they get the SAME byte serialization for any given commitment, making
// the math consistent. Senders that need their secret z to satisfy z*G == W
// must call ScalarMatchesPoint() and negate z if necessary.
std::optional<std::array<unsigned char, 33>> SubtractCommitments(
    const Commitment& C1, const Commitment& C2);

// Compute scalar*G as a 33-byte compressed pubkey. Used by ring-sig signers
// to verify that their secret z (built from blind arithmetic) actually
// matches the W point the verifier will see for their ring index.
std::optional<std::array<unsigned char, 33>> ScalarTimesG(const BlindingFactor& s);

// Negate a 32-byte scalar mod n (i.e., return n - x). Returns nullopt if x
// is not a valid scalar.
std::optional<BlindingFactor> NegateScalar(const BlindingFactor& x);

// Add two 32-byte scalars mod n. Returns nullopt if the result is invalid
// (e.g., zero) or if either input is invalid.
std::optional<BlindingFactor> AddScalars(const BlindingFactor& a, const BlindingFactor& b);

} // namespace pricoin::ct

#endif // BITCOIN_PRICOIN_CTTX_H
