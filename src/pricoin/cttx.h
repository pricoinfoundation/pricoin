// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRICOIN_CTTX_H
#define BITCOIN_PRICOIN_CTTX_H

#include <pricoin/ct.h>
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

    SERIALIZE_METHODS(CTOutput, obj) {
        READWRITE(obj.commitment.bytes);
        READWRITE(obj.rangeproof);
        READWRITE(obj.script_pubkey);
        READWRITE(obj.tx_pubkey);
    }

    bool operator==(const CTOutput&) const = default;
};

// In-memory + serializable shape of a confidential-amount transaction.
// Phase 2c: this lives alongside, not inside, CTxOut. Phase 2d will wire
// it into the consensus tx format.
struct CTBundle {
    std::vector<Commitment> input_commitments{};
    std::vector<CTOutput> outputs{};
    uint64_t transparent_fee{0};

    SERIALIZE_METHODS(CTBundle, obj) {
        READWRITE(obj.input_commitments);
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

} // namespace pricoin::ct

#endif // BITCOIN_PRICOIN_CTTX_H
