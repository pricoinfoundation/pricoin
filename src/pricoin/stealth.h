// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRICOIN_STEALTH_H
#define BITCOIN_PRICOIN_STEALTH_H

#include <key.h>
#include <pubkey.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace pricoin::stealth {

// CryptoNote-style dual-key address: (A = a*G view, B = b*G spend).
//
// The recipient publishes (A, B); the sender uses A to derive a one-time
// destination pubkey P and an ECDH shared secret with which both parties can
// derive the rangeproof rewind nonce.
struct StealthAddress {
    CPubKey view;   // A — used by the recipient to scan
    CPubKey spend;  // B — used by the recipient to compute the spend key

    bool IsValid() const { return view.IsValid() && view.IsCompressed() &&
                                  spend.IsValid() && spend.IsCompressed(); }
    bool operator==(const StealthAddress&) const = default;
};

// Bech32 encoding of (A || B). Uses HRP "pricstl" — same across networks for
// Phase 5 toy scope (proper per-network HRPs can come later if it matters).
inline constexpr std::string_view kStealthHrp{"pricstl"};

std::string Encode(const StealthAddress& a);
std::optional<StealthAddress> Decode(std::string_view encoded);

// Serialized 33-byte compressed secp256k1 point.
using PointBytes = std::array<unsigned char, 33>;

// Compute the ECDH shared point S = priv * pub. Returns the compressed
// serialization of S. Caller's responsibility to ensure pub is valid.
std::optional<PointBytes> ECDHPoint(const CKey& priv, const CPubKey& pub);

// Derive the per-output deterministic 32-byte secret used for downstream
// derivations. shared = SHA256("pricoin/stealth/secret-v1" || S || index).
std::array<unsigned char, 32> DeriveSharedSecret(
    const PointBytes& ecdh_point, uint32_t output_index);

// Compute the one-time recipient pubkey P = shared * G + B.
// Returns nullopt if the resulting point is the identity (negligible probability).
std::optional<CPubKey> DeriveOneTimePubkey(
    const std::array<unsigned char, 32>& shared, const CPubKey& spend_pubkey);

// Compute the one-time private key p = shared + b (mod n), corresponding to
// the pubkey returned by DeriveOneTimePubkey for the same shared/spend pair.
std::optional<CKey> DeriveOneTimePriv(
    const std::array<unsigned char, 32>& shared, const CKey& spend_priv);

// Per-output rangeproof rewind nonce. Both sender and receiver derive the
// same 32 bytes from the same shared secret.
std::array<unsigned char, 32> DeriveRangeProofNonce(
    const PointBytes& ecdh_point, uint32_t output_index);

} // namespace pricoin::stealth

#endif // BITCOIN_PRICOIN_STEALTH_H
