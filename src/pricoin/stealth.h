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
// Phase 5 experimental scope (proper per-network HRPs can come later if it matters).
inline constexpr std::string_view kStealthHrp{"pricstl"};

std::string Encode(const StealthAddress& a);
std::optional<StealthAddress> Decode(std::string_view encoded);

// Serialized 33-byte compressed secp256k1 point.
using PointBytes = std::array<unsigned char, 33>;

// Compute the ECDH shared point S = priv * pub. Returns the compressed
// serialization of S. Caller's responsibility to ensure pub is valid.
std::optional<PointBytes> ECDHPoint(const CKey& priv, const CPubKey& pub);

// ─── Address kinds ──────────────────────────────────────────────
//
// A wallet may surface either its master stealth address ("main") or a
// per-index subaddress derived from the same master seed via the
// DeriveSubaddress* primitives below. Senders need to know which one
// they're paying because the on-chain ECDH pub R is computed differently
// (R = r·G for main, R = r·B_i for subaddress).
//
// The two encodings live in the same base58check space but use distinct
// version bytes and distinct payload lengths, so a decoder can always
// classify by inspection. Subaddress encodings additionally carry the
// 32-bit index in their payload, so the receiver doesn't have to side-
// channel that integer to the sender.
enum class AddressKind : uint8_t {
    Main        = 0,
    Subaddress  = 1,
};

struct ParsedStealth {
    AddressKind     kind{AddressKind::Main};
    StealthAddress  address{};
    uint32_t        subaddress_index{0};  // 0 iff kind == Main
};

// Classify and decode any stealth-address string in one call. Returns
// nullopt for invalid encodings.
std::optional<ParsedStealth> ParseStealthAddress(std::string_view encoded);

// Encode a subaddress (A_i, B_i) at index i (i ≥ 1). Returns "" for
// invalid input.
std::string EncodeSubaddress(const StealthAddress& a, uint32_t index);

// Decode a subaddress encoding only. Returns nullopt if the input is
// not a subaddress (e.g. it's the main format, or invalid).
std::optional<ParsedStealth> DecodeSubaddress(std::string_view encoded);

// Compute the per-output "tx pubkey" R that the sender wires onto a
// confidential output. The formula depends on the recipient address
// kind:
//
//   * Main address (A, B):   R = r · G   (legacy CryptoNote-style)
//   * Subaddress  (A_i, B_i): R = r · B_i
//
// The receiver scans uniformly: shared = a · R reproduces r·A in the
// main case (since A = a·G ⇒ r·A = a·R) and r·A_i in the subaddress
// case (since A_i = a·B_i ⇒ a·R = a·r·B_i = r·A_i). The B-keyed R is
// what makes a single master view scalar `a` recover payments to any
// subaddress without leaking the subaddress index to the chain.
std::optional<PointBytes> ComputeStealthR(
    const CKey& r,
    const StealthAddress& a,
    AddressKind kind);

// Derive the per-output deterministic 32-byte secret used for downstream
// derivations. shared = SHA256("pricoin/stealth/secret-v1" || S || index).
std::array<unsigned char, 32> DeriveSharedSecret(
    const PointBytes& ecdh_point, uint32_t output_index);

// Compute the one-time recipient pubkey P = shared * G + B.
// Returns nullopt if the resulting point is the identity (negligible probability).
std::optional<CPubKey> DeriveOneTimePubkey(
    const std::array<unsigned char, 32>& shared, const CPubKey& spend_pubkey);

// Inverse of DeriveOneTimePubkey for use during scanning. Given the on-chain
// one-time pubkey P_observed and the per-output shared secret, returns
// B_candidate = P_observed − shared·G — the spend-point of the recipient
// identity (master B for main payments, B_i for subaddress payments).
// Compare B_candidate against the wallet's known B set to identify which
// subaddress (if any) owns the output.
std::optional<PointBytes> RecoverSpendPointFromOneTime(
    const CPubKey& one_time_pubkey,
    const std::array<unsigned char, 32>& shared);

// Compute the one-time private key p = shared + b (mod n), corresponding to
// the pubkey returned by DeriveOneTimePubkey for the same shared/spend pair.
std::optional<CKey> DeriveOneTimePriv(
    const std::array<unsigned char, 32>& shared, const CKey& spend_priv);

// Per-output rangeproof rewind nonce. Both sender and receiver derive the
// same 32 bytes from the same shared secret.
std::array<unsigned char, 32> DeriveRangeProofNonce(
    const PointBytes& ecdh_point, uint32_t output_index);

// ─── Subaddresses ───────────────────────────────────────────────
//
// CryptoNote-style per-index identities derived deterministically from the
// master (a, b). For subaddress index `i ≥ 1`:
//
//     m_i = H_subaddr(a ‖ i)        (32-byte scalar mod n)
//     b_i = b + m_i      (mod n)    (subaddress spend scalar)
//     B_i = B + m_i · G             (subaddress spend point — same scalar)
//     A_i = a · B_i                 (subaddress view point — NOT a·G)
//
// `A_i = a · B_i` (rather than `a · G`) is the key trick: it makes the
// derived address unlinkable to the master and to other subaddresses, while
// still letting the master view scalar `a` recover any payment to any index.
//
// Senders, given a subaddress payload `(A_i, B_i)`, compute
//     R = r · B_i    (NOT r · G)
//     shared = H(... ‖ r · A_i ‖ idx)
//     P      = shared · G + B_i
// The receiver scans every output uniformly: S = a · R, candidate B_i =
// P − shared·G, look up B_i in {known B's}. Same code path covers main and
// subaddress payments — only the lookup table differs.
//
// Index 0 is reserved for the main identity; DeriveSubaddress* return
// nullopt for index 0 to force callers to use the master keys directly.

struct Subaddress {
    uint32_t        index{0};
    StealthAddress  public_address;  // (A_i, B_i)
    CKey            spend_priv;      // b_i — unset for view-only derivation
};

// Derive subaddress index `i` (i ≥ 1) from the master scalars (a, b).
// Returns nullopt for i == 0 or in the negligible case of an invalid
// scalar after rehashing.
std::optional<Subaddress> DeriveSubaddress(
    const CKey& view_priv,
    const CKey& spend_priv,
    uint32_t index);

// View-only variant: derives (A_i, B_i) given the master view scalar a and
// master spend point B. The returned Subaddress has spend_priv unset.
std::optional<Subaddress> DeriveSubaddressPublic(
    const CKey& view_priv,
    const CPubKey& spend_pubkey,
    uint32_t index);

// Self-test for the subaddress derivation — invoked at daemon startup via
// pricoin::ct::RunSelfTest. Throws on failure.
void RunSubaddressSelfTest();

} // namespace pricoin::stealth

#endif // BITCOIN_PRICOIN_STEALTH_H
