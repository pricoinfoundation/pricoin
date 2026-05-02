// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRICOIN_CT_H
#define BITCOIN_PRICOIN_CT_H

#include <serialize.h>

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace pricoin::ct {

inline constexpr size_t kCommitmentSize = 33;
inline constexpr size_t kBlindingSize = 32;
inline constexpr size_t kMaxRangeProofSize = 5134; // secp256k1-zkp's worst case

using BlindingFactor = std::array<unsigned char, kBlindingSize>;
using SerializedCommitment = std::array<unsigned char, kCommitmentSize>;
using RangeProof = std::vector<unsigned char>;

// Pedersen commitment serialized as 33 bytes (8/9 prefix + 32-byte X).
struct Commitment {
    SerializedCommitment bytes{};

    static std::optional<Commitment> Create(uint64_t value, const BlindingFactor& blind);
    bool operator==(const Commitment&) const = default;

    SERIALIZE_METHODS(Commitment, obj) { READWRITE(obj.bytes); }
};

// Verify Pedersen sum: Σ(in commitments) − Σ(out commitments) − fee*H = 0.
// `transparent_fee` is the cleartext fee value paid to the explicit fee
// output; it is folded into the balance check by the verifier without
// needing a separate commitment from the sender.
bool VerifySumZero(std::span<const Commitment> in_commits,
                   std::span<const Commitment> out_commits,
                   uint64_t transparent_fee);

// Compute a blinding factor that makes the sum balance: solve for `out_n`
// such that Σ(in_blinds) − Σ(other_out_blinds) − out_n = 0. Used by the
// sender when constructing a transaction.
std::optional<BlindingFactor> BalancingBlind(
    std::span<const BlindingFactor> in_blinds,
    std::span<const BlindingFactor> out_blinds_except_last);

// Generate a Borromean rangeproof committing to `value` with `blind`. The
// proof shows the committed value lies in [0, 2^64). `extra_commit` binds
// the proof to additional context (e.g., the output's scriptPubKey) so it
// can't be replayed onto a different output. `nonce` is the sender-chosen
// secret used by the recipient to rewind the proof.
std::optional<RangeProof> CreateRangeProof(
    uint64_t value,
    const BlindingFactor& blind,
    const Commitment& commit,
    std::span<const unsigned char> extra_commit,
    const BlindingFactor& nonce);

// Verify a rangeproof. Returns the value range [min,max] as proven (the
// Borromean construction reveals these bounds, not the exact value).
struct VerifiedRange { uint64_t min_value; uint64_t max_value; };
std::optional<VerifiedRange> VerifyRangeProof(
    const Commitment& commit,
    std::span<const unsigned char> proof,
    std::span<const unsigned char> extra_commit);

// Recover (value, blind, message) from a rangeproof using the recipient's
// `nonce` (typically derived via ECDH between the sender's tx pubkey and
// the recipient's view key).
struct RewindResult {
    uint64_t value;
    BlindingFactor blind;
    std::vector<unsigned char> message;
};
std::optional<RewindResult> RewindRangeProof(
    const Commitment& commit,
    std::span<const unsigned char> proof,
    std::span<const unsigned char> extra_commit,
    const BlindingFactor& nonce);

// Phase 2b self-test: round-trip a commitment + rangeproof end-to-end.
// Throws std::runtime_error on failure. Used by the daemon at startup
// while the wrapper is unstable; remove once the integration tests cover
// the surface.
//
// `progress` (optional) is fired at the start of each major sub-section
// — used by init.cpp to surface stage names on the splash screen so the
// 2-5 second startup wait isn't an unexplained hang.
using SelfTestProgressFn = std::function<void(const std::string&)>;
void RunSelfTest(const SelfTestProgressFn& progress = {});

} // namespace pricoin::ct

#endif // BITCOIN_PRICOIN_CT_H
