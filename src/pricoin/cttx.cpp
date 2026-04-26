// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pricoin/cttx.h>

#include <crypto/sha256.h>
#include <random.h>
#include <streams.h>

#include <cstring>

namespace pricoin::ct {

namespace {

// SHA256(nonce_seed || little-endian uint32 index). Deterministic per-output
// nonce derivation so a sender can re-derive without storing one nonce per
// output, and so verification is reproducible.
BlindingFactor DerivePerOutputNonce(const BlindingFactor& seed, uint32_t index)
{
    unsigned char idx_le[4]{
        static_cast<unsigned char>(index & 0xff),
        static_cast<unsigned char>((index >> 8) & 0xff),
        static_cast<unsigned char>((index >> 16) & 0xff),
        static_cast<unsigned char>((index >> 24) & 0xff),
    };
    BlindingFactor out;
    CSHA256().Write(seed.data(), seed.size())
            .Write(idx_le, sizeof(idx_le))
            .Finalize(out.data());
    return out;
}

} // namespace

size_t CTBundle::SerializedSize() const
{
    SizeComputer sc;
    sc << *this;
    return sc.size();
}

std::optional<CTBuildResult> BuildBundle(
    std::span<const std::pair<uint64_t, BlindingFactor>> in_values_blinds,
    std::span<const std::pair<uint64_t, std::vector<unsigned char>>> out_values_scripts,
    uint64_t transparent_fee,
    const BlindingFactor& nonce_seed)
{
    if (out_values_scripts.empty()) return std::nullopt;

    // Sanity-check the value balance up front (saves cryptographic work on
    // obviously-broken inputs).
    uint64_t in_total = 0;
    for (const auto& [v, _] : in_values_blinds) in_total += v;
    uint64_t out_total = 0;
    for (const auto& [v, _] : out_values_scripts) out_total += v;
    if (in_total != out_total + transparent_fee) return std::nullopt;

    CTBuildResult result;
    auto& bundle = result.bundle;
    bundle.transparent_fee = transparent_fee;

    // Build input commitments.
    bundle.input_commitments.reserve(in_values_blinds.size());
    for (const auto& [v, blind] : in_values_blinds) {
        auto c = Commitment::Create(v, blind);
        if (!c) return std::nullopt;
        bundle.input_commitments.push_back(*c);
    }

    // Pick blinds for outputs: random for all but the last, then the last is
    // chosen so the entire blind sum balances against the input blinds. The
    // transparent fee is committed with zero blinding (its commitment is
    // implicitly fee*H).
    const size_t n_out = out_values_scripts.size();
    result.output_blinds.resize(n_out);
    for (size_t i = 0; i + 1 < n_out; ++i) {
        GetRandBytes(result.output_blinds[i]);
    }

    // Compute the last output blind as Σ in_blinds − Σ other_out_blinds.
    std::vector<BlindingFactor> in_blinds_vec;
    in_blinds_vec.reserve(in_values_blinds.size());
    for (const auto& [_, b] : in_values_blinds) in_blinds_vec.push_back(b);
    std::span<const BlindingFactor> other_outs{
        result.output_blinds.data(), n_out - 1};
    auto last_blind = BalancingBlind(in_blinds_vec, other_outs);
    if (!last_blind) return std::nullopt;
    result.output_blinds.back() = *last_blind;

    // Build output commitments + rangeproofs.
    bundle.outputs.reserve(n_out);
    for (size_t i = 0; i < n_out; ++i) {
        const auto& [value, script] = out_values_scripts[i];
        const auto& blind = result.output_blinds[i];

        auto commit = Commitment::Create(value, blind);
        if (!commit) return std::nullopt;

        const std::span<const unsigned char> script_span{
            script.data(), script.size()};
        auto nonce = DerivePerOutputNonce(nonce_seed, static_cast<uint32_t>(i));
        auto proof = CreateRangeProof(value, blind, *commit, script_span, nonce);
        if (!proof) return std::nullopt;

        bundle.outputs.push_back(CTOutput{
            .commitment = *commit,
            .rangeproof = *proof,
            .script_pubkey = script,
        });
    }
    return result;
}

bool VerifyBundle(const CTBundle& bundle)
{
    if (bundle.outputs.empty()) return false;

    // 1. Per-output rangeproof check, binding the proof to the output's
    //    scriptPubKey so it cannot be replayed onto a different output.
    for (const auto& out : bundle.outputs) {
        const std::span<const unsigned char> script_span{
            out.script_pubkey.data(), out.script_pubkey.size()};
        const std::span<const unsigned char> proof_span{
            out.rangeproof.data(), out.rangeproof.size()};
        if (!VerifyRangeProof(out.commitment, proof_span, script_span)) {
            return false;
        }
    }

    // 2. Pedersen tally with the implicit transparent-fee commitment.
    std::vector<Commitment> out_commits;
    out_commits.reserve(bundle.outputs.size());
    for (const auto& out : bundle.outputs) out_commits.push_back(out.commitment);
    return VerifySumZero(bundle.input_commitments, out_commits, bundle.transparent_fee);
}

} // namespace pricoin::ct
