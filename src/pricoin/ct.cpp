// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pricoin/ct.h>

#include <secp256k1.h>
#include <secp256k1_generator.h>
#include <secp256k1_rangeproof.h>

#include <crypto/sha256.h>
#include <logging.h>
#include <pricoin/adaptor_joint_ringsig.h>
#include <pricoin/adaptor_ringsig.h>
#include <pricoin/cttx.h>
#include <pricoin/joint_ringsig.h>
#include <pricoin/joint_stealth.h>
#include <pricoin/ringsig.h>
#include <pricoin/btc_musig2_nonce_policy.h>
#include <pricoin/clsag_nonce_policy.h>
#include <swap/atomic_swap_e2e_test.h>
#include <swap/btc_adaptor_schnorr.h>
#include <swap/btc_musig2_adaptor.h>
#include <swap/refund.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <streams.h>
#include <sync.h>

#include <cstring>
#include <stdexcept>
#include <string>

namespace pricoin::ct {

namespace {

// Process-wide non-static secp256k1 context for the privacy-module APIs
// (rangeproof_* refuses secp256k1_context_static). Initialised lazily on
// first use.
Mutex g_ctx_mutex;
secp256k1_context* g_ctx GUARDED_BY(g_ctx_mutex){nullptr};

secp256k1_context* Ctx() EXCLUSIVE_LOCKS_REQUIRED(g_ctx_mutex)
{
    if (!g_ctx) {
        g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        if (!g_ctx) throw std::runtime_error("secp256k1_context_create failed");
        // Re-randomize the context to harden against side-channel attacks.
        unsigned char seed[32];
        GetRandBytes(seed);
        if (!secp256k1_context_randomize(g_ctx, seed)) {
            // Non-fatal — context still works without randomization.
        }
    }
    return g_ctx;
}

bool ParseCommitment(const Commitment& c, secp256k1_pedersen_commitment& out)
{
    LOCK(g_ctx_mutex);
    return secp256k1_pedersen_commitment_parse(Ctx(), &out, c.bytes.data()) == 1;
}

// Self-test-only bundle builder. Builds a v4 bundle with TRANSPARENT
// recipients (one_time_pubkey / tx_pubkey are left zero). Production
// stealth-paying flows live in src/wallet/rpc/pricoin_ct.cpp where R, otp,
// and the rangeproof rewind nonce are derived per-output from the
// recipient's stealth address — DO NOT call this builder for stealth
// payments; the recipient won't be able to scan the output.
struct CTBuildResultSelfTest {
    CTBundle bundle;
    std::vector<BlindingFactor> output_blinds;
};

BlindingFactor DerivePerOutputNonceSelfTest(const BlindingFactor& seed, uint32_t index)
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

std::optional<CTBuildResultSelfTest> BuildBundleSelfTest(
    std::span<const std::pair<uint64_t, BlindingFactor>> in_values_blinds,
    std::span<const std::pair<uint64_t, std::vector<unsigned char>>> out_values_scripts,
    uint64_t transparent_fee,
    const BlindingFactor& nonce_seed)
{
    if (out_values_scripts.empty()) return std::nullopt;
    uint64_t in_total = 0;
    for (const auto& [v, _] : in_values_blinds) in_total += v;
    uint64_t out_total = 0;
    for (const auto& [v, _] : out_values_scripts) out_total += v;
    if (in_total != out_total + transparent_fee) return std::nullopt;

    CTBuildResultSelfTest result;
    auto& bundle = result.bundle;
    bundle.transparent_fee = transparent_fee;

    bundle.input_commitments.reserve(in_values_blinds.size());
    for (const auto& [v, blind] : in_values_blinds) {
        auto c = Commitment::Create(v, blind);
        if (!c) return std::nullopt;
        bundle.input_commitments.push_back(*c);
    }

    const size_t n_out = out_values_scripts.size();
    result.output_blinds.resize(n_out);
    for (size_t i = 0; i + 1 < n_out; ++i) {
        GetRandBytes(result.output_blinds[i]);
    }
    std::vector<BlindingFactor> in_blinds_vec;
    in_blinds_vec.reserve(in_values_blinds.size());
    for (const auto& [_, b] : in_values_blinds) in_blinds_vec.push_back(b);
    std::span<const BlindingFactor> other_outs{result.output_blinds.data(), n_out - 1};
    auto last_blind = BalancingBlind(in_blinds_vec, other_outs);
    if (!last_blind) return std::nullopt;
    result.output_blinds.back() = *last_blind;

    bundle.outputs.reserve(n_out);
    for (size_t i = 0; i < n_out; ++i) {
        const auto& [value, script] = out_values_scripts[i];
        const auto& blind = result.output_blinds[i];
        auto commit = Commitment::Create(value, blind);
        if (!commit) return std::nullopt;
        const std::span<const unsigned char> script_span{script.data(), script.size()};
        auto nonce = DerivePerOutputNonceSelfTest(nonce_seed, static_cast<uint32_t>(i));
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

// Self-test-only structural verifier for CT bundles built with transparent
// inputs. Checks per-output rangeproofs and Pedersen tally over
// input_commitments + outputs + transparent_fee. Does NOT verify ring
// signatures or pseudo commitments — the consensus path is
// pricoin::VerifyConfidentialContextual in pricoin/validation.cpp.
bool VerifyBundleSelfTest(const CTBundle& bundle)
{
    if (bundle.outputs.empty()) return false;
    for (const auto& out : bundle.outputs) {
        const std::span<const unsigned char> script_span{
            out.script_pubkey.data(), out.script_pubkey.size()};
        const std::span<const unsigned char> proof_span{
            out.rangeproof.data(), out.rangeproof.size()};
        if (!VerifyRangeProof(out.commitment, proof_span, script_span)) {
            return false;
        }
    }
    std::vector<Commitment> out_commits;
    out_commits.reserve(bundle.outputs.size());
    for (const auto& out : bundle.outputs) out_commits.push_back(out.commitment);
    return VerifySumZero(bundle.input_commitments, out_commits, bundle.transparent_fee);
}

bool SerializeCommitment(const secp256k1_pedersen_commitment& in, Commitment& out)
{
    LOCK(g_ctx_mutex);
    return secp256k1_pedersen_commitment_serialize(Ctx(), out.bytes.data(), &in) == 1;
}

} // namespace

std::optional<Commitment> Commitment::Create(uint64_t value, const BlindingFactor& blind)
{
    secp256k1_pedersen_commitment raw;
    {
        LOCK(g_ctx_mutex);
        if (!secp256k1_pedersen_commit(Ctx(), &raw, blind.data(), value, secp256k1_generator_h)) {
            return std::nullopt;
        }
    }
    Commitment out;
    if (!SerializeCommitment(raw, out)) return std::nullopt;
    return out;
}

bool VerifySumZero(std::span<const Commitment> in_commits,
                   std::span<const Commitment> out_commits,
                   uint64_t transparent_fee)
{
    // The fee is verified by treating it as an additional output commitment
    // with a known value and zero blinding factor: C_fee = fee*H + 0*G.
    // We allocate storage for the parsed commitments and pointer arrays
    // because secp256k1_pedersen_verify_tally takes arrays of pointers.
    std::vector<secp256k1_pedersen_commitment> parsed_in(in_commits.size());
    std::vector<secp256k1_pedersen_commitment> parsed_out(out_commits.size() + 1);
    std::vector<const secp256k1_pedersen_commitment*> in_ptrs(in_commits.size());
    std::vector<const secp256k1_pedersen_commitment*> out_ptrs(out_commits.size() + 1);

    for (size_t i = 0; i < in_commits.size(); ++i) {
        if (!ParseCommitment(in_commits[i], parsed_in[i])) return false;
        in_ptrs[i] = &parsed_in[i];
    }
    for (size_t i = 0; i < out_commits.size(); ++i) {
        if (!ParseCommitment(out_commits[i], parsed_out[i])) return false;
        out_ptrs[i] = &parsed_out[i];
    }
    // Build the implicit fee commitment.
    BlindingFactor zero_blind{};
    {
        LOCK(g_ctx_mutex);
        if (!secp256k1_pedersen_commit(Ctx(), &parsed_out.back(),
                                       zero_blind.data(), transparent_fee,
                                       secp256k1_generator_h)) {
            return false;
        }
        out_ptrs.back() = &parsed_out.back();

        return secp256k1_pedersen_verify_tally(Ctx(),
                                               in_ptrs.data(), in_ptrs.size(),
                                               out_ptrs.data(), out_ptrs.size()) == 1;
    }
}

std::optional<BlindingFactor> BalancingBlind(
    std::span<const BlindingFactor> in_blinds,
    std::span<const BlindingFactor> out_blinds_except_last)
{
    // Compute the blind for the last output as
    //     last = Σ in_blinds − Σ other_out_blinds
    // so that all blinds sum to zero (which is the precondition for the
    // commitments to balance under matching values).
    const size_t total = in_blinds.size() + out_blinds_except_last.size();
    if (total == 0) return BlindingFactor{};

    std::vector<const unsigned char*> ptrs;
    ptrs.reserve(total);
    for (const auto& b : in_blinds) ptrs.push_back(b.data());
    for (const auto& b : out_blinds_except_last) ptrs.push_back(b.data());

    BlindingFactor out{};
    LOCK(g_ctx_mutex);
    if (!secp256k1_pedersen_blind_sum(Ctx(), out.data(), ptrs.data(),
                                      total, in_blinds.size())) {
        return std::nullopt;
    }
    return out;
}

std::optional<RangeProof> CreateRangeProof(
    uint64_t value,
    const BlindingFactor& blind,
    const Commitment& commit,
    std::span<const unsigned char> extra_commit,
    const BlindingFactor& nonce)
{
    secp256k1_pedersen_commitment raw_commit;
    if (!ParseCommitment(commit, raw_commit)) return std::nullopt;

    RangeProof proof(kMaxRangeProofSize);
    size_t plen = proof.size();
    LOCK(g_ctx_mutex);
    int ok = secp256k1_rangeproof_sign(Ctx(),
                                       proof.data(), &plen,
                                       /*min_value=*/0,
                                       &raw_commit,
                                       blind.data(),
                                       nonce.data(),
                                       /*exp=*/0,
                                       /*min_bits=*/0,
                                       value,
                                       /*message=*/nullptr, /*msg_len=*/0,
                                       extra_commit.empty() ? nullptr : extra_commit.data(),
                                       extra_commit.size(),
                                       secp256k1_generator_h);
    if (!ok) return std::nullopt;
    proof.resize(plen);
    return proof;
}

std::optional<VerifiedRange> VerifyRangeProof(
    const Commitment& commit,
    std::span<const unsigned char> proof,
    std::span<const unsigned char> extra_commit)
{
    secp256k1_pedersen_commitment raw_commit;
    if (!ParseCommitment(commit, raw_commit)) return std::nullopt;

    VerifiedRange r{};
    LOCK(g_ctx_mutex);
    int ok = secp256k1_rangeproof_verify(Ctx(),
                                         &r.min_value, &r.max_value,
                                         &raw_commit,
                                         proof.data(), proof.size(),
                                         extra_commit.empty() ? nullptr : extra_commit.data(),
                                         extra_commit.size(),
                                         secp256k1_generator_h);
    if (!ok) return std::nullopt;
    return r;
}

std::optional<RewindResult> RewindRangeProof(
    const Commitment& commit,
    std::span<const unsigned char> proof,
    std::span<const unsigned char> extra_commit,
    const BlindingFactor& nonce)
{
    secp256k1_pedersen_commitment raw_commit;
    if (!ParseCommitment(commit, raw_commit)) return std::nullopt;

    RewindResult r{};
    std::vector<unsigned char> msg_buf(4096);
    size_t msg_len = msg_buf.size();
    uint64_t min_v = 0, max_v = 0;
    LOCK(g_ctx_mutex);
    int ok = secp256k1_rangeproof_rewind(Ctx(),
                                         r.blind.data(),
                                         &r.value,
                                         msg_buf.data(), &msg_len,
                                         nonce.data(),
                                         &min_v, &max_v,
                                         &raw_commit,
                                         proof.data(), proof.size(),
                                         extra_commit.empty() ? nullptr : extra_commit.data(),
                                         extra_commit.size(),
                                         secp256k1_generator_h);
    if (!ok) return std::nullopt;
    msg_buf.resize(msg_len);
    r.message = std::move(msg_buf);
    return r;
}

void RunSelfTest()
{
    // 1. Create commitments for two inputs that fund a single output and a
    //    transparent fee. Test the full signer flow: pick blinds, balance
    //    them, commit, prove, verify, sum-check.
    constexpr uint64_t kFee = 1000;
    constexpr uint64_t kIn1 = 50000;
    constexpr uint64_t kIn2 = 30000;
    constexpr uint64_t kOut = kIn1 + kIn2 - kFee;

    BlindingFactor b_in1{}, b_in2{}, b_out{};
    GetRandBytes(b_in1);
    GetRandBytes(b_in2);

    auto c_in1 = Commitment::Create(kIn1, b_in1);
    auto c_in2 = Commitment::Create(kIn2, b_in2);
    if (!c_in1 || !c_in2) throw std::runtime_error("ct self-test: commit failed");

    // Compute the output blinding so the sum balances.
    std::array<BlindingFactor, 2> ins{b_in1, b_in2};
    auto b_out_opt = BalancingBlind(ins, {});
    if (!b_out_opt) throw std::runtime_error("ct self-test: blind sum failed");
    b_out = *b_out_opt;
    auto c_out = Commitment::Create(kOut, b_out);
    if (!c_out) throw std::runtime_error("ct self-test: out commit failed");

    // Verify the sum balances with the explicit fee.
    std::array<Commitment, 2> in_arr{*c_in1, *c_in2};
    std::array<Commitment, 1> out_arr{*c_out};
    if (!VerifySumZero(in_arr, out_arr, kFee)) {
        throw std::runtime_error("ct self-test: sum did not balance");
    }
    // And it should NOT balance with the wrong fee.
    if (VerifySumZero(in_arr, out_arr, kFee + 1)) {
        throw std::runtime_error("ct self-test: sum balanced with wrong fee");
    }

    // 2. Rangeproof + verify + rewind round-trip.
    BlindingFactor nonce;
    GetRandBytes(nonce);
    const std::string extra = "pricoin ct self-test extra commit";
    std::span<const unsigned char> extra_span{
        reinterpret_cast<const unsigned char*>(extra.data()), extra.size()};

    auto proof = CreateRangeProof(kOut, b_out, *c_out, extra_span, nonce);
    if (!proof) throw std::runtime_error("ct self-test: rangeproof sign failed");

    auto verified = VerifyRangeProof(*c_out, *proof, extra_span);
    if (!verified) throw std::runtime_error("ct self-test: rangeproof verify failed");

    auto rewound = RewindRangeProof(*c_out, *proof, extra_span, nonce);
    if (!rewound) throw std::runtime_error("ct self-test: rangeproof rewind failed");
    if (rewound->value != kOut) throw std::runtime_error("ct self-test: rewound wrong value");
    if (rewound->blind != b_out) throw std::runtime_error("ct self-test: rewound wrong blind");

    // 3. CT bundle round-trip: build a 2-input, 2-output bundle (split the
    //    output among two scriptPubKeys), verify it, serialize + parse,
    //    verify again, mutate it, expect verification to fail.
    BlindingFactor seed;
    GetRandBytes(seed);
    std::vector<unsigned char> spk_a{0x76, 0xa9, 0x14, 'A','A','A','A','A','A','A','A','A','A','A','A','A','A','A','A', 0x88, 0xac};
    std::vector<unsigned char> spk_b{0x76, 0xa9, 0x14, 'B','B','B','B','B','B','B','B','B','B','B','B','B','B','B','B', 0x88, 0xac};
    std::array<std::pair<uint64_t, BlindingFactor>, 2> in_pairs{{
        {kIn1, b_in1},
        {kIn2, b_in2},
    }};
    std::array<std::pair<uint64_t, std::vector<unsigned char>>, 2> out_pairs{{
        {kOut / 2, spk_a},
        {kOut - kOut / 2, spk_b},
    }};
    auto built = BuildBundleSelfTest(in_pairs, out_pairs, kFee, seed);
    if (!built) throw std::runtime_error("ct self-test: bundle build failed");
    if (!VerifyBundleSelfTest(built->bundle)) throw std::runtime_error("ct self-test: bundle verify failed");

    // Serialize round-trip.
    DataStream ds;
    ds << built->bundle;
    CTBundle parsed;
    ds >> parsed;
    if (parsed != built->bundle) throw std::runtime_error("ct self-test: bundle serialize/parse mismatch");
    if (!VerifyBundleSelfTest(parsed)) throw std::runtime_error("ct self-test: parsed bundle verify failed");

    // Mutate: flip one bit in the first rangeproof — verification must fail.
    CTBundle tampered = parsed;
    tampered.outputs.at(0).rangeproof.at(0) ^= 0x01;
    if (VerifyBundleSelfTest(tampered)) throw std::runtime_error("ct self-test: tampered bundle verified");

    // Mutate: change the transparent fee — verification must fail.
    tampered = parsed;
    tampered.transparent_fee += 1;
    if (VerifyBundleSelfTest(tampered)) throw std::runtime_error("ct self-test: tampered fee verified");

    LogInfo("Pricoin CT bundle: 2-in/2-out demo serializes to %u bytes (%u per output rangeproof)",
            built->bundle.SerializedSize(),
            built->bundle.outputs.front().rangeproof.size());

    // 4. CTransaction format extension round-trip. Build a tx version 4 that
    //    carries the bundle, serialize + parse, confirm the bundle survives.
    CMutableTransaction mtx;
    mtx.version = PRICOIN_CT_VERSION;
    mtx.vin.push_back(CTxIn{COutPoint{Txid::FromUint256(uint256::ONE), 0}, CScript{}, 0xfffffffe});
    mtx.vin.push_back(CTxIn{COutPoint{Txid::FromUint256(uint256::ONE), 1}, CScript{}, 0xfffffffe});
    for (const auto& out : built->bundle.outputs) {
        mtx.vout.push_back(CTxOut{0, CScript(out.script_pubkey.begin(), out.script_pubkey.end())});
    }
    mtx.ct_bundle = built->bundle;

    DataStream tx_ds;
    tx_ds << TX_NO_WITNESS(mtx);
    CMutableTransaction parsed_tx;
    tx_ds >> TX_NO_WITNESS(parsed_tx);
    if (parsed_tx.version != PRICOIN_CT_VERSION) {
        throw std::runtime_error("ct self-test: version did not round-trip");
    }
    if (parsed_tx.ct_bundle != built->bundle) {
        throw std::runtime_error("ct self-test: tx-embedded bundle mismatch");
    }
    if (!VerifyBundleSelfTest(parsed_tx.ct_bundle)) {
        throw std::runtime_error("ct self-test: tx-embedded bundle did not verify");
    }
    LogInfo("Pricoin CT tx round-trip: version=%u tx serialized=%u bytes",
            parsed_tx.version, ::GetSerializeSize(TX_NO_WITNESS(parsed_tx)));

    // Phase 4a — exercise the CLSAG ring-signature primitives.
    ::pricoin::ringsig::RunSelfTest();
    LogInfo("Pricoin ringsig (CLSAG single-layer) self-test passed");

    // Atomic-swap stage 2b — cooperative CLSAG signing (single-layer
    // and multi-layer flows both exercised).
    ::pricoin::joint_ringsig::RunSelfTest();
    LogInfo("Pricoin joint_ringsig (cooperative CLSAG, single + multi-layer) self-test passed");

    // Atomic-swap phase 5 — adaptor-CLSAG (single-party + DLEQ).
    ::pricoin::adaptor_ringsig::RunSelfTest();
    LogInfo("Pricoin adaptor_ringsig (adaptor-CLSAG single-party + DLEQ) self-test passed");

    // Atomic-swap phase 5 — cooperative single-layer adaptor-CLSAG.
    ::pricoin::adaptor_joint_ringsig::RunSelfTest();
    LogInfo("Pricoin adaptor_joint_ringsig (cooperative adaptor-CLSAG single-layer) self-test passed");

    // Atomic-swap phase 5 — cooperative multi-layer adaptor-CLSAG (v4 outputs).
    ::pricoin::adaptor_joint_ringsig::RunSelfTestML();
    LogInfo("Pricoin adaptor_joint_ringsig (cooperative adaptor-CLSAG multi-layer) self-test passed");

    // Atomic-swap phase 5 — joint-stealth proof-of-possession (rogue-key defense).
    ::pricoin::joint_stealth::RunPoPSelfTest();
    LogInfo("Pricoin joint_stealth PoP (rogue-key defense) self-test passed");

    // Atomic-swap phase 5 — BIP340 adaptor-Schnorr (foreign-chain leg).
    ::pricoin::swap::btc_adaptor_schnorr::RunSelfTest();
    LogInfo("Pricoin btc_adaptor_schnorr (single-party BIP340 adaptor) self-test passed");

    // Atomic-swap phase 5 — cooperative MuSig2 + adaptor (2-of-N foreign leg).
    ::pricoin::swap::btc_musig2_adaptor::RunSelfTest();
    LogInfo("Pricoin btc_musig2_adaptor (2-of-N MuSig2 + adaptor) self-test passed");

    // Atomic-swap phase 5 — cooperative-CLSAG nonce-reuse policy (§4.1a).
    ::pricoin::clsag_nonce_policy::RunSelfTest();
    LogInfo("Pricoin clsag_nonce_policy (§4.1a nonce-reuse defence) self-test passed");

    // Atomic-swap phase 5 — BTC-side MuSig2 nonce-reuse policy (foreign-leg §4.1a analog).
    ::pricoin::btc_musig2_nonce_policy::RunSelfTest();
    LogInfo("Pricoin btc_musig2_nonce_policy (BTC-side §4.1a nonce-reuse defence) self-test passed");

    // Atomic-swap phase 5 — full cross-chain happy-path integration.
    // Walks Alice + Bob through one swap end-to-end (no chain) and
    // verifies the byte-equality of T_G + extract round-trips on both legs.
    ::pricoin::swap::atomic_swap_e2e_test::RunSelfTest();
    LogInfo("Pricoin atomic-swap E2E (cross-chain integration) self-test passed");

    // Atomic-swap phase 5 — refund-tx pre-signing (spec §6.2 step 7).
    // Validates timelock-constraint policy + non-adaptor cooperative
    // signing on both legs.
    ::pricoin::swap::refund::RunSelfTest();
    LogInfo("Pricoin swap refund (timelock policy + non-adaptor refund sigs) self-test passed");
}

} // namespace pricoin::ct
