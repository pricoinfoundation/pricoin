// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pricoin/validation.h>

#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <hash.h>
#include <pricoin/ct.h>
#include <pricoin/cttx.h>
#include <pricoin/ringsig.h>
#include <primitives/transaction.h>
#include <secp256k1.h>
#include <secp256k1_generator.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>

#include <unordered_set>

namespace pricoin {

namespace {

// In-memory global key-image set. Phase 4b MVP: not persisted; the daemon
// rebuilds the set as it replays blocks at startup (the verifier inserts
// each key image it sees into this set as it accepts a v4 ring tx).
struct KIHash {
    size_t operator()(const ringsig::Point& p) const noexcept {
        // First 8 bytes of the compressed pubkey are already uniformly distributed.
        size_t h = 0;
        std::memcpy(&h, p.data(), sizeof(h));
        return h;
    }
};
Mutex g_ki_mutex;
std::unordered_set<ringsig::Point, KIHash> g_key_images GUARDED_BY(g_ki_mutex);

// Compute the message that ring sigs commit to: the tx serialized without
// witness AND with all ring-sig fields zeroed out so the sig binds to the
// tx fields without being reflexive.
uint256 ComputeRingMessage(const CTransaction& tx)
{
    CMutableTransaction mtx{tx};
    for (auto& ri : mtx.ct_bundle.ring_inputs) {
        ri.sig = ringsig::Signature{};
    }
    HashWriter hw{};
    hw << TX_NO_WITNESS(CTransaction{std::move(mtx)});
    return hw.GetSHA256();
}

// Compute W_i = C_i − C_pseudo as a compressed pubkey, via the helper in
// pricoin/cttx.cpp.
std::optional<ringsig::Point> CommitDelta(
    const ct::Commitment& C_i, const ct::Commitment& C_pseudo)
{
    return ct::SubtractCommitments(C_i, C_pseudo);
}

bool VerifyDirectInputs(
    const CTransaction& tx,
    const CCoinsViewCache& inputs,
    int nSpendHeight,
    TxValidationState& state)
{
    if (tx.vin.size() != tx.ct_bundle.input_commitments.size()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-input-count");
    }
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const COutPoint& prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        if (coin.IsSpent()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-spent-prevout");
        }
        if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY) {
            return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "bad-txns-premature-spend-of-coinbase",
                strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
        }
        ct::Commitment expected{};
        if (coin.IsConfidential()) {
            expected = coin.commitment;
        } else {
            if (!MoneyRange(coin.out.nValue)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputvalues-outofrange");
            }
            ct::BlindingFactor zero_blind{};
            auto built = ct::Commitment::Create(static_cast<uint64_t>(coin.out.nValue), zero_blind);
            if (!built) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-input-commit-construction");
            }
            expected = *built;
        }
        if (expected != tx.ct_bundle.input_commitments[i]) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-input-commit-mismatch",
                strprintf("vin[%u] claims input commitment that does not match prev output", i));
        }
    }
    return true;
}

bool VerifyRingInputs(
    const CTransaction& tx,
    const CCoinsViewCache& inputs,
    int nSpendHeight,
    TxValidationState& state,
    std::vector<ct::Commitment>& effective_input_commits)
{
    const uint256 msg = ComputeRingMessage(tx);
    for (size_t idx = 0; idx < tx.ct_bundle.ring_inputs.size(); ++idx) {
        const auto& ri = tx.ct_bundle.ring_inputs[idx];
        if (ri.ring.empty()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-empty-ring");
        }
        if (ri.sig.s.size() != ri.ring.size()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-sig-size");
        }

        // Phase 4b-mini: single-layer CLSAG over spend pubkeys. Verifier just
        // builds the ring of P's. Multi-layer (RingCT proper) needs correct
        // commitment-to-pubkey conversion and is deferred. See sender-side
        // comment in src/wallet/rpc/pricoin_ct.cpp for the security gap.
        std::vector<ringsig::Point> ring_p(ri.ring.size());
        for (size_t k = 0; k < ri.ring.size(); ++k) {
            const COutPoint op{Txid::FromUint256(ri.ring[k].hash), ri.ring[k].n};
            const Coin& c = inputs.AccessCoin(op);
            if (c.IsSpent()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-ring-member-missing",
                    strprintf("ring[%u][%u]=%s:%u is spent or absent (have_in_view=%d)",
                              (unsigned)idx, (unsigned)k, op.hash.ToString(), op.n, (int)inputs.HaveCoin(op)));
            }
            if (!c.IsConfidential()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-ring-member-missing",
                    strprintf("ring[%u][%u] is not confidential", (unsigned)idx, (unsigned)k));
            }
            if (c.IsCoinBase() && nSpendHeight - c.nHeight < COINBASE_MATURITY) {
                return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "bad-pct-ring-member-immature");
            }
            ring_p[k] = c.one_time_pubkey;
        }

        // Key image must not be in the committed set.
        {
            LOCK(g_ki_mutex);
            if (g_key_images.contains(ri.sig.key_image)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-double-spend-keyimage");
            }
        }

        if (!ringsig::Verify(std::span<const ringsig::Point>{ring_p}, ri.sig, msg)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-ring-sig-invalid");
        }
        // Note: insertion into g_key_images happens only at block-connect via
        // CommitRingKeyImages(), so mempool-acceptance can be idempotent
        // (PreChecks may re-run validation) without rejecting our own tx.

        // The pseudo commitment is the input's contribution to the bundle's
        // tally — it's what the verifier sums in place of input_commitments[i].
        effective_input_commits.push_back(ri.pseudo_commitment);
    }
    return true;
}

} // namespace

bool VerifyConfidentialContextual(
    const CTransaction& tx,
    const CCoinsViewCache& inputs,
    int nSpendHeight,
    TxValidationState& state,
    CAmount& txfee_out)
{
    if (tx.version != PRICOIN_CT_VERSION) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-not-ct-version");
    }
    if (!inputs.HaveInputs(tx)) {
        return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent");
    }

    const bool has_direct = !tx.ct_bundle.input_commitments.empty();
    const bool has_ring = !tx.ct_bundle.ring_inputs.empty();
    if (has_direct && has_ring) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-mixed-input-modes");
    }
    if (!has_direct && !has_ring) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-no-inputs");
    }

    std::vector<ct::Commitment> effective_input_commits;
    if (has_direct) {
        if (!VerifyDirectInputs(tx, inputs, nSpendHeight, state)) return false;
        effective_input_commits = tx.ct_bundle.input_commitments;
    } else {
        if (!VerifyRingInputs(tx, inputs, nSpendHeight, state, effective_input_commits)) return false;
    }

    // Verify rangeproofs on outputs.
    for (const auto& out : tx.ct_bundle.outputs) {
        const std::span<const unsigned char> spk_span{out.script_pubkey};
        const std::span<const unsigned char> proof_span{out.rangeproof};
        if (!ct::VerifyRangeProof(out.commitment, proof_span, spk_span)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-rangeproof-invalid");
        }
    }
    // Verify tally with the effective input commitments + transparent fee.
    std::vector<ct::Commitment> out_commits;
    out_commits.reserve(tx.ct_bundle.outputs.size());
    for (const auto& o : tx.ct_bundle.outputs) out_commits.push_back(o.commitment);
    if (!ct::VerifySumZero(effective_input_commits, out_commits, tx.ct_bundle.transparent_fee)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-tally");
    }

    if (tx.ct_bundle.transparent_fee > static_cast<uint64_t>(MAX_MONEY)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-fee-toolarge");
    }
    txfee_out = static_cast<CAmount>(tx.ct_bundle.transparent_fee);
    return true;
}

void CommitRingKeyImages(const CTransaction& tx)
{
    if (tx.version != PRICOIN_CT_VERSION) return;
    LOCK(g_ki_mutex);
    for (const auto& ri : tx.ct_bundle.ring_inputs) {
        g_key_images.insert(ri.sig.key_image);
    }
}

void UncommitRingKeyImages(const CTransaction& tx)
{
    if (tx.version != PRICOIN_CT_VERSION) return;
    LOCK(g_ki_mutex);
    for (const auto& ri : tx.ct_bundle.ring_inputs) {
        g_key_images.erase(ri.sig.key_image);
    }
}

} // namespace pricoin
