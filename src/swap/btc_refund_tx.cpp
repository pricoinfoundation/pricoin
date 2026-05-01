// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <swap/btc_refund_tx.h>

#include <key.h>
#include <pubkey.h>
#include <random.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <swap/btc_musig2_adaptor.h>

#include <cstring>
#include <stdexcept>
#include <string>

namespace pricoin::swap::btc_refund_tx {

namespace {

namespace bma = ::pricoin::swap::btc_musig2_adaptor;

void Check(bool cond, const char* what)
{
    if (!cond) {
        throw std::runtime_error(std::string("BTC refund-tx self-test failed: ") + what);
    }
}

CScript P2TRScriptFromXOnly(const std::array<unsigned char, 32>& xonly)
{
    return CScript() << OP_1 << std::vector<unsigned char>(xonly.begin(), xonly.end());
}

} // namespace

std::optional<BtcRefundTxBuilt> Build(const BtcRefundTxParams& params)
{
    if (params.funding_amount_sat <= 0) return std::nullopt;
    if (params.refund_amount_sat <= 0) return std::nullopt;
    if (params.refund_amount_sat >= params.funding_amount_sat) return std::nullopt;
    // 0 is valid: no timelock, claim-tx semantics (broadcastable immediately
    // once the funding confirms). Refund txs use a real height ≥ 1.
    if (params.nlocktime < 0) return std::nullopt;
    if (params.recipient_script_pubkey.empty()) return std::nullopt;
    // agg_xonly is fixed-size; just check it's not all-zero (sentinel
    // for "uninitialized") — a real x-only pub on the curve cannot be
    // zero (zero is the point at infinity, not a valid P2TR output).
    bool all_zero = true;
    for (unsigned char b : params.agg_xonly) if (b != 0) { all_zero = false; break; }
    if (all_zero) return std::nullopt;

    BtcRefundTxBuilt out;
    CMutableTransaction& tx = out.tx;

    tx.version = 2;  // BIP68/65 compatible.
    tx.nLockTime = static_cast<uint32_t>(params.nlocktime);

    // Input: spend the funding outpoint. nSequence < 0xffffffff so
    // nLockTime is enforced (BIP65 / standard CLTV behavior).
    CTxIn in;
    in.prevout = COutPoint{Txid::FromUint256(params.funding_txid), params.funding_vout};
    in.nSequence = 0xfffffffe;
    tx.vin.push_back(std::move(in));

    // Output: pay the refund recipient.
    CTxOut o;
    o.nValue = params.refund_amount_sat;
    o.scriptPubKey = CScript(
        params.recipient_script_pubkey.begin(),
        params.recipient_script_pubkey.end());
    tx.vout.push_back(std::move(o));

    // Spent output (the funding-tx output we're consuming) — needed
    // for the BIP341 sighash, which commits to amount + scriptPubKey
    // of every spent input.
    CTxOut spent_funding;
    spent_funding.nValue = params.funding_amount_sat;
    spent_funding.scriptPubKey = P2TRScriptFromXOnly(params.agg_xonly);

    std::vector<CTxOut> spent_outputs{spent_funding};
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::move(spent_outputs), /*force=*/true);
    if (!txdata.m_bip341_taproot_ready) return std::nullopt;
    if (!txdata.m_spent_outputs_ready) return std::nullopt;

    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;

    if (!SignatureHashSchnorr(
            out.sighash, execdata, tx, /*in_pos=*/0, SIGHASH_DEFAULT,
            SigVersion::TAPROOT, txdata, MissingDataBehavior::FAIL)) {
        return std::nullopt;
    }
    return out;
}

std::optional<CTransaction> Finalize(
    const BtcRefundTxBuilt& built,
    std::span<const unsigned char> sig64)
{
    if (sig64.size() != 64) return std::nullopt;
    if (built.tx.vin.empty()) return std::nullopt;

    CMutableTransaction tx = built.tx;
    // P2TR key-path-spend witness: a single 64-byte BIP340 sig (no
    // sighash byte appended because we used SIGHASH_DEFAULT).
    tx.vin[0].scriptWitness.stack.clear();
    tx.vin[0].scriptWitness.stack.emplace_back(sig64.begin(), sig64.end());

    return CTransaction(std::move(tx));
}

// ─────────────────────────────────────────────────────────────────
// Self-test
// ─────────────────────────────────────────────────────────────────

namespace {

void TestHappyPath()
{
    // Setup: two CKeys, MuSig2 keyagg → cache + agg_xonly.
    CKey priv_A; priv_A.MakeNewKey(true);
    CKey priv_B; priv_B.MakeNewKey(true);
    const CPubKey pub_A = priv_A.GetPubKey();
    const CPubKey pub_B = priv_B.GetPubKey();
    bma::Scalar sk_A, sk_B;
    std::memcpy(sk_A.data(), priv_A.begin(), 32);
    std::memcpy(sk_B.data(), priv_B.begin(), 32);

    bma::KeyAggCache cache;
    auto agg = bma::AggregatePubkeys({pub_A, pub_B}, cache);
    Check(agg.has_value(), "keyagg");

    // Build the refund tx.
    BtcRefundTxParams params;
    GetStrongRandBytes(params.funding_txid);
    params.funding_vout = 0;
    params.funding_amount_sat = 100'000'000;
    params.agg_xonly = *agg;
    // Recipient: another P2TR address (Bob's). Use his serialized
    // x-only pubkey as the recipient witness program — irrelevant for
    // the self-test's verification path; we only care about sighash
    // round-trip.
    XOnlyPubKey bob_xonly{pub_B};
    {
        CScript spk = CScript() << OP_1
            << std::vector<unsigned char>(bob_xonly.begin(), bob_xonly.end());
        params.recipient_script_pubkey.assign(spk.begin(), spk.end());
    }
    params.refund_amount_sat = 99'990'000;  // 10000 sat fee
    params.nlocktime = 800'000;

    auto built = Build(params);
    Check(built.has_value(), "Build");
    Check(built->tx.vin.size() == 1, "single input");
    Check(built->tx.vout.size() == 1, "single output");
    Check(built->tx.nLockTime == 800'000u, "nLockTime");
    Check(built->tx.vin[0].nSequence == 0xfffffffeu, "sequence enables CLTV");

    // Cooperatively sign the sighash via MuSig2 with no adaptor.
    MuSig2SecNonce sec_A, sec_B;
    uint256 seed_A, seed_B;
    GetStrongRandBytes(seed_A);
    GetStrongRandBytes(seed_B);
    auto pn_A = bma::NonceGen(sec_A, sk_A, pub_A, built->sighash, cache, seed_A);
    auto pn_B = bma::NonceGen(sec_B, sk_B, pub_B, built->sighash, cache, seed_B);
    Check(pn_A.has_value() && pn_B.has_value(), "NonceGen");

    auto aggn = bma::AggregateNonces({*pn_A, *pn_B});
    Check(aggn.has_value(), "AggregateNonces");

    // Non-adaptor refund branch — no T_G.
    auto session = bma::ProcessNonces(*aggn, built->sighash, cache, std::nullopt);
    Check(session.has_value(), "ProcessNonces");

    auto ps_A = bma::PartialSign(sec_A, sk_A, pub_A, cache, *session);
    auto ps_B = bma::PartialSign(sec_B, sk_B, pub_B, cache, *session);
    Check(ps_A.has_value() && ps_B.has_value(), "PartialSign");

    auto sig = bma::AggregatePartials(*session, {*ps_A, *ps_B});
    Check(sig.has_value(), "AggregatePartials");

    // Finalize: attach to the tx as a P2TR key-path witness.
    auto final_tx = Finalize(*built, *sig);
    Check(final_tx.has_value(), "Finalize");
    Check(final_tx->vin.size() == 1, "finalized has input");
    Check(final_tx->vin[0].scriptWitness.stack.size() == 1, "single witness item");
    Check(final_tx->vin[0].scriptWitness.stack[0].size() == 64, "64-byte witness");

    // Verify the witness signature against the agg_xonly + sighash —
    // exactly what bitcoind would do during script validation.
    XOnlyPubKey agg_xpub{std::span<const unsigned char>{agg->data(), 32}};
    auto& w = final_tx->vin[0].scriptWitness.stack[0];
    Check(agg_xpub.VerifySchnorr(built->sighash, w),
          "witness sig verifies under agg_xonly + sighash");

    // Sighash determinism: re-Build with same params produces same sighash.
    auto built2 = Build(params);
    Check(built2.has_value(), "rebuild");
    Check(built2->sighash == built->sighash, "sighash deterministic");

    // Sighash sensitivity: tweak nLockTime → different sighash.
    BtcRefundTxParams p_alt = params;
    p_alt.nlocktime = 800'001;
    auto built3 = Build(p_alt);
    Check(built3.has_value(), "build alt");
    Check(built3->sighash != built->sighash,
          "sighash sensitive to nLockTime");

    // Sighash sensitivity: different recipient → different sighash.
    BtcRefundTxParams p_alt2 = params;
    p_alt2.recipient_script_pubkey[2] ^= 0x01;
    auto built4 = Build(p_alt2);
    Check(built4.has_value(), "build alt2");
    Check(built4->sighash != built->sighash,
          "sighash sensitive to recipient");
}

void TestNegatives()
{
    BtcRefundTxParams base;
    base.funding_amount_sat = 100;
    GetStrongRandBytes(base.funding_txid);
    base.agg_xonly[0] = 1;
    base.recipient_script_pubkey = {0x51, 0x20, 0xaa, 0xbb};  // throwaway P2TR-like
    base.refund_amount_sat = 50;
    base.nlocktime = 1;

    Check(Build(base).has_value(), "happy minimal");

    auto p = base;
    p.funding_amount_sat = 0;
    Check(!Build(p).has_value(), "reject zero funding");

    p = base;
    p.refund_amount_sat = 0;
    Check(!Build(p).has_value(), "reject zero refund");

    p = base;
    p.refund_amount_sat = p.funding_amount_sat;
    Check(!Build(p).has_value(), "reject refund >= funding (no fee headroom)");

    // nlocktime = 0 is the CLAIM-tx mode (no timelock). Module covers
    // both refund (>0) and claim (=0) shapes; only negative is invalid.
    p = base;
    p.nlocktime = 0;
    Check(Build(p).has_value(), "accept zero nLockTime (claim mode)");
    p = base;
    p.nlocktime = -1;
    Check(!Build(p).has_value(), "reject negative nLockTime");

    p = base;
    p.recipient_script_pubkey.clear();
    Check(!Build(p).has_value(), "reject empty recipient");

    p = base;
    p.agg_xonly = {};  // all zeros
    Check(!Build(p).has_value(), "reject all-zero agg_xonly");

    // Finalize negatives.
    auto built = Build(base);
    Check(built.has_value(), "build for finalize negatives");
    std::array<unsigned char, 63> too_short{};
    Check(!Finalize(*built, too_short).has_value(), "reject 63-byte sig");
    std::array<unsigned char, 65> too_long{};
    Check(!Finalize(*built, too_long).has_value(), "reject 65-byte sig");
}

} // namespace

void RunSelfTest()
{
    TestNegatives();
    TestHappyPath();
}

} // namespace pricoin::swap::btc_refund_tx
