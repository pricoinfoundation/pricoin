// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <swap/atomic_swap_e2e_test.h>

#include <key.h>
#include <pricoin/adaptor_joint_ringsig.h>
#include <pricoin/adaptor_ringsig.h>
#include <pricoin/joint_ringsig.h>
#include <pricoin/ringsig.h>
#include <pubkey.h>
#include <random.h>
#include <swap/btc_musig2_adaptor.h>
#include <uint256.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include <array>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace pricoin::swap::atomic_swap_e2e_test {

namespace pr   = ::pricoin::ringsig;
namespace par  = ::pricoin::adaptor_ringsig;
namespace pajr = ::pricoin::adaptor_joint_ringsig;
namespace pjr  = ::pricoin::joint_ringsig;
namespace bma  = ::pricoin::swap::btc_musig2_adaptor;

namespace {

void Check(bool cond, const char* what)
{
    if (!cond) {
        throw std::runtime_error(std::string("atomic-swap E2E self-test failed: ") + what);
    }
}

const secp256k1_context* SignCtx() { return GetSigningContext(); }

bool SeckeyVerify(const pr::Scalar& s)
{
    return secp256k1_ec_seckey_verify(secp256k1_context_static, s.data()) == 1;
}

// Random valid secp256k1 scalar.
pr::Scalar RandScalar()
{
    pr::Scalar s;
    while (true) {
        GetStrongRandBytes(s);
        if (SeckeyVerify(s)) return s;
    }
}

// k·G as 33-byte compressed pubkey.
pr::Point ScalarMultG(const pr::Scalar& k)
{
    secp256k1_pubkey p;
    if (!secp256k1_ec_pubkey_create(SignCtx(), &p, k.data())) {
        throw std::runtime_error("E2E: ec_pubkey_create failed");
    }
    pr::Point out;
    size_t len = 33;
    if (!secp256k1_ec_pubkey_serialize(secp256k1_context_static, out.data(), &len,
                                         &p, SECP256K1_EC_COMPRESSED) || len != 33) {
        throw std::runtime_error("E2E: ec_pubkey_serialize failed");
    }
    return out;
}

// A + B as 33-byte compressed pubkey.
pr::Point AddPoints(const pr::Point& a, const pr::Point& b)
{
    secp256k1_pubkey pa, pb;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &pa, a.data(), a.size())) {
        throw std::runtime_error("E2E: parse A failed");
    }
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &pb, b.data(), b.size())) {
        throw std::runtime_error("E2E: parse B failed");
    }
    const secp256k1_pubkey* ins[2] = {&pa, &pb};
    secp256k1_pubkey sum;
    if (!secp256k1_ec_pubkey_combine(secp256k1_context_static, &sum, ins, 2)) {
        throw std::runtime_error("E2E: pubkey_combine failed");
    }
    pr::Point out;
    size_t len = 33;
    if (!secp256k1_ec_pubkey_serialize(secp256k1_context_static, out.data(), &len,
                                         &sum, SECP256K1_EC_COMPRESSED) || len != 33) {
        throw std::runtime_error("E2E: serialize sum failed");
    }
    return out;
}

} // namespace

void RunSelfTest()
{
    // ─────────────────────────────────────────────────────────────
    // Phase 0 — setup. Both parties exchange keys + ring decoys.
    // ─────────────────────────────────────────────────────────────

    // PRIC-side ring of decoys; the joint output sits at index pi.
    constexpr size_t N = 4;
    constexpr size_t pi = 1;
    std::vector<pr::Point> ring(N);
    for (size_t i = 0; i < N; ++i) {
        ring[i] = ScalarMultG(RandScalar());
    }

    // PRIC spend-secret split between Alice and Bob: x_A + x_B == x_pi.
    const pr::Scalar x_A = RandScalar();
    const pr::Scalar x_B = RandScalar();
    const pr::Point  X_pub_A = ScalarMultG(x_A);
    const pr::Point  X_pub_B = ScalarMultG(x_B);
    const pr::Point  joint_P = AddPoints(X_pub_A, X_pub_B);
    ring[pi] = joint_P;

    // BTC-side keypairs (independent of PRIC keys — different chain,
    // different curve usage but same secp256k1 group).
    CKey btc_priv_A; btc_priv_A.MakeNewKey(/*fCompressed=*/true);
    CKey btc_priv_B; btc_priv_B.MakeNewKey(/*fCompressed=*/true);

    bma::Scalar btc_sk_A, btc_sk_B;
    std::memcpy(btc_sk_A.data(), btc_priv_A.begin(), 32);
    std::memcpy(btc_sk_B.data(), btc_priv_B.begin(), 32);
    // Even-y-normalize the signing keys exactly as the production wallet
    // does (NormalizeSeckeyEvenY) — AggregatePubkeys pins every key to its
    // even-y form, so the keys we sign with must correspond to it.
    Check(bma::NormalizeSeckeyEvenY(btc_sk_A), "normalize btc_sk_A");
    Check(bma::NormalizeSeckeyEvenY(btc_sk_B), "normalize btc_sk_B");
    CKey nbtc_A; nbtc_A.Set(btc_sk_A.begin(), btc_sk_A.end(), /*fCompressedIn=*/true);
    CKey nbtc_B; nbtc_B.Set(btc_sk_B.begin(), btc_sk_B.end(), /*fCompressedIn=*/true);
    const CPubKey btc_pub_A = nbtc_A.GetPubKey();   // even-y
    const CPubKey btc_pub_B = nbtc_B.GetPubKey();   // even-y

    // Aggregate BTC pubkey via MuSig2 keyagg.
    bma::KeyAggCache btc_cache;
    auto btc_agg_xonly = bma::AggregatePubkeys({btc_pub_A, btc_pub_B}, btc_cache);
    Check(btc_agg_xonly.has_value(), "BTC MuSig2 keyagg");

    // ─────────────────────────────────────────────────────────────
    // Phase 1 — Bob picks the cross-chain binding secret t.
    //   * T_G_pric  = t · G              (Point, 33-byte compressed)
    //   * T_H_pric  = t · H_p(joint_P)   (Point — generator dependent on PRIC pubkey)
    //   * T_G_btc   = t · G              (33 compressed bytes — IDENTICAL to T_G_pric)
    // The byte-equality of T_G across both chains is the cross-chain binding.
    // ─────────────────────────────────────────────────────────────

    const pr::Scalar t = RandScalar();
    const pr::Point  T_G_pric = ScalarMultG(t);

    auto adaptor_pric = par::ComputeAdaptorPoints(t, joint_P);
    Check(adaptor_pric.has_value(), "ComputeAdaptorPoints");
    Check(adaptor_pric->T_G == T_G_pric, "ComputeAdaptorPoints T_G consistency");

    bma::AdaptorPointCompressed T_G_btc;
    std::memcpy(T_G_btc.data(), T_G_pric.data(), 33);
    // ────── CROSS-CHAIN BINDING CHECK ──────
    // (Tautological as written, but the byte-by-byte equality is the
    // entire point — both legs use the EXACT same 33 bytes for T_G,
    // which is what makes the `t` extracted from one leg trivially
    // adapt the other.)
    Check(std::memcmp(T_G_btc.data(), adaptor_pric->T_G.data(), 33) == 0,
          "T_G byte-equality cross-chain");

    // DLEQ proof binding T_G and T_H (PRIC side).
    static constexpr char kLabel[] = "pricoin/atomic-swap-e2e/v1";
    const std::array<unsigned char, 16> session_payload{
        'a','t','o','m','i','c','-','s','w','a','p','-','e','2','e','1'};
    auto label_span   = std::span<const unsigned char>{
        reinterpret_cast<const unsigned char*>(kLabel), sizeof(kLabel) - 1};
    auto payload_span = std::span<const unsigned char>{
        session_payload.data(), session_payload.size()};

    auto dleq_t = par::MakeDLEQProof(t, joint_P, *adaptor_pric, label_span, payload_span);
    Check(dleq_t.has_value(), "MakeDLEQProof");
    Check(par::VerifyDLEQProof(joint_P, *adaptor_pric, *dleq_t, label_span, payload_span),
          "VerifyDLEQProof");

    // ─────────────────────────────────────────────────────────────
    // Phase 2 — PRIC-side cooperative adaptor-CLSAG pre-sig.
    // Both parties run rounds 1–3 honestly. Output: AdaptorPreSignature
    // that EITHER party can hold. (Adapt requires the secret t, which
    // only Bob has at this point.)
    // ─────────────────────────────────────────────────────────────

    const uint256 msg_pric = uint256::FromHex(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").value();

    auto share_A = pajr::NonceGenAdaptor(joint_P, X_pub_A, x_A, *adaptor_pric,
                                          label_span, payload_span);
    auto share_B = pajr::NonceGenAdaptor(joint_P, X_pub_B, x_B, *adaptor_pric,
                                          label_span, payload_span);
    Check(share_A.has_value() && share_B.has_value(), "NonceGenAdaptor A/B");
    Check(pajr::VerifyAdaptorNonceShare(joint_P, X_pub_A, *share_A, *adaptor_pric,
                                         label_span, payload_span),
          "VerifyAdaptorNonceShare A");
    Check(pajr::VerifyAdaptorNonceShare(joint_P, X_pub_B, *share_B, *adaptor_pric,
                                         label_span, payload_span),
          "VerifyAdaptorNonceShare B");

    std::array<pr::Point,                    2> X_pubs{X_pub_A, X_pub_B};
    std::array<pajr::AdaptorNonceShare,      2> shares{*share_A, *share_B};
    auto combined = pajr::CombineAndWalk(
        std::span<const pr::Point>{ring}, pi, msg_pric, *adaptor_pric, *dleq_t,
        std::span<const pr::Point>{X_pubs},
        std::span<const pajr::AdaptorNonceShare>{shares},
        label_span, payload_span);
    Check(combined.has_value(), "CombineAndWalk");

    auto cs_A = pajr::CooperativeCloseShareAdaptor(share_A->alpha, combined->c_pi, x_A);
    auto cs_B = pajr::CooperativeCloseShareAdaptor(share_B->alpha, combined->c_pi, x_B);
    Check(cs_A.has_value() && cs_B.has_value(), "CooperativeCloseShareAdaptor");

    std::array<pr::Scalar, 2> close_shares{*cs_A, *cs_B};
    auto presig_pric = pajr::AssembleAdaptorPreSig(
        *combined, std::span<const pr::Scalar>{close_shares}, pi, *adaptor_pric, *dleq_t);
    Check(presig_pric.has_value(), "AssembleAdaptorPreSig");
    // Pre-sig verifies off-chain. (Standard CLSAG verify of the
    // pre-sig WOULD fail until adapted with t.)
    Check(par::VerifyPreSignature(
              std::span<const pr::Point>{ring}, *presig_pric, msg_pric,
              label_span, payload_span),
          "VerifyPreSignature PRIC");

    // ─────────────────────────────────────────────────────────────
    // Phase 3 — BTC-side cooperative MuSig2 + adaptor pre-sig.
    // Both parties run nonce-gen / aggregate / process-with-T_G /
    // partial-sign / aggregate. Output: 64-byte BTC pre-signature.
    // ─────────────────────────────────────────────────────────────

    const uint256 msg_btc = uint256::FromHex(
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210").value();

    MuSig2SecNonce sec_A, sec_B;
    uint256 seed_A, seed_B;
    GetStrongRandBytes(seed_A);
    GetStrongRandBytes(seed_B);
    auto pn_A = bma::NonceGen(sec_A, btc_sk_A, btc_pub_A, msg_btc, btc_cache, seed_A);
    auto pn_B = bma::NonceGen(sec_B, btc_sk_B, btc_pub_B, msg_btc, btc_cache, seed_B);
    Check(pn_A.has_value() && pn_B.has_value(), "BTC MuSig2 NonceGen");

    auto aggn = bma::AggregateNonces({*pn_A, *pn_B});
    Check(aggn.has_value(), "BTC MuSig2 AggregateNonces");

    auto session = bma::ProcessNonces(*aggn, msg_btc, btc_cache, T_G_btc);
    Check(session.has_value(), "BTC MuSig2 ProcessNonces with adaptor");

    auto ps_A = bma::PartialSign(sec_A, btc_sk_A, btc_pub_A, btc_cache, *session);
    auto ps_B = bma::PartialSign(sec_B, btc_sk_B, btc_pub_B, btc_cache, *session);
    Check(ps_A.has_value() && ps_B.has_value(), "BTC MuSig2 PartialSign");

    auto presig_btc = bma::AggregatePartials(*session, {*ps_A, *ps_B});
    Check(presig_btc.has_value(), "BTC MuSig2 AggregatePartials");

    // BTC aggregate xonly pubkey for verification.
    XOnlyPubKey btc_agg_xpub{std::span<const unsigned char>{btc_agg_xonly->data(), 32}};
    // The pre-sig must NOT verify as a standard BIP340 sig until adapted.
    Check(!btc_agg_xpub.VerifySchnorr(msg_btc, *presig_btc),
          "BTC pre-sig must NOT verify before Adapt");

    // ─────────────────────────────────────────────────────────────
    // Phase 4 — happy path execution.
    //
    // Step 8 (per spec §6.2): Bob completes pre-sig 1 with t and
    // "broadcasts" the PRIC tx. The on-chain CLSAG signature reveals
    // (presig_pric.s_pi + t).
    //
    // Step 9: Alice extracts t from the on-chain PRIC sig, adapts the
    // BTC pre-sig, broadcasts BTC tx. Both parties have their target
    // asset.
    // ─────────────────────────────────────────────────────────────

    // Step 8: Bob adapts and "broadcasts".
    auto pric_sig = par::Adapt(*presig_pric, t,
                                 std::span<const pr::Point>{ring}, msg_pric);
    Check(pric_sig.has_value(), "PRIC Adapt");
    Check(pr::Verify(std::span<const pr::Point>{ring}, *pric_sig, msg_pric),
          "PRIC sig verifies under standard CLSAG");

    // Step 9: Alice extracts t from the on-chain PRIC sig.
    auto extracted_t_pric = par::Extract(
        std::span<const pr::Point>{ring}, *presig_pric, *pric_sig);
    Check(extracted_t_pric.has_value(), "PRIC Extract");
    Check(*extracted_t_pric == t, "extracted t matches Bob's t");

    // Convert the extracted PRIC scalar to BTC scalar (same 32 bytes).
    bma::Scalar t_btc;
    std::memcpy(t_btc.data(), extracted_t_pric->data(), 32);

    // Adapt the BTC pre-sig.
    auto btc_sig = bma::Adapt(*presig_btc, t_btc, session->nonce_parity);
    Check(btc_sig.has_value(), "BTC Adapt");
    Check(btc_agg_xpub.VerifySchnorr(msg_btc, *btc_sig),
          "BTC sig verifies under standard BIP340 (deployed XOnlyPubKey::VerifySchnorr)");

    // ─────────────────────────────────────────────────────────────
    // Phase 5 — extract symmetry. Anyone can also extract t from the
    // BTC sig + presig pair. This must yield the SAME 32 bytes —
    // both legs are different rituals around the same secret.
    // ─────────────────────────────────────────────────────────────

    auto extracted_t_btc = bma::Extract(*presig_btc, *btc_sig, session->nonce_parity);
    Check(extracted_t_btc.has_value(), "BTC Extract");
    Check(*extracted_t_btc == t_btc,
          "extracted t (BTC side) matches extracted t (PRIC side)");
    // And tying back to Bob's original choice:
    Check(std::memcmp(extracted_t_btc->data(), t.data(), 32) == 0,
          "BTC-extracted t matches Bob's original t bytes");

    // ─────────────────────────────────────────────────────────────
    // Phase 6 — adversarial: a wrong t cannot adapt either pre-sig
    // into something that verifies. (Belt and braces: the individual
    // module self-tests already cover wrong-t per leg; here we
    // confirm composition doesn't accidentally weaken either.)
    // ─────────────────────────────────────────────────────────────

    pr::Scalar wrong_t = t;
    wrong_t[0] ^= 0x01;

    // PRIC-side adapt with wrong t:
    auto bad_pric_sig = par::Adapt(*presig_pric, wrong_t,
                                     std::span<const pr::Point>{ring}, msg_pric);
    // par::Adapt verifies before returning, so wrong t → nullopt.
    Check(!bad_pric_sig.has_value(),
          "PRIC Adapt with wrong t must return nullopt");

    // BTC-side adapt with wrong t:
    bma::Scalar wrong_t_btc;
    std::memcpy(wrong_t_btc.data(), wrong_t.data(), 32);
    auto bad_btc_sig = bma::Adapt(*presig_btc, wrong_t_btc, session->nonce_parity);
    // BTC Adapt does not pre-verify (per libsecp256k1 contract), so
    // we must verify the result ourselves and confirm it fails.
    Check(bad_btc_sig.has_value(), "BTC Adapt(wrong t) returns a (bogus) sig");
    Check(!btc_agg_xpub.VerifySchnorr(msg_btc, *bad_btc_sig),
          "BTC Adapt(wrong t) sig must NOT verify");
}

} // namespace pricoin::swap::atomic_swap_e2e_test
