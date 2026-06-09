// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <swap/refund.h>

#include <key.h>
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

namespace pricoin::swap::refund {

TimelockCheck ValidateRefundTimelocks(const RefundTimelocks& t)
{
    if (t.pric_refund_height <= 0)         return TimelockCheck::PricNotPositive;
    if (t.foreign_refund_height <= 0)      return TimelockCheck::ForeignNotPositive;
    if (t.delta_min_blocks <= 0)           return TimelockCheck::DeltaMinNotPositive;
    if (t.foreign_refund_height <= t.pric_refund_height) {
        return TimelockCheck::OrderingViolation;
    }
    const int32_t delta = t.foreign_refund_height - t.pric_refund_height;
    if (delta < t.delta_min_blocks)        return TimelockCheck::DeltaTooSmall;
    return TimelockCheck::Ok;
}

const char* ExplainTimelockCheck(TimelockCheck c)
{
    switch (c) {
    case TimelockCheck::Ok:                  return "ok";
    case TimelockCheck::PricNotPositive:     return "pric_refund_height must be > 0";
    case TimelockCheck::ForeignNotPositive:  return "foreign_refund_height must be > 0";
    case TimelockCheck::DeltaMinNotPositive: return "delta_min_blocks must be > 0";
    case TimelockCheck::OrderingViolation:
        return "foreign_refund_height must be strictly greater than pric_refund_height "
               "(spec §6.2 step 7 — reversed-from-rev-1 ordering)";
    case TimelockCheck::DeltaTooSmall:
        return "foreign_refund_height − pric_refund_height < delta_min_blocks "
               "(insufficient buffer for Alice to claim foreign coin after Bob reveals t)";
    }
    return "unknown";
}

// ─────────────────────────────────────────────────────────────────
// Self-test
// ─────────────────────────────────────────────────────────────────

namespace {

namespace pr  = ::pricoin::ringsig;
namespace pjr = ::pricoin::joint_ringsig;
namespace bma = ::pricoin::swap::btc_musig2_adaptor;

void Check(bool cond, const char* what)
{
    if (!cond) {
        throw std::runtime_error(std::string("refund self-test failed: ") + what);
    }
}

const secp256k1_context* SignCtx() { return GetSigningContext(); }
const secp256k1_context* StaticCtx() { return secp256k1_context_static; }

bool SeckeyVerify(const pr::Scalar& s)
{
    return secp256k1_ec_seckey_verify(StaticCtx(), s.data()) == 1;
}

pr::Scalar RandScalar()
{
    pr::Scalar s;
    while (true) {
        GetStrongRandBytes(s);
        if (SeckeyVerify(s)) return s;
    }
}

pr::Point ScalarMultG(const pr::Scalar& k)
{
    secp256k1_pubkey p;
    if (!secp256k1_ec_pubkey_create(SignCtx(), &p, k.data())) {
        throw std::runtime_error("refund: ec_pubkey_create failed");
    }
    pr::Point out;
    size_t len = 33;
    if (!secp256k1_ec_pubkey_serialize(StaticCtx(), out.data(), &len,
                                         &p, SECP256K1_EC_COMPRESSED) || len != 33) {
        throw std::runtime_error("refund: ec_pubkey_serialize failed");
    }
    return out;
}

pr::Scalar AddScalars(const pr::Scalar& a, const pr::Scalar& b)
{
    pr::Scalar out = a;
    if (!secp256k1_ec_seckey_tweak_add(StaticCtx(), out.data(), b.data())) {
        throw std::runtime_error("refund: scalar add failed");
    }
    return out;
}

// Run cooperative non-adaptor CLSAG signing for two parties.
// This mirrors the (anon-namespace) CooperativeSignTwoParty in
// pricoin/joint_ringsig.cpp, but using the public primitives so we
// don't need to expose internal helpers. Used to sign the PRIC
// refund tx — which is the same cooperative protocol minus
// adaptor.
std::optional<pr::Signature> SignPricRefundCooperative(
    std::span<const pr::Point> ring,
    size_t pi,
    const pr::Scalar& x_A,
    const pr::Scalar& x_B,
    const uint256& msg)
{
    const pr::Point& P_pi = ring[pi];

    // Round 1.
    auto np_A = pjr::NonceGen(P_pi);
    auto np_B = pjr::NonceGen(P_pi);
    if (!np_A || !np_B) return std::nullopt;
    auto KI_A = pjr::KeyImageShare(P_pi, x_A);
    auto KI_B = pjr::KeyImageShare(P_pi, x_B);
    if (!KI_A || !KI_B) return std::nullopt;

    // Round 2 — combine.
    std::array<pr::Point, 2> L_shares{np_A->L_share, np_B->L_share};
    std::array<pr::Point, 2> R_shares{np_A->R_share, np_B->R_share};
    std::array<pr::Point, 2> KI_shares{*KI_A, *KI_B};
    auto L_pi = pjr::CombinePoints(std::span<const pr::Point>{L_shares});
    auto R_pi = pjr::CombinePoints(std::span<const pr::Point>{R_shares});
    auto KI   = pjr::CombinePoints(std::span<const pr::Point>{KI_shares});
    if (!L_pi || !R_pi || !KI) return std::nullopt;

    // Walk the ring (pure function of inputs both parties have).
    // The s_others are derived deterministically — for the cooperative
    // protocol the same scheme as the existing self-test: pick fresh
    // random scalars for s_others, both parties agree on them.
    // To keep the self-test self-contained we just use random scalars
    // (in production both parties derive deterministically from the
    // session, per spec).
    std::vector<pr::Scalar> s_others(ring.size());
    for (size_t i = 0; i < ring.size(); ++i) {
        if (i == pi) continue;  // s[pi] is the slot we'll fill
        s_others[i] = RandScalar();
    }

    auto walk = pjr::WalkRing(ring, pi, msg, *KI, *L_pi, *R_pi,
                                std::span<const pr::Scalar>{s_others});
    if (!walk) return std::nullopt;

    // Round 3 — close.
    auto cs_A = pjr::CloseShare(np_A->alpha, walk->c_pi, x_A);
    auto cs_B = pjr::CloseShare(np_B->alpha, walk->c_pi, x_B);
    if (!cs_A || !cs_B) return std::nullopt;

    std::array<pr::Scalar, 2> close_shares{*cs_A, *cs_B};
    auto s_pi = pjr::CombineScalars(std::span<const pr::Scalar>{close_shares});
    if (!s_pi) return std::nullopt;

    pr::Signature sig;
    sig.c0 = walk->c0;
    sig.s = s_others;
    sig.s[pi] = *s_pi;
    sig.key_image = *KI;
    return sig;
}

// Run cooperative non-adaptor MuSig2 signing for two parties.
// Wraps btc_musig2_adaptor with adaptor_T_G=nullopt. Used to sign
// the foreign-chain refund tx.
std::optional<bma::SignatureBytes> SignBtcRefundCooperative(
    const std::vector<CPubKey>& pubs,
    const bma::Scalar& sk_A, const bma::Scalar& sk_B,
    const CPubKey& pub_A, const CPubKey& pub_B,
    const uint256& msg)
{
    bma::KeyAggCache cache;
    auto agg = bma::AggregatePubkeys(pubs, cache);
    if (!agg) return std::nullopt;

    MuSig2SecNonce sec_A, sec_B;
    uint256 seed_A, seed_B;
    GetStrongRandBytes(seed_A);
    GetStrongRandBytes(seed_B);
    auto pn_A = bma::NonceGen(sec_A, sk_A, pub_A, msg, cache, seed_A);
    auto pn_B = bma::NonceGen(sec_B, sk_B, pub_B, msg, cache, seed_B);
    if (!pn_A || !pn_B) return std::nullopt;

    auto aggn = bma::AggregateNonces({*pn_A, *pn_B});
    if (!aggn) return std::nullopt;

    // Crucial — refund signatures are NON-adaptor:
    auto session = bma::ProcessNonces(*aggn, msg, cache, /*adaptor_T_G=*/std::nullopt);
    if (!session) return std::nullopt;

    auto ps_A = bma::PartialSign(sec_A, sk_A, pub_A, cache, *session);
    auto ps_B = bma::PartialSign(sec_B, sk_B, pub_B, cache, *session);
    if (!ps_A || !ps_B) return std::nullopt;

    return bma::AggregatePartials(*session, {*ps_A, *ps_B});
}

void TestTimelockValidator()
{
    // Reasonable production-shaped values.
    const int32_t pric_height    = 100'000;
    const int32_t delta          = 144;    // ~24h foreign blocks
    const int32_t foreign_height = pric_height + delta + 10;

    Check(ValidateRefundTimelocks({pric_height, foreign_height, delta}) == TimelockCheck::Ok,
          "happy timelocks");

    // Boundary: exactly meets delta.
    Check(ValidateRefundTimelocks({pric_height, pric_height + delta, delta}) == TimelockCheck::Ok,
          "boundary delta exact");

    // Off-by-one: foreign just under the delta buffer.
    Check(ValidateRefundTimelocks({pric_height, pric_height + delta - 1, delta})
              == TimelockCheck::DeltaTooSmall,
          "delta off-by-one");

    // Equal heights: ordering violation.
    Check(ValidateRefundTimelocks({pric_height, pric_height, delta})
              == TimelockCheck::OrderingViolation,
          "equal heights = ordering violation");

    // Reversed ordering (the catastrophic case the rev 2 fix addresses).
    Check(ValidateRefundTimelocks({pric_height, pric_height - 1, delta})
              == TimelockCheck::OrderingViolation,
          "foreign < pric");

    // Non-positive heights.
    Check(ValidateRefundTimelocks({0, 1, delta}) == TimelockCheck::PricNotPositive,
          "pric <= 0");
    Check(ValidateRefundTimelocks({1, 0, delta}) == TimelockCheck::ForeignNotPositive,
          "foreign <= 0");
    Check(ValidateRefundTimelocks({1, 2, 0}) == TimelockCheck::DeltaMinNotPositive,
          "delta <= 0");

    // Explainer covers all enum values without crashing.
    for (auto c : {TimelockCheck::Ok, TimelockCheck::PricNotPositive,
                   TimelockCheck::ForeignNotPositive, TimelockCheck::DeltaMinNotPositive,
                   TimelockCheck::OrderingViolation, TimelockCheck::DeltaTooSmall}) {
        const char* s = ExplainTimelockCheck(c);
        Check(s != nullptr && std::strlen(s) > 0, "explainer non-empty");
    }
}

void TestPricRefundCooperative()
{
    // Build a 4-member ring with the joint output at pi=2.
    constexpr size_t N = 4, pi = 2;
    std::vector<pr::Point> ring(N);
    for (size_t i = 0; i < N; ++i) ring[i] = ScalarMultG(RandScalar());

    const pr::Scalar x_A = RandScalar();
    const pr::Scalar x_B = RandScalar();
    const pr::Scalar joint_priv = AddScalars(x_A, x_B);
    ring[pi] = ScalarMultG(joint_priv);

    // Refund-tx sighash (placeholder uint256 — real msg construction
    // happens in the orchestration layer).
    const uint256 refund_msg = uint256::FromHex(
        "deadbeefcafebabe0011223344556677889900aabbccddeeff00112233445566").value();

    auto sig = SignPricRefundCooperative(
        std::span<const pr::Point>{ring}, pi, x_A, x_B, refund_msg);
    Check(sig.has_value(), "PRIC refund cooperative sign");
    Check(pr::Verify(std::span<const pr::Point>{ring}, *sig, refund_msg),
          "PRIC refund sig verifies under standard CLSAG");

    // Tamper: bit-flip in s[pi] → must fail. Confirms the cooperative
    // close arithmetic isn't quietly accepting any sig under the same
    // message. (Catches the regression class where one party silently
    // contributed a zero share.)
    pr::Signature bad = *sig;
    bad.s[pi][0] ^= 0x01;
    Check(!pr::Verify(std::span<const pr::Point>{ring}, bad, refund_msg),
          "tampered s[pi] must NOT verify");

    // Wrong-share rejection: a malicious party using x_A' ≠ x_A
    // cannot produce a verifying refund sig. (The PRIC-side claim
    // primitive's joint_ringsig self-test already covers this for
    // claim sigs; reconfirming under refund inputs catches any
    // accidental specialisation that breaks under non-claim msg.)
    const pr::Scalar wrong_x_A = RandScalar();
    auto bad_sig = SignPricRefundCooperative(
        std::span<const pr::Point>{ring}, pi, wrong_x_A, x_B, refund_msg);
    Check(!bad_sig || !pr::Verify(std::span<const pr::Point>{ring}, *bad_sig, refund_msg),
          "wrong-share refund sig must not verify");
}

void TestBtcRefundCooperative()
{
    CKey priv_A; priv_A.MakeNewKey(true);
    CKey priv_B; priv_B.MakeNewKey(true);
    bma::Scalar sk_A, sk_B;
    std::memcpy(sk_A.data(), priv_A.begin(), 32);
    std::memcpy(sk_B.data(), priv_B.begin(), 32);
    // Even-y-normalize (as production does) to match the even-y form
    // AggregatePubkeys pins.
    Check(bma::NormalizeSeckeyEvenY(sk_A), "normalize sk_A");
    Check(bma::NormalizeSeckeyEvenY(sk_B), "normalize sk_B");
    CKey nk_A; nk_A.Set(sk_A.begin(), sk_A.end(), /*fCompressedIn=*/true);
    CKey nk_B; nk_B.Set(sk_B.begin(), sk_B.end(), /*fCompressedIn=*/true);
    const CPubKey pub_A = nk_A.GetPubKey();   // even-y
    const CPubKey pub_B = nk_B.GetPubKey();   // even-y

    const uint256 refund_msg = uint256::FromHex(
        "0123456789abcdeffeedfacedeadbeef0011223344556677889900aabbccddee").value();

    std::vector<CPubKey> pubs{pub_A, pub_B};
    auto sig = SignBtcRefundCooperative(pubs, sk_A, sk_B, pub_A, pub_B, refund_msg);
    Check(sig.has_value(), "BTC refund cooperative sign (no adaptor)");

    // Aggregate xonly pubkey for verify.
    bma::KeyAggCache cache_for_verify;
    auto agg = bma::AggregatePubkeys(pubs, cache_for_verify);
    Check(agg.has_value(), "BTC refund: aggregate keyagg for verify");
    XOnlyPubKey agg_xpub{std::span<const unsigned char>{agg->data(), 32}};

    Check(agg_xpub.VerifySchnorr(refund_msg, *sig),
          "BTC refund sig verifies under deployed BIP340 (XOnlyPubKey::VerifySchnorr)");

    // Tamper: bit-flip in the s field (last byte of the 64-byte sig).
    bma::SignatureBytes bad = *sig;
    bad[63] ^= 0x01;
    Check(!agg_xpub.VerifySchnorr(refund_msg, bad),
          "tampered BTC refund sig must NOT verify");

    // Wrong-msg rejection. Catches a class of sighash mistakes where
    // the refund tx is signed under a stale msg.
    const uint256 wrong_msg = uint256::FromHex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").value();
    Check(!agg_xpub.VerifySchnorr(wrong_msg, *sig),
          "BTC refund sig must NOT verify under wrong msg");
}

} // namespace

void RunSelfTest()
{
    TestTimelockValidator();
    TestPricRefundCooperative();
    TestBtcRefundCooperative();
}

} // namespace pricoin::swap::refund
