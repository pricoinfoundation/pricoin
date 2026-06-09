// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <swap/btc_musig2_adaptor.h>

#include <key.h>
#include <pubkey.h>
#include <random.h>
#include <util/strencodings.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>
#include <secp256k1_schnorrsig.h>

#include <cassert>
#include <cstring>
#include <stdexcept>

namespace pricoin::swap::btc_musig2_adaptor {

namespace {

// Sanity-check our opaque struct sizes match libsecp256k1's. If a
// libsecp256k1 upgrade ever resizes these we want a hard build break,
// not a silent ABI mismatch.
static_assert(sizeof(secp256k1_musig_keyagg_cache) == 197);
static_assert(sizeof(secp256k1_musig_session) == 133);
static_assert(sizeof(secp256k1_musig_pubnonce) == 132);
static_assert(sizeof(secp256k1_musig_aggnonce) == 132);
static_assert(sizeof(secp256k1_musig_partial_sig) == 36);

// Most musig calls work with secp256k1_context_static (no ecmult_gen
// needed). The exceptions are nonce_gen (when binding seckey),
// keypair_create, and pubkey_create — all need a sign-capable
// context. We get one via the global ECC_Context held by the daemon.
const secp256k1_context* Ctx() { return secp256k1_context_static; }
const secp256k1_context* SignCtx() { return GetSigningContext(); }

bool ParsePubKey(const CPubKey& pk, secp256k1_pubkey& out) {
    return secp256k1_ec_pubkey_parse(Ctx(), &out, pk.data(), pk.size()) == 1;
}

void StoreCache(const secp256k1_musig_keyagg_cache& src, KeyAggCache& dst) {
    std::memcpy(dst.data.data(), src.data, dst.data.size());
}
void LoadCache(const KeyAggCache& src, secp256k1_musig_keyagg_cache& dst) {
    std::memcpy(dst.data, src.data.data(), src.data.size());
}
void StoreSession(const secp256k1_musig_session& src, Session& dst) {
    std::memcpy(dst.data.data(), src.data, dst.data.size());
}
void LoadSession(const Session& src, secp256k1_musig_session& dst) {
    std::memcpy(dst.data, src.data.data(), src.data.size());
}

} // namespace

std::optional<XOnlyPubKeyBytes> AggregatePubkeys(
    const std::vector<CPubKey>& pubkeys,
    KeyAggCache& cache_out)
{
    if (pubkeys.empty()) return std::nullopt;

    std::vector<secp256k1_pubkey> parsed(pubkeys.size());
    std::vector<const secp256k1_pubkey*> ptrs;
    ptrs.reserve(pubkeys.size());
    for (size_t i = 0; i < pubkeys.size(); ++i) {
        // Force every participant key to its even-y ("02"+xonly) form
        // before aggregating. The keyagg is parity-sensitive, so two
        // wallets that disagree on a key's parity (one stores "02"+xonly,
        // the other the natural "03"+xonly) would compute DIFFERENT
        // aggregates and never produce cross-verifying signatures. Pinning
        // to even-y makes the agg a function of the xonly coordinates only,
        // and matches the even-y-normalized signing privs (see
        // NormalizeSeckeyEvenY) so partial_sign/verify stay consistent.
        CPubKey even = pubkeys[i];
        if (even.size() == 33 && even.data()[0] != 0x02) {
            unsigned char raw[33];
            raw[0] = 0x02;
            std::memcpy(raw + 1, even.data() + 1, 32);
            even = CPubKey(raw, raw + 33);
        }
        if (!ParsePubKey(even, parsed[i])) return std::nullopt;
        ptrs.push_back(&parsed[i]);
    }

    secp256k1_musig_keyagg_cache cache;
    secp256k1_xonly_pubkey agg_xonly;
    if (!secp256k1_musig_pubkey_agg(Ctx(), &agg_xonly, &cache, ptrs.data(), ptrs.size())) {
        return std::nullopt;
    }

    XOnlyPubKeyBytes out;
    if (!secp256k1_xonly_pubkey_serialize(Ctx(), out.data(), &agg_xonly)) {
        return std::nullopt;
    }
    StoreCache(cache, cache_out);
    return out;
}

std::optional<PubNonce66> NonceGen(
    MuSig2SecNonce& secnonce_out,
    const std::optional<Scalar>& self_priv,
    const CPubKey& self_pub,
    const std::optional<uint256>& msg,
    const KeyAggCache& cache,
    const uint256& session_seed)
{
    secp256k1_pubkey self_pub_parsed;
    if (!ParsePubKey(self_pub, self_pub_parsed)) return std::nullopt;

    secp256k1_musig_keyagg_cache cache_local;
    LoadCache(cache, cache_local);

    // libsecp256k1 invalidates the session_secrand32 buffer to deter
    // reuse, so copy into a local first.
    unsigned char session_secrand[32];
    std::memcpy(session_secrand, session_seed.data(), 32);

    secp256k1_musig_pubnonce pubnonce;
    if (!secp256k1_musig_nonce_gen(
            SignCtx(),
            secnonce_out.Get(),
            &pubnonce,
            session_secrand,
            self_priv ? self_priv->data() : nullptr,
            &self_pub_parsed,
            msg ? msg->data() : nullptr,
            &cache_local,
            /*extra_input32=*/nullptr)) {
        return std::nullopt;
    }

    PubNonce66 out;
    if (!secp256k1_musig_pubnonce_serialize(Ctx(), out.data(), &pubnonce)) {
        return std::nullopt;
    }
    return out;
}

std::optional<AggNonce66> AggregateNonces(const std::vector<PubNonce66>& pubnonces)
{
    if (pubnonces.empty()) return std::nullopt;

    std::vector<secp256k1_musig_pubnonce> parsed(pubnonces.size());
    std::vector<const secp256k1_musig_pubnonce*> ptrs;
    ptrs.reserve(pubnonces.size());
    for (size_t i = 0; i < pubnonces.size(); ++i) {
        if (!secp256k1_musig_pubnonce_parse(Ctx(), &parsed[i], pubnonces[i].data())) {
            return std::nullopt;
        }
        ptrs.push_back(&parsed[i]);
    }

    secp256k1_musig_aggnonce agg;
    if (!secp256k1_musig_nonce_agg(Ctx(), &agg, ptrs.data(), ptrs.size())) {
        return std::nullopt;
    }

    AggNonce66 out;
    if (!secp256k1_musig_aggnonce_serialize(Ctx(), out.data(), &agg)) {
        return std::nullopt;
    }
    return out;
}

std::optional<Session> ProcessNonces(
    const AggNonce66& aggnonce,
    const uint256& msg,
    const KeyAggCache& cache,
    const std::optional<AdaptorPointCompressed>& adaptor_T_G)
{
    secp256k1_musig_aggnonce aggnonce_parsed;
    if (!secp256k1_musig_aggnonce_parse(Ctx(), &aggnonce_parsed, aggnonce.data())) {
        return std::nullopt;
    }

    secp256k1_musig_keyagg_cache cache_local;
    LoadCache(cache, cache_local);

    secp256k1_pubkey adaptor_parsed;
    const secp256k1_pubkey* adaptor_ptr = nullptr;
    if (adaptor_T_G) {
        if (!secp256k1_ec_pubkey_parse(Ctx(), &adaptor_parsed, adaptor_T_G->data(), adaptor_T_G->size())) {
            return std::nullopt;
        }
        adaptor_ptr = &adaptor_parsed;
    }

    secp256k1_musig_session session;
    if (!secp256k1_musig_nonce_process(Ctx(), &session, &aggnonce_parsed, msg.data(), &cache_local, adaptor_ptr)) {
        return std::nullopt;
    }

    int parity = 0;
    if (!secp256k1_musig_nonce_parity(Ctx(), &parity, &session)) {
        return std::nullopt;
    }

    Session out;
    StoreSession(session, out);
    out.nonce_parity = parity;
    return out;
}

bool NormalizeSeckeyEvenY(Scalar& seckey)
{
    // The MuSig2 keyaggs in this protocol represent each participant by
    // the BIP340 "02"+xonly (even-y) form of their pubkey. A raw seckey
    // whose natural pubkey has ODD y therefore does NOT correspond to the
    // pubkey sitting in the keyagg cache — partial_sign would reject it
    // (keypair pub ≠ declared pub). Negate (n - seckey) so the pubkey is
    // even-y, matching the keyagg. Idempotent: even-y keys are unchanged.
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(SignCtx(), &pub, seckey.data())) return false;
    unsigned char ser[33];
    size_t len = sizeof(ser);
    secp256k1_ec_pubkey_serialize(Ctx(), ser, &len, &pub, SECP256K1_EC_COMPRESSED);
    if (ser[0] == 0x03) {  // odd y
        if (!secp256k1_ec_seckey_negate(Ctx(), seckey.data())) return false;
    }
    return true;
}

std::optional<PartialSig32> PartialSign(
    MuSig2SecNonce& secnonce,
    const Scalar& self_priv,
    const CPubKey& self_pub,
    const KeyAggCache& cache,
    const Session& session)
{
    if (!secnonce.IsValid()) return std::nullopt;

    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(SignCtx(), &keypair, self_priv.data())) {
        return std::nullopt;
    }
    // Verify the keypair matches the declared self_pub — guards
    // against caller errors that would otherwise produce an invalid
    // partial sig discoverable only at aggregate time.
    secp256k1_pubkey self_pub_parsed;
    if (!ParsePubKey(self_pub, self_pub_parsed)) return std::nullopt;
    secp256k1_pubkey kp_pub;
    if (!secp256k1_keypair_pub(Ctx(), &kp_pub, &keypair)) return std::nullopt;
    if (std::memcmp(&kp_pub, &self_pub_parsed, sizeof(secp256k1_pubkey)) != 0) {
        return std::nullopt;
    }

    secp256k1_musig_keyagg_cache cache_local;
    LoadCache(cache, cache_local);
    secp256k1_musig_session session_local;
    LoadSession(session, session_local);

    secp256k1_musig_partial_sig psig;
    if (!secp256k1_musig_partial_sign(Ctx(), &psig, secnonce.Get(), &keypair, &cache_local, &session_local)) {
        return std::nullopt;
    }
    // libsecp256k1 has internally invalidated secnonce.Get()'s
    // contents; reflect that on our wrapper to deter accidental reuse.
    secnonce.Invalidate();

    PartialSig32 out;
    if (!secp256k1_musig_partial_sig_serialize(Ctx(), out.data(), &psig)) {
        return std::nullopt;
    }
    return out;
}

std::optional<SignatureBytes> AggregatePartials(
    const Session& session,
    const std::vector<PartialSig32>& partials)
{
    if (partials.empty()) return std::nullopt;

    std::vector<secp256k1_musig_partial_sig> parsed(partials.size());
    std::vector<const secp256k1_musig_partial_sig*> ptrs;
    ptrs.reserve(partials.size());
    for (size_t i = 0; i < partials.size(); ++i) {
        if (!secp256k1_musig_partial_sig_parse(Ctx(), &parsed[i], partials[i].data())) {
            return std::nullopt;
        }
        ptrs.push_back(&parsed[i]);
    }

    secp256k1_musig_session session_local;
    LoadSession(session, session_local);

    SignatureBytes out;
    if (!secp256k1_musig_partial_sig_agg(Ctx(), out.data(), &session_local, ptrs.data(), ptrs.size())) {
        return std::nullopt;
    }
    return out;
}

bool VerifyPartialSig(
    const PartialSig32& partial,
    const PubNonce66& pubnonce,
    const CPubKey& pubkey,
    const KeyAggCache& cache,
    const Session& session)
{
    secp256k1_musig_partial_sig psig;
    if (!secp256k1_musig_partial_sig_parse(Ctx(), &psig, partial.data())) return false;
    secp256k1_musig_pubnonce pn;
    if (!secp256k1_musig_pubnonce_parse(Ctx(), &pn, pubnonce.data())) return false;
    secp256k1_pubkey pk;
    if (!ParsePubKey(pubkey, pk)) return false;
    secp256k1_musig_keyagg_cache cache_local;
    LoadCache(cache, cache_local);
    secp256k1_musig_session session_local;
    LoadSession(session, session_local);
    return secp256k1_musig_partial_sig_verify(
        Ctx(), &psig, &pn, &pk, &cache_local, &session_local) == 1;
}

std::optional<SignatureBytes> Adapt(
    const SignatureBytes& presig,
    const Scalar& t,
    int nonce_parity)
{
    SignatureBytes out;
    if (!secp256k1_musig_adapt(Ctx(), out.data(), presig.data(), t.data(), nonce_parity)) {
        return std::nullopt;
    }
    return out;
}

std::optional<Scalar> Extract(
    const SignatureBytes& presig,
    const SignatureBytes& sig,
    int nonce_parity)
{
    Scalar out;
    if (!secp256k1_musig_extract_adaptor(Ctx(), out.data(), sig.data(), presig.data(), nonce_parity)) {
        return std::nullopt;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

namespace {

CKey RandKey() {
    CKey k;
    k.MakeNewKey(/*fCompressed=*/true);
    return k;
}

// Produce T_G = t·G in 33-byte compressed form, plus return t.
struct AdaptorMaterial {
    Scalar t;
    AdaptorPointCompressed T_G;
};
AdaptorMaterial MakeAdaptor() {
    AdaptorMaterial out;
    while (true) {
        GetStrongRandBytes(out.t);
        secp256k1_pubkey p;
        if (!secp256k1_ec_pubkey_create(SignCtx(), &p, out.t.data())) continue;
        size_t len = 33;
        if (!secp256k1_ec_pubkey_serialize(Ctx(), out.T_G.data(), &len, &p, SECP256K1_EC_COMPRESSED)) continue;
        if (len != 33) continue;
        return out;
    }
}

void Check(bool cond, const char* what) {
    if (!cond) {
        throw std::runtime_error(std::string("MuSig2 adaptor self-test failed: ") + what);
    }
}

void RunOnce(bool with_adaptor) {
    // Two parties A, B.
    CKey priv_A = RandKey();
    CKey priv_B = RandKey();

    Scalar sk_A, sk_B;
    std::memcpy(sk_A.data(), priv_A.begin(), 32);
    std::memcpy(sk_B.data(), priv_B.begin(), 32);
    // Sign with even-y-normalized keys, exactly as the production code does
    // (NormalizeSeckeyEvenY) — AggregatePubkeys pins every participant to
    // its even-y form, so the signing keys must correspond to it.
    Check(NormalizeSeckeyEvenY(sk_A), "normalize sk_A");
    Check(NormalizeSeckeyEvenY(sk_B), "normalize sk_B");
    CKey nk_A; nk_A.Set(sk_A.begin(), sk_A.end(), /*fCompressedIn=*/true);
    CKey nk_B; nk_B.Set(sk_B.begin(), sk_B.end(), /*fCompressedIn=*/true);
    CPubKey pub_A = nk_A.GetPubKey();   // even-y
    CPubKey pub_B = nk_B.GetPubKey();   // even-y

    std::vector<CPubKey> pubs{pub_A, pub_B};

    // Step 1: aggregate.
    KeyAggCache cache;
    auto agg = AggregatePubkeys(pubs, cache);
    Check(agg.has_value(), "AggregatePubkeys");

    // Random message + (optional) adaptor.
    uint256 msg = uint256::FromHex("0e734f9f99c5d5a39d77d3a17e5b7e6f6c0a3aaa6f9c9d4d1c5b8a7e3f1d0c2b").value();

    std::optional<AdaptorMaterial> adaptor;
    std::optional<AdaptorPointCompressed> T_G_opt;
    if (with_adaptor) {
        adaptor = MakeAdaptor();
        T_G_opt = adaptor->T_G;
    }

    // Step 2: per-party nonce gen.
    MuSig2SecNonce sec_A, sec_B;
    uint256 seed_A, seed_B;
    GetStrongRandBytes(seed_A);
    GetStrongRandBytes(seed_B);
    auto pn_A = NonceGen(sec_A, sk_A, pub_A, msg, cache, seed_A);
    auto pn_B = NonceGen(sec_B, sk_B, pub_B, msg, cache, seed_B);
    Check(pn_A.has_value(), "NonceGen A");
    Check(pn_B.has_value(), "NonceGen B");

    // Step 4: aggregate nonces.
    auto aggn = AggregateNonces({*pn_A, *pn_B});
    Check(aggn.has_value(), "AggregateNonces");

    // Step 5: process.
    auto session = ProcessNonces(*aggn, msg, cache, T_G_opt);
    Check(session.has_value(), "ProcessNonces");

    // Step 6: partial sign.
    auto ps_A = PartialSign(sec_A, sk_A, pub_A, cache, *session);
    auto ps_B = PartialSign(sec_B, sk_B, pub_B, cache, *session);
    Check(ps_A.has_value(), "PartialSign A");
    Check(ps_B.has_value(), "PartialSign B");
    Check(!sec_A.IsValid(), "secnonce A invalidated");
    Check(!sec_B.IsValid(), "secnonce B invalidated");

    // Verify each partial BEFORE aggregating — the safety check the
    // ceremony now runs on the peer's partial. Honest partials must
    // verify; a tampered one must be rejected.
    Check(VerifyPartialSig(*ps_A, *pn_A, pub_A, cache, *session), "VerifyPartialSig A");
    Check(VerifyPartialSig(*ps_B, *pn_B, pub_B, cache, *session), "VerifyPartialSig B");
    {
        PartialSig32 bad = *ps_A;
        bad[0] ^= 0x01;
        Check(!VerifyPartialSig(bad, *pn_A, pub_A, cache, *session),
              "VerifyPartialSig rejects tampered partial");
    }

    // Step 8: aggregate.
    auto presig = AggregatePartials(*session, {*ps_A, *ps_B});
    Check(presig.has_value(), "AggregatePartials");

    // The aggregate x-only pubkey, used for verification.
    XOnlyPubKey agg_xonly{std::span<const unsigned char>{agg->data(), 32}};

    if (!with_adaptor) {
        // Without adaptor, the aggregated sig should be a valid
        // BIP340 sig directly.
        Check(agg_xonly.VerifySchnorr(msg, *presig),
              "BIP340 verify (no adaptor)");
        return;
    }

    // With adaptor, the aggregated sig is a pre-signature. It should
    // NOT verify as a BIP340 sig directly.
    Check(!agg_xonly.VerifySchnorr(msg, *presig),
          "pre-sig must NOT verify as BIP340 sig");

    // Adapt with the secret t.
    auto sig = Adapt(*presig, adaptor->t, session->nonce_parity);
    Check(sig.has_value(), "Adapt");

    // Now it must verify under deployed BIP340.
    Check(agg_xonly.VerifySchnorr(msg, *sig),
          "BIP340 verify after Adapt");

    // Extract round-trip: recover t from (presig, sig).
    auto t_recovered = Extract(*presig, *sig, session->nonce_parity);
    Check(t_recovered.has_value(), "Extract");
    Check(*t_recovered == adaptor->t, "Extract round-trip mismatch");

    // Adversarial: adapt with the wrong t → must NOT verify as BIP340.
    Scalar wrong_t = adaptor->t;
    wrong_t[0] ^= 0x01;
    auto bad_sig = Adapt(*presig, wrong_t, session->nonce_parity);
    Check(bad_sig.has_value(), "Adapt(wrong t) returns a sig");
    Check(!agg_xonly.VerifySchnorr(msg, *bad_sig),
          "Adapt(wrong t) must produce invalid sig");
}

} // namespace

void RunSelfTest()
{
    // No adaptor: cooperative MuSig2 without adaptor pathway.
    RunOnce(/*with_adaptor=*/false);
    // With adaptor: full pre-sig → Adapt → BIP340 verify → Extract.
    RunOnce(/*with_adaptor=*/true);
}

} // namespace pricoin::swap::btc_musig2_adaptor
