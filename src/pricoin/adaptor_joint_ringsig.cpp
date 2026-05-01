// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pricoin/adaptor_joint_ringsig.h>

#include <crypto/sha256.h>
#include <pricoin/adaptor_ringsig.h>
#include <pricoin/ringsig.h>
#include <random.h>
#include <secp256k1.h>
#include <sync.h>

#include <cstring>
#include <stdexcept>

// IMPORTANT: ring-walk math here MUST produce signatures that
// verify under the deployed `pricoin::ringsig::Verify` after Adapt.
// The self-test at the bottom feeds every output through Verify
// and fails on mismatch.

namespace pricoin::adaptor_joint_ringsig {

namespace {

using ::pricoin::ringsig::kPointBytes;

Mutex g_ctx_mutex;
secp256k1_context* g_ctx GUARDED_BY(g_ctx_mutex){nullptr};

secp256k1_context* JCtx() EXCLUSIVE_LOCKS_REQUIRED(g_ctx_mutex)
{
    if (!g_ctx) {
        g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        if (!g_ctx) throw std::runtime_error("secp256k1_context_create failed (adaptor_joint_ringsig)");
        unsigned char seed[32];
        GetRandBytes(seed);
        if (!secp256k1_context_randomize(g_ctx, seed)) {
            // Non-fatal — context still works without randomization.
        }
    }
    return g_ctx;
}

bool ParsePoint(secp256k1_context* ctx, const Point& bytes, secp256k1_pubkey& out)
{
    return secp256k1_ec_pubkey_parse(ctx, &out, bytes.data(), bytes.size()) == 1;
}

bool SerializePoint(secp256k1_context* ctx, const secp256k1_pubkey& in, Point& out)
{
    size_t len = out.size();
    return secp256k1_ec_pubkey_serialize(ctx, out.data(), &len, &in, SECP256K1_EC_COMPRESSED) == 1
           && len == kPointBytes;
}

bool AddPoints(secp256k1_context* ctx,
               const Point& a, const Point& b, Point& out)
{
    secp256k1_pubkey pa, pb;
    if (!ParsePoint(ctx, a, pa)) return false;
    if (!ParsePoint(ctx, b, pb)) return false;
    const secp256k1_pubkey* parts[2] = {&pa, &pb};
    secp256k1_pubkey sum;
    if (!secp256k1_ec_pubkey_combine(ctx, &sum, parts, 2)) return false;
    return SerializePoint(ctx, sum, out);
}

bool ScalarMultPoint(secp256k1_context* ctx,
                     const Scalar& scalar,
                     const Point& base,
                     Point& out)
{
    secp256k1_pubkey p;
    if (!ParsePoint(ctx, base, p)) return false;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &p, scalar.data())) return false;
    return SerializePoint(ctx, p, out);
}

bool ScalarMultG(secp256k1_context* ctx, const Scalar& scalar, Point& out)
{
    secp256k1_pubkey p;
    if (!secp256k1_ec_pubkey_create(ctx, &p, scalar.data())) return false;
    return SerializePoint(ctx, p, out);
}

// Hash-to-scalar for cooperative-side helpers (deterministic
// `s_others`, commitment hash). Same rejection-rehash protocol as
// `pricoin::ringsig::HashToScalar`, distinct domain tag.
Scalar HashToScalarCoopAdaptor(
    secp256k1_context* ctx,
    std::span<const std::span<const unsigned char>> chunks)
{
    {
        CSHA256 h;
        h.Write(reinterpret_cast<const unsigned char*>(
            "pricoin/adaptor-coop-clsag/H_s-v1"), 33);
        for (const auto& c : chunks) h.Write(c.data(), c.size());
        Scalar out;
        h.Finalize(out.data());
        if (secp256k1_ec_seckey_verify(ctx, out.data())) return out;
    }
    constexpr const char* kRehashTag = "pricoin/adaptor-coop-clsag/H_s-rehash-v1";
    for (uint16_t counter = 0; counter <= 0xff; ++counter) {
        CSHA256 h;
        h.Write(reinterpret_cast<const unsigned char*>(kRehashTag), std::strlen(kRehashTag));
        for (const auto& c : chunks) h.Write(c.data(), c.size());
        const unsigned char ctr_byte = static_cast<unsigned char>(counter);
        h.Write(&ctr_byte, 1);
        Scalar out;
        h.Finalize(out.data());
        if (secp256k1_ec_seckey_verify(ctx, out.data())) return out;
    }
    throw std::runtime_error("HashToScalarCoopAdaptor: rehash exhausted");
}

// Per spec: nonce commitment binds (L_share, R_share, KI_share,
// dleq_alpha, dleq_x, T_G, T_H) plus session_label / session_payload.
Scalar ComputeNonceCommit(
    secp256k1_context* ctx,
    const AdaptorNonceShare& share,
    const AdaptorPoints& adaptor,
    std::span<const unsigned char> session_label,
    std::span<const unsigned char> session_payload)
{
    static constexpr char kTag[] = "nonce-commit-v1";

    // Serialise the DLEQ proofs as flat bytes (A_G || A_H || z each).
    std::array<unsigned char, kPointBytes * 4 + 32 * 2> dleq_blob{};
    std::memcpy(dleq_blob.data() + 0,                    share.dleq_alpha.A_G.data(), kPointBytes);
    std::memcpy(dleq_blob.data() + kPointBytes,          share.dleq_alpha.A_H.data(), kPointBytes);
    std::memcpy(dleq_blob.data() + kPointBytes * 2,      share.dleq_alpha.z.data(),   32);
    std::memcpy(dleq_blob.data() + kPointBytes * 2 + 32, share.dleq_x.A_G.data(),     kPointBytes);
    std::memcpy(dleq_blob.data() + kPointBytes * 3 + 32, share.dleq_x.A_H.data(),     kPointBytes);
    std::memcpy(dleq_blob.data() + kPointBytes * 4 + 32, share.dleq_x.z.data(),       32);

    std::span<const unsigned char> chunks_arr[]{
        std::span<const unsigned char>{reinterpret_cast<const unsigned char*>(kTag), sizeof(kTag) - 1},
        std::span<const unsigned char>{share.L_share.data(),   share.L_share.size()},
        std::span<const unsigned char>{share.R_share.data(),   share.R_share.size()},
        std::span<const unsigned char>{share.KI_share.data(),  share.KI_share.size()},
        std::span<const unsigned char>{adaptor.T_G.data(),     adaptor.T_G.size()},
        std::span<const unsigned char>{adaptor.T_H.data(),     adaptor.T_H.size()},
        std::span<const unsigned char>{dleq_blob.data(),       dleq_blob.size()},
        session_label,
        session_payload,
    };
    return HashToScalarCoopAdaptor(ctx,
        std::span<const std::span<const unsigned char>>{chunks_arr,
            sizeof(chunks_arr) / sizeof(chunks_arr[0])});
}

// Deterministic non-signer s_i derived from the canonical SESSION.
// Closes the s_others-grinding vector flagged by round-3 review
// (Finding E). The ring binding pins the index meaning.
Scalar DerivedSOther(
    secp256k1_context* ctx,
    std::span<const Point> ring,
    size_t pi,
    size_t i,
    const Point& KI,
    const AdaptorPoints& adaptor,
    std::span<const unsigned char> session_label,
    std::span<const unsigned char> session_payload)
{
    static constexpr char kTag[] = "s-others-v1";

    std::vector<unsigned char> ring_blob;
    ring_blob.reserve(ring.size() * kPointBytes);
    for (const auto& p : ring) ring_blob.insert(ring_blob.end(), p.begin(), p.end());

    const std::array<unsigned char, 4> pi_le{
        static_cast<unsigned char>(pi & 0xff),
        static_cast<unsigned char>((pi >> 8) & 0xff),
        static_cast<unsigned char>((pi >> 16) & 0xff),
        static_cast<unsigned char>((pi >> 24) & 0xff)};
    const std::array<unsigned char, 4> i_le{
        static_cast<unsigned char>(i & 0xff),
        static_cast<unsigned char>((i >> 8) & 0xff),
        static_cast<unsigned char>((i >> 16) & 0xff),
        static_cast<unsigned char>((i >> 24) & 0xff)};

    std::span<const unsigned char> chunks_arr[]{
        std::span<const unsigned char>{reinterpret_cast<const unsigned char*>(kTag), sizeof(kTag) - 1},
        std::span<const unsigned char>{ring_blob},
        std::span<const unsigned char>{pi_le.data(), pi_le.size()},
        std::span<const unsigned char>{i_le.data(),  i_le.size()},
        std::span<const unsigned char>{KI.data(),       KI.size()},
        std::span<const unsigned char>{adaptor.T_G.data(), adaptor.T_G.size()},
        std::span<const unsigned char>{adaptor.T_H.data(), adaptor.T_H.size()},
        session_label,
        session_payload,
    };
    return HashToScalarCoopAdaptor(ctx,
        std::span<const std::span<const unsigned char>>{chunks_arr,
            sizeof(chunks_arr) / sizeof(chunks_arr[0])});
}

// Step challenge — must match `pricoin::ringsig::StepChallenge`
// byte-for-byte so the post-Adapt signature verifies under the
// deployed CLSAG verifier.
Scalar StepChallengeRingsig(
    secp256k1_context* ctx,
    std::span<const Point> ring,
    const uint256& msg,
    const Point& L_i, const Point& R_i, const Point& KI)
{
    std::vector<unsigned char> ring_blob;
    ring_blob.reserve(ring.size() * kPointBytes);
    for (const auto& p : ring) ring_blob.insert(ring_blob.end(), p.begin(), p.end());
    std::span<const unsigned char> chunks_arr[5]{
        std::span<const unsigned char>{ring_blob},
        std::span<const unsigned char>{msg.data(), msg.size()},
        std::span<const unsigned char>{L_i.data(), L_i.size()},
        std::span<const unsigned char>{R_i.data(), R_i.size()},
        std::span<const unsigned char>{KI.data(),  KI.size()},
    };
    constexpr const char* kTag = "pricoin/ringsig/H_s-v1";
    constexpr size_t kTagLen = 22;
    {
        CSHA256 h;
        h.Write(reinterpret_cast<const unsigned char*>(kTag), kTagLen);
        for (const auto& c : chunks_arr) h.Write(c.data(), c.size());
        Scalar out;
        h.Finalize(out.data());
        if (secp256k1_ec_seckey_verify(ctx, out.data())) return out;
    }
    constexpr const char* kRehashTag = "pricoin/ringsig/H_s-rehash-v1";
    for (uint16_t counter = 0; counter <= 0xff; ++counter) {
        CSHA256 h;
        h.Write(reinterpret_cast<const unsigned char*>(kRehashTag), std::strlen(kRehashTag));
        for (const auto& c : chunks_arr) h.Write(c.data(), c.size());
        const unsigned char ctr_byte = static_cast<unsigned char>(counter);
        h.Write(&ctr_byte, 1);
        Scalar out;
        h.Finalize(out.data());
        if (secp256k1_ec_seckey_verify(ctx, out.data())) return out;
    }
    throw std::runtime_error("StepChallengeRingsig: rehash exhausted");
}

bool HasDuplicate(std::span<const Point> ring)
{
    for (size_t i = 0; i < ring.size(); ++i) {
        for (size_t j = i + 1; j < ring.size(); ++j) {
            if (ring[i] == ring[j]) return true;
        }
    }
    return false;
}

// Domain-separated session payloads for DLEQ-1 vs DLEQ-2. Reuses
// `adaptor_ringsig::MakeDLEQProof` which is purpose-agnostic — the
// label distinguishes the proof's role.
constexpr const char kDLEQAlphaLabel[] = "pricoin/adaptor-coop/dleq-alpha-v1";
constexpr const char kDLEQXLabel[]     = "pricoin/adaptor-coop/dleq-x-v1";

std::span<const unsigned char> AlphaLabelSpan()
{
    return std::span<const unsigned char>{
        reinterpret_cast<const unsigned char*>(kDLEQAlphaLabel),
        sizeof(kDLEQAlphaLabel) - 1};
}
std::span<const unsigned char> XLabelSpan()
{
    return std::span<const unsigned char>{
        reinterpret_cast<const unsigned char*>(kDLEQXLabel),
        sizeof(kDLEQXLabel) - 1};
}

} // namespace

// ─────────────────────────────────────────────────────────────────
// Round 1.
// ─────────────────────────────────────────────────────────────────

std::optional<AdaptorNonceShare> NonceGenAdaptor(
    const Point& P_pi,
    const Point& X_pub_X,
    const Scalar& x_X,
    const AdaptorPoints& adaptor,
    std::span<const unsigned char> session_label,
    std::span<const unsigned char> session_payload)
{
    AdaptorNonceShare share;
    {
        LOCK(g_ctx_mutex);
        secp256k1_context* ctx = JCtx();

        if (!secp256k1_ec_seckey_verify(ctx, x_X.data())) return std::nullopt;

        // Sanity: x_X · G == X_pub_X.
        Point check;
        if (!ScalarMultG(ctx, x_X, check)) return std::nullopt;
        if (check != X_pub_X) return std::nullopt;

        // Pick alpha.
        do { GetRandBytes(share.alpha); }
        while (!secp256k1_ec_seckey_verify(ctx, share.alpha.data()));

        // L_share = α_X · G
        if (!ScalarMultG(ctx, share.alpha, share.L_share)) return std::nullopt;

        // R_share = α_X · H_p(P_pi)
        const Point Hp = ::pricoin::ringsig::HashToPoint(
            std::span<const unsigned char>{P_pi.data(), P_pi.size()});
        if (!ScalarMultPoint(ctx, share.alpha, Hp, share.R_share)) return std::nullopt;

        // KI_share = x_X · H_p(P_pi)
        if (!ScalarMultPoint(ctx, x_X, Hp, share.KI_share)) return std::nullopt;
    }

    // DLEQ-1: same α_X across G and H_p(P_pi). Proof points are
    // (L_share, R_share). We reuse `adaptor_ringsig::MakeDLEQProof`
    // — it's purpose-agnostic — passing AdaptorPoints{L_share, R_share}.
    AdaptorPoints alpha_points{share.L_share, share.R_share};
    auto dleq_alpha_opt = ::pricoin::adaptor_ringsig::MakeDLEQProof(
        share.alpha, P_pi, alpha_points,
        AlphaLabelSpan(), session_payload);
    if (!dleq_alpha_opt) return std::nullopt;
    share.dleq_alpha = *dleq_alpha_opt;

    // DLEQ-2: same x_X across G and H_p(P_pi). Proof points are
    // (X_pub_X, KI_share).
    AdaptorPoints x_points{X_pub_X, share.KI_share};
    auto dleq_x_opt = ::pricoin::adaptor_ringsig::MakeDLEQProof(
        x_X, P_pi, x_points,
        XLabelSpan(), session_payload);
    if (!dleq_x_opt) return std::nullopt;
    share.dleq_x = *dleq_x_opt;

    // Commitment over all public fields + adaptor + session.
    {
        LOCK(g_ctx_mutex);
        secp256k1_context* ctx = JCtx();
        share.commitment = ComputeNonceCommit(ctx, share, adaptor,
            session_label, session_payload);
    }
    return share;
}

bool VerifyAdaptorNonceShare(
    const Point& P_pi,
    const Point& X_pub_X,
    const AdaptorNonceShare& share,
    const AdaptorPoints& adaptor,
    std::span<const unsigned char> session_label,
    std::span<const unsigned char> session_payload)
{
    // DLEQ-1 + DLEQ-2 verification BEFORE taking our mutex
    // (verification routines acquire their own locks; non-recursive).
    {
        AdaptorPoints alpha_points{share.L_share, share.R_share};
        if (!::pricoin::adaptor_ringsig::VerifyDLEQProof(
                P_pi, alpha_points, share.dleq_alpha,
                AlphaLabelSpan(), session_payload)) return false;
    }
    {
        AdaptorPoints x_points{X_pub_X, share.KI_share};
        if (!::pricoin::adaptor_ringsig::VerifyDLEQProof(
                P_pi, x_points, share.dleq_x,
                XLabelSpan(), session_payload)) return false;
    }

    // Commitment recomputation.
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = JCtx();
    const Scalar recomputed = ComputeNonceCommit(ctx, share, adaptor,
        session_label, session_payload);
    return recomputed == share.commitment;
}

// ─────────────────────────────────────────────────────────────────
// Round 2.
// ─────────────────────────────────────────────────────────────────

std::optional<AdaptorCombineOutput> CombineAndWalk(
    std::span<const Point> ring,
    size_t pi,
    const uint256& msg,
    const AdaptorPoints& adaptor,
    const DLEQProof& dleq_t,
    std::span<const Point> X_pub_shares,
    std::span<const AdaptorNonceShare> shares,
    std::span<const unsigned char> session_label,
    std::span<const unsigned char> session_payload)
{
    if (ring.empty() || pi >= ring.size()) return std::nullopt;
    if (HasDuplicate(ring)) return std::nullopt;
    if (X_pub_shares.size() != shares.size() || shares.empty()) return std::nullopt;

    // Verify Bob's adaptor DLEQ as belt-and-braces.
    if (!::pricoin::adaptor_ringsig::VerifyDLEQProof(
            ring[pi], adaptor, dleq_t, session_label, session_payload)) {
        return std::nullopt;
    }

    // Verify each party's share (DLEQs + commitment).
    for (size_t k = 0; k < shares.size(); ++k) {
        if (!VerifyAdaptorNonceShare(ring[pi], X_pub_shares[k], shares[k],
                adaptor, session_label, session_payload)) {
            return std::nullopt;
        }
    }

    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = JCtx();

    AdaptorCombineOutput out;

    // Sum L_shares, R_shares, KI_shares.
    out.L_pi = shares[0].L_share;
    out.R_pi = shares[0].R_share;
    out.KI   = shares[0].KI_share;
    for (size_t k = 1; k < shares.size(); ++k) {
        Point sum;
        if (!AddPoints(ctx, out.L_pi, shares[k].L_share, sum)) return std::nullopt;
        out.L_pi = sum;
        if (!AddPoints(ctx, out.R_pi, shares[k].R_share, sum)) return std::nullopt;
        out.R_pi = sum;
        if (!AddPoints(ctx, out.KI,   shares[k].KI_share, sum)) return std::nullopt;
        out.KI = sum;
    }

    // Sanity: Σ X_pub_shares should equal ring[pi].
    {
        Point joint_pub = X_pub_shares[0];
        for (size_t k = 1; k < X_pub_shares.size(); ++k) {
            Point sum;
            if (!AddPoints(ctx, joint_pub, X_pub_shares[k], sum)) return std::nullopt;
            joint_pub = sum;
        }
        if (joint_pub != ring[pi]) return std::nullopt;
    }

    // Apply the adaptor shift.
    if (!AddPoints(ctx, out.L_pi, adaptor.T_G, out.L_prime)) return std::nullopt;
    if (!AddPoints(ctx, out.R_pi, adaptor.T_H, out.R_prime)) return std::nullopt;

    // Derive deterministic s_others from SESSION.
    const size_t N = ring.size();
    out.s_others.resize(N);
    for (size_t i = 0; i < N; ++i) {
        if (i == pi) continue;
        out.s_others[i] = DerivedSOther(ctx, ring, pi, i, out.KI,
            adaptor, session_label, session_payload);
    }

    // Walk the ring with the shifted anchor at pi.
    std::vector<Scalar> c(N);
    c[(pi + 1) % N] = StepChallengeRingsig(ctx, ring, msg,
        out.L_prime, out.R_prime, out.KI);

    for (size_t step = 1; step < N; ++step) {
        const size_t i = (pi + step) % N;
        Point sG, cP, L_i;
        if (!ScalarMultG(ctx, out.s_others[i], sG)) return std::nullopt;
        if (!ScalarMultPoint(ctx, c[i], ring[i], cP)) return std::nullopt;
        if (!AddPoints(ctx, sG, cP, L_i)) return std::nullopt;

        const Point Hp_i = ::pricoin::ringsig::HashToPoint(
            std::span<const unsigned char>{ring[i].data(), ring[i].size()});
        Point sHp, cKI, R_i;
        if (!ScalarMultPoint(ctx, out.s_others[i], Hp_i, sHp)) return std::nullopt;
        if (!ScalarMultPoint(ctx, c[i], out.KI, cKI)) return std::nullopt;
        if (!AddPoints(ctx, sHp, cKI, R_i)) return std::nullopt;

        c[(i + 1) % N] = StepChallengeRingsig(ctx, ring, msg, L_i, R_i, out.KI);
    }
    out.c_pi = c[pi];
    out.c0   = c[0];
    return out;
}

// ─────────────────────────────────────────────────────────────────
// Round 3 — close share + assemble.
// ─────────────────────────────────────────────────────────────────

std::optional<Scalar> CooperativeCloseShareAdaptor(
    const Scalar& alpha_X, const Scalar& c_pi, const Scalar& x_X)
{
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = JCtx();
    if (!secp256k1_ec_seckey_verify(ctx, alpha_X.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_verify(ctx, c_pi.data()))    return std::nullopt;
    if (!secp256k1_ec_seckey_verify(ctx, x_X.data()))     return std::nullopt;

    // ŝ_share = α_X − c_pi · x_X (mod n)
    Scalar prod = c_pi;
    if (!secp256k1_ec_seckey_tweak_mul(ctx, prod.data(), x_X.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_negate(ctx, prod.data())) return std::nullopt;
    Scalar s_share = alpha_X;
    if (!secp256k1_ec_seckey_tweak_add(ctx, s_share.data(), prod.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_verify(ctx, s_share.data())) return std::nullopt;
    return s_share;
}

std::optional<AdaptorPreSignature> AssembleAdaptorPreSig(
    const AdaptorCombineOutput& combined,
    std::span<const Scalar> close_shares,
    size_t pi,
    const AdaptorPoints& adaptor,
    const DLEQProof& dleq_t)
{
    if (close_shares.empty()) return std::nullopt;
    if (combined.s_others.empty()) return std::nullopt;
    if (pi >= combined.s_others.size()) return std::nullopt;

    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = JCtx();

    // ŝ_pi = Σ close_shares (mod n).
    Scalar s_pi = close_shares[0];
    if (!secp256k1_ec_seckey_verify(ctx, s_pi.data())) return std::nullopt;
    for (size_t k = 1; k < close_shares.size(); ++k) {
        if (!secp256k1_ec_seckey_verify(ctx, close_shares[k].data())) return std::nullopt;
        if (!secp256k1_ec_seckey_tweak_add(ctx, s_pi.data(), close_shares[k].data())) {
            return std::nullopt;
        }
    }
    if (!secp256k1_ec_seckey_verify(ctx, s_pi.data())) return std::nullopt;

    AdaptorPreSignature out;
    out.key_image        = combined.KI;
    out.commitment_image = Point{};   // single-layer
    out.c0               = combined.c0;
    out.s                = combined.s_others;
    out.s[pi]            = s_pi;
    out.adaptor          = adaptor;
    out.dleq             = dleq_t;
    out.pi               = static_cast<uint32_t>(pi);
    return out;
}

// ─────────────────────────────────────────────────────────────────
// Self-test.
// ─────────────────────────────────────────────────────────────────

namespace {

// Simulate a 2-party honest cooperative adaptor pre-sig flow
// in-process. Returns the resulting pre-sig.
std::optional<AdaptorPreSignature> CooperativeAdaptorTwoParty(
    std::span<const Point> ring,
    size_t pi,
    const Scalar& x_A, const Scalar& x_B,
    const Point& X_pub_A, const Point& X_pub_B,
    const uint256& msg,
    const AdaptorPoints& adaptor,
    const DLEQProof& dleq_t,
    std::span<const unsigned char> session_label,
    std::span<const unsigned char> session_payload)
{
    auto share_A = NonceGenAdaptor(ring[pi], X_pub_A, x_A, adaptor,
        session_label, session_payload);
    if (!share_A) return std::nullopt;
    auto share_B = NonceGenAdaptor(ring[pi], X_pub_B, x_B, adaptor,
        session_label, session_payload);
    if (!share_B) return std::nullopt;

    std::array<Point, 2> X_pubs{X_pub_A, X_pub_B};
    std::array<AdaptorNonceShare, 2> shares{*share_A, *share_B};

    auto combined = CombineAndWalk(ring, pi, msg, adaptor, dleq_t,
        std::span<const Point>{X_pubs},
        std::span<const AdaptorNonceShare>{shares},
        session_label, session_payload);
    if (!combined) return std::nullopt;

    auto cs_A = CooperativeCloseShareAdaptor(share_A->alpha, combined->c_pi, x_A);
    auto cs_B = CooperativeCloseShareAdaptor(share_B->alpha, combined->c_pi, x_B);
    if (!cs_A || !cs_B) return std::nullopt;

    std::array<Scalar, 2> close_shares{*cs_A, *cs_B};
    return AssembleAdaptorPreSig(*combined,
        std::span<const Scalar>{close_shares}, pi, adaptor, dleq_t);
}

} // namespace

void RunSelfTest()
{
    using ::pricoin::ringsig::Verify;

    constexpr size_t N = 4;
    constexpr size_t pi = 1;

    std::vector<Point> ring(N);
    std::vector<Scalar> decoy_priv(N);

    // Decoy keypairs.
    {
        LOCK(g_ctx_mutex);
        secp256k1_context* ctx = JCtx();
        for (size_t i = 0; i < N; ++i) {
            do { GetRandBytes(decoy_priv[i]); }
            while (!secp256k1_ec_seckey_verify(ctx, decoy_priv[i].data()));
            if (!ScalarMultG(ctx, decoy_priv[i], ring[i])) {
                throw std::runtime_error("adaptor-coop self-test: decoy pubkey failed");
            }
        }
    }

    // Joint key shares: x_A + x_B = x_pi.
    Scalar x_A, x_B;
    Point X_pub_A, X_pub_B, joint_P;
    {
        LOCK(g_ctx_mutex);
        secp256k1_context* ctx = JCtx();
        do { GetRandBytes(x_A); } while (!secp256k1_ec_seckey_verify(ctx, x_A.data()));
        do { GetRandBytes(x_B); } while (!secp256k1_ec_seckey_verify(ctx, x_B.data()));
        if (!ScalarMultG(ctx, x_A, X_pub_A)) {
            throw std::runtime_error("adaptor-coop self-test: X_pub_A failed");
        }
        if (!ScalarMultG(ctx, x_B, X_pub_B)) {
            throw std::runtime_error("adaptor-coop self-test: X_pub_B failed");
        }
        if (!AddPoints(ctx, X_pub_A, X_pub_B, joint_P)) {
            throw std::runtime_error("adaptor-coop self-test: joint pub failed");
        }
    }
    ring[pi] = joint_P;

    // Bob picks adaptor secret t.
    Scalar t;
    {
        LOCK(g_ctx_mutex);
        secp256k1_context* ctx = JCtx();
        do { GetRandBytes(t); } while (!secp256k1_ec_seckey_verify(ctx, t.data()));
    }
    auto adaptor = ::pricoin::adaptor_ringsig::ComputeAdaptorPoints(t, joint_P);
    if (!adaptor) {
        throw std::runtime_error("adaptor-coop self-test: ComputeAdaptorPoints failed");
    }

    static constexpr char kLabel[] = "pricoin/adaptor-coop-clsag/test-session-v1";
    const std::array<unsigned char, 16> session_payload{
        'c','o','o','p','-','a','d','a','p','-','t','e','s','t','-','1'};
    auto label_span = std::span<const unsigned char>{
        reinterpret_cast<const unsigned char*>(kLabel), sizeof(kLabel) - 1};
    auto payload_span = std::span<const unsigned char>{
        session_payload.data(), session_payload.size()};

    auto dleq_t = ::pricoin::adaptor_ringsig::MakeDLEQProof(
        t, joint_P, *adaptor, label_span, payload_span);
    if (!dleq_t) {
        throw std::runtime_error("adaptor-coop self-test: MakeDLEQProof(t) failed");
    }

    const uint256 msg = uint256::ONE;

    // ─── Honest 2-party cooperative pre-sig ───────────────────
    auto presig = CooperativeAdaptorTwoParty(
        std::span<const Point>{ring}, pi, x_A, x_B, X_pub_A, X_pub_B,
        msg, *adaptor, *dleq_t, label_span, payload_span);
    if (!presig) {
        throw std::runtime_error("adaptor-coop self-test: cooperative pre-sig failed");
    }

    // Adapt with t → standard CLSAG sig.
    auto sig = ::pricoin::adaptor_ringsig::Adapt(*presig, t,
        std::span<const Point>{ring}, msg);
    if (!sig) {
        throw std::runtime_error("adaptor-coop self-test: Adapt failed");
    }
    if (!Verify(std::span<const Point>{ring}, *sig, msg)) {
        throw std::runtime_error("adaptor-coop self-test: adapted sig failed standard CLSAG verify");
    }

    // Extract t.
    auto extracted = ::pricoin::adaptor_ringsig::Extract(
        std::span<const Point>{ring}, *presig, *sig);
    if (!extracted || *extracted != t) {
        throw std::runtime_error("adaptor-coop self-test: Extract failed or t mismatch");
    }

    // ─── Adversarial: malformed KI_share rejected by DLEQ-2 ──
    {
        // Manually construct a malformed share for party-B with
        // KI_share that doesn't match x_B.
        auto bad_share = NonceGenAdaptor(joint_P, X_pub_B, x_B, *adaptor,
            label_span, payload_span);
        if (!bad_share) throw std::runtime_error("adaptor-coop self-test: NonceGenAdaptor failed");

        // Replace KI_share with a different value (computed from a wrong x).
        Scalar wrong_x;
        Point wrong_KI;
        {
            LOCK(g_ctx_mutex);
            secp256k1_context* ctx = JCtx();
            do { GetRandBytes(wrong_x); }
            while (!secp256k1_ec_seckey_verify(ctx, wrong_x.data()));
            const Point Hp = ::pricoin::ringsig::HashToPoint(
                std::span<const unsigned char>{joint_P.data(), joint_P.size()});
            if (!ScalarMultPoint(ctx, wrong_x, Hp, wrong_KI)) {
                throw std::runtime_error("adaptor-coop self-test: wrong_KI failed");
            }
        }
        bad_share->KI_share = wrong_KI;
        // Recompute commitment so the commit-check passes; DLEQ-2 must fail.
        {
            LOCK(g_ctx_mutex);
            secp256k1_context* ctx = JCtx();
            bad_share->commitment = ComputeNonceCommit(ctx, *bad_share,
                *adaptor, label_span, payload_span);
        }

        if (VerifyAdaptorNonceShare(joint_P, X_pub_B, *bad_share,
                *adaptor, label_span, payload_span)) {
            throw std::runtime_error(
                "adaptor-coop self-test: malformed KI_share accepted by VerifyAdaptorNonceShare");
        }
    }

    // ─── Adversarial: tampered commitment rejected ────────────
    {
        auto bad_share = NonceGenAdaptor(joint_P, X_pub_B, x_B, *adaptor,
            label_span, payload_span);
        if (!bad_share) throw std::runtime_error("adaptor-coop self-test: NonceGenAdaptor failed");
        bad_share->commitment[0] ^= 0x01;
        if (VerifyAdaptorNonceShare(joint_P, X_pub_B, *bad_share,
                *adaptor, label_span, payload_span)) {
            throw std::runtime_error(
                "adaptor-coop self-test: tampered commitment accepted");
        }
    }

    // ─── Adversarial: malformed DLEQ-1 rejected ───────────────
    {
        auto bad_share = NonceGenAdaptor(joint_P, X_pub_B, x_B, *adaptor,
            label_span, payload_span);
        if (!bad_share) throw std::runtime_error("adaptor-coop self-test: NonceGenAdaptor failed");
        bad_share->dleq_alpha.z[0] ^= 0x01;
        // Recompute commitment so the commit-check passes; DLEQ-1 must fail.
        {
            LOCK(g_ctx_mutex);
            secp256k1_context* ctx = JCtx();
            bad_share->commitment = ComputeNonceCommit(ctx, *bad_share,
                *adaptor, label_span, payload_span);
        }
        if (VerifyAdaptorNonceShare(joint_P, X_pub_B, *bad_share,
                *adaptor, label_span, payload_span)) {
            throw std::runtime_error(
                "adaptor-coop self-test: tampered DLEQ-1 accepted");
        }
    }
}

} // namespace pricoin::adaptor_joint_ringsig
