// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pricoin/joint_ringsig.h>

#include <crypto/sha256.h>
#include <pricoin/ringsig.h>
#include <random.h>
#include <secp256k1.h>
#include <sync.h>

#include <cstring>
#include <stdexcept>

// IMPORTANT: the StepChallenge / Compute_L / Compute_R math here must
// match pricoin::ringsig byte-for-byte; otherwise the produced
// Signature won't verify under pricoin::ringsig::Verify. The self-test
// at the bottom of this file feeds the cooperative output through
// Verify, so any divergence is caught at startup.

namespace pricoin::joint_ringsig {

namespace {

using ::pricoin::ringsig::kPointBytes;

Mutex g_ctx_mutex;
secp256k1_context* g_ctx GUARDED_BY(g_ctx_mutex){nullptr};

secp256k1_context* JCtx() EXCLUSIVE_LOCKS_REQUIRED(g_ctx_mutex)
{
    if (!g_ctx) {
        g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        if (!g_ctx) throw std::runtime_error("secp256k1_context_create failed (joint_ringsig)");
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

// Tagged-hash H_s — must match pricoin::ringsig::HashToScalar exactly.
Scalar HashToScalar(secp256k1_context* ctx,
                    std::span<const std::span<const unsigned char>> chunks)
{
    {
        CSHA256 h;
        h.Write(reinterpret_cast<const unsigned char*>("pricoin/ringsig/H_s-v1"), 22);
        for (const auto& c : chunks) h.Write(c.data(), c.size());
        Scalar out;
        h.Finalize(out.data());
        if (secp256k1_ec_seckey_verify(ctx, out.data())) return out;
    }
    constexpr const char* kRehashTag = "pricoin/ringsig/H_s-rehash-v1";
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
    throw std::runtime_error("HashToScalar (joint_ringsig): rehash exhausted");
}

// L_i = s_i · G + c_i · P_i
bool Compute_L(secp256k1_context* ctx, const Scalar& s_i, const Scalar& c_i,
               const Point& P_bytes, Point& out)
{
    secp256k1_pubkey sG;
    if (!secp256k1_ec_pubkey_create(ctx, &sG, s_i.data())) return false;
    secp256k1_pubkey P;
    if (!ParsePoint(ctx, P_bytes, P)) return false;
    secp256k1_pubkey cP = P;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &cP, c_i.data())) return false;
    const secp256k1_pubkey* parts[2] = {&sG, &cP};
    secp256k1_pubkey sum;
    if (!secp256k1_ec_pubkey_combine(ctx, &sum, parts, 2)) return false;
    return SerializePoint(ctx, sum, out);
}

// R_i = s_i · H_p(P_i) + c_i · KI
bool Compute_R(secp256k1_context* ctx, const Scalar& s_i, const Scalar& c_i,
               const Point& P_bytes, const Point& KI, Point& out)
{
    Point Hp = ::pricoin::ringsig::HashToPoint(
        std::span<const unsigned char>{P_bytes.data(), P_bytes.size()});
    secp256k1_pubkey Hp_pub, KI_pub;
    if (!ParsePoint(ctx, Hp, Hp_pub) || !ParsePoint(ctx, KI, KI_pub)) return false;
    secp256k1_pubkey sQ = Hp_pub;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &sQ, s_i.data())) return false;
    secp256k1_pubkey cR = KI_pub;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &cR, c_i.data())) return false;
    const secp256k1_pubkey* parts[2] = {&sQ, &cR};
    secp256k1_pubkey sum;
    if (!secp256k1_ec_pubkey_combine(ctx, &sum, parts, 2)) return false;
    return SerializePoint(ctx, sum, out);
}

// c_{i+1} = H_s("pricoin/ringsig/H_s-v1" || ring || msg || L_i || R_i || KI).
// MUST match pricoin::ringsig::StepChallenge.
Scalar StepChallenge(secp256k1_context* ctx,
                     std::span<const Point> ring,
                     const uint256& msg,
                     const Point& L_i,
                     const Point& R_i,
                     const Point& KI)
{
    std::vector<unsigned char> ring_blob;
    ring_blob.reserve(ring.size() * kPointBytes);
    for (const auto& p : ring) ring_blob.insert(ring_blob.end(), p.begin(), p.end());
    std::span<const unsigned char> chunks_arr[5]{
        std::span<const unsigned char>{ring_blob},
        std::span<const unsigned char>{msg.data(), msg.size()},
        std::span<const unsigned char>{L_i.data(), L_i.size()},
        std::span<const unsigned char>{R_i.data(), R_i.size()},
        std::span<const unsigned char>{KI.data(), KI.size()},
    };
    return HashToScalar(ctx, std::span<const std::span<const unsigned char>>{chunks_arr, 5});
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

bool HasDuplicateMembers(std::span<const MultiLayerMember> ring)
{
    for (size_t i = 0; i < ring.size(); ++i) {
        for (size_t j = i + 1; j < ring.size(); ++j) {
            if (ring[i].P == ring[j].P) return true;
        }
    }
    return false;
}

// μ_P, μ_C from (ring, KI, D). Same hash-format as
// pricoin::ringsig's anonymous MultiLayerMu — must match byte-for-
// byte or the produced signature won't verify.
bool ComputeMuInternal(secp256k1_context* ctx,
                       std::span<const MultiLayerMember> ring,
                       const Point& KI,
                       const Point& D,
                       MultiLayerMu& out)
{
    std::vector<unsigned char> ring_blob;
    ring_blob.reserve(ring.size() * (kPointBytes * 2));
    for (const auto& m : ring) {
        ring_blob.insert(ring_blob.end(), m.P.begin(), m.P.end());
        ring_blob.insert(ring_blob.end(), m.W.begin(), m.W.end());
    }
    auto mu = [&](const char* tag) {
        std::span<const unsigned char> chunks_arr[4]{
            std::span<const unsigned char>{reinterpret_cast<const unsigned char*>(tag), std::strlen(tag)},
            std::span<const unsigned char>{ring_blob},
            std::span<const unsigned char>{KI.data(), KI.size()},
            std::span<const unsigned char>{D.data(),  D.size()},
        };
        return HashToScalar(ctx, std::span<const std::span<const unsigned char>>{chunks_arr, 4});
    };
    out.mu_P = mu("pricoin/clsag/agg/P/v2");
    out.mu_C = mu("pricoin/clsag/agg/C/v2");
    return secp256k1_ec_seckey_verify(ctx, out.mu_P.data())
        && secp256k1_ec_seckey_verify(ctx, out.mu_C.data());
}

// Aggregate one ring member: out = μ_P · P + μ_C · W
bool AggregateMemberInternal(secp256k1_context* ctx,
                             const MultiLayerMember& m,
                             const Scalar& mu_P, const Scalar& mu_C,
                             Point& out)
{
    secp256k1_pubkey P, W;
    if (!ParsePoint(ctx, m.P, P) || !ParsePoint(ctx, m.W, W)) return false;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &P, mu_P.data())) return false;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &W, mu_C.data())) return false;
    const secp256k1_pubkey* parts[2] = {&P, &W};
    secp256k1_pubkey sum;
    if (!secp256k1_ec_pubkey_combine(ctx, &sum, parts, 2)) return false;
    return SerializePoint(ctx, sum, out);
}

// Multi-layer step challenge: c_{i+1} = H(ring_full || msg || L_i ||
// R_i || KI || D). Must match pricoin::ringsig's StepChallengeML.
Scalar StepChallengeML(secp256k1_context* ctx,
                       std::span<const MultiLayerMember> ring,
                       const uint256& msg,
                       const Point& L_i, const Point& R_i,
                       const Point& KI, const Point& D)
{
    std::vector<unsigned char> ring_blob;
    ring_blob.reserve(ring.size() * (kPointBytes * 2));
    for (const auto& m : ring) {
        ring_blob.insert(ring_blob.end(), m.P.begin(), m.P.end());
        ring_blob.insert(ring_blob.end(), m.W.begin(), m.W.end());
    }
    static constexpr char tag[] = "pricoin/clsag/step/v2";
    std::span<const unsigned char> chunks_arr[7]{
        std::span<const unsigned char>{reinterpret_cast<const unsigned char*>(tag), sizeof(tag) - 1},
        std::span<const unsigned char>{ring_blob},
        std::span<const unsigned char>{msg.data(), msg.size()},
        std::span<const unsigned char>{L_i.data(), L_i.size()},
        std::span<const unsigned char>{R_i.data(), R_i.size()},
        std::span<const unsigned char>{KI.data(), KI.size()},
        std::span<const unsigned char>{D.data(),  D.size()},
    };
    return HashToScalar(ctx, std::span<const std::span<const unsigned char>>{chunks_arr, 7});
}

// L_i (ML) = s_i · G + c_i · T_i; T_i is the µ-aggregated ring point.
bool Compute_L_ML(secp256k1_context* ctx,
                  const Scalar& s_i, const Scalar& c_i,
                  const Point& T_bytes, Point& out)
{
    secp256k1_pubkey sG;
    if (!secp256k1_ec_pubkey_create(ctx, &sG, s_i.data())) return false;
    secp256k1_pubkey T;
    if (!ParsePoint(ctx, T_bytes, T)) return false;
    secp256k1_pubkey cT = T;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &cT, c_i.data())) return false;
    const secp256k1_pubkey* parts[2] = {&sG, &cT};
    secp256k1_pubkey sum;
    if (!secp256k1_ec_pubkey_combine(ctx, &sum, parts, 2)) return false;
    return SerializePoint(ctx, sum, out);
}

// R_i (ML) = s_i · H_p(P_i) + c_i · I_agg
bool Compute_R_ML(secp256k1_context* ctx,
                  const Scalar& s_i, const Scalar& c_i,
                  const Point& P_bytes, const Point& I_agg,
                  Point& out)
{
    Point Hp = ::pricoin::ringsig::HashToPoint(
        std::span<const unsigned char>{P_bytes.data(), P_bytes.size()});
    secp256k1_pubkey Hp_pub, Iagg_pub;
    if (!ParsePoint(ctx, Hp, Hp_pub) || !ParsePoint(ctx, I_agg, Iagg_pub)) return false;
    secp256k1_pubkey sQ = Hp_pub;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &sQ, s_i.data())) return false;
    secp256k1_pubkey cR = Iagg_pub;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &cR, c_i.data())) return false;
    const secp256k1_pubkey* parts[2] = {&sQ, &cR};
    secp256k1_pubkey sum;
    if (!secp256k1_ec_pubkey_combine(ctx, &sum, parts, 2)) return false;
    return SerializePoint(ctx, sum, out);
}

} // namespace

std::optional<NoncePartial> NonceGen(const Point& P_pi)
{
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = JCtx();
    secp256k1_pubkey P_pub;
    if (!ParsePoint(ctx, P_pi, P_pub)) return std::nullopt;

    NoncePartial out;
    do { GetRandBytes(out.alpha); } while (!secp256k1_ec_seckey_verify(ctx, out.alpha.data()));

    // L_share = α · G
    secp256k1_pubkey aG;
    if (!secp256k1_ec_pubkey_create(ctx, &aG, out.alpha.data())) return std::nullopt;
    if (!SerializePoint(ctx, aG, out.L_share)) return std::nullopt;

    // R_share = α · H_p(P_pi)
    Point Hp = ::pricoin::ringsig::HashToPoint(
        std::span<const unsigned char>{P_pi.data(), P_pi.size()});
    secp256k1_pubkey Hp_pub;
    if (!ParsePoint(ctx, Hp, Hp_pub)) return std::nullopt;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Hp_pub, out.alpha.data())) return std::nullopt;
    if (!SerializePoint(ctx, Hp_pub, out.R_share)) return std::nullopt;
    return out;
}

std::optional<Point> KeyImageShare(const Point& P_pi, const Scalar& x_X)
{
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = JCtx();
    if (!secp256k1_ec_seckey_verify(ctx, x_X.data())) return std::nullopt;
    Point Hp = ::pricoin::ringsig::HashToPoint(
        std::span<const unsigned char>{P_pi.data(), P_pi.size()});
    secp256k1_pubkey Hp_pub;
    if (!ParsePoint(ctx, Hp, Hp_pub)) return std::nullopt;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Hp_pub, x_X.data())) return std::nullopt;
    Point out;
    if (!SerializePoint(ctx, Hp_pub, out)) return std::nullopt;
    return out;
}

Scalar NonceCommit(
    std::span<const unsigned char> session_id,
    const Point& L_share,
    const Point& R_share,
    const Point& KI_share)
{
    static constexpr char kTag[] = "pricoin/joint_ringsig/commit-v1";
    CSHA256 h;
    h.Write(reinterpret_cast<const unsigned char*>(kTag), sizeof(kTag) - 1);
    h.Write(session_id.data(), session_id.size());
    h.Write(L_share.data(), L_share.size());
    h.Write(R_share.data(), R_share.size());
    h.Write(KI_share.data(), KI_share.size());
    Scalar out;
    h.Finalize(out.data());
    return out;
}

std::optional<Point> CombinePoints(std::span<const Point> shares)
{
    if (shares.empty()) return std::nullopt;
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = JCtx();

    std::vector<secp256k1_pubkey> parsed(shares.size());
    std::vector<const secp256k1_pubkey*> ptrs(shares.size());
    for (size_t i = 0; i < shares.size(); ++i) {
        if (!ParsePoint(ctx, shares[i], parsed[i])) return std::nullopt;
        ptrs[i] = &parsed[i];
    }
    secp256k1_pubkey sum;
    if (!secp256k1_ec_pubkey_combine(ctx, &sum, ptrs.data(), ptrs.size())) {
        // secp256k1 returns 0 if the sum is the point at infinity —
        // a degenerate input set (e.g., share_A + share_B = 0).
        return std::nullopt;
    }
    Point out;
    if (!SerializePoint(ctx, sum, out)) return std::nullopt;
    return out;
}

std::optional<Scalar> CombineScalars(std::span<const Scalar> shares)
{
    if (shares.empty()) return std::nullopt;
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = JCtx();

    Scalar acc = shares[0];
    if (!secp256k1_ec_seckey_verify(ctx, acc.data())) return std::nullopt;
    for (size_t i = 1; i < shares.size(); ++i) {
        if (!secp256k1_ec_seckey_verify(ctx, shares[i].data())) return std::nullopt;
        if (!secp256k1_ec_seckey_tweak_add(ctx, acc.data(), shares[i].data())) {
            // Sum is zero (mod n) — degenerate.
            return std::nullopt;
        }
    }
    if (!secp256k1_ec_seckey_verify(ctx, acc.data())) return std::nullopt;
    return acc;
}

std::optional<WalkOutput> WalkRing(
    std::span<const Point> ring,
    size_t pi,
    const uint256& msg,
    const Point& key_image,
    const Point& L_pi,
    const Point& R_pi,
    std::span<const Scalar> s_others)
{
    if (ring.empty() || pi >= ring.size()) return std::nullopt;
    if (s_others.size() != ring.size()) return std::nullopt;
    if (HasDuplicate(ring)) return std::nullopt;

    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = JCtx();

    // Sanity check: KI parses, ring members parse.
    {
        secp256k1_pubkey tmp;
        if (!ParsePoint(ctx, key_image, tmp)) return std::nullopt;
        for (const auto& p : ring) if (!ParsePoint(ctx, p, tmp)) return std::nullopt;
    }

    const size_t N = ring.size();
    std::vector<Scalar> c(N);

    // c[(pi+1) % N] = H(ring, msg, L_pi, R_pi, KI)
    c[(pi + 1) % N] = StepChallenge(ctx, ring, msg, L_pi, R_pi, key_image);

    // Walk forward from pi+1 around to pi, building each c from the
    // previous step's L_i, R_i (computed from the AGREED-UPON s_others
    // and the running c).
    for (size_t step = 1; step < N; ++step) {
        const size_t i = (pi + step) % N;
        if (!secp256k1_ec_seckey_verify(ctx, s_others[i].data())) return std::nullopt;
        Point L_i, R_i;
        if (!Compute_L(ctx, s_others[i], c[i], ring[i], L_i)) return std::nullopt;
        if (!Compute_R(ctx, s_others[i], c[i], ring[i], key_image, R_i)) return std::nullopt;
        c[(i + 1) % N] = StepChallenge(ctx, ring, msg, L_i, R_i, key_image);
    }

    return WalkOutput{c[pi], c[0]};
}

std::optional<Scalar> CloseShare(const Scalar& alpha, const Scalar& c_pi, const Scalar& x_X)
{
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = JCtx();
    if (!secp256k1_ec_seckey_verify(ctx, alpha.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_verify(ctx, c_pi.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_verify(ctx, x_X.data())) return std::nullopt;

    // s_share = alpha - c_pi · x_X (mod n)
    Scalar prod = c_pi;
    if (!secp256k1_ec_seckey_tweak_mul(ctx, prod.data(), x_X.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_negate(ctx, prod.data())) return std::nullopt;
    Scalar s_share = alpha;
    if (!secp256k1_ec_seckey_tweak_add(ctx, s_share.data(), prod.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_verify(ctx, s_share.data())) return std::nullopt;
    return s_share;
}

// ─────────────────────────────────────────────────────────────────
// Multi-layer public API.
// ─────────────────────────────────────────────────────────────────

std::optional<MultiLayerImageShares> KICommitImageShare(
    const Point& P_pi,
    const Scalar& x_X,
    const Scalar& z_X)
{
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = JCtx();
    if (!secp256k1_ec_seckey_verify(ctx, x_X.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_verify(ctx, z_X.data())) return std::nullopt;

    const Point Hp = ::pricoin::ringsig::HashToPoint(
        std::span<const unsigned char>{P_pi.data(), P_pi.size()});

    MultiLayerImageShares out;
    {
        secp256k1_pubkey hp;
        if (!ParsePoint(ctx, Hp, hp)) return std::nullopt;
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &hp, x_X.data())) return std::nullopt;
        if (!SerializePoint(ctx, hp, out.KI_share)) return std::nullopt;
    }
    {
        secp256k1_pubkey hp;
        if (!ParsePoint(ctx, Hp, hp)) return std::nullopt;
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &hp, z_X.data())) return std::nullopt;
        if (!SerializePoint(ctx, hp, out.D_share)) return std::nullopt;
    }
    return out;
}

std::optional<MultiLayerMu> ComputeMu(
    std::span<const MultiLayerMember> ring,
    const Point& KI,
    const Point& D)
{
    if (ring.empty()) return std::nullopt;
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = JCtx();
    secp256k1_pubkey tmp;
    if (!ParsePoint(ctx, KI, tmp)) return std::nullopt;
    if (!ParsePoint(ctx, D, tmp))  return std::nullopt;
    for (const auto& m : ring) {
        if (!ParsePoint(ctx, m.P, tmp)) return std::nullopt;
        if (!ParsePoint(ctx, m.W, tmp)) return std::nullopt;
    }
    MultiLayerMu out;
    if (!ComputeMuInternal(ctx, ring, KI, D, out)) return std::nullopt;
    return out;
}

std::optional<Scalar> AggregateShare(
    const MultiLayerMu& mu,
    const Scalar& x_X,
    const Scalar& z_X)
{
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = JCtx();
    if (!secp256k1_ec_seckey_verify(ctx, mu.mu_P.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_verify(ctx, mu.mu_C.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_verify(ctx, x_X.data()))     return std::nullopt;
    if (!secp256k1_ec_seckey_verify(ctx, z_X.data()))     return std::nullopt;

    Scalar t1 = x_X;
    if (!secp256k1_ec_seckey_tweak_mul(ctx, t1.data(), mu.mu_P.data())) return std::nullopt;
    Scalar t2 = z_X;
    if (!secp256k1_ec_seckey_tweak_mul(ctx, t2.data(), mu.mu_C.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_tweak_add(ctx, t1.data(), t2.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_verify(ctx, t1.data())) return std::nullopt;
    return t1;
}

std::optional<WalkOutput> WalkRingMultiLayer(
    std::span<const MultiLayerMember> ring,
    size_t pi,
    const uint256& msg,
    const Point& KI,
    const Point& D,
    const Point& L_pi,
    const Point& R_pi,
    std::span<const Scalar> s_others)
{
    if (ring.empty() || pi >= ring.size()) return std::nullopt;
    if (s_others.size() != ring.size())     return std::nullopt;
    if (HasDuplicateMembers(ring))          return std::nullopt;

    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = JCtx();

    // Sanity: KI, D, ring members, L/R parse.
    {
        secp256k1_pubkey tmp;
        if (!ParsePoint(ctx, KI, tmp)) return std::nullopt;
        if (!ParsePoint(ctx, D, tmp))  return std::nullopt;
        if (!ParsePoint(ctx, L_pi, tmp)) return std::nullopt;
        if (!ParsePoint(ctx, R_pi, tmp)) return std::nullopt;
        for (const auto& m : ring) {
            if (!ParsePoint(ctx, m.P, tmp)) return std::nullopt;
            if (!ParsePoint(ctx, m.W, tmp)) return std::nullopt;
        }
    }

    // Recompute μ — public, deterministic given (ring, KI, D).
    MultiLayerMu mu;
    if (!ComputeMuInternal(ctx, ring, KI, D, mu)) return std::nullopt;

    // Aggregated ring T_i = μ_P · P_i + μ_C · W_i.
    std::vector<Point> T(ring.size());
    for (size_t i = 0; i < ring.size(); ++i) {
        if (!AggregateMemberInternal(ctx, ring[i], mu.mu_P, mu.mu_C, T[i])) {
            return std::nullopt;
        }
    }
    // I_agg = μ_P · KI + μ_C · D = a · H_p(P_pi).
    Point I_agg;
    {
        MultiLayerMember imgs{KI, D};
        if (!AggregateMemberInternal(ctx, imgs, mu.mu_P, mu.mu_C, I_agg)) {
            return std::nullopt;
        }
    }

    const size_t N = ring.size();
    std::vector<Scalar> c(N);
    c[(pi + 1) % N] = StepChallengeML(ctx, ring, msg, L_pi, R_pi, KI, D);

    for (size_t step = 1; step < N; ++step) {
        const size_t i = (pi + step) % N;
        if (!secp256k1_ec_seckey_verify(ctx, s_others[i].data())) return std::nullopt;
        Point L_i;
        if (!Compute_L_ML(ctx, s_others[i], c[i], T[i], L_i)) return std::nullopt;
        Point R_i;
        if (!Compute_R_ML(ctx, s_others[i], c[i], ring[i].P, I_agg, R_i)) return std::nullopt;
        c[(i + 1) % N] = StepChallengeML(ctx, ring, msg, L_i, R_i, KI, D);
    }

    return WalkOutput{c[pi], c[0]};
}

namespace {

// Run a complete cooperative MULTI-layer signing flow with TWO parties
// in-process. Mirrors CooperativeSignTwoParty but uses the multi-layer
// primitives. Result must verify under pricoin::ringsig::VerifyMultiLayer.
std::optional<Signature> CooperativeSignTwoPartyML(
    std::span<const MultiLayerMember> ring,
    size_t pi,
    const Scalar& x_A, const Scalar& x_B,
    const Scalar& z_A, const Scalar& z_B,
    const uint256& msg)
{
    if (ring.empty() || pi >= ring.size()) return std::nullopt;

    // Round 1a — nonce partials (same shape as single-layer).
    auto noncepart_A = NonceGen(ring[pi].P);
    auto noncepart_B = NonceGen(ring[pi].P);
    if (!noncepart_A || !noncepart_B) return std::nullopt;

    // Round 1b — image shares (KI + D per party).
    auto imgs_A = KICommitImageShare(ring[pi].P, x_A, z_A);
    auto imgs_B = KICommitImageShare(ring[pi].P, x_B, z_B);
    if (!imgs_A || !imgs_B) return std::nullopt;

    // Round 2 — combine.
    std::array<Point, 2> ki_shares{imgs_A->KI_share, imgs_B->KI_share};
    auto KI = CombinePoints(std::span<const Point>{ki_shares});
    if (!KI) return std::nullopt;

    std::array<Point, 2> d_shares{imgs_A->D_share, imgs_B->D_share};
    auto D = CombinePoints(std::span<const Point>{d_shares});
    if (!D) return std::nullopt;

    std::array<Point, 2> L_shares{noncepart_A->L_share, noncepart_B->L_share};
    auto L_pi = CombinePoints(std::span<const Point>{L_shares});
    if (!L_pi) return std::nullopt;

    std::array<Point, 2> R_shares{noncepart_A->R_share, noncepart_B->R_share};
    auto R_pi = CombinePoints(std::span<const Point>{R_shares});
    if (!R_pi) return std::nullopt;

    // Compute μ — same value for both parties (public).
    auto mu = ComputeMu(ring, *KI, *D);
    if (!mu) return std::nullopt;

    // Each party's aggregated priv share.
    auto a_A = AggregateShare(*mu, x_A, z_A);
    auto a_B = AggregateShare(*mu, x_B, z_B);
    if (!a_A || !a_B) return std::nullopt;

    // Designated party generates non-pi random scalars.
    const size_t N = ring.size();
    std::vector<Scalar> s_others(N);
    {
        LOCK(g_ctx_mutex);
        secp256k1_context* ctx = JCtx();
        for (size_t i = 0; i < N; ++i) {
            if (i == pi) continue;
            do { GetRandBytes(s_others[i]); }
            while (!secp256k1_ec_seckey_verify(ctx, s_others[i].data()));
        }
    }

    auto walk = WalkRingMultiLayer(ring, pi, msg, *KI, *D, *L_pi, *R_pi,
                                   std::span<const Scalar>{s_others});
    if (!walk) return std::nullopt;

    // Round 3 — close shares (using each party's aggregated priv share).
    auto sshare_A = CloseShare(noncepart_A->alpha, walk->c_pi, *a_A);
    auto sshare_B = CloseShare(noncepart_B->alpha, walk->c_pi, *a_B);
    if (!sshare_A || !sshare_B) return std::nullopt;

    std::array<Scalar, 2> s_shares{*sshare_A, *sshare_B};
    auto s_pi = CombineScalars(std::span<const Scalar>{s_shares});
    if (!s_pi) return std::nullopt;

    Signature sig;
    sig.key_image = *KI;
    sig.commitment_image = *D;
    sig.c0 = walk->c0;
    sig.s = std::move(s_others);
    sig.s[pi] = *s_pi;
    return sig;
}

// Run a complete cooperative single-layer signing flow with TWO parties
// in-process. Returns the assembled signature (which must verify under
// the standard pricoin::ringsig::Verify). For the self-test only.
std::optional<Signature> CooperativeSignTwoParty(
    std::span<const Point> ring,
    size_t pi,
    const Scalar& x_A,
    const Scalar& x_B,
    const uint256& msg)
{
    if (ring.empty() || pi >= ring.size()) return std::nullopt;

    // Round 1a — each party generates their nonce partial.
    auto noncepart_A = NonceGen(ring[pi]);
    auto noncepart_B = NonceGen(ring[pi]);
    if (!noncepart_A || !noncepart_B) return std::nullopt;

    // Round 1b — each party computes their KI share.
    auto ki_A = KeyImageShare(ring[pi], x_A);
    auto ki_B = KeyImageShare(ring[pi], x_B);
    if (!ki_A || !ki_B) return std::nullopt;

    // Round 1c — each party commits to their nonce. (We compute the
    // commitments here just to exercise the API; in a real distributed
    // protocol both commitments would be exchanged before either party
    // reveals L/R/KI in round 2.)
    const std::array<unsigned char, 16> session_id{
        'p','r','i','-','j','o','i','n','t','-','t','e','s','t','-','1'};
    Scalar commit_A = NonceCommit(session_id, noncepart_A->L_share,
                                  noncepart_A->R_share, *ki_A);
    Scalar commit_B = NonceCommit(session_id, noncepart_B->L_share,
                                  noncepart_B->R_share, *ki_B);
    // Recompute and verify (this is what a counterparty would do upon
    // seeing the round-2 reveal).
    if (commit_A != NonceCommit(session_id, noncepart_A->L_share,
                                noncepart_A->R_share, *ki_A)) return std::nullopt;
    if (commit_B != NonceCommit(session_id, noncepart_B->L_share,
                                noncepart_B->R_share, *ki_B)) return std::nullopt;

    // Round 2 — combine.
    std::array<Point, 2> ki_shares{*ki_A, *ki_B};
    auto KI = CombinePoints(std::span<const Point>{ki_shares});
    if (!KI) return std::nullopt;

    std::array<Point, 2> L_shares{noncepart_A->L_share, noncepart_B->L_share};
    auto L_pi = CombinePoints(std::span<const Point>{L_shares});
    if (!L_pi) return std::nullopt;

    std::array<Point, 2> R_shares{noncepart_A->R_share, noncepart_B->R_share};
    auto R_pi = CombinePoints(std::span<const Point>{R_shares});
    if (!R_pi) return std::nullopt;

    // Round 2 (cont.) — the designated party (party A) generates the
    // non-signer s values and broadcasts. Both parties walk the ring
    // identically.
    const size_t N = ring.size();
    std::vector<Scalar> s_others(N);
    {
        LOCK(g_ctx_mutex);
        secp256k1_context* ctx = JCtx();
        for (size_t i = 0; i < N; ++i) {
            if (i == pi) continue;
            do { GetRandBytes(s_others[i]); } while (!secp256k1_ec_seckey_verify(ctx, s_others[i].data()));
        }
        // s_others[pi] is unused; leave zero.
    }

    auto walk = WalkRing(ring, pi, msg, *KI, *L_pi, *R_pi, std::span<const Scalar>{s_others});
    if (!walk) return std::nullopt;

    // Round 3 — each party computes their close share.
    auto sshare_A = CloseShare(noncepart_A->alpha, walk->c_pi, x_A);
    auto sshare_B = CloseShare(noncepart_B->alpha, walk->c_pi, x_B);
    if (!sshare_A || !sshare_B) return std::nullopt;

    std::array<Scalar, 2> s_shares{*sshare_A, *sshare_B};
    auto s_pi = CombineScalars(std::span<const Scalar>{s_shares});
    if (!s_pi) return std::nullopt;

    // Assemble the final signature.
    Signature sig;
    sig.key_image = *KI;
    sig.commitment_image = Point{};  // single-layer
    sig.c0 = walk->c0;
    sig.s = std::move(s_others);
    sig.s[pi] = *s_pi;
    return sig;
}

} // namespace

void RunSelfTest()
{
    using ::pricoin::ringsig::Verify;

    // Build a ring of 4 random pubkeys; the joint pubkey occupies pi=2.
    constexpr size_t N = 4;
    constexpr size_t pi = 2;

    // Decoy keypairs.
    std::vector<Point> ring(N);
    std::vector<Scalar> decoy_priv(N);
    {
        LOCK(g_ctx_mutex);
        secp256k1_context* ctx = JCtx();
        for (size_t i = 0; i < N; ++i) {
            do { GetRandBytes(decoy_priv[i]); }
            while (!secp256k1_ec_seckey_verify(ctx, decoy_priv[i].data()));
            secp256k1_pubkey pk;
            if (!secp256k1_ec_pubkey_create(ctx, &pk, decoy_priv[i].data())) {
                throw std::runtime_error("joint_ringsig self-test: pubkey_create failed");
            }
            if (!SerializePoint(ctx, pk, ring[i])) {
                throw std::runtime_error("joint_ringsig self-test: serialize failed");
            }
        }
    }

    // Joint key shares for the signer position. Joint priv = x_A + x_B;
    // joint pub = ring[pi] = (x_A + x_B) · G.
    Scalar x_A, x_B;
    Point joint_P;
    {
        LOCK(g_ctx_mutex);
        secp256k1_context* ctx = JCtx();
        do { GetRandBytes(x_A); } while (!secp256k1_ec_seckey_verify(ctx, x_A.data()));
        do { GetRandBytes(x_B); } while (!secp256k1_ec_seckey_verify(ctx, x_B.data()));
        // joint priv = x_A + x_B (mod n), then derive pub.
        Scalar joint_priv = x_A;
        if (!secp256k1_ec_seckey_tweak_add(ctx, joint_priv.data(), x_B.data())) {
            throw std::runtime_error("joint_ringsig self-test: priv add failed");
        }
        secp256k1_pubkey jpk;
        if (!secp256k1_ec_pubkey_create(ctx, &jpk, joint_priv.data())) {
            throw std::runtime_error("joint_ringsig self-test: joint pubkey_create failed");
        }
        if (!SerializePoint(ctx, jpk, joint_P)) {
            throw std::runtime_error("joint_ringsig self-test: joint serialize failed");
        }
    }
    ring[pi] = joint_P;

    const uint256 msg = uint256::ONE;

    // Cooperative sign.
    auto sig = CooperativeSignTwoParty(std::span<const Point>{ring}, pi, x_A, x_B, msg);
    if (!sig) {
        throw std::runtime_error("joint_ringsig self-test: cooperative sign returned nullopt");
    }
    // Verify with the standard single-party verifier.
    if (!Verify(std::span<const Point>{ring}, *sig, msg)) {
        throw std::runtime_error("joint_ringsig self-test: cooperative sig failed Verify");
    }

    // Tamper: flip a bit in msg → must fail.
    uint256 bad_msg = msg;
    *bad_msg.data() ^= 0x01;
    if (Verify(std::span<const Point>{ring}, *sig, bad_msg)) {
        throw std::runtime_error("joint_ringsig self-test: tampered msg should have failed");
    }

    // Tamper: flip a bit in s[pi] → must fail. (Catches the case where
    // the cooperative s_pi reconstruction is wrong.)
    Signature bad_sig = *sig;
    bad_sig.s[pi][0] ^= 0x01;
    if (Verify(std::span<const Point>{ring}, bad_sig, msg)) {
        throw std::runtime_error("joint_ringsig self-test: tampered s[pi] should have failed");
    }

    // KI invariance: KI = (x_A + x_B) · H_p(P_pi). The same joint priv
    // signed under a different ring/msg must yield the same KI — i.e.
    // double-spending the joint output is detectable by KI matching.
    {
        // Same joint key, but pi = 0 in a fresh ring.
        std::vector<Point> ring2 = ring;
        std::swap(ring2[0], ring2[pi]);
        const uint256 msg2 = uint256::ZERO;
        auto sig2 = CooperativeSignTwoParty(std::span<const Point>{ring2}, 0, x_A, x_B, msg2);
        if (!sig2) {
            throw std::runtime_error("joint_ringsig self-test: second cooperative sign failed");
        }
        if (!Verify(std::span<const Point>{ring2}, *sig2, msg2)) {
            throw std::runtime_error("joint_ringsig self-test: second sig failed Verify");
        }
        if (sig2->key_image != sig->key_image) {
            throw std::runtime_error("joint_ringsig self-test: KI not invariant across ring/msg");
        }
    }

    // Independence: the cooperative KI must equal the KI you'd compute
    // from the joint priv directly. Catches sign-error in the share
    // accumulation.
    {
        Scalar joint_priv;
        {
            LOCK(g_ctx_mutex);
            secp256k1_context* ctx = JCtx();
            joint_priv = x_A;
            if (!secp256k1_ec_seckey_tweak_add(ctx, joint_priv.data(), x_B.data())) {
                throw std::runtime_error("joint_ringsig self-test: joint priv add failed");
            }
        }
        auto direct_ki = ::pricoin::ringsig::ComputeKeyImage(joint_P, joint_priv);
        if (!direct_ki || *direct_ki != sig->key_image) {
            throw std::runtime_error("joint_ringsig self-test: cooperative KI != direct KI");
        }
    }

    // Wrong-share rejection: if a party uses x_X' ≠ x_X (lying about
    // their share), the cooperative signature must NOT verify. This
    // exercises the "rogue share" attack class — a malicious party
    // can't unilaterally produce a working signature under false
    // pretenses.
    {
        Scalar wrong_x_A;
        {
            LOCK(g_ctx_mutex);
            secp256k1_context* ctx = JCtx();
            do { GetRandBytes(wrong_x_A); }
            while (!secp256k1_ec_seckey_verify(ctx, wrong_x_A.data()));
        }
        auto bad = CooperativeSignTwoParty(std::span<const Point>{ring}, pi,
                                           wrong_x_A, x_B, msg);
        if (bad && Verify(std::span<const Point>{ring}, *bad, msg)) {
            throw std::runtime_error(
                "joint_ringsig self-test: wrong x_A produced a verifying sig");
        }
    }

    // ───────────────────────────────────────────────────────────
    // Multi-layer cooperative self-test.
    // ───────────────────────────────────────────────────────────
    using ::pricoin::ringsig::VerifyMultiLayer;

    // Build a fresh 4-member multi-layer ring; pi_ml = 1. Each
    // member needs (P_i, W_i). Build fresh P's (not reusing the
    // single-layer ring, which placed joint_P at a different index
    // — using it directly would make joint_P appear twice once we
    // override at pi_ml, tripping the duplicate-member check).
    constexpr size_t pi_ml = 1;
    std::vector<MultiLayerMember> ring_ml(N);
    std::vector<Scalar> decoy_z(N);
    {
        LOCK(g_ctx_mutex);
        secp256k1_context* ctx = JCtx();
        for (size_t i = 0; i < N; ++i) {
            // Fresh decoy P at this index.
            Scalar decoy_P_priv;
            do { GetRandBytes(decoy_P_priv); }
            while (!secp256k1_ec_seckey_verify(ctx, decoy_P_priv.data()));
            secp256k1_pubkey P_pk;
            if (!secp256k1_ec_pubkey_create(ctx, &P_pk, decoy_P_priv.data())) {
                throw std::runtime_error(
                    "joint_ringsig multi-layer self-test: P pubkey_create failed");
            }
            if (!SerializePoint(ctx, P_pk, ring_ml[i].P)) {
                throw std::runtime_error(
                    "joint_ringsig multi-layer self-test: P serialize failed");
            }

            // Decoy z at this index.
            do { GetRandBytes(decoy_z[i]); }
            while (!secp256k1_ec_seckey_verify(ctx, decoy_z[i].data()));
            secp256k1_pubkey W_pk;
            if (!secp256k1_ec_pubkey_create(ctx, &W_pk, decoy_z[i].data())) {
                throw std::runtime_error(
                    "joint_ringsig multi-layer self-test: W pubkey_create failed");
            }
            if (!SerializePoint(ctx, W_pk, ring_ml[i].W)) {
                throw std::runtime_error(
                    "joint_ringsig multi-layer self-test: W serialize failed");
            }
        }
    }

    // Joint shares for pi_ml. We already have x_A, x_B summing to the
    // pubkey at ring[pi]. Move that pubkey to ring_ml[pi_ml] and
    // build a similarly split z.
    Scalar z_A, z_B;
    {
        LOCK(g_ctx_mutex);
        secp256k1_context* ctx = JCtx();
        do { GetRandBytes(z_A); } while (!secp256k1_ec_seckey_verify(ctx, z_A.data()));
        do { GetRandBytes(z_B); } while (!secp256k1_ec_seckey_verify(ctx, z_B.data()));

        Scalar joint_z = z_A;
        if (!secp256k1_ec_seckey_tweak_add(ctx, joint_z.data(), z_B.data())) {
            throw std::runtime_error("joint_ringsig ML self-test: joint_z add failed");
        }
        secp256k1_pubkey W_jpk;
        if (!secp256k1_ec_pubkey_create(ctx, &W_jpk, joint_z.data())) {
            throw std::runtime_error("joint_ringsig ML self-test: joint W create failed");
        }
        // Set ring_ml[pi_ml] to the joint (P, W).
        ring_ml[pi_ml].P = joint_P;
        if (!SerializePoint(ctx, W_jpk, ring_ml[pi_ml].W)) {
            throw std::runtime_error("joint_ringsig ML self-test: joint W serialize failed");
        }
    }

    // Cooperative sign — both parties contribute (x_X, z_X).
    auto sig_ml = CooperativeSignTwoPartyML(
        std::span<const MultiLayerMember>{ring_ml},
        pi_ml, x_A, x_B, z_A, z_B, msg);
    if (!sig_ml) {
        throw std::runtime_error(
            "joint_ringsig multi-layer self-test: cooperative sign returned nullopt");
    }
    if (!VerifyMultiLayer(std::span<const MultiLayerMember>{ring_ml}, *sig_ml, msg)) {
        throw std::runtime_error(
            "joint_ringsig multi-layer self-test: cooperative sig failed VerifyMultiLayer");
    }

    // KI invariance across multi-layer: published KI = (x_A+x_B)·H_p(P_pi)
    // and must match what we computed for the single-layer sig (same P_pi
    // and same priv).
    if (sig_ml->key_image != sig->key_image) {
        throw std::runtime_error(
            "joint_ringsig multi-layer self-test: KI must equal single-layer KI for same P_pi");
    }

    // D depends on z, so it's NOT zero (single-layer sets it zero).
    {
        Point zero{};
        if (sig_ml->commitment_image == zero) {
            throw std::runtime_error(
                "joint_ringsig multi-layer self-test: D should be non-zero");
        }
    }

    // Tamper: flip a bit in W of a non-signer ring member → verify must fail.
    {
        auto bad_ring = ring_ml;
        bad_ring[(pi_ml + 1) % N].W[0] ^= 0x01;
        if (VerifyMultiLayer(std::span<const MultiLayerMember>{bad_ring}, *sig_ml, msg)) {
            throw std::runtime_error(
                "joint_ringsig multi-layer self-test: tampered W should have failed");
        }
    }

    // Tamper: flip a bit in s[pi] → must fail. (Catches mis-aggregation
    // of the closing share.)
    {
        Signature bad_sig = *sig_ml;
        bad_sig.s[pi_ml][0] ^= 0x01;
        if (VerifyMultiLayer(std::span<const MultiLayerMember>{ring_ml}, bad_sig, msg)) {
            throw std::runtime_error(
                "joint_ringsig multi-layer self-test: tampered s[pi] should have failed");
        }
    }

    // Wrong z-share rejection. If a party uses z_X' ≠ z_X, the
    // resulting cooperative signature must not verify (the published
    // D is wrong).
    {
        Scalar wrong_z_A;
        {
            LOCK(g_ctx_mutex);
            secp256k1_context* ctx = JCtx();
            do { GetRandBytes(wrong_z_A); }
            while (!secp256k1_ec_seckey_verify(ctx, wrong_z_A.data()));
        }
        auto bad = CooperativeSignTwoPartyML(
            std::span<const MultiLayerMember>{ring_ml}, pi_ml,
            x_A, x_B, wrong_z_A, z_B, msg);
        if (bad && VerifyMultiLayer(std::span<const MultiLayerMember>{ring_ml},
                                    *bad, msg)) {
            throw std::runtime_error(
                "joint_ringsig multi-layer self-test: wrong z_A produced a verifying sig");
        }
    }
}

} // namespace pricoin::joint_ringsig
