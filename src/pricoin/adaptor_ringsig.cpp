// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pricoin/adaptor_ringsig.h>

#include <crypto/sha256.h>
#include <logging.h>
#include <pricoin/ringsig.h>
#include <random.h>
#include <secp256k1.h>
#include <sync.h>
#include <util/strencodings.h>

#include <cstring>
#include <stdexcept>

// IMPORTANT: ring-walk math here MUST match `pricoin::ringsig`'s
// `StepChallenge` byte-for-byte; otherwise adapted signatures
// produced by Adapt() will not verify under the deployed
// `pricoin::ringsig::Verify` / `VerifyMultiLayer`. Self-tests
// below feed every adapted signature through `ringsig::Verify` and
// fail on mismatch, catching divergence at every daemon start.

namespace pricoin::adaptor_ringsig {

namespace {

using ::pricoin::ringsig::kPointBytes;

Mutex g_ctx_mutex;
secp256k1_context* g_ctx GUARDED_BY(g_ctx_mutex){nullptr};

secp256k1_context* ACtx() EXCLUSIVE_LOCKS_REQUIRED(g_ctx_mutex)
{
    if (!g_ctx) {
        g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        if (!g_ctx) throw std::runtime_error("secp256k1_context_create failed (adaptor_ringsig)");
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

// out = a + b   (point addition)
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

// out = scalar · base    (where `base` is a serialized point)
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

// out = scalar · G
bool ScalarMultG(secp256k1_context* ctx, const Scalar& scalar, Point& out)
{
    secp256k1_pubkey p;
    if (!secp256k1_ec_pubkey_create(ctx, &p, scalar.data())) return false;
    return SerializePoint(ctx, p, out);
}

// Tagged hash-to-scalar with the same rejection/rehash protocol as
// `pricoin::ringsig::HashToScalar`. We use a distinct tag so DLEQ
// challenges can never collide with CLSAG step challenges.
Scalar HashToScalarAdaptor(
    secp256k1_context* ctx,
    std::span<const std::span<const unsigned char>> chunks)
{
    {
        CSHA256 h;
        h.Write(reinterpret_cast<const unsigned char*>("pricoin/adaptor-clsag/H_s-v1"), 28);
        for (const auto& c : chunks) h.Write(c.data(), c.size());
        Scalar out;
        h.Finalize(out.data());
        if (secp256k1_ec_seckey_verify(ctx, out.data())) return out;
    }
    constexpr const char* kRehashTag = "pricoin/adaptor-clsag/H_s-rehash-v1";
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
    throw std::runtime_error("HashToScalarAdaptor: rehash exhausted");
}

// DLEQ challenge per spec §3.0a:
//   e = H_session("dleq-challenge-v1",
//                 encode(G) || encode(H_p(P_pi))
//               || encode(T_G) || encode(T_H)
//               || encode(A_G) || encode(A_H)
//               || session_label || session_payload)
Scalar DLEQChallenge(
    secp256k1_context* ctx,
    const Point& G_bytes,
    const Point& Hp_bytes,
    const Point& T_G,
    const Point& T_H,
    const Point& A_G,
    const Point& A_H,
    std::span<const unsigned char> session_label,
    std::span<const unsigned char> session_payload)
{
    static constexpr char kTag[] = "dleq-challenge-v1";
    std::span<const unsigned char> chunks_arr[]{
        std::span<const unsigned char>{reinterpret_cast<const unsigned char*>(kTag), sizeof(kTag) - 1},
        std::span<const unsigned char>{G_bytes.data(),  G_bytes.size()},
        std::span<const unsigned char>{Hp_bytes.data(), Hp_bytes.size()},
        std::span<const unsigned char>{T_G.data(),      T_G.size()},
        std::span<const unsigned char>{T_H.data(),      T_H.size()},
        std::span<const unsigned char>{A_G.data(),      A_G.size()},
        std::span<const unsigned char>{A_H.data(),      A_H.size()},
        session_label,
        session_payload,
    };
    return HashToScalarAdaptor(ctx,
        std::span<const std::span<const unsigned char>>{chunks_arr,
            sizeof(chunks_arr) / sizeof(chunks_arr[0])});
}

// Encode the standard generator G as a 33-byte compressed pubkey.
// `secp256k1_ec_pubkey_create(1)` gives 1·G.
Point EncodeG(secp256k1_context* ctx)
{
    Scalar one{};
    one[31] = 0x01;
    Point G_bytes;
    if (!ScalarMultG(ctx, one, G_bytes)) {
        throw std::runtime_error("EncodeG failed");
    }
    return G_bytes;
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

} // namespace

// ─────────────────────────────────────────────────────────────────
// Public API.
// ─────────────────────────────────────────────────────────────────

std::optional<AdaptorPoints> ComputeAdaptorPoints(
    const Scalar& t, const Point& P_pi)
{
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = ACtx();
    if (!secp256k1_ec_seckey_verify(ctx, t.data())) return std::nullopt;

    AdaptorPoints out;
    if (!ScalarMultG(ctx, t, out.T_G)) return std::nullopt;

    const Point Hp = ::pricoin::ringsig::HashToPoint(
        std::span<const unsigned char>{P_pi.data(), P_pi.size()});
    if (!ScalarMultPoint(ctx, t, Hp, out.T_H)) return std::nullopt;
    return out;
}

std::optional<DLEQProof> MakeDLEQProof(
    const Scalar& t,
    const Point& P_pi,
    const AdaptorPoints& adaptor,
    std::span<const unsigned char> session_label,
    std::span<const unsigned char> session_payload)
{
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = ACtx();
    if (!secp256k1_ec_seckey_verify(ctx, t.data())) return std::nullopt;

    const Point Hp = ::pricoin::ringsig::HashToPoint(
        std::span<const unsigned char>{P_pi.data(), P_pi.size()});
    const Point G_bytes = EncodeG(ctx);

    // Pick fresh random r.
    Scalar r;
    do { GetRandBytes(r); } while (!secp256k1_ec_seckey_verify(ctx, r.data()));

    DLEQProof proof;
    if (!ScalarMultG(ctx, r, proof.A_G)) return std::nullopt;
    if (!ScalarMultPoint(ctx, r, Hp, proof.A_H)) return std::nullopt;

    const Scalar e = DLEQChallenge(ctx, G_bytes, Hp,
        adaptor.T_G, adaptor.T_H, proof.A_G, proof.A_H,
        session_label, session_payload);

    // z = r + e * t (mod n).
    Scalar et = e;
    if (!secp256k1_ec_seckey_tweak_mul(ctx, et.data(), t.data())) return std::nullopt;
    Scalar z = r;
    if (!secp256k1_ec_seckey_tweak_add(ctx, z.data(), et.data())) return std::nullopt;
    proof.z = z;
    return proof;
}

bool VerifyDLEQProof(
    const Point& P_pi,
    const AdaptorPoints& adaptor,
    const DLEQProof& proof,
    std::span<const unsigned char> session_label,
    std::span<const unsigned char> session_payload)
{
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = ACtx();

    // All points must be valid + non-infinity.
    secp256k1_pubkey tmp;
    if (!ParsePoint(ctx, adaptor.T_G, tmp)) return false;
    if (!ParsePoint(ctx, adaptor.T_H, tmp)) return false;
    if (!ParsePoint(ctx, proof.A_G,   tmp)) return false;
    if (!ParsePoint(ctx, proof.A_H,   tmp)) return false;
    if (!secp256k1_ec_seckey_verify(ctx, proof.z.data())) return false;

    const Point Hp = ::pricoin::ringsig::HashToPoint(
        std::span<const unsigned char>{P_pi.data(), P_pi.size()});
    const Point G_bytes = EncodeG(ctx);

    const Scalar e = DLEQChallenge(ctx, G_bytes, Hp,
        adaptor.T_G, adaptor.T_H, proof.A_G, proof.A_H,
        session_label, session_payload);

    // Check z·G == A_G + e·T_G.
    Point lhs1, eT_G, rhs1;
    if (!ScalarMultG(ctx, proof.z, lhs1)) return false;
    if (!ScalarMultPoint(ctx, e, adaptor.T_G, eT_G)) return false;
    if (!AddPoints(ctx, proof.A_G, eT_G, rhs1)) return false;
    if (lhs1 != rhs1) return false;

    // Check z·H_p == A_H + e·T_H.
    Point lhs2, eT_H, rhs2;
    if (!ScalarMultPoint(ctx, proof.z, Hp, lhs2)) return false;
    if (!ScalarMultPoint(ctx, e, adaptor.T_H, eT_H)) return false;
    if (!AddPoints(ctx, proof.A_H, eT_H, rhs2)) return false;
    if (lhs2 != rhs2) return false;
    return true;
}

namespace {

// Shifted-anchor pre-signature walk. Produces a CLSAG-shaped
// signature with `s[pi]` set to the pre-sig closing scalar `ŝ_pi`.
// The walk uses `L'_pi, R'_pi` (shifted by T_G, T_H) at index pi
// and the standard `pricoin::ringsig::StepChallenge` everywhere.
//
// Implementation note: we do NOT reuse `pricoin::ringsig::Sign`
// because that helper picks α internally and feeds un-shifted L,R
// to the walk. Instead we mirror its math here with the shift
// inserted at index pi.
std::optional<Signature> SignShifted(
    std::span<const Point> ring,
    size_t pi,
    const Scalar& x_pi,
    const uint256& msg,
    const AdaptorPoints& adaptor,
    secp256k1_context* ctx) EXCLUSIVE_LOCKS_REQUIRED(g_ctx_mutex)
{
    if (ring.empty() || pi >= ring.size()) return std::nullopt;
    if (HasDuplicate(ring)) return std::nullopt;
    if (!secp256k1_ec_seckey_verify(ctx, x_pi.data())) return std::nullopt;

    // Sanity: x_pi · G == ring[pi].
    {
        Point check;
        if (!ScalarMultG(ctx, x_pi, check)) return std::nullopt;
        if (check != ring[pi]) return std::nullopt;
    }

    Signature sig;
    sig.s.resize(ring.size());

    // KI = x_pi · H_p(P_pi)
    const Point Hp_pi = ::pricoin::ringsig::HashToPoint(
        std::span<const unsigned char>{ring[pi].data(), ring[pi].size()});
    if (!ScalarMultPoint(ctx, x_pi, Hp_pi, sig.key_image)) return std::nullopt;

    // Pick alpha, compute (L_pi, R_pi).
    Scalar alpha;
    do { GetRandBytes(alpha); } while (!secp256k1_ec_seckey_verify(ctx, alpha.data()));

    Point L_pi, R_pi;
    if (!ScalarMultG(ctx, alpha, L_pi)) return std::nullopt;
    if (!ScalarMultPoint(ctx, alpha, Hp_pi, R_pi)) return std::nullopt;

    // Shifted anchors.
    Point L_prime, R_prime;
    if (!AddPoints(ctx, L_pi, adaptor.T_G, L_prime)) return std::nullopt;
    if (!AddPoints(ctx, R_pi, adaptor.T_H, R_prime)) return std::nullopt;

    // Walk the ring. We need to call `ringsig::StepChallenge` and
    // the L_i / R_i computation helpers. Since those are private
    // to ringsig.cpp, we mirror them here using `ringsig::HashToPoint`
    // (public) and the same hash structure. Self-tests confirm
    // byte-compatibility.
    auto step_challenge = [&](std::span<const Point> r,
                              const uint256& m,
                              const Point& L_i, const Point& R_i,
                              const Point& KI) -> Scalar
    {
        std::vector<unsigned char> ring_blob;
        ring_blob.reserve(r.size() * kPointBytes);
        for (const auto& p : r) ring_blob.insert(ring_blob.end(), p.begin(), p.end());
        std::span<const unsigned char> chunks_arr[5]{
            std::span<const unsigned char>{ring_blob},
            std::span<const unsigned char>{m.data(), m.size()},
            std::span<const unsigned char>{L_i.data(), L_i.size()},
            std::span<const unsigned char>{R_i.data(), R_i.size()},
            std::span<const unsigned char>{KI.data(), KI.size()},
        };
        // Use ringsig's HashToScalar via its public HashToPoint sibling? No —
        // HashToScalar is private. We mirror its hashing here with the same
        // tag. Self-tests (round-trip through ringsig::Verify) catch any
        // divergence.
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
        // Rehash path mirrors ringsig.cpp.
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
        throw std::runtime_error("step_challenge: rehash exhausted");
    };

    // Compute L_i = s_i·G + c_i·P_i  and  R_i = s_i·H_p(P_i) + c_i·KI.
    auto compute_LR = [&](const Scalar& s_i, const Scalar& c_i,
                          const Point& P_i, Point& L_out, Point& R_out) -> bool
    {
        Point sG, cP;
        if (!ScalarMultG(ctx, s_i, sG)) return false;
        if (!ScalarMultPoint(ctx, c_i, P_i, cP)) return false;
        if (!AddPoints(ctx, sG, cP, L_out)) return false;
        const Point Hp_i = ::pricoin::ringsig::HashToPoint(
            std::span<const unsigned char>{P_i.data(), P_i.size()});
        Point sHp, cKI;
        if (!ScalarMultPoint(ctx, s_i, Hp_i, sHp)) return false;
        if (!ScalarMultPoint(ctx, c_i, sig.key_image, cKI)) return false;
        if (!AddPoints(ctx, sHp, cKI, R_out)) return false;
        return true;
    };

    const size_t N = ring.size();
    std::vector<Scalar> c(N);

    // c_{pi+1} from the SHIFTED anchors (this is the adaptor twist).
    c[(pi + 1) % N] = step_challenge(ring, msg, L_prime, R_prime, sig.key_image);

    for (size_t step = 1; step < N; ++step) {
        const size_t i = (pi + step) % N;
        do { GetRandBytes(sig.s[i]); } while (!secp256k1_ec_seckey_verify(ctx, sig.s[i].data()));
        Point L_i, R_i;
        if (!compute_LR(sig.s[i], c[i], ring[i], L_i, R_i)) return std::nullopt;
        c[(i + 1) % N] = step_challenge(ring, msg, L_i, R_i, sig.key_image);
    }

    // ŝ_pi = alpha - c_pi · x_pi  (mod n)
    Scalar prod = c[pi];
    if (!secp256k1_ec_seckey_tweak_mul(ctx, prod.data(), x_pi.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_negate(ctx, prod.data())) return std::nullopt;
    Scalar s_pi_pre = alpha;
    if (!secp256k1_ec_seckey_tweak_add(ctx, s_pi_pre.data(), prod.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_verify(ctx, s_pi_pre.data())) return std::nullopt;
    sig.s[pi] = s_pi_pre;
    sig.c0 = c[0];
    return sig;
}

} // namespace

std::optional<AdaptorPreSignature> MakePreSignature(
    std::span<const Point> ring,
    size_t pi,
    const Scalar& x_pi,
    const uint256& msg,
    const AdaptorPoints& adaptor,
    const DLEQProof& dleq,
    std::span<const unsigned char> session_label,
    std::span<const unsigned char> session_payload)
{
    if (pi >= ring.size()) return std::nullopt;

    // Verify the DLEQ before doing anything else (spec §3.1 step 1).
    if (!VerifyDLEQProof(ring[pi], adaptor, dleq, session_label, session_payload)) {
        return std::nullopt;
    }

    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = ACtx();
    auto sig_opt = SignShifted(ring, pi, x_pi, msg, adaptor, ctx);
    if (!sig_opt) return std::nullopt;

    AdaptorPreSignature out;
    out.key_image        = sig_opt->key_image;
    out.commitment_image = sig_opt->commitment_image;
    out.c0               = sig_opt->c0;
    out.s                = std::move(sig_opt->s);
    out.adaptor          = adaptor;
    out.dleq             = dleq;
    out.pi               = static_cast<uint32_t>(pi);
    return out;
}

bool VerifyPreSignature(
    std::span<const Point> ring,
    const AdaptorPreSignature& presig,
    const uint256& msg,
    std::span<const unsigned char> session_label,
    std::span<const unsigned char> session_payload)
{
    if (ring.empty() || presig.s.size() != ring.size()) return false;
    if (presig.pi >= ring.size()) return false;
    if (HasDuplicate(ring)) return false;

    // Verify DLEQ BEFORE taking our mutex — VerifyDLEQProof acquires
    // its own LOCK(g_ctx_mutex), and Bitcoin Core's Mutex is non-
    // recursive, so calling it from inside our locked region would
    // deadlock.
    if (!VerifyDLEQProof(ring[presig.pi], presig.adaptor, presig.dleq,
                          session_label, session_payload)) return false;

    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = ACtx();

    secp256k1_pubkey tmp;
    if (!ParsePoint(ctx, presig.key_image, tmp)) return false;
    for (const auto& p : ring) if (!ParsePoint(ctx, p, tmp)) return false;
    if (!secp256k1_ec_seckey_verify(ctx, presig.c0.data())) return false;
    for (const auto& s : presig.s) if (!secp256k1_ec_seckey_verify(ctx, s.data())) return false;

    // Walk the ring; at index pi shift L_i, R_i by T_G, T_H.
    auto step_challenge = [&](std::span<const Point> r,
                              const uint256& m,
                              const Point& L_i, const Point& R_i,
                              const Point& KI) -> Scalar
    {
        std::vector<unsigned char> ring_blob;
        ring_blob.reserve(r.size() * kPointBytes);
        for (const auto& p : r) ring_blob.insert(ring_blob.end(), p.begin(), p.end());
        std::span<const unsigned char> chunks_arr[5]{
            std::span<const unsigned char>{ring_blob},
            std::span<const unsigned char>{m.data(), m.size()},
            std::span<const unsigned char>{L_i.data(), L_i.size()},
            std::span<const unsigned char>{R_i.data(), R_i.size()},
            std::span<const unsigned char>{KI.data(), KI.size()},
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
        throw std::runtime_error("verify step_challenge: rehash exhausted");
    };

    Scalar c = presig.c0;
    const size_t N = ring.size();
    for (size_t i = 0; i < N; ++i) {
        Point sG, cP, L_i;
        if (!ScalarMultG(ctx, presig.s[i], sG)) return false;
        if (!ScalarMultPoint(ctx, c, ring[i], cP)) return false;
        if (!AddPoints(ctx, sG, cP, L_i)) return false;

        const Point Hp_i = ::pricoin::ringsig::HashToPoint(
            std::span<const unsigned char>{ring[i].data(), ring[i].size()});
        Point sHp, cKI, R_i;
        if (!ScalarMultPoint(ctx, presig.s[i], Hp_i, sHp)) return false;
        if (!ScalarMultPoint(ctx, c, presig.key_image, cKI)) return false;
        if (!AddPoints(ctx, sHp, cKI, R_i)) return false;

        if (i == presig.pi) {
            // Add T_G to L_i, T_H to R_i.
            Point L_shifted, R_shifted;
            if (!AddPoints(ctx, L_i, presig.adaptor.T_G, L_shifted)) return false;
            if (!AddPoints(ctx, R_i, presig.adaptor.T_H, R_shifted)) return false;
            L_i = L_shifted;
            R_i = R_shifted;
        }
        c = step_challenge(ring, msg, L_i, R_i, presig.key_image);
    }
    return c == presig.c0;
}

std::optional<Signature> Adapt(
    const AdaptorPreSignature& presig,
    const Scalar& t,
    std::span<const Point> ring,
    const uint256& msg)
{
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = ACtx();

    // Verify t · G == T_G (round-trip the adaptor secret).
    Point tG;
    if (!ScalarMultG(ctx, t, tG)) return std::nullopt;
    if (tG != presig.adaptor.T_G) return std::nullopt;

    Signature sig;
    sig.key_image        = presig.key_image;
    sig.commitment_image = presig.commitment_image;
    sig.c0               = presig.c0;
    sig.s                = presig.s;

    // s_pi = ŝ_pi + t  (mod n).
    Scalar s_pi = presig.s[presig.pi];
    if (!secp256k1_ec_seckey_tweak_add(ctx, s_pi.data(), t.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_verify(ctx, s_pi.data())) {
        // Negligible-probability zero result (spec §3.3 + Finding G).
        return std::nullopt;
    }
    sig.s[presig.pi] = s_pi;

    // Verify the resulting signature passes the standard CLSAG verifier.
    if (!::pricoin::ringsig::Verify(ring, sig, msg)) return std::nullopt;
    return sig;
}

std::optional<Signature> AdaptML(
    const AdaptorPreSignature& presig,
    const Scalar& t,
    std::span<const ::pricoin::ringsig::MultiLayerMember> ring,
    const uint256& msg)
{
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = ACtx();

    // Verify t · G == T_G.
    Point tG;
    if (!ScalarMultG(ctx, t, tG)) {
        LogWarning("Pricoin AdaptML: ScalarMultG(t) failed");
        return std::nullopt;
    }
    if (tG != presig.adaptor.T_G) {
        LogWarning("Pricoin AdaptML: t·G != T_G "
                   "(t·G=%s, presig.T_G=%s) — wrong adaptor secret",
                   HexStr(tG), HexStr(presig.adaptor.T_G));
        return std::nullopt;
    }

    Signature sig;
    sig.key_image        = presig.key_image;
    sig.commitment_image = presig.commitment_image;
    sig.c0               = presig.c0;
    sig.s                = presig.s;

    Scalar s_pi = presig.s[presig.pi];
    if (!secp256k1_ec_seckey_tweak_add(ctx, s_pi.data(), t.data())) {
        LogWarning("Pricoin AdaptML: s_pi + t tweak_add failed (overflow/zero)");
        return std::nullopt;
    }
    if (!secp256k1_ec_seckey_verify(ctx, s_pi.data())) {
        LogWarning("Pricoin AdaptML: s_pi+t failed seckey_verify (zero/oob)");
        return std::nullopt;
    }
    sig.s[presig.pi] = s_pi;

    // Multi-layer verify against (P, W) ring — what consensus uses.
    if (!::pricoin::ringsig::VerifyMultiLayer(ring, sig, msg)) {
        LogWarning("Pricoin AdaptML: post-tweak VerifyMultiLayer failed "
                   "(ring/msg mismatch — ring used here does not match the "
                   "one the pre-sig was built against, OR msg differs; "
                   "ring_size=%u, pi=%u, msg=%s, KI=%s, D=%s, c0=%s)",
                   (unsigned)ring.size(), (unsigned)presig.pi,
                   msg.ToString(),
                   HexStr(presig.key_image),
                   HexStr(presig.commitment_image),
                   HexStr(presig.c0));
        return std::nullopt;
    }
    return sig;
}

std::optional<Scalar> Extract(
    std::span<const Point> ring,
    const AdaptorPreSignature& presig,
    const Signature& sig)
{
    if (presig.pi >= ring.size()) return std::nullopt;
    if (sig.s.size() != presig.s.size()) return std::nullopt;

    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = ACtx();

    // t = sig.s[pi] - presig.s[pi]  (mod n).
    Scalar neg_pre = presig.s[presig.pi];
    if (!secp256k1_ec_seckey_negate(ctx, neg_pre.data())) return std::nullopt;
    Scalar t = sig.s[presig.pi];
    if (!secp256k1_ec_seckey_tweak_add(ctx, t.data(), neg_pre.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_verify(ctx, t.data())) return std::nullopt;

    // Verify t · G == T_G.
    Point tG;
    if (!ScalarMultG(ctx, t, tG)) return std::nullopt;
    if (tG != presig.adaptor.T_G) return std::nullopt;

    // Verify t · H_p(P_pi) == T_H.
    const Point Hp_pi = ::pricoin::ringsig::HashToPoint(
        std::span<const unsigned char>{ring[presig.pi].data(), ring[presig.pi].size()});
    Point tH;
    if (!ScalarMultPoint(ctx, t, Hp_pi, tH)) return std::nullopt;
    if (tH != presig.adaptor.T_H) return std::nullopt;
    return t;
}

void RunSelfTest()
{
    using ::pricoin::ringsig::Verify;

    constexpr size_t N = 4;
    constexpr size_t pi = 2;

    std::vector<Point> ring(N);
    std::vector<Scalar> privs(N);
    {
        LOCK(g_ctx_mutex);
        secp256k1_context* ctx = ACtx();
        for (size_t i = 0; i < N; ++i) {
            do { GetRandBytes(privs[i]); }
            while (!secp256k1_ec_seckey_verify(ctx, privs[i].data()));
            if (!ScalarMultG(ctx, privs[i], ring[i])) {
                throw std::runtime_error("adaptor self-test: ScalarMultG failed");
            }
        }
    }

    // Bob picks t.
    Scalar t;
    {
        LOCK(g_ctx_mutex);
        secp256k1_context* ctx = ACtx();
        do { GetRandBytes(t); }
        while (!secp256k1_ec_seckey_verify(ctx, t.data()));
    }

    auto adaptor = ComputeAdaptorPoints(t, ring[pi]);
    if (!adaptor) throw std::runtime_error("adaptor self-test: ComputeAdaptorPoints failed");

    // Session payload simulating spec §2.1's SESSION transcript.
    const std::array<unsigned char, 16> session_payload{
        'p','r','i','-','a','d','a','p','t','o','r','-','s','t','-','1'};
    static constexpr char kLabel[] = "pricoin/adaptor-clsag/test-session-v1";
    auto label_span = std::span<const unsigned char>{
        reinterpret_cast<const unsigned char*>(kLabel), sizeof(kLabel) - 1};
    auto payload_span = std::span<const unsigned char>{
        session_payload.data(), session_payload.size()};

    // ─── DLEQ honest round-trip ──────────────────────────────
    auto dleq = MakeDLEQProof(t, ring[pi], *adaptor, label_span, payload_span);
    if (!dleq) throw std::runtime_error("adaptor self-test: MakeDLEQProof failed");
    if (!VerifyDLEQProof(ring[pi], *adaptor, *dleq, label_span, payload_span)) {
        throw std::runtime_error("adaptor self-test: honest DLEQ failed verification");
    }

    // ─── DLEQ replay across sessions rejected ────────────────
    {
        const std::array<unsigned char, 16> alt_payload{
            'd','i','f','f','e','r','e','n','t','-','s','e','s','s','i','o'};
        if (VerifyDLEQProof(ring[pi], *adaptor, *dleq, label_span,
                std::span<const unsigned char>{alt_payload.data(), alt_payload.size()})) {
            throw std::runtime_error("adaptor self-test: DLEQ replay across sessions accepted");
        }
    }

    // ─── DLEQ with mismatched T_H rejected ───────────────────
    {
        AdaptorPoints bad = *adaptor;
        // Flip a bit in T_H.
        bad.T_H[5] ^= 0x01;
        if (VerifyDLEQProof(ring[pi], bad, *dleq, label_span, payload_span)) {
            throw std::runtime_error("adaptor self-test: DLEQ with tampered T_H accepted");
        }
    }

    // ─── Pre-sig + Adapt + Extract round-trip ────────────────
    const uint256 msg = uint256::ONE;
    auto presig = MakePreSignature(
        std::span<const Point>{ring}, pi, privs[pi], msg,
        *adaptor, *dleq, label_span, payload_span);
    if (!presig) throw std::runtime_error("adaptor self-test: MakePreSignature failed");

    if (!VerifyPreSignature(std::span<const Point>{ring}, *presig, msg, label_span, payload_span)) {
        throw std::runtime_error("adaptor self-test: VerifyPreSignature failed");
    }

    auto sig = Adapt(*presig, t, std::span<const Point>{ring}, msg);
    if (!sig) throw std::runtime_error("adaptor self-test: Adapt failed");

    // The adapted signature MUST verify under the standard CLSAG verifier.
    if (!Verify(std::span<const Point>{ring}, *sig, msg)) {
        throw std::runtime_error("adaptor self-test: adapted signature failed standard CLSAG verify");
    }

    auto extracted = Extract(std::span<const Point>{ring}, *presig, *sig);
    if (!extracted) throw std::runtime_error("adaptor self-test: Extract failed");
    if (*extracted != t) {
        throw std::runtime_error("adaptor self-test: extracted t != original t");
    }

    // ─── Sign-flip in Adapt detected ─────────────────────────
    // Try Adapt with -t (wrong sign). secp256k1_ec_seckey_negate
    // gives us -t; the resulting "adapted" signature must NOT
    // verify under standard CLSAG.
    {
        Scalar neg_t = t;
        {
            LOCK(g_ctx_mutex);
            secp256k1_context* ctx = ACtx();
            if (!secp256k1_ec_seckey_negate(ctx, neg_t.data())) {
                throw std::runtime_error("adaptor self-test: negate t failed");
            }
        }
        // Adapt's t·G==T_G check rejects neg_t.
        auto bad = Adapt(*presig, neg_t, std::span<const Point>{ring}, msg);
        if (bad) {
            throw std::runtime_error("adaptor self-test: Adapt accepted -t (must reject)");
        }
    }

    // ─── Tampered adapted sig detected ───────────────────────
    {
        Signature bad_sig = *sig;
        bad_sig.s[0][0] ^= 0x01;
        if (Verify(std::span<const Point>{ring}, bad_sig, msg)) {
            throw std::runtime_error("adaptor self-test: tampered s[0] accepted");
        }
    }

    // ─── Wrong-T_H base detected by Extract ──────────────────
    // Construct a presig where T_H uses a wrong base. Extract's
    // post-extraction check `t · H_p(P_pi) == T_H` must fire.
    {
        AdaptorPreSignature bad_presig = *presig;
        // Replace T_H with t·H_p(ring[0]) (wrong base).
        Scalar t_local;
        {
            LOCK(g_ctx_mutex);
            secp256k1_context* ctx = ACtx();
            // Re-extract the same t we used originally so we can
            // construct a consistent-but-wrong-base T_H.
            t_local = t;
            const Point Hp_zero = ::pricoin::ringsig::HashToPoint(
                std::span<const unsigned char>{ring[0].data(), ring[0].size()});
            if (!ScalarMultPoint(ctx, t_local, Hp_zero, bad_presig.adaptor.T_H)) {
                throw std::runtime_error("adaptor self-test: wrong-base T_H compute failed");
            }
        }
        auto bad_extract = Extract(std::span<const Point>{ring}, bad_presig, *sig);
        if (bad_extract) {
            throw std::runtime_error("adaptor self-test: Extract accepted wrong-base T_H");
        }
    }

    // ─── Pre-sig with bad DLEQ rejected ──────────────────────
    {
        AdaptorPreSignature bad_presig = *presig;
        bad_presig.dleq.z[0] ^= 0x01;
        if (VerifyPreSignature(std::span<const Point>{ring}, bad_presig, msg,
                                label_span, payload_span)) {
            throw std::runtime_error("adaptor self-test: VerifyPreSignature accepted tampered DLEQ");
        }
    }
}

} // namespace pricoin::adaptor_ringsig
