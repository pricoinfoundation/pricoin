// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pricoin/ringsig.h>

#include <crypto/sha256.h>
#include <key.h>
#include <random.h>
#include <secp256k1.h>
#include <span.h>
#include <sync.h>
#include <util/strencodings.h>

#include <cstring>
#include <stdexcept>

namespace pricoin::ringsig {

namespace {

Mutex g_mutex;
secp256k1_context* g_ctx GUARDED_BY(g_mutex){nullptr};

secp256k1_context* Ctx() EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    if (!g_ctx) g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    return g_ctx;
}

bool ParsePoint(const Point& bytes, secp256k1_pubkey& out) EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    return secp256k1_ec_pubkey_parse(Ctx(), &out, bytes.data(), bytes.size()) == 1;
}

bool SerializePoint(const secp256k1_pubkey& in, Point& out) EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    size_t len = out.size();
    return secp256k1_ec_pubkey_serialize(Ctx(), out.data(), &len, &in, SECP256K1_EC_COMPRESSED) == 1
           && len == kPointBytes;
}

// H_p: hash-to-point via try-and-increment. Take SHA256(seed || counter)
// as the candidate x-coord, try parsing as both even-y and odd-y compressed
// pubkeys until one is valid. Average ~2 retries (each x has ~50% chance of
// being on the curve).
Point HashToPointInternal(std::span<const unsigned char> seed) EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    Point result{};
    unsigned char buf[33];
    uint32_t counter = 0;
    secp256k1_pubkey raw;
    while (true) {
        CSHA256 h;
        h.Write(reinterpret_cast<const unsigned char*>("pricoin/ringsig/H_p"), 19);
        h.Write(seed.data(), seed.size());
        unsigned char ctr_bytes[4]{
            static_cast<unsigned char>(counter & 0xff),
            static_cast<unsigned char>((counter >> 8) & 0xff),
            static_cast<unsigned char>((counter >> 16) & 0xff),
            static_cast<unsigned char>((counter >> 24) & 0xff)};
        h.Write(ctr_bytes, 4);
        h.Finalize(buf + 1);
        for (unsigned char prefix : {0x02, 0x03}) {
            buf[0] = prefix;
            if (secp256k1_ec_pubkey_parse(Ctx(), &raw, buf, 33)) {
                if (SerializePoint(raw, result)) return result;
            }
        }
        ++counter;
        if (counter == 0) break; // pathological — wraparound (~impossible)
    }
    throw std::runtime_error("HashToPoint: exhausted counter (impossible)");
}

// Tagged-hash style H_s: SHA256("pricoin/ringsig/H_s-v1" || data...) reduced
// mod n. Returns a 32-byte scalar guaranteed to be a valid secp256k1 scalar.
Scalar HashToScalar(std::span<const std::span<const unsigned char>> chunks)
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    while (true) {
        CSHA256 h;
        h.Write(reinterpret_cast<const unsigned char*>("pricoin/ringsig/H_s-v1"), 22);
        for (const auto& c : chunks) h.Write(c.data(), c.size());
        Scalar out;
        h.Finalize(out.data());
        if (secp256k1_ec_seckey_verify(Ctx(), out.data())) return out;
        // If invalid (extremely rare), tweak by hashing again with a tag.
        chunks = std::span<const std::span<const unsigned char>>{};
    }
}

// Compute s*G + c*P, return as a Point. Used in the inner ring loop.
bool LinComb_sG_plus_cP(const Scalar& s, const Scalar& c, const secp256k1_pubkey& P, Point& out)
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    secp256k1_pubkey sG;
    if (!secp256k1_ec_pubkey_create(Ctx(), &sG, s.data())) return false;
    secp256k1_pubkey cP = P;
    if (!secp256k1_ec_pubkey_tweak_mul(Ctx(), &cP, c.data())) return false;
    const secp256k1_pubkey* parts[2] = {&sG, &cP};
    secp256k1_pubkey sum;
    if (!secp256k1_ec_pubkey_combine(Ctx(), &sum, parts, 2)) return false;
    return SerializePoint(sum, out);
}

// Compute s*Q + c*R, where Q, R are already-serialized points, returning a Point.
bool LinComb_sQ_plus_cR(const Scalar& s, const Point& Q_bytes, const Scalar& c, const Point& R_bytes, Point& out)
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    secp256k1_pubkey Q, R;
    if (!ParsePoint(Q_bytes, Q) || !ParsePoint(R_bytes, R)) return false;
    secp256k1_pubkey sQ = Q;
    if (!secp256k1_ec_pubkey_tweak_mul(Ctx(), &sQ, s.data())) return false;
    secp256k1_pubkey cR = R;
    if (!secp256k1_ec_pubkey_tweak_mul(Ctx(), &cR, c.data())) return false;
    const secp256k1_pubkey* parts[2] = {&sQ, &cR};
    secp256k1_pubkey sum;
    if (!secp256k1_ec_pubkey_combine(Ctx(), &sum, parts, 2)) return false;
    return SerializePoint(sum, out);
}

// L_i = s_i * G + c_i * P_i (point compose with G via pubkey_create).
bool Compute_L(const Scalar& s_i, const Scalar& c_i, const Point& P_bytes, Point& out)
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    secp256k1_pubkey P;
    if (!ParsePoint(P_bytes, P)) return false;
    return LinComb_sG_plus_cP(s_i, c_i, P, out);
}

// R_i = s_i * H_p(P_i) + c_i * I.
bool Compute_R(const Scalar& s_i, const Scalar& c_i, const Point& P_bytes, const Point& I_bytes, Point& out)
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    Point Hp = HashToPointInternal(std::span<const unsigned char>{P_bytes.data(), P_bytes.size()});
    return LinComb_sQ_plus_cR(s_i, Hp, c_i, I_bytes, out);
}

// Build the input chunks to H_s for the per-step challenge:
// H_s("pricoin/ringsig/H_s-v1" || ring || msg || L_i || R_i || I)
Scalar StepChallenge(
    std::span<const Point> ring,
    const uint256& msg,
    const Point& L_i,
    const Point& R_i,
    const Point& I) EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    // Concatenate everything into one buffer; HashToScalar splits, but for
    // simplicity build a flat chunk list.
    std::vector<unsigned char> ring_blob;
    ring_blob.reserve(ring.size() * kPointBytes);
    for (const auto& p : ring) ring_blob.insert(ring_blob.end(), p.begin(), p.end());
    std::span<const unsigned char> chunks_arr[5]{
        std::span<const unsigned char>{ring_blob},
        std::span<const unsigned char>{msg.data(), msg.size()},
        std::span<const unsigned char>{L_i.data(), L_i.size()},
        std::span<const unsigned char>{R_i.data(), R_i.size()},
        std::span<const unsigned char>{I.data(), I.size()},
    };
    return HashToScalar(std::span<const std::span<const unsigned char>>{chunks_arr, 5});
}

} // namespace

Point HashToPoint(std::span<const unsigned char> seed)
{
    LOCK(g_mutex);
    return HashToPointInternal(seed);
}

std::optional<Signature> Sign(
    std::span<const Point> ring,
    size_t pi,
    const Scalar& x_pi,
    const uint256& msg)
{
    if (ring.empty() || pi >= ring.size()) return std::nullopt;
    LOCK(g_mutex);

    // Verify x_pi corresponds to ring[pi].
    {
        secp256k1_pubkey computed;
        if (!secp256k1_ec_pubkey_create(Ctx(), &computed, x_pi.data())) return std::nullopt;
        Point computed_bytes;
        if (!SerializePoint(computed, computed_bytes)) return std::nullopt;
        if (computed_bytes != ring[pi]) return std::nullopt;
    }

    Signature sig;
    sig.s.resize(ring.size());

    // Compute key image I = x_pi * H_p(ring[pi]).
    Point Hp_pi = HashToPointInternal(std::span<const unsigned char>{ring[pi].data(), ring[pi].size()});
    {
        secp256k1_pubkey Hp_pi_pub;
        if (!ParsePoint(Hp_pi, Hp_pi_pub)) return std::nullopt;
        if (!secp256k1_ec_pubkey_tweak_mul(Ctx(), &Hp_pi_pub, x_pi.data())) return std::nullopt;
        if (!SerializePoint(Hp_pi_pub, sig.key_image)) return std::nullopt;
    }

    // Pick alpha (random scalar).
    Scalar alpha;
    do { GetRandBytes(alpha); } while (!secp256k1_ec_seckey_verify(Ctx(), alpha.data()));

    // Initial L_pi, R_pi.
    Point L_pi, R_pi;
    {
        secp256k1_pubkey aG;
        if (!secp256k1_ec_pubkey_create(Ctx(), &aG, alpha.data())) return std::nullopt;
        if (!SerializePoint(aG, L_pi)) return std::nullopt;
        secp256k1_pubkey aHp = [&] {
            secp256k1_pubkey p;
            ParsePoint(Hp_pi, p);
            return p;
        }();
        if (!secp256k1_ec_pubkey_tweak_mul(Ctx(), &aHp, alpha.data())) return std::nullopt;
        if (!SerializePoint(aHp, R_pi)) return std::nullopt;
    }

    // c_{pi+1} closes the ring around. We store all challenges, then later
    // serialize only c_0 (the verifier reconstructs the rest).
    std::vector<Scalar> c(ring.size());
    const size_t N = ring.size();
    c[(pi + 1) % N] = StepChallenge(ring, msg, L_pi, R_pi, sig.key_image);

    // Walk the ring forward from pi+1 back to pi, generating random s_i and
    // computing the next c.
    for (size_t step = 1; step < N; ++step) {
        const size_t i = (pi + step) % N;
        do { GetRandBytes(sig.s[i]); } while (!secp256k1_ec_seckey_verify(Ctx(), sig.s[i].data()));
        Point L_i, R_i;
        if (!Compute_L(sig.s[i], c[i], ring[i], L_i)) return std::nullopt;
        if (!Compute_R(sig.s[i], c[i], ring[i], sig.key_image, R_i)) return std::nullopt;
        c[(i + 1) % N] = StepChallenge(ring, msg, L_i, R_i, sig.key_image);
    }

    // s_pi = alpha - c_pi * x_pi (mod n). Compute via -tweak_add(tweak_mul(c_pi, x_pi)).
    Scalar prod = c[pi];
    if (!secp256k1_ec_seckey_tweak_mul(Ctx(), prod.data(), x_pi.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_negate(Ctx(), prod.data())) return std::nullopt;
    Scalar s_pi = alpha;
    if (!secp256k1_ec_seckey_tweak_add(Ctx(), s_pi.data(), prod.data())) return std::nullopt;
    sig.s[pi] = s_pi;

    sig.c0 = c[0];
    return sig;
}

bool Verify(
    std::span<const Point> ring,
    const Signature& sig,
    const uint256& msg)
{
    if (ring.empty() || sig.s.size() != ring.size()) return false;
    LOCK(g_mutex);
    // Validate ring members and key image are valid points.
    secp256k1_pubkey tmp;
    if (!ParsePoint(sig.key_image, tmp)) return false;
    for (const auto& p : ring) {
        if (!ParsePoint(p, tmp)) return false;
    }
    // Validate scalars.
    if (!secp256k1_ec_seckey_verify(Ctx(), sig.c0.data())) return false;
    for (const auto& s : sig.s) {
        if (!secp256k1_ec_seckey_verify(Ctx(), s.data())) return false;
    }

    // Walk the ring; recompute c at each step and check c_0 matches.
    Scalar c = sig.c0;
    const size_t N = ring.size();
    for (size_t i = 0; i < N; ++i) {
        Point L_i, R_i;
        if (!Compute_L(sig.s[i], c, ring[i], L_i)) return false;
        if (!Compute_R(sig.s[i], c, ring[i], sig.key_image, R_i)) return false;
        c = StepChallenge(ring, msg, L_i, R_i, sig.key_image);
    }
    // After full loop, c should equal c_0.
    return c == sig.c0;
}

namespace {

// Compute μ-weights for the multi-layer aggregation: μ_P, μ_C are scalars
// derived from a hash of all (P_i, W_i) pairs. Distinct prefixes for the
// two rows ensure they're independent.
std::pair<Scalar, Scalar> MultiLayerMu(std::span<const MultiLayerMember> ring)
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    std::vector<unsigned char> ring_blob;
    ring_blob.reserve(ring.size() * (kPointBytes * 2));
    for (const auto& m : ring) {
        ring_blob.insert(ring_blob.end(), m.P.begin(), m.P.end());
        ring_blob.insert(ring_blob.end(), m.W.begin(), m.W.end());
    }
    auto mu = [&](const char* tag) {
        std::span<const unsigned char> chunks_arr[2]{
            std::span<const unsigned char>{reinterpret_cast<const unsigned char*>(tag), std::strlen(tag)},
            std::span<const unsigned char>{ring_blob},
        };
        return HashToScalar(std::span<const std::span<const unsigned char>>{chunks_arr, 2});
    };
    return {mu("agg/P/v1"), mu("agg/C/v1")};
}

// Aggregate a single ring member: out = μ_P*P + μ_C*W
bool AggregateMember(const MultiLayerMember& m, const Scalar& mu_P, const Scalar& mu_C, Point& out)
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    secp256k1_pubkey P, W;
    if (!ParsePoint(m.P, P) || !ParsePoint(m.W, W)) return false;
    if (!secp256k1_ec_pubkey_tweak_mul(Ctx(), &P, mu_P.data())) return false;
    if (!secp256k1_ec_pubkey_tweak_mul(Ctx(), &W, mu_C.data())) return false;
    const secp256k1_pubkey* parts[2] = {&P, &W};
    secp256k1_pubkey sum;
    if (!secp256k1_ec_pubkey_combine(Ctx(), &sum, parts, 2)) return false;
    return SerializePoint(sum, out);
}

// Aggregate priv: x_agg = μ_P*x + μ_C*z (mod n)
bool AggregateScalar(const Scalar& x, const Scalar& z, const Scalar& mu_P, const Scalar& mu_C, Scalar& out)
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    Scalar t1 = x;
    if (!secp256k1_ec_seckey_tweak_mul(Ctx(), t1.data(), mu_P.data())) return false;
    Scalar t2 = z;
    if (!secp256k1_ec_seckey_tweak_mul(Ctx(), t2.data(), mu_C.data())) return false;
    out = t1;
    if (!secp256k1_ec_seckey_tweak_add(Ctx(), out.data(), t2.data())) return false;
    return secp256k1_ec_seckey_verify(Ctx(), out.data()) == 1;
}

} // namespace

std::optional<Signature> SignMultiLayer(
    std::span<const MultiLayerMember> ring,
    size_t pi,
    const Scalar& x_pi,
    const Scalar& z_pi,
    const uint256& msg)
{
    if (ring.empty() || pi >= ring.size()) return std::nullopt;

    std::vector<Point> agg_ring(ring.size());
    Scalar agg_priv;
    {
        LOCK(g_mutex);
        const auto [mu_P, mu_C] = MultiLayerMu(ring);
        for (size_t i = 0; i < ring.size(); ++i) {
            if (!AggregateMember(ring[i], mu_P, mu_C, agg_ring[i])) return std::nullopt;
        }
        if (!AggregateScalar(x_pi, z_pi, mu_P, mu_C, agg_priv)) return std::nullopt;
    }
    return Sign(std::span<const Point>{agg_ring}, pi, agg_priv, msg);
}

bool VerifyMultiLayer(
    std::span<const MultiLayerMember> ring,
    const Signature& sig,
    const uint256& msg)
{
    if (ring.empty()) return false;
    std::vector<Point> agg_ring(ring.size());
    {
        LOCK(g_mutex);
        const auto [mu_P, mu_C] = MultiLayerMu(ring);
        for (size_t i = 0; i < ring.size(); ++i) {
            if (!AggregateMember(ring[i], mu_P, mu_C, agg_ring[i])) return false;
        }
    }
    return Verify(std::span<const Point>{agg_ring}, sig, msg);
}

void RunSelfTest()
{
    // Build a ring of 4 random keypairs; sign with index 2.
    constexpr size_t N = 4;
    constexpr size_t pi = 2;
    std::vector<Point> ring(N);
    std::vector<Scalar> privs(N);
    for (size_t i = 0; i < N; ++i) {
        while (true) {
            GetRandBytes(privs[i]);
            LOCK(g_mutex);
            if (secp256k1_ec_seckey_verify(Ctx(), privs[i].data())) break;
        }
        secp256k1_pubkey pk;
        {
            LOCK(g_mutex);
            if (!secp256k1_ec_pubkey_create(Ctx(), &pk, privs[i].data())) {
                throw std::runtime_error("ringsig self-test: pubkey_create failed");
            }
            if (!SerializePoint(pk, ring[i])) {
                throw std::runtime_error("ringsig self-test: serialize failed");
            }
        }
    }

    uint256 msg = uint256::ONE;
    auto sig = Sign(std::span<const Point>{ring}, pi, privs[pi], msg);
    if (!sig) throw std::runtime_error("ringsig self-test: Sign returned nullopt");
    if (!Verify(std::span<const Point>{ring}, *sig, msg)) {
        throw std::runtime_error("ringsig self-test: Verify of valid sig failed");
    }

    // Tamper: flip a bit in the message — verify must fail.
    uint256 bad_msg = msg;
    *(bad_msg.data()) ^= 0x01;
    if (Verify(std::span<const Point>{ring}, *sig, bad_msg)) {
        throw std::runtime_error("ringsig self-test: Verify of tampered msg should have failed");
    }

    // Tamper: flip a bit in s[0] — verify must fail.
    Signature bad_sig = *sig;
    bad_sig.s[0][0] ^= 0x01;
    if (Verify(std::span<const Point>{ring}, bad_sig, msg)) {
        throw std::runtime_error("ringsig self-test: Verify of tampered s[0] should have failed");
    }

    // Try signing with the wrong privkey for the index — Sign must reject.
    auto wrong = Sign(std::span<const Point>{ring}, pi, privs[(pi + 1) % N], msg);
    if (wrong) {
        throw std::runtime_error("ringsig self-test: Sign should reject wrong privkey");
    }

    // Multi-layer (RingCT) self-test: build a ring of (P_i, W_i) pairs.
    // We need both spend privs (already have privs[]) and a z = b_prev − b_pseudo
    // for the signer's row. For the test we just generate fresh z's and synthesize
    // W_i = z_i*G; only z_pi needs to be known — the other W_i's are arbitrary
    // valid points (they don't have to be commitment-shaped for the math to work,
    // since CLSAG only proves "I know one z for one of these W's").
    std::vector<Scalar> zs(N);
    std::vector<MultiLayerMember> ring2(N);
    for (size_t i = 0; i < N; ++i) {
        while (true) {
            GetRandBytes(zs[i]);
            LOCK(g_mutex);
            if (secp256k1_ec_seckey_verify(Ctx(), zs[i].data())) break;
        }
        ring2[i].P = ring[i];
        secp256k1_pubkey W_pk;
        {
            LOCK(g_mutex);
            if (!secp256k1_ec_pubkey_create(Ctx(), &W_pk, zs[i].data())) {
                throw std::runtime_error("ringsig multi-layer self-test: pubkey_create failed");
            }
            if (!SerializePoint(W_pk, ring2[i].W)) {
                throw std::runtime_error("ringsig multi-layer self-test: serialize W failed");
            }
        }
    }

    auto sig2 = SignMultiLayer(std::span<const MultiLayerMember>{ring2}, pi, privs[pi], zs[pi], msg);
    if (!sig2) throw std::runtime_error("ringsig multi-layer self-test: SignMultiLayer returned nullopt");
    if (!VerifyMultiLayer(std::span<const MultiLayerMember>{ring2}, *sig2, msg)) {
        throw std::runtime_error("ringsig multi-layer self-test: Verify of valid sig failed");
    }
    // Tamper: change one W in the ring → verify must fail.
    auto bad_ring = ring2;
    bad_ring[(pi + 1) % N].W[0] ^= 0x01;
    if (VerifyMultiLayer(std::span<const MultiLayerMember>{bad_ring}, *sig2, msg)) {
        throw std::runtime_error("ringsig multi-layer self-test: tampered W should have failed");
    }
    // Wrong z at signer's index: must reject at sign time (because the resulting
    // aggregated priv won't match the aggregated ring member).
    auto wrong2 = SignMultiLayer(std::span<const MultiLayerMember>{ring2}, pi, privs[pi], zs[(pi + 1) % N], msg);
    if (wrong2) {
        throw std::runtime_error("ringsig multi-layer self-test: SignMultiLayer should reject wrong z");
    }
}

} // namespace pricoin::ringsig
