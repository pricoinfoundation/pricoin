// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <swap/btc_adaptor_schnorr.h>

#include <hash.h>
#include <key.h>
#include <pubkey.h>
#include <random.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <span.h>
#include <sync.h>
#include <uint256.h>

#include <cstring>
#include <stdexcept>
#include <vector>

// IMPORTANT: this module produces signatures intended for
// consumption by real BTC / LTC nodes (BIP340-compatible). The
// self-test feeds every adapted output through CPubKey::VerifySchnorr
// — which is libsecp256k1's BIP340 implementation, the same code
// real nodes use. Divergence fails the daemon at startup.

namespace pricoin::swap::btc_adaptor_schnorr {

namespace {

Mutex g_ctx_mutex;
secp256k1_context* g_ctx GUARDED_BY(g_ctx_mutex){nullptr};

secp256k1_context* SCtx() EXCLUSIVE_LOCKS_REQUIRED(g_ctx_mutex)
{
    if (!g_ctx) {
        g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        if (!g_ctx) throw std::runtime_error("secp256k1_context_create failed (btc_adaptor_schnorr)");
        unsigned char seed[32];
        GetRandBytes(seed);
        if (!secp256k1_context_randomize(g_ctx, seed)) {
            // Non-fatal — context still works.
        }
    }
    return g_ctx;
}

// Tagged challenge per BIP340: SHA256("BIP0340/challenge" prefix
// twice as tag) over (R.x || P.x || msg).
uint256 BIP340Challenge(
    const XOnlyPubKey& R_x,
    const XOnlyPubKey& P_x,
    const uint256& msg)
{
    HashWriter h{TaggedHash("BIP0340/challenge")};
    h.write(MakeByteSpan(std::span<const unsigned char>{R_x.data(), R_x.size()}));
    h.write(MakeByteSpan(std::span<const unsigned char>{P_x.data(), P_x.size()}));
    h.write(MakeByteSpan(std::span<const unsigned char>{msg.data(), msg.size()}));
    return h.GetSHA256();
}

// Get x-only encoding of a pubkey + parity (0 = even-y, 1 = odd-y).
bool ToXOnly(secp256k1_context* ctx, const secp256k1_pubkey& pk,
             XOnlyPubKey& out, int& parity_out)
{
    secp256k1_xonly_pubkey xonly;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly, &parity_out, &pk)) {
        return false;
    }
    return secp256k1_xonly_pubkey_serialize(ctx, out.data(), &xonly) == 1;
}

// Parse 33-byte compressed pubkey.
bool ParseCompressed(secp256k1_context* ctx,
                     const AdaptorPointCompressed& bytes,
                     secp256k1_pubkey& out)
{
    return secp256k1_ec_pubkey_parse(ctx, &out, bytes.data(), bytes.size()) == 1;
}

// Parse x-only pubkey into a full pubkey assuming even-y (BIP340
// "lift_x_evenY"). Returns the full pubkey.
bool LiftXEvenY(secp256k1_context* ctx,
                const XOnlyPubKey& x_bytes,
                secp256k1_pubkey& out)
{
    secp256k1_xonly_pubkey xonly;
    if (!secp256k1_xonly_pubkey_parse(ctx, &xonly, x_bytes.data())) return false;
    // secp256k1_xonly_pubkey is internally a "regular" pubkey with even-y
    // assumed. Cast through the serialize+reparse trick to get a usable
    // secp256k1_pubkey.
    unsigned char tmp[33];
    tmp[0] = 0x02; // even-y prefix
    size_t outlen = 32;
    if (!secp256k1_xonly_pubkey_serialize(ctx, tmp + 1, &xonly)) return false;
    return secp256k1_ec_pubkey_parse(ctx, &out, tmp, 33) == 1;
}

// Reduce a 32-byte hash to a valid secp256k1 scalar. If the hash
// is already < n, returns it as-is. Otherwise rare case: returns
// the hash mod n by subtracting n once (since 2·n > 2^256, one
// subtraction is enough). secp256k1's seckey_verify rejects 0 and
// values >= n; we handle the rare overflow by repeated reduction
// (in practice always 0 or 1 reductions).
//
// Mathematically simpler: if hash >= n, treat as failure and
// retry the signing with fresh k (the e value depends on R_pub
// which depends on k, so a fresh k changes e). Probability of
// this firing is negligible (~2^-128).
bool TryReduceToScalar(secp256k1_context* ctx,
                       const uint256& hash, Scalar& out)
{
    std::memcpy(out.data(), hash.data(), 32);
    return secp256k1_ec_seckey_verify(ctx, out.data()) == 1;
}

// Negate a scalar in-place. Wraps secp256k1_ec_seckey_negate which
// requires a valid scalar input; handles the all-zero case (we
// don't expect to hit it but guard anyway).
bool NegateScalar(secp256k1_context* ctx, Scalar& s)
{
    if (!secp256k1_ec_seckey_verify(ctx, s.data())) return false;
    return secp256k1_ec_seckey_negate(ctx, s.data()) == 1;
}

constexpr int kMaxRetries = 32;

} // namespace

std::optional<SignatureBytes> MakeAdaptorPreSig(
    const Scalar& priv,
    const uint256& msg,
    const AdaptorPointCompressed& adaptor_T_G)
{
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = SCtx();

    if (!secp256k1_ec_seckey_verify(ctx, priv.data())) return std::nullopt;

    // Parse adaptor point.
    secp256k1_pubkey T_pk;
    if (!ParseCompressed(ctx, adaptor_T_G, T_pk)) return std::nullopt;

    // Get effective signing key d_eff (BIP340 normalises so X has
    // even y). secp256k1_keypair_create + xonly_pub gives us the
    // parity bit; if 1 (odd-y P), we negate priv before using it
    // as d_eff in the s = k + e·d math.
    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(ctx, &keypair, priv.data())) return std::nullopt;
    secp256k1_xonly_pubkey P_xonly;
    int p_parity = 0;
    if (!secp256k1_keypair_xonly_pub(ctx, &P_xonly, &p_parity, &keypair)) {
        return std::nullopt;
    }
    XOnlyPubKey P_x;
    if (!secp256k1_xonly_pubkey_serialize(ctx, P_x.data(), &P_xonly)) {
        return std::nullopt;
    }
    Scalar d_eff = priv;
    if (p_parity == 1) {
        if (!NegateScalar(ctx, d_eff)) return std::nullopt;
    }

    // Retry loop on odd-y R_pub or invalid scalar e.
    for (int attempt = 0; attempt < kMaxRetries; ++attempt) {
        // Fresh nonce k.
        Scalar k;
        do { GetRandBytes(k); } while (!secp256k1_ec_seckey_verify(ctx, k.data()));

        // R_internal = k·G
        secp256k1_pubkey R_int;
        if (!secp256k1_ec_pubkey_create(ctx, &R_int, k.data())) continue;

        // R_pub = R_internal + T_G
        const secp256k1_pubkey* parts[2] = {&R_int, &T_pk};
        secp256k1_pubkey R_pub;
        if (!secp256k1_ec_pubkey_combine(ctx, &R_pub, parts, 2)) continue;

        // Get R_pub x-only encoding + parity. If odd-y, retry
        // (BIP340 requires R to be even-y, and we can't flip
        // T_G's parity).
        XOnlyPubKey R_x;
        int r_parity = 0;
        if (!ToXOnly(ctx, R_pub, R_x, r_parity)) continue;
        if (r_parity == 1) continue;

        // Challenge e = tagged_hash("BIP0340/challenge", R_x || P_x || msg).
        const uint256 e_hash = BIP340Challenge(R_x, P_x, msg);
        Scalar e;
        if (!TryReduceToScalar(ctx, e_hash, e)) continue; // negligible

        // s' = k + e·d_eff (mod n).
        Scalar prod = e;
        if (!secp256k1_ec_seckey_tweak_mul(ctx, prod.data(), d_eff.data())) continue;
        Scalar s_prime = k;
        if (!secp256k1_ec_seckey_tweak_add(ctx, s_prime.data(), prod.data())) continue;
        if (!secp256k1_ec_seckey_verify(ctx, s_prime.data())) continue;

        SignatureBytes out{};
        std::memcpy(out.data() + 0, R_x.data(), 32);
        std::memcpy(out.data() + 32, s_prime.data(), 32);
        return out;
    }
    return std::nullopt; // CSPRNG broken or unlucky beyond reason
}

bool VerifyAdaptorPreSig(
    const XOnlyPubKey& pub_x,
    const uint256& msg,
    const AdaptorPointCompressed& adaptor_T_G,
    const SignatureBytes& presig)
{
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = SCtx();

    XOnlyPubKey R_x;
    Scalar      s_prime;
    std::memcpy(R_x.data(),     presig.data() + 0,  32);
    std::memcpy(s_prime.data(), presig.data() + 32, 32);

    if (!secp256k1_ec_seckey_verify(ctx, s_prime.data())) return false;

    // Reconstruct full points.
    secp256k1_pubkey R_pub_full, P_full, T_full;
    if (!LiftXEvenY(ctx, R_x,    R_pub_full)) return false;
    if (!LiftXEvenY(ctx, pub_x,  P_full))     return false;
    if (!ParseCompressed(ctx, adaptor_T_G, T_full)) return false;

    const uint256 e_hash = BIP340Challenge(R_x, pub_x, msg);
    Scalar e;
    if (!TryReduceToScalar(ctx, e_hash, e)) return false;

    // Verify s'·G + T_G == R_pub + e·P.
    //
    // Compute LHS = s'·G + T_G:
    secp256k1_pubkey sG;
    if (!secp256k1_ec_pubkey_create(ctx, &sG, s_prime.data())) return false;
    const secp256k1_pubkey* lhs_parts[2] = {&sG, &T_full};
    secp256k1_pubkey lhs;
    if (!secp256k1_ec_pubkey_combine(ctx, &lhs, lhs_parts, 2)) return false;

    // Compute RHS = R_pub + e·P:
    secp256k1_pubkey eP = P_full;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &eP, e.data())) return false;
    const secp256k1_pubkey* rhs_parts[2] = {&R_pub_full, &eP};
    secp256k1_pubkey rhs;
    if (!secp256k1_ec_pubkey_combine(ctx, &rhs, rhs_parts, 2)) return false;

    // Compare via serialised compressed bytes.
    unsigned char lhs_bytes[33], rhs_bytes[33];
    size_t outlen = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, lhs_bytes, &outlen, &lhs, SECP256K1_EC_COMPRESSED)
        || outlen != 33) return false;
    outlen = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, rhs_bytes, &outlen, &rhs, SECP256K1_EC_COMPRESSED)
        || outlen != 33) return false;
    return std::memcmp(lhs_bytes, rhs_bytes, 33) == 0;
}

std::optional<SignatureBytes> Adapt(
    const SignatureBytes& presig,
    const Scalar& t,
    const AdaptorPointCompressed& adaptor_T_G)
{
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = SCtx();

    if (!secp256k1_ec_seckey_verify(ctx, t.data())) return std::nullopt;

    // Verify t·G == adaptor_T_G (round-trip the secret).
    secp256k1_pubkey tG;
    if (!secp256k1_ec_pubkey_create(ctx, &tG, t.data())) return std::nullopt;
    unsigned char tG_bytes[33];
    size_t outlen = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, tG_bytes, &outlen, &tG,
            SECP256K1_EC_COMPRESSED) || outlen != 33) return std::nullopt;
    if (std::memcmp(tG_bytes, adaptor_T_G.data(), 33) != 0) return std::nullopt;

    // s = s' + t (mod n).
    Scalar s_prime;
    std::memcpy(s_prime.data(), presig.data() + 32, 32);
    if (!secp256k1_ec_seckey_verify(ctx, s_prime.data())) return std::nullopt;

    Scalar s = s_prime;
    if (!secp256k1_ec_seckey_tweak_add(ctx, s.data(), t.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_verify(ctx, s.data())) return std::nullopt;

    SignatureBytes out{};
    std::memcpy(out.data() + 0,  presig.data(), 32); // R_pub.x unchanged
    std::memcpy(out.data() + 32, s.data(),      32);
    return out;
}

std::optional<Scalar> Extract(
    const SignatureBytes& presig,
    const SignatureBytes& sig,
    const AdaptorPointCompressed& adaptor_T_G)
{
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = SCtx();

    Scalar s_prime, s;
    std::memcpy(s_prime.data(), presig.data() + 32, 32);
    std::memcpy(s.data(),       sig.data()    + 32, 32);
    if (!secp256k1_ec_seckey_verify(ctx, s_prime.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_verify(ctx, s.data()))       return std::nullopt;

    // t = s - s' (mod n).
    Scalar neg_pre = s_prime;
    if (!secp256k1_ec_seckey_negate(ctx, neg_pre.data())) return std::nullopt;
    Scalar t = s;
    if (!secp256k1_ec_seckey_tweak_add(ctx, t.data(), neg_pre.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_verify(ctx, t.data())) return std::nullopt;

    // Verify t·G == adaptor_T_G.
    secp256k1_pubkey tG;
    if (!secp256k1_ec_pubkey_create(ctx, &tG, t.data())) return std::nullopt;
    unsigned char tG_bytes[33];
    size_t outlen = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, tG_bytes, &outlen, &tG,
            SECP256K1_EC_COMPRESSED) || outlen != 33) return std::nullopt;
    if (std::memcmp(tG_bytes, adaptor_T_G.data(), 33) != 0) return std::nullopt;
    return t;
}

void RunSelfTest()
{
    // ─── Setup ───────────────────────────────────────────────
    Scalar priv, t;
    {
        LOCK(g_ctx_mutex);
        secp256k1_context* ctx = SCtx();
        do { GetRandBytes(priv); } while (!secp256k1_ec_seckey_verify(ctx, priv.data()));
        do { GetRandBytes(t);    } while (!secp256k1_ec_seckey_verify(ctx, t.data()));
    }

    // Compute T_G = t·G as 33-byte compressed.
    AdaptorPointCompressed T_G{};
    {
        LOCK(g_ctx_mutex);
        secp256k1_context* ctx = SCtx();
        secp256k1_pubkey tG;
        if (!secp256k1_ec_pubkey_create(ctx, &tG, t.data())) {
            throw std::runtime_error("btc_adaptor_schnorr self-test: T_G compute failed");
        }
        size_t outlen = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, T_G.data(), &outlen, &tG,
                SECP256K1_EC_COMPRESSED) || outlen != 33) {
            throw std::runtime_error("btc_adaptor_schnorr self-test: T_G serialize failed");
        }
    }

    // Compute X.x (signer pubkey) for verification.
    XOnlyPubKey X_x{};
    {
        LOCK(g_ctx_mutex);
        secp256k1_context* ctx = SCtx();
        secp256k1_keypair kp;
        if (!secp256k1_keypair_create(ctx, &kp, priv.data())) {
            throw std::runtime_error("btc_adaptor_schnorr self-test: keypair_create failed");
        }
        secp256k1_xonly_pubkey xonly;
        int parity = 0;
        if (!secp256k1_keypair_xonly_pub(ctx, &xonly, &parity, &kp)) {
            throw std::runtime_error("btc_adaptor_schnorr self-test: xonly_pub failed");
        }
        if (!secp256k1_xonly_pubkey_serialize(ctx, X_x.data(), &xonly)) {
            throw std::runtime_error("btc_adaptor_schnorr self-test: xonly_serialize failed");
        }
    }

    const uint256 msg = uint256::ONE;

    // ─── Honest pre-sig + Adapt + standard BIP340 verify ─────
    auto presig = MakeAdaptorPreSig(priv, msg, T_G);
    if (!presig) {
        throw std::runtime_error("btc_adaptor_schnorr self-test: MakeAdaptorPreSig failed");
    }
    if (!VerifyAdaptorPreSig(X_x, msg, T_G, *presig)) {
        throw std::runtime_error(
            "btc_adaptor_schnorr self-test: pre-sig honest verify failed");
    }

    auto sig = Adapt(*presig, t, T_G);
    if (!sig) throw std::runtime_error("btc_adaptor_schnorr self-test: Adapt failed");

    // CRITICAL compatibility check: adapted sig MUST verify under
    // the deployed CPubKey::VerifySchnorr (BIP340). This is what
    // real BTC and LTC nodes use.
    {
        ::XOnlyPubKey X_xo(std::span<const unsigned char>{X_x.data(), 32});
        if (!X_xo.IsFullyValid()) {
            throw std::runtime_error("btc_adaptor_schnorr self-test: X_xo invalid");
        }
        if (!X_xo.VerifySchnorr(msg,
                std::span<const unsigned char>{sig->data(), sig->size()})) {
            throw std::runtime_error(
                "btc_adaptor_schnorr self-test: adapted sig failed standard BIP340 verify");
        }
    }

    // ─── Extract t, verify t·G == T_G ──────────────────────────
    auto extracted = Extract(*presig, *sig, T_G);
    if (!extracted) throw std::runtime_error("btc_adaptor_schnorr self-test: Extract failed");
    if (*extracted != t) {
        throw std::runtime_error("btc_adaptor_schnorr self-test: extracted t != original t");
    }

    // ─── Adversarial: Adapt with wrong t rejected ─────────────
    {
        Scalar wrong_t;
        {
            LOCK(g_ctx_mutex);
            secp256k1_context* ctx = SCtx();
            do { GetRandBytes(wrong_t); }
            while (!secp256k1_ec_seckey_verify(ctx, wrong_t.data()));
        }
        auto bad = Adapt(*presig, wrong_t, T_G);
        if (bad) {
            throw std::runtime_error(
                "btc_adaptor_schnorr self-test: Adapt accepted wrong t (must reject)");
        }
    }

    // ─── Adversarial: tampered pre-sig fails verify ───────────
    {
        SignatureBytes bad_presig = *presig;
        bad_presig[40] ^= 0x01;
        if (VerifyAdaptorPreSig(X_x, msg, T_G, bad_presig)) {
            throw std::runtime_error(
                "btc_adaptor_schnorr self-test: tampered pre-sig accepted");
        }
    }

    // ─── Adversarial: pre-sig under wrong T_G fails verify ────
    {
        AdaptorPointCompressed wrong_T_G;
        {
            LOCK(g_ctx_mutex);
            secp256k1_context* ctx = SCtx();
            Scalar wrong_t;
            do { GetRandBytes(wrong_t); }
            while (!secp256k1_ec_seckey_verify(ctx, wrong_t.data()));
            secp256k1_pubkey wrong_tG;
            if (!secp256k1_ec_pubkey_create(ctx, &wrong_tG, wrong_t.data())) {
                throw std::runtime_error("btc_adaptor_schnorr self-test: wrong_T_G failed");
            }
            size_t outlen = 33;
            if (!secp256k1_ec_pubkey_serialize(ctx, wrong_T_G.data(), &outlen, &wrong_tG,
                    SECP256K1_EC_COMPRESSED) || outlen != 33) {
                throw std::runtime_error("btc_adaptor_schnorr self-test: wrong_T_G serialize");
            }
        }
        if (VerifyAdaptorPreSig(X_x, msg, wrong_T_G, *presig)) {
            throw std::runtime_error(
                "btc_adaptor_schnorr self-test: pre-sig with wrong T_G accepted");
        }
    }

    // ─── Adversarial: tampered adapted sig fails BIP340 verify ─
    {
        SignatureBytes bad_sig = *sig;
        bad_sig[33] ^= 0x01;
        ::XOnlyPubKey X_xo(std::span<const unsigned char>{X_x.data(), 32});
        if (X_xo.VerifySchnorr(msg,
                std::span<const unsigned char>{bad_sig.data(), bad_sig.size()})) {
            throw std::runtime_error(
                "btc_adaptor_schnorr self-test: tampered adapted sig accepted by BIP340");
        }
    }
}

} // namespace pricoin::swap::btc_adaptor_schnorr
