// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pricoin/joint_stealth.h>

#include <secp256k1.h>

#include <pubkey.h>
#include <random.h>
#include <sync.h>

#include <cstring>
#include <stdexcept>

namespace pricoin::joint_stealth {

namespace {

// Mirrors the per-module context pattern used in pricoin/stealth.cpp and
// pricoin/ct.cpp — these helpers are mostly point arithmetic so a NONE
// context is sufficient. We deliberately don't share the context with
// pricoin::stealth: keeping each module's context private lets us
// re-randomize independently and avoids a cross-TU lock-order tangle.
Mutex g_ctx_mutex;
secp256k1_context* g_ctx GUARDED_BY(g_ctx_mutex){nullptr};

secp256k1_context* JointCtx() EXCLUSIVE_LOCKS_REQUIRED(g_ctx_mutex)
{
    if (!g_ctx) {
        g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        if (!g_ctx) throw std::runtime_error("secp256k1_context_create failed (joint_stealth)");
        unsigned char seed[32];
        GetRandBytes(seed);
        // Side-channel randomization is best-effort; if it fails the
        // context is still usable.
        if (!secp256k1_context_randomize(g_ctx, seed)) {
            // Non-fatal — context still works without randomization.
        }
    }
    return g_ctx;
}

// Add two compressed-pubkey serialisations into a third. Returns false
// if either input fails to parse or the sum is the point at infinity.
bool AddPubkeys(secp256k1_context* ctx,
                std::span<const unsigned char> a33,
                std::span<const unsigned char> b33,
                ::pricoin::stealth::PointBytes& out)
    EXCLUSIVE_LOCKS_REQUIRED(g_ctx_mutex)
{
    if (a33.size() != 33 || b33.size() != 33) return false;
    secp256k1_pubkey pa, pb;
    if (!secp256k1_ec_pubkey_parse(ctx, &pa, a33.data(), a33.size())) return false;
    if (!secp256k1_ec_pubkey_parse(ctx, &pb, b33.data(), b33.size())) return false;
    const secp256k1_pubkey* parts[2] = {&pa, &pb};
    secp256k1_pubkey sum;
    if (!secp256k1_ec_pubkey_combine(ctx, &sum, parts, 2)) return false;
    size_t outlen = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, out.data(), &outlen, &sum, SECP256K1_EC_COMPRESSED)) return false;
    return outlen == 33;
}

} // namespace

std::optional<::pricoin::stealth::StealthAddress> Combine(
    const ::pricoin::stealth::StealthAddress& a,
    const ::pricoin::stealth::StealthAddress& b)
{
    if (!a.IsValid() || !b.IsValid()) return std::nullopt;
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = JointCtx();

    ::pricoin::stealth::PointBytes view_sum, spend_sum;
    if (!AddPubkeys(ctx,
                    std::span<const unsigned char>{a.view.data(), a.view.size()},
                    std::span<const unsigned char>{b.view.data(), b.view.size()},
                    view_sum)) return std::nullopt;
    if (!AddPubkeys(ctx,
                    std::span<const unsigned char>{a.spend.data(), a.spend.size()},
                    std::span<const unsigned char>{b.spend.data(), b.spend.size()},
                    spend_sum)) return std::nullopt;

    ::pricoin::stealth::StealthAddress joint;
    joint.view = CPubKey(std::span<const unsigned char>{view_sum.data(), view_sum.size()});
    joint.spend = CPubKey(std::span<const unsigned char>{spend_sum.data(), spend_sum.size()});
    if (!joint.IsValid()) return std::nullopt;
    return joint;
}

std::optional<::pricoin::stealth::PointBytes> ScanPartial(
    const CKey& self_view_priv,
    std::span<const unsigned char> tx_pubkey_R_33)
{
    if (!self_view_priv.IsValid()) return std::nullopt;
    if (tx_pubkey_R_33.size() != 33) return std::nullopt;
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = JointCtx();

    secp256k1_pubkey R;
    if (!secp256k1_ec_pubkey_parse(ctx, &R, tx_pubkey_R_33.data(), tx_pubkey_R_33.size())) {
        return std::nullopt;
    }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &R,
            reinterpret_cast<const unsigned char*>(self_view_priv.data()))) {
        return std::nullopt;
    }
    ::pricoin::stealth::PointBytes out;
    size_t outlen = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, out.data(), &outlen, &R, SECP256K1_EC_COMPRESSED)) {
        return std::nullopt;
    }
    if (outlen != 33) return std::nullopt;
    return out;
}

std::optional<::pricoin::stealth::PointBytes> CombinePartials(
    std::span<const unsigned char> partial_a_33,
    std::span<const unsigned char> partial_b_33)
{
    LOCK(g_ctx_mutex);
    secp256k1_context* ctx = JointCtx();
    ::pricoin::stealth::PointBytes out;
    if (!AddPubkeys(ctx, partial_a_33, partial_b_33, out)) return std::nullopt;
    return out;
}

} // namespace pricoin::joint_stealth
