// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pricoin/joint_stealth.h>

#include <crypto/sha256.h>
#include <hash.h>
#include <key.h>
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

// ─────────────────────────────────────────────────────────────────
// Proof-of-possession (§6.0 rogue-key defense).
// ─────────────────────────────────────────────────────────────────

uint256 PoPChallenge(
    const uint256& session_id,
    const CPubKey& counterparty_spend_pubkey)
{
    static constexpr char kTag[] = "pricoin/joint-stealth/PoP-v1";
    HashWriter h{};
    h.write(MakeByteSpan(std::span<const unsigned char>{
        reinterpret_cast<const unsigned char*>(kTag), sizeof(kTag) - 1}));
    h << session_id;
    // CPubKey serialises canonically as 33 compressed bytes.
    h.write(MakeByteSpan(std::span<const unsigned char>{
        counterparty_spend_pubkey.begin(),
        static_cast<size_t>(counterparty_spend_pubkey.end() - counterparty_spend_pubkey.begin())}));
    return h.GetSHA256();
}

std::optional<std::vector<unsigned char>> ProvePossession(
    const CKey& self_spend_priv,
    const uint256& session_id,
    const CPubKey& counterparty_spend_pubkey)
{
    if (!self_spend_priv.IsValid()) return std::nullopt;
    if (!counterparty_spend_pubkey.IsValid()
        || !counterparty_spend_pubkey.IsCompressed()) return std::nullopt;
    const uint256 challenge = PoPChallenge(session_id, counterparty_spend_pubkey);
    std::vector<unsigned char> sig;
    if (!self_spend_priv.Sign(challenge, sig)) return std::nullopt;
    return sig;
}

bool VerifyPossession(
    const CPubKey& self_spend_pubkey,
    const uint256& session_id,
    const CPubKey& counterparty_spend_pubkey,
    std::span<const unsigned char> sig)
{
    if (!self_spend_pubkey.IsValid()
        || !self_spend_pubkey.IsCompressed()) return false;
    if (!counterparty_spend_pubkey.IsValid()
        || !counterparty_spend_pubkey.IsCompressed()) return false;
    if (sig.empty()) return false;
    const uint256 challenge = PoPChallenge(session_id, counterparty_spend_pubkey);
    return self_spend_pubkey.Verify(challenge,
        std::vector<unsigned char>{sig.begin(), sig.end()});
}

std::optional<::pricoin::stealth::StealthAddress> CombineWithPoP(
    const ::pricoin::stealth::StealthAddress& a,
    const ::pricoin::stealth::StealthAddress& b,
    std::span<const unsigned char> a_pop,
    std::span<const unsigned char> b_pop,
    const uint256& session_id)
{
    // Each party's PoP must bind their OWN spend pubkey, the
    // session, and the COUNTERPARTY's spend pubkey. This prevents
    // any party from picking their pubkey after seeing the other's
    // (rogue-key attack).
    if (!VerifyPossession(a.spend, session_id, b.spend, a_pop)) return std::nullopt;
    if (!VerifyPossession(b.spend, session_id, a.spend, b_pop)) return std::nullopt;
    return Combine(a, b);
}

void RunPoPSelfTest()
{
    using ::pricoin::stealth::StealthAddress;

    // Build two stealth identities directly from random privkeys.
    auto make_identity = [](StealthAddress& out, CKey& view_priv, CKey& spend_priv) {
        for (;;) {
            unsigned char buf[32];
            GetRandBytes(buf);
            view_priv.Set(buf, buf + 32, /*compressed=*/true);
            if (!view_priv.IsValid()) continue;
            GetRandBytes(buf);
            spend_priv.Set(buf, buf + 32, /*compressed=*/true);
            if (!spend_priv.IsValid()) continue;
            break;
        }
        out.view  = view_priv.GetPubKey();
        out.spend = spend_priv.GetPubKey();
    };

    StealthAddress alice, bob;
    CKey alice_view_priv, alice_spend_priv, bob_view_priv, bob_spend_priv;
    make_identity(alice, alice_view_priv, alice_spend_priv);
    make_identity(bob,   bob_view_priv,   bob_spend_priv);

    uint256 session_id;
    GetRandBytes(session_id);

    // ─── Honest PoP round-trip ────────────────────────────────
    auto a_pop = ProvePossession(alice_spend_priv, session_id, bob.spend);
    auto b_pop = ProvePossession(bob_spend_priv,   session_id, alice.spend);
    if (!a_pop || !b_pop) {
        throw std::runtime_error("joint_stealth PoP self-test: ProvePossession failed");
    }
    if (!VerifyPossession(alice.spend, session_id, bob.spend,
            std::span<const unsigned char>{*a_pop})) {
        throw std::runtime_error("joint_stealth PoP self-test: honest VerifyPossession (alice) failed");
    }
    if (!VerifyPossession(bob.spend, session_id, alice.spend,
            std::span<const unsigned char>{*b_pop})) {
        throw std::runtime_error("joint_stealth PoP self-test: honest VerifyPossession (bob) failed");
    }
    auto joint = CombineWithPoP(alice, bob,
        std::span<const unsigned char>{*a_pop},
        std::span<const unsigned char>{*b_pop},
        session_id);
    if (!joint) {
        throw std::runtime_error("joint_stealth PoP self-test: honest CombineWithPoP failed");
    }
    // Sanity: joint.spend should be alice.spend + bob.spend.
    auto plain_joint = Combine(alice, bob);
    if (!plain_joint || joint->spend != plain_joint->spend
                     || joint->view  != plain_joint->view) {
        throw std::runtime_error("joint_stealth PoP self-test: joint != plain Combine output");
    }

    // ─── Rogue-key attack rejected ────────────────────────────
    // Bob picks B_B' = B_B − B_A so B_J' = B_B'. He'd need a PoP
    // signature under B_B' but doesn't know its discrete log.
    // ProvePossession with the original bob_spend_priv against
    // B_B' would fail at the signature stage; even if Bob crafted
    // some sig that happened to verify against the WRONG pubkey,
    // VerifyPossession against B_B' (the rogue) wouldn't accept
    // a signature he made under B_B (the original).
    {
        // Construct the rogue B_B' = B_B − B_A.
        secp256k1_context* ctx;
        {
            LOCK(g_ctx_mutex);
            ctx = JointCtx();
        }
        secp256k1_pubkey alice_pk, bob_pk;
        if (secp256k1_ec_pubkey_parse(ctx, &alice_pk,
                alice.spend.begin(), 33) != 1) {
            throw std::runtime_error("joint_stealth PoP self-test: parse alice spend");
        }
        if (secp256k1_ec_pubkey_parse(ctx, &bob_pk,
                bob.spend.begin(), 33) != 1) {
            throw std::runtime_error("joint_stealth PoP self-test: parse bob spend");
        }
        // Negate alice_pk.
        secp256k1_pubkey neg_alice = alice_pk;
        if (!secp256k1_ec_pubkey_negate(ctx, &neg_alice)) {
            throw std::runtime_error("joint_stealth PoP self-test: negate alice");
        }
        const secp256k1_pubkey* parts[2] = {&bob_pk, &neg_alice};
        secp256k1_pubkey rogue;
        if (!secp256k1_ec_pubkey_combine(ctx, &rogue, parts, 2)) {
            throw std::runtime_error("joint_stealth PoP self-test: combine rogue");
        }
        unsigned char rogue_bytes[33];
        size_t outlen = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, rogue_bytes, &outlen,
                &rogue, SECP256K1_EC_COMPRESSED) || outlen != 33) {
            throw std::runtime_error("joint_stealth PoP self-test: serialize rogue");
        }
        StealthAddress bob_rogue = bob;
        bob_rogue.spend = CPubKey(std::span<const unsigned char>{rogue_bytes, 33});

        // Bob attempts to use his ORIGINAL signature (bound to
        // his ORIGINAL spend pubkey). Verifying it against the
        // ROGUE pubkey must fail.
        if (VerifyPossession(bob_rogue.spend, session_id, alice.spend,
                std::span<const unsigned char>{*b_pop})) {
            throw std::runtime_error(
                "joint_stealth PoP self-test: rogue-key attack accepted (must reject)");
        }
        // CombineWithPoP must reject the rogue scenario.
        auto rogue_joint = CombineWithPoP(alice, bob_rogue,
            std::span<const unsigned char>{*a_pop},
            std::span<const unsigned char>{*b_pop},
            session_id);
        if (rogue_joint) {
            throw std::runtime_error(
                "joint_stealth PoP self-test: rogue-key CombineWithPoP accepted");
        }
    }

    // ─── PoP replay across sessions rejected ──────────────────
    {
        uint256 different_session;
        GetRandBytes(different_session);
        if (VerifyPossession(alice.spend, different_session, bob.spend,
                std::span<const unsigned char>{*a_pop})) {
            throw std::runtime_error(
                "joint_stealth PoP self-test: PoP replayed across sessions accepted");
        }
    }

    // ─── PoP replay across counterparties rejected ────────────
    {
        StealthAddress carol;
        CKey carol_view_priv, carol_spend_priv;
        make_identity(carol, carol_view_priv, carol_spend_priv);
        if (VerifyPossession(alice.spend, session_id, carol.spend,
                std::span<const unsigned char>{*a_pop})) {
            throw std::runtime_error(
                "joint_stealth PoP self-test: PoP replayed across counterparties accepted");
        }
    }

    // ─── Tampered signature rejected ──────────────────────────
    {
        std::vector<unsigned char> tampered = *a_pop;
        tampered[0] ^= 0x01;
        if (VerifyPossession(alice.spend, session_id, bob.spend,
                std::span<const unsigned char>{tampered})) {
            throw std::runtime_error(
                "joint_stealth PoP self-test: tampered signature accepted");
        }
    }
}

} // namespace pricoin::joint_stealth
