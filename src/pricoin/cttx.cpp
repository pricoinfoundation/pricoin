// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pricoin/cttx.h>

#include <crypto/sha256.h>
#include <hash.h>
#include <random.h>
#include <secp256k1.h>
#include <secp256k1_generator.h>
#include <streams.h>
#include <sync.h>

#include <cstring>

namespace pricoin::ct {

size_t CTBundle::SerializedSize() const
{
    SizeComputer sc;
    sc << *this;
    return sc.size();
}

// HashBundle moved to pricoin/cttx_hash.cpp so it can live in
// bitcoin_consensus (script/interpreter.cpp's sighash path needs it),
// without dragging the rest of cttx.cpp's Pedersen helpers along.

namespace {

Mutex g_secp_mu;
secp256k1_context* g_secp_ctx GUARDED_BY(g_secp_mu){nullptr};

secp256k1_context* SecpCtx() EXCLUSIVE_LOCKS_REQUIRED(g_secp_mu)
{
    if (!g_secp_ctx) g_secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    return g_secp_ctx;
}

bool ParseCommitToPubkey(secp256k1_context* ctx, const Commitment& C, secp256k1_pubkey& out)
{
    secp256k1_pedersen_commitment pc;
    if (!secp256k1_pedersen_commitment_parse(ctx, &pc, C.bytes.data())) return false;
    unsigned char ser[33];
    if (!secp256k1_pedersen_commitment_serialize(ctx, ser, &pc)) return false;
    // Pedersen commitment serialization uses 0x08/0x09 prefixes; convert to
    // pubkey-compressed 0x02/0x03.
    ser[0] = (ser[0] == 8) ? 2 : 3;
    return secp256k1_ec_pubkey_parse(ctx, &out, ser, 33) == 1;
}

} // namespace

std::optional<std::array<unsigned char, 33>> SubtractCommitments(
    const Commitment& C1, const Commitment& C2)
{
    LOCK(g_secp_mu);
    secp256k1_context* ctx = SecpCtx();
    secp256k1_pedersen_commitment p1, p2;
    if (!secp256k1_pedersen_commitment_parse(ctx, &p1, C1.bytes.data())) return std::nullopt;
    if (!secp256k1_pedersen_commitment_parse(ctx, &p2, C2.bytes.data())) return std::nullopt;
    std::array<unsigned char, 33> out;
    if (!secp256k1_pedersen_commitments_subtract_to_pubkey(ctx, out.data(), &p1, &p2)) {
        return std::nullopt;
    }
    return out;
}

std::optional<BlindingFactor> NegateScalar(const BlindingFactor& x)
{
    LOCK(g_secp_mu);
    if (!secp256k1_ec_seckey_verify(SecpCtx(), x.data())) return std::nullopt;
    BlindingFactor out = x;
    if (!secp256k1_ec_seckey_negate(SecpCtx(), out.data())) return std::nullopt;
    return out;
}

std::optional<BlindingFactor> AddScalars(const BlindingFactor& a, const BlindingFactor& b)
{
    LOCK(g_secp_mu);
    BlindingFactor out = a;
    if (!secp256k1_ec_seckey_verify(SecpCtx(), out.data())) return std::nullopt;
    if (!secp256k1_ec_seckey_tweak_add(SecpCtx(), out.data(), b.data())) return std::nullopt;
    return out;
}

std::optional<std::array<unsigned char, 33>> ScalarTimesG(const BlindingFactor& s)
{
    LOCK(g_secp_mu);
    secp256k1_context* ctx = SecpCtx();
    if (!secp256k1_ec_seckey_verify(ctx, s.data())) return std::nullopt;
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(ctx, &pk, s.data())) return std::nullopt;
    std::array<unsigned char, 33> out;
    size_t len = out.size();
    if (!secp256k1_ec_pubkey_serialize(ctx, out.data(), &len, &pk, SECP256K1_EC_COMPRESSED)) {
        return std::nullopt;
    }
    return out;
}

} // namespace pricoin::ct
