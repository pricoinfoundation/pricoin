// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pricoin/stealth.h>

#include <base58.h>
#include <crypto/sha256.h>
#include <key.h>
#include <pubkey.h>
#include <secp256k1.h>
#include <span.h>
#include <sync.h>
#include <util/strencodings.h>

#include <cstring>
#include <vector>

namespace pricoin::stealth {

namespace {
// 1-byte version + 33 + 33 = 67 bytes payload (then +4-byte SHA256d checksum
// from base58check).
constexpr unsigned char kStealthAddressVersion = 0x53; // 'S' in ASCII
constexpr size_t kPayloadSize = 1 + 33 + 33;

// Pricoin stealth addresses use the bare prefix "PRIC" so they're visually
// distinct from the bech32 P2WPKH addresses (which start with the network
// HRP). We achieve this by choosing the version byte such that the base58
// encoding starts with "PRIC". Picking 0x53 happens to give addresses that
// begin with "1xx..." which isn't obviously distinct — for the toy we just
// document the format and live with it.
} // namespace

std::string Encode(const StealthAddress& a)
{
    if (!a.IsValid()) return "";
    std::vector<unsigned char> payload;
    payload.reserve(kPayloadSize);
    payload.push_back(kStealthAddressVersion);
    payload.insert(payload.end(), a.view.begin(), a.view.end());
    payload.insert(payload.end(), a.spend.begin(), a.spend.end());
    return EncodeBase58Check(payload);
}

std::optional<StealthAddress> Decode(std::string_view encoded)
{
    std::vector<unsigned char> payload;
    if (!DecodeBase58Check(std::string(encoded), payload, kPayloadSize)) {
        return std::nullopt;
    }
    if (payload.size() != kPayloadSize) return std::nullopt;
    if (payload[0] != kStealthAddressVersion) return std::nullopt;
    StealthAddress out;
    out.view = CPubKey(std::span<const unsigned char>{payload.data() + 1, 33});
    out.spend = CPubKey(std::span<const unsigned char>{payload.data() + 1 + 33, 33});
    if (!out.IsValid()) return std::nullopt;
    return out;
}

namespace {

// Process-wide secp256k1 context for stealth-address scalar/point arithmetic.
// secp256k1_context_static is sufficient for these operations (no signing).
Mutex g_stealth_ctx_mutex;
secp256k1_context* g_stealth_ctx GUARDED_BY(g_stealth_ctx_mutex){nullptr};

secp256k1_context* StealthCtx() EXCLUSIVE_LOCKS_REQUIRED(g_stealth_ctx_mutex)
{
    if (!g_stealth_ctx) {
        g_stealth_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    }
    return g_stealth_ctx;
}

void U32LittleEndian(uint32_t v, unsigned char out[4])
{
    out[0] = v & 0xff; out[1] = (v >> 8) & 0xff;
    out[2] = (v >> 16) & 0xff; out[3] = (v >> 24) & 0xff;
}

} // namespace

std::optional<PointBytes> ECDHPoint(const CKey& priv, const CPubKey& pub)
{
    if (!priv.IsValid() || !pub.IsValid()) return std::nullopt;
    LOCK(g_stealth_ctx_mutex);
    secp256k1_pubkey raw;
    if (!secp256k1_ec_pubkey_parse(StealthCtx(), &raw, pub.data(), pub.size())) {
        return std::nullopt;
    }
    if (!secp256k1_ec_pubkey_tweak_mul(StealthCtx(), &raw, reinterpret_cast<const unsigned char*>(priv.data()))) {
        return std::nullopt;
    }
    PointBytes out;
    size_t outlen = out.size();
    if (!secp256k1_ec_pubkey_serialize(StealthCtx(), out.data(), &outlen, &raw, SECP256K1_EC_COMPRESSED)) {
        return std::nullopt;
    }
    return out;
}

std::array<unsigned char, 32> DeriveSharedSecret(
    const PointBytes& ecdh_point, uint32_t output_index)
{
    unsigned char idx[4];
    U32LittleEndian(output_index, idx);
    std::array<unsigned char, 32> out;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>("pricoin/stealth/secret-v1"), 25)
        .Write(ecdh_point.data(), ecdh_point.size())
        .Write(idx, 4)
        .Finalize(out.data());
    return out;
}

std::optional<CPubKey> DeriveOneTimePubkey(
    const std::array<unsigned char, 32>& shared, const CPubKey& spend_pubkey)
{
    LOCK(g_stealth_ctx_mutex);
    secp256k1_pubkey shared_g;  // shared * G
    if (!secp256k1_ec_pubkey_create(StealthCtx(), &shared_g, shared.data())) {
        return std::nullopt;
    }
    secp256k1_pubkey spend;
    if (!secp256k1_ec_pubkey_parse(StealthCtx(), &spend, spend_pubkey.data(), spend_pubkey.size())) {
        return std::nullopt;
    }
    const secp256k1_pubkey* combined_in[2] = {&shared_g, &spend};
    secp256k1_pubkey combined;
    if (!secp256k1_ec_pubkey_combine(StealthCtx(), &combined, combined_in, 2)) {
        return std::nullopt;
    }
    std::array<unsigned char, 33> serialized;
    size_t len = serialized.size();
    if (!secp256k1_ec_pubkey_serialize(StealthCtx(), serialized.data(), &len, &combined, SECP256K1_EC_COMPRESSED)) {
        return std::nullopt;
    }
    CPubKey result(std::span<const unsigned char>{serialized.data(), len});
    if (!result.IsValid()) return std::nullopt;
    return result;
}

std::optional<CKey> DeriveOneTimePriv(
    const std::array<unsigned char, 32>& shared, const CKey& spend_priv)
{
    if (!spend_priv.IsValid()) return std::nullopt;
    std::array<unsigned char, 32> result;
    std::memcpy(result.data(), spend_priv.data(), 32);
    LOCK(g_stealth_ctx_mutex);
    if (!secp256k1_ec_seckey_tweak_add(StealthCtx(), result.data(), shared.data())) {
        return std::nullopt;
    }
    CKey out;
    out.Set(result.begin(), result.end(), /*fCompressedIn=*/true);
    if (!out.IsValid()) return std::nullopt;
    return out;
}

std::array<unsigned char, 32> DeriveRangeProofNonce(
    const PointBytes& ecdh_point, uint32_t output_index)
{
    unsigned char idx[4];
    U32LittleEndian(output_index, idx);
    std::array<unsigned char, 32> out;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>("pricoin/stealth/nonce-v1"), 24)
        .Write(ecdh_point.data(), ecdh_point.size())
        .Write(idx, 4)
        .Finalize(out.data());
    return out;
}

} // namespace pricoin::stealth
