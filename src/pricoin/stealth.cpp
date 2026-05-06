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
// Main-address payload: 1-byte version + 33 (A) + 33 (B) = 67 bytes
// (then +4-byte SHA256d checksum from base58check).
constexpr unsigned char kStealthAddressVersion = 0x53; // 'S' in ASCII
constexpr size_t kPayloadSize = 1 + 33 + 33;

// Subaddress payload: 1-byte version + 33 (A_i) + 33 (B_i) + 4 (index, LE).
// Distinct version byte AND distinct length, so any decoder can classify
// an encoding before committing to a kind.
constexpr unsigned char kSubaddressVersion = 0x54;
constexpr size_t kSubaddressPayloadSize = 1 + 33 + 33 + 4;

// Pricoin stealth addresses use the bare prefix "PRIC" so they're visually
// distinct from the bech32 P2WPKH addresses (which start with the network
// HRP). We achieve this by choosing the version byte such that the base58
// encoding starts with "PRIC". Picking 0x53 happens to give addresses that
// begin with "1xx..." which isn't obviously distinct — for the experimental we just
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

std::string EncodeSubaddress(const StealthAddress& a, uint32_t index)
{
    if (!a.IsValid() || index == 0) return "";
    std::vector<unsigned char> payload;
    payload.reserve(kSubaddressPayloadSize);
    payload.push_back(kSubaddressVersion);
    payload.insert(payload.end(), a.view.begin(), a.view.end());
    payload.insert(payload.end(), a.spend.begin(), a.spend.end());
    unsigned char idx_le[4];
    idx_le[0] = static_cast<unsigned char>(index & 0xff);
    idx_le[1] = static_cast<unsigned char>((index >>  8) & 0xff);
    idx_le[2] = static_cast<unsigned char>((index >> 16) & 0xff);
    idx_le[3] = static_cast<unsigned char>((index >> 24) & 0xff);
    payload.insert(payload.end(), idx_le, idx_le + 4);
    return EncodeBase58Check(payload);
}

std::optional<ParsedStealth> DecodeSubaddress(std::string_view encoded)
{
    std::vector<unsigned char> payload;
    if (!DecodeBase58Check(std::string(encoded), payload, kSubaddressPayloadSize)) {
        return std::nullopt;
    }
    if (payload.size() != kSubaddressPayloadSize) return std::nullopt;
    if (payload[0] != kSubaddressVersion) return std::nullopt;
    ParsedStealth out;
    out.kind = AddressKind::Subaddress;
    out.address.view  = CPubKey(std::span<const unsigned char>{payload.data() + 1, 33});
    out.address.spend = CPubKey(std::span<const unsigned char>{payload.data() + 1 + 33, 33});
    if (!out.address.IsValid()) return std::nullopt;
    const unsigned char* idx = payload.data() + 1 + 66;
    out.subaddress_index = uint32_t(idx[0])
                         | (uint32_t(idx[1]) <<  8)
                         | (uint32_t(idx[2]) << 16)
                         | (uint32_t(idx[3]) << 24);
    if (out.subaddress_index == 0) return std::nullopt;  // reserved
    return out;
}

std::optional<ParsedStealth> ParseStealthAddress(std::string_view encoded)
{
    // Distinct version+length means at most one decoder can succeed.
    if (auto m = Decode(encoded)) {
        ParsedStealth out;
        out.kind             = AddressKind::Main;
        out.address          = *m;
        out.subaddress_index = 0;
        return out;
    }
    if (auto s = DecodeSubaddress(encoded)) return s;
    return std::nullopt;
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

std::optional<PointBytes> ComputeStealthR(
    const CKey& r, const StealthAddress& a, AddressKind kind)
{
    if (!r.IsValid() || !a.IsValid()) return std::nullopt;
    if (kind == AddressKind::Main) {
        // R = r·G — just the pubkey of r.
        const CPubKey R_pub = r.GetPubKey();
        if (!R_pub.IsValid()) return std::nullopt;
        PointBytes out;
        std::memcpy(out.data(), R_pub.data(), 33);
        return out;
    }
    // R = r·B (subaddress). ECDHPoint(r, B) computes exactly that.
    return ECDHPoint(r, a.spend);
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

std::optional<PointBytes> RecoverSpendPointFromOneTime(
    const CPubKey& one_time_pubkey,
    const std::array<unsigned char, 32>& shared)
{
    if (!one_time_pubkey.IsValid()) return std::nullopt;
    LOCK(g_stealth_ctx_mutex);

    secp256k1_pubkey P;
    if (!secp256k1_ec_pubkey_parse(StealthCtx(), &P,
                                   one_time_pubkey.data(),
                                   one_time_pubkey.size())) {
        return std::nullopt;
    }
    // Compute neg_shared·G — i.e. the negation of the shared·G point.
    secp256k1_pubkey neg_shared_g;
    if (!secp256k1_ec_pubkey_create(StealthCtx(), &neg_shared_g, shared.data())) {
        return std::nullopt;
    }
    if (!secp256k1_ec_pubkey_negate(StealthCtx(), &neg_shared_g)) {
        return std::nullopt;
    }
    // B_candidate = P + (−shared·G)
    const secp256k1_pubkey* combine_in[2] = {&P, &neg_shared_g};
    secp256k1_pubkey B_candidate;
    if (!secp256k1_ec_pubkey_combine(StealthCtx(), &B_candidate, combine_in, 2)) {
        return std::nullopt;
    }
    PointBytes out;
    size_t outlen = out.size();
    if (!secp256k1_ec_pubkey_serialize(StealthCtx(), out.data(), &outlen,
                                       &B_candidate, SECP256K1_EC_COMPRESSED)) {
        return std::nullopt;
    }
    return out;
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

// ─── Subaddresses ───────────────────────────────────────────────────────

namespace {

constexpr const char* kSubaddrTag = "pricoin/stealth/subaddr-v1";

// Compute the 32-byte offset scalar m_i = H_subaddr(a ‖ i ‖ ctr), reseeding
// via the counter byte until secp256k1 accepts the result as a valid scalar
// (i.e. 0 < m_i < n). The cosmically-rare invalid case is here only because
// the math doesn't allow us to elide the counter without a different KDF.
bool DeriveSubaddressOffset(const CKey& view_priv, uint32_t index,
                            std::array<unsigned char, 32>& out)
{
    if (!view_priv.IsValid()) return false;
    unsigned char idx[4];
    U32LittleEndian(index, idx);
    LOCK(g_stealth_ctx_mutex);
    for (uint16_t ctr = 0; ctr <= 0xff; ++ctr) {
        const unsigned char ctr_byte = static_cast<unsigned char>(ctr);
        CSHA256()
            .Write(reinterpret_cast<const unsigned char*>(kSubaddrTag),
                   std::strlen(kSubaddrTag))
            .Write(reinterpret_cast<const unsigned char*>(view_priv.data()), 32)
            .Write(idx, 4)
            .Write(&ctr_byte, 1)
            .Finalize(out.data());
        if (secp256k1_ec_seckey_verify(StealthCtx(), out.data())) return true;
    }
    return false; // counter exhausted — treat as invalid input
}

// Public-key only piece of the derivation: produces B_i = B + m·G and
// A_i = a · B_i, given the offset scalar `m` and master pub `B`.
bool DeriveSubaddressPubFromOffset(
    const std::array<unsigned char, 32>& m,
    const CKey& view_priv,
    const CPubKey& spend_pubkey,
    StealthAddress& out) EXCLUSIVE_LOCKS_REQUIRED(g_stealth_ctx_mutex)
{
    secp256k1_pubkey B;
    if (!secp256k1_ec_pubkey_parse(StealthCtx(), &B,
                                   spend_pubkey.data(), spend_pubkey.size())) {
        return false;
    }
    // B_i = B + m·G  (point tweak-add)
    if (!secp256k1_ec_pubkey_tweak_add(StealthCtx(), &B, m.data())) return false;

    // A_i = a · B_i  (multiply tweaked point by view scalar)
    secp256k1_pubkey A = B;
    if (!secp256k1_ec_pubkey_tweak_mul(
            StealthCtx(), &A,
            reinterpret_cast<const unsigned char*>(view_priv.data()))) {
        return false;
    }

    std::array<unsigned char, 33> B_bytes, A_bytes;
    size_t B_len = B_bytes.size(), A_len = A_bytes.size();
    if (!secp256k1_ec_pubkey_serialize(StealthCtx(), B_bytes.data(), &B_len, &B,
                                       SECP256K1_EC_COMPRESSED)) return false;
    if (!secp256k1_ec_pubkey_serialize(StealthCtx(), A_bytes.data(), &A_len, &A,
                                       SECP256K1_EC_COMPRESSED)) return false;
    out.view  = CPubKey(std::span<const unsigned char>{A_bytes.data(), A_len});
    out.spend = CPubKey(std::span<const unsigned char>{B_bytes.data(), B_len});
    return out.IsValid();
}

} // namespace

std::optional<Subaddress> DeriveSubaddress(
    const CKey& view_priv, const CKey& spend_priv, uint32_t index)
{
    if (index == 0) return std::nullopt; // reserved: caller uses master directly
    if (!view_priv.IsValid() || !spend_priv.IsValid()) return std::nullopt;

    std::array<unsigned char, 32> m{};
    if (!DeriveSubaddressOffset(view_priv, index, m)) return std::nullopt;

    Subaddress out;
    out.index = index;

    // b_i = b + m  (mod n)
    std::array<unsigned char, 32> b_i;
    std::memcpy(b_i.data(), spend_priv.data(), 32);
    {
        LOCK(g_stealth_ctx_mutex);
        if (!secp256k1_ec_seckey_tweak_add(StealthCtx(), b_i.data(), m.data())) {
            return std::nullopt;
        }
        out.spend_priv.Set(b_i.begin(), b_i.end(), /*fCompressedIn=*/true);
        if (!out.spend_priv.IsValid()) return std::nullopt;

        if (!DeriveSubaddressPubFromOffset(m, view_priv,
                                           spend_priv.GetPubKey(),
                                           out.public_address)) {
            return std::nullopt;
        }
    }

    // Sanity: b_i · G must equal B_i. Catches any algebraic regression.
    if (out.spend_priv.GetPubKey() != out.public_address.spend) {
        return std::nullopt;
    }
    return out;
}

std::optional<Subaddress> DeriveSubaddressPublic(
    const CKey& view_priv, const CPubKey& spend_pubkey, uint32_t index)
{
    if (index == 0) return std::nullopt;
    if (!view_priv.IsValid() || !spend_pubkey.IsValid()) return std::nullopt;

    std::array<unsigned char, 32> m{};
    if (!DeriveSubaddressOffset(view_priv, index, m)) return std::nullopt;

    Subaddress out;
    out.index = index;
    LOCK(g_stealth_ctx_mutex);
    if (!DeriveSubaddressPubFromOffset(m, view_priv, spend_pubkey,
                                       out.public_address)) {
        return std::nullopt;
    }
    return out;
}

void RunSubaddressSelfTest()
{
    // Build a deterministic master identity from a fixed seed so test output
    // is reproducible (the seed isn't sensitive — it's a literal).
    auto fixed_scalar = [](unsigned char b) {
        std::array<unsigned char, 32> bytes{};
        bytes[31] = b;
        CKey k;
        k.Set(bytes.begin(), bytes.end(), /*fCompressedIn=*/true);
        if (!k.IsValid()) throw std::runtime_error(
            "subaddr self-test: fixed scalar invalid (b=" + std::to_string(b) + ")");
        return k;
    };
    const CKey a = fixed_scalar(0x11);  // master view scalar
    const CKey b = fixed_scalar(0x22);  // master spend scalar
    const CPubKey B_pub = b.GetPubKey();

    // Index 0 must be rejected.
    if (DeriveSubaddress(a, b, 0).has_value()) {
        throw std::runtime_error("subaddr self-test: index 0 was not rejected");
    }
    if (DeriveSubaddressPublic(a, B_pub, 0).has_value()) {
        throw std::runtime_error("subaddr self-test: public index 0 was not rejected");
    }

    // Determinism + priv/pub agreement.
    const auto s1a = DeriveSubaddress(a, b, 1);
    const auto s1b = DeriveSubaddress(a, b, 1);
    const auto s1pub = DeriveSubaddressPublic(a, B_pub, 1);
    if (!s1a || !s1b || !s1pub) throw std::runtime_error(
        "subaddr self-test: derivation returned nullopt for valid input");
    if (s1a->public_address != s1b->public_address) throw std::runtime_error(
        "subaddr self-test: derivation is non-deterministic");
    if (s1a->public_address != s1pub->public_address) throw std::runtime_error(
        "subaddr self-test: priv-side and pub-side derivations disagree");

    // Index isolation: different indices → different addresses.
    const auto s2 = DeriveSubaddress(a, b, 2);
    const auto s100 = DeriveSubaddress(a, b, 100);
    if (!s2 || !s100) throw std::runtime_error(
        "subaddr self-test: derivation failed for non-trivial index");
    if (s1a->public_address == s2->public_address ||
        s1a->public_address == s100->public_address ||
        s2->public_address == s100->public_address) {
        throw std::runtime_error("subaddr self-test: index collision");
    }

    // The subaddress must NOT collide with the master identity.
    if (s1a->public_address.view  == a.GetPubKey() ||
        s1a->public_address.spend == B_pub) {
        throw std::runtime_error("subaddr self-test: subaddress collides with master");
    }

    // The subaddress spend scalar produces the subaddress spend point.
    if (s1a->spend_priv.GetPubKey() != s1a->public_address.spend) {
        throw std::runtime_error("subaddr self-test: b_i · G ≠ B_i");
    }

    // ── Sender↔receiver round trip via the production helper ──────
    //
    // Both kinds (main, subaddress) run the same scan formula:
    //   shared' = H(a · R ‖ idx),  candidate = P − shared'·G
    // and the candidate must equal the recipient's spend point (B for
    // main, B_i for subaddress).
    auto roundtrip = [&](AddressKind kind, const StealthAddress& sa,
                          const CKey& spend_priv, const char* label) {
        const CKey r = fixed_scalar(0x33);
        const auto R_bytes = ComputeStealthR(r, sa, kind);
        if (!R_bytes) throw std::runtime_error(
            std::string("subaddr self-test: ComputeStealthR failed (") + label + ")");
        CPubKey R_pub(std::span<const unsigned char>{R_bytes->data(), 33});

        // Sender's shared point. Always equals r·A regardless of kind.
        const auto S_sender = ECDHPoint(r, sa.view);
        if (!S_sender) throw std::runtime_error(
            std::string("subaddr self-test: sender ECDH (") + label + ")");

        // Receiver-side scan: S = a · R must reproduce S_sender.
        const auto S_recv = ECDHPoint(a, R_pub);
        if (!S_recv) throw std::runtime_error(
            std::string("subaddr self-test: receiver ECDH (") + label + ")");
        if (*S_recv != *S_sender) throw std::runtime_error(
            std::string("subaddr self-test: ECDH disagree (") + label + ")");

        const auto shared = DeriveSharedSecret(*S_recv, /*output_index=*/0);
        const auto P_opt = DeriveOneTimePubkey(shared, sa.spend);
        if (!P_opt) throw std::runtime_error(
            std::string("subaddr self-test: DeriveOneTimePubkey (") + label + ")");

        // Spend round-trip: p = shared + spend_priv, check p · G == P.
        const auto p_opt = DeriveOneTimePriv(shared, spend_priv);
        if (!p_opt) throw std::runtime_error(
            std::string("subaddr self-test: DeriveOneTimePriv (") + label + ")");
        if (p_opt->GetPubKey() != *P_opt) throw std::runtime_error(
            std::string("subaddr self-test: priv/pub mismatch (") + label + ")");

        // Scanner inverse: B_candidate = P − shared·G must reproduce the
        // recipient's spend point (B for main, B_i for subaddress).
        const auto B_candidate = RecoverSpendPointFromOneTime(*P_opt, shared);
        if (!B_candidate) throw std::runtime_error(
            std::string("subaddr self-test: RecoverSpendPointFromOneTime (") + label + ")");
        PointBytes B_expected;
        std::memcpy(B_expected.data(), sa.spend.data(), 33);
        if (*B_candidate != B_expected) throw std::runtime_error(
            std::string("subaddr self-test: scan-side B candidate mismatch (") + label + ")");
    };

    const StealthAddress master_pub_addr{a.GetPubKey(), B_pub};
    roundtrip(AddressKind::Main,       master_pub_addr,        b,                 "main");
    roundtrip(AddressKind::Subaddress, s1a->public_address,    s1a->spend_priv,   "sub#1");
    roundtrip(AddressKind::Subaddress, s100->public_address,   s100->spend_priv,  "sub#100");

    // ── Codec round-trip + cross-rejection ─────────────────────────
    {
        // Subaddress encode/decode preserves both keys and the index.
        const std::string enc = EncodeSubaddress(s1a->public_address, s1a->index);
        if (enc.empty()) throw std::runtime_error("subaddr self-test: EncodeSubaddress empty");
        const auto dec = DecodeSubaddress(enc);
        if (!dec) throw std::runtime_error(
            "subaddr self-test: DecodeSubaddress rejected its own output");
        if (dec->kind != AddressKind::Subaddress) throw std::runtime_error(
            "subaddr self-test: codec round-trip kind mismatch");
        if (dec->address != s1a->public_address) throw std::runtime_error(
            "subaddr self-test: codec round-trip lost (A_i, B_i)");
        if (dec->subaddress_index != s1a->index) throw std::runtime_error(
            "subaddr self-test: codec round-trip lost index");

        // Index 0 is rejected by the encoder.
        if (!EncodeSubaddress(s1a->public_address, 0).empty()) {
            throw std::runtime_error("subaddr self-test: index 0 was encoded");
        }

        // ParseStealthAddress classifies subaddress encodings correctly.
        const auto parsed_sub = ParseStealthAddress(enc);
        if (!parsed_sub || parsed_sub->kind != AddressKind::Subaddress ||
            parsed_sub->subaddress_index != s1a->index) {
            throw std::runtime_error("subaddr self-test: ParseStealthAddress mis-classified subaddress");
        }

        // Main-address Decode rejects the subaddress encoding (length differs).
        const StealthAddress master_pub{a.GetPubKey(), B_pub};
        const std::string main_enc = Encode(master_pub);
        if (main_enc.empty()) throw std::runtime_error(
            "subaddr self-test: Encode(master) empty");
        if (Decode(enc).has_value()) throw std::runtime_error(
            "subaddr self-test: main Decode accepted a subaddress encoding");

        // Subaddress Decode rejects the main encoding.
        if (DecodeSubaddress(main_enc).has_value()) throw std::runtime_error(
            "subaddr self-test: subaddress Decode accepted a main encoding");

        // ParseStealthAddress classifies main encodings correctly.
        const auto parsed_main = ParseStealthAddress(main_enc);
        if (!parsed_main || parsed_main->kind != AddressKind::Main ||
            parsed_main->subaddress_index != 0 ||
            parsed_main->address != master_pub) {
            throw std::runtime_error("subaddr self-test: ParseStealthAddress mis-classified main");
        }

        // Two different subaddresses encode to two different strings.
        const std::string enc2 = EncodeSubaddress(s2->public_address, s2->index);
        if (enc == enc2) throw std::runtime_error(
            "subaddr self-test: distinct indices encoded identically");

        // Junk inputs are rejected without crashing.
        if (ParseStealthAddress("").has_value()) throw std::runtime_error(
            "subaddr self-test: ParseStealthAddress accepted empty");
        if (ParseStealthAddress("not a real address").has_value()) throw std::runtime_error(
            "subaddr self-test: ParseStealthAddress accepted garbage");
    }
}

} // namespace pricoin::stealth
