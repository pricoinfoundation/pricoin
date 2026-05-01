// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <swap/btc_htlc.h>

#include <bech32.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cstring>

namespace pricoin::swap::btc_htlc {

namespace {

// 5-bit conversion ripped from key_io.cpp's pattern. Templated on
// (frombits, tobits, pad). For our P2WSH bech32: 8→5 with padding.
template<int frombits, int tobits, bool pad, typename O, typename I>
bool ConvertBits(const O& outfn, I it, I end)
{
    size_t acc = 0;
    size_t bits = 0;
    constexpr size_t maxv = (1 << tobits) - 1;
    constexpr size_t max_acc = (1 << (frombits + tobits - 1)) - 1;
    while (it != end) {
        acc = ((acc << frombits) | *it) & max_acc;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            outfn((acc >> bits) & maxv);
        }
        ++it;
    }
    if (pad) {
        if (bits) outfn((acc << (tobits - bits)) & maxv);
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
        return false;
    }
    return true;
}

const char* HRPForNetwork(Network n)
{
    switch (n) {
        case Network::BitcoinMainnet:    return "bc";
        case Network::BitcoinTestnet:    return "tb";
        case Network::BitcoinRegtest:    return "bcrt";
        case Network::LitecoinMainnet:   return "ltc";
        case Network::LitecoinTestnet:   return "tltc";
        case Network::LitecoinRegtest:   return "rltc";
        case Network::PricoinMainnet:    return "pric";
        case Network::PricoinRegtest:    return "pricrt";
    }
    throw HTLCError("unknown network");
}

// Encode a scalar number into the form CScript << expects for an
// arbitrary integer. CScriptNum supports up to 4 bytes natively;
// CLTV needs to handle values up to 5 bytes (Unix-time horizon
// extends past 2^32). We push as little-endian byte-string.
CScript& PushTimeout(CScript& s, int64_t timeout)
{
    if (timeout < 0) throw HTLCError("timeout must be non-negative");
    // CScriptNum encoding: minimal little-endian, with sign bit on
    // the high byte. For non-negative values up to 2^39 we can
    // build manually. (Bitcoin Core's CScriptNum class only goes up
    // to 4 bytes by default; we widen by hand.)
    if (timeout == 0) {
        s << 0;
        return s;
    }
    std::vector<unsigned char> data;
    int64_t v = timeout;
    while (v > 0) {
        data.push_back(static_cast<unsigned char>(v & 0xff));
        v >>= 8;
    }
    // If the high bit of the top byte is set, we'd misinterpret it
    // as negative; push an explicit zero byte to disambiguate. Same
    // rule CScriptNum uses internally.
    if (data.back() & 0x80) data.push_back(0x00);
    s << data;
    return s;
}

} // namespace

std::array<unsigned char, 32> Sha256Preimage(std::span<const unsigned char> preimage)
{
    std::array<unsigned char, 32> out{};
    CSHA256 h;
    h.Write(preimage.data(), preimage.size());
    h.Finalize(out.data());
    return out;
}

CScript BuildHTLCScript(
    std::span<const unsigned char> preimage_hash,
    const CPubKey& recipient_pub,
    const CPubKey& sender_pub,
    int64_t timeout)
{
    if (preimage_hash.size() != 32) {
        throw HTLCError("preimage_hash must be 32 bytes (SHA-256 of the preimage)");
    }
    if (!recipient_pub.IsValid() || !recipient_pub.IsCompressed()) {
        throw HTLCError("recipient_pub must be a valid compressed pubkey");
    }
    if (!sender_pub.IsValid() || !sender_pub.IsCompressed()) {
        throw HTLCError("sender_pub must be a valid compressed pubkey");
    }
    if (timeout < 0) {
        throw HTLCError("timeout must be non-negative (block height or unix time)");
    }

    CScript s;
    s << OP_IF;
    s << OP_SHA256;
    s << std::vector<unsigned char>(preimage_hash.begin(), preimage_hash.end());
    s << OP_EQUALVERIFY;
    s << std::vector<unsigned char>(recipient_pub.begin(), recipient_pub.end());
    s << OP_CHECKSIG;
    s << OP_ELSE;
    PushTimeout(s, timeout);
    s << OP_CHECKLOCKTIMEVERIFY;
    s << OP_DROP;
    s << std::vector<unsigned char>(sender_pub.begin(), sender_pub.end());
    s << OP_CHECKSIG;
    s << OP_ENDIF;
    return s;
}

CScript BuildHTLCScriptPubKey(const CScript& redeem_script)
{
    // P2WSH: OP_0 <SHA-256 of redeem script>
    CSHA256 h;
    h.Write(redeem_script.data(), redeem_script.size());
    std::array<unsigned char, 32> hash;
    h.Finalize(hash.data());
    CScript spk;
    spk << OP_0 << std::vector<unsigned char>(hash.begin(), hash.end());
    return spk;
}

std::string BuildHTLCBech32Address(const CScript& script, Network net)
{
    CSHA256 h;
    h.Write(script.data(), script.size());
    std::array<unsigned char, 32> hash;
    h.Finalize(hash.data());

    // segwit v0 header byte = 0; followed by 5-bit-converted hash.
    std::vector<uint8_t> data{0};
    data.reserve(53);
    if (!ConvertBits<8, 5, true>(
            [&](unsigned char c) { data.push_back(c); }, hash.begin(), hash.end())) {
        throw HTLCError("ConvertBits 8->5 failed");
    }
    return bech32::Encode(bech32::Encoding::BECH32, HRPForNetwork(net), data);
}

namespace {

// Sign one P2WSH HTLC input. The witness stack for the IF branch is
// `[sig <preimage> 1 <redeem_script>]`, for the ELSE branch
// `[sig 0 <redeem_script>]`.
void SignAndAttachWitness(
    CMutableTransaction& mtx,
    unsigned int input_idx,
    const HTLCFunding& funding,
    const CKey& priv,
    bool claim_path,
    std::span<const unsigned char> preimage)
{
    // sighash for P2WSH spend.
    const uint256 sighash = SignatureHash(
        funding.redeem_script, mtx, input_idx,
        SIGHASH_ALL, funding.prev_value,
        SigVersion::WITNESS_V0);

    std::vector<unsigned char> sig;
    if (!priv.Sign(sighash, sig)) {
        throw HTLCError("ECDSA sign failed");
    }
    sig.push_back(SIGHASH_ALL);

    auto& w = mtx.vin[input_idx].scriptWitness.stack;
    w.clear();
    w.push_back(std::move(sig));
    if (claim_path) {
        if (preimage.size() != 32) {
            throw HTLCError("preimage must be 32 bytes");
        }
        w.emplace_back(preimage.begin(), preimage.end());
        w.push_back({0x01}); // OP_TRUE → take the IF branch
    } else {
        w.emplace_back();    // empty bytes == OP_0 → take the ELSE branch
    }
    // Witness script is always last on the stack.
    w.emplace_back(
        funding.redeem_script.begin(),
        funding.redeem_script.end());
}

std::vector<unsigned char> SerializeTxWithWitness(const CMutableTransaction& mtx)
{
    CTransaction tx{mtx};
    DataStream ds;
    ds << TX_WITH_WITNESS(tx);
    return std::vector<unsigned char>(
        UCharCast(ds.data()),
        UCharCast(ds.data()) + ds.size());
}

CMutableTransaction BuildHTLCSpendTxBase(
    const HTLCFunding& funding,
    const CScript& dest_script,
    CAmount fee,
    uint32_t nSequence,
    uint32_t nLockTime)
{
    if (funding.prev_value <= 0) {
        throw HTLCError("prev_value must be positive");
    }
    if (fee < 0 || fee >= funding.prev_value) {
        throw HTLCError("fee out of range");
    }
    if (dest_script.empty()) {
        throw HTLCError("dest_script empty");
    }

    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.nLockTime = nLockTime;

    CTxIn in;
    in.prevout = COutPoint(Txid::FromUint256(funding.prev_txid), funding.prev_vout);
    in.nSequence = nSequence;
    mtx.vin.push_back(std::move(in));

    CTxOut out;
    out.nValue = funding.prev_value - fee;
    out.scriptPubKey = dest_script;
    mtx.vout.push_back(std::move(out));
    return mtx;
}

} // namespace

std::vector<unsigned char> BuildClaimTx(
    const HTLCFunding& funding,
    std::span<const unsigned char> preimage,
    const CKey& recipient_priv,
    const CScript& dest_script,
    CAmount fee)
{
    if (!recipient_priv.IsValid()) {
        throw HTLCError("recipient_priv invalid");
    }
    // Claim path: nSequence not constrained, no nLockTime needed.
    auto mtx = BuildHTLCSpendTxBase(
        funding, dest_script, fee,
        /*nSequence=*/0xfffffffd, /*nLockTime=*/0);
    SignAndAttachWitness(mtx, 0, funding, recipient_priv, /*claim_path=*/true, preimage);
    return SerializeTxWithWitness(mtx);
}

std::vector<unsigned char> BuildRefundTx(
    const HTLCFunding& funding,
    int64_t timeout,
    const CKey& sender_priv,
    const CScript& dest_script,
    CAmount fee)
{
    if (!sender_priv.IsValid()) {
        throw HTLCError("sender_priv invalid");
    }
    if (timeout < 0 || timeout > 0xffffffffLL) {
        throw HTLCError("timeout out of range for nLockTime field");
    }
    // Refund path: set nLockTime to the timeout. CLTV-spent inputs
    // need nSequence < 0xfffffffe so OP_CHECKLOCKTIMEVERIFY won't
    // short-circuit (BIP65). 0xfffffffd is the standard pattern.
    auto mtx = BuildHTLCSpendTxBase(
        funding, dest_script, fee,
        /*nSequence=*/0xfffffffd,
        /*nLockTime=*/static_cast<uint32_t>(timeout));
    SignAndAttachWitness(mtx, 0, funding, sender_priv, /*claim_path=*/false, /*preimage=*/{});
    return SerializeTxWithWitness(mtx);
}

} // namespace pricoin::swap::btc_htlc
