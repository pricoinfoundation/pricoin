// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <swap/btc_htlc.h>

#include <bech32.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cstring>
#include <stdexcept>

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

CScript BuildDLHTLCScript(
    std::span<const unsigned char> adaptor_T_G_compressed,
    const CPubKey& recipient_pub,
    const CPubKey& sender_pub,
    int64_t timeout)
{
    if (adaptor_T_G_compressed.size() != 33) {
        throw HTLCError("adaptor_T_G must be 33 bytes (compressed pubkey)");
    }
    if (adaptor_T_G_compressed[0] != 0x02 && adaptor_T_G_compressed[0] != 0x03) {
        throw HTLCError("adaptor_T_G must start with 0x02 or 0x03");
    }
    {
        // Reject the identity (0x02 + 32 zero bytes is not a valid
        // curve point, but cheap to filter out cases where the
        // caller forgot to populate T_G).
        bool all_zero = true;
        for (size_t i = 1; i < 33; ++i) {
            if (adaptor_T_G_compressed[i] != 0) { all_zero = false; break; }
        }
        if (all_zero) throw HTLCError("adaptor_T_G must not be the zero point");
    }
    // Don't enforce CPubKey::IsFullyValid here — the validator runs
    // libsecp256k1 in script execution. We do enforce the byte-shape
    // checks above to catch obvious mistakes.
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
    s << std::vector<unsigned char>(recipient_pub.begin(), recipient_pub.end());
    s << OP_CHECKSIGVERIFY;
    s << std::vector<unsigned char>(
            adaptor_T_G_compressed.begin(), adaptor_T_G_compressed.end());
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

std::vector<unsigned char> BuildDLClaimTx(
    const HTLCFunding& funding,
    std::span<const unsigned char> t_scalar,
    const CKey& recipient_priv,
    const CScript& dest_script,
    CAmount fee)
{
    if (!recipient_priv.IsValid()) {
        throw HTLCError("recipient_priv invalid");
    }
    if (t_scalar.size() != 32) {
        throw HTLCError("t_scalar must be 32 bytes");
    }
    CKey t_priv;
    t_priv.Set(t_scalar.begin(), t_scalar.end(), /*fCompressedIn=*/true);
    if (!t_priv.IsValid()) {
        throw HTLCError("t_scalar not a valid secp256k1 scalar");
    }

    auto mtx = BuildHTLCSpendTxBase(
        funding, dest_script, fee,
        /*nSequence=*/0xfffffffd, /*nLockTime=*/0);

    // Both signatures sign the same P2WSH sighash. Witness elements
    // are pushed bottom→top onto the script-execution stack; the
    // script pops from the top. Walking through the IF branch:
    //   Push <recipient_pub>; CHECKSIGVERIFY pops next-deepest sig.
    //   Push <T_G>; CHECKSIG pops top-of-stack sig.
    // → witness order must be [<T_G_sig>, <recipient_sig>, 0x01,
    //   <redeem_script>] (deeper element listed first below).

    // sighash for P2WSH spend.
    const uint256 sighash = SignatureHash(
        funding.redeem_script, mtx, /*nIn=*/0,
        SIGHASH_ALL, funding.prev_value,
        SigVersion::WITNESS_V0);

    std::vector<unsigned char> sig_recipient;
    if (!recipient_priv.Sign(sighash, sig_recipient)) {
        throw HTLCError("ECDSA sign (recipient) failed");
    }
    sig_recipient.push_back(SIGHASH_ALL);

    std::vector<unsigned char> sig_T_G;
    if (!t_priv.Sign(sighash, sig_T_G)) {
        throw HTLCError("ECDSA sign (T_G) failed");
    }
    sig_T_G.push_back(SIGHASH_ALL);

    auto& w = mtx.vin[0].scriptWitness.stack;
    w.clear();
    w.push_back(std::move(sig_T_G));        // bottom of stack
    w.push_back(std::move(sig_recipient));  // middle
    w.push_back({0x01});                    // top: select IF branch
    w.emplace_back(funding.redeem_script.begin(), funding.redeem_script.end());

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

// ─── Self-test ──────────────────────────────────────────────────

namespace {

CMutableTransaction ParseTxBytes(std::span<const unsigned char> bytes)
{
    DataStream ds{bytes};
    CMutableTransaction mtx;
    ds >> TX_WITH_WITNESS(mtx);
    return mtx;
}

void Check(bool cond, const char* what)
{
    if (!cond) {
        throw std::runtime_error(std::string("DL-HTLC self-test failed: ") + what);
    }
}

} // namespace

void RunDLHTLCSelfTest()
{
    // Honest setup: alice + bob keypairs, secret t, timeout height.
    CKey alice_priv; alice_priv.MakeNewKey(/*fCompressed=*/true);
    CKey bob_priv;   bob_priv.MakeNewKey(  /*fCompressed=*/true);
    const CPubKey alice_pub = alice_priv.GetPubKey();
    const CPubKey bob_pub   = bob_priv.GetPubKey();

    // Random valid scalar t. (CKey::MakeNewKey rejects out-of-range
    // scalars, so we use that as a uniform sampler.)
    CKey t_priv; t_priv.MakeNewKey(/*fCompressed=*/true);
    std::array<unsigned char, 32> t_bytes{};
    std::memcpy(t_bytes.data(), t_priv.begin(), 32);
    const CPubKey T_G_pub = t_priv.GetPubKey();
    Check(T_G_pub.IsValid() && T_G_pub.size() == 33, "T_G valid");

    constexpr int64_t kTimeout = 1'000'000;

    const CScript redeem = BuildDLHTLCScript(
        std::span<const unsigned char>(T_G_pub.data(), 33),
        alice_pub, bob_pub, kTimeout);
    const CScript spk = BuildHTLCScriptPubKey(redeem);

    // Synthetic prior-tx funding the HTLC. We don't broadcast — only
    // its txid (= hash of the in-memory tx) is what HTLCFunding needs.
    CMutableTransaction prev;
    prev.version = 2;
    prev.nLockTime = 0;
    {
        CTxIn in;
        in.prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
        in.nSequence = 0xfffffffe;
        prev.vin.push_back(std::move(in));
    }
    {
        CTxOut o;
        o.nValue = 100'000'000;          // 1.0 LTC
        o.scriptPubKey = spk;
        prev.vout.push_back(std::move(o));
    }
    const Txid prev_txid = CTransaction(prev).GetHash();

    HTLCFunding f;
    f.prev_txid     = prev_txid.ToUint256();
    f.prev_vout     = 0;
    f.prev_value    = prev.vout[0].nValue;
    f.redeem_script = redeem;

    // Destination: P2WPKH paying alice's pubkey (just a placeholder
    // SPK so the spending tx has a valid output).
    const CKeyID alice_keyid = alice_pub.GetID();
    const CScript dest = CScript()
        << OP_0
        << std::vector<unsigned char>(alice_keyid.begin(), alice_keyid.end());
    constexpr CAmount kFee = 1000;

    const std::vector<CTxOut> spent_outputs{prev.vout[0]};

    // ─── Honest claim ───────────────────────────────────
    {
        auto tx_bytes = BuildDLClaimTx(
            f, std::span<const unsigned char>(t_bytes.data(), 32),
            alice_priv, dest, kFee);
        CMutableTransaction spend = ParseTxBytes(tx_bytes);
        PrecomputedTransactionData txdata;
        txdata.Init(spend, std::vector<CTxOut>{spent_outputs}, /*force=*/true);
        MutableTransactionSignatureChecker checker(
            &spend, /*nIn=*/0, prev.vout[0].nValue, txdata,
            MissingDataBehavior::FAIL);
        ScriptError serror = SCRIPT_ERR_OK;
        const bool ok = VerifyScript(
            CScript{}, spk, &spend.vin[0].scriptWitness,
            STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serror);
        Check(ok && serror == SCRIPT_ERR_OK, "honest DL claim verify");
    }

    // ─── Wrong t ────────────────────────────────────────
    {
        CKey wrong_t; wrong_t.MakeNewKey(true);
        std::array<unsigned char, 32> wrong{};
        std::memcpy(wrong.data(), wrong_t.begin(), 32);
        auto tx_bytes = BuildDLClaimTx(
            f, std::span<const unsigned char>(wrong.data(), 32),
            alice_priv, dest, kFee);
        CMutableTransaction spend = ParseTxBytes(tx_bytes);
        PrecomputedTransactionData txdata;
        txdata.Init(spend, std::vector<CTxOut>{spent_outputs}, /*force=*/true);
        MutableTransactionSignatureChecker checker(
            &spend, 0, prev.vout[0].nValue, txdata, MissingDataBehavior::FAIL);
        ScriptError serror = SCRIPT_ERR_OK;
        const bool ok = VerifyScript(
            CScript{}, spk, &spend.vin[0].scriptWitness,
            STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serror);
        Check(!ok, "wrong-t claim must fail");
    }

    // ─── Honest refund (after timelock) ────────────────
    {
        auto tx_bytes = BuildRefundTx(f, kTimeout, bob_priv, dest, kFee);
        CMutableTransaction spend = ParseTxBytes(tx_bytes);
        Check(spend.nLockTime == kTimeout, "refund nLockTime set");
        // The MutableTransactionSignatureChecker does not by itself
        // simulate a chain tip — CHECKLOCKTIMEVERIFY validates the
        // tx's nLockTime field against the timelock pushed by the
        // script, so the on-chain "is the height past timelock?"
        // policy is the network's job. The script here checks that
        // tx.nLockTime ≥ pushed_timeout, which we satisfy.
        PrecomputedTransactionData txdata;
        txdata.Init(spend, std::vector<CTxOut>{spent_outputs}, /*force=*/true);
        MutableTransactionSignatureChecker checker(
            &spend, 0, prev.vout[0].nValue, txdata, MissingDataBehavior::FAIL);
        ScriptError serror = SCRIPT_ERR_OK;
        const bool ok = VerifyScript(
            CScript{}, spk, &spend.vin[0].scriptWitness,
            STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serror);
        Check(ok && serror == SCRIPT_ERR_OK, "honest DL refund verify");
    }

    // ─── Refund with too-low nLockTime ─────────────────
    // CLTV check is `tx.nLockTime ≥ script-pushed timeout`. We build
    // a refund whose redeem script pushes `kTimeout+1` while the tx
    // sets `nLockTime = kTimeout` — so CLTV must fail.
    {
        const CScript redeem_late = BuildDLHTLCScript(
            std::span<const unsigned char>(T_G_pub.data(), 33),
            alice_pub, bob_pub, kTimeout + 1);
        const CScript spk_late = BuildHTLCScriptPubKey(redeem_late);
        // Re-fund into the new SPK.
        CMutableTransaction prev_late = prev;
        prev_late.vout[0].scriptPubKey = spk_late;
        const Txid prev_late_txid = CTransaction(prev_late).GetHash();
        HTLCFunding f_late = f;
        f_late.prev_txid     = prev_late_txid.ToUint256();
        f_late.redeem_script = redeem_late;

        auto tx_bytes = BuildRefundTx(f_late, /*timeout=*/kTimeout,
                                        bob_priv, dest, kFee);
        // BuildRefundTx sets nLockTime = its `timeout` arg = kTimeout,
        // but the script's pushed timeout is kTimeout+1 → CLTV fails.
        CMutableTransaction spend = ParseTxBytes(tx_bytes);
        PrecomputedTransactionData txdata;
        const std::vector<CTxOut> spent_late{prev_late.vout[0]};
        txdata.Init(spend, std::vector<CTxOut>{spent_late}, /*force=*/true);
        MutableTransactionSignatureChecker checker(
            &spend, 0, prev_late.vout[0].nValue, txdata,
            MissingDataBehavior::FAIL);
        ScriptError serror = SCRIPT_ERR_OK;
        const bool ok = VerifyScript(
            CScript{}, spk_late, &spend.vin[0].scriptWitness,
            STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serror);
        Check(!ok, "early-refund must fail");
        // CLTV failure surfaces as SCRIPT_ERR_NEGATIVE_LOCKTIME
        // or SCRIPT_ERR_UNSATISFIED_LOCKTIME depending on path.
        Check(serror == SCRIPT_ERR_UNSATISFIED_LOCKTIME
              || serror == SCRIPT_ERR_NEGATIVE_LOCKTIME,
              "early-refund must surface CLTV error");
    }
}

} // namespace pricoin::swap::btc_htlc
