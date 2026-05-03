// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pricoin_btc_holding.h>

#include <bech32.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <crypto/hmac_sha256.h>
#include <crypto/sha256.h>
#include <key.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <random.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <streams.h>
#include <support/cleanse.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/bip32.h>
#include <util/log.h>
#include <util/strencodings.h>
#include <wallet/pricoin_chain_watcher.h>
#include <wallet/pricoin_stealth.h>
#include <wallet/wallet.h>

#include <cstring>
#include <map>
#include <utility>

namespace wallet::pricoin_btc_holding {

namespace {

// ─── Per-chain table ────────────────────────────────────────────

const std::vector<ChainParams> kChains = {
    {"btc", "bc",  /*witness_v=*/1},
    {"ltc", "ltc", /*witness_v=*/0},
};

// ─── In-memory cache ────────────────────────────────────────────

struct CacheKey {
    ::wallet::CWallet* wallet;
    std::string chain;
    bool operator<(const CacheKey& o) const {
        if (wallet != o.wallet) return wallet < o.wallet;
        return chain < o.chain;
    }
};

Mutex g_mutex;
std::map<CacheKey, Identity> g_identities GUARDED_BY(g_mutex);

// HMAC chain like pricoin_swap_session — but per-chain so the BTC
// holding key, LTC holding key, and swap-identity key are all
// independent. The wallet's stealth-spend priv is the root.
bool DeriveHoldingPriv(::wallet::CWallet& wallet, const std::string& chain, CKey& out)
{
    const auto& id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
    if (!id.spend.IsValid()) return false;
    const std::string tag = "pricoin/holding/" + chain + "-v1";
    for (uint8_t counter = 0; counter < 16; ++counter) {
        CHMAC_SHA256 hmac(UCharCast(id.spend.data()), 32);
        hmac.Write(reinterpret_cast<const unsigned char*>(tag.data()), tag.size());
        hmac.Write(&counter, 1);
        unsigned char raw[32];
        hmac.Finalize(raw);
        out.Set(raw, raw + 32, /*compressed=*/true);
        memory_cleanse(raw, 32);
        if (out.IsValid()) return true;
    }
    return false;
}

// Encode an x-only pubkey (or a 20-byte hash) as a bech32(m) address
// with the given HRP and witness version.
std::string EncodeWitnessAddress(const std::string& hrp,
                                  int witness_v,
                                  std::span<const unsigned char> program)
{
    std::vector<unsigned char> data;
    data.reserve(1 + (program.size() * 8 + 4) / 5);
    data.push_back(static_cast<unsigned char>(witness_v));
    // Convert program from 8-bit to 5-bit groups, padding.
    int bits = 0;
    int acc = 0;
    for (unsigned char b : program) {
        acc = (acc << 8) | b;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            data.push_back((acc >> bits) & 0x1f);
        }
    }
    if (bits > 0) {
        data.push_back((acc << (5 - bits)) & 0x1f);
    }
    const auto encoding = (witness_v == 0)
        ? bech32::Encoding::BECH32
        : bech32::Encoding::BECH32M;
    return bech32::Encode(encoding, hrp, data);
}

} // namespace

// Decode a bech32(m) address to (witness_v, program). Returns false
// on hrp/encoding/format mismatch. Public — used by RPC layer to
// resolve LTC HTLC claim/refund destinations.
bool DecodeWitnessAddress(const std::string& addr,
                            const std::string& expected_hrp,
                            int& witness_v_out,
                            std::vector<unsigned char>& program_out)
{
    auto dec = bech32::Decode(addr);
    if (dec.encoding == bech32::Encoding::INVALID) return false;
    if (dec.hrp != expected_hrp) return false;
    if (dec.data.empty()) return false;
    const int v = dec.data[0];
    if (v < 0 || v > 16) return false;
    witness_v_out = v;
    // Re-pack 5-bit groups → 8-bit. Use ConvertBits-style accumulator.
    int bits = 0;
    int acc = 0;
    program_out.clear();
    for (size_t i = 1; i < dec.data.size(); ++i) {
        const int d = dec.data[i];
        if (d < 0 || d > 31) return false;
        acc = (acc << 5) | d;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            program_out.push_back((acc >> bits) & 0xff);
        }
    }
    if (bits >= 5 || ((acc << (8 - bits)) & 0xff) != 0) {
        // Trailing pad bits must be zero.
        return false;
    }
    if (program_out.size() < 2 || program_out.size() > 40) return false;
    // Encoding cross-check: BIP350 says v0 must use bech32, v≥1 must use bech32m.
    if (v == 0 && dec.encoding != bech32::Encoding::BECH32)  return false;
    if (v >= 1 && dec.encoding != bech32::Encoding::BECH32M) return false;
    return true;
}

// Construct the scriptPubKey for a witness-v output:
//   OP_<v> [push of program]
CScript MakeWitnessSPK(int witness_v, std::span<const unsigned char> program)
{
    if (witness_v == 0) {
        return CScript() << OP_0 << std::vector<unsigned char>(program.begin(), program.end());
    }
    return CScript() << CScript::EncodeOP_N(witness_v)
        << std::vector<unsigned char>(program.begin(), program.end());
}

const ChainParams* GetChainParams(const std::string& chain)
{
    for (const auto& cp : kChains) {
        if (cp.name == chain) return &cp;
    }
    return nullptr;
}

util::Result<Identity> GetOrCreateIdentity(::wallet::CWallet& wallet,
                                             const std::string& chain)
{
    const ChainParams* cp = GetChainParams(chain);
    if (!cp) return util::Error{Untranslated("unknown chain: " + chain)};
    {
        LOCK(g_mutex);
        auto it = g_identities.find({&wallet, chain});
        if (it != g_identities.end()) return it->second;
    }
    Identity ident;
    ident.chain = chain;
    if (!DeriveHoldingPriv(wallet, chain, ident.priv)) {
        return util::Error{Untranslated("could not derive holding priv (wallet locked?)")};
    }
    ident.pub = ident.priv.GetPubKey();
    if (!ident.pub.IsValid() || ident.pub.size() != 33) {
        return util::Error{Untranslated("derived pubkey invalid")};
    }
    XOnlyPubKey xo(ident.pub);
    std::copy(xo.begin(), xo.end(), ident.xonly.begin());

    // For P2TR (witness_v=1) the program is the 32-byte x-only pub.
    // For P2WPKH (witness_v=0) the program is HASH160(compressed_pub).
    if (cp->witness_v == 1) {
        ident.address = EncodeWitnessAddress(cp->hrp, 1,
            std::span<const unsigned char>(ident.xonly.data(), 32));
    } else if (cp->witness_v == 0) {
        const CKeyID hash = ident.pub.GetID();
        ident.address = EncodeWitnessAddress(cp->hrp, 0,
            std::span<const unsigned char>(hash.begin(), hash.size()));
    } else {
        return util::Error{Untranslated("unsupported witness version")};
    }
    {
        LOCK(g_mutex);
        g_identities[{&wallet, chain}] = ident;
    }
    return ident;
}

util::Result<std::string> GetAddress(::wallet::CWallet& wallet,
                                       const std::string& chain)
{
    auto id = GetOrCreateIdentity(wallet, chain);
    if (!id) return util::Error{util::ErrorString(id)};
    return id->address;
}

util::Result<::pricoin::swap::AddressBalance>
GetBalance(::wallet::CWallet& wallet, const std::string& chain)
{
    auto id = GetOrCreateIdentity(wallet, chain);
    if (!id) return util::Error{util::ErrorString(id)};
    auto backend = ::wallet::pricoin_chain_watcher::MakeForeignClientFromRegistry(chain);
    if (!backend) {
        return util::Error{Untranslated("no chain backend registered for " + chain
            + " — set -" + chain + "watchurl= or -chainwatchurl=" + chain + "=...")};
    }
    try {
        const auto b = backend->GetAddressBalance(id->address);
        ::pricoin::swap::AddressBalance out;
        out.confirmed_sat   = b.confirmed_sat;
        out.unconfirmed_sat = b.unconfirmed_sat;
        out.utxo_count      = b.utxo_count;
        return out;
    } catch (const std::exception& e) {
        return util::Error{Untranslated(std::string("backend balance query failed: ") + e.what())};
    }
}

util::Result<std::string> BuildAndBroadcastFundingTx(
    ::wallet::CWallet& wallet,
    const std::string& chain,
    const std::array<unsigned char, 32>& agg_xonly,
    int64_t amount_sat,
    int64_t fee_sat)
{
    if (chain != "btc") {
        // LTC mainnet/testnet has no Taproot, so there is no P2TR
        // output to fund. The atomic-swap protocol (MuSig2 + adaptor)
        // is BIP340/BIP341-only — for LTC we'd need a parallel
        // protocol over P2WSH 2-of-2 with cooperative ECDSA + ECDSA
        // adaptor signatures. That protocol isn't implemented yet,
        // so funding a swap on a non-Taproot chain has no meaning.
        // The LTC holding wallet still supports receive + balance +
        // sweep — see pricoin_btc_getaddress / _getbalance / _sweep.
        return util::Error{Untranslated(
            "swap funding is BTC-only: the swap protocol uses MuSig2 "
            "+ Schnorr adaptor signatures over BIP341 P2TR, which "
            "non-Taproot chains (LTC) cannot host. LTC swap support "
            "needs a follow-on protocol (P2WSH 2-of-2 + ECDSA "
            "cooperative signing + ECDSA adaptor signatures). "
            "For now: pricoin_btc_sweep still works for LTC, so the "
            "holding wallet is usable for receive + send.")};
    }
    if (amount_sat <= 0 || fee_sat < 0) {
        return util::Error{Untranslated("amount must be positive, fee non-negative")};
    }
    auto id = GetOrCreateIdentity(wallet, chain);
    if (!id) return util::Error{util::ErrorString(id)};
    auto backend = ::wallet::pricoin_chain_watcher::MakeForeignClientFromRegistry(chain);
    if (!backend) {
        return util::Error{Untranslated("no chain backend registered for " + chain)};
    }
    std::vector<::wallet::pricoin_chain_watcher::IForeignChainClient::Utxo> utxos;
    try {
        utxos = backend->GetAddressUtxos(id->address);
    } catch (const std::exception& e) {
        return util::Error{Untranslated(std::string("UTXO query failed: ") + e.what())};
    }
    // Pick the smallest UTXO that's >= amount + fee.
    const int64_t target = amount_sat + fee_sat;
    const ::wallet::pricoin_chain_watcher::IForeignChainClient::Utxo* picked = nullptr;
    for (const auto& u : utxos) {
        if (!u.confirmed) continue;
        if (u.value_sat < target) continue;
        if (!picked || u.value_sat < picked->value_sat) picked = &u;
    }
    if (!picked) {
        return util::Error{Untranslated(strprintf(
            "no confirmed UTXO ≥ amount+fee (%d sat); deposit BTC at %s first",
            target, id->address))};
    }
    auto picked_txid = uint256::FromHex(picked->txid);
    if (!picked_txid) {
        return util::Error{Untranslated("backend returned unparseable UTXO txid")};
    }
    const int64_t change_sat = picked->value_sat - target;

    // Build the tx skeleton. v=2, no locktime.
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.nLockTime = 0;
    CTxIn in;
    in.prevout = COutPoint{Txid::FromUint256(*picked_txid),
                            static_cast<uint32_t>(picked->vout)};
    in.nSequence = 0xfffffffe;
    mtx.vin.push_back(std::move(in));

    // Output 0: 2-of-2 funding (OP_1 <agg_xonly>).
    {
        CTxOut o;
        o.nValue = amount_sat;
        o.scriptPubKey = CScript() << OP_1
            << std::vector<unsigned char>(agg_xonly.begin(), agg_xonly.end());
        mtx.vout.push_back(std::move(o));
    }
    // Output 1: change back to self (OP_1 <my_xonly>) — only if non-dust.
    if (change_sat > 546) {
        CTxOut o;
        o.nValue = change_sat;
        o.scriptPubKey = CScript() << OP_1
            << std::vector<unsigned char>(id->xonly.begin(), id->xonly.end());
        mtx.vout.push_back(std::move(o));
    } else if (change_sat > 0) {
        // Below dust — fold into fee. Don't emit the output.
    }

    // Compute BIP341 sighash. We need to tell the verifier about
    // the spent input's value + scriptPubKey (BIP341 commits to both).
    CTxOut spent;
    spent.nValue = picked->value_sat;
    spent.scriptPubKey = CScript() << OP_1
        << std::vector<unsigned char>(id->xonly.begin(), id->xonly.end());
    std::vector<CTxOut> spent_outputs{spent};
    PrecomputedTransactionData txdata;
    txdata.Init(mtx, std::move(spent_outputs), /*force=*/true);
    if (!txdata.m_bip341_taproot_ready) {
        return util::Error{Untranslated("BIP341 sighash precompute failed")};
    }
    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;
    uint256 sighash;
    if (!SignatureHashSchnorr(sighash, execdata, mtx, /*in_pos=*/0,
            SIGHASH_DEFAULT, SigVersion::TAPROOT, txdata,
            MissingDataBehavior::FAIL)) {
        return util::Error{Untranslated("SignatureHashSchnorr failed")};
    }
    // Sign. merkle_root = nullptr → key-path-spend with no script tree
    // (the signing key is taproot-tweaked with H(P) per BIP341 rules
    // that CKey::SignSchnorr handles internally).
    std::vector<unsigned char> sig(64);
    uint256 aux_rand;
    GetStrongRandBytes(aux_rand);
    if (!id->priv.SignSchnorr(sighash,
            std::span<unsigned char>{sig.data(), sig.size()},
            /*merkle_root=*/nullptr, aux_rand)) {
        return util::Error{Untranslated("SignSchnorr failed")};
    }
    mtx.vin[0].scriptWitness.stack.clear();
    mtx.vin[0].scriptWitness.stack.emplace_back(sig.begin(), sig.end());

    // Serialize + broadcast.
    DataStream ds;
    ds << TX_WITH_WITNESS(CTransaction{mtx});
    const std::string tx_hex = HexStr(std::span<const unsigned char>{
        UCharCast(ds.data()), ds.size()});
    try {
        return backend->Broadcast(tx_hex);
    } catch (const std::exception& e) {
        return util::Error{Untranslated(std::string("broadcast failed: ") + e.what())};
    }
}

util::Result<std::string> BuildAndBroadcastSweepTx(
    ::wallet::CWallet& wallet,
    const std::string& chain,
    const std::string& dest_address,
    int64_t fee_sat)
{
    if (fee_sat < 0) return util::Error{Untranslated("fee must be non-negative")};
    const ChainParams* cp = GetChainParams(chain);
    if (!cp) return util::Error{Untranslated("unknown chain")};
    auto id = GetOrCreateIdentity(wallet, chain);
    if (!id) return util::Error{util::ErrorString(id)};
    auto backend = ::wallet::pricoin_chain_watcher::MakeForeignClientFromRegistry(chain);
    if (!backend) {
        return util::Error{Untranslated("no chain backend registered for " + chain)};
    }

    // Destination must be a bech32(m) of the same chain. We build
    // its scriptPubKey from the decoded (witness_v, program). Both
    // P2TR (v1) and P2WPKH (v0) destinations work.
    int dest_v = -1;
    std::vector<unsigned char> dest_program;
    if (!DecodeWitnessAddress(dest_address, cp->hrp, dest_v, dest_program)) {
        return util::Error{Untranslated(
            "destination address not a valid bech32(m) for chain " + chain)};
    }

    std::vector<::wallet::pricoin_chain_watcher::IForeignChainClient::Utxo> utxos;
    try { utxos = backend->GetAddressUtxos(id->address); }
    catch (const std::exception& e) {
        return util::Error{Untranslated(std::string("UTXO query failed: ") + e.what())};
    }
    if (utxos.empty()) {
        return util::Error{Untranslated("no UTXOs to sweep")};
    }
    int64_t total_in = 0;
    for (const auto& u : utxos) total_in += u.value_sat;
    const int64_t output_sat = total_in - fee_sat;
    if (output_sat <= 0) {
        return util::Error{Untranslated("fee exceeds total balance")};
    }

    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.nLockTime = 0;
    for (const auto& u : utxos) {
        auto tid = uint256::FromHex(u.txid);
        if (!tid) {
            return util::Error{Untranslated("backend returned unparseable UTXO txid")};
        }
        CTxIn in;
        in.prevout = COutPoint{Txid::FromUint256(*tid),
                                static_cast<uint32_t>(u.vout)};
        in.nSequence = 0xfffffffe;
        mtx.vin.push_back(std::move(in));
    }
    {
        CTxOut o;
        o.nValue = output_sat;
        o.scriptPubKey = MakeWitnessSPK(dest_v, dest_program);
        mtx.vout.push_back(std::move(o));
    }

    // ─── Per-input signing — chain-specific ──────────────────
    if (cp->witness_v == 1) {
        // BTC P2TR: BIP341 + Schnorr key-path-spend.
        std::vector<CTxOut> spent_outputs;
        spent_outputs.reserve(utxos.size());
        for (const auto& u : utxos) {
            CTxOut s;
            s.nValue = u.value_sat;
            s.scriptPubKey = CScript() << OP_1
                << std::vector<unsigned char>(id->xonly.begin(), id->xonly.end());
            spent_outputs.push_back(std::move(s));
        }
        PrecomputedTransactionData txdata;
        txdata.Init(mtx, std::move(spent_outputs), /*force=*/true);
        if (!txdata.m_bip341_taproot_ready) {
            return util::Error{Untranslated("BIP341 sighash precompute failed")};
        }
        for (size_t i = 0; i < mtx.vin.size(); ++i) {
            ScriptExecutionData execdata;
            execdata.m_annex_init = true;
            execdata.m_annex_present = false;
            uint256 sighash;
            if (!SignatureHashSchnorr(sighash, execdata, mtx,
                    static_cast<uint32_t>(i), SIGHASH_DEFAULT,
                    SigVersion::TAPROOT, txdata, MissingDataBehavior::FAIL)) {
                return util::Error{Untranslated(strprintf(
                    "SignatureHashSchnorr failed at input %u", i))};
            }
            std::vector<unsigned char> sig(64);
            uint256 aux_rand;
            GetStrongRandBytes(aux_rand);
            if (!id->priv.SignSchnorr(sighash,
                    std::span<unsigned char>{sig.data(), sig.size()},
                    /*merkle_root=*/nullptr, aux_rand)) {
                return util::Error{Untranslated("SignSchnorr failed")};
            }
            mtx.vin[i].scriptWitness.stack.clear();
            mtx.vin[i].scriptWitness.stack.emplace_back(sig.begin(), sig.end());
        }
    } else if (cp->witness_v == 0) {
        // LTC P2WPKH: BIP143 + ECDSA. The scriptCode for sighash is
        // the P2PKH equivalent — `OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY
        // OP_CHECKSIG` — per BIP143's "P2WPKH compatibility" rule.
        // Witness stack is [sig+sighash_byte, compressed_pubkey].
        const CKeyID my_keyid = id->pub.GetID();
        const CScript scriptCode = CScript()
            << OP_DUP << OP_HASH160
            << std::vector<unsigned char>(my_keyid.begin(), my_keyid.end())
            << OP_EQUALVERIFY << OP_CHECKSIG;
        // BIP143 sighash needs a precompute (hashes of prevouts /
        // sequences / outputs).
        std::vector<CTxOut> spent_outputs;
        spent_outputs.reserve(utxos.size());
        for (const auto& u : utxos) {
            CTxOut s;
            s.nValue = u.value_sat;
            s.scriptPubKey = CScript() << OP_0
                << std::vector<unsigned char>(my_keyid.begin(), my_keyid.end());
            spent_outputs.push_back(std::move(s));
        }
        PrecomputedTransactionData txdata;
        txdata.Init(mtx, std::move(spent_outputs), /*force=*/true);

        for (size_t i = 0; i < mtx.vin.size(); ++i) {
            const uint256 sighash = SignatureHash(
                scriptCode, mtx, static_cast<unsigned int>(i),
                SIGHASH_ALL, utxos[i].value_sat,
                SigVersion::WITNESS_V0, &txdata);
            std::vector<unsigned char> ecdsa_sig;
            if (!id->priv.Sign(sighash, ecdsa_sig)) {
                return util::Error{Untranslated("ECDSA sign failed")};
            }
            ecdsa_sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));
            mtx.vin[i].scriptWitness.stack.clear();
            mtx.vin[i].scriptWitness.stack.emplace_back(
                ecdsa_sig.begin(), ecdsa_sig.end());
            mtx.vin[i].scriptWitness.stack.emplace_back(
                id->pub.begin(), id->pub.end());
        }
    } else {
        return util::Error{Untranslated("unsupported witness version for chain")};
    }

    DataStream ds;
    ds << TX_WITH_WITNESS(CTransaction{mtx});
    const std::string tx_hex = HexStr(std::span<const unsigned char>{
        UCharCast(ds.data()), ds.size()});
    try {
        return backend->Broadcast(tx_hex);
    } catch (const std::exception& e) {
        return util::Error{Untranslated(std::string("broadcast failed: ") + e.what())};
    }
}

util::Result<std::string> BuildAndBroadcastHtlcFundingTx(
    ::wallet::CWallet& wallet,
    const std::string& chain,
    const CScript& htlc_redeem_script,
    int64_t amount_sat,
    int64_t fee_sat)
{
    if (chain != "ltc") {
        // BTC swaps don't use HTLCs (they go through MuSig2 +
        // Schnorr-adaptor over P2TR). Other non-Taproot chains
        // (DOGE, BCH) could reuse this path in the future.
        return util::Error{Untranslated(
            "HTLC funding builder is for LTC; BTC funding goes through "
            "BuildAndBroadcastFundingTx (MuSig2 P2TR)")};
    }
    if (amount_sat <= 0 || fee_sat < 0) {
        return util::Error{Untranslated("amount must be positive, fee non-negative")};
    }
    if (htlc_redeem_script.empty()) {
        return util::Error{Untranslated("htlc_redeem_script empty")};
    }
    auto id = GetOrCreateIdentity(wallet, chain);
    if (!id) return util::Error{util::ErrorString(id)};
    auto backend = ::wallet::pricoin_chain_watcher::MakeForeignClientFromRegistry(chain);
    if (!backend) {
        return util::Error{Untranslated("no chain backend registered for " + chain)};
    }
    std::vector<::wallet::pricoin_chain_watcher::IForeignChainClient::Utxo> utxos;
    try {
        utxos = backend->GetAddressUtxos(id->address);
    } catch (const std::exception& e) {
        return util::Error{Untranslated(std::string("UTXO query failed: ") + e.what())};
    }
    // Pick the smallest confirmed UTXO ≥ amount + fee (greedy, mirrors
    // the BTC builder).
    const int64_t target = amount_sat + fee_sat;
    const ::wallet::pricoin_chain_watcher::IForeignChainClient::Utxo* picked = nullptr;
    for (const auto& u : utxos) {
        if (!u.confirmed) continue;
        if (u.value_sat < target) continue;
        if (!picked || u.value_sat < picked->value_sat) picked = &u;
    }
    if (!picked) {
        return util::Error{Untranslated(strprintf(
            "no confirmed LTC UTXO ≥ amount+fee (%d sat); deposit LTC at %s first",
            target, id->address))};
    }
    auto picked_txid = uint256::FromHex(picked->txid);
    if (!picked_txid) {
        return util::Error{Untranslated("backend returned unparseable UTXO txid")};
    }
    const int64_t change_sat = picked->value_sat - target;

    // ─── Build tx skeleton ───────────────────────────────
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.nLockTime = 0;
    {
        CTxIn in;
        in.prevout = COutPoint{Txid::FromUint256(*picked_txid),
                                static_cast<uint32_t>(picked->vout)};
        in.nSequence = 0xfffffffe;
        mtx.vin.push_back(std::move(in));
    }
    // vout[0]: HTLC P2WSH = OP_0 <SHA256(redeem_script)>.
    {
        CSHA256 h;
        h.Write(htlc_redeem_script.data(), htlc_redeem_script.size());
        std::array<unsigned char, 32> redeem_hash{};
        h.Finalize(redeem_hash.data());
        CTxOut o;
        o.nValue = amount_sat;
        o.scriptPubKey = CScript() << OP_0
            << std::vector<unsigned char>(redeem_hash.begin(), redeem_hash.end());
        mtx.vout.push_back(std::move(o));
    }
    // vout[1]: change to self P2WPKH (OP_0 <HASH160(pub)>) — only if non-dust.
    const CKeyID my_keyid = id->pub.GetID();
    if (change_sat > 546) {
        CTxOut o;
        o.nValue = change_sat;
        o.scriptPubKey = CScript() << OP_0
            << std::vector<unsigned char>(my_keyid.begin(), my_keyid.end());
        mtx.vout.push_back(std::move(o));
    }

    // ─── BIP143 sighash + ECDSA sign ─────────────────────
    // P2WPKH spending: scriptCode is the P2PKH equivalent.
    const CScript scriptCode = CScript()
        << OP_DUP << OP_HASH160
        << std::vector<unsigned char>(my_keyid.begin(), my_keyid.end())
        << OP_EQUALVERIFY << OP_CHECKSIG;
    std::vector<CTxOut> spent_outputs;
    {
        CTxOut s;
        s.nValue = picked->value_sat;
        s.scriptPubKey = CScript() << OP_0
            << std::vector<unsigned char>(my_keyid.begin(), my_keyid.end());
        spent_outputs.push_back(std::move(s));
    }
    PrecomputedTransactionData txdata;
    txdata.Init(mtx, std::move(spent_outputs), /*force=*/true);

    const uint256 sighash = SignatureHash(
        scriptCode, mtx, /*nIn=*/0, SIGHASH_ALL,
        /*amount=*/picked->value_sat, SigVersion::WITNESS_V0, &txdata);
    std::vector<unsigned char> ecdsa_sig;
    if (!id->priv.Sign(sighash, ecdsa_sig)) {
        return util::Error{Untranslated("ECDSA sign failed")};
    }
    ecdsa_sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));
    mtx.vin[0].scriptWitness.stack.clear();
    mtx.vin[0].scriptWitness.stack.emplace_back(ecdsa_sig.begin(), ecdsa_sig.end());
    mtx.vin[0].scriptWitness.stack.emplace_back(id->pub.begin(), id->pub.end());

    DataStream ds;
    ds << TX_WITH_WITNESS(CTransaction{mtx});
    const std::string tx_hex = HexStr(std::span<const unsigned char>{
        UCharCast(ds.data()), ds.size()});
    try {
        return backend->Broadcast(tx_hex);
    } catch (const std::exception& e) {
        return util::Error{Untranslated(std::string("broadcast failed: ") + e.what())};
    }
}

void Shutdown()
{
    LOCK(g_mutex);
    g_identities.clear();
}

} // namespace wallet::pricoin_btc_holding
