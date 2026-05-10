// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pricoin_swap_refund.h>

#include <consensus/amount.h>
#include <core_io.h>
#include <crypto/hmac_sha256.h>
#include <interfaces/chain.h>
#include <key.h>
#include <node/types.h>
#include <pricoin/ringsig.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>
#include <streams.h>
#include <swap/btc_htlc.h>
#include <util/strencodings.h>
#include <wallet/pricoin_adaptor_swap.h>
#include <wallet/pricoin_btc_holding.h>
#include <wallet/pricoin_chain_watcher.h>
#include <wallet/pricoin_stealth.h>
#include <wallet/wallet.h>

#include <cstring>
#include <span>

namespace wallet::pricoin_swap_refund {

namespace aas  = ::wallet::pricoin_adaptor_swap;
namespace pcw  = ::wallet::pricoin_chain_watcher;
namespace bhtlc = ::pricoin::swap::btc_htlc;
namespace pbh  = ::wallet::pricoin_btc_holding;

namespace {

// Mirrors the swap-identity priv derivation used by
// PrepareLtcSwapContext in src/wallet/rpc/pricoin_ct.cpp. Same HMAC
// chain so both paths yield the same key.
bool DeriveSwapIdentityPriv(::wallet::CWallet& wallet, CKey& priv_out)
{
    const auto& stealth_id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
    constexpr const char* kSwapTag = "pricoin/swap/identity-v1";
    for (uint8_t counter = 0; counter < 16; ++counter) {
        CHMAC_SHA256 hmac(UCharCast(stealth_id.spend.data()), 32);
        hmac.Write(reinterpret_cast<const unsigned char*>(kSwapTag),
                   std::strlen(kSwapTag));
        hmac.Write(&counter, 1);
        unsigned char raw[32];
        hmac.Finalize(raw);
        priv_out.Set(raw, raw + 32, /*compressed=*/true);
        if (priv_out.IsValid()) return true;
    }
    return false;
}

}  // namespace

LtcRefundResult AutoBroadcastLtcRefund(
    ::wallet::CWallet& wallet,
    const uint256& swap_id,
    const std::string& dest_bech32,
    int64_t fee_sat)
{
    LtcRefundResult r;

    aas::AdaptorSwap snap;
    if (aas::Get(wallet, swap_id, snap) != aas::LookupResult::Ok) {
        r.error = "swap not found";
        return r;
    }
    if (snap.foreign_chain != "ltc") {
        r.error = "swap.foreign_chain != ltc";
        return r;
    }
    if (snap.role != aas::Role::Bob) {
        r.error = "LTC HTLC refund is performed by Bob (the LTC seller)";
        return r;
    }
    if (!snap.adaptor_set) {
        r.error = "adaptor materials (T_G) not set on swap";
        return r;
    }
    if (!snap.timelocks_set || snap.foreign_refund_height <= 0) {
        r.error = "foreign refund timelock not set on swap";
        return r;
    }
    if (snap.foreign_funding_txid.empty() || snap.foreign_funding_vout < 0) {
        r.error = "swap has no recorded LTC HTLC funding outpoint";
        return r;
    }
    if (!snap.foreign_refund_txid.empty()) {
        r.error = "swap already has a foreign_refund_txid recorded";
        return r;
    }

    if (wallet.HasEncryptionKeys() && wallet.IsLocked()) {
        r.error = "wallet locked — cannot derive swap-identity priv";
        return r;
    }

    CKey swap_priv;
    if (!DeriveSwapIdentityPriv(wallet, swap_priv)) {
        r.error = "swap-identity priv derivation failed";
        return r;
    }
    const CPubKey my_pub = swap_priv.GetPubKey();
    const CPubKey peer_pub(snap.counterparty_pub);
    // Bob's role: alice = peer, bob = me.
    const CPubKey alice_pub = peer_pub;
    const CPubKey bob_pub   = my_pub;

    CScript redeem;
    try {
        redeem = bhtlc::BuildDLHTLCScript(
            std::span<const unsigned char>(snap.T_G.data(), 33),
            alice_pub, bob_pub, snap.foreign_refund_height);
    } catch (const bhtlc::HTLCError& e) {
        r.error = std::string("HTLC script reconstruct failed: ") + e.what();
        return r;
    }

    int v = -1;
    std::vector<unsigned char> prog;
    if (!pbh::DecodeWitnessAddress(dest_bech32, "ltc", v, prog)) {
        r.error = "dest is not a valid LTC bech32(m) address";
        return r;
    }
    const CScript dest_spk = pbh::MakeWitnessSPK(v, prog);

    bhtlc::HTLCFunding f;
    auto ftxid = uint256::FromHex(snap.foreign_funding_txid);
    if (!ftxid) {
        r.error = "swap.foreign_funding_txid unparseable";
        return r;
    }
    f.prev_txid     = *ftxid;
    f.prev_vout     = static_cast<uint32_t>(snap.foreign_funding_vout);
    f.prev_value    = snap.foreign_amount_sat;
    f.redeem_script = redeem;

    std::vector<unsigned char> tx_bytes;
    try {
        tx_bytes = bhtlc::BuildRefundTx(
            f, snap.foreign_refund_height, swap_priv, dest_spk, fee_sat);
    } catch (const bhtlc::HTLCError& e) {
        r.error = std::string("HTLC refund build failed: ") + e.what();
        return r;
    }

    auto backend = pcw::MakeForeignClientFromRegistry("ltc");
    if (!backend) {
        r.error = "no LTC chain backend registered";
        return r;
    }
    const std::string tx_hex = HexStr(tx_bytes);
    std::string txid;
    try {
        txid = backend->Broadcast(tx_hex);
    } catch (const std::exception& e) {
        r.error = std::string("LTC broadcast failed: ") + e.what();
        return r;
    }

    pcw::WatchEntry we;
    we.swap_id = swap_id;
    we.kind = pcw::WatchKind::ForeignRefund;
    we.txid_hex = txid;
    we.vout = 0;
    we.min_confirmations = 1;
    (void)pcw::Add(wallet, we);

    r.ok = true;
    r.txid = std::move(txid);
    return r;
}

PricRefundResult AutoBroadcastPricRefund(
    ::wallet::CWallet& wallet,
    const uint256& swap_id)
{
    PricRefundResult r;

    aas::AdaptorSwap snap;
    if (aas::Get(wallet, swap_id, snap) != aas::LookupResult::Ok) {
        r.error = "swap not found";
        return r;
    }
    // State must be at least PreSigned (the cooperative refund sig
    // is produced during PreSigned), and not already terminal.
    if (snap.state != aas::State::PreSigned
        && snap.state != aas::State::PricClaimed
        && snap.state != aas::State::BothFunded) {
        // BothFunded only valid if both legs of presigs are present
        // (i.e., the ceremony completed but state-machine wasn't
        // advanced — defensive). In practice we expect PreSigned+.
        r.error = "swap state is not eligible for PRIC presigned refund";
        return r;
    }
    if (!snap.pric_refund_txid.IsNull()) {
        r.error = "swap already has a pric_refund_txid recorded";
        return r;
    }
    if (snap.pric_refund_unsigned_tx_hex.empty()) {
        r.error = "no unsigned PRIC refund tx persisted on swap (buildtx step "
                  "did not complete on this wallet)";
        return r;
    }
    if (snap.presigs.pric_refund_sig_blob.empty()) {
        r.error = "no PRIC refund cooperative signature available — "
                  "ceremony incomplete";
        return r;
    }

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, snap.pric_refund_unsigned_tx_hex,
                     /*try_no_witness=*/true, /*try_witness=*/true)) {
        r.error = "stored unsigned tx hex failed to decode";
        return r;
    }
    if (mtx.version != PRICOIN_CT_VERSION) {
        r.error = "stored tx is not a v4 confidential tx";
        return r;
    }
    if (mtx.ct_bundle.ring_inputs.size() != 1) {
        r.error = "stored tx must have exactly one ring input "
                  "(joint-spend convention)";
        return r;
    }
    DataStream ds{std::span<const unsigned char>{
        snap.presigs.pric_refund_sig_blob}};
    pricoin::ringsig::Signature sig;
    try {
        ds >> sig;
    } catch (const std::exception& e) {
        r.error = std::string("refund signature deserialise failed: ") + e.what();
        return r;
    }
    mtx.ct_bundle.ring_inputs[0].sig = std::move(sig);

    CTransactionRef tx_ref = MakeTransactionRef(std::move(mtx));
    std::string err_str;
    if (!wallet.chain().broadcastTransaction(
            tx_ref, MAX_MONEY,
            ::node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL,
            err_str)) {
        r.error = "broadcast failed: " + err_str;
        return r;
    }
    const std::string txid = tx_ref->GetHash().ToString();

    pcw::WatchEntry we;
    we.swap_id = swap_id;
    we.kind = pcw::WatchKind::PricRefund;
    we.txid_hex = txid;
    we.vout = -1;  // refund tx; we care about confirmation, not vout
    we.min_confirmations = 1;
    (void)pcw::Add(wallet, we);

    r.ok = true;
    r.txid = txid;
    return r;
}

}  // namespace wallet::pricoin_swap_refund
