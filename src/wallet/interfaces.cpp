// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <interfaces/wallet.h>

#include <algorithm>
#include <common/args.h>
#include <crypto/hmac_sha256.h>
#include <consensus/amount.h>
#include <interfaces/chain.h>
#include <interfaces/handler.h>
#include <node/types.h>
#include <policy/fees/block_policy_estimator.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <scheduler.h>
#include <support/allocators/secure.h>
#include <sync.h>
#include <uint256.h>
#include <util/check.h>
#include <util/translation.h>
#include <util/ui_change_type.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/feebumper.h>
#include <wallet/fees.h>
#include <wallet/load.h>
#include <wallet/pricoin_adaptor_swap.h>
#include <wallet/pricoin_ct_send.h>
#include <wallet/pricoin_offer.h>
#include <wallet/pricoin_stealth.h>
#include <wallet/receive.h>
#include <wallet/rpc/wallet.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>
#include <pricoin/stealth.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

using common::PSBTError;
using interfaces::Chain;
using interfaces::FoundBlock;
using interfaces::Handler;
using interfaces::MakeSignalHandler;
using interfaces::Wallet;
using interfaces::WalletAddress;
using interfaces::WalletBalances;
using interfaces::WalletLoader;
using interfaces::WalletMigrationResult;
using interfaces::WalletOrderForm;
using interfaces::WalletTx;
using interfaces::WalletTxOut;
using interfaces::WalletTxStatus;
using interfaces::WalletValueMap;

namespace wallet {
// All members of the classes in this namespace are intentionally public, as the
// classes themselves are private.
namespace {
//! Construct wallet tx struct.
WalletTx MakeWalletTx(CWallet& wallet, const CWalletTx& wtx)
{
    LOCK(wallet.cs_wallet);
    WalletTx result;
    result.tx = wtx.tx;
    result.txin_is_mine.reserve(wtx.tx->vin.size());
    for (const auto& txin : wtx.tx->vin) {
        result.txin_is_mine.emplace_back(InputIsMine(wallet, txin));
    }
    result.txout_is_mine.reserve(wtx.tx->vout.size());
    result.txout_address.reserve(wtx.tx->vout.size());
    result.txout_address_is_mine.reserve(wtx.tx->vout.size());
    for (const auto& txout : wtx.tx->vout) {
        result.txout_is_mine.emplace_back(wallet.IsMine(txout));
        result.txout_is_change.push_back(OutputIsChange(wallet, txout));
        result.txout_address.emplace_back();
        result.txout_address_is_mine.emplace_back(ExtractDestination(txout.scriptPubKey, result.txout_address.back()) ?
                                                      wallet.IsMine(result.txout_address.back()) :
                                                      false);
    }
    result.credit = CachedTxGetCredit(wallet, wtx, /*avoid_reuse=*/true);
    result.debit = CachedTxGetDebit(wallet, wtx, /*avoid_reuse=*/true);
    result.change = CachedTxGetChange(wallet, wtx);
    result.time = wtx.GetTxTime();
    result.value_map = wtx.mapValue;
    result.is_coinbase = wtx.IsCoinBase();
    return result;
}

//! Construct wallet tx status struct.
WalletTxStatus MakeWalletTxStatus(const CWallet& wallet, const CWalletTx& wtx)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);

    WalletTxStatus result;
    result.block_height =
        wtx.state<TxStateConfirmed>() ? wtx.state<TxStateConfirmed>()->confirmed_block_height :
        wtx.state<TxStateBlockConflicted>() ? wtx.state<TxStateBlockConflicted>()->conflicting_block_height :
        std::numeric_limits<int>::max();
    result.blocks_to_maturity = wallet.GetTxBlocksToMaturity(wtx);
    result.depth_in_main_chain = wallet.GetTxDepthInMainChain(wtx);
    result.time_received = wtx.nTimeReceived;
    result.lock_time = wtx.tx->nLockTime;
    result.is_trusted = CachedTxIsTrusted(wallet, wtx);
    result.is_abandoned = wtx.isAbandoned();
    result.is_coinbase = wtx.IsCoinBase();
    result.is_in_main_chain = wtx.isConfirmed();
    return result;
}

//! Construct wallet TxOut struct.
WalletTxOut MakeWalletTxOut(const CWallet& wallet,
    const CWalletTx& wtx,
    int n,
    int depth) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    WalletTxOut result;
    result.txout = wtx.tx->vout[n];
    result.time = wtx.GetTxTime();
    result.depth_in_main_chain = depth;
    result.is_spent = wallet.IsSpent(COutPoint(wtx.GetHash(), n));
    return result;
}

WalletTxOut MakeWalletTxOut(const CWallet& wallet,
    const COutput& output) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    WalletTxOut result;
    result.txout = output.txout;
    result.time = output.time;
    result.depth_in_main_chain = output.depth;
    result.is_spent = wallet.IsSpent(output.outpoint);
    return result;
}

class WalletImpl : public Wallet
{
public:
    explicit WalletImpl(WalletContext& context, const std::shared_ptr<CWallet>& wallet) : m_context(context), m_wallet(wallet) {}

    bool encryptWallet(const SecureString& wallet_passphrase) override
    {
        return m_wallet->EncryptWallet(wallet_passphrase);
    }
    bool isCrypted() override { return m_wallet->HasEncryptionKeys(); }
    bool lock() override { return m_wallet->Lock(); }
    bool unlock(const SecureString& wallet_passphrase) override { return m_wallet->Unlock(wallet_passphrase); }
    bool isLocked() override { return m_wallet->IsLocked(); }
    bool changeWalletPassphrase(const SecureString& old_wallet_passphrase,
        const SecureString& new_wallet_passphrase) override
    {
        return m_wallet->ChangeWalletPassphrase(old_wallet_passphrase, new_wallet_passphrase);
    }
    void abortRescan() override { m_wallet->AbortRescan(); }
    bool backupWallet(const std::string& filename) override { return m_wallet->BackupWallet(filename); }
    std::string getWalletName() override { return m_wallet->GetName(); }
    std::string getStealthAddress() override
    {
        try {
            const auto& id = ::wallet::pricoin_stealth::GetOrCreate(*m_wallet);
            return ::pricoin::stealth::Encode(id.public_address);
        } catch (...) {
            return {};
        }
    }
    util::Result<uint256> sendConfidential(
        const std::string& dest_stealth_address,
        CAmount amount,
        CAmount fee) override
    {
        return ::wallet::SendConfidentialTx(*m_wallet, dest_stealth_address, amount, fee);
    }
    CAmount confidentialBalance() override
    {
        try {
            return ::wallet::ConfidentialBalance(*m_wallet);
        } catch (...) {
            return 0;
        }
    }

    // ────── Phase-6 orderbook ──────
private:
    static const char* OfferOriginStr(::wallet::pricoin_offer::Origin o) {
        return o == ::wallet::pricoin_offer::Origin::Local ? "local" : "imported";
    }
    static const char* OfferSideStr(::wallet::pricoin_offer::Side s) {
        return s == ::wallet::pricoin_offer::Side::BuyPric ? "buy_pric" : "sell_pric";
    }
    static const char* OfferChainStr(::wallet::pricoin_offer::ForeignChain c) {
        return c == ::wallet::pricoin_offer::ForeignChain::Btc ? "btc" : "ltc";
    }
    static const char* OfferStatusStr(::wallet::pricoin_offer::Status s) {
        using S = ::wallet::pricoin_offer::Status;
        switch (s) {
            case S::Active:    return "active";
            case S::Matched:   return "matched";
            case S::Filled:    return "filled";
            case S::Cancelled: return "cancelled";
            case S::Expired:   return "expired";
        }
        return "unknown";
    }

    static PricoinOfferSnapshot ToSnapshot(const ::wallet::pricoin_offer::Order& o) {
        PricoinOfferSnapshot s;
        s.order_id = o.payload.order_id.ToString();
        s.origin = OfferOriginStr(o.origin);
        s.side = OfferSideStr(o.payload.side);
        s.foreign_chain = OfferChainStr(o.payload.foreign_chain);
        s.max_pric_amount_sat = o.payload.max_pric_amount_sat;
        s.foreign_amount_at_max_sat = o.payload.foreign_amount_at_max_sat;
        s.expiry_unix_sec = o.payload.expiry_unix_sec;
        s.maker_pubkey_hex = HexStr(o.payload.maker_pubkey);
        s.status = OfferStatusStr(o.status);
        s.pric_remaining_sat = o.pric_remaining_sat;
        s.pric_in_flight_sat = o.pric_in_flight_sat;
        if (!o.matched_with_order_id.IsNull()) {
            s.matched_with_order_id = o.matched_with_order_id.ToString();
        }
        s.notes = o.notes;
        s.created_time = o.created_time;
        s.updated_time = o.updated_time;
        return s;
    }

    static std::optional<uint256> ParseOid(const std::string& s) {
        return uint256::FromHex(s);
    }

    static ::wallet::pricoin_offer::Side ParseSide(const std::string& s) {
        if (s == "buy_pric")  return ::wallet::pricoin_offer::Side::BuyPric;
        return ::wallet::pricoin_offer::Side::SellPric;
    }
    static ::wallet::pricoin_offer::ForeignChain ParseChain(const std::string& s) {
        if (s == "ltc") return ::wallet::pricoin_offer::ForeignChain::Ltc;
        return ::wallet::pricoin_offer::ForeignChain::Btc;
    }

public:
    PricoinOfferCreateResult offerCreate(const PricoinOfferCreateParams& p) override {
        PricoinOfferCreateResult r;
        ::wallet::pricoin_offer::CreateParams cp;
        if (p.side != "buy_pric" && p.side != "sell_pric") {
            r.error = "side must be \"buy_pric\" or \"sell_pric\"";
            return r;
        }
        if (p.foreign_chain != "btc" && p.foreign_chain != "ltc") {
            r.error = "foreign_chain must be \"btc\" or \"ltc\"";
            return r;
        }
        cp.side = ParseSide(p.side);
        cp.foreign_chain = ParseChain(p.foreign_chain);
        cp.max_pric_amount_sat = p.max_pric_amount_sat;
        cp.foreign_amount_at_max_sat = p.foreign_amount_at_max_sat;
        cp.expiry_unix_sec = p.expiry_unix_sec;
        cp.notes = p.notes;
        ::wallet::pricoin_offer::Order o;
        auto cr = ::wallet::pricoin_offer::Create(*m_wallet, cp, o);
        using CR = ::wallet::pricoin_offer::CreateResult;
        switch (cr) {
        case CR::Ok:
            r.ok = true;
            r.record = ToSnapshot(o);
            r.uri = ::wallet::pricoin_offer::EncodeUri(o.payload);
            return r;
        case CR::InvalidInput:     r.error = "amounts and expiry must be > 0"; return r;
        case CR::Locked:           r.error = "wallet locked"; return r;
        case CR::DerivationFailed: r.error = "swap-identity priv unavailable"; return r;
        case CR::WriteFailed:      r.error = "wallet write failed"; return r;
        }
        return r;
    }

    util::Result<PricoinOfferSnapshot> offerImport(const std::string& uri) override {
        ::wallet::pricoin_offer::Order o;
        auto ir = ::wallet::pricoin_offer::Import(*m_wallet, uri, o);
        using IR = ::wallet::pricoin_offer::ImportResult;
        switch (ir) {
        case IR::Ok:                return ToSnapshot(o);
        case IR::InvalidUri:        return util::Error{Untranslated("URI did not parse as a pricoffer:v1 envelope")};
        case IR::InvalidSignature:  return util::Error{Untranslated("offer signature does not verify")};
        case IR::Duplicate:         return util::Error{Untranslated("an order with this id is already in the wallet")};
        case IR::AlreadyExpired:    return util::Error{Untranslated("offer expiry has already passed")};
        case IR::Locked:            return util::Error{Untranslated("wallet locked")};
        case IR::WriteFailed:       return util::Error{Untranslated("wallet write failed")};
        }
        return util::Error{Untranslated("unknown import error")};
    }

    std::vector<PricoinOfferSnapshot> offerList() override {
        std::vector<PricoinOfferSnapshot> out;
        std::vector<::wallet::pricoin_offer::Order> all;
        auto r = ::wallet::pricoin_offer::List(*m_wallet, all);
        if (r != ::wallet::pricoin_offer::LookupResult::Ok) return out;
        out.reserve(all.size());
        for (const auto& o : all) out.push_back(ToSnapshot(o));
        return out;
    }

    std::optional<PricoinOfferSnapshot> offerGet(const std::string& order_id) override {
        auto oid = ParseOid(order_id);
        if (!oid) return std::nullopt;
        ::wallet::pricoin_offer::Order o;
        auto r = ::wallet::pricoin_offer::Get(*m_wallet, *oid, o);
        if (r != ::wallet::pricoin_offer::LookupResult::Ok) return std::nullopt;
        return ToSnapshot(o);
    }

    std::string offerExportUri(const std::string& order_id) override {
        auto oid = ParseOid(order_id);
        if (!oid) return "";
        std::string uri;
        ::wallet::pricoin_offer::ExportUri(*m_wallet, *oid, uri);
        return uri;
    }

    util::Result<PricoinOfferSnapshot> offerCancel(const std::string& order_id) override {
        auto oid = ParseOid(order_id);
        if (!oid) return util::Error{Untranslated("order_id must be 32-byte hex")};
        auto r = ::wallet::pricoin_offer::Cancel(*m_wallet, *oid);
        if (r != ::wallet::pricoin_offer::MutateResult::Ok) {
            return util::Error{Untranslated("cancel rejected")};
        }
        ::wallet::pricoin_offer::Order o;
        ::wallet::pricoin_offer::Get(*m_wallet, *oid, o);
        return ToSnapshot(o);
    }

    util::Result<std::pair<PricoinOfferSnapshot, PricoinOfferSnapshot>>
    offerMatch(const std::string& my_order_id,
               const std::string& their_order_id,
               int64_t actual_pric_amount_sat) override {
        auto m = ParseOid(my_order_id);
        auto t = ParseOid(their_order_id);
        if (!m || !t) return util::Error{Untranslated("order ids must be 32-byte hex")};
        auto r = ::wallet::pricoin_offer::Match(*m_wallet, *m, *t, actual_pric_amount_sat);
        using MR = ::wallet::pricoin_offer::MutateResult;
        switch (r) {
        case MR::Ok: break;
        case MR::NotFound:        return util::Error{Untranslated("no order with that id")};
        case MR::InvalidState:    return util::Error{Untranslated("current state does not permit match")};
        case MR::InvalidInput:    return util::Error{Untranslated("invalid input")};
        case MR::PriceCrossFailed:return util::Error{Untranslated("orders do not price-cross")};
        case MR::Locked:          return util::Error{Untranslated("wallet locked")};
        case MR::WriteFailed:     return util::Error{Untranslated("wallet write failed")};
        }
        ::wallet::pricoin_offer::Order mo, to;
        ::wallet::pricoin_offer::Get(*m_wallet, *m, mo);
        ::wallet::pricoin_offer::Get(*m_wallet, *t, to);
        return std::make_pair(ToSnapshot(mo), ToSnapshot(to));
    }

    util::Result<PricoinOfferSnapshot> offerFill(const std::string& order_id) override {
        auto oid = ParseOid(order_id);
        if (!oid) return util::Error{Untranslated("bad order_id")};
        auto r = ::wallet::pricoin_offer::Fill(*m_wallet, *oid);
        if (r != ::wallet::pricoin_offer::MutateResult::Ok) {
            return util::Error{Untranslated("fill rejected (order not Matched, or in_flight invariant violated)")};
        }
        ::wallet::pricoin_offer::Order o;
        ::wallet::pricoin_offer::Get(*m_wallet, *oid, o);
        return ToSnapshot(o);
    }

    util::Result<PricoinOfferSnapshot> offerUnmatch(const std::string& order_id) override {
        auto oid = ParseOid(order_id);
        if (!oid) return util::Error{Untranslated("bad order_id")};
        auto r = ::wallet::pricoin_offer::Unmatch(*m_wallet, *oid);
        if (r != ::wallet::pricoin_offer::MutateResult::Ok) {
            return util::Error{Untranslated("unmatch rejected (order not Matched)")};
        }
        ::wallet::pricoin_offer::Order o;
        ::wallet::pricoin_offer::Get(*m_wallet, *oid, o);
        return ToSnapshot(o);
    }

    // ────── Phase-5/6 adaptor-swap orchestration ──────
    static const char* AdaptorSwapRoleStr(::wallet::pricoin_adaptor_swap::Role r) {
        return r == ::wallet::pricoin_adaptor_swap::Role::Alice ? "alice" : "bob";
    }
    static const char* AdaptorSwapStateStr(::wallet::pricoin_adaptor_swap::State s) {
        using S = ::wallet::pricoin_adaptor_swap::State;
        switch (s) {
        case S::Setup:        return "setup";
        case S::AdaptorReady: return "adaptor_ready";
        case S::BtcFunded:    return "btc_funded";
        case S::BothFunded:   return "both_funded";
        case S::PreSigned:    return "pre_signed";
        case S::PricClaimed:  return "pric_claimed";
        case S::Complete:     return "complete";
        case S::Refunded:     return "refunded";
        case S::Aborted:      return "aborted";
        }
        return "unknown";
    }

    static PricoinAdaptorSwapSnapshot ToSwapSnapshot(
        const ::wallet::pricoin_adaptor_swap::AdaptorSwap& s) {
        PricoinAdaptorSwapSnapshot o;
        o.swap_id = s.swap_id.ToString();
        o.role = AdaptorSwapRoleStr(s.role);
        o.state = AdaptorSwapStateStr(s.state);
        o.counterparty_pubkey_hex = HexStr(s.counterparty_pub);
        o.foreign_chain = s.foreign_chain;
        o.foreign_amount_sat = s.foreign_amount_sat;
        o.pric_joint_stealth_address = s.pric_joint_stealth_address;
        o.pric_amount_sat = s.pric_amount_sat;
        o.memo = s.memo;
        o.abort_reason = s.abort_reason;
        o.created_time = s.created_time;
        o.updated_time = s.updated_time;
        o.next_action = ::wallet::pricoin_adaptor_swap::NextActionHint(s);
        // Surface the on-record adaptor materials once they've been
        // set (T_G is all-zero before SetAdaptorMaterials).
        const bool has_adaptor = std::any_of(
            s.T_G.begin(), s.T_G.end(),
            [](unsigned char b) { return b != 0; });
        if (has_adaptor) {
            o.adaptor_T_G_hex = HexStr(s.T_G);
            o.adaptor_T_H_hex = HexStr(s.T_H);
            o.adaptor_dleq_blob_hex = HexStr(s.dleq_proof_blob);
        }
        o.foreign_funding_txid     = s.foreign_funding_txid;
        o.foreign_funding_vout     = s.foreign_funding_vout;
        o.foreign_funding_height   = s.foreign_funding_height;
        if (!s.pric_funding_txid.IsNull()) {
            o.pric_funding_txid_hex = s.pric_funding_txid.ToString();
        }
        o.pric_funding_vout        = s.pric_funding_vout;
        o.pric_funding_height      = s.pric_funding_height;
        o.pric_refund_height       = s.pric_refund_height;
        o.foreign_refund_height    = s.foreign_refund_height;
        o.delta_min_blocks         = s.delta_min_blocks;
        o.btc_alice_recipient_xonly_hex  = s.btc_alice_recipient_xonly_hex;
        o.btc_bob_recipient_xonly_hex    = s.btc_bob_recipient_xonly_hex;
        o.pric_alice_recipient_stealth   = s.pric_alice_recipient_stealth;
        o.pric_bob_recipient_stealth     = s.pric_bob_recipient_stealth;
        return o;
    }

    std::vector<PricoinAdaptorSwapSnapshot> adaptorSwapList() override {
        std::vector<PricoinAdaptorSwapSnapshot> out;
        std::vector<::wallet::pricoin_adaptor_swap::AdaptorSwap> all;
        auto r = ::wallet::pricoin_adaptor_swap::List(*m_wallet, all);
        if (r != ::wallet::pricoin_adaptor_swap::LookupResult::Ok) return out;
        out.reserve(all.size());
        for (const auto& s : all) out.push_back(ToSwapSnapshot(s));
        return out;
    }

    std::optional<PricoinAdaptorSwapSnapshot>
    adaptorSwapGet(const std::string& swap_id) override {
        auto sid = uint256::FromHex(swap_id);
        if (!sid) return std::nullopt;
        ::wallet::pricoin_adaptor_swap::AdaptorSwap s;
        auto r = ::wallet::pricoin_adaptor_swap::Get(*m_wallet, *sid, s);
        if (r != ::wallet::pricoin_adaptor_swap::LookupResult::Ok) return std::nullopt;
        return ToSwapSnapshot(s);
    }

    util::Result<PricoinAdaptorSwapSnapshot>
    adaptorSwapCreate(const PricoinAdaptorSwapCreateParams& p) override {
        const auto cp_bytes = TryParseHex<unsigned char>(p.counterparty_pubkey_hex);
        if (!cp_bytes || cp_bytes->size() != 33) {
            return util::Error{Untranslated("counterparty_pubkey must be 33-byte compressed hex")};
        }
        CPubKey cp(std::span<const unsigned char>(cp_bytes->data(), 33));
        if (!cp.IsValid() || !cp.IsCompressed()) {
            return util::Error{Untranslated("counterparty_pubkey not a valid compressed secp256k1 point")};
        }
        ::wallet::pricoin_adaptor_swap::Role role;
        if (p.role == "alice")    role = ::wallet::pricoin_adaptor_swap::Role::Alice;
        else if (p.role == "bob") role = ::wallet::pricoin_adaptor_swap::Role::Bob;
        else return util::Error{Untranslated("role must be \"alice\" or \"bob\"")};

        ::wallet::pricoin_adaptor_swap::AdaptorSwap s;
        auto r = ::wallet::pricoin_adaptor_swap::Create(
            *m_wallet, role, cp, p.foreign_chain, p.foreign_amount_sat,
            p.pric_joint_stealth_address, p.pric_amount_sat, p.memo,
            p.btc_alice_recipient_xonly_hex,
            p.btc_bob_recipient_xonly_hex,
            p.pric_alice_recipient_stealth,
            p.pric_bob_recipient_stealth, s);
        using CR = ::wallet::pricoin_adaptor_swap::CreateResult;
        switch (r) {
        case CR::Ok: return ToSwapSnapshot(s);
        case CR::InvalidCounterpartyPubkey:
            return util::Error{Untranslated("invalid counterparty pubkey")};
        case CR::InvalidForeignLeg:
            return util::Error{Untranslated("foreign chain must be btc/ltc/regtest and amount > 0")};
        case CR::InvalidPricLeg:
            return util::Error{Untranslated("pric_joint_stealth_address invalid or pric_amount <= 0")};
        case CR::Locked:        return util::Error{Untranslated("wallet locked")};
        case CR::WriteFailed:   return util::Error{Untranslated("wallet write failed")};
        }
        return util::Error{Untranslated("unknown create error")};
    }

    static util::Result<PricoinAdaptorSwapSnapshot> WrapTransition(
        ::wallet::pricoin_adaptor_swap::TransitionResult r,
        WalletImpl* self,
        const uint256& sid)
    {
        using TR = ::wallet::pricoin_adaptor_swap::TransitionResult;
        switch (r) {
        case TR::Ok: break;
        case TR::NotFound:        return util::Error{Untranslated("no swap with that id")};
        case TR::InvalidState:    return util::Error{Untranslated("current state does not permit this transition")};
        case TR::InvalidInput:    return util::Error{Untranslated("invalid input")};
        case TR::InvalidTimelocks:return util::Error{Untranslated("refund timelocks failed §6.2 step 7 validation (foreign > pric + delta_min_blocks)")};
        case TR::Locked:          return util::Error{Untranslated("wallet locked")};
        case TR::WriteFailed:     return util::Error{Untranslated("wallet write failed")};
        }
        ::wallet::pricoin_adaptor_swap::AdaptorSwap s;
        ::wallet::pricoin_adaptor_swap::Get(*self->m_wallet, sid, s);
        return ToSwapSnapshot(s);
    }

    util::Result<PricoinAdaptorSwapSnapshot> adaptorSwapSetAdaptorMaterials(
        const std::string& swap_id,
        const std::string& T_G_hex,
        const std::string& T_H_hex,
        const std::string& dleq_proof_blob_hex,
        const std::string& t_secret_hex) override
    {
        auto sid = uint256::FromHex(swap_id);
        if (!sid) return util::Error{Untranslated("swap_id must be 32-byte hex")};
        const auto T_G_bytes = TryParseHex<unsigned char>(T_G_hex);
        if (!T_G_bytes || T_G_bytes->size() != 33) {
            return util::Error{Untranslated("T_G must be 33-byte compressed pubkey hex")};
        }
        std::array<unsigned char, 33> T_G{};
        std::copy(T_G_bytes->begin(), T_G_bytes->end(), T_G.begin());
        const auto T_H_bytes = TryParseHex<unsigned char>(T_H_hex);
        if (!T_H_bytes || T_H_bytes->size() != 33) {
            return util::Error{Untranslated("T_H must be 33-byte compressed pubkey hex")};
        }
        std::array<unsigned char, 33> T_H{};
        std::copy(T_H_bytes->begin(), T_H_bytes->end(), T_H.begin());
        const auto dleq_bytes = TryParseHex<unsigned char>(dleq_proof_blob_hex);
        if (!dleq_bytes || dleq_bytes->empty()) {
            return util::Error{Untranslated("dleq_proof_blob must be non-empty hex")};
        }
        std::optional<std::array<unsigned char, 32>> t_secret;
        if (!t_secret_hex.empty()) {
            const auto t_bytes = TryParseHex<unsigned char>(t_secret_hex);
            if (!t_bytes || t_bytes->size() != 32) {
                return util::Error{Untranslated("t_secret must be 32-byte hex (or empty for Alice)")};
            }
            std::array<unsigned char, 32> t_arr{};
            std::copy(t_bytes->begin(), t_bytes->end(), t_arr.begin());
            t_secret = t_arr;
        }
        auto r = ::wallet::pricoin_adaptor_swap::SetAdaptorMaterials(
            *m_wallet, *sid, T_G, T_H, *dleq_bytes, t_secret);
        return WrapTransition(r, this, *sid);
    }

    util::Result<PricoinAdaptorSwapSnapshot> adaptorSwapSetRefundTimelocks(
        const std::string& swap_id,
        int32_t pric_refund_height,
        int32_t foreign_refund_height,
        int32_t delta_min_blocks) override
    {
        auto sid = uint256::FromHex(swap_id);
        if (!sid) return util::Error{Untranslated("swap_id must be 32-byte hex")};
        auto r = ::wallet::pricoin_adaptor_swap::SetRefundTimelocks(
            *m_wallet, *sid, pric_refund_height, foreign_refund_height, delta_min_blocks);
        return WrapTransition(r, this, *sid);
    }

    util::Result<PricoinAdaptorSwapSnapshot> adaptorSwapSetBtcFunded(
        const std::string& swap_id,
        const std::string& foreign_funding_txid,
        int32_t foreign_funding_vout,
        int32_t foreign_funding_height) override
    {
        auto sid = uint256::FromHex(swap_id);
        if (!sid) return util::Error{Untranslated("swap_id must be 32-byte hex")};
        auto r = ::wallet::pricoin_adaptor_swap::SetBtcFunded(
            *m_wallet, *sid, foreign_funding_txid,
            foreign_funding_vout, foreign_funding_height);
        return WrapTransition(r, this, *sid);
    }

    util::Result<PricoinAdaptorSwapSnapshot> adaptorSwapSetPricFunded(
        const std::string& swap_id,
        const std::string& pric_funding_txid,
        int32_t pric_funding_vout,
        int32_t pric_funding_height) override
    {
        auto sid = uint256::FromHex(swap_id);
        if (!sid) return util::Error{Untranslated("swap_id must be 32-byte hex")};
        auto txid = uint256::FromHex(pric_funding_txid);
        if (!txid) return util::Error{Untranslated("pric_funding_txid must be 32-byte hex")};
        auto r = ::wallet::pricoin_adaptor_swap::SetPricFunded(
            *m_wallet, *sid, *txid,
            pric_funding_vout, pric_funding_height);
        return WrapTransition(r, this, *sid);
    }

    util::Result<PricoinAdaptorSwapSnapshot> adaptorSwapSetPreSigned(
        const std::string& swap_id,
        const PricoinAdaptorSwapPreSigsHex& presigs) override
    {
        auto sid = uint256::FromHex(swap_id);
        if (!sid) return util::Error{Untranslated("swap_id must be 32-byte hex")};
        auto parse = [](const std::string& hex) {
            auto b = TryParseHex<unsigned char>(hex);
            return b.value_or(std::vector<unsigned char>{});
        };
        ::wallet::pricoin_adaptor_swap::AdaptorSwapPreSigs ps;
        ps.btc_claim_presig         = parse(presigs.btc_claim_presig_hex);
        ps.btc_claim_session        = parse(presigs.btc_claim_session_hex);
        ps.btc_claim_nonce_parity   = presigs.btc_claim_nonce_parity;
        ps.pric_claim_presig_blob   = parse(presigs.pric_claim_presig_blob_hex);
        ps.btc_refund_sig           = parse(presigs.btc_refund_sig_hex);
        ps.pric_refund_sig_blob     = parse(presigs.pric_refund_sig_blob_hex);
        if (ps.btc_claim_presig.size() != 64
            || ps.btc_claim_session.size() != 133
            || ps.btc_refund_sig.size() != 64
            || ps.pric_claim_presig_blob.empty()
            || ps.pric_refund_sig_blob.empty()) {
            return util::Error{Untranslated("pre-sig blobs must be valid hex of the expected lengths (64/133/64 fixed; PRIC blobs non-empty)")};
        }
        auto r = ::wallet::pricoin_adaptor_swap::SetPreSigned(*m_wallet, *sid, ps);
        return WrapTransition(r, this, *sid);
    }

    util::Result<PricoinAdaptorSwapSnapshot> adaptorSwapSetPricClaimed(
        const std::string& swap_id,
        const std::string& pric_claim_txid) override
    {
        auto sid = uint256::FromHex(swap_id);
        if (!sid) return util::Error{Untranslated("swap_id must be 32-byte hex")};
        auto txid = uint256::FromHex(pric_claim_txid);
        if (!txid) return util::Error{Untranslated("pric_claim_txid must be 32-byte hex")};
        auto r = ::wallet::pricoin_adaptor_swap::SetPricClaimed(*m_wallet, *sid, *txid);
        return WrapTransition(r, this, *sid);
    }

    util::Result<PricoinAdaptorSwapSnapshot> adaptorSwapSetComplete(
        const std::string& swap_id,
        const std::string& foreign_claim_txid) override
    {
        auto sid = uint256::FromHex(swap_id);
        if (!sid) return util::Error{Untranslated("swap_id must be 32-byte hex")};
        auto r = ::wallet::pricoin_adaptor_swap::SetComplete(*m_wallet, *sid, foreign_claim_txid);
        return WrapTransition(r, this, *sid);
    }

    util::Result<PricoinAdaptorSwapSnapshot> adaptorSwapSetRefunded(
        const std::string& swap_id,
        const std::string& pric_refund_txid_or_empty,
        const std::string& foreign_refund_txid_or_empty) override
    {
        auto sid = uint256::FromHex(swap_id);
        if (!sid) return util::Error{Untranslated("swap_id must be 32-byte hex")};
        uint256 pric_txid{};
        if (!pric_refund_txid_or_empty.empty()) {
            auto p = uint256::FromHex(pric_refund_txid_or_empty);
            if (!p) return util::Error{Untranslated("pric_refund_txid must be 32-byte hex if non-empty")};
            pric_txid = *p;
        }
        auto r = ::wallet::pricoin_adaptor_swap::SetRefunded(
            *m_wallet, *sid, pric_txid, foreign_refund_txid_or_empty);
        return WrapTransition(r, this, *sid);
    }

    util::Result<PricoinAdaptorSwapSnapshot>
    adaptorSwapAbort(const std::string& swap_id, const std::string& reason) override {
        auto sid = uint256::FromHex(swap_id);
        if (!sid) return util::Error{Untranslated("swap_id must be 32-byte hex")};
        auto r = ::wallet::pricoin_adaptor_swap::Abort(*m_wallet, *sid, reason);
        using TR = ::wallet::pricoin_adaptor_swap::TransitionResult;
        switch (r) {
        case TR::Ok: break;
        case TR::NotFound:        return util::Error{Untranslated("no swap with that id")};
        case TR::InvalidState:    return util::Error{Untranslated("current state does not permit abort")};
        case TR::InvalidInput:    return util::Error{Untranslated("invalid input")};
        case TR::InvalidTimelocks:return util::Error{Untranslated("invalid timelocks")};
        case TR::Locked:          return util::Error{Untranslated("wallet locked")};
        case TR::WriteFailed:     return util::Error{Untranslated("wallet write failed")};
        }
        ::wallet::pricoin_adaptor_swap::AdaptorSwap s;
        ::wallet::pricoin_adaptor_swap::Get(*m_wallet, *sid, s);
        return ToSwapSnapshot(s);
    }

private:
    // Re-derive the swap-identity priv. Mirrors the path inside
    // pricoin_swap_session::DeriveSwapIdentityPriv (which is private).
    bool deriveSwapIdentityPriv(CKey& out) {
        const auto& id = ::wallet::pricoin_stealth::GetOrCreate(*m_wallet);
        if (!id.spend.IsValid()) return false;
        constexpr const char* kTag = "pricoin/swap/identity-v1";
        for (uint8_t counter = 0; counter < 16; ++counter) {
            CHMAC_SHA256 hmac(UCharCast(id.spend.data()), 32);
            hmac.Write(reinterpret_cast<const unsigned char*>(kTag), std::strlen(kTag));
            hmac.Write(&counter, 1);
            unsigned char raw[32];
            hmac.Finalize(raw);
            out.Set(raw, raw + 32, /*compressed=*/true);
            if (out.IsValid()) return true;
        }
        return false;
    }

public:
    std::string getSwapIdentityXOnlyHex() override {
        CKey priv;
        if (!deriveSwapIdentityPriv(priv)) return "";
        const CPubKey pub = priv.GetPubKey();
        XOnlyPubKey xonly(pub);
        return HexStr(xonly);
    }

    util::Result<std::string> signNostrEvent(const uint256& event_id_hash) override {
        CKey priv;
        if (!deriveSwapIdentityPriv(priv)) {
            return util::Error{Untranslated("swap-identity priv unavailable (wallet locked?)")};
        }
        std::vector<unsigned char> sig(64);
        uint256 aux;
        GetStrongRandBytes(aux);
        if (!priv.SignSchnorr(event_id_hash,
                              std::span<unsigned char>{sig.data(), sig.size()},
                              /*merkle_root=*/nullptr,
                              aux)) {
            return util::Error{Untranslated("BIP340 sign failed")};
        }
        return HexStr(sig);
    }

    std::vector<PricoinMatchCandidate> offerFindMatches(const std::string& my_order_id) override {
        std::vector<PricoinMatchCandidate> out;
        auto oid = ParseOid(my_order_id);
        if (!oid) return out;
        std::vector<::wallet::pricoin_offer::MatchCandidate> cands;
        auto r = ::wallet::pricoin_offer::FindMatches(*m_wallet, *oid, cands);
        if (r != ::wallet::pricoin_offer::LookupResult::Ok) return out;
        out.reserve(cands.size());
        for (const auto& c : cands) {
            PricoinMatchCandidate m;
            m.their_order_id = c.their_order_id.ToString();
            m.their_max_pric_sat = c.their_max_pric_sat;
            m.their_foreign_at_max_sat = c.their_foreign_at_max_sat;
            m.max_actual_pric_sat = c.max_actual_pric_sat;
            m.price_advantage_milli = c.price_advantage_milli;
            out.push_back(m);
        }
        return out;
    }
    util::Result<CTxDestination> getNewDestination(const OutputType type, const std::string& label) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetNewDestination(type, label);
    }
    bool getPubKey(const CScript& script, const CKeyID& address, CPubKey& pub_key) override
    {
        std::unique_ptr<SigningProvider> provider = m_wallet->GetSolvingProvider(script);
        if (provider) {
            return provider->GetPubKey(address, pub_key);
        }
        return false;
    }
    SigningResult signMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) override
    {
        return m_wallet->SignMessage(message, pkhash, str_sig);
    }
    bool isSpendable(const CTxDestination& dest) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsMine(dest);
    }
    bool setAddressBook(const CTxDestination& dest, const std::string& name, const std::optional<AddressPurpose>& purpose) override
    {
        return m_wallet->SetAddressBook(dest, name, purpose);
    }
    bool delAddressBook(const CTxDestination& dest) override
    {
        return m_wallet->DelAddressBook(dest);
    }
    bool getAddress(const CTxDestination& dest,
        std::string* name,
        AddressPurpose* purpose) override
    {
        LOCK(m_wallet->cs_wallet);
        const auto& entry = m_wallet->FindAddressBookEntry(dest, /*allow_change=*/false);
        if (!entry) return false; // addr not found
        if (name) {
            *name = entry->GetLabel();
        }
        if (purpose) {
            // In very old wallets, address purpose may not be recorded so we derive it from IsMine
            *purpose = entry->purpose.value_or(m_wallet->IsMine(dest) ? AddressPurpose::RECEIVE : AddressPurpose::SEND);
        }
        return true;
    }
    std::vector<WalletAddress> getAddresses() override
    {
        LOCK(m_wallet->cs_wallet);
        std::vector<WalletAddress> result;
        m_wallet->ForEachAddrBookEntry([&](const CTxDestination& dest, const std::string& label, bool is_change, const std::optional<AddressPurpose>& purpose) EXCLUSIVE_LOCKS_REQUIRED(m_wallet->cs_wallet) {
            if (is_change) return;
            bool is_mine = m_wallet->IsMine(dest);
            // In very old wallets, address purpose may not be recorded so we derive it from IsMine
            result.emplace_back(dest, is_mine, purpose.value_or(is_mine ? AddressPurpose::RECEIVE : AddressPurpose::SEND), label);
        });
        return result;
    }
    std::vector<std::string> getAddressReceiveRequests() override {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetAddressReceiveRequests();
    }
    bool setAddressReceiveRequest(const CTxDestination& dest, const std::string& id, const std::string& value) override {
        // Note: The setAddressReceiveRequest interface used by the GUI to store
        // receive requests is a little awkward and could be improved in the
        // future:
        //
        // - The same method is used to save requests and erase them, but
        //   having separate methods could be clearer and prevent bugs.
        //
        // - Request ids are passed as strings even though they are generated as
        //   integers.
        //
        // - Multiple requests can be stored for the same address, but it might
        //   be better to only allow one request or only keep the current one.
        LOCK(m_wallet->cs_wallet);
        WalletBatch batch{m_wallet->GetDatabase()};
        return value.empty() ? m_wallet->EraseAddressReceiveRequest(batch, dest, id)
                             : m_wallet->SetAddressReceiveRequest(batch, dest, id, value);
    }
    util::Result<void> displayAddress(const CTxDestination& dest) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->DisplayAddress(dest);
    }
    bool lockCoin(const COutPoint& output, const bool write_to_db) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->LockCoin(output, write_to_db);
    }
    bool unlockCoin(const COutPoint& output) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->UnlockCoin(output);
    }
    bool isLockedCoin(const COutPoint& output) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsLockedCoin(output);
    }
    void listLockedCoins(std::vector<COutPoint>& outputs) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->ListLockedCoins(outputs);
    }
    util::Result<wallet::CreatedTransactionResult> createTransaction(const std::vector<CRecipient>& recipients,
        const CCoinControl& coin_control,
        bool sign,
        std::optional<unsigned int> change_pos) override
    {
        LOCK(m_wallet->cs_wallet);
        return CreateTransaction(*m_wallet, recipients, change_pos, coin_control, sign);
    }
    void commitTransaction(CTransactionRef tx,
        WalletValueMap value_map,
        WalletOrderForm order_form) override
    {
        LOCK(m_wallet->cs_wallet);
        m_wallet->CommitTransaction(std::move(tx), std::move(value_map), std::move(order_form));
    }
    bool transactionCanBeAbandoned(const Txid& txid) override { return m_wallet->TransactionCanBeAbandoned(txid); }
    bool abandonTransaction(const Txid& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->AbandonTransaction(txid);
    }
    bool transactionCanBeBumped(const Txid& txid) override
    {
        return feebumper::TransactionCanBeBumped(*m_wallet.get(), txid);
    }
    bool createBumpTransaction(const Txid& txid,
        const CCoinControl& coin_control,
        std::vector<bilingual_str>& errors,
        CAmount& old_fee,
        CAmount& new_fee,
        CMutableTransaction& mtx) override
    {
        std::vector<CTxOut> outputs; // just an empty list of new recipients for now
        return feebumper::CreateRateBumpTransaction(*m_wallet.get(), txid, coin_control, errors, old_fee, new_fee, mtx, /* require_mine= */ true, outputs) == feebumper::Result::OK;
    }
    bool signBumpTransaction(CMutableTransaction& mtx) override { return feebumper::SignTransaction(*m_wallet.get(), mtx); }
    bool commitBumpTransaction(const Txid& txid,
        CMutableTransaction&& mtx,
        std::vector<bilingual_str>& errors,
        Txid& bumped_txid) override
    {
        return feebumper::CommitTransaction(*m_wallet.get(), txid, std::move(mtx), errors, bumped_txid) ==
               feebumper::Result::OK;
    }
    CTransactionRef getTx(const Txid& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi != m_wallet->mapWallet.end()) {
            return mi->second.tx;
        }
        return {};
    }
    WalletTx getWalletTx(const Txid& txid) override
    {
        LOCK(m_wallet->cs_wallet);
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi != m_wallet->mapWallet.end()) {
            return MakeWalletTx(*m_wallet, mi->second);
        }
        return {};
    }
    std::set<WalletTx> getWalletTxs() override
    {
        LOCK(m_wallet->cs_wallet);
        std::set<WalletTx> result;
        for (const auto& entry : m_wallet->mapWallet) {
            result.emplace(MakeWalletTx(*m_wallet, entry.second));
        }
        return result;
    }
    bool tryGetTxStatus(const Txid& txid,
        interfaces::WalletTxStatus& tx_status,
        int& num_blocks,
        int64_t& block_time) override
    {
        TRY_LOCK(m_wallet->cs_wallet, locked_wallet);
        if (!locked_wallet) {
            return false;
        }
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi == m_wallet->mapWallet.end()) {
            return false;
        }
        num_blocks = m_wallet->GetLastBlockHeight();
        block_time = -1;
        CHECK_NONFATAL(m_wallet->chain().findBlock(m_wallet->GetLastBlockHash(), FoundBlock().time(block_time)));
        tx_status = MakeWalletTxStatus(*m_wallet, mi->second);
        return true;
    }
    WalletTx getWalletTxDetails(const Txid& txid,
        WalletTxStatus& tx_status,
        WalletOrderForm& order_form,
        bool& in_mempool,
        int& num_blocks) override
    {
        LOCK(m_wallet->cs_wallet);
        auto mi = m_wallet->mapWallet.find(txid);
        if (mi != m_wallet->mapWallet.end()) {
            num_blocks = m_wallet->GetLastBlockHeight();
            in_mempool = mi->second.InMempool();
            order_form = mi->second.vOrderForm;
            tx_status = MakeWalletTxStatus(*m_wallet, mi->second);
            return MakeWalletTx(*m_wallet, mi->second);
        }
        return {};
    }
    std::optional<PSBTError> fillPSBT(std::optional<int> sighash_type,
        bool sign,
        bool bip32derivs,
        size_t* n_signed,
        PartiallySignedTransaction& psbtx,
        bool& complete) override
    {
        return m_wallet->FillPSBT(psbtx, complete, sighash_type, sign, bip32derivs, n_signed);
    }
    WalletBalances getBalances() override
    {
        const auto bal = GetBalance(*m_wallet);
        WalletBalances result;
        result.balance = bal.m_mine_trusted;
        result.unconfirmed_balance = bal.m_mine_untrusted_pending;
        result.immature_balance = bal.m_mine_immature;
        result.used_balance = bal.m_mine_used;
        result.nonmempool_balance = bal.m_mine_nonmempool;
        // Pricoin: pull the recovered CT total in the same poll snapshot as
        // the transparent fields so balanceChanged() can detect a CT-only
        // change and the OverviewPage refreshes without a wallet reload.
        result.confidential_balance = ::wallet::ConfidentialBalance(*m_wallet);
        return result;
    }
    bool tryGetBalances(WalletBalances& balances, uint256& block_hash) override
    {
        TRY_LOCK(m_wallet->cs_wallet, locked_wallet);
        if (!locked_wallet) {
            return false;
        }
        block_hash = m_wallet->GetLastBlockHash();
        balances = getBalances();
        return true;
    }
    CAmount getBalance() override { return GetBalance(*m_wallet).m_mine_trusted; }
    CAmount getAvailableBalance(const CCoinControl& coin_control) override
    {
        LOCK(m_wallet->cs_wallet);
        CAmount total_amount = 0;
        // Fetch selected coins total amount
        if (coin_control.HasSelected()) {
            FastRandomContext rng{};
            CoinSelectionParams params(rng);
            // Note: for now, swallow any error.
            if (auto res = FetchSelectedInputs(*m_wallet, coin_control, params)) {
                total_amount += res->GetTotalAmount();
            }
        }

        // And fetch the wallet available coins
        if (coin_control.m_allow_other_inputs) {
            total_amount += AvailableCoins(*m_wallet, &coin_control).GetTotalAmount();
        }

        return total_amount;
    }
    bool txinIsMine(const CTxIn& txin) override
    {
        LOCK(m_wallet->cs_wallet);
        return InputIsMine(*m_wallet, txin);
    }
    bool txoutIsMine(const CTxOut& txout) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->IsMine(txout);
    }
    CAmount getDebit(const CTxIn& txin) override
    {
        LOCK(m_wallet->cs_wallet);
        return m_wallet->GetDebit(txin);
    }
    CAmount getCredit(const CTxOut& txout) override
    {
        LOCK(m_wallet->cs_wallet);
        return OutputGetCredit(*m_wallet, txout);
    }
    CoinsList listCoins() override
    {
        LOCK(m_wallet->cs_wallet);
        CoinsList result;
        for (const auto& entry : ListCoins(*m_wallet)) {
            auto& group = result[entry.first];
            for (const auto& coin : entry.second) {
                group.emplace_back(coin.outpoint,
                    MakeWalletTxOut(*m_wallet, coin));
            }
        }
        return result;
    }
    std::vector<WalletTxOut> getCoins(const std::vector<COutPoint>& outputs) override
    {
        LOCK(m_wallet->cs_wallet);
        std::vector<WalletTxOut> result;
        result.reserve(outputs.size());
        for (const auto& output : outputs) {
            result.emplace_back();
            auto it = m_wallet->mapWallet.find(output.hash);
            if (it != m_wallet->mapWallet.end()) {
                int depth = m_wallet->GetTxDepthInMainChain(it->second);
                if (depth >= 0) {
                    result.back() = MakeWalletTxOut(*m_wallet, it->second, output.n, depth);
                }
            }
        }
        return result;
    }
    CAmount getRequiredFee(unsigned int tx_bytes) override { return GetRequiredFee(*m_wallet, tx_bytes); }
    CAmount getMinimumFee(unsigned int tx_bytes,
        const CCoinControl& coin_control,
        int* returned_target,
        FeeReason* reason) override
    {
        FeeCalculation fee_calc;
        CAmount result;
        result = GetMinimumFee(*m_wallet, tx_bytes, coin_control, &fee_calc);
        if (returned_target) *returned_target = fee_calc.returnedTarget;
        if (reason) *reason = fee_calc.reason;
        return result;
    }
    unsigned int getConfirmTarget() override { return m_wallet->m_confirm_target; }
    bool hdEnabled() override { return m_wallet->IsHDEnabled(); }
    bool canGetAddresses() override { return m_wallet->CanGetAddresses(); }
    bool hasExternalSigner() override { return m_wallet->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER); }
    bool privateKeysDisabled() override { return m_wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS); }
    bool taprootEnabled() override {
        auto spk_man = m_wallet->GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/false);
        return spk_man != nullptr;
    }
    OutputType getDefaultAddressType() override { return m_wallet->m_default_address_type; }
    CAmount getDefaultMaxTxFee() override { return m_wallet->m_default_max_tx_fee; }
    void remove() override
    {
        RemoveWallet(m_context, m_wallet, /*load_on_start=*/false);
    }
    std::unique_ptr<Handler> handleUnload(UnloadFn fn) override
    {
        return MakeSignalHandler(m_wallet->NotifyUnload.connect(fn));
    }
    std::unique_ptr<Handler> handleShowProgress(ShowProgressFn fn) override
    {
        return MakeSignalHandler(m_wallet->ShowProgress.connect(fn));
    }
    std::unique_ptr<Handler> handleStatusChanged(StatusChangedFn fn) override
    {
        return MakeSignalHandler(m_wallet->NotifyStatusChanged.connect([fn](CWallet*) { fn(); }));
    }
    std::unique_ptr<Handler> handleAddressBookChanged(AddressBookChangedFn fn) override
    {
        return MakeSignalHandler(m_wallet->NotifyAddressBookChanged.connect(
            [fn](const CTxDestination& address, const std::string& label, bool is_mine,
                 AddressPurpose purpose, ChangeType status) { fn(address, label, is_mine, purpose, status); }));
    }
    std::unique_ptr<Handler> handleTransactionChanged(TransactionChangedFn fn) override
    {
        return MakeSignalHandler(m_wallet->NotifyTransactionChanged.connect(
            [fn](const Txid& txid, ChangeType status) { fn(txid, status); }));
    }
    std::unique_ptr<Handler> handleCanGetAddressesChanged(CanGetAddressesChangedFn fn) override
    {
        return MakeSignalHandler(m_wallet->NotifyCanGetAddressesChanged.connect(fn));
    }
    CWallet* wallet() override { return m_wallet.get(); }

    WalletContext& m_context;
    std::shared_ptr<CWallet> m_wallet;
};

class WalletLoaderImpl : public WalletLoader
{
public:
    WalletLoaderImpl(Chain& chain, ArgsManager& args)
    {
        m_context.chain = &chain;
        m_context.args = &args;
    }
    ~WalletLoaderImpl() override { stop(); }

    //! ChainClient methods
    void registerRpcs() override
    {
        for (const CRPCCommand& command : GetWalletRPCCommands()) {
            m_rpc_commands.emplace_back(command.category, command.name, [this, &command](const JSONRPCRequest& request, UniValue& result, bool last_handler) {
                JSONRPCRequest wallet_request = request;
                wallet_request.context = &m_context;
                return command.actor(wallet_request, result, last_handler);
            }, command.argNames, command.unique_id);
            m_rpc_handlers.emplace_back(m_context.chain->handleRpc(m_rpc_commands.back()));
        }
    }
    bool verify() override { return VerifyWallets(m_context); }
    bool load() override { return LoadWallets(m_context); }
    void start(CScheduler& scheduler) override
    {
        m_context.scheduler = &scheduler;
        return StartWallets(m_context);
    }
    void stop() override { return UnloadWallets(m_context); }
    void setMockTime(int64_t time) override { return SetMockTime(time); }
    void schedulerMockForward(std::chrono::seconds delta) override { Assert(m_context.scheduler)->MockForward(delta); }

    //! WalletLoader methods
    util::Result<std::unique_ptr<Wallet>> createWallet(const std::string& name, const SecureString& passphrase, uint64_t wallet_creation_flags, std::vector<bilingual_str>& warnings) override
    {
        DatabaseOptions options;
        DatabaseStatus status;
        ReadDatabaseArgs(*m_context.args, options);
        options.require_create = true;
        options.create_flags = wallet_creation_flags;
        options.create_passphrase = passphrase;
        bilingual_str error;
        std::unique_ptr<Wallet> wallet{MakeWallet(m_context, CreateWallet(m_context, name, /*load_on_start=*/true, options, status, error, warnings))};
        if (wallet) {
            return wallet;
        } else {
            return util::Error{error};
        }
    }
    util::Result<std::unique_ptr<Wallet>> loadWallet(const std::string& name, std::vector<bilingual_str>& warnings) override
    {
        DatabaseOptions options;
        DatabaseStatus status;
        ReadDatabaseArgs(*m_context.args, options);
        options.require_existing = true;
        bilingual_str error;
        std::unique_ptr<Wallet> wallet{MakeWallet(m_context, LoadWallet(m_context, name, /*load_on_start=*/true, options, status, error, warnings))};
        if (wallet) {
            return wallet;
        } else {
            return util::Error{error};
        }
    }
    util::Result<std::unique_ptr<Wallet>> restoreWallet(const fs::path& backup_file, const std::string& wallet_name, std::vector<bilingual_str>& warnings, bool load_after_restore) override
    {
        DatabaseStatus status;
        bilingual_str error;
        std::unique_ptr<Wallet> wallet{MakeWallet(m_context, RestoreWallet(m_context, backup_file, wallet_name, /*load_on_start=*/true, status, error, warnings, load_after_restore))};
        if (!error.empty()) {
            return util::Error{error};
        }
        return wallet;
    }
    util::Result<WalletMigrationResult> migrateWallet(const std::string& name, const SecureString& passphrase) override
    {
        auto res = wallet::MigrateLegacyToDescriptor(name, passphrase, m_context);
        if (!res) return util::Error{util::ErrorString(res)};
        WalletMigrationResult out{
            .wallet = MakeWallet(m_context, res->wallet),
            .watchonly_wallet_name = res->watchonly_wallet ? std::make_optional(res->watchonly_wallet->GetName()) : std::nullopt,
            .solvables_wallet_name = res->solvables_wallet ? std::make_optional(res->solvables_wallet->GetName()) : std::nullopt,
            .backup_path = res->backup_path,
        };
        return out;
    }
    bool isEncrypted(const std::string& wallet_name) override
    {
        auto wallets{GetWallets(m_context)};
        auto it = std::find_if(wallets.begin(), wallets.end(), [&](std::shared_ptr<CWallet> w){ return w->GetName() == wallet_name; });
        if (it != wallets.end()) return (*it)->HasEncryptionKeys();

        // Unloaded wallet, read db
        DatabaseOptions options;
        options.require_existing = true;
        DatabaseStatus status;
        bilingual_str error;
        auto db = MakeWalletDatabase(wallet_name, options, status, error);
        if (!db && status == wallet::DatabaseStatus::FAILED_LEGACY_DISABLED) {
            options.require_format = wallet::DatabaseFormat::BERKELEY_RO;
            db = MakeWalletDatabase(wallet_name, options, status, error);
        }
        if (!db) return false;
        return WalletBatch(*db).IsEncrypted();
    }
    std::string getWalletDir() override
    {
        return fs::PathToString(GetWalletDir());
    }
    std::vector<std::pair<std::string, std::string>> listWalletDir() override
    {
        std::vector<std::pair<std::string, std::string>> paths;
        for (auto& [path, format] : ListDatabases(GetWalletDir())) {
            paths.emplace_back(fs::PathToString(path), format);
        }
        return paths;
    }
    std::vector<std::unique_ptr<Wallet>> getWallets() override
    {
        std::vector<std::unique_ptr<Wallet>> wallets;
        for (const auto& wallet : GetWallets(m_context)) {
            wallets.emplace_back(MakeWallet(m_context, wallet));
        }
        return wallets;
    }
    std::unique_ptr<Handler> handleLoadWallet(LoadWalletFn fn) override
    {
        return HandleLoadWallet(m_context, std::move(fn));
    }
    WalletContext* context() override  { return &m_context; }

    WalletContext m_context;
    const std::vector<std::string> m_wallet_filenames;
    std::vector<std::unique_ptr<Handler>> m_rpc_handlers;
    std::list<CRPCCommand> m_rpc_commands;
};
} // namespace
} // namespace wallet

namespace interfaces {
std::unique_ptr<Wallet> MakeWallet(wallet::WalletContext& context, const std::shared_ptr<wallet::CWallet>& wallet) { return wallet ? std::make_unique<wallet::WalletImpl>(context, wallet) : nullptr; }

std::unique_ptr<WalletLoader> MakeWalletLoader(Chain& chain, ArgsManager& args)
{
    return std::make_unique<wallet::WalletLoaderImpl>(chain, args);
}
} // namespace interfaces
