// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <cmath>
#include <consensus/amount.h>
#include <hash.h>
#include <key.h>
#include <key_io.h>
#include <logging.h>
#include <pricoin/joint_ringsig.h>
#include <pricoin/ringsig.h>
#include <pricoin/ct.h>
#include <pricoin/adaptor_ringsig.h>
#include <pricoin/cttx.h>
#include <pricoin/joint_stealth.h>
#include <pricoin/stealth.h>
#include <pricoin/validation.h>
#include <primitives/transaction.h>
#include <interfaces/chain.h>
#include <node/types.h>
#include <pubkey.h>
#include <random.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <streams.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <core_io.h>
#include <wallet/coincontrol.h>
#include <wallet/coinselection.h>
#include <swap/btc_htlc.h>
#include <swap/btc_musig2_adaptor.h>
#include <swap/btc_musig2_runtime.h>
#include <swap/btc_refund_tx.h>
#include <crypto/hmac_sha256.h>
#include <wallet/pricoin_adaptor_swap.h>
#include <wallet/pricoin_broadcasted_kis.h>
#include <wallet/pricoin_btc_holding.h>
#include <wallet/pricoin_btc_musig2_nonce_records.h>
#include <wallet/pricoin_chain_watcher.h>
#include <wallet/pricoin_clsag_nonce_records.h>
#include <wallet/pricoin_offer.h>
#include <wallet/pricoin_ct_send.h>
#include <wallet/pricoin_stealth.h>
#include <wallet/pricoin_swap_ceremony.h>
#include <wallet/pricoin_swap_session.h>
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace wallet {

namespace {

// One picked transparent UTXO. The wallet's SignTransaction handles the
// actual signing via its own keystore — we only need the outpoint, value,
// and scriptPubKey here.
struct PickedInput {
    COutPoint outpoint;
    CAmount value;
    CScript scriptPubKey;
};

// Pick a set of P2WPKH UTXOs whose values sum to at least `target`. Greedy
// biggest-first to keep input counts small (smaller tx, fewer signatures,
// less work for the rangeproof verifier on the consumer side). Returns
// nullopt if total spendable balance is below target.
std::optional<std::vector<PickedInput>> PickP2WPKHFunding(CWallet& wallet, CAmount target)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    CoinFilterParams filter;
    filter.skip_locked = true;
    auto avail = AvailableCoins(wallet, /*coinControl=*/nullptr, /*feerate=*/std::nullopt, filter);

    std::vector<PickedInput> candidates;
    for (const auto& coin : avail.All()) {
        const CScript& spk = coin.txout.scriptPubKey;
        if (spk.size() != 22 || spk[0] != OP_0 || spk[1] != 0x14) continue;
        candidates.push_back({coin.outpoint, coin.txout.nValue, spk});
    }
    std::sort(candidates.begin(), candidates.end(),
              [](const auto& a, const auto& b) { return a.value > b.value; });

    std::vector<PickedInput> picked;
    CAmount sum = 0;
    for (auto& c : candidates) {
        picked.push_back(std::move(c));
        sum += picked.back().value;
        if (sum >= target) return picked;
    }
    return std::nullopt;
}

} // namespace (close anonymous)

// Public helpers used by both `walletsendct` / `walletsendct_multi` RPCs
// and the Qt GUI's interfaces::Wallet::sendConfidential. Return a
// util::Result so callers can translate to either JSONRPCError or a UI
// message.
namespace detail { // forward-decl in this TU; defined below the RPC.
util::Result<uint256> SendConfidentialTxMultiImpl(
    CWallet& wallet,
    std::span<const PricoinCTRecipient> recipients,
    CAmount fee,
    int32_t lock_height = 0,
    std::string* hex_out = nullptr);
} // namespace detail

util::Result<uint256> SendConfidentialTxMulti(
    CWallet& wallet,
    std::span<const PricoinCTRecipient> recipients,
    CAmount fee)
{
    if (recipients.empty()) {
        return util::Error{Untranslated("no recipients")};
    }
    if (fee < 0) {
        return util::Error{Untranslated("negative fee")};
    }
    return detail::SendConfidentialTxMultiImpl(wallet, recipients, fee);
}

util::Result<uint256> SendConfidentialTx(
    CWallet& wallet,
    const std::string& dest_addr_str,
    CAmount dest_amount,
    CAmount fee)
{
    if (dest_amount <= 0) {
        return util::Error{Untranslated("non-positive amount")};
    }
    PricoinCTRecipient one{dest_addr_str, dest_amount, /*ephemeral_priv=*/{}};
    return SendConfidentialTxMulti(wallet,
        std::span<const PricoinCTRecipient>{&one, 1}, fee);
}

namespace { // re-enter anonymous

RPCMethod walletsendct()
{
    return RPCMethod{
        "walletsendct",
        "Build, sign, and submit a Pricoin Confidential Transaction using wallet UTXOs.\n"
        "Greedy biggest-first selection across N P2WPKH wallet UTXOs until they cover\n"
        "dest_amount + fee, signs with the wallet's keystore, generates a change address\n"
        "from the wallet, and submits the resulting v4 transaction. dest_address may be\n"
        "either a stealth address (preferred — recipient can recover) or a regular bech32\n"
        "(recipient cannot scan).\n"
        "\n"
        "Optional `ephemeral_priv` pins the per-output stealth ephemeral `r` to a\n"
        "known scalar instead of using a fresh random one. Required for atomic-swap\n"
        "PRIC funding — Bob's adaptor binding committed to a specific `r`, so the\n"
        "joint funding tx must use the same `r` or the on-chain P_pi will diverge\n"
        "from the adaptor and the swap becomes unsignable. Ignored for transparent\n"
        "destinations (no stealth ephemeral) and for change outputs.\n",
        {
            {"dest_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Destination Pricoin stealth or bech32 address"},
            {"dest_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount to send in PRIC"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Transparent fee in PRIC"},
            {"ephemeral_priv", RPCArg::Type::STR_HEX, RPCArg::Default{""},
                "Optional 32-byte priv to pin as the stealth ephemeral. Empty = fresh random."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "Submitted transaction id"},
                {RPCResult::Type::BOOL, "dest_was_stealth", "Whether dest_address was decoded as a stealth address"},
            }
        },
        RPCExamples{
            HelpExampleCli("walletsendct", "\"H6...\" 25.0 0.001")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;

            const std::string dest_addr_str = request.params[0].get_str();
            const CAmount dest_amount = AmountFromValue(request.params[1]);
            const CAmount fee = AmountFromValue(request.params[2]);
            const std::string eph_hex = request.params[3].isNull() ? "" : request.params[3].get_str();

            std::vector<unsigned char> eph_priv;
            if (!eph_hex.empty()) {
                auto bytes = TryParseHex<unsigned char>(eph_hex);
                if (!bytes || bytes->size() != 32) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "ephemeral_priv must be 32-byte hex (or empty for fresh random)");
                }
                eph_priv = *bytes;
            }

            // Build a single recipient with the optional pinned ephemeral
            // and dispatch to the multi-impl.
            PricoinCTRecipient one{dest_addr_str, dest_amount, eph_priv};
            auto res = SendConfidentialTxMulti(wallet,
                std::span<const PricoinCTRecipient>{&one, 1}, fee);
            if (!res) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(res).original);

            UniValue out{UniValue::VOBJ};
            out.pushKV("txid", res->ToString());
            out.pushKV("dest_was_stealth", ::pricoin::stealth::ParseStealthAddress(dest_addr_str).has_value());
            return out;
        }
    };
}

RPCMethod walletsendct_multi()
{
    return RPCMethod{
        "walletsendct_multi",
        "Build, sign, and submit a single Pricoin Confidential Transaction paying many\n"
        "recipients in one bundle. Greedy biggest-first selection across N P2WPKH wallet\n"
        "UTXOs covers Σ(amounts) + fee; each recipient gets its own one-time stealth\n"
        "output (or a transparent output if a bech32 address is given); change goes back\n"
        "to the wallet's own stealth identity. Co-anonymizes recipients inside one tx\n"
        "and is dramatically more wire-efficient than N separate `walletsendct` calls\n"
        "(~one rangeproof set vs N) — used by the mining pool's payout path.\n",
        {
            {"recipients", RPCArg::Type::ARR, RPCArg::Optional::NO, "Recipients (one or more)",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Pricoin stealth (H6...) or transparent bech32 address"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount in PRIC"},
                        },
                    },
                },
            },
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Total transparent fee in PRIC (one fee, regardless of recipient count)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "Submitted transaction id"},
                {RPCResult::Type::NUM, "recipients", "Number of recipients in the bundle"},
                {RPCResult::Type::NUM, "outputs", "Total bundle outputs (recipients + 1 change)"},
                {RPCResult::Type::STR_AMOUNT, "total_sent", "Sum of recipient amounts in PRIC"},
                {RPCResult::Type::STR_AMOUNT, "fee", "Transparent fee in PRIC"},
            }
        },
        RPCExamples{
            HelpExampleCli("walletsendct_multi", "'[{\"address\":\"H6...\",\"amount\":1.5},{\"address\":\"H6...\",\"amount\":2.0}]' 0.001")
            + HelpExampleRpc("walletsendct_multi", "[{\"address\":\"H6...\",\"amount\":1.5},{\"address\":\"H6...\",\"amount\":2.0}], 0.001")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;

            const UniValue& arr = request.params[0].get_array();
            if (arr.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "recipients array is empty");
            }
            std::vector<PricoinCTRecipient> recipients;
            recipients.reserve(arr.size());
            CAmount total_sent = 0;
            for (size_t i = 0; i < arr.size(); ++i) {
                const UniValue& obj = arr[i];
                if (!obj.isObject()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("recipients[%u] must be an object {address, amount}", i));
                }
                const UniValue& addr_v = obj.find_value("address");
                const UniValue& amt_v  = obj.find_value("amount");
                if (addr_v.isNull() || amt_v.isNull()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("recipients[%u] missing address or amount", i));
                }
                PricoinCTRecipient r;
                r.address = addr_v.get_str();
                r.amount  = AmountFromValue(amt_v);
                if (r.amount > MAX_MONEY - total_sent) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "total recipient amount overflows MAX_MONEY");
                }
                total_sent += r.amount;
                recipients.push_back(std::move(r));
            }
            const CAmount fee = AmountFromValue(request.params[1]);

            auto res = SendConfidentialTxMulti(wallet,
                std::span<const PricoinCTRecipient>{recipients}, fee);
            if (!res) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(res).original);

            UniValue out{UniValue::VOBJ};
            out.pushKV("txid", res->ToString());
            out.pushKV("recipients", static_cast<int>(recipients.size()));
            // Bundle holds N recipients + 1 change + privacy padding (so the
            // total is ≥3 — see SendConfidentialTxMultiImpl).
            const int total_outputs = std::max<int>(static_cast<int>(recipients.size()) + 1, 3);
            out.pushKV("outputs", total_outputs);
            out.pushKV("total_sent", ValueFromAmount(total_sent));
            out.pushKV("fee", ValueFromAmount(fee));
            return out;
        }
    };
}

RPCMethod walletsendct_locked()
{
    return RPCMethod{
        "walletsendct_locked",
        "Build and sign a Pricoin Confidential Transaction with an explicit\n"
        "block-height nLockTime, but do NOT broadcast it. Returns the raw hex\n"
        "for the caller to broadcast (or hand to a counterparty) once the\n"
        "lock height has been reached.\n"
        "\n"
        "Primary use: the refund leg of an atomic swap. The funder pre-signs\n"
        "a tx that returns funds to themselves, with `lock_height` set far\n"
        "enough in the future that the swap counterparty has time to claim.\n"
        "Mempool acceptance enforces nLockTime, so the refund cannot be\n"
        "confirmed before the deadline.\n"
        "\n"
        "The wallet does NOT track the not-yet-broadcast tx, so the inputs\n"
        "remain visible to subsequent walletsendct calls — be careful not to\n"
        "spend the same UTXOs twice. (A future version may add a lock-and-\n"
        "reserve flag.)\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO,
             "Pricoin stealth (H6...) or transparent bech32 destination"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount in PRIC"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Transparent fee in PRIC"},
            {"lock_height", RPCArg::Type::NUM, RPCArg::Optional::NO,
             "Block height before which the tx cannot be confirmed (nLockTime)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "Signed transaction (raw hex)"},
                {RPCResult::Type::STR_HEX, "txid", "Resulting transaction id"},
                {RPCResult::Type::NUM, "lock_height", "nLockTime baked into the tx"},
            }
        },
        RPCExamples{
            HelpExampleCli("walletsendct_locked", "\"H6...\" 1.0 0.0001 1500")
        },
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;
            const std::string dest = request.params[0].get_str();
            const CAmount amount = AmountFromValue(request.params[1]);
            const CAmount fee = AmountFromValue(request.params[2]);
            const int lock_height = request.params[3].getInt<int>();
            if (lock_height < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "lock_height must be >= 0");
            }
            // BIP65 reads nLockTime as a height when below LOCKTIME_THRESHOLD
            // (5e8). We don't support time-based locks here — privacy chains
            // that reorg PoW timestamps shouldn't anchor refunds to wall time.
            constexpr int kLockTimeHeightMax = 499'999'999;
            if (lock_height > kLockTimeHeightMax) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("lock_height must be <= %d (height interpretation)",
                              kLockTimeHeightMax));
            }
            std::vector<PricoinCTRecipient> recipients{
                PricoinCTRecipient{.address = dest, .amount = amount, .ephemeral_priv = {}}};
            std::string hex;
            auto res = detail::SendConfidentialTxMultiImpl(
                wallet, std::span<const PricoinCTRecipient>{recipients}, fee,
                lock_height, &hex);
            if (!res) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(res).original);
            UniValue out{UniValue::VOBJ};
            out.pushKV("hex", hex);
            out.pushKV("txid", res->ToString());
            out.pushKV("lock_height", lock_height);
            return out;
        }
    };
}

} // namespace anonymous

namespace detail {

// Resolved per-output stealth/transparent material.
struct ResolvedDest {
    CScript spk;
    ::pricoin::stealth::PointBytes R{};         // tx_pubkey for stealth; zero for transparent
    ::pricoin::ct::BlindingFactor nonce{};      // rangeproof nonce
    ::pricoin::ct::SerializedPubKey33 otp{};    // one-time pubkey for stealth; zero for transparent
};

// Resolve a single recipient address (stealth H6... or transparent bech32)
// into the script + per-output stealth material at the given output index.
//
// `pinned_ephemeral_priv` (optional): if non-empty, use this 32-byte priv
// as the stealth-output ephemeral `r` instead of generating a fresh one.
// This is required for the atomic-swap flow where Bob's adaptor binding
// commits to a specific `r` (via P_pi = h_s·G + B with h_s = SHA(r·A_joint
// || index)). Funding the joint stealth with a different ephemeral makes
// the on-chain P_pi diverge from the adaptor binding and the swap becomes
// unsignable.
util::Result<ResolvedDest> ResolveDest(
    const std::string& addr,
    uint32_t output_index,
    const std::vector<unsigned char>& pinned_ephemeral_priv = {})
{
    ResolvedDest d;
    const auto parsed = ::pricoin::stealth::ParseStealthAddress(addr);
    if (parsed) {
        CKey r;
        if (!pinned_ephemeral_priv.empty()) {
            if (pinned_ephemeral_priv.size() != 32) {
                return util::Error{Untranslated("pinned ephemeral_priv must be 32 bytes")};
            }
            r.Set(pinned_ephemeral_priv.begin(), pinned_ephemeral_priv.end(),
                   /*fCompressed=*/true);
            if (!r.IsValid()) {
                return util::Error{Untranslated("pinned ephemeral_priv is not a valid secp256k1 scalar")};
            }
        } else {
            r.MakeNewKey(/*fCompressed=*/true);
        }
        // R = r·G for main, r·B_i for subaddress. The receiver scan
        // formula S = a·R is identical in both cases.
        const auto R_bytes = ::pricoin::stealth::ComputeStealthR(
            r, parsed->address, parsed->kind);
        if (!R_bytes) return util::Error{Untranslated("stealth R derivation failed")};
        std::memcpy(d.R.data(), R_bytes->data(), 33);
        auto S = ::pricoin::stealth::ECDHPoint(r, parsed->address.view);
        if (!S) return util::Error{Untranslated("stealth ECDH failed")};
        auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, output_index);
        auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, parsed->address.spend);
        if (!P) return util::Error{Untranslated("stealth onetime pubkey failed")};
        d.spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
        std::memcpy(d.otp.data(), P->data(), 33);
        auto rp_nonce = ::pricoin::stealth::DeriveRangeProofNonce(*S, output_index);
        std::memcpy(d.nonce.data(), rp_nonce.data(), 32);
    } else {
        CTxDestination dest = DecodeDestination(addr);
        if (!IsValidDestination(dest)) {
            return util::Error{Untranslated("invalid address (neither stealth nor bech32)")};
        }
        d.spk = GetScriptForDestination(dest);
        GetRandBytes(d.nonce);
        // d.R and d.otp stay zero — scanner skips outputs whose tx_pubkey is all-zero.
    }
    return d;
}

// Multi-recipient v4 builder. recipients[].address may mix stealth and
// transparent; each recipient gets its own one-time output, change goes
// to the wallet's own stealth identity at output index N.
//
// `lock_height`: nLockTime to set on the resulting transaction. 0 means
// "spendable immediately"; a non-zero value enforces a height-based
// lock (Bitcoin Core's IsFinalTx gate). Used by atomic-swap refund
// flows where the funder pre-signs a "give it back" tx that the chain
// can't confirm until block H.
//
// `hex_out`: if non-null, the caller wants the signed tx as raw hex
// for offline use (typical: hand to a counterparty who will broadcast
// it later, or stash for the timeout path of an atomic swap). When
// non-null, the function builds + signs but does NOT broadcast or add
// to the wallet's mapWallet. When null, the function commits and
// broadcasts as before.
util::Result<uint256> SendConfidentialTxMultiImpl(
    CWallet& wallet,
    std::span<const PricoinCTRecipient> recipients,
    CAmount fee,
    int32_t lock_height,
    std::string* hex_out)
{
    CAmount total_dest = 0;
    for (size_t i = 0; i < recipients.size(); ++i) {
        const auto& rcp = recipients[i];
        if (rcp.amount <= 0) {
            return util::Error{Untranslated(strprintf("recipient %u: non-positive amount", i))};
        }
        if (rcp.amount > MAX_MONEY - total_dest) {
            return util::Error{Untranslated("total recipient amount overflows MAX_MONEY")};
        }
        total_dest += rcp.amount;
    }
    const CAmount target = total_dest + fee;

    // Pick UTXOs for Σamounts + fee.
    std::optional<std::vector<PickedInput>> picked;
    {
        LOCK(wallet.cs_wallet);
        picked = PickP2WPKHFunding(wallet, target);
        if (!picked) {
            return util::Error{Untranslated("insufficient spendable P2WPKH balance for sum(amounts) + fee")};
        }
    }
    CAmount input_total = 0;
    for (const auto& p : *picked) input_total += p.value;
    const CAmount change_value = input_total - target;

    // Build the full output set (recipients + change-to-self) and shuffle so
    // the change is at a random position. Otherwise an external observer can
    // identify change as "always last", linking the sender's outputs across
    // their transaction history.
    struct PendingOut {
        std::string address;
        CAmount amount;
        std::vector<unsigned char> ephemeral_priv;
    };
    std::vector<PendingOut> pending;
    pending.reserve(recipients.size() + 2);
    for (const auto& r : recipients) {
        pending.push_back({r.address, r.amount, r.ephemeral_priv});
    }
    const auto& self_id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
    const std::string self_addr = ::pricoin::stealth::Encode(self_id.public_address);
    pending.push_back({self_addr, change_value, {}});

    // PRIVACY: pad to at least 3 outputs so the change isn't 1/2 observable.
    // The 1-recipient case was emitting (recipient, change) — two outputs of
    // identical shape, so an external observer assigned change with 50/50
    // confidence. Padding with a 0-value self-output drops that to 1/3, and
    // with the other two outputs hidden by Pedersen+rangeproof an observer
    // can't tell value=0 from value>0 anyway. The decoy goes to the wallet's
    // own stealth address so the wallet recovers it on scan (as a 0-PRIC
    // entry that ConfidentialBalance and walletsendct_from_ct ignore).
    // Multi-recipient sends already have ≥3 outputs and need no padding.
    while (pending.size() < 3) {
        pending.push_back({self_addr, 0, {}});
    }

    FastRandomContext rng;
    std::shuffle(pending.begin(), pending.end(), rng);

    // Per-output stealth derivation must use the FINAL position, because the
    // recipient scans by trying each vout's index when computing the
    // shared-secret tweak — output_index is part of the rewind nonce.
    std::vector<ResolvedDest> dests;
    dests.reserve(pending.size());
    for (size_t i = 0; i < pending.size(); ++i) {
        auto rd = ResolveDest(pending[i].address, static_cast<uint32_t>(i),
                                pending[i].ephemeral_priv);
        if (!rd) return util::Error{Untranslated(strprintf("output %u: %s", i, util::ErrorString(rd).original))};
        dests.push_back(std::move(*rd));
    }

    // Each transparent prevout commits to its value with a zero blinding
    // factor, so Σ(input_blinds) = 0 regardless of N inputs.
    pricoin::ct::BlindingFactor zero_blind{};
    std::vector<pricoin::ct::Commitment> in_commits;
    in_commits.reserve(picked->size());
    for (const auto& p : *picked) {
        auto c = pricoin::ct::Commitment::Create(
            static_cast<uint64_t>(p.value), zero_blind);
        if (!c) return util::Error{Untranslated("input commit failed")};
        in_commits.push_back(*c);
    }

    // Random blinds for all but one slot; the remaining slot gets the
    // balancing blind so Σ(output_blinds) = 0. Pedersen blinds are
    // statistically uniform, so which slot is balancing is unobservable —
    // the change slot is no more identifiable than any other.
    const size_t N = pending.size();
    std::vector<pricoin::ct::BlindingFactor> blinds(N);
    for (size_t i = 0; i + 1 < N; ++i) GetRandBytes(blinds[i]);
    {
        std::span<const pricoin::ct::BlindingFactor> other_outs{blinds.data(), N - 1};
        auto last_blind = pricoin::ct::BalancingBlind(
            std::array<pricoin::ct::BlindingFactor, 1>{zero_blind},
            other_outs);
        if (!last_blind) return util::Error{Untranslated("blind sum failed")};
        blinds.back() = *last_blind;
    }

    std::vector<pricoin::ct::CTOutput> ct_outputs;
    ct_outputs.reserve(N);
    for (size_t i = 0; i < N; ++i) {
        auto commit = pricoin::ct::Commitment::Create(
            static_cast<uint64_t>(pending[i].amount), blinds[i]);
        if (!commit) return util::Error{Untranslated(strprintf("output %u commit failed", i))};
        std::vector<unsigned char> spk_bytes(dests[i].spk.begin(), dests[i].spk.end());
        auto proof = pricoin::ct::CreateRangeProof(
            static_cast<uint64_t>(pending[i].amount), blinds[i], *commit,
            std::span<const unsigned char>{spk_bytes}, dests[i].nonce);
        if (!proof) return util::Error{Untranslated(strprintf("output %u rangeproof failed", i))};
        ct_outputs.push_back(pricoin::ct::CTOutput{
            *commit, *proof, std::move(spk_bytes), dests[i].R, dests[i].otp});
    }

    pricoin::ct::CTBundle bundle;
    bundle.input_commitments = std::move(in_commits);
    bundle.outputs = std::move(ct_outputs);
    bundle.transparent_fee = static_cast<uint64_t>(fee);

    CMutableTransaction mtx;
    mtx.version = PRICOIN_CT_VERSION;
    // Height-based lock when requested; otherwise default-final.
    // IsFinalTx interprets nLockTime < LOCKTIME_THRESHOLD (5e8) as a
    // block height, so passing a height directly is correct. nLockTime
    // is honoured iff at least one vin's nSequence is < 0xffffffff;
    // the existing 0xfffffffe (final-but-RBF-eligible) qualifies.
    mtx.nLockTime = (lock_height > 0) ? static_cast<uint32_t>(lock_height) : 0u;
    for (const auto& p : *picked) {
        mtx.vin.emplace_back(p.outpoint, CScript{}, 0xfffffffe);
    }
    for (size_t i = 0; i < N; ++i) {
        mtx.vout.emplace_back(0, dests[i].spk);
    }
    mtx.ct_bundle = std::move(bundle);

    std::map<COutPoint, Coin> coins;
    for (const auto& p : *picked) {
        Coin prev_coin;
        prev_coin.out = CTxOut{p.value, p.scriptPubKey};
        prev_coin.fCoinBase = false;
        prev_coin.nHeight = 0;
        coins.emplace(p.outpoint, std::move(prev_coin));
    }

    std::map<int, bilingual_str> input_errors;
    if (!wallet.SignTransaction(mtx, coins, SIGHASH_ALL, input_errors)) {
        std::string msg;
        for (const auto& [i, e] : input_errors) msg += strprintf("vin[%d]: %s; ", i, e.original);
        return util::Error{Untranslated("wallet failed to sign tx: " + msg)};
    }

    CTransactionRef tx_ref = MakeTransactionRef(std::move(mtx));
    if (hex_out) {
        // Build-only mode: caller broadcasts (or doesn't) on its own.
        // Don't CommitTransaction — that would add a tx the wallet can't
        // yet confirm into mapWallet, polluting balance accounting.
        DataStream ssTx;
        ssTx << TX_WITH_WITNESS(*tx_ref);
        *hex_out = HexStr(ssTx);
        return tx_ref->GetHash().ToUint256();
    }
    wallet.CommitTransaction(tx_ref, /*mapValue=*/{}, /*orderForm=*/{});
    return tx_ref->GetHash().ToUint256();
}

} // namespace detail

RPCMethod walletsendct_export() { return walletsendct(); }
RPCMethod walletsendct_multi_export() { return walletsendct_multi(); }
RPCMethod walletsendct_locked_export() { return walletsendct_locked(); }

namespace {

// Try to recover a CT output for a given wallet stealth identity. Returns
// nullopt if the output is not addressed to us (fast path: scriptPubKey
// mismatch). On match, returns the recovered (value, blind, output_index)
// plus enough material to spend the output later.
struct RecoveredOutput {
    uint32_t output_index;
    CAmount value;
    pricoin::ct::BlindingFactor blind;
    pricoin::ct::Commitment commitment;
    CScript scriptPubKey;
    CKey one_time_priv; // derived spend key for this output
    pricoin::ringsig::Point key_image{}; // I = x · H_p(P) — for spent-by-KI lookup
    // Subaddress this output paid: 0 == master, ≥1 == subaddress index.
    // The scanner sets this from the matched B-point lookup; downstream
    // RPCs surface it so exchanges can attribute deposits to users.
    uint32_t subaddress_index{0};
};

std::optional<RecoveredOutput> TryRecoverCTOutput(
    const ::wallet::pricoin_stealth::Identity& id,
    const ::wallet::pricoin_stealth::SubaddressLookup& lookup,
    const CTransaction& tx,
    uint32_t output_index)
{
    if (tx.version != PRICOIN_CT_VERSION) return std::nullopt;
    if (output_index >= tx.ct_bundle.outputs.size()) return std::nullopt;
    if (output_index >= tx.vout.size()) return std::nullopt;

    const auto& out = tx.ct_bundle.outputs[output_index];
    // tx_pubkey of all zeros means non-stealth output — skip.
    bool all_zero = true;
    for (auto b : out.tx_pubkey) { if (b != 0) { all_zero = false; break; } }
    if (all_zero) return std::nullopt;

    CPubKey R(std::span<const unsigned char>{out.tx_pubkey.data(), out.tx_pubkey.size()});
    if (!R.IsValid()) return std::nullopt;

    // Validate the on-chain one_time_pubkey before using it to recover
    // B_candidate. If P_observed doesn't hash to the script's WitnessV0
    // keyhash, the output isn't a recognised stealth payment and we
    // skip without doing further crypto work.
    CPubKey P_observed(std::span<const unsigned char>{
        out.one_time_pubkey.data(), out.one_time_pubkey.size()});
    if (!P_observed.IsValid()) return std::nullopt;
    const CScript expected_spk = GetScriptForDestination(WitnessV0KeyHash{P_observed.GetID()});
    if (tx.vout[output_index].scriptPubKey != expected_spk) return std::nullopt;

    auto S = ::pricoin::stealth::ECDHPoint(id.view, R);
    if (!S) return std::nullopt;
    auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, output_index);

    // Recover B_candidate = P_observed − shared·G and look it up in the
    // wallet's known-B map. Master matches at index 0; subaddresses
    // match at their own index. Miss => not addressed to us.
    auto B_candidate = ::pricoin::stealth::RecoverSpendPointFromOneTime(P_observed, shared);
    if (!B_candidate) return std::nullopt;
    auto it = lookup.by_b_point.find(*B_candidate);
    if (it == lookup.by_b_point.end()) return std::nullopt;
    const ::wallet::pricoin_stealth::SubaddressLookupEntry& match = it->second;

    // Rewind the rangeproof using the per-output nonce.
    auto nonce = ::pricoin::stealth::DeriveRangeProofNonce(*S, output_index);
    pricoin::ct::BlindingFactor nonce_arr{};
    std::memcpy(nonce_arr.data(), nonce.data(), 32);
    const auto& script = out.script_pubkey;
    auto rewound = pricoin::ct::RewindRangeProof(
        out.commitment,
        std::span<const unsigned char>{out.rangeproof.data(), out.rangeproof.size()},
        std::span<const unsigned char>{script.data(), script.size()},
        nonce_arr);
    if (!rewound) return std::nullopt;

    // p = shared + b_match. b_match is master b for index 0, b_i for i ≥ 1
    // — pre-derived in BuildSubaddressLookup.
    auto one_time_priv = ::pricoin::stealth::DeriveOneTimePriv(shared, match.spend_priv);
    if (!one_time_priv) return std::nullopt;

    // Compute the key image for this output — needed to detect whether
    // it has been spent on chain (the KI would appear in the global set).
    pricoin::ringsig::Point P_bytes{};
    std::memcpy(P_bytes.data(), P_observed.data(), 33);
    pricoin::ringsig::Scalar x_bytes{};
    std::memcpy(x_bytes.data(), one_time_priv->begin(), 32);
    auto ki = pricoin::ringsig::ComputeKeyImage(P_bytes, x_bytes);
    if (!ki) return std::nullopt;

    return RecoveredOutput{
        .output_index = output_index,
        .value = static_cast<CAmount>(rewound->value),
        .blind = rewound->blind,
        .commitment = out.commitment,
        .scriptPubKey = tx.vout[output_index].scriptPubKey,
        .one_time_priv = std::move(*one_time_priv),
        .key_image = *ki,
        .subaddress_index = match.index,
    };
}

// Per-wallet incremental scan cache. Without this, every
// pricoin_listownct / ConfidentialBalance / GUI balance refresh
// re-walks the entire chain and re-tries rangeproof rewind on every v4
// output. That's O(blocks * outputs_per_block * rangeproof_cost) per
// call — fine on a 100-block regtest, painful on a 100k-block live
// chain. The cache walks each block at most once per daemon run; after
// the first scan, subsequent calls only sweep the new tip-extension.
//
// Reorg handling: lazy. If our remembered scan-tip's hash no longer
// matches what's on the active chain at that height, we discard the
// cache and rescan from genesis. A more surgical "rewind to common
// ancestor" is possible but adds complexity for a path that's rare in
// practice (and that v4 chains may even reject — invalidateblock at
// depth doesn't compose well with the KI committed-set).
//
// Persisted as DBKeys::PRICOIN_RECOVERY_CACHE. Restoring the cache on
// startup avoids re-walking the full chain after every daemon restart
// — for a wallet with many recoveries on a long chain that's the
// difference between "wait several seconds for the first balance call"
// and "immediate".
//
// On-disk format (inside the encrypted wallet blob — see
// pricoin_stealth::EncryptWalletBlob, which gives the same at-rest
// posture as the stealth seed: encrypted + HMAC if the wallet is
// encrypted, plaintext-with-version-byte otherwise):
//
//   [INNER_VER:1]              version of THIS payload format
//   [last_scanned_height:i32]  little-endian
//   [last_scanned_hash:32]
//   [num_entries:varint]       compact size
//   [entry]*
//
// Each entry (89 bytes for v2):
//   [txid:32][vout:u32 LE][output_index:u32 LE]
//   [value:i64 LE][key_image:33][height:i32 LE][subaddress_index:u32 LE]
//
// Reorg detection still fires on load — if the chain at last_scanned_height
// no longer hashes to last_scanned_hash, the deserialised cache is
// dropped and a full fresh scan runs. The persisted cache is best-effort:
// missing it (corruption, wrong key, or wallet locked at scan time) just
// means a one-time full rescan on next access.
//
// v0x01: pre-subaddress format. Loaders skip v1 caches and force a full
//        rescan — they predate the subaddress lookup, and re-deriving the
//        index for old cached entries would require a chain re-walk anyway.
// v0x02: adds subaddress_index per entry.
constexpr unsigned char kRecoveryCacheInnerVer = 0x02;

struct CachedRecovery {
    uint32_t output_index{0};
    CAmount value{0};
    pricoin::ringsig::Point key_image{};
    int height{0};
    uint32_t subaddress_index{0};
};
struct CTRecoveryIndex {
    std::map<COutPoint, CachedRecovery> entries;
    int last_scanned_height{-1};
    uint256 last_scanned_hash{};
    bool persisted_load_attempted{false};
    btcsignals::scoped_connection unload_conn{btcsignals::connection{}};
};
Mutex g_recovery_index_mutex;
std::map<const CWallet*, CTRecoveryIndex> g_recovery_indices GUARDED_BY(g_recovery_index_mutex);

struct SyncStats {
    int new_blocks_scanned{0};
    bool reorg_detected{false};
};

// Serialise the in-memory index to the inner-payload format documented
// above. Caller passes through EncryptWalletBlob to get the encrypted
// DB blob.
std::vector<unsigned char> SerializeRecoveryIndex(const CTRecoveryIndex& index)
{
    DataStream ds;
    ds << kRecoveryCacheInnerVer;
    ds << static_cast<int32_t>(index.last_scanned_height);
    ds << index.last_scanned_hash;
    WriteCompactSize(ds, index.entries.size());
    for (const auto& [outpoint, rec] : index.entries) {
        ds << outpoint;
        ds << rec.output_index;
        ds << static_cast<int64_t>(rec.value);
        ds.write(std::as_bytes(std::span{rec.key_image.data(), rec.key_image.size()}));
        ds << static_cast<int32_t>(rec.height);
        ds << rec.subaddress_index;
    }
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(ds.data()),
        reinterpret_cast<const unsigned char*>(ds.data()) + ds.size());
}

bool DeserializeRecoveryIndex(std::span<const unsigned char> bytes,
                              CTRecoveryIndex& index)
{
    DataStream ds;
    ds.write(std::as_bytes(std::span{bytes.data(), bytes.size()}));
    try {
        uint8_t inner_ver;
        ds >> inner_ver;
        if (inner_ver != kRecoveryCacheInnerVer) return false;
        int32_t last_height;
        ds >> last_height;
        index.last_scanned_height = last_height;
        ds >> index.last_scanned_hash;
        const uint64_t n = ReadCompactSize(ds);
        // Sanity bound: a wallet on a busy chain might accumulate
        // tens of thousands of recoveries, but a million in one wallet
        // is implausible and would bloat the encrypted blob unhelpfully.
        if (n > 1'000'000) return false;
        for (uint64_t i = 0; i < n; ++i) {
            COutPoint outpoint;
            ds >> outpoint;
            CachedRecovery cr;
            ds >> cr.output_index;
            int64_t value;
            ds >> value;
            cr.value = value;
            ds.read(std::as_writable_bytes(
                std::span{cr.key_image.data(), cr.key_image.size()}));
            int32_t height;
            ds >> height;
            cr.height = height;
            ds >> cr.subaddress_index;
            index.entries[outpoint] = cr;
        }
        return true;
    } catch (const std::exception&) {
        // Malformed payload — likely a partial / wrong-format read.
        // Caller drops the cache and rebuilds via fresh scan.
        index.entries.clear();
        index.last_scanned_height = -1;
        index.last_scanned_hash = uint256{};
        return false;
    }
}

void PersistRecoveryIndex(CWallet& wallet, const CTRecoveryIndex& index)
{
    std::vector<unsigned char> payload = SerializeRecoveryIndex(index);
    std::vector<unsigned char> blob;
    if (!::wallet::pricoin_stealth::EncryptWalletBlob(wallet, payload, blob)) {
        // Wallet locked, or other transient encryption failure. Skip
        // the persistence — in-memory cache still works; we'll retry
        // on the next sync that actually scans new blocks.
        return;
    }
    WalletBatch batch(wallet.GetDatabase());
    batch.WritePricoinRecoveryCache(blob);
}

bool LoadPersistedRecoveryIndex(CWallet& wallet, CTRecoveryIndex& index)
{
    std::vector<unsigned char> blob;
    {
        WalletBatch batch(wallet.GetDatabase());
        if (!batch.ReadPricoinRecoveryCache(blob) || blob.empty()) return false;
    }
    std::vector<unsigned char> payload;
    try {
        if (!::wallet::pricoin_stealth::DecryptWalletBlob(wallet, blob, payload)) {
            // Bad-MAC / wrong key / corrupt. Fall through to full rescan.
            return false;
        }
    } catch (const std::exception&) {
        // Wallet locked: can't decrypt now. Caller treats as
        // "no cache available" and will retry once unlocked.
        return false;
    }
    return DeserializeRecoveryIndex(payload, index);
}

// Caller MUST hold g_recovery_index_mutex.
CTRecoveryIndex& SyncRecoveryIndexLocked(CWallet& wallet, SyncStats* stats = nullptr)
    EXCLUSIVE_LOCKS_REQUIRED(g_recovery_index_mutex)
{
    auto [it, inserted] = g_recovery_indices.try_emplace(&wallet);
    if (inserted) {
        // Drop our cache the moment the wallet is unloaded — see the
        // matching pattern in pricoin_stealth::GetOrCreate. Without it
        // the raw CWallet* would dangle into the next wallet allocated
        // at the same heap address.
        CWallet* wallet_ptr = &wallet;
        it->second.unload_conn = wallet.NotifyUnload.connect([wallet_ptr]() {
            LOCK(g_recovery_index_mutex);
            g_recovery_indices.erase(wallet_ptr);
        });
    }
    auto& index = it->second;

    // First call against this wallet (in-process): try to restore the
    // persisted cache from wallet.dat. If it loads cleanly, skip the
    // expensive full-chain rescan that would otherwise run. Treat any
    // failure (no record, corrupt, locked, etc.) as "no cache" — the
    // scan loop below will rebuild from genesis.
    if (!index.persisted_load_attempted) {
        index.persisted_load_attempted = true;
        LoadPersistedRecoveryIndex(wallet, index);
    }

    interfaces::Chain& chain = wallet.chain();
    const int tip_height = chain.getHeight().value_or(-1);
    if (tip_height < 0) return index;

    // Reorg detection: tip went backwards, OR our remembered scan tip's
    // hash no longer matches the active chain at that height.
    bool needs_full_rescan = false;
    if (index.last_scanned_height > tip_height) {
        needs_full_rescan = true;
    } else if (index.last_scanned_height >= 0) {
        const uint256 expected_hash = chain.getBlockHash(index.last_scanned_height);
        if (expected_hash != index.last_scanned_hash) {
            needs_full_rescan = true;
        }
    }
    if (needs_full_rescan) {
        index.entries.clear();
        index.last_scanned_height = -1;
        index.last_scanned_hash = uint256{};
        if (stats) stats->reorg_detected = true;
    }

    if (index.last_scanned_height >= tip_height) return index;

    // GetOrCreate primes the in-memory stealth identity if it isn't
    // already there. May throw if the wallet is encrypted+locked — in
    // that case we can't scan, and the exception propagates to the RPC
    // caller (matches pre-existing pricoin_listownct semantics).
    const auto& id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
    // Build the subaddress lookup once per sync pass — cheap for
    // master-only wallets and amortised across the block walk.
    const auto subaddr_lookup = ::wallet::pricoin_stealth::BuildSubaddressLookup(wallet);

    int new_blocks = 0;
    for (int h = index.last_scanned_height + 1; h <= tip_height; ++h) {
        const uint256 block_hash = chain.getBlockHash(h);
        CBlock block;
        if (!chain.findBlock(block_hash, interfaces::FoundBlock().data(block))) continue;
        ++new_blocks;
        for (const auto& tx_ref : block.vtx) {
            if (tx_ref->version != PRICOIN_CT_VERSION) continue;
            for (uint32_t i = 0; i < tx_ref->vout.size(); ++i) {
                auto rec = TryRecoverCTOutput(id, subaddr_lookup, *tx_ref, i);
                if (!rec) continue;
                CachedRecovery cr;
                cr.output_index = rec->output_index;
                cr.value = rec->value;
                cr.key_image = rec->key_image;
                cr.height = h;
                cr.subaddress_index = rec->subaddress_index;
                index.entries[COutPoint{tx_ref->GetHash(), rec->output_index}] = cr;
                // Restore-mode gap discovery: a payment past the
                // wallet's current ceiling bumps max_used_index so
                // future scans (and the subaddress lookup) include it.
                ::wallet::pricoin_stealth::NoteSubaddressDiscovered(
                    wallet, rec->subaddress_index);
            }
        }
        index.last_scanned_height = h;
        index.last_scanned_hash = block_hash;
    }
    if (new_blocks > 0) {
        LogDebug(BCLog::WALLETDB, "Pricoin: scanned %d new block(s) for wallet %s; %u total recoveries cached\n",
                 new_blocks, wallet.GetName(), (unsigned)index.entries.size());
        // Persist the freshly-extended index so the next daemon
        // startup doesn't have to re-walk the whole chain. Best-effort:
        // a write failure (wallet locked at this moment, etc.) is
        // logged but doesn't fail the sync — the in-memory cache still
        // serves this session.
        PersistRecoveryIndex(wallet, index);
    }
    if (stats) stats->new_blocks_scanned = new_blocks;
    return index;
}

RPCMethod pricoin_listownct()
{
    return RPCMethod{
        "pricoin_listownct",
        "Scan confirmed blocks (and the mempool) for confidential outputs addressed to this wallet's\n"
        "stealth identity (master + any subaddresses), recovering their hidden values via rangeproof\n"
        "rewind. Each row reports the subaddress index it paid (0 == master) and, for non-master\n"
        "deposits, the encoded subaddress so callers can attribute funds without an extra lookup.\n",
        {
            {"startheight", RPCArg::Type::NUM, RPCArg::Default{0}, "Block height to start scanning from"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "scanned_blocks", "How many blocks were scanned"},
                {RPCResult::Type::NUM, "scanned_mempool_txs", "How many mempool txs were scanned"},
                {RPCResult::Type::STR_AMOUNT, "total_recovered", "Total PRIC recovered as ours"},
                {RPCResult::Type::ARR, "outputs", "Per-output recoveries",
                    {{RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", ""},
                            {RPCResult::Type::NUM, "vout", ""},
                            {RPCResult::Type::STR_AMOUNT, "value", "Recovered amount in PRIC"},
                            {RPCResult::Type::NUM, "height", "Block height (-1 if mempool)"},
                            {RPCResult::Type::NUM, "subaddress_index",
                                "Subaddress index that received this output (0 == master)"},
                            {RPCResult::Type::STR, "subaddress",
                                "Encoded subaddress (pricsub-prefixed); empty when subaddress_index == 0"},
                        }}}}
            }
        },
        RPCExamples{HelpExampleCli("pricoin_listownct", "")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;
            const int startheight = request.params[0].isNull() ? 0 : request.params[0].getInt<int>();

            // Sync the per-wallet recovery cache with the chain. First
            // call after daemon restart pays a full scan; subsequent
            // calls only walk the new tip-extension (and don't redo
            // rangeproof rewinds for already-known recoveries).
            UniValue outputs{UniValue::VARR};
            CAmount total_recovered = 0;
            int scanned_blocks = 0;
            {
                LOCK(g_recovery_index_mutex);
                SyncStats sync_stats;
                CTRecoveryIndex& index = SyncRecoveryIndexLocked(wallet, &sync_stats);
                // Report only what was newly scanned in *this* call (0 on
                // a warm cache). The cache itself spans 0..tip; downstream
                // monitoring uses scanned_blocks to detect cache hits.
                scanned_blocks = sync_stats.new_blocks_scanned;
                // Phase 3a: chainstate-erasure no longer marks v4 outputs
                // spent (they're kept indefinitely as ring-decoy
                // candidates). Filter by the global key-image set —
                // an output is spent iff its KI has been committed.
                // Used to encode subaddress strings for non-master rows.
                // Building it once per RPC is fine — the master id derive
                // is cached and subaddress derivation is sub-microsecond.
                const auto& wid = ::wallet::pricoin_stealth::GetOrCreate(wallet);
                for (const auto& [outpoint, rec] : index.entries) {
                    if (rec.height < startheight) continue;
                    if (pricoin::IsKeyImageCommitted(rec.key_image)) continue;
                    // Wallet-local broadcasted-keyimage filter (2026-
                    // 05-13 tightening): any recorded broadcast for
                    // this KI hides the output from balance/listing,
                    // mempool or mined alike. The prior "show if
                    // mempool-only" carve-out caused stale-mempool
                    // outputs to surface as spendable balance only to
                    // fail at broadcast.
                    if (::wallet::pricoin_broadcasted_kis::Lookup(
                            wallet, rec.key_image)) {
                        continue;
                    }
                    // Chain-mempool check — catches mempool entries
                    // we didn't broadcast (other wallet / external
                    // tool). See walletsendct_ring picker for the
                    // detailed rationale.
                    if (wallet.chain().isPricoinKeyImageInMempool(
                            std::span<const unsigned char, 33>{
                                rec.key_image.data(), 33})) {
                        continue;
                    }
                    total_recovered += rec.value;
                    UniValue entry{UniValue::VOBJ};
                    entry.pushKV("txid", outpoint.hash.ToString());
                    entry.pushKV("vout", (int)outpoint.n);
                    entry.pushKV("value", ValueFromAmount(rec.value));
                    entry.pushKV("height", rec.height);
                    entry.pushKV("subaddress_index", (uint64_t)rec.subaddress_index);
                    std::string sub_enc;
                    if (rec.subaddress_index != 0) {
                        if (auto sa = ::pricoin::stealth::DeriveSubaddressPublic(
                                wid.view, wid.public_address.spend, rec.subaddress_index)) {
                            sub_enc = ::pricoin::stealth::EncodeSubaddress(
                                sa->public_address, sa->index);
                        }
                    }
                    entry.pushKV("subaddress", sub_enc);
                    outputs.push_back(entry);
                }
            }
            int scanned_mempool = 0;
            // Mempool sweep is omitted in this MVP — interfaces::Chain doesn't
            // expose entry iteration. A confirmed-only scan is sufficient to
            // demonstrate Phase 5e end-to-end.

            UniValue out{UniValue::VOBJ};
            out.pushKV("scanned_blocks", scanned_blocks);
            out.pushKV("scanned_mempool_txs", scanned_mempool);
            out.pushKV("total_recovered", ValueFromAmount(total_recovered));
            out.pushKV("outputs", outputs);
            return out;
        }
    };
}

// Given an outpoint that's known to be a recovered own output (per
// the recovery cache), fetch the underlying transaction and re-derive
// the full RecoveredOutput — including the blind and one_time_priv
// that the cache deliberately omits (cache stores enough to identify
// "is this mine? has it been spent?" but not enough to spend; signing
// material is rederived on demand). Returns nullopt if the tx is no
// longer on the active chain at the cached height (reorg-induced
// stale entry — caller drops the cache and resyncs).
std::optional<RecoveredOutput> RehydrateRecovery(
    const ::wallet::pricoin_stealth::Identity& id,
    const ::wallet::pricoin_stealth::SubaddressLookup& lookup,
    interfaces::Chain& chain,
    const COutPoint& outpoint,
    int height)
{
    const uint256 block_hash = chain.getBlockHash(height);
    CBlock block;
    if (!chain.findBlock(block_hash, interfaces::FoundBlock().data(block))) return std::nullopt;
    for (const auto& tx_ref : block.vtx) {
        if (tx_ref->GetHash() != outpoint.hash) continue;
        return TryRecoverCTOutput(id, lookup, *tx_ref, outpoint.n);
    }
    return std::nullopt;
}

// Helper: collect all v4 stealth outputs in confirmed blocks. Returns
// (outpoint, commitment, one_time_pubkey, height) for each — usable as ring
// members. Height is needed by the decoy sampler so it can bias toward
// recent outputs (real spends are concentrated in a recent age band; decoys
// drawn uniformly over all history would let an analyst identify the real
// spend by its age stand-out).
struct ChainCTOutput {
    pricoin::ct::PrevoutRef ref;
    pricoin::ct::Commitment commitment;
    pricoin::ct::SerializedPubKey33 one_time_pubkey;
    int height{0};
};

std::vector<ChainCTOutput> CollectChainCTOutputs(interfaces::Chain& chain)
{
    std::vector<ChainCTOutput> result;
    const int tip = chain.getHeight().value_or(-1);
    for (int h = 0; h <= tip; ++h) {
        const uint256 block_hash = chain.getBlockHash(h);
        CBlock block;
        if (!chain.findBlock(block_hash, interfaces::FoundBlock().data(block))) continue;
        for (const auto& tx_ref : block.vtx) {
            if (tx_ref->version != PRICOIN_CT_VERSION) continue;
            for (uint32_t i = 0; i < tx_ref->ct_bundle.outputs.size(); ++i) {
                const auto& o = tx_ref->ct_bundle.outputs[i];
                bool nonzero = false;
                for (auto b : o.one_time_pubkey) { if (b != 0) { nonzero = true; break; } }
                if (!nonzero) continue;
                result.push_back(ChainCTOutput{
                    .ref = pricoin::ct::PrevoutRef{tx_ref->GetHash().ToUint256(), i},
                    .commitment = o.commitment,
                    .one_time_pubkey = o.one_time_pubkey,
                    .height = h,
                });
            }
        }
    }
    return result;
}

// Sample `k` decoys from `pool` weighted toward recent outputs. Uses
// weighted reservoir sampling (A-Res) with weight = 1 / (1 + age/half_life).
// This is a stop-gap approximation of the empirical spend-age distribution
// (real spends concentrate in a recent age band, with a long tail). A full
// Monero-style gamma sampler over output age is the proper next step; the
// linear-decay weighting here is a strict improvement over uniform random,
// not a finished privacy story.
//
// PRIVACY: the half-life is sampled per-call from a wide band rather than
// hardcoded. Every wallet on a fixed half-life gives an analyst a single
// recency curve to fit, and once they have it, the real spend in each
// ring stands out as the one whose age is best-explained by that curve.
// Drawing a fresh half-life per ring tx — even within one wallet's
// history — fuzzes the inference: an attacker fitting "what curve did
// this tx use?" sees a different curve every time, with a known wide
// prior. The band [864, 5760] blocks ≈ 1.5..10 days at 150s blocks
// brackets a plausible range of real spend behaviour without devolving
// into uniform-over-history (which would re-introduce the
// pre-padding-era fingerprint of "real spend is always the recent one").
//
// TODO: switch to gamma(k=19.28, scale=1.61) over log(age_seconds) once
// the chain has enough history that the empirical parameters can be
// measured. At that point the per-call randomization can be tightened
// (or replaced) to match the empirical curve.
std::vector<ChainCTOutput> SampleDecoysRecencyWeighted(
    std::vector<ChainCTOutput> pool, size_t k, int tip_height,
    FastRandomContext& cprng)
{
    if (k >= pool.size()) return pool;

    // Random half-life per call: 864..5760 blocks (1.5..10 days).
    constexpr uint32_t kHalfLifeMin = 864;
    constexpr uint32_t kHalfLifeMax = 5760;
    const double half_life_blocks = static_cast<double>(
        kHalfLifeMin + cprng.randrange(kHalfLifeMax - kHalfLifeMin + 1));

    // A-Res (Efraimidis-Spirakis) in log-space. The textbook formulation is
    // key_i = u_i^(1/w_i), pick top-k. Computing u^(1/w) directly underflows
    // to 0.0 once age pushes 1/w past ~745, collapsing all sufficiently-old
    // items to the same key and breaking the ranking. Working in log-space
    //   log(key_i) = log(u_i) / w_i
    // is monotone-equivalent (log is strictly increasing on (0, 1)) and
    // stays in double range for any age the chain can reach. Larger key
    // (== less-negative log_key) wins.
    struct KeyedIdx { double log_key; size_t idx; };
    std::vector<KeyedIdx> keyed;
    keyed.reserve(pool.size());
    for (size_t i = 0; i < pool.size(); ++i) {
        const int age = std::max(0, tip_height - pool[i].height);
        const double weight = 1.0 / (1.0 + static_cast<double>(age) / half_life_blocks);
        // u in (0, 1) — strictly open to keep log well-defined.
        const double u = (static_cast<double>(cprng.rand32()) + 1.0) /
                         (static_cast<double>(UINT32_MAX) + 2.0);
        const double log_key = std::log(u) / weight;
        keyed.push_back({log_key, i});
    }
    std::partial_sort(keyed.begin(), keyed.begin() + k, keyed.end(),
        [](const KeyedIdx& a, const KeyedIdx& b) { return a.log_key > b.log_key; });

    std::vector<ChainCTOutput> picked;
    picked.reserve(k);
    for (size_t i = 0; i < k; ++i) {
        picked.push_back(std::move(pool[keyed[i].idx]));
    }
    return picked;
}

// TODO(multi-input ring): walletsendct_ring is still single-input — picks
// one own CT output that covers (dest_amount + fee). For multi-input we'd
// build N independent ring inputs, each with its own pseudo commitment,
// CLSAG signature, and decoy set. The bundle struct already supports it
// (`ring_inputs` is a vector). Tricky bits: (1) decoy pools must avoid
// collisions across rings AND must not include any of the wallet's other
// real inputs as decoys for this tx; (2) BalancingBlind aggregates across
// N pseudo blinds vs. output blinds; (3) per-ring sig msg construction
// stays the same since it uses the tx hash. Deferred until needed.
RPCMethod walletsendct_ring()
{
    return RPCMethod{
        "walletsendct_ring",
        "Phase 4b: send a Pricoin CT transaction with sender privacy via a CLSAG ring signature.\n"
        "Hides which prev output is spent among N candidates. Funded by a single recovered CT\n"
        "output (call walletsendct first to seed) — multi-input ring spends are not yet\n"
        "supported; if you need to send more than one own CT output's worth in a single hop,\n"
        "use walletsendct_from_ct (no sender privacy) or split across multiple ring sends.\n"
        "N-1 decoys are randomly drawn from confirmed v4 stealth outputs on the chain.\n"
        "In-memory key-image set tracks double-spends.\n",
        {
            {"dest_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Destination Pricoin stealth address"},
            {"dest_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount in PRIC"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Transparent fee in PRIC"},
            {"ring_size", RPCArg::Type::NUM, RPCArg::Default{4}, "Total ring size (must have ring_size-1 decoys available)"},
            {"pinned_ephemeral_priv", RPCArg::Type::STR_HEX, RPCArg::Default{""},
                "Optional 32-byte hex secp256k1 priv to use as the per-output ephemeral r "
                "for the recipient (NOT change/decoys). Required for atomic-swap PRIC "
                "funding so on-chain P_pi matches the adaptor binding. Empty/omitted = random."},
            {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{true},
                "If false, build + sign but do NOT broadcast. Returns `tx_hex` for the caller "
                "to relay later via pricoin_ct_relay_prebuilt. Used by the atomic-swap PRIC "
                "funding flow so cooperative refund presigs can be gathered against the "
                "planned funding output before any value is locked on-chain. The wallet "
                "does NOT persist the broadcasted-KI in this mode — the relay step does it."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", ""},
                {RPCResult::Type::NUM, "ring_size", "Number of candidates"},
                {RPCResult::Type::STR_AMOUNT, "input_value", "Recovered input value (sent privately)"},
                {RPCResult::Type::STR_AMOUNT, "change_amount", "Change amount"},
                {RPCResult::Type::NUM, "size", ""},
                {RPCResult::Type::NUM, "bundle_size", ""},
                {RPCResult::Type::NUM, "recipient_vout",
                    "Post-shuffle on-chain vout of the recipient output. "
                    "Needed by atomic-swap PRIC funding so the cooperative-sign "
                    "loadshare gets the correct vout. -1 if not found (shouldn't "
                    "happen for non-empty pending list)."},
                {RPCResult::Type::STR_HEX, "tx_hex",
                    "Hex of the signed transaction. Always set; required when broadcast=false "
                    "so the caller can relay later. Same tx the broadcast=true path sends to "
                    "the network."},
                {RPCResult::Type::BOOL, "broadcast",
                    "True if the tx was broadcast (default); false when broadcast=false was "
                    "passed and the caller must relay via pricoin_ct_relay_prebuilt."},
            }
        },
        RPCExamples{HelpExampleCli("walletsendct_ring", "\"pricstl1...\" 5 0.0001 4")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;

            const std::string dest_addr_str = request.params[0].get_str();
            const CAmount dest_amount = AmountFromValue(request.params[1]);
            const CAmount fee = AmountFromValue(request.params[2]);
            const int ring_size = request.params[3].isNull() ? 4 : request.params[3].getInt<int>();
            if (ring_size < 2) throw JSONRPCError(RPC_INVALID_PARAMETER, "ring_size must be >= 2");

            // Optional pinned ephemeral for the recipient output.
            std::vector<unsigned char> pinned_eph_priv;
            if (!request.params[4].isNull()) {
                const std::string h = request.params[4].get_str();
                if (!h.empty()) {
                    if (!IsHex(h) || h.size() != 64) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "pinned_ephemeral_priv must be 32-byte hex (64 chars)");
                    }
                    pinned_eph_priv = ParseHex(h);
                }
            }
            const bool broadcast_now =
                request.params[5].isNull() ? true : request.params[5].get_bool();

            const auto parsed_dest = ::pricoin::stealth::ParseStealthAddress(dest_addr_str);
            if (!parsed_dest) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "dest_address must be a stealth address");
            const auto* stealth_dest = &parsed_dest->address;
            const auto dest_kind = parsed_dest->kind;

            const auto& id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
            interfaces::Chain& chain = wallet.chain();

            // Safety gate: refuse to broadcast while the chain is in
            // initial-block-download (IBD). The keyimage commit set
            // (g_key_images) is rebuilt as blocks reconnect — during
            // IBD it's incomplete, so IsKeyImageCommitted may return
            // false for an output that's actually already spent in a
            // higher block we haven't replayed yet. Broadcasting then
            // double-spends the output, producing a tx that any fully-
            // synced peer rejects. Wait until IBD finishes.
            if (chain.isInitialBlockDownload()) {
                throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD,
                    "Refusing to broadcast: chain is still in initial-block-"
                    "download. Wait for sync to complete — the wallet can't "
                    "reliably detect already-spent outputs until the chain's "
                    "key-image set is fully (re)committed.");
            }

            // 1. Find our recovered CT output with sufficient value via
            //    the per-wallet recovery cache. First call after a fresh
            //    daemon start pays the chain rescan; subsequent calls
            //    only walk the new tip-extension. We rehydrate the
            //    full RecoveredOutput (blind + one_time_priv) for the
            //    one entry we actually pick.
            std::optional<RecoveredOutput> picked;
            COutPoint picked_outpoint;
            int picked_height = -1;
            const CAmount target = dest_amount + fee;
            const int tip = chain.getHeight().value_or(-1);
            {
                LOCK(g_recovery_index_mutex);
                CTRecoveryIndex& index = SyncRecoveryIndexLocked(wallet);
                for (const auto& [outpoint, rec] : index.entries) {
                    if (rec.value < target) continue;
                    if (pricoin::IsKeyImageCommitted(rec.key_image)) continue;
                    // Wallet-local broadcasted-keyimage filter — defense
                    // against re-spending an input the wallet has
                    // already broadcast a spend for, even when the
                    // chain's global keyimage set is stale (e.g. after
                    // a -reindex sync race). Closes the double-spend
                    // window hit on 2026-05-11.
                    //
                    // Tighter rule (2026-05-13): once we broadcast,
                    // those inputs are off-limits to NEW spends —
                    // whether the broadcast is in mempool, mined, or
                    // evicted. The prior "RBF carve-out" (allow
                    // re-pick if prev tx is mempool-only) let the
                    // wallet build a tx that the chain mempool then
                    // had to reject as a non-signalling replacement,
                    // breaking unrelated new swaps when an old tx
                    // hadn't yet evicted. RBF fee-bumping is a
                    // separate caller intent and needs an explicit
                    // opt-in (not wired yet).
                    if (::wallet::pricoin_broadcasted_kis::Lookup(
                            wallet, rec.key_image)) {
                        continue;
                    }
                    // Also defend against KIs that landed in the
                    // chain's mempool via a DIFFERENT wallet/tool —
                    // not in our broadcasted_kis store, so the above
                    // check misses them. Without this, the picker
                    // hands the user back a tx that the mempool
                    // rejects with "insufficient fee, rejecting
                    // replacement …". Seen in the wild on 2026-05-12
                    // after a wallet resync: a prior funding attempt
                    // sat in mempool with no matching wallet record.
                    if (chain.isPricoinKeyImageInMempool(
                            std::span<const unsigned char, 33>{
                                rec.key_image.data(), 33})) {
                        continue;
                    }
                    picked_outpoint = outpoint;
                    picked_height = rec.height;
                    break;
                }
            }
            if (picked_height >= 0) {
                const auto subaddr_lookup = ::wallet::pricoin_stealth::BuildSubaddressLookup(wallet);
                picked = RehydrateRecovery(id, subaddr_lookup, chain, picked_outpoint, picked_height);
            }
            if (!picked) throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "No recovered CT output of sufficient value");

            // 2. Collect chain CT outputs as decoy pool (excluding our own).
            auto pool = CollectChainCTOutputs(chain);
            std::vector<ChainCTOutput> decoy_pool;
            for (auto& c : pool) {
                if (c.ref.hash == picked_outpoint.hash.ToUint256() && c.ref.n == picked_outpoint.n) continue;
                decoy_pool.push_back(std::move(c));
            }
            if ((int)decoy_pool.size() < ring_size - 1) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    strprintf("Not enough chain CT outputs for ring_size=%d (have %d decoys)", ring_size, (int)decoy_pool.size()));
            }
            // Recency-weighted sample (defeats the uniform-over-history
            // fingerprint described in the security review's H-2).
            FastRandomContext rng;
            auto decoys = SampleDecoysRecencyWeighted(
                std::move(decoy_pool),
                static_cast<size_t>(ring_size - 1),
                tip,
                rng);

            // 3. Insert our own output at a random index pi.
            const size_t pi = rng.randrange(static_cast<uint32_t>(ring_size));
            std::vector<ChainCTOutput> ring(ring_size);
            for (size_t k = 0, d = 0; k < (size_t)ring_size; ++k) {
                if (k == pi) {
                    ring[k] = ChainCTOutput{
                        .ref = pricoin::ct::PrevoutRef{picked_outpoint.hash.ToUint256(), picked_outpoint.n},
                        .commitment = picked->commitment,
                        .one_time_pubkey = {},
                    };
                    // Copy our own one_time_pubkey from the picked output's
                    // scriptPubKey-derived pubkey.
                    CPubKey one_time = picked->one_time_priv.GetPubKey();
                    std::memcpy(ring[k].one_time_pubkey.data(), one_time.data(), 33);
                } else {
                    ring[k] = decoys[d++];
                }
            }

            // 4. Build pseudo input commitment with random blind.
            pricoin::ct::BlindingFactor pseudo_blind;
            GetRandBytes(pseudo_blind);
            auto pseudo = pricoin::ct::Commitment::Create(static_cast<uint64_t>(picked->value), pseudo_blind);
            if (!pseudo) throw JSONRPCError(RPC_INTERNAL_ERROR, "pseudo commit failed");

            // 5. Compute z = picked->blind - pseudo_blind (mod n).
            //    Used as the signer's commitment-row priv key.
            pricoin::ringsig::Scalar z_pi;
            {
                auto neg = pricoin::ct::NegateScalar(pseudo_blind);
                if (!neg) throw JSONRPCError(RPC_INTERNAL_ERROR, "z negate failed");
                auto sum = pricoin::ct::AddScalars(picked->blind, *neg);
                if (!sum) throw JSONRPCError(RPC_INTERNAL_ERROR, "z add failed");
                std::memcpy(z_pi.data(), sum->data(), 32);
            }

            // 6. Build outputs: recipient + change-to-self + (decoy padding to
            //    reach 3 outputs). Output blinds sum to pseudo_blind so the
            //    pseudo commitment balances against the output commitments.
            //    Padding & shuffle: PRIVACY — see the matching block in
            //    SendConfidentialTxMultiImpl. Two outputs of identical shape
            //    let an observer label change with 50/50 confidence.
            const CAmount change_value = picked->value - target;
            struct PendingOut {
                const ::pricoin::stealth::StealthAddress* stealth;
                CAmount amount;
                ::pricoin::stealth::AddressKind kind;
                bool is_recipient;  // true → use pinned_eph_priv if set
            };
            std::vector<PendingOut> pending;
            pending.reserve(3);
            pending.push_back({stealth_dest, dest_amount, dest_kind, /*is_recipient=*/true});
            pending.push_back({&id.public_address, change_value,
                               ::pricoin::stealth::AddressKind::Main, false});
            while (pending.size() < 3) {
                pending.push_back({&id.public_address, 0,
                                   ::pricoin::stealth::AddressKind::Main, false});
            }
            // Atomic-swap PRIC funding pins ephemeral r AND pre-computes
            // the joint output's P_pi at output_index=0 (Bob's adaptor
            // setup uses 0 because the on-chain vout isn't known yet at
            // setup time). Bob then signs the DLEQ proof binding T_G/T_H
            // to P_pi(idx=0). For the on-chain P_pi to match Bob's
            // proof, the recipient MUST land at vout=0 — i.e., DON'T
            // shuffle it. Shuffle the non-recipient outputs only.
            //
            // Without this, walletsendct_ring's shuffle puts the
            // recipient at a random vout, the on-chain P_pi uses that
            // vout's output_index in DeriveSharedSecret, and Bob's DLEQ
            // proof (bound to idx=0) fails to verify at cooperative-
            // sign Step 2. (Observed 2026-05-11 — root cause of the
            // "CombineAndWalk failed" failures.)
            FastRandomContext shuffle_rng;
            if (!pinned_eph_priv.empty()) {
                // Swap mode: keep recipient at index 0, shuffle the rest.
                if (pending.size() > 2) {
                    std::shuffle(pending.begin() + 1, pending.end(), shuffle_rng);
                }
            } else {
                std::shuffle(pending.begin(), pending.end(), shuffle_rng);
            }

            // Per-output stealth derivation uses the FINAL position because
            // the recipient scans by output_index.
            struct ResolvedOut {
                CScript spk;
                ::pricoin::stealth::PointBytes R;
                ::pricoin::ct::BlindingFactor nonce;
                ::pricoin::ct::SerializedPubKey33 otp;
                CAmount amount;
            };
            std::vector<ResolvedOut> outs;
            outs.reserve(pending.size());
            for (size_t i = 0; i < pending.size(); ++i) {
                CKey r;
                if (pending[i].is_recipient && !pinned_eph_priv.empty()) {
                    r.Set(pinned_eph_priv.begin(), pinned_eph_priv.end(),
                          /*fCompressed=*/true);
                    if (!r.IsValid()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "pinned_ephemeral_priv is not a valid secp256k1 scalar");
                    }
                } else {
                    r.MakeNewKey(true);
                }
                ResolvedOut ro;
                ro.amount = pending[i].amount;
                const auto R_bytes = ::pricoin::stealth::ComputeStealthR(
                    r, *pending[i].stealth, pending[i].kind);
                if (!R_bytes) throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("stealth R derivation failed (output %u)", i));
                std::memcpy(ro.R.data(), R_bytes->data(), 33);
                auto S = ::pricoin::stealth::ECDHPoint(r, pending[i].stealth->view);
                if (!S) throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("stealth ECDH failed (output %u)", i));
                auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, static_cast<uint32_t>(i));
                auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, pending[i].stealth->spend);
                if (!P) throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("stealth onetime failed (output %u)", i));
                ro.spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
                std::memcpy(ro.otp.data(), P->data(), 33);
                auto rp_nonce = ::pricoin::stealth::DeriveRangeProofNonce(*S, static_cast<uint32_t>(i));
                std::memcpy(ro.nonce.data(), rp_nonce.data(), 32);
                outs.push_back(std::move(ro));
            }

            // Random blinds for outputs [0..N-2]; the last gets the balancing
            // blind so Σ(output_blinds) = pseudo_blind. Position N-1 is random
            // w.r.t. the (recipient, change, decoy) labelling because of the
            // shuffle, so the balancing slot is unobservable.
            const size_t Nout = outs.size();
            std::vector<pricoin::ct::BlindingFactor> out_blinds(Nout);
            for (size_t i = 0; i + 1 < Nout; ++i) GetRandBytes(out_blinds[i]);
            {
                std::span<const pricoin::ct::BlindingFactor> other_outs{out_blinds.data(), Nout - 1};
                auto last = pricoin::ct::BalancingBlind(
                    std::array<pricoin::ct::BlindingFactor, 1>{pseudo_blind},
                    other_outs);
                if (!last) throw JSONRPCError(RPC_INTERNAL_ERROR, "blind sum failed");
                out_blinds.back() = *last;
            }

            std::vector<pricoin::ct::CTOutput> ct_outputs;
            ct_outputs.reserve(Nout);
            for (size_t i = 0; i < Nout; ++i) {
                auto commit = pricoin::ct::Commitment::Create(static_cast<uint64_t>(outs[i].amount), out_blinds[i]);
                if (!commit) throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("output %u commit failed", i));
                std::vector<unsigned char> spk_bytes(outs[i].spk.begin(), outs[i].spk.end());
                auto proof = pricoin::ct::CreateRangeProof(
                    static_cast<uint64_t>(outs[i].amount), out_blinds[i], *commit,
                    std::span<const unsigned char>{spk_bytes}, outs[i].nonce);
                if (!proof) throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("output %u rangeproof failed", i));
                ct_outputs.push_back(pricoin::ct::CTOutput{*commit, *proof, std::move(spk_bytes), outs[i].R, outs[i].otp});
            }

            // 7. Construct the bundle with a ring input.
            pricoin::ct::CTRingInput ring_input;
            ring_input.ring.reserve(ring_size);
            for (const auto& m : ring) ring_input.ring.push_back(m.ref);
            ring_input.pseudo_commitment = *pseudo;

            pricoin::ct::CTBundle bundle;
            bundle.ring_inputs = {ring_input}; // sig filled in below
            bundle.outputs = std::move(ct_outputs);
            bundle.transparent_fee = static_cast<uint64_t>(fee);

            // 8. Build mtx.
            CMutableTransaction mtx;
            mtx.version = PRICOIN_CT_VERSION;
            mtx.nLockTime = 0;
            // vin's prevout: set to ring[0] as a fixed convention (does not
            // reveal pi). Verifier ignores it for ring inputs.
            const COutPoint marker_outpoint{
                Txid::FromUint256(ring_input.ring[0].hash),
                ring_input.ring[0].n};
            mtx.vin.emplace_back(marker_outpoint, CScript{}, 0xfffffffe);
            for (const auto& o : outs) {
                mtx.vout.emplace_back(0, o.spk);
            }
            mtx.ct_bundle = std::move(bundle);

            // 9. Compute the message and sign with multi-layer CLSAG.
            //    The msg is the tx hash with sigs zeroed out.
            CMutableTransaction sig_input_tx{mtx};
            for (auto& ri : sig_input_tx.ct_bundle.ring_inputs) {
                ri.sig = pricoin::ringsig::Signature{};
            }
            HashWriter hw{};
            hw << TX_NO_WITNESS(CTransaction{sig_input_tx});
            const uint256 msg = hw.GetSHA256();

            // Phase 4c: multi-layer CLSAG over (P_i, W_i) pairs where
            // W_i = C_i − C_pseudo (computed at field level via the
            // pedersen_commitments_subtract_to_pubkey helper added to
            // secp256k1-zkp; this preserves the proper y-parity, so z*G
            // matches W_pi byte-for-byte without any negation hack).
            std::vector<pricoin::ringsig::MultiLayerMember> ml_ring(ring_size);
            for (size_t k = 0; k < (size_t)ring_size; ++k) {
                ml_ring[k].P = ring[k].one_time_pubkey;
                auto W = pricoin::ct::SubtractCommitments(ring[k].commitment, *pseudo);
                if (!W) throw JSONRPCError(RPC_INTERNAL_ERROR,
                    strprintf("W_%u computation failed", (unsigned)k));
                ml_ring[k].W = *W;
            }

            pricoin::ringsig::Scalar x_pi;
            std::memcpy(x_pi.data(), picked->one_time_priv.data(), 32);

            auto sig = pricoin::ringsig::SignMultiLayer(
                std::span<const pricoin::ringsig::MultiLayerMember>{ml_ring}, pi, x_pi, z_pi, msg);
            if (!sig) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "ring signing (multi-layer) failed");
            }

            // 10. Insert sig into the bundle and broadcast.
            mtx.ct_bundle.ring_inputs[0].sig = *sig;

            // Capture the keyimage BEFORE moving mtx into the
            // transaction ref — we'll persist it to the wallet's
            // broadcasted-keyimage set after a successful broadcast
            // so the picker refuses to re-spend this input even if
            // the chain's global set is later wiped/desynced.
            const std::array<unsigned char, 33> ki_to_persist =
                mtx.ct_bundle.ring_inputs[0].sig.key_image;

            CTransactionRef tx_ref = MakeTransactionRef(std::move(mtx));
            if (broadcast_now) {
                std::string err_str;
                if (!chain.broadcastTransaction(tx_ref, MAX_MONEY,
                                                 node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL,
                                                 err_str)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "broadcast failed: " + err_str);
                }

                // Persist the spent keyimage with the txid that produced
                // it. Future picker calls skip this KI outright — there's
                // no RBF carve-out (2026-05-13). The txid is still stored
                // for forensic / RPC inspection. Best-effort: broadcast
                // already succeeded; persistence failure falls back to
                // chain's keyimage set when the tx confirms.
                if (!::wallet::pricoin_broadcasted_kis::Add(
                        wallet, ki_to_persist, tx_ref->GetHash().ToUint256())) {
                    LogInfo("Pricoin walletsendct_ring: broadcasted-KI persist "
                            "failed for tx %s — chain-set fallback only\n",
                            tx_ref->GetHash().ToString());
                }
            }
            // When broadcast_now is false, intentionally skip the
            // KI persist + chain broadcast — caller is expected to
            // hold the tx, gather presigs against its output, then
            // call pricoin_ct_relay_prebuilt which performs both.

            // Find the post-shuffle position of the recipient output.
            // Critical for atomic-swap PRIC funding: the cooperative-
            // sign loadshare needs vout matching where the joint
            // stealth output actually landed on chain. Hardcoding 0
            // to the watch entry caused "scriptPubKey mismatch"
            // failures because vout 0 was usually change/decoy.
            int recipient_vout = -1;
            for (size_t i = 0; i < pending.size(); ++i) {
                if (pending[i].is_recipient) {
                    recipient_vout = static_cast<int>(i);
                    break;
                }
            }

            // Serialize the signed tx hex for the response. Always
            // returned — caller may want it for storage even on the
            // broadcast=true path (e.g. local logging).
            DataStream ss_tx;
            ss_tx << TX_WITH_WITNESS(*tx_ref);
            const std::string tx_hex_out = HexStr(ss_tx);

            UniValue out{UniValue::VOBJ};
            out.pushKV("txid", tx_ref->GetHash().ToString());
            out.pushKV("ring_size", ring_size);
            out.pushKV("input_value", ValueFromAmount(picked->value));
            out.pushKV("change_amount", ValueFromAmount(change_value));
            out.pushKV("size", (int)::GetSerializeSize(TX_WITH_WITNESS(*tx_ref)));
            out.pushKV("bundle_size", (int)tx_ref->ct_bundle.SerializedSize());
            out.pushKV("recipient_vout", recipient_vout);
            out.pushKV("tx_hex", tx_hex_out);
            out.pushKV("broadcast", broadcast_now);
            return out;
        }
    };
}

// Broadcast a previously-built (walletsendct_ring broadcast=false) signed
// Pricoin CT transaction. Persists the input key-image to the wallet's
// broadcasted-KI set on success, mirroring the integrated broadcast path
// in walletsendct_ring. Used by the atomic-swap PRIC funding flow: the
// builder pre-builds the funding tx, the cooperative-sign ceremony
// gathers refund + claim presigs against the planned output, then this
// RPC actually broadcasts. If the relay step is never reached (user
// aborts before ceremony completes), no PRIC value is locked on-chain.
RPCMethod pricoin_ct_relay_prebuilt()
{
    return RPCMethod{
        "pricoin_ct_relay_prebuilt",
        "Broadcast a previously-built pricoin CT transaction (built via "
        "walletsendct_ring with broadcast=false). Persists the broadcasted "
        "key-image on success.\n",
        {
            {"tx_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Hex of the signed tx as returned by walletsendct_ring."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", ""},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_ct_relay_prebuilt", "<tx_hex>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;

            const std::string tx_hex = request.params[0].get_str();
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, tx_hex, /*try_no_witness=*/true, /*try_witness=*/true)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "tx decode failed");
            }
            if (mtx.ct_bundle.ring_inputs.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "tx has no ring_inputs — not a pricoin CT ring-sig tx");
            }

            // Capture the input KI before MakeTransactionRef moves mtx.
            const std::array<unsigned char, 33> ki_to_persist =
                mtx.ct_bundle.ring_inputs[0].sig.key_image;

            CTransactionRef tx_ref = MakeTransactionRef(std::move(mtx));
            interfaces::Chain& chain = wallet.chain();
            std::string err_str;
            if (!chain.broadcastTransaction(tx_ref, MAX_MONEY,
                                             node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL,
                                             err_str)) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    "broadcast failed: " + err_str);
            }
            if (!::wallet::pricoin_broadcasted_kis::Add(
                    wallet, ki_to_persist, tx_ref->GetHash().ToUint256())) {
                LogInfo("Pricoin pricoin_ct_relay_prebuilt: broadcasted-KI "
                        "persist failed for tx %s — chain-set fallback only\n",
                        tx_ref->GetHash().ToString());
            }
            UniValue out{UniValue::VOBJ};
            out.pushKV("txid", tx_ref->GetHash().ToString());
            return out;
        }
    };
}

RPCMethod walletsendct_from_ct()
{
    return RPCMethod{
        "walletsendct_from_ct",
        "Send a Pricoin Confidential Transaction funded by previously-received CT outputs.\n"
        "Scans the chain for own CT outputs, picks N of them (greedy biggest-first) summing to\n"
        "at least dest_amount + fee, derives the one-time spend key for each from the wallet's\n"
        "stealth identity, and constructs + signs a v4 tx spending them all. CT-spending-CT.\n",
        {
            {"dest_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Destination Pricoin stealth or bech32 address"},
            {"dest_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount to send in PRIC"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Transparent fee in PRIC"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", ""},
                {RPCResult::Type::ARR, "spent_outpoints", "Consumed CT input outpoints (txid:vout each)", {
                    {RPCResult::Type::STR, "", ""}
                }},
                {RPCResult::Type::STR_AMOUNT, "input_value", "Sum of recovered input values"},
                {RPCResult::Type::STR_AMOUNT, "change_amount", "Change amount (kept as our own CT)"},
                {RPCResult::Type::NUM, "size", ""},
                {RPCResult::Type::NUM, "bundle_size", ""},
            }
        },
        RPCExamples{HelpExampleCli("walletsendct_from_ct", "\"pricstl1...\" 10 0.0001")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;

            const std::string dest_addr_str = request.params[0].get_str();
            const CAmount dest_amount = AmountFromValue(request.params[1]);
            const CAmount fee = AmountFromValue(request.params[2]);
            if (dest_amount <= 0 || fee < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative or zero amount");
            const CAmount target = dest_amount + fee;

            const auto& id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
            interfaces::Chain& chain = wallet.chain();

            // Pick own spendable CT outputs via the recovery cache,
            // greedy biggest-first. The cache only stores
            // (outpoint, value, key_image, height); we rehydrate the
            // full RecoveredOutput (blind + one_time_priv) on demand
            // for just the entries we end up spending.
            struct PickedCT { RecoveredOutput rec; COutPoint outpoint; };
            struct CacheCandidate { COutPoint outpoint; CAmount value; int height; };
            std::vector<CacheCandidate> sorted;
            {
                LOCK(g_recovery_index_mutex);
                CTRecoveryIndex& index = SyncRecoveryIndexLocked(wallet);
                sorted.reserve(index.entries.size());
                for (const auto& [outpoint, rec] : index.entries) {
                    if (pricoin::IsKeyImageCommitted(rec.key_image)) continue;
                    // Same wallet-local broadcasted-KI filter as
                    // walletsendct_ring's picker (2026-05-13 tightening:
                    // any broadcast for this KI hides the output).
                    if (::wallet::pricoin_broadcasted_kis::Lookup(
                            wallet, rec.key_image)) {
                        continue;
                    }
                    // Chain-mempool check — catches KIs other tools /
                    // wallets may have parked in the local mempool.
                    if (wallet.chain().isPricoinKeyImageInMempool(
                            std::span<const unsigned char, 33>{
                                rec.key_image.data(), 33})) {
                        continue;
                    }
                    sorted.push_back({outpoint, rec.value, rec.height});
                }
            }
            std::sort(sorted.begin(), sorted.end(),
                      [](const auto& a, const auto& b) { return a.value > b.value; });

            std::vector<PickedCT> picked_list;
            CAmount input_total = 0;
            const auto subaddr_lookup = ::wallet::pricoin_stealth::BuildSubaddressLookup(wallet);
            for (const auto& cand : sorted) {
                auto rehydrated = RehydrateRecovery(id, subaddr_lookup, chain, cand.outpoint, cand.height);
                if (!rehydrated) continue;  // stale cache entry; skip
                input_total += rehydrated->value;
                picked_list.push_back({std::move(*rehydrated), cand.outpoint});
                if (input_total >= target) break;
            }
            if (input_total < target) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                    "Insufficient recovered CT outputs for dest_amount + fee");
            }

            // Build outputs: dest + change-to-self + decoy padding (so the
            // bundle has ≥3 outputs and an external observer can't label
            // change with 50/50 confidence). Same shuffle/pad story as
            // SendConfidentialTxMultiImpl. Dest may be stealth (foreign) or
            // a plain transparent script; change and decoy are always
            // stealth-to-self.
            const auto parsed_dest = ::pricoin::stealth::ParseStealthAddress(dest_addr_str);
            CScript transparent_dest_spk;
            if (!parsed_dest) {
                CTxDestination d = DecodeDestination(dest_addr_str);
                if (!IsValidDestination(d)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid dest_address");
                transparent_dest_spk = GetScriptForDestination(d);
            }
            const CAmount change_value = input_total - target;

            struct OutputSpec {
                enum class Kind { StealthForeign, StealthSelf, Transparent };
                Kind kind;
                const ::pricoin::stealth::StealthAddress* stealth;
                CScript transparent_spk;
                CAmount amount;
                ::pricoin::stealth::AddressKind addr_kind;
            };
            std::vector<OutputSpec> pending;
            pending.reserve(3);
            if (parsed_dest) {
                pending.push_back({OutputSpec::Kind::StealthForeign, &parsed_dest->address,
                                   {}, dest_amount, parsed_dest->kind});
            } else {
                pending.push_back({OutputSpec::Kind::Transparent, nullptr,
                                   transparent_dest_spk, dest_amount,
                                   ::pricoin::stealth::AddressKind::Main});
            }
            pending.push_back({OutputSpec::Kind::StealthSelf, &id.public_address, {},
                               change_value, ::pricoin::stealth::AddressKind::Main});
            while (pending.size() < 3) {
                pending.push_back({OutputSpec::Kind::StealthSelf, &id.public_address, {},
                                   0, ::pricoin::stealth::AddressKind::Main});
            }
            FastRandomContext shuffle_rng;
            std::shuffle(pending.begin(), pending.end(), shuffle_rng);

            // Resolve each output into (spk, R, otp, nonce, amount). Stealth
            // derivation keys off the FINAL post-shuffle index because the
            // recipient scans by output_index.
            struct ResolvedOut {
                CScript spk;
                ::pricoin::stealth::PointBytes R;
                ::pricoin::ct::BlindingFactor nonce;
                ::pricoin::ct::SerializedPubKey33 otp;
                CAmount amount;
            };
            std::vector<ResolvedOut> outs;
            outs.reserve(pending.size());
            for (size_t i = 0; i < pending.size(); ++i) {
                ResolvedOut ro{};
                ro.amount = pending[i].amount;
                if (pending[i].kind == OutputSpec::Kind::Transparent) {
                    ro.spk = pending[i].transparent_spk;
                    GetRandBytes(ro.nonce);
                } else {
                    CKey r; r.MakeNewKey(true);
                    const auto R_bytes = ::pricoin::stealth::ComputeStealthR(
                        r, *pending[i].stealth, pending[i].addr_kind);
                    if (!R_bytes) throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("stealth R derivation failed (output %u)", i));
                    std::memcpy(ro.R.data(), R_bytes->data(), 33);
                    auto S = ::pricoin::stealth::ECDHPoint(r, pending[i].stealth->view);
                    if (!S) throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("stealth ECDH failed (output %u)", i));
                    auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, static_cast<uint32_t>(i));
                    auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, pending[i].stealth->spend);
                    if (!P) throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("stealth onetime failed (output %u)", i));
                    ro.spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
                    std::memcpy(ro.otp.data(), P->data(), 33);
                    auto rp_nonce = ::pricoin::stealth::DeriveRangeProofNonce(*S, static_cast<uint32_t>(i));
                    std::memcpy(ro.nonce.data(), rp_nonce.data(), 32);
                }
                outs.push_back(std::move(ro));
            }

            // Each input carries its real recovered blind. Random blinds for
            // outputs [0..N-2]; the last balances so Σ(out_blinds) = Σ(in_blinds).
            std::vector<pricoin::ct::BlindingFactor> in_blinds;
            in_blinds.reserve(picked_list.size());
            for (const auto& p : picked_list) in_blinds.push_back(p.rec.blind);

            const size_t Nout = outs.size();
            std::vector<pricoin::ct::BlindingFactor> out_blinds(Nout);
            for (size_t i = 0; i + 1 < Nout; ++i) GetRandBytes(out_blinds[i]);
            {
                std::span<const pricoin::ct::BlindingFactor> other_outs{out_blinds.data(), Nout - 1};
                auto last = pricoin::ct::BalancingBlind(
                    std::span<const pricoin::ct::BlindingFactor>{in_blinds},
                    other_outs);
                if (!last) throw JSONRPCError(RPC_INTERNAL_ERROR, "blind sum failed");
                out_blinds.back() = *last;
            }

            std::vector<pricoin::ct::CTOutput> ct_outputs;
            ct_outputs.reserve(Nout);
            for (size_t i = 0; i < Nout; ++i) {
                auto commit = pricoin::ct::Commitment::Create(static_cast<uint64_t>(outs[i].amount), out_blinds[i]);
                if (!commit) throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("output %u commit failed", i));
                std::vector<unsigned char> spk_bytes(outs[i].spk.begin(), outs[i].spk.end());
                auto proof = pricoin::ct::CreateRangeProof(
                    static_cast<uint64_t>(outs[i].amount), out_blinds[i], *commit,
                    std::span<const unsigned char>{spk_bytes}, outs[i].nonce);
                if (!proof) throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("output %u rangeproof failed", i));
                ct_outputs.push_back(pricoin::ct::CTOutput{*commit, *proof, std::move(spk_bytes), outs[i].R, outs[i].otp});
            }

            pricoin::ct::CTBundle bundle;
            bundle.input_commitments.reserve(picked_list.size());
            for (const auto& p : picked_list) bundle.input_commitments.push_back(p.rec.commitment);
            bundle.outputs = std::move(ct_outputs);
            bundle.transparent_fee = static_cast<uint64_t>(fee);

            CMutableTransaction mtx;
            mtx.version = PRICOIN_CT_VERSION;
            mtx.nLockTime = 0;
            for (const auto& p : picked_list) {
                mtx.vin.emplace_back(p.outpoint, CScript{}, 0xfffffffe);
            }
            for (const auto& o : outs) {
                mtx.vout.emplace_back(0, o.spk);
            }
            mtx.ct_bundle = std::move(bundle);

            // Sign each input directly with the derived one-time priv key.
            // Wallet's keystore doesn't know these keys (recovered via
            // stealth-scan, not stored), so we can't go through
            // CWallet::SignTransaction.
            const int32_t hashtype = SIGHASH_ALL;
            for (size_t i = 0; i < picked_list.size(); ++i) {
                const auto& p = picked_list[i];
                CKeyID keyid;
                const CScript& spk = p.rec.scriptPubKey;
                if (spk.size() != 22 || spk[0] != OP_0 || spk[1] != 0x14) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("recovered CT input %u is not P2WPKH", (unsigned)i));
                }
                std::copy_n(spk.begin() + 2, 20, keyid.begin());
                CScript scriptCode;
                scriptCode << OP_DUP << OP_HASH160 << ToByteVector(keyid)
                           << OP_EQUALVERIFY << OP_CHECKSIG;
                // BIP143 amount field is unused for v4 inputs (prev nValue=0).
                // The bundle-hash mixin in the sighash is what binds inputs.
                const uint256 sighash = SignatureHash(
                    scriptCode, mtx, /*nIn=*/static_cast<unsigned int>(i), hashtype,
                    /*amount=*/0, SigVersion::WITNESS_V0,
                    nullptr, nullptr);
                std::vector<unsigned char> sig;
                if (!p.rec.one_time_priv.Sign(sighash, sig, true)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("ECDSA sign failed for input %u", (unsigned)i));
                }
                sig.push_back(static_cast<unsigned char>(hashtype));
                const CPubKey one_time_pub = p.rec.one_time_priv.GetPubKey();
                mtx.vin[i].scriptWitness.stack.clear();
                mtx.vin[i].scriptWitness.stack.push_back(std::move(sig));
                mtx.vin[i].scriptWitness.stack.push_back(std::vector<unsigned char>(one_time_pub.begin(), one_time_pub.end()));
            }

            CTransactionRef tx_ref = MakeTransactionRef(std::move(mtx));
            // Broadcast directly via the chain — wallet.CommitTransaction
            // assumes wallet-owned inputs (which stealth-recovered CT inputs
            // aren't, from the wallet's bookkeeping perspective).
            std::string err_str;
            if (!chain.broadcastTransaction(tx_ref, /*max_tx_fee=*/MAX_MONEY,
                                             node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL,
                                             err_str)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "broadcastTransaction failed: " + err_str);
            }

            UniValue spent_arr{UniValue::VARR};
            for (const auto& p : picked_list) {
                spent_arr.push_back(p.outpoint.hash.ToString() + ":" + std::to_string(p.outpoint.n));
            }

            UniValue out{UniValue::VOBJ};
            out.pushKV("txid", tx_ref->GetHash().ToString());
            out.pushKV("spent_outpoints", std::move(spent_arr));
            out.pushKV("input_value", ValueFromAmount(input_total));
            out.pushKV("change_amount", ValueFromAmount(change_value));
            out.pushKV("size", (int)::GetSerializeSize(TX_WITH_WITNESS(*tx_ref)));
            out.pushKV("bundle_size", (int)tx_ref->ct_bundle.SerializedSize());
            return out;
        }
    };
}

RPCMethod pricoin_getstealthaddress()
{
    return RPCMethod{
        "pricoin_getstealthaddress",
        "Return the wallet's stealth address (CryptoNote-style dual-key (view, spend)).\n"
        "Phase 5 MVP: the identity is generated lazily on first call and held only\n"
        "in memory — it is *not* persisted across daemon restarts.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "Base58Check-encoded stealth address"},
                {RPCResult::Type::STR_HEX, "view_pubkey", "Public view key (33 bytes)"},
                {RPCResult::Type::STR_HEX, "spend_pubkey", "Public spend key (33 bytes)"},
            }
        },
        RPCExamples{
            HelpExampleCli("pricoin_getstealthaddress", "")
        },
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const auto& id = wallet::pricoin_stealth::GetOrCreate(*wallet_sp);
            UniValue out{UniValue::VOBJ};
            out.pushKV("address", ::pricoin::stealth::Encode(id.public_address));
            out.pushKV("view_pubkey", HexStr(id.public_address.view));
            out.pushKV("spend_pubkey", HexStr(id.public_address.spend));
            return out;
        }
    };
}

namespace {
UniValue SubaddressJson(const ::wallet::pricoin_stealth::Identity& id,
                          uint32_t index, const std::string& label)
{
    UniValue obj{UniValue::VOBJ};
    obj.pushKV("index", (uint64_t)index);
    if (index == 0) {
        obj.pushKV("address", ::pricoin::stealth::Encode(id.public_address));
        obj.pushKV("view_pubkey", HexStr(id.public_address.view));
        obj.pushKV("spend_pubkey", HexStr(id.public_address.spend));
    } else {
        auto sa = ::pricoin::stealth::DeriveSubaddressPublic(
            id.view, id.public_address.spend, index);
        if (sa) {
            obj.pushKV("address",
                ::pricoin::stealth::EncodeSubaddress(sa->public_address, sa->index));
            obj.pushKV("view_pubkey",  HexStr(sa->public_address.view));
            obj.pushKV("spend_pubkey", HexStr(sa->public_address.spend));
        }
    }
    obj.pushKV("label", label);
    return obj;
}
} // namespace

RPCMethod pricoin_getnewsubaddress()
{
    return RPCMethod{
        "pricoin_getnewsubaddress",
        "Allocate a new subaddress index for this wallet. Each call returns a fresh\n"
        "index ≥ 1; index 0 is reserved for the master stealth address. Encoded\n"
        "addresses use the pricsub prefix and carry the index in the payload, so a\n"
        "scanner can attribute incoming payments without an extra lookup.\n"
        "\n"
        "Use this when integrating exchange-style deposits: hand each user their own\n"
        "subaddress, then attribute deposits via the `subaddress_index` field on\n"
        "`pricoin_listownct` rows.\n",
        {
            {"label", RPCArg::Type::STR, RPCArg::Default{""}, "Optional label (utf-8) attached to this index"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM,     "index",        "Allocated index (≥1)"},
                {RPCResult::Type::STR,     "address",      "Encoded subaddress (pricsub-prefixed base58check)"},
                {RPCResult::Type::STR_HEX, "view_pubkey",  "Subaddress public view point A_i (33 bytes)"},
                {RPCResult::Type::STR_HEX, "spend_pubkey", "Subaddress public spend point B_i (33 bytes)"},
                {RPCResult::Type::STR,     "label",        "Label as supplied; empty if none"},
            }
        },
        RPCExamples{
            HelpExampleCli("pricoin_getnewsubaddress", "\"customer-4815\"") +
            HelpExampleCli("pricoin_getnewsubaddress", "")
        },
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const std::string label = request.params[0].isNull() ? std::string{}
                                                                  : request.params[0].get_str();
            const auto sub = wallet::pricoin_stealth::AllocateNextSubaddress(*wallet_sp, label);
            const auto& id = wallet::pricoin_stealth::GetOrCreate(*wallet_sp);
            return SubaddressJson(id, sub.index, label);
        }
    };
}

RPCMethod pricoin_getsubaddress()
{
    return RPCMethod{
        "pricoin_getsubaddress",
        "Read-only: return the subaddress at the given index. Index 0 returns the\n"
        "master stealth address. Indices > max_used_index are rejected — call\n"
        "`pricoin_getnewsubaddress` to allocate.\n",
        {
            {"index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Subaddress index (0 == master)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM,     "index",        "Index"},
                {RPCResult::Type::STR,     "address",      "Encoded address (pricstl for index 0, pricsub otherwise)"},
                {RPCResult::Type::STR_HEX, "view_pubkey",  "Public view point (33 bytes)"},
                {RPCResult::Type::STR_HEX, "spend_pubkey", "Public spend point (33 bytes)"},
                {RPCResult::Type::STR,     "label",        "Label if set; empty otherwise"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_getsubaddress", "47")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const int64_t idx_signed = request.params[0].getInt<int64_t>();
            if (idx_signed < 0 || idx_signed > std::numeric_limits<uint32_t>::max()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "index out of range");
            }
            const uint32_t idx = static_cast<uint32_t>(idx_signed);
            const auto state = wallet::pricoin_stealth::LoadSubaddressState(*wallet_sp);
            if (idx > state.max_used_index) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("index %u not allocated (max_used=%u)", idx, state.max_used_index));
            }
            const auto& id = wallet::pricoin_stealth::GetOrCreate(*wallet_sp);
            std::string label;
            if (auto it = state.labels.find(idx); it != state.labels.end()) label = it->second;
            return SubaddressJson(id, idx, label);
        }
    };
}

RPCMethod pricoin_listsubaddresses()
{
    return RPCMethod{
        "pricoin_listsubaddresses",
        "List every allocated subaddress (index 1 … max_used_index). The master\n"
        "(index 0) is intentionally excluded — use `pricoin_getstealthaddress` for it.\n",
        {},
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "index", ""},
                        {RPCResult::Type::STR, "address", ""},
                        {RPCResult::Type::STR_HEX, "view_pubkey", ""},
                        {RPCResult::Type::STR_HEX, "spend_pubkey", ""},
                        {RPCResult::Type::STR, "label", ""},
                    }}
            }
        },
        RPCExamples{HelpExampleCli("pricoin_listsubaddresses", "")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const auto state = wallet::pricoin_stealth::LoadSubaddressState(*wallet_sp);
            const auto& id = wallet::pricoin_stealth::GetOrCreate(*wallet_sp);
            UniValue arr{UniValue::VARR};
            for (uint32_t i = 1; i <= state.max_used_index; ++i) {
                std::string label;
                if (auto it = state.labels.find(i); it != state.labels.end()) label = it->second;
                arr.push_back(SubaddressJson(id, i, label));
            }
            return arr;
        }
    };
}

RPCMethod pricoin_setsubaddresslabel()
{
    return RPCMethod{
        "pricoin_setsubaddresslabel",
        "Set or clear the label on an allocated subaddress index. Pass an empty\n"
        "string to remove the label. Returns true on success.\n",
        {
            {"index", RPCArg::Type::NUM, RPCArg::Optional::NO, "Subaddress index (≥ 1)"},
            {"label", RPCArg::Type::STR, RPCArg::Optional::NO, "Label text (empty to clear)"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "True on success"},
        RPCExamples{HelpExampleCli("pricoin_setsubaddresslabel", "47 \"customer-4815\"")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const int64_t idx_signed = request.params[0].getInt<int64_t>();
            if (idx_signed <= 0 || idx_signed > std::numeric_limits<uint32_t>::max()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "index must be ≥ 1");
            }
            const uint32_t idx = static_cast<uint32_t>(idx_signed);
            const std::string label = request.params[1].get_str();
            const bool ok = wallet::pricoin_stealth::SetSubaddressLabel(
                *wallet_sp, idx, label);
            if (!ok) throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("index %u not allocated", idx));
            return true;
        }
    };
}

RPCMethod pricoin_getstealthseed()
{
    return RPCMethod{
        "pricoin_getstealthseed",
        "Return the 32-byte master seed from which this wallet's stealth view\n"
        "and spend keys are derived. Save this hex string offline — anyone with\n"
        "it can reconstruct your stealth address and recover all CT payments\n"
        "ever sent to it. Equivalent to a wallet seed phrase for the stealth\n"
        "side; pair it with `listdescriptors true` (for the transparent side)\n"
        "for a complete cold backup.\n"
        "\n"
        "Errors:\n"
        "  - wallet locked (call `walletpassphrase` first).\n"
        "  - wallet uses the legacy v0.1.11 key-blob format. Use `backupwallet`\n"
        "    or `bitcoin-wallet dump` to back up those wallets — there is no\n"
        "    seed to extract.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "seed", "32-byte master seed (hex)"},
            }
        },
        RPCExamples{
            HelpExampleCli("pricoin_getstealthseed", "")
        },
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            // Even though the seed is held in memory while the wallet is
            // running (so we could technically return it after walletlock),
            // we require an unlocked wallet for export — same posture as
            // dumpprivkey. Locking is the user's signal "do not surface
            // secrets right now."
            if (wallet_sp->HasEncryptionKeys() && wallet_sp->IsLocked()) {
                throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                    "Pricoin stealth seed export requires an unlocked wallet "
                    "(call `walletpassphrase` first, then retry — but treat "
                    "this seed as you would a private-key dump: anyone who "
                    "sees it can reconstruct your stealth identity).");
            }
            auto seed = wallet::pricoin_stealth::GetSeedIfAvailable(*wallet_sp);
            if (!seed) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    "This wallet uses the legacy v0.1.11 stealth-key format and has no "
                    "extractable seed. Use `backupwallet` or `bitcoin-wallet dump` to "
                    "back it up instead.");
            }
            UniValue out{UniValue::VOBJ};
            out.pushKV("seed", HexStr(*seed));
            // Wipe the stack copy of the seed before we return. The hex
            // string going through UniValue / the JSON serialiser is
            // out of our hands (and inevitably ends up on the wire), but
            // the raw 32-byte buffer in `seed` doesn't need to keep
            // sitting in memory longer than necessary.
            memory_cleanse(seed->data(), seed->size());
            return out;
        }
    };
}
RPCMethod pricoin_setstealthseed()
{
    return RPCMethod{
        "pricoin_setstealthseed",
        "Restore the wallet's stealth identity from a 32-byte seed (hex), e.g.\n"
        "from a `pricoin_getstealthseed` paper backup. Refuses to clobber an\n"
        "existing identity unless `confirm_overwrite=true` — overwriting\n"
        "discards every CT output already received by this wallet.\n"
        "\n"
        "Typical recovery flow:\n"
        "  1. createwallet \"recovered\" — produces a fresh seed.\n"
        "  2. pricoin_setstealthseed \"<32-byte hex>\" true — replaces it.\n"
        "  3. The wallet now derives the original stealth address; rescan\n"
        "     to find any CT payments previously sent to it.\n",
        {
            {"seed_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "32-byte seed in hex (64 chars)."},
            {"confirm_overwrite", RPCArg::Type::BOOL, RPCArg::Default{false},
             "If the wallet already has a stealth identity, set true to overwrite it. "
             "Any CT funds previously received are LOST (recoverable only via the "
             "old wallet.dat or seed)."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "Newly-active stealth address (Base58Check)"},
            }
        },
        RPCExamples{
            HelpExampleCli("pricoin_setstealthseed", "\"<32-byte hex>\" true")
        },
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            // The hex string itself comes from request.params, which
            // sits inside UniValue's default-allocator storage — we
            // can't cleanse that. The PARSED bytes are local; cleanse
            // them on every exit path.
            const std::string& seed_hex = request.params[0].get_str();
            const bool confirm = !request.params[1].isNull() && request.params[1].get_bool();
            if (!IsHex(seed_hex) || seed_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "seed_hex must be exactly 64 hex characters (32 bytes)");
            }
            std::vector<unsigned char> seed = ParseHex(seed_hex);
            const auto result = wallet::pricoin_stealth::SetSeed(*wallet_sp, seed, confirm);
            // Wipe our local seed copy now that SetSeed has consumed it.
            memory_cleanse(seed.data(), seed.size());
            switch (result) {
                case wallet::pricoin_stealth::SetSeedResult::Ok:
                    break;
                case wallet::pricoin_stealth::SetSeedResult::InvalidSeed:
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "seed does not derive valid secp256k1 keys");
                case wallet::pricoin_stealth::SetSeedResult::Locked:
                    throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                        "Pricoin stealth seed import requires an unlocked wallet "
                        "(call `walletpassphrase` first).");
                case wallet::pricoin_stealth::SetSeedResult::AlreadyHasIdentity:
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        "Wallet already has a stealth identity. Pass "
                        "`confirm_overwrite=true` to replace it (LOSES access to all "
                        "CT funds received under the previous identity).");
                case wallet::pricoin_stealth::SetSeedResult::WriteFailed:
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        "Failed to persist stealth seed to wallet.dat");
            }
            const auto& id = wallet::pricoin_stealth::GetOrCreate(*wallet_sp);
            UniValue out{UniValue::VOBJ};
            out.pushKV("address", ::pricoin::stealth::Encode(id.public_address));
            return out;
        }
    };
}

// ---- Atomic-swap stage 2: cooperative stealth (receive side) ----

RPCMethod pricoin_buildjointstealthaddress()
{
    return RPCMethod{
        "pricoin_buildjointstealthaddress",
        "Combine this wallet's stealth identity with another party's public\n"
        "stealth keys (view + spend pubkeys) into a joint two-party stealth\n"
        "address. Funds sent there look like a normal stealth payment on\n"
        "chain — but neither party alone can scan for them or spend them.\n"
        "Both parties must run this RPC with each other's public keys to\n"
        "obtain the SAME joint address (point addition is commutative).\n"
        "\n"
        "Used as the on-chain primitive for trustless atomic swaps: the\n"
        "PRIC funder locks coins at a joint(self, counterparty) output\n"
        "while the counterparty locks the other-chain asset at a\n"
        "matching HTLC. Cooperative recovery uses\n"
        "pricoin_jointscan_partial / pricoin_jointscan_recover.\n",
        {
            {"other_view_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Counterparty's view pubkey (33-byte compressed hex). Get this "
             "from THEIR pricoin_getstealthaddress.view_pubkey."},
            {"other_spend_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Counterparty's spend pubkey (33-byte compressed hex)."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "Joint stealth address (Base58Check)"},
                {RPCResult::Type::STR_HEX, "joint_view_pubkey", "Sum of both view pubkeys (33 bytes)"},
                {RPCResult::Type::STR_HEX, "joint_spend_pubkey", "Sum of both spend pubkeys (33 bytes)"},
            }
        },
        RPCExamples{
            HelpExampleCli("pricoin_buildjointstealthaddress",
                "\"02abcdef...\" \"02123456...\"")
        },
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const std::string other_view_hex = request.params[0].get_str();
            const std::string other_spend_hex = request.params[1].get_str();
            if (!IsHex(other_view_hex) || other_view_hex.size() != 66) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "other_view_pubkey must be 66 hex characters (33 bytes)");
            }
            if (!IsHex(other_spend_hex) || other_spend_hex.size() != 66) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "other_spend_pubkey must be 66 hex characters (33 bytes)");
            }
            const std::vector<unsigned char> other_view_bytes = ParseHex(other_view_hex);
            const std::vector<unsigned char> other_spend_bytes = ParseHex(other_spend_hex);
            ::pricoin::stealth::StealthAddress other;
            other.view = CPubKey(std::span<const unsigned char>{other_view_bytes});
            other.spend = CPubKey(std::span<const unsigned char>{other_spend_bytes});
            if (!other.IsValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "other party's pubkeys are not valid compressed secp256k1 points");
            }
            const auto& self_id = ::wallet::pricoin_stealth::GetOrCreate(*wallet_sp);
            auto joint = ::pricoin::joint_stealth::Combine(self_id.public_address, other);
            if (!joint) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "joint pubkey computation failed (degenerate inputs)");
            }
            UniValue out{UniValue::VOBJ};
            out.pushKV("address", ::pricoin::stealth::Encode(*joint));
            out.pushKV("joint_view_pubkey", HexStr(joint->view));
            out.pushKV("joint_spend_pubkey", HexStr(joint->spend));
            return out;
        }
    };
}

RPCMethod pricoin_jointstealth_pop_sign()
{
    return RPCMethod{
        "pricoin_jointstealth_pop_sign",
        "Sign the joint-stealth proof-of-possession challenge for this\n"
        "wallet's stealth spend key, binding to a specific session_id and\n"
        "counterparty spend pubkey. Required as the rogue-key defense\n"
        "(`doc/adaptor-clsag.md` §6.0) when constructing joint stealth\n"
        "addresses for trustless atomic swaps.\n"
        "\n"
        "The challenge is `H('pricoin/joint-stealth/PoP-v1' || session_id\n"
        "|| counterparty_spend_pubkey)`. Both parties exchange PoP\n"
        "signatures BEFORE constructing the joint address; if either\n"
        "fails to verify, the joint address must not be used.\n",
        {
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "32-byte session id (agreed off-band, e.g., from the swap "
                "ceremony's session id)"},
            {"counterparty_spend_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Counterparty's stealth spend pubkey (33-byte compressed)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "pop", "ECDSA-DER signature"}}
        },
        RPCExamples{HelpExampleCli("pricoin_jointstealth_pop_sign",
            "\"<session_id>\" \"<counterparty_spend_pubkey>\"")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;
            if (wallet.HasEncryptionKeys() && wallet.IsLocked()) {
                throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                    "PoP signing requires the wallet to be unlocked.");
            }

            auto sid_opt = uint256::FromHex(request.params[0].get_str());
            if (!sid_opt) throw JSONRPCError(RPC_INVALID_PARAMETER,
                "session_id must be 32-byte hex");

            const std::string cp_hex = request.params[1].get_str();
            if (!IsHex(cp_hex) || cp_hex.size() != 66) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "counterparty_spend_pubkey must be 33 bytes hex");
            }
            const std::vector<unsigned char> cp_bytes = ParseHex(cp_hex);
            CPubKey cp(std::span<const unsigned char>{cp_bytes});
            if (!cp.IsValid() || !cp.IsCompressed()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "counterparty_spend_pubkey is not a valid compressed pubkey");
            }

            const auto& self_id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
            auto pop = ::pricoin::joint_stealth::ProvePossession(
                self_id.spend, *sid_opt, cp);
            if (!pop) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "ProvePossession failed");
            }
            UniValue out{UniValue::VOBJ};
            out.pushKV("pop", HexStr(*pop));
            return out;
        }
    };
}

RPCMethod pricoin_jointstealth_pop_verify()
{
    return RPCMethod{
        "pricoin_jointstealth_pop_verify",
        "Verify a joint-stealth proof-of-possession signature.\n",
        {
            {"self_spend_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Pubkey the PoP claims to be FROM (33-byte compressed)"},
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"counterparty_spend_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "The OTHER party in the binding (33-byte compressed)"},
            {"pop", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "ECDSA-DER signature from pricoin_jointstealth_pop_sign"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::BOOL, "valid", ""}}
        },
        RPCExamples{HelpExampleCli("pricoin_jointstealth_pop_verify",
            "\"<self_pub>\" \"<session>\" \"<cp_pub>\" \"<sig>\"")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            const std::string self_hex = request.params[0].get_str();
            if (!IsHex(self_hex) || self_hex.size() != 66) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "self_spend_pubkey invalid");
            }
            const auto self_bytes = ParseHex(self_hex);
            CPubKey self_pub(std::span<const unsigned char>{self_bytes});

            auto sid_opt = uint256::FromHex(request.params[1].get_str());
            if (!sid_opt) throw JSONRPCError(RPC_INVALID_PARAMETER,
                "session_id must be 32-byte hex");

            const std::string cp_hex = request.params[2].get_str();
            if (!IsHex(cp_hex) || cp_hex.size() != 66) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "counterparty_spend_pubkey invalid");
            }
            const auto cp_bytes = ParseHex(cp_hex);
            CPubKey cp(std::span<const unsigned char>{cp_bytes});

            auto sig = TryParseHex<unsigned char>(request.params[3].get_str());
            if (!sig) throw JSONRPCError(RPC_INVALID_PARAMETER, "pop hex invalid");

            const bool ok = ::pricoin::joint_stealth::VerifyPossession(
                self_pub, *sid_opt, cp, std::span<const unsigned char>{*sig});
            UniValue out{UniValue::VOBJ};
            out.pushKV("valid", ok);
            return out;
        }
    };
}

RPCMethod pricoin_buildjointstealthaddress_pop()
{
    return RPCMethod{
        "pricoin_buildjointstealthaddress_pop",
        "Like pricoin_buildjointstealthaddress, but with mandatory mutual\n"
        "proof-of-possession (rogue-key defense per `doc/adaptor-clsag.md`\n"
        "§6.0). Required for atomic-swap setup.\n"
        "\n"
        "Both parties must have already run pricoin_jointstealth_pop_sign\n"
        "(under the SAME session_id) and exchanged the resulting pop\n"
        "signatures off-band. This RPC verifies BOTH PoPs before producing\n"
        "the joint address — if either fails, the call rejects.\n",
        {
            {"other_view_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"other_spend_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "32-byte session id (must match what both PoPs were signed against)"},
            {"self_pop", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "This wallet's PoP signature from pricoin_jointstealth_pop_sign"},
            {"other_pop", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Counterparty's PoP signature"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "Joint stealth address"},
                {RPCResult::Type::STR_HEX, "joint_view_pubkey", ""},
                {RPCResult::Type::STR_HEX, "joint_spend_pubkey", ""},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_buildjointstealthaddress_pop",
            "\"<view>\" \"<spend>\" \"<session>\" \"<self_pop>\" \"<other_pop>\"")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;
            if (wallet.HasEncryptionKeys() && wallet.IsLocked()) {
                throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
            }

            const std::string view_hex  = request.params[0].get_str();
            const std::string spend_hex = request.params[1].get_str();
            if (!IsHex(view_hex)  || view_hex.size()  != 66 ||
                !IsHex(spend_hex) || spend_hex.size() != 66) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "pubkey hex invalid");
            }
            const auto view_bytes  = ParseHex(view_hex);
            const auto spend_bytes = ParseHex(spend_hex);

            ::pricoin::stealth::StealthAddress other;
            other.view  = CPubKey(std::span<const unsigned char>{view_bytes});
            other.spend = CPubKey(std::span<const unsigned char>{spend_bytes});
            if (!other.IsValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "counterparty pubkeys are not valid compressed secp256k1 points");
            }

            auto sid_opt = uint256::FromHex(request.params[2].get_str());
            if (!sid_opt) throw JSONRPCError(RPC_INVALID_PARAMETER,
                "session_id must be 32-byte hex");

            auto self_pop  = TryParseHex<unsigned char>(request.params[3].get_str());
            auto other_pop = TryParseHex<unsigned char>(request.params[4].get_str());
            if (!self_pop || !other_pop) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "pop hex invalid");
            }

            const auto& self_id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
            auto joint = ::pricoin::joint_stealth::CombineWithPoP(
                self_id.public_address, other,
                std::span<const unsigned char>{*self_pop},
                std::span<const unsigned char>{*other_pop},
                *sid_opt);
            if (!joint) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "joint construction rejected: at least one PoP failed to verify "
                    "(possible rogue-key attempt or wrong session_id)");
            }
            UniValue out{UniValue::VOBJ};
            out.pushKV("address", ::pricoin::stealth::Encode(*joint));
            out.pushKV("joint_view_pubkey", HexStr(joint->view));
            out.pushKV("joint_spend_pubkey", HexStr(joint->spend));
            return out;
        }
    };
}

RPCMethod pricoin_jointscan_partial()
{
    return RPCMethod{
        "pricoin_jointscan_partial",
        "Compute this party's contribution to a cooperative scan of a\n"
        "two-party joint stealth output. Returns a 33-byte compressed point\n"
        "(self_view_priv * tx_pubkey_R) that the counterparty needs to\n"
        "combine with their own partial in pricoin_jointscan_recover.\n"
        "\n"
        "Sharing the partial does NOT leak this wallet's view privkey: the\n"
        "partial is a one-way scalar multiplication. The counterparty\n"
        "learns the joint output's value once they recover, which is the\n"
        "intended behaviour for a joint stealth output.\n",
        {
            {"tx_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Raw v4 transaction containing the joint output (hex). The "
             "per-output tx_pubkey is read out of the embedded ct_bundle."},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO,
             "Index of the joint output within the tx"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "partial", "33-byte compressed point self_view_priv*R"},
                {RPCResult::Type::STR_HEX, "tx_pubkey", "The R that was used (echoed for caller convenience)"},
            }
        },
        RPCExamples{
            HelpExampleCli("pricoin_jointscan_partial", "\"<tx hex>\" 1")
        },
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            if (wallet_sp->HasEncryptionKeys() && wallet_sp->IsLocked()) {
                throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                    "Cooperative scan requires the wallet to be unlocked.");
            }
            const std::string tx_hex = request.params[0].get_str();
            const uint32_t vout = request.params[1].getInt<uint32_t>();
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, tx_hex, /*try_no_witness=*/true, /*try_witness=*/true)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "tx hex failed to decode");
            }
            CTransaction tx{std::move(mtx)};
            if (tx.version != PRICOIN_CT_VERSION) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "tx is not a v4 confidential tx");
            }
            if (vout >= tx.ct_bundle.outputs.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "vout out of range");
            }
            const auto& tx_pubkey = tx.ct_bundle.outputs[vout].tx_pubkey;
            // Reject zero (transparent / non-stealth output) — it would
            // produce a useless partial.
            bool all_zero = true;
            for (auto b : tx_pubkey) { if (b != 0) { all_zero = false; break; } }
            if (all_zero) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "vout has no tx_pubkey (not a stealth output)");
            }
            std::vector<unsigned char> r_bytes(tx_pubkey.begin(), tx_pubkey.end());
            const auto& self_id = ::wallet::pricoin_stealth::GetOrCreate(*wallet_sp);
            auto partial = ::pricoin::joint_stealth::ScanPartial(self_id.view, r_bytes);
            if (!partial) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "ECDH partial computation failed (invalid R or invalid view priv)");
            }
            UniValue out{UniValue::VOBJ};
            out.pushKV("partial", HexStr(*partial));
            out.pushKV("tx_pubkey", HexStr(r_bytes));
            return out;
        }
    };
}

RPCMethod pricoin_jointscan_recover()
{
    return RPCMethod{
        "pricoin_jointscan_recover",
        "Combine this wallet's scan partial with the counterparty's\n"
        "partial to recover the joint output's value and rangeproof blind.\n"
        "Either of the two parties can run this RPC once they have BOTH\n"
        "partials (their own + the other party's, exchanged off-chain).\n"
        "\n"
        "Caller fetches the raw tx via `getrawtransaction <txid>` and\n"
        "passes the hex here. We verify that the recovered one-time pubkey\n"
        "matches the v4 output's scriptPubKey at `vout` (i.e. the chain\n"
        "output really IS the joint payment that both partials are about).\n"
        "On match, rewinds the rangeproof to the (value, blind) pair.\n",
        {
            {"tx_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Raw v4 transaction containing the joint output (hex)"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO,
             "Index of the joint output within the tx"},
            {"my_partial", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Self partial returned by pricoin_jointscan_partial"},
            {"other_partial", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Counterparty's partial (from THEIR pricoin_jointscan_partial)"},
            {"other_spend_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Counterparty's spend pubkey (33 bytes hex). Needed to "
             "reconstruct B_joint = self_spend + other_spend."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_AMOUNT, "value", "Recovered amount in PRIC"},
                {RPCResult::Type::STR_HEX, "blind", "32-byte rangeproof blind"},
                {RPCResult::Type::NUM, "vout", "Echo of input vout (for caller convenience)"},
            }
        },
        RPCExamples{
            HelpExampleCli("pricoin_jointscan_recover",
                "\"<tx hex>\" 1 \"03...\" \"03...\" \"02...\"")
        },
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;
            if (wallet.HasEncryptionKeys() && wallet.IsLocked()) {
                throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                    "Cooperative scan requires the wallet to be unlocked.");
            }

            const std::string tx_hex = request.params[0].get_str();
            const uint32_t vout = request.params[1].getInt<uint32_t>();
            const std::string my_partial_hex = request.params[2].get_str();
            const std::string other_partial_hex = request.params[3].get_str();
            const std::string other_spend_hex = request.params[4].get_str();
            for (const auto& [name, hex] : {
                    std::pair{"my_partial", my_partial_hex},
                    std::pair{"other_partial", other_partial_hex},
                    std::pair{"other_spend_pubkey", other_spend_hex}}) {
                if (!IsHex(hex) || hex.size() != 66) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("%s must be 66 hex characters (33 bytes)", name));
                }
            }
            const std::vector<unsigned char> my_partial = ParseHex(my_partial_hex);
            const std::vector<unsigned char> other_partial = ParseHex(other_partial_hex);
            const std::vector<unsigned char> other_spend_bytes = ParseHex(other_spend_hex);
            CPubKey other_spend(std::span<const unsigned char>{other_spend_bytes});
            if (!other_spend.IsValid() || !other_spend.IsCompressed()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "other_spend_pubkey is not a valid compressed secp256k1 point");
            }

            // Decode the tx.
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, tx_hex, /*try_no_witness=*/true, /*try_witness=*/true)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "tx hex failed to decode");
            }
            CTransaction tx{std::move(mtx)};
            if (tx.version != PRICOIN_CT_VERSION) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "tx is not a v4 confidential tx");
            }
            if (vout >= tx.vout.size() || vout >= tx.ct_bundle.outputs.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "vout out of range");
            }

            // Combine partials → joint ECDH point.
            auto shared_point = ::pricoin::joint_stealth::CombinePartials(my_partial, other_partial);
            if (!shared_point) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "partial combine failed");
            }
            // Standard stealth derivations from the joint point.
            auto shared = ::pricoin::stealth::DeriveSharedSecret(*shared_point, vout);

            // Joint spend pubkey B_joint = B_self + B_other.
            const auto& self_id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
            ::pricoin::stealth::StealthAddress other;
            other.view = self_id.public_address.view;     // dummy; not used downstream
            other.spend = other_spend;
            auto joint_addr = ::pricoin::joint_stealth::Combine(self_id.public_address, other);
            if (!joint_addr) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "joint key combine failed");
            }
            auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, joint_addr->spend);
            if (!P) throw JSONRPCError(RPC_INTERNAL_ERROR, "one-time pubkey derivation failed");

            const CScript expected_spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
            if (tx.vout[vout].scriptPubKey != expected_spk) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "scriptPubKey mismatch — partials don't decode to this output");
            }
            // Rewind the rangeproof using the joint shared secret as nonce.
            auto rp_nonce = ::pricoin::stealth::DeriveRangeProofNonce(*shared_point, vout);
            ::pricoin::ct::BlindingFactor nonce_arr{};
            std::memcpy(nonce_arr.data(), rp_nonce.data(), 32);
            const auto& outp = tx.ct_bundle.outputs[vout];
            const auto& script = outp.script_pubkey;
            auto rewound = ::pricoin::ct::RewindRangeProof(
                outp.commitment,
                std::span<const unsigned char>{outp.rangeproof.data(), outp.rangeproof.size()},
                std::span<const unsigned char>{script.data(), script.size()},
                nonce_arr);
            if (!rewound) throw JSONRPCError(RPC_INTERNAL_ERROR, "rangeproof rewind failed");

            UniValue out{UniValue::VOBJ};
            out.pushKV("value", ValueFromAmount(static_cast<CAmount>(rewound->value)));
            out.pushKV("blind", HexStr(rewound->blind));
            out.pushKV("vout", static_cast<int>(vout));
            return out;
        }
    };
}

// Atomic-swap stage 2b — produce a v4 spend-tx skeleton (empty CLSAG)
// for a joint stealth output, plus everything the cooperative
// signing protocol needs: the multi-layer ring, signer's index pi,
// the deterministic sighash, and a pre-randomised z-split for the
// two parties.
//
// The caller (the spending side, traditionally Alice) drives the
// flow:
//   1. Run pricoin_jointspend_loadshare to learn the joint output's
//      value/blind/pubkey and her x_share.
//   2. Run THIS RPC to build the skeleton + everything for signing.
//   3. Send (tx_hex, z_other_share) to the counterparty along with
//      the sighash + ring + pi (the counterparty will RE-derive ring
//      and sighash from the tx_hex to be sure she didn't lie).
//   4. Run the cooperative-signing rounds (round1 → combine →
//      share → assemble) to produce a multi-layer CLSAG.
//   5. Run pricoin_jointspend_submittx to inject the signature into
//      the skeleton and broadcast.
RPCMethod pricoin_jointspend_buildtx()
{
    return RPCMethod{
        "pricoin_jointspend_buildtx",
        "Build a v4 spend-tx skeleton (with empty CLSAG) for a joint stealth output.\n"
        "\n"
        "Returns the tx hex, the deterministic sighash that the cooperative\n"
        "CLSAG must commit to, the multi-layer ring (P_i, W_i for each ring\n"
        "member), the signer's index, and a random z-split so the two parties\n"
        "can run the multi-layer cooperative protocol symmetrically.\n"
        "\n"
        "WARNING: z_self embeds the wallet's joint-output blind (b_prev). Treat\n"
        "with care; only the spender (the party calling this RPC) should hold it.\n",
        {
            {"joint_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Tx id of the joint stealth output being spent"},
            {"joint_vout", RPCArg::Type::NUM, RPCArg::Optional::NO,
                "Vout index of the joint stealth output"},
            {"joint_value", RPCArg::Type::AMOUNT, RPCArg::Optional::NO,
                "Recovered value of the joint output (from loadshare)"},
            {"joint_blind", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "32-byte rangeproof blind from loadshare (b_prev)"},
            {"joint_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "33-byte one-time pubkey at the joint output"},
            {"dest_address", RPCArg::Type::STR, RPCArg::Optional::NO,
                "Destination Pricoin stealth address"},
            {"dest_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount in PRIC"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Transparent fee in PRIC"},
            {"ring_size", RPCArg::Type::NUM, RPCArg::Default{4},
                "Total ring size (must have ring_size-1 chain decoys)"},
            {"nlocktime", RPCArg::Type::NUM, RPCArg::Default{0},
                "Absolute block-height nLockTime to bake into the tx. 0 = no\n"
                "timelock (default — claim-tx behaviour). Set ≥ T_pric_refund\n"
                "(spec §6.2 step 7) to produce a refund-tx skeleton."},
            {"funding_tx_hex", RPCArg::Type::STR_HEX, RPCArg::Default{""},
                "Optional unsigned-but-signed funding tx hex. When provided, the\n"
                "joint output's commitment + one-time pubkey are read from this\n"
                "hex instead of the chain, allowing the cooperative ceremony to\n"
                "run BEFORE the funding tx is broadcast. The funding_txid must\n"
                "still match the hex's computed hash. Empty = legacy behaviour\n"
                "(chain lookup required, funding must be confirmed)."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "tx_hex", "Hex tx skeleton (empty CLSAG, ready for signing)"},
                {RPCResult::Type::STR_HEX, "sighash", "32-byte sighash to sign"},
                {RPCResult::Type::ARR, "ring_ml", "Multi-layer ring members",
                    {{RPCResult::Type::OBJ, "", "",
                      {{RPCResult::Type::STR_HEX, "P", ""},
                       {RPCResult::Type::STR_HEX, "W", ""}}}}},
                {RPCResult::Type::NUM, "pi", "Signer's index in the ring"},
                {RPCResult::Type::STR_HEX, "z_self",
                    "32-byte z-share for the spender (this party). Use as z_share in round1."},
                {RPCResult::Type::STR_HEX, "z_other",
                    "32-byte z-share to send to the counterparty. They use it as their z_share."},
                {RPCResult::Type::STR_HEX, "joint_pubkey",
                    "Echo: the one-time pubkey at ring[pi].P"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_jointspend_buildtx",
            "<joint_txid> <vout> 4.2 <blind hex> <P hex> <stealth dest> 1.0 0.0001 4")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;
            interfaces::Chain& chain = wallet.chain();

            const std::string joint_txid_hex = request.params[0].get_str();
            const uint32_t joint_vout = request.params[1].getInt<uint32_t>();
            const CAmount joint_value = AmountFromValue(request.params[2]);
            const std::string joint_blind_hex = request.params[3].get_str();
            const std::string joint_pubkey_hex = request.params[4].get_str();
            const std::string dest_addr_str = request.params[5].get_str();
            const CAmount dest_amount = AmountFromValue(request.params[6]);
            const CAmount fee = AmountFromValue(request.params[7]);
            const int ring_size = request.params[8].isNull() ? 4 : request.params[8].getInt<int>();
            if (ring_size < 2) throw JSONRPCError(RPC_INVALID_PARAMETER, "ring_size must be >= 2");
            const int64_t nlocktime = request.params[9].isNull() ? 0 : request.params[9].getInt<int64_t>();
            if (nlocktime < 0 || nlocktime > 0xffffffff) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "nlocktime must fit in uint32 (use 0 for no timelock)");
            }
            const std::string funding_tx_hex =
                request.params[10].isNull() ? std::string{} : request.params[10].get_str();

            auto joint_txid_opt = uint256::FromHex(joint_txid_hex);
            if (!joint_txid_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "joint_txid not hex");
            if (!IsHex(joint_blind_hex) || joint_blind_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "joint_blind must be 32 bytes hex");
            }
            if (!IsHex(joint_pubkey_hex) || joint_pubkey_hex.size() != 66) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "joint_pubkey must be 33 bytes hex");
            }
            const auto blind_bytes = ParseHex(joint_blind_hex);
            const auto pub_bytes = ParseHex(joint_pubkey_hex);
            pricoin::ct::BlindingFactor joint_blind{};
            std::memcpy(joint_blind.data(), blind_bytes.data(), 32);
            pricoin::ct::SerializedPubKey33 joint_pubkey{};
            std::memcpy(joint_pubkey.data(), pub_bytes.data(), 33);

            auto parsed_dest = ::pricoin::stealth::ParseStealthAddress(dest_addr_str);
            if (!parsed_dest) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "dest_address must be a stealth address");
            const auto* stealth_dest = &parsed_dest->address;
            const auto dest_kind = parsed_dest->kind;

            // Source the joint output's commitment + one_time_pubkey.
            // Two paths:
            //   1. Caller passed funding_tx_hex — decode it, verify the
            //      computed txid matches, and read commitment + otp from
            //      the embedded ct_bundle. Lets the cooperative ceremony
            //      run BEFORE the funding tx is broadcast (post-2026-05-15
            //      protocol order).
            //   2. Default — look the funding output up on chain via
            //      findCoins. Requires the funding to be confirmed.
            const COutPoint joint_outpoint{Txid::FromUint256(*joint_txid_opt), joint_vout};
            pricoin::ct::Commitment           joint_commitment{};
            pricoin::ct::SerializedPubKey33   joint_coin_otp{};
            if (!funding_tx_hex.empty()) {
                CMutableTransaction fmtx;
                if (!DecodeHexTx(fmtx, funding_tx_hex,
                                  /*try_no_witness=*/true, /*try_witness=*/true)) {
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                        "funding_tx_hex failed to decode");
                }
                CTransaction ftx{std::move(fmtx)};
                if (ftx.GetHash().ToUint256() != *joint_txid_opt) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "funding_tx_hex hashes to a different txid than joint_txid");
                }
                if (ftx.version != PRICOIN_CT_VERSION) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "funding_tx_hex is not a v4 confidential tx");
                }
                if (joint_vout >= ftx.ct_bundle.outputs.size()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "joint_vout out of range for funding_tx_hex");
                }
                joint_commitment = ftx.ct_bundle.outputs[joint_vout].commitment;
                joint_coin_otp   = ftx.ct_bundle.outputs[joint_vout].one_time_pubkey;
            } else {
                Coin joint_coin;
                std::map<COutPoint, Coin> coins{{joint_outpoint, Coin{}}};
                chain.findCoins(coins);
                joint_coin = coins[joint_outpoint];
                if (joint_coin.IsSpent() || !joint_coin.IsConfidential()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "joint outpoint not a confirmed v4 output");
                }
                joint_commitment = joint_coin.commitment;
                joint_coin_otp   = joint_coin.one_time_pubkey;
            }
            {
                auto rebuilt = pricoin::ct::Commitment::Create(static_cast<uint64_t>(joint_value), joint_blind);
                if (!rebuilt || *rebuilt != joint_commitment) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "joint_value+joint_blind do not reconstruct the funding commitment");
                }
            }
            if (joint_coin_otp != joint_pubkey) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "joint_pubkey does not match the funding one_time_pubkey");
            }

            const CAmount target = dest_amount + fee;
            if (target > joint_value) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "joint_value < dest_amount + fee");
            }
            const CAmount change_value = joint_value - target;

            const auto& id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
            const int tip = chain.getHeight().value_or(-1);

            // Build decoy pool — exclude the joint outpoint itself.
            auto pool = CollectChainCTOutputs(chain);
            std::vector<ChainCTOutput> decoy_pool;
            for (auto& c : pool) {
                if (c.ref.hash == joint_outpoint.hash.ToUint256()
                    && c.ref.n == joint_outpoint.n) continue;
                decoy_pool.push_back(std::move(c));
            }
            if ((int)decoy_pool.size() < ring_size - 1) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    strprintf("Not enough chain CT outputs for ring_size=%d (have %d decoys)",
                              ring_size, (int)decoy_pool.size()));
            }
            FastRandomContext rng;
            auto decoys = SampleDecoysRecencyWeighted(
                std::move(decoy_pool), static_cast<size_t>(ring_size - 1), tip, rng);

            // Insert joint output at random pi.
            const size_t pi = rng.randrange(static_cast<uint32_t>(ring_size));
            std::vector<ChainCTOutput> ring(ring_size);
            for (size_t k = 0, d = 0; k < (size_t)ring_size; ++k) {
                if (k == pi) {
                    ring[k] = ChainCTOutput{
                        .ref = pricoin::ct::PrevoutRef{joint_outpoint.hash.ToUint256(), joint_outpoint.n},
                        .commitment = joint_commitment,
                        .one_time_pubkey = joint_pubkey,
                    };
                } else {
                    ring[k] = decoys[d++];
                }
            }

            // Pseudo input commitment.
            pricoin::ct::BlindingFactor pseudo_blind;
            GetRandBytes(pseudo_blind);
            auto pseudo = pricoin::ct::Commitment::Create(static_cast<uint64_t>(joint_value), pseudo_blind);
            if (!pseudo) throw JSONRPCError(RPC_INTERNAL_ERROR, "pseudo commit failed");

            // z_total = joint_blind − pseudo_blind (mod n).
            pricoin::ringsig::Scalar z_total;
            {
                auto neg = pricoin::ct::NegateScalar(pseudo_blind);
                if (!neg) throw JSONRPCError(RPC_INTERNAL_ERROR, "z negate failed");
                auto sum = pricoin::ct::AddScalars(joint_blind, *neg);
                if (!sum) throw JSONRPCError(RPC_INTERNAL_ERROR, "z add failed");
                std::memcpy(z_total.data(), sum->data(), 32);
            }
            // Random split: z_other = r, z_self = z_total − r (mod n). Retry
            // on the (negligible-probability) case where either side hits zero.
            pricoin::ringsig::Scalar z_self_scalar{}, z_other_scalar{};
            for (;;) {
                pricoin::ct::BlindingFactor r_bf;
                GetRandBytes(r_bf);
                pricoin::ringsig::Scalar r;
                std::memcpy(r.data(), r_bf.data(), 32);
                pricoin::ct::BlindingFactor neg_r;
                {
                    auto neg = pricoin::ct::NegateScalar(r_bf);
                    if (!neg) continue;
                    neg_r = *neg;
                }
                pricoin::ct::BlindingFactor zt_bf;
                std::memcpy(zt_bf.data(), z_total.data(), 32);
                auto self_bf = pricoin::ct::AddScalars(zt_bf, neg_r);
                if (!self_bf) continue;
                z_other_scalar = r;
                std::memcpy(z_self_scalar.data(), self_bf->data(), 32);
                break;
            }

            // Build outputs: dest + change + (always 3 to mirror walletsendct_ring).
            struct PendingOut {
                const ::pricoin::stealth::StealthAddress* stealth;
                CAmount amount;
                ::pricoin::stealth::AddressKind kind;
            };
            std::vector<PendingOut> pending;
            pending.reserve(3);
            pending.push_back({stealth_dest, dest_amount, dest_kind});
            pending.push_back({&id.public_address, change_value,
                               ::pricoin::stealth::AddressKind::Main});
            while (pending.size() < 3) pending.push_back({&id.public_address, 0,
                                                          ::pricoin::stealth::AddressKind::Main});
            FastRandomContext shuffle_rng;
            std::shuffle(pending.begin(), pending.end(), shuffle_rng);

            struct ResolvedOut {
                CScript spk;
                ::pricoin::stealth::PointBytes R;
                ::pricoin::ct::BlindingFactor nonce;
                ::pricoin::ct::SerializedPubKey33 otp;
                CAmount amount;
            };
            std::vector<ResolvedOut> outs;
            outs.reserve(pending.size());
            for (size_t i = 0; i < pending.size(); ++i) {
                CKey r; r.MakeNewKey(true);
                ResolvedOut ro;
                ro.amount = pending[i].amount;
                const auto R_bytes = ::pricoin::stealth::ComputeStealthR(
                    r, *pending[i].stealth, pending[i].kind);
                if (!R_bytes) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth R derivation failed");
                std::memcpy(ro.R.data(), R_bytes->data(), 33);
                auto S = ::pricoin::stealth::ECDHPoint(r, pending[i].stealth->view);
                if (!S) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth ECDH failed");
                auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, static_cast<uint32_t>(i));
                auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, pending[i].stealth->spend);
                if (!P) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth onetime failed");
                ro.spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
                std::memcpy(ro.otp.data(), P->data(), 33);
                auto rp_nonce = ::pricoin::stealth::DeriveRangeProofNonce(*S, static_cast<uint32_t>(i));
                std::memcpy(ro.nonce.data(), rp_nonce.data(), 32);
                outs.push_back(std::move(ro));
            }

            // Output blinds sum to pseudo_blind.
            const size_t Nout = outs.size();
            std::vector<pricoin::ct::BlindingFactor> out_blinds(Nout);
            for (size_t i = 0; i + 1 < Nout; ++i) GetRandBytes(out_blinds[i]);
            {
                std::span<const pricoin::ct::BlindingFactor> other_outs{out_blinds.data(), Nout - 1};
                auto last = pricoin::ct::BalancingBlind(
                    std::array<pricoin::ct::BlindingFactor, 1>{pseudo_blind},
                    other_outs);
                if (!last) throw JSONRPCError(RPC_INTERNAL_ERROR, "blind sum failed");
                out_blinds.back() = *last;
            }

            std::vector<pricoin::ct::CTOutput> ct_outputs;
            ct_outputs.reserve(Nout);
            for (size_t i = 0; i < Nout; ++i) {
                auto commit = pricoin::ct::Commitment::Create(static_cast<uint64_t>(outs[i].amount), out_blinds[i]);
                if (!commit) throw JSONRPCError(RPC_INTERNAL_ERROR, "output commit failed");
                std::vector<unsigned char> spk_bytes(outs[i].spk.begin(), outs[i].spk.end());
                auto proof = pricoin::ct::CreateRangeProof(
                    static_cast<uint64_t>(outs[i].amount), out_blinds[i], *commit,
                    std::span<const unsigned char>{spk_bytes}, outs[i].nonce);
                if (!proof) throw JSONRPCError(RPC_INTERNAL_ERROR, "output rangeproof failed");
                ct_outputs.push_back(pricoin::ct::CTOutput{
                    *commit, *proof, std::move(spk_bytes), outs[i].R, outs[i].otp});
            }

            // Bundle.
            pricoin::ct::CTRingInput ring_input;
            ring_input.ring.reserve(ring_size);
            for (const auto& m : ring) ring_input.ring.push_back(m.ref);
            ring_input.pseudo_commitment = *pseudo;
            // ring_input.sig stays empty — that's the whole point.

            pricoin::ct::CTBundle bundle;
            bundle.ring_inputs = {ring_input};
            bundle.outputs = std::move(ct_outputs);
            bundle.transparent_fee = static_cast<uint64_t>(fee);

            CMutableTransaction mtx;
            mtx.version = PRICOIN_CT_VERSION;
            mtx.nLockTime = static_cast<uint32_t>(nlocktime);
            const COutPoint marker_outpoint{
                Txid::FromUint256(ring_input.ring[0].hash), ring_input.ring[0].n};
            mtx.vin.emplace_back(marker_outpoint, CScript{}, 0xfffffffe);
            for (const auto& o : outs) mtx.vout.emplace_back(0, o.spk);
            mtx.ct_bundle = std::move(bundle);

            // Compute the deterministic sighash that the cooperative CLSAG
            // must commit to (= ComputeRingMessage in validation.cpp).
            CMutableTransaction sig_input_tx{mtx};
            for (auto& ri : sig_input_tx.ct_bundle.ring_inputs) {
                ri.sig = pricoin::ringsig::Signature{};
            }
            HashWriter hw{};
            hw << TX_NO_WITNESS(CTransaction{sig_input_tx});
            const uint256 sighash = hw.GetSHA256();

            // Multi-layer ring members for the cooperative protocol.
            UniValue ring_ml_arr{UniValue::VARR};
            for (size_t k = 0; k < (size_t)ring_size; ++k) {
                auto W = pricoin::ct::SubtractCommitments(ring[k].commitment, *pseudo);
                if (!W) throw JSONRPCError(RPC_INTERNAL_ERROR, "W computation failed");
                UniValue m{UniValue::VOBJ};
                m.pushKV("P", HexStr(ring[k].one_time_pubkey));
                m.pushKV("W", HexStr(*W));
                ring_ml_arr.push_back(std::move(m));
            }

            // Serialise the skeleton (with empty sig).
            DataStream ds;
            ds << TX_WITH_WITNESS(CTransaction{std::move(mtx)});

            UniValue out{UniValue::VOBJ};
            out.pushKV("tx_hex", HexStr(ds));
            // Raw-byte hex (NOT uint256::ToString, which reverses for
            // display); the cooperative-CLSAG RPCs interpret 32-byte hex
            // as raw bytes, matching how validation.cpp's ComputeRingMessage
            // consumes the sighash internally.
            out.pushKV("sighash",
                HexStr(std::span<const unsigned char>{sighash.data(), 32}));
            out.pushKV("ring_ml", std::move(ring_ml_arr));
            out.pushKV("pi", static_cast<int>(pi));
            out.pushKV("z_self", HexStr(z_self_scalar));
            out.pushKV("z_other", HexStr(z_other_scalar));
            out.pushKV("joint_pubkey", HexStr(joint_pubkey));
            return out;
        }
    };
}

// Atomic-swap stage 2b — inject an externally-supplied (cooperative)
// CLSAG signature into a tx skeleton produced by buildtx and broadcast.
RPCMethod pricoin_jointspend_submittx()
{
    return RPCMethod{
        "pricoin_jointspend_submittx",
        "Inject a cooperatively-assembled CLSAG signature into the tx skeleton\n"
        "produced by pricoin_jointspend_buildtx and broadcast the result.\n"
        "Returns the broadcast txid on success.\n",
        {
            {"tx_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Skeleton tx hex from pricoin_jointspend_buildtx"},
            {"signature_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Hex-encoded pricoin::ringsig::Signature from pricoin_jointspend_assemble"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "Broadcast tx id"},
                {RPCResult::Type::NUM, "size", "Final tx size with signature"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_jointspend_submittx", "<tx_hex> <signature_hex>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;

            const std::string tx_hex = request.params[0].get_str();
            const std::string sig_hex = request.params[1].get_str();

            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, tx_hex, /*try_no_witness=*/true, /*try_witness=*/true)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "tx hex failed to decode");
            }
            if (mtx.version != PRICOIN_CT_VERSION) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "tx is not a v4 confidential tx");
            }
            if (mtx.ct_bundle.ring_inputs.size() != 1) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "expected exactly one ring input (joint-spend convention)");
            }

            auto sig_bytes = TryParseHex<unsigned char>(sig_hex);
            if (!sig_bytes) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "signature_hex invalid");
            }
            DataStream ds{std::span<const unsigned char>{*sig_bytes}};
            pricoin::ringsig::Signature sig;
            try {
                ds >> sig;
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    std::string("signature deserialise failed: ") + e.what());
            }

            mtx.ct_bundle.ring_inputs[0].sig = std::move(sig);

            CTransactionRef tx_ref = MakeTransactionRef(std::move(mtx));
            std::string err_str;
            if (!wallet.chain().broadcastTransaction(
                    tx_ref, MAX_MONEY,
                    node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL,
                    err_str)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "broadcast failed: " + err_str);
            }

            UniValue out{UniValue::VOBJ};
            out.pushKV("txid", tx_ref->GetHash().ToString());
            out.pushKV("size", (int)::GetSerializeSize(TX_WITH_WITNESS(*tx_ref)));
            return out;
        }
    };
}

// ─────────────────────────────────────────────────────────────────
// Atomic-swap stage 2b — swap session lifecycle RPCs.
// Each RPC is wallet-level; sessions are persisted in this wallet's
// DB (encrypted via the same EncryptWalletBlob pattern as the
// stealth-identity record).
// ─────────────────────────────────────────────────────────────────

namespace ssh = ::wallet::pricoin_swap_session;

namespace {

// Convert a SwapSession to a UniValue object for RPC output. Strips
// the per-session priv (it's secret).
UniValue SwapSessionToJSON(const ssh::SwapSession& s)
{
    UniValue out{UniValue::VOBJ};
    out.pushKV("session_id", s.session_id.ToString());
    out.pushKV("my_pubkey", HexStr(s.my_pub));
    out.pushKV("counterparty_pubkey", HexStr(s.counterparty_pub));
    out.pushKV("role", s.role == ssh::Role::Initiator ? "initiator" : "responder");
    switch (s.state) {
        case ssh::State::Active:   out.pushKV("state", "active"); break;
        case ssh::State::Complete: out.pushKV("state", "complete"); break;
        case ssh::State::Aborted:  out.pushKV("state", "aborted"); break;
    }
    if (s.state == ssh::State::Complete && !s.spend_txid.IsNull()) {
        out.pushKV("spend_txid", s.spend_txid.ToString());
    }
    if (s.state == ssh::State::Aborted && s.blame.reason != ssh::BlameReason::None) {
        UniValue blame{UniValue::VOBJ};
        switch (s.blame.reason) {
            case ssh::BlameReason::InvalidSignature:   blame.pushKV("reason", "invalid_signature"); break;
            case ssh::BlameReason::CommitmentMismatch: blame.pushKV("reason", "commitment_mismatch"); break;
            case ssh::BlameReason::InvalidShare:       blame.pushKV("reason", "invalid_share"); break;
            case ssh::BlameReason::Other:              blame.pushKV("reason", "other"); break;
            case ssh::BlameReason::None:               break;
        }
        blame.pushKV("payload",   HexStr(s.blame.payload));
        blame.pushKV("signature", HexStr(s.blame.signature));
        blame.pushKV("detail",    s.blame.detail);
        out.pushKV("blame", std::move(blame));
    }
    out.pushKV("memo", s.memo);
    out.pushKV("created_time", s.created_time);
    out.pushKV("updated_time", s.updated_time);
    return out;
}

ssh::BlameReason ParseBlameReason(const std::string& str)
{
    if (str == "invalid_signature")   return ssh::BlameReason::InvalidSignature;
    if (str == "commitment_mismatch") return ssh::BlameReason::CommitmentMismatch;
    if (str == "invalid_share")       return ssh::BlameReason::InvalidShare;
    if (str == "other")               return ssh::BlameReason::Other;
    return ssh::BlameReason::None;
}

CPubKey ParseSessionPubkey(const std::string& hex, const char* name)
{
    if (!IsHex(hex) || hex.size() != 66) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("%s must be 66 hex characters (33 bytes)", name));
    }
    auto bytes = ParseHex(hex);
    CPubKey pub{std::span<const unsigned char>{bytes.data(), bytes.size()}};
    if (!pub.IsValid() || !pub.IsCompressed()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("%s is not a valid compressed secp256k1 point", name));
    }
    return pub;
}

void ThrowFromCreateResult(ssh::CreateResult r)
{
    using R = ssh::CreateResult;
    switch (r) {
        case R::Ok: return;
        case R::InvalidCounterpartyPubkey:
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid counterparty pubkey");
        case R::DuplicateSessionId:
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Session id already exists in this wallet");
        case R::Locked:
            throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is locked");
        case R::DerivationFailed:
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Per-session key derivation failed");
        case R::WriteFailed:
            throw JSONRPCError(RPC_WALLET_ERROR, "Persistence failed");
    }
}

void ThrowFromTransition(ssh::TransitionResult r)
{
    using R = ssh::TransitionResult;
    switch (r) {
        case R::Ok: return;
        case R::NotFound:
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Session not found");
        case R::InvalidState:
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Session is not in Active state");
        case R::InvalidBlame:
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Blame payload signature does not verify against counterparty pubkey");
        case R::Locked:
            throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is locked");
        case R::WriteFailed:
            throw JSONRPCError(RPC_WALLET_ERROR, "Persistence failed");
    }
}

} // namespace

RPCMethod pricoin_swap_identity()
{
    return RPCMethod{
        "pricoin_swap_identity",
        "Return this wallet's stable swap-identity ECDSA pubkey. The same\n"
        "pubkey is reused across all swap sessions; safe to advertise once\n"
        "in an order book listing.\n"
        "\n"
        "Derivation: HMAC-SHA256(stealth_spend_priv, \"pricoin/swap/identity-v1\").\n"
        "Recoverable from the wallet seed.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "pubkey", "33-byte compressed secp256k1 pubkey"}}
        },
        RPCExamples{HelpExampleCli("pricoin_swap_identity", "")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            auto pub = ::wallet::pricoin_swap_session::GetSwapIdentityPubkey(*wallet_sp);
            if (!pub) {
                throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                    "Wallet locked, or identity derivation failed");
            }
            UniValue out{UniValue::VOBJ};
            out.pushKV("pubkey", HexStr(*pub));
            return out;
        }
    };
}

RPCMethod pricoin_swap_session_create()
{
    return RPCMethod{
        "pricoin_swap_session_create",
        "Create a new swap session as the initiator. Generates a fresh\n"
        "32-byte session_id and derives a per-session ECDSA signing key\n"
        "from the wallet's stealth spend priv + session_id. The caller\n"
        "exposes (session_id, my_pubkey) to the counterparty out-of-band.\n",
        {
            {"counterparty_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Counterparty's session pubkey (33 bytes hex)"},
            {"memo", RPCArg::Type::STR, RPCArg::Default{""}, "Free-form note for the user"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "session_id", "32-byte hex"},
                {RPCResult::Type::STR_HEX, "my_pubkey",  "33-byte hex"},
                {RPCResult::Type::STR_HEX, "counterparty_pubkey", "Echo"},
                {RPCResult::Type::STR,     "role",       "initiator|responder"},
                {RPCResult::Type::STR,     "state",      "active|complete|aborted"},
                {RPCResult::Type::STR_HEX, "spend_txid", /*optional=*/true, "Set when state == complete"},
                {RPCResult::Type::OBJ, "blame", /*optional=*/true, "Set when state == aborted with blame", {}},
                {RPCResult::Type::STR,     "memo",       "Caller-supplied free-form note"},
                {RPCResult::Type::NUM,     "created_time", "Unix seconds"},
                {RPCResult::Type::NUM,     "updated_time", "Unix seconds"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_swap_session_create", "<counterparty_pubkey> \"swap with bob\"")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CPubKey cp = ParseSessionPubkey(request.params[0].get_str(), "counterparty_pubkey");
            const std::string memo = request.params[1].isNull() ? "" : request.params[1].get_str();
            ssh::SwapSession s;
            ThrowFromCreateResult(ssh::Create(*wallet_sp, cp, memo, s));
            return SwapSessionToJSON(s);
        }
    };
}

RPCMethod pricoin_swap_session_attach()
{
    return RPCMethod{
        "pricoin_swap_session_attach",
        "Adopt an existing swap session as the responder. Takes the\n"
        "session_id and counterparty pubkey received from the initiator\n"
        "out-of-band; derives this wallet's matching per-session key.\n",
        {
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "32-byte session_id supplied by the initiator"},
            {"counterparty_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Initiator's session pubkey (33 bytes hex)"},
            {"memo", RPCArg::Type::STR, RPCArg::Default{""}, "Free-form note"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "session_id", "Echo"},
                {RPCResult::Type::STR_HEX, "my_pubkey",  "33-byte hex"},
                {RPCResult::Type::STR_HEX, "counterparty_pubkey", "Echo"},
                {RPCResult::Type::STR,     "role",       "initiator|responder"},
                {RPCResult::Type::STR,     "state",      "active|complete|aborted"},
                {RPCResult::Type::STR_HEX, "spend_txid", /*optional=*/true, ""},
                {RPCResult::Type::OBJ, "blame", /*optional=*/true, "", {}},
                {RPCResult::Type::STR,     "memo",       ""},
                {RPCResult::Type::NUM,     "created_time", ""},
                {RPCResult::Type::NUM,     "updated_time", ""},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_swap_session_attach", "<session_id> <counterparty_pubkey>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            auto sid_opt = uint256::FromHex(request.params[0].get_str());
            if (!sid_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "session_id must be 32-byte hex");
            CPubKey cp = ParseSessionPubkey(request.params[1].get_str(), "counterparty_pubkey");
            const std::string memo = request.params[2].isNull() ? "" : request.params[2].get_str();
            ssh::SwapSession s;
            ThrowFromCreateResult(ssh::Attach(*wallet_sp, *sid_opt, cp, memo, s));
            return SwapSessionToJSON(s);
        }
    };
}

RPCMethod pricoin_swap_session_sign()
{
    return RPCMethod{
        "pricoin_swap_session_sign",
        "Sign an arbitrary payload with this wallet's per-session signing\n"
        "key. Used to attest each round-message in the cooperative\n"
        "protocol so the counterparty can attribute misbehaviour to a\n"
        "specific (session_id, my_pubkey) pair.\n",
        {
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"payload_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Arbitrary payload bytes"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "signature", "ECDSA-DER signature"}}
        },
        RPCExamples{HelpExampleCli("pricoin_swap_session_sign", "<session_id> <payload>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            auto sid_opt = uint256::FromHex(request.params[0].get_str());
            if (!sid_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "session_id must be 32-byte hex");
            auto payload = TryParseHex<unsigned char>(request.params[1].get_str());
            if (!payload) throw JSONRPCError(RPC_INVALID_PARAMETER, "payload_hex invalid");
            std::vector<unsigned char> sig;
            if (!ssh::Sign(*wallet_sp, *sid_opt,
                           std::span<const unsigned char>{*payload}, sig)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Sign failed (session not found, locked, or key invalid)");
            }
            UniValue out{UniValue::VOBJ};
            out.pushKV("signature", HexStr(sig));
            return out;
        }
    };
}

RPCMethod pricoin_swap_session_verify()
{
    return RPCMethod{
        "pricoin_swap_session_verify",
        "Verify a payload signature against the session's stored\n"
        "counterparty_pubkey. Returns valid=true iff the signature is\n"
        "valid AND the session record exists locally.\n",
        {
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"payload_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"signature_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::BOOL, "valid", ""}}
        },
        RPCExamples{HelpExampleCli("pricoin_swap_session_verify", "<session_id> <payload> <sig>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            auto sid_opt = uint256::FromHex(request.params[0].get_str());
            if (!sid_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "session_id must be 32-byte hex");
            auto payload = TryParseHex<unsigned char>(request.params[1].get_str());
            if (!payload) throw JSONRPCError(RPC_INVALID_PARAMETER, "payload_hex invalid");
            auto sig = TryParseHex<unsigned char>(request.params[2].get_str());
            if (!sig) throw JSONRPCError(RPC_INVALID_PARAMETER, "signature_hex invalid");
            const bool ok = ssh::Verify(*wallet_sp, *sid_opt,
                std::span<const unsigned char>{*payload},
                std::span<const unsigned char>{*sig});
            UniValue out{UniValue::VOBJ};
            out.pushKV("valid", ok);
            return out;
        }
    };
}

RPCMethod pricoin_swap_session_complete()
{
    return RPCMethod{
        "pricoin_swap_session_complete",
        "Mark a session as Complete with the on-chain spend txid.\n"
        "Call this after pricoin_jointspend_submittx returns successfully.\n",
        {
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"spend_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "On-chain spend tx id"},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Session record (see pricoin_swap_session_create for shape)" },
        RPCExamples{HelpExampleCli("pricoin_swap_session_complete", "<session_id> <spend_txid>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            auto sid_opt = uint256::FromHex(request.params[0].get_str());
            if (!sid_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "session_id must be 32-byte hex");
            auto txid_opt = uint256::FromHex(request.params[1].get_str());
            if (!txid_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "spend_txid must be 32-byte hex");
            ThrowFromTransition(ssh::Complete(*wallet_sp, *sid_opt, *txid_opt));
            ssh::SwapSession s;
            if (ssh::Get(*wallet_sp, *sid_opt, s) != ssh::LookupResult::Ok) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Session vanished after Complete");
            }
            return SwapSessionToJSON(s);
        }
    };
}

RPCMethod pricoin_swap_session_abort()
{
    return RPCMethod{
        "pricoin_swap_session_abort",
        "Mark a session as Aborted. Optional blame ticket — payload +\n"
        "signature from the counterparty plus a reason — must verify\n"
        "against the counterparty's session pubkey or the call rejects.\n"
        "An abort without a blame ticket is permitted (e.g., voluntary\n"
        "timeout).\n",
        {
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"blame", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED,
                "Blame ticket — counterparty's signed misbehaviour message",
                {{"reason", RPCArg::Type::STR, RPCArg::Optional::NO,
                  "One of: invalid_signature, commitment_mismatch, invalid_share, other"},
                 {"payload",   RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                 {"signature", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                 {"detail",    RPCArg::Type::STR,     RPCArg::Default{""}, ""}}},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Session record (see pricoin_swap_session_create for shape)" },
        RPCExamples{HelpExampleCli("pricoin_swap_session_abort",
            R"(<session_id> '{"reason":"commitment_mismatch","payload":"<hex>","signature":"<hex>"}')")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            auto sid_opt = uint256::FromHex(request.params[0].get_str());
            if (!sid_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "session_id must be 32-byte hex");
            std::optional<ssh::BlameTicket> blame;
            if (!request.params[1].isNull()) {
                const UniValue& b = request.params[1];
                ssh::BlameTicket t;
                t.reason = ParseBlameReason(b.find_value("reason").get_str());
                if (t.reason == ssh::BlameReason::None) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "blame.reason invalid");
                }
                auto payload = TryParseHex<unsigned char>(b.find_value("payload").get_str());
                if (!payload) throw JSONRPCError(RPC_INVALID_PARAMETER, "blame.payload invalid");
                auto sig = TryParseHex<unsigned char>(b.find_value("signature").get_str());
                if (!sig) throw JSONRPCError(RPC_INVALID_PARAMETER, "blame.signature invalid");
                t.payload   = *payload;
                t.signature = *sig;
                const UniValue& d = b.find_value("detail");
                t.detail = d.isStr() ? d.get_str() : "";
                blame = std::move(t);
            }
            ThrowFromTransition(ssh::Abort(*wallet_sp, *sid_opt, std::move(blame)));
            ssh::SwapSession s;
            if (ssh::Get(*wallet_sp, *sid_opt, s) != ssh::LookupResult::Ok) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Session vanished after Abort");
            }
            return SwapSessionToJSON(s);
        }
    };
}

RPCMethod pricoin_swap_session_get()
{
    return RPCMethod{
        "pricoin_swap_session_get",
        "Look up a single swap session by id.\n",
        {{"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""}},
        RPCResult{ RPCResult::Type::ANY, "", "Session record (see pricoin_swap_session_create for shape)" },
        RPCExamples{HelpExampleCli("pricoin_swap_session_get", "<session_id>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            auto sid_opt = uint256::FromHex(request.params[0].get_str());
            if (!sid_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "session_id must be 32-byte hex");
            ssh::SwapSession s;
            const auto r = ssh::Get(*wallet_sp, *sid_opt, s);
            if (r == ssh::LookupResult::Locked) {
                throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is locked");
            }
            if (r != ssh::LookupResult::Ok) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Session not found");
            }
            return SwapSessionToJSON(s);
        }
    };
}

RPCMethod pricoin_swap_session_list()
{
    return RPCMethod{
        "pricoin_swap_session_list",
        "List all swap sessions in this wallet.\n",
        {},
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {{RPCResult::Type::ANY, "", "Session record"}}
        },
        RPCExamples{HelpExampleCli("pricoin_swap_session_list", "")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            std::vector<ssh::SwapSession> all;
            const auto r = ssh::List(*wallet_sp, all);
            if (r == ssh::LookupResult::Locked) {
                throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is locked");
            }
            UniValue out{UniValue::VARR};
            for (const auto& s : all) out.push_back(SwapSessionToJSON(s));
            return out;
        }
    };
}

// ─────────────────────────────────────────────────────────────────
// Atomic-swap stage 3 — swap ceremony state machine RPCs.
// Tracks the multi-step BTC ↔ PRIC swap workflow. State transitions
// are explicit (caller drives them); next_action returns a hint.
// ─────────────────────────────────────────────────────────────────

namespace ssc = ::wallet::pricoin_swap_ceremony;

namespace {

const char* RoleStr(ssc::Role r)
{
    return r == ssc::Role::BuyingForeign ? "buying_foreign" : "selling_foreign";
}
ssc::Role ParseRole(const std::string& s)
{
    if (s == "buying_foreign")  return ssc::Role::BuyingForeign;
    if (s == "selling_foreign") return ssc::Role::SellingForeign;
    throw JSONRPCError(RPC_INVALID_PARAMETER,
        "role must be 'buying_foreign' or 'selling_foreign'");
}

const char* StateStr(ssc::State s)
{
    switch (s) {
        case ssc::State::Init:         return "init";
        case ssc::State::BtcFunded:    return "foreign_funded";
        case ssc::State::PricFunded:   return "pric_funded";
        case ssc::State::BtcClaimed:   return "foreign_claimed";
        case ssc::State::PricReleased: return "pric_released";
        case ssc::State::Complete:     return "complete";
        case ssc::State::Aborted:      return "aborted";
    }
    return "unknown";
}

UniValue CeremonyToJSON(const ssc::SwapCeremony& s)
{
    UniValue out{UniValue::VOBJ};
    out.pushKV("ceremony_id", s.ceremony_id.ToString());
    out.pushKV("role", RoleStr(s.role));
    out.pushKV("state", StateStr(s.state));
    out.pushKV("counterparty_pubkey", HexStr(s.counterparty_pub));

    UniValue foreign{UniValue::VOBJ};
    foreign.pushKV("chain", s.foreign.chain);
    foreign.pushKV("htlc_address", s.foreign.htlc_address);
    foreign.pushKV("redeem_script", HexStr(s.foreign.redeem_script));
    foreign.pushKV("amount_sat", s.foreign.amount_sat);
    foreign.pushKV("timeout", s.foreign.timeout);
    out.pushKV("foreign", std::move(foreign));

    UniValue pric{UniValue::VOBJ};
    pric.pushKV("joint_stealth_address", s.pric.joint_stealth_address);
    pric.pushKV("amount_sat", s.pric.amount_sat);
    if (!s.pric.our_x_share.empty()) {
        // x_share is sensitive — only expose to the wallet's own RPC
        // caller, not in list dumps. Always returning hex here is OK
        // since this whole RPC requires wallet-level auth.
        pric.pushKV("our_x_share", HexStr(s.pric.our_x_share));
    }
    out.pushKV("pric", std::move(pric));

    if (!s.preimage_hash.empty()) out.pushKV("preimage_hash", HexStr(s.preimage_hash));
    if (!s.preimage.empty())      out.pushKV("preimage",      HexStr(s.preimage));

    if (!s.foreign_funding_txid.empty()) {
        out.pushKV("foreign_funding_txid", s.foreign_funding_txid);
        out.pushKV("foreign_funding_vout", s.foreign_funding_vout);
    }
    if (!s.foreign_claim_txid.empty()) out.pushKV("foreign_claim_txid", s.foreign_claim_txid);
    if (!s.pric_funding_txid.IsNull()) {
        out.pushKV("pric_funding_txid", s.pric_funding_txid.ToString());
        out.pushKV("pric_funding_vout", s.pric_funding_vout);
    }
    if (!s.pric_release_txid.IsNull()) out.pushKV("pric_release_txid", s.pric_release_txid.ToString());

    out.pushKV("memo", s.memo);
    out.pushKV("created_time", s.created_time);
    out.pushKV("updated_time", s.updated_time);
    if (!s.abort_reason.empty()) out.pushKV("abort_reason", s.abort_reason);
    out.pushKV("next_action", ssc::NextActionHint(s));
    return out;
}

void ThrowFromCeremonyCreate(ssc::CreateResult r)
{
    using R = ssc::CreateResult;
    switch (r) {
        case R::Ok: return;
        case R::InvalidCounterpartyPubkey:
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid counterparty pubkey");
        case R::InvalidForeignLeg:
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid foreign leg fields");
        case R::InvalidPricLeg:
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid PRIC leg fields");
        case R::InvalidPreimage:
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "preimage_or_hash must be 32 bytes (preimage for buying_foreign, hash for selling_foreign)");
        case R::Locked:
            throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is locked");
        case R::WriteFailed:
            throw JSONRPCError(RPC_WALLET_ERROR, "Persistence failed");
    }
}

void ThrowFromCeremonyTransition(ssc::TransitionResult r)
{
    using R = ssc::TransitionResult;
    switch (r) {
        case R::Ok: return;
        case R::NotFound:
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Ceremony not found");
        case R::InvalidState:
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Ceremony is not in the expected state for this transition");
        case R::InvalidInput:
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid input for this transition");
        case R::Locked:
            throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet is locked");
        case R::WriteFailed:
            throw JSONRPCError(RPC_WALLET_ERROR, "Persistence failed");
    }
}

ssc::ForeignLeg ParseForeignLeg(const UniValue& v)
{
    if (!v.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "foreign must be an object");
    }
    ssc::ForeignLeg f;
    f.chain         = v.find_value("chain").get_str();
    f.htlc_address  = v.find_value("htlc_address").get_str();
    const auto rs   = v.find_value("redeem_script").get_str();
    if (!IsHex(rs)) throw JSONRPCError(RPC_INVALID_PARAMETER, "foreign.redeem_script must be hex");
    f.redeem_script = ParseHex(rs);
    f.amount_sat    = v.find_value("amount_sat").getInt<int64_t>();
    f.timeout       = v.find_value("timeout").getInt<int64_t>();
    return f;
}

ssc::PricLeg ParsePricLeg(const UniValue& v)
{
    if (!v.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "pric must be an object");
    }
    ssc::PricLeg p;
    p.joint_stealth_address = v.find_value("joint_stealth_address").get_str();
    p.amount_sat            = v.find_value("amount_sat").getInt<int64_t>();
    return p;
}

} // namespace

RPCMethod pricoin_swap_ceremony_create()
{
    return RPCMethod{
        "pricoin_swap_ceremony_create",
        "Open a new swap ceremony record. Caller specifies their role,\n"
        "the counterparty's swap-identity pubkey, the foreign-chain leg\n"
        "(chain + HTLC address + redeem script + amount + timeout) and\n"
        "the PRIC leg (joint stealth address + amount).\n"
        "\n"
        "Preimage handling depends on role:\n"
        "  buying_foreign  — caller passes empty `preimage_or_hash` and\n"
        "                    we generate a 32-byte preimage. Hash is\n"
        "                    derived as SHA-256(preimage). Ship the hash\n"
        "                    to the counterparty out-of-band.\n"
        "  selling_foreign — caller passes the 32-byte hash they got\n"
        "                    from the buying counterparty. Preimage is\n"
        "                    learned later from the on-chain claim.\n"
        "\n"
        "WARNING: this state machine alone does NOT make a swap atomic.\n"
        "Without adaptor-CLSAG (deferred), use only with trusted\n"
        "counterparties or alongside slashing-deposit (phase 7).\n",
        {
            {"role", RPCArg::Type::STR, RPCArg::Optional::NO,
                "buying_foreign | selling_foreign"},
            {"counterparty_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Counterparty's stable swap-identity pubkey (33 bytes hex)"},
            {"foreign", RPCArg::Type::OBJ, RPCArg::Optional::NO, "",
                {{"chain", RPCArg::Type::STR, RPCArg::Optional::NO, ""},
                 {"htlc_address", RPCArg::Type::STR, RPCArg::Optional::NO, ""},
                 {"redeem_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                 {"amount_sat", RPCArg::Type::NUM, RPCArg::Optional::NO, ""},
                 {"timeout", RPCArg::Type::NUM, RPCArg::Optional::NO,
                     "Block height or unix time (per OP_CLTV)"}}},
            {"pric", RPCArg::Type::OBJ, RPCArg::Optional::NO, "",
                {{"joint_stealth_address", RPCArg::Type::STR, RPCArg::Optional::NO, ""},
                 {"amount_sat", RPCArg::Type::NUM, RPCArg::Optional::NO, ""}}},
            {"preimage_or_hash", RPCArg::Type::STR_HEX, RPCArg::Default{""},
                "Empty for buying_foreign (we generate); 32-byte hash for selling_foreign"},
            {"memo", RPCArg::Type::STR, RPCArg::Default{""}, "Free-form note"},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Ceremony record" },
        RPCExamples{HelpExampleCli("pricoin_swap_ceremony_create", "<role> <cp_pubkey> {...} {...}")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");

            ssc::Role role = ParseRole(request.params[0].get_str());
            CPubKey cp = ParseSessionPubkey(request.params[1].get_str(), "counterparty_pubkey");
            auto foreign = ParseForeignLeg(request.params[2]);
            auto pric    = ParsePricLeg(request.params[3]);

            std::vector<unsigned char> preimage_or_hash;
            if (!request.params[4].isNull()) {
                const auto h = request.params[4].get_str();
                if (!h.empty()) {
                    if (!IsHex(h)) throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "preimage_or_hash must be hex");
                    preimage_or_hash = ParseHex(h);
                }
            }
            const std::string memo = request.params[5].isNull() ? "" : request.params[5].get_str();

            ssc::SwapCeremony out;
            ThrowFromCeremonyCreate(ssc::Create(
                *wallet_sp, role, cp, foreign, pric,
                std::span<const unsigned char>{preimage_or_hash}, memo, out));
            return CeremonyToJSON(out);
        }
    };
}

RPCMethod pricoin_swap_ceremony_set_foreign_funded()
{
    return RPCMethod{
        "pricoin_swap_ceremony_set_foreign_funded",
        "Mark the foreign-chain HTLC as funded. State: Init → BtcFunded.\n",
        {
            {"ceremony_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"funding_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"funding_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Ceremony record" },
        RPCExamples{HelpExampleCli("pricoin_swap_ceremony_set_foreign_funded", "<id> <txid> 0")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            auto cid = uint256::FromHex(request.params[0].get_str());
            if (!cid) throw JSONRPCError(RPC_INVALID_PARAMETER, "ceremony_id must be 32-byte hex");
            const std::string txid = request.params[1].get_str();
            const int32_t vout = request.params[2].getInt<int32_t>();
            ThrowFromCeremonyTransition(
                ssc::SetForeignFunded(*wallet_sp, *cid, txid, vout));
            ssc::SwapCeremony s;
            ssc::Get(*wallet_sp, *cid, s);
            return CeremonyToJSON(s);
        }
    };
}

RPCMethod pricoin_swap_ceremony_set_pric_funded()
{
    return RPCMethod{
        "pricoin_swap_ceremony_set_pric_funded",
        "Mark the PRIC joint-stealth output as funded. State: BtcFunded → PricFunded.\n"
        "`our_x_share` is the spend-secret share returned by\n"
        "pricoin_jointspend_loadshare (with the agreed absorb_shared_secret\n"
        "convention between the parties).\n",
        {
            {"ceremony_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"pric_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"pric_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, ""},
            {"our_x_share", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "32-byte hex from pricoin_jointspend_loadshare"},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Ceremony record" },
        RPCExamples{HelpExampleCli("pricoin_swap_ceremony_set_pric_funded", "<id> <txid> <vout> <x_share>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            auto cid = uint256::FromHex(request.params[0].get_str());
            if (!cid) throw JSONRPCError(RPC_INVALID_PARAMETER, "ceremony_id must be 32-byte hex");
            auto ptxid = uint256::FromHex(request.params[1].get_str());
            if (!ptxid) throw JSONRPCError(RPC_INVALID_PARAMETER, "pric_txid must be 32-byte hex");
            const int32_t vout = request.params[2].getInt<int32_t>();
            const auto xs_hex = request.params[3].get_str();
            if (!IsHex(xs_hex) || xs_hex.size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "our_x_share must be 32-byte hex");
            }
            const auto xs = ParseHex(xs_hex);
            ThrowFromCeremonyTransition(
                ssc::SetPricFunded(*wallet_sp, *cid, *ptxid, vout,
                    std::span<const unsigned char>{xs}));
            ssc::SwapCeremony s;
            ssc::Get(*wallet_sp, *cid, s);
            return CeremonyToJSON(s);
        }
    };
}

RPCMethod pricoin_swap_ceremony_set_foreign_claimed()
{
    return RPCMethod{
        "pricoin_swap_ceremony_set_foreign_claimed",
        "Mark the foreign-chain HTLC as claimed. State: PricFunded → BtcClaimed.\n"
        "Optional `preimage` — supply the 32-byte secret extracted from\n"
        "the on-chain claim witness (selling_foreign side); the call\n"
        "rejects if SHA-256(preimage) doesn't match the recorded hash.\n",
        {
            {"ceremony_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"claim_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"preimage", RPCArg::Type::STR_HEX, RPCArg::Default{""}, ""},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Ceremony record" },
        RPCExamples{HelpExampleCli("pricoin_swap_ceremony_set_foreign_claimed", "<id> <claim_txid> [preimage]")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            auto cid = uint256::FromHex(request.params[0].get_str());
            if (!cid) throw JSONRPCError(RPC_INVALID_PARAMETER, "ceremony_id must be 32-byte hex");
            const std::string txid = request.params[1].get_str();
            std::vector<unsigned char> preimage;
            if (!request.params[2].isNull() && !request.params[2].get_str().empty()) {
                if (!IsHex(request.params[2].get_str())) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "preimage must be hex");
                }
                preimage = ParseHex(request.params[2].get_str());
            }
            ThrowFromCeremonyTransition(
                ssc::SetForeignClaimed(*wallet_sp, *cid, txid,
                    std::span<const unsigned char>{preimage}));
            ssc::SwapCeremony s;
            ssc::Get(*wallet_sp, *cid, s);
            return CeremonyToJSON(s);
        }
    };
}

RPCMethod pricoin_swap_ceremony_set_pric_released()
{
    return RPCMethod{
        "pricoin_swap_ceremony_set_pric_released",
        "Mark the cooperative PRIC release as broadcast. State: BtcClaimed → Complete.\n",
        {
            {"ceremony_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"release_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Ceremony record" },
        RPCExamples{HelpExampleCli("pricoin_swap_ceremony_set_pric_released", "<id> <release_txid>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            auto cid = uint256::FromHex(request.params[0].get_str());
            if (!cid) throw JSONRPCError(RPC_INVALID_PARAMETER, "ceremony_id must be 32-byte hex");
            auto rtxid = uint256::FromHex(request.params[1].get_str());
            if (!rtxid) throw JSONRPCError(RPC_INVALID_PARAMETER, "release_txid must be 32-byte hex");
            ThrowFromCeremonyTransition(ssc::SetPricReleased(*wallet_sp, *cid, *rtxid));
            ssc::SwapCeremony s;
            ssc::Get(*wallet_sp, *cid, s);
            return CeremonyToJSON(s);
        }
    };
}

RPCMethod pricoin_swap_ceremony_abort()
{
    return RPCMethod{
        "pricoin_swap_ceremony_abort",
        "Abort a ceremony from any non-terminal state.\n",
        {
            {"ceremony_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"reason", RPCArg::Type::STR, RPCArg::Default{""}, ""},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Ceremony record" },
        RPCExamples{HelpExampleCli("pricoin_swap_ceremony_abort", "<id> \"counterparty went silent\"")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            auto cid = uint256::FromHex(request.params[0].get_str());
            if (!cid) throw JSONRPCError(RPC_INVALID_PARAMETER, "ceremony_id must be 32-byte hex");
            const std::string reason = request.params[1].isNull() ? "" : request.params[1].get_str();
            ThrowFromCeremonyTransition(ssc::Abort(*wallet_sp, *cid, reason));
            ssc::SwapCeremony s;
            ssc::Get(*wallet_sp, *cid, s);
            return CeremonyToJSON(s);
        }
    };
}

RPCMethod pricoin_swap_ceremony_get()
{
    return RPCMethod{
        "pricoin_swap_ceremony_get",
        "Look up a single ceremony by id.\n",
        {{"ceremony_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""}},
        RPCResult{ RPCResult::Type::ANY, "", "Ceremony record" },
        RPCExamples{HelpExampleCli("pricoin_swap_ceremony_get", "<id>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            auto cid = uint256::FromHex(request.params[0].get_str());
            if (!cid) throw JSONRPCError(RPC_INVALID_PARAMETER, "ceremony_id must be 32-byte hex");
            ssc::SwapCeremony s;
            const auto r = ssc::Get(*wallet_sp, *cid, s);
            if (r == ssc::LookupResult::Locked) throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
            if (r != ssc::LookupResult::Ok) throw JSONRPCError(RPC_INVALID_PARAMETER, "Ceremony not found");
            return CeremonyToJSON(s);
        }
    };
}

RPCMethod pricoin_swap_ceremony_list()
{
    return RPCMethod{
        "pricoin_swap_ceremony_list",
        "List all ceremonies in this wallet.\n",
        {},
        RPCResult{ RPCResult::Type::ARR, "", "",
            {{RPCResult::Type::ANY, "", "Ceremony record"}} },
        RPCExamples{HelpExampleCli("pricoin_swap_ceremony_list", "")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            std::vector<ssc::SwapCeremony> all;
            const auto r = ssc::List(*wallet_sp, all);
            if (r == ssc::LookupResult::Locked) throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
            UniValue out{UniValue::VARR};
            for (const auto& s : all) out.push_back(CeremonyToJSON(s));
            return out;
        }
    };
}

// ─────────────────────────────────────────────────────────────────
// Atomic-swap phase 5 — §4.1a CLSAG nonce-reuse defence (RPC layer).
// Wallet-level RPCs to begin / mark-published / inspect / erase
// per-joint-output round-1 nonce records. The actual signing flow
// (currently in pricoin_jointspend_round1) will be retrofitted to
// invoke pricoin_clsag_nonce_begin internally in a follow-up; for now
// these RPCs are the user-facing surface that confirms persistence
// works.
// ─────────────────────────────────────────────────────────────────

namespace cnr = ::wallet::pricoin_clsag_nonce_records;
namespace cnp = ::pricoin::clsag_nonce_policy;

namespace {

cnp::Role ParseClsagRole(const std::string& s)
{
    if (s == "initiator") return cnp::Role::Initiator;
    if (s == "responder") return cnp::Role::Responder;
    throw JSONRPCError(RPC_INVALID_PARAMETER,
        "role must be \"initiator\" or \"responder\"");
}

cnp::RecordKey ParseClsagRecordKey(const UniValue& joint_output_id_hex,
                                    const UniValue& ring_hash_hex,
                                    const UniValue& role_str)
{
    auto out_id = TryParseHex<unsigned char>(joint_output_id_hex.get_str());
    if (!out_id || out_id->empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "joint_output_id must be non-empty hex");
    }
    auto ring = uint256::FromHex(ring_hash_hex.get_str());
    if (!ring) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "ring_hash must be 32-byte hex");
    }
    cnp::RecordKey k;
    k.joint_output_id = std::move(*out_id);
    k.ring_hash = *ring;
    k.role = ParseClsagRole(role_str.get_str());
    return k;
}

UniValue ClsagNonceRecordToJSON(const cnp::NonceRecord& r,
                                 bool include_alpha)
{
    UniValue out{UniValue::VOBJ};
    out.pushKV("joint_output_id", HexStr(r.key.joint_output_id));
    out.pushKV("ring_hash", r.key.ring_hash.ToString());
    out.pushKV("role",
        r.key.role == cnp::Role::Initiator ? "initiator" : "responder");
    out.pushKV("session_id", r.session_id.ToString());
    // commitment is treated as raw 32 bytes (matches the byte-order
    // produced by joint_ringsig::NonceCommit and consumed by the
    // existing pricoin_jointspend_round1 RPC). NOT uint256/big-endian
    // display.
    out.pushKV("commitment", HexStr(r.commitment));
    out.pushKV("t_published", r.t_published);
    out.pushKV("created_time", r.created_time);
    out.pushKV("updated_time", r.updated_time);
    out.pushKV("record_digest", cnp::RecordDigest(r.key).ToString());
    if (include_alpha) {
        out.pushKV("alpha", HexStr(r.alpha));
    }
    return out;
}

[[noreturn]] void ThrowFromBeginResult(cnr::BeginResult r)
{
    switch (r) {
    case cnr::BeginResult::Ok: assert(false);  // caller checks Ok separately
    case cnr::BeginResult::InvalidInput:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "joint_output_id and session_id must be non-empty / non-null");
    case cnr::BeginResult::Locked:
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
    case cnr::BeginResult::ConflictDifferentSession:
        throw JSONRPCError(RPC_INVALID_REQUEST,
            "§4.1a: a record exists for this (joint_output_id, ring_hash, role) "
            "under a DIFFERENT session_id — refusing to re-sign");
    case cnr::BeginResult::ConflictSameSessionInFlight:
        throw JSONRPCError(RPC_INVALID_REQUEST,
            "§4.1a: a record exists for this (joint_output_id, ring_hash, role) "
            "under the same session_id with t_published=false — already in flight");
    case cnr::BeginResult::WriteFailed:
        throw JSONRPCError(RPC_INTERNAL_ERROR,
            "wallet write failed (encryption or DB error)");
    }
    assert(false);
}

[[noreturn]] void ThrowFromMutateResult(cnr::MutateResult r)
{
    switch (r) {
    case cnr::MutateResult::Ok: assert(false);
    case cnr::MutateResult::NotFound:
        throw JSONRPCError(RPC_INVALID_REQUEST, "no record for this key");
    case cnr::MutateResult::Locked:
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
    case cnr::MutateResult::WriteFailed:
        throw JSONRPCError(RPC_INTERNAL_ERROR, "wallet write failed");
    }
    assert(false);
}

} // namespace

RPCMethod pricoin_clsag_nonce_begin()
{
    return RPCMethod{
        "pricoin_clsag_nonce_begin",
        "Atomic-swap phase 5 — §4.1a: persist a cooperative-CLSAG round-1\n"
        "nonce record before broadcasting its commitment.\n"
        "\n"
        "The wallet REJECTS the call if a record already exists for the same\n"
        "(joint_output_id, ring_hash, role) under a different session_id, OR\n"
        "under the same session_id with t_published=false — these are the\n"
        "preconditions for the catastrophic spend-share leak documented in\n"
        "doc/adaptor-clsag.md §4.1a.\n"
        "\n"
        "Caller is responsible for:\n"
        "  * generating alpha + commitment via the existing primitives\n"
        "    (pricoin_jointspend_round1 / NonceCommit), then\n"
        "  * calling THIS RPC to durably persist them BEFORE sending the\n"
        "    commitment to the counterparty.\n",
        {
            {"joint_output_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Chain-specific UTXO id (e.g., txid:vout encoded as bytes)"},
            {"ring_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "32-byte hash of the ring being signed over"},
            {"role", RPCArg::Type::STR, RPCArg::Optional::NO,
                "\"initiator\" or \"responder\""},
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "32-byte session id (from pricoin_swap_session_create)"},
            {"alpha", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "32-byte secret round-1 nonce"},
            {"commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "32-byte hiding commitment over (alpha · G, alpha · H_p, KI_share, ...)"},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Persisted nonce record (alpha redacted)" },
        RPCExamples{HelpExampleCli("pricoin_clsag_nonce_begin",
            "<joint_output_id> <ring_hash> initiator <session_id> <alpha> <commitment>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            cnp::RecordKey key = ParseClsagRecordKey(
                request.params[0], request.params[1], request.params[2]);
            auto sid = uint256::FromHex(request.params[3].get_str());
            if (!sid) throw JSONRPCError(RPC_INVALID_PARAMETER, "session_id must be 32-byte hex");
            auto alpha_bytes = TryParseHex<unsigned char>(request.params[4].get_str());
            if (!alpha_bytes || alpha_bytes->size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "alpha must be 32-byte hex");
            }
            auto commit_bytes = TryParseHex<unsigned char>(request.params[5].get_str());
            if (!commit_bytes || commit_bytes->size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "commitment must be 32-byte hex");
            }
            uint256 commit;
            std::copy(commit_bytes->begin(), commit_bytes->end(), commit.begin());

            cnp::Scalar alpha;
            std::copy(alpha_bytes->begin(), alpha_bytes->end(), alpha.begin());

            cnp::NonceRecord rec;
            cnr::BeginResult r = cnr::Begin(*wallet_sp, key, *sid, alpha, commit, rec);
            if (r != cnr::BeginResult::Ok) ThrowFromBeginResult(r);
            return ClsagNonceRecordToJSON(rec, /*include_alpha=*/false);
        }
    };
}

RPCMethod pricoin_clsag_nonce_mark_published()
{
    return RPCMethod{
        "pricoin_clsag_nonce_mark_published",
        "Mark a CLSAG nonce record as t_published=true. Call this when the\n"
        "adaptor secret t for the swap becomes public on-chain (PRIC side).\n"
        "After this transition, future Begin under the SAME session_id is\n"
        "permitted; under a different session_id the policy continues to\n"
        "reject (strict reading of §4.1a — manual Erase is required to\n"
        "fully reset the slot).\n",
        {
            {"joint_output_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"ring_hash",       RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"role",            RPCArg::Type::STR,     RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Updated record" },
        RPCExamples{HelpExampleCli("pricoin_clsag_nonce_mark_published",
            "<joint_output_id> <ring_hash> initiator")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            cnp::RecordKey key = ParseClsagRecordKey(
                request.params[0], request.params[1], request.params[2]);
            cnr::MutateResult r = cnr::MarkTPublished(*wallet_sp, key);
            if (r != cnr::MutateResult::Ok) ThrowFromMutateResult(r);
            cnp::NonceRecord rec;
            if (cnr::Get(*wallet_sp, key, rec) != cnr::LookupResult::Ok) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "post-mark Get failed");
            }
            return ClsagNonceRecordToJSON(rec, /*include_alpha=*/false);
        }
    };
}

RPCMethod pricoin_clsag_nonce_get()
{
    return RPCMethod{
        "pricoin_clsag_nonce_get",
        "Read a CLSAG nonce record. Includes alpha (secret) — the caller is\n"
        "expected to be a wallet-internal cooperative-signing tool.\n",
        {
            {"joint_output_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"ring_hash",       RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"role",            RPCArg::Type::STR,     RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Record (with alpha)" },
        RPCExamples{HelpExampleCli("pricoin_clsag_nonce_get",
            "<joint_output_id> <ring_hash> initiator")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            cnp::RecordKey key = ParseClsagRecordKey(
                request.params[0], request.params[1], request.params[2]);
            cnp::NonceRecord rec;
            cnr::LookupResult r = cnr::Get(*wallet_sp, key, rec);
            if (r == cnr::LookupResult::Locked) {
                throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
            }
            if (r == cnr::LookupResult::NotFound) {
                throw JSONRPCError(RPC_INVALID_REQUEST, "no record for this key");
            }
            return ClsagNonceRecordToJSON(rec, /*include_alpha=*/true);
        }
    };
}

RPCMethod pricoin_clsag_nonce_list()
{
    return RPCMethod{
        "pricoin_clsag_nonce_list",
        "Enumerate all CLSAG nonce records in this wallet. Alpha is REDACTED\n"
        "in list output — use pricoin_clsag_nonce_get for full record access.\n",
        {},
        RPCResult{ RPCResult::Type::ARR, "", "",
            {{RPCResult::Type::ANY, "", "Record (alpha redacted)"}} },
        RPCExamples{HelpExampleCli("pricoin_clsag_nonce_list", "")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            std::vector<cnp::NonceRecord> all;
            auto r = cnr::List(*wallet_sp, all);
            if (r == cnr::LookupResult::Locked) {
                throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
            }
            UniValue out{UniValue::VARR};
            for (const auto& rec : all) out.push_back(ClsagNonceRecordToJSON(rec, false));
            return out;
        }
    };
}

RPCMethod pricoin_clsag_nonce_erase()
{
    return RPCMethod{
        "pricoin_clsag_nonce_erase",
        "DESTRUCTIVE: hard-delete a CLSAG nonce record. After erase, the\n"
        "(joint_output_id, ring_hash, role) slot becomes a fresh starting\n"
        "point for any session — the §4.1a safety rail is gone for that\n"
        "slot. Use only when the joint output is permanently retired or\n"
        "you have explicit operator approval.\n",
        {
            {"joint_output_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"ring_hash",       RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"role",            RPCArg::Type::STR,     RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::BOOL, "erased", "true"}} },
        RPCExamples{HelpExampleCli("pricoin_clsag_nonce_erase",
            "<joint_output_id> <ring_hash> initiator")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            cnp::RecordKey key = ParseClsagRecordKey(
                request.params[0], request.params[1], request.params[2]);
            cnr::MutateResult r = cnr::Erase(*wallet_sp, key);
            if (r != cnr::MutateResult::Ok) ThrowFromMutateResult(r);
            UniValue out{UniValue::VOBJ};
            out.pushKV("erased", true);
            return out;
        }
    };
}

// ─────────────────────────────────────────────────────────────────
// pricoin_jointspend_round1_safe — wallet-tier wrapper around the
// stateless pricoin_jointspend_round1 primitive that ALSO durably
// persists the round-1 nonce record per §4.1a before returning.
// Callers driving real swaps should always use this variant; the
// stateless RPC is retained for unit testing and tools that don't
// have a wallet context.
// ─────────────────────────────────────────────────────────────────

namespace {

::pricoin::ringsig::Point ParseRingsigPoint33(
    const std::string& hex, const char* what)
{
    auto bytes = TryParseHex<unsigned char>(hex);
    if (!bytes || bytes->size() != 33) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            std::string(what) + " must be 33-byte hex");
    }
    ::pricoin::ringsig::Point p;
    std::copy(bytes->begin(), bytes->end(), p.begin());
    return p;
}

::pricoin::ringsig::Scalar ParseRingsigScalar32(
    const std::string& hex, const char* what)
{
    auto bytes = TryParseHex<unsigned char>(hex);
    if (!bytes || bytes->size() != 32) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            std::string(what) + " must be 32-byte hex");
    }
    ::pricoin::ringsig::Scalar s;
    std::copy(bytes->begin(), bytes->end(), s.begin());
    return s;
}

} // namespace

RPCMethod pricoin_jointspend_round1_safe()
{
    return RPCMethod{
        "pricoin_jointspend_round1_safe",
        "Stage 2b round 1 — generate and durably persist this party's\n"
        "cooperative-CLSAG nonce + image partials, atomically. Equivalent\n"
        "to pricoin_jointspend_round1 followed by pricoin_clsag_nonce_begin,\n"
        "but enforced as a single transaction: alpha is never returned to\n"
        "the caller unless the persistence record is on disk.\n"
        "\n"
        "REJECTS per §4.1a if a record already exists for the same\n"
        "(joint_output_id, ring_hash, role) under a different session_id\n"
        "or under the same session_id with t_published=false.\n"
        "\n"
        "If z_share is provided, the call is multi-layer mode and D_share\n"
        "is also returned.\n",
        {
            {"joint_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "33-byte compressed pubkey at ring[pi] (the joint spend pub)"},
            {"x_share", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "This party's 32-byte spend-secret share"},
            {"session_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "32-byte session id (typically from pricoin_swap_session_create)"},
            {"joint_output_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "UTXO id being spent (e.g., txid:vout encoded as bytes)"},
            {"ring_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "32-byte hash of the ring being signed over"},
            {"role", RPCArg::Type::STR, RPCArg::Optional::NO,
                "\"initiator\" or \"responder\""},
            {"z_share", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
                "Multi-layer: this party's 32-byte commitment-offset secret share"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "alpha", "32-byte private nonce — keep secret until round 3"},
                {RPCResult::Type::STR_HEX, "L_share", "33-byte alpha · G"},
                {RPCResult::Type::STR_HEX, "R_share", "33-byte alpha · H_p(P_pi)"},
                {RPCResult::Type::STR_HEX, "KI_share", "33-byte x_share · H_p(P_pi)"},
                {RPCResult::Type::STR_HEX, "D_share", /*optional=*/true,
                    "33-byte z_share · H_p(P_pi) (multi-layer only)"},
                {RPCResult::Type::STR_HEX, "commitment", "32-byte hash binding L/R/KI/D shares to session_id"},
                {RPCResult::Type::STR_HEX, "record_digest",
                    "32-byte digest of (joint_output_id, ring_hash, role) — DB key"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_jointspend_round1_safe",
            "<P_pi> <x_share> <session_id> <joint_output_id> <ring_hash> initiator")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");

            const auto P_pi    = ParseRingsigPoint33(request.params[0].get_str(), "joint_pubkey");
            const auto x_share = ParseRingsigScalar32(request.params[1].get_str(), "x_share");
            // session_id is parsed via uint256::FromHex for round-trip
            // consistency with pricoin_clsag_nonce_begin / _get / _list
            // (Bitcoin tx-hash display convention).
            auto session_id_opt = uint256::FromHex(request.params[2].get_str());
            if (!session_id_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "session_id must be 32-byte hex");
            }
            const uint256 session_id = *session_id_opt;
            // For passing into NonceCommit (which takes raw bytes),
            // grab the original hex bytes via TryParseHex.
            auto session_bytes = TryParseHex<unsigned char>(request.params[2].get_str());
            if (!session_bytes || session_bytes->size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "session_id must be 32-byte hex");
            }

            cnp::RecordKey key = ParseClsagRecordKey(
                request.params[3], request.params[4], request.params[5]);

            const bool multi_layer = !request.params[6].isNull();
            ::pricoin::ringsig::Scalar z_share{};
            if (multi_layer) {
                z_share = ParseRingsigScalar32(request.params[6].get_str(), "z_share");
            }

            // ─── Math ───
            auto noncepart = ::pricoin::joint_ringsig::NonceGen(P_pi);
            if (!noncepart) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "NonceGen failed");
            }
            auto KI_share_opt = ::pricoin::joint_ringsig::KeyImageShare(P_pi, x_share);
            if (!KI_share_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "x_share invalid");
            }
            ::pricoin::ringsig::Point D_share{};
            if (multi_layer) {
                auto imgs = ::pricoin::joint_ringsig::KICommitImageShare(P_pi, x_share, z_share);
                if (!imgs) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "x/z share invalid");
                }
                D_share = imgs->D_share;
                if (imgs->KI_share != *KI_share_opt) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "KI share mismatch");
                }
            }

            ::pricoin::ringsig::Scalar commit = ::pricoin::joint_ringsig::NonceCommit(
                std::span<const unsigned char>{*session_bytes},
                noncepart->L_share, noncepart->R_share, *KI_share_opt);
            if (multi_layer) {
                CSHA256 h;
                static constexpr char kTag[] = "pricoin/joint_ringsig/commit-ml-v1";
                h.Write(reinterpret_cast<const unsigned char*>(kTag), sizeof(kTag) - 1);
                h.Write(session_bytes->data(), session_bytes->size());
                h.Write(noncepart->L_share.data(), noncepart->L_share.size());
                h.Write(noncepart->R_share.data(), noncepart->R_share.size());
                h.Write(KI_share_opt->data(), KI_share_opt->size());
                h.Write(D_share.data(), D_share.size());
                h.Finalize(commit.data());
            }

            // ─── Persist BEFORE returning. If this fails the caller
            // sees an error and alpha never leaves the wallet. ───
            uint256 commit256;
            std::copy(commit.begin(), commit.end(), commit256.begin());
            cnp::NonceRecord rec;
            cnr::BeginResult br = cnr::Begin(*wallet_sp, key, session_id,
                                             noncepart->alpha, commit256, rec);
            if (br != cnr::BeginResult::Ok) ThrowFromBeginResult(br);

            // ─── Return ───
            UniValue out{UniValue::VOBJ};
            out.pushKV("alpha",      HexStr(noncepart->alpha));
            out.pushKV("L_share",    HexStr(noncepart->L_share));
            out.pushKV("R_share",    HexStr(noncepart->R_share));
            out.pushKV("KI_share",   HexStr(*KI_share_opt));
            if (multi_layer) {
                out.pushKV("D_share", HexStr(D_share));
            }
            out.pushKV("commitment",    HexStr(commit));
            out.pushKV("record_digest", cnp::RecordDigest(key).ToString());
            return out;
        }
    };
}

// Atomic-swap stage 2b — load this wallet's spend-secret share for a
// joint stealth output. The caller will pass the returned x_share into
// pricoin_jointspend_round1 as part of the cooperative signing
// protocol; one party should pass `absorb_shared_secret = true` and
// the other `false` so that the two shares sum to the one-time priv.
RPCMethod pricoin_jointspend_loadshare()
{
    return RPCMethod{
        "pricoin_jointspend_loadshare",
        "Compute this wallet's x_share (and read out the rangeproof blind\n"
        "and recovered value) for a joint stealth output. Used to drive the\n"
        "cooperative-signing flow in pricoin_jointspend_round1 et al.\n"
        "\n"
        "Inputs are the same as pricoin_jointscan_recover, plus a bool\n"
        "controlling which party absorbs the stealth-derived h_s scalar:\n"
        "exactly ONE of the two parties must pass absorb_shared_secret=true.\n"
        "Their two x_shares then sum to the joint one-time priv (= h_s +\n"
        "b_self + b_other), which is the spend secret for the joint output.\n"
        "\n"
        "WARNING: x_share embeds this wallet's stealth spend privkey. Treat\n"
        "the returned hex with the same care as a wallet seed — any party\n"
        "with both x_shares can sign solo. The cooperative-signing protocol\n"
        "assumes the caller is trusted by this wallet.\n",
        {
            {"tx_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Raw v4 transaction containing the joint output (hex)"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO,
             "Index of the joint output within the tx"},
            {"my_partial", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Self partial returned by pricoin_jointscan_partial"},
            {"other_partial", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Counterparty's partial"},
            {"other_spend_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "Counterparty's spend pubkey (33 bytes hex)"},
            {"absorb_shared_secret", RPCArg::Type::BOOL, RPCArg::Default{true},
             "Whether THIS party absorbs the stealth-derived h_s into its\n"
             "x_share. Exactly one of the two parties must pass true."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "x_share",
                    "32-byte spend-secret share for the cooperative protocol"},
                {RPCResult::Type::STR_HEX, "blind",
                    "32-byte rangeproof blind (b_prev)"},
                {RPCResult::Type::STR_AMOUNT, "value",
                    "Recovered amount in PRIC"},
                {RPCResult::Type::STR_HEX, "joint_pubkey",
                    "33-byte one-time pubkey at the joint output (= ring[pi].P "
                    "for cooperative signing)"},
                {RPCResult::Type::NUM, "vout",
                    "Echo of input vout (for caller convenience)"},
                {RPCResult::Type::STR_HEX, "x_pub", /*optional=*/true,
                    "33-byte X_pub_X = x_share · G — adaptor-mode coopsign "
                    "needs this so the dialog can auto-fill X_pub_X without "
                    "a separate scalar→pubkey computation"},
            }
        },
        RPCExamples{
            HelpExampleCli("pricoin_jointspend_loadshare",
                "\"<tx hex>\" 1 \"03...\" \"03...\" \"02...\" true")
        },
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;
            if (wallet.HasEncryptionKeys() && wallet.IsLocked()) {
                throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                    "Cooperative load requires the wallet to be unlocked.");
            }

            const std::string tx_hex = request.params[0].get_str();
            const uint32_t vout = request.params[1].getInt<uint32_t>();
            const std::string my_partial_hex = request.params[2].get_str();
            const std::string other_partial_hex = request.params[3].get_str();
            const std::string other_spend_hex = request.params[4].get_str();
            const bool absorb = request.params[5].isNull()
                ? true : request.params[5].get_bool();

            for (const auto& [name, hex] : {
                    std::pair{"my_partial", my_partial_hex},
                    std::pair{"other_partial", other_partial_hex},
                    std::pair{"other_spend_pubkey", other_spend_hex}}) {
                if (!IsHex(hex) || hex.size() != 66) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("%s must be 66 hex characters (33 bytes)", name));
                }
            }
            const std::vector<unsigned char> my_partial    = ParseHex(my_partial_hex);
            const std::vector<unsigned char> other_partial = ParseHex(other_partial_hex);
            const std::vector<unsigned char> other_spend_b = ParseHex(other_spend_hex);
            CPubKey other_spend(std::span<const unsigned char>{other_spend_b});
            if (!other_spend.IsValid() || !other_spend.IsCompressed()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "other_spend_pubkey is not a valid compressed secp256k1 point");
            }

            // Decode and sanity-check the tx.
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, tx_hex, /*try_no_witness=*/true, /*try_witness=*/true)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "tx hex failed to decode");
            }
            CTransaction tx{std::move(mtx)};
            if (tx.version != PRICOIN_CT_VERSION) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "tx is not a v4 confidential tx");
            }
            if (vout >= tx.vout.size() || vout >= tx.ct_bundle.outputs.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "vout out of range");
            }

            // Combine partials → joint ECDH point.
            auto shared_point = ::pricoin::joint_stealth::CombinePartials(my_partial, other_partial);
            if (!shared_point) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "partial combine failed");
            }
            auto shared = ::pricoin::stealth::DeriveSharedSecret(*shared_point, vout);

            const auto& self_id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
            ::pricoin::stealth::StealthAddress other;
            other.view  = self_id.public_address.view;   // dummy; not used downstream
            other.spend = other_spend;
            auto joint_addr = ::pricoin::joint_stealth::Combine(self_id.public_address, other);
            if (!joint_addr) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "joint key combine failed");
            }
            auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, joint_addr->spend);
            if (!P) throw JSONRPCError(RPC_INTERNAL_ERROR, "one-time pubkey derivation failed");

            const CScript expected_spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
            if (tx.vout[vout].scriptPubKey != expected_spk) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "scriptPubKey mismatch — partials don't decode to this output");
            }

            // Rewind the rangeproof so the caller has b_prev.
            auto rp_nonce = ::pricoin::stealth::DeriveRangeProofNonce(*shared_point, vout);
            ::pricoin::ct::BlindingFactor nonce_arr{};
            std::memcpy(nonce_arr.data(), rp_nonce.data(), 32);
            const auto& outp = tx.ct_bundle.outputs[vout];
            const auto& script = outp.script_pubkey;
            auto rewound = ::pricoin::ct::RewindRangeProof(
                outp.commitment,
                std::span<const unsigned char>{outp.rangeproof.data(), outp.rangeproof.size()},
                std::span<const unsigned char>{script.data(), script.size()},
                nonce_arr);
            if (!rewound) throw JSONRPCError(RPC_INTERNAL_ERROR, "rangeproof rewind failed");

            // Compute this party's x_share. Two cases:
            //   absorb=true  → x_share = b_self + h_s   (mod n)
            //   absorb=false → x_share = b_self
            // The two parties' x_shares sum to (b_self + b_other + h_s) =
            // the implicit one-time priv for the joint output, regardless
            // of which party absorbed.
            std::array<unsigned char, 32> x_share_bytes{};
            if (absorb) {
                auto one_time = ::pricoin::stealth::DeriveOneTimePriv(shared, self_id.spend);
                if (!one_time) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "one-time priv derivation failed");
                }
                std::memcpy(x_share_bytes.data(), one_time->begin(), 32);
            } else {
                std::memcpy(x_share_bytes.data(), self_id.spend.begin(), 32);
            }

            // Joint pubkey for the cooperative-signing ring (= the on-chain
            // one-time pubkey, which is what `ring[pi].P` will be).
            const ::pricoin::stealth::PointBytes joint_pub_bytes = [&] {
                ::pricoin::stealth::PointBytes b{};
                std::copy(P->begin(), P->end(), b.begin());
                return b;
            }();

            // X_pub for this party = x_share · G — needed by the
            // adaptor-mode cooperative protocol (each party submits
            // their own X_pub_X to combine; until now the user
            // computed this externally and pasted into the dialog).
            // Adding to the loadshare output so the dialog can
            // auto-fill it.
            std::string x_pub_hex;
            {
                CKey k;
                k.Set(x_share_bytes.begin(), x_share_bytes.end(),
                      /*compressed=*/true);
                if (k.IsValid()) {
                    const CPubKey p = k.GetPubKey();
                    x_pub_hex = HexStr(std::span<const unsigned char>{
                        p.begin(), p.size()});
                }
            }

            UniValue out{UniValue::VOBJ};
            out.pushKV("x_share",      HexStr(x_share_bytes));
            out.pushKV("blind",        HexStr(rewound->blind));
            out.pushKV("value",        ValueFromAmount(static_cast<CAmount>(rewound->value)));
            out.pushKV("joint_pubkey", HexStr(joint_pub_bytes));
            out.pushKV("vout",         static_cast<int>(vout));
            if (!x_pub_hex.empty()) {
                out.pushKV("x_pub", x_pub_hex);
            }
            return out;
        }
    };
}

// ─────────────────────────────────────────────────────────────────
// Atomic-swap phase 5 — adaptor-swap orchestration RPCs.
//
// State-machine + persistence over the spec §6.2 protocol. RPCs are
// "operator records what just happened" — the underlying cooperative
// signing machinery is in the swap/btc_musig2_adaptor + adaptor_*
// modules, plumbed in by a future commit.
// ─────────────────────────────────────────────────────────────────

namespace aas = ::wallet::pricoin_adaptor_swap;

const char* AdaptorSwapStateName(aas::State s)
{
    switch (s) {
    case aas::State::Setup:        return "setup";
    case aas::State::AdaptorReady: return "adaptor_ready";
    case aas::State::BtcFunded:    return "btc_funded";
    case aas::State::BothFunded:   return "both_funded";
    case aas::State::PreSigned:    return "pre_signed";
    case aas::State::PricClaimed:  return "pric_claimed";
    case aas::State::Complete:     return "complete";
    case aas::State::Refunded:     return "refunded";
    case aas::State::Aborted:      return "aborted";
    }
    return "unknown";
}

aas::Role ParseAdaptorSwapRole(const std::string& s)
{
    if (s == "alice") return aas::Role::Alice;
    if (s == "bob")   return aas::Role::Bob;
    throw JSONRPCError(RPC_INVALID_PARAMETER, "role must be \"alice\" or \"bob\"");
}

UniValue AdaptorSwapToJSON(const aas::AdaptorSwap& s)
{
    UniValue out{UniValue::VOBJ};
    out.pushKV("swap_id",            s.swap_id.ToString());
    out.pushKV("role",               s.role == aas::Role::Alice ? "alice" : "bob");
    out.pushKV("state",              AdaptorSwapStateName(s.state));
    out.pushKV("counterparty_pubkey", HexStr(s.counterparty_pub));

    UniValue foreign{UniValue::VOBJ};
    foreign.pushKV("chain",          s.foreign_chain);
    foreign.pushKV("amount_sat",     s.foreign_amount_sat);
    if (!s.foreign_funding_txid.empty()) {
        foreign.pushKV("funding_txid",   s.foreign_funding_txid);
        foreign.pushKV("funding_vout",   s.foreign_funding_vout);
        foreign.pushKV("funding_height", s.foreign_funding_height);
    }
    if (!s.foreign_claim_txid.empty())  foreign.pushKV("claim_txid",  s.foreign_claim_txid);
    if (!s.foreign_refund_txid.empty()) foreign.pushKV("refund_txid", s.foreign_refund_txid);
    if (!s.btc_alice_recipient_xonly_hex.empty()) {
        foreign.pushKV("alice_recipient_xonly", s.btc_alice_recipient_xonly_hex);
    }
    if (!s.btc_bob_recipient_xonly_hex.empty()) {
        foreign.pushKV("bob_recipient_xonly", s.btc_bob_recipient_xonly_hex);
    }
    out.pushKV("foreign", std::move(foreign));

    UniValue pric{UniValue::VOBJ};
    pric.pushKV("joint_stealth_address", s.pric_joint_stealth_address);
    pric.pushKV("amount_sat",            s.pric_amount_sat);
    if (!s.pric_funding_txid.IsNull()) {
        pric.pushKV("funding_txid",   s.pric_funding_txid.ToString());
        pric.pushKV("funding_vout",   s.pric_funding_vout);
        pric.pushKV("funding_height", s.pric_funding_height);
    }
    if (!s.pric_claim_txid.IsNull())  pric.pushKV("claim_txid",  s.pric_claim_txid.ToString());
    if (!s.pric_refund_txid.IsNull()) pric.pushKV("refund_txid", s.pric_refund_txid.ToString());
    if (!s.pric_alice_recipient_stealth.empty()) {
        pric.pushKV("alice_recipient_stealth", s.pric_alice_recipient_stealth);
    }
    if (!s.pric_bob_recipient_stealth.empty()) {
        pric.pushKV("bob_recipient_stealth", s.pric_bob_recipient_stealth);
    }
    if (!s.peer_view_pubkey_hex.empty()) {
        pric.pushKV("peer_view_pubkey",  s.peer_view_pubkey_hex);
    }
    if (!s.peer_spend_pubkey_hex.empty()) {
        pric.pushKV("peer_spend_pubkey", s.peer_spend_pubkey_hex);
    }
    if (!s.pric_claim_ring.empty()) {
        UniValue ring_arr{UniValue::VARR};
        for (const auto& p : s.pric_claim_ring) {
            ring_arr.push_back(HexStr(p));
        }
        pric.pushKV("pric_claim_ring", std::move(ring_arr));
    }
    if (!s.pric_claim_ring_w.empty()) {
        UniValue ring_w_arr{UniValue::VARR};
        for (const auto& w : s.pric_claim_ring_w) {
            ring_w_arr.push_back(HexStr(w));
        }
        pric.pushKV("pric_claim_ring_w", std::move(ring_w_arr));
    }
    if (!s.pric_claim_msg_hex.empty()) {
        pric.pushKV("pric_claim_msg_hex", s.pric_claim_msg_hex);
    }
    if (s.pric_claim_pi >= 0) {
        pric.pushKV("pric_claim_pi", s.pric_claim_pi);
    }
    if (!s.pric_claim_unsigned_tx_hex.empty()) {
        pric.pushKV("pric_claim_unsigned_tx_hex",
                    s.pric_claim_unsigned_tx_hex);
    }
    if (!s.pric_claim_adaptor_session_json.empty()) {
        pric.pushKV("claim_session_json", s.pric_claim_adaptor_session_json);
    }
    if (!s.pric_refund_session_json.empty()) {
        pric.pushKV("refund_session_json", s.pric_refund_session_json);
    }
    out.pushKV("pric", std::move(pric));

    if (s.adaptor_set) {
        UniValue ad{UniValue::VOBJ};
        ad.pushKV("T_G", HexStr(s.T_G));
        ad.pushKV("T_H", HexStr(s.T_H));
        ad.pushKV("dleq_proof_blob", HexStr(s.dleq_proof_blob));
        // We deliberately do NOT echo t_secret in JSON output — Bob's
        // wallet has it on-disk; exposing it via JSON would risk it
        // landing in operator logs.
        ad.pushKV("has_t", s.has_t);
        out.pushKV("adaptor", std::move(ad));
    }
    if (s.timelocks_set) {
        UniValue tl{UniValue::VOBJ};
        tl.pushKV("pric_refund_height",    s.pric_refund_height);
        tl.pushKV("foreign_refund_height", s.foreign_refund_height);
        tl.pushKV("delta_min_blocks",      s.delta_min_blocks);
        out.pushKV("refund_timelocks", std::move(tl));
    }
    if (s.presigs.IsComplete(s.foreign_chain)) {
        UniValue ps{UniValue::VOBJ};
        // BTC-side MuSig2 + Schnorr-adaptor fields only exist for
        // BTC swaps. LTC HTLC swaps leave them empty.
        if (!s.presigs.btc_claim_presig.empty()) {
            ps.pushKV("btc_claim_presig",      HexStr(s.presigs.btc_claim_presig));
            ps.pushKV("btc_claim_session",     HexStr(s.presigs.btc_claim_session));
            ps.pushKV("btc_claim_nonce_parity", s.presigs.btc_claim_nonce_parity);
            ps.pushKV("btc_refund_sig",        HexStr(s.presigs.btc_refund_sig));
        }
        ps.pushKV("pric_claim_presig_blob", HexStr(s.presigs.pric_claim_presig_blob));
        ps.pushKV("pric_refund_sig_blob",  HexStr(s.presigs.pric_refund_sig_blob));
        out.pushKV("presigs", std::move(ps));
    }

    out.pushKV("memo",         s.memo);
    out.pushKV("created_time", s.created_time);
    out.pushKV("updated_time", s.updated_time);
    if (!s.abort_reason.empty()) out.pushKV("abort_reason", s.abort_reason);
    out.pushKV("next_action", aas::NextActionHint(s));
    return out;
}

[[noreturn]] void ThrowFromAdaptorSwapCreate(aas::CreateResult r)
{
    using R = aas::CreateResult;
    switch (r) {
    case R::Ok: assert(false);
    case R::InvalidCounterpartyPubkey:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "counterparty_pubkey must be 33-byte compressed secp256k1 hex");
    case R::InvalidForeignLeg:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "foreign_chain must be btc/ltc/regtest and amount > 0");
    case R::InvalidPricLeg:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "pric_joint_stealth_address must be a valid joint-stealth string and amount > 0");
    case R::Locked:
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
    case R::WriteFailed:
        throw JSONRPCError(RPC_INTERNAL_ERROR, "wallet write failed");
    }
    assert(false);
}

[[noreturn]] void ThrowFromAdaptorSwapTransition(aas::TransitionResult r)
{
    using R = aas::TransitionResult;
    switch (r) {
    case R::Ok: assert(false);
    case R::NotFound:
        throw JSONRPCError(RPC_INVALID_REQUEST, "no swap with that id");
    case R::InvalidState:
        throw JSONRPCError(RPC_INVALID_REQUEST, "current state does not permit this transition");
    case R::InvalidInput:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid input for this transition");
    case R::InvalidTimelocks:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "refund timelocks failed validation — see swap::refund::ValidateRefundTimelocks (foreign > pric + delta_min_blocks)");
    case R::Locked:
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
    case R::WriteFailed:
        throw JSONRPCError(RPC_INTERNAL_ERROR, "wallet write failed");
    }
    assert(false);
}

uint256 ParseSwapId(const std::string& s)
{
    auto opt = uint256::FromHex(s);
    if (!opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "swap_id must be 32-byte hex");
    return *opt;
}

RPCMethod pricoin_adaptor_swap_create()
{
    return RPCMethod{
        "pricoin_adaptor_swap_create",
        "Atomic-swap phase 5 — create a new adaptor-based swap record.\n"
        "Generates a fresh swap_id; initial state is \"setup\". Subsequently\n"
        "advance via SetAdaptorMaterials, SetRefundTimelocks, SetBtcFunded,\n"
        "SetPricFunded, SetPreSigned, SetPricClaimed, SetComplete or SetRefunded.\n",
        {
            {"role",                 RPCArg::Type::STR,     RPCArg::Optional::NO, "\"alice\" (sells PRIC) or \"bob\" (sells foreign)"},
            {"counterparty_pubkey",  RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Counterparty's swap-identity pubkey (33-byte hex)"},
            {"foreign_chain",        RPCArg::Type::STR,     RPCArg::Optional::NO, "\"btc\" | \"ltc\" | \"regtest\""},
            {"foreign_amount_sat",   RPCArg::Type::NUM,     RPCArg::Optional::NO, "Foreign-leg amount, smallest unit"},
            {"pric_joint_stealth_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Joint stealth address (output of pricoin_buildjointstealthaddress)"},
            {"pric_amount_sat",      RPCArg::Type::NUM,     RPCArg::Optional::NO, "PRIC-leg amount"},
            {"memo",                 RPCArg::Type::STR,     RPCArg::Default{""}, "Free-form note"},
            {"btc_alice_recipient_xonly_hex", RPCArg::Type::STR_HEX, RPCArg::Default{""},
                "32-byte x-only pubkey hex — Alice's BTC P2TR refund recipient"},
            {"btc_bob_recipient_xonly_hex",   RPCArg::Type::STR_HEX, RPCArg::Default{""},
                "32-byte x-only pubkey hex — Bob's BTC P2TR claim recipient"},
            {"pric_alice_recipient_stealth",  RPCArg::Type::STR,     RPCArg::Default{""},
                "Alice's PRIC stealth-address claim recipient"},
            {"pric_bob_recipient_stealth",    RPCArg::Type::STR,     RPCArg::Default{""},
                "Bob's PRIC stealth-address refund recipient"},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Swap record" },
        RPCExamples{HelpExampleCli("pricoin_adaptor_swap_create",
            "alice <counterparty_pub> btc 100000000 <joint_stealth_addr> 50000000")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const aas::Role role = ParseAdaptorSwapRole(request.params[0].get_str());
            CPubKey cp = ParseSessionPubkey(request.params[1].get_str(), "counterparty_pubkey");
            const std::string chain  = request.params[2].get_str();
            const int64_t f_amt      = request.params[3].getInt<int64_t>();
            const std::string addr   = request.params[4].get_str();
            const int64_t p_amt      = request.params[5].getInt<int64_t>();
            const std::string memo   = request.params[6].isNull() ? "" : request.params[6].get_str();
            const std::string btc_alice = request.params[7].isNull() ? "" : request.params[7].get_str();
            const std::string btc_bob   = request.params[8].isNull() ? "" : request.params[8].get_str();
            const std::string pric_alice = request.params[9].isNull() ? "" : request.params[9].get_str();
            const std::string pric_bob   = request.params[10].isNull() ? "" : request.params[10].get_str();

            aas::AdaptorSwap s;
            aas::CreateResult r = aas::Create(*wallet_sp, role, cp, chain, f_amt, addr, p_amt, memo,
                btc_alice, btc_bob, pric_alice, pric_bob, s);
            if (r != aas::CreateResult::Ok) ThrowFromAdaptorSwapCreate(r);
            return AdaptorSwapToJSON(s);
        }
    };
}

RPCMethod pricoin_adaptor_swap_set_adaptor()
{
    return RPCMethod{
        "pricoin_adaptor_swap_set_adaptor",
        "Record cross-chain adaptor materials (T_G + DLEQ proof, plus secret t for Bob).\n"
        "Caller is responsible for verifying the DLEQ proof (e.g., via the\n"
        "adaptor_ringsig::VerifyDLEQProof primitive) before invoking this\n"
        "RPC — the persistence layer just stores the bytes.\n",
        {
            {"swap_id",          RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"T_G",              RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "33-byte compressed adaptor point t·G"},
            {"T_H",              RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "33-byte compressed adaptor point t·H_p(P_pi)"},
            {"dleq_proof_blob",  RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Serialized DLEQ proof bytes"},
            {"t_secret_for_bob", RPCArg::Type::STR_HEX, RPCArg::Default{""},
                "Bob ONLY: the 32-byte secret t. Empty for Alice."},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Updated swap record" },
        RPCExamples{HelpExampleCli("pricoin_adaptor_swap_set_adaptor",
            "<swap_id> <T_G_hex> <T_H_hex> <dleq_blob_hex> [<t_hex>]")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 sid = ParseSwapId(request.params[0].get_str());
            auto T_G_bytes = TryParseHex<unsigned char>(request.params[1].get_str());
            if (!T_G_bytes || T_G_bytes->size() != 33) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "T_G must be 33-byte compressed pubkey hex");
            }
            std::array<unsigned char, 33> T_G{};
            std::copy(T_G_bytes->begin(), T_G_bytes->end(), T_G.begin());
            auto T_H_bytes = TryParseHex<unsigned char>(request.params[2].get_str());
            if (!T_H_bytes || T_H_bytes->size() != 33) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "T_H must be 33-byte compressed pubkey hex");
            }
            std::array<unsigned char, 33> T_H{};
            std::copy(T_H_bytes->begin(), T_H_bytes->end(), T_H.begin());
            auto dleq = TryParseHex<unsigned char>(request.params[3].get_str());
            if (!dleq || dleq->empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "dleq_proof_blob must be non-empty hex");
            }
            std::optional<std::array<unsigned char, 32>> t_secret;
            const std::string t_hex = request.params[4].isNull() ? "" : request.params[4].get_str();
            if (!t_hex.empty()) {
                auto t_bytes = TryParseHex<unsigned char>(t_hex);
                if (!t_bytes || t_bytes->size() != 32) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "t_secret_for_bob must be 32-byte hex");
                }
                std::array<unsigned char, 32> t_arr{};
                std::copy(t_bytes->begin(), t_bytes->end(), t_arr.begin());
                t_secret = t_arr;
            }
            auto r = aas::SetAdaptorMaterials(*wallet_sp, sid, T_G, T_H, *dleq, t_secret);
            if (r != aas::TransitionResult::Ok) ThrowFromAdaptorSwapTransition(r);
            aas::AdaptorSwap out;
            (void)aas::Get(*wallet_sp, sid, out);
            return AdaptorSwapToJSON(out);
        }
    };
}

RPCMethod pricoin_adaptor_swap_set_timelocks()
{
    return RPCMethod{
        "pricoin_adaptor_swap_set_timelocks",
        "Record agreed refund timelocks. Validated against\n"
        "swap::refund::ValidateRefundTimelocks (spec §6.2 step 7).\n",
        {
            {"swap_id",              RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"pric_refund_height",   RPCArg::Type::NUM,     RPCArg::Optional::NO, "PRIC absolute block height"},
            {"foreign_refund_height", RPCArg::Type::NUM,    RPCArg::Optional::NO, "Foreign absolute block height (must exceed pric+delta_min)"},
            {"delta_min_blocks",     RPCArg::Type::NUM,     RPCArg::Optional::NO, "Minimum buffer in foreign blocks"},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Updated swap record" },
        RPCExamples{HelpExampleCli("pricoin_adaptor_swap_set_timelocks", "<swap_id> 100000 100144 144")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 sid = ParseSwapId(request.params[0].get_str());
            const int32_t p   = request.params[1].getInt<int32_t>();
            const int32_t f   = request.params[2].getInt<int32_t>();
            const int32_t d   = request.params[3].getInt<int32_t>();
            auto r = aas::SetRefundTimelocks(*wallet_sp, sid, p, f, d);
            if (r != aas::TransitionResult::Ok) ThrowFromAdaptorSwapTransition(r);
            aas::AdaptorSwap out;
            (void)aas::Get(*wallet_sp, sid, out);
            return AdaptorSwapToJSON(out);
        }
    };
}

RPCMethod pricoin_adaptor_swap_set_pric_claim_ring()
{
    return RPCMethod{
        "pricoin_adaptor_swap_set_pric_claim_ring",
        "Persist the cooperative multi-layer CLSAG ring used at PRIC adapt-\n"
        "round-1 time. Called by both wallets' coopsign dialogs after a\n"
        "successful adaptor combine, so the watcher can run extract when\n"
        "Bob's claim hits chain AND the spender can re-adapt after a\n"
        "session-JSON wipe without re-running buildtx (which would\n"
        "invalidate the pre-sig). Idempotent if the supplied ring matches.\n",
        {
            {"swap_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"ring",    RPCArg::Type::ARR,     RPCArg::Optional::NO,
                "Array of 33-byte compressed pubkey hex strings (P component)",
                {{"P", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""}}},
            {"ring_w",  RPCArg::Type::ARR,     RPCArg::Default{UniValue::VARR},
                "Optional array of W (commitment image) components aligned "
                "1:1 with `ring`. Required for the multi-layer adapt-recovery "
                "path; legacy callers may omit.",
                {{"W", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""}}},
            {"msg_hex", RPCArg::Type::STR_HEX, RPCArg::Default{""},
                "Canonical 32-byte sighash the pre-sig is bound to "
                "(from pricoin_jointspend_buildtx). Stored on the swap "
                "record so the spender's adapt path can recover after a "
                "session-JSON wipe."},
            {"pi",      RPCArg::Type::NUM,     RPCArg::Default{-1},
                "Signer index in the ring (0..ring_size-1)."},
            {"unsigned_tx_hex", RPCArg::Type::STR_HEX, RPCArg::Default{""},
                "Skeleton tx hex from pricoin_jointspend_buildtx that the "
                "pre-sig will be adapted into."},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::BOOL, "ok", "true on success"}}
        },
        RPCExamples{HelpExampleCli("pricoin_adaptor_swap_set_pric_claim_ring",
            "<swap_id> '[\"<P0>\",\"<P1>\",\"<P2>\",\"<P3>\"]' '[\"<W0>\",\"<W1>\",\"<W2>\",\"<W3>\"]'")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 sid = ParseSwapId(request.params[0].get_str());
            const UniValue& ring_arr = request.params[1];
            if (!ring_arr.isArray() || ring_arr.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "ring must be a non-empty JSON array");
            }
            std::vector<std::array<unsigned char, 33>> ring;
            ring.reserve(ring_arr.size());
            for (size_t i = 0; i < ring_arr.size(); ++i) {
                auto pb = TryParseHex<unsigned char>(ring_arr[i].get_str());
                if (!pb || pb->size() != 33) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("ring[%u] must be 33-byte compressed pubkey hex",
                                  static_cast<unsigned>(i)));
                }
                std::array<unsigned char, 33> p{};
                std::copy(pb->begin(), pb->end(), p.begin());
                ring.push_back(p);
            }
            // Optional ring_w. If present, must align 1:1 with ring.
            std::vector<std::array<unsigned char, 33>> ring_w;
            if (request.params.size() >= 3 && !request.params[2].isNull()) {
                const UniValue& w_arr = request.params[2];
                if (!w_arr.isArray()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "ring_w must be a JSON array");
                }
                if (!w_arr.empty()) {
                    if (w_arr.size() != ring.size()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "ring_w length must match ring length");
                    }
                    ring_w.reserve(w_arr.size());
                    for (size_t i = 0; i < w_arr.size(); ++i) {
                        auto wb = TryParseHex<unsigned char>(w_arr[i].get_str());
                        if (!wb || wb->size() != 33) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                strprintf("ring_w[%u] must be 33-byte hex",
                                          static_cast<unsigned>(i)));
                        }
                        std::array<unsigned char, 33> w{};
                        std::copy(wb->begin(), wb->end(), w.begin());
                        ring_w.push_back(w);
                    }
                }
            }
            // Optional canonical (msg, pi, tx_hex).
            std::string msg_hex_p;
            int32_t pi_p = -1;
            std::string tx_hex_p;
            if (request.params.size() >= 4 && !request.params[3].isNull()) {
                msg_hex_p = request.params[3].get_str();
            }
            if (request.params.size() >= 5 && !request.params[4].isNull()) {
                pi_p = request.params[4].getInt<int32_t>();
            }
            if (request.params.size() >= 6 && !request.params[5].isNull()) {
                tx_hex_p = request.params[5].get_str();
            }
            auto r = aas::SetPricClaimRing(*wallet_sp, sid, ring, ring_w,
                                            msg_hex_p, pi_p, tx_hex_p);
            if (r != aas::TransitionResult::Ok) ThrowFromAdaptorSwapTransition(r);
            UniValue out{UniValue::VOBJ};
            out.pushKV("ok", true);
            return out;
        }
    };
}

RPCMethod pricoin_adaptor_swap_set_btc_funded()
{
    return RPCMethod{
        "pricoin_adaptor_swap_set_btc_funded",
        "Record foreign 2-of-2 funding tx confirmed. Transitions adaptor_ready → btc_funded.\n",
        {
            {"swap_id",              RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"foreign_funding_txid", RPCArg::Type::STR,     RPCArg::Optional::NO, "Foreign-chain txid (chain-native format)"},
            {"foreign_funding_vout", RPCArg::Type::NUM,     RPCArg::Optional::NO, ""},
            {"foreign_funding_height", RPCArg::Type::NUM,   RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Updated swap record" },
        RPCExamples{HelpExampleCli("pricoin_adaptor_swap_set_btc_funded", "<swap_id> <txid> 0 800000")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 sid = ParseSwapId(request.params[0].get_str());
            auto r = aas::SetBtcFunded(*wallet_sp, sid,
                request.params[1].get_str(),
                request.params[2].getInt<int32_t>(),
                request.params[3].getInt<int32_t>());
            if (r != aas::TransitionResult::Ok) ThrowFromAdaptorSwapTransition(r);
            aas::AdaptorSwap out;
            (void)aas::Get(*wallet_sp, sid, out);
            return AdaptorSwapToJSON(out);
        }
    };
}

RPCMethod pricoin_adaptor_swap_set_pric_funded()
{
    return RPCMethod{
        "pricoin_adaptor_swap_set_pric_funded",
        "Record PRIC joint-stealth funding tx confirmed. Transitions btc_funded → both_funded.\n",
        {
            {"swap_id",            RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"pric_funding_txid",  RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"pric_funding_vout",  RPCArg::Type::NUM,     RPCArg::Optional::NO, ""},
            {"pric_funding_height", RPCArg::Type::NUM,    RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Updated swap record" },
        RPCExamples{HelpExampleCli("pricoin_adaptor_swap_set_pric_funded", "<swap_id> <txid> 1 12345")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 sid = ParseSwapId(request.params[0].get_str());
            auto txid = uint256::FromHex(request.params[1].get_str());
            if (!txid) throw JSONRPCError(RPC_INVALID_PARAMETER, "pric_funding_txid must be 32-byte hex");
            auto r = aas::SetPricFunded(*wallet_sp, sid, *txid,
                request.params[2].getInt<int32_t>(),
                request.params[3].getInt<int32_t>());
            if (r != aas::TransitionResult::Ok) ThrowFromAdaptorSwapTransition(r);
            aas::AdaptorSwap out;
            (void)aas::Get(*wallet_sp, sid, out);
            return AdaptorSwapToJSON(out);
        }
    };
}

RPCMethod pricoin_adaptor_swap_set_peer_stealth_pubkeys()
{
    return RPCMethod{
        "pricoin_adaptor_swap_set_peer_stealth_pubkeys",
        "Persist peer's PRIC stealth view + spend pubkeys (33-byte hex each)\n"
        "on an existing swap record. Normally called automatically at swap\n"
        "creation time; this RPC is for backfilling records that were\n"
        "created before automatic persistence landed.\n",
        {
            {"swap_id",     RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"view_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "33-byte peer stealth view pubkey"},
            {"spend_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "33-byte peer stealth spend pubkey"},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Updated swap record" },
        RPCExamples{HelpExampleCli("pricoin_adaptor_swap_set_peer_stealth_pubkeys",
            "<swap_id> <view_hex> <spend_hex>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 sid = ParseSwapId(request.params[0].get_str());
            auto r = aas::SetPeerStealthPubkeys(*wallet_sp, sid,
                request.params[1].get_str(), request.params[2].get_str());
            if (r != aas::TransitionResult::Ok) ThrowFromAdaptorSwapTransition(r);
            aas::AdaptorSwap out;
            (void)aas::Get(*wallet_sp, sid, out);
            return AdaptorSwapToJSON(out);
        }
    };
}

RPCMethod pricoin_adaptor_swap_set_pre_signed()
{
    return RPCMethod{
        "pricoin_adaptor_swap_set_pre_signed",
        "Record all 4 pre-signatures durably stored. Transitions both_funded → pre_signed.\n"
        "After this transition, refund pre-sigs are recoverable from the wallet —\n"
        "this is the watcher-model invariant of spec §6.3.\n",
        {
            {"swap_id",                 RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"btc_claim_presig",        RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "64-byte BTC adaptor pre-sig (hex)"},
            {"btc_claim_session",       RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "133-byte musig session (hex)"},
            {"btc_claim_nonce_parity",  RPCArg::Type::NUM,     RPCArg::Optional::NO, "0 or 1"},
            {"pric_claim_presig_blob",  RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Serialized adaptor_ringsig::AdaptorPreSignature"},
            {"btc_refund_sig",          RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "64-byte BIP340 sig (hex)"},
            {"pric_refund_sig_blob",    RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Serialized ringsig::Signature"},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Updated swap record" },
        RPCExamples{HelpExampleCli("pricoin_adaptor_swap_set_pre_signed", "<swap_id> ...")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 sid = ParseSwapId(request.params[0].get_str());

            auto parse_hex = [](const UniValue& v, const char* name) {
                auto bytes = TryParseHex<unsigned char>(v.get_str());
                if (!bytes) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string(name) + " must be hex");
                return *bytes;
            };
            aas::AdaptorSwapPreSigs ps;
            ps.btc_claim_presig         = parse_hex(request.params[1], "btc_claim_presig");
            ps.btc_claim_session        = parse_hex(request.params[2], "btc_claim_session");
            ps.btc_claim_nonce_parity   = request.params[3].getInt<int32_t>();
            ps.pric_claim_presig_blob   = parse_hex(request.params[4], "pric_claim_presig_blob");
            ps.btc_refund_sig           = parse_hex(request.params[5], "btc_refund_sig");
            ps.pric_refund_sig_blob     = parse_hex(request.params[6], "pric_refund_sig_blob");

            auto r = aas::SetPreSigned(*wallet_sp, sid, ps);
            if (r != aas::TransitionResult::Ok) ThrowFromAdaptorSwapTransition(r);
            aas::AdaptorSwap out;
            (void)aas::Get(*wallet_sp, sid, out);
            return AdaptorSwapToJSON(out);
        }
    };
}

RPCMethod pricoin_adaptor_swap_set_pric_claimed()
{
    return RPCMethod{
        "pricoin_adaptor_swap_set_pric_claimed",
        "Record Bob's PRIC claim tx confirmed (t now extractable from on-chain).\n"
        "Transitions pre_signed → pric_claimed. For Bob, also wipes the in-wallet\n"
        "copy of t_secret (no longer secret — it's on-chain).\n",
        {
            {"swap_id",          RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"pric_claim_txid",  RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte PRIC txid"},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Updated swap record" },
        RPCExamples{HelpExampleCli("pricoin_adaptor_swap_set_pric_claimed", "<swap_id> <txid>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 sid = ParseSwapId(request.params[0].get_str());
            auto txid = uint256::FromHex(request.params[1].get_str());
            if (!txid) throw JSONRPCError(RPC_INVALID_PARAMETER, "pric_claim_txid must be 32-byte hex");
            auto r = aas::SetPricClaimed(*wallet_sp, sid, *txid);
            if (r != aas::TransitionResult::Ok) ThrowFromAdaptorSwapTransition(r);
            aas::AdaptorSwap out;
            (void)aas::Get(*wallet_sp, sid, out);
            return AdaptorSwapToJSON(out);
        }
    };
}

RPCMethod pricoin_adaptor_swap_set_complete()
{
    return RPCMethod{
        "pricoin_adaptor_swap_set_complete",
        "Record Alice's foreign claim tx confirmed. Swap is done. pric_claimed → complete.\n",
        {
            {"swap_id",            RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"foreign_claim_txid", RPCArg::Type::STR,     RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Updated swap record" },
        RPCExamples{HelpExampleCli("pricoin_adaptor_swap_set_complete", "<swap_id> <foreign_txid>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 sid = ParseSwapId(request.params[0].get_str());
            auto r = aas::SetComplete(*wallet_sp, sid, request.params[1].get_str());
            if (r != aas::TransitionResult::Ok) ThrowFromAdaptorSwapTransition(r);
            aas::AdaptorSwap out;
            (void)aas::Get(*wallet_sp, sid, out);
            return AdaptorSwapToJSON(out);
        }
    };
}

RPCMethod pricoin_adaptor_swap_set_refunded()
{
    return RPCMethod{
        "pricoin_adaptor_swap_set_refunded",
        "Record refund tx confirmed (timelock expired). Allowed from both_funded,\n"
        "pre_signed, or pric_claimed. Pass the txid for whichever leg refunded;\n"
        "leave the other empty.\n",
        {
            {"swap_id",                   RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"pric_refund_txid_or_empty", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "32-byte PRIC txid or empty"},
            {"foreign_refund_txid_or_empty", RPCArg::Type::STR,  RPCArg::Default{""}, "Foreign txid or empty"},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Updated swap record" },
        RPCExamples{HelpExampleCli("pricoin_adaptor_swap_set_refunded", "<swap_id> <pric_txid> \"\"")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 sid = ParseSwapId(request.params[0].get_str());
            uint256 pric_txid{};
            const std::string pric_hex = request.params[1].isNull() ? "" : request.params[1].get_str();
            if (!pric_hex.empty()) {
                auto opt = uint256::FromHex(pric_hex);
                if (!opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "pric_refund_txid must be 32-byte hex if non-empty");
                pric_txid = *opt;
            }
            const std::string foreign_txid = request.params[2].isNull() ? "" : request.params[2].get_str();
            auto r = aas::SetRefunded(*wallet_sp, sid, pric_txid, foreign_txid);
            if (r != aas::TransitionResult::Ok) ThrowFromAdaptorSwapTransition(r);
            aas::AdaptorSwap out;
            (void)aas::Get(*wallet_sp, sid, out);
            return AdaptorSwapToJSON(out);
        }
    };
}

RPCMethod pricoin_adaptor_swap_abort()
{
    return RPCMethod{
        "pricoin_adaptor_swap_abort",
        "Operator-initiated abort. Allowed from any non-terminal state.\n"
        "Wipes any in-wallet copy of t_secret as a side-effect.\n",
        {
            {"swap_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"reason",  RPCArg::Type::STR,     RPCArg::Default{""}, "Free-form abort reason"},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Updated swap record" },
        RPCExamples{HelpExampleCli("pricoin_adaptor_swap_abort", "<swap_id> \"counterparty stalled\"")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 sid = ParseSwapId(request.params[0].get_str());
            const std::string reason = request.params[1].isNull() ? "" : request.params[1].get_str();
            auto r = aas::Abort(*wallet_sp, sid, reason);
            if (r != aas::TransitionResult::Ok) ThrowFromAdaptorSwapTransition(r);
            aas::AdaptorSwap out;
            (void)aas::Get(*wallet_sp, sid, out);
            return AdaptorSwapToJSON(out);
        }
    };
}

RPCMethod pricoin_adaptor_swap_get()
{
    return RPCMethod{
        "pricoin_adaptor_swap_get",
        "Read a swap record.\n",
        { {"swap_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""} },
        RPCResult{ RPCResult::Type::ANY, "", "Swap record" },
        RPCExamples{HelpExampleCli("pricoin_adaptor_swap_get", "<swap_id>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 sid = ParseSwapId(request.params[0].get_str());
            aas::AdaptorSwap out;
            auto r = aas::Get(*wallet_sp, sid, out);
            if (r == aas::LookupResult::Locked) throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
            if (r == aas::LookupResult::NotFound) throw JSONRPCError(RPC_INVALID_REQUEST, "no swap with that id");
            return AdaptorSwapToJSON(out);
        }
    };
}

RPCMethod pricoin_adaptor_swap_list()
{
    return RPCMethod{
        "pricoin_adaptor_swap_list",
        "List all adaptor-swap records in this wallet.\n",
        {},
        RPCResult{ RPCResult::Type::ARR, "", "",
            {{RPCResult::Type::ANY, "", "Swap record"}} },
        RPCExamples{HelpExampleCli("pricoin_adaptor_swap_list", "")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            std::vector<aas::AdaptorSwap> all;
            auto r = aas::List(*wallet_sp, all);
            if (r == aas::LookupResult::Locked) throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
            UniValue out{UniValue::VARR};
            for (const auto& s : all) out.push_back(AdaptorSwapToJSON(s));
            return out;
        }
    };
}

// ─────────────────────────────────────────────────────────────────
// Atomic-swap phase 5 — BTC MuSig2 wire-protocol RPCs.
//
// Thin RPC wrappers around btc_musig2_adaptor primitives that expose
// the BIP327 + adaptor flow as discrete steps callable by either
// party's wallet during a 2-of-2 cooperative signing session.
//
// FLOW (matches doc/adaptor-clsag.md §6.2 step 6 + step 7 BTC leg):
//
//   1.  pricoin_btc_musig2_keyagg            → keyagg_cache + agg xonly pub
//   2.  pricoin_btc_musig2_round1   (× each party)
//                                            → pubnonce + secnonce_handle
//   3.  pricoin_btc_musig2_aggregate_nonces  → aggnonce
//   4.  pricoin_btc_musig2_process           → session + nonce_parity
//                                              (with optional adaptor T_G)
//   5.  pricoin_btc_musig2_partial_sign  (× each party)
//                                            → partial sig (consumes handle)
//   6.  pricoin_btc_musig2_aggregate_partials → 64-byte (pre-)sig
//   7.  pricoin_btc_musig2_adapt             → BIP340 sig (from pre-sig + t)
//   8.  pricoin_btc_musig2_extract           → t (from sig + pre-sig)
//
// Step 7 is only used when an adaptor was supplied at step 4.
//
// SECNONCE LIFETIME
//   The secnonce produced at round 1 is held in process memory keyed
//   by an opaque 32-byte handle (see swap/btc_musig2_runtime). It's
//   destroyed by partial_sign (libsecp256k1 invalidates the buffer)
//   and on daemon shutdown. Caller MUST NOT call round1 twice with
//   the same swap context expecting two distinct secnonces — that's
//   the standard MuSig2 nonce-reuse footgun. A future commit will
//   add a §4.1a-style commitment record to enforce this across
//   crashes.
// ─────────────────────────────────────────────────────────────────

namespace bma = ::pricoin::swap::btc_musig2_adaptor;
namespace btr = ::pricoin::swap::btc_musig2_runtime;

namespace {

std::vector<CPubKey> ParseBtcPubKeys(const UniValue& arr)
{
    if (!arr.isArray() || arr.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "pubkeys must be a non-empty array of 33-byte hex strings");
    }
    std::vector<CPubKey> out;
    out.reserve(arr.size());
    for (size_t i = 0; i < arr.size(); ++i) {
        auto bytes = TryParseHex<unsigned char>(arr[i].get_str());
        if (!bytes || bytes->size() != 33) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "pubkeys[" + std::to_string(i) + "] must be 33-byte compressed hex");
        }
        out.emplace_back(std::span<const unsigned char>(bytes->data(), 33));
        if (!out.back().IsValid() || !out.back().IsCompressed()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "pubkeys[" + std::to_string(i) + "] is not a valid compressed pubkey");
        }
    }
    return out;
}

template <typename Array>
Array ParseFixedHex(const std::string& s, const char* what)
{
    auto bytes = TryParseHex<unsigned char>(s);
    if (!bytes || bytes->size() != Array{}.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            std::string(what) + " must be " + std::to_string(Array{}.size()) + "-byte hex");
    }
    Array out;
    std::copy(bytes->begin(), bytes->end(), out.begin());
    return out;
}

// Helpers for parsing/serializing the opaque blob types.
bma::KeyAggCache ParseKeyAggCacheBlob(const std::string& s)
{
    auto bytes = TryParseHex<unsigned char>(s);
    if (!bytes || bytes->size() != 197) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "keyagg_cache must be 197-byte hex");
    }
    bma::KeyAggCache out;
    std::copy(bytes->begin(), bytes->end(), out.data.begin());
    return out;
}

bma::Session ParseSessionBlob(const UniValue& session_obj)
{
    const auto data_hex = session_obj.find_value("data").get_str();
    auto bytes = TryParseHex<unsigned char>(data_hex);
    if (!bytes || bytes->size() != 133) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "session.data must be 133-byte hex");
    }
    bma::Session out;
    std::copy(bytes->begin(), bytes->end(), out.data.begin());
    out.nonce_parity = session_obj.find_value("nonce_parity").getInt<int>();
    return out;
}

UniValue SessionToJSON(const bma::Session& s)
{
    UniValue o{UniValue::VOBJ};
    o.pushKV("data", HexStr(s.data));
    o.pushKV("nonce_parity", s.nonce_parity);
    return o;
}

RPCMethod pricoin_btc_musig2_keyagg()
{
    return RPCMethod{
        "pricoin_btc_musig2_keyagg",
        "BIP327 MuSig2 pubkey aggregation. Returns the 32-byte x-only\n"
        "aggregate pubkey (used as the BTC 2-of-2 spend key) plus the\n"
        "197-byte keyagg_cache that subsequent steps must echo back.\n"
        "\n"
        "PUBKEY ORDER MATTERS: both parties must call this with the\n"
        "pubkeys in the same order. (BIP327 keyagg is order-sensitive.)\n",
        {
            {"pubkeys", RPCArg::Type::ARR, RPCArg::Optional::NO,
                "Array of 33-byte compressed pubkeys, identical order on both parties.",
                {
                    {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "33-byte compressed pubkey hex"},
                }
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "agg_xonly", "32-byte x-only aggregate pubkey"},
                {RPCResult::Type::STR_HEX, "keyagg_cache", "197-byte cache to pass into subsequent calls"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_btc_musig2_keyagg", "[\"<pub_a>\",\"<pub_b>\"]")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto pubs = ParseBtcPubKeys(request.params[0]);
            bma::KeyAggCache cache;
            auto agg = bma::AggregatePubkeys(pubs, cache);
            if (!agg) throw JSONRPCError(RPC_INTERNAL_ERROR, "MuSig2 keyagg failed");
            UniValue out{UniValue::VOBJ};
            out.pushKV("agg_xonly",    HexStr(*agg));
            out.pushKV("keyagg_cache", HexStr(cache.data));
            return out;
        }
    };
}

RPCMethod pricoin_btc_musig2_round1()
{
    return RPCMethod{
        "pricoin_btc_musig2_round1",
        "Round 1 of BIP327 MuSig2 — generate this party's secret nonce + public\n"
        "nonce. The secret nonce is stashed in process memory keyed by a fresh\n"
        "32-byte handle (returned); the partial_sign call retrieves it.\n"
        "\n"
        "If `self_priv` and/or `msg` are supplied, libsecp256k1 binds them into\n"
        "the nonce derivation per BIP327 — improves nonce-misuse resistance.\n"
        "Both should be supplied when known.\n"
        "\n"
        "WARNING — secnonce lifecycle:\n"
        "  * Lives in process memory only.\n"
        "  * partial_sign consumes (and invalidates) it.\n"
        "  * Daemon restart drops it. The in-flight session must be re-run\n"
        "    from round 1 if that happens.\n"
        "  * Calling round1 twice with the SAME swap context risks nonce reuse\n"
        "    across rounds; the spec §4.1a / clsag_nonce_records pattern is the\n"
        "    BTC-side analog of the defense (separate commit).\n",
        {
            {"self_pub",     RPCArg::Type::STR_HEX, RPCArg::Optional::NO,  "33-byte compressed self pubkey"},
            {"keyagg_cache", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,  "197-byte cache from pricoin_btc_musig2_keyagg"},
            {"session_seed", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,  "32-byte CSPRNG bytes — must be unique per call"},
            {"self_priv",    RPCArg::Type::STR_HEX, RPCArg::Default{""},   "Optional 32-byte priv (binding for nonce derivation)"},
            {"msg",          RPCArg::Type::STR_HEX, RPCArg::Default{""},   "Optional 32-byte sighash bound at this stage"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "pubnonce",        "66-byte serialized pubnonce"},
                {RPCResult::Type::STR_HEX, "secnonce_handle", "32-byte opaque handle for partial_sign"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_btc_musig2_round1",
            "<self_pub> <keyagg_cache> <session_seed>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            // Parse self_pub.
            auto pub_bytes = TryParseHex<unsigned char>(request.params[0].get_str());
            if (!pub_bytes || pub_bytes->size() != 33) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "self_pub must be 33-byte hex");
            }
            CPubKey self_pub(std::span<const unsigned char>(pub_bytes->data(), 33));
            if (!self_pub.IsValid() || !self_pub.IsCompressed()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "self_pub invalid");
            }
            // Parse keyagg_cache.
            bma::KeyAggCache cache = ParseKeyAggCacheBlob(request.params[1].get_str());
            // Parse session_seed (uint256-style).
            auto seed_bytes = TryParseHex<unsigned char>(request.params[2].get_str());
            if (!seed_bytes || seed_bytes->size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "session_seed must be 32-byte hex");
            }
            uint256 session_seed;
            std::copy(seed_bytes->begin(), seed_bytes->end(), session_seed.begin());
            // Optional self_priv.
            std::optional<bma::Scalar> self_priv;
            const std::string priv_hex = request.params[3].isNull() ? "" : request.params[3].get_str();
            if (!priv_hex.empty()) {
                auto priv_bytes = TryParseHex<unsigned char>(priv_hex);
                if (!priv_bytes || priv_bytes->size() != 32) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "self_priv must be 32-byte hex");
                }
                bma::Scalar s;
                std::copy(priv_bytes->begin(), priv_bytes->end(), s.begin());
                self_priv = s;
            }
            // Optional msg.
            std::optional<uint256> msg;
            const std::string msg_hex = request.params[4].isNull() ? "" : request.params[4].get_str();
            if (!msg_hex.empty()) {
                auto m = uint256::FromHex(msg_hex);
                if (!m) throw JSONRPCError(RPC_INVALID_PARAMETER, "msg must be 32-byte hex");
                msg = *m;
            }

            auto secnonce = std::make_unique<MuSig2SecNonce>();
            auto pubnonce = bma::NonceGen(*secnonce, self_priv, self_pub, msg, cache, session_seed);
            if (!pubnonce) throw JSONRPCError(RPC_INTERNAL_ERROR, "NonceGen failed");

            // Generate a fresh handle for the secnonce.
            uint256 handle;
            GetStrongRandBytes(handle);
            if (!btr::Stash(handle, std::move(secnonce))) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "secnonce handle collision");
            }

            UniValue out{UniValue::VOBJ};
            out.pushKV("pubnonce",        HexStr(*pubnonce));
            out.pushKV("secnonce_handle", handle.ToString());
            return out;
        }
    };
}

RPCMethod pricoin_btc_musig2_aggregate_nonces()
{
    return RPCMethod{
        "pricoin_btc_musig2_aggregate_nonces",
        "Aggregate all parties' 66-byte pubnonces into one 66-byte aggnonce.\n"
        "Order-independent (BIP327 nonce aggregation is commutative).\n",
        {
            {"pubnonces", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of 66-byte pubnonce hex strings",
                {
                    {"pubnonce", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "66-byte pubnonce hex"},
                }
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "aggnonce", "66-byte aggregate nonce"}}
        },
        RPCExamples{HelpExampleCli("pricoin_btc_musig2_aggregate_nonces", "[\"<pn_a>\",\"<pn_b>\"]")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            const auto& arr = request.params[0];
            if (!arr.isArray() || arr.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "pubnonces must be a non-empty array");
            }
            std::vector<bma::PubNonce66> pns;
            pns.reserve(arr.size());
            for (size_t i = 0; i < arr.size(); ++i) {
                pns.push_back(ParseFixedHex<bma::PubNonce66>(arr[i].get_str(), "pubnonce"));
            }
            auto agg = bma::AggregateNonces(pns);
            if (!agg) throw JSONRPCError(RPC_INTERNAL_ERROR, "AggregateNonces failed");
            UniValue out{UniValue::VOBJ};
            out.pushKV("aggnonce", HexStr(*agg));
            return out;
        }
    };
}

RPCMethod pricoin_btc_musig2_process()
{
    return RPCMethod{
        "pricoin_btc_musig2_process",
        "Bind the aggnonce + sighash + keyagg_cache into a session. Returns\n"
        "the 133-byte session bytes plus the nonce_parity captured at this\n"
        "step (needed later for adapt/extract).\n"
        "\n"
        "If `adaptor_T_G` is supplied, the resulting aggregated signature\n"
        "will be a pre-signature requiring Adapt(t) before BIP340 verifies.\n"
        "Omit it for plain (non-adaptor) MuSig2 — refund flow.\n",
        {
            {"aggnonce",     RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "66-byte aggregate nonce"},
            {"msg",          RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte sighash"},
            {"keyagg_cache", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "197-byte cache"},
            {"adaptor_T_G",  RPCArg::Type::STR_HEX, RPCArg::Default{""}, "Optional 33-byte adaptor point T_G"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "data",         "133-byte session bytes"},
                {RPCResult::Type::NUM,     "nonce_parity", "0 or 1 — needed for adapt/extract"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_btc_musig2_process", "<aggnonce> <msg> <cache> [<T_G>]")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto aggn = ParseFixedHex<bma::AggNonce66>(request.params[0].get_str(), "aggnonce");
            auto msg = uint256::FromHex(request.params[1].get_str());
            if (!msg) throw JSONRPCError(RPC_INVALID_PARAMETER, "msg must be 32-byte hex");
            bma::KeyAggCache cache = ParseKeyAggCacheBlob(request.params[2].get_str());
            std::optional<bma::AdaptorPointCompressed> T_G;
            const std::string tg_hex = request.params[3].isNull() ? "" : request.params[3].get_str();
            if (!tg_hex.empty()) {
                T_G = ParseFixedHex<bma::AdaptorPointCompressed>(tg_hex, "adaptor_T_G");
            }
            auto session = bma::ProcessNonces(aggn, *msg, cache, T_G);
            if (!session) throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNonces failed");
            return SessionToJSON(*session);
        }
    };
}

RPCMethod pricoin_btc_musig2_partial_sign()
{
    return RPCMethod{
        "pricoin_btc_musig2_partial_sign",
        "Per-party partial sign. Consumes the secnonce stashed at round1\n"
        "(by handle); emits a 32-byte partial signature.\n"
        "\n"
        "After this call the secnonce_handle is INVALIDATED — the same\n"
        "handle cannot be re-used.\n",
        {
            {"secnonce_handle", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Handle from round1"},
            {"self_priv",       RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte priv key"},
            {"self_pub",        RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "33-byte compressed pub"},
            {"keyagg_cache",    RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "197-byte cache"},
            {"session", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Session object from process",
                {
                    {"data",         RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                    {"nonce_parity", RPCArg::Type::NUM,     RPCArg::Optional::NO, ""},
                }
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "partial_sig", "32-byte partial signature"}}
        },
        RPCExamples{HelpExampleCli("pricoin_btc_musig2_partial_sign",
            "<handle> <priv> <pub> <cache> {\"data\":\"...\",\"nonce_parity\":0}")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto handle_opt = uint256::FromHex(request.params[0].get_str());
            if (!handle_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "secnonce_handle must be 32-byte hex");
            auto secnonce = btr::Take(*handle_opt);
            if (!secnonce) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "secnonce_handle not found — already consumed, never created, or daemon restarted");
            }
            auto priv_bytes = TryParseHex<unsigned char>(request.params[1].get_str());
            if (!priv_bytes || priv_bytes->size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "self_priv must be 32-byte hex");
            }
            bma::Scalar self_priv;
            std::copy(priv_bytes->begin(), priv_bytes->end(), self_priv.begin());

            auto pub_bytes = TryParseHex<unsigned char>(request.params[2].get_str());
            if (!pub_bytes || pub_bytes->size() != 33) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "self_pub must be 33-byte hex");
            }
            CPubKey self_pub(std::span<const unsigned char>(pub_bytes->data(), 33));

            bma::KeyAggCache cache = ParseKeyAggCacheBlob(request.params[3].get_str());
            bma::Session session = ParseSessionBlob(request.params[4]);

            auto partial = bma::PartialSign(*secnonce, self_priv, self_pub, cache, session);
            if (!partial) throw JSONRPCError(RPC_INTERNAL_ERROR, "PartialSign failed");

            UniValue out{UniValue::VOBJ};
            out.pushKV("partial_sig", HexStr(*partial));
            return out;
        }
    };
}

RPCMethod pricoin_btc_musig2_aggregate_partials()
{
    return RPCMethod{
        "pricoin_btc_musig2_aggregate_partials",
        "Aggregate per-party partial sigs into a 64-byte (pre-)signature.\n"
        "If the session was built without an adaptor, the result is a valid\n"
        "BIP340 signature. With an adaptor, it's a pre-signature requiring\n"
        "Adapt(t).\n",
        {
            {"session", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Session object",
                {
                    {"data",         RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                    {"nonce_parity", RPCArg::Type::NUM,     RPCArg::Optional::NO, ""},
                }
            },
            {"partials", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of 32-byte partial-sig hex strings",
                {
                    {"partial", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""},
                }
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "sig", "64-byte (pre-)signature"}}
        },
        RPCExamples{HelpExampleCli("pricoin_btc_musig2_aggregate_partials",
            "{\"data\":\"...\",\"nonce_parity\":0} [\"<p_a>\",\"<p_b>\"]")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            bma::Session session = ParseSessionBlob(request.params[0]);
            const auto& arr = request.params[1];
            if (!arr.isArray() || arr.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "partials must be a non-empty array");
            }
            std::vector<bma::PartialSig32> ps;
            ps.reserve(arr.size());
            for (size_t i = 0; i < arr.size(); ++i) {
                ps.push_back(ParseFixedHex<bma::PartialSig32>(arr[i].get_str(), "partial"));
            }
            auto sig = bma::AggregatePartials(session, ps);
            if (!sig) throw JSONRPCError(RPC_INTERNAL_ERROR, "AggregatePartials failed");
            UniValue out{UniValue::VOBJ};
            out.pushKV("sig", HexStr(*sig));
            return out;
        }
    };
}

RPCMethod pricoin_btc_musig2_adapt()
{
    return RPCMethod{
        "pricoin_btc_musig2_adapt",
        "Adapt a pre-signature with held secret t → 64-byte BIP340 signature.\n"
        "Verifies under the deployed XOnlyPubKey::VerifySchnorr (= libsecp256k1\n"
        "BIP340) — i.e., what real BTC nodes use.\n",
        {
            {"presig",       RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "64-byte pre-signature"},
            {"t_secret",     RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte adaptor secret"},
            {"nonce_parity", RPCArg::Type::NUM,     RPCArg::Optional::NO, "0 or 1 (from session)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "sig", "64-byte BIP340 signature"}}
        },
        RPCExamples{HelpExampleCli("pricoin_btc_musig2_adapt", "<presig> <t> 0")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto presig = ParseFixedHex<bma::SignatureBytes>(request.params[0].get_str(), "presig");
            auto t      = ParseFixedHex<bma::Scalar>(request.params[1].get_str(), "t_secret");
            const int parity = request.params[2].getInt<int>();
            auto sig = bma::Adapt(presig, t, parity);
            if (!sig) throw JSONRPCError(RPC_INTERNAL_ERROR, "Adapt failed");
            UniValue out{UniValue::VOBJ};
            out.pushKV("sig", HexStr(*sig));
            return out;
        }
    };
}

RPCMethod pricoin_btc_musig2_extract()
{
    return RPCMethod{
        "pricoin_btc_musig2_extract",
        "Extract t from (presig, sig, nonce_parity). Caller must have\n"
        "independently verified that `sig` is the published BIP340 signature\n"
        "corresponding to `presig` — this RPC does NOT validate `sig`; if it's\n"
        "invalid, the extracted scalar is nonsense (libsecp256k1 contract).\n",
        {
            {"presig",       RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "64-byte pre-signature"},
            {"sig",          RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "64-byte BIP340 sig observed on-chain"},
            {"nonce_parity", RPCArg::Type::NUM,     RPCArg::Optional::NO, "0 or 1"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "t_secret", "32-byte recovered scalar"}}
        },
        RPCExamples{HelpExampleCli("pricoin_btc_musig2_extract", "<presig> <sig> 0")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto presig = ParseFixedHex<bma::SignatureBytes>(request.params[0].get_str(), "presig");
            auto sig    = ParseFixedHex<bma::SignatureBytes>(request.params[1].get_str(), "sig");
            const int parity = request.params[2].getInt<int>();
            auto t = bma::Extract(presig, sig, parity);
            if (!t) throw JSONRPCError(RPC_INTERNAL_ERROR, "Extract failed");
            UniValue out{UniValue::VOBJ};
            out.pushKV("t_secret", HexStr(*t));
            return out;
        }
    };
}

// ─────────────────────────────────────────────────────────────────
// Atomic-swap phase 5 — BTC MuSig2 nonce-reuse defence (BTC-side §4.1a).
//
// Wallet-tier RPCs to begin / mark-finalized / inspect / erase
// per-(agg_xonly, msg, role) round-1 commitment records. Plus a
// `_safe` variant of round1 that atomically generates a pubnonce
// and persists the commitment record before the pubnonce returns.
// ─────────────────────────────────────────────────────────────────

namespace bnr = ::wallet::pricoin_btc_musig2_nonce_records;
namespace bnp = ::pricoin::btc_musig2_nonce_policy;

bnp::Role ParseBtcNonceRole(const std::string& s)
{
    if (s == "initiator") return bnp::Role::Initiator;
    if (s == "responder") return bnp::Role::Responder;
    throw JSONRPCError(RPC_INVALID_PARAMETER,
        "role must be \"initiator\" or \"responder\"");
}

bnp::RecordKey ParseBtcNonceRecordKey(
    const UniValue& agg_xonly_hex, const UniValue& msg_hex, const UniValue& role_str)
{
    auto agg = uint256::FromHex(agg_xonly_hex.get_str());
    if (!agg) throw JSONRPCError(RPC_INVALID_PARAMETER, "agg_xonly must be 32-byte hex");
    auto msg = uint256::FromHex(msg_hex.get_str());
    if (!msg) throw JSONRPCError(RPC_INVALID_PARAMETER, "msg must be 32-byte hex");
    bnp::RecordKey k;
    k.agg_xonly = *agg;
    k.msg = *msg;
    k.role = ParseBtcNonceRole(role_str.get_str());
    return k;
}

UniValue BtcNonceRecordToJSON(const bnp::NonceRecord& r)
{
    UniValue out{UniValue::VOBJ};
    out.pushKV("agg_xonly",     r.key.agg_xonly.ToString());
    out.pushKV("msg",           r.key.msg.ToString());
    out.pushKV("role",
        r.key.role == bnp::Role::Initiator ? "initiator" : "responder");
    out.pushKV("session_id",    r.session_id.ToString());
    out.pushKV("pubnonce",      HexStr(r.pubnonce));
    out.pushKV("finalized",     r.finalized);
    out.pushKV("created_time",  r.created_time);
    out.pushKV("updated_time",  r.updated_time);
    out.pushKV("record_digest", bnp::RecordDigest(r.key).ToString());
    return out;
}

[[noreturn]] void ThrowFromBtcNonceBeginResult(bnr::BeginResult r)
{
    using R = bnr::BeginResult;
    switch (r) {
    case R::Ok: assert(false);
    case R::InvalidInput:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "session_id must be non-null");
    case R::Locked:
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
    case R::ConflictDifferentSession:
        throw JSONRPCError(RPC_INVALID_REQUEST,
            "BTC §4.1a: a record exists for this (agg_xonly, msg, role) under "
            "a DIFFERENT session_id — refusing to commit a new pubnonce");
    case R::ConflictSameSessionInFlight:
        throw JSONRPCError(RPC_INVALID_REQUEST,
            "BTC §4.1a: a record exists for this (agg_xonly, msg, role) under "
            "the same session_id with finalized=false — already in flight");
    case R::WriteFailed:
        throw JSONRPCError(RPC_INTERNAL_ERROR, "wallet write failed");
    }
    assert(false);
}

[[noreturn]] void ThrowFromBtcNonceMutateResult(bnr::MutateResult r)
{
    using R = bnr::MutateResult;
    switch (r) {
    case R::Ok: assert(false);
    case R::NotFound:
        throw JSONRPCError(RPC_INVALID_REQUEST, "no record for this key");
    case R::Locked:
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
    case R::WriteFailed:
        throw JSONRPCError(RPC_INTERNAL_ERROR, "wallet write failed");
    }
    assert(false);
}

RPCMethod pricoin_btc_musig2_round1_safe()
{
    return RPCMethod{
        "pricoin_btc_musig2_round1_safe",
        "BTC-side §4.1a: generate a MuSig2 round-1 nonce AND atomically\n"
        "persist the commitment record before the pubnonce returns. Equivalent\n"
        "to pricoin_btc_musig2_round1 followed by Begin, but enforced as a\n"
        "single transaction: the pubnonce is never returned to the caller\n"
        "unless the persistence record is on disk.\n"
        "\n"
        "REJECTS if a record already exists for the same (agg_xonly, msg, role)\n"
        "under a different session_id, OR under the same session_id with\n"
        "finalized=false.\n",
        {
            {"self_pub",     RPCArg::Type::STR_HEX, RPCArg::Optional::NO,  "33-byte compressed self pubkey"},
            {"keyagg_cache", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,  "197-byte cache from pricoin_btc_musig2_keyagg"},
            {"agg_xonly",    RPCArg::Type::STR_HEX, RPCArg::Optional::NO,  "32-byte aggregate x-only pubkey (key field)"},
            {"msg",          RPCArg::Type::STR_HEX, RPCArg::Optional::NO,  "32-byte sighash (key field + nonce binding)"},
            {"role",         RPCArg::Type::STR,     RPCArg::Optional::NO,  "\"initiator\" or \"responder\""},
            {"session_id",   RPCArg::Type::STR_HEX, RPCArg::Optional::NO,  "32-byte session id (typically from pricoin_swap_session_create)"},
            {"session_seed", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,  "32-byte CSPRNG bytes — must be unique per call"},
            {"self_priv",    RPCArg::Type::STR_HEX, RPCArg::Default{""},   "Optional 32-byte priv (binding for nonce derivation)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "pubnonce",        "66-byte serialized pubnonce"},
                {RPCResult::Type::STR_HEX, "secnonce_handle", "32-byte opaque handle for partial_sign"},
                {RPCResult::Type::STR_HEX, "record_digest",   "32-byte digest of (agg_xonly, msg, role)"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_btc_musig2_round1_safe",
            "<self_pub> <cache> <agg_xonly> <msg> initiator <session_id> <seed>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");

            auto pub_bytes = TryParseHex<unsigned char>(request.params[0].get_str());
            if (!pub_bytes || pub_bytes->size() != 33) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "self_pub must be 33-byte hex");
            }
            CPubKey self_pub(std::span<const unsigned char>(pub_bytes->data(), 33));
            if (!self_pub.IsValid() || !self_pub.IsCompressed()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "self_pub invalid");
            }

            bma::KeyAggCache cache = ParseKeyAggCacheBlob(request.params[1].get_str());

            // Parse the record-key components.
            bnp::RecordKey key = ParseBtcNonceRecordKey(
                request.params[2], request.params[3], request.params[4]);

            auto sid = uint256::FromHex(request.params[5].get_str());
            if (!sid) throw JSONRPCError(RPC_INVALID_PARAMETER, "session_id must be 32-byte hex");

            auto seed_bytes = TryParseHex<unsigned char>(request.params[6].get_str());
            if (!seed_bytes || seed_bytes->size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "session_seed must be 32-byte hex");
            }
            uint256 session_seed;
            std::copy(seed_bytes->begin(), seed_bytes->end(), session_seed.begin());

            std::optional<bma::Scalar> self_priv;
            const std::string priv_hex = request.params[7].isNull() ? "" : request.params[7].get_str();
            if (!priv_hex.empty()) {
                auto priv_bytes = TryParseHex<unsigned char>(priv_hex);
                if (!priv_bytes || priv_bytes->size() != 32) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "self_priv must be 32-byte hex");
                }
                bma::Scalar s;
                std::copy(priv_bytes->begin(), priv_bytes->end(), s.begin());
                self_priv = s;
            }

            // Generate the secnonce + pubnonce.
            auto secnonce = std::make_unique<MuSig2SecNonce>();
            auto pubnonce = bma::NonceGen(*secnonce, self_priv, self_pub,
                                           key.msg, cache, session_seed);
            if (!pubnonce) throw JSONRPCError(RPC_INTERNAL_ERROR, "NonceGen failed");

            // ATOMIC: persist the commitment BEFORE we expose the pubnonce.
            // If Begin rejects, we throw without returning — pubnonce stays
            // local and the secnonce is dropped on scope exit.
            bnp::NonceRecord rec;
            bnr::BeginResult br = bnr::Begin(*wallet_sp, key, *sid, *pubnonce, rec);
            if (br != bnr::BeginResult::Ok) ThrowFromBtcNonceBeginResult(br);

            // Stash the secnonce keyed by a fresh handle.
            uint256 handle;
            GetStrongRandBytes(handle);
            if (!btr::Stash(handle, std::move(secnonce))) {
                // Should never happen — fresh random handle.
                throw JSONRPCError(RPC_INTERNAL_ERROR, "secnonce handle collision");
            }

            UniValue out{UniValue::VOBJ};
            out.pushKV("pubnonce",        HexStr(*pubnonce));
            out.pushKV("secnonce_handle", handle.ToString());
            out.pushKV("record_digest",   bnp::RecordDigest(key).ToString());
            return out;
        }
    };
}

RPCMethod pricoin_btc_musig2_nonce_mark_finalized()
{
    return RPCMethod{
        "pricoin_btc_musig2_nonce_mark_finalized",
        "Mark a BTC MuSig2 nonce-reuse record finalized. Call this when the\n"
        "corresponding BTC tx is confirmed on-chain — the spent output is\n"
        "no longer signable, so nonce-reuse is no longer a concern.\n"
        "After this transition, future round1_safe under the SAME session_id\n"
        "is permitted; under a different session_id the policy continues to\n"
        "reject (strict reading — manual Erase is required to fully reset).\n",
        {
            {"agg_xonly", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"msg",       RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"role",      RPCArg::Type::STR,     RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Updated record" },
        RPCExamples{HelpExampleCli("pricoin_btc_musig2_nonce_mark_finalized",
            "<agg_xonly> <msg> initiator")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            bnp::RecordKey key = ParseBtcNonceRecordKey(
                request.params[0], request.params[1], request.params[2]);
            auto r = bnr::MarkFinalized(*wallet_sp, key);
            if (r != bnr::MutateResult::Ok) ThrowFromBtcNonceMutateResult(r);
            bnp::NonceRecord rec;
            (void)bnr::Get(*wallet_sp, key, rec);
            return BtcNonceRecordToJSON(rec);
        }
    };
}

RPCMethod pricoin_btc_musig2_nonce_get()
{
    return RPCMethod{
        "pricoin_btc_musig2_nonce_get",
        "Read a BTC MuSig2 nonce-reuse record.\n",
        {
            {"agg_xonly", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"msg",       RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"role",      RPCArg::Type::STR,     RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Record" },
        RPCExamples{HelpExampleCli("pricoin_btc_musig2_nonce_get",
            "<agg_xonly> <msg> initiator")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            bnp::RecordKey key = ParseBtcNonceRecordKey(
                request.params[0], request.params[1], request.params[2]);
            bnp::NonceRecord rec;
            auto r = bnr::Get(*wallet_sp, key, rec);
            if (r == bnr::LookupResult::Locked) throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
            if (r == bnr::LookupResult::NotFound) throw JSONRPCError(RPC_INVALID_REQUEST, "no record for this key");
            return BtcNonceRecordToJSON(rec);
        }
    };
}

RPCMethod pricoin_btc_musig2_nonce_list()
{
    return RPCMethod{
        "pricoin_btc_musig2_nonce_list",
        "List all BTC MuSig2 nonce-reuse records in this wallet.\n",
        {},
        RPCResult{ RPCResult::Type::ARR, "", "",
            {{RPCResult::Type::ANY, "", "Record"}} },
        RPCExamples{HelpExampleCli("pricoin_btc_musig2_nonce_list", "")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            std::vector<bnp::NonceRecord> all;
            auto r = bnr::List(*wallet_sp, all);
            if (r == bnr::LookupResult::Locked) throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
            UniValue out{UniValue::VARR};
            for (const auto& rec : all) out.push_back(BtcNonceRecordToJSON(rec));
            return out;
        }
    };
}

RPCMethod pricoin_btc_musig2_nonce_erase()
{
    return RPCMethod{
        "pricoin_btc_musig2_nonce_erase",
        "DESTRUCTIVE: hard-delete a BTC MuSig2 nonce-reuse record. After erase\n"
        "the slot becomes a fresh starting point — the §4.1a safety rail is\n"
        "gone. Use only when the in-flight signing session is permanently\n"
        "aborted and you have explicit operator approval.\n",
        {
            {"agg_xonly", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"msg",       RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"role",      RPCArg::Type::STR,     RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::BOOL, "erased", "true"}} },
        RPCExamples{HelpExampleCli("pricoin_btc_musig2_nonce_erase",
            "<agg_xonly> <msg> initiator")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            bnp::RecordKey key = ParseBtcNonceRecordKey(
                request.params[0], request.params[1], request.params[2]);
            auto r = bnr::Erase(*wallet_sp, key);
            if (r != bnr::MutateResult::Ok) ThrowFromBtcNonceMutateResult(r);
            UniValue out{UniValue::VOBJ};
            out.pushKV("erased", true);
            return out;
        }
    };
}

// ─────────────────────────────────────────────────────────────────
// BTC swap-tx build / finalize / address helper.
// Wraps `swap/btc_refund_tx` so a Python test can drive a full
// BTC-side refund (or claim) end-to-end on regtest.
// ─────────────────────────────────────────────────────────────────

namespace brt = ::pricoin::swap::btc_refund_tx;

RPCMethod pricoin_btc_swap_tx_build()
{
    return RPCMethod{
        "pricoin_btc_swap_tx_build",
        "Build a BTC-side swap-tx skeleton spending a 2-of-2 P2TR funding output.\n"
        "Returns the unsigned tx hex + the BIP341 key-path-spend sighash that the\n"
        "cooperative MuSig2 flow signs. Set `nlocktime` ≥ T_foreign_refund for a\n"
        "refund tx; set 0 for a claim tx (no timelock).\n",
        {
            {"funding_txid",     RPCArg::Type::STR_HEX, RPCArg::Optional::NO,  "32-byte funding txid"},
            {"funding_vout",     RPCArg::Type::NUM,     RPCArg::Optional::NO,  ""},
            {"funding_amount_sat", RPCArg::Type::NUM,   RPCArg::Optional::NO,  "Funding output amount (smallest unit)"},
            {"agg_xonly",        RPCArg::Type::STR_HEX, RPCArg::Optional::NO,  "32-byte aggregate x-only pubkey of the 2-of-2"},
            {"recipient_script_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex of the recipient's scriptPubKey"},
            {"refund_amount_sat", RPCArg::Type::NUM,    RPCArg::Optional::NO,  "Recipient amount (= funding - fee)"},
            {"nlocktime",        RPCArg::Type::NUM,     RPCArg::Default{0},    "0 for claim, ≥1 for refund"},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "tx_hex",  "Unsigned tx (empty witness)"},
                {RPCResult::Type::STR_HEX, "sighash", "32-byte BIP341 sighash"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_btc_swap_tx_build", "<args>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            brt::BtcRefundTxParams p;
            auto txid = uint256::FromHex(request.params[0].get_str());
            if (!txid) throw JSONRPCError(RPC_INVALID_PARAMETER, "funding_txid must be 32-byte hex");
            p.funding_txid = *txid;
            p.funding_vout = request.params[1].getInt<uint32_t>();
            p.funding_amount_sat = request.params[2].getInt<int64_t>();

            auto agg = TryParseHex<unsigned char>(request.params[3].get_str());
            if (!agg || agg->size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "agg_xonly must be 32-byte hex");
            }
            std::copy(agg->begin(), agg->end(), p.agg_xonly.begin());

            auto spk = TryParseHex<unsigned char>(request.params[4].get_str());
            if (!spk || spk->empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "recipient_script_pubkey must be non-empty hex");
            }
            p.recipient_script_pubkey = *spk;

            p.refund_amount_sat = request.params[5].getInt<int64_t>();
            p.nlocktime = request.params[6].isNull() ? 0 : request.params[6].getInt<int32_t>();

            auto built = brt::Build(p);
            if (!built) throw JSONRPCError(RPC_INVALID_PARAMETER, "btc_refund_tx::Build rejected params");

            DataStream ds;
            ds << TX_WITH_WITNESS(CTransaction{built->tx});
            UniValue out{UniValue::VOBJ};
            out.pushKV("tx_hex",  HexStr(std::span<const unsigned char>{
                UCharCast(ds.data()), ds.size()}));
            // sighash is just raw 32 bytes — caller treats it as the message.
            out.pushKV("sighash", HexStr(built->sighash));
            return out;
        }
    };
}

RPCMethod pricoin_btc_swap_tx_finalize()
{
    return RPCMethod{
        "pricoin_btc_swap_tx_finalize",
        "Attach a 64-byte BIP340 (cooperative MuSig2) signature to a swap-tx skeleton's\n"
        "input 0 as a P2TR key-path-spend witness, returning the broadcastable hex.\n",
        {
            {"tx_hex",   RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Skeleton from pricoin_btc_swap_tx_build"},
            {"sig64",    RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "64-byte BIP340 signature"},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "tx_hex", "Broadcastable tx (witness attached)"}}
        },
        RPCExamples{HelpExampleCli("pricoin_btc_swap_tx_finalize", "<tx_hex> <sig64>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            // Decode the skeleton.
            auto tx_bytes = TryParseHex<unsigned char>(request.params[0].get_str());
            if (!tx_bytes) throw JSONRPCError(RPC_INVALID_PARAMETER, "tx_hex must be hex");
            CMutableTransaction mtx;
            try {
                DataStream ds{std::span<const unsigned char>{*tx_bytes}};
                ds >> TX_WITH_WITNESS(mtx);
            } catch (const std::exception&) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "tx_hex did not parse as a valid transaction");
            }
            if (mtx.vin.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "tx has no inputs");
            }

            auto sig = TryParseHex<unsigned char>(request.params[1].get_str());
            if (!sig || sig->size() != 64) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "sig64 must be 64-byte hex");
            }

            // Wrap up via Build/Finalize idiom — but we already have the skeleton,
            // so attach the witness directly (matches what brt::Finalize does).
            mtx.vin[0].scriptWitness.stack.clear();
            mtx.vin[0].scriptWitness.stack.emplace_back(sig->begin(), sig->end());

            DataStream ds;
            ds << TX_WITH_WITNESS(CTransaction{mtx});
            UniValue out{UniValue::VOBJ};
            out.pushKV("tx_hex", HexStr(std::span<const unsigned char>{
                UCharCast(ds.data()), ds.size()}));
            return out;
        }
    };
}

RPCMethod pricoin_btc_p2tr_address()
{
    return RPCMethod{
        "pricoin_btc_p2tr_address",
        "Encode a 32-byte x-only pubkey as a P2TR (BIP350 bech32m) address using\n"
        "the current chain's HRP. Useful for funding a 2-of-2 MuSig2 aggregate via\n"
        "the existing wallet sendtoaddress on regtest.\n",
        {
            {"xonly", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte x-only pubkey"},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR, "address", "P2TR bech32m address"}}
        },
        RPCExamples{HelpExampleCli("pricoin_btc_p2tr_address", "<xonly>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto bytes = TryParseHex<unsigned char>(request.params[0].get_str());
            if (!bytes || bytes->size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "xonly must be 32-byte hex");
            }
            XOnlyPubKey xonly(std::span<const unsigned char>{bytes->data(), 32});
            const std::string addr = EncodeDestination(WitnessV1Taproot{xonly});
            UniValue out{UniValue::VOBJ};
            out.pushKV("address", addr);
            return out;
        }
    };
}

// ─────────────────────────────────────────────────────────────────
// Phase 6 — orderbook offer RPCs.
// Tier 1 of UI work: local order management, signed URIs for off-band
// exchange, price-cross matching, partial-fill state machine.
// ─────────────────────────────────────────────────────────────────

namespace pof = ::wallet::pricoin_offer;

const char* OfferSideStr(pof::Side s)
{
    return s == pof::Side::BuyPric ? "buy_pric" : "sell_pric";
}

pof::Side ParseOfferSide(const std::string& s)
{
    if (s == "buy_pric")  return pof::Side::BuyPric;
    if (s == "sell_pric") return pof::Side::SellPric;
    throw JSONRPCError(RPC_INVALID_PARAMETER, "side must be \"buy_pric\" or \"sell_pric\"");
}

const char* OfferChainStr(pof::ForeignChain c)
{
    return c == pof::ForeignChain::Btc ? "btc" : "ltc";
}

pof::ForeignChain ParseOfferChain(const std::string& s)
{
    if (s == "btc") return pof::ForeignChain::Btc;
    if (s == "ltc") return pof::ForeignChain::Ltc;
    throw JSONRPCError(RPC_INVALID_PARAMETER, "foreign_chain must be \"btc\" or \"ltc\"");
}

const char* OfferStatusStr(pof::Status s)
{
    switch (s) {
    case pof::Status::Active:    return "active";
    case pof::Status::Matched:   return "matched";
    case pof::Status::Filled:    return "filled";
    case pof::Status::Cancelled: return "cancelled";
    case pof::Status::Expired:   return "expired";
    }
    return "unknown";
}

const char* OfferOriginStr(pof::Origin o)
{
    return o == pof::Origin::Local ? "local" : "imported";
}

UniValue OfferToJSON(const pof::Order& o)
{
    UniValue out{UniValue::VOBJ};
    out.pushKV("order_id",        o.payload.order_id.ToString());
    out.pushKV("origin",          OfferOriginStr(o.origin));
    out.pushKV("side",            OfferSideStr(o.payload.side));
    out.pushKV("foreign_chain",   OfferChainStr(o.payload.foreign_chain));
    out.pushKV("max_pric_amount_sat",       o.payload.max_pric_amount_sat);
    out.pushKV("foreign_amount_at_max_sat", o.payload.foreign_amount_at_max_sat);
    out.pushKV("expiry_unix_sec", o.payload.expiry_unix_sec);
    out.pushKV("maker_pubkey",    HexStr(o.payload.maker_pubkey));
    out.pushKV("status",          OfferStatusStr(o.status));
    out.pushKV("pric_remaining_sat", o.pric_remaining_sat);
    out.pushKV("pric_in_flight_sat", o.pric_in_flight_sat);
    if (!o.matched_with_order_id.IsNull()) {
        out.pushKV("matched_with_order_id", o.matched_with_order_id.ToString());
    }
    out.pushKV("notes",           o.notes);
    out.pushKV("created_time",    o.created_time);
    out.pushKV("updated_time",    o.updated_time);
    return out;
}

[[noreturn]] void ThrowFromOfferCreate(pof::CreateResult r)
{
    using R = pof::CreateResult;
    switch (r) {
    case R::Ok: assert(false);
    case R::InvalidInput:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "amounts and expiry must be > 0");
    case R::Locked:
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
    case R::DerivationFailed:
        throw JSONRPCError(RPC_INTERNAL_ERROR,
            "swap-identity priv unavailable (wallet locked or not initialized)");
    case R::WriteFailed:
        throw JSONRPCError(RPC_INTERNAL_ERROR, "wallet write failed");
    }
    assert(false);
}

[[noreturn]] void ThrowFromOfferImport(pof::ImportResult r)
{
    using R = pof::ImportResult;
    switch (r) {
    case R::Ok: assert(false);
    case R::InvalidUri:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "URI did not parse as a pricoffer:v1 envelope");
    case R::InvalidSignature:
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "offer signature does not verify against maker_pubkey");
    case R::Duplicate:
        throw JSONRPCError(RPC_INVALID_REQUEST,
            "an order with this order_id is already in the wallet");
    case R::AlreadyExpired:
        throw JSONRPCError(RPC_INVALID_REQUEST,
            "offer expiry has already passed; ask the maker for a fresh URI");
    case R::Locked:
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
    case R::WriteFailed:
        throw JSONRPCError(RPC_INTERNAL_ERROR, "wallet write failed");
    }
    assert(false);
}

[[noreturn]] void ThrowFromOfferMutate(pof::MutateResult r)
{
    using R = pof::MutateResult;
    switch (r) {
    case R::Ok: assert(false);
    case R::NotFound:
        throw JSONRPCError(RPC_INVALID_REQUEST, "no order with that id");
    case R::InvalidState:
        throw JSONRPCError(RPC_INVALID_REQUEST,
            "current state does not permit this transition");
    case R::InvalidInput:
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid input");
    case R::PriceCrossFailed:
        throw JSONRPCError(RPC_INVALID_REQUEST,
            "orders do not price-cross (or amounts/chain mismatch)");
    case R::Locked:
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
    case R::WriteFailed:
        throw JSONRPCError(RPC_INTERNAL_ERROR, "wallet write failed");
    }
    assert(false);
}

uint256 ParseOrderId(const std::string& s)
{
    auto u = uint256::FromHex(s);
    if (!u) throw JSONRPCError(RPC_INVALID_PARAMETER, "order_id must be 32-byte hex");
    return *u;
}

RPCMethod pricoin_offer_create()
{
    return RPCMethod{
        "pricoin_offer_create",
        "Create a local order in the wallet's orderbook. Generates a fresh\n"
        "order_id, signs the offer with the wallet's swap-identity priv, and\n"
        "returns the record + the canonical pricoffer:v1/<base64> URI suitable\n"
        "for off-band exchange (paste, QR, IM).\n",
        {
            {"side",                      RPCArg::Type::STR,    RPCArg::Optional::NO, "\"buy_pric\" or \"sell_pric\""},
            {"foreign_chain",             RPCArg::Type::STR,    RPCArg::Optional::NO, "\"btc\" or \"ltc\""},
            {"max_pric_amount_sat",       RPCArg::Type::NUM,    RPCArg::Optional::NO, "Max PRIC amount (sats)"},
            {"foreign_amount_at_max_sat", RPCArg::Type::NUM,    RPCArg::Optional::NO, "Foreign amount IF max_pric is fully traded — implies the rate"},
            {"expiry_unix_sec",           RPCArg::Type::NUM,    RPCArg::Optional::NO, "Unix-seconds expiry (must be in the future)"},
            {"notes",                     RPCArg::Type::STR,    RPCArg::Default{""},  "Free-form local note"},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::ANY,     "record", "Order record (see pricoin_offer_get)"},
                {RPCResult::Type::STR,     "uri",    "pricoffer:v1/... canonical URI"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_offer_create",
            "sell_pric btc 100000000 50000000 1800000000 \"my first sell offer\"")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            pof::CreateParams p;
            p.side          = ParseOfferSide(request.params[0].get_str());
            p.foreign_chain = ParseOfferChain(request.params[1].get_str());
            p.max_pric_amount_sat       = request.params[2].getInt<int64_t>();
            p.foreign_amount_at_max_sat = request.params[3].getInt<int64_t>();
            p.expiry_unix_sec           = request.params[4].getInt<int64_t>();
            p.notes = request.params[5].isNull() ? "" : request.params[5].get_str();

            pof::Order o;
            auto r = pof::Create(*wallet_sp, p, o);
            if (r != pof::CreateResult::Ok) ThrowFromOfferCreate(r);
            UniValue out{UniValue::VOBJ};
            out.pushKV("record", OfferToJSON(o));
            out.pushKV("uri",    pof::EncodeUri(o.payload));
            return out;
        }
    };
}

RPCMethod pricoin_offer_import()
{
    return RPCMethod{
        "pricoin_offer_import",
        "Import an offer from a counterparty's pricoffer:v1/<base64> URI.\n"
        "Verifies the maker's signature; rejects duplicates, malformed URIs,\n"
        "and expired offers.\n",
        {
            {"uri", RPCArg::Type::STR, RPCArg::Optional::NO, "pricoffer:v1/<base64> URI"},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Imported order record" },
        RPCExamples{HelpExampleCli("pricoin_offer_import", "pricoffer:v1/<base64>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            pof::Order o;
            auto r = pof::Import(*wallet_sp, request.params[0].get_str(), o);
            if (r != pof::ImportResult::Ok) ThrowFromOfferImport(r);
            return OfferToJSON(o);
        }
    };
}

RPCMethod pricoin_offer_get()
{
    return RPCMethod{
        "pricoin_offer_get",
        "Read an order by id.\n",
        { {"order_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""} },
        RPCResult{ RPCResult::Type::ANY, "", "Order record" },
        RPCExamples{HelpExampleCli("pricoin_offer_get", "<order_id>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            pof::Order o;
            auto r = pof::Get(*wallet_sp, ParseOrderId(request.params[0].get_str()), o);
            if (r == pof::LookupResult::Locked) throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
            if (r == pof::LookupResult::NotFound) throw JSONRPCError(RPC_INVALID_REQUEST, "no order with that id");
            return OfferToJSON(o);
        }
    };
}

RPCMethod pricoin_offer_list()
{
    return RPCMethod{
        "pricoin_offer_list",
        "List all orders in this wallet's orderbook (local + imported).\n",
        {},
        RPCResult{ RPCResult::Type::ARR, "", "",
            {{RPCResult::Type::ANY, "", "Order record"}} },
        RPCExamples{HelpExampleCli("pricoin_offer_list", "")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            std::vector<pof::Order> all;
            auto r = pof::List(*wallet_sp, all);
            if (r == pof::LookupResult::Locked) throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
            UniValue out{UniValue::VARR};
            for (const auto& o : all) out.push_back(OfferToJSON(o));
            return out;
        }
    };
}

RPCMethod pricoin_offer_cancel()
{
    return RPCMethod{
        "pricoin_offer_cancel",
        "Operator-cancel an order. Allowed from Active or Matched (cancelling\n"
        "a Matched order also releases the in-flight reservation). Terminal.\n",
        { {"order_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""} },
        RPCResult{ RPCResult::Type::ANY, "", "Updated order record" },
        RPCExamples{HelpExampleCli("pricoin_offer_cancel", "<order_id>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 oid = ParseOrderId(request.params[0].get_str());
            auto r = pof::Cancel(*wallet_sp, oid);
            if (r != pof::MutateResult::Ok) ThrowFromOfferMutate(r);
            pof::Order o;
            (void)pof::Get(*wallet_sp, oid, o);
            return OfferToJSON(o);
        }
    };
}

RPCMethod pricoin_offer_match()
{
    return RPCMethod{
        "pricoin_offer_match",
        "Match my order against their order for the chosen actual_pric_amount.\n"
        "Both must be Active and price-cross. Both transition to Matched with\n"
        "pric_in_flight = actual_pric_amount.\n",
        {
            {"my_order_id",    RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"their_order_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"actual_pric_amount_sat", RPCArg::Type::NUM, RPCArg::Optional::NO, "≤ min(both pric_remaining_sat)"},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::ANY, "my_order",    "My order after match"},
                {RPCResult::Type::ANY, "their_order", "Their order after match"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_offer_match", "<my_id> <their_id> 100000000")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 mine   = ParseOrderId(request.params[0].get_str());
            const uint256 theirs = ParseOrderId(request.params[1].get_str());
            const int64_t amount = request.params[2].getInt<int64_t>();
            auto r = pof::Match(*wallet_sp, mine, theirs, amount);
            if (r != pof::MutateResult::Ok) ThrowFromOfferMutate(r);
            pof::Order m, t;
            (void)pof::Get(*wallet_sp, mine, m);
            (void)pof::Get(*wallet_sp, theirs, t);
            UniValue out{UniValue::VOBJ};
            out.pushKV("my_order",    OfferToJSON(m));
            out.pushKV("their_order", OfferToJSON(t));
            return out;
        }
    };
}

RPCMethod pricoin_offer_fill()
{
    return RPCMethod{
        "pricoin_offer_fill",
        "Mark a Matched order as filled (swap completed). Decrements remaining\n"
        "by in_flight; transitions to Filled if remaining=0, else back to Active.\n",
        { {"order_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""} },
        RPCResult{ RPCResult::Type::ANY, "", "Updated order record" },
        RPCExamples{HelpExampleCli("pricoin_offer_fill", "<order_id>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 oid = ParseOrderId(request.params[0].get_str());
            auto r = pof::Fill(*wallet_sp, oid);
            if (r != pof::MutateResult::Ok) ThrowFromOfferMutate(r);
            pof::Order o;
            (void)pof::Get(*wallet_sp, oid, o);
            return OfferToJSON(o);
        }
    };
}

RPCMethod pricoin_offer_unmatch()
{
    return RPCMethod{
        "pricoin_offer_unmatch",
        "Release a Matched order back to Active without consuming. Used when\n"
        "the swap setup aborts before reaching finality (the residual amount\n"
        "is preserved for a future match).\n",
        { {"order_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""} },
        RPCResult{ RPCResult::Type::ANY, "", "Updated order record" },
        RPCExamples{HelpExampleCli("pricoin_offer_unmatch", "<order_id>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 oid = ParseOrderId(request.params[0].get_str());
            auto r = pof::Unmatch(*wallet_sp, oid);
            if (r != pof::MutateResult::Ok) ThrowFromOfferMutate(r);
            pof::Order o;
            (void)pof::Get(*wallet_sp, oid, o);
            return OfferToJSON(o);
        }
    };
}

RPCMethod pricoin_offer_find_matches()
{
    return RPCMethod{
        "pricoin_offer_find_matches",
        "Find imported orders that price-cross with my order, sorted best-first.\n",
        { {"my_order_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""} },
        RPCResult{ RPCResult::Type::ARR, "", "",
            {{RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "their_order_id",          ""},
                    {RPCResult::Type::NUM,     "their_max_pric_sat",      ""},
                    {RPCResult::Type::NUM,     "their_foreign_at_max_sat",""},
                    {RPCResult::Type::NUM,     "max_actual_pric_sat",     "Best fill amount given remaining on both sides"},
                    {RPCResult::Type::NUM,     "price_advantage_milli",   "Sort key (bigger = better for me)"},
                }
            }} },
        RPCExamples{HelpExampleCli("pricoin_offer_find_matches", "<my_order_id>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 oid = ParseOrderId(request.params[0].get_str());
            std::vector<pof::MatchCandidate> cands;
            auto r = pof::FindMatches(*wallet_sp, oid, cands);
            if (r == pof::LookupResult::Locked) throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
            if (r == pof::LookupResult::NotFound) throw JSONRPCError(RPC_INVALID_REQUEST, "no order with that id");
            UniValue out{UniValue::VARR};
            for (const auto& c : cands) {
                UniValue obj{UniValue::VOBJ};
                obj.pushKV("their_order_id",            c.their_order_id.ToString());
                obj.pushKV("their_max_pric_sat",        c.their_max_pric_sat);
                obj.pushKV("their_foreign_at_max_sat",  c.their_foreign_at_max_sat);
                obj.pushKV("max_actual_pric_sat",       c.max_actual_pric_sat);
                obj.pushKV("price_advantage_milli",     c.price_advantage_milli);
                out.push_back(obj);
            }
            return out;
        }
    };
}

RPCMethod pricoin_offer_export_uri()
{
    return RPCMethod{
        "pricoin_offer_export_uri",
        "Re-export a local order's pricoffer URI (for re-publishing).\n"
        "Imported orders return an empty string.\n",
        { {"order_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""} },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR, "uri", ""}}
        },
        RPCExamples{HelpExampleCli("pricoin_offer_export_uri", "<order_id>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 oid = ParseOrderId(request.params[0].get_str());
            std::string uri;
            auto r = pof::ExportUri(*wallet_sp, oid, uri);
            if (r == pof::LookupResult::Locked) throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Wallet locked");
            if (r == pof::LookupResult::NotFound) throw JSONRPCError(RPC_INVALID_REQUEST, "no order with that id");
            UniValue out{UniValue::VOBJ};
            out.pushKV("uri", uri);
            return out;
        }
    };
}

// ─── Tier-3 chain-watcher RPCs ──────────────────────────────────

namespace pcw = ::wallet::pricoin_chain_watcher;

uint256 ParseChainWatchSwapId(const UniValue& v)
{
    auto sid = uint256::FromHex(v.get_str());
    if (!sid) throw JSONRPCError(RPC_INVALID_PARAMETER, "swap_id must be 32-byte hex");
    return *sid;
}

pcw::WatchKind ParseChainWatchKind(const UniValue& v)
{
    auto k = pcw::ParseWatchKind(v.get_str());
    if (!k) throw JSONRPCError(RPC_INVALID_PARAMETER,
        "kind must be one of: foreign_funding, pric_funding, pric_claim, foreign_claim, pric_refund, foreign_refund");
    return *k;
}

void ThrowFromChainWatchStore(pcw::StoreResult r)
{
    using SR = pcw::StoreResult;
    switch (r) {
    case SR::Ok: return;
    case SR::InvalidInput: throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid input for chainwatch entry");
    case SR::Locked:       throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "wallet locked");
    case SR::WriteFailed:  throw JSONRPCError(RPC_WALLET_ERROR, "wallet write failed");
    case SR::Duplicate:    throw JSONRPCError(RPC_INVALID_REQUEST, "duplicate entry for (swap_id, kind)");
    case SR::NotFound:     throw JSONRPCError(RPC_INVALID_REQUEST, "no chainwatch entry for that (swap_id, kind)");
    }
    throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown chainwatch error");
}

UniValue ChainWatchEntryToJSON(const pcw::WatchEntry& e)
{
    UniValue o{UniValue::VOBJ};
    o.pushKV("swap_id",            e.swap_id.ToString());
    o.pushKV("kind",               pcw::WatchKindName(e.kind));
    o.pushKV("txid",               e.txid_hex);
    if (e.vout >= 0) o.pushKV("vout", e.vout);
    o.pushKV("min_confirmations",  e.min_confirmations);
    o.pushKV("added_unix",         e.added_unix);
    return o;
}

RPCMethod pricoin_swapwatch_add()
{
    return RPCMethod{
        "pricoin_swapwatch_add",
        "Tier-3 chain watcher: register a candidate txid for an in-flight swap.\n"
        "When the txid reaches `min_confirmations` confirmations on the relevant\n"
        "chain (foreign chain via the configured client; PRIC chain via the\n"
        "embedded chainstate), the watcher applies the matching SetX transition\n"
        "to the AdaptorSwap state machine and removes the entry.\n",
        {
            {"swap_id",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO,  "32-byte adaptor-swap id"},
            {"kind",                RPCArg::Type::STR,     RPCArg::Optional::NO,
                "foreign_funding | pric_funding | pric_claim | foreign_claim | pric_refund | foreign_refund"},
            {"txid",                RPCArg::Type::STR_HEX, RPCArg::Optional::NO,  "32-byte tx id"},
            {"vout",                RPCArg::Type::NUM,     RPCArg::Default{-1},   "Output index — required for funding kinds"},
            {"min_confirmations",   RPCArg::Type::NUM,     RPCArg::Default{1},    "Confirmation threshold (1 default for regtest)"},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Stored entry" },
        RPCExamples{HelpExampleCli("pricoin_swapwatch_add", "<swap_id> foreign_funding <txid> 0 1")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            pcw::WatchEntry e;
            e.swap_id = ParseChainWatchSwapId(request.params[0]);
            e.kind    = ParseChainWatchKind(request.params[1]);
            e.txid_hex = request.params[2].get_str();
            if (e.txid_hex.size() != 64 || !IsHex(e.txid_hex)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "txid must be 32-byte hex");
            }
            e.vout = request.params[3].isNull() ? -1 : request.params[3].getInt<int32_t>();
            e.min_confirmations = request.params[4].isNull()
                ? 1 : request.params[4].getInt<int32_t>();
            ThrowFromChainWatchStore(pcw::Add(*wallet_sp, e));
            return ChainWatchEntryToJSON(e);
        }
    };
}

RPCMethod pricoin_swapwatch_remove()
{
    return RPCMethod{
        "pricoin_swapwatch_remove",
        "Remove a pending chainwatch entry. NotFound is non-fatal — the call\n"
        "succeeds with `removed=false`.\n",
        {
            {"swap_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"kind",    RPCArg::Type::STR,     RPCArg::Optional::NO, "Same enum as add"},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::BOOL, "removed", "True if the entry existed and was removed"}}
        },
        RPCExamples{HelpExampleCli("pricoin_swapwatch_remove", "<swap_id> foreign_funding")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 sid = ParseChainWatchSwapId(request.params[0]);
            const pcw::WatchKind k = ParseChainWatchKind(request.params[1]);
            const auto r = pcw::Remove(*wallet_sp, sid, k);
            UniValue out{UniValue::VOBJ};
            out.pushKV("removed", r == pcw::StoreResult::Ok);
            if (r != pcw::StoreResult::Ok && r != pcw::StoreResult::NotFound) {
                ThrowFromChainWatchStore(r);
            }
            return out;
        }
    };
}

RPCMethod pricoin_swapwatch_list()
{
    return RPCMethod{
        "pricoin_swapwatch_list",
        "List all pending chainwatch entries.\n",
        {},
        RPCResult{ RPCResult::Type::ANY, "", "Array of pending chainwatch entries" },
        RPCExamples{HelpExampleCli("pricoin_swapwatch_list", "")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            std::vector<pcw::WatchEntry> all;
            const auto r = pcw::List(*wallet_sp, all);
            if (r != pcw::StoreResult::Ok) ThrowFromChainWatchStore(r);
            UniValue out{UniValue::VARR};
            for (const auto& e : all) out.push_back(ChainWatchEntryToJSON(e));
            return out;
        }
    };
}

RPCMethod pricoin_swapwatch_start()
{
    return RPCMethod{
        "pricoin_swapwatch_start",
        "Start the per-wallet swap-watcher polling thread. Each tick,\n"
        "the watcher walks all pending entries (see pricoin_swapwatch_list),\n"
        "queries the matching foreign-chain backend (configured via\n"
        "-btcwatchurl= / -ltcwatchurl=) for confirmation depth, and\n"
        "applies the matching SetX transition on the AdaptorSwap state\n"
        "machine when the threshold is reached.\n"
        "\n"
        "Idempotent — calling twice has no effect. The thread is stopped\n"
        "by pricoin_swapwatch_stop or implicitly on wallet unload /\n"
        "daemon shutdown.\n",
        {
            {"interval_sec", RPCArg::Type::NUM, RPCArg::Default{30},
                "Poll interval in seconds. Default 30."},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::BOOL, "running", "True iff the watcher is now running"}}
        },
        RPCExamples{HelpExampleCli("pricoin_swapwatch_start", "30")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const int interval = request.params[0].isNull()
                ? 30 : request.params[0].getInt<int>();
            if (interval < 1 || interval > 3600) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "interval_sec must be in [1, 3600]");
            }
            pcw::StartManaged(*wallet_sp, std::chrono::seconds{interval});
            UniValue out{UniValue::VOBJ};
            out.pushKV("running", pcw::IsManagedRunning(*wallet_sp));
            return out;
        }
    };
}

RPCMethod pricoin_swapwatch_stop()
{
    return RPCMethod{
        "pricoin_swapwatch_stop",
        "Stop the per-wallet swap-watcher polling thread. Idempotent.\n",
        {},
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::BOOL, "running", "Always false after this returns"}}
        },
        RPCExamples{HelpExampleCli("pricoin_swapwatch_stop", "")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            pcw::StopManaged(*wallet_sp);
            UniValue out{UniValue::VOBJ};
            out.pushKV("running", false);
            return out;
        }
    };
}

RPCMethod pricoin_swapwatch_status()
{
    return RPCMethod{
        "pricoin_swapwatch_status",
        "Diagnostic snapshot of the per-wallet swap-watcher.\n",
        {},
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "running", "Polling thread alive?"},
                {RPCResult::Type::NUM,  "pending_entries", "Count of pending watch entries"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_swapwatch_status", "")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            std::vector<pcw::WatchEntry> all;
            (void)pcw::List(*wallet_sp, all);
            UniValue out{UniValue::VOBJ};
            out.pushKV("running", pcw::IsManagedRunning(*wallet_sp));
            out.pushKV("pending_entries", static_cast<int>(all.size()));
            return out;
        }
    };
}

RPCMethod pricoin_swapwatch_tick_once()
{
    return RPCMethod{
        "pricoin_swapwatch_tick_once",
        "Drive a single watcher tick synchronously. Walks all pending\n"
        "entries once, queries backends, applies transitions whose\n"
        "thresholds are met. Used by tests to advance the state\n"
        "machine deterministically without a background thread.\n",
        {},
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::NUM, "pending_after", "Count of entries remaining after the tick"}}
        },
        RPCExamples{HelpExampleCli("pricoin_swapwatch_tick_once", "")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            pcw::TickOnceManaged(*wallet_sp);
            std::vector<pcw::WatchEntry> all;
            (void)pcw::List(*wallet_sp, all);
            UniValue out{UniValue::VOBJ};
            out.pushKV("pending_after", static_cast<int>(all.size()));
            return out;
        }
    };
}

RPCMethod pricoin_swapwatch_broadcast_foreign()
{
    return RPCMethod{
        "pricoin_swapwatch_broadcast_foreign",
        "Submit a foreign-chain tx (BTC claim/refund) for relay AND register\n"
        "a swapwatch entry for the resulting txid in one atomic call. The\n"
        "watcher picks up the entry on its next tick and applies the matching\n"
        "SetX transition once confirmations reach `min_confirmations`.\n"
        "\n"
        "`kind` should be one of `foreign_claim` (Bob's claim swept) or\n"
        "`foreign_refund` (Alice's refund swept).\n"
        "\n"
        "Returns {txid, watch_kind} on success. If the broadcast succeeds but\n"
        "the watch registration fails (e.g., wallet locked), the txid is\n"
        "returned but the caller must add the watch manually.\n",
        {
            {"swap_id",            RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"kind",               RPCArg::Type::STR,     RPCArg::Optional::NO,
                "foreign_claim | foreign_refund"},
            {"tx_hex",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"min_confirmations",  RPCArg::Type::NUM,     RPCArg::Default{1}, ""},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "Txid the backend accepted"},
                {RPCResult::Type::STR,     "watch_kind", "Echo of the registered kind"},
                {RPCResult::Type::BOOL,    "watch_registered", "True iff the watch entry was stored"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_swapwatch_broadcast_foreign",
            "<swap_id> foreign_claim <hex> 1")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 sid = ParseChainWatchSwapId(request.params[0]);
            const pcw::WatchKind k = ParseChainWatchKind(request.params[1]);
            if (k != pcw::WatchKind::ForeignClaim && k != pcw::WatchKind::ForeignRefund) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "broadcast_foreign only supports foreign_claim or foreign_refund kinds");
            }
            const std::string tx_hex = request.params[2].get_str();
            if (!IsHex(tx_hex) || tx_hex.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "tx_hex must be non-empty hex");
            }
            const int32_t min_conf = request.params[3].isNull()
                ? 1 : request.params[3].getInt<int32_t>();

            // Look up the swap to get its foreign chain.
            ::wallet::pricoin_adaptor_swap::AdaptorSwap s;
            if (::wallet::pricoin_adaptor_swap::Get(*wallet_sp, sid, s)
                != ::wallet::pricoin_adaptor_swap::LookupResult::Ok) {
                throw JSONRPCError(RPC_INVALID_REQUEST, "swap not found");
            }
            auto client = pcw::MakeForeignClientFromRegistry(s.foreign_chain);
            if (!client) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "no foreign-chain backend registered for chain '" + s.foreign_chain + "'");
            }
            std::string txid;
            try {
                txid = client->Broadcast(tx_hex);
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_MISC_ERROR,
                    std::string("foreign broadcast failed: ") + e.what());
            }

            // Register the watch — atomically with broadcast as far as
            // the caller's view goes. If the wallet is locked we still
            // returned the broadcast txid (the foreign tx is in flight)
            // but warn that the watch wasn't recorded.
            pcw::WatchEntry e;
            e.swap_id = sid;
            e.kind    = k;
            e.txid_hex = txid;
            e.min_confirmations = min_conf;
            const auto r = pcw::Add(*wallet_sp, e);
            UniValue out{UniValue::VOBJ};
            out.pushKV("txid",             txid);
            out.pushKV("watch_kind",       pcw::WatchKindName(k));
            out.pushKV("watch_registered", r == pcw::StoreResult::Ok);
            return out;
        }
    };
}

// ─── Phase A — BTC/LTC holding wallet RPCs ─────────────────────

namespace pbh = ::wallet::pricoin_btc_holding;
namespace bhtlc = ::pricoin::swap::btc_htlc;

RPCMethod pricoin_btc_getaddress()
{
    return RPCMethod{
        "pricoin_btc_getaddress",
        "Holding wallet receive address for the requested foreign chain.\n"
        "Single address per chain, derived from the wallet's stealth seed\n"
        "via an HMAC chain — recoverable from the same backup as the rest\n"
        "of the wallet. Funds at this address are spendable via\n"
        "pricoin_btc_fund_swap (one-click swap funding) or\n"
        "pricoin_btc_sweep (move out).\n",
        {
            {"chain", RPCArg::Type::STR, RPCArg::Default{"btc"}, "btc | ltc"},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "Bech32(m) receive address"},
                {RPCResult::Type::STR_HEX, "xonly", "32-byte x-only pubkey (BTC P2TR program)"},
                {RPCResult::Type::STR, "chain", "Echo of chain name"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_btc_getaddress", "btc")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const std::string chain = request.params[0].isNull() ? "btc"
                : request.params[0].get_str();
            auto id = pbh::GetOrCreateIdentity(*wallet_sp, chain);
            if (!id) throw JSONRPCError(RPC_WALLET_ERROR,
                util::ErrorString(id).original);
            UniValue out{UniValue::VOBJ};
            out.pushKV("address", id->address);
            out.pushKV("xonly",   HexStr(id->xonly));
            out.pushKV("chain",   chain);
            return out;
        }
    };
}

RPCMethod pricoin_btc_getbalance()
{
    return RPCMethod{
        "pricoin_btc_getbalance",
        "Confirmed + unconfirmed balance for the holding-wallet address on\n"
        "the requested chain. Queries the configured ChainBackend\n"
        "(-btcwatchurl= / -ltcwatchurl=) — fails with a helpful message\n"
        "if no backend is registered for that chain.\n",
        {
            {"chain", RPCArg::Type::STR, RPCArg::Default{"btc"}, "btc | ltc"},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "confirmed_sat",   "Confirmed balance"},
                {RPCResult::Type::NUM, "unconfirmed_sat", "Mempool-only delta"},
                {RPCResult::Type::NUM, "utxo_count",      "Unspent output count"},
                {RPCResult::Type::STR, "address",         "The address that was queried"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_btc_getbalance", "btc")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const std::string chain = request.params[0].isNull() ? "btc"
                : request.params[0].get_str();
            auto bal = pbh::GetBalance(*wallet_sp, chain);
            if (!bal) throw JSONRPCError(RPC_WALLET_ERROR,
                util::ErrorString(bal).original);
            auto id = pbh::GetOrCreateIdentity(*wallet_sp, chain);
            UniValue out{UniValue::VOBJ};
            out.pushKV("confirmed_sat",   bal->confirmed_sat);
            out.pushKV("unconfirmed_sat", bal->unconfirmed_sat);
            out.pushKV("utxo_count",      bal->utxo_count);
            out.pushKV("address",         id ? id->address : std::string{});
            return out;
        }
    };
}

RPCMethod pricoin_btc_fund_swap()
{
    return RPCMethod{
        "pricoin_btc_fund_swap",
        "One-click BTC funding for an in-flight atomic swap. Reads the\n"
        "swap record's foreign_chain, resolves the 2-of-2 P2TR target by\n"
        "MuSig2 keyagg of (alice_pub, bob_pub), picks a single confirmed\n"
        "UTXO from the holding-wallet address ≥ (foreign_amount + fee),\n"
        "builds a 1-input, 2-output funding tx (target + change), signs\n"
        "with BIP341 key-path-spend, broadcasts via the foreign-chain\n"
        "backend, and auto-registers a foreign_funding swapwatch entry.\n",
        {
            {"swap_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"fee_sat", RPCArg::Type::NUM, RPCArg::Default{1000}, "Flat fee in sats"},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "Broadcast funding txid"},
                {RPCResult::Type::BOOL,    "watch_registered", "Whether swapwatch entry was stored"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_btc_fund_swap", "<swap_id> 1000")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;
            const uint256 sid = ParseChainWatchSwapId(request.params[0]);
            const int64_t fee_sat = request.params[1].isNull() ? 1000
                : request.params[1].getInt<int64_t>();

            aas::AdaptorSwap snap;
            if (aas::Get(wallet, sid, snap) != aas::LookupResult::Ok) {
                throw JSONRPCError(RPC_INVALID_REQUEST, "swap not found");
            }

            // Derive my swap-identity priv (used as the cooperative-
            // signing key for BTC and as the LTC-HTLC role-pubkey for
            // LTC). The HMAC chain matches pricoin_swap_session.
            CKey swap_priv;
            const auto& stealth_id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
            constexpr const char* kSwapTag = "pricoin/swap/identity-v1";
            for (uint8_t counter = 0; counter < 16; ++counter) {
                CHMAC_SHA256 hmac(UCharCast(stealth_id.spend.data()), 32);
                hmac.Write(reinterpret_cast<const unsigned char*>(kSwapTag),
                            std::strlen(kSwapTag));
                hmac.Write(&counter, 1);
                unsigned char raw[32];
                hmac.Finalize(raw);
                swap_priv.Set(raw, raw + 32, true);
                if (swap_priv.IsValid()) break;
            }
            if (!swap_priv.IsValid()) {
                throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "swap identity unavailable");
            }
            const CPubKey my_swap_pub = swap_priv.GetPubKey();
            const CPubKey peer_pub(snap.counterparty_pub);
            const bool i_am_alice = (snap.role == aas::Role::Alice);

            std::string txid;
            if (snap.foreign_chain == "ltc") {
                // ─── LTC HTLC funding (Bob only) ──────────────────
                if (i_am_alice) {
                    throw JSONRPCError(RPC_INVALID_REQUEST,
                        "LTC HTLC is funded by Bob (the LTC seller); "
                        "Alice does not fund LTC");
                }
                if (!snap.has_t) {
                    throw JSONRPCError(RPC_INVALID_REQUEST,
                        "Bob's t_secret not set; complete swap setup first");
                }
                if (!snap.adaptor_set) {
                    throw JSONRPCError(RPC_INVALID_REQUEST,
                        "adaptor materials (T_G) not set; complete swap setup first");
                }
                if (!snap.timelocks_set || snap.foreign_refund_height <= 0) {
                    throw JSONRPCError(RPC_INVALID_REQUEST,
                        "foreign refund timelock not set");
                }
                // Build the discrete-log-bound HTLC. alice_pub +
                // bob_pub are the two parties' swap-identity pubkeys
                // (already exchanged at swap creation via the
                // counterparty_pub field).
                const CPubKey alice_pub = peer_pub;       // Bob is local
                const CPubKey bob_pub   = my_swap_pub;
                CScript redeem;
                try {
                    redeem = bhtlc::BuildDLHTLCScript(
                        std::span<const unsigned char>(snap.T_G.data(), 33),
                        alice_pub, bob_pub,
                        snap.foreign_refund_height);
                } catch (const bhtlc::HTLCError& e) {
                    throw JSONRPCError(RPC_WALLET_ERROR,
                        std::string("HTLC script build failed: ") + e.what());
                }
                auto txid_or = pbh::BuildAndBroadcastHtlcFundingTx(
                    wallet, snap.foreign_chain, redeem,
                    snap.foreign_amount_sat, fee_sat);
                if (!txid_or) throw JSONRPCError(RPC_WALLET_ERROR,
                    util::ErrorString(txid_or).original);
                txid = *txid_or;
            } else {
                // ─── BTC P2TR cooperative funding (existing) ──────
                std::vector<CPubKey> pubs;
                pubs.push_back(i_am_alice ? my_swap_pub : peer_pub);
                pubs.push_back(i_am_alice ? peer_pub   : my_swap_pub);
                bma::KeyAggCache cache;
                auto agg = bma::AggregatePubkeys(pubs, cache);
                if (!agg) throw JSONRPCError(RPC_INTERNAL_ERROR, "MuSig2 keyagg failed");
                auto txid_or = pbh::BuildAndBroadcastFundingTx(
                    wallet, snap.foreign_chain, *agg,
                    snap.foreign_amount_sat, fee_sat);
                if (!txid_or) throw JSONRPCError(RPC_WALLET_ERROR,
                    util::ErrorString(txid_or).original);
                txid = *txid_or;
            }

            // Auto-register a foreign_funding watch on vout 0 (both
            // builders place the swap output at index 0).
            pcw::WatchEntry e;
            e.swap_id = sid;
            e.kind    = pcw::WatchKind::ForeignFunding;
            e.txid_hex = txid;
            e.vout = 0;
            e.min_confirmations = 1;
            const auto r = pcw::Add(wallet, e);
            UniValue out{UniValue::VOBJ};
            out.pushKV("txid", txid);
            out.pushKV("watch_registered", r == pcw::StoreResult::Ok);
            return out;
        }
    };
}

RPCMethod pricoin_btc_sweep()
{
    return RPCMethod{
        "pricoin_btc_sweep",
        "Sweep all UTXOs at the holding-wallet address to a single bech32(m)\n"
        "destination, paying `fee_sat`. One input per UTXO, one output to\n"
        "the destination. Use this to move BTC out of the holding wallet.\n",
        {
            {"chain",      RPCArg::Type::STR,     RPCArg::Default{"btc"}, "btc | ltc"},
            {"dest",       RPCArg::Type::STR,     RPCArg::Optional::NO, "Destination bech32(m) address"},
            {"fee_sat",    RPCArg::Type::NUM,     RPCArg::Default{1000}, "Flat fee in sats"},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "txid", "Broadcast txid"}}
        },
        RPCExamples{HelpExampleCli("pricoin_btc_sweep", "btc bc1q... 1000")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const std::string chain = request.params[0].isNull() ? "btc"
                : request.params[0].get_str();
            const std::string dest = request.params[1].get_str();
            const int64_t fee_sat = request.params[2].isNull() ? 1000
                : request.params[2].getInt<int64_t>();
            auto txid_or = pbh::BuildAndBroadcastSweepTx(
                *wallet_sp, chain, dest, fee_sat);
            if (!txid_or) throw JSONRPCError(RPC_WALLET_ERROR,
                util::ErrorString(txid_or).original);
            UniValue out{UniValue::VOBJ};
            out.pushKV("txid", *txid_or);
            return out;
        }
    };
}

// ─── LTC HTLC claim / refund ────────────────────────────────────
//
// These RPCs spend the LTC HTLC funded by `pricoin_btc_fund_swap`.
//   * Claim: Alice extracts t from the PRIC chain (set in the swap
//     record's `t_secret` field by the swapwatch), then signs the
//     LTC claim tx twice — once under her swap-identity priv and
//     once with t (acting as the privkey for T_G). Bob's funded
//     HTLC has been waiting on this exact reveal.
//   * Refund: Bob waits until current LTC chain height ≥
//     `foreign_refund_height`, then unilaterally signs the refund
//     branch (sender_pub OP_CHECKSIG with nLockTime = timeout).
namespace {

// Common helper — reconstruct the local party's swap-identity priv
// + the HTLC redeem script for a given swap. Throws JSONRPCError on
// any inconsistency. Sets `is_alice` to the local role.
struct LtcSwapContext {
    aas::AdaptorSwap snap;
    CKey  swap_priv;
    CPubKey alice_pub;     // recipient pubkey in HTLC IF branch
    CPubKey bob_pub;       // sender pubkey in HTLC ELSE branch
    CScript redeem;
    bool i_am_alice{false};
};

LtcSwapContext PrepareLtcSwapContext(::wallet::CWallet& wallet, const uint256& sid)
{
    LtcSwapContext ctx;
    if (aas::Get(wallet, sid, ctx.snap) != aas::LookupResult::Ok) {
        throw JSONRPCError(RPC_INVALID_REQUEST, "swap not found");
    }
    if (ctx.snap.foreign_chain != "ltc") {
        throw JSONRPCError(RPC_INVALID_REQUEST,
            "swap.foreign_chain != ltc");
    }
    if (!ctx.snap.adaptor_set) {
        throw JSONRPCError(RPC_INVALID_REQUEST,
            "adaptor materials (T_G) not set on swap");
    }
    if (!ctx.snap.timelocks_set || ctx.snap.foreign_refund_height <= 0) {
        throw JSONRPCError(RPC_INVALID_REQUEST,
            "foreign refund timelock not set on swap");
    }
    if (ctx.snap.foreign_funding_txid.empty() || ctx.snap.foreign_funding_vout < 0) {
        throw JSONRPCError(RPC_INVALID_REQUEST,
            "swap has no recorded LTC HTLC funding outpoint");
    }
    // Derive my swap-identity priv. Same HMAC chain as fund_swap.
    const auto& stealth_id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
    constexpr const char* kSwapTag = "pricoin/swap/identity-v1";
    for (uint8_t counter = 0; counter < 16; ++counter) {
        CHMAC_SHA256 hmac(UCharCast(stealth_id.spend.data()), 32);
        hmac.Write(reinterpret_cast<const unsigned char*>(kSwapTag),
                    std::strlen(kSwapTag));
        hmac.Write(&counter, 1);
        unsigned char raw[32];
        hmac.Finalize(raw);
        ctx.swap_priv.Set(raw, raw + 32, true);
        if (ctx.swap_priv.IsValid()) break;
    }
    if (!ctx.swap_priv.IsValid()) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "swap identity unavailable");
    }
    const CPubKey my_pub  = ctx.swap_priv.GetPubKey();
    const CPubKey peer_pub(ctx.snap.counterparty_pub);
    ctx.i_am_alice = (ctx.snap.role == aas::Role::Alice);
    ctx.alice_pub = ctx.i_am_alice ? my_pub  : peer_pub;
    ctx.bob_pub   = ctx.i_am_alice ? peer_pub : my_pub;
    try {
        ctx.redeem = bhtlc::BuildDLHTLCScript(
            std::span<const unsigned char>(ctx.snap.T_G.data(), 33),
            ctx.alice_pub, ctx.bob_pub,
            ctx.snap.foreign_refund_height);
    } catch (const bhtlc::HTLCError& e) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            std::string("HTLC script reconstruct failed: ") + e.what());
    }
    return ctx;
}

CScript ResolveLtcDestSPK(const std::string& dest_addr)
{
    int v = -1;
    std::vector<unsigned char> prog;
    // LTC mainnet HRP. Testnet/regtest support is straightforward
    // to add when the chain backend lands.
    if (!pbh::DecodeWitnessAddress(dest_addr, "ltc", v, prog)) {
        throw JSONRPCError(RPC_INVALID_REQUEST,
            "dest is not a valid LTC bech32(m) address");
    }
    return pbh::MakeWitnessSPK(v, prog);
}

} // namespace

RPCMethod pricoin_ltc_claim_swap()
{
    return RPCMethod{
        "pricoin_ltc_claim_swap",
        "Alice's LTC-claim path: spends the LTC HTLC funded by Bob using\n"
        "the adaptor scalar t (typically obtained from\n"
        "pricoin_swapwatch_extract_pric_t after Bob's PRIC claim confirms).\n"
        "Signs the claim tx twice — once under Alice's swap-identity priv,\n"
        "and once with t (the privkey for T_G). The HTLC redeem script is\n"
        "reconstructed from the swap record (T_G + alice_pub + bob_pub +\n"
        "timelock).\n"
        "\n"
        "Requires: swap.role == Alice, swap.foreign_chain == ltc,\n"
        "swap.foreign_funding_txid populated. The supplied t MUST satisfy\n"
        "t·G == swap.T_G (we verify before signing).\n",
        {
            {"swap_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"t_hex",   RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "32-byte adaptor scalar t — typically from pricoin_swapwatch_extract_pric_t. "
                "If swap.has_t (Bob's wallet on regtest tests), may be empty to use stored t."},
            {"dest",    RPCArg::Type::STR,     RPCArg::Optional::NO,
                "LTC bech32 destination address (where Alice receives the LTC)"},
            {"fee_sat", RPCArg::Type::NUM,     RPCArg::Default{1000}, "Flat fee in sats"},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "txid", "Broadcast LTC claim txid"}}
        },
        RPCExamples{HelpExampleCli("pricoin_ltc_claim_swap", "<swap_id> <t_hex> ltc1q... 1000")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;
            const uint256 sid = ParseChainWatchSwapId(request.params[0]);
            const std::string t_hex = request.params[1].isNull() ? std::string{}
                : request.params[1].get_str();
            const std::string dest = request.params[2].get_str();
            const int64_t fee_sat = request.params[3].isNull() ? 1000
                : request.params[3].getInt<int64_t>();

            auto ctx = PrepareLtcSwapContext(wallet, sid);
            if (!ctx.i_am_alice) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "LTC HTLC claim is performed by Alice (the LTC buyer)");
            }
            // Resolve t: caller-supplied hex first, fallback to stored
            // t_secret if has_t (only set on Bob's wallet during normal
            // flow; useful for regtest where one wallet drives both).
            std::array<unsigned char, 32> t_bytes{};
            if (!t_hex.empty()) {
                auto parsed = TryParseHex<unsigned char>(t_hex);
                if (!parsed || parsed->size() != 32) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "t_hex must be 32-byte hex");
                }
                std::copy(parsed->begin(), parsed->end(), t_bytes.begin());
            } else if (ctx.snap.has_t) {
                t_bytes = ctx.snap.t_secret;
            } else {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "supply t_hex (run pricoin_swapwatch_extract_pric_t first)");
            }
            // Sanity: t·G must equal T_G — fail-fast before broadcast.
            {
                CKey k;
                k.Set(t_bytes.begin(), t_bytes.end(), /*fCompressedIn=*/true);
                if (!k.IsValid()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "t is not a valid secp256k1 scalar");
                }
                const CPubKey p = k.GetPubKey();
                if (p.size() != 33
                    || std::memcmp(p.data(), ctx.snap.T_G.data(), 33) != 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "t·G != swap.T_G — wrong scalar");
                }
            }

            const CScript dest_spk = ResolveLtcDestSPK(dest);

            bhtlc::HTLCFunding f;
            auto ftxid = uint256::FromHex(ctx.snap.foreign_funding_txid);
            if (!ftxid) throw JSONRPCError(RPC_INTERNAL_ERROR,
                "swap.foreign_funding_txid unparseable");
            f.prev_txid     = *ftxid;
            f.prev_vout     = static_cast<uint32_t>(ctx.snap.foreign_funding_vout);
            f.prev_value    = ctx.snap.foreign_amount_sat;
            f.redeem_script = ctx.redeem;

            std::vector<unsigned char> tx_bytes;
            try {
                tx_bytes = bhtlc::BuildDLClaimTx(
                    f,
                    std::span<const unsigned char>(t_bytes.data(), 32),
                    ctx.swap_priv, dest_spk, fee_sat);
            } catch (const bhtlc::HTLCError& e) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    std::string("HTLC claim build failed: ") + e.what());
            }

            auto backend = pcw::MakeForeignClientFromRegistry("ltc");
            if (!backend) throw JSONRPCError(RPC_INTERNAL_ERROR,
                "no LTC chain backend registered");
            const std::string tx_hex = HexStr(tx_bytes);
            std::string txid;
            try {
                txid = backend->Broadcast(tx_hex);
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    std::string("LTC broadcast failed: ") + e.what());
            }
            // Register a foreign_claim watch so the swapwatch advances
            // the swap to Complete when the claim confirms.
            pcw::WatchEntry e;
            e.swap_id = sid;
            e.kind = pcw::WatchKind::ForeignClaim;
            e.txid_hex = txid;
            e.vout = 0;
            e.min_confirmations = 1;
            const auto wr = pcw::Add(wallet, e);
            UniValue out{UniValue::VOBJ};
            out.pushKV("txid", txid);
            out.pushKV("watch_registered", wr == pcw::StoreResult::Ok);
            return out;
        }
    };
}

RPCMethod pricoin_ltc_refund_swap()
{
    return RPCMethod{
        "pricoin_ltc_refund_swap",
        "Bob's LTC-refund path: unilaterally spends the LTC HTLC's refund\n"
        "branch after the timelock expires. Sets nLockTime = timelock and\n"
        "nSequence = 0xfffffffd; signs under Bob's swap-identity priv.\n"
        "Caller is responsible for not broadcasting before the LTC chain\n"
        "tip reaches `foreign_refund_height` (the network will reject\n"
        "earlier, so a misbroadcast is harmless but pointless).\n",
        {
            {"swap_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"dest",    RPCArg::Type::STR,     RPCArg::Optional::NO,
                "LTC bech32 destination address (where Bob receives the refunded LTC)"},
            {"fee_sat", RPCArg::Type::NUM,     RPCArg::Default{1000}, "Flat fee in sats"},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "txid", "Broadcast LTC refund txid"}}
        },
        RPCExamples{HelpExampleCli("pricoin_ltc_refund_swap", "<swap_id> ltc1q... 1000")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;
            const uint256 sid = ParseChainWatchSwapId(request.params[0]);
            const std::string dest = request.params[1].get_str();
            const int64_t fee_sat = request.params[2].isNull() ? 1000
                : request.params[2].getInt<int64_t>();

            auto ctx = PrepareLtcSwapContext(wallet, sid);
            if (ctx.i_am_alice) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "LTC HTLC refund is performed by Bob (the LTC seller)");
            }

            const CScript dest_spk = ResolveLtcDestSPK(dest);

            bhtlc::HTLCFunding f;
            auto ftxid = uint256::FromHex(ctx.snap.foreign_funding_txid);
            if (!ftxid) throw JSONRPCError(RPC_INTERNAL_ERROR,
                "swap.foreign_funding_txid unparseable");
            f.prev_txid     = *ftxid;
            f.prev_vout     = static_cast<uint32_t>(ctx.snap.foreign_funding_vout);
            f.prev_value    = ctx.snap.foreign_amount_sat;
            f.redeem_script = ctx.redeem;

            std::vector<unsigned char> tx_bytes;
            try {
                tx_bytes = bhtlc::BuildRefundTx(
                    f, ctx.snap.foreign_refund_height,
                    ctx.swap_priv, dest_spk, fee_sat);
            } catch (const bhtlc::HTLCError& e) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    std::string("HTLC refund build failed: ") + e.what());
            }

            auto backend = pcw::MakeForeignClientFromRegistry("ltc");
            if (!backend) throw JSONRPCError(RPC_INTERNAL_ERROR,
                "no LTC chain backend registered");
            const std::string tx_hex = HexStr(tx_bytes);
            std::string txid;
            try {
                txid = backend->Broadcast(tx_hex);
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    std::string("LTC broadcast failed: ") + e.what());
            }
            // Register a foreign_refund watch so the swapwatch
            // advances the swap to Refunded when this confirms.
            pcw::WatchEntry e;
            e.swap_id = sid;
            e.kind = pcw::WatchKind::ForeignRefund;
            e.txid_hex = txid;
            e.vout = 0;
            e.min_confirmations = 1;
            const auto wr = pcw::Add(wallet, e);
            UniValue out{UniValue::VOBJ};
            out.pushKV("txid", txid);
            out.pushKV("watch_registered", wr == pcw::StoreResult::Ok);
            return out;
        }
    };
}

RPCMethod pricoin_swapwatch_adapt_pric_claim()
{
    return RPCMethod{
        "pricoin_swapwatch_adapt_pric_claim",
        "Bob's PRIC-claim path: adapt the PRIC adaptor pre-signature with the\n"
        "wallet's stored t_secret, inject the resulting CLSAG signature into a\n"
        "pre-built v4 spend tx skeleton, broadcast it via the local pricoin\n"
        "mempool, and register a swapwatch entry that auto-advances the swap\n"
        "to PricClaimed when confirmed.\n"
        "\n"
        "Caller supplies `tx_hex` — the unsigned skeleton from\n"
        "pricoin_jointspend_buildtx that was used at adapt-round-1 time. The\n"
        "ring decoys and z_self/z_other are baked into that skeleton's\n"
        "ct_bundle.ring_inputs[0].ring_outpoints, so a fresh buildtx call\n"
        "would produce a different ring and the pre-sig wouldn't apply. The\n"
        "wallet's coopsign dialog stashes this hex; Bob copies it for this\n"
        "RPC.\n"
        "\n"
        "Requires: swap.role == Bob, swap.has_t == true (Bob's t_secret on\n"
        "record), swap.presigs.pric_claim_presig_blob populated.\n",
        {
            {"swap_id",            RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"tx_hex",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Skeleton tx hex from pricoin_jointspend_buildtx (Bob's coopsign session)"},
            {"ring",               RPCArg::Type::ARR,     RPCArg::Optional::NO,
                "Multi-layer ring [{P,W}, ...] from pricoin_jointspend_buildtx's "
                "ring_ml output. Both P (one-time pubkey) and W (commitment "
                "delta) are required so AdaptML can verify the resulting sig "
                "under pricoin::ringsig::VerifyMultiLayer (what consensus uses). "
                "For backward compat, an array of P-only hex strings is also "
                "accepted but the broadcast will fail consensus validation.",
                {{"member", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                  {{"P", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
                   {"W", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""}}}}},
            {"msg_hex",            RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "32-byte sighash from pricoin_jointspend_buildtx — must match what was signed"},
            {"min_confirmations",  RPCArg::Type::NUM,     RPCArg::Default{1}, ""},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "Broadcast txid"},
                {RPCResult::Type::NUM,     "size", "Final tx size with witness/sig"},
                {RPCResult::Type::STR_HEX, "sig",  "Final CLSAG signature blob produced by Adapt"},
                {RPCResult::Type::BOOL,    "watch_registered", "True iff swapwatch entry was stored"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_swapwatch_adapt_pric_claim",
            "<swap_id> <tx_hex> '[\"<P0>\",\"<P1>\"]' <msg_hex>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;

            const uint256 sid = ParseChainWatchSwapId(request.params[0]);
            const std::string tx_hex = request.params[1].get_str();
            const UniValue& ring_arr = request.params[2];
            const std::string msg_hex = request.params[3].get_str();
            const int32_t min_conf = request.params[4].isNull() ? 1
                : request.params[4].getInt<int32_t>();

            // Parse ring. Accepts either multi-layer ([{P,W},...]) — the
            // recommended/working format — or legacy single-layer
            // ([P,...]). Single-layer adapt will produce a sig that
            // fails consensus VerifyMultiLayer; broadcasting will
            // hit `bad-pct-ring-sig-invalid`. Hence the ML format is
            // what callers should provide post-2026-05-12.
            if (!ring_arr.isArray() || ring_arr.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "ring must be a non-empty array");
            }
            const bool ring_is_ml = ring_arr[0].isObject();
            std::vector<::pricoin::ringsig::Point> ring;             // P-only view for legacy Adapt path
            std::vector<::pricoin::ringsig::MultiLayerMember> ring_ml;  // {P,W} view for AdaptML
            ring.reserve(ring_arr.size());
            ring_ml.reserve(ring_arr.size());
            for (size_t i = 0; i < ring_arr.size(); ++i) {
                const UniValue& entry = ring_arr[i];
                ::pricoin::ringsig::Point P{};
                if (ring_is_ml) {
                    if (!entry.isObject() || !entry.exists("P") || !entry.exists("W")) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("ring[%u] must be {P,W} object",
                                static_cast<unsigned>(i)));
                    }
                    auto pb = TryParseHex<unsigned char>(entry["P"].get_str());
                    auto wb = TryParseHex<unsigned char>(entry["W"].get_str());
                    if (!pb || pb->size() != 33 || !wb || wb->size() != 33) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("ring[%u] P/W must be 33-byte hex",
                                static_cast<unsigned>(i)));
                    }
                    ::pricoin::ringsig::MultiLayerMember m;
                    std::copy(pb->begin(), pb->end(), m.P.begin());
                    std::copy(wb->begin(), wb->end(), m.W.begin());
                    ring_ml.push_back(m);
                    std::copy(pb->begin(), pb->end(), P.begin());
                } else {
                    auto pb = TryParseHex<unsigned char>(entry.get_str());
                    if (!pb || pb->size() != 33) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            strprintf("ring[%u] must be 33-byte hex (or {P,W} object)",
                                static_cast<unsigned>(i)));
                    }
                    std::copy(pb->begin(), pb->end(), P.begin());
                }
                ring.push_back(P);
            }
            // CRITICAL: parse msg_hex as raw bytes (direct copy), NOT
            // via uint256::FromHex (which reverses byte order). The
            // ceremony's pricoin_jointspend_adaptor_combine uses the
            // raw-bytes convention (src/rpc/pricoin_ct.cpp via
            // ParseScalar32 + std::copy). Adapt's CLSAG verify must
            // see the SAME uint256 msg value the presig was computed
            // against, else verification fails with "ring/msg
            // mismatch". (Fixed 2026-05-12 — root cause of
            // "Adapt failed" on the first PreSigned-stage test.)
            auto msg_bytes = TryParseHex<unsigned char>(msg_hex);
            if (!msg_bytes || msg_bytes->size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "msg_hex must be 32-byte hex");
            }
            uint256 msg;
            std::copy(msg_bytes->begin(), msg_bytes->end(), msg.begin());

            // Load + validate.
            ::wallet::pricoin_adaptor_swap::AdaptorSwap snap;
            if (::wallet::pricoin_adaptor_swap::Get(wallet, sid, snap)
                != ::wallet::pricoin_adaptor_swap::LookupResult::Ok) {
                throw JSONRPCError(RPC_INVALID_REQUEST, "swap not found");
            }
            if (snap.role != ::wallet::pricoin_adaptor_swap::Role::Bob) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "adapt_pric_claim requires Bob role (only Bob holds t_secret)");
            }
            if (!snap.has_t) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "swap has no t_secret on record (already wiped or never set)");
            }
            if (snap.presigs.pric_claim_presig_blob.empty()) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "swap has no pric_claim_presig_blob — set_pre_signed not run?");
            }

            // Parse the pre-sig blob from the swap record.
            DataStream presig_ds{std::span<const unsigned char>{
                snap.presigs.pric_claim_presig_blob}};
            ::pricoin::adaptor_ringsig::AdaptorPreSignature presig;
            try { presig_ds >> presig; }
            catch (const std::exception&) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "stored pric_claim_presig_blob did not parse as AdaptorPreSignature");
            }

            // Adapt: presig + t + ring + msg → final CLSAG signature.
            // For multi-layer rings (the format produced by the
            // adaptor-ML protocol path) we route through AdaptML so
            // the post-adapt verify uses VerifyMultiLayer — the same
            // routine consensus runs at chain-validate time. The
            // single-layer Adapt branch survives for legacy callers
            // but produces a sig with zero commitment_image that will
            // fail consensus.
            ::pricoin::ringsig::Scalar t_scalar;
            std::copy(snap.t_secret.begin(), snap.t_secret.end(), t_scalar.begin());
            std::optional<::pricoin::ringsig::Signature> final_sig_opt;
            if (ring_is_ml) {
                final_sig_opt = ::pricoin::adaptor_ringsig::AdaptML(
                    presig, t_scalar,
                    std::span<const ::pricoin::ringsig::MultiLayerMember>{ring_ml},
                    msg);
            } else {
                final_sig_opt = ::pricoin::adaptor_ringsig::Adapt(
                    presig, t_scalar,
                    std::span<const ::pricoin::ringsig::Point>{ring}, msg);
            }
            if (!final_sig_opt) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "Adapt failed (t did not match T_G/T_H or pre-sig malformed or ring/msg mismatch)");
            }

            // Decode the skeleton, inject the sig.
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, tx_hex, /*try_no_witness=*/true, /*try_witness=*/true)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "tx hex failed to decode");
            }
            if (mtx.version != PRICOIN_CT_VERSION) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "tx is not a v4 confidential tx");
            }
            if (mtx.ct_bundle.ring_inputs.size() != 1) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "expected exactly one ring input (joint-spend convention)");
            }
            mtx.ct_bundle.ring_inputs[0].sig = *final_sig_opt;

            // Broadcast.
            CTransactionRef tx_ref = MakeTransactionRef(std::move(mtx));
            std::string err_str;
            if (!wallet.chain().broadcastTransaction(
                    tx_ref, MAX_MONEY,
                    node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL,
                    err_str)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "broadcast failed: " + err_str);
            }
            const std::string txid_hex = tx_ref->GetHash().ToString();

            // Register watch.
            pcw::WatchEntry e;
            e.swap_id = sid;
            e.kind    = pcw::WatchKind::PricClaim;
            e.txid_hex = txid_hex;
            e.min_confirmations = min_conf;
            const auto r = pcw::Add(wallet, e);

            // Serialize the final sig for the result so the caller can
            // share it / inspect it.
            DataStream sig_ds;
            sig_ds << *final_sig_opt;

            UniValue out{UniValue::VOBJ};
            out.pushKV("txid", txid_hex);
            out.pushKV("size", (int)::GetSerializeSize(TX_WITH_WITNESS(*tx_ref)));
            out.pushKV("sig",  HexStr(std::span<const unsigned char>{
                UCharCast(sig_ds.data()), sig_ds.size()}));
            out.pushKV("watch_registered", r == pcw::StoreResult::Ok);
            return out;
        }
    };
}

RPCMethod pricoin_swapwatch_verify_pric_claim()
{
    return RPCMethod{
        "pricoin_swapwatch_verify_pric_claim",
        "Pre-funding safety gate (Bob): verify the stored PRIC-claim adaptor\n"
        "pre-signature actually adapts — with the wallet's t_secret, over the\n"
        "canonical {P,W} ring + msg on the swap record — into a signature that\n"
        "passes consensus VerifyMultiLayer. Does NOT broadcast or mutate any\n"
        "state. Returns {valid:false, reason} instead of throwing on a bad\n"
        "pre-sig so callers can branch.\n"
        "\n"
        "Why this exists: a cooperative pre-sign ceremony that desynced the two\n"
        "parties' round-1 nonces produces a pre-sig that assembles cleanly but\n"
        "can NEVER close VerifyMultiLayer. AdaptML only checks t·G==T_G, so the\n"
        "defect stays invisible until claim time — AFTER both legs are funded\n"
        "(silent fund-lock). Bob calls this before funding the foreign chain\n"
        "and refuses to fund when valid=false.\n",
        {
            {"swap_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "valid",  "True iff the pre-sig adapts to a VerifyMultiLayer-valid sig"},
                {RPCResult::Type::STR,  "reason", "Human-readable explanation when valid=false"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_swapwatch_verify_pric_claim", "<swap_id>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;
            const uint256 sid = ParseChainWatchSwapId(request.params[0]);

            auto invalid = [](const std::string& why) {
                UniValue o{UniValue::VOBJ};
                o.pushKV("valid", false);
                o.pushKV("reason", why);
                return o;
            };

            ::wallet::pricoin_adaptor_swap::AdaptorSwap snap;
            if (::wallet::pricoin_adaptor_swap::Get(wallet, sid, snap)
                != ::wallet::pricoin_adaptor_swap::LookupResult::Ok) {
                throw JSONRPCError(RPC_INVALID_REQUEST, "swap not found");
            }
            if (snap.role != ::wallet::pricoin_adaptor_swap::Role::Bob) {
                // Only the t-holder can verify by adapting. Not a hard
                // error — Alice's side simply can't run this gate.
                return invalid("not Bob (no t_secret to adapt with)");
            }
            if (!snap.has_t)                                 return invalid("no t_secret on record");
            if (snap.presigs.pric_claim_presig_blob.empty()) return invalid("no pric_claim_presig_blob (set_pre_signed not run?)");
            if (snap.pric_claim_ring.empty())                return invalid("canonical pric_claim_ring not populated");
            if (snap.pric_claim_ring_w.size() != snap.pric_claim_ring.size())
                return invalid("pric_claim_ring_w missing/length-mismatched — need {P,W} for VerifyMultiLayer");
            if (snap.pric_claim_msg_hex.size() != 64)        return invalid("canonical pric_claim_msg_hex is not 32-byte hex");

            // Build the multi-layer ring from the canonical record fields —
            // the SAME ones autoAdaptPricClaim feeds the adapt RPC.
            std::vector<::pricoin::ringsig::MultiLayerMember> ring_ml;
            ring_ml.reserve(snap.pric_claim_ring.size());
            for (size_t i = 0; i < snap.pric_claim_ring.size(); ++i) {
                ::pricoin::ringsig::MultiLayerMember m;
                std::copy(snap.pric_claim_ring[i].begin(),   snap.pric_claim_ring[i].end(),   m.P.begin());
                std::copy(snap.pric_claim_ring_w[i].begin(), snap.pric_claim_ring_w[i].end(), m.W.begin());
                ring_ml.push_back(m);
            }

            // msg: raw-bytes copy (NOT uint256::FromHex, which reverses) —
            // same convention as the adapt RPC and the ceremony combine.
            auto msg_bytes = TryParseHex<unsigned char>(snap.pric_claim_msg_hex);
            if (!msg_bytes || msg_bytes->size() != 32) return invalid("pric_claim_msg_hex failed to parse as 32 bytes");
            uint256 msg;
            std::copy(msg_bytes->begin(), msg_bytes->end(), msg.begin());

            DataStream presig_ds{std::span<const unsigned char>{snap.presigs.pric_claim_presig_blob}};
            ::pricoin::adaptor_ringsig::AdaptorPreSignature presig;
            try { presig_ds >> presig; }
            catch (const std::exception&) { return invalid("pric_claim_presig_blob did not parse as AdaptorPreSignature"); }

            ::pricoin::ringsig::Scalar t_scalar;
            std::copy(snap.t_secret.begin(), snap.t_secret.end(), t_scalar.begin());

            // Dry-run adapt. AdaptML internally runs VerifyMultiLayer and
            // returns nullopt on any failure (wrong t, degenerate s_pi, or
            // ring/msg/nonce desync). No broadcast, no state mutation.
            auto sig = ::pricoin::adaptor_ringsig::AdaptML(
                presig, t_scalar,
                std::span<const ::pricoin::ringsig::MultiLayerMember>{ring_ml},
                msg);
            if (!sig) {
                return invalid("AdaptML failed — pre-sig does not adapt to a "
                               "VerifyMultiLayer-valid signature (round-1 nonce/"
                               "challenge desync, or wrong t). DO NOT FUND.");
            }

            UniValue out{UniValue::VOBJ};
            out.pushKV("valid", true);
            out.pushKV("reason", "");
            return out;
        }
    };
}

RPCMethod pricoin_swap_recover_refund_singlesig()
{
    return RPCMethod{
        "pricoin_swap_recover_refund_singlesig",
        "RECOVERY: sign and broadcast the PRIC timelock refund for a stuck\n"
        "swap using a SINGLE-PARTY reconstruction of the joint spend key,\n"
        "bypassing the cooperative ceremony entirely.\n"
        "\n"
        "Use this only when the stored cooperative refund signature is invalid\n"
        "(autorefund logs 'bad-pct-ring-sig-invalid') AND you control BOTH\n"
        "sides of the swap. It combines this wallet's joint-output key shares\n"
        "(x_share, z_share, read from the swap's refund coopsign session) with\n"
        "the peer's shares (passed as args) to recover the full joint secret\n"
        "x = x_local + x_peer, z = z_local + z_peer, then signs the persisted\n"
        "refund tx with the reference single-party multi-layer signer. The\n"
        "signer verifies x·G == P_pi and z·G == W_pi, so wrong shares fail\n"
        "loudly rather than producing another bad signature.\n"
        "\n"
        "SECURITY: combining both spend-key shares on one machine collapses\n"
        "the 2-of-2 — only do this to recover a swap you own both legs of.\n",
        {
            {"swap_id",      RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"peer_x_share", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Peer's 32-byte x (spend) share for the joint output — from the "
                "peer wallet's refund coopsign session (x_share field)"},
            {"peer_z_share", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Peer's 32-byte z (commitment) share for the REFUND leg — from "
                "the peer wallet's refund coopsign session (z_share field)"},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "Broadcast refund txid"},
                {RPCResult::Type::STR_HEX, "sig",  "Freshly-signed CLSAG blob injected into the refund tx"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_swap_recover_refund_singlesig",
            "<swap_id> <peer_x_share> <peer_z_share>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;
            const uint256 sid = ParseChainWatchSwapId(request.params[0]);

            ::wallet::pricoin_adaptor_swap::AdaptorSwap snap;
            if (::wallet::pricoin_adaptor_swap::Get(wallet, sid, snap)
                != ::wallet::pricoin_adaptor_swap::LookupResult::Ok) {
                throw JSONRPCError(RPC_INVALID_REQUEST, "swap not found");
            }
            if (!snap.pric_refund_txid.IsNull()) {
                throw JSONRPCError(RPC_INVALID_REQUEST, "swap already has a pric_refund_txid");
            }
            if (snap.pric_refund_unsigned_tx_hex.empty()) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "no unsigned PRIC refund tx on record (buildtx never ran on this wallet)");
            }
            if (snap.pric_refund_session_json.empty()) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "no refund coopsign session on record — cannot recover local key shares");
            }

            // Pull ring_ml / msg / pi / local shares from the refund session.
            UniValue sess;
            if (!sess.read(snap.pric_refund_session_json) || !sess.isObject()) {
                throw JSONRPCError(RPC_INVALID_REQUEST, "refund session JSON unparseable");
            }
            auto sess_str = [&](const char* k) -> std::string {
                return sess.exists(k) && sess[k].isStr() ? sess[k].get_str() : std::string{};
            };
            std::string ring_str = sess_str("ring_ml_json");
            if (ring_str.empty()) ring_str = sess_str("in_ring_or_ring_ml");
            const std::string msg_hex = sess_str("msg_hex");
            const std::string pi_str  = sess_str("pi");
            const std::string x_local = sess_str("x_share");
            const std::string z_local = sess_str("z_share");
            if (ring_str.empty() || msg_hex.size() != 64 || pi_str.empty()
                || x_local.size() != 64 || z_local.size() != 64) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "refund session missing ring_ml_json / msg_hex / pi / x_share / z_share");
            }
            const size_t pi = static_cast<size_t>(std::atoi(pi_str.c_str()));

            UniValue ring_arr;
            if (!ring_arr.read(ring_str) || !ring_arr.isArray() || ring_arr.empty()) {
                throw JSONRPCError(RPC_INVALID_REQUEST, "ring_ml_json is not a non-empty array");
            }
            std::vector<::pricoin::ringsig::MultiLayerMember> ring_ml;
            ring_ml.reserve(ring_arr.size());
            for (size_t i = 0; i < ring_arr.size(); ++i) {
                const UniValue& e = ring_arr[i];
                if (!e.isObject() || !e.exists("P") || !e.exists("W")) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("ring[%u] must be {P,W}", (unsigned)i));
                }
                auto pb = TryParseHex<unsigned char>(e["P"].get_str());
                auto wb = TryParseHex<unsigned char>(e["W"].get_str());
                if (!pb || pb->size() != 33 || !wb || wb->size() != 33) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("ring[%u] P/W must be 33-byte hex", (unsigned)i));
                }
                ::pricoin::ringsig::MultiLayerMember m;
                std::copy(pb->begin(), pb->end(), m.P.begin());
                std::copy(wb->begin(), wb->end(), m.W.begin());
                ring_ml.push_back(m);
            }
            if (pi >= ring_ml.size()) {
                throw JSONRPCError(RPC_INVALID_REQUEST, "pi out of range for ring");
            }

            // msg: raw-bytes copy (matches the ceremony / adapt convention).
            auto msg_bytes = TryParseHex<unsigned char>(msg_hex);
            if (!msg_bytes || msg_bytes->size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "msg_hex must be 32-byte hex");
            }
            uint256 msg;
            std::copy(msg_bytes->begin(), msg_bytes->end(), msg.begin());

            // Parse the four shares into scalars.
            auto to_scalar = [](const std::string& h, const char* what) {
                auto b = TryParseHex<unsigned char>(h);
                if (!b || b->size() != 32) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        std::string(what) + " must be 32-byte hex");
                }
                ::pricoin::ringsig::Scalar s;
                std::copy(b->begin(), b->end(), s.begin());
                return s;
            };
            const auto xl = to_scalar(x_local, "local x_share");
            const auto zl = to_scalar(z_local, "local z_share");
            const auto xp = to_scalar(request.params[1].get_str(), "peer_x_share");
            const auto zp = to_scalar(request.params[2].get_str(), "peer_z_share");

            // Reconstruct the full joint secrets.
            auto x_full = ::pricoin::ringsig::AddScalars(xl, xp);
            auto z_full = ::pricoin::ringsig::AddScalars(zl, zp);
            if (!x_full || !z_full) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "share addition produced an invalid scalar (zero/overflow)");
            }

            // Reference single-party signer. Verifies x·G==P_pi and z·G==W_pi
            // internally, so mismatched peer shares fail here, not on-chain.
            auto sig = ::pricoin::ringsig::SignMultiLayer(
                std::span<const ::pricoin::ringsig::MultiLayerMember>{ring_ml},
                pi, *x_full, *z_full, msg);
            if (!sig) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "SignMultiLayer failed — reconstructed x·G != P_pi or z·G != W_pi. "
                    "Check that the peer shares are the REFUND-leg x_share/z_share "
                    "from the OTHER wallet's swap record.");
            }
            // Belt-and-suspenders: the same check consensus will run.
            if (!::pricoin::ringsig::VerifyMultiLayer(
                    std::span<const ::pricoin::ringsig::MultiLayerMember>{ring_ml}, *sig, msg)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "recovered signature failed VerifyMultiLayer — not broadcasting");
            }

            // Inject into the persisted refund tx and broadcast.
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, snap.pric_refund_unsigned_tx_hex,
                             /*try_no_witness=*/true, /*try_witness=*/true)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "stored refund tx hex failed to decode");
            }
            if (mtx.version != PRICOIN_CT_VERSION) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "stored refund tx is not a v4 confidential tx");
            }
            if (mtx.ct_bundle.ring_inputs.size() != 1) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "refund tx must have exactly one ring input");
            }
            mtx.ct_bundle.ring_inputs[0].sig = *sig;

            CTransactionRef tx_ref = MakeTransactionRef(std::move(mtx));
            std::string err_str;
            if (!wallet.chain().broadcastTransaction(
                    tx_ref, MAX_MONEY,
                    node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL, err_str)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "broadcast failed: " + err_str);
            }
            const std::string txid_hex = tx_ref->GetHash().ToString();

            pcw::WatchEntry we;
            we.swap_id = sid;
            we.kind    = pcw::WatchKind::PricRefund;
            we.txid_hex = txid_hex;
            we.vout    = -1;
            we.min_confirmations = 1;
            (void)pcw::Add(wallet, we);

            DataStream sig_ds;
            sig_ds << *sig;
            UniValue out{UniValue::VOBJ};
            out.pushKV("txid", txid_hex);
            out.pushKV("sig", HexStr(std::span<const unsigned char>{
                UCharCast(sig_ds.data()), sig_ds.size()}));
            return out;
        }
    };
}

RPCMethod pricoin_swapwatch_extract_pric_t()
{
    return RPCMethod{
        "pricoin_swapwatch_extract_pric_t",
        "Alice's BTC-claim path step 1: extract the adaptor secret t from\n"
        "the on-chain CLSAG signature of Bob's PRIC claim tx, given the\n"
        "single-layer ring used for the cooperative adaptor pre-sig and\n"
        "the deserialized on-chain CLSAG signature blob.\n"
        "\n"
        "Wraps pricoin_jointspend_adaptor_extract with the swap record's\n"
        "pric_claim_presig_blob auto-loaded — caller doesn't have to\n"
        "remember which presig goes with which swap.\n"
        "\n"
        "Verifies t·G == swap.adaptor.T_G AND t·H_p(P_pi) == swap.adaptor.T_H\n"
        "via the existing extract math; returns nullopt on any failure.\n",
        {
            {"swap_id",      RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"ring",         RPCArg::Type::ARR,     RPCArg::Optional::NO,
                "Single-layer ring of joint pubkeys Bob used at adapt-round-1 time. "
                "Must be supplied by Bob (e.g. via Nostr DM with the on-chain sig).",
                {{"P", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""}}},
            {"sig_hex",      RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Serialized pricoin::ringsig::Signature from Bob's on-chain PRIC claim tx"},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "t", "32-byte recovered scalar — feed to pricoin_swapwatch_adapt_btc_claim"}}
        },
        RPCExamples{HelpExampleCli("pricoin_swapwatch_extract_pric_t",
            "<swap_id> '[\"<P0>\",\"<P1>\",\"<P2>\",\"<P3>\"]' <onchain_sig>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 sid = ParseChainWatchSwapId(request.params[0]);

            ::wallet::pricoin_adaptor_swap::AdaptorSwap snap;
            if (::wallet::pricoin_adaptor_swap::Get(*wallet_sp, sid, snap)
                != ::wallet::pricoin_adaptor_swap::LookupResult::Ok) {
                throw JSONRPCError(RPC_INVALID_REQUEST, "swap not found");
            }
            if (snap.presigs.pric_claim_presig_blob.empty()) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "swap has no pric_claim_presig_blob — set_pre_signed not run?");
            }
            // Dispatch to the existing daemon-level extract RPC. We
            // already have ring + sig_hex from the caller and the
            // presig from the record. The daemon RPC handles parsing
            // + the secp256k1 math.
            UniValue p{UniValue::VARR};
            p.push_back(request.params[1]);  // ring
            p.push_back(HexStr(snap.presigs.pric_claim_presig_blob));
            p.push_back(request.params[2].get_str());
            // We can't call RPCs from inside another RPC handler
            // cleanly via tableRPC.execute — instead, replicate the
            // tiny extract path inline. (The math is in
            // pricoin::adaptor_ringsig::Extract.)
            using namespace ::pricoin::ringsig;
            std::vector<Point> ring;
            const UniValue& ring_arr = request.params[1];
            if (!ring_arr.isArray() || ring_arr.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "ring must be a non-empty array of pubkey hex");
            }
            ring.reserve(ring_arr.size());
            for (size_t i = 0; i < ring_arr.size(); ++i) {
                auto pb = TryParseHex<unsigned char>(ring_arr[i].get_str());
                if (!pb || pb->size() != 33) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("ring[%u] must be 33-byte compressed pubkey hex", static_cast<unsigned>(i)));
                }
                Point P{};
                std::copy(pb->begin(), pb->end(), P.begin());
                ring.push_back(P);
            }
            auto presig_bytes = snap.presigs.pric_claim_presig_blob;
            DataStream presig_ds{std::span<const unsigned char>{presig_bytes}};
            ::pricoin::adaptor_ringsig::AdaptorPreSignature presig;
            try { presig_ds >> presig; }
            catch (const std::exception&) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "stored pric_claim_presig_blob did not parse as AdaptorPreSignature");
            }
            auto sig_bytes = TryParseHex<unsigned char>(request.params[2].get_str());
            if (!sig_bytes) throw JSONRPCError(RPC_INVALID_PARAMETER, "sig_hex invalid");
            DataStream sig_ds{std::span<const unsigned char>{*sig_bytes}};
            Signature sig;
            try { sig_ds >> sig; }
            catch (const std::exception& e) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    std::string("on-chain sig deserialize failed: ") + e.what());
            }
            auto t = ::pricoin::adaptor_ringsig::Extract(
                std::span<const Point>{ring}, presig, sig);
            if (!t) throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Extract failed — check t·G == T_G and t·H_p(P_pi) == T_H");

            // Persist t into the swap record so the LTC claim path
            // (and any other Alice-side claim flow) can consume it
            // without the user re-pasting hex. SetTSecret is
            // idempotent if Bob (the t holder) already had it stored.
            std::array<unsigned char, 32> t_arr{};
            std::copy(t->begin(), t->end(), t_arr.begin());
            const auto sr = ::wallet::pricoin_adaptor_swap::SetTSecret(
                *wallet_sp, sid, t_arr);
            const bool persisted =
                (sr == ::wallet::pricoin_adaptor_swap::TransitionResult::Ok);

            UniValue out{UniValue::VOBJ};
            out.pushKV("t", HexStr(*t));
            out.pushKV("persisted_to_swap_record", persisted);
            return out;
        }
    };
}

RPCMethod pricoin_swapwatch_adapt_btc_claim()
{
    return RPCMethod{
        "pricoin_swapwatch_adapt_btc_claim",
        "Adapt the BTC claim adaptor pre-signature with a known scalar t,\n"
        "build + finalize the BTC claim tx, broadcast it via the foreign-\n"
        "chain backend, and register a swapwatch entry that auto-advances\n"
        "the swap to Complete when the tx confirms.\n"
        "\n"
        "All the BTC-side state (pre-sig, parity, funding outpoint, agg\n"
        "key, recipient) is read from the swap record. The caller supplies\n"
        "`t_hex` — typically extracted from the counterparty's on-chain\n"
        "PRIC claim tx via pricoin_jointspend_adaptor_extract, or\n"
        "obtained directly if this wallet is the t holder.\n"
        "\n"
        "The swap must be in PreSigned or PricClaimed state with\n"
        "btc_claim_presig populated. Returns {txid, sig, watch_kind,\n"
        "watch_registered}.\n",
        {
            {"swap_id",            RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"t_hex",              RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "32-byte adaptor secret t — must satisfy t·G == swap.adaptor.T_G"},
            {"refund_amount_sat",  RPCArg::Type::NUM,     RPCArg::Default{0},
                "Output amount; if 0 defaults to (foreign_amount_sat - 1000) for fees."},
            {"min_confirmations",  RPCArg::Type::NUM,     RPCArg::Default{1}, ""},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "Broadcast txid"},
                {RPCResult::Type::STR_HEX, "sig",  "64-byte BIP340 sig produced by Adapt"},
                {RPCResult::Type::STR,     "watch_kind", "Always foreign_claim"},
                {RPCResult::Type::BOOL,    "watch_registered", "True iff the watch entry was stored"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_swapwatch_adapt_btc_claim",
            "<swap_id> <t_hex>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;
            const uint256 sid = ParseChainWatchSwapId(request.params[0]);
            const std::string t_hex = request.params[1].get_str();
            const int64_t  refund_arg = request.params[2].isNull() ? 0
                : request.params[2].getInt<int64_t>();
            const int32_t min_conf = request.params[3].isNull() ? 1
                : request.params[3].getInt<int32_t>();

            // ─── Load swap + sanity gates ────────────────────────
            ::wallet::pricoin_adaptor_swap::AdaptorSwap snap;
            if (::wallet::pricoin_adaptor_swap::Get(wallet, sid, snap)
                != ::wallet::pricoin_adaptor_swap::LookupResult::Ok) {
                throw JSONRPCError(RPC_INVALID_REQUEST, "swap not found");
            }
            if (snap.state != ::wallet::pricoin_adaptor_swap::State::PreSigned
                && snap.state != ::wallet::pricoin_adaptor_swap::State::PricClaimed) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "swap state must be PreSigned or PricClaimed for BTC adapt+claim");
            }
            if (snap.presigs.btc_claim_presig.size() != 64) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "btc_claim_presig missing or wrong size — set_pre_signed not run?");
            }
            if (snap.foreign_funding_txid.empty() || snap.foreign_funding_vout < 0) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "foreign funding outpoint not set on swap record");
            }
            if (snap.btc_bob_recipient_xonly_hex.size() != 64
                || !IsHex(snap.btc_bob_recipient_xonly_hex)) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "btc_bob_recipient_xonly not set on swap record (BTC claim recipient)");
            }

            // ─── Parse t and validate length ─────────────────────
            auto t_bytes = TryParseHex<unsigned char>(t_hex);
            if (!t_bytes || t_bytes->size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "t_hex must be 32-byte hex");
            }
            bma::Scalar t;
            std::copy(t_bytes->begin(), t_bytes->end(), t.begin());

            // ─── Compute agg_xonly = MuSig2 keyagg(alice_pub, bob_pub) ───
            // Order is role-determined: [alice_pub, bob_pub]. My
            // wallet's swap-identity priv signs the BIP340 events,
            // so I know my role; the counterparty pub fills the other.
            const std::string my_xonly = [&]() {
                CKey priv;
                const auto& id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
                if (!id.spend.IsValid()) return std::string{};
                constexpr const char* kTag = "pricoin/swap/identity-v1";
                for (uint8_t counter = 0; counter < 16; ++counter) {
                    CHMAC_SHA256 hmac(UCharCast(id.spend.data()), 32);
                    hmac.Write(reinterpret_cast<const unsigned char*>(kTag), std::strlen(kTag));
                    hmac.Write(&counter, 1);
                    unsigned char raw[32];
                    hmac.Finalize(raw);
                    priv.Set(raw, raw + 32, true);
                    if (priv.IsValid()) {
                        XOnlyPubKey xo(priv.GetPubKey());
                        return HexStr(xo);
                    }
                }
                return std::string{};
            }();
            if (my_xonly.size() != 64) {
                throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "swap-identity unavailable");
            }
            const std::string peer_compressed = HexStr(snap.counterparty_pub);
            const std::string my_compressed = std::string("02") + my_xonly;
            // Build [alice_pub, bob_pub] in role-order (Alice first).
            const bool i_am_alice =
                (snap.role == ::wallet::pricoin_adaptor_swap::Role::Alice);
            const std::string alice_pub_hex = i_am_alice ? my_compressed : peer_compressed;
            const std::string bob_pub_hex   = i_am_alice ? peer_compressed : my_compressed;

            std::vector<CPubKey> pubs;
            for (const auto& h : {alice_pub_hex, bob_pub_hex}) {
                auto bytes = TryParseHex<unsigned char>(h);
                if (!bytes || bytes->size() != 33) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "internal: pubkey not 33-byte compressed");
                }
                pubs.emplace_back(std::span<const unsigned char>(bytes->data(), 33));
            }
            bma::KeyAggCache cache;
            auto agg = bma::AggregatePubkeys(pubs, cache);
            if (!agg) throw JSONRPCError(RPC_INTERNAL_ERROR, "MuSig2 keyagg failed");

            // ─── Build the BTC claim tx skeleton ─────────────────
            brt::BtcRefundTxParams p;
            auto txid_opt = uint256::FromHex(snap.foreign_funding_txid);
            if (!txid_opt) throw JSONRPCError(RPC_INTERNAL_ERROR,
                "foreign_funding_txid not parseable");
            p.funding_txid = *txid_opt;
            p.funding_vout = static_cast<uint32_t>(snap.foreign_funding_vout);
            p.funding_amount_sat = snap.foreign_amount_sat;
            std::copy(agg->begin(), agg->end(), p.agg_xonly.begin());
            // Recipient SPK = OP_1 OP_PUSHBYTES_32 <32-byte xonly>.
            const auto rcpt_bytes = ParseHex(snap.btc_bob_recipient_xonly_hex);
            p.recipient_script_pubkey = {0x51, 0x20};
            p.recipient_script_pubkey.insert(p.recipient_script_pubkey.end(),
                rcpt_bytes.begin(), rcpt_bytes.end());
            // Default fee carve-out: 1000 sat.
            constexpr int64_t kDefaultBtcFee = 1000;
            p.refund_amount_sat = (refund_arg > 0)
                ? refund_arg
                : (snap.foreign_amount_sat - kDefaultBtcFee);
            if (p.refund_amount_sat <= 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "refund_amount_sat must be positive (set explicitly if funding < default fee)");
            }
            p.nlocktime = 0;  // claim — no timelock

            auto built = brt::Build(p);
            if (!built) throw JSONRPCError(RPC_INVALID_PARAMETER,
                "btc_refund_tx::Build rejected params");

            // ─── Adapt presig with t → 64-byte BIP340 sig ────────
            bma::SignatureBytes presig;
            std::copy(snap.presigs.btc_claim_presig.begin(),
                       snap.presigs.btc_claim_presig.end(), presig.begin());
            auto final_sig = bma::Adapt(presig, t,
                snap.presigs.btc_claim_nonce_parity);
            if (!final_sig) throw JSONRPCError(RPC_INVALID_PARAMETER,
                "Adapt failed — check t·G == T_G and parity");

            // ─── Finalize witness + serialize ────────────────────
            auto finalized = brt::Finalize(*built,
                std::span<const unsigned char>{final_sig->data(), final_sig->size()});
            if (!finalized) throw JSONRPCError(RPC_INTERNAL_ERROR,
                "Finalize failed");
            DataStream ds;
            ds << TX_WITH_WITNESS(*finalized);
            const std::string tx_hex_finalized = HexStr(
                std::span<const unsigned char>{UCharCast(ds.data()), ds.size()});

            // ─── Broadcast via foreign client ────────────────────
            auto client = pcw::MakeForeignClientFromRegistry(snap.foreign_chain);
            if (!client) {
                throw JSONRPCError(RPC_INVALID_REQUEST,
                    "no foreign-chain backend registered for chain '" + snap.foreign_chain + "'");
            }
            std::string broadcast_txid;
            try {
                broadcast_txid = client->Broadcast(tx_hex_finalized);
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_MISC_ERROR,
                    std::string("foreign broadcast failed: ") + e.what());
            }

            // ─── Register watch ──────────────────────────────────
            pcw::WatchEntry e;
            e.swap_id = sid;
            e.kind    = pcw::WatchKind::ForeignClaim;
            e.txid_hex = broadcast_txid;
            e.min_confirmations = min_conf;
            const auto r = pcw::Add(wallet, e);

            UniValue out{UniValue::VOBJ};
            out.pushKV("txid",             broadcast_txid);
            out.pushKV("sig",              HexStr(*final_sig));
            out.pushKV("watch_kind",       "foreign_claim");
            out.pushKV("watch_registered", r == pcw::StoreResult::Ok);
            return out;
        }
    };
}

RPCMethod pricoin_swapwatch_broadcast_pric()
{
    return RPCMethod{
        "pricoin_swapwatch_broadcast_pric",
        "Submit a cooperatively-assembled v4 spend tx to the local pricoin\n"
        "mempool AND register a swapwatch entry for the resulting txid in one\n"
        "atomic call. Wraps pricoin_jointspend_submittx; on success the\n"
        "watcher picks up the entry on its next tick and applies the matching\n"
        "SetX transition once the embedded chainstate sees `min_confirmations`.\n"
        "\n"
        "`kind` should be one of `pric_funding`, `pric_claim`, `pric_refund`.\n",
        {
            {"swap_id",            RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"kind",               RPCArg::Type::STR,     RPCArg::Optional::NO,
                "pric_funding | pric_claim | pric_refund"},
            {"tx_hex",             RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Skeleton tx hex from pricoin_jointspend_buildtx"},
            {"signature_hex",      RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "Hex-encoded pricoin::ringsig::Signature"},
            {"vout",               RPCArg::Type::NUM,     RPCArg::Default{-1},
                "Output index — required for pric_funding"},
            {"min_confirmations",  RPCArg::Type::NUM,     RPCArg::Default{1}, ""},
        },
        RPCResult{ RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "Broadcast txid"},
                {RPCResult::Type::NUM,     "size", "Final tx size with signature"},
                {RPCResult::Type::STR,     "watch_kind", "Echo of the registered kind"},
                {RPCResult::Type::BOOL,    "watch_registered", "True iff the watch entry was stored"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_swapwatch_broadcast_pric",
            "<swap_id> pric_claim <tx_hex> <sig_hex>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;

            const uint256 sid = ParseChainWatchSwapId(request.params[0]);
            const pcw::WatchKind k = ParseChainWatchKind(request.params[1]);
            if (k != pcw::WatchKind::PricFunding
                && k != pcw::WatchKind::PricClaim
                && k != pcw::WatchKind::PricRefund) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "broadcast_pric only supports pric_funding / pric_claim / pric_refund");
            }
            const std::string tx_hex = request.params[2].get_str();
            const std::string sig_hex = request.params[3].get_str();
            const int32_t vout = request.params[4].isNull() ? -1 : request.params[4].getInt<int32_t>();
            const int32_t min_conf = request.params[5].isNull()
                ? 1 : request.params[5].getInt<int32_t>();
            if (k == pcw::WatchKind::PricFunding && vout < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "pric_funding requires vout >= 0");
            }

            // Decode + validate + inject the cooperative signature —
            // duplicates pricoin_jointspend_submittx's body. Could
            // factor out, but the tx-validation guards live with
            // submittx and are easier kept local here.
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, tx_hex, /*try_no_witness=*/true, /*try_witness=*/true)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "tx hex failed to decode");
            }
            if (mtx.version != PRICOIN_CT_VERSION) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "tx is not a v4 confidential tx");
            }
            if (mtx.ct_bundle.ring_inputs.size() != 1) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "expected exactly one ring input (joint-spend convention)");
            }
            auto sig_bytes = TryParseHex<unsigned char>(sig_hex);
            if (!sig_bytes) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "signature_hex invalid");
            }
            DataStream ds{std::span<const unsigned char>{*sig_bytes}};
            pricoin::ringsig::Signature sig;
            try {
                ds >> sig;
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    std::string("signature deserialise failed: ") + e.what());
            }
            mtx.ct_bundle.ring_inputs[0].sig = std::move(sig);

            CTransactionRef tx_ref = MakeTransactionRef(std::move(mtx));
            std::string err_str;
            if (!wallet.chain().broadcastTransaction(
                    tx_ref, MAX_MONEY,
                    node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL,
                    err_str)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "broadcast failed: " + err_str);
            }
            const std::string txid = tx_ref->GetHash().ToString();

            // Register the watch.
            pcw::WatchEntry e;
            e.swap_id = sid;
            e.kind    = k;
            e.txid_hex = txid;
            e.vout     = vout;
            e.min_confirmations = min_conf;
            const auto r = pcw::Add(wallet, e);

            UniValue out{UniValue::VOBJ};
            out.pushKV("txid",             txid);
            out.pushKV("size",             (int)::GetSerializeSize(TX_WITH_WITNESS(*tx_ref)));
            out.pushKV("watch_kind",       pcw::WatchKindName(k));
            out.pushKV("watch_registered", r == pcw::StoreResult::Ok);
            return out;
        }
    };
}

RPCMethod pricoin_swapwatch_notify()
{
    return RPCMethod{
        "pricoin_swapwatch_notify",
        "Manually fire a chainwatch transition without polling. The call\n"
        "applies the matching SetX transition to the AdaptorSwap state machine\n"
        "and (if a matching pending entry exists) removes it.\n"
        "\n"
        "Used by external chain-monitoring scripts that observe foreign-chain\n"
        "confirmations and push them to the wallet, bypassing the watcher's\n"
        "own polling loop. Also used by tests to drive transitions\n"
        "deterministically.\n",
        {
            {"swap_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"kind",    RPCArg::Type::STR,     RPCArg::Optional::NO, "Same enum as add"},
            {"txid",    RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte tx id"},
            {"vout",    RPCArg::Type::NUM,     RPCArg::Default{-1},  "Funding kinds only"},
            {"height",  RPCArg::Type::NUM,     RPCArg::Default{-1},  "Confirmation block height"},
        },
        RPCResult{ RPCResult::Type::ANY, "", "Updated swap record" },
        RPCExamples{HelpExampleCli("pricoin_swapwatch_notify",
            "<swap_id> foreign_funding <txid> 0 800000")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            using namespace ::wallet::pricoin_adaptor_swap;
            using TR = TransitionResult;
            auto wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            const uint256 sid  = ParseChainWatchSwapId(request.params[0]);
            const pcw::WatchKind k = ParseChainWatchKind(request.params[1]);
            const std::string txid_hex = request.params[2].get_str();
            if (txid_hex.size() != 64 || !IsHex(txid_hex)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "txid must be 32-byte hex");
            }
            const int32_t vout   = request.params[3].isNull() ? -1 : request.params[3].getInt<int32_t>();
            const int32_t height = request.params[4].isNull() ? -1 : request.params[4].getInt<int32_t>();

            TR r = TR::InvalidInput;
            switch (k) {
            case pcw::WatchKind::ForeignFunding:
                r = SetBtcFunded(*wallet_sp, sid, txid_hex, vout, height);
                break;
            case pcw::WatchKind::PricFunding: {
                auto t = uint256::FromHex(txid_hex);
                if (!t) throw JSONRPCError(RPC_INVALID_PARAMETER, "txid invalid");
                r = SetPricFunded(*wallet_sp, sid, *t, vout, height);
                break;
            }
            case pcw::WatchKind::PricClaim: {
                auto t = uint256::FromHex(txid_hex);
                if (!t) throw JSONRPCError(RPC_INVALID_PARAMETER, "txid invalid");
                r = SetPricClaimed(*wallet_sp, sid, *t);
                break;
            }
            case pcw::WatchKind::ForeignClaim:
                r = SetComplete(*wallet_sp, sid, txid_hex);
                break;
            case pcw::WatchKind::PricRefund: {
                auto t = uint256::FromHex(txid_hex);
                if (!t) throw JSONRPCError(RPC_INVALID_PARAMETER, "txid invalid");
                r = SetRefunded(*wallet_sp, sid, *t, /*foreign=*/std::string{});
                break;
            }
            case pcw::WatchKind::ForeignRefund:
                r = SetRefunded(*wallet_sp, sid, /*pric=*/uint256{}, txid_hex);
                break;
            }
            if (r != TR::Ok) ThrowFromAdaptorSwapTransition(r);
            (void)pcw::Remove(*wallet_sp, sid, k);
            AdaptorSwap out;
            (void)Get(*wallet_sp, sid, out);
            return AdaptorSwapToJSON(out);
        }
    };
}

} // namespace (close BTC MuSig2 wire RPCs anonymous block — balances open at 4840)

} // namespace (close outer anonymous — balances open at 590; exports + helpers below are at namespace wallet level)

RPCMethod pricoin_getstealthaddress_export() { return pricoin_getstealthaddress(); }
RPCMethod pricoin_getnewsubaddress_export()    { return pricoin_getnewsubaddress(); }
RPCMethod pricoin_getsubaddress_export()       { return pricoin_getsubaddress(); }
RPCMethod pricoin_listsubaddresses_export()    { return pricoin_listsubaddresses(); }
RPCMethod pricoin_setsubaddresslabel_export()  { return pricoin_setsubaddresslabel(); }
RPCMethod pricoin_getstealthseed_export() { return pricoin_getstealthseed(); }
RPCMethod pricoin_setstealthseed_export() { return pricoin_setstealthseed(); }
RPCMethod pricoin_buildjointstealthaddress_export() { return pricoin_buildjointstealthaddress(); }
RPCMethod pricoin_jointstealth_pop_sign_export()      { return pricoin_jointstealth_pop_sign(); }
RPCMethod pricoin_jointstealth_pop_verify_export()    { return pricoin_jointstealth_pop_verify(); }
RPCMethod pricoin_buildjointstealthaddress_pop_export() { return pricoin_buildjointstealthaddress_pop(); }
RPCMethod pricoin_jointscan_partial_export() { return pricoin_jointscan_partial(); }
RPCMethod pricoin_jointscan_recover_export() { return pricoin_jointscan_recover(); }
RPCMethod pricoin_jointspend_loadshare_export() { return pricoin_jointspend_loadshare(); }
RPCMethod pricoin_jointspend_buildtx_export()   { return pricoin_jointspend_buildtx(); }
RPCMethod pricoin_jointspend_submittx_export()  { return pricoin_jointspend_submittx(); }
RPCMethod pricoin_swap_identity_export()         { return pricoin_swap_identity(); }
RPCMethod pricoin_swap_session_create_export()   { return pricoin_swap_session_create(); }
RPCMethod pricoin_swap_session_attach_export()   { return pricoin_swap_session_attach(); }
RPCMethod pricoin_swap_session_sign_export()     { return pricoin_swap_session_sign(); }
RPCMethod pricoin_swap_session_verify_export()   { return pricoin_swap_session_verify(); }
RPCMethod pricoin_swap_session_complete_export() { return pricoin_swap_session_complete(); }
RPCMethod pricoin_swap_session_abort_export()    { return pricoin_swap_session_abort(); }
RPCMethod pricoin_swap_session_get_export()      { return pricoin_swap_session_get(); }
RPCMethod pricoin_swap_session_list_export()     { return pricoin_swap_session_list(); }
RPCMethod pricoin_swap_ceremony_create_export()              { return pricoin_swap_ceremony_create(); }
RPCMethod pricoin_swap_ceremony_set_foreign_funded_export()  { return pricoin_swap_ceremony_set_foreign_funded(); }
RPCMethod pricoin_swap_ceremony_set_pric_funded_export()     { return pricoin_swap_ceremony_set_pric_funded(); }
RPCMethod pricoin_swap_ceremony_set_foreign_claimed_export() { return pricoin_swap_ceremony_set_foreign_claimed(); }
RPCMethod pricoin_swap_ceremony_set_pric_released_export()   { return pricoin_swap_ceremony_set_pric_released(); }
RPCMethod pricoin_swap_ceremony_abort_export()               { return pricoin_swap_ceremony_abort(); }
RPCMethod pricoin_swap_ceremony_get_export()                 { return pricoin_swap_ceremony_get(); }
RPCMethod pricoin_swap_ceremony_list_export()                { return pricoin_swap_ceremony_list(); }
RPCMethod pricoin_clsag_nonce_begin_export()           { return pricoin_clsag_nonce_begin(); }
RPCMethod pricoin_clsag_nonce_mark_published_export()  { return pricoin_clsag_nonce_mark_published(); }
RPCMethod pricoin_clsag_nonce_get_export()             { return pricoin_clsag_nonce_get(); }
RPCMethod pricoin_clsag_nonce_list_export()            { return pricoin_clsag_nonce_list(); }
RPCMethod pricoin_clsag_nonce_erase_export()           { return pricoin_clsag_nonce_erase(); }
RPCMethod pricoin_jointspend_round1_safe_export()      { return pricoin_jointspend_round1_safe(); }
RPCMethod pricoin_adaptor_swap_create_export()           { return pricoin_adaptor_swap_create(); }
RPCMethod pricoin_adaptor_swap_set_adaptor_export()      { return pricoin_adaptor_swap_set_adaptor(); }
RPCMethod pricoin_adaptor_swap_set_timelocks_export()    { return pricoin_adaptor_swap_set_timelocks(); }
RPCMethod pricoin_adaptor_swap_set_btc_funded_export()   { return pricoin_adaptor_swap_set_btc_funded(); }
RPCMethod pricoin_adaptor_swap_set_pric_claim_ring_export() { return pricoin_adaptor_swap_set_pric_claim_ring(); }
RPCMethod pricoin_adaptor_swap_set_pric_funded_export()  { return pricoin_adaptor_swap_set_pric_funded(); }
RPCMethod pricoin_adaptor_swap_set_peer_stealth_pubkeys_export() { return pricoin_adaptor_swap_set_peer_stealth_pubkeys(); }
RPCMethod pricoin_adaptor_swap_set_pre_signed_export()   { return pricoin_adaptor_swap_set_pre_signed(); }
RPCMethod pricoin_adaptor_swap_set_pric_claimed_export() { return pricoin_adaptor_swap_set_pric_claimed(); }
RPCMethod pricoin_adaptor_swap_set_complete_export()     { return pricoin_adaptor_swap_set_complete(); }
RPCMethod pricoin_adaptor_swap_set_refunded_export()     { return pricoin_adaptor_swap_set_refunded(); }
RPCMethod pricoin_adaptor_swap_abort_export()            { return pricoin_adaptor_swap_abort(); }
RPCMethod pricoin_adaptor_swap_get_export()              { return pricoin_adaptor_swap_get(); }
RPCMethod pricoin_adaptor_swap_list_export()             { return pricoin_adaptor_swap_list(); }
RPCMethod pricoin_btc_musig2_keyagg_export()             { return pricoin_btc_musig2_keyagg(); }
RPCMethod pricoin_btc_musig2_round1_export()             { return pricoin_btc_musig2_round1(); }
RPCMethod pricoin_btc_musig2_aggregate_nonces_export()   { return pricoin_btc_musig2_aggregate_nonces(); }
RPCMethod pricoin_btc_musig2_process_export()            { return pricoin_btc_musig2_process(); }
RPCMethod pricoin_btc_musig2_partial_sign_export()       { return pricoin_btc_musig2_partial_sign(); }
RPCMethod pricoin_btc_musig2_aggregate_partials_export() { return pricoin_btc_musig2_aggregate_partials(); }
RPCMethod pricoin_btc_musig2_adapt_export()              { return pricoin_btc_musig2_adapt(); }
RPCMethod pricoin_btc_musig2_extract_export()            { return pricoin_btc_musig2_extract(); }
RPCMethod pricoin_btc_musig2_round1_safe_export()        { return pricoin_btc_musig2_round1_safe(); }
RPCMethod pricoin_btc_musig2_nonce_mark_finalized_export() { return pricoin_btc_musig2_nonce_mark_finalized(); }
RPCMethod pricoin_btc_musig2_nonce_get_export()          { return pricoin_btc_musig2_nonce_get(); }
RPCMethod pricoin_btc_musig2_nonce_list_export()         { return pricoin_btc_musig2_nonce_list(); }
RPCMethod pricoin_btc_musig2_nonce_erase_export()        { return pricoin_btc_musig2_nonce_erase(); }
RPCMethod pricoin_btc_swap_tx_build_export()             { return pricoin_btc_swap_tx_build(); }
RPCMethod pricoin_btc_swap_tx_finalize_export()          { return pricoin_btc_swap_tx_finalize(); }
RPCMethod pricoin_btc_p2tr_address_export()              { return pricoin_btc_p2tr_address(); }
RPCMethod pricoin_offer_create_export()                  { return pricoin_offer_create(); }
RPCMethod pricoin_offer_import_export()                  { return pricoin_offer_import(); }
RPCMethod pricoin_offer_get_export()                     { return pricoin_offer_get(); }
RPCMethod pricoin_offer_list_export()                    { return pricoin_offer_list(); }
RPCMethod pricoin_offer_cancel_export()                  { return pricoin_offer_cancel(); }
RPCMethod pricoin_offer_match_export()                   { return pricoin_offer_match(); }
RPCMethod pricoin_offer_fill_export()                    { return pricoin_offer_fill(); }
RPCMethod pricoin_offer_unmatch_export()                 { return pricoin_offer_unmatch(); }
RPCMethod pricoin_offer_find_matches_export()            { return pricoin_offer_find_matches(); }
RPCMethod pricoin_offer_export_uri_export()              { return pricoin_offer_export_uri(); }
RPCMethod pricoin_swapwatch_add_export()                { return pricoin_swapwatch_add(); }
RPCMethod pricoin_swapwatch_remove_export()             { return pricoin_swapwatch_remove(); }
RPCMethod pricoin_swapwatch_list_export()               { return pricoin_swapwatch_list(); }
RPCMethod pricoin_swapwatch_start_export()              { return pricoin_swapwatch_start(); }
RPCMethod pricoin_swapwatch_stop_export()               { return pricoin_swapwatch_stop(); }
RPCMethod pricoin_swapwatch_status_export()             { return pricoin_swapwatch_status(); }
RPCMethod pricoin_swapwatch_tick_once_export()          { return pricoin_swapwatch_tick_once(); }
RPCMethod pricoin_swapwatch_notify_export()             { return pricoin_swapwatch_notify(); }
RPCMethod pricoin_swapwatch_broadcast_foreign_export()  { return pricoin_swapwatch_broadcast_foreign(); }
RPCMethod pricoin_swapwatch_broadcast_pric_export()     { return pricoin_swapwatch_broadcast_pric(); }
RPCMethod pricoin_swapwatch_adapt_btc_claim_export()    { return pricoin_swapwatch_adapt_btc_claim(); }
RPCMethod pricoin_swapwatch_extract_pric_t_export()     { return pricoin_swapwatch_extract_pric_t(); }
RPCMethod pricoin_swapwatch_adapt_pric_claim_export()   { return pricoin_swapwatch_adapt_pric_claim(); }
RPCMethod pricoin_swapwatch_verify_pric_claim_export()  { return pricoin_swapwatch_verify_pric_claim(); }
RPCMethod pricoin_swap_recover_refund_singlesig_export() { return pricoin_swap_recover_refund_singlesig(); }
RPCMethod pricoin_btc_getaddress_export()               { return pricoin_btc_getaddress(); }
RPCMethod pricoin_btc_getbalance_export()               { return pricoin_btc_getbalance(); }
RPCMethod pricoin_btc_fund_swap_export()                { return pricoin_btc_fund_swap(); }
RPCMethod pricoin_btc_sweep_export()                    { return pricoin_btc_sweep(); }
RPCMethod pricoin_ltc_claim_swap_export()               { return pricoin_ltc_claim_swap(); }
RPCMethod pricoin_ltc_refund_swap_export()              { return pricoin_ltc_refund_swap(); }
RPCMethod pricoin_listownct_export() { return pricoin_listownct(); }
RPCMethod walletsendct_from_ct_export() { return walletsendct_from_ct(); }
RPCMethod walletsendct_ring_export() { return walletsendct_ring(); }
RPCMethod pricoin_ct_relay_prebuilt_export() { return pricoin_ct_relay_prebuilt(); }

std::vector<PricoinCTRecovery> ScanTxForCTReceives(
    CWallet& wallet,
    const CTransaction& tx)
{
    std::vector<PricoinCTRecovery> out;
    if (tx.version != PRICOIN_CT_VERSION) return out;
    const auto& id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
    const auto subaddr_lookup = ::wallet::pricoin_stealth::BuildSubaddressLookup(wallet);
    for (uint32_t i = 0; i < tx.vout.size(); ++i) {
        auto rec = TryRecoverCTOutput(id, subaddr_lookup, tx, i);
        if (!rec) continue;
        PricoinCTRecovery r;
        r.vout_index = rec->output_index;
        r.value = rec->value;
        std::memcpy(r.one_time_priv.data(), rec->one_time_priv.begin(), 32);
        out.push_back(r);
    }
    return out;
}

std::vector<PricoinSwapClaimRecovery> ScanTxForSwapClaim(
    CWallet& wallet,
    const CTransaction& tx)
{
    using namespace ::wallet::pricoin_adaptor_swap;
    namespace par = ::pricoin::adaptor_ringsig;
    std::vector<PricoinSwapClaimRecovery> out;
    if (tx.version != PRICOIN_CT_VERSION) return out;
    if (tx.ct_bundle.ring_inputs.empty()) return out;

    // Pull the snapshot of all swaps once. List is small (per-user,
    // experimental/regtest scope); cheap to iterate per tx.
    std::vector<AdaptorSwap> swaps;
    if (List(wallet, swaps) != LookupResult::Ok) return out;

    for (const auto& s : swaps) {
        if (s.role != Role::Alice) continue;
        if (s.has_t) continue;
        // Post-2026-05-15 state ordering: Alice's PRIC is locked from
        // BothFunded onward (PreSigned now precedes any funding). She
        // could observe Bob's claim spending her funding at:
        //   * BothFunded — Bob has just claimed (most common path).
        //   * PricClaimed — Alice already advanced state somehow, but
        //                   t still hasn't been extracted.
        if (s.state != State::BothFunded
            && s.state != State::PricClaimed) continue;
        if (s.pric_claim_ring.empty()) continue;
        if (s.presigs.pric_claim_presig_blob.empty()) continue;
        if (s.pric_funding_txid.IsNull() || s.pric_funding_vout < 0) continue;

        // Look for the swap's joint funding outpoint in any of the
        // tx's ring_inputs. If found, this tx is a candidate spend.
        for (const auto& ri : tx.ct_bundle.ring_inputs) {
            bool match = false;
            for (const auto& po : ri.ring) {
                if (po.hash == s.pric_funding_txid
                    && static_cast<int32_t>(po.n) == s.pric_funding_vout) {
                    match = true;
                    break;
                }
            }
            if (!match) continue;

            // Reconstruct the ring as Points (33-byte arrays).
            std::vector<::pricoin::ringsig::Point> ring_pts;
            ring_pts.reserve(s.pric_claim_ring.size());
            for (const auto& p : s.pric_claim_ring) {
                ::pricoin::ringsig::Point P{};
                std::copy(p.begin(), p.end(), P.begin());
                ring_pts.push_back(P);
            }

            // Parse the persisted adaptor pre-sig blob.
            par::AdaptorPreSignature presig;
            try {
                DataStream ds{std::span<const unsigned char>{
                    s.presigs.pric_claim_presig_blob}};
                ds >> presig;
            } catch (const std::exception&) {
                continue;
            }

            // Extract t from (ring, presig, on-chain sig).
            auto t_or = par::Extract(
                std::span<const ::pricoin::ringsig::Point>{ring_pts},
                presig, ri.sig);
            if (!t_or) continue;

            PricoinSwapClaimRecovery rec;
            rec.swap_id = s.swap_id;
            rec.t_recovered = *t_or;
            out.push_back(rec);
            break; // one match per swap is enough
        }
    }
    return out;
}

CAmount ConfidentialBalance(CWallet& wallet)
{
    LOCK(g_recovery_index_mutex);
    const CTRecoveryIndex& index = SyncRecoveryIndexLocked(wallet);
    CAmount total = 0;
    for (const auto& [_, rec] : index.entries) {
        // Phase 3a: spentness is the KI set, not chainstate erasure.
        if (pricoin::IsKeyImageCommitted(rec.key_image)) continue;
        total += rec.value;
    }
    return total;
}

void DropCTRecoveryCache(CWallet& wallet)
{
    LOCK(g_recovery_index_mutex);
    g_recovery_indices.erase(&wallet);
    // Also erase the persisted copy — keeping it would let the OLD
    // identity's recoveries leak back into the cache at the next
    // startup (LoadPersistedRecoveryIndex would silently restore them
    // before any sync runs). Same correctness reason as the in-memory
    // drop in SetSeed.
    WalletBatch batch(wallet.GetDatabase());
    batch.ErasePricoinRecoveryCache();
}

void RunWithCTRecoveryCacheCleared(CWallet& wallet,
                                   std::function<bool()> inner)
{
    LOCK(g_recovery_index_mutex);
    const bool drop = inner();
    if (drop) {
        g_recovery_indices.erase(&wallet);
        WalletBatch batch(wallet.GetDatabase());
        batch.ErasePricoinRecoveryCache();
    }
}

} // namespace wallet
