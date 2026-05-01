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
#include <pricoin/ringsig.h>
#include <pricoin/ct.h>
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
#include <wallet/pricoin_ct_send.h>
#include <wallet/pricoin_stealth.h>
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
    PricoinCTRecipient one{dest_addr_str, dest_amount};
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
        "(recipient cannot scan).\n",
        {
            {"dest_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Destination Pricoin stealth or bech32 address"},
            {"dest_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount to send in PRIC"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Transparent fee in PRIC"},
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

            auto res = SendConfidentialTx(wallet, dest_addr_str, dest_amount, fee);
            if (!res) throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(res).original);

            UniValue out{UniValue::VOBJ};
            out.pushKV("txid", res->ToString());
            out.pushKV("dest_was_stealth", ::pricoin::stealth::Decode(dest_addr_str).has_value());
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
                PricoinCTRecipient{.address = dest, .amount = amount}};
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
util::Result<ResolvedDest> ResolveDest(const std::string& addr, uint32_t output_index)
{
    ResolvedDest d;
    const auto stealth = ::pricoin::stealth::Decode(addr);
    if (stealth) {
        CKey r;
        r.MakeNewKey(/*fCompressed=*/true);
        CPubKey R = r.GetPubKey();
        std::memcpy(d.R.data(), R.data(), 33);
        auto S = ::pricoin::stealth::ECDHPoint(r, stealth->view);
        if (!S) return util::Error{Untranslated("stealth ECDH failed")};
        auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, output_index);
        auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, stealth->spend);
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
    struct PendingOut { std::string address; CAmount amount; };
    std::vector<PendingOut> pending;
    pending.reserve(recipients.size() + 2);
    for (const auto& r : recipients) pending.push_back({r.address, r.amount});
    const auto& self_id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
    const std::string self_addr = ::pricoin::stealth::Encode(self_id.public_address);
    pending.push_back({self_addr, change_value});

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
        pending.push_back({self_addr, 0});
    }

    FastRandomContext rng;
    std::shuffle(pending.begin(), pending.end(), rng);

    // Per-output stealth derivation must use the FINAL position, because the
    // recipient scans by trying each vout's index when computing the
    // shared-secret tweak — output_index is part of the rewind nonce.
    std::vector<ResolvedDest> dests;
    dests.reserve(pending.size());
    for (size_t i = 0; i < pending.size(); ++i) {
        auto rd = ResolveDest(pending[i].address, static_cast<uint32_t>(i));
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
};

std::optional<RecoveredOutput> TryRecoverCTOutput(
    const ::wallet::pricoin_stealth::Identity& id,
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

    auto S = ::pricoin::stealth::ECDHPoint(id.view, R);
    if (!S) return std::nullopt;
    auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, output_index);
    auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, id.public_address.spend);
    if (!P) return std::nullopt;
    const CScript expected_spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
    if (tx.vout[output_index].scriptPubKey != expected_spk) return std::nullopt;

    // Match! Rewind the rangeproof.
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

    auto one_time_priv = ::pricoin::stealth::DeriveOneTimePriv(shared, id.spend);
    if (!one_time_priv) return std::nullopt;

    // Compute the key image for this output — needed to detect whether
    // it has been spent on chain (the KI would appear in the global set).
    pricoin::ringsig::Point P_bytes{};
    std::memcpy(P_bytes.data(), P->data(), 33);
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
// Each entry (85 bytes):
//   [txid:32][vout:u32 LE][output_index:u32 LE]
//   [value:i64 LE][key_image:33][height:i32 LE]
//
// Reorg detection still fires on load — if the chain at last_scanned_height
// no longer hashes to last_scanned_hash, the deserialised cache is
// dropped and a full fresh scan runs. The persisted cache is best-effort:
// missing it (corruption, wrong key, or wallet locked at scan time) just
// means a one-time full rescan on next access.
constexpr unsigned char kRecoveryCacheInnerVer = 0x01;

struct CachedRecovery {
    uint32_t output_index{0};
    CAmount value{0};
    pricoin::ringsig::Point key_image{};
    int height{0};
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

    int new_blocks = 0;
    for (int h = index.last_scanned_height + 1; h <= tip_height; ++h) {
        const uint256 block_hash = chain.getBlockHash(h);
        CBlock block;
        if (!chain.findBlock(block_hash, interfaces::FoundBlock().data(block))) continue;
        ++new_blocks;
        for (const auto& tx_ref : block.vtx) {
            if (tx_ref->version != PRICOIN_CT_VERSION) continue;
            for (uint32_t i = 0; i < tx_ref->vout.size(); ++i) {
                auto rec = TryRecoverCTOutput(id, *tx_ref, i);
                if (!rec) continue;
                CachedRecovery cr;
                cr.output_index = rec->output_index;
                cr.value = rec->value;
                cr.key_image = rec->key_image;
                cr.height = h;
                index.entries[COutPoint{tx_ref->GetHash(), rec->output_index}] = cr;
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
        "stealth identity, recovering their hidden values via rangeproof rewind. Phase 5e demo.\n",
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
                for (const auto& [outpoint, rec] : index.entries) {
                    if (rec.height < startheight) continue;
                    if (pricoin::IsKeyImageCommitted(rec.key_image)) continue;
                    total_recovered += rec.value;
                    UniValue entry{UniValue::VOBJ};
                    entry.pushKV("txid", outpoint.hash.ToString());
                    entry.pushKV("vout", (int)outpoint.n);
                    entry.pushKV("value", ValueFromAmount(rec.value));
                    entry.pushKV("height", rec.height);
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
    interfaces::Chain& chain,
    const COutPoint& outpoint,
    int height)
{
    const uint256 block_hash = chain.getBlockHash(height);
    CBlock block;
    if (!chain.findBlock(block_hash, interfaces::FoundBlock().data(block))) return std::nullopt;
    for (const auto& tx_ref : block.vtx) {
        if (tx_ref->GetHash() != outpoint.hash) continue;
        return TryRecoverCTOutput(id, *tx_ref, outpoint.n);
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

            const auto stealth_dest = ::pricoin::stealth::Decode(dest_addr_str);
            if (!stealth_dest) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "dest_address must be a stealth address");

            const auto& id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
            interfaces::Chain& chain = wallet.chain();

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
                    picked_outpoint = outpoint;
                    picked_height = rec.height;
                    break;
                }
            }
            if (picked_height >= 0) {
                picked = RehydrateRecovery(id, chain, picked_outpoint, picked_height);
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
            };
            std::vector<PendingOut> pending;
            pending.reserve(3);
            pending.push_back({&*stealth_dest, dest_amount});
            pending.push_back({&id.public_address, change_value});
            while (pending.size() < 3) {
                pending.push_back({&id.public_address, 0});
            }
            FastRandomContext shuffle_rng;
            std::shuffle(pending.begin(), pending.end(), shuffle_rng);

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
                CKey r; r.MakeNewKey(true);
                CPubKey R = r.GetPubKey();
                ResolvedOut ro;
                ro.amount = pending[i].amount;
                std::memcpy(ro.R.data(), R.data(), 33);
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

            CTransactionRef tx_ref = MakeTransactionRef(std::move(mtx));
            std::string err_str;
            if (!chain.broadcastTransaction(tx_ref, MAX_MONEY,
                                             node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL,
                                             err_str)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "broadcast failed: " + err_str);
            }

            UniValue out{UniValue::VOBJ};
            out.pushKV("txid", tx_ref->GetHash().ToString());
            out.pushKV("ring_size", ring_size);
            out.pushKV("input_value", ValueFromAmount(picked->value));
            out.pushKV("change_amount", ValueFromAmount(change_value));
            out.pushKV("size", (int)::GetSerializeSize(TX_WITH_WITNESS(*tx_ref)));
            out.pushKV("bundle_size", (int)tx_ref->ct_bundle.SerializedSize());
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
                    sorted.push_back({outpoint, rec.value, rec.height});
                }
            }
            std::sort(sorted.begin(), sorted.end(),
                      [](const auto& a, const auto& b) { return a.value > b.value; });

            std::vector<PickedCT> picked_list;
            CAmount input_total = 0;
            for (const auto& cand : sorted) {
                auto rehydrated = RehydrateRecovery(id, chain, cand.outpoint, cand.height);
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
            const auto stealth_dest = ::pricoin::stealth::Decode(dest_addr_str);
            CScript transparent_dest_spk;
            if (!stealth_dest) {
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
            };
            std::vector<OutputSpec> pending;
            pending.reserve(3);
            if (stealth_dest) {
                pending.push_back({OutputSpec::Kind::StealthForeign, &*stealth_dest, {}, dest_amount});
            } else {
                pending.push_back({OutputSpec::Kind::Transparent, nullptr, transparent_dest_spk, dest_amount});
            }
            pending.push_back({OutputSpec::Kind::StealthSelf, &id.public_address, {}, change_value});
            while (pending.size() < 3) {
                pending.push_back({OutputSpec::Kind::StealthSelf, &id.public_address, {}, 0});
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
                    CPubKey R = r.GetPubKey();
                    std::memcpy(ro.R.data(), R.data(), 33);
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

            auto stealth_dest = ::pricoin::stealth::Decode(dest_addr_str);
            if (!stealth_dest) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "dest_address must be a stealth address");

            // Sanity: prev coin's commitment must match Create(value, blind).
            const COutPoint joint_outpoint{Txid::FromUint256(*joint_txid_opt), joint_vout};
            Coin joint_coin;
            {
                std::map<COutPoint, Coin> coins{{joint_outpoint, Coin{}}};
                chain.findCoins(coins);
                joint_coin = coins[joint_outpoint];
            }
            if (joint_coin.IsSpent() || !joint_coin.IsConfidential()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "joint outpoint not a confirmed v4 output");
            }
            {
                auto rebuilt = pricoin::ct::Commitment::Create(static_cast<uint64_t>(joint_value), joint_blind);
                if (!rebuilt || *rebuilt != joint_coin.commitment) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        "joint_value+joint_blind do not reconstruct the on-chain commitment");
                }
            }
            if (joint_coin.one_time_pubkey != joint_pubkey) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "joint_pubkey does not match the on-chain one_time_pubkey");
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
                        .commitment = joint_coin.commitment,
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
            };
            std::vector<PendingOut> pending;
            pending.reserve(3);
            pending.push_back({&*stealth_dest, dest_amount});
            pending.push_back({&id.public_address, change_value});
            while (pending.size() < 3) pending.push_back({&id.public_address, 0});
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
                CPubKey R = r.GetPubKey();
                ResolvedOut ro;
                ro.amount = pending[i].amount;
                std::memcpy(ro.R.data(), R.data(), 33);
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
            mtx.nLockTime = 0;
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

            UniValue out{UniValue::VOBJ};
            out.pushKV("x_share",      HexStr(x_share_bytes));
            out.pushKV("blind",        HexStr(rewound->blind));
            out.pushKV("value",        ValueFromAmount(static_cast<CAmount>(rewound->value)));
            out.pushKV("joint_pubkey", HexStr(joint_pub_bytes));
            out.pushKV("vout",         static_cast<int>(vout));
            return out;
        }
    };
}

} // namespace

RPCMethod pricoin_getstealthaddress_export() { return pricoin_getstealthaddress(); }
RPCMethod pricoin_getstealthseed_export() { return pricoin_getstealthseed(); }
RPCMethod pricoin_setstealthseed_export() { return pricoin_setstealthseed(); }
RPCMethod pricoin_buildjointstealthaddress_export() { return pricoin_buildjointstealthaddress(); }
RPCMethod pricoin_jointscan_partial_export() { return pricoin_jointscan_partial(); }
RPCMethod pricoin_jointscan_recover_export() { return pricoin_jointscan_recover(); }
RPCMethod pricoin_jointspend_loadshare_export() { return pricoin_jointspend_loadshare(); }
RPCMethod pricoin_jointspend_buildtx_export()   { return pricoin_jointspend_buildtx(); }
RPCMethod pricoin_jointspend_submittx_export()  { return pricoin_jointspend_submittx(); }
RPCMethod pricoin_listownct_export() { return pricoin_listownct(); }
RPCMethod walletsendct_from_ct_export() { return walletsendct_from_ct(); }
RPCMethod walletsendct_ring_export() { return walletsendct_ring(); }

std::vector<PricoinCTRecovery> ScanTxForCTReceives(
    CWallet& wallet,
    const CTransaction& tx)
{
    std::vector<PricoinCTRecovery> out;
    if (tx.version != PRICOIN_CT_VERSION) return out;
    const auto& id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
    for (uint32_t i = 0; i < tx.vout.size(); ++i) {
        auto rec = TryRecoverCTOutput(id, tx, i);
        if (!rec) continue;
        PricoinCTRecovery r;
        r.vout_index = rec->output_index;
        r.value = rec->value;
        std::memcpy(r.one_time_priv.data(), rec->one_time_priv.begin(), 32);
        out.push_back(r);
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
