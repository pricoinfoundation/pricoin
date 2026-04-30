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
    CAmount fee);
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
            out.pushKV("outputs", static_cast<int>(recipients.size()) + 1);
            out.pushKV("total_sent", ValueFromAmount(total_sent));
            out.pushKV("fee", ValueFromAmount(fee));
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
util::Result<uint256> SendConfidentialTxMultiImpl(
    CWallet& wallet,
    std::span<const PricoinCTRecipient> recipients,
    CAmount fee)
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
    pending.reserve(recipients.size() + 1);
    for (const auto& r : recipients) pending.push_back({r.address, r.amount});
    const auto& self_id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
    pending.push_back({::pricoin::stealth::Encode(self_id.public_address), change_value});

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
    mtx.nLockTime = 0;
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
    wallet.CommitTransaction(tx_ref, /*mapValue=*/{}, /*orderForm=*/{});
    return tx_ref->GetHash().ToUint256();
}

} // namespace detail

RPCMethod walletsendct_export() { return walletsendct(); }
RPCMethod walletsendct_multi_export() { return walletsendct_multi(); }

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

            const auto& id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
            interfaces::Chain& chain = wallet.chain();

            struct Pending {
                COutPoint outpoint;
                CAmount value;
                int height;
                pricoin::ringsig::Point key_image;
            };
            std::vector<Pending> pending;
            int scanned_blocks = 0;
            int scanned_mempool = 0;

            const std::optional<int> tip_opt = chain.getHeight();
            const int tip_height = tip_opt.value_or(-1);

            for (int h = std::max(startheight, 0); h <= tip_height; ++h) {
                const uint256 block_hash = chain.getBlockHash(h);
                CBlock block;
                if (!chain.findBlock(block_hash, interfaces::FoundBlock().data(block))) continue;
                if (block.vtx.empty()) continue;
                ++scanned_blocks;
                for (const auto& tx_ref : block.vtx) {
                    if (tx_ref->version != PRICOIN_CT_VERSION) continue;
                    for (uint32_t i = 0; i < tx_ref->vout.size(); ++i) {
                        auto rec = TryRecoverCTOutput(id, *tx_ref, i);
                        if (!rec) continue;
                        pending.push_back(Pending{
                            COutPoint{tx_ref->GetHash(), rec->output_index},
                            rec->value, h, rec->key_image});
                    }
                }
            }

            // Phase 3a: chainstate-erasure no longer marks v4 outputs spent
            // (they're kept indefinitely as ring-decoy candidates). Filter
            // by the global key-image set instead — an output is spent iff
            // its KI has been committed.
            UniValue outputs{UniValue::VARR};
            CAmount total_recovered = 0;
            for (const auto& p : pending) {
                if (pricoin::IsKeyImageCommitted(p.key_image)) continue;
                total_recovered += p.value;
                UniValue entry{UniValue::VOBJ};
                entry.pushKV("txid", p.outpoint.hash.ToString());
                entry.pushKV("vout", (int)p.outpoint.n);
                entry.pushKV("value", ValueFromAmount(p.value));
                entry.pushKV("height", p.height);
                outputs.push_back(entry);
            }
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
// TODO: switch to gamma(k=19.28, scale=1.61) over log(age_seconds) once the
// chain has enough history that the empirical parameters can be measured.
std::vector<ChainCTOutput> SampleDecoysRecencyWeighted(
    std::vector<ChainCTOutput> pool, size_t k, int tip_height,
    FastRandomContext& cprng)
{
    if (k >= pool.size()) return pool;

    // Half-life ≈ 5 days at 150s blocks. Weight halves every ~2880 blocks.
    constexpr double kHalfLifeBlocks = 2880.0;

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
        const double weight = 1.0 / (1.0 + static_cast<double>(age) / kHalfLifeBlocks);
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

            // 1. Find our recovered CT output with sufficient value.
            std::optional<RecoveredOutput> picked;
            COutPoint picked_outpoint;
            const int tip = chain.getHeight().value_or(-1);
            const CAmount target = dest_amount + fee;
            for (int h = 0; h <= tip && !picked; ++h) {
                const uint256 block_hash = chain.getBlockHash(h);
                CBlock block;
                if (!chain.findBlock(block_hash, interfaces::FoundBlock().data(block))) continue;
                for (const auto& tx_ref : block.vtx) {
                    if (tx_ref->version != PRICOIN_CT_VERSION) continue;
                    for (uint32_t i = 0; i < tx_ref->vout.size(); ++i) {
                        auto rec = TryRecoverCTOutput(id, *tx_ref, i);
                        if (!rec || rec->value < target) continue;
                        // Phase 3a: skip outputs whose KI is already on chain.
                        if (pricoin::IsKeyImageCommitted(rec->key_image)) continue;
                        picked = std::move(rec);
                        picked_outpoint = COutPoint(tx_ref->GetHash(), picked->output_index);
                        break;
                    }
                    if (picked) break;
                }
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

            // 6. Build dest + change outputs (always to stealth recipients here).
            //    Output blinds are chosen so they sum to pseudo_blind (so the
            //    bundle's pseudo commitments balance against output commitments).
            const CAmount change_value = picked->value - target;

            CScript dest_spk, change_spk;
            ::pricoin::stealth::PointBytes dest_R{}, change_R{};
            ::pricoin::ct::BlindingFactor dest_nonce{}, change_nonce{};
            ::pricoin::ct::SerializedPubKey33 dest_otp{}, change_otp{};
            // Dest
            {
                CKey r; r.MakeNewKey(true);
                CPubKey R = r.GetPubKey();
                std::memcpy(dest_R.data(), R.data(), 33);
                auto S = ::pricoin::stealth::ECDHPoint(r, stealth_dest->view);
                if (!S) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth ECDH failed (dest)");
                auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, 0);
                auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, stealth_dest->spend);
                if (!P) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth onetime failed (dest)");
                dest_spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
                std::memcpy(dest_otp.data(), P->data(), 33);
                auto rp_nonce = ::pricoin::stealth::DeriveRangeProofNonce(*S, 0);
                std::memcpy(dest_nonce.data(), rp_nonce.data(), 32);
            }
            // Change
            {
                CKey r; r.MakeNewKey(true);
                CPubKey R = r.GetPubKey();
                std::memcpy(change_R.data(), R.data(), 33);
                auto S = ::pricoin::stealth::ECDHPoint(r, id.public_address.view);
                if (!S) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth ECDH failed (change)");
                auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, 1);
                auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, id.public_address.spend);
                if (!P) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth onetime failed (change)");
                change_spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
                std::memcpy(change_otp.data(), P->data(), 33);
                auto rp_nonce = ::pricoin::stealth::DeriveRangeProofNonce(*S, 1);
                std::memcpy(change_nonce.data(), rp_nonce.data(), 32);
            }

            // Output blinds: dest random, change = pseudo_blind - dest_blind
            // (so dest_blind + change_blind = pseudo_blind, which means
            // C_dest + C_change = pseudo_blind*G + value*H = C_pseudo when
            // values balance with the fee).
            pricoin::ct::BlindingFactor dest_blind;
            GetRandBytes(dest_blind);
            auto change_blind = pricoin::ct::BalancingBlind(
                std::array<pricoin::ct::BlindingFactor, 1>{pseudo_blind},
                std::array<pricoin::ct::BlindingFactor, 1>{dest_blind});
            if (!change_blind) throw JSONRPCError(RPC_INTERNAL_ERROR, "blind sum failed");

            auto dest_commit = pricoin::ct::Commitment::Create(static_cast<uint64_t>(dest_amount), dest_blind);
            auto change_commit = pricoin::ct::Commitment::Create(static_cast<uint64_t>(change_value), *change_blind);
            if (!dest_commit || !change_commit) throw JSONRPCError(RPC_INTERNAL_ERROR, "output commit failed");

            std::vector<unsigned char> dest_spk_bytes(dest_spk.begin(), dest_spk.end());
            std::vector<unsigned char> change_spk_bytes(change_spk.begin(), change_spk.end());
            auto dest_proof = pricoin::ct::CreateRangeProof(
                static_cast<uint64_t>(dest_amount), dest_blind, *dest_commit,
                std::span<const unsigned char>{dest_spk_bytes}, dest_nonce);
            auto change_proof = pricoin::ct::CreateRangeProof(
                static_cast<uint64_t>(change_value), *change_blind, *change_commit,
                std::span<const unsigned char>{change_spk_bytes}, change_nonce);
            if (!dest_proof || !change_proof) throw JSONRPCError(RPC_INTERNAL_ERROR, "rangeproof failed");

            // 7. Construct the bundle with a ring input.
            pricoin::ct::CTRingInput ring_input;
            ring_input.ring.reserve(ring_size);
            for (const auto& m : ring) ring_input.ring.push_back(m.ref);
            ring_input.pseudo_commitment = *pseudo;

            pricoin::ct::CTBundle bundle;
            bundle.ring_inputs = {ring_input}; // sig filled in below
            bundle.outputs = {
                pricoin::ct::CTOutput{*dest_commit, *dest_proof, dest_spk_bytes, dest_R, dest_otp},
                pricoin::ct::CTOutput{*change_commit, *change_proof, change_spk_bytes, change_R, change_otp},
            };
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
            mtx.vout.emplace_back(0, dest_spk);
            mtx.vout.emplace_back(0, change_spk);
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

            // Scan blocks for ALL own CT outputs that aren't already spent
            // (KI not committed). Skip ones whose blind is dummy (zero — these
            // are transparent-input commitments, not recovered receives).
            // Then pick greedy biggest-first until the sum covers `target`.
            struct PickedCT { RecoveredOutput rec; COutPoint outpoint; };
            std::vector<PickedCT> candidates;
            const int tip = chain.getHeight().value_or(-1);
            for (int h = 0; h <= tip; ++h) {
                const uint256 block_hash = chain.getBlockHash(h);
                CBlock block;
                if (!chain.findBlock(block_hash, interfaces::FoundBlock().data(block))) continue;
                for (const auto& tx_ref : block.vtx) {
                    if (tx_ref->version != PRICOIN_CT_VERSION) continue;
                    for (uint32_t i = 0; i < tx_ref->vout.size(); ++i) {
                        auto rec = TryRecoverCTOutput(id, *tx_ref, i);
                        if (!rec) continue;
                        if (pricoin::IsKeyImageCommitted(rec->key_image)) continue;
                        candidates.push_back({std::move(*rec), COutPoint(tx_ref->GetHash(), i)});
                    }
                }
            }
            std::sort(candidates.begin(), candidates.end(),
                      [](const auto& a, const auto& b) { return a.rec.value > b.rec.value; });

            std::vector<PickedCT> picked_list;
            CAmount input_total = 0;
            for (auto& c : candidates) {
                input_total += c.rec.value;
                picked_list.push_back(std::move(c));
                if (input_total >= target) break;
            }
            if (input_total < target) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                    "Insufficient recovered CT outputs for dest_amount + fee");
            }

            // Build the destination output (stealth or transparent).
            const auto stealth_dest = ::pricoin::stealth::Decode(dest_addr_str);
            CScript dest_spk;
            ::pricoin::stealth::PointBytes dest_R{};
            ::pricoin::ct::BlindingFactor dest_nonce{};
            ::pricoin::ct::SerializedPubKey33 dest_otp{};
            if (stealth_dest) {
                CKey r; r.MakeNewKey(true);
                CPubKey R = r.GetPubKey();
                std::memcpy(dest_R.data(), R.data(), 33);
                auto S = ::pricoin::stealth::ECDHPoint(r, stealth_dest->view);
                if (!S) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth ECDH failed");
                auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, 0);
                auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, stealth_dest->spend);
                if (!P) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth onetime pubkey failed");
                dest_spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
                std::memcpy(dest_otp.data(), P->data(), 33);
                auto rp_nonce = ::pricoin::stealth::DeriveRangeProofNonce(*S, 0);
                std::memcpy(dest_nonce.data(), rp_nonce.data(), 32);
            } else {
                CTxDestination d = DecodeDestination(dest_addr_str);
                if (!IsValidDestination(d)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid dest_address");
                dest_spk = GetScriptForDestination(d);
                GetRandBytes(dest_nonce);
            }

            // Change always goes to our own stealth identity.
            CScript change_spk;
            ::pricoin::stealth::PointBytes change_R{};
            ::pricoin::ct::BlindingFactor change_nonce{};
            ::pricoin::ct::SerializedPubKey33 change_otp{};
            {
                CKey r; r.MakeNewKey(true);
                CPubKey R = r.GetPubKey();
                std::memcpy(change_R.data(), R.data(), 33);
                auto S = ::pricoin::stealth::ECDHPoint(r, id.public_address.view);
                if (!S) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth ECDH (change) failed");
                auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, 1);
                auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, id.public_address.spend);
                if (!P) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth onetime pubkey (change) failed");
                change_spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
                std::memcpy(change_otp.data(), P->data(), 33);
                auto rp_nonce = ::pricoin::stealth::DeriveRangeProofNonce(*S, 1);
                std::memcpy(change_nonce.data(), rp_nonce.data(), 32);
            }

            const CAmount change_value = input_total - target;

            // Build the bundle. Each input carries its real recovered blind.
            // BalancingBlind solves: Σ(input_blinds) = dest_blind + change_blind,
            // so change_blind = Σ(input_blinds) − dest_blind.
            std::vector<pricoin::ct::BlindingFactor> in_blinds;
            in_blinds.reserve(picked_list.size());
            for (const auto& p : picked_list) in_blinds.push_back(p.rec.blind);

            pricoin::ct::BlindingFactor dest_blind;
            GetRandBytes(dest_blind);
            auto change_blind = pricoin::ct::BalancingBlind(
                std::span<const pricoin::ct::BlindingFactor>{in_blinds},
                std::array<pricoin::ct::BlindingFactor, 1>{dest_blind});
            if (!change_blind) throw JSONRPCError(RPC_INTERNAL_ERROR, "blind sum failed");

            auto dest_commit = pricoin::ct::Commitment::Create(static_cast<uint64_t>(dest_amount), dest_blind);
            auto change_commit = pricoin::ct::Commitment::Create(static_cast<uint64_t>(change_value), *change_blind);
            if (!dest_commit || !change_commit) throw JSONRPCError(RPC_INTERNAL_ERROR, "output commit failed");

            std::vector<unsigned char> dest_spk_bytes(dest_spk.begin(), dest_spk.end());
            std::vector<unsigned char> change_spk_bytes(change_spk.begin(), change_spk.end());
            auto dest_proof = pricoin::ct::CreateRangeProof(
                static_cast<uint64_t>(dest_amount), dest_blind, *dest_commit,
                std::span<const unsigned char>{dest_spk_bytes}, dest_nonce);
            auto change_proof = pricoin::ct::CreateRangeProof(
                static_cast<uint64_t>(change_value), *change_blind, *change_commit,
                std::span<const unsigned char>{change_spk_bytes}, change_nonce);
            if (!dest_proof || !change_proof) throw JSONRPCError(RPC_INTERNAL_ERROR, "rangeproof failed");

            pricoin::ct::CTBundle bundle;
            bundle.input_commitments.reserve(picked_list.size());
            for (const auto& p : picked_list) bundle.input_commitments.push_back(p.rec.commitment);
            bundle.outputs = {
                pricoin::ct::CTOutput{*dest_commit, *dest_proof, dest_spk_bytes, dest_R, dest_otp},
                pricoin::ct::CTOutput{*change_commit, *change_proof, change_spk_bytes, change_R, change_otp},
            };
            bundle.transparent_fee = static_cast<uint64_t>(fee);

            CMutableTransaction mtx;
            mtx.version = PRICOIN_CT_VERSION;
            mtx.nLockTime = 0;
            for (const auto& p : picked_list) {
                mtx.vin.emplace_back(p.outpoint, CScript{}, 0xfffffffe);
            }
            mtx.vout.emplace_back(0, dest_spk);
            mtx.vout.emplace_back(0, change_spk);
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
} // namespace

RPCMethod pricoin_getstealthaddress_export() { return pricoin_getstealthaddress(); }
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
    const auto& id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
    interfaces::Chain& chain = wallet.chain();
    const int tip = chain.getHeight().value_or(-1);

    CAmount total = 0;
    for (int h = 0; h <= tip; ++h) {
        const uint256 block_hash = chain.getBlockHash(h);
        CBlock block;
        if (!chain.findBlock(block_hash, interfaces::FoundBlock().data(block))) continue;
        for (const auto& tx_ref : block.vtx) {
            if (tx_ref->version != PRICOIN_CT_VERSION) continue;
            for (uint32_t i = 0; i < tx_ref->vout.size(); ++i) {
                auto rec = TryRecoverCTOutput(id, *tx_ref, i);
                if (!rec) continue;
                // Phase 3a: spentness is the KI set, not chainstate erasure.
                if (pricoin::IsKeyImageCommitted(rec->key_image)) continue;
                total += rec->value;
            }
        }
    }
    return total;
}

} // namespace wallet
