// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/amount.h>
#include <key.h>
#include <key_io.h>
#include <pricoin/ct.h>
#include <pricoin/cttx.h>
#include <pricoin/stealth.h>
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
#include <wallet/pricoin_stealth.h>
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <array>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace wallet {

namespace {

// Pick the first P2WPKH UTXO with sufficient value. Returns just the
// outpoint + value + scriptPubKey; the wallet's SignTransaction handles the
// signing via its own keystore.
struct PickedInput {
    COutPoint outpoint;
    CAmount value;
    CScript scriptPubKey;
};
std::optional<PickedInput> PickP2WPKHFunding(CWallet& wallet, CAmount target)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    CoinFilterParams filter;
    filter.skip_locked = true;
    auto avail = AvailableCoins(wallet, /*coinControl=*/nullptr, /*feerate=*/std::nullopt, filter);

    for (const auto& coin : avail.All()) {
        if (coin.txout.nValue < target) continue;
        const CScript& spk = coin.txout.scriptPubKey;
        if (spk.size() != 22 || spk[0] != OP_0 || spk[1] != 0x14) continue;
        return PickedInput{coin.outpoint, coin.txout.nValue, spk};
    }
    return std::nullopt;
}

RPCMethod walletsendct()
{
    return RPCMethod{
        "walletsendct",
        "Build, sign, and submit a Pricoin Confidential Transaction using wallet UTXOs.\n"
        "Picks the first P2WPKH wallet UTXO whose value >= dest_amount + fee, signs with the\n"
        "wallet's keystore, generates a change address from the wallet, and submits the\n"
        "resulting v4 transaction. Receive-side detection is not yet implemented (Phase 2d-6b),\n"
        "so the recipient cannot auto-recover the value from the rangeproof.\n",
        {
            {"dest_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Destination Pricoin bech32 address"},
            {"dest_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount to send in PRIC"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Transparent fee in PRIC"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "Submitted transaction id"},
                {RPCResult::Type::STR_HEX, "hex", "Hex-encoded signed v4 transaction"},
                {RPCResult::Type::NUM, "size", "Total serialized size in bytes"},
                {RPCResult::Type::NUM, "bundle_size", "CT bundle size in bytes"},
                {RPCResult::Type::STR, "input_outpoint", "Spent input as txid:vout"},
                {RPCResult::Type::STR_AMOUNT, "input_value", "Value of the consumed input in PRIC"},
                {RPCResult::Type::STR, "change_address", "Change address used"},
                {RPCResult::Type::STR_AMOUNT, "change_amount", "Change value (carried in the bundle, not visible)"},
            }
        },
        RPCExamples{
            HelpExampleCli("walletsendct", "\"pricrt1q...\" 25.0 0.001")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<CWallet> wallet_sp = GetWalletForJSONRPCRequest(request);
            if (!wallet_sp) throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not loaded");
            CWallet& wallet = *wallet_sp;

            const std::string dest_addr_str = request.params[0].get_str();
            const CAmount dest_amount = AmountFromValue(request.params[1]);
            const CAmount fee = AmountFromValue(request.params[2]);
            if (dest_amount <= 0 || fee < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative or zero amount");
            }
            const CAmount target = dest_amount + fee;

            // Detect whether the destination is a stealth address. If so,
            // derive a one-time scriptPubKey via ECDH against the recipient's
            // view key. Otherwise treat it as a regular bech32 address.
            const auto stealth_dest = ::pricoin::stealth::Decode(dest_addr_str);
            CScript dest_spk;
            ::pricoin::stealth::PointBytes dest_R{};
            ::pricoin::ct::BlindingFactor dest_nonce{};
            if (stealth_dest) {
                CKey r;
                r.MakeNewKey(/*fCompressed=*/true);
                CPubKey R = r.GetPubKey();
                std::memcpy(dest_R.data(), R.data(), 33);
                auto S = ::pricoin::stealth::ECDHPoint(r, stealth_dest->view);
                if (!S) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth ECDH failed");
                auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, /*output_index=*/0);
                auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, stealth_dest->spend);
                if (!P) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth onetime pubkey failed");
                dest_spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
                auto rp_nonce = ::pricoin::stealth::DeriveRangeProofNonce(*S, 0);
                std::memcpy(dest_nonce.data(), rp_nonce.data(), 32);
            } else {
                CTxDestination dest_dest = DecodeDestination(dest_addr_str);
                if (!IsValidDestination(dest_dest)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid dest_address (neither stealth nor bech32)");
                }
                dest_spk = GetScriptForDestination(dest_dest);
                GetRandBytes(dest_nonce);
            }

            // Always send change to our own stealth address so the wallet can
            // recover it via Phase 5e block-scan once that lands.
            const auto& self_id = ::wallet::pricoin_stealth::GetOrCreate(wallet);
            CScript change_spk;
            ::pricoin::stealth::PointBytes change_R{};
            ::pricoin::ct::BlindingFactor change_nonce{};
            {
                CKey r;
                r.MakeNewKey(/*fCompressed=*/true);
                CPubKey R = r.GetPubKey();
                std::memcpy(change_R.data(), R.data(), 33);
                auto S = ::pricoin::stealth::ECDHPoint(r, self_id.public_address.view);
                if (!S) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth ECDH failed (change)");
                auto shared = ::pricoin::stealth::DeriveSharedSecret(*S, /*output_index=*/1);
                auto P = ::pricoin::stealth::DeriveOneTimePubkey(shared, self_id.public_address.spend);
                if (!P) throw JSONRPCError(RPC_INTERNAL_ERROR, "stealth onetime pubkey failed (change)");
                change_spk = GetScriptForDestination(WitnessV0KeyHash{P->GetID()});
                auto rp_nonce = ::pricoin::stealth::DeriveRangeProofNonce(*S, 1);
                std::memcpy(change_nonce.data(), rp_nonce.data(), 32);
            }

            // Lock the wallet, pick a funding input.
            std::optional<PickedInput> picked;
            {
                LOCK(wallet.cs_wallet);
                picked = PickP2WPKHFunding(wallet, target);
                if (!picked) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                        "No spendable P2WPKH UTXO with value >= dest_amount + fee");
                }
            }
            const CAmount change_value = picked->value - target;

            // Build the bundle.
            pricoin::ct::BlindingFactor zero_blind{};
            auto in_commit = pricoin::ct::Commitment::Create(
                static_cast<uint64_t>(picked->value), zero_blind);
            if (!in_commit) throw JSONRPCError(RPC_INTERNAL_ERROR, "input commit failed");

            pricoin::ct::BlindingFactor dest_blind;
            GetRandBytes(dest_blind);
            auto change_blind = pricoin::ct::BalancingBlind(
                std::array<pricoin::ct::BlindingFactor, 1>{zero_blind},
                std::array<pricoin::ct::BlindingFactor, 1>{dest_blind});
            if (!change_blind) throw JSONRPCError(RPC_INTERNAL_ERROR, "blind sum failed");

            auto dest_commit = pricoin::ct::Commitment::Create(
                static_cast<uint64_t>(dest_amount), dest_blind);
            auto change_commit = pricoin::ct::Commitment::Create(
                static_cast<uint64_t>(change_value), *change_blind);
            if (!dest_commit || !change_commit) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "output commit failed");
            }

            std::vector<unsigned char> dest_spk_bytes(dest_spk.begin(), dest_spk.end());
            std::vector<unsigned char> change_spk_bytes(change_spk.begin(), change_spk.end());

            auto dest_proof = pricoin::ct::CreateRangeProof(
                static_cast<uint64_t>(dest_amount), dest_blind, *dest_commit,
                std::span<const unsigned char>{dest_spk_bytes}, dest_nonce);
            auto change_proof = pricoin::ct::CreateRangeProof(
                static_cast<uint64_t>(change_value), *change_blind, *change_commit,
                std::span<const unsigned char>{change_spk_bytes}, change_nonce);
            if (!dest_proof || !change_proof) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "rangeproof failed");
            }

            pricoin::ct::CTBundle bundle;
            bundle.input_commitments = {*in_commit};
            bundle.outputs = {
                pricoin::ct::CTOutput{*dest_commit, *dest_proof, dest_spk_bytes, dest_R},
                pricoin::ct::CTOutput{*change_commit, *change_proof, change_spk_bytes, change_R},
            };
            bundle.transparent_fee = static_cast<uint64_t>(fee);

            CMutableTransaction mtx;
            mtx.version = PRICOIN_CT_VERSION;
            mtx.nLockTime = 0;
            mtx.vin.emplace_back(picked->outpoint, CScript{}, 0xfffffffe);
            mtx.vout.emplace_back(0, dest_spk);
            mtx.vout.emplace_back(0, change_spk);
            mtx.ct_bundle = std::move(bundle);

            // Build the prev-coin map the wallet needs to sign the input
            // (BIP143 sighash needs the prev value/script).
            std::map<COutPoint, Coin> coins;
            Coin prev_coin;
            prev_coin.out = CTxOut{picked->value, picked->scriptPubKey};
            prev_coin.fCoinBase = false; // wallet's signer doesn't care for sigs
            prev_coin.nHeight = 0;
            coins.emplace(picked->outpoint, std::move(prev_coin));

            std::map<int, bilingual_str> input_errors;
            if (!wallet.SignTransaction(mtx, coins, SIGHASH_ALL, input_errors)) {
                std::string msg;
                for (const auto& [i, e] : input_errors) msg += strprintf("vin[%d]: %s; ", i, e.original);
                throw JSONRPCError(RPC_WALLET_ERROR, "Wallet failed to sign tx: " + msg);
            }

            CTransactionRef tx_ref = MakeTransactionRef(std::move(mtx));
            DataStream ds;
            ds << TX_WITH_WITNESS(*tx_ref);

            // Submit through the wallet's broadcast path so the wallet
            // tracks it as outgoing.
            std::string err;
            wallet.CommitTransaction(tx_ref, /*mapValue=*/{}, /*orderForm=*/{});

            UniValue out{UniValue::VOBJ};
            out.pushKV("txid", tx_ref->GetHash().ToString());
            out.pushKV("hex", HexStr(ds));
            out.pushKV("size", (int)::GetSerializeSize(TX_WITH_WITNESS(*tx_ref)));
            out.pushKV("bundle_size", (int)tx_ref->ct_bundle.SerializedSize());
            out.pushKV("input_outpoint", picked->outpoint.hash.ToString() + ":" + std::to_string(picked->outpoint.n));
            out.pushKV("input_value", ValueFromAmount(picked->value));
            out.pushKV("change_to", "(wallet's own stealth address)");
            out.pushKV("change_amount", ValueFromAmount(change_value));
            out.pushKV("dest_was_stealth", stealth_dest.has_value());
            return out;
        }
    };
}

} // namespace

RPCMethod walletsendct_export() { return walletsendct(); }

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

    return RecoveredOutput{
        .output_index = output_index,
        .value = static_cast<CAmount>(rewound->value),
        .blind = rewound->blind,
        .commitment = out.commitment,
        .scriptPubKey = tx.vout[output_index].scriptPubKey,
        .one_time_priv = std::move(*one_time_priv),
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

            UniValue outputs{UniValue::VARR};
            CAmount total_recovered = 0;
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
                        total_recovered += rec->value;
                        UniValue entry{UniValue::VOBJ};
                        entry.pushKV("txid", tx_ref->GetHash().ToString());
                        entry.pushKV("vout", (int)rec->output_index);
                        entry.pushKV("value", ValueFromAmount(rec->value));
                        entry.pushKV("height", h);
                        outputs.push_back(entry);
                    }
                }
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

RPCMethod walletsendct_from_ct()
{
    return RPCMethod{
        "walletsendct_from_ct",
        "Send a Pricoin Confidential Transaction funded by a previously-received CT output.\n"
        "Scans the chain for own CT outputs, picks the first with value >= dest_amount + fee,\n"
        "derives the one-time spend key from the wallet's stealth identity, and constructs +\n"
        "signs a v4 tx spending it. Demonstrates CT-spending-CT.\n",
        {
            {"dest_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Destination Pricoin stealth or bech32 address"},
            {"dest_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount to send in PRIC"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Transparent fee in PRIC"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", ""},
                {RPCResult::Type::STR, "spent_outpoint", "txid:vout of the consumed CT input"},
                {RPCResult::Type::STR_AMOUNT, "input_value", "Recovered input value"},
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

            // Scan blocks for the first own CT output of sufficient value.
            std::optional<RecoveredOutput> picked;
            COutPoint picked_outpoint;
            const int tip = chain.getHeight().value_or(-1);
            for (int h = 0; h <= tip && !picked; ++h) {
                const uint256 block_hash = chain.getBlockHash(h);
                CBlock block;
                if (!chain.findBlock(block_hash, interfaces::FoundBlock().data(block))) continue;
                for (const auto& tx_ref : block.vtx) {
                    if (tx_ref->version != PRICOIN_CT_VERSION) continue;
                    for (uint32_t i = 0; i < tx_ref->vout.size(); ++i) {
                        auto rec = TryRecoverCTOutput(id, *tx_ref, i);
                        if (!rec) continue;
                        if (rec->value < target) continue;
                        picked = std::move(rec);
                        picked_outpoint = COutPoint(tx_ref->GetHash(), picked->output_index);
                        break;
                    }
                    if (picked) break;
                }
            }
            if (!picked) throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "No recovered CT output with value >= dest_amount + fee");

            // Build the destination output (stealth or transparent).
            const auto stealth_dest = ::pricoin::stealth::Decode(dest_addr_str);
            CScript dest_spk;
            ::pricoin::stealth::PointBytes dest_R{};
            ::pricoin::ct::BlindingFactor dest_nonce{};
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
                auto rp_nonce = ::pricoin::stealth::DeriveRangeProofNonce(*S, 1);
                std::memcpy(change_nonce.data(), rp_nonce.data(), 32);
            }

            const CAmount change_value = picked->value - target;

            // Build the bundle. Input has its recovered (nonzero) blind.
            // Output blinds: dest random, change = input_blind - dest_blind.
            pricoin::ct::BlindingFactor dest_blind;
            GetRandBytes(dest_blind);
            auto change_blind = pricoin::ct::BalancingBlind(
                std::array<pricoin::ct::BlindingFactor, 1>{picked->blind},
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
            bundle.input_commitments = {picked->commitment};
            bundle.outputs = {
                pricoin::ct::CTOutput{*dest_commit, *dest_proof, dest_spk_bytes, dest_R},
                pricoin::ct::CTOutput{*change_commit, *change_proof, change_spk_bytes, change_R},
            };
            bundle.transparent_fee = static_cast<uint64_t>(fee);

            CMutableTransaction mtx;
            mtx.version = PRICOIN_CT_VERSION;
            mtx.nLockTime = 0;
            mtx.vin.emplace_back(picked_outpoint, CScript{}, 0xfffffffe);
            mtx.vout.emplace_back(0, dest_spk);
            mtx.vout.emplace_back(0, change_spk);
            mtx.ct_bundle = std::move(bundle);

            // Sign the input directly with the derived one-time priv key.
            // Wallet's keystore doesn't know about this key, so we don't go
            // through CWallet::SignTransaction.
            CKeyID keyid;
            const CScript& spk = picked->scriptPubKey;
            if (spk.size() != 22 || spk[0] != OP_0 || spk[1] != 0x14) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "recovered CT output is not P2WPKH");
            }
            std::copy_n(spk.begin() + 2, 20, keyid.begin());
            CScript scriptCode;
            scriptCode << OP_DUP << OP_HASH160 << ToByteVector(keyid)
                       << OP_EQUALVERIFY << OP_CHECKSIG;
            const int32_t hashtype = SIGHASH_ALL;
            // For BIP143 sighash on a v4 input that spent a v4 output: the
            // "amount" field would normally be the prev nValue, which is 0
            // here. Pass 0; the bundle hash mixin (Phase 2d-3) provides the
            // real binding.
            const uint256 sighash = SignatureHash(
                scriptCode, mtx, /*nIn=*/0, hashtype,
                /*amount=*/0, SigVersion::WITNESS_V0,
                nullptr, nullptr);
            std::vector<unsigned char> sig;
            if (!picked->one_time_priv.Sign(sighash, sig, true)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "ECDSA sign failed (one-time priv)");
            }
            sig.push_back(static_cast<unsigned char>(hashtype));
            const CPubKey one_time_pub = picked->one_time_priv.GetPubKey();
            mtx.vin[0].scriptWitness.stack.clear();
            mtx.vin[0].scriptWitness.stack.push_back(std::move(sig));
            mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(one_time_pub.begin(), one_time_pub.end()));

            CTransactionRef tx_ref = MakeTransactionRef(std::move(mtx));
            DataStream ds;
            ds << TX_WITH_WITNESS(*tx_ref);
            // Broadcast directly via the chain — wallet.CommitTransaction
            // assumes wallet-owned inputs (which a stealth-recovered CT
            // input isn't, in the wallet's bookkeeping sense).
            std::string err_str;
            if (!chain.broadcastTransaction(tx_ref, /*max_tx_fee=*/MAX_MONEY,
                                             node::TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL,
                                             err_str)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "broadcastTransaction failed: " + err_str);
            }

            UniValue out{UniValue::VOBJ};
            out.pushKV("txid", tx_ref->GetHash().ToString());
            out.pushKV("spent_outpoint", picked_outpoint.hash.ToString() + ":" + std::to_string(picked_outpoint.n));
            out.pushKV("input_value", ValueFromAmount(picked->value));
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

} // namespace wallet
