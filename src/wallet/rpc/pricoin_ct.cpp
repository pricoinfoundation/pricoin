// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <consensus/amount.h>
#include <key.h>
#include <key_io.h>
#include <pricoin/ct.h>
#include <pricoin/cttx.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <random.h>
#include <rpc/server.h>
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
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <array>
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

            CTxDestination dest_dest = DecodeDestination(dest_addr_str);
            if (!IsValidDestination(dest_dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid dest_address");
            }
            const CScript dest_spk = GetScriptForDestination(dest_dest);

            // Lock the wallet, pick a funding input, and grab a fresh change address.
            std::optional<PickedInput> picked;
            CTxDestination change_dest;
            {
                LOCK(wallet.cs_wallet);
                picked = PickP2WPKHFunding(wallet, target);
                if (!picked) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                        "No spendable P2WPKH UTXO with value >= dest_amount + fee");
                }
                auto change_res = wallet.GetNewChangeDestination(OutputType::BECH32);
                if (!change_res) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to allocate change address");
                }
                change_dest = *change_res;
            }
            const CScript change_spk = GetScriptForDestination(change_dest);
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

            pricoin::ct::BlindingFactor nonce_dest, nonce_change;
            GetRandBytes(nonce_dest);
            GetRandBytes(nonce_change);
            auto dest_proof = pricoin::ct::CreateRangeProof(
                static_cast<uint64_t>(dest_amount), dest_blind, *dest_commit,
                std::span<const unsigned char>{dest_spk_bytes}, nonce_dest);
            auto change_proof = pricoin::ct::CreateRangeProof(
                static_cast<uint64_t>(change_value), *change_blind, *change_commit,
                std::span<const unsigned char>{change_spk_bytes}, nonce_change);
            if (!dest_proof || !change_proof) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "rangeproof failed");
            }

            pricoin::ct::CTBundle bundle;
            bundle.input_commitments = {*in_commit};
            bundle.outputs = {
                pricoin::ct::CTOutput{*dest_commit, *dest_proof, dest_spk_bytes},
                pricoin::ct::CTOutput{*change_commit, *change_proof, change_spk_bytes},
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
            out.pushKV("change_address", EncodeDestination(change_dest));
            out.pushKV("change_amount", ValueFromAmount(change_value));
            return out;
        }
    };
}

} // namespace

RPCMethod walletsendct_export() { return walletsendct(); }

} // namespace wallet
