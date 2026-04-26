// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <key.h>
#include <key_io.h>
#include <node/context.h>
#include <pricoin/ct.h>
#include <pricoin/cttx.h>
#include <primitives/transaction.h>
#include <random.h>
#include <rpc/register.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <streams.h>
#include <txmempool.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <validation.h>

#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {

// Build the scriptCode that BIP143 v0 requires for signing a P2WPKH input.
//   OP_DUP OP_HASH160 <20-byte pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG
CScript P2WPKHScriptCode(const CKeyID& keyid)
{
    CScript code;
    code << OP_DUP << OP_HASH160 << ToByteVector(keyid)
         << OP_EQUALVERIFY << OP_CHECKSIG;
    return code;
}

RPCMethod pricoin_ct_send()
{
    return RPCMethod{
        "pricoin_ct_send",
        "Build, sign, and return a hex-encoded Pricoin Confidential Transaction (tx version 4)\n"
        "spending one P2WPKH transparent input into two confidential outputs (destination + change).\n"
        "Two outputs are required because a single CT output cannot balance against a zero-blind\n"
        "transparent input — see Pedersen commitment math in src/pricoin/cttx.cpp.\n"
        "The returned hex can be submitted via sendrawtransaction.\n",
        {
            {"input_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Prev tx id of the input"},
            {"input_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Prev vout index"},
            {"input_wif", RPCArg::Type::STR, RPCArg::Optional::NO, "WIF private key for the input's P2WPKH"},
            {"dest_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Pricoin bech32 destination (any P2WPKH/P2WSH)"},
            {"dest_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Destination amount in PRIC"},
            {"change_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Pricoin bech32 address for change/balancing output"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Cleartext transparent fee in PRIC"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "Hex-encoded signed v4 transaction"},
                {RPCResult::Type::STR_HEX, "txid", "Transaction id (SHA-256d of the tx, no witness)"},
                {RPCResult::Type::NUM, "size", "Total serialized size in bytes (with witness, with bundle)"},
                {RPCResult::Type::NUM, "bundle_size", "Bundle size in bytes"},
            }
        },
        RPCExamples{
            HelpExampleCli("pricoin_ct_send",
                "\"abc...\" 0 \"cTk...\" \"pricrt1q...\" 25.0 \"pricrt1q...\" 0.0001")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue {
            const std::string txid_hex = request.params[0].get_str();
            const int vout_idx = request.params[1].getInt<int>();
            const std::string wif = request.params[2].get_str();
            const std::string dest_addr = request.params[3].get_str();
            const CAmount dest_amount = AmountFromValue(request.params[4]);
            const std::string change_addr = request.params[5].get_str();
            const CAmount fee = AmountFromValue(request.params[6]);

            auto txid_opt = uint256::FromHex(txid_hex);
            if (!txid_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid input_txid");
            }
            const COutPoint prevout{Txid::FromUint256(*txid_opt), static_cast<uint32_t>(vout_idx)};

            // Look up prev coin to learn its value and scriptPubKey.
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            std::optional<Coin> coin_opt;
            {
                LOCK(cs_main);
                coin_opt = chainman.ActiveChainstate().CoinsTip().GetCoin(prevout);
            }
            if (!coin_opt) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Input outpoint not in current UTXO set");
            }
            const Coin& coin = *coin_opt;
            if (coin.IsSpent()) throw JSONRPCError(RPC_INVALID_PARAMETER, "Input is already spent");
            if (coin.out.nValue <= 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Phase 2d: only transparent prev outputs supported");
            }
            const CAmount input_value = coin.out.nValue;
            const CAmount change_value = input_value - dest_amount - fee;
            if (change_value < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "input_value < dest_amount + fee");
            }
            if (dest_amount < 0 || fee < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative amount or fee");
            }

            // Decode WIF and confirm pubkey hash matches the prev script.
            CKey key = DecodeSecret(wif);
            if (!key.IsValid()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid WIF");
            const CPubKey pubkey = key.GetPubKey();
            const CKeyID keyid = pubkey.GetID();
            const CScript expected_p2wpkh = CScript() << OP_0 << ToByteVector(keyid);
            if (coin.out.scriptPubKey != expected_p2wpkh) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "WIF does not unlock this prev output (must be P2WPKH for the WIF's pubkey)");
            }

            auto script_for_addr = [](const std::string& a, const char* name) {
                CTxDestination d = DecodeDestination(a);
                if (!IsValidDestination(d)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid ") + name);
                }
                return GetScriptForDestination(d);
            };
            const CScript dest_spk = script_for_addr(dest_addr, "dest_address");
            const CScript change_spk = script_for_addr(change_addr, "change_address");

            // Build the CT bundle.
            // Inputs: one transparent prev output → Commit(input_value, blind=0).
            pricoin::ct::BlindingFactor zero_blind{};
            auto in_commit = pricoin::ct::Commitment::Create(static_cast<uint64_t>(input_value), zero_blind);
            if (!in_commit) throw JSONRPCError(RPC_INTERNAL_ERROR, "input commit failed");

            // Outputs: dest gets a random blind; change blind is derived to balance.
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

            // Build the mutable tx.
            CMutableTransaction mtx;
            mtx.version = PRICOIN_CT_VERSION;
            mtx.nLockTime = 0;
            mtx.vin.emplace_back(prevout, CScript{}, /*nSequence=*/0xfffffffe);
            mtx.vout.emplace_back(0, dest_spk);
            mtx.vout.emplace_back(0, change_spk);
            mtx.ct_bundle = std::move(bundle);

            // Sign the input. Only P2WPKH supported for now: scriptCode is the
            // implicit P2PKH for the same pubkey hash. The sighash includes the
            // bundle hash (added by the v4 path in script/interpreter.cpp).
            const CScript scriptCode = P2WPKHScriptCode(keyid);
            const int32_t hashtype = SIGHASH_ALL;
            const uint256 sighash = SignatureHash(
                scriptCode, mtx, /*nIn=*/0, hashtype,
                input_value, SigVersion::WITNESS_V0,
                /*cache=*/nullptr, /*sighash_cache=*/nullptr);

            std::vector<unsigned char> sig;
            if (!key.Sign(sighash, sig, /*grind=*/true)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "ECDSA signing failed");
            }
            sig.push_back(static_cast<unsigned char>(hashtype));

            // Witness: <signature> <pubkey>
            mtx.vin[0].scriptWitness.stack.clear();
            mtx.vin[0].scriptWitness.stack.push_back(std::move(sig));
            mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(pubkey.begin(), pubkey.end()));

            // Serialize and report.
            CTransaction tx{std::move(mtx)};
            DataStream ds;
            ds << TX_WITH_WITNESS(tx);
            UniValue out{UniValue::VOBJ};
            out.pushKV("hex", HexStr(ds));
            out.pushKV("txid", tx.GetHash().ToString());
            out.pushKV("size", (int)::GetSerializeSize(TX_WITH_WITNESS(tx)));
            out.pushKV("bundle_size", (int)tx.ct_bundle.SerializedSize());
            return out;
        }
    };
}

} // namespace

void RegisterPricoinCTRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"pricoin", &pricoin_ct_send},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
