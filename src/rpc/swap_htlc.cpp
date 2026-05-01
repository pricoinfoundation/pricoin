// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <key.h>
#include <key_io.h>
#include <pubkey.h>
#include <rpc/register.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/script.h>
#include <swap/btc_htlc.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <string>

// Atomic-swap stage 3 — Bitcoin-style HTLC primitives exposed as
// stateless RPCs. Used to construct the foreign-chain leg of a
// BTC ↔ PRIC (or LTC ↔ PRIC, etc.) swap.
//
// IMPORTANT: these RPCs do NOT make a swap atomic by themselves.
// Atomicity requires the PRIC-side spend to be cryptographically
// linked to the BTC preimage reveal — that's adaptor-CLSAG, gated
// on external review and NOT implemented in this commit. See
// doc/atomic-swap-protocol.md, Q5.

namespace btc_htlc = pricoin::swap::btc_htlc;

namespace {

btc_htlc::Network ParseNetwork(const std::string& s)
{
    if (s == "btc-mainnet"  || s == "bitcoin")        return btc_htlc::Network::BitcoinMainnet;
    if (s == "btc-testnet"  || s == "bitcoin-test")   return btc_htlc::Network::BitcoinTestnet;
    if (s == "btc-regtest"  || s == "bitcoin-regtest")return btc_htlc::Network::BitcoinRegtest;
    if (s == "ltc-mainnet"  || s == "litecoin")       return btc_htlc::Network::LitecoinMainnet;
    if (s == "ltc-testnet"  || s == "litecoin-test")  return btc_htlc::Network::LitecoinTestnet;
    if (s == "ltc-regtest"  || s == "litecoin-regtest") return btc_htlc::Network::LitecoinRegtest;
    if (s == "pric-regtest" || s == "pricoin-regtest") return btc_htlc::Network::PricoinRegtest;
    if (s == "pric-mainnet" || s == "pricoin")        return btc_htlc::Network::PricoinMainnet;
    throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown network: " + s
        + " (expected btc-mainnet|btc-testnet|btc-regtest|ltc-mainnet|ltc-testnet|ltc-regtest|pric-mainnet|pric-regtest)");
}

CPubKey ParseCompressedPubkey(const std::string& hex, const char* name)
{
    if (!IsHex(hex) || hex.size() != 66) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            std::string(name) + " must be 33-byte compressed pubkey hex");
    }
    auto bytes = ParseHex(hex);
    CPubKey pub{std::span<const unsigned char>{bytes.data(), bytes.size()}};
    if (!pub.IsValid() || !pub.IsCompressed()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            std::string(name) + " is not a valid compressed pubkey");
    }
    return pub;
}

std::vector<unsigned char> ParseHex32(const std::string& hex, const char* name)
{
    if (!IsHex(hex) || hex.size() != 64) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            std::string(name) + " must be 32-byte hex");
    }
    return ParseHex(hex);
}

CScript ParseScriptHex(const std::string& hex, const char* name)
{
    if (!IsHex(hex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            std::string(name) + " must be hex");
    }
    auto bytes = ParseHex(hex);
    return CScript(bytes.begin(), bytes.end());
}

RPCMethod pricoin_btc_htlc_address()
{
    return RPCMethod{
        "pricoin_btc_htlc_address",
        "Build a Bitcoin-style HTLC redeem script and its P2WSH address.\n"
        "\n"
        "Redeem script:\n"
        "  OP_IF OP_SHA256 <hash> OP_EQUALVERIFY <recipient_pub> OP_CHECKSIG\n"
        "  OP_ELSE <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <sender_pub> OP_CHECKSIG\n"
        "  OP_ENDIF\n"
        "\n"
        "Recipient claims with [sig <preimage> 1]; sender refunds with [sig 0]\n"
        "after nLockTime ≥ timeout. Hash function is SHA-256 (matches Lightning).\n"
        "\n"
        "WARNING: this primitive on its own does NOT make a cross-chain swap atomic.\n"
        "Without adaptor-CLSAG (deferred — see doc/atomic-swap-protocol.md) the\n"
        "PRIC-side spend cannot be cryptographically linked to the BTC preimage\n"
        "reveal. Use only with trusted counterparties or alongside a slashing-\n"
        "deposit mechanism.\n",
        {
            {"preimage_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "32-byte SHA-256 of the preimage"},
            {"recipient_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "33-byte compressed pubkey of the party who claims via preimage"},
            {"sender_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "33-byte compressed pubkey of the party who refunds after timelock"},
            {"timeout", RPCArg::Type::NUM, RPCArg::Optional::NO,
                "Block height (< 500000000) or unix time (≥ 500000000) — passed to OP_CLTV"},
            {"network", RPCArg::Type::STR, RPCArg::Optional::NO,
                "btc-mainnet | btc-testnet | btc-regtest | ltc-mainnet | ltc-testnet | "
                "ltc-regtest | pric-mainnet | pric-regtest"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "P2WSH bech32 address"},
                {RPCResult::Type::STR_HEX, "redeem_script", "Hex of the redeem script"},
                {RPCResult::Type::STR_HEX, "script_pubkey",
                    "Hex of OP_0 <SHA256(redeem)>; what the funding tx's vout must contain"},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_btc_htlc_address",
            "<preimage_hash> <recipient_pub> <sender_pub> 800000 btc-mainnet")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            const auto preimage_hash = ParseHex32(request.params[0].get_str(), "preimage_hash");
            const auto recipient_pub = ParseCompressedPubkey(request.params[1].get_str(), "recipient_pubkey");
            const auto sender_pub    = ParseCompressedPubkey(request.params[2].get_str(), "sender_pubkey");
            const int64_t timeout    = request.params[3].getInt<int64_t>();
            const auto net           = ParseNetwork(request.params[4].get_str());

            try {
                CScript redeem = btc_htlc::BuildHTLCScript(
                    std::span<const unsigned char>{preimage_hash}, recipient_pub, sender_pub, timeout);
                std::string addr = btc_htlc::BuildHTLCBech32Address(redeem, net);
                CScript spk = btc_htlc::BuildHTLCScriptPubKey(redeem);

                UniValue out{UniValue::VOBJ};
                out.pushKV("address", addr);
                out.pushKV("redeem_script", HexStr(redeem));
                out.pushKV("script_pubkey", HexStr(spk));
                return out;
            } catch (const btc_htlc::HTLCError& e) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, e.what());
            }
        }
    };
}

RPCMethod pricoin_btc_htlc_build_claim()
{
    return RPCMethod{
        "pricoin_btc_htlc_build_claim",
        "Build a signed claim tx that spends an HTLC funding using the\n"
        "preimage. Caller broadcasts via pricoin_chainwatch_broadcast.\n",
        {
            {"funding_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"funding_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, ""},
            {"funding_value_sat", RPCArg::Type::NUM, RPCArg::Optional::NO,
                "Value of the HTLC funding output, in satoshis"},
            {"redeem_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"preimage", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "32-byte hex"},
            {"recipient_wif", RPCArg::Type::STR, RPCArg::Optional::NO,
                "WIF-encoded recipient privkey (matches recipient_pubkey in the redeem script)"},
            {"dest_script_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
                "scriptPubKey to receive the claimed funds"},
            {"fee_sat", RPCArg::Type::NUM, RPCArg::Optional::NO, "Miner fee in satoshis"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "tx_hex", "Signed tx hex, ready to broadcast"}}
        },
        RPCExamples{HelpExampleCli("pricoin_btc_htlc_build_claim", "<args>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            btc_htlc::HTLCFunding f;
            const auto txid_opt = uint256::FromHex(request.params[0].get_str());
            if (!txid_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "funding_txid not 32-byte hex");
            f.prev_txid = *txid_opt;
            f.prev_vout = request.params[1].getInt<uint32_t>();
            f.prev_value = static_cast<CAmount>(request.params[2].getInt<int64_t>());
            f.redeem_script = ParseScriptHex(request.params[3].get_str(), "redeem_script");

            const auto preimage = ParseHex32(request.params[4].get_str(), "preimage");

            const std::string wif = request.params[5].get_str();
            CKey priv = DecodeSecret(wif);
            if (!priv.IsValid()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid recipient_wif");

            CScript dest = ParseScriptHex(request.params[6].get_str(), "dest_script_hex");
            const CAmount fee = static_cast<CAmount>(request.params[7].getInt<int64_t>());

            try {
                auto tx_bytes = btc_htlc::BuildClaimTx(
                    f, std::span<const unsigned char>{preimage}, priv, dest, fee);
                UniValue out{UniValue::VOBJ};
                out.pushKV("tx_hex", HexStr(tx_bytes));
                return out;
            } catch (const btc_htlc::HTLCError& e) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, e.what());
            }
        }
    };
}

RPCMethod pricoin_btc_htlc_build_refund()
{
    return RPCMethod{
        "pricoin_btc_htlc_build_refund",
        "Build a signed refund tx that spends an HTLC funding back to the sender\n"
        "after the timelock. Sets nLockTime = timeout; caller broadcasts after\n"
        "the chain reaches that height/time.\n",
        {
            {"funding_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"funding_vout", RPCArg::Type::NUM, RPCArg::Optional::NO, ""},
            {"funding_value_sat", RPCArg::Type::NUM, RPCArg::Optional::NO, ""},
            {"redeem_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"timeout", RPCArg::Type::NUM, RPCArg::Optional::NO,
                "Same timeout as in the redeem script (set as nLockTime)"},
            {"sender_wif", RPCArg::Type::STR, RPCArg::Optional::NO,
                "WIF-encoded sender privkey"},
            {"dest_script_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
            {"fee_sat", RPCArg::Type::NUM, RPCArg::Optional::NO, ""},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "tx_hex", ""}}
        },
        RPCExamples{HelpExampleCli("pricoin_btc_htlc_build_refund", "<args>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            btc_htlc::HTLCFunding f;
            const auto txid_opt = uint256::FromHex(request.params[0].get_str());
            if (!txid_opt) throw JSONRPCError(RPC_INVALID_PARAMETER, "funding_txid not 32-byte hex");
            f.prev_txid = *txid_opt;
            f.prev_vout = request.params[1].getInt<uint32_t>();
            f.prev_value = static_cast<CAmount>(request.params[2].getInt<int64_t>());
            f.redeem_script = ParseScriptHex(request.params[3].get_str(), "redeem_script");
            const int64_t timeout = request.params[4].getInt<int64_t>();

            const std::string wif = request.params[5].get_str();
            CKey priv = DecodeSecret(wif);
            if (!priv.IsValid()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid sender_wif");

            CScript dest = ParseScriptHex(request.params[6].get_str(), "dest_script_hex");
            const CAmount fee = static_cast<CAmount>(request.params[7].getInt<int64_t>());

            try {
                auto tx_bytes = btc_htlc::BuildRefundTx(f, timeout, priv, dest, fee);
                UniValue out{UniValue::VOBJ};
                out.pushKV("tx_hex", HexStr(tx_bytes));
                return out;
            } catch (const btc_htlc::HTLCError& e) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, e.what());
            }
        }
    };
}

} // namespace

void RegisterPricoinHTLCRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"pricoin", &pricoin_btc_htlc_address},
        {"pricoin", &pricoin_btc_htlc_build_claim},
        {"pricoin", &pricoin_btc_htlc_build_refund},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
