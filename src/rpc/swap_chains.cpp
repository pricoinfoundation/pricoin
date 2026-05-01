// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/register.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <swap/chain_backend.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <memory>
#include <string>

// Atomic-swap stage: chainwatch RPCs. Thin shells around the
// process-level ChainBackend registry — query the foreign chain
// (BTC, LTC, ...) for tip height, tx status, address history, or
// broadcast a tx. Backends are registered at init time from the
// -btcwatchurl / -ltcwatchurl / -chainwatchurl=<chain>=<url> args.

namespace {

std::shared_ptr<pricoin::swap::ChainBackend> RequireBackend(const std::string& chain)
{
    auto b = pricoin::swap::GetBackend(chain);
    if (!b) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "No chainwatch backend registered for '" + chain
            + "'. Configure -" + chain + "watchurl=<URL> or -chainwatchurl="
            + chain + "=<URL>.");
    }
    return b;
}

UniValue TxStatusToJSON(const pricoin::swap::TxStatus& s)
{
    UniValue out{UniValue::VOBJ};
    out.pushKV("confirmed", s.confirmed);
    if (s.confirmed) {
        out.pushKV("block_height", s.block_height);
        if (!s.block_hash.empty()) out.pushKV("block_hash", s.block_hash);
        if (s.block_time > 0) out.pushKV("block_time", s.block_time);
    }
    return out;
}

RPCMethod pricoin_chainwatch_list()
{
    return RPCMethod{
        "pricoin_chainwatch_list",
        "List all chainwatch backends currently registered with this node.\n",
        {},
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {{RPCResult::Type::STR, "chain", "Symbolic chain name (btc, ltc, ...)"}}
        },
        RPCExamples{HelpExampleCli("pricoin_chainwatch_list", "")},
        [](const RPCMethod&, const JSONRPCRequest&) -> UniValue {
            UniValue out{UniValue::VARR};
            for (const auto& name : pricoin::swap::ListBackendNames()) {
                out.push_back(name);
            }
            return out;
        }
    };
}

RPCMethod pricoin_chainwatch_height()
{
    return RPCMethod{
        "pricoin_chainwatch_height",
        "Return the foreign chain's tip height as reported by the registered\n"
        "backend. Failure modes: no backend (check -<chain>watchurl), HTTP\n"
        "error reaching the backend, malformed response.\n",
        {{"chain", RPCArg::Type::STR, RPCArg::Optional::NO, "Symbolic chain name (btc, ltc, ...)"}},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::NUM, "height", ""}}
        },
        RPCExamples{HelpExampleCli("pricoin_chainwatch_height", "btc")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            const std::string chain = request.params[0].get_str();
            auto backend = RequireBackend(chain);
            try {
                const int h = backend->GetTipHeight();
                UniValue out{UniValue::VOBJ};
                out.pushKV("height", h);
                return out;
            } catch (const pricoin::swap::ChainBackendError& e) {
                throw JSONRPCError(RPC_MISC_ERROR, e.what());
            }
        }
    };
}

RPCMethod pricoin_chainwatch_get_tx()
{
    return RPCMethod{
        "pricoin_chainwatch_get_tx",
        "Return the foreign chain's tx hex + confirmation status. Useful for\n"
        "verifying a counterparty's HTLC funding tx is mined to a sufficient\n"
        "depth before completing the PRIC-side leg of an atomic swap.\n",
        {
            {"chain", RPCArg::Type::STR, RPCArg::Optional::NO, ""},
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "Raw tx as hex"},
                {RPCResult::Type::OBJ, "status", "",
                    {
                        {RPCResult::Type::BOOL, "confirmed", ""},
                        {RPCResult::Type::NUM, "block_height", /*optional=*/true, ""},
                        {RPCResult::Type::STR_HEX, "block_hash", /*optional=*/true, ""},
                        {RPCResult::Type::NUM, "block_time", /*optional=*/true, ""},
                    }},
            }
        },
        RPCExamples{HelpExampleCli("pricoin_chainwatch_get_tx", "btc <txid>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            const std::string chain = request.params[0].get_str();
            const std::string txid = request.params[1].get_str();
            auto backend = RequireBackend(chain);
            try {
                const std::string hex = backend->GetTxHex(txid);
                const auto status = backend->GetTxStatus(txid);
                UniValue out{UniValue::VOBJ};
                out.pushKV("hex", hex);
                out.pushKV("status", TxStatusToJSON(status));
                return out;
            } catch (const pricoin::swap::ChainBackendError& e) {
                throw JSONRPCError(RPC_MISC_ERROR, e.what());
            }
        }
    };
}

RPCMethod pricoin_chainwatch_address_txs()
{
    return RPCMethod{
        "pricoin_chainwatch_address_txs",
        "List recent txs touching the given foreign-chain address, with\n"
        "confirmation state and value-paid-into-this-address per tx.\n"
        "\n"
        "Used at swap time to verify that a counterparty's HTLC funding\n"
        "tx exists, is sufficiently confirmed, and pays the expected\n"
        "amount.\n",
        {
            {"chain", RPCArg::Type::STR, RPCArg::Optional::NO, ""},
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO,
                "Foreign-chain address (base58 / bech32 / etc., backend-specific)"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {{RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "txid", ""},
                    {RPCResult::Type::OBJ, "status", "", {
                        {RPCResult::Type::BOOL, "confirmed", ""},
                        {RPCResult::Type::NUM, "block_height", /*optional=*/true, ""},
                        {RPCResult::Type::STR_HEX, "block_hash", /*optional=*/true, ""},
                        {RPCResult::Type::NUM, "block_time", /*optional=*/true, ""},
                    }},
                    {RPCResult::Type::NUM, "value_received_sat",
                        "Sum of vout values paying this address, in satoshis"},
                }}}
        },
        RPCExamples{HelpExampleCli("pricoin_chainwatch_address_txs", "btc bc1q...")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            const std::string chain = request.params[0].get_str();
            const std::string address = request.params[1].get_str();
            auto backend = RequireBackend(chain);
            try {
                const auto txs = backend->GetAddressTxs(address);
                UniValue out{UniValue::VARR};
                for (const auto& t : txs) {
                    UniValue row{UniValue::VOBJ};
                    row.pushKV("txid", t.txid);
                    row.pushKV("status", TxStatusToJSON(t.status));
                    row.pushKV("value_received_sat", t.value_received_sat);
                    out.push_back(std::move(row));
                }
                return out;
            } catch (const pricoin::swap::ChainBackendError& e) {
                throw JSONRPCError(RPC_MISC_ERROR, e.what());
            }
        }
    };
}

RPCMethod pricoin_chainwatch_broadcast()
{
    return RPCMethod{
        "pricoin_chainwatch_broadcast",
        "Submit a hex-encoded foreign-chain tx for relay via the registered\n"
        "backend. Returns the txid the backend accepted.\n",
        {
            {"chain", RPCArg::Type::STR, RPCArg::Optional::NO, ""},
            {"tx_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, ""},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {{RPCResult::Type::STR_HEX, "txid", "Txid as returned by the backend"}}
        },
        RPCExamples{HelpExampleCli("pricoin_chainwatch_broadcast", "btc <hex>")},
        [](const RPCMethod&, const JSONRPCRequest& request) -> UniValue {
            const std::string chain = request.params[0].get_str();
            const std::string tx_hex = request.params[1].get_str();
            auto backend = RequireBackend(chain);
            try {
                const std::string txid = backend->Broadcast(tx_hex);
                UniValue out{UniValue::VOBJ};
                out.pushKV("txid", txid);
                return out;
            } catch (const pricoin::swap::ChainBackendError& e) {
                throw JSONRPCError(RPC_MISC_ERROR, e.what());
            }
        }
    };
}

} // namespace

void RegisterPricoinChainwatchRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"pricoin", &pricoin_chainwatch_list},
        {"pricoin", &pricoin_chainwatch_height},
        {"pricoin", &pricoin_chainwatch_get_tx},
        {"pricoin", &pricoin_chainwatch_address_txs},
        {"pricoin", &pricoin_chainwatch_broadcast},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
