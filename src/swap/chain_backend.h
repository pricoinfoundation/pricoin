// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SWAP_CHAIN_BACKEND_H
#define BITCOIN_SWAP_CHAIN_BACKEND_H

#include <cstdint>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

// Phase-2 atomic-swap plumbing — abstract "watch a foreign UTXO chain"
// backend interface used by the cross-chain swap protocol when one
// leg of a swap is on BTC, LTC, or another Bitcoin-derived chain.
//
// The intent is to keep the wallet/swap code chain-agnostic: it asks
// "is this txid confirmed yet?" / "what's been paid into this
// address?" / "broadcast this tx for me", and a registered
// ChainBackend handles the actual wire calls. Production deployments
// will typically register an EsploraBackend pointing at either a
// public Esplora instance (mempool.space, blockstream.info) or a
// self-hosted electrs+esplora-electrs.
//
// All methods throw `ChainBackendError` on failure — network error,
// HTTP non-2xx status, malformed response, or missing data. RPCs
// catch and translate to JSON-RPC errors; tests catch and inspect
// error.what() if needed.

namespace pricoin::swap {

class ChainBackendError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Tx confirmation status as exposed by the backend.
struct TxStatus {
    bool confirmed{false};
    // Set iff confirmed: the block that included the tx.
    int block_height{-1};
    std::string block_hash;
    // Set iff confirmed: unix seconds. Some backends don't expose
    // this — we tolerate 0 / unset.
    int64_t block_time{0};
};

// One row in an address history listing. The Esplora API returns
// quite a bit of detail per tx; we surface the parts a swap protocol
// actually needs (txid + confirmation state + amount paid INTO this
// address, summed across vouts).
struct AddressTx {
    std::string txid;
    TxStatus    status;
    // Sum of (vout_value for vouts paying our address). Does NOT
    // subtract spends-from-this-address, since for swap purposes we
    // care about deposits into the watched address.
    int64_t     value_received_sat{0};
};

// One UTXO for the holding-wallet path — Esplora's /address/<addr>/utxo
// endpoint returns unspent outputs only. The holding wallet uses these
// as inputs when building funding/sweep txs.
struct AddressUtxo {
    std::string txid;
    int32_t     vout{-1};
    int64_t     value_sat{0};
    TxStatus    status;
};

// Aggregate per-address balance derived from Esplora's
// /address/<addr> "chain_stats" object. Confirmed = funded_txo_sum
// minus spent_txo_sum, ignoring mempool. Useful as a one-call
// "show me the balance" pricey for the holding wallet UI.
struct AddressBalance {
    int64_t confirmed_sat{0};
    int64_t unconfirmed_sat{0};   // mempool-only
    int     utxo_count{0};
};

class ChainBackend {
public:
    virtual ~ChainBackend() = default;

    // Symbolic name: "btc", "ltc", "doge", etc. Used to key the
    // registry and as a sanity check in RPC arguments.
    virtual std::string Name() const = 0;

    // Tip height of the watched chain. Useful for confirmation
    // counting (tip - tx.block_height + 1).
    virtual int GetTipHeight() = 0;

    // Full tx as hex. Throws if the txid isn't found or the backend
    // doesn't expose hex (rare).
    virtual std::string GetTxHex(const std::string& txid) = 0;

    // Tx status — confirmed flag + block info if confirmed.
    virtual TxStatus GetTxStatus(const std::string& txid) = 0;

    // List of txs touching the given address, with confirmation +
    // value-received per tx. Returned in the order the backend gives
    // them (Esplora returns most-recent-first).
    virtual std::vector<AddressTx> GetAddressTxs(const std::string& address) = 0;

    // Unspent outputs paying the address. Used by the holding
    // wallet to pick coins when building a funding/sweep tx.
    virtual std::vector<AddressUtxo> GetAddressUtxos(const std::string& address) = 0;

    // Aggregate (confirmed + unconfirmed) balance for the address.
    // Cheaper than walking GetAddressUtxos when only the totals are
    // needed (e.g. the holding wallet's status display).
    virtual AddressBalance GetAddressBalance(const std::string& address) = 0;

    // Submit a raw tx to the backend's network for relay. Returns
    // the txid the backend assigned (typically the same hash the
    // caller computed locally; we surface what the backend says).
    virtual std::string Broadcast(const std::string& tx_hex) = 0;

    // Fee-rate estimates from the backend, in sat/vB, keyed by the
    // confirmation target in blocks. Esplora's `/fee-estimates`
    // returns roughly { "1": rate_for_next_block, "2": ..., "3": ...,
    // "6": ..., "10": ..., "20": ..., "144": ... }. Callers pick a
    // target appropriate for their use case (~6 blocks ≈ 1 hour for
    // BTC). Returns an empty map if the backend can't provide them.
    virtual std::map<int, double> GetFeeEstimates() = 0;
};

// Process-level registry of ChainBackends, keyed by Name(). Init
// reads `-btcwatchurl=URL` / `-ltcwatchurl=URL` (and similar) and
// registers EsploraBackends accordingly. RPCs look up by name.
//
// Thread-safe; backends themselves must also be thread-safe (the
// EsploraBackend impl creates a fresh libevent base per call so
// concurrent requests are independent).

void RegisterBackend(std::shared_ptr<ChainBackend> backend);

// Returns nullptr if no backend is registered for `name`.
std::shared_ptr<ChainBackend> GetBackend(const std::string& name);

// Names of all currently-registered backends. Used by RPCs that
// enumerate.
std::vector<std::string> ListBackendNames();

// Drop all registered backends. Called from the daemon shutdown path
// so the libevent state is cleaned up before atexit handlers fire.
void Shutdown();

} // namespace pricoin::swap

#endif // BITCOIN_SWAP_CHAIN_BACKEND_H
