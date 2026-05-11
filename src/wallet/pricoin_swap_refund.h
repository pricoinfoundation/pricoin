// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRICOIN_SWAP_REFUND_H
#define BITCOIN_WALLET_PRICOIN_SWAP_REFUND_H

#include <uint256.h>

#include <cstdint>
#include <string>

namespace wallet { class CWallet; }

namespace wallet::pricoin_swap_refund {

struct LtcRefundResult {
    bool ok{false};
    std::string txid;     // populated on success
    std::string error;    // populated on failure
};

struct PricRefundResult {
    bool ok{false};
    std::string txid;
    std::string error;
};

struct BtcRefundResult {
    bool ok{false};
    std::string txid;
    std::string error;
};

// Build + broadcast the LTC HTLC refund for a swap. Used by both the
// `pricoin_ltc_refund_swap` user-facing RPC and the chain watcher's
// auto-refund path. Preconditions are checked here so callers don't
// have to: swap exists, foreign_chain == "ltc", role == Bob, funding
// outpoint set, timelocks set, foreign_refund_height reached on chain.
//
// `dest_bech32` is the LTC destination address (where Bob receives
// his refunded LTC). `fee_sat` is a flat-rate fee.
//
// On success: registers a `foreign_refund` watcher entry so the swap
// auto-advances to Refunded when the broadcast tx confirms.
//
// IMPORTANT: this function does NOT check whether a refund was
// previously attempted for this swap — caller must dedup.
LtcRefundResult AutoBroadcastLtcRefund(
    ::wallet::CWallet& wallet,
    const uint256& swap_id,
    const std::string& dest_bech32,
    int64_t fee_sat);

// Inject the cooperative refund signature into the pre-built unsigned
// PRIC refund tx (both stored on the swap record after PreSigned),
// broadcast via the local pricoind mempool, and register a
// pric_refund watcher entry so the swap auto-advances to Refunded
// when the broadcast tx confirms.
//
// Requires the swap to be in state >= PreSigned with both
// `pric_refund_unsigned_tx_hex` and `presigs.pric_refund_sig_blob`
// populated. Either party's wallet can call this — both signed the
// refund cooperatively, both have the data (assuming the spender
// persisted the unsigned tx and DM'd it to the cosigner; today only
// the spender persists, so only the spender's wallet can auto-broadcast).
//
// IMPORTANT: caller must dedup. Does not check chain timelock — the
// chain enforces it via the tx's nLockTime, so a too-early broadcast
// is harmless (rejected by mempool).
PricRefundResult AutoBroadcastPricRefund(
    ::wallet::CWallet& wallet,
    const uint256& swap_id);

// Finalize the pre-built unsigned BTC refund tx by attaching the
// cooperative MuSig2 refund sig (both stored on the swap record
// after PreSigned) as a P2TR key-path-spend witness, broadcast via
// the foreign chain backend, and register a foreign_refund watcher
// entry. Mirrors AutoBroadcastPricRefund for the BTC P2TR variant.
//
// Requires the swap to be PreSigned+ with `btc_refund_unsigned_tx_hex`
// and `presigs.btc_refund_sig` populated. BTC swaps only — LTC swaps
// use the unilateral CLTV path (AutoBroadcastLtcRefund) instead.
//
// IMPORTANT: caller must dedup. Does not check chain timelock — the
// chain enforces it via the tx's nLockTime, so a too-early broadcast
// is harmless (rejected by mempool).
BtcRefundResult AutoBroadcastBtcRefund(
    ::wallet::CWallet& wallet,
    const uint256& swap_id);

}  // namespace wallet::pricoin_swap_refund

#endif  // BITCOIN_WALLET_PRICOIN_SWAP_REFUND_H
