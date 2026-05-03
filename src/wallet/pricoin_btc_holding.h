// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRICOIN_BTC_HOLDING_H
#define BITCOIN_WALLET_PRICOIN_BTC_HOLDING_H

// Phase-A "holding wallet" for foreign-chain swap funding.
//
// SCOPE — intentionally narrow.
//   * One BIP340 keypair derived from the wallet's stealth seed
//     (via HMAC chain mirroring pricoin_swap_session::DeriveSwapIdentityPriv).
//   * One per-chain receive address (BIP341 P2TR for BTC mainnet/regtest,
//     BIP143 P2WPKH for LTC where Taproot isn't activated).
//   * Balance + UTXO query via the existing pricoin::swap::ChainBackend
//     registry (Esplora-style HTTP endpoints).
//   * Build + sign + broadcast TWO tx shapes:
//       1. Fund a 2-of-2 P2TR for an active swap (one input, output =
//          agg_xonly P2TR, change to self).
//       2. Sweep all UTXOs to a single external destination.
//
// What this is NOT:
//   * Not a general-purpose foreign-chain wallet. Single address, no
//     address book, no PSBT, no fee estimation, no coin control.
//   * Not custody — meant for moving small amounts in/out around swaps.
//
// Trust model: relies on the configured ChainBackend for honest UTXO +
// balance state. A malicious Esplora can lie; mitigated by self-hosting
// (see doc/pricoin-tier3-selfhost.md).

#include <pubkey.h>
#include <key.h>
#include <util/result.h>
#include <swap/chain_backend.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace wallet { class CWallet; }

namespace wallet::pricoin_btc_holding {

// Per-chain parameters that control address encoding + sighash style.
// Keyed by the same `name` strings used by pricoin::swap::ChainBackend
// — "btc", "ltc". Mainnet HRPs only for now (the depends ChainBackend
// is pointed at mainnet/testnet via `-btcwatchurl=` config); chain-
// param expansion to per-network HRPs is straightforward but isn't
// needed for the swap-funding use case.
struct ChainParams {
    std::string name;
    std::string hrp;          // "bc" for BTC mainnet, "ltc" for LTC mainnet, etc.
    int         witness_v;    // 1 = P2TR (BTC), 0 = P2WPKH (LTC)
};

// Returns nullptr for unknown chains.
const ChainParams* GetChainParams(const std::string& chain);

struct Identity {
    std::string chain;            // echo
    // BIP340-normalized priv: if the natural pubkey has odd y, the
    // priv is negated so the on-record xonly is the even-y form.
    // For P2WPKH (LTC) we don't need this normalization but we apply
    // it anyway for shared code paths.
    CKey                            priv;
    CPubKey                         pub;        // 33-byte compressed
    std::array<unsigned char, 32>   xonly;      // BIP340 x-only
    std::string                     address;    // bech32/bech32m receive address
};

// Lazy-derive (priv, pub, address). Same priv across calls.
util::Result<Identity> GetOrCreateIdentity(::wallet::CWallet& wallet,
                                             const std::string& chain);

// Query the registered ChainBackend for the holding-wallet address's
// confirmed + unconfirmed balance.
util::Result<::pricoin::swap::AddressBalance>
GetBalance(::wallet::CWallet& wallet, const std::string& chain);

// Get the holding-wallet address as a string (just the bech32(m)).
util::Result<std::string> GetAddress(::wallet::CWallet& wallet,
                                       const std::string& chain);

// Greedy single-UTXO funding tx. Picks the smallest UTXO ≥
// (amount_sat + fee_sat) and builds:
//   vin[0] = picked UTXO
//   vout[0] = OP_1 <agg_xonly>      with `amount_sat`
//   vout[1] = self P2TR change      with `(picked - amount_sat - fee_sat)`
// Signs vin[0] with BIP341 key-path-spend (Schnorr, no script tree).
// Broadcasts via ChainBackend::Broadcast. Returns the broadcast txid.
//
// BTC only in this initial commit; LTC P2WPKH funding is a follow-on
// (LTC doesn't support the 2-of-2 P2TR funding output that this RPC
// produces — for LTC we'd build a 2-of-2 P2WSH instead, which has
// different scriptPubKey + sighash semantics).
util::Result<std::string> BuildAndBroadcastFundingTx(
    ::wallet::CWallet& wallet,
    const std::string& chain,
    const std::array<unsigned char, 32>& agg_xonly,
    int64_t amount_sat,
    int64_t fee_sat);

// Sweep ALL UTXOs at the holding-wallet address to a single bech32(m)
// destination, paying `fee_sat`. One input per UTXO; one output to the
// destination. Signs each input with BIP341 key-path. Broadcasts.
util::Result<std::string> BuildAndBroadcastSweepTx(
    ::wallet::CWallet& wallet,
    const std::string& chain,
    const std::string& dest_address,
    int64_t fee_sat);

// Idempotent shutdown — clears in-memory state. Mirrors other Pricoin
// modules' shutdown hook.
void Shutdown();

} // namespace wallet::pricoin_btc_holding

#endif // BITCOIN_WALLET_PRICOIN_BTC_HOLDING_H
