// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRICOIN_CT_SEND_H
#define BITCOIN_WALLET_PRICOIN_CT_SEND_H

#include <consensus/amount.h>
#include <uint256.h>
#include <util/result.h>

#include <functional>
#include <span>
#include <string>
#include <vector>

class CTransaction;

namespace wallet {

class CWallet;

// One destination in a multi-recipient Pricoin Confidential Transaction.
struct PricoinCTRecipient {
    std::string address;  // stealth (H6...) or transparent bech32
    CAmount amount;       // in satoshis; must be > 0
};

// Build, sign, and broadcast a Pricoin v4 confidential transaction with
// arbitrarily many recipients in a single bundle:
//   - Funds from N P2WPKH wallet UTXOs covering Σamounts + fee
//   - Each recipient gets its own one-time stealth output
//   - Single change output back to the wallet's own stealth identity
//   - Pays a single transparent `fee`
// All recipients are co-anonymized inside one tx, which both saves wire
// bytes (one rangeproof set, one signature set per input) and prevents
// the "N sequential pool payouts" fingerprint from leaking who paid whom.
util::Result<uint256> SendConfidentialTxMulti(
    CWallet& wallet,
    std::span<const PricoinCTRecipient> recipients,
    CAmount fee);

// Single-recipient convenience wrapper. Identical behavior to the multi
// form with recipients={(dest_address, amount)}. Used by both the
// JSON-RPC layer (`walletsendct`) and the Qt GUI's
// interfaces::Wallet::sendConfidential.
util::Result<uint256> SendConfidentialTx(
    CWallet& wallet,
    const std::string& dest_address,
    CAmount amount,
    CAmount fee);

// Sum the values of all unspent confidential outputs paid to this wallet's
// stealth identity. Equivalent to `pricoin_listownct.total_recovered`.
// Used by the JSON-RPC layer and by the Qt GUI's
// interfaces::Wallet::confidentialBalance.
CAmount ConfidentialBalance(CWallet& wallet);

// One per-vout result from a stealth scan of a v4 transaction.
struct PricoinCTRecovery {
    uint32_t vout_index;
    CAmount value;
    // The one-time private key for this output (= shared_secret + spend_priv mod n).
    // 32 bytes raw scalar; usable with the wallet's signer once installed.
    std::array<unsigned char, 32> one_time_priv;
};

// Scan a v4 transaction's outputs for any paid to this wallet's stealth
// identity (rangeproof rewind on each match). Returns the list of
// recovered outputs (empty if none, or if tx isn't v4). Lazily creates the
// wallet's stealth identity if needed.
std::vector<PricoinCTRecovery> ScanTxForCTReceives(
    CWallet& wallet,
    const CTransaction& tx);

// Drop the wallet's per-call recovery-scan cache. Idempotent / no-op
// for wallets that haven't scanned yet. Defined in
// wallet/rpc/pricoin_ct.cpp next to the cache.
void DropCTRecoveryCache(CWallet& wallet);

// Atomic two-lock pattern for callers that need to update *both* the
// recovery cache and other wallet-private state without a race window
// where readers can see one updated and the other not.
//
// Acquires the recovery-cache mutex, calls `inner()` while holding it,
// and (only if `inner()` returns true) drops the cache for this wallet
// before releasing the mutex. `inner` may freely take its own locks
// (e.g. pricoin_stealth's g_mutex) — the recovery-cache mutex is the
// outer one in the project's lock-order convention.
//
// Used by pricoin_stealth::SetSeed: rotating the stealth identity
// without atomically clearing the recovery cache would briefly let
// readers see the new identity paired with the old identity's cached
// (stale, wrong-keys) recoveries.
void RunWithCTRecoveryCacheCleared(CWallet& wallet,
                                   std::function<bool()> inner);

} // namespace wallet

#endif // BITCOIN_WALLET_PRICOIN_CT_SEND_H
