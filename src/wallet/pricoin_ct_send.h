// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRICOIN_CT_SEND_H
#define BITCOIN_WALLET_PRICOIN_CT_SEND_H

#include <consensus/amount.h>
#include <uint256.h>
#include <util/result.h>

#include <string>

namespace wallet {

class CWallet;

// Build, sign, and broadcast a Pricoin v4 confidential transaction:
//   - Funds from a P2WPKH wallet UTXO with value >= amount + fee
//   - Sends `amount` to `dest_address` (stealth or transparent bech32)
//   - Sends change to the wallet's own stealth identity
//   - Pays a transparent `fee`
// Returns the broadcast txid on success. Used by both the JSON-RPC layer
// (`walletsendct`) and the Qt GUI's interfaces::Wallet::sendConfidential.
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

} // namespace wallet

#endif // BITCOIN_WALLET_PRICOIN_CT_SEND_H
