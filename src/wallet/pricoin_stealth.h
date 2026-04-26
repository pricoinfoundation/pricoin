// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRICOIN_STEALTH_H
#define BITCOIN_WALLET_PRICOIN_STEALTH_H

#include <key.h>
#include <pricoin/stealth.h>

namespace wallet {
class CWallet;
} // namespace wallet

namespace wallet::pricoin_stealth {

// In-memory stealth identity for a wallet. Phase 5c MVP: NOT persisted to
// disk. A wallet's stealth address changes across daemon restarts. Persistence
// goes onto the wallet DB schema in a follow-up — for now the toy demonstrates
// the cryptographic pipeline.
struct Identity {
    CKey view;     // a
    CKey spend;    // b
    ::pricoin::stealth::StealthAddress public_address; // (A, B)
};

// Get-or-create the stealth identity associated with this wallet. Thread-safe.
const Identity& GetOrCreate(CWallet& wallet);

} // namespace wallet::pricoin_stealth

#endif // BITCOIN_WALLET_PRICOIN_STEALTH_H
