// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRICOIN_STEALTH_H
#define BITCOIN_WALLET_PRICOIN_STEALTH_H

#include <key.h>
#include <pricoin/stealth.h>

#include <array>
#include <optional>

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

// Return the wallet's 32-byte stealth seed, IF the wallet's stealth
// identity is in the seed-derived form (v0.1.12+ default). Returns
// std::nullopt for legacy v0.1.11 wallets that store a key blob — those
// don't have a recoverable seed (their view+spend keys are independent
// random scalars). The wallet must be unlocked. Must be called after
// GetOrCreate (it primes the cache). Thread-safe.
std::optional<std::array<unsigned char, 32>> GetSeedIfAvailable(CWallet& wallet);

// Reason a SetSeed call rejected.
enum class SetSeedResult {
    Ok,
    InvalidSeed,        // seed does not derive valid secp256k1 keys (~2^-128)
    Locked,             // wallet is encrypted-but-locked
    AlreadyHasIdentity, // existing seed/key-blob present and overwrite not confirmed
    WriteFailed,        // DB write returned false
};

// Set the wallet's stealth identity from a 32-byte seed. Refuses to
// overwrite an existing seed/key-blob unless `confirm_overwrite` is
// true — overwrite irrecoverably loses access to any CT outputs
// already received under the previous identity. Clears the in-memory
// cache on success so the next GetOrCreate reloads from DB.
SetSeedResult SetSeed(CWallet& wallet,
                      std::span<const unsigned char> seed,
                      bool confirm_overwrite);

// Clear the in-memory identity cache. Must be called from the daemon's
// Shutdown path before process exit. Otherwise the static map's destructor
// races with atexit cleanup of glibc / libsecp256k1 internals and triggers
// a SIGSEGV inside memory_cleanse() on each cached CKey.
void Shutdown();

} // namespace wallet::pricoin_stealth

#endif // BITCOIN_WALLET_PRICOIN_STEALTH_H
