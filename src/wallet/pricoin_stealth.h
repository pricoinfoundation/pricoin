// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRICOIN_STEALTH_H
#define BITCOIN_WALLET_PRICOIN_STEALTH_H

#include <key.h>
#include <pricoin/stealth.h>

#include <map>

#include <array>
#include <optional>

namespace wallet {
class CWallet;
} // namespace wallet

namespace wallet::pricoin_stealth {

// In-memory stealth identity for a wallet. Phase 5c MVP: NOT persisted to
// disk. A wallet's stealth address changes across daemon restarts. Persistence
// goes onto the wallet DB schema in a follow-up — for now this experimental code demonstrates
// the cryptographic pipeline.
struct Identity {
    CKey view;     // a
    CKey spend;    // b
    ::pricoin::stealth::StealthAddress public_address; // (A, B)
};

// Get-or-create the stealth identity associated with this wallet. Thread-safe.
const Identity& GetOrCreate(CWallet& wallet);

// ─── Subaddress scan lookup ──────────────────────────────────────
//
// For scanning, we want O(1)-ish recovery of "is this output mine, and if so,
// to which subaddress index?" The receiver computes
//     B_candidate = P_observed − shared·G
// and looks up B_candidate in this map. Index 0 is always present and
// resolves to the master spend scalar `b`; non-zero indices resolve to
// `b_i = b + m_i` where m_i is the subaddress offset.
//
// Each entry holds the spend scalar pre-derived so the scanner doesn't pay
// the offset-hash + scalar-tweak per output. The map is rebuilt on demand
// (BuildSubaddressLookup) when the wallet's set of known indices changes.
//
// PERSISTENCE NOTE: until the subaddress-DB plumbing lands (step 5), the
// only entry is the master. The shape stays the same so callers don't need
// to change again later — wallets with no subaddresses still get a one-
// entry map and the lookup is correct.
struct SubaddressLookupEntry {
    uint32_t index{0};
    CKey     spend_priv;  // master b for index=0, derived b_i otherwise
};

struct SubaddressLookup {
    // Keyed by the 33-byte compressed B (or B_i) point. std::map keeps the
    // ordering stable for snapshot diffing in tests; switch to an unordered
    // hashmap if the scan-side cost ever bites at scale.
    std::map<::pricoin::stealth::PointBytes, SubaddressLookupEntry> by_b_point;
};

// Build the subaddress lookup table for `wallet`. Hydrates entries for
// indices [0, max_used_index] from the persisted wallet state. Index 0
// is the master; non-zero entries derive (b_i, B_i) on the fly.
SubaddressLookup BuildSubaddressLookup(CWallet& wallet);

// ─── Subaddress allocation / labelling ────────────────────────────
//
// Wallet-level state for the subaddress feature. Persisted under DB keys
// pct_subaddr_state (singleton with max_used_index) and
// pct_subaddr_label (one record per labelled index).
//
// Allocation is monotonic — indices are never reused. The "gap-limit"
// scan extension lives in BuildSubaddressLookup, which scans beyond
// max_used_index when the sync detects a payment past it.
struct SubaddressState {
    uint32_t                       max_used_index{0};
    std::map<uint32_t, std::string> labels;  // index → label (utf-8)
};

// Read the persisted state. Empty wallet ⇒ {max=0, no labels}.
SubaddressState LoadSubaddressState(CWallet& wallet);

// Allocate the next subaddress index. Persists max_used_index+1 to the
// DB and returns the freshly-derived Subaddress. Throws on locked-and-
// encrypted wallet (we need the spend scalar to derive b_i).
::pricoin::stealth::Subaddress AllocateNextSubaddress(
    CWallet& wallet, const std::string& label = {});

// Persist (or clear) the label for an existing index. Returns false if
// the index hasn't been allocated yet.
bool SetSubaddressLabel(CWallet& wallet, uint32_t index, const std::string& label);
bool EraseSubaddressLabel(CWallet& wallet, uint32_t index);

// Restore-mode discovery: scanner found an output paying subaddress index
// `discovered` that is beyond the wallet's current max_used_index. Bump
// the ceiling so future scans (and subsequent BuildSubaddressLookup
// passes) include this index in the lookup table. Idempotent — calls
// with `discovered <= max_used` are no-ops.
void NoteSubaddressDiscovered(CWallet& wallet, uint32_t discovered);

// BIP-44-style gap limit. BuildSubaddressLookup pre-derives entries for
// indices [1, max_used_index + kSubaddressGapLimit] so the scanner can
// recognise payments past the current ceiling. If a payment lands within
// the gap window, NoteSubaddressDiscovered extends max_used_index.
inline constexpr uint32_t kSubaddressGapLimit = 100;

// Return the wallet's 32-byte stealth seed, IF the wallet's stealth
// identity is in the seed-derived form (v0.1.12+ default). Returns
// std::nullopt for legacy v0.1.11 wallets that store a key blob — those
// don't have a recoverable seed (their view+spend keys are independent
// random scalars). The wallet must be unlocked. Must be called after
// GetOrCreate (it primes the cache). Thread-safe.
std::optional<std::array<unsigned char, 32>> GetSeedIfAvailable(CWallet& wallet);

// Encrypt a payload blob using the wallet's at-rest encryption posture
// — encrypted+HMAC if the wallet has encryption keys (and is unlocked),
// plaintext-with-version-byte otherwise. Returns false if the wallet is
// encrypted-but-locked. Used by other wallet-private records (e.g. the
// CT-recovery scan cache) that want the same at-rest protection as the
// stealth identity itself.
bool EncryptWalletBlob(CWallet& wallet,
                       std::span<const unsigned char> plain,
                       std::vector<unsigned char>& blob_out);

// Inverse of EncryptWalletBlob. Throws std::runtime_error if the blob
// is encrypted and the wallet is currently locked (matches GetOrCreate's
// posture). Returns false on corruption, wrong key, or unrecognised
// format. Refuses the legacy v1 (no-MAC) format on this path — DB-record
// callers were never written in that format, so seeing it here is
// necessarily a downgrade-attack attempt.
bool DecryptWalletBlob(CWallet& wallet,
                       std::span<const unsigned char> blob,
                       std::vector<unsigned char>& plain_out);

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
