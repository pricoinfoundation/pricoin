// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRICOIN_VALIDATION_H
#define BITCOIN_PRICOIN_VALIDATION_H

#include <consensus/amount.h>
#include <pricoin/ringsig.h>
#include <uint256.h>

#include <functional>
#include <span>
#include <string>

class CCoinsViewCache;
class CTransaction;
class TxValidationState;

namespace pricoin {

// Contextual verification for a Pricoin Confidential Transaction (tx version
// PRICOIN_CT_VERSION). The caller must have already passed CheckTransaction
// (structural rules) and inputs.HaveInputs(tx).
//
// Phase 2d-2 scope:
//   - All inputs must spend TRANSPARENT prev outputs (versions 1-3). This
//     keeps Coin/CCoinsView untouched. A future change extends Coin to carry
//     commitments for v4 outputs, enabling CT-spending-CT.
//   - For each input, the sender-claimed input_commitments[i] must equal
//     Commit(prev_value, blind=0). This is what makes the privacy guarantee
//     real: without this check, the sender could fabricate input commitments
//     and balance the bundle against fake values, inflating supply.
//   - Per-output rangeproofs are checked, and the Pedersen tally
//     (Σin − Σout − fee*H == 0) is verified inline here.
//
// On success, sets txfee_out to ct_bundle.transparent_fee.
[[nodiscard]] bool VerifyConfidentialContextual(
    const CTransaction& tx,
    const CCoinsViewCache& inputs,
    int nSpendHeight,
    TxValidationState& state,
    CAmount& txfee_out);

// Pricoin: commit a block's ring-input key images to the global in-memory
// set AND append a per-block entry to the persistent file. Tagging by
// block_hash lets DisconnectBlock undo cleanly. Called from ConnectBlock
// after the block has fully validated. Idempotent against re-runs of the
// same block.
void CommitBlockKIs(const uint256& block_hash,
                    std::span<const ringsig::Point> kis);

// Remove all key images committed by `block_hash` from both the in-memory
// set and the persistent file. Called from DisconnectBlock. No-op for a
// block that wasn't committed (e.g. a v4-empty block).
void UncommitBlockKIs(const uint256& block_hash);

// Initialize the key-image persistent store. Loads any existing key images
// from <datadir>/pricoin_keyimages.dat into the in-memory set, and opens
// the file for append. Called once at daemon startup.
//
// If `wipe_on_init` is true (typically when -reindex or
// -reindex-chainstate is passed), the file is deleted before loading.
// Without this, a reindex rebuilds chainstate from genesis but the
// keyimage store keeps the previous session's entries — the same
// blocks then fail re-validation as "double-spend" of keyimages the
// store thinks are already used.
void InitKeyImageStore(const std::string& datadir_path,
                        bool wipe_on_init = false);

// Drop all keyimages associated with block_hashes that aren't in the
// active chain. Called from init.cpp after chainstate is fully
// loaded, as a self-heal against half-applied reorgs (e.g., crash
// between CommitBlockKIs and chainstate flush). Idempotent.
void PruneOrphanedKeyImages(
    const std::function<bool(const uint256&)>& is_in_active_chain);

// Pricoin: query whether a given key image has been committed to the
// global set (either via on-chain ring tx or via load-from-file at
// startup). Used by wallet bookkeeping (pricoin_listownct,
// ConfidentialBalance) to filter out spent outputs in the Phase 3a model
// where chainstate-erasure is no longer the spent indicator.
bool IsKeyImageCommitted(const ringsig::Point& ki);

// Diagnostic: total count of KIs in the global committed set. Used by
// the startup self-heal pass in init.cpp to detect whether a rebuild-
// from-chain walk added any missing entries.
size_t CountCommittedKeyImages();

} // namespace pricoin

#endif // BITCOIN_PRICOIN_VALIDATION_H
