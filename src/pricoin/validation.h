// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRICOIN_VALIDATION_H
#define BITCOIN_PRICOIN_VALIDATION_H

#include <consensus/amount.h>
#include <pricoin/ringsig.h>

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
//   - pricoin::ct::VerifyBundle then checks rangeproofs (per output) and the
//     Pedersen tally (Σin − Σout − fee*H == 0).
//
// On success, sets txfee_out to ct_bundle.transparent_fee.
[[nodiscard]] bool VerifyConfidentialContextual(
    const CTransaction& tx,
    const CCoinsViewCache& inputs,
    int nSpendHeight,
    TxValidationState& state,
    CAmount& txfee_out);

// Pricoin: commit each ring-input's key image to the global in-memory set
// AND append it to the persistent on-disk file. Called from ConnectBlock
// after the block has fully validated. Idempotent.
void CommitRingKeyImages(const CTransaction& tx);

// Remove key images committed by tx (for chain reorgs / DisconnectBlock).
// Note: in-memory only — does not modify the persistent file. The toy
// scope accepts that on a reorg + restart, the persistent set may be
// slightly stale; correctness is preserved for forward operation.
void UncommitRingKeyImages(const CTransaction& tx);

// Initialize the key-image persistent store. Loads any existing key images
// from <datadir>/pricoin_keyimages.dat into the in-memory set, and opens
// the file for append. Called once at daemon startup.
void InitKeyImageStore(const std::string& datadir_path);

// Pricoin: query whether a given key image has been committed to the
// global set (either via on-chain ring tx or via load-from-file at
// startup). Used by wallet bookkeeping (pricoin_listownct,
// ConfidentialBalance) to filter out spent outputs in the Phase 3a model
// where chainstate-erasure is no longer the spent indicator.
bool IsKeyImageCommitted(const ringsig::Point& ki);

} // namespace pricoin

#endif // BITCOIN_PRICOIN_VALIDATION_H
