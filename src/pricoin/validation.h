// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRICOIN_VALIDATION_H
#define BITCOIN_PRICOIN_VALIDATION_H

#include <consensus/amount.h>

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

} // namespace pricoin

#endif // BITCOIN_PRICOIN_VALIDATION_H
