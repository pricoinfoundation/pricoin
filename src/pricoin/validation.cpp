// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pricoin/validation.h>

#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <pricoin/ct.h>
#include <pricoin/cttx.h>
#include <primitives/transaction.h>
#include <tinyformat.h>

namespace pricoin {

bool VerifyConfidentialContextual(
    const CTransaction& tx,
    const CCoinsViewCache& inputs,
    int nSpendHeight,
    TxValidationState& state,
    CAmount& txfee_out)
{
    // Caller's responsibility — sanity-asserted here.
    if (tx.version != PRICOIN_CT_VERSION) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-not-ct-version");
    }

    if (!inputs.HaveInputs(tx)) {
        return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent");
    }

    if (tx.vin.size() != tx.ct_bundle.input_commitments.size()) {
        // Re-check despite CheckTransaction having done it; the consensus
        // layer should never trust prior-stage invariants on safety-critical
        // values.
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-input-count");
    }

    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const COutPoint& prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        // HaveInputs already guaranteed non-spent existence.
        if (coin.IsSpent()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-spent-prevout");
        }
        if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY) {
            return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "bad-txns-premature-spend-of-coinbase",
                strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
        }

        // Phase 2d-2 restriction: prev output must be transparent. We detect
        // this via nValue > 0 (CT outputs are stored with nValue=0 in their
        // CTxOut). A more permissive check (allowing CT-spending-CT) needs
        // Coin to carry the commitment for v4 outputs, deferred to a later
        // phase.
        if (coin.out.nValue == 0) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-spends-confidential-prev",
                "Phase 2d-2 only allows CT to spend transparent prev outputs");
        }
        if (!MoneyRange(coin.out.nValue)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputvalues-outofrange");
        }

        // Reconstruct the expected input commitment: Commit(prev_value, 0).
        // Sender must have used these in their balance calculation; if they
        // claim something else, balance verifies against fake amounts.
        ct::BlindingFactor zero_blind{};
        auto expected = ct::Commitment::Create(static_cast<uint64_t>(coin.out.nValue), zero_blind);
        if (!expected) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-input-commit-construction");
        }
        if (*expected != tx.ct_bundle.input_commitments[i]) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-input-commit-mismatch",
                strprintf("vin[%u] claims input commitment that does not match prev output value", i));
        }
    }

    // All input commitments check out; now verify rangeproofs + tally.
    if (!ct::VerifyBundle(tx.ct_bundle)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-bundle-invalid");
    }

    // Fee is the cleartext transparent_fee carried in the bundle.
    if (tx.ct_bundle.transparent_fee > static_cast<uint64_t>(MAX_MONEY)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-fee-toolarge");
    }
    txfee_out = static_cast<CAmount>(tx.ct_bundle.transparent_fee);
    return true;
}

} // namespace pricoin
