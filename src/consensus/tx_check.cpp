// Copyright (c) 2017-present The Bitcoin Core developers
// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_check.h>

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <consensus/validation.h>

bool CheckTransaction(const CTransaction& tx, TxValidationState& state)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-oversize");
    }

    // Check for negative or overflow output values (see CVE-2010-5139)
    CAmount nValueOut = 0;
    for (const auto& txout : tx.vout)
    {
        if (txout.nValue < 0)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-txouttotal-toolarge");
    }

    // Check for duplicate inputs (see CVE-2018-17144)
    // While Consensus::CheckTxInputs does check if all inputs of a tx are available, and UpdateCoins marks all inputs
    // of a tx as spent, it does not check if the tx has duplicate inputs.
    // Failure to run this check will result in either a crash or an inflation bug, depending on the implementation of
    // the underlying coins database.
    std::set<COutPoint> vInOutPoints;
    for (const auto& txin : tx.vin) {
        if (!vInOutPoints.insert(txin.prevout).second)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputs-duplicate");
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-length");
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-prevout-null");
    }

    // Pricoin: structural rules for the confidential-transaction tx version.
    // Coinbase is excluded (subsidy is auditable; coinbase stays transparent).
    if (tx.version == PRICOIN_CT_VERSION) {
        if (tx.IsCoinBase()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-coinbase");
        }
        if (tx.ct_bundle.input_commitments.size() != tx.vin.size()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-input-count");
        }
        if (tx.ct_bundle.outputs.size() != tx.vout.size()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-output-count");
        }
        // All visible vout amounts must be zero — the real values live in
        // commitments; the cleartext fee lives in ct_bundle.transparent_fee.
        for (const auto& txout : tx.vout) {
            if (txout.nValue != 0) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-nonzero-vout");
            }
        }
        // Bundle output scripts must match vout scripts (the rangeproof's
        // extra_commit binds to the script, so a mismatch would already make
        // verification fail — but reject early with a clear reason).
        for (size_t i = 0; i < tx.vout.size(); ++i) {
            const auto& spk = tx.vout[i].scriptPubKey;
            const auto& bundle_spk = tx.ct_bundle.outputs[i].script_pubkey;
            if (spk.size() != bundle_spk.size() ||
                !std::equal(spk.begin(), spk.end(), bundle_spk.begin())) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-script-mismatch");
            }
            if (tx.ct_bundle.outputs[i].rangeproof.empty()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-empty-rangeproof");
            }
        }
        // Sanity: transparent_fee fits in CAmount range.
        if (tx.ct_bundle.transparent_fee > static_cast<uint64_t>(MAX_MONEY)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-pct-fee-toolarge");
        }
    } else {
        // Non-CT versions must not carry a CT bundle.
        if (!tx.ct_bundle.input_commitments.empty() ||
            !tx.ct_bundle.outputs.empty() ||
            tx.ct_bundle.transparent_fee != 0) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-non-pct-has-bundle");
        }
    }

    return true;
}
