// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/transactionrecord.h>

#include <chain.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <primitives/transaction.h>

#include <cstdint>
#include <cstdlib>

#include <QDateTime>

/* Return positive answer if transaction should be shown in list.
 */
bool TransactionRecord::showTransaction()
{
    // There are currently no cases where we hide transactions, but
    // we may want to use this in the future for things like RBF.
    return true;
}

/*
 * Decompose CWallet transaction to model transaction records.
 */
QList<TransactionRecord> TransactionRecord::decomposeTransaction(const interfaces::WalletTx& wtx)
{
    QList<TransactionRecord> parts;
    int64_t nTime = wtx.time;
    CAmount nCredit = wtx.credit;
    CAmount nDebit = wtx.debit;
    CAmount nNet = nCredit - nDebit;
    Txid hash = wtx.tx->GetHash();
    std::map<std::string, std::string> mapValue = wtx.value_map;

    bool all_from_me = true;
    bool any_from_me = false;
    if (wtx.is_coinbase) {
        all_from_me = false;
    } else {
        for (const bool mine : wtx.txin_is_mine)
        {
            all_from_me = all_from_me && mine;
            if (mine) any_from_me = true;
        }
    }

    // Pricoin Phase B: explicit accounting for v4 confidential transactions.
    // For these, every vout has nValue=0 (real values live in commitments) and
    // outputs are P2WPKH on a one-time stealth-derived pubkey, so the wallet's
    // IsMine returns false for them. The wallet's stealth-scan path stashes
    // recovered values per vout in mapValue under "pct_v<i>"; surface them
    // directly as credits, and compute the matching debit from the wallet's
    // transparent contribution.
    if (wtx.tx->version == PRICOIN_CT_VERSION) {
        CAmount total_credit = 0;
        for (size_t i = 0; i < wtx.tx->vout.size(); ++i) {
            const std::string vk = "pct_v" + std::to_string(i);
            auto it = mapValue.find(vk);
            if (it == mapValue.end()) continue;
            const CAmount v = std::strtoll(it->second.c_str(), nullptr, 10);
            if (v <= 0) continue;
            TransactionRecord sub(hash, nTime);
            sub.idx = (int)i;
            sub.credit = v;
            sub.type = TransactionRecord::RecvWithAddress;
            sub.address = "(confidential — stealth)";
            parts.append(sub);
            total_credit += v;
        }
        if (any_from_me) {
            // We contributed a transparent input (wtx.debit) and recovered
            // some of it back as our own change (total_credit). Whatever's
            // left went to the recipient + the transparent fee.
            const CAmount sent = nDebit - total_credit;
            if (sent > 0) {
                TransactionRecord sub(hash, nTime);
                sub.idx = -1;
                sub.debit = -sent;
                sub.type = TransactionRecord::SendToOther;
                sub.address = "(confidential — stealth)";
                parts.append(sub);
            }
        }
        if (parts.isEmpty()) {
            // v4 tx that neither receives to us nor draws on our funds —
            // shouldn't normally appear, but render a neutral placeholder so
            // it doesn't vanish silently.
            parts.append(TransactionRecord(hash, nTime, TransactionRecord::Other, "(confidential)", 0, 0));
        }
        return parts;
    }

    if (all_from_me || !any_from_me) {
        CAmount nTxFee = nDebit - wtx.tx->GetValueOut();

        for(unsigned int i = 0; i < wtx.tx->vout.size(); i++)
        {
            const CTxOut& txout = wtx.tx->vout[i];

            if (all_from_me) {
                // Change is only really possible if we're the sender
                // Otherwise, someone just sent bitcoins to a change address, which should be shown
                if (wtx.txout_is_change[i]) {
                    continue;
                }

                //
                // Debit
                //

                TransactionRecord sub(hash, nTime);
                sub.idx = i;

                if (!std::get_if<CNoDestination>(&wtx.txout_address[i]))
                {
                    // Sent to Bitcoin Address
                    sub.type = TransactionRecord::SendToAddress;
                    sub.address = EncodeDestination(wtx.txout_address[i]);
                }
                else
                {
                    // Sent to IP, or other non-address transaction like OP_EVAL
                    sub.type = TransactionRecord::SendToOther;
                    sub.address = mapValue["to"];
                }

                CAmount nValue = txout.nValue;
                /* Add fee to first output */
                if (nTxFee > 0)
                {
                    nValue += nTxFee;
                    nTxFee = 0;
                }
                sub.debit = -nValue;

                parts.append(sub);
            }

            bool mine = wtx.txout_is_mine[i];
            if(mine)
            {
                //
                // Credit
                //

                TransactionRecord sub(hash, nTime);
                sub.idx = i; // vout index
                sub.credit = txout.nValue;
                if (wtx.txout_address_is_mine[i])
                {
                    // Received by Bitcoin Address
                    sub.type = TransactionRecord::RecvWithAddress;
                    sub.address = EncodeDestination(wtx.txout_address[i]);
                }
                else
                {
                    // Received by IP connection (deprecated features), or a multisignature or other non-simple transaction
                    sub.type = TransactionRecord::RecvFromOther;
                    sub.address = mapValue["from"];
                }
                if (wtx.is_coinbase)
                {
                    // Generated
                    sub.type = TransactionRecord::Generated;
                }

                parts.append(sub);
            }
        }
    } else {
        //
        // Mixed debit transaction, can't break down payees
        //
        parts.append(TransactionRecord(hash, nTime, TransactionRecord::Other, "", nNet, 0));
    }

    return parts;
}

void TransactionRecord::updateStatus(const interfaces::WalletTxStatus& wtx, const uint256& block_hash, int numBlocks, int64_t block_time)
{
    // Determine transaction status

    // Sort order, unrecorded transactions sort to the top
    int typesort;
    switch (type) {
    case SendToAddress: case SendToOther:
        typesort = 2; break;
    case RecvWithAddress: case RecvFromOther:
        typesort = 3; break;
    default:
        typesort = 9;
    }
    status.sortKey = strprintf("%010d-%01d-%010u-%03d-%d",
        wtx.block_height,
        wtx.is_coinbase ? 1 : 0,
        wtx.time_received,
        idx,
        typesort);
    status.countsForBalance = wtx.is_trusted && !(wtx.blocks_to_maturity > 0);
    status.depth = wtx.depth_in_main_chain;
    status.m_cur_block_hash = block_hash;

    // For generated transactions, determine maturity
    if (type == TransactionRecord::Generated) {
        if (wtx.blocks_to_maturity > 0)
        {
            status.status = TransactionStatus::Immature;

            if (wtx.is_in_main_chain)
            {
                status.matures_in = wtx.blocks_to_maturity;
            }
            else
            {
                status.status = TransactionStatus::NotAccepted;
            }
        }
        else
        {
            status.status = TransactionStatus::Confirmed;
        }
    }
    else
    {
        if (status.depth < 0)
        {
            status.status = TransactionStatus::Conflicted;
        }
        else if (status.depth == 0)
        {
            status.status = TransactionStatus::Unconfirmed;
            if (wtx.is_abandoned)
                status.status = TransactionStatus::Abandoned;
        }
        else if (status.depth < RecommendedNumConfirmations)
        {
            status.status = TransactionStatus::Confirming;
        }
        else
        {
            status.status = TransactionStatus::Confirmed;
        }
    }
    status.needsUpdate = false;
}

bool TransactionRecord::statusUpdateNeeded(const uint256& block_hash) const
{
    assert(!block_hash.IsNull());
    return status.m_cur_block_hash != block_hash || status.needsUpdate;
}

QString TransactionRecord::getTxHash() const
{
    return QString::fromStdString(hash.ToString());
}

int TransactionRecord::getOutputIndex() const
{
    return idx;
}
