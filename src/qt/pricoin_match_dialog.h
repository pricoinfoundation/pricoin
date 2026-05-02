// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_PRICOIN_MATCH_DIALOG_H
#define BITCOIN_QT_PRICOIN_MATCH_DIALOG_H

#include <QDialog>
#include <QString>
#include <cstdint>
#include <vector>

#include <interfaces/wallet.h>

QT_BEGIN_NAMESPACE
class QLabel;
class QPushButton;
class QSpinBox;
class QTableView;
class QStandardItemModel;
QT_END_NAMESPACE

// Modal dialog that replaces the "Find matches" QMessageBox.
//
// Inputs:
//   * `mine`       — the user's selected Local order.
//   * `candidates` — outputs of `offerFindMatches(mine.order_id)`.
// Lets the user pick one candidate, dial in the `actual_pric_amount`
// (defaults to the maximum legal under both sides' remainings), and
// previews the computed `actual_foreign_amount` at the maker (asker)'s
// rate. On OK the dialog returns the chosen `(their_order_id,
// actual_pric_amount)` pair via accessors.

class PricoinMatchDialog : public QDialog
{
    Q_OBJECT

public:
    PricoinMatchDialog(
        const interfaces::Wallet::PricoinOfferSnapshot& mine,
        std::vector<interfaces::Wallet::PricoinMatchCandidate> candidates,
        const std::vector<interfaces::Wallet::PricoinOfferSnapshot>& wallet_orders,
        QWidget* parent = nullptr);
    ~PricoinMatchDialog() override = default;

    // Valid only after exec() returns Accepted.
    std::string chosenTheirOrderId() const { return m_chosen_their_id; }
    int64_t     chosenActualPricSat() const { return m_chosen_actual_pric_sat; }

private Q_SLOTS:
    void onCandidateChanged();
    void onAmountChanged(int);

private:
    interfaces::Wallet::PricoinOfferSnapshot m_mine;
    std::vector<interfaces::Wallet::PricoinMatchCandidate> m_candidates;
    // Index by order_id for easy lookup of the maker (asker)'s rate.
    std::vector<interfaces::Wallet::PricoinOfferSnapshot> m_wallet_orders;

    QTableView* m_table{nullptr};
    QStandardItemModel* m_model{nullptr};
    QSpinBox* m_amount_spin{nullptr};
    QLabel* m_preview_label{nullptr};
    QPushButton* m_ok_button{nullptr};

    std::string m_chosen_their_id;
    int64_t m_chosen_actual_pric_sat{0};

    void buildLayout();
    int  selectedCandidateIndex() const;
    void updatePreview();

    // Locate the order with `order_id` in `m_wallet_orders` (which
    // holds the wallet's full snapshot at the time the dialog opened).
    const interfaces::Wallet::PricoinOfferSnapshot* findOrder(const std::string& order_id) const;
};

#endif // BITCOIN_QT_PRICOIN_MATCH_DIALOG_H
