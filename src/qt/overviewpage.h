// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_OVERVIEWPAGE_H
#define BITCOIN_QT_OVERVIEWPAGE_H

#include <interfaces/wallet.h>

#include <QWidget>
#include <memory>
#include <string>
#include <vector>

class ClientModel;
class TransactionFilterProxy;
class TxViewDelegate;
class PlatformStyle;
class WalletModel;

namespace Ui {
    class OverviewPage;
}

QT_BEGIN_NAMESPACE
class QDialog;
class QLabel;
class QModelIndex;
class QTableWidget;
QT_END_NAMESPACE

/** Overview ("home") page widget */
class OverviewPage : public QWidget
{
    Q_OBJECT

public:
    explicit OverviewPage(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~OverviewPage();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);
    void showOutOfSyncWarning(bool fShow);

public Q_SLOTS:
    void setBalance(const interfaces::WalletBalances& balances);
    void setPrivacy(bool privacy);

Q_SIGNALS:
    void transactionClicked(const QModelIndex &index);
    void outOfSyncWarningClicked();

protected:
    void changeEvent(QEvent* e) override;

private:
    Ui::OverviewPage *ui;
    ClientModel* clientModel{nullptr};
    WalletModel* walletModel{nullptr};
    bool m_privacy{false};

    const PlatformStyle* m_platform_style;

    TxViewDelegate *txdelegate;
    std::unique_ptr<TransactionFilterProxy> filter;

    // Pricoin Phase B: confidential balance label, populated on each
    // setBalance() call.
    QLabel* m_pricoin_ct_label{nullptr};

    // Pricoin: persistent confidential-transaction history table, fed by
    // the `pricoin_listcttransactions` RPC (received + reconstructed sends,
    // surviving spend). Refreshed on the same trigger as the CT balance.
    QTableWidget* m_pricoin_ct_tx_table{nullptr};
    void refreshPricoinCtTransactions();

    // Full RPC JSON for each visible CT-table row (same order as the table),
    // so the click-for-details dialog can show the fields the columns omit
    // (vout, spent_in_txid, total_input, change_returned, ...).
    std::vector<std::string> m_pricoin_ct_rows;
    QDialog* m_pricoin_ct_detail_dialog{nullptr};

private Q_SLOTS:
    void LimitTransactionRows();
    void updateDisplayUnit();
    void handleTransactionClicked(const QModelIndex &index);
    void showPricoinCtTxDetails(int row, int column);
    void updateAlerts(const QString &warnings);
    void setMonospacedFont(const QFont&);
};

#endif // BITCOIN_QT_OVERVIEWPAGE_H
