// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_PRICOIN_HOLDING_PAGE_H
#define BITCOIN_QT_PRICOIN_HOLDING_PAGE_H

#include <QWidget>

class WalletModel;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QLabel;
class QLineEdit;
class QPushButton;
class QTimer;
QT_END_NAMESPACE

// Phase A — BTC/LTC "holding wallet" surface in the Qt GUI.
//
// Each chain (btc, ltc) has its own panel showing:
//   * The wallet's deterministic receive address (HMAC-derived from
//     the wallet's stealth seed; same on every restart).
//   * Confirmed + unconfirmed balance + UTXO count, refreshed every
//     15 s via the configured ChainBackend (Esplora-style HTTP).
//   * "Copy address" button.
//   * "Sweep all to…" button — collects all UTXOs at the holding
//     address into a single tx paying a user-supplied destination.
//
// The page calls the existing pricoin_btc_getaddress / _getbalance /
// _sweep RPCs via the same `CallWalletRpc` helper used by other
// Pricoin Qt pages. No interfaces::Wallet plumbing.
//
// The chain backends must be configured (`-btcwatchurl=`,
// `-ltcwatchurl=`) for balance lookups to succeed; without them, the
// balance row shows a "no backend configured" hint.

class PricoinHoldingPage : public QWidget
{
    Q_OBJECT

public:
    explicit PricoinHoldingPage(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~PricoinHoldingPage() override;

    void setModel(WalletModel* model);

private Q_SLOTS:
    void onRefreshClicked();
    void onAutoRefreshTick();
    void onCopyBtcClicked();
    void onCopyLtcClicked();
    void onSweepBtcClicked();
    void onSweepLtcClicked();

private:
    struct ChainPanel {
        QLineEdit*   address{nullptr};
        QLabel*      balance{nullptr};
        QLabel*      hint{nullptr};
        QPushButton* btn_copy{nullptr};
        QPushButton* btn_sweep{nullptr};
    };

    WalletModel* m_model{nullptr};
    const PlatformStyle* m_platform_style;

    QPushButton* m_btn_refresh{nullptr};
    QLabel*      m_status{nullptr};
    QTimer*      m_refresh_timer{nullptr};

    ChainPanel m_btc;
    ChainPanel m_ltc;

    void buildLayout();
    void refreshChain(const QString& chain, ChainPanel& panel);
    void doSweep(const QString& chain, const ChainPanel& panel);
    void setStatus(const QString& msg, bool error = false);
};

#endif // BITCOIN_QT_PRICOIN_HOLDING_PAGE_H
