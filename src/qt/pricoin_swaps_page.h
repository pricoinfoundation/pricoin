// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_PRICOIN_SWAPS_PAGE_H
#define BITCOIN_QT_PRICOIN_SWAPS_PAGE_H

#include <QWidget>

#include <vector>

#include <interfaces/wallet.h>

class WalletModel;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QTableView;
class QStandardItemModel;
class QPushButton;
class QLabel;
class QTextEdit;
class QTimer;
class QCheckBox;
class QJsonObject;
QT_END_NAMESPACE

// Phase 5/6 cross-track UI: read-only view of `pricoin_adaptor_swap`
// records, with the role-aware "next action" hint surfaced per row.
//
// State transitions through the multi-step swap protocol (set adaptor
// materials, set timelocks, pre-sign, claim, fill, refund) are still
// driven via RPC for now — this page exists to give the GUI user
// visibility into the running swaps the orderbook produced (or that
// were created via the existing 12 lifecycle RPCs). A follow-up
// commit will add wizard-style action buttons that wrap each
// transition.
//
// Refresh is automatic every 5 s plus on `setModel()`.

class PricoinSwapsPage : public QWidget
{
    Q_OBJECT

public:
    explicit PricoinSwapsPage(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~PricoinSwapsPage() override;

    void setModel(WalletModel* model);

private Q_SLOTS:
    void onRefreshClicked();
    void onAbortClicked();
    void onAdvanceClicked();
    void onRefundClicked();
    void onSelectionChanged();
    void onAutoRefreshTick();
    void onSwapwatchStartClicked();
    void onSwapwatchStopClicked();
    void onSwapwatchTickClicked();
    void onSwapwatchAddClicked();
    void onSwapwatchRemoveClicked();
    void onSwapwatchRefresh();
    void onAdaptBtcClaimClicked();
    void onAdaptPricClaimClicked();
    void onLtcRefundClicked();
    void onExtractTClicked();

private:
    WalletModel* m_model{nullptr};
    const PlatformStyle* m_platform_style;

    QTableView* m_table{nullptr};
    QStandardItemModel* m_table_model{nullptr};
    QPushButton* m_btn_refresh{nullptr};
    QCheckBox*   m_filter_hide_terminal{nullptr};
    QPushButton* m_btn_advance{nullptr};
    QPushButton* m_btn_refund{nullptr};
    QPushButton* m_btn_abort{nullptr};
    QLabel*      m_status_label{nullptr};
    QTextEdit*   m_next_action_view{nullptr};
    QTimer*      m_auto_refresh_timer{nullptr};

    // ─── Tier-3 swap-watcher panel ───
    QLabel*             m_sw_status_label{nullptr};
    QPushButton*        m_btn_sw_start{nullptr};
    QPushButton*        m_btn_sw_stop{nullptr};
    QPushButton*        m_btn_sw_tick{nullptr};
    QPushButton*        m_btn_sw_add{nullptr};
    QPushButton*        m_btn_sw_remove{nullptr};
    QPushButton*        m_btn_sw_refresh{nullptr};
    QPushButton*        m_btn_adapt_btc_claim{nullptr};
    QPushButton*        m_btn_adapt_pric_claim{nullptr};
    QPushButton*        m_btn_ltc_refund{nullptr};
    QPushButton*        m_btn_extract_t{nullptr};
    QTableView*         m_sw_table{nullptr};
    QStandardItemModel* m_sw_table_model{nullptr};

    std::vector<interfaces::Wallet::PricoinAdaptorSwapSnapshot> m_swaps;

    void buildLayout();
    void refreshTable();
    void setStatus(const QString& msg, bool error = false);
    std::string selectedSwapId() const;
    std::string selectedSwapwatchSwapId() const;
    std::string selectedSwapwatchKind()   const;

    // Send a DM to a swap's counterparty. Used to mirror state changes
    // that the protocol layer doesn't observe on chain (abort,
    // adaptor-setup payload). Returns true if at least one relay
    // accepted the event.
    bool sendSwapCoordDM(const std::string& swap_id,
                          const QJsonObject& msg);
};

#endif // BITCOIN_QT_PRICOIN_SWAPS_PAGE_H
