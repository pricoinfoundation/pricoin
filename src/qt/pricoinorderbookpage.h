// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_PRICOINORDERBOOKPAGE_H
#define BITCOIN_QT_PRICOINORDERBOOKPAGE_H

#include <QWidget>

#include <vector>

#include <interfaces/wallet.h>

class PricoinNostrClient;
class WalletModel;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QTableView;
class QStandardItemModel;
class QSortFilterProxyModel;
class QPushButton;
class QLabel;
class QCheckBox;
class QComboBox;
class QTimer;
QT_END_NAMESPACE

// Phase-6 orderbook UI (Tier 1).
//
// Single-page widget surface backing the wallet's order management:
// a table of all orders + buttons for the lifecycle operations
// (create, import, cancel, copy URI, find matches, fill, unmatch).
//
// Each operation calls into `interfaces::Wallet` (offerCreate,
// offerImport, offerList, etc.). Match-driven swap orchestration
// (kicking off the cooperative-signing protocol once a match locks)
// is a follow-up — this page exposes the order state machine but
// does not yet drive the on-chain swap from the GUI.
//
// Layout (top to bottom):
//   [ Create ] [ Import URI ] [ Refresh ]              status label
//   ┌─ orders table (id-prefix, origin, side, chain,
//   │                max_pric, foreign_at_max, status,
//   │                remaining, in_flight, matched_with) ┐
//   └──────────────────────────────────────────────────────┘
//   [ Cancel ] [ Copy URI ] [ Find Matches ] [ Fill ] [ Unmatch ]

class PricoinOrderbookPage : public QWidget
{
    Q_OBJECT

public:
    explicit PricoinOrderbookPage(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~PricoinOrderbookPage() override;

    void setModel(WalletModel* model);

private Q_SLOTS:
    void onCreateClicked();
    void onImportClicked();
    void onRefreshClicked();
    void onCancelClicked();
    void onCopyUriClicked();
    void onFindMatchesClicked();
    void onFillClicked();
    void onUnmatchClicked();
    void onSelectionChanged();
    void onPublishClicked();
    void onConnectRelaysClicked();
    void onRelaySettingsClicked();
    void onStartSwapClicked();
    void onNostrOfferReceived(const QString& uri);
    void onNostrDmReceived(const QString& from_xonly_hex, const QString& plaintext);
    void onNostrLog(const QString& msg);
    void onNostrRelayStatus(const QString& url, bool connected);
    void onAutoRefreshTick();
    void onFilterChanged();

private:
    WalletModel* m_model{nullptr};
    const PlatformStyle* m_platform_style;

    QTableView* m_table{nullptr};
    QStandardItemModel* m_table_model{nullptr};
    QSortFilterProxyModel* m_proxy{nullptr};
    QCheckBox*  m_filter_active_only{nullptr};
    QComboBox*  m_filter_origin{nullptr};
    QComboBox*  m_filter_chain{nullptr};
    QPushButton* m_btn_create{nullptr};
    QPushButton* m_btn_import{nullptr};
    QPushButton* m_btn_refresh{nullptr};
    QPushButton* m_btn_cancel{nullptr};
    QPushButton* m_btn_copy_uri{nullptr};
    QPushButton* m_btn_find_matches{nullptr};
    QPushButton* m_btn_fill{nullptr};
    QPushButton* m_btn_unmatch{nullptr};
    QPushButton* m_btn_publish{nullptr};
    QPushButton* m_btn_start_swap{nullptr};
    QPushButton* m_btn_connect_relays{nullptr};
    QPushButton* m_btn_relay_settings{nullptr};
    QLabel*      m_status_label{nullptr};
    QLabel*      m_relay_status_label{nullptr};
    QTimer*      m_auto_refresh_timer{nullptr};

    PricoinNostrClient* m_nostr{nullptr};
    int                 m_connected_relay_count{0};

    void rebuildNostrClient();

    // Cached snapshots indexed parallel to table rows so we can map
    // a selected row back to the underlying order_id without
    // re-parsing the table cells.
    std::vector<interfaces::Wallet::PricoinOfferSnapshot> m_orders;

    void buildLayout();
    void refreshTable();
    void setStatus(const QString& msg, bool error = false);
    std::string selectedOrderId() const;  // empty if nothing selected
};

#endif // BITCOIN_QT_PRICOINORDERBOOKPAGE_H
