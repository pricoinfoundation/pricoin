// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_PRICOINORDERBOOKPAGE_H
#define BITCOIN_QT_PRICOINORDERBOOKPAGE_H

#include <QHash>
#include <QSet>
#include <QString>
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
    void onNostrOfferCancellationReceived(const QString& order_id_hex);
    void onNostrDmReceived(const QString& from_xonly_hex, const QString& plaintext);
    void onNostrDmSent(const QString& dm_id, const QString& peer_xonly_hex);
    void onNostrDmAcked(const QString& dm_id, const QString& peer_xonly_hex);
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

    // Pending DM tracking — maps dm_id → human description ("Match
    // notification for order X…"). Populated on dmSent, cleared on
    // dmAcked. Used to surface "Awaiting receipt…" / "Counterparty
    // received" status updates.
    QHash<QString, QString> m_pending_dms;
    // Label for the NEXT publishDirectMessage call. Set just before
    // the publish; consumed by onNostrDmSent (which fires
    // synchronously via Qt::AutoConnection on the same thread).
    QString                 m_next_dm_label;

    PricoinNostrClient* m_nostr{nullptr};
    int                 m_connected_relay_count{0};

    // Local orders that have been created/cancelled while no relay
    // was connected. Drained from onNostrRelayStatus when at least
    // one relay comes up. Stores the order_id; on drain we re-read
    // the order's current status from the wallet, so a record that
    // was created and then immediately cancelled while offline still
    // gets the cancellation published (not the now-stale create).
    QSet<QString>       m_pending_publish_offers;
    QSet<QString>       m_pending_publish_cancels;
    // Per-local-order remember of the last `pric_remaining_sat` we
    // republished to peers. The refresh tick only sends a fresh
    // offer URI when the remaining has actually shrunk since the
    // previous publish — avoids spamming relays on every refresh.
    // In-memory only; on restart we'll republish once per order
    // whose remaining < max (cheap, idempotent on the peer side).
    QHash<QString, int64_t> m_last_republished_remaining;

    // Counterparty's swap-side addresses, keyed by THE LOCAL ORDER ID
    // they're pinned to. Populated when the swap_addrs DM lands;
    // consumed when the user opens Start-swap so they don't have to
    // paste the peer's BTC P2TR xonly + PRIC stealth manually. Both
    // sides exchange these automatically right after a match.
    //
    // view_pubkey + spend_pubkey are the peer's raw PRIC stealth
    // pubkeys (33-byte hex each). The dialog uses them to pre-compute
    // the joint stealth address client-side instead of requiring the
    // separate joint-stealth-dialog handshake.
    struct PeerSwapAddrs {
        QString btc_xonly;
        QString pric_stealth;
        QString view_pubkey;
        QString spend_pubkey;
        QString joint_address;     // computed on receive, cached
    };
    QHash<QString, PeerSwapAddrs> m_peer_swap_addrs;

    void rebuildNostrClient();
    // Publish helpers used by onCreateClicked / onCancelClicked.
    // If at least one relay is connected, push immediately;
    // otherwise queue for drain on relayStatusChanged → connected.
    void publishOrQueueOffer(const std::string& order_id);
    void publishOrQueueCancel(const std::string& order_id);
    void drainPendingPublishes();

    // Wallet-derived helpers used by the Start-swap pre-fill path.
    // Both pull from the loaded wallet via the existing RPC surface:
    //   pricoin_btc_getaddress(chain) → {address, xonly, chain}
    //   pricoin_getstealthaddress    → {address, view_pubkey, …}
    // Returns empty on failure (locked wallet, RPC error, …).
    QString getMyBtcXOnly(const QString& chain) const;
    QString getMyPricStealth() const;

    // Send the peer my BTC P2TR xonly + PRIC stealth so they can
    // pre-fill their Start-swap dialog. Symmetrical: both sides call
    // it right after a match. Idempotent.
    void sendSwapAddrs(const std::string& my_oid,
                        const std::string& peer_oid,
                        const std::string& foreign_chain);

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
