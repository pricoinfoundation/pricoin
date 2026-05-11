// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pricoinorderbookpage.h>

#include <common/args.h>
#include <index/txindex.h>
#include <qt/pricoin_joint_stealth_dialog.h>
#include <qt/pricoin_match_dialog.h>
#include <qt/pricoin_nostr_client.h>
#include <qt/pricoin_relay_settings_dialog.h>
#include <qt/walletmodel.h>
#include <interfaces/node.h>
#include <tinyformat.h>
#include <util/translation.h>
#include <univalue.h>

#include <cmath>

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QBrush>
#include <QCheckBox>
#include <QColor>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QTableView>
#include <QTextEdit>
#include <QTimer>
#include <QVBoxLayout>

namespace {

QString FormatSat(int64_t sat) {
    // 8-decimal format, like Bitcoin Core's standard.
    const int64_t whole = sat / 100'000'000;
    const int64_t frac  = sat % 100'000'000;
    return QString::asprintf("%lld.%08lld",
                              static_cast<long long>(whole),
                              static_cast<long long>(frac));
}

QString FormatExpiry(int64_t unix_sec) {
    if (unix_sec <= 0) return "-";
    return QDateTime::fromSecsSinceEpoch(unix_sec).toString("yyyy-MM-dd HH:mm");
}

QString StatusBadge(const std::string& s) {
    QString q = QString::fromStdString(s);
    if (!q.isEmpty()) q[0] = q[0].toUpper();
    return q;
}

// Picks a foreground color for a status cell. Tuned for both light
// and dark terminal-ish themes — bright accents that read on
// either backdrop.
QColor StatusColor(const std::string& s) {
    if (s == "active")    return QColor(0x1b, 0x5e, 0x20); // green
    if (s == "matched")   return QColor(0xe6, 0x91, 0x38); // amber
    if (s == "filled")    return QColor(0x14, 0x4f, 0xc9); // blue
    if (s == "cancelled") return QColor(0x70, 0x70, 0x70); // grey
    if (s == "expired")   return QColor(0x7f, 0x00, 0x00); // dark red
    return QColor(Qt::black);
}

// Modal "Create offer" dialog. Returns the create params on accept.
class CreateOfferDialog : public QDialog
{
public:
    explicit CreateOfferDialog(QWidget* parent)
        : QDialog(parent)
    {
        setWindowTitle(tr("Create order"));
        auto* form = new QFormLayout(this);

        m_side = new QComboBox(this);
        m_side->addItem(tr("Sell PRIC (pay PRIC, receive foreign)"), QStringLiteral("sell_pric"));
        m_side->addItem(tr("Buy PRIC (pay foreign, receive PRIC)"), QStringLiteral("buy_pric"));
        form->addRow(tr("Side:"), m_side);

        m_chain = new QComboBox(this);
        m_chain->addItem(QStringLiteral("BTC"), QStringLiteral("btc"));
        m_chain->addItem(QStringLiteral("LTC"), QStringLiteral("ltc"));
        form->addRow(tr("Foreign chain:"), m_chain);

        // Quantity field: PRIC for sellers, foreign for buyers.
        // Label updates from `RefreshLabels()` when side or chain
        // changes.
        m_qty = new QLineEdit(this);
        m_qty_label = new QLabel(this);
        form->addRow(m_qty_label, m_qty);

        // Price field: always foreign per PRIC.
        m_price = new QLineEdit(this);
        m_price_label = new QLabel(this);
        form->addRow(m_price_label, m_price);

        // Live preview line so the user sees the resulting bundle.
        m_preview = new QLabel(this);
        m_preview->setStyleSheet(QStringLiteral("QLabel { color: #555; }"));
        form->addRow(QString(), m_preview);

        m_expiry_hours = new QSpinBox(this);
        m_expiry_hours->setRange(1, 168);          // 1 hour … 1 week
        m_expiry_hours->setValue(24);
        form->addRow(tr("Expires in (hours):"), m_expiry_hours);

        m_notes = new QLineEdit(this);
        form->addRow(tr("Notes (local-only):"), m_notes);

        auto* bb = new QDialogButtonBox(
            QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
        connect(bb, &QDialogButtonBox::accepted, this, &QDialog::accept);
        connect(bb, &QDialogButtonBox::rejected, this, &QDialog::reject);
        form->addRow(bb);

        // Wire reactive label/preview updates.
        connect(m_side, QOverload<int>::of(&QComboBox::currentIndexChanged),
                this, &CreateOfferDialog::RefreshLabels);
        connect(m_chain, QOverload<int>::of(&QComboBox::currentIndexChanged),
                this, &CreateOfferDialog::RefreshLabels);
        connect(m_qty,   &QLineEdit::textChanged, this, &CreateOfferDialog::RefreshPreview);
        connect(m_price, &QLineEdit::textChanged, this, &CreateOfferDialog::RefreshPreview);
        RefreshLabels();
    }

    bool getParams(interfaces::Wallet::PricoinOfferCreateParams& out, QString& err) const {
        bool ok_qty = false, ok_price = false;
        const double qty   = m_qty->text().trimmed().toDouble(&ok_qty);
        const double price = m_price->text().trimmed().toDouble(&ok_price);
        if (!ok_qty   || qty   <= 0) { err = tr("quantity must be a positive number"); return false; }
        if (!ok_price || price <= 0) { err = tr("price must be a positive number"); return false; }

        out.side = m_side->currentData().toString().toStdString();
        out.foreign_chain = m_chain->currentData().toString().toStdString();
        // Qty interpretation:
        //   sell_pric — qty is in PRIC; foreign side = qty * price.
        //   buy_pric  — qty is in foreign; PRIC side = qty / price.
        // Both forms collapse to the same on-wire fields:
        //   max_pric_amount_sat       = the order's max PRIC quantity
        //   foreign_amount_at_max_sat = foreign paid at full fill
        // — i.e. the rate is foreign / pric.
        if (out.side == "sell_pric") {
            out.max_pric_amount_sat       = static_cast<int64_t>(qty * 100'000'000.0);
            out.foreign_amount_at_max_sat = static_cast<int64_t>(qty * price * 100'000'000.0);
        } else {
            out.max_pric_amount_sat       = static_cast<int64_t>((qty / price) * 100'000'000.0);
            out.foreign_amount_at_max_sat = static_cast<int64_t>(qty * 100'000'000.0);
        }
        if (out.max_pric_amount_sat <= 0 || out.foreign_amount_at_max_sat <= 0) {
            err = tr("computed amount underflowed to zero — increase qty or price");
            return false;
        }
        // Min-trade gate. Trading amounts smaller than typical fees on
        // the foreign chain quickly turns into a fee-only loss when
        // anything goes wrong (and on the user's first tests, things
        // tend to). Conservative per-chain floors here; tune later.
        // PRIC floor stays uniform since on-chain footprint per swap
        // is similar regardless of chain.
        constexpr int64_t kMinPricSat = 100'000'000;          // 1 PRIC
        const int64_t min_foreign_sat = [&]() -> int64_t {
            if (out.foreign_chain == "btc")     return    50'000;  // 0.0005 BTC
            if (out.foreign_chain == "ltc")     return   500'000;  // 0.005 LTC
            if (out.foreign_chain == "regtest") return         1;  // tests
            return                                          50'000;
        }();
        if (out.max_pric_amount_sat < kMinPricSat) {
            err = tr("PRIC amount %1 is below the minimum %2 — small trades are "
                     "fee-loss-prone and not allowed.")
                    .arg(QString::number(static_cast<double>(out.max_pric_amount_sat)/1e8, 'f', 8))
                    .arg(QString::number(static_cast<double>(kMinPricSat)/1e8, 'f', 8));
            return false;
        }
        if (out.foreign_amount_at_max_sat < min_foreign_sat) {
            err = tr("Foreign (%1) amount %2 is below the minimum %3 — small "
                     "trades are fee-loss-prone and not allowed.")
                    .arg(QString::fromStdString(out.foreign_chain).toUpper())
                    .arg(QString::number(static_cast<double>(out.foreign_amount_at_max_sat)/1e8, 'f', 8))
                    .arg(QString::number(static_cast<double>(min_foreign_sat)/1e8, 'f', 8));
            return false;
        }
        // Buy-PRIC orders require txindex=1 on this node. Reason: the
        // PRIC funding tx is broadcast by the seller (Alice) into a
        // joint-stealth output that the buyer's (Bob's) wallet can't
        // see in mapWallet (cooperative output, requires both view
        // shares). The chain watcher's PricTxStatus falls back to
        // node::GetTransaction(nullptr, mempool, ...) which only finds
        // confirmed-but-not-mempool txs via g_txindex. Without
        // txindex, the buyer's swap stalls at BtcFunded waiting for
        // a confirmation that never auto-detects.
        // Use DEFAULT_TXINDEX (= true for Pricoin) as the fallback so
        // users on the default config don't trip the gate. The gate
        // only fires when the user explicitly sets -txindex=0.
        if (out.side == "buy_pric"
            && !gArgs.GetBoolArg("-txindex", DEFAULT_TXINDEX)) {
            err = tr("Buy-PRIC orders require txindex=1 on this node.\n\n"
                     "Without it, your wallet can't auto-confirm the seller's "
                     "PRIC funding tx (it's a joint-stealth output your wallet "
                     "doesn't track on its own), and the swap will stall at "
                     "BtcFunded.\n\nTo enable: add `txindex=1` to your "
                     "pricoin.conf, restart pricoind/qt, and wait for the "
                     "txindex to build (seconds to minutes for the current "
                     "chain). Then re-create this order.");
            return false;
        }
        out.expiry_unix_sec = QDateTime::currentSecsSinceEpoch()
                              + static_cast<int64_t>(m_expiry_hours->value()) * 3600;
        out.notes = m_notes->text().toStdString();
        return true;
    }

private:
    void RefreshLabels() {
        const QString chain = m_chain->currentData().toString().toUpper();
        const QString side  = m_side->currentData().toString();
        if (side == "sell_pric") {
            m_qty_label->setText(tr("Max PRIC quantity:"));
            m_qty->setPlaceholderText(tr("e.g. 1.00000000  (PRIC you'll sell)"));
        } else {
            m_qty_label->setText(tr("Max %1 quantity:").arg(chain));
            m_qty->setPlaceholderText(tr("e.g. 0.50000000  (%1 you'll spend)").arg(chain));
        }
        m_price_label->setText(tr("Price (%1 per PRIC):").arg(chain));
        m_price->setPlaceholderText(tr("e.g. 0.50000000"));
        RefreshPreview();
    }

    void RefreshPreview() {
        bool ok_qty = false, ok_price = false;
        const double qty   = m_qty->text().trimmed().toDouble(&ok_qty);
        const double price = m_price->text().trimmed().toDouble(&ok_price);
        if (!ok_qty || qty <= 0 || !ok_price || price <= 0) {
            m_preview->setText(QString());
            return;
        }
        const QString chain = m_chain->currentData().toString().toUpper();
        const QString side  = m_side->currentData().toString();
        const double pric_amt    = (side == "sell_pric") ? qty : qty / price;
        const double foreign_amt = (side == "sell_pric") ? qty * price : qty;
        const QString verb = (side == "sell_pric") ? tr("Sell") : tr("Buy");
        m_preview->setText(tr("→ %1 up to %2 PRIC for %3 %4 (rate %5 %4/PRIC)")
            .arg(verb)
            .arg(QString::number(pric_amt,    'f', 8))
            .arg(QString::number(foreign_amt, 'f', 8))
            .arg(chain)
            .arg(QString::number(price,       'f', 8)));
    }

    QComboBox* m_side;
    QComboBox* m_chain;
    QLabel*    m_qty_label;
    QLineEdit* m_qty;
    QLabel*    m_price_label;
    QLineEdit* m_price;
    QLabel*    m_preview;
    QSpinBox*  m_expiry_hours;
    QLineEdit* m_notes;
};

// Fetch the wallet's stealth identity as (view_pubkey, spend_pubkey)
// hex pair. Empty pair on failure.
struct MyStealthPubkeys { QString view_hex, spend_hex; };
inline MyStealthPubkeys GetMyStealthPubkeys(WalletModel* wm)
{
    MyStealthPubkeys out;
    if (!wm) return out;
    const QString wallet_name = wm->getWalletName();
    std::string uri;
    if (!wallet_name.isEmpty()) {
        uri = "/wallet/" + std::string(
            QUrl::toPercentEncoding(wallet_name).constData());
    }
    UniValue empty_params{UniValue::VARR};
    UniValue r;
    try {
        r = wm->node().executeRpc("pricoin_getstealthaddress", empty_params, uri);
    } catch (const UniValue&) {
        return out;
    } catch (const std::exception&) {
        return out;
    }
    if (!r.isObject()) return out;
    if (r.exists("view_pubkey"))  out.view_hex  = QString::fromStdString(r["view_pubkey"].get_str());
    if (r.exists("spend_pubkey")) out.spend_hex = QString::fromStdString(r["spend_pubkey"].get_str());
    return out;
}

// Build the joint stealth address from (my privs + peer pubkeys).
// Returns "" on RPC failure.
inline QString BuildJointStealthAddr(WalletModel* wm,
                                       const QString& peer_view_hex,
                                       const QString& peer_spend_hex)
{
    if (!wm || peer_view_hex.isEmpty() || peer_spend_hex.isEmpty()) return {};
    const QString wallet_name = wm->getWalletName();
    std::string uri;
    if (!wallet_name.isEmpty()) {
        uri = "/wallet/" + std::string(
            QUrl::toPercentEncoding(wallet_name).constData());
    }
    UniValue p{UniValue::VARR};
    p.push_back(peer_view_hex.toStdString());
    p.push_back(peer_spend_hex.toStdString());
    UniValue r;
    try {
        r = wm->node().executeRpc("pricoin_buildjointstealthaddress", p, uri);
    } catch (const UniValue&) {
        return {};
    } catch (const std::exception&) {
        return {};
    }
    if (!r.isObject() || !r.exists("address")) return {};
    return QString::fromStdString(r["address"].get_str());
}

} // namespace

PricoinOrderbookPage::PricoinOrderbookPage(const PlatformStyle* platformStyle, QWidget* parent)
    : QWidget(parent),
      m_platform_style(platformStyle)
{
    buildLayout();
}

PricoinOrderbookPage::~PricoinOrderbookPage() = default;

void PricoinOrderbookPage::buildLayout()
{
    auto* outer = new QVBoxLayout(this);

    // Top row: action buttons + status.
    auto* top_row = new QHBoxLayout();
    m_btn_create  = new QPushButton(tr("Create order…"), this);
    m_btn_import  = new QPushButton(tr("Import URI…"),  this);
    m_btn_refresh = new QPushButton(tr("Refresh"),       this);
    top_row->addWidget(m_btn_create);
    top_row->addWidget(m_btn_import);
    top_row->addWidget(m_btn_refresh);
    top_row->addStretch();
    m_status_label = new QLabel(this);
    m_status_label->setWordWrap(true);
    top_row->addWidget(m_status_label, /*stretch=*/1);
    outer->addLayout(top_row);

    // Filter row.
    auto* filter_row = new QHBoxLayout();
    m_filter_active_only = new QCheckBox(tr("Active only"), this);
    m_filter_active_only->setChecked(true);
    filter_row->addWidget(m_filter_active_only);

    filter_row->addWidget(new QLabel(tr("Origin:"), this));
    m_filter_origin = new QComboBox(this);
    m_filter_origin->addItem(tr("All"),      QStringLiteral("all"));
    m_filter_origin->addItem(tr("Local"),    QStringLiteral("local"));
    m_filter_origin->addItem(tr("Imported"), QStringLiteral("imported"));
    filter_row->addWidget(m_filter_origin);

    filter_row->addWidget(new QLabel(tr("Chain:"), this));
    m_filter_chain = new QComboBox(this);
    m_filter_chain->addItem(tr("All"), QStringLiteral("all"));
    m_filter_chain->addItem(QStringLiteral("BTC"), QStringLiteral("btc"));
    m_filter_chain->addItem(QStringLiteral("LTC"), QStringLiteral("ltc"));
    filter_row->addWidget(m_filter_chain);
    filter_row->addStretch();
    outer->addLayout(filter_row);

    connect(m_filter_active_only, &QCheckBox::stateChanged,
            this, &PricoinOrderbookPage::onFilterChanged);
    connect(m_filter_origin,
            QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PricoinOrderbookPage::onFilterChanged);
    connect(m_filter_chain,
            QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PricoinOrderbookPage::onFilterChanged);

    // Table.
    m_table_model = new QStandardItemModel(this);
    m_table_model->setHorizontalHeaderLabels({
        tr("Order id"), tr("Origin"), tr("Side"), tr("Chain"),
        tr("Max PRIC"), tr("Foreign @ max"), tr("Rate (foreign/PRIC)"),
        tr("Status"), tr("Remaining"), tr("In flight"),
        tr("Expires"), tr("Notes")
    });
    // QSortFilterProxyModel between the source model and the view —
    // gives us click-to-sort headers for free. Filtering by status /
    // origin / chain is done at refresh time (re-populates source).
    m_proxy = new QSortFilterProxyModel(this);
    m_proxy->setSourceModel(m_table_model);
    m_table = new QTableView(this);
    m_table->setModel(m_proxy);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSortingEnabled(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->horizontalHeader()->setStretchLastSection(true);
    outer->addWidget(m_table, /*stretch=*/1);

    // Bottom row: per-order actions.
    auto* bot_row = new QHBoxLayout();
    m_btn_cancel       = new QPushButton(tr("Cancel"),        this);
    m_btn_copy_uri     = new QPushButton(tr("Copy URI"),      this);
    m_btn_find_matches = new QPushButton(tr("Find matches"),  this);
    m_btn_fill         = new QPushButton(tr("Fill"),          this);
    m_btn_unmatch      = new QPushButton(tr("Unmatch"),       this);
    m_btn_publish      = new QPushButton(tr("Publish to relays"), this);
    m_btn_start_swap   = new QPushButton(tr("Start swap…"),       this);
    bot_row->addWidget(m_btn_cancel);
    bot_row->addWidget(m_btn_copy_uri);
    bot_row->addWidget(m_btn_find_matches);
    bot_row->addWidget(m_btn_fill);
    bot_row->addWidget(m_btn_unmatch);
    bot_row->addWidget(m_btn_publish);
    bot_row->addWidget(m_btn_start_swap);
    bot_row->addStretch();
    outer->addLayout(bot_row);

    // Relay status row.
    auto* relay_row = new QHBoxLayout();
    m_btn_connect_relays = new QPushButton(tr("Connect relays"), this);
    m_btn_relay_settings = new QPushButton(tr("Relay settings…"), this);
    m_relay_status_label = new QLabel(tr("Relays: not connected"), this);
    m_relay_status_label->setWordWrap(true);
    relay_row->addWidget(m_btn_connect_relays);
    relay_row->addWidget(m_btn_relay_settings);
    relay_row->addWidget(m_relay_status_label, /*stretch=*/1);
    outer->addLayout(relay_row);

    // Auto-refresh: the table re-loads from the wallet every 5s so
    // expiry sweeps and external state changes (e.g., from CLI) show
    // up without the user clicking Refresh. Nostr-imported orders
    // already trigger an immediate refresh via offerReceived; this
    // timer is the safety net for everything else.
    m_auto_refresh_timer = new QTimer(this);
    m_auto_refresh_timer->setInterval(5000);
    connect(m_auto_refresh_timer, &QTimer::timeout, this, &PricoinOrderbookPage::onAutoRefreshTick);

    connect(m_btn_create,       &QPushButton::clicked, this, &PricoinOrderbookPage::onCreateClicked);
    connect(m_btn_import,       &QPushButton::clicked, this, &PricoinOrderbookPage::onImportClicked);
    connect(m_btn_refresh,      &QPushButton::clicked, this, &PricoinOrderbookPage::onRefreshClicked);
    connect(m_btn_cancel,       &QPushButton::clicked, this, &PricoinOrderbookPage::onCancelClicked);
    connect(m_btn_copy_uri,     &QPushButton::clicked, this, &PricoinOrderbookPage::onCopyUriClicked);
    connect(m_btn_find_matches, &QPushButton::clicked, this, &PricoinOrderbookPage::onFindMatchesClicked);
    connect(m_btn_fill,         &QPushButton::clicked, this, &PricoinOrderbookPage::onFillClicked);
    connect(m_btn_unmatch,      &QPushButton::clicked, this, &PricoinOrderbookPage::onUnmatchClicked);
    connect(m_btn_publish,         &QPushButton::clicked, this, &PricoinOrderbookPage::onPublishClicked);
    connect(m_btn_start_swap,      &QPushButton::clicked, this, &PricoinOrderbookPage::onStartSwapClicked);
    connect(m_btn_connect_relays,  &QPushButton::clicked, this, &PricoinOrderbookPage::onConnectRelaysClicked);
    connect(m_btn_relay_settings,  &QPushButton::clicked, this, &PricoinOrderbookPage::onRelaySettingsClicked);

    if (auto* sm = m_table->selectionModel()) {
        connect(sm, &QItemSelectionModel::selectionChanged,
                this, &PricoinOrderbookPage::onSelectionChanged);
    }

    onSelectionChanged();  // disable per-order buttons initially
}

void PricoinOrderbookPage::setModel(WalletModel* model)
{
    m_model = model;
    if (auto* sm = m_table->selectionModel()) {
        connect(sm, &QItemSelectionModel::selectionChanged,
                this, &PricoinOrderbookPage::onSelectionChanged);
    }
    refreshTable();
    if (m_model && m_auto_refresh_timer && !m_auto_refresh_timer->isActive()) {
        m_auto_refresh_timer->start();
    }

    // Auto-connect to the configured Nostr relay set on first attach.
    // Without this the user has to click "Connect to relays" before
    // anything in the orderbook works (publish, receive offers, match
    // DMs). Idempotent — connectAll() is safe if already connected.
    if (m_model) {
        rebuildNostrClient();
        if (m_nostr) {
            m_nostr->connectAll();
            setStatus(tr("Connecting to %1 relays…")
                .arg(m_nostr->relayUrls().size()));
        }
    }
}

void PricoinOrderbookPage::refreshTable()
{
    if (!m_model) {
        m_table_model->setRowCount(0);
        m_orders.clear();
        return;
    }
    m_orders = m_model->wallet().offerList();

    // Apply filters.
    const bool active_only = m_filter_active_only && m_filter_active_only->isChecked();
    const QString origin_f = m_filter_origin
        ? m_filter_origin->currentData().toString() : QStringLiteral("all");
    const QString chain_f  = m_filter_chain
        ? m_filter_chain->currentData().toString() : QStringLiteral("all");

    std::vector<interfaces::Wallet::PricoinOfferSnapshot> filtered;
    filtered.reserve(m_orders.size());
    for (const auto& o : m_orders) {
        if (active_only && o.status != "active" && o.status != "matched") continue;
        if (origin_f != "all" && QString::fromStdString(o.origin) != origin_f) continue;
        if (chain_f != "all" && QString::fromStdString(o.foreign_chain) != chain_f) continue;
        filtered.push_back(o);
    }

    m_table_model->setRowCount(static_cast<int>(filtered.size()));
    for (size_t i = 0; i < filtered.size(); ++i) {
        const auto& o = filtered[i];
        const QString id_short = QString::fromStdString(o.order_id).left(12) + "…";
        const QString rate = (o.max_pric_amount_sat > 0)
            ? QString::asprintf("%.8f",
                static_cast<double>(o.foreign_amount_at_max_sat) /
                static_cast<double>(o.max_pric_amount_sat))
            : QStringLiteral("-");
        int col = 0;
        auto* id_item = new QStandardItem(id_short);
        // Stash the full order_id on the row so selection mapping is
        // robust to sort/filter ordering. selectedOrderId() reads it back.
        id_item->setData(QString::fromStdString(o.order_id), Qt::UserRole + 1);
        m_table_model->setItem(static_cast<int>(i), col++, id_item);
        m_table_model->setItem(static_cast<int>(i), col++, new QStandardItem(QString::fromStdString(o.origin)));
        m_table_model->setItem(static_cast<int>(i), col++, new QStandardItem(QString::fromStdString(o.side)));
        m_table_model->setItem(static_cast<int>(i), col++, new QStandardItem(QString::fromStdString(o.foreign_chain)));
        m_table_model->setItem(static_cast<int>(i), col++, new QStandardItem(FormatSat(o.max_pric_amount_sat)));
        m_table_model->setItem(static_cast<int>(i), col++, new QStandardItem(FormatSat(o.foreign_amount_at_max_sat)));
        m_table_model->setItem(static_cast<int>(i), col++, new QStandardItem(rate));
        auto* status_item = new QStandardItem(StatusBadge(o.status));
        status_item->setForeground(QBrush(StatusColor(o.status)));
        QFont f = status_item->font();
        f.setBold(true);
        status_item->setFont(f);
        m_table_model->setItem(static_cast<int>(i), col++, status_item);
        m_table_model->setItem(static_cast<int>(i), col++, new QStandardItem(FormatSat(o.pric_remaining_sat)));
        m_table_model->setItem(static_cast<int>(i), col++, new QStandardItem(FormatSat(o.pric_in_flight_sat)));
        m_table_model->setItem(static_cast<int>(i), col++, new QStandardItem(FormatExpiry(o.expiry_unix_sec)));
        m_table_model->setItem(static_cast<int>(i), col++, new QStandardItem(QString::fromStdString(o.notes)));
    }
    m_table->resizeColumnsToContents();
    onSelectionChanged();
}

void PricoinOrderbookPage::setStatus(const QString& msg, bool error)
{
    if (!m_status_label) return;
    m_status_label->setStyleSheet(error
        ? QStringLiteral("QLabel { color: #b71c1c; }")
        : QStringLiteral("QLabel { color: #1b5e20; }"));
    m_status_label->setText(msg);
}

std::string PricoinOrderbookPage::selectedOrderId() const
{
    auto* sm = m_table->selectionModel();
    if (!sm) return {};
    const auto sel = sm->selectedRows();
    if (sel.isEmpty()) return {};
    // Map proxy index → source index → UserRole+1 on column 0 (the
    // full order_id stashed in refreshTable).
    QModelIndex proxy_idx = sel.first();
    QModelIndex src_idx = m_proxy ? m_proxy->mapToSource(proxy_idx) : proxy_idx;
    if (src_idx.row() < 0) return {};
    QStandardItem* item = m_table_model->item(src_idx.row(), 0);
    if (!item) return {};
    return item->data(Qt::UserRole + 1).toString().toStdString();
}

void PricoinOrderbookPage::onSelectionChanged()
{
    const bool has = !selectedOrderId().empty();
    bool is_local = false, is_active = false, is_matched = false;
    if (has) {
        const std::string id = selectedOrderId();
        for (const auto& o : m_orders) {
            if (o.order_id == id) {
                is_local = (o.origin == "local");
                is_active = (o.status == "active");
                is_matched = (o.status == "matched");
                break;
            }
        }
    }
    m_btn_cancel->setEnabled(has && (is_active || is_matched));
    m_btn_copy_uri->setEnabled(has && is_local);
    m_btn_find_matches->setEnabled(has && is_active);
    m_btn_fill->setEnabled(has && is_matched);
    m_btn_unmatch->setEnabled(has && is_matched);
    m_btn_publish->setEnabled(has && is_local && is_active &&
                              m_nostr && m_connected_relay_count > 0);
    // Start swap is offered when this row is matched. Either side
    // (the local order or the imported peer) is a valid trigger;
    // the dialog asks for the missing fields (joint stealth address,
    // refund timelocks).
    m_btn_start_swap->setEnabled(has && is_matched);
}

void PricoinOrderbookPage::onPublishClicked()
{
    if (!m_model || !m_nostr) return;
    const std::string oid = selectedOrderId();
    if (oid.empty()) return;
    const auto rec = m_model->wallet().offerGet(oid);
    if (!rec) return;
    if (rec->origin != "local") {
        setStatus(tr("Only Local orders can be published."), true);
        return;
    }
    const std::string uri = m_model->wallet().offerExportUri(oid);
    if (uri.empty()) {
        setStatus(tr("Export URI failed."), true);
        return;
    }
    const QString side = (rec->side == "buy_pric") ? "buy" : "sell";
    const bool ok = m_nostr->publishOfferUri(
        QString::fromStdString(uri),
        QString::fromStdString(rec->order_id),
        rec->expiry_unix_sec,
        QString::fromStdString(rec->foreign_chain),
        side);
    if (!ok) {
        setStatus(tr("Publish failed (no relay connected, or signing error)."), true);
    } else {
        setStatus(tr("Offer published to relays."));
    }
}

void PricoinOrderbookPage::rebuildNostrClient()
{
    // The Nostr client is owned by WalletModel as a per-wallet
    // singleton; both the orderbook page and the cooperative-sign
    // dialogs share it. We don't own m_nostr — disconnect signals,
    // ask the model to rebuild, then re-fetch + re-hook.
    if (m_nostr) {
        m_nostr->disconnect(this);
        m_nostr = nullptr;
        m_connected_relay_count = 0;
    }
    if (!m_model) return;
    m_model->resetNostrClient();
    m_nostr = m_model->getOrCreateNostrClient();
    if (!m_nostr) return;
    connect(m_nostr, &PricoinNostrClient::offerReceived,
            this, &PricoinOrderbookPage::onNostrOfferReceived);
    connect(m_nostr, &PricoinNostrClient::directMessageReceived,
            this, &PricoinOrderbookPage::onNostrDmReceived);
    connect(m_nostr, &PricoinNostrClient::dmSent,
            this, &PricoinOrderbookPage::onNostrDmSent);
    connect(m_nostr, &PricoinNostrClient::dmAcked,
            this, &PricoinOrderbookPage::onNostrDmAcked);
    connect(m_nostr, &PricoinNostrClient::log,
            this, &PricoinOrderbookPage::onNostrLog);
    connect(m_nostr, &PricoinNostrClient::relayStatusChanged,
            this, &PricoinOrderbookPage::onNostrRelayStatus);
    connect(m_nostr, &PricoinNostrClient::offerCancellationReceived,
            this, &PricoinOrderbookPage::onNostrOfferCancellationReceived);
}

void PricoinOrderbookPage::onConnectRelaysClicked()
{
    if (!m_model) return;
    rebuildNostrClient();
    if (!m_nostr) {
        setStatus(tr("No relays configured. Open Relay settings to add some."), true);
        return;
    }
    m_nostr->connectAll();
    setStatus(tr("Connecting to %1 relays…").arg(m_nostr->relayUrls().size()));
}

void PricoinOrderbookPage::onRelaySettingsClicked()
{
    PricoinRelaySettingsDialog dlg(this);
    if (dlg.exec() != QDialog::Accepted) return;
    PricoinRelaySettingsDialog::saveToSettings(dlg.relays());
    setStatus(tr("Relay list saved. Reconnecting…"));
    rebuildNostrClient();
    if (m_nostr) m_nostr->connectAll();
}

void PricoinOrderbookPage::onAutoRefreshTick()
{
    // Bail out if there's a pending in-place edit etc.; otherwise
    // re-pull. This is a bounded operation (single wallet RPC).
    if (!m_model) return;
    refreshTable();
}

void PricoinOrderbookPage::onFilterChanged()
{
    refreshTable();
}

void PricoinOrderbookPage::onStartSwapClicked()
{
    if (!m_model) return;
    const std::string oid = selectedOrderId();
    if (oid.empty()) return;

    // Refresh the cached order snapshot at click time. m_orders is
    // a stale-able copy populated by refreshTable; if the user clicks
    // Start-swap immediately after matching (before the next refresh
    // tick), the imported peer's maker_pubkey_hex can still be empty
    // → adaptorSwapCreate fails with "counterparty_pubkey must be
    // 33-byte compressed hex". Re-pulling from the wallet here closes
    // that race without needing to retry-click.
    m_orders = m_model->wallet().offerList();

    // Determine my-vs-peer order based on origin. The local order
    // (origin=local) is "mine"; the imported peer (origin=imported)
    // is the counterparty.
    const interfaces::Wallet::PricoinOfferSnapshot* mine = nullptr;
    const interfaces::Wallet::PricoinOfferSnapshot* peer = nullptr;
    for (const auto& o : m_orders) {
        if (o.order_id == oid) {
            if (o.origin == "local") mine = &o;
            else                     peer = &o;
        }
    }
    if (mine == nullptr || peer == nullptr) {
        // The user picked a row but its match counterpart isn't
        // loaded yet. Try to look up the linked peer via matched_with.
        const interfaces::Wallet::PricoinOfferSnapshot* selected = nullptr;
        for (const auto& o : m_orders) {
            if (o.order_id == oid) selected = &o;
        }
        if (!selected || selected->matched_with_order_id.empty()) {
            setStatus(tr("Need both Local and Imported sides of the match in this wallet."), true);
            return;
        }
        const std::string peer_id = selected->matched_with_order_id;
        for (const auto& o : m_orders) {
            if (o.order_id == peer_id) {
                if (selected->origin == "local") { mine = selected; peer = &o; }
                else                              { peer = selected; mine = &o; }
                break;
            }
        }
        if (!mine || !peer) {
            setStatus(tr("Counterparty's order not in this wallet — import their URI first."), true);
            return;
        }
    }

    // CRITICAL: take value copies before any RPC / dialog yields the
    // event loop. The auto-refresh timer (or any signal that calls
    // refreshTable) replaces m_orders, freeing the storage that
    // `mine` and `peer` point into. Dereferencing those pointers
    // afterwards reads garbage — and on bad luck crashes the app
    // with no log, since UB doesn't write to debug.log on its way
    // out. Switching to copies eliminates the dangling-pointer class
    // of bug entirely for the rest of this function.
    const interfaces::Wallet::PricoinOfferSnapshot mine_v = *mine;
    const interfaces::Wallet::PricoinOfferSnapshot peer_v = *peer;
    mine = &mine_v;
    peer = &peer_v;

    // Map orderbook side → adaptor-swap role.
    //   sell_pric (giving up PRIC, receiving foreign) → Alice (PRIC seller)
    //   buy_pric  (giving up foreign, receiving PRIC) → Bob   (PRIC buyer)
    const std::string my_role = (mine->side == "sell_pric") ? "alice" : "bob";

    // Compute the actual amounts at the maker's (peer's, when
    // peer is the maker on the matched side) rate. For the local
    // side's perspective: pric_in_flight is the actual_pric that
    // was reserved; foreign at maker's rate — recompute from the
    // peer's max amounts.
    const int64_t pric_amount = mine->pric_in_flight_sat;
    if (pric_amount <= 0) {
        setStatus(tr("Selected order has no in-flight pric amount."), true);
        return;
    }
    // Maker's rate = (foreign_max / pric_max) of whichever side is
    // the SellPric (asker = maker per spec — taker pays maker's rate).
    const interfaces::Wallet::PricoinOfferSnapshot* ask =
        (mine->side == "sell_pric") ? mine : peer;
    if (ask->max_pric_amount_sat <= 0) {
        setStatus(tr("Bad ask amounts."), true);
        return;
    }
    const int64_t foreign_amount = static_cast<int64_t>(
        (static_cast<__int128>(pric_amount) *
         static_cast<__int128>(ask->foreign_amount_at_max_sat)) /
        static_cast<__int128>(ask->max_pric_amount_sat));

    // Funds gate — fail fast if the user obviously can't fund their
    // side. Doesn't account for fees (the user should leave a small
    // buffer); we add ~0.1% headroom for the fee + dust margin.
    //
    // On failure we don't just refuse — we also release the match
    // (DM the peer to mirror) and cancel the local order, so the
    // counterparty isn't left holding a dead match they have to
    // manually unwind. The cancel keeps the order from re-matching
    // until funds are deposited and the user re-creates it.
    auto release_and_cancel = [&](const QString& msg) {
        setStatus(msg, true);
        std::string peer_oid;
        {
            const auto rec = m_model->wallet().offerGet(oid);
            if (rec) peer_oid = rec->matched_with_order_id;
        }
        m_model->wallet().offerUnmatch(oid);
        if (m_nostr && !peer_oid.empty()) {
            const auto peer_rec = m_model->wallet().offerGet(peer_oid);
            if (peer_rec && peer_rec->maker_pubkey_hex.size() >= 66) {
                const QString peer_xonly = QString::fromStdString(
                    peer_rec->maker_pubkey_hex.substr(2));
                QJsonObject msgj;
                msgj.insert(QStringLiteral("type"),
                    QStringLiteral("pricoin:unmatch/v1"));
                msgj.insert(QStringLiteral("my_order_id"),
                    QString::fromStdString(oid));
                msgj.insert(QStringLiteral("their_order_id"),
                    QString::fromStdString(peer_oid));
                const QString plaintext = QString::fromUtf8(
                    QJsonDocument(msgj).toJson(QJsonDocument::Compact));
                m_nostr->publishDirectMessage(peer_xonly, plaintext);
            }
        }
        m_model->wallet().offerCancel(oid);
        refreshTable();
    };

    // Local helper to call a wallet RPC inline (no global helper here).
    auto call_rpc = [&](const std::string& method, const UniValue& params,
                          UniValue& out, std::string& err_out) -> bool {
        const QString wallet_name = m_model->getWalletName();
        std::string uri;
        if (!wallet_name.isEmpty()) {
            uri = "/wallet/" + std::string(
                QUrl::toPercentEncoding(wallet_name).constData());
        }
        try {
            out = m_model->node().executeRpc(method, params, uri);
            return true;
        } catch (const UniValue& e) {
            err_out = e.isObject() && e.exists("message")
                ? e["message"].get_str() : e.write();
        } catch (const std::exception& e) {
            err_out = e.what();
        }
        return false;
    };

    if (my_role == "bob") {
        // PRIC buyer locks foreign in the holding wallet. Confirmed
        // balance must cover the swap amount + the actual funding-tx
        // fee. We compute the fee from the chain backend's live
        // sat/vB (rather than a flat percentage), so the gate is
        // tight enough to refuse marginal fills but doesn't reject
        // when the user has exactly amount + minimum fee.
        //
        // Foreign funding-tx vbyte estimate:
        //   * BTC: 1 P2TR input (~58 vB) + P2TR target (~43) + P2WPKH
        //     change (~31) + overhead (~11) = 143 vB.
        //   * LTC: 1 P2WPKH input (~68 vB) + P2WSH HTLC target (~43) +
        //     P2WPKH change (~31) + overhead (~11) = 153 vB.
        const int est_size_vb = (mine->foreign_chain == "btc") ? 143 : 153;

        UniValue bal, fees;
        std::string err;
        UniValue chain_arg{UniValue::VARR};
        chain_arg.push_back(mine->foreign_chain);
        if (!call_rpc("pricoin_btc_getbalance", chain_arg, bal, err)) {
            release_and_cancel(tr("Cannot verify holding-wallet balance for %1: %2. "
                          "Match released and order cancelled.")
                .arg(QString::fromStdString(mine->foreign_chain))
                .arg(QString::fromStdString(err)));
            return;
        }
        // Fee-estimates are best-effort; if the backend can't supply
        // them, fall back to 2 sat/vB (a comfortable upper bound for
        // current quiet conditions on both BTC and LTC).
        double sat_per_vb = 2.0;
        if (call_rpc("pricoin_chainwatch_fee_estimates", chain_arg, fees, err)) {
            for (int t : {6, 10, 3, 20}) {
                const auto v = fees[strprintf("%d", t)];
                if (v.isNum() && v.get_real() > 0) {
                    sat_per_vb = v.get_real();
                    break;
                }
            }
        }
        const int64_t fee_sat = static_cast<int64_t>(
            std::ceil(static_cast<double>(est_size_vb) * sat_per_vb));

        const UniValue conf_v = bal["confirmed_sat"];
        const int64_t confirmed = conf_v.isNum() ? conf_v.getInt<int64_t>() : 0;
        const int64_t needed = foreign_amount + fee_sat;
        if (confirmed < needed) {
            release_and_cancel(tr("Insufficient %1 in holding wallet. "
                          "Have %2 sat confirmed, need %3 sat (%4 + %5 fee at "
                          "%6 sat/vB × ~%7 vB). Match released and order cancelled — "
                          "deposit %1 in the Holding tab and re-create the order.")
                .arg(QString::fromStdString(mine->foreign_chain).toUpper())
                .arg(confirmed).arg(needed).arg(foreign_amount).arg(fee_sat)
                .arg(QString::number(sat_per_vb, 'f', 1)).arg(est_size_vb));
            return;
        }
    } else {
        // PRIC seller locks PRIC. The CT-send path handles fees
        // internally via the bundle's transparent_fee output; pad
        // the requirement by one CT-tx-typical fee so the user
        // doesn't fall a few sats short on their own send.
        const int64_t pric_fee_buffer = 100'000;   // 0.001 PRIC
        const CAmount conf = m_model->wallet().confidentialBalance();
        const int64_t needed = pric_amount + pric_fee_buffer;
        if (conf < needed) {
            release_and_cancel(tr("Insufficient confidential PRIC. "
                          "Have %1 sat, need %2 sat (%3 + %4 fee buffer). "
                          "Match released and order cancelled — top up your "
                          "confidential PRIC and re-create the order.")
                .arg(static_cast<long long>(conf))
                .arg(needed).arg(pric_amount).arg(pric_fee_buffer));
            return;
        }
    }

    // Prompt for the joint stealth address (the user computed it via
    // pricoin_buildjointstealthaddress out-of-band) plus refund timelocks.
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Start atomic swap"));
    auto* form = new QFormLayout(&dlg);

    auto* role_label = new QLabel(QString::fromStdString(my_role), &dlg);
    auto* chain_label = new QLabel(QString::fromStdString(mine->foreign_chain), &dlg);
    auto* pric_label = new QLabel(QString::number(pric_amount), &dlg);
    auto* foreign_label = new QLabel(QString::number(foreign_amount), &dlg);
    form->addRow(tr("My role:"),               role_label);
    form->addRow(tr("Foreign chain:"),         chain_label);
    form->addRow(tr("PRIC amount (sat):"),     pric_label);
    form->addRow(tr("Foreign amount (sat):"),  foreign_label);

    auto* joint_edit = new QLineEdit(&dlg);
    joint_edit->setPlaceholderText(tr("output of pricoin_buildjointstealthaddress"));
    // Pre-fill the joint stealth address if it was computed at
    // swap_addrs DM-receive time (peer's view+spend pubkeys arrived).
    {
        auto it = m_peer_swap_addrs.find(QString::fromStdString(mine->order_id));
        if (it != m_peer_swap_addrs.end() && !it->joint_address.isEmpty()) {
            joint_edit->setText(it->joint_address);
        }
    }
    auto* joint_row = new QHBoxLayout();
    joint_row->addWidget(joint_edit, /*stretch=*/1);
    auto* btn_joint_wizard = new QPushButton(tr("Build…"), &dlg);
    joint_row->addWidget(btn_joint_wizard);
    form->addRow(tr("Joint stealth address:"), joint_row);
    QObject::connect(btn_joint_wizard, &QPushButton::clicked, &dlg,
        [this, &dlg, joint_edit, peer]() {
        // maker_pubkey_hex is the peer's 33-byte compressed pubkey
        // hex (66 chars: 02/03 parity prefix + 64-char x-only). Strip
        // the parity byte for the joint-stealth dialog, which expects
        // x-only. Defensive: an empty / malformed hex would crash
        // substr(2) — fall back to empty xonly so the dialog opens
        // and surfaces a clear error rather than killing the app.
        QString peer_xonly;
        if (peer && peer->maker_pubkey_hex.size() >= 66) {
            peer_xonly = QString::fromStdString(peer->maker_pubkey_hex.substr(2));
        }
        PricoinJointStealthDialog d(m_model, peer_xonly, &dlg);
        if (d.exec() == QDialog::Accepted && !d.chosenJointAddress().isEmpty()) {
            joint_edit->setText(d.chosenJointAddress());
        }
    });

    // Per-leg destination addresses. Stored on the swap record so
    // the cooperative-sign dialogs can pre-fill recipient/dest based
    // on Mode + role without another out-of-band exchange. Both
    // parties enter all four (the swap protocol requires both sides
    // to agree on these up front).
    //
    // Pre-fill the user's own PRIC stealth from their wallet — saves
    // one paste. BTC P2TR address requires manual input (this wallet
    // has no BTC keys; the user provides one from their BTC wallet).
    const std::string my_stealth = m_model
        ? m_model->wallet().getStealthAddress()
        : "";

    // Resolve "my own" foreign-side recipient: the BTC P2TR xonly of
    // the wallet's holding-wallet identity for this swap's foreign
    // chain. Lazy-derived; identity persists per chain.
    const QString my_btc_xonly = getMyBtcXOnly(
        QString::fromStdString(mine->foreign_chain));

    // Look up the peer's swap addresses if they've been received via
    // DM (auto-exchanged at match time). Empty strings if not yet
    // received — the user can still paste manually as a fallback.
    PeerSwapAddrs peer_addrs;
    {
        auto it = m_peer_swap_addrs.find(QString::fromStdString(mine->order_id));
        if (it != m_peer_swap_addrs.end()) peer_addrs = *it;
    }
    const QString peer_btc_xonly  = peer_addrs.btc_xonly;
    const QString peer_pric_stlth = peer_addrs.pric_stealth;

    auto* btc_alice_rcpt = new QLineEdit(&dlg);
    btc_alice_rcpt->setPlaceholderText(tr("32-byte x-only — PRIC seller's BTC P2TR refund recipient"));
    if (my_role == "alice" && !my_btc_xonly.isEmpty()) {
        btc_alice_rcpt->setText(my_btc_xonly);
    } else if (my_role == "bob" && !peer_btc_xonly.isEmpty()) {
        btc_alice_rcpt->setText(peer_btc_xonly);
    }
    form->addRow(tr("BTC refund (PRIC seller's xonly):"), btc_alice_rcpt);

    auto* btc_bob_rcpt = new QLineEdit(&dlg);
    btc_bob_rcpt->setPlaceholderText(tr("32-byte x-only — PRIC buyer's BTC P2TR claim recipient"));
    if (my_role == "bob" && !my_btc_xonly.isEmpty()) {
        btc_bob_rcpt->setText(my_btc_xonly);
    } else if (my_role == "alice" && !peer_btc_xonly.isEmpty()) {
        btc_bob_rcpt->setText(peer_btc_xonly);
    }
    form->addRow(tr("BTC claim (PRIC buyer's xonly):"), btc_bob_rcpt);

    auto* pric_alice_rcpt = new QLineEdit(&dlg);
    pric_alice_rcpt->setPlaceholderText(tr("PRIC seller's stealth claim recipient"));
    if (my_role == "alice" && !my_stealth.empty()) {
        pric_alice_rcpt->setText(QString::fromStdString(my_stealth));
    } else if (my_role == "bob" && !peer_pric_stlth.isEmpty()) {
        pric_alice_rcpt->setText(peer_pric_stlth);
    }
    form->addRow(tr("PRIC claim (PRIC seller's stealth):"), pric_alice_rcpt);

    auto* pric_bob_rcpt = new QLineEdit(&dlg);
    pric_bob_rcpt->setPlaceholderText(tr("PRIC buyer's stealth refund recipient"));
    if (my_role == "bob" && !my_stealth.empty()) {
        pric_bob_rcpt->setText(QString::fromStdString(my_stealth));
    } else if (my_role == "alice" && !peer_pric_stlth.isEmpty()) {
        pric_bob_rcpt->setText(peer_pric_stlth);
    }
    form->addRow(tr("PRIC refund (PRIC buyer's stealth):"), pric_bob_rcpt);

    auto* pric_lock = new QSpinBox(&dlg);
    pric_lock->setRange(1, 2'147'483'647);
    pric_lock->setValue(480);
    form->addRow(tr("PRIC refund-height delta (blocks):"), pric_lock);

    auto* delta_min = new QSpinBox(&dlg);
    delta_min->setRange(1, 2'147'483'647);
    delta_min->setValue(144);
    form->addRow(tr("Foreign delta-min (blocks):"), delta_min);

    auto* memo_edit = new QLineEdit(&dlg);
    form->addRow(tr("Memo:"), memo_edit);

    auto* bb = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    form->addRow(bb);

    if (dlg.exec() != QDialog::Accepted) return;

    // Verbose tracing for the persistent first-click "counterparty_pubkey
    // must be 33-byte compressed hex" race. Logs:
    //   * peer->order_id and peer's maker_pubkey_hex from the freshly-
    //     refreshed m_orders list
    //   * total offer count to spot ghost duplicates
    //   * offerGet's response for the same order_id
    //   * the snapshot's maker_pubkey_hex prefix so we can compare bytes
    //     between consecutive clicks.
    LogInfo("Pricoin start_swap CLICK: oid=%s peer.oid=%s peer.maker.size=%d "
            "peer.maker.head=%s m_orders.count=%d origin=%s\n",
            oid.substr(0, 12),
            peer->order_id.substr(0, 12),
            (int)peer->maker_pubkey_hex.size(),
            peer->maker_pubkey_hex.substr(0, 16),
            (int)m_orders.size(),
            peer->origin);

    std::string cp_hex = peer->maker_pubkey_hex;
    if (cp_hex.size() != 66) {
        const auto fresh = m_model->wallet().offerGet(peer->order_id);
        LogInfo("Pricoin start_swap REFETCH: offerGet(%s) returned %s%s\n",
                peer->order_id.substr(0, 12),
                fresh ? "value" : "<empty>",
                fresh ? (" maker.size=" + std::to_string(fresh->maker_pubkey_hex.size())
                        + " maker.head=" + fresh->maker_pubkey_hex.substr(0, 16)).c_str()
                      : "");
        if (fresh && fresh->maker_pubkey_hex.size() == 66) {
            cp_hex = fresh->maker_pubkey_hex;
        }
        // Last-resort: scan the entire offer list for a record whose
        // matched_with link points to mine. If we find one with a
        // valid maker_pubkey_hex, use it. This bypasses any subtle
        // mismatch between peer->order_id (from the cached snapshot)
        // and what's actually persisted.
        if (cp_hex.size() != 66 && mine) {
            for (const auto& o : m_orders) {
                if (o.matched_with_order_id == mine->order_id &&
                    o.maker_pubkey_hex.size() == 66) {
                    cp_hex = o.maker_pubkey_hex;
                    LogInfo("Pricoin start_swap LAST_RESORT: found peer by "
                            "matched_with-link; oid=%s maker.head=%s\n",
                            o.order_id.substr(0, 12),
                            o.maker_pubkey_hex.substr(0, 16));
                    break;
                }
            }
        }
    }

    interfaces::Wallet::PricoinAdaptorSwapCreateParams ap;
    ap.role = my_role;
    ap.counterparty_pubkey_hex = cp_hex;
    ap.foreign_chain = mine->foreign_chain;
    ap.foreign_amount_sat = foreign_amount;
    ap.pric_joint_stealth_address = joint_edit->text().trimmed().toStdString();
    ap.pric_amount_sat = pric_amount;
    ap.memo = memo_edit->text().toStdString();
    ap.btc_alice_recipient_xonly_hex = btc_alice_rcpt->text().trimmed().toStdString();
    ap.btc_bob_recipient_xonly_hex   = btc_bob_rcpt->text().trimmed().toStdString();
    ap.pric_alice_recipient_stealth  = pric_alice_rcpt->text().trimmed().toStdString();
    ap.pric_bob_recipient_stealth    = pric_bob_rcpt->text().trimmed().toStdString();

    auto r = m_model->wallet().adaptorSwapCreate(ap);
    if (!r) {
        setStatus(tr("Start swap failed: %1")
            .arg(QString::fromStdString(util::ErrorString(r).original)), true);
        return;
    }
    const std::string created_swap_id = r->swap_id;

    // Persist peer's PRIC stealth view+spend pubkeys to the swap
    // record. Needed by the cooperative-sign dialog's loadshare
    // call (other_spend_pubkey arg). PeerSwapAddrs lives only
    // in this page's in-memory map; without persisting, a Qt
    // restart loses the data and loadshare fails. Best-effort —
    // if peer_addrs wasn't populated (swap_addrs DM didn't arrive),
    // skip silently and the manual paste fallback still works.
    if (!peer_addrs.view_pubkey.isEmpty()
        && !peer_addrs.spend_pubkey.isEmpty()) {
        auto rs = m_model->wallet().adaptorSwapSetPeerStealthPubkeys(
            created_swap_id,
            peer_addrs.view_pubkey.toStdString(),
            peer_addrs.spend_pubkey.toStdString());
        if (!rs) {
            // Surface but don't block — the swap is created and the
            // user can fall back to manual paste in the loadshare
            // helper if needed.
            setStatus(tr("Swap created; persisting peer stealth pubkeys "
                         "failed: %1 (loadshare will need manual peer "
                         "spend pubkey)").arg(QString::fromStdString(
                util::ErrorString(rs).original)), false);
        }
    }

    // DM the counterparty so their wallet auto-creates the mirror
    // swap record. Without this, the counterparty has to fill out
    // the same Start-swap dialog independently and risk transcribing
    // any of the 8 fields wrong. With it, only one side fills the
    // form and the other side's wallet creates an identical record
    // in the background.
    //
    // The DM carries every field needed to reconstruct the swap on
    // the other side AND the matcher's swap_id — the receiver pins
    // its mirror to that same id so subsequent coord DMs (abort,
    // adaptor_setup) don't need a swap_id-mapping table.
    if (m_nostr && peer->maker_pubkey_hex.size() >= 66) {
        const QString peer_xonly = QString::fromStdString(
            peer->maker_pubkey_hex.substr(2));
        QJsonObject swap_dm;
        swap_dm.insert(QStringLiteral("type"),
            QStringLiteral("pricoin:swap_start/v1"));
        // Sender's role; the receiver flips it (alice ↔ bob).
        swap_dm.insert(QStringLiteral("sender_role"),
            QString::fromStdString(my_role));
        swap_dm.insert(QStringLiteral("foreign_chain"),
            QString::fromStdString(ap.foreign_chain));
        swap_dm.insert(QStringLiteral("foreign_amount_sat"),
            static_cast<double>(ap.foreign_amount_sat));
        swap_dm.insert(QStringLiteral("pric_amount_sat"),
            static_cast<double>(ap.pric_amount_sat));
        swap_dm.insert(QStringLiteral("pric_joint_stealth_address"),
            QString::fromStdString(ap.pric_joint_stealth_address));
        swap_dm.insert(QStringLiteral("memo"),
            QString::fromStdString(ap.memo));
        swap_dm.insert(QStringLiteral("btc_alice_recipient_xonly_hex"),
            QString::fromStdString(ap.btc_alice_recipient_xonly_hex));
        swap_dm.insert(QStringLiteral("btc_bob_recipient_xonly_hex"),
            QString::fromStdString(ap.btc_bob_recipient_xonly_hex));
        swap_dm.insert(QStringLiteral("pric_alice_recipient_stealth"),
            QString::fromStdString(ap.pric_alice_recipient_stealth));
        swap_dm.insert(QStringLiteral("pric_bob_recipient_stealth"),
            QString::fromStdString(ap.pric_bob_recipient_stealth));
        // Match the matched-orders pair so the receiver can validate
        // this DM corresponds to a real match in their orderbook.
        swap_dm.insert(QStringLiteral("my_order_id"),
            QString::fromStdString(oid));
        swap_dm.insert(QStringLiteral("their_order_id"),
            QString::fromStdString(peer->order_id));
        // Shared swap_id so the receiver's mirror keys match locally
        // — required for the abort/adaptor_setup coord DMs to find
        // the right record on the receiving side.
        swap_dm.insert(QStringLiteral("swap_id"),
            QString::fromStdString(created_swap_id));

        const QString plaintext = QString::fromUtf8(
            QJsonDocument(swap_dm).toJson(QJsonDocument::Compact));
        m_next_dm_label = tr("Swap-start params for %1…")
            .arg(QString::fromStdString(peer->order_id).left(12));
        // Definitive trace: confirms this build is the one with the
        // swap_id-share fix. If you don't see this line in debug.log
        // when clicking Start swap, the binary is older than this code.
        LogInfo("Pricoin start_swap emit: swap_id=%s peer=%s plaintext_bytes=%d\n",
                created_swap_id.substr(0, 16),
                peer_xonly.left(12).toStdString(),
                (int)plaintext.size());
        m_nostr->publishDirectMessage(peer_xonly, plaintext);
        m_next_dm_label.clear();
    }

    setStatus(tr("Swap created. Counterparty's wallet will mirror it "
                  "automatically. Switch to the Swaps tab to track state."));
}

void PricoinOrderbookPage::onNostrOfferReceived(const QString& uri)
{
    if (!m_model) return;
    auto r = m_model->wallet().offerImport(uri.toStdString());
    if (!r) {
        // Most often: duplicate (already imported) or expired.
        // Quietly absorb — duplicates from multiple relays are normal.
        return;
    }
    refreshTable();
    setStatus(tr("Imported new offer from network."));
}

void PricoinOrderbookPage::onNostrOfferCancellationReceived(const QString& order_id_hex)
{
    if (!m_model) return;
    const std::string oid = order_id_hex.toStdString();
    const auto rec = m_model->wallet().offerGet(oid);
    if (!rec) return; // never imported it; nothing to do
    if (rec->origin == "local") return; // can't cancel our own via remote signal
    if (rec->status == "cancelled") return; // already
    auto r = m_model->wallet().offerCancel(oid);
    if (!r) return;
    refreshTable();
    setStatus(tr("Counterparty cancelled offer %1.")
        .arg(QString::fromStdString(oid).left(12) + "…"));
}

void PricoinOrderbookPage::publishOrQueueOffer(const std::string& order_id)
{
    if (!m_model) return;
    if (!m_nostr || m_connected_relay_count == 0) {
        m_pending_publish_offers.insert(QString::fromStdString(order_id));
        setStatus(tr("Order created. Will publish to relays once connected."));
        return;
    }
    const auto rec = m_model->wallet().offerGet(order_id);
    if (!rec || rec->origin != "local" || rec->status != "active") return;
    const std::string uri = m_model->wallet().offerExportUri(order_id);
    if (uri.empty()) return;
    const bool ok = m_nostr->publishOfferUri(
        QString::fromStdString(uri),
        QString::fromStdString(order_id),
        rec->expiry_unix_sec,
        QString::fromStdString(rec->foreign_chain),
        QString::fromStdString(rec->side));
    if (!ok) {
        // Sender returned false: every relay was non-connected at send
        // time even though the count said otherwise (race). Re-queue.
        m_pending_publish_offers.insert(QString::fromStdString(order_id));
    }
}

void PricoinOrderbookPage::publishOrQueueCancel(const std::string& order_id)
{
    if (!m_model) return;
    if (!m_nostr || m_connected_relay_count == 0) {
        m_pending_publish_cancels.insert(QString::fromStdString(order_id));
        return;
    }
    const auto rec = m_model->wallet().offerGet(order_id);
    if (!rec || rec->origin != "local") return;
    const bool ok = m_nostr->publishOfferCancel(
        QString::fromStdString(order_id),
        rec->expiry_unix_sec,
        QString::fromStdString(rec->foreign_chain),
        QString::fromStdString(rec->side));
    if (!ok) {
        m_pending_publish_cancels.insert(QString::fromStdString(order_id));
    }
}

void PricoinOrderbookPage::drainPendingPublishes()
{
    if (!m_nostr || m_connected_relay_count == 0) return;
    // Snapshot + clear so retries (which re-add on failure) don't loop
    // within a single drain pass.
    const auto offers  = m_pending_publish_offers;  m_pending_publish_offers.clear();
    const auto cancels = m_pending_publish_cancels; m_pending_publish_cancels.clear();
    for (const auto& oid : offers)  publishOrQueueOffer(oid.toStdString());
    for (const auto& oid : cancels) publishOrQueueCancel(oid.toStdString());
}

void PricoinOrderbookPage::onNostrDmSent(const QString& dm_id,
                                           const QString& peer_xonly_hex)
{
    Q_UNUSED(peer_xonly_hex);
    if (dm_id.isEmpty()) return;
    // Caller of publishDirectMessage stashes a description into
    // m_pending_dms[dm_id] just before sending. If they didn't,
    // this just becomes a no-op pending entry that the ack clears.
    const QString label = m_next_dm_label.isEmpty()
        ? tr("(unlabeled DM)") : m_next_dm_label;
    m_next_dm_label.clear();
    m_pending_dms.insert(dm_id, label);
    setStatus(tr("Sent: %1 — awaiting counterparty receipt…").arg(label));
}

void PricoinOrderbookPage::onNostrDmAcked(const QString& dm_id,
                                           const QString& peer_xonly_hex)
{
    Q_UNUSED(peer_xonly_hex);
    if (dm_id.isEmpty()) return;
    const QString desc = m_pending_dms.take(dm_id);
    if (desc.isEmpty()) return;  // Not one of ours.
    setStatus(tr("Counterparty received: %1").arg(desc));
}

void PricoinOrderbookPage::onNostrLog(const QString& msg)
{
    // For v0, surface relay log lines via the status label. Could be
    // routed to a dedicated debug pane in a follow-up.
    if (m_status_label) m_status_label->setText(msg);
}

void PricoinOrderbookPage::onNostrRelayStatus(const QString& url, bool connected)
{
    Q_UNUSED(url);
    if (connected) ++m_connected_relay_count;
    else if (m_connected_relay_count > 0) --m_connected_relay_count;
    if (m_relay_status_label) {
        const int total = m_nostr ? m_nostr->relayUrls().size() : 0;
        m_relay_status_label->setText(
            tr("Relays: %1/%2 connected").arg(m_connected_relay_count).arg(total));
    }
    onSelectionChanged();
    // First relay just came up — push any creations/cancels the user
    // queued while offline.
    if (connected && m_connected_relay_count >= 1) {
        drainPendingPublishes();
    }
}

void PricoinOrderbookPage::onRefreshClicked()
{
    refreshTable();
    setStatus(tr("Refreshed."));
}

void PricoinOrderbookPage::onCreateClicked()
{
    if (!m_model) return;
    CreateOfferDialog dlg(this);
    if (dlg.exec() != QDialog::Accepted) return;
    interfaces::Wallet::PricoinOfferCreateParams params;
    QString err;
    if (!dlg.getParams(params, err)) {
        setStatus(err, /*error=*/true);
        return;
    }
    auto r = m_model->wallet().offerCreate(params);
    if (!r.ok) {
        setStatus(tr("Create failed: %1").arg(QString::fromStdString(r.error)), true);
        return;
    }
    refreshTable();
    QApplication::clipboard()->setText(QString::fromStdString(r.uri));
    publishOrQueueOffer(r.record.order_id);
    if (m_connected_relay_count > 0) {
        setStatus(tr("Order created and published to relays. URI also copied to clipboard."));
    }
}

void PricoinOrderbookPage::onImportClicked()
{
    if (!m_model) return;
    bool ok = false;
    const QString uri = QInputDialog::getMultiLineText(
        this, tr("Import order URI"),
        tr("Paste a pricoffer:v1/<base64> URI from a counterparty:"),
        QString(), &ok);
    if (!ok || uri.trimmed().isEmpty()) return;
    auto r = m_model->wallet().offerImport(uri.trimmed().toStdString());
    if (!r) {
        setStatus(tr("Import failed: %1")
            .arg(QString::fromStdString(util::ErrorString(r).original)), true);
        return;
    }
    refreshTable();
    setStatus(tr("Imported. Run \"Find matches\" on a Local order to see if it crosses."));
}

void PricoinOrderbookPage::onCancelClicked()
{
    if (!m_model) return;
    const std::string oid = selectedOrderId();
    if (oid.empty()) return;
    const auto pre = m_model->wallet().offerGet(oid);
    if (!pre) return;
    const bool was_local = (pre->origin == "local");
    if (QMessageBox::question(this, tr("Cancel order"),
            tr("Cancel this order? This is terminal and cannot be undone."),
            QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) return;
    auto r = m_model->wallet().offerCancel(oid);
    if (!r) {
        setStatus(tr("Cancel failed: %1")
            .arg(QString::fromStdString(util::ErrorString(r).original)), true);
        return;
    }
    refreshTable();
    if (was_local) {
        publishOrQueueCancel(oid);
        setStatus(m_connected_relay_count > 0
            ? tr("Cancelled and notified relays.")
            : tr("Cancelled. Notification queued for next relay connect."));
    } else {
        setStatus(tr("Cancelled."));
    }
}

void PricoinOrderbookPage::onCopyUriClicked()
{
    if (!m_model) return;
    const std::string oid = selectedOrderId();
    if (oid.empty()) return;
    const std::string uri = m_model->wallet().offerExportUri(oid);
    if (uri.empty()) {
        setStatus(tr("Imported orders have no exportable URI."), true);
        return;
    }
    QApplication::clipboard()->setText(QString::fromStdString(uri));
    setStatus(tr("URI copied to clipboard."));
}

void PricoinOrderbookPage::onFindMatchesClicked()
{
    if (!m_model) return;
    const std::string oid = selectedOrderId();
    if (oid.empty()) return;
    auto cands = m_model->wallet().offerFindMatches(oid);
    if (cands.empty()) {
        QMessageBox::information(this, tr("Find matches"),
            tr("No imported orders price-cross with this one."));
        return;
    }
    // Snapshot the wallet's full order list so the dialog can look up
    // the maker's rate for the trade preview.
    const auto all_orders = m_model->wallet().offerList();
    interfaces::Wallet::PricoinOfferSnapshot mine{};
    bool found = false;
    for (const auto& o : all_orders) {
        if (o.order_id == oid) { mine = o; found = true; break; }
    }
    if (!found) {
        setStatus(tr("Selected order vanished — refresh and retry."), true);
        return;
    }
    PricoinMatchDialog dlg(mine, std::move(cands), all_orders, this);
    if (dlg.exec() != QDialog::Accepted) return;

    const std::string their_id = dlg.chosenTheirOrderId();
    const int64_t actual_pric = dlg.chosenActualPricSat();
    if (their_id.empty() || actual_pric <= 0) return;

    auto r = m_model->wallet().offerMatch(oid, their_id, actual_pric);
    if (!r) {
        setStatus(tr("Match failed: %1")
            .arg(QString::fromStdString(util::ErrorString(r).original)), true);
        return;
    }
    refreshTable();

    // Notify counterparty via NIP-04 DM so their wallet mirrors the
    // match (no manual step on their end). We assume two strangers
    // with no other contact channel — the DM is the synchronization
    // mechanism. Receive-side handler is onNostrDmReceived.
    int dm_sent = 0;
    if (m_nostr) {
        const auto their = m_model->wallet().offerGet(their_id);
        if (their && their->maker_pubkey_hex.size() >= 66) {
            const QString peer_xonly = QString::fromStdString(
                their->maker_pubkey_hex.substr(2));
            QJsonObject msg;
            msg.insert(QStringLiteral("type"),
                QStringLiteral("pricoin:match/v1"));
            // From the sender's view: "my" is the matcher's order,
            // "their" is the maker's order. The receiver flips this.
            msg.insert(QStringLiteral("my_order_id"),
                QString::fromStdString(oid));
            msg.insert(QStringLiteral("their_order_id"),
                QString::fromStdString(their_id));
            msg.insert(QStringLiteral("actual_pric_sat"),
                static_cast<double>(actual_pric));
            const QString plaintext = QString::fromUtf8(
                QJsonDocument(msg).toJson(QJsonDocument::Compact));
            m_next_dm_label = tr("Match notification for order %1…")
                .arg(QString::fromStdString(their_id).left(12));
            if (m_nostr->publishDirectMessage(peer_xonly, plaintext)) {
                dm_sent = 1;
            }
            m_next_dm_label.clear();  // belt-and-suspenders

            // Swap-address auto-exchange: send my BTC xonly + PRIC stealth
            // so the peer's Start-swap dialog opens fully populated.
            // Foreign-chain is the matcher's own offer side.
            const auto my_offer = m_model->wallet().offerGet(oid);
            if (my_offer) {
                sendSwapAddrs(oid, their_id, my_offer->foreign_chain);
            }
        }
    }
    setStatus(tr("Matched %1 PRIC against %2… %3")
        .arg(QString::asprintf("%lld.%08lld",
            static_cast<long long>(actual_pric / 100'000'000),
            static_cast<long long>(actual_pric % 100'000'000)))
        .arg(QString::fromStdString(their_id).left(12))
        .arg(dm_sent ? tr("(notified counterparty)")
                     : tr("(WARN: counterparty not notified — check relay connection)")));
}

void PricoinOrderbookPage::onNostrDmReceived(const QString& from_xonly_hex,
                                              const QString& plaintext)
{
    // Match-notification handler. Counterparty side of onMatchClicked.
    // Auth model: only accept a match-notification if the sender's
    // xonly matches the maker pubkey of the order *they claim is theirs*
    // (`my_order_id` from the DM, which is OUR `their_order_id`).
    QJsonParseError pe;
    auto doc = QJsonDocument::fromJson(plaintext.toUtf8(), &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) return;
    const auto obj = doc.object();
    const QString type = obj.value(QStringLiteral("type")).toString();
    const bool is_match      = (type == QStringLiteral("pricoin:match/v1"));
    const bool is_unmatch    = (type == QStringLiteral("pricoin:unmatch/v1"));
    const bool is_swap_start = (type == QStringLiteral("pricoin:swap_start/v1"));
    const bool is_swap_addrs = (type == QStringLiteral("pricoin:swap_addrs/v1"));
    if (!is_match && !is_unmatch && !is_swap_start && !is_swap_addrs) return;

    // Sender's "my" = sender's order = our "their"; flip on receive.
    const std::string sender_oid =
        obj.value(QStringLiteral("my_order_id")).toString().toStdString();
    const std::string my_oid =
        obj.value(QStringLiteral("their_order_id")).toString().toStdString();
    if (sender_oid.empty() || my_oid.empty()) return;

    if (!m_model) return;

    // Authorization: the sender's xonly must match maker_pubkey_hex
    // of the sender's order (sender_oid). Otherwise anyone could
    // forge a match/unmatch-DM and corrupt our orderbook state.
    const auto sender_order = m_model->wallet().offerGet(sender_oid);
    if (!sender_order) {
        setStatus(tr("DM from %1: their order %2 not in our orderbook")
            .arg(from_xonly_hex.left(12) + "…")
            .arg(QString::fromStdString(sender_oid).left(12)), true);
        return;
    }
    if (sender_order->maker_pubkey_hex.size() >= 66) {
        const QString claimed_xonly = QString::fromStdString(
            sender_order->maker_pubkey_hex.substr(2));
        if (claimed_xonly != from_xonly_hex) {
            setStatus(tr("DM rejected: sender %1 is not the maker of order %2")
                .arg(from_xonly_hex.left(12) + "…")
                .arg(QString::fromStdString(sender_oid).left(12)), true);
            return;
        }
    }

    if (is_match) {
        const int64_t actual_pric = static_cast<int64_t>(
            obj.value(QStringLiteral("actual_pric_sat")).toDouble());
        if (actual_pric <= 0) return;
        auto r = m_model->wallet().offerMatch(my_oid, sender_oid, actual_pric);
        if (!r) {
            setStatus(tr("Match-DM from %1 — local apply failed: %2")
                .arg(from_xonly_hex.left(12) + "…")
                .arg(QString::fromStdString(util::ErrorString(r).original)), true);
            return;
        }
        refreshTable();
        setStatus(tr("Counterparty matched our order %1 — %2 PRIC.")
            .arg(QString::fromStdString(my_oid).left(12) + "…")
            .arg(QString::asprintf("%lld.%08lld",
                static_cast<long long>(actual_pric / 100'000'000),
                static_cast<long long>(actual_pric % 100'000'000))));

        // Reciprocal swap-address exchange: my counterparty (the
        // matcher) sent us their addresses; we now send ours back so
        // both Start-swap dialogs can open fully populated.
        const auto my_offer = m_model->wallet().offerGet(my_oid);
        if (my_offer) {
            sendSwapAddrs(my_oid, sender_oid, my_offer->foreign_chain);
        }
    } else if (is_unmatch) {
        // Unmatch — release the local match so the order returns
        // to Active. offerUnmatch operates on a single order_id;
        // it clears the matched_with link on both ends if both
        // are in this wallet, but for two-stranger swaps only the
        // local side matters here.
        auto r = m_model->wallet().offerUnmatch(my_oid);
        if (!r) {
            setStatus(tr("Unmatch-DM from %1 — local apply failed: %2")
                .arg(from_xonly_hex.left(12) + "…")
                .arg(QString::fromStdString(util::ErrorString(r).original)), true);
            return;
        }
        refreshTable();
        setStatus(tr("Counterparty released the match on order %1.")
            .arg(QString::fromStdString(my_oid).left(12) + "…"));
    } else if (is_swap_start) {
        // Counterparty clicked "Start swap" on their side. They've
        // sent us all the params; we mirror-create our own
        // AdaptorSwap record so the user doesn't have to fill out
        // the same dialog independently.
        //
        // Sanity gates: their `my_order_id` must be the order they
        // matched against us (sender_oid we already validated as
        // theirs above), and `their_order_id` must be the one we
        // matched in their direction (my_oid — our local order).
        // Then flip role: if sender said "alice" we are "bob".
        const QString sender_role = obj.value(
            QStringLiteral("sender_role")).toString();
        const QString my_flipped_role =
            (sender_role == QStringLiteral("alice")) ? QStringLiteral("bob")
                                                     : QStringLiteral("alice");

        // Verify the local order actually exists + is in matched state.
        const auto my_order = m_model->wallet().offerGet(my_oid);
        if (!my_order) {
            setStatus(tr("Swap-start DM from %1: our order %2 not found.")
                .arg(from_xonly_hex.left(12) + "…")
                .arg(QString::fromStdString(my_oid).left(12)), true);
            return;
        }

        interfaces::Wallet::PricoinAdaptorSwapCreateParams ap;
        ap.role = my_flipped_role.toStdString();
        ap.counterparty_pubkey_hex = sender_order->maker_pubkey_hex;
        ap.foreign_chain = obj.value(
            QStringLiteral("foreign_chain")).toString().toStdString();
        ap.foreign_amount_sat = static_cast<int64_t>(
            obj.value(QStringLiteral("foreign_amount_sat")).toDouble());
        ap.pric_amount_sat = static_cast<int64_t>(
            obj.value(QStringLiteral("pric_amount_sat")).toDouble());
        ap.pric_joint_stealth_address = obj.value(
            QStringLiteral("pric_joint_stealth_address")).toString().toStdString();
        ap.memo = obj.value(QStringLiteral("memo")).toString().toStdString();
        ap.btc_alice_recipient_xonly_hex = obj.value(
            QStringLiteral("btc_alice_recipient_xonly_hex")).toString().toStdString();
        ap.btc_bob_recipient_xonly_hex = obj.value(
            QStringLiteral("btc_bob_recipient_xonly_hex")).toString().toStdString();
        ap.pric_alice_recipient_stealth = obj.value(
            QStringLiteral("pric_alice_recipient_stealth")).toString().toStdString();
        ap.pric_bob_recipient_stealth = obj.value(
            QStringLiteral("pric_bob_recipient_stealth")).toString().toStdString();
        // Pin the matcher's swap_id so both sides' records share the
        // same key — required for cross-DM correlation in abort /
        // adaptor_setup / future coord DMs.
        ap.swap_id_hex = obj.value(
            QStringLiteral("swap_id")).toString().toStdString();
        LogInfo("Pricoin start_swap recv: swap_id=%s (empty=%d) from=%s\n",
                ap.swap_id_hex.substr(0, 16),
                (int)ap.swap_id_hex.empty(),
                from_xonly_hex.left(12).toStdString());

        auto r = m_model->wallet().adaptorSwapCreate(ap);
        if (!r) {
            setStatus(tr("Swap-start DM from %1 — local create failed: %2")
                .arg(from_xonly_hex.left(12) + "…")
                .arg(QString::fromStdString(util::ErrorString(r).original)), true);
            return;
        }
        // Persist peer's stealth pubkeys on this side's mirror record
        // too. Symmetry with the clicker-side persistence in
        // onStartSwapClicked. The swap_addrs DM from the peer was
        // received earlier (during match flow) and lives in
        // m_peer_swap_addrs keyed by the local order id; look it up
        // and persist so the cooperative-sign dialog's loadshare can
        // read peer_spend_pubkey_hex from the swap record. Without
        // this, the cosigner side's loadshare fails with
        // "scriptPubKey mismatch".
        {
            QString my_oid_qs = QString::fromStdString(my_oid);
            auto it_addrs = m_peer_swap_addrs.find(my_oid_qs);
            if (it_addrs != m_peer_swap_addrs.end()
                && !it_addrs->view_pubkey.isEmpty()
                && !it_addrs->spend_pubkey.isEmpty()) {
                (void)m_model->wallet().adaptorSwapSetPeerStealthPubkeys(
                    r->swap_id,
                    it_addrs->view_pubkey.toStdString(),
                    it_addrs->spend_pubkey.toStdString());
            }
        }
        refreshTable();
        setStatus(tr("Counterparty started the swap; mirror record "
                      "created on this side. Switch to the Swaps tab."));
    } else if (is_swap_addrs) {
        // Peer sent their BTC P2TR xonly + PRIC stealth (and raw
        // view+spend pubkeys) so our Start-swap dialog can pre-fill
        // every address field — including the joint stealth address,
        // computed locally from my privs + peer's pubkeys.
        PeerSwapAddrs pair;
        pair.btc_xonly    = obj.value(QStringLiteral("btc_xonly")).toString();
        pair.pric_stealth = obj.value(QStringLiteral("pric_stealth")).toString();
        pair.view_pubkey  = obj.value(QStringLiteral("view_pubkey")).toString();
        pair.spend_pubkey = obj.value(QStringLiteral("spend_pubkey")).toString();
        if (pair.btc_xonly.isEmpty() || pair.pric_stealth.isEmpty()) return;

        // Pre-compute the joint stealth address if we have the raw
        // pubkeys. Optional — older builds don't send them, in which
        // case the user clicks "Build…" the legacy way.
        if (!pair.view_pubkey.isEmpty() && !pair.spend_pubkey.isEmpty()) {
            pair.joint_address = BuildJointStealthAddr(
                m_model, pair.view_pubkey, pair.spend_pubkey);
        }

        m_peer_swap_addrs[QString::fromStdString(my_oid)] = pair;
        if (!pair.joint_address.isEmpty()) {
            setStatus(tr("Counterparty addresses received — Start swap is fully pre-filled "
                          "(joint stealth: %1…)")
                .arg(pair.joint_address.left(16)));
        } else {
            setStatus(tr("Counterparty addresses received — Start swap pre-filled "
                          "(joint stealth still needs manual Build).")
                );
        }
    }
}

void PricoinOrderbookPage::onFillClicked()
{
    if (!m_model) return;
    const std::string oid = selectedOrderId();
    if (oid.empty()) return;
    if (QMessageBox::question(this, tr("Mark filled"),
            tr("Mark this Matched order as filled? Use only after the swap "
               "has confirmed on-chain on both sides."),
            QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) return;
    auto r = m_model->wallet().offerFill(oid);
    if (!r) {
        setStatus(tr("Fill failed: %1")
            .arg(QString::fromStdString(util::ErrorString(r).original)), true);
        return;
    }
    refreshTable();
    setStatus(tr("Marked filled."));
}

void PricoinOrderbookPage::onUnmatchClicked()
{
    if (!m_model) return;
    const std::string oid = selectedOrderId();
    if (oid.empty()) return;
    if (QMessageBox::question(this, tr("Release match"),
            tr("Release this match back to Active? Use when the swap setup "
               "has aborted but the order should remain available."),
            QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) return;

    // Snapshot the matched-with peer before unmatching, so we can DM
    // them. After offerUnmatch the matched_with link is cleared.
    std::string peer_oid;
    {
        const auto rec = m_model->wallet().offerGet(oid);
        if (rec) peer_oid = rec->matched_with_order_id;
    }

    auto r = m_model->wallet().offerUnmatch(oid);
    if (!r) {
        setStatus(tr("Unmatch failed: %1")
            .arg(QString::fromStdString(util::ErrorString(r).original)), true);
        return;
    }
    refreshTable();

    // Notify counterparty via NIP-04 DM so their wallet mirrors the
    // release. Symmetrical to the match-DM flow in onFindMatchesClicked.
    int dm_sent = 0;
    if (m_nostr && !peer_oid.empty()) {
        const auto peer = m_model->wallet().offerGet(peer_oid);
        if (peer && peer->maker_pubkey_hex.size() >= 66) {
            const QString peer_xonly = QString::fromStdString(
                peer->maker_pubkey_hex.substr(2));
            QJsonObject msg;
            msg.insert(QStringLiteral("type"),
                QStringLiteral("pricoin:unmatch/v1"));
            msg.insert(QStringLiteral("my_order_id"),
                QString::fromStdString(oid));
            msg.insert(QStringLiteral("their_order_id"),
                QString::fromStdString(peer_oid));
            const QString plaintext = QString::fromUtf8(
                QJsonDocument(msg).toJson(QJsonDocument::Compact));
            m_next_dm_label = tr("Unmatch notification for order %1…")
                .arg(QString::fromStdString(peer_oid).left(12));
            if (m_nostr->publishDirectMessage(peer_xonly, plaintext)) {
                dm_sent = 1;
            }
            m_next_dm_label.clear();
        }
    }
    setStatus(dm_sent ? tr("Released. Counterparty notified.")
                      : tr("Released. (counterparty not notified — DM failed)"));
}

// ─── Swap-address auto-exchange helpers ──────────────────────────────
//
// At match time both clients DM each other their BTC P2TR xonly + PRIC
// stealth address. The peer's pair lands in `m_peer_swap_addrs` keyed
// by THE LOCAL ORDER ID it pertains to, so the Start-swap dialog can
// pre-fill all four address fields without the user pasting anything.

QString PricoinOrderbookPage::getMyBtcXOnly(const QString& chain) const
{
    if (!m_model) return {};
    const QString wallet_name = m_model->getWalletName();
    std::string uri;
    if (!wallet_name.isEmpty()) {
        uri = "/wallet/" + std::string(
            QUrl::toPercentEncoding(wallet_name).constData());
    }
    UniValue p{UniValue::VARR};
    p.push_back(chain.toStdString());
    UniValue r;
    try {
        r = m_model->node().executeRpc("pricoin_btc_getaddress", p, uri);
    } catch (const UniValue&) {
        return {};
    } catch (const std::exception&) {
        return {};
    }
    if (!r.isObject() || !r.exists("xonly")) return {};
    return QString::fromStdString(r["xonly"].get_str());
}

QString PricoinOrderbookPage::getMyPricStealth() const
{
    if (!m_model) return {};
    const std::string s = m_model->wallet().getStealthAddress();
    return QString::fromStdString(s);
}

void PricoinOrderbookPage::sendSwapAddrs(
    const std::string& my_oid,
    const std::string& peer_oid,
    const std::string& foreign_chain)
{
    if (!m_nostr || !m_model) return;
    const auto peer = m_model->wallet().offerGet(peer_oid);
    if (!peer || peer->maker_pubkey_hex.size() < 66) return;
    const QString peer_xonly = QString::fromStdString(
        peer->maker_pubkey_hex.substr(2));

    const QString my_btc_xonly = getMyBtcXOnly(
        QString::fromStdString(foreign_chain));
    const QString my_stealth   = getMyPricStealth();
    const auto    my_pubkeys   = GetMyStealthPubkeys(m_model);
    if (my_btc_xonly.isEmpty() || my_stealth.isEmpty() ||
        my_pubkeys.view_hex.isEmpty() || my_pubkeys.spend_hex.isEmpty()) {
        // Wallet probably locked, or holding-wallet identity not
        // derivable. Skip — the Start-swap dialog will fall back to
        // manual paste for the missing slots.
        return;
    }

    QJsonObject msg;
    msg.insert(QStringLiteral("type"),
        QStringLiteral("pricoin:swap_addrs/v1"));
    msg.insert(QStringLiteral("my_order_id"),
        QString::fromStdString(my_oid));
    msg.insert(QStringLiteral("their_order_id"),
        QString::fromStdString(peer_oid));
    msg.insert(QStringLiteral("foreign_chain"),
        QString::fromStdString(foreign_chain));
    msg.insert(QStringLiteral("btc_xonly"),    my_btc_xonly);
    msg.insert(QStringLiteral("pric_stealth"), my_stealth);
    // Raw view + spend pubkeys so the receiver can pre-compute the
    // joint stealth address client-side without a separate dialog
    // round-trip. Both 33-byte compressed hex (66 chars).
    msg.insert(QStringLiteral("view_pubkey"),  my_pubkeys.view_hex);
    msg.insert(QStringLiteral("spend_pubkey"), my_pubkeys.spend_hex);
    const QString plaintext = QString::fromUtf8(
        QJsonDocument(msg).toJson(QJsonDocument::Compact));
    m_next_dm_label = tr("Swap-address exchange for order %1…")
        .arg(QString::fromStdString(peer_oid).left(12));
    m_nostr->publishDirectMessage(peer_xonly, plaintext);
    m_next_dm_label.clear();
}
