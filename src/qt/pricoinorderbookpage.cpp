// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pricoinorderbookpage.h>

#include <qt/pricoin_match_dialog.h>
#include <qt/pricoin_nostr_client.h>
#include <qt/pricoin_relay_settings_dialog.h>
#include <qt/walletmodel.h>
#include <util/translation.h>

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
        m_side->addItem(tr("Buy PRIC (pay foreign, receive PRIC)"), QStringLiteral("buy_pric"));
        m_side->addItem(tr("Sell PRIC (pay PRIC, receive foreign)"), QStringLiteral("sell_pric"));
        form->addRow(tr("Side:"), m_side);

        m_chain = new QComboBox(this);
        m_chain->addItem(QStringLiteral("BTC"), QStringLiteral("btc"));
        m_chain->addItem(QStringLiteral("LTC"), QStringLiteral("ltc"));
        form->addRow(tr("Foreign chain:"), m_chain);

        m_pric = new QLineEdit(this);
        m_pric->setPlaceholderText(tr("e.g. 1.00000000"));
        form->addRow(tr("Max PRIC amount:"), m_pric);

        m_foreign = new QLineEdit(this);
        m_foreign->setPlaceholderText(tr("e.g. 0.50000000 (foreign at max)"));
        form->addRow(tr("Foreign at max:"), m_foreign);

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
    }

    bool getParams(interfaces::Wallet::PricoinOfferCreateParams& out, QString& err) const {
        bool ok_pric = false, ok_for = false;
        const double pric_d = m_pric->text().trimmed().toDouble(&ok_pric);
        const double for_d  = m_foreign->text().trimmed().toDouble(&ok_for);
        if (!ok_pric || pric_d <= 0) { err = tr("max PRIC must be a positive number"); return false; }
        if (!ok_for  || for_d  <= 0) { err = tr("foreign at max must be a positive number"); return false; }
        out.side = m_side->currentData().toString().toStdString();
        out.foreign_chain = m_chain->currentData().toString().toStdString();
        out.max_pric_amount_sat = static_cast<int64_t>(pric_d * 100'000'000.0);
        out.foreign_amount_at_max_sat = static_cast<int64_t>(for_d * 100'000'000.0);
        out.expiry_unix_sec = QDateTime::currentSecsSinceEpoch()
                              + static_cast<int64_t>(m_expiry_hours->value()) * 3600;
        out.notes = m_notes->text().toStdString();
        return true;
    }

private:
    QComboBox* m_side;
    QComboBox* m_chain;
    QLineEdit* m_pric;
    QLineEdit* m_foreign;
    QSpinBox*  m_expiry_hours;
    QLineEdit* m_notes;
};

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
    if (m_nostr) {
        m_nostr->disconnectAll();
        m_nostr->deleteLater();
        m_nostr = nullptr;
        m_connected_relay_count = 0;
    }
    if (!m_model) return;
    const QStringList relays = PricoinRelaySettingsDialog::loadFromSettings();
    if (relays.isEmpty()) return;
    m_nostr = new PricoinNostrClient(m_model, relays, this);
    connect(m_nostr, &PricoinNostrClient::offerReceived,
            this, &PricoinOrderbookPage::onNostrOfferReceived);
    connect(m_nostr, &PricoinNostrClient::log,
            this, &PricoinOrderbookPage::onNostrLog);
    connect(m_nostr, &PricoinNostrClient::relayStatusChanged,
            this, &PricoinOrderbookPage::onNostrRelayStatus);
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

    // Map orderbook side → adaptor-swap role.
    //   sell_pric (giving up PRIC, receiving foreign) → Alice
    //   buy_pric  (giving up foreign, receiving PRIC) → Bob
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
    form->addRow(tr("Joint stealth address:"), joint_edit);

    // Per-leg destination addresses. Stored on the swap record so
    // the cooperative-sign dialogs can pre-fill recipient/dest based
    // on Mode + role without another out-of-band exchange. Both
    // parties enter all four (the swap protocol requires both sides
    // to agree on these up front).
    auto* btc_alice_rcpt = new QLineEdit(&dlg);
    btc_alice_rcpt->setPlaceholderText(tr("32-byte x-only — Alice's BTC P2TR refund recipient"));
    form->addRow(tr("BTC refund (Alice's xonly):"), btc_alice_rcpt);

    auto* btc_bob_rcpt = new QLineEdit(&dlg);
    btc_bob_rcpt->setPlaceholderText(tr("32-byte x-only — Bob's BTC P2TR claim recipient"));
    form->addRow(tr("BTC claim (Bob's xonly):"), btc_bob_rcpt);

    auto* pric_alice_rcpt = new QLineEdit(&dlg);
    pric_alice_rcpt->setPlaceholderText(tr("Alice's PRIC stealth claim recipient"));
    form->addRow(tr("PRIC claim (Alice's stealth):"), pric_alice_rcpt);

    auto* pric_bob_rcpt = new QLineEdit(&dlg);
    pric_bob_rcpt->setPlaceholderText(tr("Bob's PRIC stealth refund recipient"));
    form->addRow(tr("PRIC refund (Bob's stealth):"), pric_bob_rcpt);

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

    interfaces::Wallet::PricoinAdaptorSwapCreateParams ap;
    ap.role = my_role;
    ap.counterparty_pubkey_hex = peer->maker_pubkey_hex;
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
    setStatus(tr("Swap created. Switch to the Swaps tab to track its state."));
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
    setStatus(tr("Order created. URI copied to clipboard — share with counterparty."));
    QApplication::clipboard()->setText(QString::fromStdString(r.uri));
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
    setStatus(tr("Cancelled."));
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
    setStatus(tr("Matched %1 PRIC against %2…")
        .arg(QString::asprintf("%lld.%08lld",
            static_cast<long long>(actual_pric / 100'000'000),
            static_cast<long long>(actual_pric % 100'000'000)))
        .arg(QString::fromStdString(their_id).left(12)));
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
    auto r = m_model->wallet().offerUnmatch(oid);
    if (!r) {
        setStatus(tr("Unmatch failed: %1")
            .arg(QString::fromStdString(util::ErrorString(r).original)), true);
        return;
    }
    refreshTable();
    setStatus(tr("Released."));
}
