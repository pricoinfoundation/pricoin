// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pricoinorderbookpage.h>

#include <qt/pricoin_nostr_client.h>
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
#include <QStandardItemModel>
#include <QTableView>
#include <QTextEdit>
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
    // Title-case status; the table view doesn't yet color-code.
    QString q = QString::fromStdString(s);
    if (!q.isEmpty()) q[0] = q[0].toUpper();
    return q;
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

    // Table.
    m_table_model = new QStandardItemModel(this);
    m_table_model->setHorizontalHeaderLabels({
        tr("Order id"), tr("Origin"), tr("Side"), tr("Chain"),
        tr("Max PRIC"), tr("Foreign @ max"), tr("Rate (foreign/PRIC)"),
        tr("Status"), tr("Remaining"), tr("In flight"),
        tr("Expires"), tr("Notes")
    });
    m_table = new QTableView(this);
    m_table->setModel(m_table_model);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSortingEnabled(false);
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
    bot_row->addWidget(m_btn_cancel);
    bot_row->addWidget(m_btn_copy_uri);
    bot_row->addWidget(m_btn_find_matches);
    bot_row->addWidget(m_btn_fill);
    bot_row->addWidget(m_btn_unmatch);
    bot_row->addWidget(m_btn_publish);
    bot_row->addStretch();
    outer->addLayout(bot_row);

    // Relay status row.
    auto* relay_row = new QHBoxLayout();
    m_btn_connect_relays = new QPushButton(tr("Connect relays"), this);
    m_relay_status_label = new QLabel(tr("Relays: not connected"), this);
    m_relay_status_label->setWordWrap(true);
    relay_row->addWidget(m_btn_connect_relays);
    relay_row->addWidget(m_relay_status_label, /*stretch=*/1);
    outer->addLayout(relay_row);

    connect(m_btn_create,       &QPushButton::clicked, this, &PricoinOrderbookPage::onCreateClicked);
    connect(m_btn_import,       &QPushButton::clicked, this, &PricoinOrderbookPage::onImportClicked);
    connect(m_btn_refresh,      &QPushButton::clicked, this, &PricoinOrderbookPage::onRefreshClicked);
    connect(m_btn_cancel,       &QPushButton::clicked, this, &PricoinOrderbookPage::onCancelClicked);
    connect(m_btn_copy_uri,     &QPushButton::clicked, this, &PricoinOrderbookPage::onCopyUriClicked);
    connect(m_btn_find_matches, &QPushButton::clicked, this, &PricoinOrderbookPage::onFindMatchesClicked);
    connect(m_btn_fill,         &QPushButton::clicked, this, &PricoinOrderbookPage::onFillClicked);
    connect(m_btn_unmatch,      &QPushButton::clicked, this, &PricoinOrderbookPage::onUnmatchClicked);
    connect(m_btn_publish,         &QPushButton::clicked, this, &PricoinOrderbookPage::onPublishClicked);
    connect(m_btn_connect_relays,  &QPushButton::clicked, this, &PricoinOrderbookPage::onConnectRelaysClicked);

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
}

void PricoinOrderbookPage::refreshTable()
{
    if (!m_model) {
        m_table_model->setRowCount(0);
        m_orders.clear();
        return;
    }
    m_orders = m_model->wallet().offerList();
    m_table_model->setRowCount(static_cast<int>(m_orders.size()));
    for (size_t i = 0; i < m_orders.size(); ++i) {
        const auto& o = m_orders[i];
        const QString id_short = QString::fromStdString(o.order_id).left(12) + "…";
        const QString rate = (o.max_pric_amount_sat > 0)
            ? QString::asprintf("%.8f",
                static_cast<double>(o.foreign_amount_at_max_sat) /
                static_cast<double>(o.max_pric_amount_sat))
            : QStringLiteral("-");
        int col = 0;
        m_table_model->setItem(static_cast<int>(i), col++, new QStandardItem(id_short));
        m_table_model->setItem(static_cast<int>(i), col++, new QStandardItem(QString::fromStdString(o.origin)));
        m_table_model->setItem(static_cast<int>(i), col++, new QStandardItem(QString::fromStdString(o.side)));
        m_table_model->setItem(static_cast<int>(i), col++, new QStandardItem(QString::fromStdString(o.foreign_chain)));
        m_table_model->setItem(static_cast<int>(i), col++, new QStandardItem(FormatSat(o.max_pric_amount_sat)));
        m_table_model->setItem(static_cast<int>(i), col++, new QStandardItem(FormatSat(o.foreign_amount_at_max_sat)));
        m_table_model->setItem(static_cast<int>(i), col++, new QStandardItem(rate));
        m_table_model->setItem(static_cast<int>(i), col++, new QStandardItem(StatusBadge(o.status)));
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
    const int row = sel.first().row();
    if (row < 0 || row >= static_cast<int>(m_orders.size())) return {};
    return m_orders[row].order_id;
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

void PricoinOrderbookPage::onConnectRelaysClicked()
{
    if (!m_model) return;
    if (!m_nostr) {
        // Default relay list. Replace via QSettings or a config dialog
        // in a follow-up commit.
        QStringList relays;
        relays << "wss://relay.damus.io"
               << "wss://nos.lol"
               << "wss://relay.snort.social";
        m_nostr = new PricoinNostrClient(m_model, relays, this);
        connect(m_nostr, &PricoinNostrClient::offerReceived,
                this, &PricoinOrderbookPage::onNostrOfferReceived);
        connect(m_nostr, &PricoinNostrClient::log,
                this, &PricoinOrderbookPage::onNostrLog);
        connect(m_nostr, &PricoinNostrClient::relayStatusChanged,
                this, &PricoinOrderbookPage::onNostrRelayStatus);
    }
    m_nostr->connectAll();
    setStatus(tr("Connecting to %1 relays…").arg(m_nostr->relayUrls().size()));
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
    const auto cands = m_model->wallet().offerFindMatches(oid);
    if (cands.empty()) {
        QMessageBox::information(this, tr("Find matches"),
            tr("No imported orders price-cross with this one."));
        return;
    }
    QStringList lines;
    lines << tr("%1 candidate(s) — best first:").arg(cands.size());
    for (const auto& c : cands) {
        lines << tr("  %1… max %2 PRIC")
            .arg(QString::fromStdString(c.their_order_id).left(12))
            .arg(FormatSat(c.max_actual_pric_sat));
    }
    QMessageBox::information(this, tr("Find matches"), lines.join('\n'));
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
