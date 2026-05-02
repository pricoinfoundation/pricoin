// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pricoin_swaps_page.h>

#include <qt/walletmodel.h>
#include <util/translation.h>

#include <QBrush>
#include <QColor>
#include <QFont>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QStandardItemModel>
#include <QTableView>
#include <QTextEdit>
#include <QTimer>
#include <QVBoxLayout>

namespace {

QString FormatSat(int64_t sat) {
    const int64_t whole = sat / 100'000'000;
    const int64_t frac  = sat % 100'000'000;
    return QString::asprintf("%lld.%08lld",
                              static_cast<long long>(whole),
                              static_cast<long long>(frac));
}

QColor StateColor(const std::string& s) {
    if (s == "setup")         return QColor(0x70, 0x70, 0x70); // grey — gathering data
    if (s == "adaptor_ready") return QColor(0x14, 0x4f, 0xc9); // blue
    if (s == "btc_funded")    return QColor(0x00, 0x80, 0x80); // teal
    if (s == "both_funded")   return QColor(0x00, 0x80, 0x80);
    if (s == "pre_signed")    return QColor(0xe6, 0x91, 0x38); // amber
    if (s == "pric_claimed")  return QColor(0xe6, 0x91, 0x38);
    if (s == "complete")      return QColor(0x1b, 0x5e, 0x20); // green
    if (s == "refunded")      return QColor(0xb7, 0x1c, 0x1c); // red
    if (s == "aborted")       return QColor(0xb7, 0x1c, 0x1c);
    return QColor(Qt::black);
}

QString StateBadge(const std::string& s) {
    QString q = QString::fromStdString(s);
    if (!q.isEmpty()) q[0] = q[0].toUpper();
    q.replace('_', ' ');
    return q;
}

} // namespace

PricoinSwapsPage::PricoinSwapsPage(const PlatformStyle* platformStyle, QWidget* parent)
    : QWidget(parent), m_platform_style(platformStyle)
{
    buildLayout();
}

PricoinSwapsPage::~PricoinSwapsPage() = default;

void PricoinSwapsPage::buildLayout()
{
    auto* outer = new QVBoxLayout(this);

    auto* top = new QHBoxLayout();
    m_btn_refresh = new QPushButton(tr("Refresh"), this);
    top->addWidget(m_btn_refresh);
    top->addStretch();
    m_status_label = new QLabel(this);
    m_status_label->setWordWrap(true);
    top->addWidget(m_status_label, /*stretch=*/1);
    outer->addLayout(top);

    m_table_model = new QStandardItemModel(this);
    m_table_model->setHorizontalHeaderLabels({
        tr("Swap id"), tr("Role"), tr("State"), tr("Counterparty"),
        tr("Chain"), tr("Foreign sat"), tr("PRIC"),
        tr("Joint stealth"), tr("Updated")
    });
    m_table = new QTableView(this);
    m_table->setModel(m_table_model);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setStretchLastSection(true);
    outer->addWidget(m_table, /*stretch=*/1);

    auto* hint_box = new QVBoxLayout();
    hint_box->addWidget(new QLabel(tr("Next action:"), this));
    m_next_action_view = new QTextEdit(this);
    m_next_action_view->setReadOnly(true);
    m_next_action_view->setMaximumHeight(80);
    hint_box->addWidget(m_next_action_view);
    outer->addLayout(hint_box);

    auto* bot = new QHBoxLayout();
    m_btn_abort = new QPushButton(tr("Abort swap"), this);
    bot->addWidget(m_btn_abort);
    bot->addStretch();
    outer->addLayout(bot);

    connect(m_btn_refresh, &QPushButton::clicked, this, &PricoinSwapsPage::onRefreshClicked);
    connect(m_btn_abort,   &QPushButton::clicked, this, &PricoinSwapsPage::onAbortClicked);

    if (auto* sm = m_table->selectionModel()) {
        connect(sm, &QItemSelectionModel::selectionChanged,
                this, &PricoinSwapsPage::onSelectionChanged);
    }

    m_auto_refresh_timer = new QTimer(this);
    m_auto_refresh_timer->setInterval(5000);
    connect(m_auto_refresh_timer, &QTimer::timeout, this, &PricoinSwapsPage::onAutoRefreshTick);

    onSelectionChanged();
}

void PricoinSwapsPage::setModel(WalletModel* model)
{
    m_model = model;
    if (auto* sm = m_table->selectionModel()) {
        connect(sm, &QItemSelectionModel::selectionChanged,
                this, &PricoinSwapsPage::onSelectionChanged);
    }
    refreshTable();
    if (m_model && m_auto_refresh_timer && !m_auto_refresh_timer->isActive()) {
        m_auto_refresh_timer->start();
    }
}

void PricoinSwapsPage::refreshTable()
{
    if (!m_model) {
        m_table_model->setRowCount(0);
        m_swaps.clear();
        return;
    }
    m_swaps = m_model->wallet().adaptorSwapList();
    m_table_model->setRowCount(static_cast<int>(m_swaps.size()));
    for (size_t i = 0; i < m_swaps.size(); ++i) {
        const auto& s = m_swaps[i];
        int col = 0;
        m_table_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(QString::fromStdString(s.swap_id).left(12) + "…"));
        m_table_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(QString::fromStdString(s.role)));
        auto* state_item = new QStandardItem(StateBadge(s.state));
        state_item->setForeground(QBrush(StateColor(s.state)));
        QFont f = state_item->font();
        f.setBold(true);
        state_item->setFont(f);
        m_table_model->setItem(static_cast<int>(i), col++, state_item);
        m_table_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(QString::fromStdString(s.counterparty_pubkey_hex).left(16) + "…"));
        m_table_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(QString::fromStdString(s.foreign_chain)));
        m_table_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(QString::number(s.foreign_amount_sat)));
        m_table_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(FormatSat(s.pric_amount_sat)));
        m_table_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(QString::fromStdString(s.pric_joint_stealth_address).left(20) + "…"));
        m_table_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(QString::number(s.updated_time)));
    }
    m_table->resizeColumnsToContents();
    onSelectionChanged();
}

void PricoinSwapsPage::setStatus(const QString& msg, bool error)
{
    m_status_label->setStyleSheet(error
        ? QStringLiteral("QLabel { color: #b71c1c; }")
        : QStringLiteral("QLabel { color: #1b5e20; }"));
    m_status_label->setText(msg);
}

std::string PricoinSwapsPage::selectedSwapId() const
{
    auto* sm = m_table->selectionModel();
    if (!sm) return {};
    const auto sel = sm->selectedRows();
    if (sel.isEmpty()) return {};
    const int row = sel.first().row();
    if (row < 0 || row >= static_cast<int>(m_swaps.size())) return {};
    return m_swaps[row].swap_id;
}

void PricoinSwapsPage::onSelectionChanged()
{
    const std::string sid = selectedSwapId();
    bool can_abort = false;
    QString hint;
    if (!sid.empty()) {
        for (const auto& s : m_swaps) {
            if (s.swap_id == sid) {
                hint = QString::fromStdString(s.next_action);
                can_abort = (s.state != "complete" && s.state != "refunded"
                             && s.state != "aborted");
                break;
            }
        }
    }
    if (m_next_action_view) m_next_action_view->setPlainText(hint);
    m_btn_abort->setEnabled(!sid.empty() && can_abort);
}

void PricoinSwapsPage::onRefreshClicked()
{
    refreshTable();
    setStatus(tr("Refreshed."));
}

void PricoinSwapsPage::onAutoRefreshTick()
{
    if (m_model) refreshTable();
}

void PricoinSwapsPage::onAbortClicked()
{
    if (!m_model) return;
    const std::string sid = selectedSwapId();
    if (sid.empty()) return;
    bool ok = false;
    const QString reason = QInputDialog::getText(
        this, tr("Abort swap"),
        tr("Abort reason (free text — recorded in the swap record):"),
        QLineEdit::Normal, QString(), &ok);
    if (!ok) return;
    auto r = m_model->wallet().adaptorSwapAbort(sid, reason.toStdString());
    if (!r) {
        setStatus(tr("Abort failed: %1")
            .arg(QString::fromStdString(util::ErrorString(r).original)), true);
        return;
    }
    refreshTable();
    setStatus(tr("Swap aborted."));
}
