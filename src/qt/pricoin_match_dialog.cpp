// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pricoin_match_dialog.h>

#include <QDialogButtonBox>
#include <QDoubleSpinBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QStandardItemModel>
#include <QTableView>
#include <QVBoxLayout>

#include <algorithm>
#include <cmath>
#include <limits>

namespace {

QString FormatSat(int64_t sat) {
    const int64_t whole = sat / 100'000'000;
    const int64_t frac  = sat % 100'000'000;
    return QString::asprintf("%lld.%08lld",
                              static_cast<long long>(whole),
                              static_cast<long long>(frac));
}

// Compute foreign-amount at the maker (ask)'s rate:
//   foreign = floor(actual_pric * ask.foreign_at_max / ask.max_pric)
// Uses int128 to avoid 64-bit overflow.
int64_t ProRateForeign(int64_t actual_pric_sat,
                        int64_t ask_max_pric_sat,
                        int64_t ask_foreign_at_max_sat)
{
    if (ask_max_pric_sat <= 0 || actual_pric_sat <= 0) return 0;
    __int128 prod = static_cast<__int128>(actual_pric_sat) *
                    static_cast<__int128>(ask_foreign_at_max_sat);
    return static_cast<int64_t>(prod / ask_max_pric_sat);
}

} // namespace

PricoinMatchDialog::PricoinMatchDialog(
    const interfaces::Wallet::PricoinOfferSnapshot& mine,
    std::vector<interfaces::Wallet::PricoinMatchCandidate> candidates,
    const std::vector<interfaces::Wallet::PricoinOfferSnapshot>& wallet_orders,
    QWidget* parent)
    : QDialog(parent),
      m_mine(mine),
      m_candidates(std::move(candidates)),
      m_wallet_orders(wallet_orders)
{
    setWindowTitle(tr("Match — pick a counterparty"));
    resize(720, 480);
    buildLayout();
    if (!m_candidates.empty()) {
        m_table->selectRow(0);
        onCandidateChanged();
    } else {
        m_ok_button->setEnabled(false);
    }
}

const interfaces::Wallet::PricoinOfferSnapshot*
PricoinMatchDialog::findOrder(const std::string& order_id) const
{
    for (const auto& o : m_wallet_orders) {
        if (o.order_id == order_id) return &o;
    }
    return nullptr;
}

void PricoinMatchDialog::buildLayout()
{
    auto* outer = new QVBoxLayout(this);

    auto* hdr = new QLabel(this);
    hdr->setWordWrap(true);
    hdr->setText(tr("My order: <b>%1</b>, %2 PRIC max @ %3 foreign/PRIC, "
                     "remaining %4 PRIC.")
        .arg(QString::fromStdString(m_mine.side))
        .arg(FormatSat(m_mine.max_pric_amount_sat))
        .arg(m_mine.max_pric_amount_sat > 0
            ? QString::asprintf("%.8f",
                static_cast<double>(m_mine.foreign_amount_at_max_sat) /
                static_cast<double>(m_mine.max_pric_amount_sat))
            : QStringLiteral("-"))
        .arg(FormatSat(m_mine.pric_remaining_sat)));
    outer->addWidget(hdr);

    m_model = new QStandardItemModel(this);
    m_model->setHorizontalHeaderLabels({
        tr("Their id"), tr("Max PRIC"), tr("Foreign @ max"),
        tr("Their rate"), tr("Max actual fill"), tr("Advantage")
    });
    m_table = new QTableView(this);
    m_table->setModel(m_model);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->verticalHeader()->setVisible(false);
    m_table->horizontalHeader()->setStretchLastSection(true);

    m_model->setRowCount(static_cast<int>(m_candidates.size()));
    for (size_t i = 0; i < m_candidates.size(); ++i) {
        const auto& c = m_candidates[i];
        const QString their_rate = (c.their_max_pric_sat > 0)
            ? QString::asprintf("%.8f",
                static_cast<double>(c.their_foreign_at_max_sat) /
                static_cast<double>(c.their_max_pric_sat))
            : QStringLiteral("-");
        int col = 0;
        m_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(QString::fromStdString(c.their_order_id).left(12) + "…"));
        m_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(FormatSat(c.their_max_pric_sat)));
        m_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(FormatSat(c.their_foreign_at_max_sat)));
        m_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(their_rate));
        m_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(FormatSat(c.max_actual_pric_sat)));
        m_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(QString::number(c.price_advantage_milli)));
    }
    m_table->resizeColumnsToContents();
    outer->addWidget(m_table, /*stretch=*/1);

    auto* amt_row = new QHBoxLayout();
    amt_row->addWidget(new QLabel(tr("Actual PRIC fill:"), this));
    // Display in PRIC (8 decimals) instead of raw sats — keeps the
    // value human-readable. Internal conversion ×1e8 = sats. Range
    // covers the full int64 sat space (~92 billion PRIC); QDouble-
    // SpinBox holds it as a double which is lossless to ~92 PRIC at
    // 8-decimal precision (well above any realistic order size).
    m_amount_spin = new QDoubleSpinBox(this);
    m_amount_spin->setDecimals(8);
    m_amount_spin->setRange(0.0, 1e10);
    m_amount_spin->setSingleStep(1.0);
    m_amount_spin->setSuffix(QStringLiteral(" PRIC"));
    m_amount_spin->setAlignment(Qt::AlignRight);
    amt_row->addWidget(m_amount_spin);
    amt_row->addStretch();
    outer->addLayout(amt_row);

    m_preview_label = new QLabel(this);
    m_preview_label->setWordWrap(true);
    outer->addWidget(m_preview_label);

    auto* bb = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    m_ok_button = bb->button(QDialogButtonBox::Ok);
    m_ok_button->setText(tr("Match"));
    connect(bb, &QDialogButtonBox::accepted, this, [this]() {
        const int idx = selectedCandidateIndex();
        if (idx < 0) { reject(); return; }
        m_chosen_their_id = m_candidates[idx].their_order_id;
        // Convert PRIC display to sats (×1e8) for storage. llround
        // for the half-up conversion since QDoubleSpinBox stepping
        // can leave tiny float drift.
        m_chosen_actual_pric_sat = static_cast<int64_t>(
            std::llround(m_amount_spin->value() * 100'000'000.0));
        accept();
    });
    connect(bb, &QDialogButtonBox::rejected, this, &QDialog::reject);
    outer->addWidget(bb);

    if (auto* sm = m_table->selectionModel()) {
        connect(sm, &QItemSelectionModel::selectionChanged,
                this, &PricoinMatchDialog::onCandidateChanged);
    }
    connect(m_amount_spin,
            QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &PricoinMatchDialog::onAmountChanged);
}

int PricoinMatchDialog::selectedCandidateIndex() const
{
    auto* sm = m_table->selectionModel();
    if (!sm) return -1;
    const auto sel = sm->selectedRows();
    if (sel.isEmpty()) return -1;
    const int row = sel.first().row();
    if (row < 0 || row >= static_cast<int>(m_candidates.size())) return -1;
    return row;
}

void PricoinMatchDialog::onCandidateChanged()
{
    const int idx = selectedCandidateIndex();
    if (idx < 0) {
        m_amount_spin->setRange(0.0, 0.0);
        m_amount_spin->setValue(0.0);
        m_preview_label->setText({});
        m_ok_button->setEnabled(false);
        return;
    }
    const auto& c = m_candidates[idx];
    // Convert sat-cap to PRIC for the display widget. doubles handle
    // values up to 2^53 sats precisely, so no precision concern for
    // any realistic order.
    const double max_pric =
        static_cast<double>(c.max_actual_pric_sat) / 100'000'000.0;
    const double min_pric = 0.00000001;   // 1 sat
    m_amount_spin->setRange(min_pric, std::max(min_pric, max_pric));
    m_amount_spin->setValue(max_pric);    // default to maximum legal fill
    m_ok_button->setEnabled(true);
    updatePreview();
}

void PricoinMatchDialog::onAmountChanged(double)
{
    updatePreview();
}

void PricoinMatchDialog::updatePreview()
{
    const int idx = selectedCandidateIndex();
    if (idx < 0) { m_preview_label->setText({}); return; }
    const auto& c = m_candidates[idx];
    const int64_t actual_pric = static_cast<int64_t>(
        std::llround(m_amount_spin->value() * 100'000'000.0));

    // Identify the maker (asker) — whichever side is sell_pric.
    // The maker's rate determines the trade.
    const auto* their = findOrder(c.their_order_id);
    if (!their) {
        m_preview_label->setText(tr("(Counterparty order not in wallet)"));
        return;
    }
    const interfaces::Wallet::PricoinOfferSnapshot* ask =
        (m_mine.side == "sell_pric") ? &m_mine : their;
    const int64_t actual_foreign = ProRateForeign(
        actual_pric, ask->max_pric_amount_sat, ask->foreign_amount_at_max_sat);

    m_preview_label->setText(
        tr("<b>Trade preview:</b> %1 PRIC ↔ %2 foreign sat at maker's "
            "(asker's) rate %3. Both sides → Matched on accept.")
        .arg(FormatSat(actual_pric))
        .arg(actual_foreign)
        .arg(ask->max_pric_amount_sat > 0
            ? QString::asprintf("%.8f",
                static_cast<double>(ask->foreign_amount_at_max_sat) /
                static_cast<double>(ask->max_pric_amount_sat))
            : QStringLiteral("-")));
}
