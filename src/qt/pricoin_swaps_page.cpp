// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pricoin_swaps_page.h>

#include <qt/walletmodel.h>
#include <util/translation.h>

#include <QBrush>
#include <QColor>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFont>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QPlainTextEdit>
#include <QSpinBox>
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
    m_btn_advance = new QPushButton(tr("Advance state…"), this);
    m_btn_refund  = new QPushButton(tr("Refund…"),         this);
    m_btn_abort   = new QPushButton(tr("Abort swap"),      this);
    bot->addWidget(m_btn_advance);
    bot->addWidget(m_btn_refund);
    bot->addWidget(m_btn_abort);
    bot->addStretch();
    outer->addLayout(bot);

    connect(m_btn_refresh, &QPushButton::clicked, this, &PricoinSwapsPage::onRefreshClicked);
    connect(m_btn_advance, &QPushButton::clicked, this, &PricoinSwapsPage::onAdvanceClicked);
    connect(m_btn_refund,  &QPushButton::clicked, this, &PricoinSwapsPage::onRefundClicked);
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
    bool can_advance = false;
    bool can_refund = false;
    QString hint;
    if (!sid.empty()) {
        for (const auto& s : m_swaps) {
            if (s.swap_id == sid) {
                hint = QString::fromStdString(s.next_action);
                const std::string& st = s.state;
                can_abort = (st != "complete" && st != "refunded" && st != "aborted");
                // Advance is offered for any non-terminal pre-Complete state.
                can_advance = (st == "setup" || st == "adaptor_ready"
                               || st == "btc_funded" || st == "both_funded"
                               || st == "pre_signed" || st == "pric_claimed");
                // Refund is allowed once funding has confirmed.
                can_refund = (st == "both_funded" || st == "pre_signed"
                              || st == "pric_claimed");
                break;
            }
        }
    }
    if (m_next_action_view) m_next_action_view->setPlainText(hint);
    m_btn_advance->setEnabled(can_advance);
    m_btn_refund->setEnabled(can_refund);
    m_btn_abort->setEnabled(can_abort);
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

// ─── Advance-state dialogs (one per source state) ───────────────────
//
// Each helper builds a modal QDialog with state-appropriate fields,
// runs exec(), and on Accepted calls the wallet method and refreshes.
// Helpers return true on success so the caller can refresh the UI.

namespace {

// Adds a label+QLineEdit row, returns the edit so the caller can
// read the value back.
QLineEdit* AddTextRow(QFormLayout* form, const QString& label,
                      QWidget* parent, const QString& placeholder = {})
{
    auto* edit = new QLineEdit(parent);
    if (!placeholder.isEmpty()) edit->setPlaceholderText(placeholder);
    form->addRow(label, edit);
    return edit;
}

// Adds a label+QPlainTextEdit row for variable-length hex blobs.
QPlainTextEdit* AddBlobRow(QFormLayout* form, const QString& label,
                            QWidget* parent, int max_h = 60)
{
    auto* edit = new QPlainTextEdit(parent);
    edit->setMaximumHeight(max_h);
    form->addRow(label, edit);
    return edit;
}

QSpinBox* AddIntRow(QFormLayout* form, const QString& label,
                    QWidget* parent, int min, int max, int default_val)
{
    auto* spin = new QSpinBox(parent);
    spin->setRange(min, max);
    spin->setValue(default_val);
    form->addRow(label, spin);
    return spin;
}

// Builds an OK/Cancel button box and connects to the dialog.
void AddOkCancel(QFormLayout* form, QDialog* dlg)
{
    auto* bb = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dlg);
    QObject::connect(bb, &QDialogButtonBox::accepted, dlg, &QDialog::accept);
    QObject::connect(bb, &QDialogButtonBox::rejected, dlg, &QDialog::reject);
    form->addRow(bb);
}

} // namespace

void PricoinSwapsPage::onAdvanceClicked()
{
    if (!m_model) return;
    const std::string sid = selectedSwapId();
    if (sid.empty()) return;

    // Capture a copy of the selected swap.
    interfaces::Wallet::PricoinAdaptorSwapSnapshot snap{};
    bool found = false;
    for (const auto& s : m_swaps) {
        if (s.swap_id == sid) { snap = s; found = true; break; }
    }
    if (!found) return;

    QDialog dlg(this);
    auto* form = new QFormLayout(&dlg);

    // Each branch: build state-specific form, exec, then call wallet.
    // ─── Setup → AdaptorReady (combined) ───
    if (snap.state == "setup") {
        dlg.setWindowTitle(tr("Set adaptor materials + refund timelocks"));
        form->addRow(new QLabel(tr("Both adaptor materials and refund timelocks "
                                    "must be set to advance to AdaptorReady."), &dlg));
        auto* T_G = AddTextRow(form, tr("T_G (33-byte compressed hex):"), &dlg);
        auto* dleq = AddBlobRow(form, tr("DLEQ proof blob (hex):"), &dlg, 80);
        auto* t_secret_label = new QLabel(snap.role == "bob"
            ? tr("(Bob — required)") : tr("(Alice — leave empty)"), &dlg);
        auto* t_secret = new QLineEdit(&dlg);
        t_secret->setPlaceholderText(tr("32-byte hex if Bob, empty if Alice"));
        form->addRow(tr("t_secret:"), t_secret);
        form->addRow(QString(), t_secret_label);

        // Refund timelocks (suggested defaults: arbitrary high values).
        auto* p_h = AddIntRow(form, tr("PRIC refund height:"),
                               &dlg, 1, 2'000'000'000, 100'000);
        auto* f_h = AddIntRow(form, tr("Foreign refund height:"),
                               &dlg, 1, 2'000'000'000, 100'200);
        auto* d_m = AddIntRow(form, tr("Delta min (foreign blocks):"),
                               &dlg, 1, 2'000'000'000, 144);
        AddOkCancel(form, &dlg);

        if (dlg.exec() != QDialog::Accepted) return;
        auto r1 = m_model->wallet().adaptorSwapSetAdaptorMaterials(
            sid, T_G->text().trimmed().toStdString(),
            dleq->toPlainText().trimmed().toStdString(),
            t_secret->text().trimmed().toStdString());
        if (!r1) {
            setStatus(tr("Set adaptor failed: %1")
                .arg(QString::fromStdString(util::ErrorString(r1).original)), true);
            return;
        }
        auto r2 = m_model->wallet().adaptorSwapSetRefundTimelocks(
            sid, p_h->value(), f_h->value(), d_m->value());
        if (!r2) {
            setStatus(tr("Set timelocks failed: %1")
                .arg(QString::fromStdString(util::ErrorString(r2).original)), true);
            return;
        }
        refreshTable();
        setStatus(tr("Advanced to AdaptorReady."));
        return;
    }

    // ─── AdaptorReady → BtcFunded ───
    if (snap.state == "adaptor_ready") {
        dlg.setWindowTitle(tr("Set BTC funded"));
        auto* txid = AddTextRow(form, tr("Foreign funding txid:"), &dlg);
        auto* vout = AddIntRow(form, tr("Foreign funding vout:"), &dlg, 0, 65535, 0);
        auto* h    = AddIntRow(form, tr("Foreign funding height:"), &dlg, 1, 2'000'000'000, 1);
        AddOkCancel(form, &dlg);
        if (dlg.exec() != QDialog::Accepted) return;
        auto r = m_model->wallet().adaptorSwapSetBtcFunded(
            sid, txid->text().trimmed().toStdString(), vout->value(), h->value());
        if (!r) { setStatus(tr("Failed: %1")
            .arg(QString::fromStdString(util::ErrorString(r).original)), true); return; }
        refreshTable();
        setStatus(tr("Advanced to BtcFunded."));
        return;
    }

    // ─── BtcFunded → BothFunded ───
    if (snap.state == "btc_funded") {
        dlg.setWindowTitle(tr("Set PRIC funded"));
        auto* txid = AddTextRow(form, tr("PRIC funding txid (32-byte hex):"), &dlg);
        auto* vout = AddIntRow(form, tr("PRIC funding vout:"), &dlg, 0, 65535, 0);
        auto* h    = AddIntRow(form, tr("PRIC funding height:"), &dlg, 1, 2'000'000'000, 1);
        AddOkCancel(form, &dlg);
        if (dlg.exec() != QDialog::Accepted) return;
        auto r = m_model->wallet().adaptorSwapSetPricFunded(
            sid, txid->text().trimmed().toStdString(), vout->value(), h->value());
        if (!r) { setStatus(tr("Failed: %1")
            .arg(QString::fromStdString(util::ErrorString(r).original)), true); return; }
        refreshTable();
        setStatus(tr("Advanced to BothFunded."));
        return;
    }

    // ─── BothFunded → PreSigned ───
    if (snap.state == "both_funded") {
        dlg.setWindowTitle(tr("Set pre-signatures"));
        form->addRow(new QLabel(tr("Paste the 4 cooperative pre-signatures "
                                    "(spec §6.2 step 5+6+7) as hex blobs."), &dlg));
        auto* btc_p   = AddBlobRow(form, tr("BTC claim pre-sig (64 bytes hex):"), &dlg, 50);
        auto* btc_s   = AddBlobRow(form, tr("BTC claim session (133 bytes hex):"), &dlg, 60);
        auto* btc_par = AddIntRow (form, tr("BTC claim nonce parity (0/1):"), &dlg, 0, 1, 0);
        auto* pric_p  = AddBlobRow(form, tr("PRIC claim pre-sig blob (hex):"), &dlg, 80);
        auto* btc_r   = AddBlobRow(form, tr("BTC refund sig (64 bytes hex):"), &dlg, 50);
        auto* pric_r  = AddBlobRow(form, tr("PRIC refund sig blob (hex):"), &dlg, 80);
        AddOkCancel(form, &dlg);
        if (dlg.exec() != QDialog::Accepted) return;
        interfaces::Wallet::PricoinAdaptorSwapPreSigsHex ps;
        ps.btc_claim_presig_hex       = btc_p->toPlainText().trimmed().toStdString();
        ps.btc_claim_session_hex      = btc_s->toPlainText().trimmed().toStdString();
        ps.btc_claim_nonce_parity     = btc_par->value();
        ps.pric_claim_presig_blob_hex = pric_p->toPlainText().trimmed().toStdString();
        ps.btc_refund_sig_hex         = btc_r->toPlainText().trimmed().toStdString();
        ps.pric_refund_sig_blob_hex   = pric_r->toPlainText().trimmed().toStdString();
        auto r = m_model->wallet().adaptorSwapSetPreSigned(sid, ps);
        if (!r) { setStatus(tr("Failed: %1")
            .arg(QString::fromStdString(util::ErrorString(r).original)), true); return; }
        refreshTable();
        setStatus(tr("Advanced to PreSigned."));
        return;
    }

    // ─── PreSigned → PricClaimed ───
    if (snap.state == "pre_signed") {
        dlg.setWindowTitle(tr("Set PRIC claimed"));
        form->addRow(new QLabel(tr("Bob's PRIC claim tx is on-chain — t is now "
                                    "extractable. Record the claim txid."), &dlg));
        auto* txid = AddTextRow(form, tr("PRIC claim txid:"), &dlg);
        AddOkCancel(form, &dlg);
        if (dlg.exec() != QDialog::Accepted) return;
        auto r = m_model->wallet().adaptorSwapSetPricClaimed(
            sid, txid->text().trimmed().toStdString());
        if (!r) { setStatus(tr("Failed: %1")
            .arg(QString::fromStdString(util::ErrorString(r).original)), true); return; }
        refreshTable();
        setStatus(tr("Advanced to PricClaimed."));
        return;
    }

    // ─── PricClaimed → Complete ───
    if (snap.state == "pric_claimed") {
        dlg.setWindowTitle(tr("Set complete"));
        form->addRow(new QLabel(tr("Alice's foreign claim tx confirmed; swap done."), &dlg));
        auto* txid = AddTextRow(form, tr("Foreign claim txid:"), &dlg);
        AddOkCancel(form, &dlg);
        if (dlg.exec() != QDialog::Accepted) return;
        auto r = m_model->wallet().adaptorSwapSetComplete(
            sid, txid->text().trimmed().toStdString());
        if (!r) { setStatus(tr("Failed: %1")
            .arg(QString::fromStdString(util::ErrorString(r).original)), true); return; }
        refreshTable();
        setStatus(tr("Swap complete."));
        return;
    }

    setStatus(tr("No advance available from state %1.")
        .arg(QString::fromStdString(snap.state)), true);
}

void PricoinSwapsPage::onRefundClicked()
{
    if (!m_model) return;
    const std::string sid = selectedSwapId();
    if (sid.empty()) return;

    QDialog dlg(this);
    dlg.setWindowTitle(tr("Set refunded"));
    auto* form = new QFormLayout(&dlg);
    form->addRow(new QLabel(tr("Pass the txid of whichever leg refunded; "
                                "leave the other empty."), &dlg));
    auto* pric  = AddTextRow(form, tr("PRIC refund txid (32-byte hex, optional):"), &dlg);
    auto* foreign = AddTextRow(form, tr("Foreign refund txid (optional):"), &dlg);
    AddOkCancel(form, &dlg);
    if (dlg.exec() != QDialog::Accepted) return;
    auto r = m_model->wallet().adaptorSwapSetRefunded(
        sid, pric->text().trimmed().toStdString(),
        foreign->text().trimmed().toStdString());
    if (!r) {
        setStatus(tr("Refund failed: %1")
            .arg(QString::fromStdString(util::ErrorString(r).original)), true);
        return;
    }
    refreshTable();
    setStatus(tr("Swap moved to Refunded."));
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
