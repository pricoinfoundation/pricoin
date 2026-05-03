// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pricoin_swaps_page.h>

#include <interfaces/node.h>
#include <qt/pricoin_coopsign_dialog.h>
#include <qt/pricoin_pric_coopsign_dialog.h>
#include <qt/walletmodel.h>
#include <random.h>
#include <support/cleanse.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <QBrush>
#include <QColor>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFont>
#include <QFormLayout>
#include <QGroupBox>
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
#include <QUrl>
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

    // ─── Tier-3 swap-watcher panel ───
    auto* sw_box = new QGroupBox(tr("Swap watcher (auto-advance from chain events)"), this);
    sw_box->setStyleSheet(QStringLiteral("QGroupBox { font-weight: bold; }"));
    auto* sw_outer = new QVBoxLayout(sw_box);

    auto* sw_top = new QHBoxLayout();
    m_btn_sw_start   = new QPushButton(tr("Start watcher"),   sw_box);
    m_btn_sw_stop    = new QPushButton(tr("Stop watcher"),    sw_box);
    m_btn_sw_tick    = new QPushButton(tr("Tick once"),       sw_box);
    m_btn_sw_refresh = new QPushButton(tr("Refresh entries"), sw_box);
    sw_top->addWidget(m_btn_sw_start);
    sw_top->addWidget(m_btn_sw_stop);
    sw_top->addWidget(m_btn_sw_tick);
    sw_top->addWidget(m_btn_sw_refresh);
    sw_top->addStretch();
    m_sw_status_label = new QLabel(tr("Watcher: unknown"), sw_box);
    m_sw_status_label->setWordWrap(true);
    sw_top->addWidget(m_sw_status_label, /*stretch=*/1);
    sw_outer->addLayout(sw_top);

    m_sw_table_model = new QStandardItemModel(sw_box);
    m_sw_table_model->setHorizontalHeaderLabels({
        tr("Swap id"), tr("Kind"), tr("Txid"),
        tr("Vout"), tr("Min conf")
    });
    m_sw_table = new QTableView(sw_box);
    m_sw_table->setModel(m_sw_table_model);
    m_sw_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_sw_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_sw_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_sw_table->verticalHeader()->setVisible(false);
    m_sw_table->horizontalHeader()->setStretchLastSection(true);
    m_sw_table->setMaximumHeight(140);
    sw_outer->addWidget(m_sw_table);

    auto* sw_bot = new QHBoxLayout();
    m_btn_sw_add    = new QPushButton(tr("Add watch…"),    sw_box);
    m_btn_sw_remove = new QPushButton(tr("Remove watch"),  sw_box);
    m_btn_adapt_btc_claim = new QPushButton(
        tr("Adapt + broadcast BTC claim…"), sw_box);
    m_btn_adapt_pric_claim = new QPushButton(
        tr("Adapt + broadcast PRIC claim… (Bob)"), sw_box);
    sw_bot->addWidget(m_btn_sw_add);
    sw_bot->addWidget(m_btn_sw_remove);
    sw_bot->addWidget(m_btn_adapt_btc_claim);
    sw_bot->addWidget(m_btn_adapt_pric_claim);
    sw_bot->addStretch();
    sw_outer->addLayout(sw_bot);
    outer->addWidget(sw_box);

    connect(m_btn_refresh, &QPushButton::clicked, this, &PricoinSwapsPage::onRefreshClicked);
    connect(m_btn_advance, &QPushButton::clicked, this, &PricoinSwapsPage::onAdvanceClicked);
    connect(m_btn_refund,  &QPushButton::clicked, this, &PricoinSwapsPage::onRefundClicked);
    connect(m_btn_abort,   &QPushButton::clicked, this, &PricoinSwapsPage::onAbortClicked);
    connect(m_btn_sw_start,   &QPushButton::clicked, this, &PricoinSwapsPage::onSwapwatchStartClicked);
    connect(m_btn_sw_stop,    &QPushButton::clicked, this, &PricoinSwapsPage::onSwapwatchStopClicked);
    connect(m_btn_sw_tick,    &QPushButton::clicked, this, &PricoinSwapsPage::onSwapwatchTickClicked);
    connect(m_btn_sw_refresh, &QPushButton::clicked, this, &PricoinSwapsPage::onSwapwatchRefresh);
    connect(m_btn_sw_add,     &QPushButton::clicked, this, &PricoinSwapsPage::onSwapwatchAddClicked);
    connect(m_btn_sw_remove,  &QPushButton::clicked, this, &PricoinSwapsPage::onSwapwatchRemoveClicked);
    connect(m_btn_adapt_btc_claim, &QPushButton::clicked, this, &PricoinSwapsPage::onAdaptBtcClaimClicked);
    connect(m_btn_adapt_pric_claim, &QPushButton::clicked, this, &PricoinSwapsPage::onAdaptPricClaimClicked);

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
    onSwapwatchRefresh();
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
    if (!m_model) return;
    refreshTable();
    onSwapwatchRefresh();
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
        auto* T_H = AddTextRow(form, tr("T_H (33-byte compressed hex):"), &dlg);
        auto* dleq = AddBlobRow(form, tr("DLEQ proof blob (hex):"), &dlg, 80);
        auto* t_secret_label = new QLabel(snap.role == "bob"
            ? tr("(Bob — required)") : tr("(Alice — leave empty)"), &dlg);
        auto* t_secret = new QLineEdit(&dlg);
        t_secret->setPlaceholderText(tr("32-byte hex if Bob, empty if Alice"));
        form->addRow(tr("t_secret:"), t_secret);
        form->addRow(QString(), t_secret_label);

        // Bob-only auto-derive helper: generates a fresh ephemeral
        // r + a fresh t, computes P_pi from the snapshot's joint
        // stealth address, then T_G + T_H + DLEQ proof in one shot.
        // The chosen ephemeral pubkey R = r·G is surfaced so the
        // user can wire it into the eventual walletsendct funding
        // call (toy scope — the funding RPC currently doesn't accept
        // a pinned ephemeral; if it picks a different one, the
        // on-chain P_pi will diverge from the adaptor's binding and
        // the swap will fail at sig time. Track in the swap notes.)
        // Hidden for Alice (she receives these from Bob — paste).
        QLineEdit* eph_edit = nullptr;
        QLineEdit* p_pi_edit = nullptr;
        if (snap.role == "bob") {
            // The ephemeral PRIV r is surfaced (not the pub R) —
            // the user needs r to reuse the same ephemeral when
            // funding via walletsendct so the on-chain P_pi
            // matches the adaptor binding. Keep this row safe by
            // making it read-only after generation.
            eph_edit = AddTextRow(form,
                tr("Ephemeral priv r (record for funding):"), &dlg);
            eph_edit->setReadOnly(true);
            eph_edit->setEchoMode(QLineEdit::Password);
            p_pi_edit = AddTextRow(form,
                tr("Computed P_pi (read-only):"), &dlg);
            p_pi_edit->setReadOnly(true);
            auto* derive_btn = new QPushButton(
                tr("Generate r + t → derive P_pi / T_G / T_H / DLEQ"), &dlg);
            form->addRow(QString(), derive_btn);
            QObject::connect(derive_btn, &QPushButton::clicked, &dlg,
                [this, &dlg, T_G, T_H, dleq, t_secret, eph_edit, p_pi_edit, sid, snap]() {
                const std::string joint_addr = snap.pric_joint_stealth_address;
                if (joint_addr.empty()) {
                    QMessageBox::warning(&dlg, tr("Auto-derive"),
                        tr("Swap record has no joint stealth address."));
                    return;
                }
                // Fresh ephemeral priv r — 32 random bytes.
                unsigned char r_raw[32];
                unsigned char t_raw[32];
                GetStrongRandBytes(r_raw);
                GetStrongRandBytes(t_raw);
                const std::string r_hex = HexStr(std::span<const unsigned char>{r_raw, 32});
                const std::string t_hex = HexStr(std::span<const unsigned char>{t_raw, 32});
                memory_cleanse(r_raw, 32);
                memory_cleanse(t_raw, 32);

                // Compute P_pi from the joint stealth address +
                // ephemeral. R = r·G is surfaced separately below
                // for the user to wire into the funding step.
                auto p_pi_or = m_model->wallet().computeStealthOneTimePubkey(
                    joint_addr, r_hex, /*output_index=*/0);
                if (!p_pi_or) {
                    QMessageBox::warning(&dlg, tr("Auto-derive"),
                        tr("computeStealthOneTimePubkey failed: %1")
                            .arg(QString::fromStdString(util::ErrorString(p_pi_or).original)));
                    return;
                }
                const std::string p_pi_hex = *p_pi_or;
                p_pi_edit->setText(QString::fromStdString(p_pi_hex));

                // pricoin_adaptor_compute_points(t, P_pi) for T_G/T_H.
                UniValue p1{UniValue::VARR};
                p1.push_back(t_hex);
                p1.push_back(p_pi_hex);
                UniValue r1;
                try {
                    r1 = m_model->node().executeRpc(
                        "pricoin_adaptor_compute_points", p1, "");
                } catch (const UniValue& e) {
                    QMessageBox::warning(&dlg, tr("Auto-derive"),
                        tr("compute_points failed: %1")
                            .arg(QString::fromStdString(e.write())));
                    return;
                }
                const std::string T_G_hex = r1["T_G"].get_str();
                const std::string T_H_hex = r1["T_H"].get_str();

                // pricoin_adaptor_dleq_prove(t, P_pi, T_G, T_H, label, payload).
                // Use the swap_id as both binding label + payload.
                UniValue p2{UniValue::VARR};
                p2.push_back(t_hex);
                p2.push_back(p_pi_hex);
                p2.push_back(T_G_hex);
                p2.push_back(T_H_hex);
                p2.push_back(sid);
                p2.push_back(sid);
                UniValue r2;
                try {
                    r2 = m_model->node().executeRpc(
                        "pricoin_adaptor_dleq_prove", p2, "");
                } catch (const UniValue& e) {
                    QMessageBox::warning(&dlg, tr("Auto-derive"),
                        tr("dleq_prove failed: %1")
                            .arg(QString::fromStdString(e.write())));
                    return;
                }
                const std::string dleq_hex = r2["dleq"].get_str();

                T_G->setText(QString::fromStdString(T_G_hex));
                T_H->setText(QString::fromStdString(T_H_hex));
                dleq->setPlainText(QString::fromStdString(dleq_hex));
                t_secret->setText(QString::fromStdString(t_hex));
                // Surface r in the ephemeral row (password-masked)
                // so the user can copy it for the funding step.
                // walletsendct currently picks its own ephemeral —
                // pinning is TODO; for now the user must verify the
                // on-chain P_pi after funding matches this one or
                // re-run the adaptor setup with the funding's
                // chosen ephemeral.
                eph_edit->setText(QString::fromStdString(r_hex));
            });
        }

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
            T_H->text().trimmed().toStdString(),
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
        // Launcher for the BTC claim adaptor cooperative-signing
        // dialog. On dialog close with a final sig, the three BTC-
        // claim form fields auto-fill — saves the user from manually
        // copy-pasting blob/session/parity back into this form.
        auto* btc_claim_helper = new QPushButton(tr("Sign BTC claim adaptor… (cooperative)"), &dlg);
        QObject::connect(btc_claim_helper, &QPushButton::clicked, &dlg,
            [this, &dlg, sid, btc_p, btc_s, btc_par]() {
            CoopSignDialog d(m_model, CoopSignDialog::Mode::BtcAdaptor,
                             tr("BTC claim adaptor pre-sig"), sid, &dlg);
            d.exec();
            if (!d.finalSigHex().isEmpty()) {
                btc_p->setPlainText(d.finalSigHex());
                if (!d.sessionDataHex().isEmpty()) {
                    btc_s->setPlainText(d.sessionDataHex());
                }
                btc_par->setValue(d.nonceParity());
            }
        });
        form->addRow(QString(), btc_claim_helper);
        auto* pric_p  = AddBlobRow(form, tr("PRIC claim pre-sig blob (hex):"), &dlg, 80);
        // Launcher for the PRIC claim adaptor-CLSAG cooperative dialog.
        auto* pric_claim_helper = new QPushButton(tr("Sign PRIC claim adaptor… (cooperative)"), &dlg);
        QObject::connect(pric_claim_helper, &QPushButton::clicked, &dlg,
            [this, &dlg, sid, pric_p]() {
            PricCoopSignDialog d(m_model, PricCoopSignDialog::Mode::PricAdaptor,
                                 tr("PRIC claim adaptor pre-sig"), sid, &dlg);
            d.exec();
            if (!d.finalBlobHex().isEmpty()) {
                pric_p->setPlainText(d.finalBlobHex());
            }
        });
        form->addRow(QString(), pric_claim_helper);
        auto* btc_r   = AddBlobRow(form, tr("BTC refund sig (64 bytes hex):"), &dlg, 50);
        // Launcher for the BTC refund cooperative-signing dialog
        // (plain MuSig2, no adaptor).
        auto* btc_refund_helper = new QPushButton(tr("Sign BTC refund sig… (cooperative)"), &dlg);
        QObject::connect(btc_refund_helper, &QPushButton::clicked, &dlg,
            [this, &dlg, sid, btc_r]() {
            CoopSignDialog d(m_model, CoopSignDialog::Mode::BtcPlain,
                             tr("BTC refund cooperative sig"), sid, &dlg);
            d.exec();
            if (!d.finalSigHex().isEmpty()) {
                btc_r->setPlainText(d.finalSigHex());
            }
        });
        form->addRow(QString(), btc_refund_helper);
        auto* pric_r  = AddBlobRow(form, tr("PRIC refund sig blob (hex):"), &dlg, 80);
        // Launcher for the PRIC refund cooperative-CLSAG dialog
        // (multi-layer plain — no adaptor).
        auto* pric_refund_helper = new QPushButton(tr("Sign PRIC refund sig… (cooperative)"), &dlg);
        QObject::connect(pric_refund_helper, &QPushButton::clicked, &dlg,
            [this, &dlg, sid, pric_r]() {
            PricCoopSignDialog d(m_model, PricCoopSignDialog::Mode::PricPlain,
                                 tr("PRIC refund cooperative sig"), sid, &dlg);
            d.exec();
            if (!d.finalBlobHex().isEmpty()) {
                pric_r->setPlainText(d.finalBlobHex());
            }
        });
        form->addRow(QString(), pric_refund_helper);
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

// ─── Tier-3 swap-watcher panel ──────────────────────────────────

namespace {

// Local helper: dispatch a wallet-RPC by name via node().executeRpc.
// Returns std::nullopt on RPC error (with msg in *err).
std::optional<UniValue> CallWalletRpc(WalletModel* wm,
                                       const std::string& method,
                                       const UniValue& params,
                                       std::string* err)
{
    if (!wm) { if (err) *err = "wallet not attached"; return std::nullopt; }
    const QString wallet_name = wm->getWalletName();
    std::string uri;
    if (!wallet_name.isEmpty()) {
        QByteArray enc = QUrl::toPercentEncoding(wallet_name);
        uri = "/wallet/" + std::string(enc.constData(), enc.length());
    }
    try {
        return wm->node().executeRpc(method, params, uri);
    } catch (const UniValue& e) {
        if (err) {
            if (e.isObject() && e.exists("message")) *err = e["message"].get_str();
            else                                     *err = e.write();
        }
    } catch (const std::exception& e) {
        if (err) *err = e.what();
    } catch (...) {
        if (err) *err = "unknown RPC error";
    }
    return std::nullopt;
}

} // namespace

void PricoinSwapsPage::onSwapwatchRefresh()
{
    if (!m_model) return;
    std::string err;
    auto status = CallWalletRpc(m_model, "pricoin_swapwatch_status", UniValue{UniValue::VARR}, &err);
    auto entries = CallWalletRpc(m_model, "pricoin_swapwatch_list",   UniValue{UniValue::VARR}, &err);
    if (!status || !entries) {
        setStatus(tr("Swapwatch refresh failed: %1").arg(QString::fromStdString(err)), true);
        return;
    }
    const bool running = (*status)["running"].get_bool();
    const int  pending = (*status)["pending_entries"].getInt<int>();
    m_sw_status_label->setText(tr("Watcher: %1 — %2 pending entries")
        .arg(running ? tr("running") : tr("stopped"))
        .arg(pending));
    m_sw_status_label->setStyleSheet(running
        ? QStringLiteral("QLabel { color: #1b5e20; }")
        : QStringLiteral("QLabel { color: #b71c1c; }"));

    const auto& arr = *entries;
    m_sw_table_model->setRowCount(static_cast<int>(arr.size()));
    for (size_t i = 0; i < arr.size(); ++i) {
        const auto& e = arr[i];
        const QString swap_id = QString::fromStdString(e["swap_id"].get_str());
        auto* item0 = new QStandardItem(swap_id.left(12) + "…");
        item0->setData(swap_id,                        Qt::UserRole + 1);
        item0->setData(QString::fromStdString(e["kind"].get_str()), Qt::UserRole + 2);
        m_sw_table_model->setItem(static_cast<int>(i), 0, item0);
        m_sw_table_model->setItem(static_cast<int>(i), 1,
            new QStandardItem(QString::fromStdString(e["kind"].get_str())));
        const QString txid = QString::fromStdString(e["txid"].get_str());
        m_sw_table_model->setItem(static_cast<int>(i), 2,
            new QStandardItem(txid.left(16) + "…"));
        const QString vout_s = e.exists("vout")
            ? QString::number(e["vout"].getInt<int>())
            : QStringLiteral("-");
        m_sw_table_model->setItem(static_cast<int>(i), 3,
            new QStandardItem(vout_s));
        m_sw_table_model->setItem(static_cast<int>(i), 4,
            new QStandardItem(QString::number(e["min_confirmations"].getInt<int>())));
    }
    m_sw_table->resizeColumnsToContents();
}

void PricoinSwapsPage::onSwapwatchStartClicked()
{
    if (!m_model) return;
    UniValue params{UniValue::VARR};
    params.push_back(30);  // 30s default poll interval
    std::string err;
    if (auto r = CallWalletRpc(m_model, "pricoin_swapwatch_start", params, &err)) {
        setStatus(tr("Watcher started."));
    } else {
        setStatus(tr("Start failed: %1").arg(QString::fromStdString(err)), true);
    }
    onSwapwatchRefresh();
}

void PricoinSwapsPage::onSwapwatchStopClicked()
{
    if (!m_model) return;
    std::string err;
    if (auto r = CallWalletRpc(m_model, "pricoin_swapwatch_stop", UniValue{UniValue::VARR}, &err)) {
        setStatus(tr("Watcher stopped."));
    } else {
        setStatus(tr("Stop failed: %1").arg(QString::fromStdString(err)), true);
    }
    onSwapwatchRefresh();
}

void PricoinSwapsPage::onSwapwatchTickClicked()
{
    if (!m_model) return;
    std::string err;
    if (auto r = CallWalletRpc(m_model, "pricoin_swapwatch_tick_once", UniValue{UniValue::VARR}, &err)) {
        const int after = (*r)["pending_after"].getInt<int>();
        setStatus(tr("Tick OK — %1 pending entries remaining.").arg(after));
    } else {
        setStatus(tr("Tick failed: %1").arg(QString::fromStdString(err)), true);
    }
    refreshTable();
    onSwapwatchRefresh();
}

void PricoinSwapsPage::onSwapwatchAddClicked()
{
    if (!m_model) return;
    const std::string sel_sid = selectedSwapId();

    // Modal form: swap_id (default = selected), kind, txid, vout, min_conf.
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Add swap-watch entry"));
    auto* form = new QFormLayout(&dlg);
    auto* sid_edit = new QLineEdit(QString::fromStdString(sel_sid), &dlg);
    sid_edit->setPlaceholderText(tr("32-byte swap_id hex"));
    form->addRow(tr("Swap id:"), sid_edit);
    auto* kind = new QComboBox(&dlg);
    kind->addItems({QStringLiteral("foreign_funding"), QStringLiteral("pric_funding"),
                    QStringLiteral("pric_claim"),     QStringLiteral("foreign_claim"),
                    QStringLiteral("pric_refund"),    QStringLiteral("foreign_refund")});
    form->addRow(tr("Kind:"), kind);
    auto* txid_edit = new QLineEdit(&dlg);
    txid_edit->setPlaceholderText(tr("32-byte tx id hex"));
    form->addRow(tr("Txid:"), txid_edit);
    auto* vout = new QSpinBox(&dlg);
    vout->setRange(-1, 65535);
    vout->setValue(0);
    form->addRow(tr("Vout (-1 if not funding):"), vout);
    auto* min_conf = new QSpinBox(&dlg);
    min_conf->setRange(0, 1'000'000);
    min_conf->setValue(1);
    form->addRow(tr("Min confirmations:"), min_conf);
    auto* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    QObject::connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    QObject::connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    form->addRow(bb);
    if (dlg.exec() != QDialog::Accepted) return;

    UniValue params{UniValue::VARR};
    params.push_back(sid_edit->text().trimmed().toStdString());
    params.push_back(kind->currentText().toStdString());
    params.push_back(txid_edit->text().trimmed().toStdString());
    params.push_back(vout->value());
    params.push_back(min_conf->value());
    std::string err;
    if (CallWalletRpc(m_model, "pricoin_swapwatch_add", params, &err)) {
        setStatus(tr("Watch entry added."));
    } else {
        setStatus(tr("Add failed: %1").arg(QString::fromStdString(err)), true);
    }
    onSwapwatchRefresh();
}

std::string PricoinSwapsPage::selectedSwapwatchSwapId() const
{
    if (!m_sw_table) return {};
    auto* sm = m_sw_table->selectionModel();
    if (!sm) return {};
    const auto sel = sm->selectedRows();
    if (sel.isEmpty()) return {};
    auto* item = m_sw_table_model->item(sel.first().row(), 0);
    if (!item) return {};
    return item->data(Qt::UserRole + 1).toString().toStdString();
}

std::string PricoinSwapsPage::selectedSwapwatchKind() const
{
    if (!m_sw_table) return {};
    auto* sm = m_sw_table->selectionModel();
    if (!sm) return {};
    const auto sel = sm->selectedRows();
    if (sel.isEmpty()) return {};
    auto* item = m_sw_table_model->item(sel.first().row(), 0);
    if (!item) return {};
    return item->data(Qt::UserRole + 2).toString().toStdString();
}

void PricoinSwapsPage::onAdaptBtcClaimClicked()
{
    if (!m_model) return;
    const std::string sid = selectedSwapId();
    if (sid.empty()) {
        setStatus(tr("Select a swap row first."), true);
        return;
    }
    bool ok = false;
    const QString t_hex = QInputDialog::getText(
        this, tr("Adapt + broadcast BTC claim"),
        tr("32-byte adaptor secret t (hex). Extract via "
            "pricoin_jointspend_adaptor_extract from the counterparty's "
            "on-chain PRIC claim tx, or paste your own t_secret if you "
            "are the t holder."),
        QLineEdit::Password, QString(), &ok);
    if (!ok || t_hex.size() != 64) {
        if (ok) setStatus(tr("t must be 32-byte hex (64 chars)."), true);
        return;
    }
    UniValue p{UniValue::VARR};
    p.push_back(sid);
    p.push_back(t_hex.toStdString());
    p.push_back(0);  // refund_amount_sat — let the RPC default to (funding - 1000)
    p.push_back(1);  // min_confirmations
    std::string err;
    auto r = CallWalletRpc(m_model, "pricoin_swapwatch_adapt_btc_claim", p, &err);
    if (!r) {
        setStatus(tr("Adapt+broadcast failed: %1").arg(QString::fromStdString(err)), true);
        return;
    }
    const QString txid = QString::fromStdString((*r)["txid"].get_str());
    setStatus(tr("BTC claim broadcast — txid %1… (watching for confirmations).")
        .arg(txid.left(16)));
    refreshTable();
    onSwapwatchRefresh();
}

void PricoinSwapsPage::onAdaptPricClaimClicked()
{
    if (!m_model) return;
    const std::string sid = selectedSwapId();
    if (sid.empty()) {
        setStatus(tr("Select a swap row first."), true);
        return;
    }
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Adapt + broadcast PRIC claim (Bob)"));
    auto* form = new QFormLayout(&dlg);
    form->addRow(new QLabel(tr("Bob-only: uses the wallet's stored t_secret to "
        "adapt the PRIC adaptor pre-sig and broadcast the claim. The 3 inputs "
        "below come from Bob's cooperative-sign dialog session — paste tx_hex "
        "(buildtx output), the single-layer ring of joint pubkeys, and the "
        "32-byte sighash."), &dlg));
    auto* tx_hex = new QPlainTextEdit(&dlg);
    tx_hex->setPlaceholderText(tr("Skeleton tx hex from pricoin_jointspend_buildtx"));
    tx_hex->setMaximumHeight(80);
    form->addRow(tr("tx_hex:"), tx_hex);
    auto* ring = new QPlainTextEdit(&dlg);
    ring->setPlaceholderText(tr("JSON array of 33-byte compressed pubkey hex strings"));
    ring->setMaximumHeight(80);
    form->addRow(tr("ring (JSON):"), ring);
    auto* msg = new QLineEdit(&dlg);
    msg->setPlaceholderText(tr("32-byte sighash hex"));
    form->addRow(tr("msg (sighash):"), msg);
    auto* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    QObject::connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    QObject::connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    form->addRow(bb);
    if (dlg.exec() != QDialog::Accepted) return;

    UniValue ring_v;
    if (!ring_v.read(ring->toPlainText().toStdString()) || !ring_v.isArray()) {
        setStatus(tr("ring must be a JSON array of pubkey hex strings"), true);
        return;
    }
    UniValue p{UniValue::VARR};
    p.push_back(sid);
    p.push_back(tx_hex->toPlainText().trimmed().toStdString());
    p.push_back(ring_v);
    p.push_back(msg->text().trimmed().toStdString());
    p.push_back(1);  // min_confirmations
    std::string err;
    auto r = CallWalletRpc(m_model, "pricoin_swapwatch_adapt_pric_claim", p, &err);
    if (!r) {
        setStatus(tr("Adapt+broadcast PRIC failed: %1").arg(QString::fromStdString(err)), true);
        return;
    }
    const QString txid = QString::fromStdString((*r)["txid"].get_str());
    setStatus(tr("PRIC claim broadcast — txid %1… (watching for confirmations).")
        .arg(txid.left(16)));
    refreshTable();
    onSwapwatchRefresh();
}

void PricoinSwapsPage::onSwapwatchRemoveClicked()
{
    if (!m_model) return;
    const std::string sid = selectedSwapwatchSwapId();
    const std::string knd = selectedSwapwatchKind();
    if (sid.empty() || knd.empty()) {
        setStatus(tr("Select an entry in the swap-watch table first."), true);
        return;
    }
    UniValue params{UniValue::VARR};
    params.push_back(sid);
    params.push_back(knd);
    std::string err;
    if (auto r = CallWalletRpc(m_model, "pricoin_swapwatch_remove", params, &err)) {
        const bool removed = (*r)["removed"].get_bool();
        setStatus(removed ? tr("Watch entry removed.")
                          : tr("Watch entry was not present."));
    } else {
        setStatus(tr("Remove failed: %1").arg(QString::fromStdString(err)), true);
    }
    onSwapwatchRefresh();
}
