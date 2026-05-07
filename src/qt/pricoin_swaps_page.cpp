// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pricoin_swaps_page.h>

#include <interfaces/node.h>
#include <qt/pricoin_coopsign_dialog.h>
#include <qt/pricoin_nostr_client.h>
#include <qt/pricoin_pric_coopsign_dialog.h>
#include <qt/walletmodel.h>
#include <random.h>
#include <support/cleanse.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <QJsonDocument>
#include <QJsonObject>

#include <QBrush>
#include <QColor>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFont>
#include <QFontMetrics>
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

PricoinSwapsPage::~PricoinSwapsPage()
{
    // Stop the auto-refresh timer before destruction so a tick can't
    // fire after our slot's captured state (m_model, sub-widgets) has
    // been torn down. Without this, a 5s timer that fires while Qt is
    // mid-shutdown crashes the main thread on a dangling m_model —
    // which in turn aborts pricoind's shutoff sequence and leaves
    // leveldb writes mid-flight (= corrupted chain db on next launch).
    if (m_auto_refresh_timer) {
        m_auto_refresh_timer->stop();
        m_auto_refresh_timer->disconnect();
    }
}

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
        tr("Adapt + broadcast foreign claim… (PRIC seller)"), sw_box);
    m_btn_adapt_pric_claim = new QPushButton(
        tr("Adapt + broadcast PRIC claim… (PRIC buyer)"), sw_box);
    m_btn_ltc_refund = new QPushButton(
        tr("LTC refund… (PRIC buyer)"), sw_box);
    m_btn_extract_t = new QPushButton(
        tr("Extract t… (PRIC seller)"), sw_box);
    sw_bot->addWidget(m_btn_sw_add);
    sw_bot->addWidget(m_btn_sw_remove);
    sw_bot->addWidget(m_btn_adapt_btc_claim);
    sw_bot->addWidget(m_btn_adapt_pric_claim);
    sw_bot->addWidget(m_btn_ltc_refund);
    sw_bot->addWidget(m_btn_extract_t);
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
    connect(m_btn_ltc_refund, &QPushButton::clicked, this, &PricoinSwapsPage::onLtcRefundClicked);
    connect(m_btn_extract_t,  &QPushButton::clicked, this, &PricoinSwapsPage::onExtractTClicked);

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
    // Subscribe to the model's destruction so a teardown that happens
    // BEFORE this page is destroyed (e.g. wallet close while the page
    // is still parented somewhere) doesn't leave us with a dangling
    // m_model that the auto-refresh timer would dereference.
    if (m_model) {
        connect(m_model, &QObject::destroyed, this, [this]() {
            m_model = nullptr;
            if (m_auto_refresh_timer) m_auto_refresh_timer->stop();
        });
    } else {
        // Explicit setModel(nullptr) — stop the timer; nothing to
        // refresh against.
        if (m_auto_refresh_timer) m_auto_refresh_timer->stop();
    }
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
        // Show full pubkey + joint stealth address — operators verify
        // these visually against the counterparty (DM exchange, etc.)
        // and truncating with "…" defeats that. The table is set up
        // with horizontal scroll so wide rows are usable.
        m_table_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(QString::fromStdString(s.counterparty_pubkey_hex)));
        m_table_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(QString::fromStdString(s.foreign_chain)));
        m_table_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(QString::number(s.foreign_amount_sat)));
        m_table_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(FormatSat(s.pric_amount_sat)));
        m_table_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(QString::fromStdString(s.pric_joint_stealth_address)));
        m_table_model->setItem(static_cast<int>(i), col++,
            new QStandardItem(QString::number(s.updated_time)));
    }
    m_table->resizeColumnsToContents();
    // Allow per-pixel horizontal scrolling for the wide address
    // columns; without this the table only scrolls one column at a
    // time and feels jittery.
    m_table->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
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
        // Hands-free path. Two strangers can't paste pubkeys to each
        // other, so the dialog-with-fields flow doesn't fit the
        // orderbook discovery model. Instead:
        //   * Alice (PRIC seller): waits. Her wallet's DM handler
        //     will auto-apply the materials when Bob's
        //     pricoin:adaptor_setup/v1 DM lands.
        //   * Bob (PRIC buyer): derives r/t/P_pi/T_G/T_H/DLEQ in-line
        //     using the same RPCs the old dialog's Generate button
        //     used, sets materials + default refund timelocks, then
        //     DM-notifies Alice. No dialog needed.
        // The fallback dialog further down stays as a safety net for
        // unusual inputs / future protocol variants.
        if (snap.role == "alice") {
            setStatus(tr("Waiting for PRIC buyer to commit adaptor materials. "
                          "Your wallet will auto-advance when their DM arrives."));
            return;
        }
        if (snap.role == "bob") {
            const std::string joint_addr = snap.pric_joint_stealth_address;
            if (joint_addr.empty()) {
                setStatus(tr("Cannot auto-advance: swap has no joint stealth address."), true);
                return;
            }
            // Fresh ephemeral r + fresh secret t.
            unsigned char r_raw[32]; unsigned char t_raw[32];
            GetStrongRandBytes(r_raw); GetStrongRandBytes(t_raw);
            const std::string r_hex = HexStr(std::span<const unsigned char>{r_raw, 32});
            const std::string t_hex = HexStr(std::span<const unsigned char>{t_raw, 32});
            memory_cleanse(r_raw, 32); memory_cleanse(t_raw, 32);

            auto p_pi_or = m_model->wallet().computeStealthOneTimePubkey(
                joint_addr, r_hex, /*output_index=*/0);
            if (!p_pi_or) {
                setStatus(tr("Auto-advance failed (computeStealthOneTimePubkey): %1")
                    .arg(QString::fromStdString(util::ErrorString(p_pi_or).original)), true);
                return;
            }
            const std::string p_pi_hex = *p_pi_or;

            UniValue p1{UniValue::VARR};
            p1.push_back(t_hex);
            p1.push_back(p_pi_hex);
            UniValue r1; std::string T_G_hex, T_H_hex;
            try {
                r1 = m_model->node().executeRpc("pricoin_adaptor_compute_points", p1, "");
                T_G_hex = r1["T_G"].get_str();
                T_H_hex = r1["T_H"].get_str();
            } catch (const UniValue& e) {
                setStatus(tr("Auto-advance failed (compute_points): %1")
                    .arg(QString::fromStdString(e.write())), true);
                return;
            } catch (const std::exception& e) {
                setStatus(tr("Auto-advance failed (compute_points): %1").arg(e.what()), true);
                return;
            }

            UniValue p2{UniValue::VARR};
            p2.push_back(t_hex); p2.push_back(p_pi_hex);
            p2.push_back(T_G_hex); p2.push_back(T_H_hex);
            p2.push_back(sid); p2.push_back(sid);
            UniValue r2; std::string dleq_hex;
            try {
                r2 = m_model->node().executeRpc("pricoin_adaptor_dleq_prove", p2, "");
                dleq_hex = r2["dleq"].get_str();
            } catch (const UniValue& e) {
                setStatus(tr("Auto-advance failed (dleq_prove): %1")
                    .arg(QString::fromStdString(e.write())), true);
                return;
            } catch (const std::exception& e) {
                setStatus(tr("Auto-advance failed (dleq_prove): %1").arg(e.what()), true);
                return;
            }

            // Apply locally: set materials (with t_secret) + refund timelocks (defaults).
            const auto sm = m_model->wallet().adaptorSwapSetAdaptorMaterials(
                sid, T_G_hex, T_H_hex, dleq_hex, t_hex);
            if (!sm) {
                setStatus(tr("Set adaptor failed: %1")
                    .arg(QString::fromStdString(util::ErrorString(sm).original)), true);
                return;
            }
            // Default refund timelocks — suggested values that match the
            // legacy dialog's defaults. Future revision: derive from
            // chain heights + spec-mandated minimums.
            constexpr int kDefaultPricRefundHeight    = 100000;
            constexpr int kDefaultForeignRefundHeight = 100200;
            constexpr int kDefaultDeltaMin            = 144;
            const auto rt = m_model->wallet().adaptorSwapSetRefundTimelocks(
                sid, kDefaultPricRefundHeight, kDefaultForeignRefundHeight,
                kDefaultDeltaMin);
            if (!rt) {
                setStatus(tr("Set timelocks failed: %1")
                    .arg(QString::fromStdString(util::ErrorString(rt).original)), true);
                return;
            }
            refreshTable();

            // Push the materials to Alice via DM so her side auto-advances too.
            QJsonObject m;
            m.insert(QStringLiteral("type"),
                QStringLiteral("pricoin:adaptor_setup/v1"));
            m.insert(QStringLiteral("T_G"),  QString::fromStdString(T_G_hex));
            m.insert(QStringLiteral("T_H"),  QString::fromStdString(T_H_hex));
            m.insert(QStringLiteral("dleq"), QString::fromStdString(dleq_hex));
            m.insert(QStringLiteral("pric_refund_height"),    kDefaultPricRefundHeight);
            m.insert(QStringLiteral("foreign_refund_height"), kDefaultForeignRefundHeight);
            m.insert(QStringLiteral("delta_min"),             kDefaultDeltaMin);
            const bool dm_sent = sendSwapCoordDM(sid, m);
            setStatus(dm_sent
                ? tr("Advanced to AdaptorReady. Counterparty notified.")
                : tr("Advanced to AdaptorReady. (counterparty notification failed — they may need to retry)"));
            return;
        }

        // Fallback: unknown role — show the legacy dialog as a safety net.
        dlg.setWindowTitle(tr("Set adaptor materials + refund timelocks"));
        form->addRow(new QLabel(tr("Both adaptor materials and refund timelocks "
                                    "must be set to advance to AdaptorReady."), &dlg));
        auto* T_G = AddTextRow(form, tr("T_G (33-byte compressed hex):"), &dlg);
        auto* T_H = AddTextRow(form, tr("T_H (33-byte compressed hex):"), &dlg);
        auto* dleq = AddBlobRow(form, tr("DLEQ proof blob (hex):"), &dlg, 80);
        auto* t_secret_label = new QLabel(snap.role == "bob"
            ? tr("(PRIC buyer — required)")
            : tr("(PRIC seller — leave empty)"), &dlg);
        auto* t_secret = new QLineEdit(&dlg);
        t_secret->setPlaceholderText(tr("32-byte hex (PRIC buyer), empty (PRIC seller)"));
        form->addRow(tr("t_secret:"), t_secret);
        form->addRow(QString(), t_secret_label);

        // Bob-only auto-derive helper: generates a fresh ephemeral
        // r + a fresh t, computes P_pi from the snapshot's joint
        // stealth address, then T_G + T_H + DLEQ proof in one shot.
        // The chosen ephemeral pubkey R = r·G is surfaced so the
        // user can wire it into the eventual walletsendct funding
        // call (experimental scope — the funding RPC currently doesn't accept
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
        const std::string T_G_str = T_G->text().trimmed().toStdString();
        const std::string T_H_str = T_H->text().trimmed().toStdString();
        const std::string dleq_str = dleq->toPlainText().trimmed().toStdString();
        auto r1 = m_model->wallet().adaptorSwapSetAdaptorMaterials(
            sid, T_G_str, T_H_str, dleq_str,
            t_secret->text().trimmed().toStdString());
        if (!r1) {
            setStatus(tr("Set adaptor failed: %1")
                .arg(QString::fromStdString(util::ErrorString(r1).original)), true);
            return;
        }
        const int p_h_v = p_h->value();
        const int f_h_v = f_h->value();
        const int d_m_v = d_m->value();
        auto r2 = m_model->wallet().adaptorSwapSetRefundTimelocks(
            sid, p_h_v, f_h_v, d_m_v);
        if (!r2) {
            setStatus(tr("Set timelocks failed: %1")
                .arg(QString::fromStdString(util::ErrorString(r2).original)), true);
            return;
        }
        refreshTable();

        // Auto-coordination: PRIC buyer (Bob) pushes the adaptor
        // materials + refund timelocks to PRIC seller (Alice) so her
        // wallet auto-advances to AdaptorReady without manual paste.
        // t_secret is intentionally NOT shipped — Alice extracts it
        // from Bob's PRIC claim tx later.
        bool dm_sent = false;
        if (snap.role == "bob") {
            QJsonObject m;
            m.insert(QStringLiteral("type"),
                QStringLiteral("pricoin:adaptor_setup/v1"));
            m.insert(QStringLiteral("T_G"),  QString::fromStdString(T_G_str));
            m.insert(QStringLiteral("T_H"),  QString::fromStdString(T_H_str));
            m.insert(QStringLiteral("dleq"), QString::fromStdString(dleq_str));
            m.insert(QStringLiteral("pric_refund_height"),    p_h_v);
            m.insert(QStringLiteral("foreign_refund_height"), f_h_v);
            m.insert(QStringLiteral("delta_min"),             d_m_v);
            dm_sent = sendSwapCoordDM(sid, m);
        }
        setStatus(snap.role == "bob"
            ? (dm_sent
                ? tr("Advanced to AdaptorReady. Counterparty notified.")
                : tr("Advanced to AdaptorReady. (counterparty notification failed — they may need to paste manually)"))
            : tr("Advanced to AdaptorReady."));
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
        const bool is_ltc = (snap.foreign_chain == "ltc");
        dlg.setWindowTitle(tr("Set pre-signatures"));
        form->addRow(new QLabel(is_ltc
            ? tr("LTC swap: only PRIC pre-signatures are required. The LTC HTLC "
                 "is unilaterally claimable (PRIC seller with t) and refundable "
                 "(PRIC buyer after timelock) — no cooperative MuSig2 step.")
            : tr("Paste the 4 cooperative pre-signatures "
                 "(spec §6.2 step 5+6+7) as hex blobs."),
            &dlg));
        QPlainTextEdit* btc_p   = nullptr;
        QPlainTextEdit* btc_s   = nullptr;
        QSpinBox*       btc_par = nullptr;
        if (!is_ltc) {
            btc_p   = AddBlobRow(form, tr("BTC claim pre-sig (64 bytes hex):"), &dlg, 50);
            btc_s   = AddBlobRow(form, tr("BTC claim session (133 bytes hex):"), &dlg, 60);
            btc_par = AddIntRow (form, tr("BTC claim nonce parity (0/1):"), &dlg, 0, 1, 0);
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
        }
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
        QPlainTextEdit* btc_r = nullptr;
        if (!is_ltc) {
            btc_r = AddBlobRow(form, tr("BTC refund sig (64 bytes hex):"), &dlg, 50);
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
        }
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
        if (!is_ltc) {
            ps.btc_claim_presig_hex       = btc_p->toPlainText().trimmed().toStdString();
            ps.btc_claim_session_hex      = btc_s->toPlainText().trimmed().toStdString();
            ps.btc_claim_nonce_parity     = btc_par->value();
            ps.btc_refund_sig_hex         = btc_r->toPlainText().trimmed().toStdString();
        }
        ps.pric_claim_presig_blob_hex = pric_p->toPlainText().trimmed().toStdString();
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
        form->addRow(new QLabel(tr("PRIC buyer's claim tx is on-chain — t is now "
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
        form->addRow(new QLabel(tr("PRIC seller's foreign claim tx confirmed; swap done."), &dlg));
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

bool PricoinSwapsPage::sendSwapCoordDM(const std::string& swap_id,
                                         const QJsonObject& msg)
{
    if (!m_model) return false;
    auto snap = m_model->wallet().adaptorSwapGet(swap_id);
    if (!snap) return false;
    // counterparty_pubkey_hex is 33-byte compressed (66 hex chars).
    // NIP-04 expects 32-byte xonly (64 hex chars) — strip the parity.
    if (snap->counterparty_pubkey_hex.size() < 66) return false;
    const QString peer_xonly = QString::fromStdString(
        snap->counterparty_pubkey_hex.substr(2));
    auto* nostr = m_model->getOrCreateNostrClient();
    if (!nostr) return false;
    QJsonObject m = msg;
    if (!m.contains(QStringLiteral("swap_id"))) {
        m.insert(QStringLiteral("swap_id"), QString::fromStdString(swap_id));
    }
    const QString plaintext = QString::fromUtf8(
        QJsonDocument(m).toJson(QJsonDocument::Compact));
    return nostr->publishDirectMessage(peer_xonly, plaintext);
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
    // Notify the counterparty so their wallet mirrors the abort. This
    // completes the "two strangers, no other channel" story for the
    // swap state machine — same pattern as match/unmatch DMs in the
    // orderbook.
    QJsonObject msg;
    msg.insert(QStringLiteral("type"),    QStringLiteral("pricoin:swap_abort/v1"));
    msg.insert(QStringLiteral("swap_id"), QString::fromStdString(sid));
    msg.insert(QStringLiteral("reason"),  reason);
    const bool sent = sendSwapCoordDM(sid, msg);
    setStatus(sent
        ? tr("Swap aborted. Counterparty notified.")
        : tr("Swap aborted. (counterparty notification failed — they may need to abort manually)"));
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
    // Chain dispatch: BTC uses MuSig2 + Schnorr-adapted P2TR claim;
    // LTC uses the discrete-log-bound HTLC claim (sig under T_G +
    // sig under Alice's swap-identity priv). The user-visible
    // difference is that LTC also asks for a destination address.
    std::string chain;
    bool has_t_snap = false;
    std::string t_snap_hex;
    for (const auto& s : m_swaps) {
        if (s.swap_id == sid) {
            chain = s.foreign_chain;
            has_t_snap = s.has_t;
            t_snap_hex = s.t_secret_hex;
            break;
        }
    }
    if (chain.empty()) {
        setStatus(tr("Selected swap not found."), true);
        return;
    }

    if (chain == "ltc") {
        QDialog dlg(this);
        dlg.setWindowTitle(tr("Broadcast LTC HTLC claim (PRIC seller)"));
        auto* form = new QFormLayout(&dlg);
        form->addRow(new QLabel(has_t_snap
            ? tr("PRIC-seller LTC claim path. t is auto-filled from the swap "
                 "record (extracted earlier from the PRIC buyer's on-chain "
                 "PRIC claim). Specify a destination address for the LTC.")
            : tr("PRIC-seller LTC claim path. The 32-byte t scalar comes from "
                 "extracting it on-chain after the PRIC buyer's PRIC claim "
                 "confirms — use the \"Extract t…\" button on the swap row, "
                 "or run pricoin_swapwatch_extract_pric_t. The dest address "
                 "is where the LTC will be paid."),
            &dlg));
        auto* t_in    = new QLineEdit(&dlg);
        t_in->setEchoMode(QLineEdit::Password);
        t_in->setPlaceholderText(tr("64-char hex"));
        if (has_t_snap) {
            t_in->setText(QString::fromStdString(t_snap_hex));
        }
        form->addRow(tr("t (hex):"), t_in);
        auto* dest_in = new QLineEdit(&dlg);
        dest_in->setPlaceholderText(tr("ltc1q… bech32 address"));
        {
            QFontMetrics fm(dest_in->font());
            dest_in->setMinimumWidth(fm.horizontalAdvance(QLatin1Char('M')) * 70);
        }
        form->addRow(tr("Destination LTC address:"), dest_in);
        auto* fee_in  = new QLineEdit(&dlg);
        fee_in->setText(QStringLiteral("1000"));
        form->addRow(tr("Fee (sats):"), fee_in);
        auto* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
        QObject::connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
        QObject::connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
        form->addRow(bb);
        if (dlg.exec() != QDialog::Accepted) return;

        const QString t_hex = t_in->text().trimmed();
        const QString dest  = dest_in->text().trimmed();
        bool fee_ok = false;
        const int64_t fee_sat = fee_in->text().toLongLong(&fee_ok);
        if (t_hex.size() != 64) {
            setStatus(tr("t must be 32-byte hex (64 chars)."), true);
            return;
        }
        if (dest.isEmpty()) {
            setStatus(tr("Destination address required."), true);
            return;
        }
        if (!fee_ok || fee_sat < 0) {
            setStatus(tr("Fee must be non-negative integer sats."), true);
            return;
        }
        UniValue p{UniValue::VARR};
        p.push_back(sid);
        p.push_back(t_hex.toStdString());
        p.push_back(dest.toStdString());
        p.push_back(fee_sat);
        std::string err;
        auto r = CallWalletRpc(m_model, "pricoin_ltc_claim_swap", p, &err);
        if (!r) {
            setStatus(tr("LTC claim failed: %1").arg(QString::fromStdString(err)), true);
            return;
        }
        const QString txid = QString::fromStdString((*r)["txid"].get_str());
        setStatus(tr("LTC claim broadcast — txid %1… (watching for confirmations).")
            .arg(txid.left(16)));
        refreshTable();
        onSwapwatchRefresh();
        return;
    }

    // ─── BTC path (existing) ───
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

void PricoinSwapsPage::onExtractTClicked()
{
    if (!m_model) return;
    const std::string sid = selectedSwapId();
    if (sid.empty()) {
        setStatus(tr("Select a swap row first."), true);
        return;
    }
    bool already_has_t = false;
    std::string role;
    std::vector<std::string> persisted_ring;
    for (const auto& s : m_swaps) {
        if (s.swap_id == sid) {
            already_has_t = s.has_t;
            role = s.role;
            persisted_ring = s.pric_claim_ring_hex;
            break;
        }
    }
    if (role != "alice") {
        setStatus(tr("Extract is for the PRIC seller — the PRIC buyer already "
                      "holds t from setup."), true);
        return;
    }
    if (already_has_t) {
        setStatus(tr("This swap already has t stored — re-extract isn't needed."));
        return;
    }

    QDialog dlg(this);
    dlg.setWindowTitle(tr("Extract t from PRIC buyer's claim tx"));
    auto* form = new QFormLayout(&dlg);
    form->addRow(new QLabel(persisted_ring.empty()
        ? tr("Recovers the adaptor scalar t from the PRIC buyer's on-chain "
             "PRIC claim CLSAG signature. The ring + sig hex come from the "
             "buyer's Nostr DM (sent when they broadcast). On success t is "
             "persisted into the swap record so the LTC claim dialog "
             "auto-fills it.\n\n"
             "Note: under the watcher auto-extract path, this dialog is "
             "rarely needed — the wallet picks up the spend directly from "
             "chain. Use this only if the wallet was offline when the "
             "buyer's claim hit chain.")
        : tr("Recovers the adaptor scalar t from the PRIC buyer's on-chain "
             "PRIC claim CLSAG signature. The ring is auto-filled from the "
             "swap record — only paste the on-chain sig hex (the buyer "
             "sends it via Nostr DM).\n\n"
             "Note: under the watcher auto-extract path, this dialog is "
             "rarely needed — the wallet picks up the spend directly from "
             "chain. Use this only if the wallet was offline when the "
             "buyer's claim hit chain."),
        &dlg));
    auto* ring_in = new QPlainTextEdit(&dlg);
    ring_in->setPlaceholderText(tr("JSON array of 33-byte compressed pubkey hex strings"));
    ring_in->setMaximumHeight(80);
    if (!persisted_ring.empty()) {
        // Render as JSON array.
        QString json = QStringLiteral("[");
        for (size_t i = 0; i < persisted_ring.size(); ++i) {
            if (i) json += QStringLiteral(",");
            json += QStringLiteral("\"") + QString::fromStdString(persisted_ring[i]) + QStringLiteral("\"");
        }
        json += QStringLiteral("]");
        ring_in->setPlainText(json);
    }
    form->addRow(tr("ring (JSON):"), ring_in);
    auto* sig_in = new QPlainTextEdit(&dlg);
    sig_in->setPlaceholderText(tr("hex of pricoin::ringsig::Signature blob from the PRIC buyer's claim tx"));
    sig_in->setMaximumHeight(80);
    form->addRow(tr("sig (hex):"), sig_in);
    auto* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    QObject::connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    QObject::connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    form->addRow(bb);
    if (dlg.exec() != QDialog::Accepted) return;

    UniValue ring_v;
    if (!ring_v.read(ring_in->toPlainText().toStdString()) || !ring_v.isArray()) {
        setStatus(tr("ring must be a JSON array of pubkey hex strings"), true);
        return;
    }
    UniValue p{UniValue::VARR};
    p.push_back(sid);
    p.push_back(ring_v);
    p.push_back(sig_in->toPlainText().trimmed().toStdString());
    std::string err;
    auto r = CallWalletRpc(m_model, "pricoin_swapwatch_extract_pric_t", p, &err);
    if (!r) {
        setStatus(tr("Extract failed: %1").arg(QString::fromStdString(err)), true);
        return;
    }
    const QString t_hex = QString::fromStdString((*r)["t"].get_str());
    const bool persisted = (*r)["persisted_to_swap_record"].get_bool();
    setStatus(persisted
        ? tr("Extracted t and saved into swap record — open LTC claim to broadcast.")
        : tr("Extracted t (%1) but couldn't persist; copy it manually for the claim.")
            .arg(t_hex.left(12)));
    refreshTable();
}

void PricoinSwapsPage::onLtcRefundClicked()
{
    if (!m_model) return;
    const std::string sid = selectedSwapId();
    if (sid.empty()) {
        setStatus(tr("Select a swap row first."), true);
        return;
    }
    std::string chain;
    std::string role;
    for (const auto& s : m_swaps) {
        if (s.swap_id == sid) {
            chain = s.foreign_chain;
            role  = s.role;
            break;
        }
    }
    if (chain != "ltc") {
        setStatus(tr("LTC refund only applies to LTC swaps."), true);
        return;
    }
    if (role != "bob") {
        setStatus(tr("LTC HTLC refund is performed by the PRIC buyer (LTC seller)."), true);
        return;
    }

    QDialog dlg(this);
    dlg.setWindowTitle(tr("Broadcast LTC HTLC refund (PRIC buyer)"));
    auto* form = new QFormLayout(&dlg);
    form->addRow(new QLabel(tr("Spends the LTC HTLC refund branch. Only valid after "
                                "the foreign refund timelock expires; the network "
                                "rejects earlier broadcasts."), &dlg));
    auto* dest_in = new QLineEdit(&dlg);
    dest_in->setPlaceholderText(tr("ltc1q… bech32 address (where the PRIC buyer receives the refunded LTC)"));
    {
        QFontMetrics fm(dest_in->font());
        dest_in->setMinimumWidth(fm.horizontalAdvance(QLatin1Char('M')) * 70);
    }
    form->addRow(tr("Destination LTC address:"), dest_in);
    auto* fee_in = new QLineEdit(&dlg);
    fee_in->setText(QStringLiteral("1000"));
    form->addRow(tr("Fee (sats):"), fee_in);
    auto* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    QObject::connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    QObject::connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    form->addRow(bb);
    if (dlg.exec() != QDialog::Accepted) return;

    const QString dest = dest_in->text().trimmed();
    bool fee_ok = false;
    const int64_t fee_sat = fee_in->text().toLongLong(&fee_ok);
    if (dest.isEmpty()) {
        setStatus(tr("Destination address required."), true);
        return;
    }
    if (!fee_ok || fee_sat < 0) {
        setStatus(tr("Fee must be non-negative integer sats."), true);
        return;
    }
    UniValue p{UniValue::VARR};
    p.push_back(sid);
    p.push_back(dest.toStdString());
    p.push_back(fee_sat);
    std::string err;
    auto r = CallWalletRpc(m_model, "pricoin_ltc_refund_swap", p, &err);
    if (!r) {
        setStatus(tr("LTC refund failed: %1").arg(QString::fromStdString(err)), true);
        return;
    }
    const QString txid = QString::fromStdString((*r)["txid"].get_str());
    setStatus(tr("LTC refund broadcast — txid %1… (watching for confirmations).")
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
    dlg.setWindowTitle(tr("Adapt + broadcast PRIC claim (PRIC buyer)"));
    auto* form = new QFormLayout(&dlg);
    form->addRow(new QLabel(tr("PRIC buyer only: uses the wallet's stored "
        "t_secret to adapt the PRIC adaptor pre-sig and broadcast the claim. "
        "The 3 inputs below come from the cooperative-sign dialog session — "
        "paste tx_hex (buildtx output), the single-layer ring of joint "
        "pubkeys, and the 32-byte sighash."), &dlg));
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
