// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pricoin_swaps_page.h>

#include <common/args.h>
#include <core_io.h>
#include <interfaces/node.h>
#include <qt/pricoin_coopsign_dialog.h>
#include <qt/pricoin_nostr_client.h>
#include <qt/pricoin_pric_coopsign_dialog.h>
#include <qt/walletmodel.h>
#include <random.h>
#include <support/cleanse.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <cmath>

#include <QEventLoop>
#include <QJsonDocument>
#include <QJsonObject>

#include <QBrush>
#include <QCheckBox>
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

// Per-tx vbyte estimates for foreign-chain transactions in the swap
// flow. Approximate; the exact byte count depends on segwit
// witness sizes and BIP341 control-block lengths, but these are
// within ~10% which is fine for fee estimation.
constexpr int kVbForeignFunding   = 155;  // 1-in / 2-out P2TR or P2WPKH
constexpr int kVbForeignClaim     = 155;  // 1-in P2TR/P2WPKH + 1-out (claim path)
constexpr int kVbForeignRefund    = 155;  // similar shape (refund path)

// Estimate a foreign-chain fee in sats. Calls the chain backend's
// fee-estimator (Esplora), picks a 6-block-target rate, multiplies
// by the supplied vbyte estimate. Falls back to a high hardcode if
// the backend is unreachable — overpaying by a small amount is
// better than producing a tx no miner will include during a fee
// spike. Used by every swap-page broadcast site so users don't see
// a 1000-sat hardcode silently produce stuck txs.
int64_t EstimateForeignFeeSat(::interfaces::Node& node,
                               const std::string& chain,
                               int est_vb,
                               int64_t fallback_sat = 10000)
{
    UniValue pe{UniValue::VARR};
    pe.push_back(chain);
    try {
        UniValue est = node.executeRpc(
            "pricoin_chainwatch_fee_estimates", pe, "");
        double sat_per_vb = -1.0;
        if (est.isObject()) {
            for (int t : {6, 10, 3, 20, 144, 2, 1}) {
                const auto v = est[strprintf("%d", t)];
                if (v.isNum() && v.get_real() > 0) {
                    sat_per_vb = v.get_real();
                    break;
                }
            }
        }
        if (sat_per_vb > 0.0) {
            return static_cast<int64_t>(
                std::ceil(static_cast<double>(est_vb) * sat_per_vb));
        }
    } catch (...) {
        // Backend unreachable — fall through to fallback.
    }
    return fallback_sat;
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
    m_filter_hide_terminal = new QCheckBox(
        tr("Hide complete / aborted / refunded"), this);
    m_filter_hide_terminal->setChecked(true);  // default hide noise
    top->addWidget(m_filter_hide_terminal);
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
    connect(m_filter_hide_terminal, &QCheckBox::toggled, this,
            [this](bool){ refreshTable(); });
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

    // Detect state transitions and auto-fire the next-step UI so the
    // user doesn't have to keep clicking "Advance state". Per the
    // 2026-05-13 UX direction (memory: swap_ux_target.md), after a
    // swap is matched and Start Trade is clicked, every state
    // transition should drive itself forward; the user only sees
    // progress, not buttons. Specifically: on BothFunded, we want
    // the "Set pre-signatures" flow to open on BOTH sides so the
    // cooperative ceremony fires without manual coordination.
    std::vector<std::string> auto_advance_sids;
    for (const auto& s : m_swaps) {
        auto it = m_last_seen_state.find(s.swap_id);
        const std::string prev = (it == m_last_seen_state.end()) ? "" : it->second;
        m_last_seen_state[s.swap_id] = s.state;
        // Re-entry guard: m_auto_advance_fired tracks "we already
        // fired auto-advance at LEAST ONCE for this swap during this
        // session". We need to allow a follow-up auto-advance after
        // state changes — e.g., setup → adaptor_ready (Bob's t/T_G
        // generation) and later both_funded → pre_signed (cooperative
        // ceremony). Track per-state instead.
        const std::string fire_key = s.swap_id + "@" + s.state;
        if (m_auto_advance_fired.contains(fire_key)) continue;

        bool should_fire = false;
        if (s.state == "setup" && s.role == "bob") {
            // Bob (PRIC buyer) is the only side that needs to act at
            // setup state: derive r/t/T_G/T_H/dleq_t, set adaptor
            // materials, DM Alice. Alice's onAdvanceClicked at setup
            // just sets a "waiting" status, so firing it would be a
            // no-op. Fire only for Bob.
            should_fire = true;
        }
        // Post-2026-05-15 protocol order:
        //   adaptor_ready → PreSigned (cooperative ceremony, BEFORE funding)
        //   pre_signed    → BtcFunded   (Bob funds LTC, role-gated)
        //   btc_funded    → BothFunded  (Alice broadcasts pre-built, role-gated)
        //   both_funded   → PricClaimed (Bob auto-adapt+broadcast claim)
        //   pric_claimed  → Complete    (Alice auto-LTC-claim)
        if (s.state == "adaptor_ready") {
            // Cooperative-sign ceremony fires on BOTH roles. Alice's
            // path runs walletsendct_ring (broadcast=false) and DMs
            // Bob the hex; both then open the coopsign dialog. Bob
            // can ONLY fire once the hex DM has landed — otherwise
            // his onAdvanceClicked returns early ("waiting…") and the
            // fire_key would mark him as already-fired, blocking the
            // re-try when the DM eventually arrives. Gate his fire on
            // hex presence; the fire_key is only inserted when fired,
            // so subsequent ticks retry the check naturally.
            // No prev-state guard — we want every tick to re-evaluate
            // until the prerequisite (hex for Bob) becomes available.
            if (s.role == "alice"
                || !s.pric_funding_unsigned_tx_hex.empty()) {
                should_fire = true;
            }
        }
        if (s.state == "pre_signed" && s.role == "bob") {
            // Bob auto-funds the foreign chain (BTC/LTC) once presigs
            // are in hand. Alice's path at this state is "wait for
            // tx-announce DM", handled inline by the wallet-tier
            // chainwatch DM handler.
            should_fire = true;
        }
        if (s.state == "btc_funded" && s.role == "alice") {
            // Alice auto-broadcasts the pre-built PRIC funding tx via
            // pricoin_ct_relay_prebuilt. No I-ACCEPT typed gate — she
            // already holds Bob's cooperative refund presig.
            should_fire = true;
        }
        if (s.state == "both_funded" && s.role == "bob") {
            // Bob auto-adapts + broadcasts the PRIC claim using the
            // pre-signed claim adaptor sig. Bypasses onAdvanceClicked.
            // Retry-on-failure: if autoAdaptPricClaim returns false
            // (transient broadcast / RPC / chain-watcher condition),
            // erase the fire_key so the next refresh tick can retry.
            // Without this, a single failure permanently strands the
            // swap at BothFunded with no auto-recovery.
            QMetaObject::invokeMethod(this, [this, sid = s.swap_id, fire_key]() {
                if (!autoAdaptPricClaim(sid)) {
                    m_auto_advance_fired.erase(fire_key);
                }
            }, Qt::QueuedConnection);
            m_auto_advance_fired.insert(fire_key);
            continue;
        }
        // Sticky re-DM: tx_announce envelopes used to be sent once
        // (at the moment of broadcast) and lost if the peer's wallet
        // wasn't subscribed to a relay we hit. The receive-side
        // pricoin_swapwatch_add is idempotent (duplicate Add returns
        // ok), so blind retries are safe. Replay on every refresh
        // tick while the state implies the peer still needs the
        // announcement.
        auto resend_tx_announce = [&](const std::string& kind,
                                        const std::string& txid_hex,
                                        int32_t vout,
                                        int32_t min_conf) {
            if (s.counterparty_pubkey_hex.size() < 66) return;
            const QString peer_xonly = QString::fromStdString(
                s.counterparty_pubkey_hex.substr(2));
            auto* nostr = m_model->getOrCreateNostrClient();
            if (!nostr) return;
            nostr->publishBroadcastAnnouncement(
                peer_xonly,
                QString::fromStdString(s.swap_id),
                QString::fromStdString(kind),
                QString::fromStdString(txid_hex),
                vout, min_conf);
        };
        // Bob → Alice: foreign_funding announcement. Bob is BtcFunded
        // and Alice still needs to learn the LTC funding txid so her
        // watcher can advance her PreSigned → BtcFunded.
        if (s.role == "bob"
            && (s.state == "btc_funded" || s.state == "both_funded")
            && !s.foreign_funding_txid.empty()
            && s.foreign_funding_vout >= 0) {
            resend_tx_announce("foreign_funding", s.foreign_funding_txid,
                                s.foreign_funding_vout, /*min_conf=*/1);
        }
        // Alice → Bob: pric_funding announcement. Alice is past
        // BothFunded (her PRIC tx is broadcast) and Bob needs the
        // txid to advance his BtcFunded → BothFunded.
        if (s.role == "alice"
            && (s.state == "both_funded" || s.state == "pric_claimed")
            && !s.pric_funding_txid_hex.empty()
            && s.pric_funding_vout >= 0) {
            resend_tx_announce("pric_funding", s.pric_funding_txid_hex,
                                s.pric_funding_vout, /*min_conf=*/1);
        }
        if (s.state == "pric_claimed" && s.role == "alice"
            && s.foreign_chain == "ltc") {
            // Alice extracts t from Bob's on-chain PRIC claim (handled
            // by the wallet tx-scan path → SetTSecret → SetPricClaimed)
            // and now needs to spend the LTC HTLC. Headless if
            // -pricoinltcclaimaddr is configured; otherwise leaves
            // the manual button as the fallback.
            // Retry-on-failure (same pattern as both_funded → bob:
            // erase fire_key on false return so next refresh retries).
            QMetaObject::invokeMethod(this, [this, sid = s.swap_id, fire_key]() {
                if (!autoLtcClaim(sid)) {
                    m_auto_advance_fired.erase(fire_key);
                }
            }, Qt::QueuedConnection);
            m_auto_advance_fired.insert(fire_key);
            continue;
        }
        if (should_fire) {
            auto_advance_sids.push_back(s.swap_id);
            m_auto_advance_fired.insert(fire_key);
        }
    }
    // Defer the actual onAdvanceClicked invocation so we don't open a
    // modal dialog from inside refreshTable (which would recurse via
    // auto-refresh tick or block the table rebuild). Queued connection
    // = next event loop spin.
    for (const auto& sid : auto_advance_sids) {
        QMetaObject::invokeMethod(this, [this, sid]() {
            // Re-check the current state at fire time — user may have
            // already clicked through manually, or the swap may have
            // advanced on its own. The queued invocation must accept
            // every state we auto-advance from (setup, adaptor_ready,
            // both_funded). 2026-05-15: this used to hardcode
            // "both_funded" — leftover from when only the BothFunded
            // transition auto-fired. After setup + adaptor_ready
            // were added, the early-return kept blocking them.
            bool eligible = false;
            for (const auto& s : m_swaps) {
                if (s.swap_id != sid) continue;
                // Post-2026-05-15 ordering: the queued auto-advance
                // fires onAdvanceClicked for setup, adaptor_ready (the
                // coopsign ceremony), pre_signed (Bob funds LTC) and
                // btc_funded (Alice broadcasts pre-built PRIC). The
                // both_funded → pric_claimed path goes through the
                // direct autoAdaptPricClaim continue above.
                eligible = (s.state == "setup"
                            || s.state == "adaptor_ready"
                            || s.state == "pre_signed"
                            || s.state == "btc_funded");
                break;
            }
            if (!eligible) return;
            // Select the row so onAdvanceClicked picks it up via
            // selectedSwapId(). Falls back to a no-op if the row isn't
            // selectable (e.g. terminal-filter hides it).
            for (int row = 0; row < m_table_model->rowCount(); ++row) {
                auto* item = m_table_model->item(row, 0);
                if (!item) continue;
                bool ok = false;
                const auto src_idx = item->data(Qt::UserRole + 1)
                                         .toULongLong(&ok);
                if (!ok || src_idx >= m_swaps.size()) continue;
                if (m_swaps[src_idx].swap_id != sid) continue;
                m_table->selectRow(row);
                onAdvanceClicked();
                return;
            }
        }, Qt::QueuedConnection);
    }

    // Apply the "hide terminal" filter so the table doesn't bloat with
    // completed / aborted / refunded swaps once an operator has run a
    // few. m_swaps still holds the full list so the row-id↔snapshot
    // mapping stays correct for handlers that re-look up by sid.
    const bool hide_terminal = m_filter_hide_terminal &&
                               m_filter_hide_terminal->isChecked();
    auto is_terminal = [](const std::string& st) {
        return st == "complete" || st == "aborted" || st == "refunded";
    };
    std::vector<size_t> visible_idx;
    visible_idx.reserve(m_swaps.size());
    for (size_t i = 0; i < m_swaps.size(); ++i) {
        if (hide_terminal && is_terminal(m_swaps[i].state)) continue;
        visible_idx.push_back(i);
    }
    m_table_model->setRowCount(static_cast<int>(visible_idx.size()));
    for (size_t row = 0; row < visible_idx.size(); ++row) {
        const size_t i = visible_idx[row];
        const auto& s = m_swaps[i];
        int col = 0;
        m_table_model->setItem(static_cast<int>(row), col++,
            new QStandardItem(QString::fromStdString(s.swap_id).left(12) + "…"));
        m_table_model->setItem(static_cast<int>(row), col++,
            new QStandardItem(QString::fromStdString(s.role)));
        auto* state_item = new QStandardItem(StateBadge(s.state));
        state_item->setForeground(QBrush(StateColor(s.state)));
        QFont f = state_item->font();
        f.setBold(true);
        state_item->setFont(f);
        m_table_model->setItem(static_cast<int>(row), col++, state_item);
        // Stash the source-vector index in column 0 so the lookup
        // helpers (selectedSwapId etc.) can recover the snapshot
        // even when rows are filtered.
        if (auto* item = m_table_model->item(static_cast<int>(row), 0)) {
            item->setData(QVariant::fromValue<qulonglong>(static_cast<qulonglong>(i)),
                          Qt::UserRole + 1);
        }
        // Show full pubkey + joint stealth address — operators verify
        // these visually against the counterparty (DM exchange, etc.)
        // and truncating with "…" defeats that. The table is set up
        // with horizontal scroll so wide rows are usable.
        m_table_model->setItem(static_cast<int>(row), col++,
            new QStandardItem(QString::fromStdString(s.counterparty_pubkey_hex)));
        m_table_model->setItem(static_cast<int>(row), col++,
            new QStandardItem(QString::fromStdString(s.foreign_chain)));
        m_table_model->setItem(static_cast<int>(row), col++,
            new QStandardItem(QString::number(s.foreign_amount_sat)));
        m_table_model->setItem(static_cast<int>(row), col++,
            new QStandardItem(FormatSat(s.pric_amount_sat)));
        m_table_model->setItem(static_cast<int>(row), col++,
            new QStandardItem(QString::fromStdString(s.pric_joint_stealth_address)));
        m_table_model->setItem(static_cast<int>(row), col++,
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
    if (row < 0) return {};
    // The "Hide complete/aborted/refunded" filter omits rows from the
    // table without shrinking m_swaps, so the displayed row index
    // doesn't directly map to m_swaps. Use the source-index we stashed
    // in UserRole+1 of column 0 during refreshTable.
    if (auto* item = m_table_model->item(row, 0)) {
        const auto v = item->data(Qt::UserRole + 1);
        if (v.isValid()) {
            const auto src = static_cast<size_t>(v.toULongLong());
            if (src < m_swaps.size()) return m_swaps[src].swap_id;
        }
    }
    if (row < static_cast<int>(m_swaps.size())) return m_swaps[row].swap_id;
    return {};
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

            // Persist Bob's ephemeral r BEFORE adaptor materials so a
            // mid-step crash leaves the swap in a recoverable state
            // (r without materials is a noop; materials without r is
            // the bug we just fixed).
            const auto sr = m_model->wallet().adaptorSwapSetPricEphemeralR(sid, r_hex);
            if (!sr) {
                setStatus(tr("Persist ephemeral r failed: %1")
                    .arg(QString::fromStdString(util::ErrorString(sr).original)), true);
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
            // Refund timelocks — derived from CURRENT chain heights plus a
            // safety delta. Hardcoded absolute heights (the old default of
            // 100000/100200) are nonsensical on any real chain — the LTC
            // mainnet tip is in the millions, so 100200 puts the HTLC
            // refund path immediately spendable on confirmation, racing
            // with the claim path. Compute relative offsets:
            //   * foreign delta: 144 blocks. On LTC (2.5min) ≈ 6 hours;
            //     on BTC (10min) ≈ 24 hours. Plenty of time for a
            //     happy-path claim to fire before the refund window
            //     opens.
            //   * pric delta: foreign delta in seconds × pric_blocks_per_sec
            //     + delta_min_blocks (144) safety. Pricoin's 150s block
            //     time means foreign 144 LTC blocks = ~21,600s = 144 PRIC
            //     blocks; so we need pric refund to be later than that
            //     plus the delta-min safety gap. Settle on
            //     pric_delta = foreign_delta * (foreign_block_time / 150)
            //     + delta_min_blocks.
            const std::string& chain = snap.foreign_chain;
            constexpr int kDeltaMin            = 144;
            constexpr int kForeignDelta        = 144;
            // Foreign-chain block-time approximations (seconds).
            const int foreign_block_time = (chain == "btc") ? 600 : 150;  // ltc=150
            const int pric_delta = static_cast<int>(
                (static_cast<double>(kForeignDelta) * foreign_block_time) / 150.0)
                + kDeltaMin;

            int pric_tip = 0;
            if (auto h = m_model->node().getNumBlocks(); h > 0) pric_tip = static_cast<int>(h);
            int foreign_tip = 0;
            try {
                UniValue p_h{UniValue::VARR};
                p_h.push_back(chain);
                UniValue r_h = m_model->node().executeRpc(
                    "pricoin_chainwatch_height", p_h, "");
                if (r_h.isObject() && r_h.exists("height") && r_h["height"].isNum()) {
                    foreign_tip = r_h["height"].getInt<int>();
                }
            } catch (...) {
                // Backend unreachable — fall back to a conservative
                // far-future value so the HTLC refund path doesn't
                // open immediately.
                foreign_tip = 0;
            }
            if (foreign_tip <= 0 || pric_tip <= 0) {
                setStatus(tr("Cannot derive refund timelocks: foreign or PRIC "
                              "chain tip unavailable. Check %1 backend / wallet sync.")
                    .arg(QString::fromStdString(chain)), true);
                return;
            }
            const int pric_refund_h    = pric_tip    + pric_delta;
            const int foreign_refund_h = foreign_tip + kForeignDelta;
            const auto rt = m_model->wallet().adaptorSwapSetRefundTimelocks(
                sid, pric_refund_h, foreign_refund_h, kDeltaMin);
            if (!rt) {
                setStatus(tr("Set timelocks failed: %1")
                    .arg(QString::fromStdString(util::ErrorString(rt).original)), true);
                return;
            }
            refreshTable();

            // Push the materials + ephemeral r + the freshly-derived
            // refund heights to Alice via DM so her side auto-advances
            // and applies the SAME timelocks (otherwise the two sides'
            // refund txs would target different heights, breaking the
            // delta_min safety).
            QJsonObject m;
            m.insert(QStringLiteral("type"),
                QStringLiteral("pricoin:adaptor_setup/v1"));
            m.insert(QStringLiteral("T_G"),  QString::fromStdString(T_G_hex));
            m.insert(QStringLiteral("T_H"),  QString::fromStdString(T_H_hex));
            m.insert(QStringLiteral("dleq"), QString::fromStdString(dleq_hex));
            m.insert(QStringLiteral("r"),    QString::fromStdString(r_hex));
            m.insert(QStringLiteral("pric_refund_height"),    pric_refund_h);
            m.insert(QStringLiteral("foreign_refund_height"), foreign_refund_h);
            m.insert(QStringLiteral("delta_min"),             kDeltaMin);
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

    // ─── PreSigned → BtcFunded ───
    // Post-2026-05-15 protocol order: the cooperative refund + claim
    // presigs are exchanged BEFORE any on-chain funding, so PreSigned
    // precedes BtcFunded. Bob's LTC funding is the first locked-value
    // step; Bob's unilateral CLTV refund covers the trivial case
    // where Alice never broadcasts. Alice already has Bob's PRIC
    // refund presig in hand at this point — no I-ACCEPT gate later.
    if (snap.state == "pre_signed") {
        // Hands-free funding for the PRIC buyer (Bob): foreign-chain
        // 2-of-2 funding tx is built, signed, broadcast, and watch-
        // registered in one shot via pricoin_btc_fund_swap. Then we
        // DM Alice a tx_announce so her chain watcher tracks the
        // same txid. Alice doesn't fund foreign — she waits.
        //
        // The legacy paste dialog stays as a fallback when role isn't
        // recognised; that path is what was here before automation.
        if (snap.role == "alice") {
            setStatus(tr("Waiting for PRIC buyer to fund the foreign chain. "
                          "Your wallet will auto-advance when their tx-announce "
                          "DM arrives and the funding tx confirms."));
            return;
        }
        if (snap.role == "bob") {
            // Estimate the funding-tx fee from the chain backend's
            // sat/vB targets instead of the old 1000-sat hardcode.
            // Funding tx is 1-input (key-path P2TR) + 2-output P2TR
            // (the agg_xonly recipient + change to self) ≈ 155 vbytes.
            // Picks the 6-block target with sensible fallbacks. If
            // the backend is unreachable we fall back to a much higher
            // hardcode (10000 sats) than the old 1000 — better to
            // overpay slightly than to broadcast a tx that no miner
            // includes during congestion.
            const int64_t fund_fee_sat = EstimateForeignFeeSat(
                m_model->node(), snap.foreign_chain, kVbForeignFunding);
            UniValue p{UniValue::VARR};
            p.push_back(sid);
            p.push_back(fund_fee_sat);
            UniValue r;
            try {
                r = m_model->node().executeRpc("pricoin_btc_fund_swap", p,
                    "/wallet/" + m_model->getWalletName().toStdString());
            } catch (const UniValue& e) {
                setStatus(tr("BTC fund failed: %1").arg(
                    e.isObject() && e.exists("message")
                        ? QString::fromStdString(e["message"].get_str())
                        : QString::fromStdString(e.write())), true);
                return;
            } catch (const std::exception& e) {
                setStatus(tr("BTC fund failed: %1").arg(e.what()), true);
                return;
            }
            const std::string txid_hex = r["txid"].get_str();
            // The funding RPC just broadcast — local state is still
            // AdaptorReady until the chain watcher confirms. The
            // watcher entry was auto-registered by the RPC. We DM
            // Alice the txid so her watcher tracks it too.
            const std::string& cp = snap.counterparty_pubkey_hex;
            if (cp.size() >= 66) {
                const QString peer_xonly = QString::fromStdString(cp.substr(2));
                auto* nostr = m_model->getOrCreateNostrClient();
                if (nostr) {
                    nostr->publishBroadcastAnnouncement(
                        peer_xonly,
                        QString::fromStdString(sid),
                        QStringLiteral("foreign_funding"),
                        QString::fromStdString(txid_hex),
                        /*vout=*/0,
                        /*min_confirmations=*/1);
                }
            }
            setStatus(tr("BTC funding tx broadcast — txid %1. Your watcher "
                          "will mark BtcFunded once it confirms; counterparty "
                          "notified to track the same tx.")
                .arg(QString::fromStdString(txid_hex).left(16) + "…"));
            refreshTable();
            return;
        }

        // Fallback: unknown role → show the legacy paste dialog.
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
    // Post-2026-05-15 protocol order: Alice already holds Bob's PRIC
    // refund presig (gathered at AdaptorReady, before any funding).
    // The I-ACCEPT typed-confirmation gate is GONE — there is no
    // "strand-funds risk" to acknowledge, because Alice has a presigned
    // cooperative refund that she can broadcast unilaterally after the
    // PRIC refund timelock.
    // Alice's only action here is to release the pre-built funding tx
    // she signed at AdaptorReady. pricoin_ct_relay_prebuilt does the
    // network broadcast + persists the spent KI (skipped during
    // pre-build).
    if (snap.state == "btc_funded") {
        if (snap.role == "bob") {
            setStatus(tr("Waiting for PRIC seller to broadcast the pre-built "
                          "PRIC funding tx. Your wallet will auto-advance when "
                          "the tx-announce DM arrives and the funding confirms."));
            return;
        }
        if (snap.role == "alice") {
            if (snap.pric_funding_unsigned_tx_hex.empty()
                || snap.pric_funding_planned_vout < 0) {
                setStatus(tr("Cannot broadcast PRIC funding: pre-built tx hex "
                              "not on the swap record. Was the AdaptorReady "
                              "pre-build step skipped?"), true);
                return;
            }
            UniValue p_relay{UniValue::VARR};
            p_relay.push_back(snap.pric_funding_unsigned_tx_hex);
            UniValue r_relay;
            try {
                r_relay = m_model->node().executeRpc(
                    "pricoin_ct_relay_prebuilt", p_relay,
                    "/wallet/" + m_model->getWalletName().toStdString());
            } catch (const UniValue& e) {
                setStatus(tr("PRIC broadcast failed: %1").arg(
                    e.isObject() && e.exists("message")
                        ? QString::fromStdString(e["message"].get_str())
                        : QString::fromStdString(e.write())), true);
                return;
            } catch (const std::exception& e) {
                setStatus(tr("PRIC broadcast failed: %1").arg(e.what()), true);
                return;
            }
            const std::string txid_hex = r_relay["txid"].get_str();
            const int recipient_vout = snap.pric_funding_planned_vout;
            // Register the local pric_funding watch.
            try {
                UniValue p_watch{UniValue::VARR};
                p_watch.push_back(sid);
                p_watch.push_back("pric_funding");
                p_watch.push_back(txid_hex);
                p_watch.push_back(recipient_vout);
                p_watch.push_back(1);
                m_model->node().executeRpc("pricoin_swapwatch_add", p_watch,
                    "/wallet/" + m_model->getWalletName().toStdString());
            } catch (...) {
                setStatus(tr("PRIC fund broadcast but local watcher entry "
                              "could not be registered — state may need a "
                              "manual SetPricFunded after confirmation."), true);
            }
            // DM Bob the txid so his watcher tracks it.
            const std::string& cp = snap.counterparty_pubkey_hex;
            if (cp.size() >= 66) {
                const QString peer_xonly = QString::fromStdString(cp.substr(2));
                auto* nostr = m_model->getOrCreateNostrClient();
                if (nostr) {
                    nostr->publishBroadcastAnnouncement(
                        peer_xonly,
                        QString::fromStdString(sid),
                        QStringLiteral("pric_funding"),
                        QString::fromStdString(txid_hex),
                        recipient_vout,
                        /*min_confirmations=*/1);
                }
            }
            setStatus(tr("PRIC funding tx broadcast — txid %1. Your watcher "
                          "will mark BothFunded once it confirms; counterparty "
                          "notified to track the same tx.")
                .arg(QString::fromStdString(txid_hex).left(16) + "…"));
            refreshTable();
            return;
        }

        // Fallback: unknown role → legacy paste dialog.
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

    // ─── AdaptorReady → PreSigned ───
    // Post-2026-05-15 protocol order: cooperative presigs are gathered
    // BEFORE any on-chain funding. Alice's wallet first pre-builds
    // (but does NOT broadcast) her PRIC funding tx via
    // walletsendct_ring(broadcast=false), persists the hex + planned
    // vout via adaptorSwapSetPricFundingPlanned, and DMs the hex to
    // Bob (he needs it to compute his half of the cooperative scan
    // partials). Both wallets then run the cooperative-sign dialog
    // against the planned funding output. SetPreSigned advances state
    // when both presigs are in hand.
    if (snap.state == "adaptor_ready") {
        // Alice's pre-build step — only runs if not already done.
        if (snap.role == "alice"
            && snap.pric_funding_unsigned_tx_hex.empty()) {
            if (!snap.has_pric_ephemeral_r
                || snap.pric_ephemeral_r_hex.size() != 64) {
                setStatus(tr("Cannot pre-build PRIC funding: missing ephemeral r "
                             "from counterparty. Wait for the adaptor_setup DM."), true);
                return;
            }
            // Modest fixed fee — same as the post-funding path. Tx is
            // ~3.5 KB; 10000 sats ≈ 3 sat/B on the experimental chain.
            const CAmount fee_sats = 10000;
            UniValue p_send{UniValue::VARR};
            p_send.push_back(snap.pric_joint_stealth_address);
            p_send.push_back(ValueFromAmount(snap.pric_amount_sat));
            p_send.push_back(ValueFromAmount(fee_sats));
            p_send.push_back(/*ring_size=*/4);
            p_send.push_back(snap.pric_ephemeral_r_hex);
            p_send.push_back(false);  // broadcast=false: build + sign only
            UniValue r_send;
            try {
                r_send = m_model->node().executeRpc("walletsendct_ring", p_send,
                    "/wallet/" + m_model->getWalletName().toStdString());
            } catch (const UniValue& e) {
                setStatus(tr("PRIC pre-build failed: %1").arg(
                    e.isObject() && e.exists("message")
                        ? QString::fromStdString(e["message"].get_str())
                        : QString::fromStdString(e.write())), true);
                return;
            } catch (const std::exception& e) {
                setStatus(tr("PRIC pre-build failed: %1").arg(e.what()), true);
                return;
            }
            if (!r_send.exists("tx_hex") || !r_send["tx_hex"].isStr()) {
                setStatus(tr("PRIC pre-build returned no tx_hex"), true);
                return;
            }
            const std::string built_hex = r_send["tx_hex"].get_str();
            int recipient_vout = 0;
            if (r_send.exists("recipient_vout") && r_send["recipient_vout"].isNum()) {
                recipient_vout = r_send["recipient_vout"].getInt<int>();
                if (recipient_vout < 0) recipient_vout = 0;
            }
            auto sp = m_model->wallet().adaptorSwapSetPricFundingPlanned(
                sid, built_hex, recipient_vout);
            if (!sp) {
                setStatus(tr("Persist planned funding failed: %1")
                    .arg(QString::fromStdString(util::ErrorString(sp).original)), true);
                return;
            }
            // DM Bob the hex so his coopsign can compute scan partials.
            if (snap.counterparty_pubkey_hex.size() >= 66) {
                auto* nostr = m_model->getOrCreateNostrClient();
                if (nostr) {
                    nostr->publishPricFundingPlanned(
                        QString::fromStdString(snap.counterparty_pubkey_hex.substr(2)),
                        QString::fromStdString(sid),
                        QString::fromStdString(built_hex),
                        recipient_vout);
                }
            }
            // Refresh snapshot so the dialog sees the new fields.
            auto snap_after = m_model->wallet().adaptorSwapGet(sid);
            if (snap_after) snap = *snap_after;
        }
        // Bob waits until the DM lands and the swap record has the hex.
        if (snap.role == "bob"
            && snap.pric_funding_unsigned_tx_hex.empty()) {
            setStatus(tr("Waiting for PRIC seller's pre-built funding hex DM "
                         "(needed for cooperative-sign scan partials)."));
            return;
        }
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
            // Headless when auto-coord is driving. Use runHeadless()
            // instead of exec() — exec() forces WA_ShowModal which
            // would invisibly modal-block the whole app (close button
            // dead, no clicks possible). runHeadless() spins a local
            // event loop without modality so the main window keeps
            // processing input throughout the ceremony.
            d.setHeadlessMode(true);
            d.runHeadless();
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
            d.setHeadlessMode(true);
            d.runHeadless();
            if (!d.finalBlobHex().isEmpty()) {
                pric_r->setPlainText(d.finalBlobHex());
            }
        });
        form->addRow(QString(), pric_refund_helper);
        AddOkCancel(form, &dlg);

        // Auto-coord finale: chain the two cooperative-sign sub-
        // dialogs and the outer OK so the user doesn't have to
        // click anything between BothFunded and PreSigned. Each
        // sub-dialog auto-runs its own ceremony (Phase 1+2+3
        // landed in PricCoopSignDialog) and auto-accepts on Step
        // 4 success. Manual fallback: cancel any sub-dialog or
        // the outer dialog to fall back to paste mode. LTC variant
        // only — BTC variant (with MuSig2 BTC sigs) still goes
        // through the manual path until that dialog auto-coord
        // also lands.
        if (is_ltc) {
            // Headless: keep the outer "Set pre-signatures" dialog
            // off-screen too — combined with the inner dialogs being
            // headless, the entire ceremony runs invisibly. The user
            // only sees the row-level state on the Swaps page advance
            // through Cooperative-signing → PreSigned.
            //
            // CRITICAL: don't use QDialog::exec() — it unconditionally
            // sets Qt::WA_ShowModal which application-modals the
            // dialog. Combined with WA_DontShowOnScreen, that makes
            // the whole app appear frozen (close button dead, no
            // clicks). We spin a local QEventLoop manually below and
            // connect dlg.finished() → loop.quit() so blocking-the-
            // caller semantics are preserved without the modal flag.
            dlg.setAttribute(Qt::WA_DontShowOnScreen, true);
            dlg.setWindowModality(Qt::NonModal);
            dlg.setWindowFlag(Qt::Tool, true);
            dlg.setWindowFlag(Qt::FramelessWindowHint, true);
            QMetaObject::invokeMethod(&dlg, [pric_claim_helper, pric_p,
                                              pric_refund_helper, pric_r,
                                              &dlg]() {
                pric_claim_helper->click();
                if (pric_p->toPlainText().trimmed().isEmpty()) return;
                pric_refund_helper->click();
                if (pric_r->toPlainText().trimmed().isEmpty()) return;
                dlg.accept();
            }, Qt::QueuedConnection);

            // Manual non-modal "exec": show + spin until finished.
            QEventLoop loop;
            QObject::connect(&dlg, &QDialog::finished, &loop, &QEventLoop::quit);
            dlg.show();
            loop.exec();
            if (dlg.result() != QDialog::Accepted) return;
        } else {
            // BTC / non-auto-coord path — keep legacy modal dialog with
            // visible UI so the user can paste fields manually.
            if (dlg.exec() != QDialog::Accepted) return;
        }
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

    // ─── BothFunded → PricClaimed ───
    // Post-2026-05-15 protocol order: PRIC claim happens once BOTH
    // legs are funded. Bob's wallet auto-fires `autoAdaptPricClaim`
    // from refreshTable's auto-advance pass; this manual paste is a
    // fallback for advanced users.
    if (snap.state == "both_funded") {
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

    // Safety gate: if the swap is past funding and there's no refund
    // pre-signature in place, aborting STRANDS funds in the 2-of-2
    // multisig output. The button used to allow this silently — that's
    // exactly how 0.0002 BTC got locked the first time. Now we surface
    // the consequence in a dialog the user has to actively confirm,
    // and only allow proceed via typed confirmation.
    //
    // Funded states (per the current state machine ordering):
    //   * btc_funded  — Bob's BTC in 2-of-2, no refund presig yet.
    //   * both_funded — Alice's PRIC also locked, still no refund presig.
    //   * pre_signed  — both refund presigs exchanged → "Refund…" is
    //                   the right button, NOT Abort.
    // Pre-funding states (setup, adaptor_ready) are safe to abort.
    {
        const auto snap_opt = m_model->wallet().adaptorSwapGet(sid);
        if (snap_opt) {
            const std::string& st = snap_opt->state;
            const bool funded_no_recovery =
                (st == "btc_funded" || st == "both_funded");
            if (funded_no_recovery) {
                QString detail = tr(
                    "<b>Aborting at this state will permanently strand on-chain funds.</b><br><br>"
                    "This swap has reached <b>%1</b>. At this stage, neither side has "
                    "exchanged a refund pre-signature — the funding output is a 2-of-2 "
                    "multisig with no unilateral exit. Marking the swap aborted only "
                    "updates the local record; it does NOT broadcast a refund tx, "
                    "because no refund tx has been built.<br><br>"
                    "<b>What's actually locked:</b><br>"
                    "&nbsp;&nbsp;• Foreign-chain funding: %2 sats in the 2-of-2 output.<br>"
                    "&nbsp;&nbsp;• PRIC funding (if reached): %3 sats in the joint stealth.<br><br>"
                    "<b>Recovery options:</b><br>"
                    "&nbsp;&nbsp;• <b>Don't abort.</b> Continue the protocol forward to PreSigned, "
                    "then click <b>Refund…</b> — that path uses a properly signed refund tx.<br>"
                    "&nbsp;&nbsp;• If your counterparty has disappeared, the funds are unrecoverable "
                    "without a cooperative MuSig2 signing ceremony (not yet wired into the GUI).<br><br>"
                    "Proceeding with Abort means you are knowingly accepting that the funds "
                    "above will be stuck until either a recovery flow lands or the counterparty "
                    "agrees to cooperatively sign a recovery tx.<br><br>"
                    "Type <b>ABANDON FUNDS</b> below to confirm.")
                        .arg(QString::fromStdString(st))
                        .arg(QString::number(snap_opt->foreign_amount_sat))
                        .arg(QString::number(snap_opt->pric_amount_sat));
                bool ok_typed = false;
                const QString confirm = QInputDialog::getText(
                    this, tr("⚠ Abort would strand funds"),
                    detail, QLineEdit::Normal, QString(), &ok_typed);
                if (!ok_typed) return;
                if (confirm.trimmed() != QStringLiteral("ABANDON FUNDS")) {
                    setStatus(tr("Abort cancelled (confirmation phrase mismatch — funds remain safe in protocol)."));
                    return;
                }
            }
        }
    }

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
        fee_in->setText(QString::number(
            EstimateForeignFeeSat(m_model->node(), "ltc", kVbForeignRefund)));
        form->addRow(tr("Fee (sats — backend-estimated):"), fee_in);
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
        // DM the PRIC buyer so his wallet auto-advances pric_claimed
        // → complete on confirmation (same logic as autoLtcClaim).
        for (const auto& s2 : m_swaps) {
            if (s2.swap_id != sid) continue;
            if (s2.counterparty_pubkey_hex.size() < 66) break;
            const QString peer_xonly = QString::fromStdString(
                s2.counterparty_pubkey_hex.substr(2));
            auto* nostr = m_model->getOrCreateNostrClient();
            if (nostr) {
                nostr->publishBroadcastAnnouncement(
                    peer_xonly,
                    QString::fromStdString(sid),
                    QStringLiteral("foreign_claim"),
                    txid,
                    /*vout=*/0,
                    /*min_confirmations=*/1);
            }
            break;
        }
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
    // Pre-fill from -pricoinltcrefundaddr config if set, so users
    // who configured auto-refund don't have to re-type for the
    // manual fallback path.
    {
        const std::string cfg_dest = gArgs.GetArg("-pricoinltcrefundaddr", "");
        if (!cfg_dest.empty()) {
            dest_in->setText(QString::fromStdString(cfg_dest));
        }
    }
    {
        QFontMetrics fm(dest_in->font());
        dest_in->setMinimumWidth(fm.horizontalAdvance(QLatin1Char('M')) * 70);
    }
    form->addRow(tr("Destination LTC address:"), dest_in);
    auto* fee_in = new QLineEdit(&dlg);
    fee_in->setText(QString::number(
        EstimateForeignFeeSat(m_model->node(), "ltc", kVbForeignClaim)));
    form->addRow(tr("Fee (sats — backend-estimated):"), fee_in);
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
        "The 3 inputs below auto-fill from the cooperative-sign session "
        "saved on the swap record (Phase 2026-05-11) — override only if "
        "the auto-filled values are stale."), &dlg));
    auto* tx_hex = new QPlainTextEdit(&dlg);
    tx_hex->setPlaceholderText(tr("Skeleton tx hex from pricoin_jointspend_buildtx"));
    tx_hex->setMaximumHeight(80);
    form->addRow(tr("tx_hex:"), tx_hex);
    auto* ring = new QPlainTextEdit(&dlg);
    ring->setPlaceholderText(tr("Multi-layer ring_ml as JSON array of {P,W} objects (matches buildtx output)"));
    ring->setMaximumHeight(80);
    form->addRow(tr("ring_ml (JSON):"), ring);
    auto* msg = new QLineEdit(&dlg);
    msg->setPlaceholderText(tr("32-byte sighash hex"));
    form->addRow(tr("msg (sighash):"), msg);

    // Auto-fill the 3 fields. Preferred source is the swap record
    // (canonical, persisted atomically with the pre-sig). Falls back
    // to session JSON for pre-2026-05-17 swaps that didn't store
    // (msg, pi, tx_hex) on the record.
    if (auto snap_opt = m_model->wallet().adaptorSwapGet(sid); snap_opt) {
        if (!snap_opt->pric_claim_unsigned_tx_hex.empty()) {
            tx_hex->setPlainText(QString::fromStdString(
                snap_opt->pric_claim_unsigned_tx_hex));
        }
        if (!snap_opt->pric_claim_msg_hex.empty()) {
            msg->setText(QString::fromStdString(snap_opt->pric_claim_msg_hex));
        }
        // Session-JSON fallback for any field still empty.
        const std::string& blob = snap_opt->pric_claim_adaptor_session_json;
        UniValue j;
        const bool have_session = !blob.empty() && j.read(blob) && j.isObject();
        if (have_session) {
            if (tx_hex->toPlainText().trimmed().isEmpty()
                && j.exists("unsigned_tx_hex") && j["unsigned_tx_hex"].isStr()) {
                tx_hex->setPlainText(QString::fromStdString(
                    j["unsigned_tx_hex"].get_str()));
            }
            if (msg->text().trimmed().isEmpty()
                && j.exists("msg_hex") && j["msg_hex"].isStr()) {
                msg->setText(QString::fromStdString(
                    j["msg_hex"].get_str()));
            }
            if (ring->toPlainText().trimmed().isEmpty()
                && j.exists("ring_json") && j["ring_json"].isStr()) {
                ring->setPlainText(QString::fromStdString(
                    j["ring_json"].get_str()));
            }
        }
        // Recovery fallback: session JSON's ring_json is empty or
        // stale (e.g. after a crash + restart wiped it). If the swap
        // record has the {P, W} ring components, reconstruct ring_ml
        // from those so the multi-layer adapt path works without
        // requiring a re-buildtx (which would generate fresh decoys
        // and invalidate the stored pre-sig).
        if (ring->toPlainText().trimmed().isEmpty()
            && !snap_opt->pric_claim_ring_hex.empty()
            && snap_opt->pric_claim_ring_w_hex.size()
                 == snap_opt->pric_claim_ring_hex.size()) {
            UniValue ml_arr{UniValue::VARR};
            for (size_t i = 0; i < snap_opt->pric_claim_ring_hex.size(); ++i) {
                UniValue m{UniValue::VOBJ};
                m.pushKV("P", snap_opt->pric_claim_ring_hex[i]);
                m.pushKV("W", snap_opt->pric_claim_ring_w_hex[i]);
                ml_arr.push_back(m);
            }
            ring->setPlainText(QString::fromStdString(ml_arr.write(0)));
        }
        // Legacy fallback: P-only ring (no W on record). Adapt RPC
        // will take the legacy path that fails consensus, but at
        // least surfaces a clear error rather than a silent "0
        // inputs filled". Pre-2026-05-16 swaps fall here.
        if (ring->toPlainText().trimmed().isEmpty()
            && !snap_opt->pric_claim_ring_hex.empty()) {
            UniValue ring_arr{UniValue::VARR};
            for (const auto& h : snap_opt->pric_claim_ring_hex) {
                ring_arr.push_back(h);
            }
            ring->setPlainText(QString::fromStdString(ring_arr.write(0)));
        }
    }
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

bool PricoinSwapsPage::autoLtcClaim(const std::string& sid)
{
    // Alice's headless LTC HTLC claim. Pulls t_secret from the swap
    // record (set by the wallet's tx-scan extractor when Bob's PRIC
    // claim hit chain), the destination from -pricoinltcclaimaddr,
    // and a sane default fee. No dialog. Skipped if config is missing
    // — the user can still click the manual button.
    if (!m_model) return false;
    auto snap_opt = m_model->wallet().adaptorSwapGet(sid);
    if (!snap_opt) return false;
    if (snap_opt->role != "alice") return false;
    if (snap_opt->foreign_chain != "ltc") return false;
    if (!snap_opt->has_t) {
        // Wallet auto-extractor hasn't yet seen Bob's claim tx; will
        // be re-checked on the next refreshTable tick.
        return false;
    }
    // Destination resolution: explicit config wins, otherwise fall
    // back to the wallet's holding LTC address. The holding address
    // is derived locally (no chain-backend dependency) so this
    // always populates when the wallet has stealth identity, which
    // it must to have reached this state.
    std::string dest = gArgs.GetArg("-pricoinltcclaimaddr", "");
    if (dest.empty()) {
        UniValue p_ha{UniValue::VARR};
        p_ha.push_back(std::string{"ltc"});
        std::string ha_err;
        auto r_ha = CallWalletRpc(m_model, "pricoin_btc_getaddress",
                                   p_ha, &ha_err);
        if (r_ha && (*r_ha).exists("address") && (*r_ha)["address"].isStr()) {
            dest = (*r_ha)["address"].get_str();
        }
    }
    if (dest.empty()) {
        setStatus(tr("Auto: LTC claim — destination unknown. Set "
                      "-pricoinltcclaimaddr in pricoin.conf or ensure "
                      "the holding LTC address is available, then click "
                      "\"Adapt + broadcast LTC claim\" manually."), true);
        return false;
    }
    const int64_t fee_sat = EstimateForeignFeeSat(
        m_model->node(), "ltc", kVbForeignClaim);
    UniValue p{UniValue::VARR};
    p.push_back(sid);
    p.push_back("");        // empty t_hex → use stored t_secret (has_t == true)
    p.push_back(dest);
    p.push_back(fee_sat);
    std::string err;
    auto r = CallWalletRpc(m_model, "pricoin_ltc_claim_swap", p, &err);
    if (!r) {
        setStatus(tr("Auto: LTC claim failed: %1")
            .arg(QString::fromStdString(err)), true);
        return false;
    }
    const QString txid = QString::fromStdString((*r)["txid"].get_str());
    setStatus(tr("Auto: LTC claim broadcast — txid %1… (watching for confirmations).")
        .arg(txid.left(16)));
    // Register a local ForeignClaim watch entry on Alice's side too.
    // Without this, her watcher never fires SetComplete on her own
    // claim → her swap stays at pric_claimed forever → the
    // post-terminal hook never runs → linked orders stay Matched.
    // The watcher polls foreign tx confirmation and advances state on
    // its own (same path Bob uses via the DM-registered watch).
    try {
        UniValue p_watch{UniValue::VARR};
        p_watch.push_back(sid);
        p_watch.push_back("foreign_claim");
        p_watch.push_back(txid.toStdString());
        p_watch.push_back(0);   // vout
        p_watch.push_back(1);   // min_confirmations
        m_model->node().executeRpc("pricoin_swapwatch_add", p_watch,
            "/wallet/" + m_model->getWalletName().toStdString());
    } catch (...) {
        // Already present (race) or other backend issue — best-effort.
    }
    // DM Bob the LTC claim txid so his wallet also registers a
    // ForeignClaim watch — that's what advances his side from
    // pric_claimed → complete (his wallet didn't broadcast and
    // wouldn't otherwise know the LTC claim txid to monitor).
    // Bob's wallet's tx_announce DM handler (walletmodel.cpp:656)
    // calls pricoin_swapwatch_add with this txid + kind=foreign_claim.
    if (snap_opt->counterparty_pubkey_hex.size() >= 66) {
        const QString peer_xonly = QString::fromStdString(
            snap_opt->counterparty_pubkey_hex.substr(2));
        auto* nostr = m_model->getOrCreateNostrClient();
        if (nostr) {
            nostr->publishBroadcastAnnouncement(
                peer_xonly,
                QString::fromStdString(sid),
                QStringLiteral("foreign_claim"),
                txid,
                /*vout=*/0,
                /*min_confirmations=*/1);
        }
    }
    refreshTable();
    onSwapwatchRefresh();
    return true;
}

bool PricoinSwapsPage::autoAdaptPricClaim(const std::string& sid)
{
    // Headless variant of onAdaptPricClaimClicked — same RPC call,
    // no dialog. Used by the pre_signed auto-trigger so Bob's PRIC
    // claim broadcasts without manual button-click. Returns true on
    // success.
    //
    // Source of truth for (tx_hex, ring, msg): the swap record, set
    // atomically with the pre-sig at Step 2 success. The session JSON
    // is only a fallback for swaps that predate that persistence
    // (2026-05-17). Reading from session is fragile because nothing
    // prevents the spender's buildtx from re-running across dialog
    // restarts and overwriting the cached ring/msg — which is exactly
    // the bug class we hit on 2026-05-16.
    if (!m_model) return false;
    auto snap_opt = m_model->wallet().adaptorSwapGet(sid);
    if (!snap_opt) return false;

    std::string tx_hex_use;
    std::string msg_hex_use;
    UniValue ring_v;
    // Preferred path: swap record (canonical).
    if (!snap_opt->pric_claim_unsigned_tx_hex.empty()
        && !snap_opt->pric_claim_msg_hex.empty()
        && !snap_opt->pric_claim_ring_hex.empty()) {
        tx_hex_use  = snap_opt->pric_claim_unsigned_tx_hex;
        msg_hex_use = snap_opt->pric_claim_msg_hex;
        // Prefer ring_ml ({P,W}) when W is available; fall back to
        // P-only (single-layer; will fail consensus but at least
        // surfaces a clear error).
        ring_v = UniValue{UniValue::VARR};
        if (snap_opt->pric_claim_ring_w_hex.size()
            == snap_opt->pric_claim_ring_hex.size()) {
            for (size_t i = 0; i < snap_opt->pric_claim_ring_hex.size(); ++i) {
                UniValue m{UniValue::VOBJ};
                m.pushKV("P", snap_opt->pric_claim_ring_hex[i]);
                m.pushKV("W", snap_opt->pric_claim_ring_w_hex[i]);
                ring_v.push_back(m);
            }
        } else {
            for (const auto& h : snap_opt->pric_claim_ring_hex) {
                ring_v.push_back(h);
            }
        }
    } else {
        // Legacy fallback: pre-2026-05-17 swaps store this only in
        // the session JSON.
        const std::string& blob = snap_opt->pric_claim_adaptor_session_json;
        if (blob.empty()) {
            setStatus(tr("Auto: PRIC claim — neither swap-record context nor "
                          "session JSON has tx_hex/ring/msg."), true);
            return false;
        }
        UniValue j;
        if (!j.read(blob) || !j.isObject()) {
            setStatus(tr("Auto: PRIC claim — coopsign session JSON unparseable."), true);
            return false;
        }
        if (!j.exists("unsigned_tx_hex") || !j["unsigned_tx_hex"].isStr()
            || !j.exists("msg_hex") || !j["msg_hex"].isStr()) {
            setStatus(tr("Auto: PRIC claim — session missing unsigned_tx_hex/msg_hex."), true);
            return false;
        }
        tx_hex_use  = j["unsigned_tx_hex"].get_str();
        msg_hex_use = j["msg_hex"].get_str();
        if (j.exists("ring_json") && j["ring_json"].isStr()
            && ring_v.read(j["ring_json"].get_str()) && ring_v.isArray()) {
            // ok
        } else if (!snap_opt->pric_claim_ring_hex.empty()) {
            ring_v = UniValue{UniValue::VARR};
            for (const auto& h : snap_opt->pric_claim_ring_hex) {
                ring_v.push_back(h);
            }
        } else {
            setStatus(tr("Auto: PRIC claim — no ring data available."), true);
            return false;
        }
    }

    UniValue p{UniValue::VARR};
    p.push_back(sid);
    p.push_back(tx_hex_use);
    p.push_back(ring_v);
    p.push_back(msg_hex_use);
    p.push_back(1);  // min_confirmations
    const bool is_ml_ring =
        ring_v.isArray() && !ring_v.empty() && ring_v[0].isObject();
    // Log every adapt attempt with the precise inputs — pairs with
    // AdaptML's LogWarning so debug.log shows BOTH what we passed
    // AND which sub-check (t·G != T_G / s_pi+t overflow / VerifyMultiLayer)
    // tripped. Source tag tells us whether the canonical swap-record
    // fields were populated (preferred path) or we fell back to
    // session_json (which is bound to whatever the last buildtx run
    // produced — drift-vulnerable if Step 2 didn't persist canonicals).
    const bool used_canonical =
        !snap_opt->pric_claim_unsigned_tx_hex.empty()
        && !snap_opt->pric_claim_msg_hex.empty()
        && !snap_opt->pric_claim_ring_hex.empty();
    LogInfo("Pricoin autoAdaptPricClaim: swap=%s src=%s ring=%s ring_size=%u "
            "msg=%s tx_hex_len=%u canonical_W_len=%u canonical_msg=%s\n",
            sid.substr(0, 16).c_str(),
            used_canonical ? "swap_record" : "session_json",
            is_ml_ring ? "ml(P+W)" : "single(P)",
            (unsigned)ring_v.size(),
            msg_hex_use.substr(0, 16).c_str(),
            (unsigned)tx_hex_use.size(),
            (unsigned)snap_opt->pric_claim_ring_w_hex.size(),
            snap_opt->pric_claim_msg_hex.empty() ? "EMPTY"
                : snap_opt->pric_claim_msg_hex.substr(0, 16).c_str());
    std::string err;
    auto r = CallWalletRpc(m_model, "pricoin_swapwatch_adapt_pric_claim", p, &err);
    if (!r) {
        // 2026-05-14: surface what we passed so we can correlate
        // with the on-side adapt diagnostics. The adapt RPC's failure
        // message is opaque (3 possible causes); pairing it with the
        // ring shape + msg here narrows the search space.
        const std::string ring_summary = is_ml_ring
            ? "ring_ml({P,W})" : "ring_singlelayer(P)";
        setStatus(tr("Auto: Adapt+broadcast PRIC failed: %1\n"
                      "  swap_id=%2  msg=%3  ring=%4 size=%5")
            .arg(QString::fromStdString(err))
            .arg(QString::fromStdString(sid).left(12) + "…")
            .arg(QString::fromStdString(msg_hex_use).left(16) + "…")
            .arg(QString::fromStdString(ring_summary))
            .arg(static_cast<int>(ring_v.size())),
            true);
        LogInfo("Pricoin autoAdaptPricClaim: RPC failed: %s\n", err.c_str());
        return false;
    }
    const QString txid = QString::fromStdString((*r)["txid"].get_str());
    setStatus(tr("Auto: PRIC claim broadcast — txid %1… (watching for confirmations).")
        .arg(txid.left(16)));
    // DM Alice the PRIC claim txid so her watcher registers a
    // pric_claim entry directly — fallback for the case where her
    // wallet's tx-arrival ScanTxForSwapClaim path didn't see the tx
    // (e.g. tx arrived before her wallet was scanning the new state).
    // Alice's wallet's tx_announce DM handler in walletmodel.cpp:656
    // calls pricoin_swapwatch_add with kind=pric_claim. Once the
    // watcher's TxStatus returns confirmed, SetPricClaimed advances
    // her state automatically.
    if (snap_opt->counterparty_pubkey_hex.size() >= 66) {
        const QString peer_xonly = QString::fromStdString(
            snap_opt->counterparty_pubkey_hex.substr(2));
        auto* nostr = m_model->getOrCreateNostrClient();
        if (nostr) {
            nostr->publishBroadcastAnnouncement(
                peer_xonly,
                QString::fromStdString(sid),
                QStringLiteral("pric_claim"),
                txid,
                /*vout=*/0,
                /*min_confirmations=*/1);
        }
    }
    refreshTable();
    onSwapwatchRefresh();
    return true;
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
