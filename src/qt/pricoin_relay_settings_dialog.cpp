// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pricoin_relay_settings_dialog.h>

#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QListWidget>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>
#include <QUrl>
#include <QVBoxLayout>

namespace {

// Bumped from "pricoin/orderbook/nostr_relays" (v1) to v2 when the
// default mesh switched from the public Damus/snort/nos.lol set to
// Pricoin's own cross-streamed strfry mesh (relay1..4.pricoin.io).
// On first launch of the new build, loadFromSettings() sees no v2
// key and falls through to the new defaults — replacing any cached
// v1 list. Manual customizations from v1 are NOT preserved (rare;
// user can re-add via Relay settings).
constexpr const char* kSettingsKey   = "pricoin/orderbook/nostr_relays_v2";
constexpr const char* kSettingsKeyV1 = "pricoin/orderbook/nostr_relays";

bool ValidRelayUrl(const QString& s)
{
    const QUrl u(s);
    if (!u.isValid()) return false;
    const QString scheme = u.scheme().toLower();
    return scheme == QStringLiteral("ws") || scheme == QStringLiteral("wss");
}

} // namespace

QStringList PricoinRelaySettingsDialog::defaultRelays()
{
    // Pricoin-operated cross-streamed relay mesh. Each instance runs
    // strfry behind Caddy TLS and bidirectionally syncs to the other
    // three via `strfry stream --dir both`, so events ingested at
    // any one are visible at all four. Generic public relays remain
    // available as opt-in via Relay settings — but using only the
    // Pricoin mesh by default keeps the orderbook focused on
    // Pricoin traffic and avoids spam-filter rejections from
    // general-purpose relays that don't expect kind=30030.
    return {
        QStringLiteral("wss://relay1.pricoin.io"),
        QStringLiteral("wss://relay2.pricoin.io"),
        QStringLiteral("wss://relay3.pricoin.io"),
        QStringLiteral("wss://relay4.pricoin.io"),
    };
}

QStringList PricoinRelaySettingsDialog::loadFromSettings()
{
    QSettings s;
    // First-time-on-v2: stale v1 key is irrelevant — start from
    // the new defaults and clear v1 so it doesn't accumulate.
    if (!s.contains(kSettingsKey)) {
        s.remove(kSettingsKeyV1);
        return defaultRelays();
    }
    const QStringList stored = s.value(kSettingsKey).toStringList();
    if (stored.isEmpty()) return defaultRelays();
    return stored;
}

void PricoinRelaySettingsDialog::saveToSettings(const QStringList& urls)
{
    QSettings s;
    s.setValue(kSettingsKey, urls);
    // Keep v1 cleared so we don't re-read it on a subsequent
    // downgrade.
    s.remove(kSettingsKeyV1);
}

PricoinRelaySettingsDialog::PricoinRelaySettingsDialog(QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Nostr relay settings"));
    resize(420, 320);

    auto* outer = new QVBoxLayout(this);

    m_list = new QListWidget(this);
    outer->addWidget(m_list);

    auto* row = new QHBoxLayout();
    m_btn_add    = new QPushButton(tr("Add…"),    this);
    m_btn_remove = new QPushButton(tr("Remove"),   this);
    m_btn_reset  = new QPushButton(tr("Reset to defaults"), this);
    row->addWidget(m_btn_add);
    row->addWidget(m_btn_remove);
    row->addWidget(m_btn_reset);
    row->addStretch();
    outer->addLayout(row);

    auto* bb = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(bb, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, this, &QDialog::reject);
    outer->addWidget(bb);

    connect(m_btn_add,    &QPushButton::clicked, this, &PricoinRelaySettingsDialog::onAdd);
    connect(m_btn_remove, &QPushButton::clicked, this, &PricoinRelaySettingsDialog::onRemove);
    connect(m_btn_reset,  &QPushButton::clicked, this, &PricoinRelaySettingsDialog::onResetDefaults);

    load();
}

void PricoinRelaySettingsDialog::load()
{
    m_list->clear();
    for (const QString& u : loadFromSettings()) {
        m_list->addItem(u);
    }
}

QStringList PricoinRelaySettingsDialog::relays() const
{
    QStringList out;
    out.reserve(m_list->count());
    for (int i = 0; i < m_list->count(); ++i) {
        out.append(m_list->item(i)->text());
    }
    return out;
}

void PricoinRelaySettingsDialog::onAdd()
{
    bool ok = false;
    const QString u = QInputDialog::getText(
        this, tr("Add relay"),
        tr("Relay URL (ws:// or wss://):"),
        QLineEdit::Normal, QStringLiteral("wss://"), &ok);
    if (!ok || u.trimmed().isEmpty()) return;
    const QString trimmed = u.trimmed();
    if (!ValidRelayUrl(trimmed)) {
        QMessageBox::warning(this, tr("Add relay"),
            tr("URL must use ws:// or wss:// scheme."));
        return;
    }
    // Reject duplicates.
    for (int i = 0; i < m_list->count(); ++i) {
        if (m_list->item(i)->text() == trimmed) {
            QMessageBox::information(this, tr("Add relay"),
                tr("That relay is already in the list."));
            return;
        }
    }
    m_list->addItem(trimmed);
}

void PricoinRelaySettingsDialog::onRemove()
{
    const auto sel = m_list->selectedItems();
    for (auto* item : sel) {
        delete m_list->takeItem(m_list->row(item));
    }
}

void PricoinRelaySettingsDialog::onResetDefaults()
{
    if (QMessageBox::question(this, tr("Reset to defaults"),
            tr("Replace the current list with the built-in default relays?"),
            QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) return;
    m_list->clear();
    for (const QString& u : defaultRelays()) m_list->addItem(u);
}
