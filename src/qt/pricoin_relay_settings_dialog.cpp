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

constexpr const char* kSettingsKey = "pricoin/orderbook/nostr_relays";

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
    return {
        QStringLiteral("wss://relay.damus.io"),
        QStringLiteral("wss://nos.lol"),
        QStringLiteral("wss://relay.snort.social"),
    };
}

QStringList PricoinRelaySettingsDialog::loadFromSettings()
{
    QSettings s;
    if (!s.contains(kSettingsKey)) return defaultRelays();
    const QStringList stored = s.value(kSettingsKey).toStringList();
    if (stored.isEmpty()) return defaultRelays();
    return stored;
}

void PricoinRelaySettingsDialog::saveToSettings(const QStringList& urls)
{
    QSettings s;
    s.setValue(kSettingsKey, urls);
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
