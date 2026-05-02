// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_PRICOIN_RELAY_SETTINGS_DIALOG_H
#define BITCOIN_QT_PRICOIN_RELAY_SETTINGS_DIALOG_H

#include <QDialog>
#include <QStringList>

QT_BEGIN_NAMESPACE
class QListWidget;
class QPushButton;
QT_END_NAMESPACE

// Modal dialog for editing the wallet's Nostr relay list. The current
// list is loaded from QSettings on open; on accept, the edited list
// is persisted and exposed via accepted().
//
// Persistence key: "pricoin/orderbook/nostr_relays" (QStringList).
//
// Validation is minimal: scheme must be ws:// or wss://. Anything
// else is rejected with a status label hint.

class PricoinRelaySettingsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit PricoinRelaySettingsDialog(QWidget* parent = nullptr);
    ~PricoinRelaySettingsDialog() override = default;

    // Returns the (potentially edited) relay list. Valid after exec()
    // returns Accepted.
    QStringList relays() const;

    // Default relays for first-run / reset. Public so the orderbook
    // page can also reuse them when QSettings has nothing stored.
    static QStringList defaultRelays();

    // Read the persisted list, or defaultRelays() if QSettings is
    // empty. Convenience for the orderbook page.
    static QStringList loadFromSettings();

    // Persist `urls` to QSettings.
    static void saveToSettings(const QStringList& urls);

private Q_SLOTS:
    void onAdd();
    void onRemove();
    void onResetDefaults();

private:
    QListWidget* m_list{nullptr};
    QPushButton* m_btn_add{nullptr};
    QPushButton* m_btn_remove{nullptr};
    QPushButton* m_btn_reset{nullptr};

    void load();
};

#endif // BITCOIN_QT_PRICOIN_RELAY_SETTINGS_DIALOG_H
