// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_PRICOIN_JOINT_STEALTH_DIALOG_H
#define BITCOIN_QT_PRICOIN_JOINT_STEALTH_DIALOG_H

#include <QDialog>
#include <QString>

class PricoinNostrClient;
class WalletModel;

QT_BEGIN_NAMESPACE
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
QT_END_NAMESPACE

// Joint stealth address wizard for atomic swaps.
//
// PROBLEM
//   Atomic swaps need both parties to agree on a single joint stealth
//   address (joint view + spend = sum of both parties' pubkeys). Today
//   this requires CLI ping-pong: each party calls
//   pricoin_buildjointstealthaddress with the other's view+spend
//   pubkeys, exchanges via DM/email, and pastes the resulting address
//   into the Start-swap form. Several round-trip steps with manual
//   copy-paste of 132 hex characters (two pubkeys) — easy to fat-finger.
//
// THIS DIALOG
//   * Shows my own view + spend pubkeys as a single copyable
//     "share-this-with-peer" blob (JSON envelope).
//   * Paste field for peer's view + spend (JSON envelope).
//   * "Build" button calls pricoin_buildjointstealthaddress in-process,
//     displays the joint address.
//   * "Send via Nostr DM" / "Auto-paste from DM" optional automation
//     when the orderbook's shared Nostr client is connected.
//   * "Use" closes the dialog returning the joint address; the caller
//     (Start-swap form) auto-fills its joint_stealth_address field.

class PricoinJointStealthDialog : public QDialog
{
    Q_OBJECT

public:
    PricoinJointStealthDialog(WalletModel* wallet_model,
                                const QString& peer_xonly_hex,
                                QWidget* parent = nullptr);

    // Valid only after exec() returns Accepted.
    QString chosenJointAddress() const { return m_chosen_joint_address; }

private Q_SLOTS:
    void onSendDM();
    void onBuildClicked();
    void onUseClicked();
    void onDMReceived(const QString& from_xonly_hex, const QString& plaintext);

private:
    WalletModel* m_wm{nullptr};
    QString m_peer_xonly;
    PricoinNostrClient* m_nostr{nullptr};
    QString m_chosen_joint_address;

    QPlainTextEdit* m_my_envelope{nullptr};
    QPlainTextEdit* m_peer_envelope{nullptr};
    QLineEdit*      m_joint_address{nullptr};
    QLabel*         m_status{nullptr};
    QPushButton*    m_btn_send_dm{nullptr};
    QPushButton*    m_btn_build{nullptr};
    QPushButton*    m_btn_use{nullptr};

    void buildLayout();
    void populateMyEnvelope();
    void setStatus(const QString& msg, bool error = false);
};

#endif // BITCOIN_QT_PRICOIN_JOINT_STEALTH_DIALOG_H
