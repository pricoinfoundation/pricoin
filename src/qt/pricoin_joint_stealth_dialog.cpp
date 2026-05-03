// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pricoin_joint_stealth_dialog.h>

#include <interfaces/node.h>
#include <qt/pricoin_nostr_client.h>
#include <qt/walletmodel.h>
#include <univalue.h>

#include <QApplication>
#include <QClipboard>
#include <QDialogButtonBox>
#include <QFontDatabase>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QUrl>
#include <QVBoxLayout>

PricoinJointStealthDialog::PricoinJointStealthDialog(
    WalletModel* wallet_model,
    const QString& peer_xonly_hex,
    QWidget* parent)
    : QDialog(parent),
      m_wm(wallet_model),
      m_peer_xonly(peer_xonly_hex)
{
    setModal(true);
    setWindowTitle(tr("Build joint stealth address"));
    resize(720, 540);
    buildLayout();
    populateMyEnvelope();
    if (m_wm) {
        m_nostr = m_wm->getOrCreateNostrClient();
        if (m_nostr) {
            connect(m_nostr, &PricoinNostrClient::directMessageReceived,
                    this, &PricoinJointStealthDialog::onDMReceived);
        }
    }
    if (m_btn_send_dm) {
        m_btn_send_dm->setEnabled(m_nostr && !m_peer_xonly.isEmpty());
    }
}

void PricoinJointStealthDialog::buildLayout()
{
    auto* outer = new QVBoxLayout(this);

    auto* hdr = new QLabel(this);
    hdr->setWordWrap(true);
    hdr->setText(tr(
        "<b>Atomic-swap joint stealth address.</b><br/>"
        "Both parties must run this and obtain the SAME joint address. "
        "Share your envelope (top) with the peer; paste theirs into the middle "
        "field; click <b>Build</b>. The Start-swap dialog will auto-fill from "
        "the joint address shown at the bottom."));
    outer->addWidget(hdr);

    const QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);

    // My envelope (read-only — generated from my stealth identity).
    outer->addWidget(new QLabel(tr("My stealth pubkeys (send to peer):"), this));
    m_my_envelope = new QPlainTextEdit(this);
    m_my_envelope->setFont(mono);
    m_my_envelope->setReadOnly(true);
    m_my_envelope->setMaximumHeight(80);
    outer->addWidget(m_my_envelope);
    auto* my_row = new QHBoxLayout();
    auto* btn_copy = new QPushButton(tr("Copy"), this);
    connect(btn_copy, &QPushButton::clicked, this, [this]() {
        QApplication::clipboard()->setText(m_my_envelope->toPlainText());
    });
    my_row->addWidget(btn_copy);
    m_btn_send_dm = new QPushButton(tr("Send via Nostr DM"), this);
    my_row->addWidget(m_btn_send_dm);
    my_row->addStretch();
    outer->addLayout(my_row);
    connect(m_btn_send_dm, &QPushButton::clicked, this, &PricoinJointStealthDialog::onSendDM);

    // Peer's envelope (paste).
    outer->addWidget(new QLabel(tr("Peer's stealth pubkeys (paste from their wizard):"), this));
    m_peer_envelope = new QPlainTextEdit(this);
    m_peer_envelope->setFont(mono);
    m_peer_envelope->setMaximumHeight(80);
    m_peer_envelope->setPlaceholderText(tr(
        "{\"v\":1,\"type\":\"joint_stealth_keys\","
        "\"view_pubkey\":\"<33B hex>\",\"spend_pubkey\":\"<33B hex>\"}"));
    outer->addWidget(m_peer_envelope);
    auto* peer_row = new QHBoxLayout();
    auto* btn_paste = new QPushButton(tr("Paste"), this);
    connect(btn_paste, &QPushButton::clicked, this, [this]() {
        m_peer_envelope->setPlainText(QApplication::clipboard()->text().trimmed());
    });
    peer_row->addWidget(btn_paste);
    peer_row->addStretch();
    outer->addLayout(peer_row);

    // Build + result.
    m_btn_build = new QPushButton(tr("Build joint stealth address"), this);
    outer->addWidget(m_btn_build);
    connect(m_btn_build, &QPushButton::clicked, this, &PricoinJointStealthDialog::onBuildClicked);

    outer->addWidget(new QLabel(tr("Joint stealth address:"), this));
    m_joint_address = new QLineEdit(this);
    m_joint_address->setReadOnly(true);
    m_joint_address->setFont(mono);
    outer->addWidget(m_joint_address);

    m_status = new QLabel(this);
    m_status->setWordWrap(true);
    outer->addWidget(m_status);

    auto* bb = new QDialogButtonBox(this);
    m_btn_use = bb->addButton(tr("Use this address"), QDialogButtonBox::AcceptRole);
    bb->addButton(QDialogButtonBox::Cancel);
    m_btn_use->setEnabled(false);
    connect(bb, &QDialogButtonBox::accepted, this, &PricoinJointStealthDialog::onUseClicked);
    connect(bb, &QDialogButtonBox::rejected, this, &QDialog::reject);
    outer->addWidget(bb);
}

void PricoinJointStealthDialog::populateMyEnvelope()
{
    if (!m_wm) return;
    // Pull my view + spend pubkeys from my stealth address. The
    // address encodes (view||spend) as 67 bytes; we re-fetch via the
    // RPC to get the canonical form, then decode client-side.
    const std::string my_addr = m_wm->wallet().getStealthAddress();
    if (my_addr.empty()) {
        setStatus(tr("Stealth identity unavailable (wallet locked?)"), true);
        return;
    }
    // Easiest path: pricoin_getstealthaddress returns the address +
    // view_pubkey + spend_pubkey directly.
    const std::string uri = "/wallet/" + m_wm->getWalletName().toStdString();
    UniValue empty_params{UniValue::VARR};
    UniValue r;
    try {
        r = m_wm->node().executeRpc("pricoin_getstealthaddress",
            empty_params, uri);
    } catch (const std::exception&) {
        setStatus(tr("getstealthaddress RPC failed"), true);
        return;
    } catch (const UniValue&) {
        setStatus(tr("getstealthaddress RPC failed"), true);
        return;
    }
    UniValue env{UniValue::VOBJ};
    env.pushKV("v",            1);
    env.pushKV("type",         "joint_stealth_keys");
    env.pushKV("view_pubkey",  r["view_pubkey"].get_str());
    env.pushKV("spend_pubkey", r["spend_pubkey"].get_str());
    m_my_envelope->setPlainText(QString::fromStdString(env.write(2)));
}

void PricoinJointStealthDialog::setStatus(const QString& msg, bool error)
{
    if (!m_status) return;
    m_status->setStyleSheet(error
        ? QStringLiteral("QLabel { color: #b71c1c; }")
        : QStringLiteral("QLabel { color: #1b5e20; }"));
    m_status->setText(msg);
}

void PricoinJointStealthDialog::onBuildClicked()
{
    if (!m_wm) return;
    const QString peer_text = m_peer_envelope->toPlainText().trimmed();
    if (peer_text.isEmpty()) {
        setStatus(tr("Paste the peer's envelope first."), true);
        return;
    }
    UniValue env;
    if (!env.read(peer_text.toStdString()) || !env.isObject()) {
        setStatus(tr("Peer envelope is not valid JSON"), true);
        return;
    }
    if (!env.exists("view_pubkey") || !env.exists("spend_pubkey")) {
        setStatus(tr("Peer envelope missing view_pubkey / spend_pubkey"), true);
        return;
    }
    const std::string view_hex  = env["view_pubkey"].get_str();
    const std::string spend_hex = env["spend_pubkey"].get_str();

    UniValue p{UniValue::VARR};
    p.push_back(view_hex);
    p.push_back(spend_hex);
    const std::string uri = "/wallet/" + m_wm->getWalletName().toStdString();
    UniValue r;
    try {
        r = m_wm->node().executeRpc("pricoin_buildjointstealthaddress",
            p, uri);
    } catch (const UniValue& e) {
        setStatus(tr("buildjointstealthaddress failed: %1").arg(
            e.exists("message")
                ? QString::fromStdString(e["message"].get_str())
                : QString::fromStdString(e.write())), true);
        return;
    } catch (const std::exception& e) {
        setStatus(tr("buildjointstealthaddress failed: %1").arg(e.what()), true);
        return;
    }
    const QString addr = QString::fromStdString(r["address"].get_str());
    m_joint_address->setText(addr);
    m_btn_use->setEnabled(true);
    setStatus(tr("Joint address built. Click \"Use this address\" to fill it into the swap form."));
}

void PricoinJointStealthDialog::onUseClicked()
{
    m_chosen_joint_address = m_joint_address->text().trimmed();
    if (m_chosen_joint_address.isEmpty()) {
        setStatus(tr("Build the joint address first."), true);
        return;
    }
    accept();
}

void PricoinJointStealthDialog::onSendDM()
{
    if (!m_nostr || m_peer_xonly.isEmpty()) return;
    const QString plaintext = m_my_envelope->toPlainText();
    if (m_nostr->publishDirectMessage(m_peer_xonly, plaintext)) {
        setStatus(tr("Sent envelope to peer via Nostr DM."));
    } else {
        setStatus(tr("DM send failed (no relays connected?)"), true);
    }
}

void PricoinJointStealthDialog::onDMReceived(const QString& from_xonly_hex,
                                                const QString& plaintext)
{
    // Filter to messages from this swap's counterparty + the right type.
    if (!m_peer_xonly.isEmpty() && from_xonly_hex != m_peer_xonly) return;
    UniValue env;
    if (!env.read(plaintext.toStdString()) || !env.isObject()) return;
    if (!env.exists("type") || env["type"].get_str() != "joint_stealth_keys") return;
    m_peer_envelope->setPlainText(plaintext);
    setStatus(tr("Peer envelope auto-pasted from DM. Click Build."));
}
