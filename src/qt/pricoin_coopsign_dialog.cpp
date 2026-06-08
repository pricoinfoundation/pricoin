// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pricoin_coopsign_dialog.h>

#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <qt/pricoin_nostr_client.h>
#include <qt/pricoin_relay_settings_dialog.h>
#include <qt/walletmodel.h>
#include <random.h>
#include <univalue.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QEventLoop>
#include <QFontDatabase>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QStackedWidget>
#include <QUrl>
#include <QVBoxLayout>

#include <stdexcept>

namespace {

// Wraps a (label, edit, button-row) trio used for each step. Each
// step is its own QGroupBox so the visual flow reads top-down.
QGroupBox* MakeStepBox(const QString& title, QWidget* parent)
{
    auto* box = new QGroupBox(title, parent);
    box->setStyleSheet(QStringLiteral("QGroupBox { font-weight: bold; }"));
    return box;
}

// Three-button row that hangs below an output text area: Copy /
// Paste / Clear. Standard convenience widgets so the user can shuttle
// blobs through the system clipboard during the manual round trips.
QHBoxLayout* MakeCopyPasteRow(QPlainTextEdit* edit, QWidget* /*parent*/)
{
    auto* row = new QHBoxLayout();
    auto* btn_copy  = new QPushButton(QObject::tr("Copy"), edit);
    auto* btn_paste = new QPushButton(QObject::tr("Paste"), edit);
    auto* btn_clear = new QPushButton(QObject::tr("Clear"), edit);
    row->addWidget(btn_copy);
    row->addWidget(btn_paste);
    row->addWidget(btn_clear);
    row->addStretch();
    QObject::connect(btn_copy, &QPushButton::clicked, edit, [edit]() {
        QApplication::clipboard()->setText(edit->toPlainText());
    });
    QObject::connect(btn_paste, &QPushButton::clicked, edit, [edit]() {
        edit->setPlainText(QApplication::clipboard()->text().trimmed());
    });
    QObject::connect(btn_clear, &QPushButton::clicked, edit, [edit]() {
        edit->clear();
    });
    return row;
}

// Force a monospace font on a text edit so the user can eyeball
// hex blob lengths.
void MakeMono(QPlainTextEdit* edit)
{
    edit->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    edit->setLineWrapMode(QPlainTextEdit::WidgetWidth);
}

} // namespace

CoopSignDialog::CoopSignDialog(WalletModel* wallet_model,
                                Mode mode,
                                const QString& title,
                                const std::string& swap_id,
                                QWidget* parent)
    : QDialog(parent),
      m_wm(wallet_model),
      m_mode(mode),
      m_swap_id(QString::fromStdString(swap_id))
{
    setModal(true);
    resize(820, 800);
    // Relay list: same QSettings key as the orderbook page so
    // user's saved relays are reused. We don't auto-connect — the
    // user clicks "Connect Nostr DM" if they want auto-delivery.
    m_relay_urls = PricoinRelaySettingsDialog::loadFromSettings();

    buildLayout(title);

    // If a swap_id was given, pre-fill what we can from the wallet's
    // adaptor-swap record. Saves the user from re-typing fields the
    // wallet already knows.
    if (!swap_id.empty() && m_wm) {
        auto snap = m_wm->wallet().adaptorSwapGet(swap_id);
        if (snap) {
            // Peer xonly = last 32 bytes of the 33-byte compressed
            // counterparty pubkey (drop the parity prefix).
            if (!snap->counterparty_pubkey_hex.empty()
                && snap->counterparty_pubkey_hex.size() >= 66) {
                m_peer_xonly = QString::fromStdString(
                    snap->counterparty_pubkey_hex.substr(2));
            }
            // Peer pubkey: the swap's counterparty_pubkey, 33-byte
            // compressed already.
            if (m_in_peer_pub && !snap->counterparty_pubkey_hex.empty()) {
                m_in_peer_pub->setText(QString::fromStdString(snap->counterparty_pubkey_hex));
            }
            // Swap role — drives the canonical keyagg ordering in Step 1.
            m_swap_role = QString::fromStdString(snap->role);
            // Map the swap role to the MuSig2 role label (only used to key
            // the per-wallet nonce-reuse record, not the signature) so the
            // headless path has a consistent value without user input.
            if (m_in_role) {
                if (m_swap_role == "alice")     m_in_role->setCurrentText("initiator");
                else if (m_swap_role == "bob")  m_in_role->setCurrentText("responder");
            }
            // My pubkey: take the wallet's BIP340 swap-identity x-only
            // and synthesise the 33-byte compressed (even-y) form by
            // prefixing 0x02. BIP327 keyagg accepts this; the parity
            // is internal to the keyagg cache.
            const std::string xonly = m_wm->wallet().getSwapIdentityXOnlyHex();
            if (m_in_my_pub && xonly.size() == 64) {
                m_in_my_pub->setText(QStringLiteral("02") + QString::fromStdString(xonly));
            }
            // Adaptor T_G (claim leg only).
            if (m_mode == Mode::BtcAdaptor && m_in_adaptor_T_G
                && !snap->adaptor_T_G_hex.empty()) {
                m_in_adaptor_T_G->setText(QString::fromStdString(snap->adaptor_T_G_hex));
            }
            // Funding outpoint + amount: auto-fill the tx-context
            // helper rows once they exist (built later in
            // buildLayout). Done after the layout is up via a
            // single-shot timer-style assignment.
            if (m_in_funding_txid && !snap->foreign_funding_txid.empty()) {
                m_in_funding_txid->setText(QString::fromStdString(snap->foreign_funding_txid));
            }
            if (m_in_funding_vout && snap->foreign_funding_vout >= 0) {
                m_in_funding_vout->setText(QString::number(snap->foreign_funding_vout));
            }
            if (m_in_funding_amount && snap->foreign_amount_sat > 0) {
                m_in_funding_amount->setText(QString::number(snap->foreign_amount_sat));
                // Default refund amount = funding amount minus a
                // tiny fee (1000 sat). The user can override this.
                if (m_in_refund_amount && snap->foreign_amount_sat > 1000) {
                    m_in_refund_amount->setText(QString::number(snap->foreign_amount_sat - 1000));
                }
            }
            // Refund mode: nlocktime = foreign_refund_height.
            if (m_mode == Mode::BtcPlain && m_in_nlocktime
                && snap->foreign_refund_height > 0) {
                m_in_nlocktime->setText(QString::number(snap->foreign_refund_height));
            }
            // Recipient: BTC claim (adaptor) → Bob's xonly, BTC
            // refund (plain) → Alice's xonly. Both wallets store
            // both addresses so each side can pre-fill independent
            // of role.
            if (m_in_recipient_xonly) {
                const std::string& rcpt =
                    (m_mode == Mode::BtcAdaptor) ? snap->btc_bob_recipient_xonly_hex
                                                  : snap->btc_alice_recipient_xonly_hex;
                if (!rcpt.empty()) {
                    m_in_recipient_xonly->setText(QString::fromStdString(rcpt));
                }
            }
        }
    }
}

void CoopSignDialog::onComputeSighash()
{
    if (m_agg_xonly.isEmpty()) {
        setStatus(tr("Run step 1 (keyagg) first — sighash binds to agg_xonly."), true);
        return;
    }
    const QString f_txid = m_in_funding_txid->text().trimmed();
    const QString f_vout = m_in_funding_vout->text().trimmed();
    const QString f_amt  = m_in_funding_amount->text().trimmed();
    const QString rcpt   = m_in_recipient_xonly->text().trimmed();
    const QString r_amt  = m_in_refund_amount->text().trimmed();
    const QString nlt    = m_in_nlocktime->text().trimmed();
    if (f_txid.size() != 64) {
        setStatus(tr("Funding txid must be 32-byte hex"), true); return;
    }
    bool vout_ok = false, fa_ok = false, ra_ok = false, nl_ok = false;
    int  vout = f_vout.toInt(&vout_ok);
    long long fa = f_amt.toLongLong(&fa_ok);
    long long ra = r_amt.toLongLong(&ra_ok);
    int  nl   = nlt.toInt(&nl_ok);
    if (!vout_ok || vout < 0) { setStatus(tr("Funding vout invalid"), true); return; }
    if (!fa_ok || fa <= 0)    { setStatus(tr("Funding amount sat invalid"), true); return; }
    if (!ra_ok || ra <= 0)    { setStatus(tr("Output amount sat invalid"), true); return; }
    if (!nl_ok || nl < 0)     { setStatus(tr("nlocktime invalid"), true); return; }
    if (rcpt.size() != 64) {
        setStatus(tr("Recipient x-only must be 32-byte hex"), true); return;
    }
    // Synthesize the P2TR scriptPubKey from the recipient x-only:
    //   OP_1 OP_PUSHBYTES_32 <32 bytes> = 0x51 0x20 ...
    const std::string spk_hex = std::string("5120") + rcpt.toStdString();

    // pricoin_btc_swap_tx_build(funding_txid, funding_vout, funding_amount_sat, agg_xonly, recipient_script_pubkey, refund_amount_sat, nlocktime)
    std::string params = std::string("[\"")
        + f_txid.toStdString() + "\","
        + std::to_string(vout) + ","
        + std::to_string(fa) + ",\""
        + m_agg_xonly.toStdString() + "\",\""
        + spk_hex + "\","
        + std::to_string(ra) + ","
        + std::to_string(nl) + "]";
    auto r = callRpc("pricoin_btc_swap_tx_build", params);
    if (!r.ok) {
        setStatus(tr("swap_tx_build failed: %1").arg(QString::fromStdString(r.error_msg)), true);
        return;
    }
    UniValue v;
    v.read(r.json);
    const QString sighash = QString::fromStdString(v["sighash"].get_str());
    m_unsigned_tx_hex = QString::fromStdString(v["tx_hex"].get_str());
    if (m_in_msg) m_in_msg->setText(sighash);
    setStatus(tr("Sighash auto-filled (%1…). Proceed to step 2.").arg(sighash.left(16)));

    // BTC refund: persist the unsigned tx hex on the swap record so
    // the auto-refund watcher can finalize + broadcast at timelock
    // without requiring both parties to walk the cooperative dialog
    // again. Mirrors PRIC refund persistence in PricCoopSignDialog.
    if (m_mode == Mode::BtcPlain && m_wm && !m_swap_id.isEmpty()
        && !m_unsigned_tx_hex.isEmpty()) {
        auto rr = m_wm->wallet().adaptorSwapSetBtcRefundTx(
            m_swap_id.toStdString(), m_unsigned_tx_hex.toStdString());
        if (!rr) {
            setStatus(tr("Sighash OK; persisting BTC refund tx for "
                         "auto-refund failed: %1")
                .arg(QString::fromStdString(util::ErrorString(rr).original)),
                /*error=*/false);
        }
    }
}

QString CoopSignDialog::RandomHex32()
{
    unsigned char buf[32];
    GetStrongRandBytes(buf);
    return QString::fromStdString(HexStr(std::span<const unsigned char>{buf, 32}));
}

CoopSignDialog::RpcResult
CoopSignDialog::callRpc(const std::string& method, const std::string& params_json)
{
    if (!m_wm) {
        return {false, {}, "wallet not attached"};
    }
    UniValue params;
    if (!params.read(params_json) || !params.isArray()) {
        return {false, {}, "internal: malformed params JSON for " + method};
    }
    const QString wallet_name = m_wm->getWalletName();
    std::string uri;
    if (!wallet_name.isEmpty()) {
        QByteArray enc = QUrl::toPercentEncoding(wallet_name);
        uri = "/wallet/" + std::string(enc.constData(), enc.length());
    }
    try {
        UniValue out = m_wm->node().executeRpc(method, params, uri);
        return {true, out.write(2), {}};
    } catch (const UniValue& e) {
        // JSON-RPC errors arrive as UniValue objects with code/message.
        std::string msg;
        if (e.isObject() && e.exists("message") && e["message"].isStr()) {
            msg = e["message"].get_str();
        } else {
            msg = e.write();
        }
        return {false, {}, msg};
    } catch (const std::exception& e) {
        return {false, {}, e.what()};
    } catch (...) {
        return {false, {}, "unknown RPC error"};
    }
}

void CoopSignDialog::setStatus(const QString& msg, bool error)
{
    if (!m_status_label) return;
    m_status_label->setStyleSheet(error
        ? QStringLiteral("QLabel { color: #b71c1c; }")
        : QStringLiteral("QLabel { color: #1b5e20; }"));
    m_status_label->setText(msg);
}

void CoopSignDialog::buildLayout(const QString& title)
{
    setWindowTitle(title);

    auto* outer = new QVBoxLayout(this);

    // ─── Nostr DM section (optional auto-delivery) ────────────
    {
        auto* box = new QGroupBox(tr("Nostr DM (optional — auto-deliver pubnonce/partial to peer)"), this);
        box->setStyleSheet(QStringLiteral("QGroupBox { font-weight: bold; }"));
        auto* h = new QHBoxLayout(box);
        m_btn_nostr_connect = new QPushButton(tr("Connect Nostr DM"), box);
        h->addWidget(m_btn_nostr_connect);
        m_chk_auto_paste = new QCheckBox(tr("Auto-paste from peer DMs"), box);
        m_chk_auto_paste->setChecked(true);
        h->addWidget(m_chk_auto_paste);
        m_lbl_nostr_status = new QLabel(box);
        m_lbl_nostr_status->setWordWrap(true);
        h->addWidget(m_lbl_nostr_status, /*stretch=*/1);
        outer->addWidget(box);
        connect(m_btn_nostr_connect, &QPushButton::clicked, this, &CoopSignDialog::onNostrConnectClicked);
        updateNostrStatus();
    }

    // Header — explain the protocol shape so a user that hasn't run
    // through this before doesn't get lost.
    auto* hdr = new QLabel(this);
    hdr->setWordWrap(true);
    hdr->setText(tr(
        "<b>%1</b><br/>"
        "Run each step in order. Steps 1 and 2 are local-only "
        "(no peer round trip). After step 2, copy your "
        "<code>pubnonce</code> to your peer and paste their "
        "<code>pubnonce</code> into step 3. After step 3, copy your "
        "<code>partial_sig</code> to your peer and paste theirs into "
        "step 4. Step 4 produces the final %2.")
        .arg(title)
        .arg(m_mode == Mode::BtcAdaptor
            ? tr("64-byte adaptor pre-signature")
            : tr("64-byte BIP340 signature")));
    outer->addWidget(hdr);

    // Scroll area wraps the four step boxes — the dialog itself
    // becomes uncomfortably tall otherwise.
    auto* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    auto* scroll_inner = new QWidget(scroll);
    auto* steps_v = new QVBoxLayout(scroll_inner);

    // ─── Step 1: Keyagg ────────────────────────────────────────
    {
        auto* box = MakeStepBox(tr("Step 1 — Keyagg (local)"), scroll_inner);
        auto* form = new QFormLayout(box);
        m_in_my_pub   = new QLineEdit(box);
        m_in_peer_pub = new QLineEdit(box);
        m_in_my_pub->setPlaceholderText(tr("My 33-byte compressed pubkey hex"));
        m_in_peer_pub->setPlaceholderText(tr("Peer's 33-byte compressed pubkey hex"));
        form->addRow(tr("My pubkey:"),    m_in_my_pub);
        form->addRow(tr("Peer pubkey:"),  m_in_peer_pub);
        m_btn_step1 = new QPushButton(tr("Compute keyagg"), box);
        form->addRow(QString(), m_btn_step1);
        m_out_step1 = new QPlainTextEdit(box);
        MakeMono(m_out_step1);
        m_out_step1->setReadOnly(true);
        m_out_step1->setMaximumHeight(110);
        form->addRow(tr("Output:"), m_out_step1);
        form->addRow(QString(), MakeCopyPasteRow(m_out_step1, box));
        steps_v->addWidget(box);
        connect(m_btn_step1, &QPushButton::clicked, this, &CoopSignDialog::onStep1Compute);
    }

    // ─── Tx-context helper (between step 1 and step 2) ─────────
    {
        auto* box = MakeStepBox(tr("Tx context (optional helper — auto-compute sighash)"),
                                  scroll_inner);
        auto* form = new QFormLayout(box);
        form->addRow(new QLabel(tr("Calls pricoin_btc_swap_tx_build with the funding "
                                    "outpoint + recipient + amount + nlocktime; the "
                                    "resulting BIP341 sighash auto-fills the Sighash "
                                    "field below."), box));

        m_in_funding_txid = new QLineEdit(box);
        m_in_funding_txid->setPlaceholderText(tr("32-byte funding txid (auto-pulled from swap record if available)"));
        form->addRow(tr("Funding txid:"), m_in_funding_txid);

        m_in_funding_vout = new QLineEdit(box);
        m_in_funding_vout->setPlaceholderText(tr("0"));
        form->addRow(tr("Funding vout:"), m_in_funding_vout);

        m_in_funding_amount = new QLineEdit(box);
        m_in_funding_amount->setPlaceholderText(tr("Funding amount in sat"));
        form->addRow(tr("Funding amount sat:"), m_in_funding_amount);

        m_in_recipient_xonly = new QLineEdit(box);
        m_in_recipient_xonly->setPlaceholderText(tr("Recipient 32-byte x-only pubkey hex (P2TR — for claim use Bob's, for refund use Alice's)"));
        form->addRow(tr("Recipient (x-only):"), m_in_recipient_xonly);

        m_in_refund_amount = new QLineEdit(box);
        m_in_refund_amount->setPlaceholderText(tr("Output amount in sat (= funding minus fee)"));
        form->addRow(tr("Output amount sat:"), m_in_refund_amount);

        m_in_nlocktime = new QLineEdit(box);
        m_in_nlocktime->setText(m_mode == Mode::BtcAdaptor
            ? QStringLiteral("0")
            : QStringLiteral(""));
        m_in_nlocktime->setPlaceholderText(m_mode == Mode::BtcAdaptor
            ? tr("0 (claim — no timelock)")
            : tr("Refund block height (= foreign_refund_height; auto-pulled from swap record)"));
        form->addRow(tr("nlocktime:"), m_in_nlocktime);

        m_btn_compute_sighash = new QPushButton(tr("Compute sighash → fill below"), box);
        form->addRow(QString(), m_btn_compute_sighash);
        steps_v->addWidget(box);
        connect(m_btn_compute_sighash, &QPushButton::clicked, this, &CoopSignDialog::onComputeSighash);
    }

    // ─── Step 2: My round-1 ────────────────────────────────────
    {
        auto* box = MakeStepBox(tr("Step 2 — My round-1 (local; persists nonce record)"), scroll_inner);
        auto* form = new QFormLayout(box);

        m_in_my_priv = new QLineEdit(box);
        m_in_my_priv->setEchoMode(QLineEdit::Password);
        m_in_my_priv->setPlaceholderText(tr("My 32-byte priv hex (kept local)"));
        form->addRow(tr("My privkey:"), m_in_my_priv);

        m_in_msg = new QLineEdit(box);
        m_in_msg->setPlaceholderText(tr("32-byte sighash to sign (e.g. from pricoin_btc_swap_tx_build)"));
        form->addRow(tr("Sighash (msg):"), m_in_msg);

        m_in_role = new QComboBox(box);
        m_in_role->addItem(QStringLiteral("initiator"));
        m_in_role->addItem(QStringLiteral("responder"));
        form->addRow(tr("My role:"), m_in_role);

        m_in_session_id = new QLineEdit(box);
        m_in_session_id->setText(RandomHex32());
        m_in_session_id->setToolTip(tr("32-byte session id — both parties MUST use the same value"));
        form->addRow(tr("Session id:"), m_in_session_id);

        m_in_session_seed = new QLineEdit(box);
        m_in_session_seed->setText(RandomHex32());
        m_in_session_seed->setToolTip(tr("32-byte CSPRNG bytes — unique per ceremony. Do NOT regenerate "
                                          "after sending your pubnonce to the peer: a fresh seed mints a "
                                          "new nonce and desyncs the signature. Only regenerate for a "
                                          "brand-new signing session."));
        form->addRow(tr("Session seed:"), m_in_session_seed);

        m_btn_step2 = new QPushButton(tr("Run round-1 (atomic persist)"), box);
        form->addRow(QString(), m_btn_step2);

        m_out_step2 = new QPlainTextEdit(box);
        MakeMono(m_out_step2);
        m_out_step2->setReadOnly(true);
        m_out_step2->setMaximumHeight(140);
        form->addRow(tr("Output (send `pubnonce` to peer):"), m_out_step2);
        form->addRow(QString(), MakeCopyPasteRow(m_out_step2, box));

        m_btn_send_dm_round2 = new QPushButton(tr("Send pubnonce via Nostr DM"), box);
        m_btn_send_dm_round2->setEnabled(false);
        form->addRow(QString(), m_btn_send_dm_round2);

        steps_v->addWidget(box);
        connect(m_btn_step2,           &QPushButton::clicked, this, &CoopSignDialog::onStep2Compute);
        connect(m_btn_send_dm_round2,  &QPushButton::clicked, this, &CoopSignDialog::onSendDmRound2);
    }

    // ─── Step 3: Combine + my partial ──────────────────────────
    {
        auto* box = MakeStepBox(tr("Step 3 — Aggregate nonces + my partial-sign (local; consumes nonce)"), scroll_inner);
        auto* form = new QFormLayout(box);

        m_in_peer_pubnonce = new QPlainTextEdit(box);
        MakeMono(m_in_peer_pubnonce);
        m_in_peer_pubnonce->setMaximumHeight(70);
        m_in_peer_pubnonce->setPlaceholderText(tr("Peer's 66-byte pubnonce hex"));
        form->addRow(tr("Peer pubnonce:"),         m_in_peer_pubnonce);
        form->addRow(QString(), MakeCopyPasteRow(m_in_peer_pubnonce, box));

        if (m_mode == Mode::BtcAdaptor) {
            m_in_adaptor_T_G = new QLineEdit(box);
            m_in_adaptor_T_G->setPlaceholderText(tr("33-byte compressed adaptor point T_G hex (claim leg)"));
            form->addRow(tr("Adaptor T_G:"), m_in_adaptor_T_G);
        }

        m_btn_step3 = new QPushButton(tr("Combine + partial-sign"), box);
        form->addRow(QString(), m_btn_step3);

        m_out_step3 = new QPlainTextEdit(box);
        MakeMono(m_out_step3);
        m_out_step3->setReadOnly(true);
        m_out_step3->setMaximumHeight(160);
        form->addRow(tr("Output (send `partial_sig` to peer):"), m_out_step3);
        form->addRow(QString(), MakeCopyPasteRow(m_out_step3, box));

        m_btn_send_dm_round3 = new QPushButton(tr("Send partial_sig via Nostr DM"), box);
        m_btn_send_dm_round3->setEnabled(false);
        form->addRow(QString(), m_btn_send_dm_round3);

        steps_v->addWidget(box);
        connect(m_btn_step3,           &QPushButton::clicked, this, &CoopSignDialog::onStep3Compute);
        connect(m_btn_send_dm_round3,  &QPushButton::clicked, this, &CoopSignDialog::onSendDmRound3);
    }

    // ─── Step 4: Aggregate partials ────────────────────────────
    {
        auto* box = MakeStepBox(tr("Step 4 — Aggregate partials (local) → final (pre-)signature"), scroll_inner);
        auto* form = new QFormLayout(box);

        m_in_peer_partial = new QPlainTextEdit(box);
        MakeMono(m_in_peer_partial);
        m_in_peer_partial->setMaximumHeight(50);
        m_in_peer_partial->setPlaceholderText(tr("Peer's 32-byte partial-sig hex"));
        form->addRow(tr("Peer partial:"), m_in_peer_partial);
        form->addRow(QString(), MakeCopyPasteRow(m_in_peer_partial, box));

        m_btn_step4 = new QPushButton(
            m_mode == Mode::BtcAdaptor ? tr("Aggregate → adaptor pre-sig")
                                        : tr("Aggregate → final BIP340 sig"),
            box);
        form->addRow(QString(), m_btn_step4);

        m_out_step4 = new QPlainTextEdit(box);
        MakeMono(m_out_step4);
        m_out_step4->setReadOnly(true);
        m_out_step4->setMaximumHeight(110);
        form->addRow(tr("Final output:"), m_out_step4);
        form->addRow(QString(), MakeCopyPasteRow(m_out_step4, box));

        // Broadcast convenience — BtcPlain (refund) mode only. The
        // adaptor variant produces a pre-sig that needs to be
        // adapted with t before broadcast, which happens outside
        // this dialog.
        if (m_mode == Mode::BtcPlain) {
            m_btn_broadcast = new QPushButton(
                tr("Broadcast refund + watch + announce"), box);
            m_btn_broadcast->setEnabled(false);
            form->addRow(QString(), m_btn_broadcast);
            connect(m_btn_broadcast, &QPushButton::clicked, this,
                     &CoopSignDialog::onBroadcastClicked);
        }

        steps_v->addWidget(box);
        connect(m_btn_step4, &QPushButton::clicked, this, &CoopSignDialog::onStep4Compute);
    }

    steps_v->addStretch();
    scroll->setWidget(scroll_inner);
    outer->addWidget(scroll, /*stretch=*/1);

    // Status + close.
    m_status_label = new QLabel(this);
    m_status_label->setWordWrap(true);
    outer->addWidget(m_status_label);

    auto* bb = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(bb, &QDialogButtonBox::rejected, this, &QDialog::accept);
    outer->addWidget(bb);
}

void CoopSignDialog::onStep1Compute()
{
    const QString my_pub   = m_in_my_pub->text().trimmed();
    const QString peer_pub = m_in_peer_pub->text().trimmed();
    if (my_pub.size() != 66 || peer_pub.size() != 66) {
        setStatus(tr("Both pubkeys must be 33-byte (66-char) hex."), true);
        return;
    }
    // BIP327 keyagg is order-sensitive and secp256k1_musig_pubkey_agg
    // does NOT sort, so both parties MUST aggregate in the SAME order.
    // The canonical order is [alice_pub, bob_pub] — the same order
    // pricoin_swapwatch_adapt_btc_claim uses — so derive it from the
    // swap role rather than [my, peer] (which would give Alice [A,B]
    // but Bob [B,A] → different aggregate keys → Bob's pre-sig would
    // not adapt at claim time, and refund partials wouldn't aggregate).
    // When the role is unknown (dialog opened without a swap_id), fall
    // back to the legacy [my, peer] order.
    QString first = my_pub, second = peer_pub;
    if (m_swap_role == "alice") {
        first = my_pub;  second = peer_pub;   // I am alice → [my, peer]
    } else if (m_swap_role == "bob") {
        first = peer_pub; second = my_pub;    // I am bob   → [peer, my] = [alice, bob]
    }
    const std::string params = std::string("[[\"")
        + first.toStdString() + "\",\"" + second.toStdString() + "\"]]";
    auto r = callRpc("pricoin_btc_musig2_keyagg", params);
    if (!r.ok) {
        setStatus(tr("keyagg failed: %1").arg(QString::fromStdString(r.error_msg)), true);
        return;
    }
    UniValue v;
    v.read(r.json);
    m_agg_xonly    = QString::fromStdString(v["agg_xonly"].get_str());
    m_keyagg_cache = QString::fromStdString(v["keyagg_cache"].get_str());
    m_my_pub       = my_pub;
    m_out_step1->setPlainText(QString::fromStdString(r.json));
    setStatus(tr("Step 1 OK. agg_xonly = %1…").arg(m_agg_xonly.left(16)));
}

void CoopSignDialog::onStep2Compute()
{
    if (m_keyagg_cache.isEmpty()) {
        setStatus(tr("Run step 1 first."), true);
        return;
    }
    const QString my_priv = m_in_my_priv->text().trimmed();
    const QString msg     = m_in_msg->text().trimmed();
    // my_priv may be EMPTY: round1_safe/partial_sign then derive the
    // wallet's swap-identity priv internally (headless path — no raw key
    // is ever pasted). If supplied it must be a 32-byte hex.
    if (msg.size() != 64) {
        setStatus(tr("msg must be 32-byte (64-char) hex."), true);
        return;
    }
    if (!my_priv.isEmpty() && my_priv.size() != 64) {
        setStatus(tr("priv must be empty (use wallet swap-identity) or 32-byte hex."), true);
        return;
    }
    const QString role        = m_in_role->currentText();
    const QString session_id  = m_in_session_id->text().trimmed();
    const QString session_seed= m_in_session_seed->text().trimmed();
    if (session_id.size() != 64 || session_seed.size() != 64) {
        setStatus(tr("session_id and session_seed must each be 32-byte hex."), true);
        return;
    }

    // ── MuSig2 nonce idempotency guard (2026-06-06) ──────────────────
    // The secnonce/pubnonce must be generated exactly once per (session,
    // msg). Re-running Step 2 after the pubnonce was already sent to the
    // peer would mint a NEW secnonce while the peer still holds the OLD
    // pubnonce — a desync that yields an unverifiable partial/adaptor sig
    // (the BTC analogue of the 2026-06-05 PRIC round-1 desync). The
    // RPC-tier reuse record (bnr::Begin) already REJECTS nonce reuse, so
    // a naive re-run here just errors confusingly; this makes it a clean
    // no-op that re-offers the existing pubnonce. A genuine msg change
    // (rebuilt tx → new sighash) still regenerates a fresh nonce.
    if (!m_my_pubnonce.isEmpty() && !m_msg_hex.isEmpty() && m_msg_hex == msg) {
        setStatus(tr("Step 2 already done — reusing the existing pubnonce "
                     "(regenerating would desync the peer)."));
        return;
    }

    // pricoin_btc_musig2_round1_safe:
    //   (self_pub, keyagg_cache, agg_xonly, msg, role, session_id, session_seed, [self_priv])
    std::string params = std::string("[\"")
        + m_my_pub.toStdString() + "\",\""
        + m_keyagg_cache.toStdString() + "\",\""
        + m_agg_xonly.toStdString() + "\",\""
        + msg.toStdString() + "\",\""
        + role.toStdString() + "\",\""
        + session_id.toStdString() + "\",\""
        + session_seed.toStdString() + "\",\""
        + my_priv.toStdString() + "\"]";

    auto r = callRpc("pricoin_btc_musig2_round1_safe", params);
    if (!r.ok) {
        setStatus(tr("round1_safe failed: %1").arg(QString::fromStdString(r.error_msg)), true);
        return;
    }
    UniValue v;
    v.read(r.json);
    m_my_pubnonce     = QString::fromStdString(v["pubnonce"].get_str());
    m_secnonce_handle = QString::fromStdString(v["secnonce_handle"].get_str());
    m_my_priv         = my_priv;
    m_msg_hex         = msg;
    m_role            = role;
    m_out_step2->setPlainText(QString::fromStdString(r.json));
    setStatus(tr("Step 2 OK. pubnonce ready to send to peer."));
    updateNostrStatus();
}

void CoopSignDialog::onStep3Compute()
{
    if (m_secnonce_handle.isEmpty()) {
        setStatus(tr("Run step 2 first."), true);
        return;
    }
    const QString peer_pn = m_in_peer_pubnonce->toPlainText().trimmed();
    if (peer_pn.size() != 132) {
        setStatus(tr("Peer pubnonce must be 66-byte (132-char) hex."), true);
        return;
    }
    QString tg_hex;
    if (m_mode == Mode::BtcAdaptor) {
        tg_hex = m_in_adaptor_T_G ? m_in_adaptor_T_G->text().trimmed() : QString{};
        if (tg_hex.size() != 66) {
            setStatus(tr("Adaptor T_G must be 33-byte (66-char) hex."), true);
            return;
        }
    }

    // (a) aggregate_nonces
    std::string agg_params = std::string("[[\"")
        + m_my_pubnonce.toStdString() + "\",\""
        + peer_pn.toStdString() + "\"]]";
    auto r1 = callRpc("pricoin_btc_musig2_aggregate_nonces", agg_params);
    if (!r1.ok) {
        setStatus(tr("aggregate_nonces failed: %1").arg(QString::fromStdString(r1.error_msg)), true);
        return;
    }
    UniValue v1;
    v1.read(r1.json);
    const std::string aggnonce_hex = v1["aggnonce"].get_str();

    // (b) process — bind aggnonce + msg + cache (+ optional T_G)
    std::string proc_params = std::string("[\"")
        + aggnonce_hex + "\",\""
        + m_msg_hex.toStdString() + "\",\""
        + m_keyagg_cache.toStdString() + "\"";
    if (m_mode == Mode::BtcAdaptor) {
        proc_params += std::string(",\"") + tg_hex.toStdString() + "\"";
    }
    proc_params += "]";
    auto r2 = callRpc("pricoin_btc_musig2_process", proc_params);
    if (!r2.ok) {
        setStatus(tr("process failed: %1").arg(QString::fromStdString(r2.error_msg)), true);
        return;
    }
    UniValue v2;
    v2.read(r2.json);
    const std::string session_data = v2["data"].get_str();
    const int parity              = v2["nonce_parity"].getInt<int>();

    // (c) partial_sign — consumes the secnonce_handle.
    std::string sign_params = std::string("[\"")
        + m_secnonce_handle.toStdString() + "\",\""
        + m_my_priv.toStdString() + "\",\""
        + m_my_pub.toStdString() + "\",\""
        + m_keyagg_cache.toStdString()
        + "\",{\"data\":\"" + session_data
        + "\",\"nonce_parity\":" + std::to_string(parity)
        + "}]";
    auto r3 = callRpc("pricoin_btc_musig2_partial_sign", sign_params);
    if (!r3.ok) {
        setStatus(tr("partial_sign failed: %1").arg(QString::fromStdString(r3.error_msg)), true);
        return;
    }
    UniValue v3;
    v3.read(r3.json);
    m_my_partial    = QString::fromStdString(v3["partial_sig"].get_str());
    m_session_data  = QString::fromStdString(session_data);
    m_nonce_parity  = parity;
    // Combined output blob — pretty-printed for the user.
    UniValue combined{UniValue::VOBJ};
    combined.pushKV("aggnonce",     aggnonce_hex);
    combined.pushKV("session_data", session_data);
    combined.pushKV("nonce_parity", parity);
    combined.pushKV("partial_sig",  m_my_partial.toStdString());
    m_out_step3->setPlainText(QString::fromStdString(combined.write(2)));
    setStatus(tr("Step 3 OK. Send `partial_sig` to peer; keep session locally for step 4."));
    updateNostrStatus();
}

void CoopSignDialog::onStep4Compute()
{
    if (m_my_partial.isEmpty() || m_session_data.isEmpty()) {
        setStatus(tr("Run step 3 first."), true);
        return;
    }
    const QString peer_partial = m_in_peer_partial->toPlainText().trimmed();
    if (peer_partial.size() != 64) {
        setStatus(tr("Peer partial must be 32-byte (64-char) hex."), true);
        return;
    }

    // ── Verify the peer's partial BEFORE aggregating (2026-06-06) ─────
    // aggregate_partials does not validate its inputs, so a desynced or
    // forged peer partial would be silently folded into a (pre-)signature
    // that only fails later, after funds are at risk (the BTC analogue of
    // the PRIC nonce-desync incident). secp256k1_musig_partial_sig_verify
    // catches it now. Best-effort: we can only check when we hold the
    // peer's pubnonce (Step 3 input) + pubkey (Step 1 input), which the
    // normal ceremony flow always has by this point.
    {
        const QString peer_pn  = m_in_peer_pubnonce
            ? m_in_peer_pubnonce->toPlainText().trimmed() : QString{};
        const QString peer_pub = m_in_peer_pub ? m_in_peer_pub->text().trimmed() : QString{};
        if (peer_pn.size() == 132 && peer_pub.size() == 66) {
            const std::string vparams = std::string("[\"")
                + peer_partial.toStdString() + "\",\""
                + peer_pn.toStdString() + "\",\""
                + peer_pub.toStdString() + "\",\""
                + m_keyagg_cache.toStdString()
                + "\",{\"data\":\"" + m_session_data.toStdString()
                + "\",\"nonce_parity\":" + std::to_string(m_nonce_parity) + "}]";
            auto vr = callRpc("pricoin_btc_musig2_partial_verify", vparams);
            bool valid = false;
            if (vr.ok) {
                UniValue vv;
                vv.read(vr.json);
                valid = vv.exists("valid") && vv["valid"].isBool() && vv["valid"].get_bool();
            }
            if (!valid) {
                setStatus(tr("Step 4 ABORT — the peer's partial signature failed "
                             "verification (MuSig2 nonce/session desync). NOT "
                             "aggregating; the ceremony must be re-run."), true);
                return;
            }
        }
    }

    std::string params = std::string("[{\"data\":\"")
        + m_session_data.toStdString()
        + "\",\"nonce_parity\":" + std::to_string(m_nonce_parity)
        + "},[\"" + m_my_partial.toStdString()
        + "\",\"" + peer_partial.toStdString() + "\"]]";
    auto r = callRpc("pricoin_btc_musig2_aggregate_partials", params);
    if (!r.ok) {
        setStatus(tr("aggregate_partials failed: %1").arg(QString::fromStdString(r.error_msg)), true);
        return;
    }
    UniValue v;
    v.read(r.json);
    m_final_sig_hex = QString::fromStdString(v["sig"].get_str());
    UniValue out{UniValue::VOBJ};
    out.pushKV("sig",          m_final_sig_hex.toStdString());
    out.pushKV("nonce_parity", m_nonce_parity);
    out.pushKV("kind", m_mode == Mode::BtcAdaptor
        ? std::string("adaptor_pre_sig")
        : std::string("final_bip340_sig"));
    m_out_step4->setPlainText(QString::fromStdString(out.write(2)));
    setStatus(tr("Step 4 OK. Final %1 produced.")
        .arg(m_mode == Mode::BtcAdaptor ? tr("adaptor pre-signature")
                                         : tr("BIP340 signature")));
    // Enable the refund-broadcast button now that we have the
    // final sig + a saved unsigned tx_hex from sighash compute.
    if (m_btn_broadcast) {
        m_btn_broadcast->setEnabled(
            !m_final_sig_hex.isEmpty() && !m_unsigned_tx_hex.isEmpty());
    }
}

// ─── Nostr DM transport ──────────────────────────────────────────

void CoopSignDialog::updateNostrStatus()
{
    if (!m_lbl_nostr_status) return;
    if (!m_nostr) {
        m_lbl_nostr_status->setText(tr("DM relay: disconnected. Peer xonly: %1")
            .arg(m_peer_xonly.isEmpty()
                ? tr("(unknown — set by ctor swap_id)")
                : m_peer_xonly.left(16) + "…"));
        if (m_btn_send_dm_round2) m_btn_send_dm_round2->setEnabled(false);
        if (m_btn_send_dm_round3) m_btn_send_dm_round3->setEnabled(false);
        if (m_btn_nostr_connect) m_btn_nostr_connect->setText(tr("Connect Nostr DM"));
        return;
    }
    m_lbl_nostr_status->setText(
        tr("DM relay: %1/%2 connected. Peer xonly: %3")
            .arg(m_relay_connected_count)
            .arg(m_relay_urls.size())
            .arg(m_peer_xonly.isEmpty() ? tr("(unknown)") : m_peer_xonly.left(16) + "…"));
    const bool can_send = (m_relay_connected_count > 0 && !m_peer_xonly.isEmpty());
    if (m_btn_send_dm_round2) m_btn_send_dm_round2->setEnabled(
        can_send && !m_my_pubnonce.isEmpty());
    if (m_btn_send_dm_round3) m_btn_send_dm_round3->setEnabled(
        can_send && !m_my_partial.isEmpty());
    if (m_btn_nostr_connect) m_btn_nostr_connect->setText(tr("Disconnect Nostr DM"));
}

void CoopSignDialog::onNostrConnectClicked()
{
    if (m_nostr) {
        // The client is owned by WalletModel and may be in use by
        // the orderbook page or the other coopsign dialog — don't
        // destroy it. Just unhook this dialog's signals.
        m_nostr->disconnect(this);
        m_nostr = nullptr;
        m_relay_connected_count = 0;
        updateNostrStatus();
        return;
    }
    if (m_peer_xonly.isEmpty()) {
        setStatus(tr("Peer xonly unknown — DM destination cannot be determined."), true);
        return;
    }
    m_nostr = m_wm ? m_wm->getOrCreateNostrClient() : nullptr;
    if (!m_nostr) {
        setStatus(tr("No Nostr relays configured. Use Orderbook → Relay settings… first."), true);
        return;
    }
    connect(m_nostr, &PricoinNostrClient::log,
            this, &CoopSignDialog::onNostrLog);
    connect(m_nostr, &PricoinNostrClient::relayStatusChanged,
            this, &CoopSignDialog::onNostrRelayStatus);
    connect(m_nostr, &PricoinNostrClient::directMessageReceived,
            this, &CoopSignDialog::onDmReceived);
    // If the shared client isn't connected yet, kick it off. If
    // already connected (e.g., orderbook page hooked it earlier),
    // existing connections persist; relayStatusChanged signals fire
    // for any subsequent changes.
    m_relay_urls = m_nostr->relayUrls();
    if (m_nostr->connectedCount() == 0) {
        m_nostr->connectAll();
        m_relay_connected_count = 0;
    } else {
        m_relay_connected_count = m_nostr->connectedCount();
    }
    updateNostrStatus();
}

void CoopSignDialog::onNostrRelayStatus(const QString& url, bool connected)
{
    Q_UNUSED(url);
    if (connected) ++m_relay_connected_count;
    else --m_relay_connected_count;
    if (m_relay_connected_count < 0) m_relay_connected_count = 0;
    updateNostrStatus();
    // A relay just came up — flush any pending pubnonce/partial sends and
    // generally re-drive the cascade.
    if (connected) kickAutoCoord();
}

void CoopSignDialog::setHeadlessMode(bool on)
{
    m_headless = on;
    // Off-screen but still in the local event loop, and explicitly
    // non-modal so exec()'s loop doesn't freeze the main window (same
    // rationale as PricCoopSignDialog::setHeadlessMode).
    setAttribute(Qt::WA_DontShowOnScreen, on);
    if (on) {
        setWindowModality(Qt::NonModal);
        setWindowFlag(Qt::Tool, true);
        setWindowFlag(Qt::FramelessWindowHint, true);
        // The cascade advances on peer DMs, which only auto-paste when
        // this is checked.
        if (m_chk_auto_paste) m_chk_auto_paste->setChecked(true);
    }
}

void CoopSignDialog::runHeadless()
{
    setHeadlessMode(true);
    show();
    // Bring up the DM transport so pubnonce/partial exchange can flow.
    if (m_nostr == nullptr || m_relay_connected_count == 0) {
        onNostrConnectClicked();
    }
    QEventLoop loop;
    connect(this, &QDialog::finished, &loop, &QEventLoop::quit);
    // Kick after the loop is running so the first synchronous steps
    // (keyagg → sighash → nonce → send pubnonce) execute, then we idle
    // until the peer's DMs drive the rest.
    QMetaObject::invokeMethod(this, [this]{ kickAutoCoord(); }, Qt::QueuedConnection);
    loop.exec();
}

void CoopSignDialog::kickAutoCoord()
{
    if (!m_headless) return;

    // 1. Keyagg (canonical [alice,bob] order, set in onStep1Compute).
    if (!m_auto_step1_fired
        && m_in_my_pub   && m_in_my_pub->text().trimmed().size() == 66
        && m_in_peer_pub && m_in_peer_pub->text().trimmed().size() == 66) {
        m_auto_step1_fired = true;
        onStep1Compute();
        if (m_agg_xonly.isEmpty()) { m_auto_step1_fired = false; return; }
    }

    // 2. Compute the sighash → msg (only if not already populated).
    if (!m_agg_xonly.isEmpty() && !m_auto_sighash_fired
        && m_in_msg && m_in_msg->text().trimmed().isEmpty()) {
        m_auto_sighash_fired = true;
        onComputeSighash();
        if (m_in_msg->text().trimmed().size() != 64) m_auto_sighash_fired = false;
    }

    // 3. Round-1 nonce (my_priv left empty → wallet-derived).
    if (!m_auto_step2_fired && !m_agg_xonly.isEmpty()
        && m_in_msg && m_in_msg->text().trimmed().size() == 64) {
        m_auto_step2_fired = true;
        onStep2Compute();
        if (m_my_pubnonce.isEmpty()) { m_auto_step2_fired = false; return; }
    }

    // 4. Send my pubnonce to the peer.
    if (!m_auto_pn_sent && !m_my_pubnonce.isEmpty()
        && m_nostr && m_relay_connected_count > 0 && !m_peer_xonly.isEmpty()) {
        m_auto_pn_sent = true;
        onSendDmRound2();
    }

    // 5. Combine + my partial (needs the peer's pubnonce).
    if (!m_auto_step3_fired && !m_my_pubnonce.isEmpty()
        && m_in_peer_pubnonce
        && m_in_peer_pubnonce->toPlainText().trimmed().size() == 132) {
        m_auto_step3_fired = true;
        onStep3Compute();
        if (m_my_partial.isEmpty()) { m_auto_step3_fired = false; return; }
    }

    // 6. Send my partial to the peer.
    if (!m_auto_partial_sent && !m_my_partial.isEmpty()
        && m_nostr && m_relay_connected_count > 0 && !m_peer_xonly.isEmpty()) {
        m_auto_partial_sent = true;
        onSendDmRound3();
    }

    // 7. Aggregate → final (pre-)sig (needs the peer's partial). This runs
    // the partial-verify gate; on success we accept() to end runHeadless().
    if (!m_auto_step4_fired && !m_my_partial.isEmpty()
        && m_in_peer_partial
        && m_in_peer_partial->toPlainText().trimmed().size() == 64) {
        m_auto_step4_fired = true;
        onStep4Compute();
        if (!m_final_sig_hex.isEmpty()) {
            QMetaObject::invokeMethod(this, [this]{ accept(); }, Qt::QueuedConnection);
        } else {
            m_auto_step4_fired = false;  // verify failed / error — allow retry
        }
    }
}

void CoopSignDialog::onNostrLog(const QString& msg)
{
    setStatus(msg);
}

void CoopSignDialog::onSendDmRound2()
{
    if (!m_nostr || m_my_pubnonce.isEmpty() || m_peer_xonly.isEmpty()) return;
    UniValue env{UniValue::VOBJ};
    env.pushKV("v",        1);
    env.pushKV("leg",      m_mode == Mode::BtcAdaptor ? "btc_claim_adaptor"
                                                       : "btc_refund");
    env.pushKV("swap_id",  m_swap_id.toStdString());
    env.pushKV("round",    2);
    env.pushKV("pubnonce", m_my_pubnonce.toStdString());
    const QString plaintext = QString::fromStdString(env.write(0));
    if (m_nostr->publishDirectMessage(m_peer_xonly, plaintext)) {
        setStatus(tr("Round-1 pubnonce DM sent."));
    }
}

void CoopSignDialog::onSendDmRound3()
{
    if (!m_nostr || m_my_partial.isEmpty() || m_peer_xonly.isEmpty()) return;
    UniValue env{UniValue::VOBJ};
    env.pushKV("v",        1);
    env.pushKV("leg",      m_mode == Mode::BtcAdaptor ? "btc_claim_adaptor"
                                                       : "btc_refund");
    env.pushKV("swap_id",  m_swap_id.toStdString());
    env.pushKV("round",    3);
    env.pushKV("partial",  m_my_partial.toStdString());
    const QString plaintext = QString::fromStdString(env.write(0));
    if (m_nostr->publishDirectMessage(m_peer_xonly, plaintext)) {
        setStatus(tr("Round-2 partial DM sent."));
    }
}

void CoopSignDialog::onBroadcastClicked()
{
    if (m_mode != Mode::BtcPlain) return;  // claim path adapts elsewhere
    if (m_final_sig_hex.isEmpty() || m_unsigned_tx_hex.isEmpty()) {
        setStatus(tr("Need step 4 final sig + sighash-compute output first."), true);
        return;
    }
    if (m_swap_id.isEmpty()) {
        setStatus(tr("No swap_id — open this dialog from the Swaps page."), true);
        return;
    }

    // Step 1: pricoin_btc_swap_tx_finalize(tx_hex, sig64) → broadcastable hex.
    {
        UniValue p{UniValue::VARR};
        p.push_back(m_unsigned_tx_hex.toStdString());
        p.push_back(m_final_sig_hex.toStdString());
        auto r = callRpc("pricoin_btc_swap_tx_finalize", p.write(0));
        if (!r.ok) {
            setStatus(tr("Finalize failed: %1").arg(QString::fromStdString(r.error_msg)), true);
            return;
        }
        UniValue v;
        v.read(r.json);
        m_unsigned_tx_hex = QString::fromStdString(v["tx_hex"].get_str());
    }

    // Step 2: pricoin_swapwatch_broadcast_foreign(swap_id, foreign_refund, tx_hex, 1).
    QString broadcast_txid;
    {
        UniValue p{UniValue::VARR};
        p.push_back(m_swap_id.toStdString());
        p.push_back("foreign_refund");
        p.push_back(m_unsigned_tx_hex.toStdString());
        p.push_back(1);  // min_confirmations
        auto r = callRpc("pricoin_swapwatch_broadcast_foreign", p.write(0));
        if (!r.ok) {
            setStatus(tr("Broadcast failed: %1").arg(QString::fromStdString(r.error_msg)), true);
            return;
        }
        UniValue v;
        v.read(r.json);
        broadcast_txid = QString::fromStdString(v["txid"].get_str());
    }

    // Step 3: announce to peer via Nostr (best effort).
    if (m_nostr && m_relay_connected_count > 0 && !m_peer_xonly.isEmpty()) {
        m_nostr->publishBroadcastAnnouncement(
            m_peer_xonly, m_swap_id, "foreign_refund",
            broadcast_txid, /*vout=*/-1, /*min_conf=*/1);
    }
    setStatus(tr("Broadcast OK — txid %1… (announced to peer if connected).")
        .arg(broadcast_txid.left(16)));
}

void CoopSignDialog::onDmReceived(const QString& from_xonly_hex,
                                    const QString& plaintext)
{
    // Filter: only DMs from this swap's counterparty.
    if (!m_peer_xonly.isEmpty() && from_xonly_hex != m_peer_xonly) return;
    UniValue env;
    if (!env.read(plaintext.toStdString()) || !env.isObject()) {
        return;
    }
    if (env.exists("swap_id")
        && env["swap_id"].get_str() != m_swap_id.toStdString()
        && !m_swap_id.isEmpty()) {
        return;  // different swap, ignore
    }
    if (!m_chk_auto_paste || !m_chk_auto_paste->isChecked()) {
        setStatus(tr("Peer DM received (auto-paste disabled — use Paste buttons)."));
        return;
    }
    if (!env.exists("round")) return;
    const int round = env["round"].getInt<int>();
    if (round == 2 && env.exists("pubnonce") && m_in_peer_pubnonce) {
        m_in_peer_pubnonce->setPlainText(
            QString::fromStdString(env["pubnonce"].get_str()));
        setStatus(m_headless ? tr("Peer pubnonce received — auto-advancing.")
                             : tr("Peer pubnonce auto-pasted from DM. Run step 3."));
    } else if (round == 3 && env.exists("partial") && m_in_peer_partial) {
        m_in_peer_partial->setPlainText(
            QString::fromStdString(env["partial"].get_str()));
        setStatus(m_headless ? tr("Peer partial received — auto-advancing.")
                             : tr("Peer partial auto-pasted from DM. Run step 4."));
    }
    // Headless: a peer DM just landed — advance the cascade (combine on
    // pubnonce, aggregate on partial).
    kickAutoCoord();
}
