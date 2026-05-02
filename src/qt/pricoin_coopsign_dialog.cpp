// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pricoin_coopsign_dialog.h>

#include <interfaces/node.h>
#include <qt/walletmodel.h>
#include <random.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QDialogButtonBox>
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
      m_mode(mode)
{
    setModal(true);
    resize(820, 740);
    buildLayout(title);

    // If a swap_id was given, pre-fill what we can from the wallet's
    // adaptor-swap record. Saves the user from re-typing fields the
    // wallet already knows.
    if (!swap_id.empty() && m_wm) {
        auto snap = m_wm->wallet().adaptorSwapGet(swap_id);
        if (snap) {
            // Peer pubkey: the swap's counterparty_pubkey, 33-byte
            // compressed already.
            if (m_in_peer_pub && !snap->counterparty_pubkey_hex.empty()) {
                m_in_peer_pub->setText(QString::fromStdString(snap->counterparty_pubkey_hex));
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
    if (m_in_msg) m_in_msg->setText(sighash);
    setStatus(tr("Sighash auto-filled (%1…). Proceed to step 2.").arg(sighash.left(16)));
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
        m_in_session_seed->setToolTip(tr("32-byte CSPRNG bytes — must be unique per call (regenerate if running again)"));
        form->addRow(tr("Session seed:"), m_in_session_seed);

        m_btn_step2 = new QPushButton(tr("Run round-1 (atomic persist)"), box);
        form->addRow(QString(), m_btn_step2);

        m_out_step2 = new QPlainTextEdit(box);
        MakeMono(m_out_step2);
        m_out_step2->setReadOnly(true);
        m_out_step2->setMaximumHeight(140);
        form->addRow(tr("Output (send `pubnonce` to peer):"), m_out_step2);
        form->addRow(QString(), MakeCopyPasteRow(m_out_step2, box));

        steps_v->addWidget(box);
        connect(m_btn_step2, &QPushButton::clicked, this, &CoopSignDialog::onStep2Compute);
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

        steps_v->addWidget(box);
        connect(m_btn_step3, &QPushButton::clicked, this, &CoopSignDialog::onStep3Compute);
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
    // BIP327 keyagg is order-sensitive; the convention here is the
    // user enters [my, peer] consistently. The peer must use the
    // SAME order on their side or the agg_xonly won't match.
    const std::string params = std::string("[[\"")
        + my_pub.toStdString() + "\",\"" + peer_pub.toStdString() + "\"]]";
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
    if (my_priv.size() != 64 || msg.size() != 64) {
        setStatus(tr("priv and msg must each be 32-byte (64-char) hex."), true);
        return;
    }
    const QString role        = m_in_role->currentText();
    const QString session_id  = m_in_session_id->text().trimmed();
    const QString session_seed= m_in_session_seed->text().trimmed();
    if (session_id.size() != 64 || session_seed.size() != 64) {
        setStatus(tr("session_id and session_seed must each be 32-byte hex."), true);
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
}

void CoopSignDialog::onCopyButton() {}
void CoopSignDialog::onPasteButton() {}
