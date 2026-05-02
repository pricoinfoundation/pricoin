// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pricoin_pric_coopsign_dialog.h>

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
#include <QUrl>
#include <QVBoxLayout>

#include <stdexcept>

namespace {

QGroupBox* MakeStepBox(const QString& title, QWidget* parent)
{
    auto* box = new QGroupBox(title, parent);
    box->setStyleSheet(QStringLiteral("QGroupBox { font-weight: bold; }"));
    return box;
}

// Three-button row hanging below an output text area for clipboard
// shuttling during inter-party blob exchange. (Same as the BTC
// dialog — could share, but the duplication is trivial.)
QHBoxLayout* MakeCopyPasteRow(QPlainTextEdit* edit)
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

void MakeMono(QPlainTextEdit* edit)
{
    edit->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    edit->setLineWrapMode(QPlainTextEdit::WidgetWidth);
}

} // namespace

PricCoopSignDialog::PricCoopSignDialog(WalletModel* wallet_model,
                                        Mode mode,
                                        const QString& title,
                                        QWidget* parent)
    : QDialog(parent),
      m_wm(wallet_model),
      m_mode(mode)
{
    setModal(true);
    resize(880, 900);
    buildLayout(title);
}

QString PricCoopSignDialog::RandomHex32()
{
    unsigned char buf[32];
    GetStrongRandBytes(buf);
    return QString::fromStdString(HexStr(std::span<const unsigned char>{buf, 32}));
}

PricCoopSignDialog::RpcResult
PricCoopSignDialog::callRpc(const std::string& method, const std::string& params_json)
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

void PricCoopSignDialog::setStatus(const QString& msg, bool error)
{
    if (!m_status_label) return;
    m_status_label->setStyleSheet(error
        ? QStringLiteral("QLabel { color: #b71c1c; }")
        : QStringLiteral("QLabel { color: #1b5e20; }"));
    m_status_label->setText(msg);
}

void PricCoopSignDialog::buildLayout(const QString& title)
{
    setWindowTitle(title);
    const bool adaptor = (m_mode == Mode::PricAdaptor);

    auto* outer = new QVBoxLayout(this);

    auto* hdr = new QLabel(this);
    hdr->setWordWrap(true);
    hdr->setText(tr(
        "<b>%1</b><br/>"
        "Cooperative %2 CLSAG sign — fill the inputs, then run the "
        "four steps in order. Step 1 is local-only. After step 1, "
        "send your share JSON to your peer; paste theirs into step "
        "2. After step 3, send your <code>s_share</code> to your "
        "peer; paste theirs into step 4. Step 4 produces the final "
        "%3.")
        .arg(title)
        .arg(adaptor ? tr("single-layer adaptor") : tr("multi-layer plain"))
        .arg(adaptor ? tr("AdaptorPreSignature blob")
                      : tr("CLSAG signature blob")));
    outer->addWidget(hdr);

    auto* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    auto* scroll_inner = new QWidget(scroll);
    auto* steps_v = new QVBoxLayout(scroll_inner);

    // ─── Inputs box ────────────────────────────────────────────
    {
        auto* box = MakeStepBox(tr("Inputs (from buildtx + loadshare + your role)"),
                                  scroll_inner);
        auto* form = new QFormLayout(box);

        m_in_x_share = new QLineEdit(box);
        m_in_x_share->setEchoMode(QLineEdit::Password);
        m_in_x_share->setPlaceholderText(tr("32-byte spend-secret share from loadshare"));
        form->addRow(tr("x_share:"), m_in_x_share);

        if (!adaptor) {
            m_in_z_share = new QLineEdit(box);
            m_in_z_share->setEchoMode(QLineEdit::Password);
            m_in_z_share->setPlaceholderText(tr("32-byte commitment-offset share (multi-layer): z_self for spender, z_other for peer"));
            form->addRow(tr("z_share:"), m_in_z_share);
        }

        m_in_joint_pubkey = new QLineEdit(box);
        m_in_joint_pubkey->setPlaceholderText(tr("33-byte joint pubkey at ring[pi].P (the joint stealth one-time pubkey)"));
        form->addRow(tr("joint_pubkey (P_pi):"), m_in_joint_pubkey);

        m_in_msg = new QLineEdit(box);
        m_in_msg->setPlaceholderText(tr("32-byte sighash from buildtx"));
        form->addRow(tr("msg / sighash:"), m_in_msg);

        m_in_pi = new QLineEdit(box);
        m_in_pi->setPlaceholderText(tr("Signer index in ring (from buildtx)"));
        form->addRow(tr("pi:"), m_in_pi);

        m_in_session_id = new QLineEdit(box);
        m_in_session_id->setText(RandomHex32());
        m_in_session_id->setToolTip(tr("32-byte session id — both parties MUST use the same value"));
        form->addRow(tr("session_id:"), m_in_session_id);

        m_in_ring_hash = new QLineEdit(box);
        m_in_ring_hash->setPlaceholderText(tr("32-byte hash of the ring being signed"));
        form->addRow(tr("ring_hash:"), m_in_ring_hash);

        m_in_joint_output_id = new QLineEdit(box);
        m_in_joint_output_id->setPlaceholderText(tr("UTXO id being spent (e.g. txid:vout encoded as bytes)"));
        form->addRow(tr("joint_output_id:"), m_in_joint_output_id);

        m_in_role = new QComboBox(box);
        m_in_role->addItem(QStringLiteral("initiator"));
        m_in_role->addItem(QStringLiteral("responder"));
        form->addRow(tr("role:"), m_in_role);

        if (adaptor) {
            m_in_X_pub_X = new QLineEdit(box);
            m_in_X_pub_X->setPlaceholderText(tr("33-byte public spend share = x_share · G"));
            form->addRow(tr("X_pub_X (mine):"), m_in_X_pub_X);

            m_in_T_G = new QLineEdit(box);
            m_in_T_G->setPlaceholderText(tr("33-byte adaptor point T_G = t · G"));
            form->addRow(tr("T_G:"), m_in_T_G);

            m_in_T_H = new QLineEdit(box);
            m_in_T_H->setPlaceholderText(tr("33-byte adaptor point T_H = t · H_p(P_pi)"));
            form->addRow(tr("T_H:"), m_in_T_H);

            m_in_dleq_t = new QPlainTextEdit(box);
            MakeMono(m_in_dleq_t);
            m_in_dleq_t->setMaximumHeight(60);
            m_in_dleq_t->setPlaceholderText(tr("Serialized DLEQProof bytes binding T_G/T_H to t (hex)"));
            form->addRow(tr("dleq_t:"), m_in_dleq_t);

            m_in_session_label = new QLineEdit(box);
            m_in_session_label->setPlaceholderText(tr("Session label (plaintext or hex)"));
            form->addRow(tr("session_label:"), m_in_session_label);

            m_in_session_payload = new QLineEdit(box);
            m_in_session_payload->setPlaceholderText(tr("Session payload (plaintext or hex)"));
            form->addRow(tr("session_payload:"), m_in_session_payload);
        }

        m_in_ring_or_ring_ml = new QPlainTextEdit(box);
        MakeMono(m_in_ring_or_ring_ml);
        m_in_ring_or_ring_ml->setMaximumHeight(110);
        m_in_ring_or_ring_ml->setPlaceholderText(adaptor
            ? tr("ring as JSON array of pubkey hex strings, e.g. [\"<P0>\",\"<P1>\",...]")
            : tr("ring_ml as JSON array of {P,W} objects, e.g. [{\"P\":\"<P0>\",\"W\":\"<W0>\"},...]"));
        form->addRow(adaptor ? tr("ring (JSON):") : tr("ring_ml (JSON):"),
                      m_in_ring_or_ring_ml);

        steps_v->addWidget(box);
    }

    // ─── Step 1: My round 1 ────────────────────────────────────
    {
        auto* box = MakeStepBox(tr("Step 1 — My round 1 (local; persists §4.1a nonce record)"),
                                  scroll_inner);
        auto* layout = new QVBoxLayout(box);
        m_btn_step1 = new QPushButton(adaptor
            ? tr("Run adaptor_round1")
            : tr("Run round1_safe"), box);
        layout->addWidget(m_btn_step1);
        m_out_step1 = new QPlainTextEdit(box);
        MakeMono(m_out_step1);
        m_out_step1->setReadOnly(true);
        m_out_step1->setMaximumHeight(180);
        layout->addWidget(new QLabel(tr("Output (send to peer; alpha is omitted/secret):"), box));
        layout->addWidget(m_out_step1);
        layout->addLayout(MakeCopyPasteRow(m_out_step1));
        steps_v->addWidget(box);
        connect(m_btn_step1, &QPushButton::clicked, this, &PricCoopSignDialog::onStep1Compute);
    }

    // ─── Step 2: Combine ───────────────────────────────────────
    {
        auto* box = MakeStepBox(tr("Step 2 — Combine (paste peer's round-1 share)"),
                                  scroll_inner);
        auto* layout = new QVBoxLayout(box);
        layout->addWidget(new QLabel(tr("Peer's round-1 share JSON (the object returned by their step 1):"), box));
        m_in_peer_share_json = new QPlainTextEdit(box);
        MakeMono(m_in_peer_share_json);
        m_in_peer_share_json->setMaximumHeight(140);
        m_in_peer_share_json->setPlaceholderText(tr("{\"L_share\":\"...\",\"R_share\":\"...\",\"KI_share\":\"...\",\"D_share\":\"...\"(plain only),\"dleq_alpha\":\"...\"(adaptor only),\"dleq_x\":\"...\"(adaptor only),\"commitment\":\"...\"}"));
        layout->addWidget(m_in_peer_share_json);
        layout->addLayout(MakeCopyPasteRow(m_in_peer_share_json));

        if (adaptor) {
            auto* peer_pub_row = new QFormLayout();
            m_in_X_pub_peer = new QLineEdit(box);
            m_in_X_pub_peer->setPlaceholderText(tr("33-byte public spend share = peer's x · G"));
            peer_pub_row->addRow(tr("Peer X_pub:"), m_in_X_pub_peer);
            layout->addLayout(peer_pub_row);
        } else {
            layout->addWidget(new QLabel(tr("s_others (decoy closing scalars, JSON array of 32-byte hex; entry at pi will be ignored — fill with zeros):"), box));
            m_in_s_others_seed_json = new QPlainTextEdit(box);
            MakeMono(m_in_s_others_seed_json);
            m_in_s_others_seed_json->setMaximumHeight(80);
            m_in_s_others_seed_json->setPlaceholderText(tr("[\"<s0>\",\"<s1>\",\"<s2>\",\"<s3>\"]"));
            layout->addWidget(m_in_s_others_seed_json);
            layout->addLayout(MakeCopyPasteRow(m_in_s_others_seed_json));
        }

        m_btn_step2 = new QPushButton(adaptor
            ? tr("Run adaptor_combine")
            : tr("Run combine"), box);
        layout->addWidget(m_btn_step2);
        m_out_step2 = new QPlainTextEdit(box);
        MakeMono(m_out_step2);
        m_out_step2->setReadOnly(true);
        m_out_step2->setMaximumHeight(180);
        layout->addWidget(new QLabel(tr("Output:"), box));
        layout->addWidget(m_out_step2);
        layout->addLayout(MakeCopyPasteRow(m_out_step2));
        steps_v->addWidget(box);
        connect(m_btn_step2, &QPushButton::clicked, this, &PricCoopSignDialog::onStep2Compute);
    }

    // ─── Step 3: My round 3 (s_share) ──────────────────────────
    {
        auto* box = MakeStepBox(tr("Step 3 — My round 3 / close share (local)"), scroll_inner);
        auto* layout = new QVBoxLayout(box);
        m_btn_step3 = new QPushButton(tr("Run share"), box);
        layout->addWidget(m_btn_step3);
        m_out_step3 = new QPlainTextEdit(box);
        MakeMono(m_out_step3);
        m_out_step3->setReadOnly(true);
        m_out_step3->setMaximumHeight(70);
        layout->addWidget(new QLabel(tr("Output (send `s_share` to peer):"), box));
        layout->addWidget(m_out_step3);
        layout->addLayout(MakeCopyPasteRow(m_out_step3));
        steps_v->addWidget(box);
        connect(m_btn_step3, &QPushButton::clicked, this, &PricCoopSignDialog::onStep3Compute);
    }

    // ─── Step 4: Assemble ──────────────────────────────────────
    {
        auto* box = MakeStepBox(tr("Step 4 — Assemble (paste peer's s_share)"), scroll_inner);
        auto* layout = new QVBoxLayout(box);
        auto* form_peer = new QFormLayout();
        m_in_peer_s_share = new QLineEdit(box);
        m_in_peer_s_share->setPlaceholderText(tr("32-byte hex"));
        form_peer->addRow(tr("Peer s_share:"), m_in_peer_s_share);
        layout->addLayout(form_peer);
        m_btn_step4 = new QPushButton(adaptor
            ? tr("Run adaptor_assemble → AdaptorPreSignature")
            : tr("Run assemble → final CLSAG signature"), box);
        layout->addWidget(m_btn_step4);
        m_out_step4 = new QPlainTextEdit(box);
        MakeMono(m_out_step4);
        m_out_step4->setReadOnly(true);
        m_out_step4->setMaximumHeight(180);
        layout->addWidget(new QLabel(tr("Final blob:"), box));
        layout->addWidget(m_out_step4);
        layout->addLayout(MakeCopyPasteRow(m_out_step4));
        steps_v->addWidget(box);
        connect(m_btn_step4, &QPushButton::clicked, this, &PricCoopSignDialog::onStep4Compute);
    }

    steps_v->addStretch();
    scroll->setWidget(scroll_inner);
    outer->addWidget(scroll, /*stretch=*/1);

    m_status_label = new QLabel(this);
    m_status_label->setWordWrap(true);
    outer->addWidget(m_status_label);

    auto* bb = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(bb, &QDialogButtonBox::rejected, this, &QDialog::accept);
    outer->addWidget(bb);
}

void PricCoopSignDialog::onStep1Compute()
{
    const bool adaptor = (m_mode == Mode::PricAdaptor);

    m_x_share          = m_in_x_share->text().trimmed();
    if (!adaptor) {
        m_z_share = m_in_z_share->text().trimmed();
    }
    const QString joint_pubkey = m_in_joint_pubkey->text().trimmed();
    m_msg_hex          = m_in_msg->text().trimmed();
    m_pi               = m_in_pi->text().trimmed();
    m_session_id       = m_in_session_id->text().trimmed();
    m_ring_hash        = m_in_ring_hash->text().trimmed();
    m_joint_output_id  = m_in_joint_output_id->text().trimmed();
    m_role             = m_in_role->currentText();
    m_ring_ml_json     = adaptor ? QString{} : m_in_ring_or_ring_ml->toPlainText().trimmed();
    m_ring_json        = adaptor ? m_in_ring_or_ring_ml->toPlainText().trimmed() : QString{};
    if (adaptor) {
        m_X_pub_X        = m_in_X_pub_X->text().trimmed();
        m_T_G            = m_in_T_G->text().trimmed();
        m_T_H            = m_in_T_H->text().trimmed();
        m_dleq_t         = m_in_dleq_t->toPlainText().trimmed();
        m_session_label  = m_in_session_label->text().trimmed();
        m_session_payload= m_in_session_payload->text().trimmed();
    }

    // Sanity checks — cheap and gives the user better errors than
    // the RPC-internal validation messages.
    if (m_x_share.size() != 64) { setStatus(tr("x_share must be 32-byte hex"), true); return; }
    if (joint_pubkey.size() != 66) { setStatus(tr("joint_pubkey must be 33-byte hex"), true); return; }
    if (m_msg_hex.size() != 64) { setStatus(tr("msg must be 32-byte hex"), true); return; }
    if (m_session_id.size() != 64) { setStatus(tr("session_id must be 32-byte hex"), true); return; }

    if (adaptor) {
        // pricoin_jointspend_adaptor_round1(P_pi, X_pub_X, x_X, T_G, T_H, label, payload)
        std::string params = std::string("[\"")
            + joint_pubkey.toStdString() + "\",\""
            + m_X_pub_X.toStdString()    + "\",\""
            + m_x_share.toStdString()    + "\",\""
            + m_T_G.toStdString()        + "\",\""
            + m_T_H.toStdString()        + "\",\""
            + m_session_label.toStdString()   + "\",\""
            + m_session_payload.toStdString() + "\"]";
        auto r = callRpc("pricoin_jointspend_adaptor_round1", params);
        if (!r.ok) {
            setStatus(tr("adaptor_round1 failed: %1").arg(QString::fromStdString(r.error_msg)), true);
            return;
        }
        UniValue v;
        v.read(r.json);
        m_alpha          = QString::fromStdString(v["alpha"].get_str());
        m_my_L_share     = QString::fromStdString(v["L_share"].get_str());
        m_my_R_share     = QString::fromStdString(v["R_share"].get_str());
        m_my_KI_share    = QString::fromStdString(v["KI_share"].get_str());
        m_my_dleq_alpha  = QString::fromStdString(v["dleq_alpha"].get_str());
        m_my_dleq_x      = QString::fromStdString(v["dleq_x"].get_str());
        m_my_commitment  = QString::fromStdString(v["commitment"].get_str());
        // Strip alpha from the displayed JSON — it must NEVER leave
        // the wallet before round 3. Show the rest as the share to
        // hand to the peer.
        UniValue share_for_peer{UniValue::VOBJ};
        share_for_peer.pushKV("L_share",    v["L_share"]);
        share_for_peer.pushKV("R_share",    v["R_share"]);
        share_for_peer.pushKV("KI_share",   v["KI_share"]);
        share_for_peer.pushKV("dleq_alpha", v["dleq_alpha"]);
        share_for_peer.pushKV("dleq_x",     v["dleq_x"]);
        share_for_peer.pushKV("commitment", v["commitment"]);
        m_out_step1->setPlainText(QString::fromStdString(share_for_peer.write(2)));
    } else {
        // pricoin_jointspend_round1_safe(joint_pubkey, x_share, session_id, joint_output_id, ring_hash, role, [z_share])
        std::string params = std::string("[\"")
            + joint_pubkey.toStdString() + "\",\""
            + m_x_share.toStdString()    + "\",\""
            + m_session_id.toStdString() + "\",\""
            + m_joint_output_id.toStdString() + "\",\""
            + m_ring_hash.toStdString()  + "\",\""
            + m_role.toStdString() + "\"";
        if (!m_z_share.isEmpty()) {
            params += std::string(",\"") + m_z_share.toStdString() + "\"";
        }
        params += "]";
        auto r = callRpc("pricoin_jointspend_round1_safe", params);
        if (!r.ok) {
            setStatus(tr("round1_safe failed: %1").arg(QString::fromStdString(r.error_msg)), true);
            return;
        }
        UniValue v;
        v.read(r.json);
        m_alpha          = QString::fromStdString(v["alpha"].get_str());
        m_my_L_share     = QString::fromStdString(v["L_share"].get_str());
        m_my_R_share     = QString::fromStdString(v["R_share"].get_str());
        m_my_KI_share    = QString::fromStdString(v["KI_share"].get_str());
        if (v.exists("D_share")) {
            m_my_D_share = QString::fromStdString(v["D_share"].get_str());
        }
        m_my_commitment  = QString::fromStdString(v["commitment"].get_str());
        UniValue share_for_peer{UniValue::VOBJ};
        share_for_peer.pushKV("L_share",  v["L_share"]);
        share_for_peer.pushKV("R_share",  v["R_share"]);
        share_for_peer.pushKV("KI_share", v["KI_share"]);
        if (v.exists("D_share")) {
            share_for_peer.pushKV("D_share", v["D_share"]);
        }
        share_for_peer.pushKV("commitment", v["commitment"]);
        m_out_step1->setPlainText(QString::fromStdString(share_for_peer.write(2)));
    }
    setStatus(tr("Step 1 OK. alpha kept locally; share JSON ready for peer."));
}

void PricCoopSignDialog::onStep2Compute()
{
    if (m_my_commitment.isEmpty()) {
        setStatus(tr("Run step 1 first."), true);
        return;
    }
    const bool adaptor = (m_mode == Mode::PricAdaptor);

    UniValue peer{UniValue::VOBJ};
    if (!peer.read(m_in_peer_share_json->toPlainText().trimmed().toStdString()) || !peer.isObject()) {
        setStatus(tr("Peer share JSON not parseable as an object"), true);
        return;
    }

    if (adaptor) {
        // Build X_pub_shares array — convention here is initiator
        // first, responder second. The peer's role is the opposite of
        // mine.
        const QString peer_pub = m_in_X_pub_peer->text().trimmed();
        if (peer_pub.size() != 66) {
            setStatus(tr("Peer X_pub must be 33-byte hex"), true);
            return;
        }
        const QString first_pub  = (m_role == "initiator") ? m_X_pub_X : peer_pub;
        const QString second_pub = (m_role == "initiator") ? peer_pub  : m_X_pub_X;

        // Per-party shares array — same role-ordered.
        UniValue mine_share{UniValue::VOBJ};
        mine_share.pushKV("L_share",    m_my_L_share.toStdString());
        mine_share.pushKV("R_share",    m_my_R_share.toStdString());
        mine_share.pushKV("KI_share",   m_my_KI_share.toStdString());
        mine_share.pushKV("dleq_alpha", m_my_dleq_alpha.toStdString());
        mine_share.pushKV("dleq_x",     m_my_dleq_x.toStdString());
        mine_share.pushKV("commitment", m_my_commitment.toStdString());

        UniValue first_share  = (m_role == "initiator") ? mine_share : peer;
        UniValue second_share = (m_role == "initiator") ? peer       : mine_share;

        UniValue params{UniValue::VARR};
        // ring (parsed from JSON)
        UniValue ring_v;
        if (!ring_v.read(m_ring_json.toStdString()) || !ring_v.isArray()) {
            setStatus(tr("ring must be a JSON array of pubkey hex strings"), true);
            return;
        }
        params.push_back(ring_v);
        params.push_back(m_pi.toInt());
        params.push_back(m_msg_hex.toStdString());
        params.push_back(m_T_G.toStdString());
        params.push_back(m_T_H.toStdString());
        params.push_back(m_dleq_t.toStdString());
        UniValue Xs{UniValue::VARR};
        Xs.push_back(first_pub.toStdString());
        Xs.push_back(second_pub.toStdString());
        params.push_back(Xs);
        UniValue shares_arr{UniValue::VARR};
        shares_arr.push_back(first_share);
        shares_arr.push_back(second_share);
        params.push_back(shares_arr);
        params.push_back(m_session_label.toStdString());
        params.push_back(m_session_payload.toStdString());

        auto r = callRpc("pricoin_jointspend_adaptor_combine", params.write(0));
        if (!r.ok) {
            setStatus(tr("adaptor_combine failed: %1").arg(QString::fromStdString(r.error_msg)), true);
            return;
        }
        UniValue v;
        v.read(r.json);
        m_KI       = QString::fromStdString(v["KI"].get_str());
        m_L_pi     = QString::fromStdString(v["L_pi"].get_str());
        m_R_pi     = QString::fromStdString(v["R_pi"].get_str());
        m_L_prime  = QString::fromStdString(v["L_prime"].get_str());
        m_R_prime  = QString::fromStdString(v["R_prime"].get_str());
        m_c_pi     = QString::fromStdString(v["c_pi"].get_str());
        m_c0       = QString::fromStdString(v["c0"].get_str());
        // Echo s_others verbatim — needed at assemble.
        m_s_others_json = QString::fromStdString(v["s_others"].write(0));
        m_out_step2->setPlainText(QString::fromStdString(r.json));
    } else {
        // Plain combine.
        UniValue ring_ml_v;
        if (!ring_ml_v.read(m_ring_ml_json.toStdString()) || !ring_ml_v.isArray()) {
            setStatus(tr("ring_ml must be a JSON array of {P,W} objects"), true);
            return;
        }
        UniValue s_others_v;
        if (!s_others_v.read(m_in_s_others_seed_json->toPlainText().trimmed().toStdString())
            || !s_others_v.isArray()) {
            setStatus(tr("s_others seed must be a JSON array"), true);
            return;
        }

        UniValue mine_share{UniValue::VOBJ};
        mine_share.pushKV("L_share",  m_my_L_share.toStdString());
        mine_share.pushKV("R_share",  m_my_R_share.toStdString());
        mine_share.pushKV("KI_share", m_my_KI_share.toStdString());
        if (!m_my_D_share.isEmpty()) {
            mine_share.pushKV("D_share", m_my_D_share.toStdString());
        }
        mine_share.pushKV("commitment", m_my_commitment.toStdString());

        UniValue first  = (m_role == "initiator") ? mine_share : peer;
        UniValue second = (m_role == "initiator") ? peer       : mine_share;
        UniValue parties_arr{UniValue::VARR};
        parties_arr.push_back(first);
        parties_arr.push_back(second);

        // pricoin_jointspend_combine(ring(null), ring_ml, pi, msg, session_id, parties, s_others)
        UniValue params{UniValue::VARR};
        params.push_back(UniValue{UniValue::VARR}); // empty ring — multi-layer mode
        params.push_back(ring_ml_v);
        params.push_back(m_pi.toInt());
        params.push_back(m_msg_hex.toStdString());
        params.push_back(m_session_id.toStdString());
        params.push_back(parties_arr);
        params.push_back(s_others_v);

        auto r = callRpc("pricoin_jointspend_combine", params.write(0));
        if (!r.ok) {
            setStatus(tr("combine failed: %1").arg(QString::fromStdString(r.error_msg)), true);
            return;
        }
        UniValue v;
        v.read(r.json);
        m_KI    = QString::fromStdString(v["KI"].get_str());
        if (v.exists("D"))    m_D    = QString::fromStdString(v["D"].get_str());
        m_L_pi  = QString::fromStdString(v["L_pi"].get_str());
        m_R_pi  = QString::fromStdString(v["R_pi"].get_str());
        if (v.exists("mu_P")) m_mu_P = QString::fromStdString(v["mu_P"].get_str());
        if (v.exists("mu_C")) m_mu_C = QString::fromStdString(v["mu_C"].get_str());
        m_c_pi  = QString::fromStdString(v["c_pi"].get_str());
        m_c0    = QString::fromStdString(v["c0"].get_str());
        m_s_others_json = m_in_s_others_seed_json->toPlainText().trimmed();
        m_out_step2->setPlainText(QString::fromStdString(r.json));
    }
    setStatus(tr("Step 2 OK. Combine output saved; proceed to step 3."));
}

void PricCoopSignDialog::onStep3Compute()
{
    if (m_c_pi.isEmpty() || m_alpha.isEmpty()) {
        setStatus(tr("Run steps 1 and 2 first."), true);
        return;
    }
    // pricoin_jointspend_share(alpha, c_pi, x_share, [z_share, mu_P, mu_C])
    std::string params = std::string("[\"")
        + m_alpha.toStdString()  + "\",\""
        + m_c_pi.toStdString()   + "\",\""
        + m_x_share.toStdString() + "\"";
    if (m_mode == Mode::PricPlain && !m_z_share.isEmpty()
        && !m_mu_P.isEmpty() && !m_mu_C.isEmpty()) {
        params += std::string(",\"") + m_z_share.toStdString() + "\"";
        params += std::string(",\"") + m_mu_P.toStdString()    + "\"";
        params += std::string(",\"") + m_mu_C.toStdString()    + "\"";
    }
    params += "]";

    auto r = callRpc("pricoin_jointspend_share", params);
    if (!r.ok) {
        setStatus(tr("share failed: %1").arg(QString::fromStdString(r.error_msg)), true);
        return;
    }
    UniValue v;
    v.read(r.json);
    m_my_s_share = QString::fromStdString(v["s_share"].get_str());
    m_out_step3->setPlainText(m_my_s_share);
    setStatus(tr("Step 3 OK. Send `s_share` to peer."));
}

void PricCoopSignDialog::onStep4Compute()
{
    if (m_my_s_share.isEmpty()) {
        setStatus(tr("Run step 3 first."), true);
        return;
    }
    const bool adaptor = (m_mode == Mode::PricAdaptor);
    const QString peer_s = m_in_peer_s_share->text().trimmed();
    if (peer_s.size() != 64) {
        setStatus(tr("Peer s_share must be 32-byte hex"), true);
        return;
    }

    // Order shares as [initiator, responder] to match adaptor_combine
    // ordering. Plain assemble doesn't care about order — the shares
    // are summed mod n.
    UniValue close_shares{UniValue::VARR};
    if (m_role == "initiator") {
        close_shares.push_back(m_my_s_share.toStdString());
        close_shares.push_back(peer_s.toStdString());
    } else {
        close_shares.push_back(peer_s.toStdString());
        close_shares.push_back(m_my_s_share.toStdString());
    }

    if (adaptor) {
        // pricoin_jointspend_adaptor_assemble(KI, L_pi, R_pi, L_prime, R_prime, c_pi, c0, s_others, close_shares, pi, T_G, T_H, dleq_t)
        UniValue s_others_v;
        if (!s_others_v.read(m_s_others_json.toStdString()) || !s_others_v.isArray()) {
            setStatus(tr("internal: s_others vanished"), true);
            return;
        }
        UniValue params{UniValue::VARR};
        params.push_back(m_KI.toStdString());
        params.push_back(m_L_pi.toStdString());
        params.push_back(m_R_pi.toStdString());
        params.push_back(m_L_prime.toStdString());
        params.push_back(m_R_prime.toStdString());
        params.push_back(m_c_pi.toStdString());
        params.push_back(m_c0.toStdString());
        params.push_back(s_others_v);
        params.push_back(close_shares);
        params.push_back(m_pi.toInt());
        params.push_back(m_T_G.toStdString());
        params.push_back(m_T_H.toStdString());
        params.push_back(m_dleq_t.toStdString());
        auto r = callRpc("pricoin_jointspend_adaptor_assemble", params.write(0));
        if (!r.ok) {
            setStatus(tr("adaptor_assemble failed: %1").arg(QString::fromStdString(r.error_msg)), true);
            return;
        }
        UniValue v;
        v.read(r.json);
        m_final_blob_hex = QString::fromStdString(v["presig"].get_str());
        UniValue out{UniValue::VOBJ};
        out.pushKV("presig", m_final_blob_hex.toStdString());
        out.pushKV("kind",   "adaptor_pre_signature");
        m_out_step4->setPlainText(QString::fromStdString(out.write(2)));
        setStatus(tr("Step 4 OK. AdaptorPreSignature blob produced."));
    } else {
        // pricoin_jointspend_assemble(KI, c0, s_others, s_pi_shares, pi, [D])
        UniValue s_others_v;
        if (!s_others_v.read(m_s_others_json.toStdString()) || !s_others_v.isArray()) {
            setStatus(tr("internal: s_others seed vanished"), true);
            return;
        }
        UniValue params{UniValue::VARR};
        params.push_back(m_KI.toStdString());
        params.push_back(m_c0.toStdString());
        params.push_back(s_others_v);
        params.push_back(close_shares);
        params.push_back(m_pi.toInt());
        if (!m_D.isEmpty()) {
            params.push_back(m_D.toStdString());
        }
        auto r = callRpc("pricoin_jointspend_assemble", params.write(0));
        if (!r.ok) {
            setStatus(tr("assemble failed: %1").arg(QString::fromStdString(r.error_msg)), true);
            return;
        }
        UniValue v;
        v.read(r.json);
        m_final_blob_hex = QString::fromStdString(v["signature_hex"].get_str());
        UniValue out{UniValue::VOBJ};
        out.pushKV("signature_hex", m_final_blob_hex.toStdString());
        out.pushKV("kind",          "final_clsag_signature");
        m_out_step4->setPlainText(QString::fromStdString(out.write(2)));
        setStatus(tr("Step 4 OK. Final CLSAG signature blob produced."));
    }
}
