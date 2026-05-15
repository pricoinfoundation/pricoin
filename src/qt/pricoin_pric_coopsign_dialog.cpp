// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pricoin_pric_coopsign_dialog.h>

#include <crypto/sha256.h>
#include <key.h>
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
#include <QTimer>
#include <QCheckBox>
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

// Time the dialog will wait for at least one Nostr relay to connect
// before declaring the swap dead. 30s covers a slow relay handshake
// and a few transport retries without making the user stare at a
// frozen UI.
constexpr int kNostrConnectGraceMs = 30 * 1000;

// Derive `secret · G` as 33-byte compressed pubkey hex. Returns empty
// string on failure (zero/oversize scalar, etc.). Used to auto-fill
// the adaptor-ML Z_pub_X field from the user's z_share without a
// round-trip through an RPC.
QString DerivePubkeyHex(const QString& secret_hex)
{
    if (secret_hex.size() != 64) return {};
    const auto bytes = TryParseHex<unsigned char>(secret_hex.toStdString());
    if (!bytes || bytes->size() != 32) return {};
    CKey k;
    k.Set(bytes->begin(), bytes->end(), /*compressed=*/true);
    if (!k.IsValid()) return {};
    const CPubKey p = k.GetPubKey();
    return QString::fromStdString(
        HexStr(std::span<const unsigned char>{p.begin(), p.size()}));
}

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
                                        const std::string& swap_id,
                                        QWidget* parent)
    : QDialog(parent),
      m_wm(wallet_model),
      m_mode(mode),
      m_swap_id(QString::fromStdString(swap_id))
{
    setModal(true);
    resize(880, 960);
    m_relay_urls = PricoinRelaySettingsDialog::loadFromSettings();
    buildLayout(title);

    // Pin session strings to swap_id IMMEDIATELY after layout build,
    // before any session-restore or DM handler can touch them. These
    // are deterministic; nothing should ever load a different value.
    // 2026-05-14: tightened after a Mac wallet was found running with
    // a leaked self-test value 'ml-coop-adap-t-1' that had been
    // persisted from a prior session and was overriding the live
    // swap_id even after the load-time force-reset. Setting here
    // makes the value correct from the moment the member exists.
    m_session_label   = m_swap_id;
    m_session_payload = m_swap_id;

    // Pre-fill from the swap record where we can: adaptor materials
    // (claim leg only) + buildtx-helper joint-funding fields + the
    // refund nlocktime (refund leg).
    if (!swap_id.empty() && m_wm) {
        auto snap = m_wm->wallet().adaptorSwapGet(swap_id);
        if (snap) {
            if (!snap->counterparty_pubkey_hex.empty()
                && snap->counterparty_pubkey_hex.size() >= 66) {
                m_peer_xonly = QString::fromStdString(
                    snap->counterparty_pubkey_hex.substr(2));
            }
            if (m_mode == Mode::PricAdaptor) {
                if (m_in_T_G && !snap->adaptor_T_G_hex.empty()) {
                    m_in_T_G->setText(QString::fromStdString(snap->adaptor_T_G_hex));
                }
                if (m_in_T_H && !snap->adaptor_T_H_hex.empty()) {
                    m_in_T_H->setText(QString::fromStdString(snap->adaptor_T_H_hex));
                }
                if (m_in_dleq_t && !snap->adaptor_dleq_blob_hex.empty()) {
                    m_in_dleq_t->setPlainText(QString::fromStdString(snap->adaptor_dleq_blob_hex));
                }
            }
            // Buildtx helper auto-pulls. Prefer the on-chain values
            // once funding has broadcast; fall back to the pre-built
            // funding tx (planned vout) when the protocol is running
            // the cooperative ceremony BEFORE broadcast. Note: the
            // pre-built path can't pre-fill `bt_joint_txid` until we
            // compute the txid locally — that's a CHash on the
            // serialized hex, which the dialog doesn't decode. The
            // ceremony's loadshare path handles a missing txid by
            // computing it from the supplied hex anyway, so we leave
            // the field empty and rely on the auto-partial path to
            // source from `pric_funding_unsigned_tx_hex` directly.
            if (m_in_bt_joint_txid && !snap->pric_funding_txid_hex.empty()) {
                m_in_bt_joint_txid->setText(QString::fromStdString(snap->pric_funding_txid_hex));
            }
            if (m_in_bt_joint_vout) {
                if (snap->pric_funding_vout >= 0) {
                    m_in_bt_joint_vout->setText(QString::number(snap->pric_funding_vout));
                } else if (snap->pric_funding_planned_vout >= 0) {
                    m_in_bt_joint_vout->setText(QString::number(snap->pric_funding_planned_vout));
                }
            }
            if (m_in_bt_joint_value && snap->pric_amount_sat > 0) {
                // Joint output value in PRIC = sat / 1e8.
                const double v = static_cast<double>(snap->pric_amount_sat) / 1.0e8;
                m_in_bt_joint_value->setText(QString::number(v, 'f', 8));
                if (m_in_bt_dest_amount) {
                    // Default dest amount = joint value minus the
                    // 0.00001 default fee. User can override.
                    m_in_bt_dest_amount->setText(QString::number(v - 0.00001, 'f', 8));
                }
            }
            // Refund leg: nlocktime = pric_refund_height.
            if (m_mode == Mode::PricPlain && m_in_bt_nlocktime
                && snap->pric_refund_height > 0) {
                m_in_bt_nlocktime->setText(QString::number(snap->pric_refund_height));
            }
            // Destination convention: the CLAIM leg pays the PRIC
            // buyer (Bob); the REFUND leg returns PRIC to the seller
            // (Alice). Earlier this was inverted — claim went to
            // pric_alice_recipient_stealth and refund to bob's. That
            // meant Bob's PRIC claim broadcast paid into Alice's
            // stealth instead of his own; recovery requires Alice's
            // wallet to manually return the PRIC. 2026-05-15 fix.
            if (m_in_bt_dest) {
                const std::string& dest =
                    (m_mode == Mode::PricAdaptor) ? snap->pric_bob_recipient_stealth
                                                   : snap->pric_alice_recipient_stealth;
                if (!dest.empty()) {
                    m_in_bt_dest->setText(QString::fromStdString(dest));
                }
            }
        }
    }

    // Auto-coord: derive role (initiator/responder) from swap role
    // + leg. Convention: spender = initiator, cosigner = responder.
    // PricAdaptor (claim) → spender is Bob. PricPlain (refund) →
    // spender is Alice. Set the combobox so the user doesn't have
    // to think about it.
    //
    // Also set absorb_shared_secret deterministically: Alice = true,
    // Bob = false. EXACTLY ONE party must absorb so the two x_shares
    // sum to the joint one-time priv. Default-to-true on both was
    // producing two-true → invalid x_share sum.
    if (m_wm && !swap_id.empty()) {
        auto snap = m_wm->wallet().adaptorSwapGet(swap_id);
        if (snap) {
            const bool i_am_alice = (snap->role == "alice");
            const bool i_am_spender =
                (m_mode == Mode::PricAdaptor && !i_am_alice) ||
                (m_mode == Mode::PricPlain   &&  i_am_alice);
            if (m_in_role) {
                m_in_role->setCurrentText(i_am_spender
                    ? QStringLiteral("initiator")
                    : QStringLiteral("responder"));
            }
            if (m_in_ls_absorb) {
                m_in_ls_absorb->setCurrentText(i_am_alice
                    ? QStringLiteral("true")
                    : QStringLiteral("false"));
            }
        }
    }

    // Restore cooperative-sign session state if persisted from a
    // previous dialog instance (close/reopen cycle). Loads m_alpha,
    // m_my_commitment, m_my_s_share, etc. plus mirrors back into
    // input widgets so the user sees resumed progress.
    if (m_wm && !swap_id.empty()) {
        auto snap = m_wm->wallet().adaptorSwapGet(swap_id);
        if (snap) {
            const std::string& blob = (m_mode == Mode::PricAdaptor)
                ? snap->pric_claim_adaptor_session_json
                : snap->pric_refund_session_json;
            if (!blob.empty()) {
                loadSessionFromRecord(blob);
            }
        }
    }

    // Subscribe to the shared Nostr client SYNCHRONOUSLY so we don't
    // race against incoming DMs that arrive between dialog show and
    // QueuedConnection delivery. (Observed 2026-05-11: Mac's partial
    // DM arrived before Linux's deferred subscribe ran, signal fired
    // with no listeners, DM lost.) The compute step still goes via
    // QueuedConnection so it doesn't block ctor on RPC calls.
    if (!m_nostr) onNostrConnectClicked();
    QMetaObject::invokeMethod(this, [this]{
        // If a previous run already completed this leg (session
        // restore set m_final_blob_hex), auto-accept on construction
        // so the outer dialog's Phase-4 chain proceeds without
        // forcing the user to re-run the ceremony.
        //
        // BUT: before closing, re-send any DMs the peer might be
        // waiting on. The most common stuck scenario is "our side
        // completed, peer stuck at Step-3-done because our s_share
        // DM was lost." Resending our own round-1 share + round-3
        // s_share + buildtx envelope is idempotent on the peer (the
        // staleness checks in their receive handler will accept the
        // overwrite while their step hasn't been consumed). Fixes
        // the 2026-05-14 case where Mac's claim completed but
        // Linux's claim was stuck waiting for Mac's s_share.
        if (!m_final_blob_hex.isEmpty()) {
            // Wait until Nostr connects (m_relay_connected_count>0)
            // before declaring "previous session done" — otherwise
            // we close before any resend DM has gone out. Hand off
            // to a short delayed retry.
            auto try_resend_then_accept = [this]() {
                m_auto_buildtx_sent = false;
                m_auto_step1_dm_sent = false;
                m_auto_step3_dm_sent = false;
                tryAutoSendBuildtx();
                tryAutoSendRound1();
                tryAutoSendRound3();
            };
            try_resend_then_accept();
            // Retry once after the Nostr-connect grace, in case the
            // first attempt fired before relays attached.
            QTimer::singleShot(kNostrConnectGraceMs,
                this, [this, try_resend_then_accept]() {
                if (m_final_blob_hex.isEmpty()) return;
                try_resend_then_accept();
                setStatus(tr("Auto: previous session completed — final blob "
                              "restored, dialog closing."));
                accept();
            });
            return;
        }
        // Always start from the top of the chain — each tryAuto step
        // is gated on its own preconditions, so calling them in order
        // gracefully resumes whatever was in flight. Important on
        // dialog reopen after a binary upgrade or daemon restart,
        // where m_my_commitment / m_in_peer_share_json may be present
        // but the auto-fire flags are false (they aren't persisted),
        // so the next-step would otherwise sit idle. The cascade has
        // to include EVERY intermediate step — earlier versions
        // skipped tryAutoLoadshare and tryAutoBuildtx and ended up
        // with dialogs stuck at "Scanning joint stealth output…"
        // after a session restore that had both jointscan partials
        // present but never re-ran loadshare.
        tryAutoComputeJointscanPartial();
        tryAutoSendJointscanPartial();
        tryAutoSendXpubAnnounce();
        tryAutoLoadshare();
        tryAutoBuildtx();
        tryAutoSendBuildtx();
        tryAutoStep1();
        tryAutoSendRound1();
        tryAutoStep2();
        tryAutoStep3();
        tryAutoSendRound3();
        tryAutoStep4();
    }, Qt::QueuedConnection);

    // Nostr-connectivity gate: the entire auto-coord chain is gated
    // on a working relay (Phase 1 DMs, xpub announce, round-1 share,
    // round-3 share are all sent over Nostr). If no relay connects
    // within the grace window, the user is sitting in front of a
    // dialog that will silently never advance. Surface that with a
    // loud error rather than a hung progress UI.
    QTimer::singleShot(kNostrConnectGraceMs, this, [this]() {
        if (m_final_blob_hex.isEmpty() && m_relay_connected_count == 0) {
            setStatus(tr(
                "Cannot reach the Nostr relay — peer communication "
                "is required for cooperative signing. Cancel this "
                "trade and try again once Nostr is connected. "
                "(Settings → Pricoin → Nostr relays.)"), /*error=*/true);
            if (m_progress_state) {
                m_progress_state->setText(tr(
                    "✗ Nostr unreachable — cannot communicate with peer."));
            }
        }
    });
}

void PricCoopSignDialog::onRunLoadshare()
{
    const QString joint_txid_field = m_in_bt_joint_txid ? m_in_bt_joint_txid->text().trimmed() : QString{};
    const QString joint_vout_field = m_in_bt_joint_vout ? m_in_bt_joint_vout->text().trimmed() : QString{};

    // Resolve the joint output's tx hex + vout. Two sources, in
    // preference order — same dispatch as tryAutoComputeJointscanPartial:
    //   1. snap->pric_funding_unsigned_tx_hex / pric_funding_planned_vout
    //      — Alice's pre-built funding tx, persisted before broadcast.
    //   2. Form field `joint_txid` + on-chain getrawtransaction —
    //      fallback for the legacy/post-funding ceremony order.
    std::string tx_hex_resolved;
    int vout = -1;
    bool used_planned = false;
    if (m_wm && !m_swap_id.isEmpty()) {
        auto snap_pre = m_wm->wallet().adaptorSwapGet(m_swap_id.toStdString());
        if (snap_pre
            && !snap_pre->pric_funding_unsigned_tx_hex.empty()
            && snap_pre->pric_funding_planned_vout >= 0) {
            tx_hex_resolved = snap_pre->pric_funding_unsigned_tx_hex;
            vout = snap_pre->pric_funding_planned_vout;
            used_planned = true;
        }
    }
    if (!used_planned) {
        if (joint_txid_field.size() != 64) {
            setStatus(tr("Joint txid must be 32-byte hex (fill it in the Buildtx helper above first), "
                         "or wait for the pre-built funding tx hex to land on the swap record."), true);
            return;
        }
        bool vout_ok = false;
        vout = joint_vout_field.toInt(&vout_ok);
        if (!vout_ok || vout < 0) {
            setStatus(tr("Joint vout invalid"), true);
            return;
        }
    } else {
        // Best-effort: also surface the planned vout in the form so a
        // user inspecting the dialog sees what was used.
        if (m_in_bt_joint_vout
            && m_in_bt_joint_vout->text().trimmed().isEmpty()) {
            m_in_bt_joint_vout->setText(QString::number(vout));
        }
    }
    const QString my_p   = m_in_ls_my_partial->text().trimmed();
    const QString peer_p = m_in_ls_peer_partial->text().trimmed();
    if (my_p.isEmpty() || peer_p.isEmpty()) {
        setStatus(tr("Provide both partials (run pricoin_jointscan_partial first)"), true);
        return;
    }
    const std::string absorb = m_in_ls_absorb->currentText().toStdString();

    // The RPC takes 6 params: (tx_hex, vout, my_partial, other_partial,
    // other_spend_pubkey, absorb_shared_secret). other_spend_pubkey is
    // the counterparty's STEALTH spend pubkey (NOT the swap-identity
    // counterparty_pubkey, which is the ECDSA pubkey used for HTLCs
    // — different key entirely). Persisted to the swap record at
    // creation time via adaptorSwapSetPeerStealthPubkeys.
    std::string other_spend_hex;
    if (m_wm && !m_swap_id.isEmpty()) {
        auto snap = m_wm->wallet().adaptorSwapGet(m_swap_id.toStdString());
        if (snap && snap->peer_spend_pubkey_hex.size() == 66) {
            other_spend_hex = snap->peer_spend_pubkey_hex;
        }
    }
    if (other_spend_hex.size() != 66) {
        setStatus(tr("Peer stealth spend pubkey not on swap record. "
                     "Was the swap_addrs DM delivered? Manual fallback: "
                     "paste peer's 33-byte spend pubkey hex into the "
                     "swap record via cli."), true);
        return;
    }

    // Need the joint tx_hex. If we sourced it from the swap record
    // (pre-funding ceremony order, post-2026-05-15), reuse it. Otherwise
    // fetch via getrawtransaction (works with -txindex=1, now defaulted,
    // for any historical tx).
    std::string tx_hex;
    if (used_planned) {
        tx_hex = tx_hex_resolved;
    } else {
        UniValue params_get_v{UniValue::VARR};
        params_get_v.push_back(joint_txid_field.toStdString());
        params_get_v.push_back(1);
        auto rg = callRpc("getrawtransaction", params_get_v.write(0));
        if (!rg.ok) {
            setStatus(tr("getrawtransaction failed: %1").arg(QString::fromStdString(rg.error_msg)), true);
            return;
        }
        UniValue gv;
        gv.read(rg.json);
        tx_hex = gv["hex"].get_str();
    }

    UniValue params_v{UniValue::VARR};
    params_v.push_back(tx_hex);
    params_v.push_back(vout);
    params_v.push_back(my_p.toStdString());
    params_v.push_back(peer_p.toStdString());
    params_v.push_back(other_spend_hex);
    params_v.push_back(absorb == std::string{"true"});  // bool
    auto r = callRpc("pricoin_jointspend_loadshare", params_v.write(0));
    if (!r.ok) {
        setStatus(tr("loadshare failed: %1").arg(QString::fromStdString(r.error_msg)), true);
        return;
    }
    UniValue v;
    v.read(r.json);
    const std::string x_share        = v["x_share"].get_str();
    // RPC returns the field as "blind" — older code here read
    // "b_prev" and silently fell back to empty, which then failed
    // buildtx with "joint_blind must be 32-byte hex". Fixed.
    const std::string blind_hex      = v.exists("blind")      ? v["blind"].get_str()      : "";
    const std::string joint_pub_hex  = v.exists("joint_pubkey") ? v["joint_pubkey"].get_str() : "";
    const std::string value_str      = v.exists("value")      ? v["value"].getValStr()    : "";
    const std::string x_pub_hex      = v.exists("x_pub")      ? v["x_pub"].get_str()      : "";
    if (m_in_x_share)         m_in_x_share->setText(QString::fromStdString(x_share));
    if (m_in_bt_joint_blind && !blind_hex.empty()) {
        m_in_bt_joint_blind->setText(QString::fromStdString(blind_hex));
    }
    if (m_in_joint_pubkey && !joint_pub_hex.empty()) {
        m_in_joint_pubkey->setText(QString::fromStdString(joint_pub_hex));
    }
    // Adaptor-mode helper: x_pub = x_share · G is needed at Step 1.
    // Today the user pastes it manually; loadshare now returns it
    // so we can just auto-fill.
    if (m_in_X_pub_X && !x_pub_hex.empty()
        && m_in_X_pub_X->text().trimmed().isEmpty()) {
        m_in_X_pub_X->setText(QString::fromStdString(x_pub_hex));
    }
    // Show the loadshare echo (excluding x_share since it's a
    // long-lived secret and shouldn't be screen-pasted).
    UniValue echo{UniValue::VOBJ};
    if (!blind_hex.empty())     echo.pushKV("blind",        blind_hex);
    if (!joint_pub_hex.empty()) echo.pushKV("joint_pubkey", joint_pub_hex);
    if (!value_str.empty())     echo.pushKV("value",        value_str);
    if (!x_pub_hex.empty())     echo.pushKV("x_pub",        x_pub_hex);
    m_out_loadshare->setPlainText(QString::fromStdString(echo.write(2)));
    setStatus(tr("Loadshare OK. x_share + joint_blind + joint_pubkey filled."));

    // Capture loadshare outputs into m_* shadows for persistSession.
    m_x_share = QString::fromStdString(x_share);
    if (m_in_x_share) m_in_x_share->setText(m_x_share);
    persistSession();

    // Auto-coord chain: Phase 2 (xpub announce + auto-buildtx if I'm
    // spender) and Phase 3 (Step 1+ chain).
    tryAutoSendXpubAnnounce();
    tryAutoBuildtx();
    tryAutoStep1();
}

void PricCoopSignDialog::onRunBuildtx()
{
    const QString joint_txid = m_in_bt_joint_txid->text().trimmed();
    const QString joint_vout = m_in_bt_joint_vout->text().trimmed();
    const QString joint_val  = m_in_bt_joint_value->text().trimmed();
    const QString joint_blind= m_in_bt_joint_blind->text().trimmed();
    const QString joint_pub  = m_in_joint_pubkey ? m_in_joint_pubkey->text().trimmed() : QString{};
    const QString dest       = m_in_bt_dest->text().trimmed();
    const QString dest_amt   = m_in_bt_dest_amount->text().trimmed();
    const QString fee        = m_in_bt_fee->text().trimmed();
    const QString ring_size  = m_in_bt_ring_size->text().trimmed();
    const QString nlt        = m_in_bt_nlocktime->text().trimmed();
    if (joint_txid.size() != 64)   { setStatus(tr("Joint txid must be 32-byte hex"), true); return; }
    if (joint_blind.size() != 64)  { setStatus(tr("Joint blind must be 32-byte hex"), true); return; }
    if (joint_pub.size() != 66)    { setStatus(tr("Joint pubkey must be 33-byte hex (fill in Inputs above or run loadshare)"), true); return; }
    bool vout_ok=false, rs_ok=false, nl_ok=false;
    int vout = joint_vout.toInt(&vout_ok);
    int rs   = ring_size.toInt(&rs_ok);
    int nl   = nlt.toInt(&nl_ok);
    if (!vout_ok || vout < 0) { setStatus(tr("Joint vout invalid"), true); return; }
    if (!rs_ok || rs < 2)     { setStatus(tr("Ring size must be >= 2"), true); return; }
    if (!nl_ok || nl < 0)     { setStatus(tr("nlocktime invalid"), true); return; }

    // pricoin_jointspend_buildtx(joint_txid, joint_vout, joint_value, joint_blind, joint_pubkey, dest, dest_amount, fee, ring_size, nlocktime)
    std::string params = std::string("[\"")
        + joint_txid.toStdString() + "\","
        + std::to_string(vout) + ","
        + joint_val.toStdString() + ",\""    // amount as numeric / string
        + joint_blind.toStdString() + "\",\""
        + joint_pub.toStdString() + "\",\""
        + dest.toStdString() + "\","
        + dest_amt.toStdString() + ","
        + fee.toStdString() + ","
        + std::to_string(rs) + ","
        + std::to_string(nl) + "]";
    // The amounts (joint_val, dest_amt, fee) are strings here without
    // quotes — that's the convention RPC type-conversion follows for
    // AMOUNT params; a numeric is also accepted. To be safe quote the
    // numerics when they have decimal points.
    {
        // Simple comma-aware re-quoting for the three amount fields.
        // Replace ",<value>," with ",\"<value>\","
        // Done only for dest_amt + fee since they're decimals; the
        // joint_val we already quoted via outer "\"" above. Cleaner
        // to build via UniValue.
    }

    // If the swap record has a pre-built (not yet broadcast) funding tx
    // hex, pass it as the optional 11th param so the buildtx RPC can
    // source the joint output's commitment + one-time pubkey from the
    // hex instead of looking it up on-chain. Required for the
    // post-2026-05-15 cooperative-sign-before-funding flow.
    std::string funding_hex;
    if (m_wm && !m_swap_id.isEmpty()) {
        auto snap_bt = m_wm->wallet().adaptorSwapGet(m_swap_id.toStdString());
        if (snap_bt && !snap_bt->pric_funding_unsigned_tx_hex.empty()
            && snap_bt->pric_funding_height <= 0) {
            funding_hex = snap_bt->pric_funding_unsigned_tx_hex;
        }
    }

    UniValue p{UniValue::VARR};
    p.push_back(joint_txid.toStdString());
    p.push_back(vout);
    p.push_back(joint_val.toStdString());
    p.push_back(joint_blind.toStdString());
    p.push_back(joint_pub.toStdString());
    p.push_back(dest.toStdString());
    p.push_back(dest_amt.toStdString());
    p.push_back(fee.toStdString());
    p.push_back(rs);
    p.push_back(nl);
    p.push_back(funding_hex);
    auto r = callRpc("pricoin_jointspend_buildtx", p.write(0));
    if (!r.ok) {
        setStatus(tr("buildtx failed: %1").arg(QString::fromStdString(r.error_msg)), true);
        return;
    }
    UniValue v;
    v.read(r.json);
    const std::string sighash    = v["sighash"].get_str();
    const std::string z_self     = v["z_self"].get_str();
    const std::string z_other    = v["z_other"].get_str();
    const int         pi         = v["pi"].getInt<int>();
    const std::string ring_ml    = v["ring_ml"].write(0);
    m_unsigned_tx_hex = QString::fromStdString(v["tx_hex"].get_str());
    if (m_in_msg) m_in_msg->setText(QString::fromStdString(sighash));
    if (m_in_pi)  m_in_pi->setText(QString::number(pi));
    // Both PricPlain and PricAdaptor now use the multi-layer ring_ml
    // format end-to-end. Previously adaptor mode projected ring_ml to
    // single-layer P-only, which made the resulting sig fail consensus
    // VerifyMultiLayer (commitment_image == zero point). Per
    // 2026-05-12 fix: keep the multi-layer view and route Step 2
    // through pricoin_jointspend_adaptor_combine_ml.
    if (m_in_ring_or_ring_ml) {
        m_in_ring_or_ring_ml->setPlainText(QString::fromStdString(ring_ml));
    }
    // Spender's z_self auto-fills the z_share field for BOTH modes.
    // adaptor_ml needs z_X (= z_self for the spender) to build
    // D_share = z_X·H_p(P_pi) at round1.
    if (m_in_z_share) {
        m_in_z_share->setText(QString::fromStdString(z_self));
    }
    // adaptor_ml: Z_pub_X = z_X · G. Auto-derive from z_self so the
    // user doesn't have to compute or paste it.
    if (m_in_Z_pub_X && m_mode == Mode::PricAdaptor) {
        const QString zpub = DerivePubkeyHex(QString::fromStdString(z_self));
        if (!zpub.isEmpty()) m_in_Z_pub_X->setText(zpub);
    }
    // adaptor_ml: the spender knows BOTH z-halves at buildtx time
    // (z_self for self, z_other for peer). Compute the peer's
    // Z_pub directly from z_other so the spender doesn't need a
    // DM round-trip with the cosigner to fill it in. Without this,
    // the xpub_announce DM arrives BEFORE the cosigner has derived
    // their own Z_pub (xpub_announce fires at loadshare-end, which
    // is before buildtx is received), so the spender's Z_pub_peer
    // stays empty and Step 2 (combine_ml) blocks. Cosigner derives
    // their own Z_pub_X from z_other when the buildtx DM lands.
    if (m_in_Z_pub_peer && m_mode == Mode::PricAdaptor) {
        const QString zpub_peer = DerivePubkeyHex(QString::fromStdString(z_other));
        if (!zpub_peer.isEmpty()) m_in_Z_pub_peer->setText(zpub_peer);
    }
    UniValue out{UniValue::VOBJ};
    out.pushKV("sighash",     sighash);
    out.pushKV("pi",          pi);
    out.pushKV("z_self",      z_self);
    out.pushKV("z_other_for_peer", z_other);
    out.pushKV("ring_ml",     v["ring_ml"]);
    out.pushKV("joint_pubkey", v["joint_pubkey"]);
    m_out_buildtx->setPlainText(QString::fromStdString(out.write(2)));
    setStatus(tr("Buildtx OK. msg / ring_ml / pi / z_self auto-filled. Send `z_other_for_peer` + ring + pi + msg + joint_pubkey to peer."));

    // Persist the unsigned PRIC refund tx for the auto-refund
    // watcher. Plain mode only (PricPlain == refund leg). Best-
    // effort — failure here just means auto-refund won't trigger
    // for this swap; manual refund still works.
    if (m_mode == Mode::PricPlain && m_wm && !m_swap_id.isEmpty()
        && !m_unsigned_tx_hex.isEmpty()) {
        auto rr = m_wm->wallet().adaptorSwapSetPricRefundTx(
            m_swap_id.toStdString(), m_unsigned_tx_hex.toStdString());
        if (!rr) {
            // Surface but don't block.
            setStatus(tr("Buildtx OK; persisting refund tx for auto-refund "
                         "failed: %1")
                .arg(QString::fromStdString(util::ErrorString(rr).original)),
                /*error=*/false);
        }
    }
    persistSession();
    // Auto-DM the buildtx output to the cosigner so they don't have
    // to copy-paste msg/pi/ring/etc. Idempotent guard.
    tryAutoSendBuildtx();
    tryAutoStep1();
}

// ─── Nostr DM transport ──────────────────────────────────────────

void PricCoopSignDialog::updateNostrStatus()
{
    if (!m_lbl_nostr_status) return;
    if (!m_nostr) {
        m_lbl_nostr_status->setText(tr("DM relay: disconnected. Peer xonly: %1")
            .arg(m_peer_xonly.isEmpty()
                ? tr("(unknown — set by ctor swap_id)")
                : m_peer_xonly.left(16) + "…"));
        if (m_btn_send_dm_round1) m_btn_send_dm_round1->setEnabled(false);
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
    if (m_btn_send_dm_round1) m_btn_send_dm_round1->setEnabled(
        can_send && !m_my_commitment.isEmpty());
    if (m_btn_send_dm_round3) m_btn_send_dm_round3->setEnabled(
        can_send && !m_my_s_share.isEmpty());
    if (m_btn_nostr_connect) m_btn_nostr_connect->setText(tr("Disconnect Nostr DM"));
}

void PricCoopSignDialog::onNostrConnectClicked()
{
    if (m_nostr) {
        // Shared client owned by WalletModel — only unhook this
        // dialog's signals; don't tear it down.
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
            this, &PricCoopSignDialog::onNostrLog);
    connect(m_nostr, &PricoinNostrClient::relayStatusChanged,
            this, &PricCoopSignDialog::onNostrRelayStatus);
    connect(m_nostr, &PricoinNostrClient::directMessageReceived,
            this, &PricCoopSignDialog::onDmReceived);
    m_relay_urls = m_nostr->relayUrls();
    if (m_nostr->connectedCount() == 0) {
        m_nostr->connectAll();
        m_relay_connected_count = 0;
    } else {
        m_relay_connected_count = m_nostr->connectedCount();
    }
    updateNostrStatus();
    // Auto-coord kickoff: when this dialog hooks into an already-
    // connected shared client, no relayStatusChanged signal fires
    // (the relays were connected before we subscribed), so the
    // auto-coord chain never starts. Drive it here too.
    if (m_relay_connected_count > 0) {
        tryAutoComputeJointscanPartial();
        tryAutoSendJointscanPartial();
        tryAutoSendXpubAnnounce();
    }
}

void PricCoopSignDialog::onNostrRelayStatus(const QString& url, bool connected)
{
    Q_UNUSED(url);
    if (connected) ++m_relay_connected_count;
    else --m_relay_connected_count;
    if (m_relay_connected_count < 0) m_relay_connected_count = 0;
    updateNostrStatus();
    // Auto-coord retry: now that we're connected, try the jointscan
    // partial path again. Either the partial wasn't yet computed (will
    // compute now) or was computed but not sent (will send now).
    if (connected && m_relay_connected_count > 0) {
        tryAutoComputeJointscanPartial();
        tryAutoSendJointscanPartial();
    }
}

void PricCoopSignDialog::onNostrLog(const QString& msg)
{
    setStatus(msg);
}

void PricCoopSignDialog::onSendDmRound1()
{
    if (!m_nostr || m_my_commitment.isEmpty() || m_peer_xonly.isEmpty()) return;
    // The "share" envelope is the same JSON the peer will paste into
    // m_in_peer_share_json on their side (the keys mirror the
    // round1 RPC output, minus alpha).
    UniValue share{UniValue::VOBJ};
    share.pushKV("L_share",  m_my_L_share.toStdString());
    share.pushKV("R_share",  m_my_R_share.toStdString());
    share.pushKV("KI_share", m_my_KI_share.toStdString());
    if (!m_my_D_share.isEmpty()) {
        share.pushKV("D_share", m_my_D_share.toStdString());
    }
    if (!m_my_dleq_alpha.isEmpty()) {
        share.pushKV("dleq_alpha", m_my_dleq_alpha.toStdString());
    }
    if (!m_my_dleq_x.isEmpty()) {
        share.pushKV("dleq_x", m_my_dleq_x.toStdString());
    }
    if (!m_my_dleq_z.isEmpty()) {
        // 2026-05-13: ML adaptor protocol's third DLEQ proof binding
        // z_X across G + H_p(P_pi). Required by adaptor_combine_ml's
        // ParseBlob<DLEQProof>(s["dleq_z"]) — omission here surfaces
        // as "JSON value of type null is not of expected type string"
        // at Step 2 on the receiving side.
        share.pushKV("dleq_z", m_my_dleq_z.toStdString());
    }
    share.pushKV("commitment", m_my_commitment.toStdString());

    UniValue env{UniValue::VOBJ};
    env.pushKV("v",        1);
    env.pushKV("leg",      m_mode == Mode::PricAdaptor ? "pric_claim_adaptor"
                                                        : "pric_refund");
    env.pushKV("swap_id",  m_swap_id.toStdString());
    env.pushKV("round",    1);
    env.pushKV("share",    share);
    const QString plaintext = QString::fromStdString(env.write(0));
    if (m_nostr->publishDirectMessage(m_peer_xonly, plaintext)) {
        setStatus(tr("Round-1 share DM sent."));
    }
}

void PricCoopSignDialog::onSendDmRound3()
{
    if (!m_nostr || m_my_s_share.isEmpty() || m_peer_xonly.isEmpty()) return;
    UniValue env{UniValue::VOBJ};
    env.pushKV("v",        1);
    env.pushKV("leg",      m_mode == Mode::PricAdaptor ? "pric_claim_adaptor"
                                                        : "pric_refund");
    env.pushKV("swap_id",  m_swap_id.toStdString());
    env.pushKV("round",    3);
    env.pushKV("s_share",  m_my_s_share.toStdString());
    const QString plaintext = QString::fromStdString(env.write(0));
    if (m_nostr->publishDirectMessage(m_peer_xonly, plaintext)) {
        setStatus(tr("Round-3 s_share DM sent."));
    }
}

void PricCoopSignDialog::onDmReceived(const QString& from_xonly_hex,
                                       const QString& plaintext)
{
    if (!m_peer_xonly.isEmpty() && from_xonly_hex != m_peer_xonly) return;
    UniValue env;
    if (!env.read(plaintext.toStdString()) || !env.isObject()) return;
    if (env.exists("swap_id")
        && env["swap_id"].get_str() != m_swap_id.toStdString()
        && !m_swap_id.isEmpty()) {
        return;
    }
    if (!m_chk_auto_paste || !m_chk_auto_paste->isChecked()) {
        setStatus(tr("Peer DM received (auto-paste disabled — use Paste buttons)."));
        return;
    }

    // Auto-coord: jointscan partial exchange. Envelope shape:
    //   { v:1, leg:"...", swap_id:"...", kind:"jointscan",
    //     partial:"<33-byte hex>" }
    // Filter to this leg so a refund-leg DM doesn't cross-fill the
    // claim-leg dialog.
    const std::string my_leg = (m_mode == Mode::PricAdaptor)
        ? "pric_claim_adaptor" : "pric_refund";
    if (env.exists("kind") && env["kind"].isStr()) {
        const std::string env_leg = env.exists("leg") && env["leg"].isStr()
            ? env["leg"].get_str() : std::string{};
        if (!env_leg.empty() && env_leg != my_leg) return;
        const std::string kind = env["kind"].get_str();

        if (kind == "jointscan") {
            if (!env.exists("partial") || !env["partial"].isStr()) return;
            const std::string partial = env["partial"].get_str();
            if (partial.size() != 66) return;  // 33-byte hex
            // Accept overwrites until loadshare has consumed the
            // partials (m_x_share set). After loadshare runs, the
            // partials have been baked into x_share / blind; replacing
            // them would just be ignored. Same staleness fix class
            // as round-1 / round-3 (2026-05-14).
            if (!m_in_ls_peer_partial) return;
            const QString incoming = QString::fromStdString(partial);
            const QString current  = m_in_ls_peer_partial->text().trimmed();
            const bool consumed = !m_x_share.isEmpty();
            if (!consumed && (current.isEmpty() || current != incoming)) {
                m_in_ls_peer_partial->setText(incoming);
                setStatus(tr("Peer scan partial auto-pasted from DM."));
                persistSession();
                m_auto_loadshare_fired = false;
                tryAutoLoadshare();
                // Bilateral resend: if I sent my partial before peer's
                // dialog was subscribed, peer never received it. Now
                // that peer is clearly online (we just received from
                // them), re-send our own partial so peer can fill
                // their side. Drop the idempotent guard for this case.
                m_auto_partial_sent = false;
                tryAutoSendJointscanPartial();
            }
            return;
        }

        if (kind == "xpub_announce") {
            // Adaptor mode only — plain mode has no X_pub field.
            if (m_mode != Mode::PricAdaptor) return;
            if (!env.exists("x_pub") || !env["x_pub"].isStr()) return;
            const std::string xpub = env["x_pub"].get_str();
            if (xpub.size() != 66) return;
            // Accept overwrites until Step 2 has consumed X_pub_peer
            // / Z_pub_peer (m_KI set). After that, replacing them
            // would just produce inconsistent state.
            const bool consumed = !m_KI.isEmpty();
            bool any_change = false;
            if (!consumed && m_in_X_pub_peer) {
                const QString incoming = QString::fromStdString(xpub);
                const QString current  = m_in_X_pub_peer->text().trimmed();
                if (current.isEmpty() || current != incoming) {
                    m_in_X_pub_peer->setText(incoming);
                    any_change = true;
                }
            }
            if (!consumed && env.exists("z_pub") && env["z_pub"].isStr()
                && m_in_Z_pub_peer) {
                const std::string zpub = env["z_pub"].get_str();
                if (zpub.size() == 66) {
                    const QString incoming = QString::fromStdString(zpub);
                    const QString current  = m_in_Z_pub_peer->text().trimmed();
                    if (current.isEmpty() || current != incoming) {
                        m_in_Z_pub_peer->setText(incoming);
                        any_change = true;
                    }
                }
            }
            if (any_change) {
                setStatus(tr("Peer X_pub/Z_pub auto-pasted from DM."));
                m_auto_step1_fired = false;
                tryAutoStep1();
                // Bilateral resend (see jointscan above).
                m_auto_xpub_announced = false;
                tryAutoSendXpubAnnounce();
            }
            return;
        }

        if (kind == "buildtx") {
            // Cosigner-side auto-fill from spender's buildtx output.
            // Accept overwrites until Step 2 has consumed these
            // (m_KI set) — afterwards changing them would just
            // produce inconsistent state. The session_id / ring_hash
            // / joint_output_id paths already overwrite
            // unconditionally because they MUST agree across both
            // sides; we keep that behavior. (2026-05-14 staleness
            // hardening — same class as round-1 / round-3.)
            const bool consumed_for_step2 = !m_KI.isEmpty();
            auto set_if_changed_le = [&](QLineEdit* w, const QString& incoming) {
                if (!w) return;
                if (consumed_for_step2) return;
                const QString current = w->text().trimmed();
                if (current.isEmpty() || current != incoming) w->setText(incoming);
            };
            auto set_if_changed_txt = [&](QPlainTextEdit* w, const QString& incoming) {
                if (!w) return;
                if (consumed_for_step2) return;
                const QString current = w->toPlainText().trimmed();
                if (current.isEmpty() || current != incoming) w->setPlainText(incoming);
            };
            if (env.exists("sighash") && env["sighash"].isStr()) {
                set_if_changed_le(m_in_msg,
                    QString::fromStdString(env["sighash"].get_str()));
            }
            if (env.exists("pi")) {
                set_if_changed_le(m_in_pi,
                    QString::number(env["pi"].getInt<int>()));
            }
            if (env.exists("ring_or_ml")) {
                set_if_changed_txt(m_in_ring_or_ring_ml,
                    QString::fromStdString(env["ring_or_ml"].write(2)));
            }
            if (env.exists("joint_pubkey") && env["joint_pubkey"].isStr()) {
                set_if_changed_le(m_in_joint_pubkey,
                    QString::fromStdString(env["joint_pubkey"].get_str()));
            }
            if (env.exists("session_id") && env["session_id"].isStr()
                && m_in_session_id) {
                // session_id MUST match across both parties — overwrite
                // even if the user (or the ctor-default RandomHex32)
                // pre-filled with a different value.
                m_in_session_id->setText(
                    QString::fromStdString(env["session_id"].get_str()));
            }
            if (env.exists("ring_hash") && env["ring_hash"].isStr()
                && m_in_ring_hash) {
                m_in_ring_hash->setText(
                    QString::fromStdString(env["ring_hash"].get_str()));
            }
            if (env.exists("joint_output_id") && env["joint_output_id"].isStr()
                && m_in_joint_output_id) {
                m_in_joint_output_id->setText(
                    QString::fromStdString(env["joint_output_id"].get_str()));
            }
            // z_other → cosigner's z_share, for BOTH modes. adaptor_ml
            // needs z_X to compute D_share at round1; without it the
            // sig fails consensus VerifyMultiLayer.
            if (env.exists("z_other") && env["z_other"].isStr()) {
                const QString incoming = QString::fromStdString(env["z_other"].get_str());
                set_if_changed_le(m_in_z_share, incoming);
                if (m_in_Z_pub_X && m_mode == Mode::PricAdaptor) {
                    const QString zpub = DerivePubkeyHex(incoming);
                    if (!zpub.isEmpty()) set_if_changed_le(m_in_Z_pub_X, zpub);
                }
            }
            if (m_mode == Mode::PricAdaptor) {
                if (env.exists("x_pub_spender") && env["x_pub_spender"].isStr()) {
                    set_if_changed_le(m_in_X_pub_peer,
                        QString::fromStdString(env["x_pub_spender"].get_str()));
                }
                if (env.exists("z_pub_spender") && env["z_pub_spender"].isStr()) {
                    set_if_changed_le(m_in_Z_pub_peer,
                        QString::fromStdString(env["z_pub_spender"].get_str()));
                }
                // Validate (don't adopt) peer's session_label / payload.
                // Both sides MUST derive these deterministically from
                // the swap_id, so accepting peer-supplied values opens
                // a back-channel for divergence — exactly the bug class
                // we hit 2026-05-13. If the peer sent something else,
                // flag it loudly: their binary is misconfigured.
                if (env.exists("session_label") && env["session_label"].isStr()) {
                    const QString peer_label = QString::fromStdString(
                        env["session_label"].get_str());
                    if (peer_label != m_swap_id) {
                        setStatus(tr(
                            "Peer's session_label disagrees with swap_id — "
                            "their wallet may be on an older binary. "
                            "Cancel this swap; do not retry until both sides "
                            "run a version that derives session strings "
                            "deterministically from swap_id."), /*error=*/true);
                    }
                }
                if (env.exists("session_payload") && env["session_payload"].isStr()) {
                    const QString peer_payload = QString::fromStdString(
                        env["session_payload"].get_str());
                    if (peer_payload != m_swap_id) {
                        setStatus(tr(
                            "Peer's session_payload disagrees with swap_id — "
                            "binary mismatch. Cancel and retry on matching "
                            "versions."), /*error=*/true);
                    }
                }
                // Always force our own input back to swap_id — defense
                // against the user manually editing the field.
                if (m_in_session_label)   m_in_session_label->setText(m_swap_id);
                if (m_in_session_payload) m_in_session_payload->setText(m_swap_id);
            }
            setStatus(tr("Buildtx output auto-pasted from peer DM."));
            persistSession();
            tryAutoStep1();
            return;
        }
    }

    if (!env.exists("round")) return;
    const int round = env["round"].getInt<int>();
    if (round == 1 && env.exists("share") && m_in_peer_share_json) {
        // When we haven't yet run Step 2 (m_KI empty), the peer share
        // hasn't been consumed — accept any incoming. This matters
        // after a binary upgrade where the persisted blob still has
        // an old share bound to a stale session_payload: the
        // dleq_z-presence check we used to do is necessary-but-not-
        // sufficient (both old and new shares can have dleq_z; what
        // matters is which one is bound to the CURRENT session
        // strings on the peer's running dialog).
        const std::string current = m_in_peer_share_json->toPlainText().trimmed().toStdString();
        bool replace = current.empty() || m_KI.isEmpty();
        if (!replace) {
            // Step 2 already ran successfully and produced KI. The
            // peer should not be sending more round-1 shares; ignore.
        }
        if (replace) {
            m_in_peer_share_json->setPlainText(
                QString::fromStdString(env["share"].write(2)));
            setStatus(tr("Peer share auto-pasted from DM."));
            persistSession();
            // Stale Step-2 may have already fired and failed; reset
            // the auto-fire flag so the upgraded share triggers a
            // fresh attempt.
            m_auto_step2_fired = false;
            tryAutoStep2();
            // Bilateral resend: if my Step 1 share was sent before
            // peer subscribed, it never landed. Resend now that peer
            // is clearly online.
            m_auto_step1_dm_sent = false;
            tryAutoSendRound1();
        }
    } else if (round == 3 && env.exists("s_share") && m_in_peer_s_share) {
        // Accept any incoming s_share until Step 4 has produced the
        // final blob. Same staleness class as round 1 — a peer's
        // s_share restored from yesterday's blob blocks today's
        // fresh DM under the empty-only check. (2026-05-14 fix.)
        const QString incoming = QString::fromStdString(env["s_share"].get_str());
        const QString current  = m_in_peer_s_share->text().trimmed();
        if (m_final_blob_hex.isEmpty() &&
            (current.isEmpty() || current != incoming)) {
            m_in_peer_s_share->setText(incoming);
            setStatus(tr("Peer s_share auto-pasted from DM."));
            persistSession();
            // Reset auto-fire flag so a stale earlier attempt that
            // failed under a different s_share doesn't block re-fire.
            m_auto_step4_fired = false;
            tryAutoStep4();
            // Bilateral resend (same reasoning as round 1).
            m_auto_step3_dm_sent = false;
            tryAutoSendRound3();
        }
    }
}

// ─── Auto-coord helpers ──────────────────────────────────────────
//
// Phase 1: jointscan partial. Both wallets need each other's
// scan partial to recover the joint output's (value, blind,
// joint_pubkey). Today the user runs pricoin_jointscan_partial
// manually, exchanges partials by hand, pastes them in. Auto-coord:
// dialog computes its own partial when preconditions met (Nostr
// connected, swap record has pric_funding_txid + pric_funding_height,
// peer xonly known), DMs to peer, fills own field, and fires
// "Run loadshare" automatically once the peer's partial arrives.

// Cooperative-sign session persistence — serializes the dialog's
// in-memory + input-widget state to a JSON blob and stores on the
// swap record. Mirror loader rehydrates on dialog reopen.
//
// Field selection: every m_* shadow we set across step computes
// (alpha, my_*_share, commitment, dleq_*, X_pub_X, KI, L_pi, R_pi,
// L_prime, R_prime, c_pi, c0, mu_P, mu_C, s_others_json, my_s_share,
// final_blob, unsigned_tx, x_share, z_share) plus the user-visible
// input widgets (joint_pubkey, msg, pi, session_id, ring_hash,
// joint_output_id, role, X_pub_peer, session_label, session_payload,
// ring_or_ring_ml, buildtx helpers, loadshare partials/absorb, peer
// share/s_share/X_pub_peer/x_pub).
//
// JSON shape: flat object, key = field name, value = string.
void PricCoopSignDialog::persistSession()
{
    if (!m_wm || m_swap_id.isEmpty()) return;
    UniValue j{UniValue::VOBJ};

    auto put = [&](const char* k, const QString& v) {
        if (!v.isEmpty()) j.pushKV(k, v.toStdString());
    };
    auto put_txt = [&](const char* k, QPlainTextEdit* w) {
        if (w && !w->toPlainText().trimmed().isEmpty()) {
            j.pushKV(k, w->toPlainText().trimmed().toStdString());
        }
    };
    auto put_le = [&](const char* k, QLineEdit* w) {
        if (w && !w->text().trimmed().isEmpty()) {
            j.pushKV(k, w->text().trimmed().toStdString());
        }
    };

    put("alpha", m_alpha);
    put("my_L_share", m_my_L_share);
    put("my_R_share", m_my_R_share);
    put("my_KI_share", m_my_KI_share);
    put("my_D_share", m_my_D_share);
    put("my_commitment", m_my_commitment);
    put("my_dleq_alpha", m_my_dleq_alpha);
    put("my_dleq_x", m_my_dleq_x);
    put("my_dleq_z", m_my_dleq_z);
    put("X_pub_X", m_X_pub_X);
    put("Z_pub_X", m_Z_pub_X);
    put("KI", m_KI);
    put("D", m_D);
    put("L_pi", m_L_pi);
    put("R_pi", m_R_pi);
    put("L_prime", m_L_prime);
    put("R_prime", m_R_prime);
    put("c_pi", m_c_pi);
    put("c0", m_c0);
    put("mu_P", m_mu_P);
    put("mu_C", m_mu_C);
    put("s_others_json", m_s_others_json);
    put("my_s_share", m_my_s_share);
    put("final_blob_hex", m_final_blob_hex);
    put("unsigned_tx_hex", m_unsigned_tx_hex);
    put("x_share", m_x_share);
    put("z_share", m_z_share);
    put("msg_hex", m_msg_hex);
    put("pi", m_pi);
    put("session_id", m_session_id);
    put("ring_hash", m_ring_hash);
    put("joint_output_id", m_joint_output_id);
    put("role", m_role);
    put("T_G", m_T_G);
    put("T_H", m_T_H);
    put("dleq_t", m_dleq_t);
    // session_label / session_payload are intentionally NOT persisted:
    // they're deterministic from the swap_id and any persisted value
    // would just be a chance to diverge after a binary upgrade. See
    // 2026-05-13 root cause: cosigner restored a stale persisted
    // session_payload from a pre-_ml binary; spender's dialog used the
    // ctor default (swap_id); dleq_z proofs computed under different
    // payloads → verify failed at Step 2.
    put("ring_ml_json", m_ring_ml_json);
    put("ring_json", m_ring_json);

    // Input-widget fields that aren't mirrored by an m_* shadow.
    put_le("in_joint_pubkey",  m_in_joint_pubkey);
    put_le("in_X_pub_peer",    m_in_X_pub_peer);
    put_le("in_Z_pub_peer",    m_in_Z_pub_peer);
    put_le("in_X_pub_X",       m_in_X_pub_X);
    put_le("in_Z_pub_X",       m_in_Z_pub_X);
    put_le("in_z_share",       m_in_z_share);
    put_le("in_ls_my_partial", m_in_ls_my_partial);
    put_le("in_ls_peer_partial", m_in_ls_peer_partial);
    put_le("in_peer_s_share",  m_in_peer_s_share);
    put_le("in_bt_joint_txid", m_in_bt_joint_txid);
    put_le("in_bt_joint_vout", m_in_bt_joint_vout);
    put_le("in_bt_joint_value", m_in_bt_joint_value);
    put_le("in_bt_joint_blind", m_in_bt_joint_blind);
    put_le("in_bt_dest",        m_in_bt_dest);
    put_le("in_bt_dest_amount", m_in_bt_dest_amount);
    put_le("in_bt_fee",         m_in_bt_fee);
    put_le("in_bt_ring_size",   m_in_bt_ring_size);
    put_le("in_bt_nlocktime",   m_in_bt_nlocktime);
    put_txt("in_peer_share_json", m_in_peer_share_json);
    put_txt("in_s_others_seed_json", m_in_s_others_seed_json);
    put_txt("in_ring_or_ring_ml",  m_in_ring_or_ring_ml);
    put_txt("in_dleq_t", m_in_dleq_t);

    using namespace ::interfaces;
    const Wallet::CoopsignLeg leg = (m_mode == Mode::PricAdaptor)
        ? Wallet::CoopsignLeg::PricClaimAdaptor
        : Wallet::CoopsignLeg::PricRefund;
    (void)m_wm->wallet().adaptorSwapSetCoopsignSession(
        m_swap_id.toStdString(), leg, j.write(0));
}

void PricCoopSignDialog::loadSessionFromRecord(const std::string& json)
{
    if (json.empty()) return;
    UniValue j;
    if (!j.read(json) || !j.isObject()) return;

    auto load_str = [&](const char* k, QString& dst) {
        if (j.exists(k) && j[k].isStr()) {
            dst = QString::fromStdString(j[k].get_str());
        }
    };
    auto load_le = [&](const char* k, QLineEdit* w) {
        if (w && j.exists(k) && j[k].isStr()) {
            w->setText(QString::fromStdString(j[k].get_str()));
        }
    };
    auto load_txt = [&](const char* k, QPlainTextEdit* w) {
        if (w && j.exists(k) && j[k].isStr()) {
            w->setPlainText(QString::fromStdString(j[k].get_str()));
        }
    };

    load_str("alpha", m_alpha);
    load_str("my_L_share", m_my_L_share);
    load_str("my_R_share", m_my_R_share);
    load_str("my_KI_share", m_my_KI_share);
    load_str("my_D_share", m_my_D_share);
    load_str("my_commitment", m_my_commitment);
    load_str("my_dleq_alpha", m_my_dleq_alpha);
    load_str("my_dleq_x", m_my_dleq_x);
    load_str("my_dleq_z", m_my_dleq_z);
    load_str("X_pub_X", m_X_pub_X);
    load_str("Z_pub_X", m_Z_pub_X);
    load_str("KI", m_KI);
    load_str("D", m_D);
    load_str("L_pi", m_L_pi);
    load_str("R_pi", m_R_pi);
    load_str("L_prime", m_L_prime);
    load_str("R_prime", m_R_prime);
    load_str("c_pi", m_c_pi);
    load_str("c0", m_c0);
    load_str("mu_P", m_mu_P);
    load_str("mu_C", m_mu_C);
    load_str("s_others_json", m_s_others_json);
    load_str("my_s_share", m_my_s_share);
    load_str("final_blob_hex", m_final_blob_hex);
    load_str("unsigned_tx_hex", m_unsigned_tx_hex);
    load_str("x_share", m_x_share);
    load_str("z_share", m_z_share);
    load_str("msg_hex", m_msg_hex);
    load_str("pi", m_pi);
    load_str("session_id", m_session_id);
    load_str("ring_hash", m_ring_hash);
    load_str("joint_output_id", m_joint_output_id);
    load_str("role", m_role);
    load_str("T_G", m_T_G);
    load_str("T_H", m_T_H);
    load_str("dleq_t", m_dleq_t);
    // Intentionally do NOT load session_label / session_payload from
    // the persisted blob — see persistSession() for why. We force
    // these back to swap_id below (after the rest of restore runs).
    load_str("ring_ml_json", m_ring_ml_json);
    load_str("ring_json", m_ring_json);

    // Restore input widgets so the user sees what was filled before.
    auto restore_le = [&](const char* k, QLineEdit* w) {
        if (w && j.exists(k) && j[k].isStr()) {
            const QString v = QString::fromStdString(j[k].get_str());
            if (!v.isEmpty()) w->setText(v);
        }
    };
    restore_le("in_joint_pubkey",   m_in_joint_pubkey);
    restore_le("in_X_pub_peer",     m_in_X_pub_peer);
    restore_le("in_Z_pub_peer",     m_in_Z_pub_peer);
    restore_le("in_X_pub_X",        m_in_X_pub_X);
    restore_le("in_Z_pub_X",        m_in_Z_pub_X);
    restore_le("in_z_share",        m_in_z_share);
    restore_le("in_ls_my_partial",  m_in_ls_my_partial);
    restore_le("in_ls_peer_partial", m_in_ls_peer_partial);
    restore_le("in_peer_s_share",   m_in_peer_s_share);
    restore_le("in_bt_joint_txid",  m_in_bt_joint_txid);
    restore_le("in_bt_joint_vout",  m_in_bt_joint_vout);
    restore_le("in_bt_joint_value", m_in_bt_joint_value);
    restore_le("in_bt_joint_blind", m_in_bt_joint_blind);
    restore_le("in_bt_dest",        m_in_bt_dest);
    restore_le("in_bt_dest_amount", m_in_bt_dest_amount);
    restore_le("in_bt_fee",         m_in_bt_fee);
    restore_le("in_bt_ring_size",   m_in_bt_ring_size);
    restore_le("in_bt_nlocktime",   m_in_bt_nlocktime);
    load_txt("in_peer_share_json",  m_in_peer_share_json);
    load_txt("in_s_others_seed_json", m_in_s_others_seed_json);
    load_txt("in_ring_or_ring_ml",  m_in_ring_or_ring_ml);
    load_txt("in_dleq_t",           m_in_dleq_t);

    // Mirror m_* into the simple-input widgets so the user sees
    // resumption visibly.
    if (m_in_x_share && !m_x_share.isEmpty()) m_in_x_share->setText(m_x_share);
    if (m_in_z_share && !m_z_share.isEmpty()) m_in_z_share->setText(m_z_share);
    if (m_in_msg && !m_msg_hex.isEmpty())     m_in_msg->setText(m_msg_hex);
    if (m_in_pi && !m_pi.isEmpty())           m_in_pi->setText(m_pi);
    if (m_in_session_id && !m_session_id.isEmpty()) m_in_session_id->setText(m_session_id);
    if (m_in_ring_hash && !m_ring_hash.isEmpty())   m_in_ring_hash->setText(m_ring_hash);
    if (m_in_joint_output_id && !m_joint_output_id.isEmpty()) m_in_joint_output_id->setText(m_joint_output_id);
    if (m_in_T_G && !m_T_G.isEmpty()) m_in_T_G->setText(m_T_G);
    if (m_in_T_H && !m_T_H.isEmpty()) m_in_T_H->setText(m_T_H);
    if (m_in_X_pub_X && !m_X_pub_X.isEmpty()) m_in_X_pub_X->setText(m_X_pub_X);
    // Force session strings to swap_id, overriding any stale restored
    // text. Both sides MUST agree on these or every adaptor DLEQ
    // proof fails to verify at Step 2 (CombineAndWalkML). Tying them
    // to swap_id is the only way to guarantee bilateral agreement
    // without a sync DM. Side-channels through the persisted blob
    // are exactly how 2026-05-13's "dleq_z verify failed" snuck in.
    // We re-pin here too (ctor pins immediately post-buildLayout)
    // because loadSessionFromRecord runs as part of dialog
    // construction and is the most likely place a stale value would
    // sneak in (load_str is now a no-op for these keys, but defense
    // in depth — if ANY future code path mutates these mid-restore,
    // this catches it).
    m_session_label   = m_swap_id;
    m_session_payload = m_swap_id;
    if (m_in_session_label)   m_in_session_label->setText(m_swap_id);
    if (m_in_session_payload) m_in_session_payload->setText(m_swap_id);
    if (m_in_role) {
        if (!m_role.isEmpty()) m_in_role->setCurrentText(m_role);
    }

    // Mark auto-coord guards as already-fired for milestones we
    // restored, so we don't re-fire jointscan/loadshare/buildtx.
    if (!m_in_ls_my_partial || !m_in_ls_my_partial->text().trimmed().isEmpty()) {
        m_auto_partial_computed = true;
    }
    if (!m_x_share.isEmpty() && !m_in_joint_pubkey->text().trimmed().isEmpty()) {
        m_auto_loadshare_fired = true;
    }
    if (!m_unsigned_tx_hex.isEmpty()) {
        m_auto_buildtx_fired = true;
    }
    if (!m_my_commitment.isEmpty()) {
        m_auto_step1_fired = true;
    }
    if (!m_KI.isEmpty()) {
        m_auto_step2_fired = true;
    }
    if (!m_my_s_share.isEmpty()) {
        m_auto_step3_fired = true;
    }
    if (!m_final_blob_hex.isEmpty()) {
        m_auto_step4_fired = true;
    }
}

void PricCoopSignDialog::tryAutoComputeJointscanPartial()
{
    if (m_auto_partial_computed) return;
    if (!m_wm) return;
    if (m_swap_id.isEmpty()) return;
    if (!m_in_ls_my_partial) return;
    if (!m_in_ls_my_partial->text().trimmed().isEmpty()) {
        // User pre-filled it — don't clobber.
        m_auto_partial_computed = true;
        tryAutoSendJointscanPartial();
        return;
    }
    auto snap = m_wm->wallet().adaptorSwapGet(m_swap_id.toStdString());
    if (!snap) return;

    // Resolve the funding tx hex + vout. Two sources, in preference order:
    //   1. snap->pric_funding_unsigned_tx_hex — set by Alice's wallet
    //      after walletsendct_ring(broadcast=false) so cooperative
    //      presigs can run BEFORE the funding tx hits the chain. This
    //      is the post-2026-05-15 protocol order (presigs before
    //      funding); the funding doesn't yet exist on-chain.
    //   2. on-chain via getrawtransaction (pric_funding_txid_hex +
    //      pric_funding_height) — fallback for already-funded swaps
    //      or for the legacy ceremony order. The funding tx is in a
    //      block and we look it up by blockhash so this works without
    //      -txindex.
    std::string tx_hex;
    int32_t resolved_vout = -1;
    if (!snap->pric_funding_unsigned_tx_hex.empty()
        && snap->pric_funding_planned_vout >= 0) {
        tx_hex = snap->pric_funding_unsigned_tx_hex;
        resolved_vout = snap->pric_funding_planned_vout;
    } else if (!snap->pric_funding_txid_hex.empty()
               && snap->pric_funding_vout >= 0
               && snap->pric_funding_height > 0) {
        std::string blockhash_hex;
        {
            UniValue p_h{UniValue::VARR};
            p_h.push_back(snap->pric_funding_height);
            auto rh = callRpc("getblockhash", p_h.write(0));
            if (!rh.ok) {
                setStatus(tr("Auto: getblockhash(%1) failed: %2")
                    .arg(snap->pric_funding_height)
                    .arg(QString::fromStdString(rh.error_msg)), true);
                return;
            }
            UniValue v_h;
            v_h.read(rh.json);
            if (v_h.isStr()) blockhash_hex = v_h.get_str();
        }
        if (blockhash_hex.empty()) return;

        UniValue p_g{UniValue::VARR};
        p_g.push_back(snap->pric_funding_txid_hex);
        p_g.push_back(0);  // verbosity 0 → raw hex
        p_g.push_back(blockhash_hex);
        auto rg = callRpc("getrawtransaction", p_g.write(0));
        if (!rg.ok) {
            setStatus(tr("Auto: getrawtransaction failed: %1")
                .arg(QString::fromStdString(rg.error_msg)), true);
            return;
        }
        UniValue v_g;
        v_g.read(rg.json);
        tx_hex = v_g.isStr() ? v_g.get_str() : std::string{};
        resolved_vout = snap->pric_funding_vout;
    } else {
        // Neither source is ready — try again on the next refresh tick.
        return;
    }
    if (tx_hex.empty() || resolved_vout < 0) return;

    UniValue p_p{UniValue::VARR};
    p_p.push_back(tx_hex);
    p_p.push_back(resolved_vout);
    auto rp = callRpc("pricoin_jointscan_partial", p_p.write(0));
    if (!rp.ok) {
        setStatus(tr("Auto: pricoin_jointscan_partial failed: %1")
            .arg(QString::fromStdString(rp.error_msg)), true);
        return;
    }
    UniValue v_p;
    v_p.read(rp.json);
    if (!v_p.exists("partial") || !v_p["partial"].isStr()) return;
    const QString partial = QString::fromStdString(v_p["partial"].get_str());
    m_in_ls_my_partial->setText(partial);
    m_auto_partial_computed = true;
    setStatus(tr("Auto: scan partial computed locally."));

    tryAutoSendJointscanPartial();
}

void PricCoopSignDialog::tryAutoSendJointscanPartial()
{
    if (m_auto_partial_sent) return;
    if (!m_nostr || m_relay_connected_count == 0) return;
    if (m_peer_xonly.isEmpty()) return;
    if (!m_in_ls_my_partial) return;
    const QString partial = m_in_ls_my_partial->text().trimmed();
    if (partial.size() != 66) return;

    UniValue env{UniValue::VOBJ};
    env.pushKV("v",        1);
    env.pushKV("leg",      m_mode == Mode::PricAdaptor ? "pric_claim_adaptor"
                                                        : "pric_refund");
    env.pushKV("swap_id",  m_swap_id.toStdString());
    env.pushKV("kind",     "jointscan");
    env.pushKV("partial",  partial.toStdString());
    const QString plaintext = QString::fromStdString(env.write(0));
    if (m_nostr->publishDirectMessage(m_peer_xonly, plaintext)) {
        m_auto_partial_sent = true;
        setStatus(tr("Auto: scan partial DM sent to peer."));
    }
}

void PricCoopSignDialog::tryAutoLoadshare()
{
    if (m_auto_loadshare_fired) return;
    if (!m_in_ls_my_partial || !m_in_ls_peer_partial) return;
    const QString my   = m_in_ls_my_partial->text().trimmed();
    const QString peer = m_in_ls_peer_partial->text().trimmed();
    if (my.size() != 66 || peer.size() != 66) return;
    m_auto_loadshare_fired = true;
    setStatus(tr("Auto: both partials present — running loadshare."));
    onRunLoadshare();
    // onRunLoadshare itself fires tryAutoBuildtx + tryAutoStep1
    // at the end via the explicit calls there, so don't double-fire.
}

// Phase 2a — auto-DM own X_pub_X to peer. Adaptor mode only — plain
// mode doesn't use X_pub. Each party sends their own; receive fills
// m_in_X_pub_peer. Independent of spender/cosigner role; both fire.
void PricCoopSignDialog::tryAutoSendXpubAnnounce()
{
    if (m_auto_xpub_announced) return;
    if (m_mode != Mode::PricAdaptor) return;
    if (!m_nostr || m_relay_connected_count == 0) return;
    if (m_peer_xonly.isEmpty()) return;
    if (!m_in_X_pub_X) return;
    const QString xpub = m_in_X_pub_X->text().trimmed();
    if (xpub.size() != 66) return;  // 33-byte hex

    UniValue env{UniValue::VOBJ};
    env.pushKV("v",       1);
    env.pushKV("leg",     "pric_claim_adaptor");
    env.pushKV("swap_id", m_swap_id.toStdString());
    env.pushKV("kind",    "xpub_announce");
    env.pushKV("x_pub",   xpub.toStdString());
    // Also include z_pub if we already have a z_share filled in
    // (typically the spender has it post-buildtx; the cosigner has it
    // after receiving the buildtx DM). Best-effort — if absent, the
    // receiver will see only x_pub and the Z_pub_peer field stays
    // empty until later sync.
    if (m_in_Z_pub_X) {
        const QString zpub = m_in_Z_pub_X->text().trimmed();
        if (zpub.size() == 66) env.pushKV("z_pub", zpub.toStdString());
    }
    const QString plaintext = QString::fromStdString(env.write(0));
    if (m_nostr->publishDirectMessage(m_peer_xonly, plaintext)) {
        m_auto_xpub_announced = true;
        setStatus(tr("Auto: own X_pub announced to peer."));
    }
}

// Phase 2b — auto-buildtx (spender only). In LTC swap:
//   PricAdaptor (claim leg) → spender = Bob (PRIC buyer).
//   PricPlain   (refund leg) → spender = Alice (PRIC funder).
// Cosigner needs to receive the buildtx output (msg/pi/ring/...) via
// DM to populate its own inputs without paste. Sender DMs after fire.
//
// Preconditions: loadshare done (joint_pubkey + x_share + joint_blind
// populated), swap record loaded with role + pric funding info.
void PricCoopSignDialog::tryAutoBuildtx()
{
    if (m_auto_buildtx_fired) return;
    if (!m_wm) return;
    if (m_swap_id.isEmpty()) return;
    if (!m_in_joint_pubkey || m_in_joint_pubkey->text().trimmed().size() != 66) return;
    if (!m_in_bt_joint_blind || m_in_bt_joint_blind->text().trimmed().size() != 64) return;

    // Spender role detection.
    auto snap = m_wm->wallet().adaptorSwapGet(m_swap_id.toStdString());
    if (!snap) return;
    const bool i_am_alice = (snap->role == "alice");
    const bool i_am_spender =
        (m_mode == Mode::PricAdaptor && !i_am_alice) ||
        (m_mode == Mode::PricPlain   &&  i_am_alice);
    if (!i_am_spender) {
        // Cosigner waits for the buildtx DM from peer; don't fire
        // buildtx locally.
        m_auto_buildtx_fired = true;  // gate to avoid re-checks
        return;
    }

    m_auto_buildtx_fired = true;
    setStatus(tr("Auto: I'm the spender — running buildtx."));
    onRunBuildtx();
    tryAutoSendBuildtx();
}

void PricCoopSignDialog::tryAutoSendBuildtx()
{
    if (m_auto_buildtx_sent) return;
    if (!m_nostr || m_relay_connected_count == 0) return;
    if (m_peer_xonly.isEmpty()) return;
    // m_unsigned_tx_hex set by onRunBuildtx on success; m_in_msg/pi/
    // ring_or_ring_ml also populated by onRunBuildtx.
    if (m_unsigned_tx_hex.isEmpty()) return;
    if (!m_in_msg || m_in_msg->text().trimmed().size() != 64) return;
    if (!m_in_pi  || m_in_pi->text().trimmed().isEmpty()) return;
    if (!m_in_ring_or_ring_ml
        || m_in_ring_or_ring_ml->toPlainText().trimmed().isEmpty()) return;

    UniValue env{UniValue::VOBJ};
    env.pushKV("v",        1);
    env.pushKV("leg",      m_mode == Mode::PricAdaptor ? "pric_claim_adaptor"
                                                        : "pric_refund");
    env.pushKV("swap_id",  m_swap_id.toStdString());
    env.pushKV("kind",     "buildtx");
    env.pushKV("sighash",  m_in_msg->text().trimmed().toStdString());
    env.pushKV("pi",       m_in_pi->text().trimmed().toInt());
    UniValue ring_v;
    if (ring_v.read(m_in_ring_or_ring_ml->toPlainText().trimmed().toStdString())
        && (ring_v.isArray() || ring_v.isObject())) {
        env.pushKV("ring_or_ml", ring_v);
    }
    env.pushKV("joint_pubkey",      m_in_joint_pubkey->text().trimmed().toStdString());
    env.pushKV("session_id",        m_in_session_id->text().trimmed().toStdString());
    if (m_in_ring_hash) {
        env.pushKV("ring_hash",     m_in_ring_hash->text().trimmed().toStdString());
    }
    if (m_in_joint_output_id) {
        env.pushKV("joint_output_id",
                   m_in_joint_output_id->text().trimmed().toStdString());
    }
    // Spender's z_other is cosigner's z_share — needed for BOTH plain
    // and adaptor_ml mode. The buildtx echo includes "z_other_for_peer"
    // (extract from m_out_buildtx, parsed JSON we displayed).
    {
        UniValue echo;
        if (echo.read(m_out_buildtx->toPlainText().toStdString()) && echo.isObject()
            && echo.exists("z_other_for_peer") && echo["z_other_for_peer"].isStr()) {
            env.pushKV("z_other", echo["z_other_for_peer"].get_str());
        }
    }
    if (m_mode == Mode::PricAdaptor) {
        // Adaptor mode: spender includes own X_pub_X (= x_share·G),
        // own Z_pub_X (= z_share·G), and session_label/payload so the
        // cosigner can fill them and Step 1 can fire.
        if (m_in_X_pub_X) {
            env.pushKV("x_pub_spender",
                       m_in_X_pub_X->text().trimmed().toStdString());
        }
        if (m_in_Z_pub_X) {
            env.pushKV("z_pub_spender",
                       m_in_Z_pub_X->text().trimmed().toStdString());
        }
        // session_label / session_payload are deterministic from
        // swap_id on both sides — we still ship them in the envelope
        // so the receive side can DETECT a version mismatch (its
        // validator raises a clear error if the peer sends a
        // non-swap_id value). Do NOT pull from the widget here in
        // case it's been corrupted; pull straight from m_swap_id.
        env.pushKV("session_label",   m_swap_id.toStdString());
        env.pushKV("session_payload", m_swap_id.toStdString());
    }

    const QString plaintext = QString::fromStdString(env.write(0));
    if (m_nostr->publishDirectMessage(m_peer_xonly, plaintext)) {
        m_auto_buildtx_sent = true;
        setStatus(tr("Auto: buildtx output DM sent to peer."));
    }
}

// Phase 3 — auto-fire the four-step ceremony once required inputs are
// populated. Step 1 + Step 3 also auto-DM their share/s_share so the
// user no longer needs to click Send-DM buttons. Step 2 + Step 4 fire
// when the peer's DM arrives (auto-paste already populates the input;
// these helpers detect that and advance).
//
// Inputs that must be present BEFORE Step 1 can fire:
//   - x_share (from loadshare)
//   - joint_pubkey (from loadshare)
//   - msg, pi, ring_or_ml (from buildtx — manual today; Phase 2 TODO)
//   - session_id, ring_hash, joint_output_id (manual today)
//   - For adaptor mode: T_G/T_H/dleq_t (auto-filled by ctor),
//     X_pub_X, session_label, session_payload (manual today)
//   - For plain mode:   z_share (auto-filled by buildtx for spender,
//                       received via buildtx-DM for cosigner — Phase 2)

void PricCoopSignDialog::tryAutoStep1()
{
    if (m_auto_step1_fired) return;
    if (!m_in_x_share || !m_in_joint_pubkey || !m_in_msg
        || !m_in_pi || !m_in_session_id) return;
    if (m_in_x_share->text().trimmed().size() != 64) return;
    if (m_in_joint_pubkey->text().trimmed().size() != 66) return;
    if (m_in_msg->text().trimmed().size() != 64) return;
    if (m_in_session_id->text().trimmed().size() != 64) return;
    if (m_in_pi->text().trimmed().isEmpty()) return;
    if (!m_in_ring_or_ring_ml
        || m_in_ring_or_ring_ml->toPlainText().trimmed().isEmpty()) return;
    if (m_mode == Mode::PricAdaptor) {
        // Multi-layer adaptor round 1 needs ALL of: T_G + T_H +
        // X_pub_X + Z_pub_X + z_share. Previously this gate only
        // checked T_G + X_pub_X; on the cosigner side that meant
        // Step 1 could fire after loadshare but BEFORE the spender's
        // buildtx DM arrived (which is what carries z_other + thus
        // Z_pub_X). Result: round1_ml fails on Z_pub_X validation
        // or — worse — the DLEQ proofs end up bound to a stale
        // Z_pub_X if the field was restored from a prior session.
        if (!m_in_T_G || m_in_T_G->text().trimmed().size() != 66) return;
        if (!m_in_T_H || m_in_T_H->text().trimmed().size() != 66) return;
        if (!m_in_X_pub_X || m_in_X_pub_X->text().trimmed().size() != 66) return;
        if (!m_in_Z_pub_X || m_in_Z_pub_X->text().trimmed().size() != 66) return;
        if (!m_in_z_share || m_in_z_share->text().trimmed().size() != 64) return;
        // dleq_t must also be present — combine_ml verifies it on
        // both sides at Step 2, and the validator we run there
        // wants the proof bytes to parse.
        if (!m_in_dleq_t || m_in_dleq_t->toPlainText().trimmed().isEmpty()) return;
    } else {
        if (!m_in_z_share || m_in_z_share->text().trimmed().size() != 64) return;
    }
    m_auto_step1_fired = true;
    setStatus(tr("Auto: inputs ready — running Step 1."));
    onStep1Compute();
    tryAutoSendRound1();
}

void PricCoopSignDialog::tryAutoSendRound1()
{
    if (m_auto_step1_dm_sent) return;
    if (m_my_commitment.isEmpty()) return;
    if (!m_nostr || m_relay_connected_count == 0 || m_peer_xonly.isEmpty()) return;
    onSendDmRound1();
    m_auto_step1_dm_sent = true;
}

void PricCoopSignDialog::tryAutoStep2()
{
    if (m_auto_step2_fired) return;
    // Gate on the actual Step-1-intermediate state (m_my_commitment),
    // not the auto-fire flag. The dialog's Step 1 can run via the
    // auto chain OR a manual button click; either way commits the
    // nonce. Step 2 needs Step 1's output, not the auto-fire flag.
    // (Previously gated on m_auto_step1_fired only — manual Step 1
    // wouldn't progress to auto Step 2 on peer-share receive.)
    if (m_my_commitment.isEmpty()) return;
    if (!m_in_peer_share_json
        || m_in_peer_share_json->toPlainText().trimmed().isEmpty()) return;
    m_auto_step2_fired = true;
    setStatus(tr("Auto: peer share present — running Step 2."));
    onStep2Compute();
    tryAutoStep3();
}

void PricCoopSignDialog::tryAutoStep3()
{
    if (m_auto_step3_fired) return;
    // Gate on Step 2 intermediate state (m_KI), not the auto-fire flag.
    if (m_KI.isEmpty()) return;
    m_auto_step3_fired = true;
    setStatus(tr("Auto: Step 2 complete — running Step 3."));
    onStep3Compute();
    tryAutoSendRound3();
}

void PricCoopSignDialog::tryAutoSendRound3()
{
    if (m_auto_step3_dm_sent) return;
    if (m_my_s_share.isEmpty()) return;
    if (!m_nostr || m_relay_connected_count == 0 || m_peer_xonly.isEmpty()) return;
    onSendDmRound3();
    m_auto_step3_dm_sent = true;
}

void PricCoopSignDialog::tryAutoStep4()
{
    if (m_auto_step4_fired) return;
    // Gate on Step 3 intermediate state (m_my_s_share), not the
    // auto-fire flag. Manual Step 3 also sets this.
    if (m_my_s_share.isEmpty()) return;
    if (!m_in_peer_s_share || m_in_peer_s_share->text().trimmed().isEmpty()) return;
    m_auto_step4_fired = true;
    setStatus(tr("Auto: peer s_share present — running Step 4."));
    onStep4Compute();
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
    if (m_status_label) {
        m_status_label->setStyleSheet(error
            ? QStringLiteral("QLabel { color: #b71c1c; }")
            : QStringLiteral("QLabel { color: #1b5e20; }"));
        m_status_label->setText(msg);
    }
    // Mirror to the progress UI so the user-visible label stays in
    // sync without us having to call two setters at every site.
    if (m_progress_action) {
        m_progress_action->setStyleSheet(error
            ? QStringLiteral("QLabel { color: #b71c1c; padding: 0 8px 8px 8px; }")
            : QStringLiteral("QLabel { color: #555; padding: 0 8px 8px 8px; }"));
        m_progress_action->setText(msg);
    }
    // Coarse-grained state line — derived from the auto-fire flags
    // that already track ceremony progress. Cheaper than threading
    // explicit state updates through every setStatus call site.
    if (m_progress_state) {
        // States ordered most-advanced → least-advanced; first match
        // wins. "fired" means we kicked off the RPC for that step;
        // having the step's OUTPUT in a member shadow doesn't bump
        // us forward (the next step has to actually fire). Earlier
        // version mislabeled "Step 3 done, waiting for peer s_share"
        // as "Step 4" because m_my_s_share-non-empty looked like 4.
        QString state;
        if (!m_final_blob_hex.isEmpty()) {
            state = tr("Done — cooperative signature produced.");
        } else if (m_auto_step4_fired) {
            state = tr("Step 4 of 4 — assembling pre-signature…");
        } else if (!m_my_s_share.isEmpty()) {
            state = tr("Step 3 of 4 done — waiting for peer's close share…");
        } else if (m_auto_step3_fired) {
            state = tr("Step 3 of 4 — computing close share…");
        } else if (!m_KI.isEmpty()) {
            state = tr("Step 2 of 4 done — running Step 3…");
        } else if (m_auto_step2_fired) {
            state = tr("Step 2 of 4 — combining round-1 shares…");
        } else if (!m_my_commitment.isEmpty()) {
            state = tr("Step 1 of 4 done — waiting for peer's round-1 share…");
        } else if (m_auto_step1_fired) {
            state = tr("Step 1 of 4 — computing my round-1 share…");
        } else if (m_auto_buildtx_fired) {
            state = tr("Building spend transaction…");
        } else if (m_auto_loadshare_fired) {
            state = tr("Recovering joint output share…");
        } else if (m_auto_partial_computed) {
            state = tr("Scanning joint stealth output…");
        } else {
            state = tr("Connecting…");
        }
        m_progress_state->setText(state);
    }
}

void PricCoopSignDialog::buildLayout(const QString& title)
{
    setWindowTitle(title);
    const bool adaptor = (m_mode == Mode::PricAdaptor);

    auto* outer = new QVBoxLayout(this);

    // ─── Nostr DM section (optional auto-delivery) ────────────
    {
        auto* box = new QGroupBox(tr("Nostr DM (optional — auto-deliver share/s_share to peer)"), this);
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
        connect(m_btn_nostr_connect, &QPushButton::clicked, this, &PricCoopSignDialog::onNostrConnectClicked);
        updateNostrStatus();
    }

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

        // z_share is needed for BOTH plain and adaptor multi-layer.
        // Spender: filled from buildtx's z_self. Cosigner: filled from
        // peer's buildtx-DM `z_other`. Without it, adaptor_round1_ml
        // can't build D_share, and CombineAndWalkML / consensus
        // VerifyMultiLayer will reject the resulting sig.
        m_in_z_share = new QLineEdit(box);
        m_in_z_share->setEchoMode(QLineEdit::Password);
        m_in_z_share->setPlaceholderText(tr("32-byte commitment-offset share (multi-layer): z_self for spender, z_other for peer"));
        form->addRow(tr("z_share:"), m_in_z_share);

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
        // Auto-populate with random hex — both parties must use the
        // SAME ring_hash (it keys the nonce-record store). Spender
        // ships their random value via the buildtx auto-DM; cosigner
        // overwrites their auto-default on receive. Manual users
        // are still free to overwrite locally.
        m_in_ring_hash->setText(RandomHex32());
        m_in_ring_hash->setToolTip(tr("32-byte ring hash — both parties MUST use the same value"));
        form->addRow(tr("ring_hash:"), m_in_ring_hash);

        m_in_joint_output_id = new QLineEdit(box);
        m_in_joint_output_id->setText(RandomHex32());
        m_in_joint_output_id->setToolTip(tr("UTXO id being spent — both parties MUST use the same value"));
        form->addRow(tr("joint_output_id:"), m_in_joint_output_id);

        m_in_role = new QComboBox(box);
        m_in_role->addItem(QStringLiteral("initiator"));
        m_in_role->addItem(QStringLiteral("responder"));
        form->addRow(tr("role:"), m_in_role);

        if (adaptor) {
            m_in_X_pub_X = new QLineEdit(box);
            m_in_X_pub_X->setPlaceholderText(tr("33-byte public spend share = x_share · G"));
            form->addRow(tr("X_pub_X (mine):"), m_in_X_pub_X);

            m_in_Z_pub_X = new QLineEdit(box);
            m_in_Z_pub_X->setPlaceholderText(tr("33-byte public commitment-offset share = z_share · G"));
            form->addRow(tr("Z_pub_X (mine):"), m_in_Z_pub_X);

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
            // Default to the swap_id. Bob's adaptor_dleq_prove (called
            // at adaptor-setup time in pricoin_swaps_page.cpp's Bob
            // branch) signs the DLEQ proof with session_label = sid
            // AND session_payload = sid. For Step 2's combine to
            // verify Bob's proof, the cooperative-sign dialog MUST
            // use the SAME values. Otherwise the DLEQ challenge
            // differs and verify fails with "DLEQ verify failed".
            // (Previously random per-dialog — that was the root cause
            // of the persistent Step-2 failure on 2026-05-11.)
            m_in_session_label->setText(m_swap_id);
            m_in_session_label->setReadOnly(true);
            m_in_session_label->setToolTip(tr("Session label — deterministically derived from swap_id; read-only (manual edits broke DLEQ verify in live testing)"));
            form->addRow(tr("session_label:"), m_in_session_label);

            m_in_session_payload = new QLineEdit(box);
            m_in_session_payload->setText(m_swap_id);
            m_in_session_payload->setReadOnly(true);
            m_in_session_payload->setToolTip(tr("Session payload — deterministically derived from swap_id; read-only"));
            form->addRow(tr("session_payload:"), m_in_session_payload);
        }

        m_in_ring_or_ring_ml = new QPlainTextEdit(box);
        MakeMono(m_in_ring_or_ring_ml);
        m_in_ring_or_ring_ml->setMaximumHeight(110);
        m_in_ring_or_ring_ml->setPlaceholderText(
            tr("ring_ml as JSON array of {P,W} objects, e.g. [{\"P\":\"<P0>\",\"W\":\"<W0>\"},...]"));
        form->addRow(tr("ring_ml (JSON):"), m_in_ring_or_ring_ml);

        steps_v->addWidget(box);
    }

    // ─── Loadshare helper (auto-derives x_share + blind + value) ───
    {
        auto* box = MakeStepBox(tr("Loadshare helper (optional — auto-derives x_share + joint_blind + value)"),
                                  scroll_inner);
        auto* form = new QFormLayout(box);
        form->addRow(new QLabel(tr("Both parties first run pricoin_jointscan_partial on the joint stealth tx, then exchange the partials. Provide both partials here; one party (the h_s absorber) sets <i>absorb=true</i>, the other false. The result auto-fills <i>x_share</i> + the buildtx <i>joint_blind</i>/<i>joint_pubkey</i>/<i>value</i>."), box));

        m_in_ls_my_partial = new QLineEdit(box);
        m_in_ls_my_partial->setPlaceholderText(tr("My pricoin_jointscan_partial output (hex blob)"));
        form->addRow(tr("My partial:"), m_in_ls_my_partial);

        m_in_ls_peer_partial = new QLineEdit(box);
        m_in_ls_peer_partial->setPlaceholderText(tr("Peer's pricoin_jointscan_partial output (hex blob)"));
        form->addRow(tr("Peer partial:"), m_in_ls_peer_partial);

        m_in_ls_absorb = new QComboBox(box);
        m_in_ls_absorb->addItem(QStringLiteral("true"));
        m_in_ls_absorb->addItem(QStringLiteral("false"));
        m_in_ls_absorb->setToolTip(tr("Exactly one party must set absorb_shared_secret=true so the two x_shares sum to the joint one-time priv."));
        form->addRow(tr("absorb_shared_secret:"), m_in_ls_absorb);

        m_btn_run_loadshare = new QPushButton(tr("Run loadshare → fill x_share / blind / value"), box);
        form->addRow(QString(), m_btn_run_loadshare);

        m_out_loadshare = new QPlainTextEdit(box);
        MakeMono(m_out_loadshare);
        m_out_loadshare->setReadOnly(true);
        m_out_loadshare->setMaximumHeight(120);
        form->addRow(tr("Output:"), m_out_loadshare);
        steps_v->addWidget(box);
        connect(m_btn_run_loadshare, &QPushButton::clicked, this, &PricCoopSignDialog::onRunLoadshare);
    }

    // ─── Buildtx helper (spender-only — pre-fills msg/ring_ml/pi/z) ───
    {
        auto* box = MakeStepBox(tr("Buildtx helper (spender-only — pre-fills msg / ring_ml / pi / z_self)"),
                                  scroll_inner);
        auto* form = new QFormLayout(box);
        form->addRow(new QLabel(tr("Calls pricoin_jointspend_buildtx on the joint stealth output to produce the sighash + ring + signer index. The peer pastes these values into their own dialog manually (or via a copyable bundle)."), box));

        m_in_bt_joint_txid = new QLineEdit(box);
        m_in_bt_joint_txid->setPlaceholderText(tr("32-byte joint output txid"));
        form->addRow(tr("Joint txid:"), m_in_bt_joint_txid);

        m_in_bt_joint_vout = new QLineEdit(box);
        m_in_bt_joint_vout->setText(QStringLiteral("0"));
        form->addRow(tr("Joint vout:"), m_in_bt_joint_vout);

        m_in_bt_joint_value = new QLineEdit(box);
        m_in_bt_joint_value->setPlaceholderText(tr("Joint output value in PRIC (e.g. 1.0)"));
        form->addRow(tr("Joint value (PRIC):"), m_in_bt_joint_value);

        m_in_bt_joint_blind = new QLineEdit(box);
        m_in_bt_joint_blind->setEchoMode(QLineEdit::Password);
        m_in_bt_joint_blind->setPlaceholderText(tr("32-byte joint_blind / b_prev (from loadshare)"));
        form->addRow(tr("Joint blind:"), m_in_bt_joint_blind);

        m_in_bt_dest = new QLineEdit(box);
        m_in_bt_dest->setPlaceholderText(tr("Recipient PRIC stealth address (Bob's for claim, Alice's for refund)"));
        form->addRow(tr("Destination:"), m_in_bt_dest);

        m_in_bt_dest_amount = new QLineEdit(box);
        m_in_bt_dest_amount->setPlaceholderText(tr("Destination amount in PRIC"));
        form->addRow(tr("Dest amount:"), m_in_bt_dest_amount);

        m_in_bt_fee = new QLineEdit(box);
        m_in_bt_fee->setText(QStringLiteral("0.00001"));
        form->addRow(tr("Fee (PRIC):"), m_in_bt_fee);

        m_in_bt_ring_size = new QLineEdit(box);
        m_in_bt_ring_size->setText(QStringLiteral("4"));
        form->addRow(tr("Ring size:"), m_in_bt_ring_size);

        m_in_bt_nlocktime = new QLineEdit(box);
        m_in_bt_nlocktime->setText((m_mode == Mode::PricAdaptor)
            ? QStringLiteral("0")
            : QStringLiteral(""));
        m_in_bt_nlocktime->setPlaceholderText(tr("0 for claim; pric_refund_height for refund (auto-pulled from swap record)"));
        form->addRow(tr("nlocktime:"), m_in_bt_nlocktime);

        m_btn_run_buildtx = new QPushButton(tr("Run buildtx → fill msg / ring / pi / z_self"), box);
        form->addRow(QString(), m_btn_run_buildtx);

        m_out_buildtx = new QPlainTextEdit(box);
        MakeMono(m_out_buildtx);
        m_out_buildtx->setReadOnly(true);
        m_out_buildtx->setMaximumHeight(180);
        form->addRow(tr("Output (send ring/pi/msg/z_other/joint_pubkey to peer):"),
                     m_out_buildtx);
        steps_v->addWidget(box);
        connect(m_btn_run_buildtx, &QPushButton::clicked, this, &PricCoopSignDialog::onRunBuildtx);
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
        m_btn_send_dm_round1 = new QPushButton(tr("Send share via Nostr DM"), box);
        m_btn_send_dm_round1->setEnabled(false);
        layout->addWidget(m_btn_send_dm_round1);
        steps_v->addWidget(box);
        connect(m_btn_step1,          &QPushButton::clicked, this, &PricCoopSignDialog::onStep1Compute);
        connect(m_btn_send_dm_round1, &QPushButton::clicked, this, &PricCoopSignDialog::onSendDmRound1);
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
            m_in_Z_pub_peer = new QLineEdit(box);
            m_in_Z_pub_peer->setPlaceholderText(tr("33-byte public commitment-offset share = peer's z · G"));
            peer_pub_row->addRow(tr("Peer Z_pub:"), m_in_Z_pub_peer);
            layout->addLayout(peer_pub_row);
        } else {
            layout->addWidget(new QLabel(tr("s_others (decoy closing scalars, JSON array of 32-byte hex; entry at pi will be ignored — fill with zeros):"), box));
            m_in_s_others_seed_json = new QPlainTextEdit(box);
            MakeMono(m_in_s_others_seed_json);
            m_in_s_others_seed_json->setMaximumHeight(80);
            m_in_s_others_seed_json->setPlaceholderText(tr("[\"<s0>\",\"<s1>\",\"<s2>\",\"<s3>\"]"));
            // Auto-fill with deterministic values derived from swap_id +
            // index, so both parties produce the same array without
            // needing to DM-exchange it. CSHA256(swap_id || idx_byte) ×
            // ring_size. Default ring size is 4 (matches the
            // hardcoded buildtx ring_size below).
            if (!m_swap_id.isEmpty()) {
                UniValue arr{UniValue::VARR};
                const std::string sid_str = m_swap_id.toStdString();
                for (unsigned char i = 0; i < 4; ++i) {
                    unsigned char digest[32];
                    CSHA256()
                        .Write(reinterpret_cast<const unsigned char*>(
                                   sid_str.data()), sid_str.size())
                        .Write(reinterpret_cast<const unsigned char*>(
                                   "pricoin/s_others_v1/"), 20)
                        .Write(&i, 1)
                        .Finalize(digest);
                    arr.push_back(HexStr(std::span<const unsigned char>{
                        digest, 32}));
                }
                m_in_s_others_seed_json->setPlainText(
                    QString::fromStdString(arr.write(0)));
            }
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
        m_btn_send_dm_round3 = new QPushButton(tr("Send s_share via Nostr DM"), box);
        m_btn_send_dm_round3->setEnabled(false);
        layout->addWidget(m_btn_send_dm_round3);
        steps_v->addWidget(box);
        connect(m_btn_step3,          &QPushButton::clicked, this, &PricCoopSignDialog::onStep3Compute);
        connect(m_btn_send_dm_round3, &QPushButton::clicked, this, &PricCoopSignDialog::onSendDmRound3);
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

        // Broadcast convenience: PricPlain (refund) only — the
        // adaptor variant produces a pre-sig that needs to be
        // adapted with t before it's broadcastable.
        if (m_mode == Mode::PricPlain) {
            m_btn_broadcast = new QPushButton(
                tr("Broadcast refund + watch + announce"), box);
            m_btn_broadcast->setEnabled(false);
            layout->addWidget(m_btn_broadcast);
            connect(m_btn_broadcast, &QPushButton::clicked, this,
                     &PricCoopSignDialog::onBroadcastClicked);
        }

        steps_v->addWidget(box);
        connect(m_btn_step4, &QPushButton::clicked, this, &PricCoopSignDialog::onStep4Compute);
    }

    steps_v->addStretch();
    scroll->setWidget(scroll_inner);
    m_scroll_area = scroll;
    outer->addWidget(scroll, /*stretch=*/1);

    // ─── Progress-only UI (default for live use) ──────────────────
    // The block above is the "advanced" view exposing every step and
    // every cryptographic field. For real users we want a one-line
    // "your trade is running, leave this open" header and a status
    // line. The advanced view is hidden behind a toggle button so
    // anyone debugging a stuck swap can still see what's going on.
    {
        m_progress_header = new QLabel(this);
        m_progress_header->setWordWrap(true);
        m_progress_header->setStyleSheet(
            QStringLiteral("QLabel { font-size: 14pt; padding: 16px 8px; }"));
        m_progress_header->setText(tr(
            "<b>Cooperative signing in progress.</b><br/>"
            "Leave this window open until the swap completes. The "
            "ceremony runs automatically — no action needed."));
        outer->addWidget(m_progress_header);

        m_progress_state = new QLabel(this);
        m_progress_state->setWordWrap(true);
        m_progress_state->setStyleSheet(
            QStringLiteral("QLabel { font-weight: bold; padding: 4px 8px; }"));
        m_progress_state->setText(tr("Starting…"));
        outer->addWidget(m_progress_state);

        m_progress_action = new QLabel(this);
        m_progress_action->setWordWrap(true);
        m_progress_action->setStyleSheet(
            QStringLiteral("QLabel { color: #555; padding: 0 8px 8px 8px; }"));
        outer->addWidget(m_progress_action);
    }

    m_status_label = new QLabel(this);
    m_status_label->setWordWrap(true);
    outer->addWidget(m_status_label);

    auto* bb = new QDialogButtonBox(QDialogButtonBox::Close, this);
    m_btn_toggle_advanced = new QPushButton(tr("Show advanced…"), this);
    m_btn_toggle_advanced->setCheckable(true);
    connect(m_btn_toggle_advanced, &QPushButton::toggled, this, [this](bool on) {
        if (m_scroll_area) m_scroll_area->setVisible(on);
        if (m_btn_toggle_advanced) {
            m_btn_toggle_advanced->setText(on ? tr("Hide advanced") : tr("Show advanced…"));
        }
    });
    bb->addButton(m_btn_toggle_advanced, QDialogButtonBox::ActionRole);
    connect(bb, &QDialogButtonBox::rejected, this, &QDialog::accept);
    outer->addWidget(bb);
}

void PricCoopSignDialog::setProgressOnlyMode(bool on)
{
    m_progress_only = on;
    if (m_scroll_area) m_scroll_area->setVisible(!on);
    if (m_progress_header) m_progress_header->setVisible(true);
    if (m_progress_state) m_progress_state->setVisible(true);
    if (m_progress_action) m_progress_action->setVisible(true);
    if (m_btn_toggle_advanced) {
        m_btn_toggle_advanced->setChecked(!on);
        m_btn_toggle_advanced->setText(on ? tr("Show advanced…") : tr("Hide advanced"));
    }
    // Compact window in progress-only mode, but tall enough to show
    // the header + state + status + bottom button bar without the
    // status line getting clipped under the buttons.
    if (on) {
        resize(640, 360);
        setMinimumSize(560, 320);
    }
}

void PricCoopSignDialog::onStep1Compute()
{
    const bool adaptor = (m_mode == Mode::PricAdaptor);

    m_x_share          = m_in_x_share->text().trimmed();
    // z_share is needed for both plain and adaptor_ml.
    if (m_in_z_share) m_z_share = m_in_z_share->text().trimmed();
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
        if (m_in_Z_pub_X) m_Z_pub_X = m_in_Z_pub_X->text().trimmed();
        m_T_G            = m_in_T_G->text().trimmed();
        m_T_H            = m_in_T_H->text().trimmed();
        m_dleq_t         = m_in_dleq_t->toPlainText().trimmed();
        // Override the widget reads — these must be bilaterally
        // identical, and the only value both sides agree on without
        // a DM round-trip is swap_id. Reading the widget would let a
        // stale persisted value or a user edit silently break the
        // peer's DLEQ verify. (Belt-and-suspenders alongside the
        // restore-time force-reset.)
        m_session_label  = m_swap_id;
        m_session_payload= m_swap_id;
        if (m_in_session_label)   m_in_session_label->setText(m_swap_id);
        if (m_in_session_payload) m_in_session_payload->setText(m_swap_id);
    }

    // Sanity checks — cheap and gives the user better errors than
    // the RPC-internal validation messages.
    if (m_x_share.size() != 64) { setStatus(tr("x_share must be 32-byte hex"), true); return; }
    if (joint_pubkey.size() != 66) { setStatus(tr("joint_pubkey must be 33-byte hex"), true); return; }
    if (m_msg_hex.size() != 64) { setStatus(tr("msg must be 32-byte hex"), true); return; }
    if (m_session_id.size() != 64) { setStatus(tr("session_id must be 32-byte hex"), true); return; }

    if (adaptor) {
        // Multi-layer adaptor round 1. Args:
        //   (P_pi, X_pub_X, Z_pub_X, x_X, z_X, T_G, T_H, label, payload)
        // Falling back to the single-layer adaptor_round1 produces a
        // pre-sig with zero commitment_image, which fails consensus
        // VerifyMultiLayer when broadcast.
        if (m_z_share.size() != 64) {
            setStatus(tr("z_share must be 32-byte hex (auto-filled from buildtx z_self/z_other for adaptor_ml)"), true);
            return;
        }
        if (m_Z_pub_X.size() != 66) {
            setStatus(tr("Z_pub_X must be 33-byte hex (auto-derived from z_share)"), true);
            return;
        }
        std::string params = std::string("[\"")
            + joint_pubkey.toStdString() + "\",\""
            + m_X_pub_X.toStdString()    + "\",\""
            + m_Z_pub_X.toStdString()    + "\",\""
            + m_x_share.toStdString()    + "\",\""
            + m_z_share.toStdString()    + "\",\""
            + m_T_G.toStdString()        + "\",\""
            + m_T_H.toStdString()        + "\",\""
            + m_session_label.toStdString()   + "\",\""
            + m_session_payload.toStdString() + "\"]";
        auto r = callRpc("pricoin_jointspend_adaptor_round1_ml", params);
        if (!r.ok) {
            setStatus(tr("adaptor_round1_ml failed: %1").arg(QString::fromStdString(r.error_msg)), true);
            return;
        }
        UniValue v;
        v.read(r.json);
        m_alpha          = QString::fromStdString(v["alpha"].get_str());
        m_my_L_share     = QString::fromStdString(v["L_share"].get_str());
        m_my_R_share     = QString::fromStdString(v["R_share"].get_str());
        m_my_KI_share    = QString::fromStdString(v["KI_share"].get_str());
        m_my_D_share     = QString::fromStdString(v["D_share"].get_str());
        m_my_dleq_alpha  = QString::fromStdString(v["dleq_alpha"].get_str());
        m_my_dleq_x      = QString::fromStdString(v["dleq_x"].get_str());
        m_my_dleq_z      = QString::fromStdString(v["dleq_z"].get_str());
        m_my_commitment  = QString::fromStdString(v["commitment"].get_str());
        // Strip alpha from the displayed JSON — it must NEVER leave
        // the wallet before round 3. Show the rest as the share to
        // hand to the peer.
        UniValue share_for_peer{UniValue::VOBJ};
        share_for_peer.pushKV("L_share",    v["L_share"]);
        share_for_peer.pushKV("R_share",    v["R_share"]);
        share_for_peer.pushKV("KI_share",   v["KI_share"]);
        share_for_peer.pushKV("D_share",    v["D_share"]);
        share_for_peer.pushKV("dleq_alpha", v["dleq_alpha"]);
        share_for_peer.pushKV("dleq_x",     v["dleq_x"]);
        share_for_peer.pushKV("dleq_z",     v["dleq_z"]);
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
    updateNostrStatus();
    persistSession();
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
        // Build X_pub_shares + Z_pub_shares arrays — convention is
        // initiator first, responder second. The peer's role is the
        // opposite of mine.
        const QString peer_pub  = m_in_X_pub_peer->text().trimmed();
        const QString peer_zpub = m_in_Z_pub_peer ? m_in_Z_pub_peer->text().trimmed() : QString{};
        if (peer_pub.size() != 66) {
            setStatus(tr("Peer X_pub must be 33-byte hex"), true);
            return;
        }
        if (peer_zpub.size() != 66) {
            setStatus(tr("Peer Z_pub must be 33-byte hex (auto-filled from peer's buildtx DM in adaptor_ml)"), true);
            return;
        }
        // Multi-layer round 1 requires D_share + dleq_z in BOTH our
        // share and the peer's share. A missing field here usually
        // means one party's dialog re-displayed a Step-1 output that
        // was generated by a pre-_ml binary build (the persisted
        // session text out-lived the binary upgrade). Catch that
        // here with an actionable message instead of letting the
        // combine_ml RPC fail with an opaque
        // "JSON value of type null is not of expected type string".
        if (m_my_D_share.isEmpty() || m_my_dleq_z.isEmpty()) {
            setStatus(tr("Own Step-1 output is missing D_share / dleq_z — click "
                         "\"Run my round 1\" again to regenerate with the "
                         "multi-layer binary."), true);
            return;
        }
        if (!peer.exists("D_share") || !peer["D_share"].isStr()
            || !peer.exists("dleq_z") || !peer["dleq_z"].isStr()) {
            setStatus(tr("Peer Step-1 share is missing D_share / dleq_z — ask "
                         "peer to click \"Run my round 1\" again on their "
                         "side (their dialog likely restored a session from "
                         "before the multi-layer binary)."), true);
            return;
        }
        const QString first_pub   = (m_role == "initiator") ? m_X_pub_X  : peer_pub;
        const QString second_pub  = (m_role == "initiator") ? peer_pub   : m_X_pub_X;
        const QString first_zpub  = (m_role == "initiator") ? m_Z_pub_X  : peer_zpub;
        const QString second_zpub = (m_role == "initiator") ? peer_zpub  : m_Z_pub_X;

        // Per-party shares array — same role-ordered.
        UniValue mine_share{UniValue::VOBJ};
        mine_share.pushKV("L_share",    m_my_L_share.toStdString());
        mine_share.pushKV("R_share",    m_my_R_share.toStdString());
        mine_share.pushKV("KI_share",   m_my_KI_share.toStdString());
        mine_share.pushKV("D_share",    m_my_D_share.toStdString());
        mine_share.pushKV("dleq_alpha", m_my_dleq_alpha.toStdString());
        mine_share.pushKV("dleq_x",     m_my_dleq_x.toStdString());
        mine_share.pushKV("dleq_z",     m_my_dleq_z.toStdString());
        mine_share.pushKV("commitment", m_my_commitment.toStdString());

        UniValue first_share  = (m_role == "initiator") ? mine_share : peer;
        UniValue second_share = (m_role == "initiator") ? peer       : mine_share;

        UniValue params{UniValue::VARR};
        // ring_ml: array of {P,W} objects (multi-layer).
        UniValue ring_ml_v;
        if (!ring_ml_v.read(m_ring_json.toStdString()) || !ring_ml_v.isArray()) {
            setStatus(tr("ring must be a JSON array of {P,W} objects"), true);
            return;
        }
        params.push_back(ring_ml_v);
        params.push_back(m_pi.toInt());
        params.push_back(m_msg_hex.toStdString());
        params.push_back(m_T_G.toStdString());
        params.push_back(m_T_H.toStdString());
        params.push_back(m_dleq_t.toStdString());
        UniValue Xs{UniValue::VARR};
        Xs.push_back(first_pub.toStdString());
        Xs.push_back(second_pub.toStdString());
        params.push_back(Xs);
        UniValue Zs{UniValue::VARR};
        Zs.push_back(first_zpub.toStdString());
        Zs.push_back(second_zpub.toStdString());
        params.push_back(Zs);
        UniValue shares_arr{UniValue::VARR};
        shares_arr.push_back(first_share);
        shares_arr.push_back(second_share);
        params.push_back(shares_arr);
        params.push_back(m_session_label.toStdString());
        params.push_back(m_session_payload.toStdString());

        auto r = callRpc("pricoin_jointspend_adaptor_combine_ml", params.write(0));
        if (!r.ok) {
            setStatus(tr("adaptor_combine_ml failed: %1").arg(QString::fromStdString(r.error_msg)), true);
            return;
        }
        UniValue v;
        v.read(r.json);
        m_KI       = QString::fromStdString(v["KI"].get_str());
        m_D        = QString::fromStdString(v["D"].get_str());
        m_L_pi     = QString::fromStdString(v["L_pi"].get_str());
        m_R_pi     = QString::fromStdString(v["R_pi"].get_str());
        m_L_prime  = QString::fromStdString(v["L_prime"].get_str());
        m_R_prime  = QString::fromStdString(v["R_prime"].get_str());
        m_mu_P     = QString::fromStdString(v["mu_P"].get_str());
        m_mu_C     = QString::fromStdString(v["mu_C"].get_str());
        m_c_pi     = QString::fromStdString(v["c_pi"].get_str());
        m_c0       = QString::fromStdString(v["c0"].get_str());
        // Echo s_others verbatim — needed at assemble.
        m_s_others_json = QString::fromStdString(v["s_others"].write(0));
        m_out_step2->setPlainText(QString::fromStdString(r.json));

        // Persist the cooperative ring into the swap record so the
        // watcher can run extract automatically when Bob's claim hits
        // chain. The set_pric_claim_ring RPC stores only the P side
        // (extract just needs ring[pi].P for the t·G==T_G check); we
        // project ring_ml {P,W} → [P] before calling. Best-effort.
        if (!m_swap_id.isEmpty()) {
            UniValue ring_p_only{UniValue::VARR};
            for (size_t i = 0; i < ring_ml_v.size(); ++i) {
                const UniValue& entry = ring_ml_v[i];
                if (entry.isObject() && entry.exists("P") && entry["P"].isStr()) {
                    ring_p_only.push_back(entry["P"]);
                }
            }
            UniValue ring_params{UniValue::VARR};
            ring_params.push_back(m_swap_id.toStdString());
            ring_params.push_back(ring_p_only);
            auto rr = callRpc("pricoin_adaptor_swap_set_pric_claim_ring",
                                ring_params.write(0));
            if (!rr.ok) {
                setStatus(tr("ring persisted via adaptor_combine_ml but "
                              "set_pric_claim_ring failed: %1")
                    .arg(QString::fromStdString(rr.error_msg)), false);
            }
        }
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
    persistSession();
}

void PricCoopSignDialog::onStep3Compute()
{
    if (m_c_pi.isEmpty() || m_alpha.isEmpty()) {
        setStatus(tr("Run steps 1 and 2 first."), true);
        return;
    }
    // pricoin_jointspend_share(alpha, c_pi, x_share, [z_share, mu_P, mu_C])
    //
    // Multi-layer signing — BOTH PricPlain (plain CLSAG-ML) and
    // PricAdaptor (adaptor-CLSAG-ML) — needs the z_share + μ_P + μ_C
    // triple appended so the close share is computed as
    //   close = α - c_pi · (μ_P · x_share + μ_C · z_share)
    // i.e. the multi-layer aggregated form. Without it, the close
    // share collapses to the single-layer `α - c_pi · x_share`, and
    // when assembled the presig's s_pi is missing the μ_C · z term.
    // VerifyMultiLayer's walk then fails to close at index pi.
    //
    // 2026-05-14: this gate used to require `m_mode == PricPlain`.
    // That was correct pre-ML-adaptor-port (when PricAdaptor was
    // single-layer). After the ML port (v0.1.73), PricAdaptor is
    // multi-layer too — the mode check was a leftover. Symptom in
    // live testing: every PRIC claim adapt+broadcast failed with
    // "Adapt failed (... ring/msg mismatch)" because the recomputed
    // walk diverged at the signer index.
    std::string params = std::string("[\"")
        + m_alpha.toStdString()  + "\",\""
        + m_c_pi.toStdString()   + "\",\""
        + m_x_share.toStdString() + "\"";
    if (!m_z_share.isEmpty()
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
    updateNostrStatus();
    persistSession();
    // Auto-DM s_share so the peer's dialog can fire Step 4. Same
    // behavior whether Step 3 came via auto-fire or manual click.
    tryAutoSendRound3();
    // If peer s_share already arrived, fire Step 4 immediately.
    tryAutoStep4();
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
        // pricoin_jointspend_adaptor_assemble_ml(KI, D, L_pi, R_pi,
        //   L_prime, R_prime, mu_P, mu_C, c_pi, c0, s_others,
        //   close_shares, pi, T_G, T_H, dleq_t)
        UniValue s_others_v;
        if (!s_others_v.read(m_s_others_json.toStdString()) || !s_others_v.isArray()) {
            setStatus(tr("internal: s_others vanished"), true);
            return;
        }
        if (m_D.isEmpty() || m_mu_P.isEmpty() || m_mu_C.isEmpty()) {
            setStatus(tr("internal: D / mu_P / mu_C vanished — re-run Step 2"), true);
            return;
        }
        UniValue params{UniValue::VARR};
        params.push_back(m_KI.toStdString());
        params.push_back(m_D.toStdString());
        params.push_back(m_L_pi.toStdString());
        params.push_back(m_R_pi.toStdString());
        params.push_back(m_L_prime.toStdString());
        params.push_back(m_R_prime.toStdString());
        params.push_back(m_mu_P.toStdString());
        params.push_back(m_mu_C.toStdString());
        params.push_back(m_c_pi.toStdString());
        params.push_back(m_c0.toStdString());
        params.push_back(s_others_v);
        params.push_back(close_shares);
        params.push_back(m_pi.toInt());
        params.push_back(m_T_G.toStdString());
        params.push_back(m_T_H.toStdString());
        params.push_back(m_dleq_t.toStdString());
        auto r = callRpc("pricoin_jointspend_adaptor_assemble_ml", params.write(0));
        if (!r.ok) {
            setStatus(tr("adaptor_assemble_ml failed: %1").arg(QString::fromStdString(r.error_msg)), true);
            return;
        }
        UniValue v;
        v.read(r.json);
        m_final_blob_hex = QString::fromStdString(v["presig"].get_str());
        UniValue out{UniValue::VOBJ};
        out.pushKV("presig", m_final_blob_hex.toStdString());
        out.pushKV("kind",   "adaptor_pre_signature_ml");
        m_out_step4->setPlainText(QString::fromStdString(out.write(2)));
        setStatus(tr("Step 4 OK. Multi-layer AdaptorPreSignature blob produced."));
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
    if (m_btn_broadcast) {
        m_btn_broadcast->setEnabled(
            !m_final_blob_hex.isEmpty() && !m_unsigned_tx_hex.isEmpty());
    }
    persistSession();

    // Auto-coord finale: when Step 4 succeeds and we got here via the
    // auto-coord chain (not manual button-click), auto-accept the
    // dialog so the caller (the "Set pre-signatures" outer dialog)
    // can proceed without a click. Manual users see the result for
    // a brief moment before auto-close — sufficient for "watch it
    // work" without blocking the flow.
    if (!m_final_blob_hex.isEmpty() && m_auto_step4_fired) {
        // Defer accept so the status label paints first.
        QMetaObject::invokeMethod(this, [this]{
            if (!m_final_blob_hex.isEmpty()) accept();
        }, Qt::QueuedConnection);
    }
}

void PricCoopSignDialog::onBroadcastClicked()
{
    if (m_mode != Mode::PricPlain) return;
    if (m_final_blob_hex.isEmpty() || m_unsigned_tx_hex.isEmpty()) {
        setStatus(tr("Need step 4 final blob + buildtx output first."), true);
        return;
    }
    if (m_swap_id.isEmpty()) {
        setStatus(tr("No swap_id — open this dialog from the Swaps page."), true);
        return;
    }

    // pricoin_swapwatch_broadcast_pric(swap_id, pric_refund, tx_hex, sig_hex, vout=-1, min_conf=1).
    UniValue p{UniValue::VARR};
    p.push_back(m_swap_id.toStdString());
    p.push_back("pric_refund");
    p.push_back(m_unsigned_tx_hex.toStdString());
    p.push_back(m_final_blob_hex.toStdString());
    p.push_back(-1);
    p.push_back(1);
    auto r = callRpc("pricoin_swapwatch_broadcast_pric", p.write(0));
    if (!r.ok) {
        setStatus(tr("Broadcast failed: %1").arg(QString::fromStdString(r.error_msg)), true);
        return;
    }
    UniValue v;
    v.read(r.json);
    const QString broadcast_txid = QString::fromStdString(v["txid"].get_str());

    // Announce to peer via Nostr (best effort).
    if (m_nostr && m_relay_connected_count > 0 && !m_peer_xonly.isEmpty()) {
        m_nostr->publishBroadcastAnnouncement(
            m_peer_xonly, m_swap_id, "pric_refund",
            broadcast_txid, /*vout=*/-1, /*min_conf=*/1);
    }
    setStatus(tr("Broadcast OK — txid %1… (announced to peer if connected).")
        .arg(broadcast_txid.left(16)));
}
