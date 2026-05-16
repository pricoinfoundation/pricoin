// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_PRICOIN_PRIC_COOPSIGN_DIALOG_H
#define BITCOIN_QT_PRICOIN_PRIC_COOPSIGN_DIALOG_H

#include <QDialog>
#include <QString>
#include <cstdint>
#include <string>

class PricoinNostrClient;
class WalletModel;

QT_BEGIN_NAMESPACE
class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QScrollArea;
QT_END_NAMESPACE

// PricCoopSignDialog — guided UI for the PRIC-side cooperative-CLSAG
// signing dance. Two modes:
//
//   PricPlain    — multi-layer cooperative CLSAG (used for the
//                  PRIC refund cooperative sig — a normal v4 spend
//                  signed cooperatively without an adaptor).
//                  RPC chain: pricoin_jointspend_round1_safe →
//                  pricoin_jointspend_combine →
//                  pricoin_jointspend_share →
//                  pricoin_jointspend_assemble.
//
//   PricAdaptor  — single-layer cooperative adaptor-CLSAG (per
//                  doc/adaptor-clsag.md §4, used for the PRIC claim
//                  adaptor pre-sig — adapts under T_G).
//                  RPC chain: pricoin_jointspend_adaptor_round1 →
//                  pricoin_jointspend_adaptor_combine →
//                  pricoin_jointspend_share (reused) →
//                  pricoin_jointspend_adaptor_assemble.
//
// Both flows are 2-round-trip: round 1 exchanges shares
// (L/R/KI[/D] + commitment + DLEQ proofs in adaptor mode); round 2
// exchanges close shares.
//
// The dialog is hand-paste mode — the user supplies x_share, z_share
// (plain), session bookkeeping (session_id, ring_hash,
// joint_output_id, role), and the buildtx output (ring_ml or ring,
// pi, msg) themselves. Auto-pulling these from a swap session
// record is a follow-on concern.

class PricCoopSignDialog : public QDialog
{
    Q_OBJECT

public:
    enum class Mode {
        PricPlain,    // refund — multi-layer, no adaptor
        PricAdaptor,  // claim — single-layer + adaptor
    };

    // `swap_id` may be empty; if non-empty the dialog looks up the
    // wallet's PricoinAdaptorSwap record and pre-fills T_G + dleq_t
    // in adaptor mode (the rest stays user-supplied).
    PricCoopSignDialog(WalletModel* wallet_model,
                       Mode mode,
                       const QString& title,
                       const std::string& swap_id,
                       QWidget* parent = nullptr);

    // Final result. PricPlain → 32-byte signature_hex (final CLSAG sig
    // blob, broadcastable). PricAdaptor → 32-byte presig (serialized
    // AdaptorPreSignature blob — feeds adaptorSwapSetPreSigned).
    QString finalBlobHex() const { return m_final_blob_hex; }

    // Progress-only UX (default for live use): hide the full step-by-
    // step form and show only a status line + a small "Advanced…"
    // toggle. The auto-coord chain runs identically; the user just
    // sees high-level progress instead of raw cryptographic fields.
    // Call BEFORE exec() / show().
    void setProgressOnlyMode(bool on);
    // Headless mode — the dialog still exec()'s its modal event loop
    // and drives the cooperative-sign ceremony to completion, but it
    // is never painted on screen (Qt::WA_DontShowOnScreen). Used by
    // the swaps page's auto-coord so the ceremony is invisible
    // plumbing — the user only sees the row-level progress on the
    // Swaps page. Must be set BEFORE the first show()/exec().
    void setHeadlessMode(bool on);

private Q_SLOTS:
    void onStep1Compute();
    void onStep2Compute();
    void onStep3Compute();
    void onStep4Compute();
    void onRunBuildtx();
    void onRunLoadshare();
    void onNostrConnectClicked();
    void onSendDmRound1();
    void onSendDmRound3();
    void onBroadcastClicked();
    void onDmReceived(const QString& from_xonly_hex, const QString& plaintext);
    void onNostrLog(const QString& msg);
    void onNostrRelayStatus(const QString& url, bool connected);

    // Auto-coord helpers — drive the ceremony forward without user
    // clicks once preconditions are met. Each fires at most once per
    // milestone and is safe to call repeatedly (idempotent guards).
    void tryAutoComputeJointscanPartial();
    void tryAutoSendJointscanPartial();
    void tryAutoLoadshare();
    void tryAutoSendXpubAnnounce();
    void tryAutoBuildtx();
    void tryAutoSendBuildtx();
    void tryAutoStep1();
    void tryAutoSendRound1();
    void tryAutoStep2();
    void tryAutoStep3();
    void tryAutoSendRound3();
    void tryAutoStep4();

private:
    WalletModel* m_wm{nullptr};
    Mode m_mode;

    // Saved between steps.
    QString m_alpha;          // 32-byte hex; SECRET, never displayed
    QString m_my_L_share;
    QString m_my_R_share;
    QString m_my_KI_share;
    QString m_my_D_share;     // multi-layer (plain OR adaptor_ml)
    QString m_my_commitment;
    QString m_my_dleq_alpha;  // adaptor only
    QString m_my_dleq_x;      // adaptor only
    QString m_my_dleq_z;      // adaptor_ml only
    QString m_X_pub_X;        // adaptor only — x_X·G
    QString m_Z_pub_X;        // adaptor_ml only — z_X·G
    QString m_KI;
    QString m_D;
    QString m_L_pi, m_R_pi;
    QString m_L_prime, m_R_prime;       // adaptor only
    QString m_c_pi, m_c0;
    QString m_mu_P, m_mu_C;             // multi-layer plain only
    QString m_s_others_json;            // JSON array of hex strings
    QString m_my_s_share;
    QString m_final_blob_hex;
    QString m_unsigned_tx_hex;  // saved from buildtx for the
                                 // refund-broadcast convenience path

    // Inputs that persist for cross-step recall.
    QString m_x_share, m_z_share;
    // z_other_for_peer — the half of the buildtx z-split that the
    // spender must ship to the cosigner so they can use it as their
    // own z_share. Persisted because the buildtx output widget itself
    // (m_out_buildtx) is not, and the resend timer needs to be able
    // to include z_other in re-fired buildtx DMs after a dialog
    // restart (otherwise the cosigner's z_share stays empty and Step
    // 1 silently blocks).
    QString m_z_other;
    QString m_msg_hex;
    QString m_pi;
    QString m_session_id;
    QString m_ring_hash, m_joint_output_id;
    QString m_role;
    QString m_T_G, m_T_H, m_dleq_t;
    QString m_session_label, m_session_payload;
    QString m_X_pub_shares_json;        // JSON array
    QString m_ring_ml_json;             // multi-layer
    QString m_ring_json;                // single-layer (adaptor)

    // ─── Setup form fields ───
    QLineEdit*      m_in_x_share{nullptr};
    QLineEdit*      m_in_z_share{nullptr};
    QLineEdit*      m_in_joint_pubkey{nullptr};
    QLineEdit*      m_in_msg{nullptr};
    QLineEdit*      m_in_pi{nullptr};
    QLineEdit*      m_in_session_id{nullptr};
    QLineEdit*      m_in_ring_hash{nullptr};
    QLineEdit*      m_in_joint_output_id{nullptr};
    QComboBox*      m_in_role{nullptr};
    // adaptor-only:
    QLineEdit*      m_in_X_pub_X{nullptr};
    QLineEdit*      m_in_Z_pub_X{nullptr};
    QLineEdit*      m_in_T_G{nullptr};
    QLineEdit*      m_in_T_H{nullptr};
    QPlainTextEdit* m_in_dleq_t{nullptr};
    QLineEdit*      m_in_session_label{nullptr};
    QLineEdit*      m_in_session_payload{nullptr};
    // ring/ring_ml + s_others input pasted as JSON:
    QPlainTextEdit* m_in_ring_or_ring_ml{nullptr};

    // ─── Buildtx helper (spender-only — pre-fills msg/ring_ml/pi/z) ───
    QLineEdit*      m_in_bt_joint_txid{nullptr};
    QLineEdit*      m_in_bt_joint_vout{nullptr};
    QLineEdit*      m_in_bt_joint_value{nullptr};
    QLineEdit*      m_in_bt_joint_blind{nullptr};
    QLineEdit*      m_in_bt_dest{nullptr};
    QLineEdit*      m_in_bt_dest_amount{nullptr};
    QLineEdit*      m_in_bt_fee{nullptr};
    QLineEdit*      m_in_bt_ring_size{nullptr};
    QLineEdit*      m_in_bt_nlocktime{nullptr};
    QPushButton*    m_btn_run_buildtx{nullptr};
    QPlainTextEdit* m_out_buildtx{nullptr};

    // ─── Loadshare helper (auto-derives x_share / blind / value) ───
    QLineEdit*      m_in_ls_my_partial{nullptr};
    QLineEdit*      m_in_ls_peer_partial{nullptr};
    QComboBox*      m_in_ls_absorb{nullptr};   // "true" | "false"
    QPushButton*    m_btn_run_loadshare{nullptr};
    QPlainTextEdit* m_out_loadshare{nullptr};

    // ─── Step 1: My round 1 (local; persists nonce record) ───
    QPushButton*    m_btn_step1{nullptr};
    QPlainTextEdit* m_out_step1{nullptr};

    // ─── Step 2: Combine (paste peer's round-1 share) ───
    QPlainTextEdit* m_in_peer_share_json{nullptr};
    QLineEdit*      m_in_X_pub_peer{nullptr};   // adaptor only
    QLineEdit*      m_in_Z_pub_peer{nullptr};   // adaptor_ml only
    QPlainTextEdit* m_in_s_others_seed_json{nullptr}; // plain only — taker-supplied decoy s_others
    QPushButton*    m_btn_step2{nullptr};
    QPlainTextEdit* m_out_step2{nullptr};

    // ─── Step 3: My round 3 (local) ───
    QPushButton*    m_btn_step3{nullptr};
    QPlainTextEdit* m_out_step3{nullptr};

    // ─── Step 4: Assemble (paste peer's s_share) ───
    QLineEdit*      m_in_peer_s_share{nullptr};
    QPushButton*    m_btn_step4{nullptr};
    QPlainTextEdit* m_out_step4{nullptr};
    // Refund convenience: PricPlain mode only.
    QPushButton*    m_btn_broadcast{nullptr};

    QLabel*         m_status_label{nullptr};

    // Progress-only mode plumbing.
    QScrollArea*    m_scroll_area{nullptr};      // the field-heavy section
    QLabel*         m_progress_header{nullptr};  // big "leave this open" label
    QLabel*         m_progress_state{nullptr};   // current swap state line
    QLabel*         m_progress_action{nullptr};  // last-action / status line
    QPushButton*    m_btn_toggle_advanced{nullptr};
    bool            m_progress_only{false};
    bool            m_headless{false};

    // ─── Nostr DM transport ───
    QString             m_swap_id;
    QString             m_peer_xonly;
    QStringList         m_relay_urls;
    PricoinNostrClient* m_nostr{nullptr};
    int                 m_relay_connected_count{0};

    QPushButton*    m_btn_nostr_connect{nullptr};
    QLabel*         m_lbl_nostr_status{nullptr};
    QCheckBox*      m_chk_auto_paste{nullptr};
    QPushButton*    m_btn_send_dm_round1{nullptr};
    QPushButton*    m_btn_send_dm_round3{nullptr};

    // Auto-coord state — one-shot guards so the same milestone never
    // re-fires. Reset to false in ctor.
    bool m_auto_partial_computed{false};
    bool m_auto_partial_sent{false};
    bool m_auto_loadshare_fired{false};
    bool m_auto_buildtx_fired{false};
    bool m_auto_buildtx_sent{false};
    bool m_auto_xpub_announced{false};
    bool m_auto_step1_fired{false};
    bool m_auto_step1_dm_sent{false};
    bool m_auto_step2_fired{false};
    bool m_auto_step3_fired{false};
    bool m_auto_step3_dm_sent{false};
    bool m_auto_step4_fired{false};

    void buildLayout(const QString& title);
    void setStatus(const QString& msg, bool error = false);
    void updateNostrStatus();

    struct RpcResult {
        bool ok;
        std::string json;
        std::string error_msg;
    };
    RpcResult callRpc(const std::string& method, const std::string& params_json);

    static QString RandomHex32();

    // Cooperative-sign session persistence. Serializes the dialog's
    // per-step state (m_alpha + commitments + intermediates + input
    // widget contents) to a JSON blob keyed by leg on the swap
    // record. Restored on ctor when the swap record has a non-empty
    // session for this dialog's mode. Lets users close/reopen the
    // dialog mid-ceremony without losing progress.
    void persistSession();
    void loadSessionFromRecord(const std::string& json);
};

#endif // BITCOIN_QT_PRICOIN_PRIC_COOPSIGN_DIALOG_H
