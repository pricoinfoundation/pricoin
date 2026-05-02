// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_PRICOIN_COOPSIGN_DIALOG_H
#define BITCOIN_QT_PRICOIN_COOPSIGN_DIALOG_H

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
class QStackedWidget;
class QVBoxLayout;
QT_END_NAMESPACE

// CoopSignDialog — guided UI for the BTC-side MuSig2 cooperative
// signing dance (refund + adaptor claim variants).
//
// The protocol runs in four sequential local steps with two
// inter-party round trips. Each step reveals one panel; clicking the
// step's action button calls the corresponding wallet RPC via
// node().executeRpc() and surfaces the resulting blob in a copyable
// text area. Inter-party blobs (the peer's pubnonce in step 3 and
// the peer's partial sig in step 4) are pasted into matching
// QPlainTextEdits before the local computation can advance.
//
// Pages (BTC plain / BTC adaptor share the layout — the only
// difference is whether step 3 takes an `adaptor_T_G` field):
//
//   1. Keyagg          — enters [my_pub, peer_pub], emits
//                        (agg_xonly, keyagg_cache).
//   2. My round 1      — enters [my_priv, msg/sighash, role,
//                        session_id, session_seed]; calls
//                        pricoin_btc_musig2_round1_safe; emits
//                        (my_pubnonce, secnonce_handle).
//   3. Combine         — enters peer_pubnonce + (for adaptor) T_G;
//                        runs aggregate_nonces + process +
//                        partial_sign; emits (aggnonce, session
//                        bytes, nonce_parity, my_partial).
//   4. Finalize        — enters peer_partial; runs
//                        aggregate_partials; emits the 64-byte
//                        (pre-)sig.
//
// PRIC cooperative CLSAG is a 4-round protocol (alpha-commit ↔
// combine ↔ s_share ↔ assemble) plus multi-layer + adaptor variants;
// covering it doubles this file. PRIC support stays as a follow-on
// commit — the existing "paste 6 hex blobs" form on the Swaps page
// continues to accept PRIC pre-sig blobs in the meantime.

class CoopSignDialog : public QDialog
{
    Q_OBJECT

public:
    enum class Mode {
        BtcPlain,    // refund leg — no adaptor
        BtcAdaptor,  // claim leg — adapts under T_G
    };

    // `swap_id` may be empty; if non-empty the dialog looks up the
    // wallet's PricoinAdaptorSwap record and pre-fills what it can
    // (peer pubkey, my pubkey, and adaptor T_G in adaptor mode).
    CoopSignDialog(WalletModel* wallet_model,
                   Mode mode,
                   const QString& title,
                   const std::string& swap_id,
                   QWidget* parent = nullptr);

    // Valid only after the dialog completes step 4. The 64-byte sig
    // is the BIP340 final signature for plain mode, or the adaptor
    // pre-signature for adaptor mode (caller's responsibility to
    // know which).
    QString finalSigHex() const { return m_final_sig_hex; }

    // For adaptor mode: the nonce parity captured at step 3 — the
    // pre-sig consumer needs it to call pricoin_btc_musig2_adapt /
    // _extract later. Empty for plain mode.
    int nonceParity() const { return m_nonce_parity; }

    // 133-byte session blob produced at step 3. The BothFunded form
    // needs this for the BTC claim leg (it's stored alongside the
    // pre-sig so the t-holder can call _adapt later).
    QString sessionDataHex() const { return m_session_data; }

private Q_SLOTS:
    void onStep1Compute();
    void onStep2Compute();
    void onStep3Compute();
    void onStep4Compute();
    void onComputeSighash();
    void onNostrConnectClicked();
    void onSendDmRound2();
    void onSendDmRound3();
    void onDmReceived(const QString& from_xonly_hex, const QString& plaintext);
    void onNostrLog(const QString& msg);
    void onNostrRelayStatus(const QString& url, bool connected);

    void onCopyButton();
    void onPasteButton();

private:
    WalletModel* m_wm{nullptr};
    Mode m_mode;

    // Plumbing references — saved between steps.
    QString m_keyagg_cache;       // 197-byte hex
    QString m_agg_xonly;          // 32-byte hex
    QString m_my_pubnonce;        // 66-byte hex
    QString m_secnonce_handle;    // 32-byte hex
    QString m_session_data;       // 133-byte hex
    int     m_nonce_parity{-1};
    QString m_my_partial;         // 32-byte hex
    QString m_final_sig_hex;      // 64-byte hex (or pre-sig)

    // Inputs that persist across steps for cross-step recall.
    QString m_my_pub;
    QString m_my_priv;
    QString m_msg_hex;
    QString m_role;

    // ─── Step 1: Keyagg ───
    QLineEdit*      m_in_my_pub{nullptr};
    QLineEdit*      m_in_peer_pub{nullptr};
    QPushButton*    m_btn_step1{nullptr};
    QPlainTextEdit* m_out_step1{nullptr};

    // ─── Step 2: My round-1 ───
    QLineEdit*      m_in_my_priv{nullptr};
    QLineEdit*      m_in_msg{nullptr};
    QComboBox*      m_in_role{nullptr};
    QLineEdit*      m_in_session_id{nullptr};
    QLineEdit*      m_in_session_seed{nullptr};
    QPushButton*    m_btn_step2{nullptr};
    QPlainTextEdit* m_out_step2{nullptr};

    // ─── Tx-context auto-sighash (optional helper, sits between
    // step 1 and step 2) ───
    QLineEdit*      m_in_funding_txid{nullptr};
    QLineEdit*      m_in_funding_vout{nullptr};
    QLineEdit*      m_in_funding_amount{nullptr};
    QLineEdit*      m_in_recipient_xonly{nullptr};
    QLineEdit*      m_in_refund_amount{nullptr};
    QLineEdit*      m_in_nlocktime{nullptr};
    QPushButton*    m_btn_compute_sighash{nullptr};

    // ─── Step 3: Combine ───
    QPlainTextEdit* m_in_peer_pubnonce{nullptr};
    QLineEdit*      m_in_adaptor_T_G{nullptr};
    QPushButton*    m_btn_step3{nullptr};
    QPlainTextEdit* m_out_step3{nullptr};

    // ─── Step 4: Finalize ───
    QPlainTextEdit* m_in_peer_partial{nullptr};
    QPushButton*    m_btn_step4{nullptr};
    QPlainTextEdit* m_out_step4{nullptr};

    QLabel* m_status_label{nullptr};

    // ─── Nostr DM transport ───
    QString             m_swap_id;
    QString             m_peer_xonly;
    QStringList         m_relay_urls;
    PricoinNostrClient* m_nostr{nullptr};
    int                 m_relay_connected_count{0};

    QPushButton*    m_btn_nostr_connect{nullptr};
    QLabel*         m_lbl_nostr_status{nullptr};
    QCheckBox*      m_chk_auto_paste{nullptr};
    QPushButton*    m_btn_send_dm_round2{nullptr};
    QPushButton*    m_btn_send_dm_round3{nullptr};

    void buildLayout(const QString& title);
    void setStatus(const QString& msg, bool error = false);
    void updateNostrStatus();

    // RPC dispatch helper. Returns the parsed UniValue result on
    // success; on RPC error, surfaces a message via setStatus and
    // returns std::nullopt. Calls go through node().executeRpc()
    // with the wallet's URI so wallet RPCs route correctly.
    struct RpcResult {
        bool ok;
        std::string json;       // result on success
        std::string error_msg;  // human-readable on failure
    };
    RpcResult callRpc(const std::string& method, const std::string& params_json);

    // Generates 32 bytes of random hex via /dev/urandom (the
    // session_seed and session_id fields default-fill from this).
    static QString RandomHex32();
};

#endif // BITCOIN_QT_PRICOIN_COOPSIGN_DIALOG_H
