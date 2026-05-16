// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRICOIN_ADAPTOR_SWAP_H
#define BITCOIN_WALLET_PRICOIN_ADAPTOR_SWAP_H

#include <consensus/amount.h>
#include <pubkey.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wallet { class CWallet; }

// Phase-5 atomic-swap orchestration: state machine + wallet
// persistence for the adaptor-based protocol from
// `doc/adaptor-clsag.md` §6.2.
//
// Distinct from `pricoin_swap_ceremony` (which tracks the legacy
// HTLC-with-preimage flow). The adaptor flow is the trustless
// variant: both legs are tied together by a single cross-chain
// secret t (encoded as a 33-byte compressed point T_G), and the
// publish of t on-chain (via Bob's PRIC claim) is what unlocks
// Alice's foreign-chain claim.
//
// THIS COMMIT — orchestration scaffold only.
//
//   This module provides the state-machine + persistence layer.
//   It does NOT yet drive the actual cooperative-signing wallet
//   protocol (the multi-message dance between Alice's and Bob's
//   wallets to produce each pre-signature). That's a follow-up:
//   the underlying crypto primitives are already in place
//   (`btc_musig2_adaptor`, `adaptor_joint_ringsig`, `swap::refund`,
//   `clsag_nonce_policy`); this module is the persistence + state
//   tracker that the protocol driver plugs into.
//
//   Right now state transitions are MANUAL — RPCs let an operator
//   record "I (or my wallet driver) just produced X off-band, save
//   it." This matches the existing `pricoin_swap_ceremony` pattern.
//
// THREAT-MODEL CAVEATS
//
//   * Pre-signatures are SECRET to the swap and MUST persist before
//     either funding tx broadcasts (per spec §6.3 watcher-model
//     requirements). This module persists them via the standard
//     EncryptWalletBlob pattern; loss of the wallet during step 9
//     means Alice cannot complete her foreign claim even if t
//     becomes public on-chain.
//   * Bob's secret t is also persisted (encrypted at rest) until
//     Bob broadcasts the PRIC claim. After that, t is on-chain;
//     Alice extracts it via `adaptor_ringsig::Extract`.
//   * Refund pre-sigs are pre-signed BEFORE either funding broadcasts
//     and persisted on both parties' wallets. Loss of the refund
//     pre-sig blob = loss of the asymmetric-disaster-recovery layer.

namespace wallet::pricoin_adaptor_swap {

// State machine — a strict superset of swap_ceremony's phases,
// shaped for the spec §6.2 pre-sign-then-execute pattern.
//
//     Setup                    (record created; identity exchange)
//      ↓
//     AdaptorReady             (T_G + DLEQ verified; refund timelocks set)
//      ↓
//     BtcFunded                (foreign 2-of-2 confirmed)
//      ↓
//     BothFunded               (PRIC joint stealth confirmed)
//      ↓
//     PreSigned                (all 4 pre-sigs durably stored)
//      ↓
//     PricClaimed              (Bob's PRIC claim on-chain; t extractable)
//      ↓
//     Complete                 (Alice's foreign claim confirmed)
//
// Off-path:
//
//     any non-terminal ─→  Aborted     (operator-initiated abort)
//     any non-terminal ─→  Refunded    (timelock expired; refund tx broadcast)
enum class State : uint8_t {
    Setup        = 0,
    AdaptorReady = 1,
    BtcFunded    = 2,
    BothFunded   = 3,
    PreSigned    = 4,
    PricClaimed  = 5,
    Complete     = 6,
    Refunded     = 7,
    Aborted      = 8,
};

enum class Role : uint8_t {
    // Sells PRIC, buys foreign coin. Locks PRIC; eventually broadcasts
    // foreign-chain claim using the t she extracts from Bob's PRIC
    // claim.
    Alice = 0,
    // Sells foreign coin, buys PRIC. Picks t. Locks foreign 2-of-2;
    // eventually broadcasts PRIC claim (revealing t on-chain).
    Bob   = 1,
};

// ─── Pre-signature blobs ────────────────────────────────────────
//
// Stored as opaque byte vectors so the orchestration layer doesn't
// need to know the exact crypto-module struct shapes. The wallet is
// expected to populate these before broadcasting any funding tx.

struct AdaptorSwapPreSigs {
    // BTC-side: 64-byte adaptor pre-sig + the 133-byte session bytes
    // needed to call `btc_musig2_adaptor::Adapt` after extracting t,
    // plus the nonce parity captured in the session.
    std::vector<unsigned char> btc_claim_presig;          // 64 bytes
    std::vector<unsigned char> btc_claim_session;         // 133 bytes
    int32_t                    btc_claim_nonce_parity{0};

    // PRIC-side: serialized adaptor_ringsig::AdaptorPreSignature.
    std::vector<unsigned char> pric_claim_presig_blob;

    // BTC-side refund: a fully-formed 64-byte BIP340 signature
    // (non-adaptor — produced via the no-adaptor branch of MuSig2).
    // Broadcastable as-is once foreign_refund_height is reached.
    std::vector<unsigned char> btc_refund_sig;            // 64 bytes

    // PRIC-side refund: serialized ringsig::Signature.
    std::vector<unsigned char> pric_refund_sig_blob;

    bool operator==(const AdaptorSwapPreSigs&) const = default;

    SERIALIZE_METHODS(AdaptorSwapPreSigs, obj) {
        READWRITE(obj.btc_claim_presig);
        READWRITE(obj.btc_claim_session);
        READWRITE(obj.btc_claim_nonce_parity);
        READWRITE(obj.pric_claim_presig_blob);
        READWRITE(obj.btc_refund_sig);
        READWRITE(obj.pric_refund_sig_blob);
    }

    // Chain-aware completeness check. The required field set varies
    // by foreign chain:
    //   * "btc"  — full cooperative-MuSig2 + Schnorr-adaptor flow:
    //              all fields below required.
    //   * "ltc"  — HTLC + same-secret binding flow: BTC-side MuSig2
    //              + Schnorr-adaptor fields are not used (the LTC
    //              HTLC is unilaterally claimable/refundable and
    //              `t` arrives via the PRIC chain). Only the PRIC
    //              presig + PRIC refund presig are required.
    bool IsComplete(const std::string& foreign_chain) const {
        const bool pric_ready = !pric_claim_presig_blob.empty()
                              && !pric_refund_sig_blob.empty();
        if (!pric_ready) return false;
        if (foreign_chain == "ltc") return true;
        // Default (BTC and any future cooperative-Schnorr chain):
        // require the full set.
        return !btc_claim_presig.empty()
            && !btc_claim_session.empty()
            && !btc_refund_sig.empty();
    }
};

struct AdaptorSwap {
    uint256 swap_id{};
    Role    role{Role::Alice};
    State   state{State::Setup};

    // Counterparty's stable swap-identity pubkey. This is the
    // pricoin_swap_session::GetSwapIdentityPubkey output of the
    // counterparty's wallet.
    CPubKey counterparty_pub;

    // Foreign-chain leg.
    std::string foreign_chain;             // "btc" | "ltc" | ...
    int64_t     foreign_amount_sat{0};
    std::string foreign_funding_txid;
    int32_t     foreign_funding_vout{-1};
    int32_t     foreign_funding_height{0};
    std::string foreign_claim_txid;        // populated on Complete
    std::string foreign_refund_txid;       // populated on Refunded (Bob)

    // PRIC leg.
    std::string pric_joint_stealth_address;
    int64_t     pric_amount_sat{0};
    uint256     pric_funding_txid{};
    int32_t     pric_funding_vout{-1};
    int32_t     pric_funding_height{0};
    uint256     pric_claim_txid{};         // populated on PricClaimed
    uint256     pric_refund_txid{};        // populated on Refunded (Alice)

    // Cross-chain binding (both parties hold T_G + T_H; only Bob holds t).
    // T_H = t · H_p(P_pi) where P_pi is the joint pubkey at the ring's
    // signer index. Bob can derive locally; Alice receives T_H over
    // the same channel as T_G + dleq_proof, after verifying the
    // DLEQ proof binds them.
    std::array<unsigned char, 33> T_G{};
    std::array<unsigned char, 33> T_H{};
    std::vector<unsigned char>    dleq_proof_blob;
    bool                          adaptor_set{false};

    // Bob's secret t (encrypted at rest along with the rest of the
    // record). Empty for Alice; populated for Bob between Setup and
    // PricClaimed. Cleared once t is on-chain (no longer secret).
    std::array<unsigned char, 32> t_secret{};
    bool                          has_t{false};

    // Refund timelocks (both parties hold these — they're public
    // protocol parameters). Validated via swap::refund::ValidateRefundTimelocks.
    int32_t pric_refund_height{0};
    int32_t foreign_refund_height{0};
    int32_t delta_min_blocks{0};
    bool    timelocks_set{false};

    // Pre-signature blobs. Populated in the PreSigned transition.
    AdaptorSwapPreSigs presigs;

    // Bookkeeping.
    std::string memo;
    int64_t     created_time{0};
    int64_t     updated_time{0};
    std::string abort_reason;

    // Per-leg destination addresses, agreed at swap creation. The
    // BTC P2TR recipients are 32-byte x-only pubkey hex (the dialogs
    // synthesize 0x5120<xonly> to get the SPK). The PRIC recipients
    // are full stealth-address strings.
    //
    // Convention: BTC alice = refund recipient (Alice gets BTC back
    // on abort); BTC bob = claim recipient (Bob receives BTC). PRIC
    // alice = claim recipient (Alice receives PRIC); PRIC bob =
    // refund recipient (Bob gets PRIC back on abort).
    std::string btc_alice_recipient_xonly_hex;
    std::string btc_bob_recipient_xonly_hex;
    std::string pric_alice_recipient_stealth;
    std::string pric_bob_recipient_stealth;

    // Cooperative ring used at adapt-round-1 time (single-layer CLSAG
    // ring of joint pubkeys). Persisted on Alice's wallet so that
    // when Bob's claim hits the chain, t can be extracted without
    // requiring Alice to paste the ring back in. Each entry is a
    // 33-byte compressed pubkey (Pricoin one-time pubkey, except
    // the signer-index entry which is the joint stealth pub).
    std::vector<std::array<unsigned char, 33>> pric_claim_ring;

    // W (commitment image) component of each multi-layer ring member.
    // Paired position-wise with `pric_claim_ring`'s P side. Stored on
    // the swap record so a session-JSON wipe (crash + re-buildtx)
    // doesn't lose the ML ring the original PRIC claim pre-sig is
    // bound to — without W the adapt path can only fall back to the
    // legacy single-layer route which fails consensus VerifyMultiLayer.
    // Empty when the swap predates this field or when buildtx hasn't
    // run yet. Same length as `pric_claim_ring` once populated.
    std::vector<std::array<unsigned char, 33>> pric_claim_ring_w;

    // Pricoin-stealth ephemeral private `r` chosen by Bob at adaptor-
    // setup. Bob uses it to compute P_pi = shared(r·A_J)·G + B_J;
    // T_G/T_H/DLEQ are bound to that P_pi. For the on-chain P_pi to
    // match the binding when Alice broadcasts the PRIC funding tx,
    // Alice must reuse the SAME r. Bob persists it locally; both
    // sides ship/store it so Alice's auto-fund step can pin
    // walletsendct's ephemeral. Empty for the legacy/manual path or
    // when not yet known on Alice's side. 32 bytes when set.
    std::array<unsigned char, 32> pric_ephemeral_r{};
    bool                          has_pric_ephemeral_r{false};

    // PRIC refund unsigned tx hex. Captured by the spender (Alice for
    // PRIC refund) at buildtx time during the PreSigned ceremony, so
    // the auto-refund watcher can inject the cooperative refund sig
    // and broadcast at PRIC refund timelock without dialog state. The
    // sig blob itself is in `presigs.pric_refund_sig_blob`. Empty for
    // pre-PreSigned swaps.
    std::string pric_refund_unsigned_tx_hex;

    // BTC refund unsigned tx hex. Captured at sighash-compute time
    // during BTC swap's cooperative-sign ceremony so the auto-refund
    // watcher can finalize with `presigs.btc_refund_sig` and broadcast
    // at foreign refund timelock without requiring Alice and Bob both
    // online. Mirrors `pric_refund_unsigned_tx_hex` for BTC P2TR swaps.
    // Empty for LTC swaps (LTC uses unilateral CLTV path) and for
    // BTC swaps that haven't reached PreSigned yet.
    std::string btc_refund_unsigned_tx_hex;

    // PRIC funding unsigned-but-signed tx hex, captured by Alice's
    // wallet at AdaptorReady time when the protocol pre-builds the
    // funding tx so cooperative presigns can run before broadcast.
    // Once the ceremony completes Alice broadcasts this hex and the
    // watcher detects the funding output as it confirms. Bob also
    // persists the hex (DM'd from Alice) so his side of the
    // cooperative ceremony can compute scan partials without
    // depending on `getrawtransaction` (the funding tx isn't on-chain
    // until after the presigs are in hand). The signed hex is
    // already final — Alice has signed her inputs locally; we just
    // hold off on broadcast until the ceremony completes.
    std::string pric_funding_unsigned_tx_hex;
    // Planned recipient_vout for the joint stealth output inside the
    // unsigned tx above. walletsendct_ring shuffles outputs at build
    // time, so the vout is only known after the build. Persisted so
    // the dialog + watcher know where to look.
    int32_t     pric_funding_planned_vout{-1};

    // Cooperative-sign session state, persisted across dialog closes
    // so the user can quit/reopen mid-ceremony without losing alpha,
    // commitments, s_share, and other per-step intermediates. Each
    // leg has its own JSON blob (opaque key=value map serialized by
    // the dialog). Empty until the dialog persists.
    std::string pric_claim_adaptor_session_json;
    std::string pric_refund_session_json;
    std::string btc_claim_adaptor_session_json;
    std::string btc_refund_session_json;

    // Peer's PRIC stealth view + spend pubkeys (33-byte hex). Used
    // at swap creation time to build the joint stealth address; now
    // also persisted so the cooperative-sign dialog can pass the
    // peer's spend pubkey to pricoin_jointspend_loadshare. Without
    // these, loadshare fails with "scriptPubKey mismatch" because it
    // can't reconstruct the joint one-time pubkey.
    std::string peer_view_pubkey_hex;
    std::string peer_spend_pubkey_hex;

    SERIALIZE_METHODS(AdaptorSwap, obj) {
        READWRITE(obj.swap_id);
        uint8_t role_byte = static_cast<uint8_t>(obj.role);
        READWRITE(role_byte);
        SER_READ(obj, obj.role = static_cast<Role>(role_byte));
        uint8_t state_byte = static_cast<uint8_t>(obj.state);
        READWRITE(state_byte);
        SER_READ(obj, obj.state = static_cast<State>(state_byte));

        std::array<unsigned char, 33> cp_bytes{};
        SER_WRITE(obj, std::copy(obj.counterparty_pub.begin(),
                                 obj.counterparty_pub.end(), cp_bytes.begin()));
        READWRITE(cp_bytes);
        SER_READ(obj, obj.counterparty_pub = CPubKey(
            std::span<const unsigned char>(cp_bytes.data(), 33)));

        READWRITE(obj.foreign_chain);
        READWRITE(obj.foreign_amount_sat);
        READWRITE(obj.foreign_funding_txid);
        READWRITE(obj.foreign_funding_vout);
        READWRITE(obj.foreign_funding_height);
        READWRITE(obj.foreign_claim_txid);
        READWRITE(obj.foreign_refund_txid);

        READWRITE(obj.pric_joint_stealth_address);
        READWRITE(obj.pric_amount_sat);
        READWRITE(obj.pric_funding_txid);
        READWRITE(obj.pric_funding_vout);
        READWRITE(obj.pric_funding_height);
        READWRITE(obj.pric_claim_txid);
        READWRITE(obj.pric_refund_txid);

        READWRITE(obj.T_G);
        READWRITE(obj.T_H);
        READWRITE(obj.dleq_proof_blob);
        uint8_t adaptor_set_byte = obj.adaptor_set ? 1 : 0;
        READWRITE(adaptor_set_byte);
        SER_READ(obj, obj.adaptor_set = (adaptor_set_byte != 0));

        READWRITE(obj.t_secret);
        uint8_t has_t_byte = obj.has_t ? 1 : 0;
        READWRITE(has_t_byte);
        SER_READ(obj, obj.has_t = (has_t_byte != 0));

        READWRITE(obj.pric_refund_height);
        READWRITE(obj.foreign_refund_height);
        READWRITE(obj.delta_min_blocks);
        uint8_t tl_byte = obj.timelocks_set ? 1 : 0;
        READWRITE(tl_byte);
        SER_READ(obj, obj.timelocks_set = (tl_byte != 0));

        READWRITE(obj.presigs);

        READWRITE(obj.memo);
        READWRITE(obj.created_time);
        READWRITE(obj.updated_time);
        READWRITE(obj.abort_reason);

        // Per-leg destination addresses (appended 2026-05-02). These
        // fields are required for new records; existing pre-format
        // records will fail to deserialize. Experimental/regtest scope —
        // purge old swap records via a wallet reset if needed.
        READWRITE(obj.btc_alice_recipient_xonly_hex);
        READWRITE(obj.btc_bob_recipient_xonly_hex);
        READWRITE(obj.pric_alice_recipient_stealth);
        READWRITE(obj.pric_bob_recipient_stealth);

        // Cooperative ring (appended 2026-05-04). Same experimental/regtest
        // scope caveat — old records will fail to deserialize.
        READWRITE(obj.pric_claim_ring);

        // PRIC stealth ephemeral r (appended 2026-05-08). Same
        // experimental/regtest caveat as the prior appended fields.
        READWRITE(obj.pric_ephemeral_r);
        uint8_t r_byte = obj.has_pric_ephemeral_r ? 1 : 0;
        READWRITE(r_byte);
        SER_READ(obj, obj.has_pric_ephemeral_r = (r_byte != 0));

        // PRIC refund unsigned tx hex (appended 2026-05-11). Used by
        // the auto-refund watcher to broadcast Alice's presigned
        // refund without requiring the cooperative-sign dialog to be
        // open. Empty when not yet set by the buildtx step.
        READWRITE(obj.pric_refund_unsigned_tx_hex);

        // Peer's PRIC stealth view + spend pubkeys (appended
        // 2026-05-11). Persisted at swap creation so the loadshare
        // RPC can reconstruct the joint one-time pubkey without the
        // cooperative-sign dialog needing access to the orderbook
        // page's in-memory PeerSwapAddrs map.
        READWRITE(obj.peer_view_pubkey_hex);
        READWRITE(obj.peer_spend_pubkey_hex);

        // BTC refund unsigned tx hex (appended 2026-05-11). Used by
        // the auto-refund watcher to broadcast the BTC P2TR refund
        // without both parties needing to be online and walk through
        // the cooperative-sign dialog at timelock. Empty for LTC
        // swaps and pre-PreSigned BTC swaps.
        READWRITE(obj.btc_refund_unsigned_tx_hex);

        // Cooperative-sign per-leg session JSON (appended 2026-05-11).
        // Holds alpha, commitments, s_share, intermediates from each
        // step so the dialog can survive close+reopen without
        // restarting the ceremony.
        READWRITE(obj.pric_claim_adaptor_session_json);
        READWRITE(obj.pric_refund_session_json);
        READWRITE(obj.btc_claim_adaptor_session_json);
        READWRITE(obj.btc_refund_session_json);

        // PRIC funding unsigned-but-signed tx hex + planned vout
        // (appended 2026-05-15). Holds Alice's pre-built funding tx
        // so the cooperative ceremony can run before broadcast.
        // Same experimental/regtest-scope caveat as prior appends —
        // pre-format records will fail to deserialize.
        READWRITE(obj.pric_funding_unsigned_tx_hex);
        READWRITE(obj.pric_funding_planned_vout);

        // W (commitment image) ring components paired with
        // pric_claim_ring (appended 2026-05-16). Persisted so a
        // session-JSON wipe doesn't lose the multi-layer ring the
        // PRIC claim pre-sig is bound to.
        READWRITE(obj.pric_claim_ring_w);
    }
};

// ─── Result enums ────────────────────────────────────────────────

enum class CreateResult {
    Ok,
    InvalidCounterpartyPubkey,
    InvalidForeignLeg,
    InvalidPricLeg,
    Locked,
    WriteFailed,
};

enum class TransitionResult {
    Ok,
    NotFound,
    InvalidState,         // current state not a valid predecessor
    InvalidInput,
    InvalidTimelocks,     // ValidateRefundTimelocks rejected
    Locked,
    WriteFailed,
};

enum class LookupResult { Ok, NotFound, Locked };

// ─── API ────────────────────────────────────────────────────────

// Create a new swap record. If `swap_id_pinned` is non-null and
// non-zero, that id is used instead of generating a fresh one — used
// by the receiver-side mirror create (the matcher's wallet sends its
// swap_id in the swap_start DM so both sides key on the same id, with
// no swap_id-mapping needed in subsequent coord DMs).
// The Setup state is initial; the caller subsequently advances through
// the state machine via the SetX RPCs.
CreateResult Create(
    CWallet& wallet,
    Role role,
    const CPubKey& counterparty_pub,
    const std::string& foreign_chain,
    int64_t foreign_amount_sat,
    const std::string& pric_joint_stealth_address,
    int64_t pric_amount_sat,
    const std::string& memo,
    const std::string& btc_alice_recipient_xonly_hex,
    const std::string& btc_bob_recipient_xonly_hex,
    const std::string& pric_alice_recipient_stealth,
    const std::string& pric_bob_recipient_stealth,
    AdaptorSwap& out,
    const uint256* swap_id_pinned = nullptr);

// Stash the PRIC stealth ephemeral `r`. Bob calls this when he picks
// `r` at adaptor-setup time; Alice calls it when his ephemeral arrives
// via the adaptor_setup DM. Required for the auto-fund path so the
// on-chain P_pi matches the adaptor binding.
TransitionResult SetPricEphemeralR(
    CWallet& wallet,
    const uint256& swap_id,
    const std::array<unsigned char, 32>& r);

// Set adaptor materials. For Bob: provide t_secret + T_G + dleq.
// For Alice: provide T_G + dleq (Bob's t_secret is not given to her).
//
// Either way, the wallet code is expected to verify the DLEQ proof
// before calling — this function does NOT re-run DLEQ verification
// (the orchestration driver caller has the curve context). It only
// records the bytes.
//
// Transitions Setup → AdaptorReady IF timelocks are also set; if not,
// the record is updated but state stays Setup until SetRefundTimelocks
// is also called (then EITHER call advances to AdaptorReady).
TransitionResult SetAdaptorMaterials(
    CWallet& wallet,
    const uint256& swap_id,
    const std::array<unsigned char, 33>& T_G,
    const std::array<unsigned char, 33>& T_H,
    const std::vector<unsigned char>& dleq_proof_blob,
    const std::optional<std::array<unsigned char, 32>>& t_secret_for_bob);

// Set refund timelocks. Validated via swap::refund::ValidateRefundTimelocks.
//
// Transitions Setup → AdaptorReady IF adaptor materials are also set
// (else state stays Setup).
TransitionResult SetRefundTimelocks(
    CWallet& wallet,
    const uint256& swap_id,
    int32_t pric_refund_height,
    int32_t foreign_refund_height,
    int32_t delta_min_blocks);

// Record foreign-chain funding tx confirmed.
// Transitions AdaptorReady → BtcFunded.
TransitionResult SetBtcFunded(
    CWallet& wallet,
    const uint256& swap_id,
    const std::string& foreign_funding_txid,
    int32_t foreign_funding_vout,
    int32_t foreign_funding_height);

// Record PRIC funding tx confirmed.
// Transitions BtcFunded → BothFunded.
TransitionResult SetPricFunded(
    CWallet& wallet,
    const uint256& swap_id,
    const uint256& pric_funding_txid,
    int32_t pric_funding_vout,
    int32_t pric_funding_height);

// Record all 4 pre-signatures durably stored.
// Transitions BothFunded → PreSigned. Rejects if presigs.IsComplete()
// is false. After this transition the record is "armed" — funding
// txs can be safely broadcast knowing the refund path is recoverable.
//
// (NB: in production, this transition logically happens BEFORE the
// funding broadcasts. The state-machine ordering here treats funding
// confirmation as "we got it on-chain"; pre-sign stash is simultaneous
// with locking. In practice we expect callers to call SetPreSigned
// before broadcasting, then SetBtcFunded / SetPricFunded after each
// confirmation. The state names follow the chronological observation
// order; the protocol guarantees the pre-sigs already exist by then.)
TransitionResult SetPreSigned(
    CWallet& wallet,
    const uint256& swap_id,
    const AdaptorSwapPreSigs& presigs);

// Record Bob's PRIC claim tx confirmed (t now extractable from on-chain).
// Transitions PreSigned → PricClaimed.
TransitionResult SetPricClaimed(
    CWallet& wallet,
    const uint256& swap_id,
    const uint256& pric_claim_txid);

// Persist the adaptor scalar t into the swap record. Used by Alice's
// flow after she extracts t from Bob's on-chain PRIC claim
// (`pricoin_swapwatch_extract_pric_t` runs the math; SetTSecret
// stores it). State-machine-neutral — does NOT advance state. Idempotent
// if `t` matches the already-stored value; rejects with InvalidInput if
// has_t already and the supplied t differs (defensive against caller
// bugs). For Bob (t known at setup), this is a no-op when called with
// the same t — but normal Bob flow uses SetAdaptorMaterials.
TransitionResult SetTSecret(
    CWallet& wallet,
    const uint256& swap_id,
    const std::array<unsigned char, 32>& t);

// Persist the cooperative ring used at PRIC adapt-round-1 time. Called
// by both wallets' coopsign dialogs after a successful adaptor combine,
// so that when Bob's claim later hits chain the watcher can run extract
// (Alice) or re-adapt (Bob, after a session-JSON wipe) without manually
// re-running buildtx and invalidating the pre-sig. State-machine-neutral.
// Idempotent if the supplied ring matches the stored one. Rejects with
// InvalidInput if `ring` is empty or `ring_w` (when supplied) doesn't
// match `ring` in length.
TransitionResult SetPricClaimRing(
    CWallet& wallet,
    const uint256& swap_id,
    const std::vector<std::array<unsigned char, 33>>& ring,
    const std::vector<std::array<unsigned char, 33>>& ring_w = {});

// Record the pre-built unsigned PRIC refund tx hex. Captured by the
// spender (Alice) during the PreSigned ceremony's buildtx step so
// the auto-refund watcher can inject the cooperative refund sig and
// broadcast at PRIC refund timelock without dialog state. State-
// agnostic — allowed from any non-terminal state after Setup.
TransitionResult SetPricRefundTx(
    CWallet& wallet,
    const uint256& swap_id,
    const std::string& unsigned_tx_hex);

// Persist peer's stealth view + spend pubkeys (33-byte hex each).
// Set by the orderbook page right after swap creation, when it
// still has the PeerSwapAddrs pair from the swap_addrs DM. Needed
// by the cooperative-sign dialog's loadshare call. Idempotent
// re-set with same values is OK; conflicting re-set rejected.
TransitionResult SetPeerStealthPubkeys(
    CWallet& wallet,
    const uint256& swap_id,
    const std::string& view_hex,
    const std::string& spend_hex);

// Record the pre-built unsigned BTC refund tx hex. Captured by the
// cooperative-sign dialog at sighash-compute time (BtcPlain mode)
// so the auto-refund watcher can broadcast the BTC refund without
// dialog state. State-agnostic — allowed from any non-terminal
// state after Setup. Mirrors SetPricRefundTx.
TransitionResult SetBtcRefundTx(
    CWallet& wallet,
    const uint256& swap_id,
    const std::string& unsigned_tx_hex);

// Pin Alice's pre-built (but not yet broadcast) PRIC funding tx
// hex + the planned recipient_vout for the joint stealth output.
// Captured by Alice's wallet right after walletsendct_ring(broadcast=false)
// returns, and propagated to Bob's wallet via the funding-hex DM so
// both sides can compute scan partials in the cooperative ceremony
// before the funding tx hits the chain. State-restricted to non-
// terminal pre-funding states (Setup, AdaptorReady, BtcFunded).
// Idempotent re-set with same hex+vout is OK; clobber with different
// values is rejected (refusing to forget a value already committed).
TransitionResult SetPricFundingPlanned(
    CWallet& wallet,
    const uint256& swap_id,
    const std::string& unsigned_tx_hex,
    int32_t planned_vout);

// Cooperative-sign session legs. Selects which per-leg session JSON
// field to read/write.
enum class CoopsignLeg : uint8_t {
    PricClaimAdaptor = 0,
    PricRefund       = 1,
    BtcClaimAdaptor  = 2,
    BtcRefund        = 3,
};

// Persist a cooperative-sign dialog's per-step state as an opaque
// JSON blob keyed by leg. Used by the dialog to survive close+
// reopen without restarting the ceremony. State-agnostic — allowed
// from any non-terminal state.
TransitionResult SetCoopsignSession(
    CWallet& wallet,
    const uint256& swap_id,
    CoopsignLeg leg,
    const std::string& session_json);

// Record Alice's foreign claim tx confirmed. Swap is done.
// Transitions PricClaimed → Complete.
TransitionResult SetComplete(
    CWallet& wallet,
    const uint256& swap_id,
    const std::string& foreign_claim_txid);

// Record refund tx confirmed. Allowed from any non-terminal state
// after BothFunded (specifically: BothFunded, PreSigned, PricClaimed —
// the spec contemplates a refund any time the counterparty stalls
// during pre-sign or after one funding confirmed).
//
// `pric_refund_txid_or_empty` and `foreign_refund_txid_or_empty` —
// caller passes whichever leg refunded (typically just one).
TransitionResult SetRefunded(
    CWallet& wallet,
    const uint256& swap_id,
    const uint256& pric_refund_txid_or_empty,
    const std::string& foreign_refund_txid_or_empty);

// Operator-initiated abort. Allowed from any non-terminal state.
TransitionResult Abort(
    CWallet& wallet,
    const uint256& swap_id,
    const std::string& reason);

// Read.
LookupResult Get(CWallet& wallet, const uint256& swap_id, AdaptorSwap& out);
LookupResult List(CWallet& wallet, std::vector<AdaptorSwap>& out);

// Compute a human-readable hint of what this wallet should do next
// given the swap's current state + role.
std::string NextActionHint(const AdaptorSwap& s);

// Lifecycle.
bool LoadFromDB(CWallet& wallet);
void Shutdown();

} // namespace wallet::pricoin_adaptor_swap

#endif // BITCOIN_WALLET_PRICOIN_ADAPTOR_SWAP_H
