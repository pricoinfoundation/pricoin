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

    bool IsComplete() const {
        return !btc_claim_presig.empty()
            && !btc_claim_session.empty()
            && !pric_claim_presig_blob.empty()
            && !btc_refund_sig.empty()
            && !pric_refund_sig_blob.empty();
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
        // records will fail to deserialize. Toy/regtest scope —
        // purge old swap records via a wallet reset if needed.
        READWRITE(obj.btc_alice_recipient_xonly_hex);
        READWRITE(obj.btc_bob_recipient_xonly_hex);
        READWRITE(obj.pric_alice_recipient_stealth);
        READWRITE(obj.pric_bob_recipient_stealth);
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

// Create a new swap record. Generates a fresh 32-byte swap_id.
// The Setup state is initial; the caller subsequently advances
// through the state machine via the SetX RPCs.
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
    AdaptorSwap& out);

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
