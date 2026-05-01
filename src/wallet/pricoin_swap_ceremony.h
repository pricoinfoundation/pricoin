// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRICOIN_SWAP_CEREMONY_H
#define BITCOIN_WALLET_PRICOIN_SWAP_CEREMONY_H

#include <consensus/amount.h>
#include <pubkey.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wallet {
class CWallet;
} // namespace wallet

// Phase-3 atomic-swap orchestration. SwapCeremony is the wallet-level
// state machine that walks a single cross-chain swap end-to-end —
// foreign-chain (BTC/LTC/...) HTLC funding + claim/refund on one
// side, PRIC joint-stealth output + cooperative spend on the other.
//
// IMPORTANT: this state machine alone does NOT make a swap atomic.
// Real atomicity requires adaptor-CLSAG (deferred — see
// doc/atomic-swap-protocol.md, Q5). Without it, the party who
// finalizes second can stall, and the counterparty's only safeguard
// is the foreign-chain timelock refund. Use only with trusted
// counterparties or alongside a slashing-deposit mechanism (which
// will land in phase 7's order book).
//
// State machine (forward path):
//
//     Init  ──────► BtcFunded  ──────► PricFunded  ──────►
//   (record           (counterparty       (joint stealth
//    created)         locked their        output created
//                     foreign HTLC)        on PRIC)
//
//     BtcClaimed ──────► PricReleased
//   (we claimed       (cooperatively
//    foreign chain     signed PRIC
//    via preimage)     spend)            ─► Complete
//
// Off-path:
//
//     any state ──────► Aborted (with reason / blame ticket)
//
// Roles:
//   * BuyingForeign — we send PRIC, receive BTC/LTC. We're the
//     "Alice" side: we lock PRIC into joint stealth, then claim
//     the foreign HTLC with our preimage.
//   * SellingForeign — we send BTC/LTC, receive PRIC. We're the
//     "Bob" side: we lock the foreign HTLC, wait for Alice to
//     claim BTC + reveal preimage (or extract t via adaptor in
//     phase 5), then cooperatively claim PRIC.
//
// For each role, `pricoin_swap_ceremony_next_action` returns a
// human-readable hint string describing what should happen next.

namespace wallet::pricoin_swap_ceremony {

enum class State : uint8_t {
    Init         = 0,
    BtcFunded    = 1,
    PricFunded   = 2,
    BtcClaimed   = 3,
    PricReleased = 4,
    Complete     = 5,
    Aborted      = 6,
};

enum class Role : uint8_t {
    BuyingForeign  = 0,  // we send PRIC, receive foreign coin
    SellingForeign = 1,  // we send foreign coin, receive PRIC
};

// Foreign-chain side details — captured at creation, immutable
// thereafter. Counterparty learns these out-of-band (or via the
// future order-book service).
struct ForeignLeg {
    // Symbolic chain name; matches a registered chainwatch backend.
    std::string chain;            // "btc", "ltc", ...
    // P2WSH bech32 address derived from the HTLC redeem script.
    std::string htlc_address;
    // Hex of the redeem script — needed to spend the HTLC.
    std::vector<unsigned char> redeem_script;
    // Amount that should be locked into the HTLC, in the foreign
    // chain's smallest unit (satoshi for BTC/LTC).
    int64_t amount_sat{0};
    // Block height (or unix time, per OP_CLTV semantics) at which
    // the refund path becomes spendable.
    int64_t timeout{0};

    SERIALIZE_METHODS(ForeignLeg, obj) {
        READWRITE(obj.chain);
        READWRITE(obj.htlc_address);
        READWRITE(obj.redeem_script);
        READWRITE(obj.amount_sat);
        READWRITE(obj.timeout);
    }
};

// PRIC-side details.
struct PricLeg {
    // Joint stealth address — both parties cooperate to spend.
    std::string joint_stealth_address;
    // Our share of the joint output's spend secret. NOT a wallet's
    // long-term identity — it's the per-output share derived via
    // pricoin_jointspend_loadshare, valid only for this output.
    std::vector<unsigned char> our_x_share;  // empty until the joint
                                             // output is recovered
    // Amount in PRIC satoshis.
    int64_t amount_sat{0};

    SERIALIZE_METHODS(PricLeg, obj) {
        READWRITE(obj.joint_stealth_address);
        READWRITE(obj.our_x_share);
        READWRITE(obj.amount_sat);
    }
};

struct SwapCeremony {
    uint256 ceremony_id{};
    Role    role{Role::BuyingForeign};
    State   state{State::Init};

    // Counterparty's stable swap-identity pubkey (from
    // pricoin_swap_identity in their wallet).
    CPubKey counterparty_pub;

    ForeignLeg foreign;
    PricLeg    pric;

    // 32-byte preimage hash. The preimage itself is held only by
    // BuyingForeign (Alice); they reveal it on-chain when claiming.
    std::vector<unsigned char> preimage_hash;
    // Set on BuyingForeign once they generate it; serialized so
    // recovery from wallet backup works. SellingForeign learns it
    // only when it's revealed on the foreign chain.
    std::vector<unsigned char> preimage;

    // Outpoints populated as the protocol advances.
    std::string foreign_funding_txid;
    int32_t     foreign_funding_vout{-1};
    std::string foreign_claim_txid;     // set on BtcClaimed
    uint256     pric_funding_txid;
    int32_t     pric_funding_vout{-1};
    uint256     pric_release_txid;      // set on PricReleased

    // Free-form note + timestamps + abort details.
    std::string memo;
    int64_t created_time{0};
    int64_t updated_time{0};
    std::string abort_reason;

    SERIALIZE_METHODS(SwapCeremony, obj) {
        READWRITE(obj.ceremony_id);
        uint8_t r = static_cast<uint8_t>(obj.role);
        READWRITE(r);
        SER_READ(obj, obj.role = static_cast<Role>(r));
        uint8_t st = static_cast<uint8_t>(obj.state);
        READWRITE(st);
        SER_READ(obj, obj.state = static_cast<State>(st));

        std::array<unsigned char, 33> cp_bytes{};
        SER_WRITE(obj, std::copy(obj.counterparty_pub.begin(),
                                 obj.counterparty_pub.end(), cp_bytes.begin()));
        READWRITE(cp_bytes);
        SER_READ(obj, obj.counterparty_pub = CPubKey(
            std::span<const unsigned char>(cp_bytes.data(), 33)));

        READWRITE(obj.foreign);
        READWRITE(obj.pric);
        READWRITE(obj.preimage_hash);
        READWRITE(obj.preimage);
        READWRITE(obj.foreign_funding_txid);
        READWRITE(obj.foreign_funding_vout);
        READWRITE(obj.foreign_claim_txid);
        READWRITE(obj.pric_funding_txid);
        READWRITE(obj.pric_funding_vout);
        READWRITE(obj.pric_release_txid);
        READWRITE(obj.memo);
        READWRITE(obj.created_time);
        READWRITE(obj.updated_time);
        READWRITE(obj.abort_reason);
    }
};

enum class CreateResult {
    Ok,
    InvalidCounterpartyPubkey,
    InvalidForeignLeg,
    InvalidPricLeg,
    InvalidPreimage,    // override length wrong, or hash supplied by SellingForeign isn't 32 bytes
    Locked,
    WriteFailed,
};

enum class TransitionResult {
    Ok,
    NotFound,
    InvalidState,
    InvalidInput,
    Locked,
    WriteFailed,
};

enum class LookupResult { Ok, NotFound, Locked };

// Reset / lifecycle helpers (mirrors pricoin_swap_session pattern).
void Shutdown();

// Create a new ceremony. Generates a fresh 32-byte ceremony_id and
// (for BuyingForeign role) a fresh 32-byte preimage. Returns the
// session record.
//
// `preimage_override` lets a caller supply an externally-generated
// preimage (e.g., for deterministic test fixtures or HD derivation).
// Pass empty to have us generate one.
CreateResult Create(
    CWallet& wallet,
    Role role,
    const CPubKey& counterparty_pub,
    const ForeignLeg& foreign,
    const PricLeg& pric,
    std::span<const unsigned char> preimage_override,
    const std::string& memo,
    SwapCeremony& out);

// Record the foreign-chain HTLC funding. Transitions Init →
// BtcFunded.
TransitionResult SetForeignFunded(
    CWallet& wallet,
    const uint256& ceremony_id,
    const std::string& funding_txid,
    int32_t funding_vout);

// Record the PRIC joint-stealth output. Transitions BtcFunded →
// PricFunded. `our_x_share` is the spend-secret share returned by
// pricoin_jointspend_loadshare.
TransitionResult SetPricFunded(
    CWallet& wallet,
    const uint256& ceremony_id,
    const uint256& pric_txid,
    int32_t pric_vout,
    std::span<const unsigned char> our_x_share);

// Record a successful foreign-chain claim. Transitions PricFunded →
// BtcClaimed. The recorded `claim_txid` is for status display; the
// preimage is already in the record for BuyingForeign role, and
// SellingForeign should learn it from the on-chain claim and pass
// it here.
TransitionResult SetForeignClaimed(
    CWallet& wallet,
    const uint256& ceremony_id,
    const std::string& claim_txid,
    std::span<const unsigned char> preimage);

// Record a successful PRIC cooperative spend. Transitions BtcClaimed →
// PricReleased → Complete.
TransitionResult SetPricReleased(
    CWallet& wallet,
    const uint256& ceremony_id,
    const uint256& release_txid);

// Abort from any non-terminal state.
TransitionResult Abort(
    CWallet& wallet,
    const uint256& ceremony_id,
    const std::string& reason);

// Read.
LookupResult Get(CWallet& wallet, const uint256& ceremony_id, SwapCeremony& out);
LookupResult List(CWallet& wallet, std::vector<SwapCeremony>& out);

// Compute a human-readable hint describing the next action expected
// of THIS wallet, given the ceremony's current state + role.
std::string NextActionHint(const SwapCeremony& s);

// Load all ceremonies persisted in this wallet's DB. Called from
// wallet open path (or lazily on first authenticated access).
bool LoadFromDB(CWallet& wallet);

} // namespace wallet::pricoin_swap_ceremony

#endif // BITCOIN_WALLET_PRICOIN_SWAP_CEREMONY_H
