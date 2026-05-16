// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRICOIN_OFFER_H
#define BITCOIN_WALLET_PRICOIN_OFFER_H

#include <key.h>
#include <pubkey.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wallet { class CWallet; }

// Phase 6 (UI Tier 1) — local order management for the atomic-swap
// orderbook. Users post offers (fixed price, max quantity) and import
// counterparties' offers via signed URIs. The matching engine surfaces
// price-crosses; an accept transitions both orders to Matched and
// kicks off the existing swap-session / adaptor-swap setup.
//
// SCOPE OF THIS COMMIT (Tier 1)
//   * Local persistence of orders + URI serialization for off-band
//     exchange (paste, QR, Telegram, etc.).
//   * RPCs for create / import / list / get / cancel / find_matches /
//     match / fill / unmatch / export.
//   * No network propagation (Tier 2).
//   * No Qt UI (separate commit).
//
// SECURITY POSTURE
//   * The maker signs the offer payload with their swap-identity
//     ECDSA priv (the same key from `pricoin_swap_session::GetSwapIdentityPubkey`).
//     Importers verify the signature against `maker_pubkey` — proves
//     the offer originated from that pubkey.
//   * Importing duplicates (same `order_id`) is rejected: prevents an
//     attacker from re-importing a stale offer to confuse the wallet.
//   * Expiry is wall-clock; expired-but-still-Active orders auto-
//     transition to Expired on the next list/match call.
//
// PARTIAL-FILL STATE MACHINE
//   `pric_remaining_sat` starts at `payload.max_pric_amount_sat` and
//   decrements only on `Fill` (swap completion). `pric_in_flight_sat`
//   is reserved during `Matched` and zeroed on either Fill or Unmatch.
//   At any time at most ONE counterparty is in-flight per order
//   (enforced by the Matched state being mutually exclusive).

namespace wallet::pricoin_offer {

enum class Side : uint8_t {
    BuyPric  = 0,  // pay foreign, receive PRIC
    SellPric = 1,  // pay PRIC, receive foreign
};

enum class ForeignChain : uint8_t {
    Btc = 0,
    Ltc = 1,
};

enum class Origin : uint8_t {
    Local    = 0,  // we created this order; we hold the maker_priv
    Imported = 1,  // we received this order from someone else
};

enum class Status : uint8_t {
    Active    = 0,
    Matched   = 1,
    Filled    = 2,  // pric_remaining == 0 (fully consumed)
    Cancelled = 3,
    Expired   = 4,
};

// Serialized inside the URI; signed by the maker. Receiving wallets
// reproduce these bytes byte-for-byte to verify the signature.
struct OfferPayload {
    uint8_t version{1};
    uint256 order_id{};
    Side side{Side::BuyPric};
    ForeignChain foreign_chain{ForeignChain::Btc};
    int64_t max_pric_amount_sat{0};
    int64_t foreign_amount_at_max_sat{0};  // implies the rate
    int64_t expiry_unix_sec{0};
    CPubKey maker_pubkey;
    std::vector<unsigned char> signature;  // ECDSA-DER over the above

    bool operator==(const OfferPayload&) const = default;

    SERIALIZE_METHODS(OfferPayload, obj) {
        READWRITE(obj.version);
        READWRITE(obj.order_id);
        uint8_t side = static_cast<uint8_t>(obj.side);
        READWRITE(side);
        SER_READ(obj, obj.side = static_cast<Side>(side));
        uint8_t chain = static_cast<uint8_t>(obj.foreign_chain);
        READWRITE(chain);
        SER_READ(obj, obj.foreign_chain = static_cast<ForeignChain>(chain));
        READWRITE(obj.max_pric_amount_sat);
        READWRITE(obj.foreign_amount_at_max_sat);
        READWRITE(obj.expiry_unix_sec);
        std::array<unsigned char, 33> pub_bytes{};
        SER_WRITE(obj, std::copy(obj.maker_pubkey.begin(),
                                 obj.maker_pubkey.end(), pub_bytes.begin()));
        READWRITE(pub_bytes);
        SER_READ(obj, obj.maker_pubkey = CPubKey(
            std::span<const unsigned char>(pub_bytes.data(), 33)));
        READWRITE(obj.signature);
    }
};

// On-disk record. Carries OfferPayload plus local-only metadata.
struct Order {
    OfferPayload payload;
    Origin       origin{Origin::Local};
    Status       status{Status::Active};

    // Partial-fill bookkeeping.
    int64_t      pric_remaining_sat{0};   // initialized to payload.max_pric_amount_sat
    int64_t      pric_in_flight_sat{0};   // reserved while Matched
    uint256      matched_with_order_id{}; // peer order's id while Matched

    std::string  notes;                   // free-form, local only
    int64_t      created_time{0};
    int64_t      updated_time{0};

    // AdaptorSwap id created from this order. Set by LinkSwap once the
    // orderbook page's Start-swap path returns successfully. Survives
    // Unmatch (which clears matched_with_order_id) so the watcher's
    // post-terminal hook can find the order to Fill even if the user
    // — or a peer DM — released the match mid-swap. Null while the
    // order has never been used to drive a swap. Cleared by Fill
    // (success) since the swap has consumed its in-flight share.
    uint256      linked_swap_id{};

    bool operator==(const Order&) const = default;

    SERIALIZE_METHODS(Order, obj) {
        READWRITE(obj.payload);
        uint8_t origin_byte = static_cast<uint8_t>(obj.origin);
        READWRITE(origin_byte);
        SER_READ(obj, obj.origin = static_cast<Origin>(origin_byte));
        uint8_t status_byte = static_cast<uint8_t>(obj.status);
        READWRITE(status_byte);
        SER_READ(obj, obj.status = static_cast<Status>(status_byte));
        READWRITE(obj.pric_remaining_sat);
        READWRITE(obj.pric_in_flight_sat);
        READWRITE(obj.matched_with_order_id);
        READWRITE(obj.notes);
        READWRITE(obj.created_time);
        READWRITE(obj.updated_time);

        // linked_swap_id (appended 2026-05-16). Tolerate older records
        // that lack the field — the wallet's offer cache treats deser
        // failure on append as "use default (null) and continue", per
        // the same convention used in pricoin_adaptor_swap.
        READWRITE(obj.linked_swap_id);
    }
};

// ─── URI codec ──────────────────────────────────────────────────────

// Encode an OfferPayload into the canonical URI form:
//   pricoffer:v1/<base64url(serialize(payload))>
std::string EncodeUri(const OfferPayload& p);

// Parse a URI back to an OfferPayload. Validates the scheme prefix
// and base64 decoding; does NOT verify the signature (caller does).
std::optional<OfferPayload> DecodeUri(const std::string& uri);

// ─── Signing & verification ─────────────────────────────────────────

// Compute the SHA256d of the payload bytes (sans signature) used as
// the digest under ECDSA. Both maker and verifier must agree on this.
uint256 SigningHash(const OfferPayload& p);

// Sign an unsigned payload with `priv`, populating `payload.signature`
// and `payload.maker_pubkey`. The wallet's swap-identity priv is
// expected.
bool SignPayload(OfferPayload& payload, const CKey& priv);

// Verify a signed payload's signature against its `maker_pubkey`.
// Does NOT check expiry or any wallet state.
bool VerifySignedPayload(const OfferPayload& p);

// ─── Matching logic (pure) ──────────────────────────────────────────

struct MatchProposal {
    int64_t actual_pric_amount_sat{0};
    int64_t actual_foreign_amount_sat{0};  // computed at maker's (ask's) rate
    bool    bid_is_us{false};               // true: my order is the bid; false: my order is the ask
};

// Determine whether `mine` and `theirs` cross. Returns the proposed
// fill if so, given a desired actual_pric_amount that the taker chose.
// Validates:
//   * statuses both Active, neither expired (vs `now`)
//   * opposite sides, same foreign_chain
//   * price-cross (bid.rate ≥ ask.rate)
//   * actual_pric ≤ min(both pric_remaining_sat)
// Returns nullopt on any validation failure.
std::optional<MatchProposal> EvaluateMatch(
    const Order& mine, const Order& theirs,
    int64_t actual_pric_amount_sat, int64_t now_unix_sec);

// Helper: compute foreign-amount at maker's rate, with int128 overflow
// safety. Returns nullopt if the multiplication can't fit.
//   foreign = floor(pric_amount * ask.foreign_at_max / ask.pric_max)
std::optional<int64_t> ProRateForeign(
    int64_t pric_amount_sat,
    int64_t ask_max_pric_sat,
    int64_t ask_foreign_at_max_sat);

// ─── Wallet API ─────────────────────────────────────────────────────

enum class CreateResult {
    Ok,
    InvalidInput,
    Locked,                  // wallet encrypted-but-locked
    DerivationFailed,        // swap-identity priv unavailable
    WriteFailed,
};

struct CreateParams {
    Side          side;
    ForeignChain  foreign_chain;
    int64_t       max_pric_amount_sat;
    int64_t       foreign_amount_at_max_sat;
    int64_t       expiry_unix_sec;
    std::string   notes;
};

// Create a Local order. Generates a fresh order_id, derives maker_priv
// from the wallet's swap identity, signs the payload.
CreateResult Create(CWallet& wallet, const CreateParams& params, Order& out);

enum class ImportResult {
    Ok,
    InvalidUri,
    InvalidSignature,
    Duplicate,                   // order_id already in this wallet
    AlreadyExpired,
    Locked,
    WriteFailed,
};

// Import an Imported order from a URI string.
ImportResult Import(CWallet& wallet, const std::string& uri, Order& out);

enum class MutateResult {
    Ok,
    NotFound,
    InvalidState,
    InvalidInput,
    PriceCrossFailed,            // EvaluateMatch said no
    Locked,
    WriteFailed,
};

// Operator-cancel a non-terminal order (Active → Cancelled).
MutateResult Cancel(CWallet& wallet, const uint256& order_id);

// Two orders held by THIS wallet are crossed and locked to each
// other. Both must be Active. After Match: status=Matched on both,
// pric_in_flight_sat = actual_pric_amount, matched_with_order_id set.
//
// Note: in production both orders won't both be in this wallet (the
// counterparty has theirs). This RPC is the single-wallet primitive;
// wallets-with-counterparty workflows use it to seal the local-side
// view of the match (their_order is an Imported one).
MutateResult Match(
    CWallet& wallet,
    const uint256& my_order_id,
    const uint256& their_order_id,
    int64_t actual_pric_amount_sat);

// Mark a matched order as filled (swap completed). Decrements
// pric_remaining_sat by pric_in_flight_sat; resets in_flight to 0.
// If remaining==0 → status=Filled (terminal); else → status=Active.
MutateResult Fill(CWallet& wallet, const uint256& order_id);

// Release a Matched order back to Active without consuming. Used
// when the swap setup aborts before reaching the finality point.
MutateResult Unmatch(CWallet& wallet, const uint256& order_id);

// Tag an order with the AdaptorSwap id it backed. Set by the
// orderbook page right after a successful adaptorSwapCreate so the
// linkage survives Unmatch / Cancel (which clear `matched_with_order_id`).
// Idempotent — re-set with same value is OK; re-set with a different
// value is rejected to prevent silent overwrite of a real linkage.
MutateResult LinkSwap(
    CWallet& wallet, const uint256& order_id, const uint256& swap_id);

// Apply a swap-consumed deduction to an order, independent of current
// status — used by the watcher's self-heal when the order's
// `matched_with` link was cleared (Unmatch / Cancel cascade) before
// the swap reached its terminal state. Decrements
// `pric_remaining_sat` by `consumed`, resets `pric_in_flight_sat` to
// 0, clears `linked_swap_id`, and sets status:
//   * Matched / Active → Active if remaining > dust else Filled.
//   * Filled / Cancelled / Expired → unchanged (terminal).
// Returns Ok in both the "applied" and "already-applied (idempotent)"
// cases so the caller's retry-loop doesn't churn.
MutateResult FillFromLinkedSwap(
    CWallet& wallet, const uint256& order_id, int64_t consumed_sat);

// Build a freshly-signed offer URI for the LIVE remaining amount of
// a local order. Uses the same maker priv as the original payload —
// peer wallets validate the new sig against the existing
// maker_pubkey, so the URI is a drop-in replacement. The new payload
// keeps the same `order_id`, `side`, `foreign_chain`, `expiry`, and
// `maker_pubkey`; only `max_pric_amount_sat` (= current
// pric_remaining_sat) and `foreign_amount_at_max_sat` (scaled to
// preserve the original rate) change. Returns empty string on
// failure (wallet locked, not a local order, remaining ≤ 0, etc).
//
// Caller (typically the chain watcher's post-Fill hook or the
// orderbook page) is responsible for publishing the URI to peers
// via Nostr. The local order itself is NOT mutated by this call.
std::string RepublishUri(CWallet& wallet, const uint256& order_id);

// Receive-side counterpart to RepublishUri: apply a maker-supplied
// updated offer payload to an already-imported order. Validates that:
//   * The order exists locally with origin=Imported.
//   * The new payload's maker_pubkey matches the stored one.
//   * The new payload's signature verifies.
//   * The new max_pric_amount_sat is ≤ the stored max (monotonic non-
//     increase — peers can shrink offers via fills, never grow them).
// On accept, the import record's max + foreign + payload + signature
// are replaced and `pric_remaining_sat` is clamped to the new max.
// `pric_in_flight_sat` / `matched_with_order_id` are NOT touched (an
// active match against the order is unaffected by a shrink).
MutateResult ApplyImportedUpdate(
    CWallet& wallet, const std::string& uri);

// Auto-expire (no-op if Active and not expired). Idempotent.
// Useful as a periodic sweep; also called by List/Get internally.
void SweepExpired(CWallet& wallet, int64_t now_unix_sec);

// Read.
enum class LookupResult { Ok, NotFound, Locked };
LookupResult Get(CWallet& wallet, const uint256& order_id, Order& out);
LookupResult List(CWallet& wallet, std::vector<Order>& out);

// Find candidate price-crosses for `my_order_id` among the wallet's
// Imported orders that are Active and not expired. Returns sorted
// best-first (best price for me at index 0).
struct MatchCandidate {
    uint256 their_order_id;
    int64_t their_max_pric_sat;
    int64_t their_foreign_at_max_sat;
    int64_t max_actual_pric_sat;     // min(my, their) remaining
    int64_t price_advantage_milli;   // basis-points-ish; bigger = better for me
};
LookupResult FindMatches(
    CWallet& wallet,
    const uint256& my_order_id,
    std::vector<MatchCandidate>& out);

// Re-export an order's URI (for re-publishing). Local-only orders.
LookupResult ExportUri(CWallet& wallet, const uint256& order_id, std::string& uri_out);

// Lifecycle.
bool LoadFromDB(CWallet& wallet);
void Shutdown();

// Daemon-startup self-test (URI codec + matching logic + signature).
void RunSelfTest();

} // namespace wallet::pricoin_offer

#endif // BITCOIN_WALLET_PRICOIN_OFFER_H
