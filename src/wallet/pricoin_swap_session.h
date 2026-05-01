// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRICOIN_SWAP_SESSION_H
#define BITCOIN_WALLET_PRICOIN_SWAP_SESSION_H

#include <key.h>
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

// Per-wallet records that track the lifecycle of cooperative-CLSAG
// signing sessions (the PRIC-side primitive used by atomic-swap
// stage 2b → stage 3). Each session has:
//
//   * A 32-byte session_id (random, generated at create time).
//   * A reference to the wallet's STABLE swap-identity ECDSA signing
//     key — derived once from the stealth spend priv via a tagged
//     HMAC (so the long-term spend privkey is never used for routine
//     round-message signing, and one pubkey-per-wallet can be
//     advertised in an order book without rotation per session).
//   * The counterparty's swap-identity pubkey (received out-of-band,
//     typically from an order book listing).
//   * A state machine: Active → Complete | Aborted.
//   * On Aborted: a structured "blame ticket" — the counterparty's
//     signed misbehaviour-message plus the reason — that anyone
//     with the counterparty's session pubkey can verify.
//
// Sessions are persisted in the wallet DB using the existing
// at-rest encryption pattern (EncryptWalletBlob). An in-memory
// cache mirrors the DB; reads/writes go through this module.
//
// Threat model for v1:
//   * Confidentiality of session priv: same as stealth_spend_priv
//     (compromise of either compromises both, due to derivation).
//   * Counterparty authenticity: out-of-band ("the user is
//     responsible for verifying that the session pubkey they paste
//     in really belongs to the counterparty they think they're
//     trading with"). Future commits will integrate with an
//     order-book service that publishes counterparty identity keys
//     under a stable identifier.

namespace wallet::pricoin_swap_session {

enum class Role : uint8_t {
    Initiator = 0,
    Responder = 1,
};

enum class State : uint8_t {
    Active   = 0,
    Complete = 1,
    Aborted  = 2,
};

// Reason recorded with a blame ticket. Numeric so we can extend
// without breaking existing serialized records.
enum class BlameReason : uint8_t {
    None              = 0,
    InvalidSignature  = 1,  // counterparty message didn't verify against their session pubkey
    CommitmentMismatch= 2,  // counterparty round-1 commitment doesn't open to their (L,R,KI[,D])
    InvalidShare      = 3,  // counterparty round-3 share doesn't sum into a valid signature
    Other             = 255,
};

struct BlameTicket {
    BlameReason reason{BlameReason::None};
    std::vector<unsigned char> payload;    // counterparty's signed message bytes
    std::vector<unsigned char> signature;  // their ECDSA signature on the message
    std::string detail;                    // human-readable description

    SERIALIZE_METHODS(BlameTicket, obj) {
        uint8_t reason_byte = static_cast<uint8_t>(obj.reason);
        READWRITE(reason_byte);
        SER_READ(obj, obj.reason = static_cast<BlameReason>(reason_byte));
        READWRITE(obj.payload);
        READWRITE(obj.signature);
        READWRITE(obj.detail);
    }
    bool operator==(const BlameTicket&) const = default;
};

struct SwapSession {
    uint256 session_id{};

    // Per-session signing key. priv is encrypted-at-rest along with
    // the rest of the record via EncryptWalletBlob; in memory it's
    // a CKey but we serialize as the raw 32-byte secret.
    CKey    my_priv;
    CPubKey my_pub;
    CPubKey counterparty_pub;

    Role  role{Role::Initiator};
    State state{State::Active};

    // Populated on Complete:
    uint256 spend_txid{};
    // Populated on Aborted-with-blame:
    BlameTicket blame{};

    int64_t created_time{0};
    int64_t updated_time{0};

    // Application-specific metadata (e.g. counterparty's stealth
    // address, joint output hint, etc.). Opaque to this module.
    std::string memo;

    SERIALIZE_METHODS(SwapSession, obj) {
        READWRITE(obj.session_id);
        // priv as 32 raw bytes; reconstruct CKey on load. The
        // SER_WRITE / SER_READ wrappers give us the correct const-
        // ness for `obj` regardless of serialization direction.
        std::array<unsigned char, 32> priv_bytes{};
        SER_WRITE(obj, std::copy(UCharCast(obj.my_priv.data()),
                                 UCharCast(obj.my_priv.data()) + 32,
                                 priv_bytes.begin()));
        READWRITE(priv_bytes);
        SER_READ(obj, obj.my_priv.Set(priv_bytes.begin(), priv_bytes.end(), true));

        std::array<unsigned char, 33> pub_bytes{};
        std::array<unsigned char, 33> cp_bytes{};
        SER_WRITE(obj, std::copy(obj.my_pub.begin(), obj.my_pub.end(),
                                 pub_bytes.begin()));
        SER_WRITE(obj, std::copy(obj.counterparty_pub.begin(),
                                 obj.counterparty_pub.end(),
                                 cp_bytes.begin()));
        READWRITE(pub_bytes);
        READWRITE(cp_bytes);
        SER_READ(obj, obj.my_pub = CPubKey(std::span<const unsigned char>(pub_bytes.data(), 33)));
        SER_READ(obj, obj.counterparty_pub = CPubKey(std::span<const unsigned char>(cp_bytes.data(), 33)));
        uint8_t role_byte = static_cast<uint8_t>(obj.role);
        READWRITE(role_byte);
        SER_READ(obj, obj.role = static_cast<Role>(role_byte));
        uint8_t state_byte = static_cast<uint8_t>(obj.state);
        READWRITE(state_byte);
        SER_READ(obj, obj.state = static_cast<State>(state_byte));
        READWRITE(obj.spend_txid);
        READWRITE(obj.blame);
        READWRITE(obj.created_time);
        READWRITE(obj.updated_time);
        READWRITE(obj.memo);
    }
};

// Reason a Create or Attach call rejected.
enum class CreateResult {
    Ok,
    InvalidCounterpartyPubkey,
    DuplicateSessionId,    // Attach: a session with this id already exists locally
    Locked,                // Wallet encrypted-but-locked
    DerivationFailed,      // Swap-identity priv derivation produced an invalid scalar
    WriteFailed,
};

// Return this wallet's stable swap-identity pubkey. Same key across
// all sessions; safe to advertise in an order book. Derivation is
// HMAC-SHA256(stealth_spend_priv, "pricoin/swap/identity-v1") so it's
// recoverable from the wallet seed.
//
// Returns nullopt if the wallet is encrypted-but-locked or the
// derivation produced an invalid scalar (~2^-128 probability).
std::optional<CPubKey> GetSwapIdentityPubkey(CWallet& wallet);

// Initiator path. Generates a fresh random session_id, derives a
// per-session signing key from the wallet's stealth spend priv,
// stores the session record. On success, the caller exposes
// session_id + my_pub to the counterparty out-of-band.
CreateResult Create(
    CWallet& wallet,
    const CPubKey& counterparty_pub,
    const std::string& memo,
    SwapSession& out);

// Responder path. Takes the session_id + counterparty pubkey
// supplied by the initiator and creates a matching local record.
// session_id must NOT already exist in this wallet.
CreateResult Attach(
    CWallet& wallet,
    const uint256& session_id,
    const CPubKey& counterparty_pub,
    const std::string& memo,
    SwapSession& out);

// Sign a payload using the session's per-session priv. Returns
// false if the session doesn't exist or the wallet is locked.
bool Sign(
    CWallet& wallet,
    const uint256& session_id,
    std::span<const unsigned char> payload,
    std::vector<unsigned char>& sig_out);

// Verify a payload's signature against the session's stored
// counterparty pubkey. Returns false on lookup miss or invalid sig.
bool Verify(
    CWallet& wallet,
    const uint256& session_id,
    std::span<const unsigned char> payload,
    std::span<const unsigned char> sig);

// Result of looking up a session.
enum class LookupResult { Ok, NotFound, Locked };
LookupResult Get(CWallet& wallet, const uint256& session_id, SwapSession& out);

// Enumerate all sessions in this wallet.
LookupResult List(CWallet& wallet, std::vector<SwapSession>& out);

// Reason a state-transition call rejected.
enum class TransitionResult {
    Ok,
    NotFound,
    InvalidState,    // session is already Complete/Aborted
    InvalidBlame,    // blame's signature doesn't verify against counterparty_pub
    Locked,
    WriteFailed,
};

// Mark a session Complete with the on-chain spend txid.
TransitionResult Complete(
    CWallet& wallet,
    const uint256& session_id,
    const uint256& spend_txid);

// Mark a session Aborted. If `blame` is provided, its `payload` +
// `signature` MUST verify against the counterparty's session pubkey
// (else InvalidBlame); this is what makes the abort identifiable.
// An abort without a blame ticket is permitted (e.g., voluntary
// timeout) — the session just transitions to Aborted with empty blame.
TransitionResult Abort(
    CWallet& wallet,
    const uint256& session_id,
    std::optional<BlameTicket> blame);

// Drop the in-memory cache. Called from the daemon's Shutdown path
// before process exit (mirrors wallet/pricoin_stealth.cpp pattern).
void Shutdown();

// Load all session records persisted for `wallet` into the in-memory
// cache. Called from CWallet::LoadWallet after the DB is opened.
// Returns false on a corrupt record (the caller treats that as a
// load error).
bool LoadFromDB(CWallet& wallet);

} // namespace wallet::pricoin_swap_session

#endif // BITCOIN_WALLET_PRICOIN_SWAP_SESSION_H
