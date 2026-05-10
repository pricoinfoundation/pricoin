// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRICOIN_CHAIN_WATCHER_H
#define BITCOIN_WALLET_PRICOIN_CHAIN_WATCHER_H

// Phase-6 Tier-3 chain watcher.
//
// pricoind autonomously detects on-chain events (foreign and PRIC)
// and advances the AdaptorSwap state machine via the existing
// pricoin_adaptor_swap::SetX transitions, eliminating the manual
// "Set BTC funded / Set PRIC claimed / etc." clicks for the
// happy-path swap flow.
//
// DESIGN
// ─────
// The watcher works on **registered txids**: rather than scan
// arbitrary addresses (which would need an indexer like Esplora or
// `-txindex`), the user — or an external script wired to the
// foreign-chain RPC — registers a candidate txid via the
// `pricoin_chainwatch_add` RPC. The watcher polls confirmations on
// that txid and, when threshold is reached, calls the matching
// SetX transition.
//
// For experimental/regtest scope without a real foreign-chain HTTP client,
// an external script (or the user) can drive transitions directly
// via `pricoin_chainwatch_notify`, which acts as a manual
// "confirmation observed" event.
//
// PERSISTENCE
// ───────────
// Pending watch entries live in the wallet DB (key
// `pct_chain_watch`), keyed by SHA256(swap_id || kind). Records
// are encrypted at rest via EncryptWalletBlob — they're not secret
// but the at-rest posture matches the rest of the wallet.
//
// FOREIGN CHAIN CLIENT
// ────────────────────
// The watcher takes an `IForeignChainClient` per chain. The mock
// client (used by tests) returns canned values; a real Bitcoin
// Core RPC backend is a follow-on commit. The PRIC leg uses the
// embedded chainstate directly via interfaces::Chain (no client).
//
// THREADING
// ─────────
// `Start()` spawns a single polling thread. `Stop()` joins it.
// `TickOnce()` is exposed for tests so the loop can be driven
// synchronously without a thread.

#include <serialize.h>
#include <uint256.h>
#include <util/result.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace wallet {
class CWallet;
class WalletBatch;
} // namespace wallet

namespace wallet::pricoin_chain_watcher {

// What kind of transition this watch entry will trigger when the
// txid reaches the required confirmation depth.
enum class WatchKind : uint8_t {
    ForeignFunding = 1,   // → SetBtcFunded
    PricFunding    = 2,   // → SetPricFunded
    PricClaim      = 3,   // → SetPricClaimed
    ForeignClaim   = 4,   // → SetComplete
    PricRefund     = 5,   // → SetRefunded (pric leg)
    ForeignRefund  = 6,   // → SetRefunded (foreign leg)
};

const char* WatchKindName(WatchKind k);
std::optional<WatchKind> ParseWatchKind(const std::string& s);

struct WatchEntry {
    uint256     swap_id{};
    WatchKind   kind{WatchKind::ForeignFunding};
    std::string txid_hex;          // 64-char lowercase hex
    int32_t     vout{-1};          // funding kinds only
    int32_t     min_confirmations{1};
    int64_t     added_unix{0};

    SERIALIZE_METHODS(WatchEntry, obj) {
        READWRITE(obj.swap_id);
        uint8_t kind_byte = static_cast<uint8_t>(obj.kind);
        READWRITE(kind_byte);
        SER_READ(obj, obj.kind = static_cast<WatchKind>(kind_byte));
        READWRITE(obj.txid_hex);
        READWRITE(obj.vout);
        READWRITE(obj.min_confirmations);
        READWRITE(obj.added_unix);
    }
};

// Foreign-chain client abstraction. The watcher calls into this to
// poll confirmations on registered txids. PRIC-leg watching uses
// interfaces::Chain directly; this interface covers BTC + LTC.
struct ForeignTxStatus {
    bool found{false};
    int  confirmations{0};
    int  block_height{-1};
};

class IForeignChainClient {
public:
    virtual ~IForeignChainClient() = default;
    // Returns the current tip height of the foreign chain, or
    // std::nullopt if the chain is unreachable.
    virtual std::optional<int> TipHeight() = 0;
    // Look up a tx's confirmation status. `not found` and
    // `unreachable` are different — the caller distinguishes via
    // the return: nullopt = unreachable; ForeignTxStatus.found=false
    // = relay says no such tx.
    virtual std::optional<ForeignTxStatus> TxStatus(const std::string& txid_hex) = 0;

    // Broadcast a hex-encoded tx to the foreign chain. Returns the
    // txid the backend accepted (typically equal to the locally-
    // computed hash). Throws on failure — wraps the underlying
    // backend error in std::runtime_error so the wallet library
    // doesn't need to link the swap module's exception type.
    virtual std::string Broadcast(const std::string& tx_hex) = 0;

    // Holding-wallet support: enumerate the unspent outputs paying
    // the address, and the aggregate confirmed/unconfirmed balance.
    // Throws on backend failure.
    struct Utxo {
        std::string txid;
        int32_t     vout{-1};
        int64_t     value_sat{0};
        bool        confirmed{false};
        int         block_height{-1};
    };
    virtual std::vector<Utxo> GetAddressUtxos(const std::string& address) = 0;

    struct Balance {
        int64_t confirmed_sat{0};
        int64_t unconfirmed_sat{0};
        int     utxo_count{0};
    };
    virtual Balance GetAddressBalance(const std::string& address) = 0;

    // Backend's per-confirmation-target fee-rate estimates, in sat/vB.
    // Empty map if the backend can't provide them; callers fall back
    // to a hardcoded default in that case. See Esplora's
    // `/fee-estimates` for the source format.
    virtual std::map<int, double> GetFeeEstimates() = 0;
};

// Pluggable factory for resolving a foreign-chain client by chain
// name. The daemon (init.cpp) installs an implementation that
// delegates to `pricoin::swap::GetBackend(chain_name)` wrapped in
// `ChainBackendForeignClient` — but the wallet library can't link
// the swap module directly (the bitcoin-wallet utility doesn't pull
// it in), so we route through this hook.
//
// Tests may also override the factory to inject mocks, though most
// tests use the explicit ForeignClientMap on the ChainWatcher
// constructor (which short-circuits the factory).
using ForeignClientFactory =
    std::function<std::shared_ptr<IForeignChainClient>(const std::string&)>;

void SetForeignClientFactory(ForeignClientFactory factory);
std::shared_ptr<IForeignChainClient> MakeForeignClientFromRegistry(
    const std::string& chain_name);

// Test/dev mock. Configurable via Set* setters; thread-safe.
class MockForeignChainClient final : public IForeignChainClient {
public:
    std::optional<int> TipHeight() override;
    std::optional<ForeignTxStatus> TxStatus(const std::string& txid_hex) override;

    std::string Broadcast(const std::string& tx_hex) override;
    std::vector<Utxo>    GetAddressUtxos(const std::string& address) override;
    Balance              GetAddressBalance(const std::string& address) override;
    std::map<int, double> GetFeeEstimates() override;

    // Test config — protected by an internal mutex.
    void SetTipHeight(std::optional<int> h);
    void SetTxStatus(const std::string& txid_hex, ForeignTxStatus s);
    void ClearTxStatus(const std::string& txid_hex);
    void SetBroadcastResponse(const std::string& txid);
    std::string LastBroadcast() const;
private:
    mutable std::mutex m_mu;
    std::optional<int> m_tip_height;
    std::map<std::string, ForeignTxStatus> m_tx_status;
    std::string m_broadcast_response_txid;
    std::string m_last_broadcast;
};

// ─── Persistence + lookup ────────────────────────────────────────

enum class StoreResult {
    Ok,
    InvalidInput,
    Locked,
    WriteFailed,
    Duplicate,
    NotFound,
};

const char* StoreResultName(StoreResult r);

// Add a pending watch entry. Duplicate (swap_id, kind) overwrites
// the existing entry — call sites that want strict-no-clobber
// should call Get() first.
StoreResult Add(::wallet::CWallet& wallet, const WatchEntry& e);
// Remove a pending entry. NotFound is non-fatal for callers that
// just want to ensure absence.
StoreResult Remove(::wallet::CWallet& wallet,
                    const uint256& swap_id, WatchKind kind);
// Read a single entry.
StoreResult Get(::wallet::CWallet& wallet,
                 const uint256& swap_id, WatchKind kind, WatchEntry& out);
// Snapshot all entries — order is unspecified.
StoreResult List(::wallet::CWallet& wallet, std::vector<WatchEntry>& out);

// Read all rows from disk into the in-memory cache. Call on wallet
// load. Idempotent.
bool LoadFromDB(::wallet::CWallet& wallet);
// Tear down the in-memory cache; called from init::Shutdown.
void Shutdown();

// ─── ChainWatcher service ────────────────────────────────────────

using ForeignClientMap = std::map<std::string, std::shared_ptr<IForeignChainClient>>;

class ChainWatcher {
public:
    ChainWatcher(::wallet::CWallet& wallet,
                  ForeignClientMap clients,
                  std::chrono::seconds interval = std::chrono::seconds{30});
    ~ChainWatcher();

    // Spawn the polling thread. No-op if already started.
    void Start();
    // Stop the polling thread. No-op if not started. Blocks until
    // the thread joins.
    void Stop();

    // Drive a single tick synchronously — for tests. Iterates all
    // pending entries once and applies any state-machine
    // transitions whose threshold is reached. Safe to call while
    // Start() has not been called.
    void TickOnce();

    // Diagnostic snapshot: how many transitions did this watcher
    // apply since construction?
    int64_t TransitionsApplied() const { return m_transitions_applied.load(); }

private:
    void Loop();
    void Tick();
    // Try to advance one entry. Returns true if the entry was
    // consumed (transition applied or definitively rejected — in
    // both cases the entry should be removed from the pending set).
    bool HandleEntry(const WatchEntry& e);

    // Per-chain error backoff. When a backend query fails (returns
    // nullopt — indicating "unreachable", as opposed to "tx not
    // found"), record the time and skip queries for that chain
    // until the cooldown elapses. Without this a flaky relay
    // would be hammered every Tick.
    bool IsChainCoolingDown(const std::string& chain_name) const;
    void RecordChainError(const std::string& chain_name);

    // PRIC-leg confirmation lookup via the embedded chainstate.
    // Returns the same shape as IForeignChainClient::TxStatus.
    std::optional<ForeignTxStatus> PricTxStatus(const std::string& txid_hex);

    // Auto-refund sweep — runs each Tick after the standard
    // entry-handling loop. For active swaps where the local wallet's
    // role can unilaterally refund (currently: Bob with LTC HTLC at
    // CLTV expiry; PRIC presigned-refund TODO), broadcast the refund
    // automatically. Gated on `-pricoinautorefund=1` and requires a
    // configured `-pricoinltcrefundaddr=<bech32>`. In-memory dedup
    // via `m_refund_attempted` so a flaky LTC backend doesn't
    // re-broadcast every tick after a successful submission.
    void TryAutoRefundLtc();
    void TryAutoRefundPric();
    std::set<uint256> m_refund_attempted;
    std::set<uint256> m_pric_refund_attempted;

    ::wallet::CWallet& m_wallet;
    ForeignClientMap m_clients;
    std::chrono::seconds m_interval;
    std::thread m_thread;
    std::atomic<bool> m_stopping{false};
    std::atomic<int64_t> m_transitions_applied{0};

    // Backoff state. Mutex-protected because Tick() may run on the
    // poll thread while TickOnce() is called from the main thread
    // in tests.
    mutable std::mutex m_backoff_mu;
    std::map<std::string, std::chrono::steady_clock::time_point>
        m_chain_error_at;
    static constexpr std::chrono::seconds kBackoffCooldown{60};
};

// ─── Per-wallet polling manager ─────────────────────────────────
//
// Singleton-per-wallet ChainWatcher manager. Tier-3 RPCs (start /
// stop / status / tick_once) operate against this manager. The
// chain backends are auto-discovered from the
// `pricoin::swap::ChainBackend` registry on Start; if no backends
// are registered the watcher still runs but transitions only fire
// for PRIC-leg kinds (which read the embedded chainstate directly).

// Start the polling watcher for `wallet`. Idempotent — calling
// Start twice has no effect. Auto-discovers backends from the
// registry; the watcher periodically re-binds them per tick so
// hot-reloading the backend registry is honoured.
void StartManaged(::wallet::CWallet& wallet,
                   std::chrono::seconds interval = std::chrono::seconds{30});
// Stop the polling watcher for `wallet`. No-op if not running.
void StopManaged(::wallet::CWallet& wallet);
// True iff a polling thread is currently running for `wallet`.
bool IsManagedRunning(::wallet::CWallet& wallet);
// Drive a single tick synchronously for `wallet` — for tests.
// Works regardless of whether StartManaged has been called.
void TickOnceManaged(::wallet::CWallet& wallet);
// Stop all managed watchers. Called from process Shutdown to
// terminate threads cleanly before joining.
void StopAllManaged();

} // namespace wallet::pricoin_chain_watcher

#endif // BITCOIN_WALLET_PRICOIN_CHAIN_WATCHER_H
