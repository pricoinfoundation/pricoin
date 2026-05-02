// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pricoin_chain_watcher.h>

#include <crypto/sha256.h>
#include <interfaces/chain.h>
#include <logging.h>
#include <random.h>
#include <tinyformat.h>
#include <util/log.h>
#include <streams.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <wallet/pricoin_adaptor_swap.h>
#include <wallet/pricoin_stealth.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <map>
#include <utility>

namespace wallet::pricoin_chain_watcher {

const char* WatchKindName(WatchKind k)
{
    switch (k) {
    case WatchKind::ForeignFunding: return "foreign_funding";
    case WatchKind::PricFunding:    return "pric_funding";
    case WatchKind::PricClaim:      return "pric_claim";
    case WatchKind::ForeignClaim:   return "foreign_claim";
    case WatchKind::PricRefund:     return "pric_refund";
    case WatchKind::ForeignRefund:  return "foreign_refund";
    }
    return "unknown";
}

std::optional<WatchKind> ParseWatchKind(const std::string& s)
{
    if (s == "foreign_funding") return WatchKind::ForeignFunding;
    if (s == "pric_funding")    return WatchKind::PricFunding;
    if (s == "pric_claim")      return WatchKind::PricClaim;
    if (s == "foreign_claim")   return WatchKind::ForeignClaim;
    if (s == "pric_refund")     return WatchKind::PricRefund;
    if (s == "foreign_refund")  return WatchKind::ForeignRefund;
    return std::nullopt;
}

const char* StoreResultName(StoreResult r)
{
    switch (r) {
    case StoreResult::Ok:           return "ok";
    case StoreResult::InvalidInput: return "invalid_input";
    case StoreResult::Locked:       return "locked";
    case StoreResult::WriteFailed:  return "write_failed";
    case StoreResult::Duplicate:    return "duplicate";
    case StoreResult::NotFound:     return "not_found";
    }
    return "unknown";
}

// ─── In-memory cache ────────────────────────────────────────────

namespace {

struct Cache {
    bool loaded{false};
    std::map<uint256, WatchEntry> by_digest;  // SHA256(swap_id || kind_byte)
};

Mutex g_mutex;
std::map<::wallet::CWallet*, Cache> g_caches GUARDED_BY(g_mutex);

Cache& EnsureCacheLocked(::wallet::CWallet& w) EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    return g_caches[&w];
}

uint256 RecordDigest(const uint256& swap_id, WatchKind kind)
{
    CSHA256 h;
    static constexpr char kTag[] = "pricoin/chainwatch/key-v1";
    h.Write(reinterpret_cast<const unsigned char*>(kTag), sizeof(kTag) - 1);
    h.Write(swap_id.data(), 32);
    const uint8_t kb = static_cast<uint8_t>(kind);
    h.Write(&kb, 1);
    uint256 out;
    h.Finalize(out.data());
    return out;
}

bool RequireUnlocked(::wallet::CWallet& w)
{
    return !(w.HasEncryptionKeys() && w.IsLocked());
}

bool WriteEntryToDB(::wallet::CWallet& wallet, const WatchEntry& e)
{
    DataStream ds;
    ds << e;
    std::vector<unsigned char> blob(
        UCharCast(ds.data()), UCharCast(ds.data()) + ds.size());
    std::vector<unsigned char> enc;
    if (!::wallet::pricoin_stealth::EncryptWalletBlob(wallet, blob, enc)) return false;
    WalletBatch batch(wallet.GetDatabase());
    return batch.WritePricoinChainWatch(RecordDigest(e.swap_id, e.kind), enc);
}

bool EraseEntryInDB(::wallet::CWallet& wallet,
                     const uint256& swap_id, WatchKind kind)
{
    WalletBatch batch(wallet.GetDatabase());
    return batch.ErasePricoinChainWatch(RecordDigest(swap_id, kind));
}

bool LoadFromDBLocked(::wallet::CWallet& wallet, Cache& cache)
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    std::map<uint256, std::vector<unsigned char>> blobs;
    {
        WalletBatch batch(wallet.GetDatabase());
        if (!batch.ReadAllPricoinChainWatches(blobs)) return false;
    }
    for (auto& [digest, blob] : blobs) {
        std::vector<unsigned char> plain;
        if (!::wallet::pricoin_stealth::DecryptWalletBlob(wallet, blob, plain)) return false;
        DataStream ds{std::span<const unsigned char>{plain}};
        WatchEntry e;
        try {
            ds >> e;
        } catch (const std::exception&) {
            return false;
        }
        if (RecordDigest(e.swap_id, e.kind) != digest) return false;
        cache.by_digest[digest] = std::move(e);
    }
    return true;
}

bool EnsureLoadedLocked(::wallet::CWallet& wallet, Cache& cache)
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    if (cache.loaded) return true;
    if (!LoadFromDBLocked(wallet, cache)) return false;
    cache.loaded = true;
    return true;
}

bool ValidEntry(const WatchEntry& e)
{
    if (e.swap_id.IsNull()) return false;
    if (e.txid_hex.size() != 64) return false;
    if (!IsHex(e.txid_hex)) return false;
    if (e.min_confirmations < 0) return false;
    if ((e.kind == WatchKind::ForeignFunding ||
         e.kind == WatchKind::PricFunding) && e.vout < 0) return false;
    return true;
}

} // namespace

// ─── Persistence API ────────────────────────────────────────────

StoreResult Add(::wallet::CWallet& wallet, const WatchEntry& e_in)
{
    if (!ValidEntry(e_in)) return StoreResult::InvalidInput;
    if (!RequireUnlocked(wallet)) return StoreResult::Locked;

    WatchEntry e = e_in;
    if (e.added_unix == 0) {
        e.added_unix = GetTime<std::chrono::seconds>().count();
    }

    LOCK(g_mutex);
    auto& cache = EnsureCacheLocked(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return StoreResult::WriteFailed;
    if (!WriteEntryToDB(wallet, e)) return StoreResult::WriteFailed;
    cache.by_digest[RecordDigest(e.swap_id, e.kind)] = e;
    return StoreResult::Ok;
}

StoreResult Remove(::wallet::CWallet& wallet,
                    const uint256& swap_id, WatchKind kind)
{
    if (!RequireUnlocked(wallet)) return StoreResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCacheLocked(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return StoreResult::WriteFailed;
    const uint256 digest = RecordDigest(swap_id, kind);
    auto it = cache.by_digest.find(digest);
    if (it == cache.by_digest.end()) return StoreResult::NotFound;
    if (!EraseEntryInDB(wallet, swap_id, kind)) return StoreResult::WriteFailed;
    cache.by_digest.erase(it);
    return StoreResult::Ok;
}

StoreResult Get(::wallet::CWallet& wallet,
                 const uint256& swap_id, WatchKind kind, WatchEntry& out)
{
    LOCK(g_mutex);
    auto& cache = EnsureCacheLocked(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return StoreResult::WriteFailed;
    auto it = cache.by_digest.find(RecordDigest(swap_id, kind));
    if (it == cache.by_digest.end()) return StoreResult::NotFound;
    out = it->second;
    return StoreResult::Ok;
}

StoreResult List(::wallet::CWallet& wallet, std::vector<WatchEntry>& out)
{
    LOCK(g_mutex);
    auto& cache = EnsureCacheLocked(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return StoreResult::WriteFailed;
    out.reserve(cache.by_digest.size());
    for (auto& [_, e] : cache.by_digest) out.push_back(e);
    return StoreResult::Ok;
}

bool LoadFromDB(::wallet::CWallet& wallet)
{
    LOCK(g_mutex);
    auto& cache = EnsureCacheLocked(wallet);
    return EnsureLoadedLocked(wallet, cache);
}

void Shutdown()
{
    // Stop polling threads first so they don't touch the cache
    // mid-clear.
    StopAllManaged();
    LOCK(g_mutex);
    g_caches.clear();
}

// ─── Foreign-client factory hook ─────────────────────────────────
//
// The daemon installs an implementation in init.cpp that wraps
// `pricoin::swap::GetBackend(chain_name)` in a ChainBackendForeignClient.
// The bitcoin-wallet utility doesn't link the swap module so the
// factory stays unset and MakeForeignClientFromRegistry returns
// nullptr — fine for the wallet utility (it never polls foreign chains).

namespace {
Mutex g_factory_mutex;
ForeignClientFactory g_factory GUARDED_BY(g_factory_mutex);
} // namespace

void SetForeignClientFactory(ForeignClientFactory factory)
{
    LOCK(g_factory_mutex);
    g_factory = std::move(factory);
}

std::shared_ptr<IForeignChainClient> MakeForeignClientFromRegistry(
    const std::string& chain_name)
{
    ForeignClientFactory f;
    {
        LOCK(g_factory_mutex);
        f = g_factory;
    }
    if (!f) return nullptr;
    return f(chain_name);
}

// ─── MockForeignChainClient ─────────────────────────────────────

std::optional<int> MockForeignChainClient::TipHeight()
{
    std::lock_guard<std::mutex> lk(m_mu);
    return m_tip_height;
}

std::optional<ForeignTxStatus>
MockForeignChainClient::TxStatus(const std::string& txid_hex)
{
    std::lock_guard<std::mutex> lk(m_mu);
    auto it = m_tx_status.find(txid_hex);
    if (it == m_tx_status.end()) {
        // Unknown to the mock — treat as "reachable but tx not seen"
        // (relay returns "found=false") so the watcher can keep
        // polling without giving up. To simulate unreachable, return
        // nullopt — tests can do that explicitly via SetTipHeight(nullopt)
        // or by calling ClearTxStatus + a fresh (unmocked) txid.
        ForeignTxStatus s;
        s.found = false;
        return s;
    }
    return it->second;
}

void MockForeignChainClient::SetTipHeight(std::optional<int> h)
{
    std::lock_guard<std::mutex> lk(m_mu);
    m_tip_height = h;
}

void MockForeignChainClient::SetTxStatus(const std::string& txid_hex, ForeignTxStatus s)
{
    std::lock_guard<std::mutex> lk(m_mu);
    m_tx_status[txid_hex] = s;
}

void MockForeignChainClient::ClearTxStatus(const std::string& txid_hex)
{
    std::lock_guard<std::mutex> lk(m_mu);
    m_tx_status.erase(txid_hex);
}

std::string MockForeignChainClient::Broadcast(const std::string& tx_hex)
{
    std::lock_guard<std::mutex> lk(m_mu);
    m_last_broadcast = tx_hex;
    if (m_broadcast_response_txid.empty()) {
        throw std::runtime_error("MockForeignChainClient: no broadcast response configured");
    }
    return m_broadcast_response_txid;
}

void MockForeignChainClient::SetBroadcastResponse(const std::string& txid)
{
    std::lock_guard<std::mutex> lk(m_mu);
    m_broadcast_response_txid = txid;
}

std::string MockForeignChainClient::LastBroadcast() const
{
    std::lock_guard<std::mutex> lk(m_mu);
    return m_last_broadcast;
}

// ─── ChainWatcher service ───────────────────────────────────────

ChainWatcher::ChainWatcher(::wallet::CWallet& wallet,
                            ForeignClientMap clients,
                            std::chrono::seconds interval)
    : m_wallet(wallet),
      m_clients(std::move(clients)),
      m_interval(interval)
{
}

ChainWatcher::~ChainWatcher()
{
    Stop();
}

void ChainWatcher::Start()
{
    if (m_thread.joinable()) return;
    m_stopping = false;
    m_thread = std::thread([this]() { Loop(); });
}

void ChainWatcher::Stop()
{
    if (!m_thread.joinable()) return;
    m_stopping = true;
    m_thread.join();
}

void ChainWatcher::Loop()
{
    // Coarse polling — sleep in 200ms steps so Stop() responds
    // quickly without sleeping the whole interval.
    auto next_tick = std::chrono::steady_clock::now();
    while (!m_stopping.load()) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= next_tick) {
            try {
                Tick();
            } catch (const std::exception& e) {
                LogInfo("ChainWatcher Tick threw: %s\n", e.what());
            }
            next_tick = now + m_interval;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{200});
    }
}

void ChainWatcher::TickOnce()
{
    Tick();
}

void ChainWatcher::Tick()
{
    std::vector<WatchEntry> entries;
    if (List(m_wallet, entries) != StoreResult::Ok) return;

    for (const auto& e : entries) {
        if (m_stopping.load()) return;
        if (HandleEntry(e)) {
            // Entry consumed — remove from pending set.
            (void)Remove(m_wallet, e.swap_id, e.kind);
            ++m_transitions_applied;
        }
    }
}

// PRIC-leg confirmation lookup via interfaces::Chain. Equivalent
// to "getrawtransaction <txid> 1" + (tip - in_active_chain) for
// the confirmation count. Implemented via Chain::findCommonAncestor
// + Chain::findFirstBlockWithTimeAndHeight is overkill; instead
// we use Chain::hasBlocks + Chain::findBlock to locate the block
// containing the tx. For the pricoin scope, the simpler path is
// to read the wallet's known transaction map (CWallet::GetWalletTx)
// — but this only works for txs the wallet knows about. For txs
// it doesn't, we'd need an indexer.
//
// Toy/regtest scope: the watcher polls txs the wallet itself
// broadcasts (PRIC claim/refund) so they're in mapWallet. For the
// foreign leg, we go through IForeignChainClient. PRIC lookups
// for txs the wallet didn't broadcast aren't supported in this
// chunk; the user has to use chainwatch_notify directly.
std::optional<ForeignTxStatus> ChainWatcher::PricTxStatus(const std::string& txid_hex)
{
    auto txid = uint256::FromHex(txid_hex);
    if (!txid) return std::nullopt;
    LOCK(m_wallet.cs_wallet);
    auto it = m_wallet.mapWallet.find(Txid::FromUint256(*txid));
    if (it == m_wallet.mapWallet.end()) {
        ForeignTxStatus s;
        s.found = false;
        return s;
    }
    const ::wallet::CWalletTx& wtx = it->second;
    ForeignTxStatus s;
    s.found = true;
    // GetDepthInMainChain returns 0 for unconfirmed, ≥1 for confirmed.
    s.confirmations = m_wallet.GetTxDepthInMainChain(wtx);
    if (s.confirmations > 0) {
        // Best-effort block height — interfaces::Chain has it but
        // wtx itself doesn't expose it cleanly. The watcher's
        // SetX calls accept height; passing the wallet's chain tip
        // minus depth as a reasonable approximation.
        const std::optional<int> tip = m_wallet.chain().getHeight();
        if (tip) s.block_height = *tip - s.confirmations + 1;
    }
    return s;
}

bool ChainWatcher::HandleEntry(const WatchEntry& e)
{
    using namespace ::wallet::pricoin_adaptor_swap;
    using TR = TransitionResult;

    // Decide which client to query based on kind.
    std::optional<ForeignTxStatus> st;
    const bool is_foreign =
        (e.kind == WatchKind::ForeignFunding ||
         e.kind == WatchKind::ForeignClaim ||
         e.kind == WatchKind::ForeignRefund);
    if (is_foreign) {
        // Look up the swap to find which foreign chain we're on.
        AdaptorSwap s;
        if (Get(m_wallet, e.swap_id, s) != LookupResult::Ok) {
            // Swap gone (aborted/refunded externally) — drop entry.
            return true;
        }
        // Resolve client: prefer the explicitly-injected map (for
        // tests that wire in mocks), fall back to the registry-
        // backed adapter (the production path that uses the
        // configured Esplora backends).
        std::shared_ptr<IForeignChainClient> client;
        auto it = m_clients.find(s.foreign_chain);
        if (it != m_clients.end()) {
            client = it->second;
        } else {
            client = MakeForeignClientFromRegistry(s.foreign_chain);
        }
        if (!client) {
            // No client for this chain — leave entry pending so a
            // future Start() with a configured client can pick it up.
            return false;
        }
        st = client->TxStatus(e.txid_hex);
    } else {
        st = PricTxStatus(e.txid_hex);
    }
    if (!st) return false;        // unreachable; retry next tick
    if (!st->found) return false; // not yet relayed; retry next tick
    if (st->confirmations < e.min_confirmations) return false;

    // Threshold reached — apply the matching state-machine transition.
    TR r = TR::InvalidInput;
    switch (e.kind) {
    case WatchKind::ForeignFunding:
        r = SetBtcFunded(m_wallet, e.swap_id, e.txid_hex, e.vout, st->block_height);
        break;
    case WatchKind::PricFunding: {
        auto txid = uint256::FromHex(e.txid_hex);
        if (!txid) { r = TR::InvalidInput; break; }
        r = SetPricFunded(m_wallet, e.swap_id, *txid, e.vout, st->block_height);
        break;
    }
    case WatchKind::PricClaim: {
        auto txid = uint256::FromHex(e.txid_hex);
        if (!txid) { r = TR::InvalidInput; break; }
        r = SetPricClaimed(m_wallet, e.swap_id, *txid);
        break;
    }
    case WatchKind::ForeignClaim:
        r = SetComplete(m_wallet, e.swap_id, e.txid_hex);
        break;
    case WatchKind::PricRefund: {
        auto txid = uint256::FromHex(e.txid_hex);
        if (!txid) { r = TR::InvalidInput; break; }
        r = SetRefunded(m_wallet, e.swap_id, *txid, /*foreign=*/std::string{});
        break;
    }
    case WatchKind::ForeignRefund:
        r = SetRefunded(m_wallet, e.swap_id, /*pric=*/uint256{}, e.txid_hex);
        break;
    }

    if (r != TR::Ok) {
        // The state machine rejected the transition (wrong state,
        // already-set field, etc.). Drop the entry so we don't
        // hammer it forever; the user can re-add manually if this
        // was a transient race.
        LogInfo("ChainWatcher: %s for swap %s rejected by SetX (%d) — dropping\n",
                  WatchKindName(e.kind),
                  e.swap_id.ToString().substr(0, 12).c_str(),
                  static_cast<int>(r));
    }
    return true;  // entry consumed either way
}

// ─── Per-wallet polling manager ─────────────────────────────────

namespace {

// Process-level registry of running ChainWatcher instances, one per
// wallet. Mutex-protected; entries inserted on StartManaged, erased
// on StopManaged / StopAllManaged / Shutdown. Each ChainWatcher
// owns its polling thread; we hold a unique_ptr.
Mutex g_managed_mutex;
std::map<::wallet::CWallet*, std::unique_ptr<ChainWatcher>> g_managed
    GUARDED_BY(g_managed_mutex);

} // namespace

void StartManaged(::wallet::CWallet& wallet, std::chrono::seconds interval)
{
    LOCK(g_managed_mutex);
    auto& slot = g_managed[&wallet];
    if (slot) return;  // already running
    // Empty client map → registry fallback drives the lookups
    // (production path); tests can register backends directly via
    // pricoin::swap::RegisterBackend before calling StartManaged.
    slot = std::make_unique<ChainWatcher>(wallet, ForeignClientMap{}, interval);
    slot->Start();
}

void StopManaged(::wallet::CWallet& wallet)
{
    std::unique_ptr<ChainWatcher> watcher;
    {
        LOCK(g_managed_mutex);
        auto it = g_managed.find(&wallet);
        if (it == g_managed.end()) return;
        watcher = std::move(it->second);
        g_managed.erase(it);
    }
    // Destructor joins the thread; do this outside the mutex so a
    // tick currently running doesn't deadlock on g_managed_mutex.
    watcher.reset();
}

bool IsManagedRunning(::wallet::CWallet& wallet)
{
    LOCK(g_managed_mutex);
    auto it = g_managed.find(&wallet);
    return it != g_managed.end() && it->second != nullptr;
}

void TickOnceManaged(::wallet::CWallet& wallet)
{
    // If a managed watcher exists, drive its TickOnce. Otherwise
    // construct a transient watcher and tick it once. Tests that
    // exercise the autonomous path without StartManaged use this
    // entry point for deterministic, thread-free ticking.
    {
        LOCK(g_managed_mutex);
        auto it = g_managed.find(&wallet);
        if (it != g_managed.end() && it->second) {
            it->second->TickOnce();
            return;
        }
    }
    ChainWatcher transient(wallet, ForeignClientMap{}, std::chrono::seconds{0});
    transient.TickOnce();
}

void StopAllManaged()
{
    std::map<::wallet::CWallet*, std::unique_ptr<ChainWatcher>> taken;
    {
        LOCK(g_managed_mutex);
        std::swap(taken, g_managed);
    }
    // Joining threads — outside the mutex.
    taken.clear();
}

} // namespace wallet::pricoin_chain_watcher
