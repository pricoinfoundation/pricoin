// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pricoin_swap_ceremony.h>

#include <crypto/sha256.h>
#include <random.h>
#include <streams.h>
#include <sync.h>
#include <util/time.h>
#include <wallet/pricoin_stealth.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <map>
#include <memory>
#include <sstream>

namespace wallet::pricoin_swap_ceremony {

namespace {

struct WalletCache {
    std::map<uint256, SwapCeremony> by_id;
    bool loaded{false};
};

Mutex g_mutex;
std::map<CWallet*, std::unique_ptr<WalletCache>> g_caches GUARDED_BY(g_mutex);

WalletCache& EnsureCache(CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    auto it = g_caches.find(&wallet);
    if (it == g_caches.end()) {
        it = g_caches.emplace(&wallet, std::make_unique<WalletCache>()).first;
    }
    return *it->second;
}

bool RequireUnlocked(CWallet& wallet)
{
    return !(wallet.HasEncryptionKeys() && wallet.IsLocked());
}

bool LoadFromDBLocked(CWallet& wallet, WalletCache& cache)
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex);

bool EnsureLoadedLocked(CWallet& wallet, WalletCache& cache)
    EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    if (cache.loaded) return true;
    if (!LoadFromDBLocked(wallet, cache)) return false;
    cache.loaded = true;
    return true;
}

bool WriteCeremonyToDB(CWallet& wallet, const SwapCeremony& s)
{
    DataStream ds;
    ds << s;
    std::vector<unsigned char> blob(
        UCharCast(ds.data()), UCharCast(ds.data()) + ds.size());

    std::vector<unsigned char> enc;
    if (!::wallet::pricoin_stealth::EncryptWalletBlob(wallet, blob, enc)) {
        return false;
    }
    WalletBatch batch(wallet.GetDatabase());
    return batch.WritePricoinSwapCeremony(s.ceremony_id, enc);
}

bool LoadFromDBLocked(CWallet& wallet, WalletCache& cache)
{
    std::map<uint256, std::vector<unsigned char>> blobs;
    {
        WalletBatch batch(wallet.GetDatabase());
        if (!batch.ReadAllPricoinSwapCeremonies(blobs)) return false;
    }
    for (auto& [cid, blob] : blobs) {
        std::vector<unsigned char> plain;
        if (!::wallet::pricoin_stealth::DecryptWalletBlob(wallet, blob, plain)) {
            return false;
        }
        DataStream ds{std::span<const unsigned char>{plain}};
        SwapCeremony s;
        try {
            ds >> s;
        } catch (const std::exception&) {
            return false;
        }
        if (s.ceremony_id != cid) return false;
        cache.by_id[cid] = std::move(s);
    }
    return true;
}

bool ValidateForeignLeg(const ForeignLeg& f)
{
    if (f.chain.empty()) return false;
    if (f.htlc_address.empty()) return false;
    if (f.redeem_script.empty()) return false;
    if (f.amount_sat <= 0) return false;
    if (f.timeout < 0) return false;
    return true;
}

bool ValidatePricLeg(const PricLeg& p)
{
    if (p.joint_stealth_address.empty()) return false;
    if (p.amount_sat <= 0) return false;
    return true;
}

void TouchTimestamp(SwapCeremony& s)
{
    s.updated_time = static_cast<int64_t>(GetTime<std::chrono::seconds>().count());
}

} // namespace

CreateResult Create(
    CWallet& wallet,
    Role role,
    const CPubKey& counterparty_pub,
    const ForeignLeg& foreign,
    const PricLeg& pric,
    std::span<const unsigned char> preimage_override,
    const std::string& memo,
    SwapCeremony& out)
{
    if (!counterparty_pub.IsValid() || !counterparty_pub.IsCompressed()) {
        return CreateResult::InvalidCounterpartyPubkey;
    }
    if (!ValidateForeignLeg(foreign)) return CreateResult::InvalidForeignLeg;
    if (!ValidatePricLeg(pric))       return CreateResult::InvalidPricLeg;
    if (!RequireUnlocked(wallet))     return CreateResult::Locked;

    SwapCeremony s;
    // Fresh ceremony id.
    for (int i = 0; i < 8; ++i) {
        GetRandBytes(s.ceremony_id);
        if (!s.ceremony_id.IsNull()) break;
    }
    if (s.ceremony_id.IsNull()) return CreateResult::WriteFailed;

    s.role = role;
    s.state = State::Init;
    s.counterparty_pub = counterparty_pub;
    s.foreign = foreign;
    s.pric = pric;
    s.memo = memo;

    // Preimage handling — only BuyingForeign holds a real preimage
    // up front. SellingForeign learns it later from on-chain claim.
    if (role == Role::BuyingForeign) {
        if (preimage_override.size() == 32) {
            s.preimage.assign(preimage_override.begin(), preimage_override.end());
        } else if (preimage_override.empty()) {
            s.preimage.resize(32);
            GetRandBytes(s.preimage);
        } else {
            return CreateResult::InvalidPreimage;
        }
        // Hash = SHA-256(preimage).
        s.preimage_hash.resize(32);
        CSHA256 h;
        h.Write(s.preimage.data(), s.preimage.size());
        h.Finalize(s.preimage_hash.data());
    } else {
        // SellingForeign expects to receive the preimage_hash from
        // the counterparty out-of-band. Caller supplies via
        // preimage_override (which we re-purpose to mean "the hash").
        if (preimage_override.size() != 32) {
            return CreateResult::InvalidPreimage;
        }
        s.preimage_hash.assign(preimage_override.begin(), preimage_override.end());
    }

    const auto now = GetTime<std::chrono::seconds>().count();
    s.created_time = static_cast<int64_t>(now);
    s.updated_time = s.created_time;

    {
        LOCK(g_mutex);
        auto& cache = EnsureCache(wallet);
        if (!EnsureLoadedLocked(wallet, cache)) return CreateResult::WriteFailed;
        if (!WriteCeremonyToDB(wallet, s))      return CreateResult::WriteFailed;
        cache.by_id[s.ceremony_id] = s;
    }
    out = std::move(s);
    return CreateResult::Ok;
}

namespace {

TransitionResult MutateAndPersist(
    CWallet& wallet,
    const uint256& ceremony_id,
    State expected_from,
    State to_state,
    std::function<bool(SwapCeremony&)> mutator)
{
    if (!RequireUnlocked(wallet)) return TransitionResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return TransitionResult::WriteFailed;

    auto it = cache.by_id.find(ceremony_id);
    if (it == cache.by_id.end()) return TransitionResult::NotFound;
    if (it->second.state != expected_from) return TransitionResult::InvalidState;

    // Snapshot to roll back on persistence failure.
    SwapCeremony backup = it->second;
    if (!mutator(it->second)) {
        it->second = std::move(backup);
        return TransitionResult::InvalidInput;
    }
    it->second.state = to_state;
    TouchTimestamp(it->second);
    if (!WriteCeremonyToDB(wallet, it->second)) {
        it->second = std::move(backup);
        return TransitionResult::WriteFailed;
    }
    return TransitionResult::Ok;
}

} // namespace

TransitionResult SetForeignFunded(
    CWallet& wallet, const uint256& ceremony_id,
    const std::string& funding_txid, int32_t funding_vout)
{
    return MutateAndPersist(wallet, ceremony_id,
        State::Init, State::BtcFunded,
        [&](SwapCeremony& s) {
            if (funding_txid.size() != 64 || funding_vout < 0) return false;
            s.foreign_funding_txid = funding_txid;
            s.foreign_funding_vout = funding_vout;
            return true;
        });
}

TransitionResult SetPricFunded(
    CWallet& wallet, const uint256& ceremony_id,
    const uint256& pric_txid, int32_t pric_vout,
    std::span<const unsigned char> our_x_share)
{
    return MutateAndPersist(wallet, ceremony_id,
        State::BtcFunded, State::PricFunded,
        [&](SwapCeremony& s) {
            if (pric_txid.IsNull() || pric_vout < 0) return false;
            if (our_x_share.size() != 32)            return false;
            s.pric_funding_txid = pric_txid;
            s.pric_funding_vout = pric_vout;
            s.pric.our_x_share.assign(our_x_share.begin(), our_x_share.end());
            return true;
        });
}

TransitionResult SetForeignClaimed(
    CWallet& wallet, const uint256& ceremony_id,
    const std::string& claim_txid,
    std::span<const unsigned char> preimage)
{
    return MutateAndPersist(wallet, ceremony_id,
        State::PricFunded, State::BtcClaimed,
        [&](SwapCeremony& s) {
            if (claim_txid.size() != 64) return false;
            s.foreign_claim_txid = claim_txid;
            // Validate the preimage (if supplied) against the
            // recorded hash. This is the moment SellingForeign
            // learns the preimage and we want to be sure it matches.
            if (!preimage.empty()) {
                if (preimage.size() != 32) return false;
                std::array<unsigned char, 32> h;
                CSHA256 hash;
                hash.Write(preimage.data(), preimage.size());
                hash.Finalize(h.data());
                if (s.preimage_hash.size() != 32 ||
                    !std::equal(h.begin(), h.end(), s.preimage_hash.begin())) {
                    return false;
                }
                s.preimage.assign(preimage.begin(), preimage.end());
            }
            return true;
        });
}

TransitionResult SetPricReleased(
    CWallet& wallet, const uint256& ceremony_id,
    const uint256& release_txid)
{
    return MutateAndPersist(wallet, ceremony_id,
        State::BtcClaimed, State::Complete,
        [&](SwapCeremony& s) {
            if (release_txid.IsNull()) return false;
            s.pric_release_txid = release_txid;
            return true;
        });
}

TransitionResult Abort(
    CWallet& wallet, const uint256& ceremony_id,
    const std::string& reason)
{
    if (!RequireUnlocked(wallet)) return TransitionResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return TransitionResult::WriteFailed;

    auto it = cache.by_id.find(ceremony_id);
    if (it == cache.by_id.end()) return TransitionResult::NotFound;
    if (it->second.state == State::Complete || it->second.state == State::Aborted) {
        return TransitionResult::InvalidState;
    }
    SwapCeremony backup = it->second;
    it->second.state = State::Aborted;
    it->second.abort_reason = reason;
    TouchTimestamp(it->second);
    if (!WriteCeremonyToDB(wallet, it->second)) {
        it->second = std::move(backup);
        return TransitionResult::WriteFailed;
    }
    return TransitionResult::Ok;
}

LookupResult Get(CWallet& wallet, const uint256& ceremony_id, SwapCeremony& out)
{
    if (!RequireUnlocked(wallet)) return LookupResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return LookupResult::NotFound;
    auto it = cache.by_id.find(ceremony_id);
    if (it == cache.by_id.end()) return LookupResult::NotFound;
    out = it->second;
    return LookupResult::Ok;
}

LookupResult List(CWallet& wallet, std::vector<SwapCeremony>& out)
{
    if (!RequireUnlocked(wallet)) return LookupResult::Locked;
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (!EnsureLoadedLocked(wallet, cache)) return LookupResult::NotFound;
    out.clear();
    out.reserve(cache.by_id.size());
    for (const auto& [_, s] : cache.by_id) out.push_back(s);
    return LookupResult::Ok;
}

std::string NextActionHint(const SwapCeremony& s)
{
    std::ostringstream os;
    const bool buying = (s.role == Role::BuyingForeign);
    switch (s.state) {
        case State::Init:
            if (buying) {
                // We send PRIC, receive foreign coin. Counterparty
                // funds the foreign HTLC first. We wait.
                os << "Wait for the counterparty to fund the foreign-chain "
                   << "HTLC at " << s.foreign.htlc_address
                   << " (" << s.foreign.amount_sat << " sat). "
                   << "Use pricoin_chainwatch_address_txs to confirm; "
                   << "then call pricoin_swap_ceremony_set_foreign_funded.";
            } else {
                os << "Fund the foreign-chain HTLC at " << s.foreign.htlc_address
                   << " with " << s.foreign.amount_sat << " sat from your "
                   << s.foreign.chain << " wallet, broadcast it, and call "
                   << "pricoin_swap_ceremony_set_foreign_funded.";
            }
            break;
        case State::BtcFunded:
            if (buying) {
                os << "Foreign HTLC funded. Now lock PRIC into the joint stealth "
                   << "address " << s.pric.joint_stealth_address
                   << " via walletsendct, then run pricoin_jointspend_loadshare "
                   << "and call pricoin_swap_ceremony_set_pric_funded.";
            } else {
                os << "Foreign HTLC funded. Wait for the counterparty to lock PRIC "
                   << "into " << s.pric.joint_stealth_address
                   << "; once they do, run pricoin_jointspend_loadshare and call "
                   << "pricoin_swap_ceremony_set_pric_funded.";
            }
            break;
        case State::PricFunded:
            if (buying) {
                os << "PRIC locked. Build + broadcast a foreign-chain claim "
                   << "(pricoin_btc_htlc_build_claim with your preimage), "
                   << "then call pricoin_swap_ceremony_set_foreign_claimed. "
                   << "WARNING: until you reach BtcClaimed, do not cooperatively "
                   << "release PRIC — the counterparty has nothing to lose.";
            } else {
                os << "PRIC locked. Wait for the counterparty to claim the foreign "
                   << "HTLC (which reveals the preimage on chain). Watch via "
                   << "pricoin_chainwatch_get_tx; once seen, extract the preimage "
                   << "from the witness and call pricoin_swap_ceremony_set_foreign_claimed.";
            }
            break;
        case State::BtcClaimed:
            if (buying) {
                os << "Foreign claimed. Cooperate with the counterparty to release "
                   << "the PRIC joint output to them — drive the cooperative-CLSAG "
                   << "round protocol (pricoin_jointspend_round1/combine/share/"
                   << "assemble), then call pricoin_swap_ceremony_set_pric_released.";
            } else {
                os << "Preimage revealed on foreign chain. You now have the secret "
                   << "needed (in the adaptor-CLSAG variant — for now, you simply "
                   << "cooperate with the counterparty to release the PRIC joint "
                   << "output to yourself). Drive cooperative-CLSAG and call "
                   << "pricoin_swap_ceremony_set_pric_released when broadcast.";
            }
            break;
        case State::PricReleased:
            os << "PRIC released. Verify the spend tx mined and call "
               << "pricoin_swap_ceremony_set_complete (handled implicitly by "
               << "set_pric_released).";
            break;
        case State::Complete:
            os << "Swap complete.";
            break;
        case State::Aborted:
            os << "Swap aborted: " << s.abort_reason
               << ". If applicable, refund the foreign-chain HTLC after the "
               << "timeout (pricoin_btc_htlc_build_refund) and/or cooperatively "
               << "refund the PRIC joint output.";
            break;
    }
    return os.str();
}

bool LoadFromDB(CWallet& wallet)
{
    if (!RequireUnlocked(wallet)) return true;  // lazy-load on first use
    LOCK(g_mutex);
    auto& cache = EnsureCache(wallet);
    if (cache.loaded) return true;
    if (!LoadFromDBLocked(wallet, cache)) return false;
    cache.loaded = true;
    return true;
}

void Shutdown()
{
    LOCK(g_mutex);
    g_caches.clear();
}

} // namespace wallet::pricoin_swap_ceremony
