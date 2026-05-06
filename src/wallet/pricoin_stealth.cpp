// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pricoin_stealth.h>

#include <btcsignals.h>
#include <crypto/common.h>
#include <crypto/hmac_sha256.h>
#include <key.h>
#include <logging.h>
#include <pricoin/stealth.h>
#include <random.h>
#include <support/cleanse.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/fs.h>
#include <wallet/crypter.h>
#include <wallet/db.h>
#include <wallet/pricoin_ct_send.h>
#include <wallet/wallet.h>

#include <array>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <span>
#include <stdexcept>
#include <vector>

namespace wallet::pricoin_stealth {

namespace {

// Form in which the wallet persists the stealth identity.
//   Seed:    32-byte master from which view+spend are derived
//            (current path; one secret to back up).
//   KeyBlob: 64-byte (view||spend) blob (legacy v0.1.11 wallets — kept on
//            read so users don't lose access on upgrade; new wallets do
//            not write this form).
enum class PersistKind { Seed, KeyBlob };

struct CacheEntry {
    Identity id;
    // True once we've persisted this identity in the format that matches
    // the wallet's current encryption state. False means the keys exist
    // in memory only (e.g. they were generated while the wallet was
    // encrypted+locked, so we couldn't safely write them yet) — retry
    // the save on the next GetOrCreate call.
    bool saved_in_target_format{false};
    // Which DB record we own. Drives the retry-save path.
    PersistKind persist_kind{PersistKind::Seed};
    // For seed-based entries, the raw seed bytes are kept so a deferred
    // save (after the wallet unlocks) can re-encrypt and re-write. Empty
    // / unused for KeyBlob entries.
    std::array<unsigned char, 32> seed{};
    // RAII handle into wallet.NotifyUnload that erases this entry from the
    // cache when its CWallet is unloaded. Without it, the raw CWallet*
    // key in `g_identities` would dangle, and a future wallet allocated at
    // the same address would silently inherit this identity.
    btcsignals::scoped_connection unload_conn{btcsignals::connection{}};
};

Mutex g_mutex;
std::map<const CWallet*, CacheEntry> g_identities GUARDED_BY(g_mutex);

// Side-file alongside the wallet's primary DB file. Format:
//   [version:1] [...]
//     0x00: 64 bytes plaintext (view_priv || spend_priv).
//     0x01: legacy encrypted, no MAC: 32-byte IV || ciphertext. Read-only;
//           any save upgrades to 0x02. Kept so existing on-disk wallets
//           continue to load.
//     0x02: encrypted with HMAC: 32-byte IV || ciphertext || 32-byte
//           HMAC-SHA256(mk, "pricoin/stealth/mac-v1" || ver || IV ||
//           ciphertext). Without the MAC, a single flipped bit in the
//           ciphertext silently corrupts the keys (AES-CBC is malleable
//           and the wallet would then derive a *different* stealth address,
//           making already-received payments unrecoverable).
// Legacy unversioned files (pre-encryption) are exactly 64 bytes; on load
// we detect that and upgrade to versioned-plaintext (or to the encrypted
// format if the wallet is currently encrypted) on the next save.
constexpr unsigned char kVersionPlain = 0x00;
constexpr unsigned char kVersionEncryptedNoMac = 0x01;  // legacy read-only
constexpr unsigned char kVersionEncrypted = 0x02;
constexpr size_t kKeyBlobSize = 64;       // view (32) + spend (32)
constexpr size_t kSeedSize = 32;          // master seed for HD derivation
constexpr size_t kIVSize = 32;
constexpr size_t kMacSize = 32;
constexpr const char* kMacTag = "pricoin/stealth/mac-v1";
constexpr const char* kViewTag = "pricoin/stealth/view-v1";
constexpr const char* kSpendTag = "pricoin/stealth/spend-v1";

// Constant-time byte compare. Used for MAC verification: lookup-table or
// short-circuit memcmp leaks information about *where* the MAC differs,
// which an attacker with file-write access could exploit to fish for a
// valid MAC byte-by-byte.
bool ConstantTimeEqual(const unsigned char* a, const unsigned char* b, size_t n)
{
    unsigned char diff = 0;
    for (size_t i = 0; i < n; ++i) diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    return diff == 0;
}

void ComputeStealthFileMac(const CKeyingMaterial& mk,
                           unsigned char ver,
                           std::span<const unsigned char> iv,
                           std::span<const unsigned char> ciphertext,
                           unsigned char out[kMacSize])
{
    CHMAC_SHA256 hmac(mk.data(), mk.size());
    hmac.Write(reinterpret_cast<const unsigned char*>(kMacTag),
               std::strlen(kMacTag));
    hmac.Write(&ver, 1);
    hmac.Write(iv.data(), iv.size());
    hmac.Write(ciphertext.data(), ciphertext.size());
    hmac.Finalize(out);
}

fs::path StealthFilePath(CWallet& wallet)
{
    fs::path db_path = fs::PathFromString(wallet.GetDatabase().Filename());
    fs::path dir = db_path.has_parent_path() ? db_path.parent_path() : fs::path{};
    return dir / "pricoin_stealth.dat";
}

// Sets the two privkeys + derived public_address into `out`. `plain` holds
// 32 view + 32 spend bytes; cleansed by the caller after this returns.
bool MaterializeIdentity(const std::array<unsigned char, kKeyBlobSize>& plain, Identity& out)
{
    out.view.Set(plain.begin(), plain.begin() + 32, /*fCompressedIn=*/true);
    out.spend.Set(plain.begin() + 32, plain.begin() + 64, /*fCompressedIn=*/true);
    if (!out.view.IsValid() || !out.spend.IsValid()) return false;
    out.public_address.view = out.view.GetPubKey();
    out.public_address.spend = out.spend.GetPubKey();
    return true;
}

// Derive view+spend from a 32-byte seed via tagged SHA-256:
//   k = SHA256(tag || seed || ctr) until k is a valid secp256k1 scalar.
// The counter loop covers the ~2^-128 invalid-scalar case; in practice the
// first hash always succeeds. Tags are domain-separated so view ≠ spend
// for the same seed and so this scheme can't collide with future KDFs
// over the same secret.
Identity DeriveIdentityFromSeed(std::span<const unsigned char> seed)
{
    auto derive_key = [&seed](const char* tag, CKey& out) {
        for (uint16_t ctr = 0; ctr <= 0xff; ++ctr) {
            CSHA256 h;
            h.Write(reinterpret_cast<const unsigned char*>(tag), std::strlen(tag));
            h.Write(seed.data(), seed.size());
            const unsigned char ctr_byte = static_cast<unsigned char>(ctr);
            h.Write(&ctr_byte, 1);
            std::array<unsigned char, 32> bytes{};
            h.Finalize(bytes.data());
            out.Set(bytes.begin(), bytes.end(), /*fCompressedIn=*/true);
            memory_cleanse(bytes.data(), bytes.size());
            if (out.IsValid()) return;
        }
        throw std::runtime_error("stealth seed derivation: rehash counter exhausted");
    };
    Identity id;
    derive_key(kViewTag, id.view);
    derive_key(kSpendTag, id.spend);
    if (!id.view.IsValid() || !id.spend.IsValid()) {
        throw std::runtime_error("stealth seed derivation produced invalid keys");
    }
    id.public_address.view = id.view.GetPubKey();
    id.public_address.spend = id.spend.GetPubKey();
    return id;
}

// Decode a versioned secret blob into raw plaintext bytes. Caller owns
// validating the resulting size against the secret type it expected (32
// for a seed, 64 for a key-blob). Throws std::runtime_error if the blob
// is encrypted and the wallet is currently locked. Sets `needs_upgrade`
// when the on-disk format is older than what we'd write today.
//
// `accept_no_mac` controls whether the legacy v0.1.x kVersionEncryptedNoMac
// (0x01, AES-CBC without HMAC) format is honoured. DB-record callers
// must set this to false: those records were never written in the
// no-MAC format, so seeing 0x01 in a DB record is necessarily a
// downgrade-attack attempt against a v0.2 ciphertext (strip MAC, flip
// version byte → AES-CBC malleability lets an attacker silently swap
// the wallet's identity). Side-file callers may set true for
// migration of pre-HMAC wallets, but log a deprecation warning.
//
// Note: `buf.size() == kKeyBlobSize` (a raw 64-byte buffer with no
// version byte) is intentionally NOT supported here — that legacy form
// only ever existed in the side file. The caller handles that case
// before calling DecodeBlob.
bool DecodeBlob(CWallet& wallet,
                std::span<const unsigned char> buf,
                std::vector<unsigned char>& plain,
                bool& needs_upgrade,
                bool accept_no_mac = false)
{
    needs_upgrade = false;
    plain.clear();
    if (buf.empty()) return false;

    if (buf[0] == kVersionPlain) {
        if (buf.size() < 2) return false;
        plain.assign(buf.begin() + 1, buf.end());
        if (wallet.HasEncryptionKeys() && !wallet.IsLocked()) {
            needs_upgrade = true;
        }
        return true;
    }

    if (buf[0] == kVersionEncryptedNoMac && !accept_no_mac) {
        // Refuse: a v0.1.x no-MAC record showing up where we only ever
        // write v0.2 (DB records) means someone's writing to that file.
        // Even if the original ciphertext was authentic, AES-CBC alone
        // is malleable; without the MAC we'd silently decrypt to
        // attacker-controlled garbage and adopt wrong keys.
        return false;
    }
    if (buf[0] != kVersionEncryptedNoMac && buf[0] != kVersionEncrypted) {
        return false;
    }
    const bool has_mac = (buf[0] == kVersionEncrypted);
    const size_t min_size = has_mac
        ? (1 + kIVSize + 1 + kMacSize)
        : (1 + kIVSize + 1);
    if (buf.size() < min_size) return false;
    if (wallet.IsLocked()) {
        throw std::runtime_error(
            "Pricoin stealth keys are encrypted; unlock the wallet "
            "(`walletpassphrase`) before scanning or sending confidential transactions");
    }
    uint256 iv;
    std::memcpy(iv.begin(), buf.data() + 1, kIVSize);
    const size_t ct_end = buf.size() - (has_mac ? kMacSize : 0);
    std::vector<unsigned char> ciphertext(buf.begin() + 1 + kIVSize,
                                          buf.begin() + ct_end);
    CKeyingMaterial decrypted;
    bool ok = false;
    wallet.WithEncryptionKey([&](const CKeyingMaterial& mk) {
        if (mk.empty()) return false;
        if (has_mac) {
            unsigned char expected[kMacSize];
            ComputeStealthFileMac(mk, buf[0],
                                  std::span<const unsigned char>{iv.begin(), kIVSize},
                                  ciphertext, expected);
            const unsigned char* on_disk = buf.data() + ct_end;
            if (!ConstantTimeEqual(expected, on_disk, kMacSize)) {
                return false;
            }
        }
        if (!DecryptSecret(mk, ciphertext, iv, decrypted)) return false;
        ok = !decrypted.empty();
        return ok;
    });
    if (!ok) return false;
    plain.assign(decrypted.begin(), decrypted.end());
    memory_cleanse(decrypted.data(), decrypted.size());
    if (!has_mac) needs_upgrade = true;
    return true;
}

// Encode a plaintext secret of arbitrary size into a versioned blob.
// Returns false if the wallet is encrypted-but-locked.
bool EncodeBlob(CWallet& wallet,
                std::span<const unsigned char> plain,
                std::vector<unsigned char>& blob)
{
    if (plain.empty()) return false;

    if (wallet.HasEncryptionKeys() && wallet.IsLocked()) {
        return false;
    }

    if (wallet.HasEncryptionKeys() && !wallet.IsLocked()) {
        uint256 iv;
        GetRandBytes(iv);
        CKeyingMaterial pt(plain.begin(), plain.end());
        std::vector<unsigned char> ciphertext;
        unsigned char mac[kMacSize]{};
        const unsigned char ver = kVersionEncrypted;
        bool ok = false;
        wallet.WithEncryptionKey([&](const CKeyingMaterial& mk) {
            if (mk.empty()) return false;
            if (!EncryptSecret(mk, pt, iv, ciphertext)) return false;
            ComputeStealthFileMac(mk, ver,
                                  std::span<const unsigned char>{iv.begin(), kIVSize},
                                  ciphertext, mac);
            ok = true;
            return ok;
        });
        memory_cleanse(pt.data(), pt.size());
        if (!ok) return false;
        blob.clear();
        blob.reserve(1 + kIVSize + ciphertext.size() + kMacSize);
        blob.push_back(ver);
        blob.insert(blob.end(), iv.begin(), iv.begin() + kIVSize);
        blob.insert(blob.end(), ciphertext.begin(), ciphertext.end());
        blob.insert(blob.end(), mac, mac + kMacSize);
        return true;
    }

    // Unencrypted wallet: store plaintext alongside the wallet's other
    // plaintext secrets.
    blob.clear();
    blob.reserve(1 + plain.size());
    blob.push_back(kVersionPlain);
    blob.insert(blob.end(), plain.begin(), plain.end());
    return true;
}

bool ReadKeyBlobFromDB(CWallet& wallet, std::vector<unsigned char>& blob)
{
    WalletBatch batch(wallet.GetDatabase());
    return batch.ReadPricoinStealth(blob);
}

bool WriteKeyBlobToDB(CWallet& wallet, const std::vector<unsigned char>& blob)
{
    WalletBatch batch(wallet.GetDatabase());
    return batch.WritePricoinStealth(blob);
}

bool ReadSeedFromDB(CWallet& wallet, std::vector<unsigned char>& blob)
{
    WalletBatch batch(wallet.GetDatabase());
    return batch.ReadPricoinStealthSeed(blob);
}

bool WriteSeedToDB(CWallet& wallet, const std::vector<unsigned char>& blob)
{
    WalletBatch batch(wallet.GetDatabase());
    return batch.WritePricoinStealthSeed(blob);
}

// Legacy: read the raw side-file blob. Used only for one-time migration
// into the wallet DB so existing wallets keep their identity after upgrade.
bool ReadBlobFromLegacyFile(CWallet& wallet, std::vector<unsigned char>& blob)
{
    const std::string path_str = fs::PathToString(StealthFilePath(wallet));
    std::ifstream f(path_str, std::ios::binary);
    if (!f) return false;
    blob.assign(std::istreambuf_iterator<char>(f),
                std::istreambuf_iterator<char>());
    return !blob.empty();
}

// Try to read & decode the seed record. On success, `seed_out` holds the
// 32 raw bytes and `out` is the derived identity. May throw on locked.
bool LoadFromSeedRecord(CWallet& wallet,
                        Identity& out,
                        std::array<unsigned char, kSeedSize>& seed_out,
                        bool& needs_upgrade)
{
    needs_upgrade = false;
    std::vector<unsigned char> blob;
    if (!ReadSeedFromDB(wallet, blob)) return false;
    std::vector<unsigned char> plain;
    if (!DecodeBlob(wallet, blob, plain, needs_upgrade)) return false;
    if (plain.size() != kSeedSize) {
        memory_cleanse(plain.data(), plain.size());
        return false;
    }
    std::memcpy(seed_out.data(), plain.data(), kSeedSize);
    memory_cleanse(plain.data(), plain.size());
    out = DeriveIdentityFromSeed(seed_out);
    return true;
}

// Try to read & decode the legacy v0.1.11 key-blob record.
bool LoadFromKeyBlobRecord(CWallet& wallet, Identity& out, bool& needs_upgrade)
{
    needs_upgrade = false;
    std::vector<unsigned char> blob;
    if (!ReadKeyBlobFromDB(wallet, blob)) return false;
    std::vector<unsigned char> plain;
    if (!DecodeBlob(wallet, blob, plain, needs_upgrade)) return false;
    if (plain.size() != kKeyBlobSize) {
        memory_cleanse(plain.data(), plain.size());
        return false;
    }
    std::array<unsigned char, kKeyBlobSize> arr{};
    std::memcpy(arr.data(), plain.data(), kKeyBlobSize);
    memory_cleanse(plain.data(), plain.size());
    bool ok = MaterializeIdentity(arr, out);
    memory_cleanse(arr.data(), arr.size());
    return ok;
}

// Try to read & decode the legacy side-file (pre-v0.1.11). Handles the
// even-older 64-byte unversioned form too. Returns false if the file
// is absent. Throws if the file is present but doesn't decode — silently
// regenerating fresh keys over a corrupt-but-present legacy file would
// brick recovery of every payment received under the original identity
// (same hazard the seed/key-blob DB records guard against).
bool LoadFromLegacyFile(CWallet& wallet, Identity& out)
{
    std::vector<unsigned char> blob;
    if (!ReadBlobFromLegacyFile(wallet, blob)) return false;  // not present

    bool decoded = false;
    if (blob.size() == kKeyBlobSize) {
        // Pre-versioning: raw 64 bytes (view||spend), no header.
        std::array<unsigned char, kKeyBlobSize> arr{};
        std::memcpy(arr.data(), blob.data(), kKeyBlobSize);
        decoded = MaterializeIdentity(arr, out);
        memory_cleanse(arr.data(), arr.size());
    } else {
        bool unused_upgrade = false;
        std::vector<unsigned char> plain;
        // accept_no_mac=true: side files predate the HMAC-on-stealth
        // change. Migration of an authentic v0.1.x ciphertext into the
        // v0.2 DB format is the legitimate use case here. The
        // downgrade-attack threat (MEDIUM-2) doesn't apply to side
        // files: an attacker rewriting the side file *as 0x01* gains
        // nothing they couldn't already do by overwriting the file
        // outright (no DB record exists yet to downgrade).
        if (DecodeBlob(wallet, blob, plain, unused_upgrade, /*accept_no_mac=*/true) &&
            plain.size() == kKeyBlobSize) {
            std::array<unsigned char, kKeyBlobSize> arr{};
            std::memcpy(arr.data(), plain.data(), kKeyBlobSize);
            memory_cleanse(plain.data(), plain.size());
            decoded = MaterializeIdentity(arr, out);
            memory_cleanse(arr.data(), arr.size());
        } else {
            memory_cleanse(plain.data(), plain.size());
        }
    }

    if (!decoded) {
        throw std::runtime_error(strprintf(
            "Pricoin legacy stealth file %s exists but failed to decode "
            "(corrupt blob, unrecognised version, or wrong size). Refusing "
            "to silently regenerate — that would discard every CT payment "
            "ever received under the original identity. Inspect or remove "
            "the file manually if it is genuinely garbage.",
            fs::PathToString(StealthFilePath(wallet))));
    }
    return true;
}

bool SaveSeed(CWallet& wallet, std::span<const unsigned char> seed)
{
    if (seed.size() != kSeedSize) return false;
    std::vector<unsigned char> blob;
    if (!EncodeBlob(wallet, seed, blob)) return false;
    return WriteSeedToDB(wallet, blob);
}

// Save a legacy v0.1.11 key blob (only used when migrating a legacy
// side file or refreshing the on-disk format of an existing key-blob
// wallet — never when we're starting from scratch).
bool SaveKeyBlob(CWallet& wallet, const Identity& id)
{
    std::array<unsigned char, kKeyBlobSize> plain{};
    std::memcpy(plain.data(),      id.view.data(),  32);
    std::memcpy(plain.data() + 32, id.spend.data(), 32);
    std::vector<unsigned char> blob;
    bool ok = EncodeBlob(wallet, plain, blob);
    memory_cleanse(plain.data(), plain.size());
    if (!ok) return false;
    return WriteKeyBlobToDB(wallet, blob);
}

} // namespace

const Identity& GetOrCreate(CWallet& wallet)
{
    LOCK(g_mutex);
    auto it = g_identities.find(&wallet);
    if (it != g_identities.end()) {
        // Cached. If we couldn't persist last time (wallet was locked),
        // try again now — by the time the user calls into us a second
        // time, walletpassphrase has typically been called.
        if (!it->second.saved_in_target_format) {
            bool ok = false;
            if (it->second.persist_kind == PersistKind::Seed) {
                ok = SaveSeed(wallet, it->second.seed);
            } else {
                ok = SaveKeyBlob(wallet, it->second.id);
            }
            if (ok) {
                it->second.saved_in_target_format = true;
                LogInfo("Pricoin: persisted previously-in-memory stealth identity for wallet %s",
                        wallet.GetName());
            }
        }
        return it->second.id;
    }

    Identity id;
    PersistKind kind = PersistKind::Seed;
    std::array<unsigned char, kSeedSize> seed{};
    bool loaded = false;
    bool needs_resave = false;
    const char* origin = nullptr;

    // For both record types: if the row is present but the load fails,
    // surface the decode failure instead of silently regenerating.
    // Generating fresh keys over a corrupt-but-present record would
    // permanently brick recovery of every payment received under the
    // original identity.
    auto guard_corrupt = [](const char* which) {
        throw std::runtime_error(strprintf(
            "Pricoin stealth %s record in wallet.dat failed to decode "
            "(wallet locked, wrong passphrase, or corrupt entry)",
            which));
    };

    // 1. Seed record (current home for new wallets).
    {
        bool seed_resave = false;
        if (LoadFromSeedRecord(wallet, id, seed, seed_resave)) {
            loaded = true;
            kind = PersistKind::Seed;
            needs_resave = seed_resave;
            origin = "wallet.dat (seed)";
        } else {
            std::vector<unsigned char> probe;
            if (ReadSeedFromDB(wallet, probe) && !probe.empty()) {
                guard_corrupt("seed");
            }
        }
    }

    // 2. Legacy v0.1.11 key-blob record. Don't migrate to seed — we
    //    can't reverse-derive a seed from random keys. Keep using the
    //    key blob to preserve the user's existing identity.
    if (!loaded) {
        bool kb_resave = false;
        if (LoadFromKeyBlobRecord(wallet, id, kb_resave)) {
            loaded = true;
            kind = PersistKind::KeyBlob;
            needs_resave = kb_resave;
            origin = "wallet.dat (legacy key blob)";
        } else {
            std::vector<unsigned char> probe;
            if (ReadKeyBlobFromDB(wallet, probe) && !probe.empty()) {
                guard_corrupt("key-blob");
            }
        }
    }

    // 3. Legacy side file (pre-v0.1.11). Migrate into a key-blob DB
    //    record so future backups carry the identity. We don't migrate
    //    to seed for the same reason as case 2.
    if (!loaded && LoadFromLegacyFile(wallet, id)) {
        loaded = true;
        kind = PersistKind::KeyBlob;
        needs_resave = true;
        origin = "legacy pricoin_stealth.dat (migrating to wallet.dat key blob)";
    }

    // 4. Nothing on disk — generate a fresh seed-based identity.
    if (!loaded) {
        GetRandBytes(seed);
        id = DeriveIdentityFromSeed(seed);
        kind = PersistKind::Seed;
        needs_resave = true;
        origin = "generated (seed-derived)";
    }

    bool saved = false;
    if (needs_resave) {
        if (kind == PersistKind::Seed) {
            saved = SaveSeed(wallet, seed);
        } else {
            saved = SaveKeyBlob(wallet, id);
        }
        if (saved) {
            LogInfo("Pricoin: stealth identity for wallet %s — %s, persisted to wallet.dat",
                    wallet.GetName(), origin);
        } else if (!loaded) {
            LogWarning("Pricoin: stealth identity not yet persisted (wallet locked); will retry on next access");
        } else {
            LogWarning("Pricoin: loaded stealth identity for wallet %s from %s but couldn't re-save (wallet locked)",
                       wallet.GetName(), origin);
        }
    } else {
        saved = true;
        LogInfo("Pricoin: loaded stealth identity for wallet %s from %s",
                wallet.GetName(), origin);
    }

    CacheEntry entry;
    entry.id = std::move(id);
    entry.saved_in_target_format = saved;
    entry.persist_kind = kind;
    if (kind == PersistKind::Seed) entry.seed = seed;
    auto [inserted, _] = g_identities.emplace(&wallet, std::move(entry));
    // Drop our cache entry the moment the wallet is unloaded, so a future
    // wallet that happens to be allocated at the same heap address can't
    // inherit this identity. NotifyUnload fires from RemoveWallet() before
    // ~CWallet, so the pointer is still valid when the slot runs.
    CWallet* wallet_ptr = &wallet;
    inserted->second.unload_conn = wallet.NotifyUnload.connect([wallet_ptr]() {
        LOCK(g_mutex);
        auto cached = g_identities.find(wallet_ptr);
        if (cached != g_identities.end()) {
            memory_cleanse(cached->second.seed.data(), cached->second.seed.size());
        }
        g_identities.erase(wallet_ptr);
    });
    // The local `seed` was copied into `entry.seed` above (or unused for
    // KeyBlob entries). Cleanse the stack copy so it doesn't linger in
    // the caller's frame.
    memory_cleanse(seed.data(), seed.size());
    return inserted->second.id;
}

std::optional<std::array<unsigned char, 32>> GetSeedIfAvailable(CWallet& wallet)
{
    // Prime the cache (load or generate). After this, g_identities has
    // the entry — possibly seed-backed, possibly key-blob (legacy).
    GetOrCreate(wallet);
    LOCK(g_mutex);
    auto it = g_identities.find(&wallet);
    if (it == g_identities.end()) return std::nullopt;
    if (it->second.persist_kind != PersistKind::Seed) return std::nullopt;
    return it->second.seed;
}

SetSeedResult SetSeed(CWallet& wallet,
                      std::span<const unsigned char> seed,
                      bool confirm_overwrite)
{
    if (seed.size() != kSeedSize) return SetSeedResult::InvalidSeed;

    // Validate the seed derives well-formed keys before we write anything.
    // Throws on cryptographic failure; the rare invalid-scalar path
    // already loops with a counter, so this should never fire.
    try {
        Identity probe = DeriveIdentityFromSeed(seed);
        if (!probe.view.IsValid() || !probe.spend.IsValid()) {
            return SetSeedResult::InvalidSeed;
        }
    } catch (...) {
        return SetSeedResult::InvalidSeed;
    }

    // Lock order: g_recovery_index_mutex (outer) -> g_mutex (inner).
    // Matches the reader path (SyncRecoveryIndexLocked → GetOrCreate),
    // so concurrent readers can't deadlock against this writer. The
    // recovery cache is dropped iff the inner stealth-state update
    // succeeds — atomic w.r.t. readers, so a balance query in flight
    // at rotation time always sees one consistent identity, never
    // new-id paired with old-id cache entries.
    SetSeedResult result = SetSeedResult::WriteFailed;
    RunWithCTRecoveryCacheCleared(wallet, [&]() -> bool {
        LOCK(g_mutex);
        if (wallet.HasEncryptionKeys() && wallet.IsLocked()) {
            result = SetSeedResult::Locked;
            return false;
        }

        // Refuse to clobber an existing identity unless the caller has
        // explicitly opted in. We check both the in-memory cache and the
        // on-disk records, since the cache might be stale relative to
        // disk (e.g., the user just imported via createfromdump).
        if (!confirm_overwrite) {
            auto it = g_identities.find(&wallet);
            if (it != g_identities.end()) {
                result = SetSeedResult::AlreadyHasIdentity;
                return false;
            }
            std::vector<unsigned char> probe;
            if (ReadSeedFromDB(wallet, probe) && !probe.empty()) {
                result = SetSeedResult::AlreadyHasIdentity;
                return false;
            }
            if (ReadKeyBlobFromDB(wallet, probe) && !probe.empty()) {
                result = SetSeedResult::AlreadyHasIdentity;
                return false;
            }
        }

        // Write the new seed and erase the legacy key-blob record (if
        // any), so future loads come from a single source of truth.
        if (!SaveSeed(wallet, seed)) {
            result = SetSeedResult::WriteFailed;
            return false;
        }
        {
            WalletBatch batch(wallet.GetDatabase());
            batch.ErasePricoinStealth();
        }
        auto it = g_identities.find(&wallet);
        if (it != g_identities.end()) {
            memory_cleanse(it->second.seed.data(), it->second.seed.size());
            g_identities.erase(it);
        }
        result = SetSeedResult::Ok;
        // Returning true tells the wrapper to also drop the wallet's
        // recovery cache before releasing g_recovery_index_mutex —
        // that cache holds entries whose key_image / value were
        // derived under the OLD identity. Leaving them would inflate
        // the new identity's balance and surface stale spend
        // candidates.
        return true;
    });
    return result;
}

bool EncryptWalletBlob(CWallet& wallet,
                       std::span<const unsigned char> plain,
                       std::vector<unsigned char>& blob_out)
{
    return EncodeBlob(wallet, plain, blob_out);
}

bool DecryptWalletBlob(CWallet& wallet,
                       std::span<const unsigned char> blob,
                       std::vector<unsigned char>& plain_out)
{
    bool unused_upgrade = false;
    // accept_no_mac defaults to false — DB-record callers don't accept
    // v1 legacy ciphertexts. Throws on locked-encrypted; returns false
    // on corruption / wrong-key / unrecognised format.
    return DecodeBlob(wallet, blob, plain_out, unused_upgrade);
}

void Shutdown()
{
    LOCK(g_mutex);
    g_identities.clear();
}

SubaddressLookup BuildSubaddressLookup(CWallet& wallet)
{
    SubaddressLookup out;
    const auto& id = GetOrCreate(wallet);  // primes cache, may throw on locked

    // Master entry — the existing behaviour. Index 0 is reserved for
    // "the master identity" so callers can branch on (index == 0) to
    // skip subaddress derivation.
    ::pricoin::stealth::PointBytes master_B{};
    std::memcpy(master_B.data(), id.public_address.spend.data(), 33);
    out.by_b_point[master_B] = SubaddressLookupEntry{
        .index = 0,
        .spend_priv = id.spend,
    };

    // Hydrate persisted subaddress indices from the wallet DB plus a
    // gap-limit window of unused indices. The gap window lets the scanner
    // recognise payments past the current ceiling (BIP-44 pattern); if a
    // hit lands in the gap, the wallet bumps max_used_index via
    // NoteSubaddressDiscovered after the block walk.
    const auto state = LoadSubaddressState(wallet);
    const uint64_t high =
        static_cast<uint64_t>(state.max_used_index) + kSubaddressGapLimit;
    const uint32_t cap = (high > std::numeric_limits<uint32_t>::max())
                            ? std::numeric_limits<uint32_t>::max()
                            : static_cast<uint32_t>(high);
    for (uint32_t i = 1; i <= cap; ++i) {
        auto sub = ::pricoin::stealth::DeriveSubaddress(id.view, id.spend, i);
        if (!sub) continue;  // cosmically rare scalar-invalid case; skip
        ::pricoin::stealth::PointBytes B_i{};
        std::memcpy(B_i.data(), sub->public_address.spend.data(), 33);
        out.by_b_point[B_i] = SubaddressLookupEntry{
            .index = i,
            .spend_priv = sub->spend_priv,
        };
    }
    return out;
}

namespace {

// Subaddress state blob format (versioned, encrypted-at-rest via
// EncryptWalletBlob). Singleton record under DBKeys::PRICOIN_SUBADDRESS_STATE.
//   [ver:1=0x01][max_used_index:u32 LE]
constexpr unsigned char kSubaddrStateVer = 0x01;

// Per-label record: [ver:1=0x01][label_utf8:varbytes].
constexpr unsigned char kSubaddrLabelVer = 0x01;

struct StateCacheEntry {
    SubaddressState state;
    bool unload_wired{false};
    btcsignals::scoped_connection unload_conn{btcsignals::connection{}};
};
Mutex g_subaddr_state_mutex;
std::map<const CWallet*, StateCacheEntry> g_subaddr_state GUARDED_BY(g_subaddr_state_mutex);

void U32LE(uint32_t v, unsigned char out[4])
{
    out[0] = v & 0xff; out[1] = (v >> 8) & 0xff;
    out[2] = (v >> 16) & 0xff; out[3] = (v >> 24) & 0xff;
}
uint32_t U32LERead(const unsigned char in[4])
{
    return uint32_t(in[0])
         | (uint32_t(in[1]) << 8)
         | (uint32_t(in[2]) << 16)
         | (uint32_t(in[3]) << 24);
}

bool DecodeStateBlob(const std::vector<unsigned char>& plain, SubaddressState& out)
{
    if (plain.size() != 5) return false;
    if (plain[0] != kSubaddrStateVer) return false;
    out.max_used_index = U32LERead(plain.data() + 1);
    return true;
}

std::vector<unsigned char> EncodeStateBlob(const SubaddressState& s)
{
    std::vector<unsigned char> v(5);
    v[0] = kSubaddrStateVer;
    U32LE(s.max_used_index, v.data() + 1);
    return v;
}

bool DecodeLabelBlob(const std::vector<unsigned char>& plain, std::string& label_out)
{
    if (plain.empty()) return false;
    if (plain[0] != kSubaddrLabelVer) return false;
    label_out.assign(reinterpret_cast<const char*>(plain.data() + 1),
                     plain.size() - 1);
    return true;
}

std::vector<unsigned char> EncodeLabelBlob(const std::string& label)
{
    std::vector<unsigned char> v;
    v.reserve(1 + label.size());
    v.push_back(kSubaddrLabelVer);
    v.insert(v.end(), label.begin(), label.end());
    return v;
}

// Load directly from the wallet DB (skipping the cache). Throws if
// the wallet is encrypted+locked — labels are kept under at-rest
// encryption, and we can't decode them otherwise.
SubaddressState LoadFromDb(CWallet& wallet)
{
    SubaddressState out;
    WalletBatch batch{wallet.GetDatabase()};

    std::vector<unsigned char> blob;
    if (batch.ReadPricoinSubaddressState(blob)) {
        std::vector<unsigned char> plain;
        if (DecryptWalletBlob(wallet, blob, plain)) {
            DecodeStateBlob(plain, out);
        }
    }

    std::map<uint32_t, std::vector<unsigned char>> labels;
    if (batch.ReadAllPricoinSubaddressLabels(labels)) {
        for (auto& [idx, lblob] : labels) {
            std::vector<unsigned char> plain;
            std::string label;
            if (DecryptWalletBlob(wallet, lblob, plain) &&
                DecodeLabelBlob(plain, label)) {
                out.labels[idx] = std::move(label);
                if (idx > out.max_used_index) {
                    // Restore-mode: a label record exists past the
                    // recorded ceiling. Defensive consistency — bump
                    // max_used_index so subsequent scans/RPCs see it.
                    out.max_used_index = idx;
                }
            }
        }
    }
    return out;
}

// Cached version. Returns a snapshot so the caller can iterate without
// holding the mutex.
SubaddressState LoadStateCached(CWallet& wallet)
{
    {
        LOCK(g_subaddr_state_mutex);
        auto it = g_subaddr_state.find(&wallet);
        if (it != g_subaddr_state.end()) return it->second.state;
    }

    SubaddressState fresh = LoadFromDb(wallet);

    LOCK(g_subaddr_state_mutex);
    auto& entry = g_subaddr_state[&wallet];
    entry.state = fresh;
    if (!entry.unload_wired) {
        CWallet* wallet_ptr = &wallet;
        entry.unload_conn = wallet.NotifyUnload.connect([wallet_ptr]() {
            LOCK(g_subaddr_state_mutex);
            g_subaddr_state.erase(wallet_ptr);
        });
        entry.unload_wired = true;
    }
    return entry.state;
}

void OverwriteStateCache(CWallet& wallet, const SubaddressState& s)
{
    LOCK(g_subaddr_state_mutex);
    auto& entry = g_subaddr_state[&wallet];
    entry.state = s;
    if (!entry.unload_wired) {
        CWallet* wallet_ptr = &wallet;
        entry.unload_conn = wallet.NotifyUnload.connect([wallet_ptr]() {
            LOCK(g_subaddr_state_mutex);
            g_subaddr_state.erase(wallet_ptr);
        });
        entry.unload_wired = true;
    }
}

} // namespace

SubaddressState LoadSubaddressState(CWallet& wallet)
{
    return LoadStateCached(wallet);
}

::pricoin::stealth::Subaddress AllocateNextSubaddress(
    CWallet& wallet, const std::string& label)
{
    // Need the spend scalar to derive b_i — fail fast if locked.
    const auto& id = GetOrCreate(wallet);
    SubaddressState st = LoadStateCached(wallet);
    const uint32_t new_index = st.max_used_index + 1;
    if (new_index == 0) {  // overflow; 4 billion subaddresses is a hard ceiling
        throw std::runtime_error("subaddress index overflow");
    }
    auto sub = ::pricoin::stealth::DeriveSubaddress(id.view, id.spend, new_index);
    if (!sub) throw std::runtime_error("subaddress derivation failed");

    WalletBatch batch{wallet.GetDatabase()};
    SubaddressState updated = st;
    updated.max_used_index = new_index;

    std::vector<unsigned char> state_plain = EncodeStateBlob(updated);
    std::vector<unsigned char> state_blob;
    if (!EncryptWalletBlob(wallet, state_plain, state_blob) ||
        !batch.WritePricoinSubaddressState(state_blob)) {
        throw std::runtime_error("failed to persist subaddress state");
    }

    if (!label.empty()) {
        std::vector<unsigned char> label_plain = EncodeLabelBlob(label);
        std::vector<unsigned char> label_blob;
        if (!EncryptWalletBlob(wallet, label_plain, label_blob) ||
            !batch.WritePricoinSubaddressLabel(new_index, label_blob)) {
            throw std::runtime_error("failed to persist subaddress label");
        }
        updated.labels[new_index] = label;
    }

    OverwriteStateCache(wallet, updated);
    return *sub;
}

bool SetSubaddressLabel(CWallet& wallet, uint32_t index, const std::string& label)
{
    if (index == 0) return false;
    SubaddressState st = LoadStateCached(wallet);
    if (index > st.max_used_index) return false;

    WalletBatch batch{wallet.GetDatabase()};
    if (label.empty()) {
        // Treat empty as erase to keep the API simple.
        batch.ErasePricoinSubaddressLabel(index);
        st.labels.erase(index);
    } else {
        std::vector<unsigned char> plain = EncodeLabelBlob(label);
        std::vector<unsigned char> blob;
        if (!EncryptWalletBlob(wallet, plain, blob)) return false;
        if (!batch.WritePricoinSubaddressLabel(index, blob)) return false;
        st.labels[index] = label;
    }
    OverwriteStateCache(wallet, st);
    return true;
}

bool EraseSubaddressLabel(CWallet& wallet, uint32_t index)
{
    return SetSubaddressLabel(wallet, index, "");
}

void NoteSubaddressDiscovered(CWallet& wallet, uint32_t discovered)
{
    SubaddressState st = LoadStateCached(wallet);
    if (discovered <= st.max_used_index) return;  // idempotent
    st.max_used_index = discovered;

    WalletBatch batch{wallet.GetDatabase()};
    std::vector<unsigned char> plain = EncodeStateBlob(st);
    std::vector<unsigned char> blob;
    if (EncryptWalletBlob(wallet, plain, blob)) {
        batch.WritePricoinSubaddressState(blob);
    }
    OverwriteStateCache(wallet, st);
}

} // namespace wallet::pricoin_stealth
