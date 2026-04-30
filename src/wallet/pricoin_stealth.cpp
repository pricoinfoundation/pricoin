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
#include <uint256.h>
#include <util/fs.h>
#include <wallet/crypter.h>
#include <wallet/db.h>
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

struct CacheEntry {
    Identity id;
    // True once we've persisted this identity in the format that matches
    // the wallet's current encryption state. False means the keys exist
    // in memory only (e.g. they were generated while the wallet was
    // encrypted+locked, so we couldn't safely write them yet) — retry
    // the save on the next GetOrCreate call.
    bool saved_in_target_format{false};
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
constexpr size_t kPlaintextSize = 64;
constexpr size_t kIVSize = 32;
constexpr size_t kMacSize = 32;
constexpr const char* kMacTag = "pricoin/stealth/mac-v1";

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

CKey FreshKey()
{
    CKey k;
    k.MakeNewKey(/*fCompressed=*/true);
    return k;
}

fs::path StealthFilePath(CWallet& wallet)
{
    fs::path db_path = fs::PathFromString(wallet.GetDatabase().Filename());
    fs::path dir = db_path.has_parent_path() ? db_path.parent_path() : fs::path{};
    return dir / "pricoin_stealth.dat";
}

// Sets the two privkeys + derived public_address into `out`. `plain` holds
// 32 view + 32 spend bytes; cleansed by the caller after this returns.
bool MaterializeIdentity(const std::array<unsigned char, kPlaintextSize>& plain, Identity& out)
{
    out.view.Set(plain.begin(), plain.begin() + 32, /*fCompressedIn=*/true);
    out.spend.Set(plain.begin() + 32, plain.begin() + 64, /*fCompressedIn=*/true);
    if (!out.view.IsValid() || !out.spend.IsValid()) return false;
    out.public_address.view = out.view.GetPubKey();
    out.public_address.spend = out.spend.GetPubKey();
    return true;
}

// Decode a stealth-identity blob (any of the supported versions) into the
// 64-byte plaintext (view||spend). Throws std::runtime_error if the blob
// is encrypted and the wallet is currently locked. Sets `needs_upgrade`
// when the blob's format is older than what we'd write today, so the
// caller can re-save to migrate.
bool DecodeBlob(CWallet& wallet,
                std::span<const unsigned char> buf,
                std::array<unsigned char, kPlaintextSize>& plain,
                bool& needs_upgrade)
{
    needs_upgrade = false;
    if (buf.empty()) return false;
    bool plaintext = false;

    if (buf.size() == kPlaintextSize) {
        // Legacy unversioned 64-byte plaintext (file-only; never written
        // to the DB). Always upgrade.
        std::memcpy(plain.data(), buf.data(), kPlaintextSize);
        plaintext = true;
        needs_upgrade = true;
    } else if (buf[0] == kVersionPlain) {
        if (buf.size() != 1 + kPlaintextSize) return false;
        std::memcpy(plain.data(), buf.data() + 1, kPlaintextSize);
        plaintext = true;
    } else if (buf[0] == kVersionEncryptedNoMac || buf[0] == kVersionEncrypted) {
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
                    // Wrong key, or tampered ciphertext. AES-CBC has no
                    // built-in integrity; a bad-MAC plaintext is garbage.
                    return false;
                }
            }
            if (!DecryptSecret(mk, ciphertext, iv, decrypted)) return false;
            ok = (decrypted.size() == kPlaintextSize);
            return ok;
        });
        if (!ok) return false;
        std::memcpy(plain.data(), decrypted.data(), kPlaintextSize);
        memory_cleanse(decrypted.data(), decrypted.size());
        if (!has_mac) needs_upgrade = true;
    } else {
        return false;
    }

    // Plaintext loaded under an encrypted wallet → upgrade so the next
    // write encrypts the keys at rest.
    if (plaintext && wallet.HasEncryptionKeys() && !wallet.IsLocked()) {
        needs_upgrade = true;
    }
    return true;
}

// Encode a 64-byte plaintext into a versioned blob ready for storage.
// Returns false if the wallet is encrypted-but-locked (caller retries
// later — see SaveIdentity comment for why we won't write plaintext
// under an encrypted wallet).
bool EncodeBlob(CWallet& wallet,
                std::span<const unsigned char> plain,
                std::vector<unsigned char>& blob)
{
    if (plain.size() != kPlaintextSize) return false;

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
    blob.reserve(1 + kPlaintextSize);
    blob.push_back(kVersionPlain);
    blob.insert(blob.end(), plain.begin(), plain.end());
    return true;
}

// Read the stealth blob from the wallet's DB. Returns false if absent or
// the read failed.
bool ReadBlobFromDB(CWallet& wallet, std::vector<unsigned char>& blob)
{
    WalletBatch batch(wallet.GetDatabase());
    return batch.ReadPricoinStealth(blob);
}

bool WriteBlobToDB(CWallet& wallet, const std::vector<unsigned char>& blob)
{
    WalletBatch batch(wallet.GetDatabase());
    return batch.WritePricoinStealth(blob);
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

// Wrap DecodeBlob to fill an Identity, cleansing the intermediate plaintext.
bool DecodeBlobIntoIdentity(CWallet& wallet,
                            std::span<const unsigned char> blob,
                            Identity& out,
                            bool& needs_upgrade)
{
    std::array<unsigned char, kPlaintextSize> plain{};
    if (!DecodeBlob(wallet, blob, plain, needs_upgrade)) return false;
    bool ok = MaterializeIdentity(plain, out);
    memory_cleanse(plain.data(), plain.size());
    return ok;
}

bool SaveIdentity(CWallet& wallet, const Identity& id)
{
    std::array<unsigned char, kPlaintextSize> plain{};
    std::memcpy(plain.data(),      id.view.data(),  32);
    std::memcpy(plain.data() + 32, id.spend.data(), 32);
    std::vector<unsigned char> blob;
    bool ok = EncodeBlob(wallet, plain, blob);
    memory_cleanse(plain.data(), plain.size());
    if (!ok) return false;
    return WriteBlobToDB(wallet, blob);
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
            if (SaveIdentity(wallet, it->second.id)) {
                it->second.saved_in_target_format = true;
                LogInfo("Pricoin: persisted previously-in-memory stealth identity for wallet %s",
                        wallet.GetName());
            }
        }
        return it->second.id;
    }

    Identity id;
    bool loaded = false;
    bool needs_resave = false;
    const char* origin = nullptr;

    // 1. Wallet DB (current home — what `backupwallet` covers).
    std::vector<unsigned char> blob;
    if (ReadBlobFromDB(wallet, blob)) {
        if (!DecodeBlobIntoIdentity(wallet, blob, id, needs_resave)) {
            // DB record exists but we can't decode it. Don't silently
            // overwrite — the user may have wallet-locked state or a
            // genuinely corrupt entry. Surface the failure.
            throw std::runtime_error(
                "Pricoin stealth record in wallet.dat failed to decode "
                "(wallet locked, wrong passphrase, or corrupt entry)");
        }
        loaded = true;
        origin = "wallet.dat";
    }

    // 2. Legacy side file (pre-this-commit installs). Migrate into the DB
    //    on first read so future backups carry the identity. The file is
    //    intentionally left in place as a downgrade safety net — it's no
    //    longer the source of truth, but reverting to an older binary
    //    will still find it.
    if (!loaded && ReadBlobFromLegacyFile(wallet, blob)) {
        if (DecodeBlobIntoIdentity(wallet, blob, id, needs_resave)) {
            loaded = true;
            origin = "legacy pricoin_stealth.dat (migrating to wallet.dat)";
            needs_resave = true;  // always migrate format-wise too
        }
    }

    // 3. Nothing on disk — generate a fresh identity.
    if (!loaded) {
        id.view = FreshKey();
        id.spend = FreshKey();
        id.public_address.view = id.view.GetPubKey();
        id.public_address.spend = id.spend.GetPubKey();
        needs_resave = true;
        origin = "generated";
    }

    bool saved = false;
    if (needs_resave) {
        saved = SaveIdentity(wallet, id);
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
    auto [inserted, _] = g_identities.emplace(&wallet, CacheEntry{std::move(id), saved});
    // Drop our cache entry the moment the wallet is unloaded, so a future
    // wallet that happens to be allocated at the same heap address can't
    // inherit this identity. NotifyUnload fires from RemoveWallet() before
    // ~CWallet, so the pointer is still valid when the slot runs.
    CWallet* wallet_ptr = &wallet;
    inserted->second.unload_conn = wallet.NotifyUnload.connect([wallet_ptr]() {
        LOCK(g_mutex);
        g_identities.erase(wallet_ptr);
    });
    return inserted->second.id;
}

void Shutdown()
{
    LOCK(g_mutex);
    g_identities.clear();
}

} // namespace wallet::pricoin_stealth
