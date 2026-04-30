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

// Throws std::runtime_error if the file is encrypted and the wallet is
// currently locked. Sets `needs_resave` to true if the on-disk format is
// not what we'd write today (legacy 64-byte file, or plaintext-on-disk
// while the wallet is encrypted) — the caller should re-save to upgrade.
bool LoadFromDisk(CWallet& wallet, Identity& out, bool& needs_resave)
{
    needs_resave = false;
    const std::string path_str = fs::PathToString(StealthFilePath(wallet));
    std::ifstream f(path_str, std::ios::binary);
    if (!f) return false;
    std::vector<unsigned char> buf((std::istreambuf_iterator<char>(f)),
                                    std::istreambuf_iterator<char>());
    if (buf.empty()) return false;

    std::array<unsigned char, kPlaintextSize> plain{};
    bool plaintext_on_disk = false;

    if (buf.size() == kPlaintextSize) {
        // Legacy unversioned plaintext.
        std::memcpy(plain.data(), buf.data(), kPlaintextSize);
        plaintext_on_disk = true;
        needs_resave = true;
    } else if (buf[0] == kVersionPlain) {
        if (buf.size() != 1 + kPlaintextSize) return false;
        std::memcpy(plain.data(), buf.data() + 1, kPlaintextSize);
        plaintext_on_disk = true;
    } else if (buf[0] == kVersionEncryptedNoMac || buf[0] == kVersionEncrypted) {
        const bool has_mac = (buf[0] == kVersionEncrypted);
        const size_t min_size = has_mac
            ? (1 + kIVSize + 1 + kMacSize)  // ver + iv + ≥1 byte ct + mac
            : (1 + kIVSize + 1);            // ver + iv + ≥1 byte ct
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
                    // Either wrong key or tampered file. Don't try to
                    // decrypt — AES-CBC has no built-in integrity, so a
                    // bad-MAC plaintext is meaningless garbage.
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
        // Legacy no-MAC ciphertext loaded successfully → upgrade on next save.
        if (!has_mac) needs_resave = true;
    } else {
        return false;
    }

    // Plaintext on disk + wallet is now encrypted → upgrade.
    if (plaintext_on_disk && wallet.HasEncryptionKeys() && !wallet.IsLocked()) {
        needs_resave = true;
    }

    bool ok = MaterializeIdentity(plain, out);
    memory_cleanse(plain.data(), plain.size());
    return ok;
}

bool SaveToDisk(CWallet& wallet, const Identity& id)
{
    // Refuse to persist while the wallet is encrypted-but-locked: writing
    // the plaintext branch would break the wallet's encryption invariant
    // (every other secret in the wallet is encrypted at rest). The
    // caller keeps the keys in memory and retries the save once the
    // wallet is unlocked. This matters because rescans triggered by
    // `createwallet` with a passphrase fire ScanTxForCTReceives, which
    // calls GetOrCreate while the freshly-encrypted wallet is still locked.
    if (wallet.HasEncryptionKeys() && wallet.IsLocked()) {
        return false;
    }

    const std::string path_str = fs::PathToString(StealthFilePath(wallet));
    std::ofstream f(path_str, std::ios::binary | std::ios::trunc);
    if (!f) return false;

    std::array<unsigned char, kPlaintextSize> plain{};
    std::memcpy(plain.data(),      id.view.data(),  32);
    std::memcpy(plain.data() + 32, id.spend.data(), 32);

    if (wallet.HasEncryptionKeys() && !wallet.IsLocked()) {
        uint256 iv;
        GetRandBytes(iv);
        CKeyingMaterial pt(plain.begin(), plain.end());
        memory_cleanse(plain.data(), plain.size());
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
        f.write(reinterpret_cast<const char*>(&ver), 1);
        f.write(reinterpret_cast<const char*>(iv.begin()), kIVSize);
        f.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
        f.write(reinterpret_cast<const char*>(mac), kMacSize);
        return f.good();
    }

    // Unencrypted wallet: matches the encryption status of every other
    // seckey in the wallet (transparent privkeys, etc., are also plaintext
    // on disk in this case). One-byte version prefix distinguishes the new
    // format from legacy 64-byte files.
    const unsigned char ver = kVersionPlain;
    f.write(reinterpret_cast<const char*>(&ver), 1);
    f.write(reinterpret_cast<const char*>(plain.data()), plain.size());
    bool good = f.good();
    memory_cleanse(plain.data(), plain.size());
    return good;
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
            if (SaveToDisk(wallet, it->second.id)) {
                it->second.saved_in_target_format = true;
                LogInfo("Pricoin: persisted previously-in-memory stealth identity at %s",
                        fs::PathToString(StealthFilePath(wallet)));
            }
        }
        return it->second.id;
    }

    Identity id;
    bool needs_resave = false;
    const bool loaded = LoadFromDisk(wallet, id, needs_resave);  // may throw on locked
    if (!loaded) {
        id.view = FreshKey();
        id.spend = FreshKey();
        id.public_address.view = id.view.GetPubKey();
        id.public_address.spend = id.spend.GetPubKey();
        needs_resave = true;
    }
    bool saved = false;
    if (needs_resave) {
        saved = SaveToDisk(wallet, id);
        if (saved) {
            LogInfo("Pricoin: %s stealth identity at %s",
                    loaded ? "re-saved (upgraded)" : "generated and saved",
                    fs::PathToString(StealthFilePath(wallet)));
        } else if (!loaded) {
            LogWarning("Pricoin: stealth identity not yet persisted (wallet locked); will retry on next access");
        }
    } else {
        // File on disk already matches what we'd write — no save needed.
        saved = true;
        LogInfo("Pricoin: loaded stealth identity from %s", fs::PathToString(StealthFilePath(wallet)));
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
