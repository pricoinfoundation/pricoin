// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pricoin_stealth.h>

#include <key.h>
#include <logging.h>
#include <pricoin/stealth.h>
#include <random.h>
#include <sync.h>
#include <util/fs.h>
#include <wallet/db.h>
#include <wallet/wallet.h>

#include <fstream>
#include <map>
#include <span>

namespace wallet::pricoin_stealth {

namespace {

Mutex g_mutex;
std::map<const CWallet*, Identity> g_identities GUARDED_BY(g_mutex);

CKey FreshKey()
{
    CKey k;
    k.MakeNewKey(/*fCompressed=*/true);
    return k;
}

// Side-file alongside the wallet's primary DB file. 64-byte raw blob:
// view_priv (32) || spend_priv (32). No checksum; if the file is corrupt
// we just regenerate (toy scope).
fs::path StealthFilePath(CWallet& wallet)
{
    fs::path db_path = fs::PathFromString(wallet.GetDatabase().Filename());
    fs::path dir = db_path.has_parent_path() ? db_path.parent_path() : fs::path{};
    return dir / "pricoin_stealth.dat";
}

bool LoadFromDisk(CWallet& wallet, Identity& out)
{
    const std::string path_str = fs::PathToString(StealthFilePath(wallet));
    std::ifstream f(path_str, std::ios::binary);
    if (!f) return false;
    std::array<unsigned char, 64> buf;
    f.read(reinterpret_cast<char*>(buf.data()), buf.size());
    if (f.gcount() != static_cast<std::streamsize>(buf.size())) return false;
    out.view.Set(buf.begin(), buf.begin() + 32, /*fCompressedIn=*/true);
    out.spend.Set(buf.begin() + 32, buf.begin() + 64, /*fCompressedIn=*/true);
    if (!out.view.IsValid() || !out.spend.IsValid()) return false;
    out.public_address.view = out.view.GetPubKey();
    out.public_address.spend = out.spend.GetPubKey();
    return true;
}

bool SaveToDisk(CWallet& wallet, const Identity& id)
{
    const std::string path_str = fs::PathToString(StealthFilePath(wallet));
    std::ofstream f(path_str, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(id.view.data()), 32);
    f.write(reinterpret_cast<const char*>(id.spend.data()), 32);
    return f.good();
}

} // namespace

const Identity& GetOrCreate(CWallet& wallet)
{
    LOCK(g_mutex);
    auto it = g_identities.find(&wallet);
    if (it != g_identities.end()) return it->second;

    Identity id;
    if (LoadFromDisk(wallet, id)) {
        LogInfo("Pricoin: loaded stealth identity from %s", fs::PathToString(StealthFilePath(wallet)));
    } else {
        id.view = FreshKey();
        id.spend = FreshKey();
        id.public_address.view = id.view.GetPubKey();
        id.public_address.spend = id.spend.GetPubKey();
        if (SaveToDisk(wallet, id)) {
            LogInfo("Pricoin: generated and saved stealth identity to %s", fs::PathToString(StealthFilePath(wallet)));
        } else {
            LogWarning("Pricoin: failed to persist stealth identity (in-memory only this session)");
        }
    }
    auto [inserted, _] = g_identities.emplace(&wallet, std::move(id));
    return inserted->second;
}

void Shutdown()
{
    LOCK(g_mutex);
    g_identities.clear();
}

} // namespace wallet::pricoin_stealth
