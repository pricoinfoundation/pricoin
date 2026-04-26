// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pricoin_stealth.h>

#include <key.h>
#include <pricoin/stealth.h>
#include <random.h>
#include <sync.h>
#include <wallet/wallet.h>

#include <map>

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

} // namespace

const Identity& GetOrCreate(CWallet& wallet)
{
    LOCK(g_mutex);
    auto it = g_identities.find(&wallet);
    if (it != g_identities.end()) return it->second;

    Identity id;
    id.view = FreshKey();
    id.spend = FreshKey();
    id.public_address.view = id.view.GetPubKey();
    id.public_address.spend = id.spend.GetPubKey();
    auto [inserted, _] = g_identities.emplace(&wallet, std::move(id));
    return inserted->second;
}

} // namespace wallet::pricoin_stealth
