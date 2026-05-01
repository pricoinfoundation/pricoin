// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <swap/btc_musig2_runtime.h>

#include <sync.h>

#include <map>

namespace pricoin::swap::btc_musig2_runtime {

namespace {

Mutex g_mutex;
std::map<uint256, std::unique_ptr<MuSig2SecNonce>> g_stash GUARDED_BY(g_mutex);

} // namespace

bool Stash(const uint256& handle, std::unique_ptr<MuSig2SecNonce> sec)
{
    if (!sec) return false;
    LOCK(g_mutex);
    auto [it, inserted] = g_stash.emplace(handle, std::move(sec));
    return inserted;
}

std::unique_ptr<MuSig2SecNonce> Take(const uint256& handle)
{
    LOCK(g_mutex);
    auto it = g_stash.find(handle);
    if (it == g_stash.end()) return nullptr;
    auto out = std::move(it->second);
    g_stash.erase(it);
    return out;
}

void Shutdown()
{
    LOCK(g_mutex);
    g_stash.clear();
}

size_t Size()
{
    LOCK(g_mutex);
    return g_stash.size();
}

} // namespace pricoin::swap::btc_musig2_runtime
