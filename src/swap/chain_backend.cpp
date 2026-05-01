// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <swap/chain_backend.h>

#include <sync.h>

#include <map>

namespace pricoin::swap {

namespace {

Mutex g_mutex;
std::map<std::string, std::shared_ptr<ChainBackend>> g_backends GUARDED_BY(g_mutex);

} // namespace

void RegisterBackend(std::shared_ptr<ChainBackend> backend)
{
    if (!backend) return;
    const std::string name = backend->Name();
    LOCK(g_mutex);
    g_backends[name] = std::move(backend);
}

std::shared_ptr<ChainBackend> GetBackend(const std::string& name)
{
    LOCK(g_mutex);
    auto it = g_backends.find(name);
    if (it == g_backends.end()) return nullptr;
    return it->second;
}

std::vector<std::string> ListBackendNames()
{
    LOCK(g_mutex);
    std::vector<std::string> out;
    out.reserve(g_backends.size());
    for (const auto& [name, _] : g_backends) out.push_back(name);
    return out;
}

void Shutdown()
{
    LOCK(g_mutex);
    g_backends.clear();
}

} // namespace pricoin::swap
