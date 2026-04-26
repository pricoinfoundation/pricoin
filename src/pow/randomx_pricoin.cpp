// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow/randomx_pricoin.h>

#include <crypto/randomx/src/randomx.h>
#include <crypto/sha256.h>
#include <primitives/block.h>
#include <streams.h>
#include <sync.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string_view>

namespace pricoin::randomx {

namespace {

// Fixed seed string for Phase 1b. Hash with SHA-256 to derive the 32-byte
// RandomX cache key. Replace with a per-epoch derivation when seed rotation
// lands.
constexpr std::string_view kSeedString{"Pricoin RandomX fixed seed v1"};

Mutex g_mutex;
::randomx_cache* g_cache GUARDED_BY(g_mutex){nullptr};
::randomx_vm* g_vm GUARDED_BY(g_mutex){nullptr};

void EnsureInitialized() EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    if (g_vm) return;

    std::array<unsigned char, 32> seed_bytes;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(kSeedString.data()), kSeedString.size())
        .Finalize(seed_bytes.data());

    // Light mode (cache-only, ~256MB) — slower per hash than full-dataset
    // mode but adequate for verification. The miner could spin up its own
    // dataset-mode VM for speed; not done in Phase 1b.
    ::randomx_flags flags = ::randomx_get_flags();
    g_cache = ::randomx_alloc_cache(flags);
    if (!g_cache) throw std::runtime_error("randomx_alloc_cache failed");
    ::randomx_init_cache(g_cache, seed_bytes.data(), seed_bytes.size());
    g_vm = ::randomx_create_vm(flags, g_cache, nullptr);
    if (!g_vm) {
        ::randomx_release_cache(g_cache);
        g_cache = nullptr;
        throw std::runtime_error("randomx_create_vm failed");
    }
}

} // namespace

uint256 GetPoWHashOfBytes(std::span<const unsigned char> data)
{
    LOCK(g_mutex);
    EnsureInitialized();
    std::array<unsigned char, RANDOMX_HASH_SIZE> out{};
    ::randomx_calculate_hash(g_vm, data.data(), data.size(), out.data());
    return uint256{std::span<const unsigned char>{out.data(), out.size()}};
}

uint256 GetPoWHashOfHeader(const CBlockHeader& header)
{
    DataStream ds;
    ds << header;
    return GetPoWHashOfBytes(std::span<const unsigned char>{
        reinterpret_cast<const unsigned char*>(ds.data()), ds.size()});
}

void Shutdown()
{
    LOCK(g_mutex);
    if (g_vm) { ::randomx_destroy_vm(g_vm); g_vm = nullptr; }
    if (g_cache) { ::randomx_release_cache(g_cache); g_cache = nullptr; }
}

} // namespace pricoin::randomx
