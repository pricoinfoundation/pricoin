// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow/randomx_pricoin.h>

#include <chain.h>
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

// Bootstrap seed used during the genesis-era epoch (heights < EPOCH_LAG).
// Same constant as the Phase 1b fixed seed so existing regtest chains keep
// validating across the upgrade.
constexpr std::string_view kBootstrapSeedString{"Pricoin RandomX fixed seed v1"};

uint256 SeedKeyFromHash(const uint256& seed_hash)
{
    // Hash the seed_hash once more under a tag so that whatever the seed
    // representation is on chain, the RandomX cache key is a fixed-length
    // tagged digest.
    static constexpr std::string_view kTag{"pricoin/randomx/cache-key/v1"};
    std::array<unsigned char, 32> out;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(kTag.data()), kTag.size())
        .Write(seed_hash.data(), seed_hash.size())
        .Finalize(out.data());
    return uint256{std::span<const unsigned char>{out.data(), out.size()}};
}

Mutex g_mutex;
// Cached RandomX VM keyed by the *raw* seed_hash that was used to generate
// it. A single slot is sufficient: epoch boundaries are 2048 blocks apart,
// so consecutive PoW checks almost always hit the same seed. When the seed
// changes, we tear down the old VM and rebuild — slow but rare.
::randomx_cache* g_cache GUARDED_BY(g_mutex){nullptr};
::randomx_vm* g_vm GUARDED_BY(g_mutex){nullptr};
uint256 g_seed_hash GUARDED_BY(g_mutex){};
bool g_initialized GUARDED_BY(g_mutex){false};

void EnsureSeed(const uint256& seed_hash) EXCLUSIVE_LOCKS_REQUIRED(g_mutex)
{
    if (g_initialized && g_seed_hash == seed_hash) return;

    const uint256 cache_key = SeedKeyFromHash(seed_hash);
    ::randomx_flags flags = ::randomx_get_flags();

    if (g_vm) { ::randomx_destroy_vm(g_vm); g_vm = nullptr; }
    if (g_cache) { ::randomx_release_cache(g_cache); g_cache = nullptr; }

    g_cache = ::randomx_alloc_cache(flags);
    if (!g_cache) throw std::runtime_error("randomx_alloc_cache failed");
    ::randomx_init_cache(g_cache, cache_key.data(), cache_key.size());
    g_vm = ::randomx_create_vm(flags, g_cache, nullptr);
    if (!g_vm) {
        ::randomx_release_cache(g_cache);
        g_cache = nullptr;
        throw std::runtime_error("randomx_create_vm failed");
    }
    g_seed_hash = seed_hash;
    g_initialized = true;
}

} // namespace

int ComputeSeedHeight(int height)
{
    if (height < EPOCH_LAG) return 0;
    // Mask off the low bits to align to an EPOCH_BLOCKS boundary.
    static_assert((EPOCH_BLOCKS & (EPOCH_BLOCKS - 1)) == 0, "EPOCH_BLOCKS must be power of two");
    return (height - EPOCH_LAG) & ~(EPOCH_BLOCKS - 1);
}

uint256 BootstrapSeedHash()
{
    std::array<unsigned char, 32> out;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(kBootstrapSeedString.data()),
               kBootstrapSeedString.size())
        .Finalize(out.data());
    return uint256{std::span<const unsigned char>{out.data(), out.size()}};
}

uint256 GetPoWHashOfBytes(std::span<const unsigned char> data, const uint256& seed_hash)
{
    LOCK(g_mutex);
    EnsureSeed(seed_hash);
    std::array<unsigned char, RANDOMX_HASH_SIZE> out{};
    ::randomx_calculate_hash(g_vm, data.data(), data.size(), out.data());
    return uint256{std::span<const unsigned char>{out.data(), out.size()}};
}

uint256 GetPoWHashOfHeader(const CBlockHeader& header, const uint256& seed_hash)
{
    DataStream ds;
    ds << header;
    return GetPoWHashOfBytes(std::span<const unsigned char>{
        reinterpret_cast<const unsigned char*>(ds.data()), ds.size()}, seed_hash);
}

uint256 GetPoWHashOfHeader(const CBlockHeader& header, int height, const CChain* chain)
{
    const int seed_height = ComputeSeedHeight(height);
    uint256 seed = BootstrapSeedHash();
    if (seed_height > 0 && chain) {
        const CBlockIndex* idx = (*chain)[seed_height];
        if (idx) seed = idx->GetBlockHash();
    }
    return GetPoWHashOfHeader(header, seed);
}

uint256 GetPoWHashOfHeader(const CBlockHeader& header)
{
    return GetPoWHashOfHeader(header, BootstrapSeedHash());
}

void Shutdown()
{
    LOCK(g_mutex);
    if (g_vm) { ::randomx_destroy_vm(g_vm); g_vm = nullptr; }
    if (g_cache) { ::randomx_release_cache(g_cache); g_cache = nullptr; }
    g_initialized = false;
}

} // namespace pricoin::randomx
