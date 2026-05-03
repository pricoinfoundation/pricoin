// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_RANDOMX_PRICOIN_H
#define BITCOIN_POW_RANDOMX_PRICOIN_H

#include <uint256.h>

#include <optional>
#include <span>

class CBlockHeader;
class CChain;

namespace pricoin::randomx {

// Monero-style epoch rotation: seed changes every 2048 blocks, with a
// 64-block lag so miners can't precompute the next seed too far ahead.
constexpr int EPOCH_BLOCKS = 2048;
constexpr int EPOCH_LAG = 64;

// Block height → height of the block whose hash supplies this height's seed.
// For heights below EPOCH_LAG, returns 0 (genesis-era bootstrap).
int ComputeSeedHeight(int height);

// PoW hash of a header given the 32-byte seed for its epoch. Caller is
// responsible for resolving the seed by looking up the block at
// ComputeSeedHeight(height) and passing its hash. The seed bytes are
// hashed (SHA-256) once more internally before being fed to RandomX so
// that block-hash format details don't leak into the cache key derivation.
uint256 GetPoWHashOfHeader(const CBlockHeader& header, const uint256& seed_hash);
uint256 GetPoWHashOfBytes(std::span<const unsigned char> data, const uint256& seed_hash);

// Convenience: resolve seed_hash via the active chain for this height.
// Returns nullopt when the seed block ISN'T yet indexed in `chain` —
// typical during header-sync past the first epoch boundary, where peer
// has advanced past height 2112 but slow node hasn't downloaded block
// 2048 yet. Caller chooses behavior:
//   * Header-acceptance path: defer PoW verification (treat as pass).
//     The block-validation path runs CheckBlockHeader again with the
//     full block context, where the seed block IS indexed because
//     blocks download in sequence. Any genuinely-bogus PoW gets caught
//     there.
//   * Block-validation path: nullopt is unexpected (seed block must be
//     in chain by then). Treat as failure.
// Returns the hash for height < EPOCH_LAG using the bootstrap seed,
// regardless of `chain`.
std::optional<uint256> TryGetPoWHashOfHeader(
    const CBlockHeader& header, int height, const CChain* chain);

// Legacy convenience: like TryGetPoWHashOfHeader but silently falls
// back to the bootstrap seed when the seed block isn't indexed. Kept
// for callers that explicitly accept the silent-fallback semantics
// (e.g. mining-loop helpers); new code should prefer the optional
// overload above.
uint256 GetPoWHashOfHeader(const CBlockHeader& header, int height, const CChain* chain);

// Single-argument overload: equivalent to passing BootstrapSeedHash().
// Correct only for heights < EPOCH_LAG. Callers that don't have height
// context (e.g., header-only PoW pre-checks before parent index resolution)
// use this and accept that consensus correctness past the first epoch
// boundary requires height threading. TODO before mainnet: surface
// height/chain in CheckBlockHeader and HasValidProofOfWork.
uint256 GetPoWHashOfHeader(const CBlockHeader& header);

// The seed used at heights < EPOCH_LAG (genesis era). Returned as a uint256
// derived from a fixed tag string. Use this when no parent chain is
// available yet (e.g. validating a header at height 0..EPOCH_LAG-1).
uint256 BootstrapSeedHash();

// Tear down cache + VM. Optional. Idempotent.
void Shutdown();

} // namespace pricoin::randomx

#endif // BITCOIN_POW_RANDOMX_PRICOIN_H
