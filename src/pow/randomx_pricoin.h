// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_RANDOMX_PRICOIN_H
#define BITCOIN_POW_RANDOMX_PRICOIN_H

#include <uint256.h>

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

// Convenience: resolve seed_hash via the active chain for this height. If
// height < EPOCH_LAG (genesis era) the bootstrap seed is used. If
// ComputeSeedHeight(height) > the chain's known tip, falls back to bootstrap
// (this should never happen for properly-validated blocks but is defensive
// for partial header sync). Pass nullptr if no chain is available — same
// effect as bootstrap.
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
