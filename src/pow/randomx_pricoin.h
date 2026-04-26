// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_RANDOMX_PRICOIN_H
#define BITCOIN_POW_RANDOMX_PRICOIN_H

#include <uint256.h>

#include <span>

class CBlockHeader;

namespace pricoin::randomx {

// Phase 1b uses one process-wide seed and never rotates it. Monero-style
// 2048-block epoch rotation is planned for Phase 2; until then, a fork that
// runs long enough for an attacker to precompute the seed is theoretically
// weaker than upstream RandomX. Acceptable for the toy/educational scope.
uint256 GetPoWHashOfHeader(const CBlockHeader& header);
uint256 GetPoWHashOfBytes(std::span<const unsigned char> data);

// Tear down cache + VM. Optional. Idempotent.
void Shutdown();

} // namespace pricoin::randomx

#endif // BITCOIN_POW_RANDOMX_PRICOIN_H
