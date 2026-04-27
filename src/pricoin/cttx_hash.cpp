// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// HashBundle is the only piece of cttx.cpp that bitcoin_consensus needs:
// script/interpreter.cpp mixes the bundle hash into the sighash for v4
// transactions. The rest of cttx.cpp (Pedersen subtraction, scalar
// arithmetic, BalancingBlind, ...) lives in bitcoin_common because it
// pulls in libsecp256k1-zkp's generator API. Splitting HashBundle into
// its own tiny TU keeps bitcoin_consensus self-contained at link time.

#include <pricoin/cttx.h>

#include <hash.h>
#include <uint256.h>

namespace pricoin::ct {

uint256 HashBundle(const CTBundle& bundle)
{
    HashWriter hw{};
    hw << bundle;
    // Plain SHA-256 (single, not double) — matches Bitcoin's
    // HashWriter::GetSHA256 pattern used for sighash subhashes.
    return hw.GetSHA256();
}

} // namespace pricoin::ct
