// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SWAP_BTC_MUSIG2_RUNTIME_H
#define BITCOIN_SWAP_BTC_MUSIG2_RUNTIME_H

#include <musig.h>      // MuSig2SecNonce
#include <uint256.h>

#include <memory>

// Process-tier in-memory stash for live MuSig2 secret nonces.
//
// CONTEXT
//   The BTC MuSig2 wire protocol has a separation between round 1
//   (NonceGen — produces secnonce + pubnonce; secnonce MUST stay
//   secret) and the eventual partial-sign call (consumes the
//   secnonce and produces a partial signature).
//
//   `MuSig2SecNonce` is a libsecp256k1-allocated secret-zeroing
//   container intentionally NOT designed to be serialized or copied
//   (per libsecp256k1 docs: "Avoid copying or serializing the
//   secnonce. This reduces the possibility of nonce reuse, which
//   would compromise the secret key.").
//
//   The wire protocol therefore runs entirely in-process: the
//   `round1` RPC stashes the secnonce here keyed by an opaque
//   handle; the `partial_sign` RPC takes it back. Crash → secnonce
//   destroyed; the in-flight signing session must be re-run from
//   round 1, but no secret key material has leaked.
//
//   For crash-safety beyond this minimum, callers should pair the
//   stash with `clsag_nonce_records`-style commitment persistence:
//   write a "we committed to a pubnonce for this signing context"
//   record BEFORE returning the pubnonce to the counterparty, so
//   that on restart the wallet refuses to start a new signing
//   session under the same key/output (which would risk nonce
//   reuse and key leakage). That layer is out of scope for this
//   commit; this module is the in-process plumbing only.
//
//   Production: wire this stash + a §4.1a-style BTC commitment
//   record (separate module, follow-up commit).

namespace pricoin::swap::btc_musig2_runtime {

// Stash a MuSig2 secret nonce, taking ownership. The handle is the
// opaque 32-byte id the caller will later pass to `Take` to retrieve
// it. Returns false if the handle is already in use.
bool Stash(const uint256& handle, std::unique_ptr<MuSig2SecNonce> sec);

// Take the secret nonce for `handle`, transferring ownership to the
// caller. Returns nullptr if no secnonce is stashed under that handle.
std::unique_ptr<MuSig2SecNonce> Take(const uint256& handle);

// Drop all stashed secnonces. Called from the daemon's Shutdown path.
void Shutdown();

// Returns the number of currently-stashed handles. For tests.
size_t Size();

} // namespace pricoin::swap::btc_musig2_runtime

#endif // BITCOIN_SWAP_BTC_MUSIG2_RUNTIME_H
