// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SWAP_ESPLORA_BACKEND_H
#define BITCOIN_SWAP_ESPLORA_BACKEND_H

#include <swap/chain_backend.h>

#include <cstdint>
#include <memory>
#include <string>

// EsploraBackend — speaks the Esplora REST API
// (https://github.com/Blockstream/esplora/blob/master/API.md).
// Plain HTTP only for v1; HTTPS is a follow-up commit (it requires
// pulling openssl into the libevent bufferevent stack, or shelling
// out to libcurl).
//
// Construction takes a base URL like "http://localhost:3002/api"
// (no trailing slash) and a chain-symbolic name like "btc". The
// backend appends Esplora paths ("/blocks/tip/height", "/tx/<txid>",
// etc.). Compatible with public Esplora instances when proxied
// through a local HTTP-only relay, and with self-hosted electrs +
// esplora-electrs setups.

namespace pricoin::swap {

struct EsploraBackendOptions {
    // "http://localhost:3002/api" or similar. Must start with
    // "http://" — HTTPS support is deferred.
    std::string base_url;
    // Chain symbolic name. Stored in the backend so registry
    // lookups by name work.
    std::string chain_name;
    // Per-request timeout in seconds. 30 is a reasonable default
    // for public Esplora; bump for self-hosted on slow disks.
    int timeout_seconds{30};
};

// Construct an Esplora backend. Throws std::invalid_argument if
// the URL doesn't start with "http://" (we explicitly don't
// support HTTPS in this revision; document loudly).
std::shared_ptr<ChainBackend> MakeEsploraBackend(const EsploraBackendOptions& opts);

} // namespace pricoin::swap

#endif // BITCOIN_SWAP_ESPLORA_BACKEND_H
