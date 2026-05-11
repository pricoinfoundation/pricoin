// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRICOIN_BROADCASTED_KIS_H
#define BITCOIN_WALLET_PRICOIN_BROADCASTED_KIS_H

// Wallet-local broadcasted-keyimage tracking. Persistent, per-wallet
// set of keyimages this wallet has produced as the real-signer in
// any v4 CT ring-input it has broadcast.
//
// PURPOSE: defense in depth against double-spending wallet outputs
// after a -reindex / sync race / reorg leaves the chain's global
// keyimage set (`g_key_images` in pricoin/validation.cpp) incomplete
// relative to chain history. The wallet's input picker
// (walletsendct_ring) filters candidate UTXOs by checking
// IsKeyImageCommitted against the global set — which can falsely
// return "unspent" during sync. Combining with this wallet-local
// set means the wallet refuses to re-spend any input it has already
// produced a ring sig for, regardless of chain state.
//
// PERSISTENCE: rows live in the wallet DB under the
// `pct_wallet_broadcasted_ki` prefix (one row per keyimage, empty
// value). Survives -reindex / -reindex-chainstate (chain's
// keyimages.dat gets wiped on those operations; this stays).
//
// CALLERS: walletsendct_ring (and any future ring-input broadcasting
// RPC) calls Add() RIGHT AFTER chain.broadcastTransaction returns
// success. The picker calls Contains() per candidate UTXO.

#include <array>
#include <cstdint>

namespace wallet { class CWallet; }

namespace wallet::pricoin_broadcasted_kis {

// Initialize the in-memory cache from the wallet DB. Called once at
// wallet load. Idempotent.
bool LoadFromDB(::wallet::CWallet& wallet);

// Persist a newly-broadcasted keyimage to both memory + disk.
// Returns true on success. Safe to call with the same KI multiple
// times — second call is a no-op.
bool Add(::wallet::CWallet& wallet,
          const std::array<unsigned char, 33>& key_image);

// Lookup: has the wallet ever broadcast a ring tx using this
// keyimage as the real signer?
bool Contains(::wallet::CWallet& wallet,
               const std::array<unsigned char, 33>& key_image);

}  // namespace wallet::pricoin_broadcasted_kis

#endif  // BITCOIN_WALLET_PRICOIN_BROADCASTED_KIS_H
