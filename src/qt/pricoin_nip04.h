// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_PRICOIN_NIP04_H
#define BITCOIN_QT_PRICOIN_NIP04_H

#include <QString>
#include <array>
#include <optional>
#include <string>

// NIP-04 (encrypted DM) encrypt/decrypt helpers.
//
// NIP-04 content shape: "<base64(ciphertext)>?iv=<base64(iv)>"
// Encryption: AES-256-CBC with PKCS#7 padding. The key is the 32-byte
// X-coordinate of the ECDH multiplication of the two parties'
// secp256k1 keys (derived elsewhere — see WalletImpl::nip04SharedKey).
// IV is 16 random bytes per message.
//
// These helpers don't do any priv-key handling — they take the
// pre-derived 32-byte AES key as input. ECDH is the wallet's job.

namespace pricoin::nip04 {

// Build the NIP-04 content string for `plaintext` under `aes_key`.
// Returns "<b64ct>?iv=<b64iv>" on success. The IV is filled by
// the caller via `iv16` (16 random bytes); the helper handles
// padding and base64. Returns std::nullopt on internal failure
// (only on AES init / programming error).
std::optional<QString> Encrypt(
    const std::array<unsigned char, 32>& aes_key,
    const std::array<unsigned char, 16>& iv16,
    const QString& plaintext);

// Convenience overload — generates a fresh IV via GetStrongRandBytes
// and encrypts.
std::optional<QString> Encrypt(
    const std::array<unsigned char, 32>& aes_key,
    const QString& plaintext);

// Decrypt a NIP-04 content string. Returns the plaintext on
// success, std::nullopt on parse failure (no `?iv=`, malformed
// base64, ciphertext not a multiple of 16, padding error,
// non-UTF-8 plaintext, etc.).
std::optional<QString> Decrypt(
    const std::array<unsigned char, 32>& aes_key,
    const QString& content);

} // namespace pricoin::nip04

#endif // BITCOIN_QT_PRICOIN_NIP04_H
