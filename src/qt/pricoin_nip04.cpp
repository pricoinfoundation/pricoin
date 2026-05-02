// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pricoin_nip04.h>

#include <crypto/aes.h>
#include <random.h>
#include <util/strencodings.h>

#include <QByteArray>
#include <vector>

namespace pricoin::nip04 {

std::optional<QString> Encrypt(
    const std::array<unsigned char, 32>& aes_key,
    const std::array<unsigned char, 16>& iv16,
    const QString& plaintext)
{
    AES256CBCEncrypt enc(aes_key.data(), iv16.data(), /*padIn=*/true);

    const QByteArray pt_utf8 = plaintext.toUtf8();
    // AES-CBC with PKCS#7 padding emits at most input + AES_BLOCKSIZE
    // bytes (one trailing pad block when input is a block multiple).
    std::vector<unsigned char> ct(pt_utf8.size() + AES_BLOCKSIZE);
    int written = enc.Encrypt(reinterpret_cast<const unsigned char*>(pt_utf8.constData()),
                               pt_utf8.size(), ct.data());
    if (written <= 0) return std::nullopt;
    ct.resize(static_cast<size_t>(written));

    const std::string ct_b64 = EncodeBase64(std::span<const unsigned char>{ct});
    const std::string iv_b64 = EncodeBase64(std::span<const unsigned char>{iv16});
    return QString::fromStdString(ct_b64 + "?iv=" + iv_b64);
}

std::optional<QString> Encrypt(
    const std::array<unsigned char, 32>& aes_key,
    const QString& plaintext)
{
    std::array<unsigned char, 16> iv{};
    GetStrongRandBytes(iv);
    return Encrypt(aes_key, iv, plaintext);
}

std::optional<QString> Decrypt(
    const std::array<unsigned char, 32>& aes_key,
    const QString& content)
{
    const int sep = content.indexOf(QStringLiteral("?iv="));
    if (sep < 0) return std::nullopt;
    const std::string ct_b64 = content.left(sep).toStdString();
    const std::string iv_b64 = content.mid(sep + 4).toStdString();
    auto ct_opt = DecodeBase64(ct_b64);
    auto iv_opt = DecodeBase64(iv_b64);
    if (!ct_opt || !iv_opt) return std::nullopt;
    if (iv_opt->size() != AES_BLOCKSIZE) return std::nullopt;
    if (ct_opt->empty() || ct_opt->size() % AES_BLOCKSIZE != 0) return std::nullopt;

    std::array<unsigned char, 16> iv{};
    std::copy(iv_opt->begin(), iv_opt->end(), iv.begin());
    AES256CBCDecrypt dec(aes_key.data(), iv.data(), /*padIn=*/true);

    std::vector<unsigned char> pt(ct_opt->size());
    int written = dec.Decrypt(ct_opt->data(), ct_opt->size(), pt.data());
    if (written <= 0) return std::nullopt;  // padding error
    pt.resize(static_cast<size_t>(written));
    // Round-trip via QString::fromUtf8 — invalid UTF-8 is a soft
    // failure (returns a replacement-char string), so we accept
    // anything; coopsign blobs are hex strings or JSON, both ASCII.
    return QString::fromUtf8(reinterpret_cast<const char*>(pt.data()),
                              static_cast<int>(pt.size()));
}

} // namespace pricoin::nip04
