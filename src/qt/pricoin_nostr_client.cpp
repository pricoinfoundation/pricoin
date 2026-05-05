// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/pricoin_nostr_client.h>

#include <qt/pricoin_nip04.h>
#include <qt/walletmodel.h>

#include <crypto/sha256.h>
#include <interfaces/wallet.h>
#include <random.h>
#include <pubkey.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <QByteArray>
#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QString>
#include <QUrl>
#include <QWebSocket>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

// NIP-01 canonical serializer for the [0, pk, ts, kind, tags, content]
// array. JSON with no whitespace; control chars 0x00–0x1f escaped per
// RFC 8259; quote (\"), backslash (\\), and the named escapes \b \f
// \n \r \t. Other Unicode is kept as raw UTF-8 bytes.
QByteArray EscapeJsonString(const QString& s)
{
    QByteArray utf8 = s.toUtf8();
    QByteArray out;
    out.reserve(utf8.size() + 2);
    out.append('"');
    for (unsigned char c : utf8) {
        switch (c) {
        case '\\':  out.append("\\\\", 2); break;
        case '"':   out.append("\\\"", 2); break;
        case '\b':  out.append("\\b",  2); break;
        case '\f':  out.append("\\f",  2); break;
        case '\n':  out.append("\\n",  2); break;
        case '\r':  out.append("\\r",  2); break;
        case '\t':  out.append("\\t",  2); break;
        default:
            if (c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned int>(c));
                out.append(buf);
            } else {
                out.append(static_cast<char>(c));
            }
        }
    }
    out.append('"');
    return out;
}

QByteArray SerializeTag(const QStringList& tag)
{
    QByteArray out;
    out.append('[');
    for (int i = 0; i < tag.size(); ++i) {
        if (i > 0) out.append(',');
        out.append(EscapeJsonString(tag[i]));
    }
    out.append(']');
    return out;
}

// Serialize the [0, pk, ts, kind, tags, content] array per NIP-01.
QByteArray CanonicalSerialize(int kind,
                               const QString& pubkey_hex,
                               qint64 created_at,
                               const QList<QStringList>& tags,
                               const QString& content)
{
    QByteArray out;
    out.append("[0,");
    out.append(EscapeJsonString(pubkey_hex));
    out.append(',');
    out.append(QByteArray::number(created_at));
    out.append(',');
    out.append(QByteArray::number(kind));
    out.append(",[");
    for (int i = 0; i < tags.size(); ++i) {
        if (i > 0) out.append(',');
        out.append(SerializeTag(tags[i]));
    }
    out.append("],");
    out.append(EscapeJsonString(content));
    out.append(']');
    return out;
}

uint256 Sha256(const QByteArray& data)
{
    uint256 out;
    CSHA256 h;
    h.Write(reinterpret_cast<const unsigned char*>(data.constData()),
            data.size());
    h.Finalize(out.data());
    return out;
}

} // namespace

PricoinNostrClient::PricoinNostrClient(WalletModel* model,
                                         const QStringList& relay_urls,
                                         QObject* parent)
    : QObject(parent),
      m_model(model),
      m_relay_urls(relay_urls)
{
    // Subscribe under a stable id so reconnects re-use it.
    uint256 sub_seed;
    GetStrongRandBytes(sub_seed);
    m_subid = QStringLiteral("pricoffer-") +
              QString::fromStdString(HexStr(std::span<const unsigned char>{
                  sub_seed.data(), 8}));
}

PricoinNostrClient::~PricoinNostrClient()
{
    disconnectAll();
}

void PricoinNostrClient::connectAll()
{
    for (const QString& url : m_relay_urls) {
        if (m_socket_by_url.contains(url)) continue;
        auto* sock = new QWebSocket(QString(),
                                     QWebSocketProtocol::VersionLatest, this);
        m_relay_url_by_socket.insert(sock, url);
        m_socket_by_url.insert(url, sock);

        connect(sock, &QWebSocket::connected,    this, &PricoinNostrClient::onConnected);
        connect(sock, &QWebSocket::disconnected, this, &PricoinNostrClient::onDisconnected);
        connect(sock, &QWebSocket::textMessageReceived,
                this, &PricoinNostrClient::onTextMessage);
        connect(sock,
                QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
                this, [this, sock](QAbstractSocket::SocketError) {
                    Q_EMIT log(tr("Relay error: %1: %2")
                        .arg(m_relay_url_by_socket.value(sock, "?"))
                        .arg(sock->errorString()));
                });

        Q_EMIT log(tr("Connecting to %1…").arg(url));
        sock->open(QUrl(url));
    }
}

void PricoinNostrClient::disconnectAll()
{
    for (auto* sock : m_relay_url_by_socket.keys()) {
        sock->close();
        sock->deleteLater();
    }
    m_relay_url_by_socket.clear();
    m_socket_by_url.clear();
}

bool PricoinNostrClient::anyConnected() const
{
    for (auto it = m_socket_by_url.constBegin();
         it != m_socket_by_url.constEnd(); ++it) {
        if (it.value()->state() == QAbstractSocket::ConnectedState) return true;
    }
    return false;
}

int PricoinNostrClient::connectedCount() const
{
    int n = 0;
    for (auto it = m_socket_by_url.constBegin();
         it != m_socket_by_url.constEnd(); ++it) {
        if (it.value()->state() == QAbstractSocket::ConnectedState) ++n;
    }
    return n;
}

void PricoinNostrClient::onConnected()
{
    auto* sock = qobject_cast<QWebSocket*>(sender());
    if (!sock) return;
    const QString url = m_relay_url_by_socket.value(sock);
    Q_EMIT relayStatusChanged(url, /*connected=*/true);
    Q_EMIT log(tr("Connected: %1").arg(url));
    sendSubscription(sock);
}

void PricoinNostrClient::onDisconnected()
{
    auto* sock = qobject_cast<QWebSocket*>(sender());
    if (!sock) return;
    const QString url = m_relay_url_by_socket.value(sock);
    Q_EMIT relayStatusChanged(url, /*connected=*/false);
    Q_EMIT log(tr("Disconnected: %1").arg(url));
}

void PricoinNostrClient::sendSubscription(QWebSocket* sock)
{
    // Two filters: kind=30030 for orderbook (no per-recipient
    // narrowing — anyone may broadcast offers we want to see), and
    // kind=4 NIP-04 DMs narrowed to events tagged for our xonly.
    // Sent as a single REQ with multiple filter clauses (NIP-01: a
    // REQ accepts an array of filters, OR-combined).
    QJsonObject filter_offers;
    filter_offers.insert("kinds", QJsonArray{kOfferKind});
    filter_offers.insert("limit", 256);

    QJsonArray req;
    req.append(QStringLiteral("REQ"));
    req.append(m_subid);
    req.append(filter_offers);

    // DM filter — only attempt if the wallet's xonly is available.
    if (m_model) {
        const std::string xonly = m_model->wallet().getSwapIdentityXOnlyHex();
        if (!xonly.empty()) {
            QJsonObject filter_dms;
            filter_dms.insert("kinds", QJsonArray{kDmKind});
            QJsonArray p_tag;
            p_tag.append(QString::fromStdString(xonly));
            filter_dms.insert("#p", p_tag);
            filter_dms.insert("limit", 256);
            req.append(filter_dms);
        }
    }

    const QString frame = QString::fromUtf8(
        QJsonDocument(req).toJson(QJsonDocument::Compact));
    sock->sendTextMessage(frame);
}

bool PricoinNostrClient::publishOfferUri(const QString& uri,
                                          const QString& order_id_hex,
                                          qint64 expiry_unix_sec,
                                          const QString& chain,
                                          const QString& side)
{
    if (!m_model) return false;
    const std::string xonly = m_model->wallet().getSwapIdentityXOnlyHex();
    if (xonly.empty()) {
        Q_EMIT log(tr("Cannot publish: swap-identity unavailable (wallet locked?)"));
        return false;
    }
    const QString pubkey_hex = QString::fromStdString(xonly);
    const qint64 created_at = QDateTime::currentSecsSinceEpoch();

    QList<QStringList> tags;
    tags.append({QStringLiteral("d"), order_id_hex});
    tags.append({QStringLiteral("expiration"), QString::number(expiry_unix_sec)});
    tags.append({QStringLiteral("c"), chain});
    tags.append({QStringLiteral("s"), side});

    const QByteArray canon =
        CanonicalSerialize(kOfferKind, pubkey_hex, created_at, tags, uri);
    const uint256 id = Sha256(canon);
    const QString id_hex = QString::fromStdString(HexStr(id));

    auto sig_or = m_model->wallet().signNostrEvent(id);
    if (!sig_or) {
        Q_EMIT log(tr("Cannot sign Nostr event: %1")
            .arg(QString::fromStdString(util::ErrorString(sig_or).original)));
        return false;
    }

    QJsonObject ev;
    ev.insert("id",         id_hex);
    ev.insert("pubkey",     pubkey_hex);
    ev.insert("created_at", static_cast<double>(created_at));
    ev.insert("kind",       kOfferKind);
    QJsonArray tags_json;
    for (const auto& t : tags) {
        QJsonArray a;
        for (const auto& v : t) a.append(v);
        tags_json.append(a);
    }
    ev.insert("tags",       tags_json);
    ev.insert("content",    uri);
    ev.insert("sig",        QString::fromStdString(*sig_or));

    QJsonArray msg;
    msg.append(QStringLiteral("EVENT"));
    msg.append(ev);
    const QString frame = QString::fromUtf8(
        QJsonDocument(msg).toJson(QJsonDocument::Compact));

    int sent = 0;
    for (auto it = m_socket_by_url.constBegin();
         it != m_socket_by_url.constEnd(); ++it) {
        QWebSocket* sock = it.value();
        if (sock->state() != QAbstractSocket::ConnectedState) continue;
        sock->sendTextMessage(frame);
        ++sent;
    }
    Q_EMIT log(tr("Published offer %1 to %2 relay(s).")
        .arg(order_id_hex.left(12) + "…").arg(sent));
    return sent > 0;
}

bool PricoinNostrClient::publishDirectMessage(const QString& peer_xonly_hex,
                                                const QString& plaintext)
{
    if (!m_model) return false;
    const std::string xonly = m_model->wallet().getSwapIdentityXOnlyHex();
    if (xonly.empty()) {
        Q_EMIT log(tr("Cannot publish DM: swap-identity unavailable (wallet locked?)"));
        return false;
    }
    auto key_or = m_model->wallet().nip04SharedKey(peer_xonly_hex.toStdString());
    if (!key_or) {
        Q_EMIT log(tr("Cannot derive NIP-04 key for peer %1: %2")
            .arg(peer_xonly_hex.left(12) + "…")
            .arg(QString::fromStdString(util::ErrorString(key_or).original)));
        return false;
    }

    // dm_id injection: if plaintext is a JSON object, ensure it has a
    // `dm_id` field for ACK tracking. Free-form (non-JSON) plaintext
    // gets no ACK — it's an opaque payload to us.
    QString dm_id;
    QString actual_plaintext = plaintext;
    {
        QJsonParseError pe;
        auto doc = QJsonDocument::fromJson(plaintext.toUtf8(), &pe);
        if (pe.error == QJsonParseError::NoError && doc.isObject()) {
            QJsonObject obj = doc.object();
            // Skip ACK injection on ACKs themselves (would loop).
            const bool is_ack = (obj.value(QStringLiteral("type")).toString()
                                  == QStringLiteral("pricoin:ack/v1"));
            if (!is_ack) {
                if (!obj.contains(QStringLiteral("dm_id"))) {
                    unsigned char rnd[16];
                    GetStrongRandBytes(rnd);
                    dm_id = QString::fromStdString(
                        HexStr(std::span<const unsigned char>{rnd, 16}));
                    obj.insert(QStringLiteral("dm_id"), dm_id);
                } else {
                    dm_id = obj.value(QStringLiteral("dm_id")).toString();
                }
                actual_plaintext = QString::fromUtf8(
                    QJsonDocument(obj).toJson(QJsonDocument::Compact));
            }
        }
    }

    auto content_or = pricoin::nip04::Encrypt(*key_or, actual_plaintext);
    if (!content_or) {
        Q_EMIT log(tr("NIP-04 encrypt failed"));
        return false;
    }

    const QString my_pubkey_hex = QString::fromStdString(xonly);
    const qint64 created_at = QDateTime::currentSecsSinceEpoch();

    QList<QStringList> tags;
    tags.append({QStringLiteral("p"), peer_xonly_hex});

    const QByteArray canon =
        CanonicalSerialize(kDmKind, my_pubkey_hex, created_at, tags, *content_or);
    const uint256 id = Sha256(canon);
    const QString id_hex = QString::fromStdString(HexStr(id));

    auto sig_or = m_model->wallet().signNostrEvent(id);
    if (!sig_or) {
        Q_EMIT log(tr("Cannot sign DM: %1")
            .arg(QString::fromStdString(util::ErrorString(sig_or).original)));
        return false;
    }

    QJsonObject ev;
    ev.insert("id",         id_hex);
    ev.insert("pubkey",     my_pubkey_hex);
    ev.insert("created_at", static_cast<double>(created_at));
    ev.insert("kind",       kDmKind);
    QJsonArray tags_json;
    for (const auto& t : tags) {
        QJsonArray a;
        for (const auto& v : t) a.append(v);
        tags_json.append(a);
    }
    ev.insert("tags",       tags_json);
    ev.insert("content",    *content_or);
    ev.insert("sig",        QString::fromStdString(*sig_or));

    QJsonArray msg;
    msg.append(QStringLiteral("EVENT"));
    msg.append(ev);
    const QString frame = QString::fromUtf8(
        QJsonDocument(msg).toJson(QJsonDocument::Compact));

    int sent = 0;
    for (auto it = m_socket_by_url.constBegin();
         it != m_socket_by_url.constEnd(); ++it) {
        QWebSocket* sock = it.value();
        if (sock->state() != QAbstractSocket::ConnectedState) continue;
        sock->sendTextMessage(frame);
        ++sent;
    }
    Q_EMIT log(tr("Published DM to %1 → %2 relay(s).")
        .arg(peer_xonly_hex.left(12) + "…").arg(sent));
    if (sent > 0 && !dm_id.isEmpty()) {
        Q_EMIT dmSent(dm_id, peer_xonly_hex);
    }
    return sent > 0;
}

bool PricoinNostrClient::publishBroadcastAnnouncement(
    const QString& peer_xonly_hex,
    const QString& swap_id_hex,
    const QString& kind,
    const QString& txid_hex,
    int32_t vout,
    int32_t min_confirmations)
{
    QJsonObject env;
    env.insert("v",       1);
    env.insert("type",    QStringLiteral("tx_announce"));
    env.insert("swap_id", swap_id_hex);
    env.insert("kind",    kind);
    env.insert("txid",    txid_hex);
    env.insert("vout",    vout);
    env.insert("min_confirmations", min_confirmations);
    const QString plaintext = QString::fromUtf8(
        QJsonDocument(env).toJson(QJsonDocument::Compact));
    return publishDirectMessage(peer_xonly_hex, plaintext);
}

bool PricoinNostrClient::verifyEvent(const QString& pubkey_hex,
                                      const QString& id_hex,
                                      const QString& sig_hex,
                                      const QString& canonical_serialized)
{
    // Recompute id and verify it matches.
    const QByteArray canon = canonical_serialized.toUtf8();
    const uint256 id = Sha256(canon);
    if (QString::fromStdString(HexStr(id)) != id_hex) return false;

    // Verify BIP340 sig.
    const auto pub_bytes = TryParseHex<unsigned char>(pubkey_hex.toStdString());
    if (!pub_bytes || pub_bytes->size() != 32) return false;
    const auto sig_bytes = TryParseHex<unsigned char>(sig_hex.toStdString());
    if (!sig_bytes || sig_bytes->size() != 64) return false;

    XOnlyPubKey xonly(std::span<const unsigned char>(pub_bytes->data(), 32));
    return xonly.VerifySchnorr(id,
        std::span<const unsigned char>(sig_bytes->data(), sig_bytes->size()));
}

void PricoinNostrClient::onTextMessage(const QString& message)
{
    QJsonParseError pe;
    auto doc = QJsonDocument::fromJson(message.toUtf8(), &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isArray()) return;
    const QJsonArray arr = doc.array();
    if (arr.isEmpty() || !arr[0].isString()) return;
    const QString tag = arr[0].toString();

    if (tag == QStringLiteral("EVENT")) {
        // ["EVENT", <subid>, <event>]
        if (arr.size() < 3 || !arr[2].isObject()) return;
        const QJsonObject ev = arr[2].toObject();
        const int kind = ev.value("kind").toInt();
        if (kind != kOfferKind && kind != kDmKind) return;

        const QString id_hex     = ev.value("id").toString();
        const QString pubkey_hex = ev.value("pubkey").toString();
        const QString sig_hex    = ev.value("sig").toString();
        const QString content    = ev.value("content").toString();
        const qint64 created_at  =
            static_cast<qint64>(ev.value("created_at").toDouble());

        if (m_seen_event_ids.contains(id_hex)) return;
        Q_EMIT log(tr("Received kind=%1 event %2 from %3…")
            .arg(kind).arg(id_hex.left(12) + "…").arg(pubkey_hex.left(12)));

        // Reconstruct canonical serialization.
        QList<QStringList> tags;
        const QJsonArray jtags = ev.value("tags").toArray();
        for (const QJsonValue& jt : jtags) {
            if (!jt.isArray()) continue;
            QStringList t;
            for (const QJsonValue& jv : jt.toArray()) {
                t.append(jv.toString());
            }
            tags.append(t);
        }
        const QByteArray canon = CanonicalSerialize(
            kind, pubkey_hex, created_at, tags, content);

        if (!verifyEvent(pubkey_hex, id_hex, sig_hex, QString::fromUtf8(canon))) {
            Q_EMIT log(tr("Rejected event %1: signature/id mismatch")
                .arg(id_hex.left(12) + "…"));
            return;
        }

        m_seen_event_ids.insert(id_hex);
        if (kind == kOfferKind) {
            Q_EMIT offerReceived(content);
        } else {
            // kind=4 NIP-04 DM. Decrypt with the wallet's NIP-04
            // shared key for the sender. If the relay was loose
            // about #p filtering and delivered a DM not for us,
            // decryption will fail (different ECDH key) and we
            // silently drop.
            if (!m_model) return;
            auto key_or = m_model->wallet().nip04SharedKey(pubkey_hex.toStdString());
            if (!key_or) return;
            auto pt_or = pricoin::nip04::Decrypt(*key_or, content);
            if (!pt_or) {
                Q_EMIT log(tr("DM from %1: decrypt failed (not for us, or malformed)")
                    .arg(pubkey_hex.left(12) + "…"));
                return;
            }

            // Inspect the plaintext for ACK frames + dm_id tracking.
            // Two cases:
            //   (1) type == "pricoin:ack/v1" — peer confirms receipt
            //       of an earlier DM we sent. Emit dmAcked, do not
            //       fan out as a normal DM.
            //   (2) any other JSON object — if it carries a dm_id,
            //       echo back an ACK so the sender sees delivery.
            //       Then emit directMessageReceived for normal handling.
            const QString pt_qstr = *pt_or;
            QJsonParseError pe;
            const auto doc = QJsonDocument::fromJson(pt_qstr.toUtf8(), &pe);
            bool is_ack = false;
            QString incoming_dm_id;
            if (pe.error == QJsonParseError::NoError && doc.isObject()) {
                const auto obj = doc.object();
                if (obj.value(QStringLiteral("type")).toString()
                    == QStringLiteral("pricoin:ack/v1")) {
                    const QString ack_for =
                        obj.value(QStringLiteral("ack_for")).toString();
                    if (!ack_for.isEmpty()) {
                        Q_EMIT dmAcked(ack_for, pubkey_hex);
                    }
                    is_ack = true;
                } else {
                    incoming_dm_id = obj.value(QStringLiteral("dm_id")).toString();
                }
            }
            if (is_ack) return;
            if (!incoming_dm_id.isEmpty()) {
                // Auto-ACK back. We synthesize a small JSON object —
                // publishDirectMessage will skip dm_id injection on
                // ACKs because of the type check.
                QJsonObject ack;
                ack.insert(QStringLiteral("type"),
                    QStringLiteral("pricoin:ack/v1"));
                ack.insert(QStringLiteral("ack_for"), incoming_dm_id);
                const QString ack_json = QString::fromUtf8(
                    QJsonDocument(ack).toJson(QJsonDocument::Compact));
                publishDirectMessage(pubkey_hex, ack_json);
            }
            Q_EMIT directMessageReceived(pubkey_hex, pt_qstr);
        }
    } else if (tag == QStringLiteral("OK")) {
        // ["OK", <event_id>, <accepted_bool>, <message>]  (NIP-20).
        // Surface so users can see whether their published events
        // were accepted or rejected by each relay.
        const QString eid = arr.size() > 1 ? arr[1].toString() : QString{};
        const bool accepted = arr.size() > 2 && arr[2].toBool();
        const QString why  = arr.size() > 3 ? arr[3].toString() : QString{};
        Q_EMIT log(tr("Relay OK: event %1 %2%3")
            .arg(eid.left(12) + "…")
            .arg(accepted ? tr("accepted") : tr("rejected"))
            .arg(why.isEmpty() ? QString{} : QStringLiteral(" — ") + why));
    } else if (tag == QStringLiteral("NOTICE")) {
        const QString notice = arr.size() > 1 ? arr[1].toString() : QString{};
        Q_EMIT log(tr("Relay NOTICE: %1").arg(notice));
    } else if (tag == QStringLiteral("EOSE") ||
               tag == QStringLiteral("CLOSED") ||
               tag == QStringLiteral("AUTH")) {
        // Silently ignore EOSE / CLOSED / AUTH for v0.
    }
}
