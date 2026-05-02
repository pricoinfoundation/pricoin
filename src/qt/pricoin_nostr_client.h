// Copyright (c) 2026-present The Pricoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_PRICOIN_NOSTR_CLIENT_H
#define BITCOIN_QT_PRICOIN_NOSTR_CLIENT_H

#include <QHash>
#include <QObject>
#include <QSet>
#include <QString>
#include <QStringList>

QT_BEGIN_NAMESPACE
class QWebSocket;
QT_END_NAMESPACE

class WalletModel;

// Phase-6 Tier-2: Nostr-relay transport for the orderbook.
//
// Wraps QWebSocket connections to one or more Nostr relays. Publishes
// the wallet's Local offers as kind-30030 events (parameterized
// replaceable, NIP-33), and subscribes to incoming kind-30030 events
// from any maker. Each event's BIP340 sig is verified against its
// `pubkey` field; the embedded `content` carries the canonical
// pricoffer:v1/<base64> URI. Successfully-validated URIs are surfaced
// via `offerReceived(uri)` for the orderbook page to import.
//
// EVENT SHAPE
//   kind:    30030  (NIP-33 parameterized replaceable, in the
//                    application-specific 30000–39999 range)
//   pubkey:  maker's swap-identity x-only pubkey, hex
//   tags:
//     ["d", "<order_id>"]              — replaceable key (NIP-33)
//     ["expiration", "<unix_sec>"]     — relay should drop after (NIP-40)
//     ["c", "btc" | "ltc"]             — chain, for relay-side tag filtering
//     ["s", "buy" | "sell"]            — side
//   content: full pricoffer:v1/<base64> URI
//   id:      sha256 of NIP-01 canonical [0,pk,ts,kind,tags,content]
//   sig:     BIP340 over id by the swap-identity priv
//
// Two-layer authentication: the URI's internal ECDSA sig (validated
// by `offerImport`) AND the Nostr event's BIP340 sig (validated here).
// Both must be by the same key (URI's maker_pubkey is the compressed
// form of the event's xonly pubkey). A mismatch is rejected.

class PricoinNostrClient : public QObject
{
    Q_OBJECT

public:
    static constexpr int kOfferKind = 30030;
    // NIP-04 encrypted DMs use kind=4. Subscribed to with a #p
    // tag filter set to the wallet's xonly pubkey, so the relay
    // only sends events addressed to us.
    static constexpr int kDmKind = 4;

    PricoinNostrClient(WalletModel* model,
                       const QStringList& relay_urls,
                       QObject* parent = nullptr);
    ~PricoinNostrClient() override;

    // Open WebSocket connections to all configured relays. On connect,
    // a subscription for kind-30030 events is sent.
    void connectAll();
    // Close all WebSocket connections.
    void disconnectAll();

    // Publish a local offer URI to all currently-connected relays.
    // Wraps the URI in a Nostr event, signs via the wallet's swap
    // identity, sends ["EVENT", <obj>] frames. Returns true if at
    // least one relay was sent to.
    bool publishOfferUri(const QString& uri,
                         const QString& order_id_hex,
                         qint64 expiry_unix_sec,
                         const QString& chain,        // "btc" | "ltc"
                         const QString& side);        // "buy" | "sell"

    // Publish a NIP-04 encrypted direct message to `peer_xonly_hex`.
    // The wallet derives the AES key via ECDH(my_swap_priv,
    // peer_xonly→even-y), encrypts `plaintext` with AES-256-CBC +
    // random IV, and packages it as a kind-4 event with a `["p",
    // peer]` tag. Returns true if at least one relay was sent to.
    bool publishDirectMessage(const QString& peer_xonly_hex,
                               const QString& plaintext);

    // Tier-3 helper: announce that this wallet broadcast a swap-leg
    // tx, so the peer can auto-add a swapwatch entry. Builds the
    // standard envelope:
    //   {"v":1,"type":"tx_announce",
    //    "swap_id":..., "kind":..., "txid":..., "vout":N}
    // and DMs it to `peer_xonly_hex`. Returns true if at least one
    // relay was sent to.
    bool publishBroadcastAnnouncement(const QString& peer_xonly_hex,
                                        const QString& swap_id_hex,
                                        const QString& kind,
                                        const QString& txid_hex,
                                        int32_t vout,
                                        int32_t min_confirmations);

    // True if at least one relay is currently connected.
    bool anyConnected() const;
    // Count of currently-connected relays (0..relayUrls().size()).
    // Useful for cooperative-sign dialogs that hook into a shared
    // client that may already be connected.
    int connectedCount() const;

    QStringList relayUrls() const { return m_relay_urls; }

Q_SIGNALS:
    // Fired for each VALIDATED inbound offer URI that this wallet
    // has not yet imported. The orderbook page calls offerImport on
    // it and refreshes its view.
    void offerReceived(const QString& uri);
    // Fired for each VALIDATED inbound NIP-04 DM. `from_xonly_hex`
    // is the sender's xonly pubkey (32-byte hex). `plaintext` is
    // the decrypted content.
    void directMessageReceived(const QString& from_xonly_hex,
                                 const QString& plaintext);
    // Status delta — true=connected, false=disconnected.
    void relayStatusChanged(const QString& relay_url, bool connected);
    // Diagnostic stream (relay errors, parse failures, etc.).
    void log(const QString& message);

private Q_SLOTS:
    void onConnected();
    void onTextMessage(const QString& message);
    void onDisconnected();

private:
    WalletModel* m_model;
    QStringList m_relay_urls;
    QHash<QWebSocket*, QString> m_relay_url_by_socket;
    QHash<QString, QWebSocket*> m_socket_by_url;
    QString m_subid;

    // Track event ids we've already surfaced (to dedupe across
    // multiple relays delivering the same event). Bounded by the
    // wallet's order count; trimming is left for a follow-up.
    QSet<QString> m_seen_event_ids;

    void sendSubscription(QWebSocket* sock);
    bool verifyEvent(const QString& pubkey_hex,
                     const QString& id_hex,
                     const QString& sig_hex,
                     const QString& canonical_serialized);
};

#endif // BITCOIN_QT_PRICOIN_NOSTR_CLIENT_H
