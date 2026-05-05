# Pricoin relay deploy kit

A four-node strfry mesh that backs Pricoin's orderbook + NIP-04 DM
transport. Each node accepts events from clients on `wss://relayN.pricoin.io`
and bidirectionally cross-streams to the other three, so an event
ingested anywhere is visible everywhere within a few hundred ms.

## Topology

```
       relay1 ─── relay2
        │  ╲      ╱  │
        │   ╲    ╱   │
        │    ╲  ╱    │
        │     ╲╱     │
        │     ╱╲     │
        │    ╱  ╲    │
        │   ╱    ╲   │
        │  ╱      ╲  │
       relay4 ─── relay3
```

Full mesh of 6 edges. Each node runs three `strfry stream
--dir both` daemons, one per peer. Any single node going down
doesn't drop traffic — clients use multiple relays in parallel,
and the surviving three keep mirroring among themselves.

## Per-host map

| systemd hostname | DNS A record         | IP                |
| ---------------- | -------------------- | ----------------- |
| rpc1             | relay1.pricoin.io    | 37.60.228.6       |
| rpc2             | relay2.pricoin.io    | 37.60.226.223     |
| rpc3             | relay3.pricoin.io    | 37.60.228.70      |
| rpc4             | relay4.pricoin.io    | 37.60.226.180     |

## Deploy

DNS must already be pointing each `relay<N>.pricoin.io` at its
box (above) — Caddy hits Let's Encrypt on first launch, which
fails if DNS hasn't propagated.

Then on each node, run `install.sh` with that node's hostname
first followed by the other three:

```bash
# rpc1:
ssh root@rpc1 'mkdir -p /root/pricoin-relay'
scp -r contrib/pricoin-relay/* root@rpc1:/root/pricoin-relay/
ssh root@rpc1 'cd /root/pricoin-relay && \
    ./install.sh relay1.pricoin.io \
        relay2.pricoin.io relay3.pricoin.io relay4.pricoin.io'

# rpc2:
ssh root@rpc2 'mkdir -p /root/pricoin-relay'
scp -r contrib/pricoin-relay/* root@rpc2:/root/pricoin-relay/
ssh root@rpc2 'cd /root/pricoin-relay && \
    ./install.sh relay2.pricoin.io \
        relay1.pricoin.io relay3.pricoin.io relay4.pricoin.io'

# rpc3:
ssh root@rpc3 'mkdir -p /root/pricoin-relay'
scp -r contrib/pricoin-relay/* root@rpc3:/root/pricoin-relay/
ssh root@rpc3 'cd /root/pricoin-relay && \
    ./install.sh relay3.pricoin.io \
        relay1.pricoin.io relay2.pricoin.io relay4.pricoin.io'

# rpc4:
ssh root@rpc4 'mkdir -p /root/pricoin-relay'
scp -r contrib/pricoin-relay/* root@rpc4:/root/pricoin-relay/
ssh root@rpc4 'cd /root/pricoin-relay && \
    ./install.sh relay4.pricoin.io \
        relay1.pricoin.io relay2.pricoin.io relay3.pricoin.io'
```

## Verify

After all four are up:

```bash
# NIP-11 info doc — confirms TLS + strfry are responding.
for n in 1 2 3 4; do
    echo "── relay$n ──"
    curl -s -H 'Accept: application/nostr+json' \
        https://relay$n.pricoin.io/ | jq '.name, .supported_nips'
done

# Stream-mesh health — each node should have three active streams.
for n in 1 2 3 4; do
    echo "── relay$n streams ──"
    ssh root@rpc$n 'systemctl list-units "pricoin-relay-stream@*.service" \
        --no-pager --no-legend'
done
```

## Local round-trip test

```bash
# Publish a junk event to relay1 with nak, watch it arrive on relay4.
nak event -k 30030 --content "test mesh propagation" \
    --sec $(openssl rand -hex 32) \
    wss://relay1.pricoin.io
nak req -k 30030 --limit 1 wss://relay4.pricoin.io
```

## What strfry stores

Per the writepolicy plugin (`writepolicy.sh`), each relay accepts
**only**:

- kind=4 — NIP-04 encrypted DMs (peer-to-peer swap coordination)
- kind=5 — NIP-09 deletes
- kind=30030 — Pricoin orderbook offers (parameterized replaceable)

Everything else is rejected at ingest. This keeps the relay focused
and avoids accumulating unrelated Nostr noise (notes, profiles,
reactions, etc.).

## Operational notes

- Logs: `journalctl -u pricoin-relay -f` for the relay,
  `journalctl -u 'pricoin-relay-stream@*' -f` for streams,
  `/var/log/caddy/relay<N>.pricoin.io.log` for HTTP/TLS.
- DB: LMDB at `/var/lib/pricoin-relay/db`. Capped at 64 GiB by
  config — should never approach that with kind-restricted
  ingest. `du -sh` to monitor.
- Rotation: replaceable kind=30030 events automatically supersede
  older versions of the same `d`-tag pair. Plus `events.rejectEventsOlderThanSeconds`
  drops anything > 30 days at ingest.
- Restart relay: `systemctl restart pricoin-relay`. Streams
  auto-restart with it via `PartOf=`.
- Restart one stream: `systemctl restart 'pricoin-relay-stream@relay2.pricoin.io'`.

## Troubleshooting

- **Caddy keeps failing to issue cert**: check DNS is actually
  pointing at this box (`dig relay<N>.pricoin.io`). Caddy logs at
  `journalctl -u caddy`.
- **Client says "rejected — invalid: bad signature"**: client is
  publishing with the broken pre-Schnorr-fix code. Rebuild client
  to latest.
- **Client says "rejected — kind not allowed"**: writepolicy.sh
  is doing its job; client tried to publish a non-Pricoin kind.
- **Streams not connecting**: check the peer relay is up + has
  the latest cert; `systemctl status 'pricoin-relay-stream@<peer>'`
  surfaces the strfry error.
