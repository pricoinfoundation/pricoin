# Pricoin Tier-3: Self-hosted Esplora setup

The Tier-3 swap watcher (see `pricoin-tier3-swapwatch.md`) polls a
foreign-chain backend to detect on-chain events for atomic swaps.
Public Esplora endpoints (mempool.space, blockstream.info,
litecoinspace.org) work out of the box, but they're rate-limited
and a malicious operator could lie about confirmations to trick
the watcher into advancing prematurely.

For high-value swaps you should self-host. This guide walks
through the standard stack: **Bitcoin Core + electrs + esplora**
behind a local HTTPS reverse proxy, with `pricoind` pointed at it.

The same approach works for Litecoin via `litecoind` + electrs's
`-network=liquid`-style fork (or just the same electrs binary —
both BTC and LTC speak the same RPC dialect for the subset
electrs needs).

## Stack

```
┌────────────┐   ┌──────────┐   ┌──────────┐   ┌─────────┐
│ Bitcoin    │──▶│ electrs  │──▶│ esplora  │──▶│ nginx   │
│ Core       │   │          │   │ -electrs │   │ (HTTPS) │
└────────────┘   └──────────┘   └──────────┘   └─────────┘
                                                      │
                                                      ▼
                                              -btcwatchurl=
                                              https://your-host/api
```

## Step 1: Bitcoin Core

Run a full node with `-txindex=1` so electrs can read tx data
without rebuilding its own index from scratch.

```bash
bitcoind -daemon -txindex=1
```

Wait for full sync. On mainnet this takes 1-3 days depending on
disk speed.

## Step 2: electrs

[Blockstream/electrs](https://github.com/Blockstream/electrs)
serves an Electrum-compatible RPC over the indexed tx data.

```bash
git clone https://github.com/Blockstream/electrs
cd electrs
cargo build --release
./target/release/electrs \
  --network mainnet \
  --daemon-dir ~/.bitcoin \
  --db-dir /var/lib/electrs \
  --http-addr 127.0.0.1:3000
```

First run will index the chain; on mainnet this is several hours
+ ~150 GB. Subsequent runs catch up incrementally.

Check it's up:

```bash
curl -s http://127.0.0.1:3000/blocks/tip/height
```

Should return the current tip height as a plain text integer.

## Step 3: nginx HTTPS reverse proxy

`pricoind`'s built-in HTTP client (libevent + OpenSSL) speaks
HTTPS. For local-only use, plain HTTP works — but for any
production setup you want TLS so the swap watcher's queries can't
be MITM'd. Get a Let's Encrypt cert via certbot, then:

```nginx
server {
    listen 443 ssl;
    server_name esplora.example.com;

    ssl_certificate     /etc/letsencrypt/live/esplora.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/esplora.example.com/privkey.pem;

    location /api/ {
        proxy_pass http://127.0.0.1:3000/;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Step 4: Point pricoind at it

```bash
pricoind \
  -btcwatchurl=https://esplora.example.com/api \
  -pricoinswapwatch_interval=30
```

Verify via the wallet RPC that the backend is reachable:

```bash
pricoin-cli pricoin_chainwatch_height btc
```

Should return the same tip height as your local electrs.

## Step 5: Litecoin (same stack)

For an LTC backend, repeat with `litecoind -txindex=1` and
electrs configured with `--network mainnet --daemon-rpc-addr
127.0.0.1:9332`. Use `-ltcwatchurl=` or `-chainwatchurl=ltc=` to
register it with pricoind.

Note: electrs needs a chain-specific patch for LTC; see
[romanz/electrs](https://github.com/romanz/electrs) (the
non-Blockstream fork) which handles altcoins more flexibly.

## Operational notes

* **Storage**: electrs needs ~150 GB for mainnet BTC, ~50 GB for
  LTC. Plan accordingly.

* **Rebuild on corruption**: if electrs's RocksDB gets corrupted
  (unclean shutdown, disk full, etc.), the simplest fix is to
  delete `--db-dir` and re-index. Several hours but unattended.

* **Rate limit yourself**: even self-hosted, the watcher polling
  every 30s isn't load. Public endpoints would throttle but
  yours won't — feel free to drop `-pricoinswapwatch_interval=`
  to 10-15s for faster confirmation detection on higher-stakes
  swaps.

* **Backup the swap state**: `pricoin_adaptor_swap_*` records
  and `pricoin_swapwatch_*` entries live in the wallet DB.
  Standard wallet backups cover them.

* **Monitor the relay**: if electrs falls behind (e.g., bitcoind
  hung), the watcher will think confirmations aren't progressing
  and stall the auto-advance. The watcher's 60s backoff on
  backend errors helps surface this — check `pricoin_chainwatch_height`
  vs. `bitcoin-cli getblockcount` periodically.

## Threat model

Self-hosting the backend addresses the trust-the-Esplora-operator
risk from `pricoin-tier3-swapwatch.md`. You still need to trust:

* Your own indexer software (electrs is open source; well-audited
  by the Bitcoin community).
* Your own bitcoind (also well-audited).
* The TLS path between pricoind and your nginx. (Local TLS or
  unix socket eliminates this if pricoind is on the same host.)

For the highest-stakes deployments, run pricoind, bitcoind, and
electrs on the same host and use `-btcwatchurl=http://127.0.0.1:3000`
to skip the nginx layer entirely.
