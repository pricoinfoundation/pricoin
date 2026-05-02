# Pricoin Tier-3: Autonomous Swap Watcher

## Overview

The Tier-3 swap watcher lets `pricoind` autonomously detect on-chain
events for in-flight atomic swaps and advance the AdaptorSwap state
machine without manual `Set…Funded` / `Set…Claimed` clicks.

It works by polling **registered txids**: the user (or a peer's
Nostr DM) tells the wallet "watch this txid; when it confirms,
advance the swap to state X". The wallet polls the foreign-chain
backend on each tick and applies the matching `Set…` transition
when confirmation depth reaches threshold.

For PRIC-leg events the wallet reads its own embedded chainstate
(no backend needed). For BTC/LTC events the wallet queries the
chain-backend registry populated from `-btcwatchurl=` /
`-ltcwatchurl=` / `-chainwatchurl=<chain>=<url>` args at startup.

## Configuration

```
-btcwatchurl=<URL>            BTC Esplora-style HTTPS endpoint.
-ltcwatchurl=<URL>            LTC Esplora-style HTTPS endpoint.
-chainwatchurl=<chain>=<URL>  Repeatable; register additional chains.
-pricoinswapwatch=<0|1>       Auto-start watcher per wallet on load
                              (default 1).
-pricoinswapwatch_interval=<sec>
                              Poll interval (default 30; clamped 1-3600).
```

Public Esplora endpoints (mempool.space, blockstream.info) work
out of the box. For self-hosted setups, run [Blockstream's
electrs+esplora](https://github.com/Blockstream/electrs) against
your own Bitcoin Core node.

Example:

```
pricoind \
  -btcwatchurl=https://mempool.space/api \
  -ltcwatchurl=https://litecoinspace.org/api \
  -pricoinswapwatch_interval=30
```

## RPC surface

The wallet exposes 9 RPCs in the `pricoin_swapwatch_*` namespace:

| RPC | Purpose |
|-----|---------|
| `pricoin_swapwatch_add(swap_id, kind, txid, [vout], [min_conf])` | Register a pending watch. |
| `pricoin_swapwatch_remove(swap_id, kind)` | Drop a pending watch. Idempotent. |
| `pricoin_swapwatch_list()` | Snapshot all pending watches. |
| `pricoin_swapwatch_start([interval_sec])` | Start the polling thread. |
| `pricoin_swapwatch_stop()` | Stop the polling thread. |
| `pricoin_swapwatch_status()` | `{running, pending_entries}`. |
| `pricoin_swapwatch_tick_once()` | Drive a single tick synchronously (testing). |
| `pricoin_swapwatch_notify(swap_id, kind, txid, [vout], [height])` | Manual external-script push: apply the matching `Set…` directly. |
| `pricoin_swapwatch_broadcast_foreign(swap_id, kind, tx_hex, [min_conf])` | Atomic broadcast + watch-register for the BTC/LTC leg. |
| `pricoin_swapwatch_broadcast_pric(swap_id, kind, tx_hex, sig_hex, [vout], [min_conf])` | Atomic broadcast + watch-register for the PRIC leg. |

`kind` is one of:

```
foreign_funding   → triggers SetBtcFunded   when confirmed
pric_funding      → triggers SetPricFunded  when confirmed
pric_claim        → triggers SetPricClaimed when confirmed
foreign_claim     → triggers SetComplete    when confirmed
pric_refund       → triggers SetRefunded    (PRIC leg)
foreign_refund    → triggers SetRefunded    (foreign leg)
```

## Nostr DM auto-watch

When the cooperative-sign flow is used over Nostr DM, peers can
announce broadcasts to each other so the receiver auto-adds a
watch entry without manual paste:

Envelope (encrypted via NIP-04, kind=4):

```json
{"v":1,"type":"tx_announce",
 "swap_id":"<32-byte hex>","kind":"<WatchKind>",
 "txid":"<32-byte hex>","vout":N,"min_confirmations":N}
```

The receiver's `WalletModel` cross-checks the sender's xonly
against the swap's `counterparty_pubkey` — only the counterparty
can announce, so a stranger DM'ing a forged announcement is
silently dropped.

`PricoinNostrClient::publishBroadcastAnnouncement(...)` is the
wallet-facing helper that builds and sends this envelope.

## Backoff

If a foreign-chain backend is unreachable, the watcher records
the error timestamp and skips queries for that chain for **60
seconds** before retrying. PRIC-leg watches are unaffected (they
read the embedded chainstate).

This protects the backend from being hammered every poll
interval when the relay is down or the network drops.

## Persistence

Pending watch entries live in the wallet DB under DBKey
`pct_chain_watch`, keyed by `SHA256(swap_id || kind_byte)`,
encrypted at rest via the existing `EncryptWalletBlob` pattern.

Entries survive `unloadwallet`/`loadwallet` and daemon restart.
On startup, the watcher's polling thread auto-starts per wallet
(unless `-pricoinswapwatch=0`).

## Threat model notes

* **Trust assumption**: the foreign-chain backend is trusted to
  return honest tx-status answers. A malicious Esplora could
  lie about confirmations and trick the watcher into advancing
  prematurely. Mitigations:
  * Run your own indexer (`electrs+esplora-electrs` against your
    own Bitcoin Core node) for high-value swaps.
  * Use `min_confirmations` ≥ 6 on mainnet.

* **Nostr announcements** are authenticated (BIP340 sig over the
  event id, plus counterparty xonly cross-check), but the txid
  is just a string the peer sent — they could announce a junk
  txid that the watcher polls forever. Cost is one DB row + the
  per-tick poll; the entry never advances state because the txid
  isn't real, and the user can `pricoin_swapwatch_remove` it.

* The watcher itself never broadcasts or signs — it only reads
  chain state and calls `Set…` transitions. The signing/broadcast
  side stays under explicit user/dialog control.
