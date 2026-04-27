Pricoin
=======

> **Status: experimental fork.** Bugs in confidential
> transactions or ring signatures can break privacy *silently* without breaking
> consensus. Pricoin is a fork of Bitcoin Core 31.0.

Pricoin (ticker **PRIC**) is a Bitcoin Core fork that swaps Bitcoin's
transparent transactions for a privacy-mandatory model inspired by Monero:
Pedersen commitments hide values, dual-key stealth addresses hide
recipients, and CLSAG ring signatures hide senders. Coinbase (mining
rewards) stays transparent so total emission remains auditable; every
non-coinbase transaction must be a v4 confidential transaction.

What's different from Bitcoin Core
----------------------------------

| Aspect | Bitcoin Core | Pricoin |
|---|---|---|
| Sender privacy | None (addresses are public) | CLSAG ring signatures, fixed ring size 16 |
| Recipient privacy | Reusable address visible on chain | Dual-key stealth address; one-time output script per payment |
| Amount privacy | Cleartext `nValue` per output | Pedersen commitment + Borromean rangeproof |
| Tx version | 1, 2, 3 | **4 only** (coinbase excepted) |
| Block time | 600 s | 150 s |
| Halving interval | 210,000 blocks | 840,000 blocks (preserves ~4-year cadence) |
| Proof of work | SHA-256d | RandomX (CPU-friendly) |
| Pruning | Supported | (Phase 3 — pending) |
| HRP | `bc` / `tb` / `bcrt` | `pric` / `tpric` / `pricrt` |
| Magic / ports | Bitcoin's | Pricoin-specific |

Quick start
-----------

```bash
# 1. Build (Linux, depends static)
cd depends && make HOST=x86_64-pc-linux-gnu NO_QR=1
cd ..
cmake -S . -B build --toolchain depends/x86_64-pc-linux-gnu/toolchain.cmake -DBUILD_GUI=ON -DWITH_QRENCODE=OFF
cmake --build build -j

# 2. Run regtest
build/bin/pricoind -regtest -datadir=/tmp/pricoin -daemon
build/bin/pricoin-cli -regtest -datadir=/tmp/pricoin -rpcwait getblockcount

# 3. Three-wallet end-to-end demo (transparent → CT → ring CT)
CLI="build/bin/pricoin-cli -regtest -datadir=/tmp/pricoin"
$CLI createwallet alice
$CLI createwallet bob
$CLI createwallet carol

# Mine to alice (transparent coinbase)
$CLI generatetoaddress 110 "$($CLI -rpcwallet=alice getnewaddress '' bech32)"

# alice → bob: transparent input → confidential output (stealth)
BOB=$($CLI -rpcwallet=bob pricoin_getstealthaddress | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"])')
$CLI -rpcwallet=alice walletsendct "$BOB" 25.0 0.0001
$CLI generatetoaddress 1 "$($CLI -rpcwallet=alice getnewaddress)"

# bob recovers via stealth scan
$CLI -rpcwallet=bob pricoin_listownct 0
```

For a full ring-signed (sender-private) spend of bob's CT output, see
[`doc/build-pricoin.md`](doc/build-pricoin.md).

Build
-----

- **Linux / depends static (recommended for releases):** see
  [`doc/build-pricoin.md`](doc/build-pricoin.md).
- **Linux / system packages (faster, less portable):** see
  [`doc/build-unix.md`](doc/build-unix.md), with the lprodump fix noted
  in `doc/build-pricoin.md`.
- **macOS / Windows:** the CI workflow at `.github/workflows/release.yml`
  is the authoritative reference. macOS uses Homebrew Qt6; Windows
  cross-compiles from Linux via `depends/`.

Privacy model in three sentences
--------------------------------

1. **Confidential amounts.** Each v4 output stores a Pedersen
   commitment `C = v·H + b·G` where `v` is the value and `b` is a
   secret blinding factor. A Borromean rangeproof asserts `0 ≤ v < 2^64`
   without revealing `v`.

2. **Stealth addresses.** A long-lived public identity encodes two
   pubkeys: view `A = a·G` and spend `B = b·G`. Each payment derives a
   fresh one-time output pubkey `P' = H(a·R || i)·G + B` where `R` is a
   per-tx ephemeral pubkey published in the bundle. Two payments to the
   same identity look uncorrelated to anyone without the view key `a`.

3. **Ring signatures.** A v4 input references `N = 16` ring candidates
   (one is the real spender, the rest are decoys drawn from prior chain
   outputs). A multi-layer CLSAG signature proves "the signer owns the
   private key for one of these N candidates" without revealing which,
   and publishes a key image `I = x · H_p(P)` that the consensus rules
   reject if it has been seen before — preventing double-spends.

JSON-RPC commands of interest
-----------------------------

| Command | What it does |
|---|---|
| `walletsendct DEST AMT FEE` | Build, sign, broadcast a v4 CT tx with one transparent input |
| `walletsendct_ring DEST AMT FEE [RING]` | Same but with a CLSAG ring (sender privacy). Funded from a recovered CT output. |
| `walletsendct_from_ct PREVOUT VOUT DEST AMT FEE` | Direct CT-to-CT spend (no ring) |
| `pricoin_getstealthaddress` | Return this wallet's reusable stealth identity |
| `pricoin_listownct [STARTHEIGHT]` | Scan chain for confidential outputs paid to this wallet |

Transparent send RPCs (`sendtoaddress`, `sendmany`, `send`, `sendall`,
`bumpfee`, `psbtbumpfee`) are stubbed and return
`RPC_METHOD_DEPRECATED (-32)` — Pricoin enforces v4-only at consensus.

License
-------

MIT. See [COPYING](COPYING).

Pricoin is derived from [Bitcoin Core](https://github.com/bitcoin/bitcoin)
and inherits its license. Vendored libraries:

- `src/secp256k1/` — [BlockstreamResearch/secp256k1-zkp](https://github.com/BlockstreamResearch/secp256k1-zkp) (MIT)
- `src/crypto/randomx/` — [tevador/RandomX](https://github.com/tevador/RandomX) (BSD-3-Clause)
