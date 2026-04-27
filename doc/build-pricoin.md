Building Pricoin
================

Pricoin is a fork of Bitcoin Core. Most of `doc/build-*.md` still applies,
but a few things differ. This file documents the deltas. The
authoritative build reference is the CI workflow at
`.github/workflows/release.yml` — if you can reproduce what that does
locally, you'll get the same binary.

Prerequisites
-------------

### Ubuntu 22.04 / Debian 12

System toolchain:

```bash
sudo apt-get install -y \
    build-essential cmake make pkgconf python3 \
    curl wget bison patch xz-utils ca-certificates \
    autoconf automake libtool gettext
```

That's all you need for the **`depends/`-static** build path
(recommended; what release artifacts are built with). For a
**system-packages** build you also need:

```bash
sudo apt-get install -y \
    libssl-dev libevent-dev libsqlite3-dev libboost-dev \
    libzmq3-dev libgl-dev \
    qt6-base-dev qt6-base-dev-tools qt6-tools-dev qt6-l10n-tools \
    qttools5-dev-tools
```

#### lprodump workaround (system-packages build only)

Ubuntu 22.04's `qt6-tools-dev` is missing the `lprodump` binary that
Qt6's `find_package(LinguistTools)` references. The qt5 package ships a
compatible binary; symlink it where Qt6 expects it:

```bash
sudo ln -sf /usr/lib/qt5/bin/lprodump /usr/lib/qt6/libexec/lprodump
```

If you skip this, cmake will fail with `Could NOT find Qt
(missing: Qt6_FOUND)`.

### macOS

```bash
brew install cmake ninja boost libevent qt@6 sqlite zeromq pkgconf
```

Then point cmake at Homebrew's prefix when configuring:

```bash
export CMAKE_PREFIX_PATH="$(brew --prefix qt@6):$(brew --prefix sqlite):$(brew --prefix libevent):$(brew --prefix zeromq):$(brew --prefix boost)"
cmake -S . -B build -DBUILD_GUI=ON -DWITH_QRENCODE=OFF
cmake --build build -j "$(sysctl -n hw.ncpu)"
```

### Windows (cross-compile from Linux, recommended)

```bash
sudo apt-get install -y \
    g++-mingw-w64-x86-64-posix gcc-mingw-w64-x86-64-posix \
    mingw-w64
sudo update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix
sudo update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix

cd depends && make -j"$(nproc)" HOST=x86_64-w64-mingw32 NO_QR=1
cd ..
cmake -S . -B build \
    --toolchain depends/x86_64-w64-mingw32/toolchain.cmake \
    -DBUILD_GUI=ON -DWITH_QRENCODE=OFF
cmake --build build -j"$(nproc)"
# Output: build/bin/pricoin-qt.exe
```

Build paths
-----------

### A. depends-static (recommended)

Mirror what CI does. Statically links Qt, Boost, libevent, sqlite, zmq,
and the X/xcb stack — the result runs on any glibc-compatible Linux
without runtime Qt6 / Boost / libevent / libssl version concerns.

```bash
cd depends && make -j"$(nproc)" HOST=x86_64-pc-linux-gnu NO_QR=1
cd ..
cmake -S . -B build \
    --toolchain depends/x86_64-pc-linux-gnu/toolchain.cmake \
    -DBUILD_GUI=ON -DWITH_QRENCODE=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
strip build/bin/pricoind build/bin/pricoin-cli build/bin/pricoin-qt
```

Cold build is ~30–45 minutes. Subsequent builds (under `depends/built`)
are minutes.

### B. system-packages (fast iteration)

```bash
cmake -S . -B build_pric -DBUILD_GUI=ON -DWITH_QRENCODE=OFF
cmake --build build_pric -j"$(nproc)"
```

What you give up: portability — the binary depends on whatever Qt6,
libssl, libevent, libsqlite3, libboost-system, libzmq, libdbus,
libstdc++ and glibc you have installed. It will refuse to start on a
machine that's even one `.so` minor version off.

### C. Wallet-disabled / daemon-only (smallest)

```bash
cmake -S . -B build -DBUILD_GUI=OFF -DENABLE_WALLET=OFF
cmake --build build -j
```

You get just `pricoind` and `pricoin-cli`. Useful for nodes that just
relay/validate.

End-to-end CT demo (regtest)
----------------------------

```bash
CLI="build/bin/pricoin-cli -regtest -datadir=/tmp/pricoin"

# Start daemon (no flags needed — Pricoin doesn't require -acceptnonstdtxn)
build/bin/pricoind -regtest -datadir=/tmp/pricoin -daemon
$CLI -rpcwait getblockcount

# Three wallets
$CLI createwallet alice
$CLI createwallet bob
$CLI createwallet carol

ALICE=$($CLI -rpcwallet=alice getnewaddress "" bech32)
$CLI generatetoaddress 110 "$ALICE"          # mine 110 blocks → coinbase to alice

BOB=$($CLI -rpcwallet=bob   pricoin_getstealthaddress | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"])')
CAROL=$($CLI -rpcwallet=carol pricoin_getstealthaddress | python3 -c 'import json,sys; print(json.load(sys.stdin)["address"])')

# Step 1: alice → bob, transparent input → CT output
$CLI -rpcwallet=alice walletsendct "$BOB" 25.0 0.0001
$CLI generatetoaddress 1 "$ALICE"
$CLI -rpcwallet=bob pricoin_listownct 0      # bob recovers 25 PRIC

# Step 2: alice gives bob more CT outputs (so he has ring decoys)
for i in 1 2 3; do
    $CLI -rpcwallet=alice walletsendct "$BOB" 10.0 0.0001
    $CLI generatetoaddress 1 "$ALICE"
done

# Step 3: bob → carol, ring-signed CT spend (sender privacy)
$CLI -rpcwallet=bob walletsendct_ring "$CAROL" 5.0 0.0001 4
$CLI generatetoaddress 1 "$ALICE"
$CLI -rpcwallet=carol pricoin_listownct 0    # carol recovers 5 PRIC
```

What is *not* expected to work
------------------------------

| Surface | Status |
|---|---|
| `sendtoaddress`, `sendmany`, `send`, `sendall`, `bumpfee`, `psbtbumpfee` | Stubbed (return `RPC_METHOD_DEPRECATED`); use `walletsendct` / `walletsendct_ring` instead |
| `getbalance`, `listtransactions`, `gettransaction.amount` | Don't reflect CT (transparent-only). Use `pricoin_listownct.total_recovered` for the CT total |
| `BitcoinAddressValidator` (address book / payment URI) | Doesn't recognize `H6…` stealth addresses |
| `-prune` | Phase 3 pending — pruning isn't useful since v4 outputs are needed indefinitely as ring decoys |
| Qt GUI Send tab | CT-aware; takes a stealth address (`H6…`), funds from one transparent UTXO |
| Qt GUI history list | Shows v4 receives via wallet stealth-scan; v4 sends show as `Sent N (confidential — stealth)` |

Toy / educational caveats
-------------------------

- The build is reproducible to the extent that `depends/` is, but
  Pricoin doesn't (yet) wrap a Guix-based reproducible build like
  Bitcoin Core does for releases. Two builds on different days, even
  with `depends/`, are not bit-identical.
- Bugs in the CT or CLSAG code paths can break privacy without
  breaking consensus. There is no test suite covering Pricoin-specific
  paths yet.
- Decoy selection is uniform-random over confirmed v4 outputs, not
  gamma-distributed (as Monero recommends). Bad selection has been
  demonstrated to leak in real Monero attacks; do not assume the
  current Pricoin selector is forensically robust.
- The rangeproof construction is Borromean (~1.3 KB / output). A switch
  to Bulletproofs++ is documented in project notes but blocked on
  upstream secp256k1-zkp landing the rangeproof PR + a rewind/decode
  API for recipient scanning.

Tests
-----

Pricoin's privacy-mandatory consensus rule (only v4 confidential txs are
valid for non-coinbase) breaks most of Bitcoin Core's existing functional
test suite — anything that calls `sendtoaddress` / `sendmany` / `send` /
`bumpfee`, builds raw v1/v2 txs, or otherwise assumes transparent flow
will fail.

Run only the Pricoin-relevant subset (skips ~80 known-broken upstream tests):

```bash
ln -sf "$PWD/build_pric/test/config.ini" "$PWD/test/config.ini"
ln -sf "$PWD/test/functional/feature_pricoin_ct.py" \
      "$PWD/build_pric/test/functional/feature_pricoin_ct.py"

BITCOIND=$PWD/build_pric/bin/pricoind \
BITCOINCLI=$PWD/build_pric/bin/pricoin-cli \
python3 test/functional/test_runner.py --pricoin --filter feature_pricoin_ct
```

The `--pricoin` flag adds `PRICOIN_KNOWN_BROKEN` (defined in
`test/functional/test_runner.py`) to `--exclude`. The release CI runs
`feature_pricoin_ct.py` on every Linux build as a smoke gate; broader
re-enabling of upstream tests would require auditing each one for
transparent-flow assumptions.

Project notes & design rationale
--------------------------------

- The fork's design memo lives in the project memory file referenced
  from CLAUDE-style tooling; it covers the phase plan, vendored
  libraries, and consensus changes. Most relevant excerpts are
  duplicated in this file's "What is not expected to work" table.
