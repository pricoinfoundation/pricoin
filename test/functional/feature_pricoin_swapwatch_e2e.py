#!/usr/bin/env python3
# Copyright (c) 2026-present The Pricoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end test for the Tier-3 autonomous swap watcher.

Spins up a fake Esplora HTTP server (same shape as
feature_pricoin_chainwatch.py) and points the daemon at it via
-btcwatchurl=. Registers a `foreign_funding` swap-watch entry,
then drives `pricoin_swapwatch_tick_once` and verifies the
AdaptorSwap state machine auto-advances when the fake server
reports the tx as confirmed.

Covers:
  * Synchronous tick path drives BtcFunded transition end-to-end.
  * Insufficient confirmations → entry stays pending (no transition).
  * Tx not found on backend → entry stays pending (transient).
  * Pending entry pruned after successful transition.
"""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)


def random_hex(n_bytes):
    return os.urandom(n_bytes).hex()


SECP256K1_G_HEX = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


class _FakeEsploraHandler(BaseHTTPRequestHandler):
    """Minimal Esplora subset: tip height + tx status + tx hex."""
    server_version = "FakeEsplora-SW/0.1"

    state = {
        "height": 1234,
        "txs": {},  # txid_hex → status dict
    }

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        path = self.path
        if path == "/blocks/tip/height":
            return self._reply_text(200, str(self.state["height"]))
        if path.startswith("/tx/"):
            rest = path[len("/tx/"):]
            if "/" in rest:
                txid, suffix = rest.split("/", 1)
                tx = self.state["txs"].get(txid)
                if tx is None:
                    return self._reply_text(404, "tx not found")
                if suffix == "hex":
                    return self._reply_text(200, "deadbeef" * 4)
                if suffix == "status":
                    return self._reply_json(200, tx["status"])
                return self._reply_text(404, "unknown subpath")
        return self._reply_text(404, "not found")

    def do_POST(self):
        return self._reply_text(404, "not supported in this test")

    def _reply_text(self, status, body):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _reply_json(self, status, obj):
        encoded = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class PricoinSwapwatchE2ETest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        # Bind fake Esplora to a free port and pass it to the node
        # via -btcwatchurl so the chain-backend registry is populated
        # at daemon init.
        self.fake_server = ThreadingHTTPServer(
            ("127.0.0.1", 0), _FakeEsploraHandler)
        self.fake_port = self.fake_server.server_address[1]
        self.fake_thread = threading.Thread(target=self.fake_server.serve_forever)
        self.fake_thread.daemon = True
        self.fake_thread.start()
        self.log.info(f"Fake Esplora listening on 127.0.0.1:{self.fake_port}")

        url = f"http://127.0.0.1:{self.fake_port}"
        self.extra_args = [[f"-btcwatchurl={url}"]]
        super().setup_network()

    def shutdown_network(self):
        try:
            self.fake_server.shutdown()
            self.fake_server.server_close()
        except Exception:
            pass

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("alice_e2e")
        alice = node.get_wallet_rpc("alice_e2e")
        node.createwallet("bob_e2e")
        bob = node.get_wallet_rpc("bob_e2e")

        bob_pub = bob.pricoin_swap_identity()["pubkey"]
        joint_addr = alice.pricoin_getstealthaddress()["address"]

        T_G = SECP256K1_G_HEX
        T_H = SECP256K1_G_HEX
        dleq_blob = random_hex(64)

        # ─── Section 1: create swap, advance to AdaptorReady ────
        self.log.info("Section 1: create swap")
        sa = alice.pricoin_adaptor_swap_create(
            "alice", bob_pub, "btc", 100_000_000,
            joint_addr, 50_000_000, "swapwatch e2e")
        sid = sa["swap_id"]
        alice.pricoin_adaptor_swap_set_timelocks(sid, 100_000, 100_200, 144)
        alice.pricoin_adaptor_swap_set_adaptor(sid, T_G, T_H, dleq_blob, "")
        # Presigs before funding (the watcher's SetBtcFunded now requires
        # presigs.IsComplete()) — so reach pre_signed before the funding
        # watch can advance the swap.
        alice.pricoin_adaptor_swap_set_pre_signed(
            sid, random_hex(64), random_hex(133), 0,
            random_hex(120), random_hex(64), random_hex(160))

        # ─── Section 2: register watch + tick on tx-not-found ───
        # Backend returns 404 → entry stays pending.
        self.log.info("Section 2: tick with tx not in backend")
        f_txid = "11" * 32
        alice.pricoin_swapwatch_add(sid, "foreign_funding", f_txid, 0, 1)
        r = alice.pricoin_swapwatch_tick_once()
        assert_equal(r["pending_after"], 1)
        assert_equal(alice.pricoin_adaptor_swap_get(sid)["state"], "pre_signed")

        # ─── Section 3: tx exists but unconfirmed → pending ─────
        self.log.info("Section 3: tick with unconfirmed tx")
        _FakeEsploraHandler.state["txs"][f_txid] = {
            "status": {"confirmed": False}
        }
        r = alice.pricoin_swapwatch_tick_once()
        assert_equal(r["pending_after"], 1)
        assert_equal(alice.pricoin_adaptor_swap_get(sid)["state"], "pre_signed")

        # ─── Section 4: tx confirmed at depth 5 (tip 1234, block 1230)
        # → 5 confirmations ≥ min_confirmations=1 → transition fires.
        self.log.info("Section 4: tick with confirmed tx → BtcFunded")
        _FakeEsploraHandler.state["txs"][f_txid] = {
            "status": {
                "confirmed": True,
                "block_height": 1230,
                "block_hash": "00" * 32,
                "block_time": 1700000000,
            }
        }
        r = alice.pricoin_swapwatch_tick_once()
        # Entry consumed; swap advanced to btc_funded.
        assert_equal(r["pending_after"], 0)
        s = alice.pricoin_adaptor_swap_get(sid)
        assert_equal(s["state"], "btc_funded")
        assert_equal(s["foreign"]["funding_txid"], f_txid)
        assert_equal(s["foreign"]["funding_vout"], 0)
        assert_equal(s["foreign"]["funding_height"], 1230)

        # ─── Section 5: status RPC reports state ────────────────
        self.log.info("Section 5: status RPC")
        st = alice.pricoin_swapwatch_status()
        assert_equal(st["running"], False)  # we used tick_once, not start
        assert_equal(st["pending_entries"], 0)

        # Start the polling thread (just to verify lifecycle works).
        alice.pricoin_swapwatch_start(1)
        st = alice.pricoin_swapwatch_status()
        assert_equal(st["running"], True)
        alice.pricoin_swapwatch_stop()
        st = alice.pricoin_swapwatch_status()
        assert_equal(st["running"], False)

        # ─── Section 6: min_confirmations gate ──────────────────
        # Set tip back to a value where the tx has 0 confirmations
        # (block_height > tip), then bump tip just enough.
        self.log.info("Section 6: min_confirmations gate")
        # Add a fresh swap to test against.
        sb = alice.pricoin_adaptor_swap_create(
            "alice", bob_pub, "btc", 100_000_000,
            joint_addr, 50_000_000, "swapwatch e2e b")
        bid = sb["swap_id"]
        alice.pricoin_adaptor_swap_set_timelocks(bid, 100_000, 100_200, 144)
        alice.pricoin_adaptor_swap_set_adaptor(bid, T_G, T_H, dleq_blob, "")
        alice.pricoin_adaptor_swap_set_pre_signed(
            bid, random_hex(64), random_hex(133), 0,
            random_hex(120), random_hex(64), random_hex(160))

        f2_txid = "22" * 32
        # min_confirmations=6
        alice.pricoin_swapwatch_add(bid, "foreign_funding", f2_txid, 0, 6)
        # Tx confirmed at depth 5 (1234 - 1230 + 1 = 5). 5 < 6 → no transition.
        _FakeEsploraHandler.state["txs"][f2_txid] = {
            "status": {
                "confirmed": True,
                "block_height": 1230,
                "block_hash": "00" * 32,
                "block_time": 1700000000,
            }
        }
        r = alice.pricoin_swapwatch_tick_once()
        assert_equal(r["pending_after"], 1)
        assert_equal(alice.pricoin_adaptor_swap_get(bid)["state"], "pre_signed")

        # Bump tip so the same tx now has 6 confirmations.
        _FakeEsploraHandler.state["height"] = 1235
        r = alice.pricoin_swapwatch_tick_once()
        assert_equal(r["pending_after"], 0)
        assert_equal(alice.pricoin_adaptor_swap_get(bid)["state"], "btc_funded")

        self.log.info("Pricoin swapwatch e2e (autonomous poll path) OK")


if __name__ == "__main__":
    PricoinSwapwatchE2ETest(__file__).main()
