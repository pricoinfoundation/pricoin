#!/usr/bin/env python3
# Copyright (c) 2026-present The Pricoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional test for the chainwatch backend abstraction.

Spins up a tiny in-process HTTP server that speaks just enough of the
Esplora REST API for our backend to drive — height, tx hex, tx
status, address history, broadcast — then drives the wallet's
pricoin_chainwatch_* RPCs against it.

Covers:
  * height
  * get_tx (hex + status combined)
  * address_txs (with value-paid-into-address summed across vouts)
  * broadcast
  * Error path: missing tx → backend reports HTTP 404 → RPC returns -1
  * No-backend path: querying an unknown chain returns helpful error.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class FakeEsploraHandler(BaseHTTPRequestHandler):
    """Servlet that satisfies the subset of Esplora endpoints we use."""
    server_version = "FakeEsplora/0.1"

    # Class-level storage so tests can mutate at runtime.
    state = {
        "height": 1234,
        "txs": {
            "ab" * 32: {
                "hex": "0123456789abcdef" * 4,
                "status": {
                    "confirmed": True,
                    "block_height": 1230,
                    "block_hash": "00" * 32,
                    "block_time": 1700000000,
                },
            },
            # Unconfirmed tx — exists, but not in a block.
            "cd" * 32: {
                "hex": "deadbeef" * 4,
                "status": {"confirmed": False},
            },
        },
        # Address history: keyed by address.
        "addresses": {
            "bc1qtest": [
                {
                    "txid": "ab" * 32,
                    "status": {
                        "confirmed": True,
                        "block_height": 1230,
                        "block_hash": "00" * 32,
                        "block_time": 1700000000,
                    },
                    "vout": [
                        {"scriptpubkey_address": "bc1qtest", "value": 50000},
                        {"scriptpubkey_address": "bc1qother", "value": 12345},
                        {"scriptpubkey_address": "bc1qtest", "value": 25000},
                    ],
                },
            ],
        },
        # Last broadcast hex (for assertions).
        "last_broadcast": None,
        # Txid the broadcast endpoint will respond with.
        "broadcast_response_txid": "ef" * 32,
    }

    # Silence per-request log spam.
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
                    return self._reply_text(200, tx["hex"])
                if suffix == "status":
                    return self._reply_json(200, tx["status"])
                return self._reply_text(404, "unknown subpath")
            return self._reply_text(404, "no subpath")
        if path.startswith("/address/"):
            rest = path[len("/address/"):]
            if "/txs" in rest:
                addr = rest.split("/txs", 1)[0]
                txs = self.state["addresses"].get(addr, [])
                return self._reply_json(200, txs)
        return self._reply_text(404, "not found")

    def do_POST(self):
        if self.path == "/tx":
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("ascii", errors="replace").strip()
            self.state["last_broadcast"] = body
            return self._reply_text(200, self.state["broadcast_response_txid"])
        return self._reply_text(404, "not found")

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


class PricoinChainwatchTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        pass  # No wallet needed; chainwatch RPCs are node-level.

    def setup_network(self):
        # Spin up the fake Esplora before starting the node so we can
        # pass -btcwatchurl pointing at it. Bind to 127.0.0.1:0 to
        # let the OS pick a free port.
        self.fake_server = ThreadingHTTPServer(("127.0.0.1", 0), FakeEsploraHandler)
        self.fake_port = self.fake_server.server_address[1]
        self.fake_thread = threading.Thread(target=self.fake_server.serve_forever)
        self.fake_thread.daemon = True
        self.fake_thread.start()
        self.log.info(f"Fake Esplora listening on 127.0.0.1:{self.fake_port}")

        url = f"http://127.0.0.1:{self.fake_port}"
        self.extra_args = [[f"-btcwatchurl={url}",
                            f"-chainwatchurl=ltc={url}"]]
        super().setup_network()

    def shutdown_network(self):
        try:
            self.fake_server.shutdown()
            self.fake_server.server_close()
        except Exception:
            pass

    def run_test(self):
        node = self.nodes[0]

        # ---- list ----
        backends = node.pricoin_chainwatch_list()
        assert "btc" in backends, f"btc not in {backends}"
        assert "ltc" in backends, f"ltc not in {backends}"

        # ---- height ----
        h = node.pricoin_chainwatch_height("btc")
        assert_equal(h["height"], 1234)
        # LTC backend points at the same fake server in this test.
        assert_equal(node.pricoin_chainwatch_height("ltc")["height"], 1234)

        # ---- get_tx (confirmed) ----
        txid = "ab" * 32
        tx = node.pricoin_chainwatch_get_tx("btc", txid)
        assert_equal(tx["hex"], "0123456789abcdef" * 4)
        assert_equal(tx["status"]["confirmed"], True)
        assert_equal(tx["status"]["block_height"], 1230)

        # ---- get_tx (unconfirmed) ----
        tx = node.pricoin_chainwatch_get_tx("btc", "cd" * 32)
        assert_equal(tx["status"]["confirmed"], False)
        assert "block_height" not in tx["status"]

        # ---- get_tx (missing) ----
        assert_raises_rpc_error(
            -1, "404",
            node.pricoin_chainwatch_get_tx, "btc", "00" * 32)

        # ---- address_txs ----
        txs = node.pricoin_chainwatch_address_txs("btc", "bc1qtest")
        assert_equal(len(txs), 1)
        # Two vouts pay bc1qtest: 50000 + 25000 = 75000.
        assert_equal(txs[0]["value_received_sat"], 75000)
        assert_equal(txs[0]["status"]["confirmed"], True)

        # Empty address (no history).
        empty = node.pricoin_chainwatch_address_txs("btc", "bc1qnone")
        assert_equal(empty, [])

        # ---- broadcast ----
        tx_hex = "deadbeefcafebabe"
        result = node.pricoin_chainwatch_broadcast("btc", tx_hex)
        assert_equal(result["txid"], "ef" * 32)
        assert_equal(FakeEsploraHandler.state["last_broadcast"], tx_hex)

        # ---- broadcast with malformed hex rejected client-side ----
        assert_raises_rpc_error(
            -1, "non-hex",
            node.pricoin_chainwatch_broadcast, "btc", "not hex!!!")

        # ---- unknown chain ----
        assert_raises_rpc_error(
            -8, "No chainwatch backend",
            node.pricoin_chainwatch_height, "doge")

        # ---- address with path-control chars rejected ----
        assert_raises_rpc_error(
            -1, "illegal characters",
            node.pricoin_chainwatch_address_txs, "btc", "../etc/passwd")

        self.log.info("Pricoin chainwatch backend test OK")


if __name__ == "__main__":
    PricoinChainwatchTest(__file__).main()
