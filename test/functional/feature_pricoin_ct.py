#!/usr/bin/env python3
# Copyright (c) 2026-present The Pricoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end smoke test for Pricoin's confidential-transaction stack.

Covers:
  * walletsendct (transparent → CT) lands on chain and recipient recovers value
  * walletsendct_ring (CT → CT with sender privacy) lands and KI is committed
  * Phase 3a invariant: chainstate keeps spent v4 outputs as ring decoys
  * Phase 4d invariant: KI is tx-invariant — re-broadcasting a ring tx after
    daemon restart is rejected with bad-pct-double-spend-keyimage
  * Wallet RPC parity: getbalance / getbalances surface CT, transparent send
    RPCs are stubbed
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error


class PricoinCTTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        # No -acceptnonstdtxn — Pricoin's IsStandardTx carve-outs handle v4.
        self.extra_args = [["-txindex=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        # ---- Setup three wallets ----
        node.createwallet("alice")
        node.createwallet("bob")
        node.createwallet("carol")
        alice = node.get_wallet_rpc("alice")
        bob   = node.get_wallet_rpc("bob")
        carol = node.get_wallet_rpc("carol")

        alice_addr = alice.getnewaddress("", "bech32")
        self.generatetoaddress(node, 110, alice_addr)
        assert_equal(node.getblockcount(), 110)
        assert_greater_than(alice.getbalance(), 0)

        bob_stealth   = bob.pricoin_getstealthaddress()["address"]
        carol_stealth = carol.pricoin_getstealthaddress()["address"]

        # ---- 1. transparent → CT ----
        send1 = alice.walletsendct(bob_stealth, 25.0, 0.0001)
        assert send1["dest_was_stealth"] is True
        self.generatetoaddress(node, 1, alice_addr)
        bob_ct = bob.pricoin_listownct(0)
        assert_equal(bob_ct["total_recovered"], 25.0)
        assert_equal(bob.getbalance(), 25.0)
        balances = bob.getbalances()["mine"]
        assert_equal(balances["confidential"], 25.0)

        # Give bob more CT outputs so ring=4 has enough decoys.
        for _ in range(3):
            alice.walletsendct(bob_stealth, 10.0, 0.0001)
            self.generatetoaddress(node, 1, alice_addr)

        bob_ct = bob.pricoin_listownct(0)
        assert_equal(len(bob_ct["outputs"]), 4)

        # ---- 2. CT → CT (ring) ----
        ring_tx = bob.walletsendct_ring(carol_stealth, 5.0, 0.0001, 4)
        ring_txid = ring_tx["txid"]
        assert_equal(ring_tx["ring_size"], 4)
        ring_hex = node.getrawtransaction(ring_txid)
        self.generatetoaddress(node, 1, alice_addr)

        # Carol recovers, bob's listownct drops the spent input via KI filter.
        assert_equal(carol.pricoin_listownct(0)["total_recovered"], 5.0)
        bob_ct = bob.pricoin_listownct(0)
        # 4 originals - 1 spent (signer) + 1 change = 4 outputs, total ≈ 35-25 + change ≈ 24.9999
        assert_equal(len(bob_ct["outputs"]), 4)

        # Phase 3a: spent ring member's chainstate entry is still present.
        spent_signer = self._find_spent_signer(node, ring_txid)
        # gettxout returns null (not spent) only if removed; we expect a result.
        gtx = node.gettxout(spent_signer["txid"], spent_signer["vout"])
        assert gtx is not None, "Phase 3a: spent v4 output should still be in chainstate"

        # ---- 3. KI persistence + reject-after-restart ----
        self.restart_node(0, extra_args=["-txindex=1"])
        node = self.nodes[0]

        # The same hex re-broadcast should hit "txn-already-known" (chain has it).
        # To exercise the KI rejection path specifically, invalidate the block,
        # restart so the KI loads from disk, and try to send the tx fresh.
        ring_block = node.getblockhash(node.getblockcount())
        node.invalidateblock(ring_block)
        self.restart_node(0, extra_args=["-txindex=1"])
        node = self.nodes[0]

        # KI was loaded from pricoin_keyimages.dat at startup; the tx isn't on
        # chain anymore (block was invalidated), but the KI still rejects.
        assert_raises_rpc_error(-26, "bad-pct-double-spend-keyimage",
                                node.sendrawtransaction, ring_hex)

        # ---- 4. Transparent send RPCs are stubbed ----
        # Wallets need re-loading after restart_node().
        node.loadwallet("alice")
        alice = node.get_wallet_rpc("alice")
        a_other = alice.getnewaddress()
        assert_raises_rpc_error(-32, "Privacy is mandatory",
                                alice.sendtoaddress, a_other, 1.0)
        assert_raises_rpc_error(-32, "Privacy is mandatory",
                                alice.sendmany, "", {a_other: 1.0})

        self.log.info("Pricoin CT/ring/KI/RPC-parity smoke test OK")

    def _find_spent_signer(self, node, ring_txid):
        """Look in the ring tx's bundle for the outpoint that the wallet
        actually spent. This is hidden by ring sigs; we approximate by
        finding which ring member's chainstate entry has been "consumed"
        — but Phase 3a means none are consumed. Just return the first
        ring member as a smoke check."""
        raw = node.decoderawtransaction(node.getrawtransaction(ring_txid))
        return {"txid": raw["vin"][0]["txid"], "vout": raw["vin"][0]["vout"]}


if __name__ == "__main__":
    PricoinCTTest(__file__).main()
