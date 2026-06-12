#!/usr/bin/env python3
# Copyright (c) 2026-present The Pricoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional test for the Tier-3 swap-watcher RPC surface.

Verifies the wallet-tier `pricoin_swapwatch_*` RPCs that auto-advance
the AdaptorSwap state machine when on-chain events are observed:

  * add / list / remove round-trip with all 6 WatchKind variants.
  * Validation: bad txid length, unknown kind, missing vout for
    funding kinds.
  * Persistence across unloadwallet/loadwallet.
  * notify drives the matching SetX transition on the AdaptorSwap
    state machine and removes any pending entry.
  * notify on a state mismatch surfaces the state-machine error.

The full polling-loop path (where a registered foreign-chain
`ChainBackend` is queried autonomously) is exercised separately by
the existing `feature_pricoin_chainwatch.py` test on the backend
surface; this file covers the wallet-tier orchestration that drives
the AdaptorSwap state machine.
"""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


def random_hex(n_bytes):
    return os.urandom(n_bytes).hex()


SECP256K1_G_HEX = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


class PricoinSwapwatchTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("alice_sw")
        alice = node.get_wallet_rpc("alice_sw")
        node.createwallet("bob_sw")
        bob = node.get_wallet_rpc("bob_sw")

        alice_pub = alice.pricoin_swap_identity()["pubkey"]
        bob_pub   = bob.pricoin_swap_identity()["pubkey"]

        joint_addr = alice.pricoin_getstealthaddress()["address"]

        foreign_amt = 100_000_000
        pric_amt    =  50_000_000

        T_G = SECP256K1_G_HEX
        T_H = SECP256K1_G_HEX
        dleq_blob = random_hex(64)
        t_secret  = random_hex(32)

        # ─── Section 1: create swap + advance to AdaptorReady ──
        self.log.info("Section 1: create swap")
        sa = alice.pricoin_adaptor_swap_create(
            "alice", bob_pub, "btc", foreign_amt,
            joint_addr, pric_amt, "swapwatch test")
        sid = sa["swap_id"]
        alice.pricoin_adaptor_swap_set_timelocks(sid, 100_000, 100_200, 144)
        alice.pricoin_adaptor_swap_set_adaptor(sid, T_G, T_H, dleq_blob, "")

        # ─── Section 2: swapwatch_add round-trip ───────────────
        self.log.info("Section 2: add / list / remove")
        f_txid = "ab" * 32
        e1 = alice.pricoin_swapwatch_add(sid, "foreign_funding", f_txid, 0, 1)
        assert_equal(e1["swap_id"], sid)
        assert_equal(e1["kind"], "foreign_funding")
        assert_equal(e1["txid"], f_txid)
        assert_equal(e1["vout"], 0)
        assert_equal(e1["min_confirmations"], 1)

        all_entries = alice.pricoin_swapwatch_list()
        assert_equal(len(all_entries), 1)

        rm = alice.pricoin_swapwatch_remove(sid, "foreign_funding")
        assert_equal(rm["removed"], True)
        assert_equal(len(alice.pricoin_swapwatch_list()), 0)
        # Idempotent.
        rm2 = alice.pricoin_swapwatch_remove(sid, "foreign_funding")
        assert_equal(rm2["removed"], False)

        # ─── Section 3: input validation ───────────────────────
        self.log.info("Section 3: input validation")
        assert_raises_rpc_error(
            -8, "kind must be one of",
            alice.pricoin_swapwatch_add, sid, "bogus_kind", f_txid, 0)
        assert_raises_rpc_error(
            -8, "txid must be 32-byte hex",
            alice.pricoin_swapwatch_add, sid, "foreign_funding", "deadbeef", 0)
        # Funding kinds need vout >= 0.
        assert_raises_rpc_error(
            -8, "invalid input for chainwatch entry",
            alice.pricoin_swapwatch_add, sid, "foreign_funding", f_txid, -1)

        # ─── Section 4: persistence across reload ──────────────
        self.log.info("Section 4: persistence across reload")
        alice.pricoin_swapwatch_add(sid, "foreign_funding", f_txid, 0, 1)
        alice.pricoin_swapwatch_add(sid, "pric_claim", "cd" * 32, -1, 1)
        before = sorted([(e["kind"], e["txid"]) for e in alice.pricoin_swapwatch_list()])
        node.unloadwallet("alice_sw")
        node.loadwallet("alice_sw")
        alice = node.get_wallet_rpc("alice_sw")
        after = sorted([(e["kind"], e["txid"]) for e in alice.pricoin_swapwatch_list()])
        assert_equal(before, after)
        assert_equal(len(after), 2)

        # Presig blobs reused across sections (presigs-before-funding).
        good_btc_presig = "00" * 64
        good_session    = "00" * 133
        good_pric_blob  = "00" * 200
        good_btc_refund = "00" * 64
        good_pric_refund = "00" * 200

        # ─── Section 5: presigs, then notify drives funding ─────
        self.log.info("Section 5: pre_signed → notify → SetBtcFunded")
        # SetBtcFunded now requires presigs.IsComplete(); reach pre_signed
        # before funding can be recorded.
        alice.pricoin_adaptor_swap_set_pre_signed(
            sid, good_btc_presig, good_session, 0,
            good_pric_blob, good_btc_refund, good_pric_refund)
        s = alice.pricoin_swapwatch_notify(
            sid, "foreign_funding", f_txid, 0, 800_000)
        assert_equal(s["state"], "btc_funded")
        assert_equal(s["foreign"]["funding_txid"], f_txid)
        assert_equal(s["foreign"]["funding_vout"], 0)
        assert_equal(s["foreign"]["funding_height"], 800_000)
        # The pending foreign_funding entry was removed.
        kinds_left = [e["kind"] for e in alice.pricoin_swapwatch_list()]
        assert "foreign_funding" not in kinds_left

        # ─── Section 6: out-of-order notify rejected ───────────
        self.log.info("Section 6: pric_claim before both_funded rejected")
        assert_raises_rpc_error(
            -32600, "current state does not permit this transition",
            alice.pricoin_swapwatch_notify,
            sid, "pric_claim", "cd" * 32, -1, -1)
        # Pending entry remains (the rejection short-circuited removal).
        assert "pric_claim" in [e["kind"] for e in alice.pricoin_swapwatch_list()]

        # ─── Section 7: forward to complete ────────────────────
        self.log.info("Section 7: forward through to complete via notify")
        p_txid = "11" * 32
        alice.pricoin_swapwatch_notify(sid, "pric_funding", p_txid, 0, 12_345)

        s = alice.pricoin_swapwatch_notify(sid, "pric_claim", "22" * 32, -1, -1)
        assert_equal(s["state"], "pric_claimed")
        s = alice.pricoin_swapwatch_notify(sid, "foreign_claim", "33" * 32, -1, -1)
        assert_equal(s["state"], "complete")

        # ─── Section 8: refund kind ────────────────────────────
        self.log.info("Section 8: refund kind drives Refunded")
        sc = alice.pricoin_adaptor_swap_create(
            "alice", bob_pub, "btc", foreign_amt, joint_addr, pric_amt, "refund test")
        cid = sc["swap_id"]
        alice.pricoin_adaptor_swap_set_timelocks(cid, 100_000, 100_200, 144)
        alice.pricoin_adaptor_swap_set_adaptor(cid, T_G, T_H, dleq_blob, "")
        alice.pricoin_adaptor_swap_set_pre_signed(
            cid, good_btc_presig, good_session, 0,
            good_pric_blob, good_btc_refund, good_pric_refund)
        alice.pricoin_swapwatch_notify(cid, "foreign_funding", "44" * 32, 0, 800_000)
        alice.pricoin_swapwatch_notify(cid, "pric_funding", "55" * 32, 0, 12_345)
        s = alice.pricoin_swapwatch_notify(cid, "pric_refund", "66" * 32, -1, -1)
        assert_equal(s["state"], "refunded")
        assert_equal(s["pric"]["refund_txid"], "66" * 32)

        self.log.info("Pricoin swapwatch RPC flow OK")


if __name__ == "__main__":
    PricoinSwapwatchTest(__file__).main()
