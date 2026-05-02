#!/usr/bin/env python3
# Copyright (c) 2026-present The Pricoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional test for the Phase-6 orderbook (Tier 1) wallet RPCs.

Single-process test using two wallets (alice + bob) to exercise the
URI signing / verification / duplicate / tamper rejection paths, then
collapses to alice's wallet (holding both her local order and bob's
imported one) for the match/fill/unmatch state-machine tests — each
wallet maintains its own independent view, so a real cross-wallet
flow has each side mirror these operations locally.
"""

import os
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


SAT_PER_PRIC = 100_000_000


class PricoinOfferTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("alice")
        node.createwallet("bob")
        alice = node.get_wallet_rpc("alice")
        bob   = node.get_wallet_rpc("bob")
        alice.pricoin_getstealthaddress()
        bob.pricoin_getstealthaddress()

        future = int(time.time()) + 86400

        # ─── Section 1: empty list, then create ───
        self.log.info("Section 1: empty list, create local order")
        assert_equal(alice.pricoin_offer_list(), [])
        c = alice.pricoin_offer_create(
            "sell_pric", "btc",
            10 * SAT_PER_PRIC, 5 * SAT_PER_PRIC,  # rate = 0.5 BTC per PRIC
            future, "alice's first ask")
        rec = c["record"]
        uri_alice = c["uri"]
        assert uri_alice.startswith("pricoffer:v1/"), "URI scheme"
        assert_equal(rec["origin"], "local")
        assert_equal(rec["status"], "active")
        assert_equal(rec["max_pric_amount_sat"], 10 * SAT_PER_PRIC)
        assert_equal(rec["pric_remaining_sat"], 10 * SAT_PER_PRIC)
        alice_id = rec["order_id"]

        re_export = alice.pricoin_offer_export_uri(alice_id)
        assert_equal(re_export["uri"], uri_alice)

        # ─── Section 2: input validation ───
        self.log.info("Section 2: input validation")
        assert_raises_rpc_error(-8, "amounts and expiry must be > 0",
            alice.pricoin_offer_create, "sell_pric", "btc", 0, 1, future, "")
        assert_raises_rpc_error(-8, "amounts and expiry must be > 0",
            alice.pricoin_offer_create, "sell_pric", "btc", 1, 1, 0, "")
        assert_raises_rpc_error(-8, "side must be",
            alice.pricoin_offer_create, "trade_pric", "btc", 1, 1, future, "")
        assert_raises_rpc_error(-8, "foreign_chain must be",
            alice.pricoin_offer_create, "buy_pric", "xmr", 1, 1, future, "")

        # ─── Section 3: import in counterparty wallet, dup + tamper rejected ───
        self.log.info("Section 3: import in bob's wallet, dup + tamper rejected")
        imported = bob.pricoin_offer_import(uri_alice)
        assert_equal(imported["origin"], "imported")
        assert_equal(imported["order_id"], alice_id)

        assert_raises_rpc_error(-32600, "already in the wallet",
            bob.pricoin_offer_import, uri_alice)

        # Tampered URI: flip a base64 char inside the body. Try a few
        # offsets — at least one will land in a field that breaks
        # signature verification.
        scheme_len = len("pricoffer:v1/")
        rejected = False
        for offset_from_end in (5, 12, 25):
            if offset_from_end >= len(uri_alice) - scheme_len:
                continue
            idx = len(uri_alice) - offset_from_end
            old = uri_alice[idx]
            new = "A" if old != "A" else "B"
            tampered = uri_alice[:idx] + new + uri_alice[idx+1:]
            try:
                bob.pricoin_offer_import(tampered)
            except Exception as e:
                msg = str(e)
                if ("URI did not parse" in msg or
                    "signature does not verify" in msg):
                    rejected = True
                    break
                # If the tamper landed in an inert spot AND signature
                # somehow still verified AND order_id was unchanged → dup.
                # Try the next offset.
        assert rejected, "no tamper offset triggered URI/signature rejection"

        assert_raises_rpc_error(-8, "URI did not parse",
            bob.pricoin_offer_import, "notpricoffer:v1/abcd")

        # ─── Section 4: bob creates a counter-bid; alice imports it ───
        self.log.info("Section 4: bob creates bid, alice imports it")
        c_bob = bob.pricoin_offer_create(
            "buy_pric", "btc",
            10 * SAT_PER_PRIC, 6 * SAT_PER_PRIC,  # bob willing to pay up to 0.6/PRIC
            future, "bob's bid above alice's ask")
        bob_id = c_bob["record"]["order_id"]
        # Alice imports bob's URI so her wallet holds both for matching.
        alice.pricoin_offer_import(c_bob["uri"])
        assert_equal(len(alice.pricoin_offer_list()), 2)

        # ─── Section 5: alice finds matches; bob's URI is the candidate ───
        self.log.info("Section 5: alice finds matches in her own wallet")
        cands = alice.pricoin_offer_find_matches(alice_id)
        assert_equal(len(cands), 1)
        assert_equal(cands[0]["their_order_id"], bob_id)
        assert_equal(cands[0]["max_actual_pric_sat"], 10 * SAT_PER_PRIC)

        # ─── Section 6: alice matches partial in her wallet ───
        self.log.info("Section 6: partial match (4 PRIC of 10)")
        partial = 4 * SAT_PER_PRIC
        m = alice.pricoin_offer_match(alice_id, bob_id, partial)
        assert_equal(m["my_order"]["status"], "matched")
        assert_equal(m["my_order"]["pric_in_flight_sat"], partial)
        assert_equal(m["my_order"]["matched_with_order_id"], bob_id)
        assert_equal(m["their_order"]["status"], "matched")
        assert_equal(m["their_order"]["pric_in_flight_sat"], partial)

        # ─── Section 7: re-match while Matched is rejected ───
        self.log.info("Section 7: re-match while Matched rejected")
        # find_matches doesn't surface Matched orders.
        assert_equal(alice.pricoin_offer_find_matches(alice_id), [])
        # Direct match attempt fails because either side isn't Active.
        # Create a third party offer (alice uses her own 2nd order).
        c3 = alice.pricoin_offer_create(
            "buy_pric", "btc", SAT_PER_PRIC, SAT_PER_PRIC, future, "")
        third_id = c3["record"]["order_id"]
        # alice_id is Matched, so trying to match it again with third → rejected.
        assert_raises_rpc_error(-32600, "do not price-cross",
            alice.pricoin_offer_match, alice_id, third_id, SAT_PER_PRIC)

        # ─── Section 8: unmatch returns to Active, no consumption ───
        self.log.info("Section 8: unmatch returns to Active")
        u = alice.pricoin_offer_unmatch(alice_id)
        assert_equal(u["status"], "active")
        assert_equal(u["pric_in_flight_sat"], 0)
        assert_equal(u["pric_remaining_sat"], 10 * SAT_PER_PRIC)
        # Bob's imported copy in alice's wallet was also released.
        bob_view = alice.pricoin_offer_get(bob_id)
        assert_equal(bob_view["status"], "active")

        # ─── Section 9: match + partial fill (cascades to peer) ───
        self.log.info("Section 9: match + partial fill cascades to peer")
        alice.pricoin_offer_match(alice_id, bob_id, partial)
        f = alice.pricoin_offer_fill(alice_id)
        assert_equal(f["status"], "active")
        assert_equal(f["pric_remaining_sat"], 10 * SAT_PER_PRIC - partial)
        assert_equal(f["pric_in_flight_sat"], 0)
        # Cascaded: bob's imported copy also moved Matched → Active.
        bob_view = alice.pricoin_offer_get(bob_id)
        assert_equal(bob_view["status"], "active")
        assert_equal(bob_view["pric_remaining_sat"], 10 * SAT_PER_PRIC - partial)

        # ─── Section 10: match + fill remaining → Filled terminal (both) ───
        self.log.info("Section 10: fill remaining → Filled terminal cascades")
        rest = 10 * SAT_PER_PRIC - partial  # 6 PRIC left on each
        alice.pricoin_offer_match(alice_id, bob_id, rest)
        f_alice_final = alice.pricoin_offer_fill(alice_id)
        assert_equal(f_alice_final["status"], "filled")
        assert_equal(f_alice_final["pric_remaining_sat"], 0)
        # Peer cascaded to Filled too.
        bob_view_final = alice.pricoin_offer_get(bob_id)
        assert_equal(bob_view_final["status"], "filled")

        # Filled is terminal — fill/match/unmatch/cancel all reject.
        assert_raises_rpc_error(-32600, "current state does not permit",
            alice.pricoin_offer_fill, alice_id)
        assert_raises_rpc_error(-32600, "current state does not permit",
            alice.pricoin_offer_unmatch, alice_id)
        assert_raises_rpc_error(-32600, "current state does not permit",
            alice.pricoin_offer_cancel, alice_id)

        # ─── Section 11: cancel from Active ───
        self.log.info("Section 11: cancel from Active")
        ctc = alice.pricoin_offer_create(
            "buy_pric", "ltc", SAT_PER_PRIC, SAT_PER_PRIC, future, "alice ltc bid")
        cancelled = alice.pricoin_offer_cancel(ctc["record"]["order_id"])
        assert_equal(cancelled["status"], "cancelled")
        assert_raises_rpc_error(-32600, "current state does not permit",
            alice.pricoin_offer_cancel, ctc["record"]["order_id"])

        # ─── Section 12: chain mismatch / side mismatch don't cross ───
        self.log.info("Section 12: chain/side mismatch don't cross")
        a_btc = alice.pricoin_offer_create(
            "sell_pric", "btc", SAT_PER_PRIC, SAT_PER_PRIC, future, "")
        a_ltc = alice.pricoin_offer_create(
            "buy_pric", "ltc", SAT_PER_PRIC, SAT_PER_PRIC, future, "")
        assert_raises_rpc_error(-32600, "do not price-cross",
            alice.pricoin_offer_match,
            a_btc["record"]["order_id"], a_ltc["record"]["order_id"], SAT_PER_PRIC)

        a_btc2 = alice.pricoin_offer_create(
            "sell_pric", "btc", SAT_PER_PRIC, SAT_PER_PRIC, future, "")
        assert_raises_rpc_error(-32600, "do not price-cross",
            alice.pricoin_offer_match,
            a_btc["record"]["order_id"], a_btc2["record"]["order_id"], SAT_PER_PRIC)

        # ─── Section 13: persistence across wallet reload ───
        self.log.info("Section 13: persistence across wallet reload")
        before = sorted(o["order_id"] for o in alice.pricoin_offer_list())
        node.unloadwallet("alice")
        node.loadwallet("alice")
        alice = node.get_wallet_rpc("alice")
        after = sorted(o["order_id"] for o in alice.pricoin_offer_list())
        assert_equal(before, after)
        rec = alice.pricoin_offer_get(alice_id)
        assert_equal(rec["status"], "filled")

        # ─── Section 14: expired URI rejected on import ───
        self.log.info("Section 14: expired URI rejected on import")
        c_short = alice.pricoin_offer_create(
            "sell_pric", "btc", SAT_PER_PRIC, SAT_PER_PRIC,
            int(time.time()) + 1, "expires soon")
        time.sleep(2)
        assert_raises_rpc_error(-32600, "expiry has already passed",
            bob.pricoin_offer_import, c_short["uri"])

        self.log.info("Pricoin offer (Phase-6 orderbook tier 1) RPC flow OK")


if __name__ == "__main__":
    PricoinOfferTest(__file__).main()
