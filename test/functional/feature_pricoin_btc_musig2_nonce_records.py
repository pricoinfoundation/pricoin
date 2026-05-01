#!/usr/bin/env python3
# Copyright (c) 2026-present The Pricoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional test for BTC MuSig2 nonce-reuse defence (BTC-side §4.1a).

Mirrors the PRIC clsag_nonce_records test for the foreign-leg
analog. Verifies the wallet-level RPC surface for reject-on-conflict
nonce-commit policy:

  * pricoin_btc_musig2_round1_safe atomically generates a pubnonce
    and persists the commitment record before the pubnonce returns.
  * Re-call under the SAME session_id with finalized=false → rejected.
  * Re-call under a DIFFERENT session_id → rejected (the attack).
  * After mark_finalized: same-session permitted, different-session
    still rejected (strict reading of §4.1a).
  * Records survive a wallet reload.
  * Erase clears the slot.
  * Different (agg_xonly, msg, role) keys are independent.
"""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


def random_hex(n_bytes):
    return os.urandom(n_bytes).hex()


G_HEX  = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
TWOG   = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"


class PricoinBtcMusig2NonceRecordsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("alice_btcn")
        w = node.get_wallet_rpc("alice_btcn")
        w.pricoin_getstealthaddress()  # prime stealth identity for at-rest crypto

        # Use priv=1, priv=2 to derive a 2-of-2 aggregate via keyagg.
        priv_a = "00" * 31 + "01"
        priv_b = "00" * 31 + "02"
        pub_a = G_HEX
        pub_b = TWOG

        kg = w.pricoin_btc_musig2_keyagg([pub_a, pub_b])
        cache = kg["keyagg_cache"]
        agg_xonly = kg["agg_xonly"]

        msg = random_hex(32)
        msg_alt = random_hex(32)
        sid_a = random_hex(32)
        sid_b = random_hex(32)
        seed1 = random_hex(32)
        seed2 = random_hex(32)
        seed3 = random_hex(32)

        # ─── Section 1: empty list, then round1_safe succeeds ───
        self.log.info("Section 1: empty + first round1_safe")
        assert_equal(w.pricoin_btc_musig2_nonce_list(), [])

        r1 = w.pricoin_btc_musig2_round1_safe(
            pub_a, cache, agg_xonly, msg, "initiator", sid_a, seed1, priv_a)
        assert_equal(len(r1["pubnonce"]), 66 * 2)
        assert_equal(len(r1["secnonce_handle"]), 64)
        assert_equal(len(r1["record_digest"]), 64)

        # Persistence record exists.
        rec = w.pricoin_btc_musig2_nonce_get(agg_xonly, msg, "initiator")
        assert_equal(rec["pubnonce"], r1["pubnonce"])
        assert_equal(rec["session_id"], sid_a)
        assert_equal(rec["finalized"], False)

        all_recs = w.pricoin_btc_musig2_nonce_list()
        assert_equal(len(all_recs), 1)

        # ─── Section 2: same session, in-flight → REJECT ───
        self.log.info("Section 2: same session in-flight rejected")
        assert_raises_rpc_error(
            -32600, "BTC §4.1a",
            w.pricoin_btc_musig2_round1_safe,
            pub_a, cache, agg_xonly, msg, "initiator", sid_a, seed2, priv_a)

        # ─── Section 3: different session → REJECT (the attack) ───
        self.log.info("Section 3: different session rejected (the attack)")
        assert_raises_rpc_error(
            -32600, "DIFFERENT session_id",
            w.pricoin_btc_musig2_round1_safe,
            pub_a, cache, agg_xonly, msg, "initiator", sid_b, seed2, priv_a)

        # ─── Section 4: different role on same (agg_xonly, msg) is independent ───
        self.log.info("Section 4: different role independent")
        r1_resp = w.pricoin_btc_musig2_round1_safe(
            pub_b, cache, agg_xonly, msg, "responder", sid_a, seed2, priv_b)
        assert_equal(len(r1_resp["pubnonce"]), 66 * 2)
        assert_equal(len(w.pricoin_btc_musig2_nonce_list()), 2)

        # ─── Section 5: different msg on same (agg_xonly, role) is independent ───
        self.log.info("Section 5: different msg independent")
        r1_alt = w.pricoin_btc_musig2_round1_safe(
            pub_a, cache, agg_xonly, msg_alt, "initiator", sid_a, seed3, priv_a)
        assert_equal(len(r1_alt["pubnonce"]), 66 * 2)
        assert_equal(len(w.pricoin_btc_musig2_nonce_list()), 3)

        # ─── Section 6: mark_finalized + same-session re-attempt permitted ───
        self.log.info("Section 6: post-finalize, same session permitted")
        marked = w.pricoin_btc_musig2_nonce_mark_finalized(
            agg_xonly, msg, "initiator")
        assert_equal(marked["finalized"], True)
        # Same session_id round1_safe now succeeds (slot is logically free).
        r1_again = w.pricoin_btc_musig2_round1_safe(
            pub_a, cache, agg_xonly, msg, "initiator", sid_a, random_hex(32), priv_a)
        # Re-attempt overwrote the record; still finalized=false now.
        rec2 = w.pricoin_btc_musig2_nonce_get(agg_xonly, msg, "initiator")
        assert_equal(rec2["finalized"], False)

        # ─── Section 7: mark_finalized, then DIFFERENT session still rejected ───
        # Strict reading: different session_id is unconditionally rejected
        # while a record exists. Operator must Erase first.
        self.log.info("Section 7: post-finalize, different session still rejected")
        w.pricoin_btc_musig2_nonce_mark_finalized(agg_xonly, msg, "initiator")
        assert_raises_rpc_error(
            -32600, "DIFFERENT session_id",
            w.pricoin_btc_musig2_round1_safe,
            pub_a, cache, agg_xonly, msg, "initiator", sid_b, random_hex(32), priv_a)

        # ─── Section 8: Erase clears the slot, new session permitted ───
        self.log.info("Section 8: erase + new session permitted")
        before = len(w.pricoin_btc_musig2_nonce_list())
        erased = w.pricoin_btc_musig2_nonce_erase(agg_xonly, msg, "initiator")
        assert_equal(erased["erased"], True)
        assert_equal(len(w.pricoin_btc_musig2_nonce_list()), before - 1)
        # Fresh session for the same slot now permitted.
        r1_post_erase = w.pricoin_btc_musig2_round1_safe(
            pub_a, cache, agg_xonly, msg, "initiator", sid_b, random_hex(32), priv_a)
        rec3 = w.pricoin_btc_musig2_nonce_get(agg_xonly, msg, "initiator")
        assert_equal(rec3["session_id"], sid_b)

        # ─── Section 9: persistence across wallet reload ───
        self.log.info("Section 9: persistence across wallet reload")
        digests_before = sorted(
            r["record_digest"] for r in w.pricoin_btc_musig2_nonce_list())
        node.unloadwallet("alice_btcn")
        node.loadwallet("alice_btcn")
        w = node.get_wallet_rpc("alice_btcn")
        digests_after = sorted(
            r["record_digest"] for r in w.pricoin_btc_musig2_nonce_list())
        assert_equal(digests_before, digests_after)
        # Get on the same key still returns the same record after reload.
        rec_reloaded = w.pricoin_btc_musig2_nonce_get(
            agg_xonly, msg, "initiator")
        assert_equal(rec_reloaded["session_id"], sid_b)

        self.log.info("Pricoin BTC MuSig2 nonce-records (BTC-side §4.1a) RPC flow OK")


if __name__ == "__main__":
    PricoinBtcMusig2NonceRecordsTest(__file__).main()
