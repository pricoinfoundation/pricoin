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

        # NOTE: round1_safe derives the secnonce AND session_id
        # DETERMINISTICALLY from (priv, agg_xonly, msg, role) — the caller's
        # session_id/seed args are overridden (det-sid-v1, since v0.1.140) so
        # a crashed ceremony can resume by reproducing the exact same nonce.
        # Consequences this test asserts: a re-call for the same record key
        # is IDEMPOTENT (same pubnonce, same derived session_id) regardless of
        # the session_id passed in; and the key-reuse defence has moved to the
        # partial_sign aggregate-nonce binding (Section 8).

        # ─── Section 1: empty list, then round1_safe succeeds ───
        self.log.info("Section 1: empty + first round1_safe")
        assert_equal(w.pricoin_btc_musig2_nonce_list(), [])

        r1 = w.pricoin_btc_musig2_round1_safe(
            pub_a, cache, agg_xonly, msg, "initiator", sid_a, seed1, priv_a)
        assert_equal(len(r1["pubnonce"]), 66 * 2)
        assert_equal(len(r1["secnonce_handle"]), 64)
        assert_equal(len(r1["record_digest"]), 64)

        # Persistence record exists. session_id is the DERIVED one (not sid_a).
        rec = w.pricoin_btc_musig2_nonce_get(agg_xonly, msg, "initiator")
        assert_equal(rec["pubnonce"], r1["pubnonce"])
        det_sid = rec["session_id"]
        assert_equal(len(det_sid), 64)
        assert_equal(rec["finalized"], False)

        all_recs = w.pricoin_btc_musig2_nonce_list()
        assert_equal(len(all_recs), 1)

        # ─── Section 2: deterministic idempotent re-commit ───
        # A second round1_safe for the same (agg_xonly, msg, role) reproduces
        # the EXACT same pubnonce + derived session_id, so the policy treats
        # it as an idempotent re-commit (crash-resume), regardless of the
        # session_id/seed passed. This is the deterministic-nonce behaviour.
        self.log.info("Section 2: deterministic idempotent re-commit")
        r1_again = w.pricoin_btc_musig2_round1_safe(
            pub_a, cache, agg_xonly, msg, "initiator", sid_b, seed2, priv_a)
        assert_equal(r1_again["pubnonce"], r1["pubnonce"])
        rec_again = w.pricoin_btc_musig2_nonce_get(agg_xonly, msg, "initiator")
        assert_equal(rec_again["session_id"], det_sid)
        assert_equal(len(w.pricoin_btc_musig2_nonce_list()), 1)

        # ─── Section 3: different role on same (agg_xonly, msg) is independent ───
        self.log.info("Section 3: different role independent")
        r1_resp = w.pricoin_btc_musig2_round1_safe(
            pub_b, cache, agg_xonly, msg, "responder", sid_a, seed2, priv_b)
        assert_equal(len(r1_resp["pubnonce"]), 66 * 2)
        assert_equal(len(w.pricoin_btc_musig2_nonce_list()), 2)

        # ─── Section 4: different msg on same (agg_xonly, role) is independent ───
        self.log.info("Section 4: different msg independent")
        r1_alt = w.pricoin_btc_musig2_round1_safe(
            pub_a, cache, agg_xonly, msg_alt, "initiator", sid_a, seed3, priv_a)
        assert_equal(len(r1_alt["pubnonce"]), 66 * 2)
        assert_equal(len(w.pricoin_btc_musig2_nonce_list()), 3)

        # ─── Section 5: mark_finalized then re-commit still permitted ───
        self.log.info("Section 5: post-finalize re-commit permitted")
        marked = w.pricoin_btc_musig2_nonce_mark_finalized(
            agg_xonly, msg, "initiator")
        assert_equal(marked["finalized"], True)
        r1_postfin = w.pricoin_btc_musig2_round1_safe(
            pub_a, cache, agg_xonly, msg, "initiator", sid_a, random_hex(32), priv_a)
        assert_equal(r1_postfin["pubnonce"], r1["pubnonce"])
        rec2 = w.pricoin_btc_musig2_nonce_get(agg_xonly, msg, "initiator")
        assert_equal(rec2["finalized"], False)

        # ─── Section 6: Erase clears the slot ───
        self.log.info("Section 6: erase clears the slot")
        before = len(w.pricoin_btc_musig2_nonce_list())
        erased = w.pricoin_btc_musig2_nonce_erase(agg_xonly, msg, "initiator")
        assert_equal(erased["erased"], True)
        assert_equal(len(w.pricoin_btc_musig2_nonce_list()), before - 1)
        # Fresh round1_safe for the same slot re-creates it.
        w.pricoin_btc_musig2_round1_safe(
            pub_a, cache, agg_xonly, msg, "initiator", sid_b, random_hex(32), priv_a)
        rec3 = w.pricoin_btc_musig2_nonce_get(agg_xonly, msg, "initiator")
        assert_equal(rec3["session_id"], det_sid)  # same derived sid

        # ─── Section 7: persistence across wallet reload ───
        self.log.info("Section 7: persistence across wallet reload")
        digests_before = sorted(
            r["record_digest"] for r in w.pricoin_btc_musig2_nonce_list())
        node.unloadwallet("alice_btcn")
        node.loadwallet("alice_btcn")
        w = node.get_wallet_rpc("alice_btcn")
        digests_after = sorted(
            r["record_digest"] for r in w.pricoin_btc_musig2_nonce_list())
        assert_equal(digests_before, digests_after)
        rec_reloaded = w.pricoin_btc_musig2_nonce_get(
            agg_xonly, msg, "initiator")
        assert_equal(rec_reloaded["session_id"], det_sid)

        # ─── Section 8: aggregate-nonce binding (the key-leak defence) ───
        # Because round1_safe re-derives the SAME secnonce k, two partial
        # signatures over that k with DIFFERENT aggregate nonces would let the
        # peer solve d = (s - s')/(e - e') and steal the key. partial_sign
        # therefore binds the secnonce to exactly one aggregate nonce: the
        # first partial records it; a second partial over a different
        # aggregate nonce is REJECTED, while re-signing the same one is
        # idempotent (crash-resume).
        self.log.info("Section 8: partial_sign aggregate-nonce binding")
        msg_c = random_hex(32)
        T_G = pub_b  # any valid point; adaptor semantics not exercised here

        # Party A commits deterministically (round1_safe); party B with plain
        # round1. First ceremony with B's nonce #1:
        ra = w.pricoin_btc_musig2_round1_safe(
            pub_a, cache, agg_xonly, msg_c, "initiator", random_hex(32),
            random_hex(32), priv_a)
        rb1 = w.pricoin_btc_musig2_round1(pub_b, cache, random_hex(32), priv_b, msg_c)
        agg1 = w.pricoin_btc_musig2_aggregate_nonces([ra["pubnonce"], rb1["pubnonce"]])
        sess1 = w.pricoin_btc_musig2_process(agg1["aggnonce"], msg_c, cache, T_G)
        psa1 = w.pricoin_btc_musig2_partial_sign(
            ra["secnonce_handle"], priv_a, pub_a, cache, sess1)
        assert_equal(len(psa1["partial_sig"]), 32 * 2)

        # The attack: B supplies a DIFFERENT nonce → a different aggregate
        # nonce. A re-derives the same secnonce (idempotent round1_safe) and
        # tries to partial-sign again. This MUST be refused.
        rb2 = w.pricoin_btc_musig2_round1(pub_b, cache, random_hex(32), priv_b, msg_c)
        agg2 = w.pricoin_btc_musig2_aggregate_nonces([ra["pubnonce"], rb2["pubnonce"]])
        assert agg2["aggnonce"] != agg1["aggnonce"], "different B nonce must change aggnonce"
        sess2 = w.pricoin_btc_musig2_process(agg2["aggnonce"], msg_c, cache, T_G)
        ra2 = w.pricoin_btc_musig2_round1_safe(
            pub_a, cache, agg_xonly, msg_c, "initiator", random_hex(32),
            random_hex(32), priv_a)
        assert_equal(ra2["pubnonce"], ra["pubnonce"])  # deterministic: same k
        assert_raises_rpc_error(
            -32600, "leak the signing key",
            w.pricoin_btc_musig2_partial_sign,
            ra2["secnonce_handle"], priv_a, pub_a, cache, sess2)

        # Re-signing the ORIGINAL aggregate nonce is idempotent and yields the
        # identical partial (legitimate crash-resume).
        ra3 = w.pricoin_btc_musig2_round1_safe(
            pub_a, cache, agg_xonly, msg_c, "initiator", random_hex(32),
            random_hex(32), priv_a)
        psa1b = w.pricoin_btc_musig2_partial_sign(
            ra3["secnonce_handle"], priv_a, pub_a, cache, sess1)
        assert_equal(psa1b["partial_sig"], psa1["partial_sig"])

        self.log.info("Pricoin BTC MuSig2 nonce-records (BTC-side §4.1a) RPC flow OK")


if __name__ == "__main__":
    PricoinBtcMusig2NonceRecordsTest(__file__).main()
