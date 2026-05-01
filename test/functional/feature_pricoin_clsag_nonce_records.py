#!/usr/bin/env python3
# Copyright (c) 2026-present The Pricoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional test for CLSAG round-1 nonce records (§4.1a).

Verifies the wallet-level RPC surface for the §4.1a nonce-reuse
defence:

  * pricoin_clsag_nonce_begin persists a record before broadcast.
  * Re-Begin under the SAME session_id while t_published=false is
    rejected (in-flight reuse — would leak the spend share if signed).
  * Re-Begin under a DIFFERENT session_id is rejected (the catastrophic
    cross-session reuse — same situation as above plus an active
    attacker).
  * After mark_published, same-session re-Begin is permitted; different
    session_id is still rejected (strict reading of §4.1a).
  * Records survive a wallet reload (the records are persisted to
    wallet.dat and re-loaded on next access).
  * Erase removes a record.

Each branch corresponds to a §4.1a clause; failure of any one would
re-introduce the spend-share leak.
"""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


def random_hex(n_bytes):
    return os.urandom(n_bytes).hex()


class PricoinClsagNonceRecordsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("alice_nonce")
        alice = node.get_wallet_rpc("alice_nonce")
        # Prime stealth identity so encrypt/decrypt blob path is valid.
        alice.pricoin_getstealthaddress()

        # Fixed test inputs — using a 36-byte canonical txid:vout
        # encoding for the joint output id, a random 32-byte ring hash,
        # and a fresh session id.
        joint_out_a = "11" * 32 + "00000000"  # 36 bytes
        joint_out_b = "22" * 32 + "00000001"  # different output, same length
        ring_hash_a = random_hex(32)
        ring_hash_b = random_hex(32)
        session_id_1 = random_hex(32)
        session_id_2 = random_hex(32)
        alpha_1 = random_hex(32)
        alpha_2 = random_hex(32)
        commit_1 = random_hex(32)
        commit_2 = random_hex(32)

        # ─── Section 1: empty list, then begin succeeds ───
        self.log.info("Section 1: empty list, then Begin")
        assert_equal(alice.pricoin_clsag_nonce_list(), [])
        rec = alice.pricoin_clsag_nonce_begin(
            joint_out_a, ring_hash_a, "initiator",
            session_id_1, alpha_1, commit_1)
        assert_equal(rec["session_id"], session_id_1)
        assert_equal(rec["commitment"], commit_1)
        assert_equal(rec["t_published"], False)
        assert_equal(rec["role"], "initiator")
        assert "alpha" not in rec  # redacted in begin response

        # Get returns the record with alpha included.
        full = alice.pricoin_clsag_nonce_get(joint_out_a, ring_hash_a, "initiator")
        assert_equal(full["alpha"], alpha_1)
        assert_equal(full["session_id"], session_id_1)

        # List has the one record (alpha redacted).
        all_recs = alice.pricoin_clsag_nonce_list()
        assert_equal(len(all_recs), 1)
        assert "alpha" not in all_recs[0]

        # ─── Section 2: same session, in-flight, MUST reject ───
        self.log.info("Section 2: same session in-flight rejected")
        assert_raises_rpc_error(
            -32600, "§4.1a",
            alice.pricoin_clsag_nonce_begin,
            joint_out_a, ring_hash_a, "initiator",
            session_id_1, alpha_2, commit_2)

        # ─── Section 3: different session, t_published=false, MUST reject ───
        self.log.info("Section 3: different session rejected (the attack)")
        assert_raises_rpc_error(
            -32600, "DIFFERENT session_id",
            alice.pricoin_clsag_nonce_begin,
            joint_out_a, ring_hash_a, "initiator",
            session_id_2, alpha_2, commit_2)

        # ─── Section 4: different role on same output is independent ───
        self.log.info("Section 4: responder role is independent")
        rec_resp = alice.pricoin_clsag_nonce_begin(
            joint_out_a, ring_hash_a, "responder",
            session_id_1, alpha_1, commit_1)
        assert_equal(rec_resp["role"], "responder")
        assert_equal(len(alice.pricoin_clsag_nonce_list()), 2)

        # ─── Section 5: different ring hash on same output is independent ───
        self.log.info("Section 5: different ring_hash is independent")
        rec_other_ring = alice.pricoin_clsag_nonce_begin(
            joint_out_a, ring_hash_b, "initiator",
            session_id_1, alpha_2, commit_2)
        assert_equal(rec_other_ring["ring_hash"], ring_hash_b)
        assert_equal(len(alice.pricoin_clsag_nonce_list()), 3)

        # ─── Section 6: mark_published, then same session permitted ───
        self.log.info("Section 6: post-publish, same session permitted")
        marked = alice.pricoin_clsag_nonce_mark_published(
            joint_out_a, ring_hash_a, "initiator")
        assert_equal(marked["t_published"], True)
        # Same session_id Begin now succeeds:
        rec_again = alice.pricoin_clsag_nonce_begin(
            joint_out_a, ring_hash_a, "initiator",
            session_id_1, alpha_2, commit_2)
        assert_equal(rec_again["session_id"], session_id_1)
        # Begin reset t_published to false (fresh signing session).
        assert_equal(rec_again["t_published"], False)

        # ─── Section 7: mark_published, then DIFFERENT session still rejected ───
        # Strict reading of §4.1a: different session_id is unconditionally rejected
        # while a record exists. Operator must explicitly Erase first.
        self.log.info("Section 7: post-publish, different session still rejected")
        alice.pricoin_clsag_nonce_mark_published(
            joint_out_a, ring_hash_a, "initiator")
        assert_raises_rpc_error(
            -32600, "DIFFERENT session_id",
            alice.pricoin_clsag_nonce_begin,
            joint_out_a, ring_hash_a, "initiator",
            session_id_2, alpha_2, commit_2)

        # ─── Section 8: Erase clears the slot, new session permitted ───
        self.log.info("Section 8: erase + new session permitted")
        erased = alice.pricoin_clsag_nonce_erase(
            joint_out_a, ring_hash_a, "initiator")
        assert_equal(erased["erased"], True)
        # After erase, list count drops by one (we had 3; should be 2).
        assert_equal(len(alice.pricoin_clsag_nonce_list()), 2)
        # New session for the same slot is now permitted.
        rec_post_erase = alice.pricoin_clsag_nonce_begin(
            joint_out_a, ring_hash_a, "initiator",
            session_id_2, alpha_2, commit_2)
        assert_equal(rec_post_erase["session_id"], session_id_2)

        # ─── Section 9: persistence across wallet reload ───
        self.log.info("Section 9: persistence across wallet reload")
        before = sorted(
            (r["record_digest"] for r in alice.pricoin_clsag_nonce_list()))
        node.unloadwallet("alice_nonce")
        node.loadwallet("alice_nonce")
        alice = node.get_wallet_rpc("alice_nonce")
        after = sorted(
            (r["record_digest"] for r in alice.pricoin_clsag_nonce_list()))
        assert_equal(before, after)
        # And the alpha-bearing get still works after reload:
        rec_reloaded = alice.pricoin_clsag_nonce_get(
            joint_out_a, ring_hash_a, "initiator")
        assert_equal(rec_reloaded["alpha"], alpha_2)

        # ─── Section 10: different output, same ring/role/session permitted ───
        self.log.info("Section 10: different joint_output_id is independent")
        rec_other_out = alice.pricoin_clsag_nonce_begin(
            joint_out_b, ring_hash_a, "initiator",
            session_id_1, alpha_1, commit_1)
        assert_equal(rec_other_out["joint_output_id"], joint_out_b)

        # ─── Section 11: pricoin_jointspend_round1_safe — atomic
        # math+persist for real cooperative signing.
        # Uses a fresh wallet (otherwise the existing slots above would
        # conflict on the joint_pubkey-derived ring_hash assumptions).
        self.log.info("Section 11: pricoin_jointspend_round1_safe (atomic math+persist)")
        node.createwallet("alice_safe")
        safe = node.get_wallet_rpc("alice_safe")
        safe.pricoin_getstealthaddress()

        # Build a real joint pubkey via the existing primitives. We
        # avoid pulling in the cooperative setup machinery and just
        # use any valid 33-byte compressed pubkey by deriving one from
        # a random scalar via getstealthaddress's underlying key.
        # Simpler: cooperative signing in production would supply real
        # group elements — for this test we just pick any plausible
        # pubkey (all-byte secp256k1 scalar mod n → pubkey via the
        # node's existing math). For a black-box RPC test we can
        # compose with pricoin_jointspend_round1 to obtain a workable
        # P_pi: that primitive accepts any 33-byte compressed point.
        # Here we just use a fixed valid compressed pubkey from a known
        # scalar.
        joint_pub_hex = (
            "02"  # compressed even-y prefix
            + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )  # = G  (the curve generator) — always valid
        x_share_hex = (
            "0000000000000000000000000000000000000000000000000000000000000001"
        )

        joint_out_safe = "33" * 32 + "00000000"
        ring_hash_safe = random_hex(32)
        session_safe = random_hex(32)

        r1 = safe.pricoin_jointspend_round1_safe(
            joint_pub_hex, x_share_hex, session_safe,
            joint_out_safe, ring_hash_safe, "initiator")
        # The RPC returned alpha (= the persisted alpha).
        assert "alpha" in r1
        assert "L_share" in r1
        assert "R_share" in r1
        assert "KI_share" in r1
        assert "commitment" in r1
        assert "record_digest" in r1

        # The persistence record exists under the same key.
        full = safe.pricoin_clsag_nonce_get(
            joint_out_safe, ring_hash_safe, "initiator")
        assert_equal(full["alpha"], r1["alpha"])
        assert_equal(full["commitment"], r1["commitment"])
        assert_equal(full["session_id"], session_safe)
        assert_equal(full["t_published"], False)

        # Section 12: re-call round1_safe with same key/session →
        # rejected (the RPC ATOMICITY claim — alpha never leaks).
        self.log.info("Section 12: round1_safe re-call same session rejected")
        assert_raises_rpc_error(
            -32600, "§4.1a",
            safe.pricoin_jointspend_round1_safe,
            joint_pub_hex, x_share_hex, session_safe,
            joint_out_safe, ring_hash_safe, "initiator")

        # Section 13: different session — rejected.
        self.log.info("Section 13: round1_safe re-call different session rejected")
        assert_raises_rpc_error(
            -32600, "DIFFERENT session_id",
            safe.pricoin_jointspend_round1_safe,
            joint_pub_hex, x_share_hex, random_hex(32),
            joint_out_safe, ring_hash_safe, "initiator")

        self.log.info("Pricoin CLSAG nonce-records (§4.1a) RPC flow OK")


if __name__ == "__main__":
    PricoinClsagNonceRecordsTest(__file__).main()
