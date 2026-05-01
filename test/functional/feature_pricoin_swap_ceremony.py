#!/usr/bin/env python3
# Copyright (c) 2026-present The Pricoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional test for the swap ceremony state machine.

Drives a buy-PRIC-with-BTC ceremony manually through every state,
verifying:
  * Roles serialise correctly.
  * State transitions: Init → BtcFunded → PricFunded → BtcClaimed → Complete.
  * Out-of-order transitions are rejected.
  * Abort works from non-terminal states.
  * Preimage validation: passing a wrong preimage to set_foreign_claimed
    is rejected (SHA-256 mismatch).
  * next_action hint is non-empty and changes per state.
  * Persistence: list shows the records; get returns the same content.

The ceremony state machine alone doesn't make a swap atomic — it's a
workflow tracker. This test verifies the workflow plumbing; the
actual cross-chain crypto is tested elsewhere (jointspend, btc_htlc,
chainwatch).
"""

import hashlib
import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


def random_hex(n_bytes):
    return os.urandom(n_bytes).hex()


def sha256_hex(hex_str):
    return hashlib.sha256(bytes.fromhex(hex_str)).digest().hex()


class PricoinSwapCeremonyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def make_foreign(self):
        return {
            "chain": "btc",
            "htlc_address": "bc1q" + "x" * 38,
            "redeem_script": "63a820" + "00" * 32 + "8821" + "02" + "01" * 32 + "ac6703" + "abcdef" + "b1752102" + "02" * 32 + "ac68",
            "amount_sat": 100_000_000,
            "timeout": 800_000,
        }

    def make_pric(self):
        return {
            "joint_stealth_address": "pricstl1q" + "y" * 50,
            "amount_sat": 50_000_000,
        }

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("alice_swp")
        node.createwallet("bob_swp")
        alice = node.get_wallet_rpc("alice_swp")
        bob   = node.get_wallet_rpc("bob_swp")

        # Prime stealth identities so swap_identity returns a pubkey.
        alice.pricoin_getstealthaddress()
        bob.pricoin_getstealthaddress()
        alice_pub = alice.pricoin_swap_identity()["pubkey"]
        bob_pub   = bob.pricoin_swap_identity()["pubkey"]

        foreign = self.make_foreign()
        pric    = self.make_pric()

        # ─── Section 1: buying_foreign happy path ────────────────
        self.log.info("Section 1: buying_foreign happy path")
        # Alice is buying BTC (sending PRIC). She generates the preimage.
        ceremony = alice.pricoin_swap_ceremony_create(
            "buying_foreign", bob_pub, foreign, pric, "", "alice buying btc")
        cid = ceremony["ceremony_id"]
        assert_equal(ceremony["role"], "buying_foreign")
        assert_equal(ceremony["state"], "init")
        assert "preimage" in ceremony
        assert "preimage_hash" in ceremony
        assert_equal(sha256_hex(ceremony["preimage"]), ceremony["preimage_hash"])
        assert ceremony["next_action"], "next_action hint should be non-empty"

        # Save the hash to ship to Bob.
        preimage_hex = ceremony["preimage"]
        preimage_hash_hex = ceremony["preimage_hash"]

        # Bob (selling_foreign) creates his side with the hash.
        bob_ceremony = bob.pricoin_swap_ceremony_create(
            "selling_foreign", alice_pub, foreign, pric,
            preimage_hash_hex, "bob selling btc")
        assert_equal(bob_ceremony["role"], "selling_foreign")
        assert_equal(bob_ceremony["preimage_hash"], preimage_hash_hex)
        assert "preimage" not in bob_ceremony  # Bob doesn't know it yet.

        # Step 1: foreign HTLC funded by Bob.
        funding_txid = "ab" * 32
        funding_vout = 0
        c = alice.pricoin_swap_ceremony_set_foreign_funded(cid, funding_txid, funding_vout)
        assert_equal(c["state"], "foreign_funded")
        assert_equal(c["foreign_funding_txid"], funding_txid)
        assert_equal(c["foreign_funding_vout"], funding_vout)
        prev_hint = ceremony["next_action"]
        assert c["next_action"] != prev_hint, "hint should advance"

        # Step 2: PRIC locked by Alice (joint stealth funded).
        pric_txid = "cd" * 32
        pric_vout = 1
        x_share_hex = random_hex(32)
        c = alice.pricoin_swap_ceremony_set_pric_funded(
            cid, pric_txid, pric_vout, x_share_hex)
        assert_equal(c["state"], "pric_funded")
        assert_equal(c["pric_funding_txid"], pric_txid)
        assert_equal(c["pric"]["our_x_share"], x_share_hex)

        # Step 3: Alice claims foreign HTLC. She already has the
        # preimage; passing it via the RPC is optional but a reasonable
        # check that we get the same thing back.
        claim_txid = "ef" * 32
        c = alice.pricoin_swap_ceremony_set_foreign_claimed(
            cid, claim_txid, preimage_hex)
        assert_equal(c["state"], "foreign_claimed")
        assert_equal(c["foreign_claim_txid"], claim_txid)

        # Step 4: PRIC released cooperatively.
        release_txid = "12" * 32
        c = alice.pricoin_swap_ceremony_set_pric_released(cid, release_txid)
        assert_equal(c["state"], "complete")
        assert_equal(c["pric_release_txid"], release_txid)

        # Trying to advance further → InvalidState.
        assert_raises_rpc_error(
            -8, "expected state",
            alice.pricoin_swap_ceremony_set_pric_released, cid, release_txid)

        # ─── Section 2: out-of-order rejection ─────────────────
        self.log.info("Section 2: out-of-order rejection")
        c2 = alice.pricoin_swap_ceremony_create(
            "buying_foreign", bob_pub, foreign, pric, "", "")
        cid2 = c2["ceremony_id"]
        # set_pric_funded before set_foreign_funded should reject.
        assert_raises_rpc_error(
            -8, "expected state",
            alice.pricoin_swap_ceremony_set_pric_funded,
            cid2, "00" * 32, 0, "00" * 32)
        # set_foreign_claimed before pric_funded should reject.
        alice.pricoin_swap_ceremony_set_foreign_funded(cid2, "ab" * 32, 0)
        assert_raises_rpc_error(
            -8, "expected state",
            alice.pricoin_swap_ceremony_set_foreign_claimed,
            cid2, "ef" * 32)

        # ─── Section 3: bad preimage rejected ──────────────────
        self.log.info("Section 3: bad preimage rejected")
        # Bob's side: he passes a wrong preimage when claiming.
        bob_cid = bob_ceremony["ceremony_id"]
        bob.pricoin_swap_ceremony_set_foreign_funded(bob_cid, "ab" * 32, 0)
        bob.pricoin_swap_ceremony_set_pric_funded(
            bob_cid, "cd" * 32, 1, random_hex(32))
        wrong_preimage = "00" * 32
        assert_raises_rpc_error(
            -8, "Invalid input",
            bob.pricoin_swap_ceremony_set_foreign_claimed,
            bob_cid, "ef" * 32, wrong_preimage)
        # Right preimage → accepted, and Bob now knows it.
        c = bob.pricoin_swap_ceremony_set_foreign_claimed(
            bob_cid, "ef" * 32, preimage_hex)
        assert_equal(c["state"], "foreign_claimed")
        assert_equal(c["preimage"], preimage_hex)

        # ─── Section 4: abort + persistence ────────────────────
        self.log.info("Section 4: abort + persistence")
        c4 = alice.pricoin_swap_ceremony_create(
            "buying_foreign", bob_pub, foreign, pric, "", "abort test")
        cid4 = c4["ceremony_id"]
        a = alice.pricoin_swap_ceremony_abort(cid4, "counterparty went silent")
        assert_equal(a["state"], "aborted")
        assert_equal(a["abort_reason"], "counterparty went silent")
        # Aborting again → InvalidState.
        assert_raises_rpc_error(
            -8, "expected state",
            alice.pricoin_swap_ceremony_abort, cid4, "again")

        # List/get round-trip.
        all_alice = alice.pricoin_swap_ceremony_list()
        states = sorted(c["state"] for c in all_alice)
        assert "complete" in states
        assert "aborted" in states
        assert "foreign_funded" in states  # cid2 left at this state

        got = alice.pricoin_swap_ceremony_get(cid)
        assert_equal(got["ceremony_id"], cid)
        assert_equal(got["state"], "complete")

        # ─── Section 5: input validation ───────────────────────
        self.log.info("Section 5: input validation")

        # Wrong role string.
        assert_raises_rpc_error(
            -8, "must be",
            alice.pricoin_swap_ceremony_create,
            "wrong_role", bob_pub, foreign, pric, "", "")

        # selling_foreign without a hash → InvalidPreimage.
        assert_raises_rpc_error(
            -8, "32 bytes",
            alice.pricoin_swap_ceremony_create,
            "selling_foreign", bob_pub, foreign, pric, "", "")

        # buying_foreign with wrong-length preimage override.
        assert_raises_rpc_error(
            -8, "32 bytes",
            alice.pricoin_swap_ceremony_create,
            "buying_foreign", bob_pub, foreign, pric, "ab" * 16, "")

        # foreign with empty chain → ValidateForeignLeg rejects.
        bad_foreign = dict(foreign, chain="")
        assert_raises_rpc_error(
            -8, "Invalid foreign",
            alice.pricoin_swap_ceremony_create,
            "buying_foreign", bob_pub, bad_foreign, pric, "", "")

        self.log.info("Pricoin swap ceremony test OK")


if __name__ == "__main__":
    PricoinSwapCeremonyTest(__file__).main()
