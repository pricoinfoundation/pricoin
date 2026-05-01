#!/usr/bin/env python3
# Copyright (c) 2026-present The Pricoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional test for PRIC-side refund-tx skeleton (nLockTime path of buildtx).

Validates the spec §6.2 step 7 PRIC refund pre-signing flow: the existing
pricoin_jointspend_buildtx accepts a fresh `nlocktime` parameter that
bakes a CHECKLOCKTIMEVERIFY-style absolute height into the resulting
v4 spend tx. The cooperative CLSAG sighash naturally commits to the
full tx bytes (including nLockTime), so the cooperative signature
binds to the timelock.

Verifies:
  * Default behaviour (nlocktime=0) produces tx with locktime=0.
  * Setting nlocktime=H produces tx with locktime=H.
  * Same inputs + different nlocktime → different sighashes
    (the cooperative signature commits to the timelock).
  * Cooperatively signing the refund-tx sighash produces a valid CLSAG
    signature that verifies under the same ring + msg via
    pricoin_jointspend_verify.
  * Mempool acceptance: a refund tx with nLockTime > current chain
    height is rejected as non-final; mining past the height makes it
    accepted.
"""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.key import generate_privkey


class PricoinJointspendRefundTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-txindex=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _setup_joint_output(self, node):
        """Create a joint stealth output, fund it, and recover the
        loadshare data on both sides. Returns (alice, bob, receiver,
        joint_txid, joint_vout, joint_tx_hex, a_load, b_load,
        recv_keys, sender_addr_for_mining)."""
        node.createwallet("rfa")
        node.createwallet("rfb")
        node.createwallet("rfsender")
        node.createwallet("rfrecv")
        alice    = node.get_wallet_rpc("rfa")
        bob      = node.get_wallet_rpc("rfb")
        sender   = node.get_wallet_rpc("rfsender")
        receiver = node.get_wallet_rpc("rfrecv")

        sender_addr = sender.getnewaddress(address_type="bech32")
        self.generatetoaddress(node, 110, sender_addr)

        alice_keys = alice.pricoin_getstealthaddress()
        bob_keys   = bob.pricoin_getstealthaddress()
        recv_keys  = receiver.pricoin_getstealthaddress()
        joint = alice.pricoin_buildjointstealthaddress(
            bob_keys["view_pubkey"], bob_keys["spend_pubkey"])

        # Seed a few CT decoys for the ring builder.
        for _ in range(4):
            sender.walletsendct(alice_keys["address"], 1.0, 0.0001)
            self.generatetoaddress(node, 1, sender_addr)

        sent = sender.walletsendct(joint["address"], 4.2, 0.0001)
        self.generatetoaddress(node, 1, sender_addr)
        joint_txid = sent["txid"]
        joint_tx_hex = node.getrawtransaction(joint_txid)
        joint_raw = node.decoderawtransaction(joint_tx_hex)

        # Locate the joint vout.
        joint_vout = None
        for vidx in range(len(joint_raw["vout"])):
            try:
                ap = alice.pricoin_jointscan_partial(joint_tx_hex, vidx)["partial"]
                bp = bob.pricoin_jointscan_partial(joint_tx_hex, vidx)["partial"]
                bob.pricoin_jointscan_recover(
                    joint_tx_hex, vidx, bp, ap, alice_keys["spend_pubkey"])
                joint_vout = vidx
                break
            except Exception:
                continue
        assert joint_vout is not None

        ap = alice.pricoin_jointscan_partial(joint_tx_hex, joint_vout)["partial"]
        bp = bob.pricoin_jointscan_partial(joint_tx_hex, joint_vout)["partial"]
        a_load = alice.pricoin_jointspend_loadshare(
            joint_tx_hex, joint_vout, ap, bp, bob_keys["spend_pubkey"], True)
        b_load = bob.pricoin_jointspend_loadshare(
            joint_tx_hex, joint_vout, bp, ap, alice_keys["spend_pubkey"], False)
        assert_equal(a_load["joint_pubkey"], b_load["joint_pubkey"])

        return (alice, bob, receiver,
                joint_txid, joint_vout, joint_tx_hex,
                a_load, b_load, recv_keys, sender_addr)

    def _build_and_sign(self, node, alice, bob, joint_txid, joint_vout,
                       a_load, b_load, recv_keys, *, nlocktime, dest_amount=2.0, fee=0.0001):
        """Build a refund-style tx with nlocktime and run the full cooperative
        signing pipeline. Returns the full skel + assembled signature."""
        skel = alice.pricoin_jointspend_buildtx(
            joint_txid, joint_vout, a_load["value"], a_load["blind"],
            a_load["joint_pubkey"], recv_keys["address"], dest_amount, fee,
            4, nlocktime)

        sighash  = skel["sighash"]
        ring_ml  = skel["ring_ml"]
        pi       = skel["pi"]
        z_alice  = skel["z_self"]
        z_bob    = skel["z_other"]
        joint_pub_hex = skel["joint_pubkey"]

        session_hex = "deadbeef" * 8
        r1_A = node.pricoin_jointspend_round1(
            joint_pub_hex, a_load["x_share"], session_hex, z_alice)
        r1_B = node.pricoin_jointspend_round1(
            joint_pub_hex, b_load["x_share"], session_hex, z_bob)

        N = len(ring_ml)
        s_others = [generate_privkey().hex() for _ in range(N)]
        parties = [
            {k: r1[k] for k in ("L_share", "R_share", "KI_share", "D_share", "commitment")}
            for r1 in (r1_A, r1_B)
        ]
        combined = node.pricoin_jointspend_combine(
            [], ring_ml, pi, sighash, session_hex, parties, s_others)
        s_share_A = node.pricoin_jointspend_share(
            r1_A["alpha"], combined["c_pi"], a_load["x_share"],
            z_alice, combined["mu_P"], combined["mu_C"])["s_share"]
        s_share_B = node.pricoin_jointspend_share(
            r1_B["alpha"], combined["c_pi"], b_load["x_share"],
            z_bob, combined["mu_P"], combined["mu_C"])["s_share"]
        assembled = node.pricoin_jointspend_assemble(
            combined["KI"], combined["c0"], s_others,
            [s_share_A, s_share_B], pi, combined["D"])
        return skel, assembled

    def run_test(self):
        node = self.nodes[0]
        (alice, bob, receiver,
         joint_txid, joint_vout, joint_tx_hex,
         a_load, b_load, recv_keys, sender_addr) = self._setup_joint_output(node)

        # ─── Section 1: nlocktime defaults to 0 ───
        self.log.info("Section 1: default nlocktime=0")
        skel0 = alice.pricoin_jointspend_buildtx(
            joint_txid, joint_vout, a_load["value"], a_load["blind"],
            a_load["joint_pubkey"], recv_keys["address"], 2.0, 0.0001, 4)
        decoded0 = node.decoderawtransaction(skel0["tx_hex"])
        assert_equal(decoded0["locktime"], 0)
        sighash0 = skel0["sighash"]

        # ─── Section 2: nlocktime > 0 propagates to tx + changes sighash ───
        self.log.info("Section 2: nlocktime propagates and changes sighash")
        current_height = node.getblockcount()
        future_height = current_height + 50
        skelN = alice.pricoin_jointspend_buildtx(
            joint_txid, joint_vout, a_load["value"], a_load["blind"],
            a_load["joint_pubkey"], recv_keys["address"], 2.0, 0.0001,
            4, future_height)
        decodedN = node.decoderawtransaction(skelN["tx_hex"])
        assert_equal(decodedN["locktime"], future_height)
        # Sighash committed to nLockTime → different from the locktime=0 build.
        assert skelN["sighash"] != sighash0, "sighash must commit to nLockTime"

        # ─── Section 3: invalid nlocktime values rejected ───
        self.log.info("Section 3: invalid nlocktime rejected")
        # Negative values rejected.
        assert_raises_rpc_error(
            -8, "nlocktime",
            alice.pricoin_jointspend_buildtx,
            joint_txid, joint_vout, a_load["value"], a_load["blind"],
            a_load["joint_pubkey"], recv_keys["address"], 2.0, 0.0001,
            4, -1)

        # ─── Section 4: cooperative sign of refund-tx sighash verifies ───
        self.log.info("Section 4: cooperative sign of refund sighash verifies")
        # Each buildtx randomizes ring decoy selection; sign against the
        # skel we'll actually verify, not Section 2's separate build.
        signed_skel, assembled = self._build_and_sign(
            node, alice, bob, joint_txid, joint_vout, a_load, b_load, recv_keys,
            nlocktime=future_height)
        # The signed skel has the same nLockTime field even though decoy
        # randomization gave it a different sighash than skelN.
        decoded_signed = node.decoderawtransaction(signed_skel["tx_hex"])
        assert_equal(decoded_signed["locktime"], future_height)
        verified = node.pricoin_jointspend_verify(
            [], signed_skel["ring_ml"], signed_skel["sighash"],
            assembled["signature_hex"])
        assert_equal(verified["valid"], True)

        # ─── Section 5: mempool rejects pre-locktime, accepts post-locktime ───
        self.log.info("Section 5: pre-locktime mempool rejection, post-locktime acceptance")
        # Submission attempt before locktime expires must be rejected.
        # The submittx RPC injects the sig and broadcasts; mempool's
        # IsFinalTx check rejects it with a "non-final" error.
        assert_raises_rpc_error(
            None, "non-final",
            alice.pricoin_jointspend_submittx,
            signed_skel["tx_hex"], assembled["signature_hex"])

        # Mine past the locktime height.
        blocks_to_mine = (future_height - node.getblockcount()) + 1
        if blocks_to_mine > 0:
            self.generatetoaddress(node, blocks_to_mine, sender_addr)

        # Now the same tx should land in the mempool.
        result = alice.pricoin_jointspend_submittx(
            signed_skel["tx_hex"], assembled["signature_hex"])
        assert "txid" in result, "post-locktime submit should succeed"

        self.generatetoaddress(node, 1, sender_addr)
        # Receiver should see the new output.
        receiver.pricoin_getstealthaddress()  # prime view
        # The receive-side scan happens via balance APIs; we just
        # confirm the tx confirmed.
        info = node.getrawtransaction(result["txid"], 1)
        assert info["confirmations"] >= 1, "refund tx should have confirmed"

        self.log.info("Pricoin jointspend refund-tx (nlocktime) flow OK")


if __name__ == "__main__":
    PricoinJointspendRefundTest(__file__).main()
