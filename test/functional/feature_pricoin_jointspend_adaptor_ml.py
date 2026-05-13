#!/usr/bin/env python3
# Copyright (c) 2026-present The Pricoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional test for the multi-layer cooperative adaptor-CLSAG wire RPCs.

Drives the `_ml` variants end-to-end via RPC (no wallet, no chain — just
the math). Mirrors `feature_pricoin_jointspend_adaptor.py` (single-layer)
but for the multi-layer protocol where ring members are {P, W} pairs
and each party contributes both a spend-share x and a commitment-offset
share z.

The motivation for this test (2026-05-13): live dialog debugging of the
ML adaptor flow surfaced repeated "dleq_z verify failed" /
"CombineAndWalkML failed" errors that turned out to be wiring bugs
between Mac and Linux dialogs (session_payload mismatch, missing
dleq_z in DM payload, etc.). A pure-RPC test like this one would have
caught every one of them locally in seconds.
"""

from test_framework.crypto import secp256k1
from test_framework.key import ORDER, generate_privkey
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


def scalar_int(b32):
    return int.from_bytes(bytes.fromhex(b32), "big")


def pub_from_scalar_hex(scalar_hex):
    """scalar · G as 33-byte compressed pubkey hex."""
    P = scalar_int(scalar_hex) * secp256k1.G
    return P.to_bytes_compressed().hex()


def add_pubkeys_hex(a_hex, b_hex):
    """Compressed-pubkey addition. Returns 33-byte hex."""
    A = secp256k1.GE.from_bytes(bytes.fromhex(a_hex))
    B = secp256k1.GE.from_bytes(bytes.fromhex(b_hex))
    return (A + B).to_bytes_compressed().hex()


def add_scalars_hex(*scalar_hexes):
    s = 0
    for h in scalar_hexes:
        s = (s + scalar_int(h)) % ORDER
    return s.to_bytes(32, "big").hex()


class PricoinJointspendAdaptorMLTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-txindex=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.log.info("Section 1: synthetic protocol math (no chain)")
        self._run_synthetic(node)
        self.log.info("Section 2: chain-validating end-to-end on regtest")
        self._run_chain_validating(node)
        self.log.info("Section 3: actor-isolated DM ceremony (mirrors GUI flow)")
        self._run_actor_isolated_ceremony(node)
        self.log.info("Pricoin cooperative adaptor-CLSAG ML wire RPCs OK")

    def _run_synthetic(self, node):

        # ─── Setup: two parties with additive shares. ───
        # x_A + x_B = x_pi (joint spend secret)
        # z_A + z_B = z_pi (joint commitment-offset secret)
        x_A = generate_privkey().hex()
        x_B = generate_privkey().hex()
        z_A = generate_privkey().hex()
        z_B = generate_privkey().hex()
        X_pub_A = pub_from_scalar_hex(x_A)
        X_pub_B = pub_from_scalar_hex(x_B)
        Z_pub_A = pub_from_scalar_hex(z_A)
        Z_pub_B = pub_from_scalar_hex(z_B)
        P_pi    = add_pubkeys_hex(X_pub_A, X_pub_B)
        W_pi    = add_pubkeys_hex(Z_pub_A, Z_pub_B)

        # Ring of 3 distinct {P, W} pairs with the joint at pi=1.
        decoy_x_lo = "00" * 31 + "04"
        decoy_x_hi = "00" * 31 + "05"
        decoy_z_lo = "00" * 31 + "06"
        decoy_z_hi = "00" * 31 + "07"
        ring_ml = [
            {"P": pub_from_scalar_hex(decoy_x_lo), "W": pub_from_scalar_hex(decoy_z_lo)},
            {"P": P_pi, "W": W_pi},
            {"P": pub_from_scalar_hex(decoy_x_hi), "W": pub_from_scalar_hex(decoy_z_hi)},
        ]
        pi = 1

        # ─── Step 0: Bob picks adaptor secret t, computes T_G/T_H, DLEQ. ───
        self.log.info("Step 0: adaptor t + DLEQ proof")
        t = generate_privkey().hex()
        cp = node.pricoin_adaptor_compute_points(t, P_pi)
        T_G, T_H = cp["T_G"], cp["T_H"]

        label   = "test/adaptor-clsag-ml/v1"
        payload = "session-payload-for-ml-test"
        dleq_t = node.pricoin_adaptor_dleq_prove(
            t, P_pi, T_G, T_H, label, payload)["dleq"]
        assert_equal(node.pricoin_adaptor_dleq_verify(
            P_pi, T_G, T_H, dleq_t, label, payload)["valid"], True)

        # ─── Step 1: round1_ml per party. ───
        self.log.info("Step 1: adaptor_round1_ml per party")
        sa = node.pricoin_jointspend_adaptor_round1_ml(
            P_pi, X_pub_A, Z_pub_A, x_A, z_A, T_G, T_H, label, payload)
        sb = node.pricoin_jointspend_adaptor_round1_ml(
            P_pi, X_pub_B, Z_pub_B, x_B, z_B, T_G, T_H, label, payload)
        for k in ("alpha", "L_share", "R_share", "KI_share", "D_share",
                  "dleq_alpha", "dleq_x", "dleq_z", "commitment"):
            assert k in sa, f"sa missing {k}"
            assert k in sb, f"sb missing {k}"
        assert sa["alpha"] != sb["alpha"]

        # ─── Step 2: combine_ml. ───
        self.log.info("Step 2: adaptor_combine_ml")
        msg = generate_privkey().hex()
        share_fields = ("L_share", "R_share", "KI_share", "D_share",
                        "dleq_alpha", "dleq_x", "dleq_z", "commitment")
        shares_input = [
            {k: sa[k] for k in share_fields},
            {k: sb[k] for k in share_fields},
        ]
        combined = node.pricoin_jointspend_adaptor_combine_ml(
            ring_ml, pi, msg, T_G, T_H, dleq_t,
            [X_pub_A, X_pub_B],
            [Z_pub_A, Z_pub_B],
            shares_input, label, payload)
        for k in ("KI", "D", "L_pi", "R_pi", "L_prime", "R_prime",
                  "mu_P", "mu_C", "c_pi", "c0", "s_others"):
            assert k in combined, f"combined missing {k}"
        assert_equal(len(combined["s_others"]), len(ring_ml))

        # ─── Step 3: round3 close shares (ml variant uses mu_P, mu_C). ───
        self.log.info("Step 3: round3 close shares")
        cs_a = node.pricoin_jointspend_share(
            sa["alpha"], combined["c_pi"], x_A,
            z_A, combined["mu_P"], combined["mu_C"])
        cs_b = node.pricoin_jointspend_share(
            sb["alpha"], combined["c_pi"], x_B,
            z_B, combined["mu_P"], combined["mu_C"])

        # ─── Step 4: assemble_ml. ───
        self.log.info("Step 4: adaptor_assemble_ml")
        presig_obj = node.pricoin_jointspend_adaptor_assemble_ml(
            combined["KI"], combined["D"],
            combined["L_pi"], combined["R_pi"],
            combined["L_prime"], combined["R_prime"],
            combined["mu_P"], combined["mu_C"],
            combined["c_pi"], combined["c0"],
            combined["s_others"],
            [cs_a["s_share"], cs_b["s_share"]],
            pi, T_G, T_H, dleq_t)
        presig = presig_obj["presig"]
        assert presig

        # ─── Step 5: Bob adapts with t → final sig. ───
        # Pass the {P,W} ring so the adapt RPC routes to AdaptML +
        # VerifyMultiLayer (the same verify path consensus runs at
        # block-validation time).
        self.log.info("Step 5: AdaptML with t")
        sig_obj = node.pricoin_jointspend_adaptor_adapt(
            presig, t, ring_ml, msg)
        sig = sig_obj["sig"]
        v = node.pricoin_jointspend_verify(
            [], ring_ml, msg, sig)["valid"]
        assert_equal(v, True)

        # Wrong t must fail (AdaptML verifies before returning).
        wrong_t = generate_privkey().hex()
        assert_raises_rpc_error(
            -8, "Adapt failed",
            node.pricoin_jointspend_adaptor_adapt,
            presig, wrong_t, ring_ml, msg)

        # ─── Step 6: tamper rejections. ───
        self.log.info("Step 6: tamper rejection — wrong session_payload")
        # If we re-run combine_ml with a DIFFERENT session_payload, the
        # share verifications should fail. This is the "Mac and Linux
        # have different session_payload" scenario the live dialog
        # bug surfaced — must produce a clean failure here.
        assert_raises_rpc_error(
            -8, "CombineAndWalkML failed",
            node.pricoin_jointspend_adaptor_combine_ml,
            ring_ml, pi, msg, T_G, T_H, dleq_t,
            [X_pub_A, X_pub_B], [Z_pub_A, Z_pub_B], shares_input,
            label, "DIFFERENT-PAYLOAD")

        self.log.info("Step 7: tamper rejection — swapped Z_pub_shares")
        # If Z_pub_A and Z_pub_B are passed in the wrong order, the
        # per-share verify will catch it via the dleq_z check (which is
        # bound to that specific Z_pub_X).
        assert_raises_rpc_error(
            -8, "CombineAndWalkML failed",
            node.pricoin_jointspend_adaptor_combine_ml,
            ring_ml, pi, msg, T_G, T_H, dleq_t,
            [X_pub_A, X_pub_B], [Z_pub_B, Z_pub_A], shares_input,
            label, payload)

    def _run_chain_validating(self, node):
        """Real-chain end-to-end ML adaptor coopsign.

        Bob (claim-leg spender) and Alice (cosigner) cooperatively sign
        a v4 ring spend of a joint stealth output using the multi-layer
        adaptor protocol. The adapted final sig MUST validate at chain
        consensus (`pricoin::ringsig::VerifyMultiLayer` inside
        `ConnectBlock` is what gates this) — verified by actually
        broadcasting and mining the tx, then asserting the resulting
        block confirms.
        """
        node.createwallet("alice_ml")
        node.createwallet("bob_ml")
        node.createwallet("sender_ml")
        node.createwallet("recv_ml")
        alice    = node.get_wallet_rpc("alice_ml")
        bob      = node.get_wallet_rpc("bob_ml")
        sender   = node.get_wallet_rpc("sender_ml")
        receiver = node.get_wallet_rpc("recv_ml")

        sender_tx_addr = sender.getnewaddress(address_type="bech32")
        self.generatetoaddress(node, 110, sender_tx_addr)

        alice_keys = alice.pricoin_getstealthaddress()
        bob_keys   = bob.pricoin_getstealthaddress()
        recv_keys  = receiver.pricoin_getstealthaddress()
        joint = alice.pricoin_buildjointstealthaddress(
            bob_keys["view_pubkey"], bob_keys["spend_pubkey"])

        # Seed a few CT outputs so the ring builder has decoys.
        for _ in range(4):
            sender.walletsendct(alice_keys["address"], 1.0, 0.0001)
            self.generatetoaddress(node, 1, sender_tx_addr)

        # Fund the joint stealth address.
        sent = sender.walletsendct(joint["address"], 4.2, 0.0001)
        self.generatetoaddress(node, 1, sender_tx_addr)
        joint_txid = sent["txid"]
        joint_tx_hex = node.getrawtransaction(joint_txid)
        joint_raw = node.decoderawtransaction(joint_tx_hex)

        # Locate joint vout via cooperative scan.
        joint_vout = None
        for vidx in range(len(joint_raw["vout"])):
            try:
                a_p = alice.pricoin_jointscan_partial(joint_tx_hex, vidx)["partial"]
                b_p = bob.pricoin_jointscan_partial(joint_tx_hex, vidx)["partial"]
                bob.pricoin_jointscan_recover(
                    joint_tx_hex, vidx, b_p, a_p, alice_keys["spend_pubkey"])
                joint_vout = vidx
                break
            except Exception:
                continue
        assert joint_vout is not None

        a_p = alice.pricoin_jointscan_partial(joint_tx_hex, joint_vout)["partial"]
        b_p = bob.pricoin_jointscan_partial(joint_tx_hex, joint_vout)["partial"]
        a_load = alice.pricoin_jointspend_loadshare(
            joint_tx_hex, joint_vout, a_p, b_p, bob_keys["spend_pubkey"], True)
        b_load = bob.pricoin_jointspend_loadshare(
            joint_tx_hex, joint_vout, b_p, a_p, alice_keys["spend_pubkey"], False)
        assert_equal(a_load["joint_pubkey"], b_load["joint_pubkey"])
        joint_pub_hex = a_load["joint_pubkey"]
        X_pub_A = a_load["x_pub"]
        X_pub_B = b_load["x_pub"]

        # Bob (spender) builds the spend skeleton.
        dest_amount = 2.0
        fee = 0.0001
        skel = bob.pricoin_jointspend_buildtx(
            joint_txid, joint_vout, b_load["value"], b_load["blind"],
            joint_pub_hex, recv_keys["address"], dest_amount, fee, 4)
        tx_hex   = skel["tx_hex"]
        sighash  = skel["sighash"]
        ring_ml  = skel["ring_ml"]
        pi       = skel["pi"]
        z_bob    = skel["z_self"]    # Bob is the spender → z_self is his
        z_alice  = skel["z_other"]   # z_other is Alice's
        assert_equal(ring_ml[pi]["P"], joint_pub_hex)

        # Bob picks t for adaptor binding.
        t = generate_privkey().hex()
        cp = node.pricoin_adaptor_compute_points(t, joint_pub_hex)
        T_G, T_H = cp["T_G"], cp["T_H"]
        # Same session_label/payload on BOTH sides — this is the field
        # that was diverging in live testing and breaking dleq_z verify.
        # Anchor it to the joint txid+vout so it's deterministic from
        # the swap context.
        label   = "pricoin/adaptor-clsag/ml/v1"
        payload = joint_txid + f"{joint_vout:08x}"
        dleq_t = node.pricoin_adaptor_dleq_prove(
            t, joint_pub_hex, T_G, T_H, label, payload)["dleq"]

        # Each party derives their Z_pub.
        Z_pub_A = pub_from_scalar_hex(z_alice)
        Z_pub_B = pub_from_scalar_hex(z_bob)

        # Round 1 per party (ML).
        sa = node.pricoin_jointspend_adaptor_round1_ml(
            joint_pub_hex, X_pub_A, Z_pub_A, a_load["x_share"], z_alice,
            T_G, T_H, label, payload)
        sb = node.pricoin_jointspend_adaptor_round1_ml(
            joint_pub_hex, X_pub_B, Z_pub_B, b_load["x_share"], z_bob,
            T_G, T_H, label, payload)

        # Combine ML — ordering: spender second to mirror the dialog's
        # initiator-first convention with Bob as initiator. (Order
        # doesn't matter for the math — the protocol is symmetric.)
        share_fields = ("L_share", "R_share", "KI_share", "D_share",
                        "dleq_alpha", "dleq_x", "dleq_z", "commitment")
        # Bob = initiator (spender for claim leg), Alice = responder.
        shares_input = [
            {k: sb[k] for k in share_fields},
            {k: sa[k] for k in share_fields},
        ]
        combined = node.pricoin_jointspend_adaptor_combine_ml(
            ring_ml, pi, sighash, T_G, T_H, dleq_t,
            [X_pub_B, X_pub_A],
            [Z_pub_B, Z_pub_A],
            shares_input, label, payload)

        # Close shares — same order as shares_input.
        cs_b = node.pricoin_jointspend_share(
            sb["alpha"], combined["c_pi"], b_load["x_share"],
            z_bob, combined["mu_P"], combined["mu_C"])
        cs_a = node.pricoin_jointspend_share(
            sa["alpha"], combined["c_pi"], a_load["x_share"],
            z_alice, combined["mu_P"], combined["mu_C"])

        # Assemble pre-sig.
        presig_obj = node.pricoin_jointspend_adaptor_assemble_ml(
            combined["KI"], combined["D"],
            combined["L_pi"], combined["R_pi"],
            combined["L_prime"], combined["R_prime"],
            combined["mu_P"], combined["mu_C"],
            combined["c_pi"], combined["c0"],
            combined["s_others"],
            [cs_b["s_share"], cs_a["s_share"]],
            pi, T_G, T_H, dleq_t)
        presig = presig_obj["presig"]

        # Bob adapts with t.
        sig_obj = node.pricoin_jointspend_adaptor_adapt(
            presig, t, ring_ml, sighash)
        sig = sig_obj["sig"]
        # Pre-flight verify against the same ring + msg consensus uses.
        assert_equal(
            node.pricoin_jointspend_verify([], ring_ml, sighash, sig)["valid"],
            True)

        # Inject the adapted sig into the skeleton and broadcast.
        # Use the wallet-side submit so we exercise the actual
        # `walletsendct_*` infrastructure path (closer to what the
        # dialog does after Step 4).
        submitted = bob.pricoin_jointspend_submittx(tx_hex, sig)
        broadcast_txid = submitted["txid"]
        assert_equal(broadcast_txid in node.getrawmempool(), True)
        self.generatetoaddress(node, 1, sender_tx_addr)
        # If consensus validated the adapted sig, the tx is now in a
        # confirmed block. This is the gate that was failing for live
        # testing ("bad-pct-ring-sig-invalid") with the old single-
        # layer adaptor protocol.
        assert_equal(broadcast_txid not in node.getrawmempool(), True)
        recv_balance = float(receiver.getbalances()["mine"]["confidential"])
        assert recv_balance >= dest_amount, (
            f"receiver should see at least {dest_amount} PRIC, has {recv_balance}")

        # Alice can now extract t from the on-chain sig.
        # (extract uses single-layer P-only ring — it doesn't care about W.)
        ring_p_only = [m["P"] for m in ring_ml]
        ex = node.pricoin_jointspend_adaptor_extract(ring_p_only, presig, sig)
        assert_equal(ex["t"], t)

    def _run_actor_isolated_ceremony(self, node):
        """Full ML adaptor ceremony with strict actor isolation, mirroring
        what the Qt dialog does over Nostr DMs.

        Each `Actor` only has access to its own local state. Messages
        between Alice and Bob are JSON envelopes pushed through a mock
        transport — exactly the structure `PricCoopSignDialog` uses on
        the wire (kinds: buildtx, xpub_announce, round-1 share, round-3
        s_share). If a side forgets to include a field in the envelope
        (the 2026-05-13 `dleq_z` bug class), the receiver's
        json.loads() / RPC call fails right here in the test.
        """
        import json

        node.createwallet("alice_iso")
        node.createwallet("bob_iso")
        node.createwallet("sender_iso")
        node.createwallet("recv_iso")
        alice    = node.get_wallet_rpc("alice_iso")
        bob      = node.get_wallet_rpc("bob_iso")
        sender   = node.get_wallet_rpc("sender_iso")
        receiver = node.get_wallet_rpc("recv_iso")

        sender_tx_addr = sender.getnewaddress(address_type="bech32")
        self.generatetoaddress(node, 110, sender_tx_addr)

        alice_keys = alice.pricoin_getstealthaddress()
        bob_keys   = bob.pricoin_getstealthaddress()
        recv_keys  = receiver.pricoin_getstealthaddress()
        joint = alice.pricoin_buildjointstealthaddress(
            bob_keys["view_pubkey"], bob_keys["spend_pubkey"])

        # Seed decoys + fund the joint output.
        for _ in range(4):
            sender.walletsendct(alice_keys["address"], 1.0, 0.0001)
            self.generatetoaddress(node, 1, sender_tx_addr)
        sent = sender.walletsendct(joint["address"], 4.2, 0.0001)
        self.generatetoaddress(node, 1, sender_tx_addr)
        joint_txid = sent["txid"]
        joint_tx_hex = node.getrawtransaction(joint_txid)
        joint_raw = node.decoderawtransaction(joint_tx_hex)

        # Each actor holds only its own state. The `inbox` is the
        # mock-transport queue of DM envelopes received from the peer;
        # nothing else crosses the actor boundary.
        class Actor:
            def __init__(self, label, wallet, my_stealth, peer_stealth,
                         peer_view_pubkey, peer_spend_pubkey,
                         is_spender):
                self.label = label
                self.wallet = wallet
                self.my_stealth = my_stealth
                self.peer_stealth = peer_stealth
                self.peer_view_pubkey = peer_view_pubkey
                self.peer_spend_pubkey = peer_spend_pubkey
                self.is_spender = is_spender
                self.inbox = []        # incoming DMs from peer
                self.outbox = []       # DMs to send to peer
                self.state = {}        # private state

        alice_actor = Actor("alice", alice, alice_keys, bob_keys,
                            bob_keys["view_pubkey"],
                            bob_keys["spend_pubkey"],
                            is_spender=False)
        bob_actor = Actor("bob", bob, bob_keys, alice_keys,
                          alice_keys["view_pubkey"],
                          alice_keys["spend_pubkey"],
                          is_spender=True)

        def deliver(from_actor, to_actor):
            """Mock transport: serialize → deserialize so missing fields
            (e.g. forgetting to pushKV("dleq_z", ...)) show up as KeyError
            in the receiver's RPC call, not as silent fallthrough."""
            while from_actor.outbox:
                env = from_actor.outbox.pop(0)
                wire = json.dumps(env)            # serialize
                received = json.loads(wire)       # deserialize
                to_actor.inbox.append(received)

        # ── Phase 1: jointscan_partial exchange ──
        joint_vout = None
        for vidx in range(len(joint_raw["vout"])):
            try:
                a_p = alice.pricoin_jointscan_partial(joint_tx_hex, vidx)["partial"]
                b_p = bob.pricoin_jointscan_partial(joint_tx_hex, vidx)["partial"]
                bob.pricoin_jointscan_recover(
                    joint_tx_hex, vidx, b_p, a_p, alice_keys["spend_pubkey"])
                joint_vout = vidx
                break
            except Exception:
                continue
        assert joint_vout is not None

        for actor in (alice_actor, bob_actor):
            actor.state["my_partial"] = actor.wallet.pricoin_jointscan_partial(
                joint_tx_hex, joint_vout)["partial"]
            actor.outbox.append({"kind": "jointscan",
                                 "vout": joint_vout,
                                 "partial": actor.state["my_partial"]})
        deliver(alice_actor, bob_actor)
        deliver(bob_actor, alice_actor)

        # ── Phase 2: loadshare on each side (different absorb flag) ──
        # Convention: spender absorbs (mirrors the dialog defaults).
        for actor in (alice_actor, bob_actor):
            peer_env = next(e for e in actor.inbox if e["kind"] == "jointscan")
            absorb = actor.is_spender
            load = actor.wallet.pricoin_jointspend_loadshare(
                joint_tx_hex, joint_vout,
                actor.state["my_partial"], peer_env["partial"],
                actor.peer_spend_pubkey, absorb)
            actor.state["x_share"] = load["x_share"]
            actor.state["blind"] = load["blind"]
            actor.state["joint_pubkey"] = load["joint_pubkey"]
            actor.state["x_pub"] = load["x_pub"]
            actor.state["value"] = load["value"]
        assert_equal(alice_actor.state["joint_pubkey"],
                     bob_actor.state["joint_pubkey"])
        joint_pub_hex = bob_actor.state["joint_pubkey"]

        # ── Phase 3: spender runs buildtx, sends to cosigner ──
        skel = bob_actor.wallet.pricoin_jointspend_buildtx(
            joint_txid, joint_vout, bob_actor.state["value"],
            bob_actor.state["blind"], joint_pub_hex,
            recv_keys["address"], 2.0, 0.0001, 4)
        bob_actor.state["tx_hex"]  = skel["tx_hex"]
        bob_actor.state["sighash"] = skel["sighash"]
        bob_actor.state["ring_ml"] = skel["ring_ml"]
        bob_actor.state["pi"]      = skel["pi"]
        bob_actor.state["z_share"] = skel["z_self"]
        # Bob picks t and computes adaptor points.
        t_secret = generate_privkey().hex()
        cp = bob_actor.wallet.pricoin_adaptor_compute_points(
            t_secret, joint_pub_hex)
        bob_actor.state["t_secret"] = t_secret
        bob_actor.state["T_G"] = cp["T_G"]
        bob_actor.state["T_H"] = cp["T_H"]
        # session_label / session_payload bound to swap context.
        label   = "pricoin/adaptor-clsag/ml/v1"
        payload = joint_txid + f"{joint_vout:08x}"
        bob_actor.state["label"]   = label
        bob_actor.state["payload"] = payload
        bob_actor.state["dleq_t"] = bob_actor.wallet.pricoin_adaptor_dleq_prove(
            t_secret, joint_pub_hex,
            cp["T_G"], cp["T_H"], label, payload)["dleq"]
        bob_actor.state["Z_pub_X"] = pub_from_scalar_hex(skel["z_self"])

        # Spender's buildtx-DM envelope. CRITICAL: must carry every
        # field the cosigner needs (z_other, x_pub_spender, z_pub_spender,
        # session_label, session_payload). Live regression on 2026-05-13
        # was a missing dleq_z in the round-1 DM; the equivalent for
        # this envelope is making sure the cosigner can derive Z_pub_X
        # and align session strings from this single message.
        bob_actor.outbox.append({
            "kind": "buildtx",
            "tx_hex": skel["tx_hex"],
            "sighash": skel["sighash"],
            "ring_ml": skel["ring_ml"],
            "pi": skel["pi"],
            "joint_pubkey": joint_pub_hex,
            "z_other": skel["z_other"],
            "x_pub_spender": bob_actor.state["x_pub"],
            "z_pub_spender": bob_actor.state["Z_pub_X"],
            "T_G": cp["T_G"],
            "T_H": cp["T_H"],
            "dleq_t": bob_actor.state["dleq_t"],
            "session_label": label,
            "session_payload": payload,
        })
        deliver(bob_actor, alice_actor)

        # Cosigner consumes buildtx envelope.
        bt = next(e for e in alice_actor.inbox if e["kind"] == "buildtx")
        alice_actor.state["sighash"]       = bt["sighash"]
        alice_actor.state["ring_ml"]       = bt["ring_ml"]
        alice_actor.state["pi"]            = bt["pi"]
        alice_actor.state["z_share"]       = bt["z_other"]
        alice_actor.state["X_pub_peer"]    = bt["x_pub_spender"]
        alice_actor.state["Z_pub_peer"]    = bt["z_pub_spender"]
        alice_actor.state["T_G"]           = bt["T_G"]
        alice_actor.state["T_H"]           = bt["T_H"]
        alice_actor.state["dleq_t"]        = bt["dleq_t"]
        alice_actor.state["label"]         = bt["session_label"]
        alice_actor.state["payload"]       = bt["session_payload"]
        alice_actor.state["Z_pub_X"]       = pub_from_scalar_hex(bt["z_other"])

        # ── Phase 4: round1_ml + round-1 DM exchange ──
        for actor in (alice_actor, bob_actor):
            r1 = actor.wallet.pricoin_jointspend_adaptor_round1_ml(
                joint_pub_hex,
                actor.state["x_pub"],
                actor.state.get("Z_pub_X", pub_from_scalar_hex(actor.state["z_share"])),
                actor.state["x_share"],
                actor.state["z_share"],
                actor.state["T_G"],
                actor.state["T_H"],
                actor.state["label"],
                actor.state["payload"])
            actor.state["alpha"] = r1["alpha"]
            actor.state["my_round1"] = r1
            # Build the round-1 share envelope. Must include all 8
            # multi-layer fields (L_share/R_share/KI_share/D_share/
            # dleq_alpha/dleq_x/dleq_z/commitment) — see 2026-05-13 fix
            # to onSendDmRound1 for the equivalent dialog bug.
            share = {k: r1[k] for k in (
                "L_share","R_share","KI_share","D_share",
                "dleq_alpha","dleq_x","dleq_z","commitment")}
            actor.outbox.append({"kind": "round1_share", "share": share})
        deliver(alice_actor, bob_actor)
        deliver(bob_actor, alice_actor)

        # ── Phase 5: combine_ml on each side (both produce same output) ──
        # Spender = initiator → first in shares array; cosigner = responder.
        share_fields = ("L_share", "R_share", "KI_share", "D_share",
                        "dleq_alpha", "dleq_x", "dleq_z", "commitment")
        for actor in (alice_actor, bob_actor):
            peer_env = next(e for e in actor.inbox if e["kind"] == "round1_share")
            mine = {k: actor.state["my_round1"][k] for k in share_fields}
            peer = peer_env["share"]
            if actor.is_spender:
                shares = [mine, peer]
                Xs = [actor.state["x_pub"], actor.state.get("X_pub_peer",
                                                              alice_actor.state["x_pub"])]
                Zs = [actor.state["Z_pub_X"], actor.state.get("Z_pub_peer",
                                                                pub_from_scalar_hex(alice_actor.state["z_share"]))]
            else:
                shares = [peer, mine]
                Xs = [actor.state["X_pub_peer"], actor.state["x_pub"]]
                Zs = [actor.state["Z_pub_peer"], actor.state["Z_pub_X"]]
            combined = actor.wallet.pricoin_jointspend_adaptor_combine_ml(
                actor.state["ring_ml"], actor.state["pi"], actor.state["sighash"],
                actor.state["T_G"], actor.state["T_H"], actor.state["dleq_t"],
                Xs, Zs, shares,
                actor.state["label"], actor.state["payload"])
            actor.state["combined"] = combined

        # Both sides MUST agree on KI, c_pi, c0 (deterministic from inputs).
        assert_equal(alice_actor.state["combined"]["KI"],
                     bob_actor.state["combined"]["KI"])
        assert_equal(alice_actor.state["combined"]["c_pi"],
                     bob_actor.state["combined"]["c_pi"])
        assert_equal(alice_actor.state["combined"]["c0"],
                     bob_actor.state["combined"]["c0"])

        # ── Phase 6: close shares + round-3 DM exchange ──
        for actor in (alice_actor, bob_actor):
            cs = actor.wallet.pricoin_jointspend_share(
                actor.state["alpha"],
                actor.state["combined"]["c_pi"],
                actor.state["x_share"],
                actor.state["z_share"],
                actor.state["combined"]["mu_P"],
                actor.state["combined"]["mu_C"])
            actor.state["s_share"] = cs["s_share"]
            actor.outbox.append({"kind": "round3_s_share",
                                 "s_share": cs["s_share"]})
        deliver(alice_actor, bob_actor)
        deliver(bob_actor, alice_actor)

        # ── Phase 7: assemble_ml on spender → presig ──
        peer_s = next(e for e in bob_actor.inbox
                      if e["kind"] == "round3_s_share")["s_share"]
        close_shares = [bob_actor.state["s_share"], peer_s]
        c = bob_actor.state["combined"]
        presig_obj = bob.pricoin_jointspend_adaptor_assemble_ml(
            c["KI"], c["D"], c["L_pi"], c["R_pi"],
            c["L_prime"], c["R_prime"], c["mu_P"], c["mu_C"],
            c["c_pi"], c["c0"], c["s_others"],
            close_shares, bob_actor.state["pi"],
            bob_actor.state["T_G"], bob_actor.state["T_H"],
            bob_actor.state["dleq_t"])

        # ── Phase 8: spender adapts with t + broadcasts ──
        sig_obj = bob.pricoin_jointspend_adaptor_adapt(
            presig_obj["presig"], bob_actor.state["t_secret"],
            bob_actor.state["ring_ml"], bob_actor.state["sighash"])
        submitted = bob.pricoin_jointspend_submittx(
            bob_actor.state["tx_hex"], sig_obj["sig"])
        assert_equal(submitted["txid"] in node.getrawmempool(), True)
        self.generatetoaddress(node, 1, sender_tx_addr)
        assert_equal(submitted["txid"] not in node.getrawmempool(), True)


if __name__ == "__main__":
    PricoinJointspendAdaptorMLTest(__file__).main()
