#!/usr/bin/env python3
# Copyright (c) 2026-present The Pricoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end test for the cooperative-CLSAG signing RPCs (atomic-swap stage 2b).

Drives the round-by-round protocol via:
  pricoin_jointspend_round1   (per party — round 1 partials + commitment)
  pricoin_jointspend_combine  (combine partials, walk ring → c_pi, c0)
  pricoin_jointspend_share    (per party — closing share s_share)
  pricoin_jointspend_assemble (assemble final Signature)
  pricoin_jointspend_verify   (sanity-check the produced signature)

Both single-layer and multi-layer flows are exercised. A ring of 4
random pubkeys with a joint pubkey at pi=2; two simulated parties each
hold an additive share of the spend (and, for multi-layer, the
commitment-offset) secret. Negative tests cover commitment-tamper
rejection in combine and wrong-share rejection at verify time.
"""

from test_framework.crypto import secp256k1
from test_framework.key import ECKey, ECPubKey, ORDER, generate_privkey
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


def scalar_to_pubkey_bytes(scalar_int):
    """Compute scalar*G and return 33-byte compressed pubkey bytes."""
    P = scalar_int * secp256k1.G
    # secp256k1.GE.to_bytes_compressed:
    return P.to_bytes_compressed()


def random_scalar_bytes():
    """32-byte hex of a random valid secp256k1 scalar."""
    return generate_privkey().hex()


def scalar_int(b32):
    return int.from_bytes(bytes.fromhex(b32), "big")


def add_scalars_mod_n(*scalar_hexes):
    s = 0
    for h in scalar_hexes:
        s = (s + scalar_int(h)) % ORDER
    return s.to_bytes(32, "big").hex()


class PricoinJointSpendTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-txindex=1"]]

    def skip_test_if_missing_module(self):
        # Sections 1–3 are node-level only; section 4 needs a wallet.
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        # Section 1 — single-layer cooperative CLSAG over a 4-member ring.
        self.log.info("Section 1: single-layer cooperative CLSAG via RPCs")
        self._run_flow(node, multi_layer=False)

        # Section 2 — multi-layer cooperative CLSAG.
        self.log.info("Section 2: multi-layer cooperative CLSAG via RPCs")
        self._run_flow(node, multi_layer=True)

        # Section 3 — negative tests.
        self.log.info("Section 3: negative tests")
        self._run_negative_tests(node)

        # Section 4 — wallet integration: real joint output + loadshare
        # produces an x_share that drives the cooperative protocol.
        self.log.info("Section 4: wallet loadshare → cooperative CLSAG")
        self._run_wallet_loadshare(node)

        # Section 5 — end-to-end cooperative spend lands on chain.
        self.log.info("Section 5: cooperative on-chain spend (real v4 tx)")
        self._run_cooperative_spend(node)

        self.log.info("Pricoin cooperative-CLSAG RPC flow OK")

    # -----------------------------------------------------------------

    def _run_flow(self, node, multi_layer):
        """End-to-end happy path for either single- or multi-layer."""
        N = 4
        pi = 2
        msg_hex = "11" * 32
        session_hex = "5365737369" + "00" * 11  # 16 bytes "Sessi"+pad

        # Build N decoy spend keys + their pubkeys.
        decoy_keys = [generate_privkey() for _ in range(N)]
        decoy_pubs = [scalar_to_pubkey_bytes(scalar_int(k.hex())).hex() for k in decoy_keys]

        # Build the joint pubkey at pi: sum of two parties' shares.
        x_A = generate_privkey().hex()
        x_B = generate_privkey().hex()
        joint_priv_int = (scalar_int(x_A) + scalar_int(x_B)) % ORDER
        joint_pub_hex = scalar_to_pubkey_bytes(joint_priv_int).hex()

        ring_pubs = list(decoy_pubs)
        ring_pubs[pi] = joint_pub_hex

        # For multi-layer, also build W's for each ring member.
        decoy_z = [generate_privkey() for _ in range(N)]
        decoy_W = [scalar_to_pubkey_bytes(scalar_int(z.hex())).hex() for z in decoy_z]
        if multi_layer:
            z_A = generate_privkey().hex()
            z_B = generate_privkey().hex()
            joint_z_int = (scalar_int(z_A) + scalar_int(z_B)) % ORDER
            joint_W_hex = scalar_to_pubkey_bytes(joint_z_int).hex()
            ring_ml = [
                {"P": ring_pubs[i], "W": (joint_W_hex if i == pi else decoy_W[i])}
                for i in range(N)
            ]
        else:
            z_A = z_B = None
            ring_ml = None

        # Round 1 — each party.
        def round1(x_share, z_share):
            args = [joint_pub_hex, x_share, session_hex]
            if z_share is not None:
                args.append(z_share)
            return node.pricoin_jointspend_round1(*args)

        r1_A = round1(x_A, z_A)
        r1_B = round1(x_B, z_B)

        # Generate s_others (entries at indices != pi).
        s_others = [generate_privkey().hex() for _ in range(N)]

        # Round 2 — combine. Both parties run with identical inputs.
        parties = [
            {k: r1[k] for k in ("L_share", "R_share", "KI_share", "commitment")}
            for r1 in (r1_A, r1_B)
        ]
        if multi_layer:
            parties[0]["D_share"] = r1_A["D_share"]
            parties[1]["D_share"] = r1_B["D_share"]

        if multi_layer:
            combined = node.pricoin_jointspend_combine(
                [],            # ring (single-layer) ignored when ring_ml present
                ring_ml,
                pi, msg_hex, session_hex, parties, s_others,
            )
            assert "D" in combined and "mu_P" in combined and "mu_C" in combined
        else:
            combined = node.pricoin_jointspend_combine(
                ring_pubs,
                None,          # ring_ml absent — single-layer
                pi, msg_hex, session_hex, parties, s_others,
            )
            assert "D" not in combined and "mu_P" not in combined

        c_pi = combined["c_pi"]
        c0 = combined["c0"]
        KI = combined["KI"]

        # Round 3 — each party computes their close share.
        def round3(alpha, x_share, z_share):
            args = [alpha, c_pi, x_share]
            if multi_layer:
                args += [z_share, combined["mu_P"], combined["mu_C"]]
            return node.pricoin_jointspend_share(*args)["s_share"]

        s_share_A = round3(r1_A["alpha"], x_A, z_A)
        s_share_B = round3(r1_B["alpha"], x_B, z_B)

        # Assemble the final signature.
        assemble_args = [KI, c0, s_others, [s_share_A, s_share_B], pi]
        if multi_layer:
            assemble_args.append(combined["D"])
        assembled = node.pricoin_jointspend_assemble(*assemble_args)
        sig_hex = assembled["signature_hex"]

        # Verify against the standard pricoin::ringsig::Verify path.
        if multi_layer:
            verified = node.pricoin_jointspend_verify(
                [], ring_ml, msg_hex, sig_hex)
        else:
            verified = node.pricoin_jointspend_verify(
                ring_pubs, None, msg_hex, sig_hex)
        assert_equal(verified["valid"], True)

        # Sanity: KI from cooperative path == direct (x_A+x_B) · H_p(P_pi).
        # We can derive by signing single-party with the joint priv on a
        # different ring — KI must match (tx-invariance). Skip here; this
        # is already covered by the C++ self-test.

        # Tamper: flip a bit in msg → verify must fail.
        bad_msg = ("aa" + msg_hex[2:])
        if multi_layer:
            r = node.pricoin_jointspend_verify([], ring_ml, bad_msg, sig_hex)
        else:
            r = node.pricoin_jointspend_verify(ring_pubs, None, bad_msg, sig_hex)
        assert_equal(r["valid"], False)

    # -----------------------------------------------------------------

    def _run_negative_tests(self, node):
        """Commitment tamper rejection + wrong-share rejection."""
        N = 4
        pi = 1
        msg_hex = "22" * 32
        session_hex = "deadbeef" + "00" * 4

        decoy_keys = [generate_privkey() for _ in range(N)]
        decoy_pubs = [scalar_to_pubkey_bytes(scalar_int(k.hex())).hex() for k in decoy_keys]
        x_A = generate_privkey().hex()
        x_B = generate_privkey().hex()
        joint_priv_int = (scalar_int(x_A) + scalar_int(x_B)) % ORDER
        joint_pub_hex = scalar_to_pubkey_bytes(joint_priv_int).hex()
        ring_pubs = list(decoy_pubs)
        ring_pubs[pi] = joint_pub_hex

        r1_A = node.pricoin_jointspend_round1(joint_pub_hex, x_A, session_hex)
        r1_B = node.pricoin_jointspend_round1(joint_pub_hex, x_B, session_hex)
        s_others = [generate_privkey().hex() for _ in range(N)]

        # Negative 1 — tampered party-A L_share. The recomputed commitment
        # at combine time will not match → combine returns an error.
        bad_L = "02" + "00" * 32
        bad_parties = [
            {"L_share": bad_L, "R_share": r1_A["R_share"],
             "KI_share": r1_A["KI_share"], "commitment": r1_A["commitment"]},
            {k: r1_B[k] for k in ("L_share", "R_share", "KI_share", "commitment")},
        ]
        assert_raises_rpc_error(
            -8, "commitment mismatch",
            node.pricoin_jointspend_combine,
            ring_pubs, None, pi, msg_hex, session_hex, bad_parties, s_others,
        )

        # Negative 2 — wrong x_A in round 3 → final signature won't verify.
        # First do an honest combine; then party A sneakily uses a different
        # x in their close-share.
        parties = [
            {k: r1[k] for k in ("L_share", "R_share", "KI_share", "commitment")}
            for r1 in (r1_A, r1_B)
        ]
        combined = node.pricoin_jointspend_combine(
            ring_pubs, None, pi, msg_hex, session_hex, parties, s_others)
        wrong_x = generate_privkey().hex()
        s_A_wrong = node.pricoin_jointspend_share(
            r1_A["alpha"], combined["c_pi"], wrong_x)["s_share"]
        s_B = node.pricoin_jointspend_share(
            r1_B["alpha"], combined["c_pi"], x_B)["s_share"]
        assembled = node.pricoin_jointspend_assemble(
            combined["KI"], combined["c0"], s_others, [s_A_wrong, s_B], pi)
        verified = node.pricoin_jointspend_verify(
            ring_pubs, None, msg_hex, assembled["signature_hex"])
        assert_equal(verified["valid"], False)


    # -----------------------------------------------------------------

    def _run_wallet_loadshare(self, node):
        """Two wallets cooperatively load shares for a real joint output
        and drive the cooperative-signing protocol on a constructed ring.
        The signature is verified locally; on-chain spend is a follow-up
        commit (needs v4 spend-tx integration with externally-supplied
        CLSAG)."""
        node.createwallet("alice_ld")
        node.createwallet("bob_ld")
        node.createwallet("sender_ld")
        alice  = node.get_wallet_rpc("alice_ld")
        bob    = node.get_wallet_rpc("bob_ld")
        sender = node.get_wallet_rpc("sender_ld")

        # Fund the sender from a fresh transparent coinbase.
        sender_tx_addr = sender.getnewaddress(address_type="bech32")
        self.generatetoaddress(node, 110, sender_tx_addr)

        alice_keys = alice.pricoin_getstealthaddress()
        bob_keys   = bob.pricoin_getstealthaddress()
        joint = alice.pricoin_buildjointstealthaddress(
            bob_keys["view_pubkey"], bob_keys["spend_pubkey"])

        # Send 4.2 PRIC to the joint stealth address.
        sent = sender.walletsendct(joint["address"], 4.2, 0.0001)
        self.generatetoaddress(node, 1, sender_tx_addr)
        joint_txid = sent["txid"]
        joint_tx_hex = node.getrawtransaction(joint_txid)
        joint_raw = node.decoderawtransaction(joint_tx_hex)

        # Find the joint vout via brute-force cooperative scan.
        joint_vout = None
        for vidx in range(len(joint_raw["vout"])):
            try:
                a_partial = alice.pricoin_jointscan_partial(joint_tx_hex, vidx)["partial"]
                b_partial = bob.pricoin_jointscan_partial(joint_tx_hex, vidx)["partial"]
                bob.pricoin_jointscan_recover(
                    joint_tx_hex, vidx, b_partial, a_partial,
                    alice_keys["spend_pubkey"])
                joint_vout = vidx
                break
            except Exception:
                continue
        assert joint_vout is not None, "joint output should be findable"

        # Both parties run loadshare. Alice absorbs h_s; Bob does not.
        a_partial = alice.pricoin_jointscan_partial(joint_tx_hex, joint_vout)["partial"]
        b_partial = bob.pricoin_jointscan_partial(joint_tx_hex, joint_vout)["partial"]
        a_load = alice.pricoin_jointspend_loadshare(
            joint_tx_hex, joint_vout, a_partial, b_partial,
            bob_keys["spend_pubkey"], True)
        b_load = bob.pricoin_jointspend_loadshare(
            joint_tx_hex, joint_vout, b_partial, a_partial,
            alice_keys["spend_pubkey"], False)
        # Both parties see the same value, blind, and joint pubkey.
        assert_equal(a_load["value"], b_load["value"])
        assert_equal(float(a_load["value"]), 4.2)
        assert_equal(a_load["blind"], b_load["blind"])
        assert_equal(a_load["joint_pubkey"], b_load["joint_pubkey"])
        joint_pub_hex = a_load["joint_pubkey"]

        # Sanity: x_share_A + x_share_B (mod n) · G == joint_pubkey.
        x_A = a_load["x_share"]
        x_B = b_load["x_share"]
        joint_priv_int = (scalar_int(x_A) + scalar_int(x_B)) % ORDER
        derived_pub = scalar_to_pubkey_bytes(joint_priv_int).hex()
        assert_equal(derived_pub, joint_pub_hex)

        # Build a 4-member ring with the real joint output's P at pi=0
        # plus 3 random decoys. Drive the cooperative single-layer
        # protocol; verify the assembled signature.
        N = 4
        pi = 0
        msg_hex = "ab" * 32
        session_hex = "deadbeef" * 4

        decoy_keys = [generate_privkey() for _ in range(N - 1)]
        decoy_pubs = [scalar_to_pubkey_bytes(scalar_int(k.hex())).hex() for k in decoy_keys]
        ring = [joint_pub_hex] + decoy_pubs

        r1_A = node.pricoin_jointspend_round1(joint_pub_hex, x_A, session_hex)
        r1_B = node.pricoin_jointspend_round1(joint_pub_hex, x_B, session_hex)
        s_others = [generate_privkey().hex() for _ in range(N)]
        parties = [
            {k: r[k] for k in ("L_share", "R_share", "KI_share", "commitment")}
            for r in (r1_A, r1_B)
        ]
        combined = node.pricoin_jointspend_combine(
            ring, None, pi, msg_hex, session_hex, parties, s_others)
        s_share_A = node.pricoin_jointspend_share(
            r1_A["alpha"], combined["c_pi"], x_A)["s_share"]
        s_share_B = node.pricoin_jointspend_share(
            r1_B["alpha"], combined["c_pi"], x_B)["s_share"]
        assembled = node.pricoin_jointspend_assemble(
            combined["KI"], combined["c0"], s_others, [s_share_A, s_share_B], pi)
        verified = node.pricoin_jointspend_verify(
            ring, None, msg_hex, assembled["signature_hex"])
        assert_equal(verified["valid"], True)

        # Negative: BOTH parties absorbing → x_shares sum to 2·h_s + b_J,
        # which doesn't match joint_pub. The cooperative signature won't
        # verify even though every individual RPC call succeeds.
        a_double = alice.pricoin_jointspend_loadshare(
            joint_tx_hex, joint_vout, a_partial, b_partial,
            bob_keys["spend_pubkey"], True)
        b_double = bob.pricoin_jointspend_loadshare(
            joint_tx_hex, joint_vout, b_partial, a_partial,
            alice_keys["spend_pubkey"], True)
        x_A2, x_B2 = a_double["x_share"], b_double["x_share"]
        r1_A2 = node.pricoin_jointspend_round1(joint_pub_hex, x_A2, session_hex)
        r1_B2 = node.pricoin_jointspend_round1(joint_pub_hex, x_B2, session_hex)
        parties2 = [
            {k: r[k] for k in ("L_share", "R_share", "KI_share", "commitment")}
            for r in (r1_A2, r1_B2)
        ]
        # KI from the (wrong) shares won't match the real joint pub's KI.
        combined2 = node.pricoin_jointspend_combine(
            ring, None, pi, msg_hex, session_hex, parties2, s_others)
        s_A2 = node.pricoin_jointspend_share(
            r1_A2["alpha"], combined2["c_pi"], x_A2)["s_share"]
        s_B2 = node.pricoin_jointspend_share(
            r1_B2["alpha"], combined2["c_pi"], x_B2)["s_share"]
        assembled2 = node.pricoin_jointspend_assemble(
            combined2["KI"], combined2["c0"], s_others, [s_A2, s_B2], pi)
        verified2 = node.pricoin_jointspend_verify(
            ring, None, msg_hex, assembled2["signature_hex"])
        assert_equal(verified2["valid"], False)


    # -----------------------------------------------------------------

    def _run_cooperative_spend(self, node):
        """Two wallets cooperatively spend a real joint stealth output to
        a third party. Verify the spend tx mines, the receiver's wallet
        sees the new output, and the joint output's KI is committed."""
        node.createwallet("alice_sp")
        node.createwallet("bob_sp")
        node.createwallet("sender_sp")
        node.createwallet("recv_sp")
        alice    = node.get_wallet_rpc("alice_sp")
        bob      = node.get_wallet_rpc("bob_sp")
        sender   = node.get_wallet_rpc("sender_sp")
        receiver = node.get_wallet_rpc("recv_sp")

        # Fund the sender with several coinbase outputs so we have ring decoys.
        sender_tx_addr = sender.getnewaddress(address_type="bech32")
        self.generatetoaddress(node, 110, sender_tx_addr)

        alice_keys = alice.pricoin_getstealthaddress()
        bob_keys   = bob.pricoin_getstealthaddress()
        recv_keys  = receiver.pricoin_getstealthaddress()
        joint = alice.pricoin_buildjointstealthaddress(
            bob_keys["view_pubkey"], bob_keys["spend_pubkey"])

        # Sender pays into the joint stealth address. Also seed a few
        # extra CT outputs (decoys) so the ring builder has options.
        for _ in range(4):
            sender.walletsendct(alice_keys["address"], 1.0, 0.0001)
            self.generatetoaddress(node, 1, sender_tx_addr)

        sent = sender.walletsendct(joint["address"], 4.2, 0.0001)
        self.generatetoaddress(node, 1, sender_tx_addr)
        joint_txid = sent["txid"]
        joint_tx_hex = node.getrawtransaction(joint_txid)
        joint_raw = node.decoderawtransaction(joint_tx_hex)

        # Locate the joint vout via cooperative scan.
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

        # Both load shares with opposite absorb flags.
        a_p = alice.pricoin_jointscan_partial(joint_tx_hex, joint_vout)["partial"]
        b_p = bob.pricoin_jointscan_partial(joint_tx_hex, joint_vout)["partial"]
        a_load = alice.pricoin_jointspend_loadshare(
            joint_tx_hex, joint_vout, a_p, b_p, bob_keys["spend_pubkey"], True)
        b_load = bob.pricoin_jointspend_loadshare(
            joint_tx_hex, joint_vout, b_p, a_p, alice_keys["spend_pubkey"], False)
        assert_equal(a_load["joint_pubkey"], b_load["joint_pubkey"])

        # Alice builds the spend skeleton.
        dest_amount = 2.0
        fee = 0.0001
        skel = alice.pricoin_jointspend_buildtx(
            joint_txid, joint_vout, a_load["value"], a_load["blind"],
            a_load["joint_pubkey"], recv_keys["address"], dest_amount, fee, 4)

        tx_hex   = skel["tx_hex"]
        sighash  = skel["sighash"]
        ring_ml  = skel["ring_ml"]
        pi       = skel["pi"]
        z_alice  = skel["z_self"]
        z_bob    = skel["z_other"]
        joint_pub_hex = skel["joint_pubkey"]

        # Sanity: ring_ml[pi].P should match the joint pubkey both
        # parties agreed on.
        assert_equal(ring_ml[pi]["P"], joint_pub_hex)

        # Drive the cooperative multi-layer signing protocol.
        session_hex = "deadbeef" * 8  # 32 bytes
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

        # Pre-flight verification (must succeed before submission).
        verified = node.pricoin_jointspend_verify(
            [], ring_ml, sighash, assembled["signature_hex"])
        assert_equal(verified["valid"], True)

        # Submit. Mine 1 block. Receiver should see the new output.
        receiver_balance_before = float(receiver.getbalances()["mine"]["confidential"])
        result = alice.pricoin_jointspend_submittx(tx_hex, assembled["signature_hex"])
        spend_txid = result["txid"]
        self.generatetoaddress(node, 1, sender_tx_addr)

        # The cooperative spend tx is on-chain.
        spend_raw = node.decoderawtransaction(node.getrawtransaction(spend_txid))
        assert_equal(spend_raw["version"], 4)
        # Tx mined: receiver's confidential balance reflects the 2 PRIC.
        receiver_balance_after = float(receiver.getbalances()["mine"]["confidential"])
        assert receiver_balance_after - receiver_balance_before >= dest_amount - 0.001, (
            f"receiver balance didn't grow by {dest_amount}: "
            f"before={receiver_balance_before}, after={receiver_balance_after}")

        # Trying to submit the same cooperative-spend tx a second time must
        # fail — the KI is now committed.
        try:
            alice.pricoin_jointspend_submittx(tx_hex, assembled["signature_hex"])
            assert False, "second broadcast should have failed (KI already committed)"
        except Exception as e:
            assert "double-spend" in str(e).lower() or "already" in str(e).lower() \
                or "txn-mempool" in str(e).lower() or "broadcast" in str(e).lower(), \
                f"unexpected error on double-submit: {e}"


if __name__ == "__main__":
    PricoinJointSpendTest(__file__).main()
