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
        # No wallet ops needed — these are node-level RPCs.
        pass

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


if __name__ == "__main__":
    PricoinJointSpendTest(__file__).main()
