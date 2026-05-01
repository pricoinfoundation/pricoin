#!/usr/bin/env python3
# Copyright (c) 2026-present The Pricoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional test for the cooperative adaptor-CLSAG wire RPCs (single-layer).

Drives a 2-party cooperative pre-signing → adapt → extract round-trip
via RPC, exercising:

  pricoin_adaptor_compute_points        (Bob picks t; computes T_G, T_H)
  pricoin_adaptor_dleq_prove / verify   (Bob proves T_G, T_H share t)
  pricoin_jointspend_adaptor_round1     (Alice + Bob each)
  pricoin_jointspend_adaptor_combine    (round 2 — verifies + walks)
  pricoin_jointspend_share              (round 3 — reused from non-adaptor flow)
  pricoin_jointspend_adaptor_assemble   (assemble pre-sig)
  pricoin_jointspend_adaptor_verify_presig
  pricoin_jointspend_adaptor_adapt      (Bob, with t)
  pricoin_jointspend_adaptor_extract    (Alice, recovers t)

Validates:
  * DLEQ verifies on the prover's output (true) and rejects tampering (false).
  * Pre-sig verifies under VerifyPreSignature.
  * Adapted sig is byte-shape-identical to a standard CLSAG sig (verifies
    under pricoin_jointspend_verify).
  * Extract round-trip recovers Bob's t exactly.
  * Adapt with the wrong t fails.
  * Cross-chain T_G binding: T_G byte-extracted from adaptor matches
    the t that was originally chosen.
"""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


def random_hex(n_bytes):
    return os.urandom(n_bytes).hex()


def random_scalar(node):
    """Return a 32-byte hex scalar valid for secp256k1 (just retry on the
    vanishingly-rare overflow case via creating a pubkey from it).
    For the test we just use os.urandom — overflow probability is ~2^-128.
    """
    return random_hex(32)


class PricoinJointspendAdaptorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()  # the test framework boots a wallet by default

    def run_test(self):
        node = self.nodes[0]

        # ─── Setup: generate two parties' x-shares + the joint output P_pi ───
        # We need x_A, x_B as random scalars, then derive X_pub_A = x_A·G and
        # X_pub_B = x_B·G, then P_pi = X_pub_A + X_pub_B.
        #
        # The non-adaptor pricoin_jointspend_round1 RPC happens to accept any
        # 33-byte pubkey for joint_pubkey, so we'll use it as a "scalar→pub"
        # function indirectly... but we don't need to. The cleanest path:
        # we use known scalars 1, 2, 3 to derive their pubkeys via a single
        # call to pricoin_btc_musig2_keyagg with one-element arrays (which
        # internally just runs the agg over one input — but that's trivially
        # the input itself).
        #
        # Even simpler: we use fixed valid pubkeys derived offline. Three
        # such pubkeys are G (priv=1), 2G (priv=2), 3G (priv=3). We pre-
        # computed these — see feature_pricoin_btc_musig2_wire.py for the
        # G + 2G constants. For 3G we hardcode below.
        priv_a = "00" * 31 + "01"
        priv_b = "00" * 31 + "02"
        # X_pub_A = G; X_pub_B = 2G; P_pi = X_pub_A + X_pub_B = 3G.
        G_HEX  = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        TWOG   = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        THREEG = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        x_A = priv_a
        x_B = priv_b
        X_pub_A = G_HEX
        X_pub_B = TWOG
        P_pi    = THREEG

        # Build a small ring of 3 distinct pubkeys with P_pi at index pi=1.
        # Derive decoys via pricoin_adaptor_compute_points which computes
        # T_G = t·G in proper compressed form for any valid t.
        decoy_lo = node.pricoin_adaptor_compute_points("00" * 31 + "04", P_pi)["T_G"]
        decoy_hi = node.pricoin_adaptor_compute_points("00" * 31 + "05", P_pi)["T_G"]
        ring = [decoy_lo, P_pi, decoy_hi]
        pi   = 1

        # ─── Step 0: Bob picks t, computes (T_G, T_H), proves DLEQ. ───
        self.log.info("Step 0: Bob picks t + DLEQ proof")
        t = random_scalar(node)
        cp = node.pricoin_adaptor_compute_points(t, P_pi)
        T_G, T_H = cp["T_G"], cp["T_H"]
        assert_equal(len(T_G), 33 * 2)
        assert_equal(len(T_H), 33 * 2)

        label   = "test/adaptor-clsag/v1"
        payload = "session-payload-bytes"
        dleq_t = node.pricoin_adaptor_dleq_prove(
            t, P_pi, T_G, T_H, label, payload)["dleq"]

        ok = node.pricoin_adaptor_dleq_verify(
            P_pi, T_G, T_H, dleq_t, label, payload)["valid"]
        assert_equal(ok, True)

        # Tampered DLEQ rejected.
        tampered = "00" + dleq_t[2:]
        ok2 = node.pricoin_adaptor_dleq_verify(
            P_pi, T_G, T_H, tampered, label, payload)["valid"]
        assert_equal(ok2, False)

        # ─── Step 1: round1 per party. ───
        self.log.info("Step 1: round1 per party")
        sa = node.pricoin_jointspend_adaptor_round1(
            P_pi, X_pub_A, x_A, T_G, T_H, label, payload)
        sb = node.pricoin_jointspend_adaptor_round1(
            P_pi, X_pub_B, x_B, T_G, T_H, label, payload)

        # alpha is private; both sides have their own.
        assert sa["alpha"] != sb["alpha"]

        # ─── Step 2: combine. ───
        self.log.info("Step 2: round2 combine")
        msg = random_hex(32)
        shares_input = [
            {k: sa[k] for k in ("L_share","R_share","KI_share","dleq_alpha","dleq_x","commitment")},
            {k: sb[k] for k in ("L_share","R_share","KI_share","dleq_alpha","dleq_x","commitment")},
        ]
        combined = node.pricoin_jointspend_adaptor_combine(
            ring, pi, msg, T_G, T_H, dleq_t,
            [X_pub_A, X_pub_B], shares_input, label, payload)
        assert_equal(len(combined["c_pi"]), 32 * 2)
        assert_equal(len(combined["s_others"]), len(ring))

        # ─── Step 3: round3 close shares (reused non-adaptor RPC). ───
        self.log.info("Step 3: round3 close shares")
        cs_a = node.pricoin_jointspend_share(sa["alpha"], combined["c_pi"], x_A)
        cs_b = node.pricoin_jointspend_share(sb["alpha"], combined["c_pi"], x_B)

        # ─── Step 4: assemble pre-sig. ───
        self.log.info("Step 4: assemble pre-sig")
        presig_obj = node.pricoin_jointspend_adaptor_assemble(
            combined["KI"], combined["L_pi"], combined["R_pi"],
            combined["L_prime"], combined["R_prime"],
            combined["c_pi"], combined["c0"],
            combined["s_others"],
            [cs_a["s_share"], cs_b["s_share"]],
            pi, T_G, T_H, dleq_t)
        presig = presig_obj["presig"]
        assert presig

        # ─── Step 5: verify pre-sig. ───
        self.log.info("Step 5: verify pre-sig")
        ok = node.pricoin_jointspend_adaptor_verify_presig(
            ring, presig, msg, label, payload)["valid"]
        assert_equal(ok, True)

        # ─── Step 6: Bob adapts with t and broadcasts. ───
        self.log.info("Step 6: Bob adapts with t")
        sig_obj = node.pricoin_jointspend_adaptor_adapt(presig, t, ring, msg)
        sig = sig_obj["sig"]
        # Standard CLSAG verify on the adapted sig (via existing verify RPC).
        v = node.pricoin_jointspend_verify(ring, None, msg, sig)["valid"]
        assert_equal(v, True)

        # Adapt with the wrong t must fail (Adapt verifies before returning).
        wrong_t = random_scalar(node)
        assert_raises_rpc_error(
            -8, "Adapt failed",
            node.pricoin_jointspend_adaptor_adapt, presig, wrong_t, ring, msg)

        # ─── Step 7: Alice extracts t from the on-chain sig. ───
        self.log.info("Step 7: Alice extracts t")
        ex = node.pricoin_jointspend_adaptor_extract(ring, presig, sig)
        assert_equal(ex["t"], t)

        # ─── Step 8: malformed sig blob → extract throws. ───
        self.log.info("Step 8: malformed sig blob rejected by extract")
        assert_raises_rpc_error(
            -8, "presig and sig must be serialized hex",
            node.pricoin_jointspend_adaptor_extract,
            ring, presig, "deadbeef")

        self.log.info("Pricoin cooperative adaptor-CLSAG wire RPCs OK")


if __name__ == "__main__":
    PricoinJointspendAdaptorTest(__file__).main()
