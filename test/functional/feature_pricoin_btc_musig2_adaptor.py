#!/usr/bin/env python3
"""Regression test for the BTC MuSig2 + adaptor RPC flow, driven exactly as
the cooperative-sign dialog drives it (round1_safe, even-y self_pub, T_G in
process), with a REAL BIP340 verify of the final signature.

This guards the msg byte-order bug (2026-06-10): round1/process/record-key
parsed the 32-byte sighash via uint256::FromHex (which byte-reverses), so the
ceremony signed over the REVERSED sighash. Partials verified internally but the
aggregate sig was over the wrong message → on-chain "Invalid Schnorr
signature". The pre-existing musig2_wire test never actually BIP340-verified,
so it missed this."""

import os
from test_framework.test_framework import BitcoinTestFramework
from test_framework.key import (ECKey, generate_privkey, verify_schnorr,
                                sign_schnorr, compute_xonly_pubkey)


def pub_compressed(secret: bytes) -> str:
    k = ECKey()
    k.set(secret, True)
    return k.get_pubkey().get_bytes().hex()


def even_priv():
    while True:
        k = generate_privkey()
        if pub_compressed(k)[:2] == "02":
            return k


class BtcMusig2AdaptorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="w")
        self.w = node.get_wallet_rpc("w")

        # Harness sanity: a single-key BIP340 sig must verify.
        sk = generate_privkey()
        xo, _ = compute_xonly_pubkey(sk)
        m = os.urandom(32)
        assert verify_schnorr(xo, sign_schnorr(sk, m), m), "verify_schnorr broken"

        # Non-adaptor ceremony: the aggregate is a COMPLETE sig — must verify.
        agg, sig, msg, _ = self._ceremony(use_adaptor=False)
        assert verify_schnorr(bytes.fromhex(agg), bytes.fromhex(sig), bytes.fromhex(msg)), \
            "non-adaptor MuSig2 aggregate failed BIP340 verify (msg byte-order?)"
        self.log.info("non-adaptor sig verifies")

        # Adaptor ceremony: pre-sig must NOT verify raw; adapt(t) must verify.
        agg, presig, msg, t = self._ceremony(use_adaptor=True)
        assert not verify_schnorr(bytes.fromhex(agg), bytes.fromhex(presig), bytes.fromhex(msg)), \
            "adaptor pre-sig unexpectedly verified before adapt"
        ok = False
        for parity in (0, 1):
            sg = self.w.pricoin_btc_musig2_adapt(presig, t.hex(), parity)["sig"]
            if verify_schnorr(bytes.fromhex(agg), bytes.fromhex(sg), bytes.fromhex(msg)):
                ok = True
                break
        assert ok, "adapted BTC sig failed BIP340 verify for both parities"
        self.log.info("adaptor flow OK — adapted sig verifies")

    def _ceremony(self, use_adaptor):
        w = self.w
        a, b = even_priv(), even_priv()
        t = generate_privkey()
        a_pub, b_pub = pub_compressed(a), pub_compressed(b)
        T_G = pub_compressed(t)
        msg = os.urandom(32).hex()

        ka = w.pricoin_btc_musig2_keyagg([a_pub, b_pub])
        agg_xonly, cache = ka["agg_xonly"], ka["keyagg_cache"]

        r1a = w.pricoin_btc_musig2_round1_safe(
            a_pub, cache, agg_xonly, msg, "initiator",
            os.urandom(32).hex(), os.urandom(32).hex(), a.hex())
        r1b = w.pricoin_btc_musig2_round1_safe(
            b_pub, cache, agg_xonly, msg, "responder",
            os.urandom(32).hex(), os.urandom(32).hex(), b.hex())

        aggn = w.pricoin_btc_musig2_aggregate_nonces(
            [r1a["pubnonce"], r1b["pubnonce"]])["aggnonce"]
        sess = (w.pricoin_btc_musig2_process(aggn, msg, cache, T_G) if use_adaptor
                else w.pricoin_btc_musig2_process(aggn, msg, cache))
        session = {"data": sess["data"], "nonce_parity": sess["nonce_parity"]}

        pa = w.pricoin_btc_musig2_partial_sign(
            r1a["secnonce_handle"], a.hex(), a_pub, cache, session)["partial_sig"]
        pb = w.pricoin_btc_musig2_partial_sign(
            r1b["secnonce_handle"], b.hex(), b_pub, cache, session)["partial_sig"]
        out = w.pricoin_btc_musig2_aggregate_partials(session, [pa, pb])["sig"]
        return agg_xonly, out, msg, t


if __name__ == "__main__":
    BtcMusig2AdaptorTest(__file__).main()
