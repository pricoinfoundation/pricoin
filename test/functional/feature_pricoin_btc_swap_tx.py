#!/usr/bin/env python3
# Copyright (c) 2026-present The Pricoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Functional test for the BTC-side swap-tx wallet RPCs.

Drives the BIP327 + BIP341 cooperative-spend pipeline through the wallet
RPC surface end-to-end, validating that the produced bytes are correctly
shaped without actually broadcasting on-chain (Pricoin regtest enforces
mandatory-CT consensus and would reject any standard non-CT tx; the BTC
side is a *foreign* chain — broadcasting requires a separate bitcoind
binary, which is the next-tier multi-process integration test).

What's covered:
  1.  pricoin_btc_musig2_keyagg → aggregate xonly pubkey + cache.
  2.  pricoin_btc_p2tr_address → BIP350 bech32m P2TR address.
  3.  pricoin_btc_swap_tx_build (refund shape, nlocktime > 0): tx_hex + sighash.
  4.  Cooperative MuSig2 sign (no adaptor) over the BIP341 sighash.
  5.  pricoin_btc_swap_tx_finalize → witness attached.
  6.  Decode the finalized hex: locktime + witness present and well-formed.
  7.  Same flow with nlocktime=0 (claim shape) — sighash differs from refund's.

Witness *cryptographic* validity is exercised by the daemon-startup
self-test (`btc_refund_tx::RunSelfTest`) which verifies the BIP340 sig
under the aggregate XOnlyPubKey — the same code path bitcoind would run.
"""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


def random_hex(n_bytes):
    return os.urandom(n_bytes).hex()


G_HEX = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
TWOG  = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"


class PricoinBtcSwapTxTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _cooperative_sign(self, w, agg_xonly, cache, sighash, priv_a, pub_a, priv_b, pub_b):
        """Run a non-adaptor 2-party MuSig2 sign over `sighash`. Returns the
        64-byte BIP340 signature hex."""
        seed_a = random_hex(32)
        seed_b = random_hex(32)
        r1a = w.pricoin_btc_musig2_round1(pub_a, cache, seed_a, priv_a, sighash)
        r1b = w.pricoin_btc_musig2_round1(pub_b, cache, seed_b, priv_b, sighash)
        agg = w.pricoin_btc_musig2_aggregate_nonces([r1a["pubnonce"], r1b["pubnonce"]])
        sess = w.pricoin_btc_musig2_process(agg["aggnonce"], sighash, cache, "")
        psa = w.pricoin_btc_musig2_partial_sign(
            r1a["secnonce_handle"], priv_a, pub_a, cache, sess)
        psb = w.pricoin_btc_musig2_partial_sign(
            r1b["secnonce_handle"], priv_b, pub_b, cache, sess)
        agg_sig = w.pricoin_btc_musig2_aggregate_partials(
            sess, [psa["partial_sig"], psb["partial_sig"]])
        return agg_sig["sig"]

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("btc_swap_test")
        w = node.get_wallet_rpc("btc_swap_test")

        priv_a = "00" * 31 + "01"
        priv_b = "00" * 31 + "02"
        pub_a, pub_b = G_HEX, TWOG

        # ─── Step 1: keyagg + P2TR address derivation ───
        self.log.info("Step 1: keyagg + P2TR address derivation")
        kg = w.pricoin_btc_musig2_keyagg([pub_a, pub_b])
        agg_xonly = kg["agg_xonly"]
        cache = kg["keyagg_cache"]
        assert_equal(len(agg_xonly), 64)

        addr_obj = w.pricoin_btc_p2tr_address(agg_xonly)
        agg_p2tr_addr = addr_obj["address"]
        info = node.validateaddress(agg_p2tr_addr)
        assert_equal(info["isvalid"], True)
        assert info.get("iswitness", False), "P2TR address must be witness"
        assert_equal(info["witness_version"], 1)
        assert_equal(info["witness_program"], agg_xonly)

        # ─── Step 2: build the refund-tx skeleton (nlocktime > 0) ───
        self.log.info("Step 2: build refund-tx skeleton (nlocktime > 0)")
        # Use a synthetic funding outpoint — we're not broadcasting, just
        # testing the wallet RPC bytes-on-the-wire layer. Real swap drivers
        # would pass a real bitcoind funding txid.
        funding_txid = random_hex(32)
        funding_vout = 0
        funding_amount_sat = 100_000_000  # 1 BTC
        # Recipient: a different P2TR address.
        recipient_xonly = random_hex(32)
        recipient_addr_obj = w.pricoin_btc_p2tr_address(recipient_xonly)
        # Compute the recipient scriptPubKey (OP_1 0x20 <xonly>).
        recipient_spk = "5120" + recipient_xonly
        future_height = 800_000
        fee_sat = 10_000
        refund_amount_sat = funding_amount_sat - fee_sat

        skel_refund = w.pricoin_btc_swap_tx_build(
            funding_txid, funding_vout, funding_amount_sat,
            agg_xonly, recipient_spk, refund_amount_sat, future_height)
        decoded_refund = node.decoderawtransaction(skel_refund["tx_hex"])
        assert_equal(decoded_refund["locktime"], future_height)
        assert_equal(len(decoded_refund["vin"]), 1)
        assert_equal(len(decoded_refund["vout"]), 1)
        assert_equal(decoded_refund["vin"][0]["sequence"], 0xfffffffe)
        assert_equal(decoded_refund["vout"][0]["scriptPubKey"]["hex"], recipient_spk)
        # Sighash is 32-byte hex.
        assert_equal(len(skel_refund["sighash"]), 64)

        # ─── Step 3: cooperative MuSig2 sign over BIP341 sighash ───
        self.log.info("Step 3: cooperative MuSig2 sign over BIP341 sighash")
        sig64 = self._cooperative_sign(
            w, agg_xonly, cache, skel_refund["sighash"],
            priv_a, pub_a, priv_b, pub_b)
        assert_equal(len(sig64), 128)  # 64 bytes hex

        # ─── Step 4: finalize witness + decode ───
        self.log.info("Step 4: finalize witness")
        finalized_refund = w.pricoin_btc_swap_tx_finalize(skel_refund["tx_hex"], sig64)
        decoded_final = node.decoderawtransaction(finalized_refund["tx_hex"])
        assert_equal(decoded_final["locktime"], future_height)
        assert_equal(decoded_final["vin"][0]["txinwitness"], [sig64])

        # ─── Step 5: build + sign claim-tx shape (nlocktime=0) ───
        self.log.info("Step 5: claim-tx shape (nlocktime=0)")
        skel_claim = w.pricoin_btc_swap_tx_build(
            funding_txid, funding_vout, funding_amount_sat,
            agg_xonly, recipient_spk, refund_amount_sat, 0)
        decoded_claim = node.decoderawtransaction(skel_claim["tx_hex"])
        assert_equal(decoded_claim["locktime"], 0)
        # Sighash differs from refund's (nLockTime is committed).
        assert skel_claim["sighash"] != skel_refund["sighash"], \
            "claim-shape sighash must differ from refund-shape (nLockTime is committed)"

        sig64_claim = self._cooperative_sign(
            w, agg_xonly, cache, skel_claim["sighash"],
            priv_a, pub_a, priv_b, pub_b)
        finalized_claim = w.pricoin_btc_swap_tx_finalize(skel_claim["tx_hex"], sig64_claim)
        decoded_claim_final = node.decoderawtransaction(finalized_claim["tx_hex"])
        assert_equal(decoded_claim_final["locktime"], 0)
        assert_equal(decoded_claim_final["vin"][0]["txinwitness"], [sig64_claim])

        # ─── Step 6: input-validation negatives ───
        self.log.info("Step 6: input-validation negatives")
        # negative nlocktime rejected
        assert_raises_rpc_error(
            -8, "btc_refund_tx::Build rejected params",
            w.pricoin_btc_swap_tx_build,
            funding_txid, funding_vout, funding_amount_sat,
            agg_xonly, recipient_spk, refund_amount_sat, -1)
        # refund_amount >= funding_amount rejected (no fee headroom)
        assert_raises_rpc_error(
            -8, "btc_refund_tx::Build rejected params",
            w.pricoin_btc_swap_tx_build,
            funding_txid, funding_vout, funding_amount_sat,
            agg_xonly, recipient_spk, funding_amount_sat, future_height)
        # bad sig length rejected
        assert_raises_rpc_error(
            -8, "sig64 must be 64-byte hex",
            w.pricoin_btc_swap_tx_finalize, skel_refund["tx_hex"], "deadbeef")
        # bad agg_xonly length rejected
        assert_raises_rpc_error(
            -8, "agg_xonly must be 32-byte hex",
            w.pricoin_btc_swap_tx_build,
            funding_txid, funding_vout, funding_amount_sat,
            "deadbeef", recipient_spk, refund_amount_sat, future_height)
        # bad xonly length to P2TR helper
        assert_raises_rpc_error(
            -8, "xonly must be 32-byte hex",
            w.pricoin_btc_p2tr_address, "deadbeef")

        self.log.info("Pricoin BTC swap-tx wallet RPCs OK")


if __name__ == "__main__":
    PricoinBtcSwapTxTest(__file__).main()
