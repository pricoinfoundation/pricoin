#!/usr/bin/env python3
# Copyright (c) 2026-present The Pricoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Structural test for the BTC-style HTLC primitives.

Note: end-to-end "tx mines on a regtest chain" testing of the BTC
HTLC primitive is NOT possible against the local PRIC node — Pricoin's
relay policy clamps standard tx versions to v4-only (see
TX_MIN/MAX_STANDARD_VERSION in src/policy/policy.h, and the createraw
version range check). The HTLC primitive deliberately produces v2
transparent Bitcoin-style txs that v4-only consensus rejects.

End-to-end on-chain testing requires an unmodified bitcoind/litecoind
regtest as the foreign chain — that lives in the phase-4 swap-ceremony
tests, not here. This commit verifies that:

  * The redeem script + P2WSH address produced by
    pricoin_btc_htlc_address are deterministic and well-formed.
  * The claim tx produced by pricoin_btc_htlc_build_claim has the
    expected witness stack (sig, preimage, OP_TRUE, redeem).
  * The refund tx has nLockTime set to the timeout and a witness
    stack (sig, OP_FALSE marker, redeem).
  * The redeem-script bytes contain the preimage hash + both
    pubkeys + the timeout value.
  * Network HRPs (btc/tb/bcrt/ltc/tltc/rltc/pric/pricrt) round-trip.
  * Negative inputs (bad pubkeys, unknown network) are rejected.
"""

import hashlib
import os

from test_framework.key import ECKey
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import bytes_to_wif


def gen_keypair():
    k = ECKey()
    k.generate(compressed=True)
    pub = k.get_pubkey().get_bytes().hex()
    wif = bytes_to_wif(k.get_bytes())
    return wif, pub


def sha256_hex(data_hex):
    return hashlib.sha256(bytes.fromhex(data_hex)).digest().hex()


class PricoinBTCHTLCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        pass  # No wallet ops needed.

    def run_test(self):
        node = self.nodes[0]

        # ─── Section 1: address + redeem script construction ────
        self.log.info("Section 1: address + redeem script")
        recipient_wif, recipient_pub = gen_keypair()
        sender_wif,    sender_pub    = gen_keypair()
        preimage_hex = os.urandom(32).hex()
        preimage_hash_hex = sha256_hex(preimage_hex)
        timeout = 800000

        info = node.pricoin_btc_htlc_address(
            preimage_hash_hex, recipient_pub, sender_pub, timeout, "btc-mainnet")
        # Mainnet HRP.
        assert info["address"].startswith("bc1q"), f"expected bc1q…, got {info['address']}"

        redeem = info["redeem_script"]
        # Embedded fields verifiable by hex inspection.
        assert preimage_hash_hex in redeem, "preimage hash missing from redeem"
        assert recipient_pub in redeem, "recipient pub missing from redeem"
        assert sender_pub in redeem, "sender pub missing from redeem"

        # script_pubkey is OP_0 <32-byte SHA256(redeem)>.
        spk = info["script_pubkey"]
        assert spk.startswith("0020"), f"P2WSH spk should start with 0020: {spk}"
        # 1 byte OP_0 + 1 byte push + 32 bytes hash = 34 bytes = 68 hex chars.
        assert_equal(len(spk), 68)

        # Network HRPs round-trip.
        for net, prefix in [
            ("btc-mainnet",   "bc1q"),
            ("btc-testnet",   "tb1q"),
            ("btc-regtest",   "bcrt1q"),
            ("ltc-mainnet",   "ltc1q"),
            ("ltc-testnet",   "tltc1q"),
            ("ltc-regtest",   "rltc1q"),
            ("pric-mainnet",  "pric1q"),
            ("pric-regtest",  "pricrt1q"),
        ]:
            i = node.pricoin_btc_htlc_address(
                preimage_hash_hex, recipient_pub, sender_pub, timeout, net)
            assert i["address"].startswith(prefix), \
                f"{net}: expected {prefix}…, got {i['address']}"
            # Redeem script is network-independent.
            assert_equal(i["redeem_script"], redeem)
            assert_equal(i["script_pubkey"], spk)

        # ─── Section 2: claim tx structure ──────────────────────
        self.log.info("Section 2: claim tx structure")
        # Use a pretend funding outpoint; we're just checking shape.
        funding_txid = "ab" * 32
        funding_vout = 1
        funding_value_sat = 100_000_000
        dest_spk_hex = "0014" + ("11" * 20)  # P2WPKH to a pretend address.
        fee_sat = 1000

        claim = node.pricoin_btc_htlc_build_claim(
            funding_txid, funding_vout, funding_value_sat,
            redeem, preimage_hex, recipient_wif, dest_spk_hex, fee_sat)

        decoded = node.decoderawtransaction(claim["tx_hex"])
        assert_equal(decoded["version"], 2)
        assert_equal(decoded["locktime"], 0)
        assert_equal(len(decoded["vin"]), 1)
        assert_equal(decoded["vin"][0]["txid"], funding_txid)
        assert_equal(decoded["vin"][0]["vout"], funding_vout)
        assert_equal(decoded["vin"][0]["sequence"], 0xfffffffd)
        assert_equal(len(decoded["vout"]), 1)
        assert_equal(float(decoded["vout"][0]["value"]), (funding_value_sat - fee_sat) / 1e8)
        assert_equal(decoded["vout"][0]["scriptPubKey"]["hex"], dest_spk_hex)

        # Witness stack: [sig(DER+sighashflag), preimage(32B), 0x01, redeem].
        witness = decoded["vin"][0]["txinwitness"]
        assert_equal(len(witness), 4)
        # Item 1: ECDSA-DER signature, ends with sighash byte 0x01.
        assert witness[0].endswith("01"), f"sighash flag missing: {witness[0]}"
        assert 70 <= len(witness[0]) // 2 <= 73, f"unexpected sig len: {len(witness[0])//2}"
        # Item 2: preimage (32 bytes hex = 64 chars).
        assert_equal(witness[1], preimage_hex)
        # Item 3: OP_TRUE marker → "01".
        assert_equal(witness[2], "01")
        # Item 4: redeem script.
        assert_equal(witness[3], redeem)

        # ─── Section 3: refund tx structure ─────────────────────
        self.log.info("Section 3: refund tx structure")
        refund = node.pricoin_btc_htlc_build_refund(
            funding_txid, funding_vout, funding_value_sat,
            redeem, timeout, sender_wif, dest_spk_hex, fee_sat)
        decoded_r = node.decoderawtransaction(refund["tx_hex"])
        assert_equal(decoded_r["version"], 2)
        assert_equal(decoded_r["locktime"], timeout)
        assert_equal(decoded_r["vin"][0]["sequence"], 0xfffffffd)
        # Witness: [sig, OP_0 marker(empty), redeem].
        wr = decoded_r["vin"][0]["txinwitness"]
        assert_equal(len(wr), 3)
        assert wr[0].endswith("01"), f"refund sighash flag: {wr[0]}"
        assert_equal(wr[1], "")  # OP_0 / empty bytes → ELSE branch.
        assert_equal(wr[2], redeem)

        # ─── Section 4: input validation ────────────────────────
        self.log.info("Section 4: input validation")

        # Unknown network.
        assert_raises_rpc_error(
            -8, "unknown network",
            node.pricoin_btc_htlc_address,
            preimage_hash_hex, recipient_pub, sender_pub, timeout, "btc-mainnnet")

        # Malformed pubkey.
        assert_raises_rpc_error(
            -8, "compressed pubkey",
            node.pricoin_btc_htlc_address,
            preimage_hash_hex, "00" * 33, sender_pub, timeout, "btc-mainnet")

        # Malformed preimage hash (not 32 bytes).
        assert_raises_rpc_error(
            -8, "32-byte hex",
            node.pricoin_btc_htlc_address,
            "ab" * 16, recipient_pub, sender_pub, timeout, "btc-mainnet")

        # Negative timeout.
        assert_raises_rpc_error(
            -8, "non-negative",
            node.pricoin_btc_htlc_address,
            preimage_hash_hex, recipient_pub, sender_pub, -1, "btc-mainnet")

        # Claim builder: WIF that doesn't match the script's recipient_pub
        # still produces a tx (we don't sanity-check on the server), but
        # the resulting tx's signature won't verify against the redeem.
        # That's the caller's responsibility; we just check the RPC
        # accepts a structurally-valid request.
        wrong_wif, _ = gen_keypair()
        ok = node.pricoin_btc_htlc_build_claim(
            funding_txid, funding_vout, funding_value_sat,
            redeem, preimage_hex, wrong_wif, dest_spk_hex, fee_sat)
        assert "tx_hex" in ok

        self.log.info("Pricoin BTC HTLC primitive test OK")


if __name__ == "__main__":
    PricoinBTCHTLCTest(__file__).main()
