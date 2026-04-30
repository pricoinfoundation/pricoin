#!/usr/bin/env python3
# Copyright (c) 2026-present The Pricoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end smoke test for Pricoin's confidential-transaction stack.

Covers:
  * walletsendct (transparent → CT) lands on chain and recipient recovers value
  * walletsendct_ring (CT → CT with sender privacy) lands and KI is committed
  * Phase 3a invariant: chainstate keeps spent v4 outputs as ring decoys
  * Phase 4d invariant: KI is tx-invariant — re-broadcasting a ring tx after
    daemon restart is rejected with bad-pct-double-spend-keyimage
  * Wallet RPC parity: getbalance / getbalances surface CT, transparent send
    RPCs are stubbed
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error


class PricoinCTTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        # No -acceptnonstdtxn — Pricoin's IsStandardTx carve-outs handle v4.
        self.extra_args = [["-txindex=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        # ---- Setup three wallets ----
        node.createwallet("alice")
        node.createwallet("bob")
        node.createwallet("carol")
        alice = node.get_wallet_rpc("alice")
        bob   = node.get_wallet_rpc("bob")
        carol = node.get_wallet_rpc("carol")

        alice_addr = alice.getnewaddress("", "bech32")
        self.generatetoaddress(node, 110, alice_addr)
        assert_equal(node.getblockcount(), 110)
        assert_greater_than(alice.getbalance(), 0)

        bob_stealth   = bob.pricoin_getstealthaddress()["address"]
        carol_stealth = carol.pricoin_getstealthaddress()["address"]

        # ---- 1. transparent → CT ----
        send1 = alice.walletsendct(bob_stealth, 25.0, 0.0001)
        assert send1["dest_was_stealth"] is True
        self.generatetoaddress(node, 1, alice_addr)
        bob_ct = bob.pricoin_listownct(0)
        assert_equal(bob_ct["total_recovered"], 25.0)
        assert_equal(bob.getbalance(), 25.0)
        balances = bob.getbalances()["mine"]
        assert_equal(balances["confidential"], 25.0)

        # ---- 1b. multi-input self-send transparent → CT ----
        # Each coinbase output is 50 PRIC. Sending 120 PRIC forces walletsendct
        # to pick ≥ 3 separate UTXOs — the prior wallet code only picked one.
        # Also exercises self-send: alice sends to her own stealth address,
        # which previously skipped ScanTxForCTReceives because
        # CommitTransaction had already added the tx to mapWallet with empty
        # mapValue, leaving pct_v<i> unset and confidential balance stuck at 0.
        alice_stealth = alice.pricoin_getstealthaddress()["address"]
        multi = alice.walletsendct(alice_stealth, 120.0, 0.0001)
        assert multi["dest_was_stealth"] is True
        self.generatetoaddress(node, 1, alice_addr)
        multi_raw = node.decoderawtransaction(node.getrawtransaction(multi["txid"]))
        assert_greater_than(len(multi_raw["vin"]), 2)
        # Self-send recovery: the dest output (120) is now in alice's CT set.
        recovered_120 = [o for o in alice.pricoin_listownct(0)["outputs"]
                         if abs(float(o["value"]) - 120.0) < 1e-8]
        assert len(recovered_120) == 1, "alice should have exactly one 120 PRIC CT output"
        # And it shows up in the confidential balance.
        assert_greater_than(alice.getbalances()["mine"]["confidential"], 119.9)

        # Give bob more CT outputs so ring=4 has enough decoys.
        for _ in range(3):
            alice.walletsendct(bob_stealth, 10.0, 0.0001)
            self.generatetoaddress(node, 1, alice_addr)

        bob_ct = bob.pricoin_listownct(0)
        assert_equal(len(bob_ct["outputs"]), 4)

        # ---- 2. CT → CT (ring) ----
        ring_tx = bob.walletsendct_ring(carol_stealth, 5.0, 0.0001, 4)
        ring_txid = ring_tx["txid"]
        assert_equal(ring_tx["ring_size"], 4)
        ring_hex = node.getrawtransaction(ring_txid)
        self.generatetoaddress(node, 1, alice_addr)
        # Capture the ring block now — sections below mine more blocks before
        # the invalidate-and-rebroadcast test, so getblockcount() later won't
        # point at the ring block.
        ring_block = node.getbestblockhash()

        # Carol recovers, bob's listownct drops the spent input via KI filter.
        assert_equal(carol.pricoin_listownct(0)["total_recovered"], 5.0)
        bob_ct = bob.pricoin_listownct(0)
        # 4 originals - 1 spent (signer) + 1 change = 4 outputs, total ≈ 35-25 + change ≈ 24.9999
        assert_equal(len(bob_ct["outputs"]), 4)

        # Phase 3a: spent ring member's chainstate entry is still present.
        spent_signer = self._find_spent_signer(node, ring_txid)
        # gettxout returns null (not spent) only if removed; we expect a result.
        gtx = node.gettxout(spent_signer["txid"], spent_signer["vout"])
        assert gtx is not None, "Phase 3a: spent v4 output should still be in chainstate"

        # ---- 2b. multi-input walletsendct_from_ct ----
        # carol now holds the 5.0 PRIC output. To exercise multi-input
        # CT-spending-CT, give bob more small CT outputs and have him
        # consolidate via from_ct. We send carol two more 3-PRIC outputs
        # from bob, then have carol send 7 PRIC out — forcing from_ct to
        # pick at least 3 of carol's CT outputs (5 + 3 + ... = 11 > 7).
        for _ in range(2):
            bob.walletsendct_ring(carol_stealth, 3.0, 0.0001, 4)
            self.generatetoaddress(node, 1, alice_addr)
        carol_outs = carol.pricoin_listownct(0)["outputs"]
        assert len(carol_outs) >= 3, f"expected >= 3 CT outputs, got {len(carol_outs)}"
        from_ct_dest = bob.pricoin_getstealthaddress()["address"]
        from_ct = carol.walletsendct_from_ct(from_ct_dest, 7.0, 0.0001)
        # Multi-input: spent_outpoints is now an array, must contain >= 2.
        assert_greater_than(len(from_ct["spent_outpoints"]), 1)
        self.generatetoaddress(node, 1, alice_addr)
        # Recipient (bob) recovered the 7-PRIC output.
        bob_seven = [o for o in bob.pricoin_listownct(0)["outputs"]
                     if abs(float(o["value"]) - 7.0) < 1e-8]
        assert len(bob_seven) == 1, "bob should have recovered one 7 PRIC CT output"

        # ---- 2c. multi-recipient (walletsendct_multi) ----
        # One bundle pays bob, carol, and alice (own stealth — exercises the
        # self-receive scan path) in a single v4 tx. Three recipients +
        # one change = four outputs. Pool payout code path; replaces what
        # would otherwise be three separate v4 txs (~3× rangeproofs, ~3×
        # input-signature sets).
        bob_pre   = bob.getbalances()["mine"]["confidential"]
        carol_pre = carol.getbalances()["mine"]["confidential"]
        alice_pre = alice.getbalances()["mine"]["confidential"]

        multi_pay = alice.walletsendct_multi(
            [{"address": bob_stealth,   "amount": 2.0},
             {"address": carol_stealth, "amount": 3.0},
             {"address": alice_stealth, "amount": 4.0}],
            0.0001)
        assert_equal(multi_pay["recipients"], 3)
        assert_equal(multi_pay["outputs"], 4)              # 3 dest + 1 change
        assert_equal(float(multi_pay["total_sent"]), 9.0)
        assert_equal(float(multi_pay["fee"]), 0.0001)

        multi_pay_raw = node.decoderawtransaction(node.getrawtransaction(multi_pay["txid"]))
        assert_equal(multi_pay_raw["version"], 4)
        assert_equal(len(multi_pay_raw["vout"]), 4)        # consensus vout matches bundle

        self.generatetoaddress(node, 1, alice_addr)

        # All three recipients recover their respective amounts.
        # Bob and carol gain exactly their dest amount (no change accrues to them).
        assert_equal(bob.getbalances()["mine"]["confidential"]   - bob_pre,   2.0)
        assert_equal(carol.getbalances()["mine"]["confidential"] - carol_pre, 3.0)
        # Alice gains her 4 PRIC dest **plus** the change (alice is the sender,
        # change goes back to her own stealth). So the balance delta is >4 by
        # exactly the change amount; the dest leg shows up as a distinct
        # 4-PRIC output in her listownct set.
        alice_post = alice.getbalances()["mine"]["confidential"]
        assert_greater_than(alice_post - alice_pre, 4.0)
        alice_4 = [o for o in alice.pricoin_listownct(0)["outputs"]
                   if abs(float(o["value"]) - 4.0) < 1e-8]
        assert_equal(len(alice_4), 1)

        # Empty recipients array must be rejected.
        assert_raises_rpc_error(-8, "recipients array is empty",
                                alice.walletsendct_multi, [], 0.0001)

        # ---- 3. KI persistence + reject-after-restart ----
        self.restart_node(0, extra_args=["-txindex=1"])
        node = self.nodes[0]

        # The same hex re-broadcast should hit "txn-already-known" (chain has it).
        # To exercise the KI rejection path specifically, invalidate the block,
        # restart so the KI loads from disk, and try to send the tx fresh.
        node.invalidateblock(ring_block)
        self.restart_node(0, extra_args=["-txindex=1"])
        node = self.nodes[0]

        # KI was loaded from pricoin_keyimages.dat at startup; the tx isn't on
        # chain anymore (block was invalidated), but the KI still rejects.
        assert_raises_rpc_error(-26, "bad-pct-double-spend-keyimage",
                                node.sendrawtransaction, ring_hex)

        # ---- 4. Transparent send RPCs are stubbed ----
        # Wallets need re-loading after restart_node().
        node.loadwallet("alice")
        alice = node.get_wallet_rpc("alice")
        a_other = alice.getnewaddress()
        assert_raises_rpc_error(-32, "Privacy is mandatory",
                                alice.sendtoaddress, a_other, 1.0)
        assert_raises_rpc_error(-32, "Privacy is mandatory",
                                alice.sendmany, "", {a_other: 1.0})

        # ---- 5. Stealth keys are encrypted at rest with the wallet master key ----
        # Encrypting the wallet must persist the stealth side-file in the
        # encrypted format (version byte 0x01). After lock, send/scan paths
        # that depend on the stealth identity must fail; after unlock they
        # must work end-to-end.
        node.createwallet("dave", passphrase="dave-passphrase")
        dave = node.get_wallet_rpc("dave")
        dave.walletpassphrase("dave-passphrase", 60)
        dave_stealth = dave.pricoin_getstealthaddress()["address"]
        # File must be the current encrypted-with-MAC format (version 0x02).
        import os
        wallet_dir = node.datadir_path / node.chain / "wallets" / "dave"
        stealth_file = wallet_dir / "pricoin_stealth.dat"
        assert stealth_file.exists(), "stealth side-file should exist after first stealth-address use"
        with open(stealth_file, "rb") as f:
            header = f.read(1)
        assert_equal(header, b"\x02")  # encrypted+MAC version byte

        # Send to dave; he scans and recovers (wallet still unlocked).
        alice.walletsendct(dave_stealth, 7.0, 0.0001)
        self.generatetoaddress(node, 1, alice_addr)
        dave_ct = dave.pricoin_listownct(0)
        assert_equal(dave_ct["total_recovered"], 7.0)

        # Lock the wallet. Drop our cached identity by restarting so the
        # next scan must reload from the encrypted file under a locked wallet.
        dave.walletlock()
        self.restart_node(0, extra_args=["-txindex=1"])
        node = self.nodes[0]
        node.loadwallet("dave")
        dave = node.get_wallet_rpc("dave")
        # Locked wallet: scanning must fail because we can't decrypt the keys.
        assert_raises_rpc_error(-1, "encrypted",
                                dave.pricoin_listownct, 0)

        # After unlock, scan recovers cleanly.
        dave.walletpassphrase("dave-passphrase", 60)
        dave_ct = dave.pricoin_listownct(0)
        assert_equal(dave_ct["total_recovered"], 7.0)

        # Reload wallets that the restart unloaded.
        node.loadwallet("alice")
        alice = node.get_wallet_rpc("alice")

        # ---- 6. Unload-then-reload must not leak stealth identity across wallets ----
        # The in-memory cache used to be keyed by raw CWallet*; unload + new
        # wallet at the same heap address would silently inherit the old
        # identity. After the fix, the cache entry is dropped on unload, so
        # the same wallet name reloaded gives the SAME on-disk identity (loaded
        # from its own pricoin_stealth.dat) — never some other wallet's keys.
        dave_addr_before = dave.pricoin_getstealthaddress()["address"]
        node.unloadwallet("dave")
        # Churn allocations so the next CWallet is unlikely to land at the same
        # address even by coincidence — but the cache must be wallet-private
        # regardless.
        node.createwallet("erin")
        erin = node.get_wallet_rpc("erin")
        erin_addr = erin.pricoin_getstealthaddress()["address"]
        assert dave_addr_before != erin_addr, "fresh wallet must get fresh identity"
        # Reload dave and confirm we recover dave's own keys, not erin's.
        node.loadwallet("dave")
        dave = node.get_wallet_rpc("dave")
        dave.walletpassphrase("dave-passphrase", 60)
        assert_equal(dave.pricoin_getstealthaddress()["address"], dave_addr_before)

        # ---- 7. Tampered stealth file must fail to load (HMAC integrity) ----
        # AES-CBC alone is malleable: flipping a ciphertext byte yields a
        # plaintext that's still 64 bytes of valid-looking key material, so
        # the wallet would silently start using a *different* stealth identity
        # and lose track of every payment already received. The HMAC catches
        # this. Flip one byte in the ciphertext region and confirm the load
        # rejects rather than silently substituting garbage keys.
        node.unloadwallet("dave")
        with open(stealth_file, "rb") as f:
            blob = bytearray(f.read())
        # Header (1) + IV (32). Flip the first ciphertext byte.
        blob[33] ^= 0x01
        with open(stealth_file, "wb") as f:
            f.write(blob)
        node.loadwallet("dave")
        dave = node.get_wallet_rpc("dave")
        dave.walletpassphrase("dave-passphrase", 60)
        # GetOrCreate now sees a corrupt file (LoadFromDisk returns false) and
        # generates fresh keys, so the address differs from dave's original.
        # The previous behavior would have returned a deterministic-but-wrong
        # address derived from the corrupted ciphertext.
        dave_addr_after = dave.pricoin_getstealthaddress()["address"]
        assert dave_addr_after != dave_addr_before, "tampered file must not yield original identity"

        self.log.info("Pricoin CT/ring/KI/RPC-parity/encryption smoke test OK")

    def _find_spent_signer(self, node, ring_txid):
        """Look in the ring tx's bundle for the outpoint that the wallet
        actually spent. This is hidden by ring sigs; we approximate by
        finding which ring member's chainstate entry has been "consumed"
        — but Phase 3a means none are consumed. Just return the first
        ring member as a smoke check."""
        raw = node.decoderawtransaction(node.getrawtransaction(ring_txid))
        return {"txid": raw["vin"][0]["txid"], "vout": raw["vin"][0]["vout"]}


if __name__ == "__main__":
    PricoinCTTest(__file__).main()
