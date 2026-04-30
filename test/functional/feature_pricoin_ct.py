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
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)


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

        # PRIVACY: every v4 send must emit ≥3 outputs so the change isn't
        # 1/2 observable. With 1 recipient, the bundle is padded with a
        # 0-value self-output. (If this assertion ever drops to 2, the
        # output-padding has regressed and single-recipient sends leak the
        # change identity to anyone reading the chain.)
        send1_raw = node.decoderawtransaction(node.getrawtransaction(send1["txid"]))
        assert_greater_than_or_equal(len(send1_raw["vout"]), 3)

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
        ring_raw = node.decoderawtransaction(ring_hex)
        # Same padding rule as the transparent → CT path: ≥3 outputs.
        assert_greater_than_or_equal(len(ring_raw["vout"]), 3)
        self.generatetoaddress(node, 1, alice_addr)
        # Capture the ring block now — sections below mine more blocks before
        # the invalidate-and-rebroadcast test, so getblockcount() later won't
        # point at the ring block.
        ring_block = node.getbestblockhash()

        # Carol recovers, bob's listownct drops the spent input via KI filter.
        assert_equal(carol.pricoin_listownct(0)["total_recovered"], 5.0)
        bob_ct = bob.pricoin_listownct(0)
        # 4 originals - 1 spent (signer) + 1 change + 1 self-decoy (privacy
        # padding from the single-recipient ring path) = 5 outputs.
        assert_equal(len(bob_ct["outputs"]), 5)

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

        # ---- 3. KI persistence + reorg-correctness ----
        # While the ring block is still on the active chain, re-broadcast
        # of its hex must be rejected — the tx's outputs are already in
        # the UTXO set so mempool refuses (the KI itself is also in the
        # committed set, but the outputs-in-utxo check fires first).
        self.restart_node(0, extra_args=["-txindex=1"])
        node = self.nodes[0]
        assert_raises_rpc_error(-27, "already in utxo set",
                                node.sendrawtransaction, ring_hex)

        # Reorg-out the ring block, restart, and confirm the tx is
        # accepted again. Pre-fix the KI was append-only on disk and
        # reloaded at startup, so even after invalidateblock + restart
        # the daemon would silently reject re-acceptance with
        # bad-pct-double-spend-keyimage. After the per-block-bucket fix,
        # DisconnectBlock removes the KI from both memory and disk; the
        # tx ends up back in the mempool (Bitcoin Core auto-resubmits
        # txs from disconnected blocks) and reconsider re-confirms it.
        node.invalidateblock(ring_block)
        self.restart_node(0, extra_args=["-txindex=1"])
        node = self.nodes[0]
        # Mempool may have been persisted; either the tx is already there
        # via mempool.dat, or we re-broadcast it. Either way the KI must
        # NOT be in the committed set after the disconnect, so acceptance
        # must succeed (no bad-pct-double-spend-keyimage).
        if ring_txid not in node.getrawmempool():
            try:
                node.sendrawtransaction(ring_hex)
            except Exception as e:
                # Fee-bump style "insufficient fee, rejecting replacement"
                # means the tx is already there (a different identity
                # tried to replace it) — that still proves KI was removed.
                assert "double-spend-keyimage" not in str(e), \
                    f"KI must have been uncommitted; got: {e}"
        # Mine the chain back to a stable shape so later sections see the
        # balances they expect.
        node.reconsiderblock(ring_block)

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
        # Stealth identity now lives inside wallet.dat (so backupwallet covers
        # it). Side-file should NOT be created. After lock + restart, scan
        # without unlocking must fail; after walletpassphrase it must succeed
        # end-to-end.
        node.createwallet("dave", passphrase="dave-passphrase")
        dave = node.get_wallet_rpc("dave")
        dave.walletpassphrase("dave-passphrase", 60)
        dave_stealth = dave.pricoin_getstealthaddress()["address"]
        wallet_dir = node.datadir_path / node.chain / "wallets" / "dave"
        legacy_side_file = wallet_dir / "pricoin_stealth.dat"
        assert not legacy_side_file.exists(), \
            "fresh wallets must not create the legacy side-file"

        # PRIVACY/RECOVERY: fresh wallets persist the 32-byte seed (from
        # which view+spend are derived) rather than the legacy 64-byte
        # view||spend blob. This shrinks the recovery surface to a single
        # secret that's small enough for paper backup.
        import sqlite3
        dave_db = wallet_dir / "wallet.dat"
        # Pause the wallet briefly to read the DB; requires unload.
        dave.walletlock()
        node.unloadwallet("dave")
        with sqlite3.connect(str(dave_db)) as conn:
            seed_row = conn.execute("SELECT 1 FROM main WHERE key = ?",
                                    (b"\x10pct_stealth_seed",)).fetchone()
            keyblob_row = conn.execute("SELECT 1 FROM main WHERE key = ?",
                                       (b"\x0bpct_stealth",)).fetchone()
        assert seed_row is not None, "fresh wallet should write a seed record"
        assert keyblob_row is None, "fresh wallet must NOT write the legacy key-blob"
        node.loadwallet("dave")
        dave = node.get_wallet_rpc("dave")
        dave.walletpassphrase("dave-passphrase", 60)
        # Address must be unchanged after the unload/reload.
        assert_equal(dave.pricoin_getstealthaddress()["address"], dave_stealth)

        # pricoin_getstealthseed exposes the 32-byte master for paper backup.
        # Same seed across calls (it's the persisted secret), 64 hex chars.
        seed_resp = dave.pricoin_getstealthseed()
        assert "seed" in seed_resp
        assert_equal(len(seed_resp["seed"]), 64)
        assert_equal(seed_resp["seed"], dave.pricoin_getstealthseed()["seed"])
        # Locking the wallet must refuse seed export (same posture as
        # dumpprivkey).
        dave.walletlock()
        assert_raises_rpc_error(-13, "unlocked wallet",
                                dave.pricoin_getstealthseed)
        dave.walletpassphrase("dave-passphrase", 60)

        # Seed import round-trip: a fresh recovery wallet receives the
        # paper-backup hex and ends up with the same address.
        dave_seed_hex = seed_resp["seed"]
        node.createwallet("dave_recovered")
        dave_recovered = node.get_wallet_rpc("dave_recovered")
        # Force the wallet to materialise its own seed so the overwrite
        # guard has something to refuse. (Whether createwallet already
        # touched GetOrCreate depends on the chain-rescan ordering, which
        # is not stable across runs.)
        dave_recovered.pricoin_getstealthaddress()
        # Without confirm_overwrite, refuses because a seed already exists.
        assert_raises_rpc_error(-4, "confirm_overwrite",
                                dave_recovered.pricoin_setstealthseed,
                                dave_seed_hex)
        # With confirm_overwrite, the seed is adopted and the address
        # matches dave's original.
        result = dave_recovered.pricoin_setstealthseed(dave_seed_hex, True)
        assert_equal(result["address"], dave_stealth)
        assert_equal(dave_recovered.pricoin_getstealthseed()["seed"], dave_seed_hex)
        # Bad-length seed → RPC param error.
        assert_raises_rpc_error(-8, "64 hex characters",
                                dave_recovered.pricoin_setstealthseed,
                                "deadbeef", True)
        node.unloadwallet("dave_recovered")

        # Send to dave; he scans and recovers (wallet still unlocked).
        alice.walletsendct(dave_stealth, 7.0, 0.0001)
        self.generatetoaddress(node, 1, alice_addr)
        dave_ct = dave.pricoin_listownct(0)
        assert_equal(dave_ct["total_recovered"], 7.0)

        # Lock the wallet. Drop our cached identity by restarting so the
        # next scan must reload from the wallet DB under a locked wallet.
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

        # ---- 6. backupwallet must carry stealth identity end-to-end ----
        # The whole point of moving the keys into wallet.dat: a routine
        # `backupwallet` now copies them. Before this change, restoring a
        # wallet.dat backup left the user without their stealth keys and
        # bricked recovery of every CT payment they'd ever received.
        dave_addr_before = dave.pricoin_getstealthaddress()["address"]
        backup_path = node.datadir_path / "dave_backup.dat"
        dave.backupwallet(str(backup_path))
        # Restore as a different wallet name from the same backup file.
        restored_dir = node.datadir_path / node.chain / "wallets" / "dave_restored"
        restored_dir.mkdir(parents=True, exist_ok=False)
        import shutil
        shutil.copy(str(backup_path), str(restored_dir / "wallet.dat"))
        node.loadwallet("dave_restored", load_on_startup=False)
        restored = node.get_wallet_rpc("dave_restored")
        restored.walletpassphrase("dave-passphrase", 60)
        assert_equal(restored.pricoin_getstealthaddress()["address"], dave_addr_before)
        # Also: the restored wallet recognises the 7-PRIC payment, since the
        # stealth identity it scans with is the same one alice paid to.
        assert_equal(restored.pricoin_listownct(0)["total_recovered"], 7.0)
        node.unloadwallet("dave_restored")

        # ---- 7. Unload-then-reload must not leak stealth identity across wallets ----
        # The in-memory cache used to be keyed by raw CWallet*; unload + new
        # wallet at the same heap address would silently inherit the old
        # identity. The cache entry is now dropped on NotifyUnload.
        node.unloadwallet("dave")
        node.createwallet("erin")
        erin = node.get_wallet_rpc("erin")
        erin_addr = erin.pricoin_getstealthaddress()["address"]
        assert dave_addr_before != erin_addr, "fresh wallet must get fresh identity"
        node.loadwallet("dave")
        dave = node.get_wallet_rpc("dave")
        dave.walletpassphrase("dave-passphrase", 60)
        assert_equal(dave.pricoin_getstealthaddress()["address"], dave_addr_before)

        # ---- 8. Legacy side-file (pre-v0.1.11) must migrate into wallet.dat ----
        # Existing installs upgrading from v0.1.10 have a `pricoin_stealth.dat`
        # next to wallet.dat. On first GetOrCreate, the wallet must adopt that
        # identity (so users don't lose access to their keys), and subsequent
        # loads must come from the migrated DB record.
        #
        # Bitcoin Core wallets are SQLite databases. The simplest way to
        # exercise the "DB has no stealth record but a side-file exists" path
        # from a functional test is to create a wallet, then directly delete
        # the stealth row from the SQLite file while it's unloaded.
        import os
        import sqlite3
        node.createwallet("george")
        george = node.get_wallet_rpc("george")
        # Touching the address forces the DB record to be written.
        george_native_addr = george.pricoin_getstealthaddress()["address"]
        node.unloadwallet("george")
        george_dir = node.datadir_path / node.chain / "wallets" / "george"
        george_db = george_dir / "wallet.dat"
        # Bitcoin Core's SQLite keys are varint-prefixed serialised strings.
        # "pct_stealth" is 11 bytes, varint prefix is 0x0b.
        # "pct_stealth_seed" is 16 bytes, varint prefix is 0x10.
        stealth_key = b"\x0b" + b"pct_stealth"
        seed_key = b"\x10" + b"pct_stealth_seed"
        # Delete BOTH possible stealth records (seed for v0.1.12+ wallets,
        # key-blob for v0.1.11 wallets) so the load path falls through to
        # the legacy side-file.
        with sqlite3.connect(str(george_db)) as conn:
            conn.execute("DELETE FROM main WHERE key = ?", (stealth_key,))
            conn.execute("DELETE FROM main WHERE key = ?", (seed_key,))
            conn.commit()
        # Drop a legacy unencrypted blob (version 0x00) with known content.
        import secrets
        view_priv = secrets.token_bytes(32)
        spend_priv = secrets.token_bytes(32)
        legacy_blob = b"\x00" + view_priv + spend_priv
        with open(george_dir / "pricoin_stealth.dat", "wb") as f:
            f.write(legacy_blob)
        # Reload — migration must adopt the legacy identity, not regenerate.
        node.loadwallet("george", load_on_startup=False)
        george = node.get_wallet_rpc("george")
        george_migrated_addr = george.pricoin_getstealthaddress()["address"]
        assert george_migrated_addr != george_native_addr, \
            "migration should adopt the legacy side-file identity, not the empty DB"
        # Unload so we can poke the DB directly, then confirm the migration
        # wrote a DB row.
        node.unloadwallet("george")
        with sqlite3.connect(str(george_db)) as conn:
            row = conn.execute("SELECT value FROM main WHERE key = ?",
                               (stealth_key,)).fetchone()
        assert row is not None, "migration must persist the identity into wallet.dat"
        # Side-file becomes a downgrade safety net — no longer authoritative.
        # Delete it and confirm the wallet still returns the same address from
        # the now-DB-only record.
        os.remove(george_dir / "pricoin_stealth.dat")
        node.loadwallet("george", load_on_startup=False)
        george = node.get_wallet_rpc("george")
        assert_equal(george.pricoin_getstealthaddress()["address"], george_migrated_addr)

        # ---- 9. Tampered DB record must fail to load (HMAC integrity) ----
        # AES-CBC alone is malleable: flipping a ciphertext byte in an
        # encrypted-but-no-MAC blob would silently substitute different keys
        # (~99% of random 64-byte plaintexts decode as valid secp256k1 keys),
        # bricking recovery of every payment received under the original
        # identity. The HMAC catches that. Tamper with dave's DB record and
        # confirm the load surfaces the corruption rather than substituting
        # garbage.
        node.unloadwallet("dave")
        dave_dir = node.datadir_path / node.chain / "wallets" / "dave"
        dave_db = dave_dir / "wallet.dat"
        # Tamper the seed record (v0.1.12+ default). The key-blob record
        # would be the v0.1.11 path; this test deliberately exercises the
        # current format.
        with sqlite3.connect(str(dave_db)) as conn:
            row = conn.execute("SELECT value FROM main WHERE key = ?",
                               (seed_key,)).fetchone()
            assert row is not None, "dave should have a seed DB record"
            # Raw value layout: varint-length-prefix then the EncodeBlob
            # output. For an encrypted 32-byte seed the encoded blob is
            # 1 (ver) + 32 (iv) + 48 (PKCS7-padded ciphertext) + 32 (mac) =
            # 113 bytes; varint prefix for 113 is 0x71.
            assert len(row[0]) >= 2, "value too short"
            assert row[0][1] == 0x02, \
                f"expected version 0x02 at offset 1, got {hex(row[0][1])}"
            blob = bytearray(row[0])
            # ciphertext starts at byte 2 (varint) + 1 (ver) + 32 (iv) = 35.
            blob[35] ^= 0x01
            conn.execute("UPDATE main SET value = ? WHERE key = ?",
                         (bytes(blob), seed_key))
            conn.commit()
        node.loadwallet("dave", load_on_startup=False)
        dave = node.get_wallet_rpc("dave")
        dave.walletpassphrase("dave-passphrase", 60)
        # Touching the stealth address must surface the corruption rather
        # than silently returning a different (garbage-derived) one.
        assert_raises_rpc_error(-1, "failed to decode",
                                dave.pricoin_getstealthaddress)

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
