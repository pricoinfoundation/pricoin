# Adaptor-CLSAG protocol spec (revision 4 — post round-3 review)

**Status: research draft, revision 4.** Round-3 AI review verdict
was the strongest yet: "I would not call the spec broken... research
prototype OK after revisions." Revision 4 incorporates the round-3
findings — foreign-adaptor binding, canonical tx-template byte
layout, mandatory share-consistency DLEQs everywhere in adaptor
mode, nonce persistence requirement, zero-scalar abort, expanded
adversarial test vectors. Also drops the rev-3 `msg_adaptor`
construction in favour of plain `tx_sighash` after working through
the consensus-verification implications: keeping SESSION binding
purely off-chain (in DLEQ challenge + nonce commits) is simpler,
requires no consensus changes, and the round-3 reviewer didn't
push back on the alternative.

> **Standing caveat (unchanged).** Reviewed by AI models, not by a
> human cryptographer. After three review rounds with no
> fundamental breaks remaining, the maintainer plans to begin
> implementation against this revision. Round-4 review (against
> rev 4) is recommended but not blocking. Suggested human
> reviewers in §12 if/when the protocol handles non-trivial value.

> **Standing caveat.** This document is reviewed by AI models, not
> by a human cryptographer with publication record in adaptor
> signatures or ring signatures. Reviewer guidance for human-audit
> candidates if/when this project handles non-trivial value lives
> in §12.

This document describes the math and on-the-wire protocol for an
adaptor-signature variant of CLSAG, intended for use as the PRIC-
side primitive in trustless cross-chain atomic swaps. The
construction composes three features that are already implemented
in this codebase (`pricoin/ringsig.cpp`, `pricoin/joint_ringsig.cpp`):

1. CLSAG ring signatures (single-layer + µ-aggregated multi-layer).
2. Cooperative signing by additive secret-sharing.
3. Adaptor-signature semantics (pre-signature + adapt + extract).

## Revision history

* **rev 4 (2026-05-01).** Round-3 review revisions. Highlights:
  * **Dropped `msg_adaptor` wrapper.** The on-chain CLSAG signs
    plain `tx_sighash` (= existing `ComputeRingMessage(tx)`). No
    consensus changes; existing `pricoin::ringsig::Verify` /
    `VerifyMultiLayer` accept adapted signatures unchanged.
    SESSION binding lives entirely off-chain — in DLEQ challenge
    hashes, nonce commitments, and pre-signature transcripts.
    The argument: the on-chain sig binds the specific tx via
    `tx_sighash`; cross-session replay protection is enforced
    off-chain where it actually does work; consensus changes
    aren't justified by the marginal defense-in-depth gain.
    Round-3 reviewer accepted `msg_adaptor` without pushing for
    it over alternatives.
  * **§6.0a NEW: foreign-adaptor binding requirement.** The BTC/
    LTC Schnorr adaptor point MUST be byte-identical to PRIC
    `T_G`. Both chains use secp256k1 generator `G`, so byte-
    equality is meaningful. Closes Finding A — the "unverifiable
    same-secret" gap that rev 2 fixed for hashlocks but rev 3
    left re-introduced for the foreign Schnorr adaptor.
  * **§2.1 canonical tx-template byte layout** specified
    explicitly (not prose). Defines exactly what bytes go into
    `pric_claim_template`, `pric_refund_template`,
    `foreign_claim_template`, `foreign_refund_template` hashes.
  * **§4.2 / §5.2 share-consistency DLEQs are now mandatory in
    ALL adaptor mode** (single-layer too). Rev 3 had them
    optional for single-layer; round-3 reviewer flagged as a
    footgun (same code path reused for multi-layer).
  * **§4.1 reference existing `HashToScalar` for `s_others`**
    derivation (with rejection/rehash) instead of vague "reduce
    mod n, retry."
  * **§4.1a NEW: nonce persistence requirement.** Wallet MUST
    durably persist `(session_id, joint_output, ring_hash, role,
    nonce_commit)` before broadcasting commitment. On restart,
    refuse to sign if a conflicting tuple exists.
  * **§3.3 zero-scalar abort.** If `s_pi == 0` after Adapt or any
    `s_share == 0`, abort and restart with fresh nonces.
  * **§6.3 liquidity griefing** acknowledged as distinct from
    atomicity.
  * **§13 expanded adversarial test vectors:** malformed shares,
    DLEQ for wrong session, foreign adaptor mismatch, repeated
    nonce, concurrent sessions with same id, leaked pi, SESSION
    mutation after round 1.

* **rev 3 (2026-05-01).** Round-2 review revisions. Highlights:
  * **Transcript binding moved from step-challenge to message
    digest.** Revision 2's `H_session(...)` step-challenge
    contradicted the "byte-identical to ordinary CLSAG" claim and
    would have produced signatures the existing verifier rejects.
    Replaced with:
    ```
    msg_adaptor = H("pricoin/adaptor-clsag/msg-v1"
                   ‖ canonical_SESSION
                   ‖ tx_sighash)
    ```
    The CLSAG layer signs `msg_adaptor` using its existing
    challenge hash (`StepChallenge` / `StepChallengeML`) without
    modification. Adapted on-chain signatures verify against the
    deployed `ringsig::Verify` / `ringsig::VerifyMultiLayer`
    unchanged.
  * **Multi-layer share-consistency DLEQs now MANDATORY.**
    Removed the "optional" framing in §4.2; rev 2 was internally
    inconsistent (§4.2 said optional, §5.3 said mandatory).
  * **§6.3 atomicity rewritten as liveness-dependent.** "Holds
    under bounded-delay, bounded-reorg, and successful-claim
    assumptions" — matches industry-standard atomic-swap framing.
  * **§6.1 restricts v1 to Schnorr/Taproot chains.** Adaptor-ECDSA
    is significantly harder (Lindell-style two-party ECDSA), out
    of scope for v1.
  * **§2.1 SESSION uses unsigned tx-template hashes / sighashes**,
    not txids — closes the chicken-and-egg circularity.
  * **Rogue-key defense for joint stealth setup** added in §6.0.
  * **Mandatory test vectors** added as §13.

* **rev 2 (2026-05-01).** Round-1 review revisions. Highlights:
  * **§6 atomic-swap protocol completely rewritten.** The previous
    plain-HTLC + SHA256(t) construction is **unverifiable**: Alice
    cannot check that Bob's BTC HTLC hash uses the same `t` as the
    adaptor point. Replaced with adaptor-Schnorr (post-taproot
    BTC/LTC) or adaptor-ECDSA (pre-taproot) on both legs.
  * **Timelock direction reversed:** `T_foreign_refund > T_pric_refund
    + δ`, not the other way. Old direction let Bob refund foreign
    coin and still claim PRIC.
  * **§3.0a:** explicit Chaum-Pedersen DLEQ construction added,
    replacing the "Camenisch-Stadler" hand-wave.
  * **§3.1, §4.1, §5.1:** transcript-binding requirements added —
    every commitment / hash binds session_id, chain ids, ring hash,
    msg/tx digest, π, KI, D (multi-layer), T_G, T_H, refund + claim
    tx ids.
  * **§4.1:** multi-layer NonceCommit must bind D_share (not just
    KI_share). `s_others` must be derived deterministically from
    the session transcript or commit-revealed.
  * **§4.2 added:** cooperative-share consistency proofs (DLEQ
    proofs tying x_X·G to x_X·H_p(P_pi)). Required for
    identifiable abort; optional for abort-only threat models with
    explicit acknowledgment.
  * **§11 added:** implementation hazards ordered by severity.
  * **§12 added:** suggested human reviewers if/when value scales up.

* **rev 1 (2026-05-01).** Initial draft — superseded by rev 2.
  Failed round-1 review (Q7 + Finding B).

## 1. Goals

The PRIC-side leg of an atomic swap needs to be cryptographically
linked to the foreign-chain leg's secret reveal. Specifically:

* Alice locks PRIC into a 2-of-2 cooperative output (joint stealth).
* Bob locks foreign coin (BTC, LTC, …) into a similar 2-of-2 output
  on the foreign chain.
* Both legs are pre-signed with adaptor signatures sharing the same
  scalar `t`.
* The first party to broadcast their leg reveals `t` on chain. The
  other party extracts `t` from the broadcast and uses it to
  complete their leg.

The reason both legs must be adaptor signatures (not one adaptor +
one HTLC): a SHA-256 hashlock on one chain cannot be cryptographically
bound to an EC adaptor scalar on the other. The party verifying the
HTLC has no way to confirm the hashlock and the adaptor point
correspond to the same secret, opening a theft vector. **Round-1
reviewer Finding B; corrected here.**

## 2. Notation

| Symbol         | Meaning                                                   |
|----------------|-----------------------------------------------------------|
| `G`            | secp256k1 generator                                       |
| `n`            | secp256k1 group order                                     |
| `H_p(·)`       | hash-to-point (try-and-increment, tag `pricoin/ringsig/H_p`) |
| `H_s(·)`       | tagged hash-to-scalar (`pricoin/ringsig/H_s-v1`)          |
| `‖`            | byte concatenation                                        |
| `x ← R`        | sample `x` uniformly at random                            |
| `[a]·G`        | scalar-multiplication of `G` by `a`                       |
| `H_session(·)` | tagged hash for protocol-session transcript binding (see §2.1) |

For a ring of `N` members at indices `0..N-1`:
* `P_i` — spend pubkey at index `i`.
* `W_i` — commitment-offset pubkey at index `i` (multi-layer).
* The signer is at index `pi`; their secrets are `x_pi` (spend) and
  `z_pi = b_prev - b_pseudo` (commitment-offset, multi-layer only).
* `KI = x_pi · H_p(P_pi)` — published key image (links double-spends).
* `D  = z_pi · H_p(P_pi)` — published commitment image (multi-layer).

For cooperative signing, `x_pi = Σ x_X` over the parties X; same
for `z_pi = Σ z_X`.

For adaptor signing, `t` is the **adaptor secret** (a scalar in
[1, n-1]) and the corresponding **adaptor points** are:

* `T_G = t · G`
* `T_H = t · H_p(P_pi)` — note this uses the **same** generator as
  `R_pi`, namely `H_p(P_pi)`, NOT the µ-aggregated image `I_agg`.
  Reviewer Section 4 hazard #3.

The DLEQ proof `π_t` proves to a verifier that the same `t` was
used in `T_G` and `T_H` (without revealing `t`). Construction in
§3.0a.

### 2.1 Session transcript and domain separation

The protocol uses a **canonical session transcript** that pins
every parameter the parties have agreed on, so adversarial
manipulation of any field invalidates the resulting cooperative
proofs. The transcript binds **off-chain** — in DLEQ challenges,
nonce commitments, pre-signature transcripts. The **on-chain**
CLSAG signs the standard `tx_sighash` (= existing
`ComputeRingMessage(tx)` from `src/pricoin/validation.cpp`); no
consensus changes.

```
SESSION = "pricoin/adaptor-clsag/v1"
        ‖ network                 (bytes; e.g., "pric-mainnet")
        ‖ asset_pair              (bytes; e.g., "pric/btc")
        ‖ role_label              (bytes; "buyer-foreign" | "seller-foreign")
        ‖ session_id              (32 bytes, random, agreed at setup)
        ‖ ring_hash               (32 bytes, SHA256 of canonical ring)
        ‖ pi                      (uint32 LE)
        ‖ KI                      (33 bytes)
        ‖ D_or_zero               (33 bytes; all-zero for single-layer)
        ‖ T_G                     (33 bytes)
        ‖ T_H                     (33 bytes)
        ‖ pric_claim_template     (32 bytes, see §2.1.1)
        ‖ pric_refund_template    (32 bytes, same form)
        ‖ foreign_claim_template  (32 bytes, same form)
        ‖ foreign_refund_template (32 bytes, same form)
        ‖ pric_refund_locktime    (uint64 LE)
        ‖ foreign_refund_locktime (uint64 LE)
```

The canonical SESSION must be agreed and signed/acknowledged by
all participants **before round 1** of any cooperative protocol.
Any field change after round 1 invalidates all produced
commitments and proofs.

**SESSION is privacy-sensitive — it contains `pi`.** Pre-signature
transcripts and SESSION objects must NEVER be shown to a third-
party verifier (logs, RPC debug, dispute messages, crash dumps).
Cooperating parties already know `pi` (they chose it together at
swap setup). On-chain adapted signatures don't include SESSION,
so chain observers learn nothing extra. **Round-3 reviewer
Finding B.**

`H_session(label, payload)` = `SHA256(label ‖ SESSION ‖ payload)`
where `label` is a per-call literal (e.g.,
`"dleq-challenge-v1"`, `"nonce-commit-ml-v2"`,
`"s-others-derivation-v1"`). Used for off-chain helper hashes
(DLEQ challenge, nonce commitments, deterministic `s_others`).

The on-chain CLSAG signs `tx_sighash`, which is what the
existing `pricoin::ringsig::Verify` / `VerifyMultiLayer` consume.
Cross-session and cross-protocol replay protection comes from:

* **`tx_sighash` itself** — binds outpoints, outputs, locktimes,
  ring members, KI, D. Replaying a sig on a different tx is
  detected by tx-uniqueness.
* **DLEQ challenge** binds T_G, T_H to SESSION (incl. session_id,
  pi). Replaying a DLEQ across sessions fails verification.
* **Nonce commitments** bind L/R/KI/D shares to SESSION. Replaying
  a nonce reveal across sessions fails commitment verification.

The combination is sufficient — the on-chain signature itself
doesn't need extra binding because cross-session manipulation is
caught at the off-chain protocol layer. **Round-3 reviewer
accepted both `tx_sighash` and the off-chain-only alternative;
rev 4 picks the simpler off-chain-only path.**

#### 2.1.1 Canonical transaction-template byte layout

Round-3 reviewer Q1 / Finding A: prose was insufficient. Each
template hash binds **all** fields that determine the spend's
economic effect, with signature/witness fields blanked. Specific
construction:

**`pric_claim_template`, `pric_refund_template`** (PRIC v4 spend
tx with empty CLSAG):
```
pric_template = SHA256(
    uint32_le(tx.version)
  ‖ uint32_le(tx.nLockTime)
  ‖ varint(len(tx.vin))
  ‖ for each vin:
      tx.vin[i].prevout.hash             (32 bytes)
      uint32_le(tx.vin[i].prevout.n)
      uint32_le(tx.vin[i].nSequence)
      // scriptSig blanked (always empty for v4)
  ‖ varint(len(tx.vout))
  ‖ for each vout:
      uint64_le(tx.vout[i].nValue)        // == 0 for v4
      varint(len(spk))
      tx.vout[i].scriptPubKey
  ‖ ct_bundle_template
)

ct_bundle_template = SHA256(
    varint(len(input_commitments))
  ‖ for each input_commitment: 33 bytes
  ‖ varint(len(ring_inputs))
  ‖ for each ring_input:
      varint(len(ring))
      for each ring_member: prev_txid (32) ‖ uint32_le(prev_n)
      pseudo_commitment                   (33 bytes)
      // sig blanked
  ‖ varint(len(outputs))
  ‖ for each output:
      commitment                          (33 bytes)
      varint(len(rangeproof)) ‖ rangeproof
      varint(len(script_pubkey)) ‖ script_pubkey
      tx_pubkey                           (33 bytes)
      one_time_pubkey                     (33 bytes)
  ‖ uint64_le(transparent_fee)
)
```

**`foreign_claim_template`, `foreign_refund_template`**
(Bitcoin/Litecoin v2 P2TR spend, witness blanked):
```
foreign_template = SHA256(
    standard Bitcoin pre-segwit tx serialization with:
      tx.version
      vin[i].prevout, scriptSig (empty for SegWit), nSequence
      vout[i].nValue, scriptPubKey
      tx.nLockTime
    // no witness fields
)
```

These hashes are **deterministic from the unsigned tx skeleton**
— no signature or witness data, no chicken-and-egg with the
adaptor signatures we're producing. Any field that would change
the spend's destination, amount, locktime, or fee is bound.

## 3. Single-party adaptor-CLSAG (single-layer)

This is the simplest variant — one signer, no cooperative split,
single-layer ring (no commitment-offset row). Establish the math
first, then layer cooperative + multi-layer.

### 3.0a Chaum-Pedersen DLEQ proof for (T_G, T_H)

The adaptor-publishing party (the one holding `t`) must produce a
non-interactive Chaum-Pedersen DLEQ proof certifying that the same
`t` is the discrete log of `T_G` w.r.t. `G` AND of `T_H` w.r.t.
`H_p(P_pi)`. Verbatim from round-1 reviewer:

**Prover.** Given `t`, points `(G, H_p(P_pi), T_G, T_H)`:
1. Sample `r ← R` (a fresh random scalar).
2. Compute `A_G = r · G`, `A_H = r · H_p(P_pi)`.
3. Compute the challenge:
   ```
   e = H_session("dleq-challenge-v1",
                 encode(G) ‖ encode(H_p(P_pi))
               ‖ encode(T_G) ‖ encode(T_H)
               ‖ encode(A_G) ‖ encode(A_H))
   ```
4. Compute `z = r + e · t (mod n)`.
5. Output `π_t = (A_G, A_H, z)` (or `(e, z)` with `(A_G, A_H)`
   reconstructed by the verifier; we use the explicit form for
   wire-format clarity).

**Verifier.** Given proof `π_t = (A_G, A_H, z)` and points:
1. Recompute `e` exactly as above (H_session uses the same SESSION).
2. Check `z · G == A_G + e · T_G`.
3. Check `z · H_p(P_pi) == A_H + e · T_H`.
4. Reject if either fails. Reject if any of `A_G, A_H, T_G, T_H` is
   the point at infinity, or if `z, e` aren't valid scalars.

This is honest-verifier zero-knowledge in the Schnorr sense, with
Fiat-Shamir soundness in the ROM. The transcript binding through
SESSION prevents replay across sessions/chains/roles.

### 3.1 Pre-signature generation

**Inputs:**
* Ring `[P_0, …, P_{N-1}]`.
* Signer index `pi` and secret `x_pi` such that `P_pi = x_pi · G`.
* Message `msg`.
* Adaptor points `T_G`, `T_H` and DLEQ proof `π_t` as in §3.0a.
   The signer does **not** know `t`. (For atomic swaps, the
   counterparty owns `t`.)
* Full session transcript SESSION as in §2.1.

**Steps:**
1. Verify `π_t` against `(T_G, T_H)` per §3.0a. If invalid, abort.
2. Compute `tx_sighash` = `ComputeRingMessage(spending_tx)`
   (existing function in `src/pricoin/validation.cpp`). This is
   the message all CLSAG variants sign on chain. SESSION binding
   lives off-chain (DLEQ challenges, nonce commits — see §4.1);
   it is NOT mixed into the on-chain message.
3. Sample nonce `α ← R`.
4. Compute `L_pi = α · G`, `R_pi = α · H_p(P_pi)`.
5. Compute the *shifted* anchors:
     `L'_pi = L_pi + T_G`
     `R'_pi = R_pi + T_H`
   Reject if either is the point at infinity.
6. Compute the key image `KI = x_pi · H_p(P_pi)`.
7. Walk the ring using **the existing CLSAG step-challenge
   function** with `msg = tx_sighash`. At index `pi`, anchor on
   `L'_pi, R'_pi` (NOT `L_pi, R_pi`):
     ```
     c_{pi+1} = StepChallenge(ring, tx_sighash, L'_pi, R'_pi, KI)
     ```
   For `i = pi+1, …, pi-1` (mod N):
     ```
     s_i ← deterministic (see §4.1 for cooperative case;
                          single-party can sample fresh)
     L_i = s_i · G + c_i · P_i
     R_i = s_i · H_p(P_i) + c_i · KI
     c_{i+1} = StepChallenge(ring, tx_sighash, L_i, R_i, KI)
     ```
   `StepChallenge` is the existing function in
   `pricoin::ringsig` — no changes.
8. Compute the closing scalar:
     `ŝ_pi = α - c_pi · x_pi   (mod n)`

**Pre-signature object** (off-chain, between cooperating parties):
```
{ pi, c_0, ŝ_pi, s_0, …, s_{pi-1}, s_{pi+1}, …, s_{N-1},
  KI, T_G, T_H, π_t, SESSION }
```

The on-chain version after Adapt drops `pi`, `T_G`, `T_H`, `π_t`,
SESSION extras — only `(c_0, s_0..s_{N-1}, KI)` go on chain, which
is byte-identical in shape to a normal CLSAG.

### 3.2 Pre-signature verification

The verifier holds the pre-sig object and SESSION. They check:
1. Verify `π_t` against `(T_G, T_H)`.
2. Recompute `tx_sighash = ComputeRingMessage(spending_tx)` from
   the agreed unsigned tx template. Confirm it matches.
3. Walk the ring N steps, starting from `c_0`. At each step:
   ```
   L_i = s_i · G + c_i · P_i             (where s_pi := ŝ_pi)
   R_i = s_i · H_p(P_i) + c_i · KI
   ```
   At index `pi` only, additionally shift:
   ```
   L_i ← L_i + T_G
   R_i ← R_i + T_H
   ```
   Then:
   ```
   c_{i+1} = StepChallenge(ring, tx_sighash, L_i, R_i, KI)
   ```
4. Accept iff `c_N == c_0`.

The verifier MUST know `pi` (it's in the pre-sig object). This
leaks `pi` to the off-chain receiver — acceptable because in the
cooperative-spend setting both parties already know `pi` (they
chose it together at protocol setup). Pre-sig objects must NEVER
be shown to a third-party verifier; they are private swap
secrets. Logging, RPC debug dumps, and dispute transcripts must
exclude pre-sig objects. (Reviewer Q8.)

### 3.3 Adapt

Given pre-sig `ŝ_pi` and the secret `t`:
   `s_pi = ŝ_pi + t   (mod n)`

Adapter MUST verify before broadcast:
- `(t · G) == T_G` (round-trip the secret).
- `s_pi != 0` (mod n). Negligible-probability case, but if it
  fires, abort and restart the cooperative signing protocol with
  fresh nonces — `secp256k1_ec_seckey_verify` rejects zero, so
  on-chain verification would fail. **Round-3 reviewer Finding G.**
- The resulting on-chain signature `(c_0, s_0..s_{N-1}, KI)`
  verifies under the standard CLSAG verifier (§3.4).

Same restart-on-zero rule applies to any individual `s_share_X`
during cooperative round 3 (§4.1).

If any check fails, abort: something is malformed (DLEQ was
bogus, or implementation bug, or the negligible zero-scalar
case fired).

### 3.4 Standard verification of the adapted signature

The on-chain signature is **byte-identical in shape** to a normal
CLSAG. The verifier is the deployed `pricoin::ringsig::Verify(ring,
sig, tx_sighash)` — no adaptor-specific code path. Standard
CLSAG verification computes:
```
L_i = s_i · G + c_i · P_i
R_i = s_i · H_p(P_i) + c_i · KI
c_{i+1} = StepChallenge(ring, tx_sighash, L_i, R_i, KI)
```

At index `pi`:
```
L_pi = s_pi · G + c_pi · P_pi
     = (ŝ_pi + t) · G + c_pi · x_pi · G
     = (α - c_pi · x_pi + t) · G + c_pi · x_pi · G
     = (α + t) · G
     = L'_pi (the shifted anchor used in pre-sig walk).
```

Same for `R_pi = R'_pi`. The walk reproduces the same `c_{pi+1}`
as the pre-sig walk; the rest of the ring is identical; `c_0`
round-trips. ✓

### 3.5 Extract

Given the on-chain `s_pi` and the held pre-signature `ŝ_pi`:
   `t = s_pi - ŝ_pi   (mod n)`

MUST verify after extraction:
- `(t · G) == T_G`.
- `(t · H_p(P_pi)) == T_H`.

Both checks; reviewer Section 4 hazard #1 (sign error). If either
fails, the published `s_pi` is malformed and the swap is in an
error state — caller decides recovery.

## 4. Cooperative adaptor-CLSAG (single-layer)

The cooperative variant has multiple parties X = 1..k each holding
shares `x_X` such that `Σ x_X = x_pi`. The pre-signature is built
piece-by-piece; the adaptor secret `t` is held by exactly one party
(the foreign-chain party in our atomic-swap context).

### 4.1 Round protocol

**Setup.** Parties have agreed on `ring`, `pi`, `msg`, and exchanged
each party's spend share's pubkey (so `Σ x_X · G = ring[pi]`). The
adaptor party (say "Bob") chooses `t`, publishes `(T_G, T_H, π_t)`,
and the SESSION transcript is fully constructed and agreed before
round 1.

**Round 1 — commit.** Each party X:
1. Samples `α_X ← R`. **Reuse-prevention requirement**: each session
   MUST use a fresh `α_X`; reuse leaks `x_X`. Recommended:
   ```
   α_X = H_session("nonce-derivation-v1",
                   secret_nonce_key_X ‖ counter_X)
        XOR (32 bytes from CSPRNG)
   ```
   where `secret_nonce_key_X` is per-wallet, persistent, and
   `counter_X` increments monotonically per session. Reviewer
   Section 4 hazard #14.
2. Computes `L_share_X = α_X · G`, `R_share_X = α_X · H_p(P_pi)`,
   `KI_share_X = x_X · H_p(P_pi)`.
3. Broadcasts a hiding commitment:
   ```
   commit_X = H_session("nonce-commit-v1",
                        L_share_X ‖ R_share_X ‖ KI_share_X)
   ```

**Round 2 — open.** Each party reveals `(L_share_X, R_share_X,
KI_share_X)`. Counterparties verify the round-1 commitments.

The combiner (any party) computes:
* `KI = Σ KI_share_X`
* `L_pi = Σ L_share_X`
* `R_pi = Σ R_share_X`
* `L'_pi = L_pi + T_G`
* `R'_pi = R_pi + T_H`

The non-signer ring scalars `s_others[i]` (for i ≠ pi) MUST be
**derived deterministically from SESSION**, not generated by a
single party. Use the existing
`pricoin::ringsig::HashToScalar(...)` (which already implements
the rejection/rehash protocol with domain-tagged input) seeded
with:
```
s_others[i] = HashToScalar([
    "pricoin/adaptor-clsag/s-others-v1",
    SESSION,            // includes pi, ring_hash, KI, D, T_G, T_H,
                        // tx templates, locktimes, role labels, etc.
    uint32_le(index)    // ring index i (i ≠ pi)
])
```
`HashToScalar` rejects and rehashes invalid scalars per the
existing CLSAG implementation; same protocol applies here.
**Round-3 reviewer Finding D.**

This eliminates the grinding vector (a designated party choosing
non-signer scalars adversarially) without requiring extra
round-trips. (Trade-off: deterministic `s_others` reduces the
entropy of the published signature slightly — by ~32×N bits —
which is harmless against the distinguishing analyses we know
about. Reviewer can confirm.)

All parties walk the ring with `(L'_pi, R'_pi)` and the
deterministic `s_others`, getting the same `c_pi` and `c_0`.

**Round 3 — close.** Each party computes
`ŝ_share_X = α_X - c_pi · x_X (mod n)` and broadcasts. The
combiner sums to `ŝ_pi = Σ ŝ_share_X`.

**Pre-signature object** (as in §3.1) plus the `(T_G, T_H, π_t)`
tuple. The full SESSION must be archived alongside.

### 4.1a Nonce persistence requirement

**Round-3 reviewer Q5 + hazard #15.** Concurrent-session
hardening for cooperative adaptor signing requires more than just
commit-reveal in-memory; the wallet MUST durably persist nonce
state to disk **before** broadcasting any nonce commitment.

**Required wallet behaviour:**

1. Before sending round-1 commitment `commit_X` (§4.1 step 3):
   write a record to wallet.dat keyed by
   `(session_id, joint_output, ring_hash, role)` containing:
   * `α_X` (the nonce that was committed).
   * `commit_X` itself.
   * `t_published` flag (false initially; set true if this is the
     adaptor party and `t` has been broadcast / extracted).
   `fsync` before the commitment leaves the wallet.

2. On every cooperative-signing call (start of round 1):
   reject if a record with the same
   `(joint_output, ring_hash, role)` exists with a different
   `session_id` or with `t_published == false`. This blocks
   "sign twice with the same joint output under different
   sessions" — the prerequisite for the most common nonce-reuse
   attack.

3. On wallet restart (e.g., after crash): replay any pending
   nonce records into the in-memory cache. Any cooperative
   signing call that arrives must pass the same conflict check.

**Why this matters.** A naive in-memory implementation that
loses state on crash, then signs again with a freshly-derived
α, produces two cooperative signatures over the same key with
different challenges. Linear algebra recovers the spend share:
`x_X = (ŝ_share_X − ŝ_share_X') / (c_pi' − c_pi)`. Catastrophic.

The deterministic nonce derivation in §4.1 (HMAC of secret nonce
key + counter + CSPRNG) reduces but does not eliminate this risk
— the counter must increment monotonically across crashes, which
requires persistence.

### 4.2 Cooperative-share consistency DLEQs

**Round-3 reviewer Finding C:** revision 3 had single-layer DLEQs
optional. This is a footgun — same code path will be reused for
multi-layer where they're mandatory; an "optional" branch in v1
becomes a "skipped" branch in v2 by accident. Rev 4 simplifies:

* **Share-consistency DLEQs are MANDATORY for ALL adaptor mode**
  — single-layer and multi-layer alike. No optional branch.
* The non-adaptor cooperative CLSAG (already implemented in
  `pricoin/joint_ringsig.cpp`) is unaffected; abort-only safety
  remains there.

**The proofs.** Each party X publishes:

* DLEQ-1: `L_share_X = α_X · G` and `R_share_X = α_X · H_p(P_pi)`
  use the same `α_X`. Standard Chaum-Pedersen (§3.0a) over
  generators `(G, H_p(P_pi))` and points `(L_share_X, R_share_X)`.
* DLEQ-2: `X_pub_X = x_X · G` (the party's pre-committed public
  spend share, fixed at swap setup) and `KI_share_X = x_X ·
  H_p(P_pi)` use the same `x_X`. Same form.
* DLEQ-3 (multi-layer only): `Z_pub_X = z_X · G` and `D_share_X
  = z_X · H_p(P_pi)` use the same `z_X`. Same form.

All DLEQs bind the canonical SESSION via `H_session(...)`.

**Precommit order (round-3 reviewer Q4 hard requirement).**
Each party's public spend share `X_pub_X = x_X · G` (and, for
multi-layer, `Z_pub_X = z_X · G`) MUST be committed and exchanged
**before** any of:
* the adaptor secret `t` is chosen,
* `T_G` / `T_H` are published,
* nonce commitments are sent.

This means the joint stealth address setup (§6.0) must finalize
public shares — including PoP signatures — before the parties
proceed to adaptor-specific steps. Without this ordering, a
malicious counterparty can adapt their public share after seeing
the adaptor point or the honest party's nonce commitment, biasing
the resulting `µ` (multi-layer) or facilitating rogue-key choice
(single- and multi-layer).

Identifiable abort (proving on-chain that party X misbehaved) is
deferred to phase 7's reputation/slashing infrastructure. The
DLEQs make abort SAFE (malformed shares produce a failed sig);
making abort IDENTIFIABLE additionally needs the on-chain proof
artifact, which is a separate concern.

### 4.3 Adapt + Extract

Bob holds `t`. He computes `s_pi = ŝ_pi + t` and broadcasts. The
other parties see the on-chain `s_pi` and extract `t = s_pi - ŝ_pi`
using their pre-sig copy. Both checks from §3.5 apply.

## 5. Cooperative adaptor multi-layer CLSAG

Multi-layer is what v4 PRIC outputs actually use. The adaptor
extension composes with multi-layer's µ-aggregation. **Reviewer
Q4 — informally argued, not proven; this is the main place to
push back during re-review.**

### 5.1 The composition

In multi-layer:
* Each ring member is `(P_i, W_i)`.
* The signer knows `(x_pi, z_pi)` such that `P_pi = x_pi·G`,
  `W_pi = z_pi·G`.
* `KI = x_pi · H_p(P_pi)`, `D = z_pi · H_p(P_pi)` are both
  published.
* `µ_P, µ_C` derive exactly as in the existing
  `pricoin::ringsig::SignMultiLayer` (`MultiLayerMu` —
  `H_s(tag ‖ ring ‖ KI ‖ D)` with separate tags for P and C).
  No adaptor-specific changes.
* Aggregated ring: `T_i = µ_P · P_i + µ_C · W_i`.
* Aggregated priv at pi: `a = µ_P · x_pi + µ_C · z_pi`.
* Aggregated image: `I_agg = µ_P · KI + µ_C · D = a · H_p(P_pi)`.
* `α ← R`, `L_pi = α·G`, `R_pi = α·H_p(P_pi)`.

For the adaptor variant, shift `L_pi` and `R_pi` by `T_G`, `T_H`
(where `T_H = t·H_p(P_pi)`, NOT `t·I_agg` — reviewer hazard #3):
* `L'_pi = L_pi + T_G`
* `R'_pi = R_pi + T_H`

Walk uses `L'_pi`, `R'_pi`, and the existing
`StepChallengeML(ring, tx_sighash, L_i, R_i, KI, D)` from
`pricoin::ringsig` — no changes to the multi-layer challenge
function. SESSION binding is at the message-digest layer
(§2.1).

Closing: `ŝ_pi = α - c_pi · a`.

Adapt: `s_pi = ŝ_pi + t`. Standard verifier recomputes:
* `L_pi = s_pi · G + c_pi · T_pi = (α + t) · G = L'_pi`
* `R_pi = s_pi · H_p(P_pi) + c_pi · I_agg = (α + t) · H_p(P_pi) = R'_pi`

So the walk's `c_pi+1` is the same as the pre-sig's. `c_0`
round-trips. ✓

### 5.2 Cooperative multi-layer

Same as §4.1 but each party holds shares of BOTH `x` and `z`. Two
mandatory differences:

1. **NonceCommit binds `D_share`** in addition to `L_share,
   R_share, KI_share`. Existing `joint_ringsig.cpp::NonceCommit`
   doesn't, and **must be updated** before any adaptor multi-
   layer code uses it. Round-2 reviewer hazard #6.
   ```
   commit_X = H_session("nonce-commit-ml-v2",
                        L_share_X ‖ R_share_X
                     ‖ KI_share_X ‖ D_share_X)
   ```
2. **Share-consistency DLEQs (§4.2) are mandatory**, not optional.
   Each party publishes DLEQ-1, DLEQ-2, DLEQ-3 alongside their
   round-2 reveal.

The aggregated priv share: `a_share_X = µ_P · x_X + µ_C · z_X`.
Closing share: `ŝ_share_X = α_X - c_pi · a_share_X`.

### 5.3 Why µ × adaptor doesn't break (informal)

`µ_P, µ_C` are deterministic functions of public data
(`ring, KI, D`). They depend on the **published** image points,
not on `α, t, ŝ_pi, s_pi`. The adaptor's effect is entirely
additive on the **anchor points** `(L_pi, R_pi)` and the
**closing scalar**.

**Conjecture (informal):** if adaptor-CLSAG single-layer is
secure, then adaptor-CLSAG multi-layer is secure under the same
hardness assumption.

**The argument fragility flagged by round-1 review:** an
adversarial party in the cooperative setting controls part of
the published `(KI, D)` via their `KI_share_X, D_share_X`, and
therefore part of `µ`. The argument above assumes `µ` is fixed
public data; an adversary who can grind their image-shares to
manipulate `µ` may obtain attack surface. Round-1 review found
no concrete counter-example but flagged this as the weakest part
of the spec.

**Mitigation (mandatory in revision 3):** §5.2's share-consistency
DLEQs (DLEQ-2 ties `x_X · G` to `KI_share_X = x_X · H_p(P_pi)`;
DLEQ-3 ties `z_X · G` to `D_share_X = z_X · H_p(P_pi)`) close the
grinding surface. Each party's contribution to `(KI, D)` is
proved consistent with their public shares, which were committed
at swap setup before `t` was chosen. No party can manipulate `µ`
adversarially — they can only DoS the protocol (which the abort
path handles).

**Round-2 reviewer Q4:** "I do not see a way to make extraction
fail with mandatory share-consistency DLEQs and precommitted
shares" — the spec now requires both. Q4 still flagged for a
human cryptographer's formal proof if/when value scales up.

## 6. Atomic-swap protocol (revision 3)

Section rewritten end-to-end across two review rounds. Round 1
caught the SHA-256-HTLC + adaptor-scalar binding gap; round 2
caught the timelock direction error and demanded a tighter
atomicity-claim phrasing. This revision incorporates both.

### 6.0 Joint-stealth setup: rogue-key defense

The cooperative joint-stealth construction in
`pricoin::joint_stealth` adds Alice's and Bob's spend pubkeys
additively: `B_J = B_A + B_B`. In a plain additive multisig with
unbounded share selection, this is vulnerable to rogue-key
attacks: after seeing `B_A`, an attacker can pick
`B_B' = B_B - B_A` so that `B_J = B_B'`, giving them sole
control of the joint key. Round-2 reviewer Finding B.

**Defense (mandatory for trustless atomic swaps):** the joint-
stealth setup MUST use one of:

1. **Proof of possession.** Each party publishes a Schnorr
   signature on a fixed-format challenge `H("pricoin/joint-
   stealth/PoP-v1" ‖ session_id ‖ counterparty_pub)` using their
   spend privkey. Counterparty verifies before computing `B_J`.
   This is the simplest fix and is what we'll implement.

2. **Commit-before-reveal.** Both parties commit to their pubkey
   hashes first; reveal the actual pubkeys only after both
   commitments are exchanged. Prevents the after-the-fact pubkey
   selection.

3. **Coefficient-weighted (MuSig-style) aggregation.**
   `B_J = h_A · B_A + h_B · B_B` where `h_X = H(B_A ‖ B_B ‖ X)`
   bind each party's contribution to both pubkeys. Heaviest fix;
   changes the joint-stealth wire format. Out of scope for v1.

**Decision: option 1 (proof of possession).** Wallet-side helper:
both parties exchange `(B_X, sig_X)` where `sig_X` is a Schnorr
signature on the PoP challenge under `B_X`. Verifying the PoP
before constructing the joint address blocks the `B_B' = B_B -
B_A` rogue-key attack. The existing `pricoin_buildjointstealthaddress`
RPC must be extended with a PoP requirement before use in any
adaptor swap — this is a **must-do before atomic-swap implementation**.

### 6.0a Foreign-adaptor binding (cross-chain T_G must be the same)

**Round-3 reviewer Finding A — highest-priority new finding.**

The protocol uses the same scalar `t` on both legs: PRIC adaptor-
CLSAG's `T_G = t · G`, and the foreign chain's adaptor-Schnorr
point. **Both chains use secp256k1 with the same generator G.**
Therefore the adaptor point on each chain MUST be byte-identical
to `T_G`.

**Verification step (mandatory before signing the foreign leg):**

When Alice receives Bob's foreign-chain adaptor pre-signature
(or vice versa), the recipient MUST:

1. Extract the foreign adaptor point `T_G_foreign` from the
   foreign pre-signature.
2. Confirm `T_G_foreign` is byte-equal to `T_G` (the PRIC adaptor
   point published in §6.2 step 2).
3. If they differ, **abort the swap**. A non-equal `T_G_foreign`
   means the foreign leg uses a different secret than PRIC; the
   parties' adaptor expectations are inconsistent and atomicity
   is broken.

**Why byte-equality and not a DLEQ proof:** since both chains use
the same secp256k1 G, `t · G` is a well-defined point, and any
`t' · G ≠ t · G` for `t' ≠ t`. Comparing the 33-byte compressed
encoding catches every mismatch — there's no need for a DLEQ
proof when the bases are identical.

**Future-proofing for non-secp256k1 chains.** If a future foreign
chain uses a different curve (e.g., ed25519 for some Cardano-like
target), `t · G_foreign` won't be byte-comparable with `t · G_pric`.
At that point the protocol would need a cross-curve DLEQ proof
binding the two adaptor points to the same scalar. **This is
explicitly out of scope for v1.** v1 supports only Bitcoin-derived
secp256k1 chains.

**Implementation hazard #1** (round-3 reviewer): "Foreign adaptor
point not bound to PRIC T_G" — guard with TV-A1 in §13.



The foreign chain (BTC, LTC, or another Bitcoin-derived chain)
must support **adaptor-Schnorr signatures**. In practice this
means **post-taproot mainnets only**:

* BTC mainnet: taproot active since November 2021. ✓
* LTC mainnet: taproot active since 0.21.4 (May 2024). ✓
* DOGE: no taproot. ✗ — out of scope for v1.
* BCH: Schnorr (non-taproot) since 2019; possible but uses a
  different output format. Out of scope for v1.

**Construction.** The output is a 2-of-2 MuSig2-aggregated P2TR
key `P_AB = MuSig2(P_A, P_B)`. The spend tx is pre-signed
cooperatively as a Schnorr adaptor signature with adaptor scalar
`t`. References: Aumayr et al. ASIACRYPT 2021 for the adaptor
abstraction; Nick-Ruffing-Seurin Crypto 2021 for the MuSig2
multi-sig layer. Implementation reference:
[`rust-secp256k1`'s `adaptor` module](https://github.com/RustCrypto/elliptic-curves)
or `secp256k1-zkp`'s `schnorrsig_adaptor_*` (already a
dependency of this project).

**Adaptor-ECDSA explicitly deferred.** ECDSA adaptors require
Lindell-style two-party ECDSA + Paillier or class-group
commitments. Round-2 reviewer Finding F + hazard #20: too much
extra crypto + new assumptions for v1. A separate spec document
will cover them when (if) v2 expands chain coverage.

**Status of existing primitives.** `src/swap/btc_htlc.cpp`
implements **plain SHA-256 HTLC** — explicitly NOT suitable as
the foreign-chain leg of a trustless atomic swap (see round-1
Finding B, fixed by switching to Schnorr adaptors). It remains
useful for **trust-based swaps only** (friends-and-family,
slashing-deposit systems). A new module
`src/swap/btc_adaptor_schnorr.cpp` is required before any
trustless atomic-swap code uses the foreign leg. Out of scope for
this spec; tracked as a separate phase-5 deliverable.

### 6.2 The protocol

**Roles.** Alice sells PRIC, buys BTC. Bob sells BTC, buys PRIC.

**Setup (round 0).**

1. Pubkey exchange (out-of-band or via future order book): Alice
   publishes her swap-identity pubkey, Bob publishes his.
2. Bob picks `t ← R` (the adaptor secret). He publishes:
   * `T_G = t · G`.
   * `T_H = t · H_p(P_pi)` where `P_pi` is the PRIC joint stealth
     output's one-time pubkey (computed in step 4 below; this is
     deferred until then in practice).
   * DLEQ proof `π_t` per §3.0a binding the two.

   Alice verifies `π_t` and aborts if invalid.

**Funding phase.**

3. **Bob locks foreign coin.** Bob constructs a 2-of-2 (post-
   taproot: MuSig2-aggregated; pre-taproot: P2WSH multisig) output
   on the foreign chain, payable to (Alice, Bob). Funds it from his
   foreign-chain wallet. Alice waits for sufficient confirmations
   (say, 6 for BTC).
4. **Alice locks PRIC.** Alice locks her PRIC into a joint stealth
   output(Alice, Bob) per stage 2a of `doc/atomic-swap-protocol.md`.
   Bob waits for confirmations.

**Pre-sign phase.**

5. **Cooperative pre-sig 1: PRIC-side.** Alice and Bob run the
   cooperative adaptor multi-layer CLSAG protocol from §5 to
   produce a pre-signature on a transaction `tx_pric_claim` that
   spends the PRIC joint output to **Bob's** stealth address. The
   pre-sig embeds `(T_G, T_H, π_t)`. Both parties hold the pre-sig.

6. **Cooperative pre-sig 2: foreign-chain side.** Alice and Bob
   produce a Schnorr (or ECDSA) adaptor pre-signature on a
   transaction `tx_foreign_claim` that spends the foreign 2-of-2
   to **Alice's** address, with adaptor scalar `t` (the SAME `t`
   as in pre-sig 1). Both parties hold the pre-sig.

7. **Cooperative refund tx pre-signs (no adaptor).**
   * `tx_pric_refund`: PRIC joint → Alice. nLockTime ≥ T_pric_refund.
   * `tx_foreign_refund`: foreign 2-of-2 → Bob. nLockTime ≥
     T_foreign_refund.
   Both are pre-signed cooperatively as standard (non-adaptor)
   signatures. Each party gets the refund tx that pays them.

   **Timelock constraint (rev 2 fix, reversed from rev 1):**
   ```
   T_foreign_refund > T_pric_refund + δ
   ```
   where `δ` is large enough for Alice to claim foreign coin if
   Bob does publish. Reviewer Q7. Concretely, with BTC ~10-min
   blocks and a reasonable buffer:
   ```
   T_pric_refund    = funding_height + 24 hours (~480 PRIC blocks
                                                  at 180s blocks)
   T_foreign_refund = T_pric_refund + 24 hours (~144 BTC blocks)
   ```

**Execution (happy path).**

8. **Bob completes pre-sig 1, broadcasts `tx_pric_claim`.**
   `s_pi = ŝ_pi + t`. Bob's PRIC arrives. `t` is now extractable
   from the on-chain signature (via `s_pi - ŝ_pi`, where Alice
   also holds the pre-sig).

9. **Alice extracts `t` and completes pre-sig 2.** Broadcasts
   `tx_foreign_claim`. Alice's foreign coin arrives. Both parties
   have their target asset. Done.

**Refund path (Bob goes silent OR Alice goes silent).**

* If Bob doesn't publish step 8: Alice can broadcast
  `tx_pric_refund` after `T_pric_refund`. PRIC returns to Alice.
  Bob can't subsequently complete pre-sig 1 because the joint
  output is now spent (double-spend conflict).
* If Alice can't complete step 9 in time (network failure, etc.):
  Bob can broadcast `tx_foreign_refund` after `T_foreign_refund`.
  Foreign coin returns to Bob.

### 6.3 Atomicity argument (revision 3)

**Headline claim (rev 3 — revised after round-2 review):**
atomicity holds **under bounded-delay, bounded-reorg, and
successful-claim assumptions**. Specifically:

> Given that Alice's wallet is online, monitors the PRIC chain,
> and can confirm her foreign-chain claim within δ blocks of Bob
> revealing `t` (where δ is calibrated to the foreign chain's
> reorg depth and worst-case fee/confirmation conditions during
> the swap window), no party can be strictly worse off than their
> starting position without their counterparty also losing.

This is the same liveness-dependent atomicity claim as every
practical atomic-swap protocol (Bisq, Farcaster, COMIT,
submarine swaps). It is NOT absolute atomicity under arbitrary
network conditions. Round-2 reviewer Q7 + Finding E.

**Watcher-model requirements.** For the atomicity claim to hold,
Alice's wallet (or her swap-coordinator service) must:

1. **Persist the cooperative pre-signatures.** If the wallet is
   destroyed mid-swap, Alice cannot complete the foreign-claim
   leg even if `t` is revealed.
2. **Monitor the PRIC chain** for `tx_pric_claim` (the spend that
   reveals `t`) at least once per `T_pric_refund - now` interval.
3. **Have foreign-chain wallet keys + funded-fee inputs** ready
   to broadcast `tx_foreign_claim` on demand.
4. **Implement fee-bumping** (CPFP / RBF) on the foreign chain
   in case fees spike during the claim window.
5. **Tolerate reorgs up to depth `D_reorg`** on both chains —
   `δ` must exceed `D_reorg + safety_margin` blocks at the
   foreign chain's expected block rate.

A concrete starting calibration (BTC at 10-min blocks; PRIC at
180-sec blocks):
```
T_pric_refund    = funding_height + 480 PRIC blocks  (~24 hours)
T_foreign_refund = T_pric_refund_walltime + 48 hours
                 ~ +288 BTC blocks beyond T_pric_refund
                 — gives δ ≈ 144 BTC blocks (~24 hours) for Alice
                   to claim foreign coin.
D_reorg          = 6 BTC blocks (standard); δ ≫ D_reorg ✓
```

**Strategy tree (Bob's options).** Same as rev 2 but with the
liveness assumption made explicit:

* Bob refuses to participate: both refund. No loss.
* Bob completes `tx_pric_claim`: Alice extracts `t`, claims
  foreign. **Liveness assumption:** Alice's claim confirms
  before `T_foreign_refund`. If it doesn't, Alice has lost PRIC.
* Bob waits past `T_pric_refund` without completing: Alice
  refunds PRIC. Bob's pre-sig is now a double-spend attempt —
  invalid. Bob refunds foreign coin at `T_foreign_refund`.
* **Closed vs revision 1:** Bob cannot refund foreign coin at
  `T_foreign_refund` and *then* claim PRIC. By the timelock
  constraint, `T_foreign_refund > T_pric_refund + δ`, so by the
  time Bob can refund foreign, Alice has already refunded PRIC
  and the joint output is gone.

**Strategy tree (Alice's options).**

* Alice doesn't lock PRIC: Bob refunds foreign coin. No loss.
* Alice fails to complete `tx_foreign_claim` after `t` is revealed:
  she has lost PRIC. **This is the residual liveness risk.** It
  cannot be eliminated without a stronger model (e.g., on-chain
  watchtower service with slashing). v1 documents the
  requirement; v2 may add watchtower support.

**What "atomic" means here.** The protocol provides:
* No party can lose funds while their counterparty also loses
  nothing (no asymmetric theft).
* Bob's BTC-refund-then-claim-PRIC scam from rev 1 is closed.
* The residual risk is concentrated on Alice's *availability*:
  if she's online and her transactions confirm, she gets her
  target asset; if not, she may lose her source asset.

This is the standard atomic-swap guarantee, not a defect of this
specific protocol.

### 6.4 Liquidity griefing (distinct from atomicity)

**Round-3 reviewer Finding H.** Atomicity protects against theft.
It does NOT protect against denial-of-service / liquidity lockup:

* **Funding-stage griefing.** Bob funds the foreign HTLC at step 3.
  Alice then disappears before locking PRIC. Bob's foreign coin is
  locked until `T_foreign_refund`. Alice has lost nothing. Bob has
  lost the use of his foreign coin for the timelock duration plus
  the gas to refund it. **No theft, but free liquidity lockup
  for an attacker.**
* **Pre-sign-stage griefing.** Both parties have funded; one
  refuses to participate in cooperative signing. Both have to wait
  out their refund timelocks.
* **Watcher-side griefing.** Alice maintains a hot wallet during
  the swap window (per §6.3). An attacker who can disrupt Alice's
  uptime (network attack, DoS the node she's connected to, etc.)
  during the brief window between Bob's PRIC claim and
  `T_foreign_refund` could cause her to miss the foreign claim.

These are not protocol bugs; they're inherent costs of trustless
cross-chain swaps. The phase-7 order book / reputation layer
should mitigate them via:

* **Posted bond / slashing deposit** — counterparty puts up
  collateral that's slashed for griefing.
* **Reputation scores** — repeated griefers get filtered out.
* **Capacity limits** — small swap amounts limit the value of
  any individual lockup.
* **Watchtower service** — a third party can broadcast Alice's
  claim on her behalf if she's offline (with appropriate fee).

For v1 (research prototype), document the griefing risk and rely
on user-side caution. Don't claim "atomic" without the
"liveness-dependent" qualifier.

## 7. Security claims

### 7.1 Pre-signature unforgeability

**Claim.** No PPT adversary without `t` can convert a legitimately-
generated pre-sig `ŝ_pi` into a valid on-chain CLSAG `s_pi`.

**Reduction sketch.** Any forger gives us either `t`
(extracting `t = s_pi - ŝ_pi` from the forgery, then plugging
into the DLEQ to break the gap-DDH assumption underlying the
DLEQ proof) OR a forgery of standard CLSAG (which breaks discrete
log under the random oracle model for `H_p, H_s, H_session`).
**The standard adaptor-Schnorr argument generalizes to CLSAG;
formal proof is the reviewer task at re-review.**

### 7.2 Extraction soundness

**Claim.** Given `(ŝ_pi, s_pi)` both verifying as expected, the
extracted `t = s_pi - ŝ_pi` satisfies `t · G = T_G` AND
`t · H_p(P_pi) = T_H`.

**Argument.** By construction. The §3.5 verification step makes
this an explicit check after extraction, catching any malformed
case.

### 7.3 Pre-signature indistinguishability

**Claim.** A pre-sig leaks no information about `t` beyond what's
in `(T_G, T_H, π_t)` (already public).

**Argument.** `ŝ_pi = α - c_pi · x_pi` is a uniform random scalar
in `[1, n-1]` over the choice of `α`, independent of `t`. The
DLEQ is HVZK in the ROM.

### 7.4 Linkability

**Claim.** Linkability of the underlying CLSAG (KI matches across
all spends of the same output) is preserved.

**Argument.** `KI = x_pi · H_p(P_pi)` is unmodified. Same as
standard CLSAG.

### 7.5 Concurrent-session safety (Wagner-style attacks)

**Claim.** A malicious counterparty running k parallel cooperative-
adaptor sessions cannot extract a victim's spend share or forge a
pre-signature, beyond what a single session allows.

**Argument.** Round-1 commit-reveal binding (§4.1) prevents the
adversary from choosing their nonce after seeing the victim's.
This is the MuSig1-style 3-round pattern, which is concurrent-
session-safe. (MuSig2's two-round pattern requires the additional
2-nonce structure; we don't use it because we're 3-round.)
**Reviewer Q5 — confirmed as "likely OK as a 3-round design but
not audited enough for large value."**

## 8. Open questions for re-reviewer (Q1–Q9, revision 2)

Numbered for citation. **Q4 remains the highest-priority question.**

**Q1.** Pre-signature transcript binding (rev 2 §2.1, §3.0a).
Does the SESSION binding cover everything an adversary could
manipulate? Specifically: are `pric_refund_txid` and
`foreign_refund_txid` always known at SESSION-construction time,
or is there a chicken-and-egg with txid depending on signature
which depends on transcript?

**Q2.** DLEQ proof — Chaum-Pedersen as in §3.0a. Standard
construction; reviewer to confirm wire format (explicit
`(A_G, A_H, z)` vs. compressed `(e, z)`) and that the transcript
binding through `H_session` is sufficient.

**Q3.** Hash-to-point soundness. Try-and-increment `H_p` is
inherited from the existing CLSAG implementation. Modern best
practice would be a hash-to-curve suite (RFC 9380). Worth
upgrading?

**Q4 [highest priority].** µ-aggregation × adaptor — §5.3.
Revision 2 mitigates the cooperative grinding surface via
mandatory share-consistency DLEQs (§5.2 → §4.2). Does this
close the gap, or does µ remain attackable?

**Q5.** Concurrent-session attacks — §7.5. Confirmed as 3-round
commit-reveal pattern; sufficient under standard assumptions?

**Q6.** Identifiable abort — §4.2. Required for v1 or
deferrable to phase 7?

**Q7.** Refund timelock direction — §6.2 fixed in revision 2.
Verify the new direction (`T_foreign_refund > T_pric_refund + δ`)
is correct and sufficient.

**Q8.** Pre-sig leaks `pi` to off-chain receiver — §3.2.
Acceptable in cooperative-spend setting where both parties
already know `pi`. Reviewer confirmed; logging warnings now in
spec.

**Q9.** Side-channel and timing — §3.0a (DLEQ generation),
§3.3 (Adapt), §3.5 (Extract). Reviewer flagged DLEQ generation
+ pre-sig verification branch on `pi`. Constant-time
implementation requirements documented in §11.

## 9. References / prior art

* **CLSAG.** Goodell, Noether, Salazar. "Concise Linkable Ring
  Signatures and Forgery Against Adversarial Keys." 2019.
* **Adaptor signatures (formal model).** Aumayr, Ersoy, Erwig,
  Faust, Hostáková, Maffei, Moreno-Sanchez, Riahi. "Generalized
  Channels from Limited Blockchain Scripts and Adaptor
  Signatures." Asiacrypt 2021.
* **MuSig2.** Nick, Ruffing, Seurin. "MuSig2: Simple Two-Round
  Schnorr Multi-Signatures." Crypto 2021.
* **BTC ↔ XMR atomic swaps.** Joël Gugger / @h4sh3d.
  "Bitcoin–Monero Cross-chain Atomic Swap." 2020.
* **Farcaster project.** Open-source BTC↔XMR implementation.
  Reference for adaptor-Schnorr and adaptor-ECDSA patterns.
* **OSTIF Monero CLSAG audit.** JP Aumasson and Antony Vennard.
  Reference for the kind of audit a serious deployment would
  want.

## 10. AI review prompts

(See `doc/adaptor-clsag-review-prompt.md`. Round-1 prompts run
2026-05-01; responses archived in
`doc/adaptor-clsag-review-responses.md`. Round-2 prompts should
target this revision.)

## 11. Implementation hazards (severity ordered)

Inherited verbatim from round-1 reviewer Section 4, with
revision-2 status notes added:

1. **Wrong timelock inequality.** **FIXED in rev 2 §6.**
2. **Unverifiable SHA256(t) ↔ T_G binding.** **FIXED in rev 2 §6**
   by switching foreign leg to adaptor-Schnorr / adaptor-ECDSA.
3. **Using `T_H = t·I_agg` instead of `t · H_p(P_pi)`.** Implementation
   must use `H_p(P_pi)` as the base for the adaptor's R-shift.
   §2 + §5 explicit.
4. **Sign error in close/adapt/extract.** Correct equations:
   `ŝ = α - c·a`, `s = ŝ + t`, `t = s - ŝ`. Tests must catch sign
   flips.
5. **Not verifying DLEQ before participating.** §3.0a verification
   is a hard precondition for §3.1 step 1.
6. **DLEQ transcript not domain-bound.** §3.0a uses
   `H_session("dleq-challenge-v1", …)` with full SESSION binding.
7. **Failing to validate scalar ranges.** Reject zero, overflow,
   invalid secp256k1 scalars. Consistently in implementation.
8. **Failing to validate points.** Reject invalid compressed
   points and point-at-infinity from combinations.
9. **Omitting D_share from multi-layer commitments.** Fixed in
   §5.2.
10. **Malformed share consistency.** §4.2 + §5.2 require DLEQ
    proofs for shares (mandatory in multi-layer for §5.3 reasons).
11. **Incorrect µ recomputation.** Byte-order, tag,
    serialization, KI/D mismatch all fail. Test with
    deliberately-corrupt µ inputs.
12. **Publishing π accidentally.** π is in pre-sig only; never
    on-chain. Audit RPC outputs.
13. **Logging pre-signatures.** Must redact at INFO level; only
    DEBUG logs may carry them.
14. **Nonce reuse.** §4.1 specifies session-bound deterministic
    derivation with auxiliary CSPRNG entropy.
15. **Grinding `s_others`.** §4.1 specifies deterministic
    derivation from SESSION.
16. **Inadequate tests.** Required tests: single-layer adapt/
    extract, multi-layer adapt/extract, wrong T_H, wrong DLEQ,
    wrong sign, wrong π, swapped KI/D, malformed share, zero
    scalar, infinity combine, concurrent sessions, timelock
    simulations.

## 12. Recommended human reviewers (if value scales up)

If/when this protocol handles non-trivial value, the maintainer
should engage a human cryptographer with publication record in
adaptor signatures or ring signatures. Round-1 reviewer's
suggested names, transferred verbatim:

* **CLSAG-style ring signatures.** Sarang Noether or Brandon
  Goodell (CLSAG paper authors).
* **Schnorr multisig / concurrent-session security.** Tim
  Ruffing or Jonas Nick (MuSig2 authors).
* **Adaptor-signature constructions and channels.** Lukas Aumayr,
  Sebastian Faust, or Pedro Moreno-Sanchez (generalized channels
  paper).
* **BTC ↔ Monero-style atomic swaps.** Joël Gugger or
  contributors around h4sh3d / Farcaster / COMIT.
* **Audit firms with prior Monero CLSAG audit experience.** OSTIF
  reports JP Aumasson and Antony Vennard reviewed Monero CLSAG.

These recommendations are pointers, not endorsements — confirm
current availability and engagement terms directly.

## 13. Mandatory test vectors

Round-2 reviewer Section 6 #8: implementation must include test
vectors that catch each known sign / hash / composition error.
The implementation pull request **MUST** include passing tests
for every item below. Failure of any test is a release blocker.

### 13.1 Math vectors

* **TV-M1: Single-layer adapt/extract round-trip.** Generate a
  pre-sig + adaptor pair, Adapt, verify on-chain compatibility,
  Extract, confirm `t · G == T_G ∧ t · H_p(P_pi) == T_H`.
* **TV-M2: Multi-layer adapt/extract round-trip.** Same flow
  with µ-aggregated 2-row signing.
* **TV-M3: Single-party Adapt-with-wrong-sign.** Implementation
  computes `s_pi = ŝ_pi - t` (sign flip). Resulting signature
  MUST fail standard CLSAG verification.
* **TV-M4: Single-party Extract-with-wrong-sign.** Compute
  `t' = ŝ_pi - s_pi` (flipped). Verify `t' · G != T_G` — test
  catches it.
* **TV-M5: Wrong T_H base.** Construct a pre-sig with
  `T_H = t · I_agg` instead of `t · H_p(P_pi)` (a likely
  implementation slip in multi-layer). Confirm pre-sig
  verification fails.
* **TV-M6: Adapted signature under standard CLSAG verifier.**
  After Adapt, run `pricoin::ringsig::Verify` /
  `VerifyMultiLayer` with `tx_sighash` as the message. Must
  pass — confirms byte-compatibility (round-2 Finding A check).

### 13.2 DLEQ vectors

* **TV-D1: Honest DLEQ verifies.** `(T_G, T_H, π_t)` produced
  with same `t`. Verifier accepts.
* **TV-D2: Mismatched DLEQ rejected.** `T_G = t · G`, `T_H = t' ·
  H_p(P_pi)` for `t' ≠ t`. Verifier rejects.
* **TV-D3: DLEQ replay rejected.** Take `(T_G, T_H, π_t)` from
  session A; submit in session B (different `session_id` /
  `ring`). Verifier rejects (transcript binding).
* **TV-D4: Malformed DLEQ rejected.** `A_G = ∞`, `z = 0`, or
  invalid encoding. Verifier rejects.

### 13.3 Cooperative vectors

* **TV-C1: Honest 2-party cooperative single-layer adapt.** Both
  parties contribute correctly. Result verifies; Extract works.
* **TV-C2: Honest 2-party cooperative multi-layer adapt.** Same
  with multi-layer + share-consistency DLEQs.
* **TV-C3: Multi-layer NonceCommit must bind D_share.** Construct
  a session where party-B's `D_share` differs at commit-time vs
  reveal-time. Combine MUST reject (existing
  `joint_ringsig.cpp::NonceCommit` doesn't include `D_share` —
  test confirms the upgrade landed).
* **TV-C4: Malformed `KI_share` rejected (multi-layer mandatory).**
  Party-B publishes `KI_share_B = x_B' · H_p(P_pi)` for `x_B' ≠
  x_B`. Their DLEQ-2 must fail; combine rejects.
* **TV-C5: Malformed `D_share` rejected (multi-layer mandatory).**
  Party-B publishes `D_share_B` inconsistent with `Z_pub_B`.
  DLEQ-3 fails; combine rejects.
* **TV-C6: Single-layer abort-only mode.** With share-consistency
  DLEQs disabled, malformed shares cause Verify to fail (not
  identifiable but safe). Confirms abort-only safety claim.

### 13.4 Rogue-key vectors

* **TV-R1: Joint-stealth PoP required before swap.** A counterparty
  presenting `B_B' = B_B - B_A` (rogue) without a valid PoP
  signature is rejected by the joint-stealth setup helper.
* **TV-R2: PoP replay across sessions rejected.** PoP signature
  for session A replayed into session B fails (challenge binds
  `session_id`).

### 13.5 Watcher-model simulation

* **TV-W1: Bob refunds foreign first.** Simulate the rev-1 attack:
  Bob refunds foreign at `T_foreign_refund`, then attempts to
  publish `tx_pric_claim`. With rev-3 timelocks (`T_foreign_refund
  > T_pric_refund + δ`), Alice has already refunded PRIC and Bob's
  pre-sig is invalid. Test confirms.
* **TV-W2: Alice timeout.** Simulate Alice failing to claim
  foreign coin within δ. Verify Alice loses PRIC (residual
  liveness risk). Documents the protocol's stated guarantee.

### 13.6 Compatibility vectors

* **TV-X1: Existing CLSAG signatures still verify after
  introducing adaptor code.** Run all existing
  `feature_pricoin_ct.py` and `feature_pricoin_jointspend.py` tests
  unchanged. No regression.
* **TV-X2: `tx_sighash`-signed CLSAG verifies under deployed
  `Verify` / `VerifyMultiLayer`.** Pure compatibility check;
  TV-M6 covers it explicitly.

### 13.7 Adversarial cooperative tests (rev 4 additions)

Round-3 reviewer Section 6 #7 — required adversarial cases that
go beyond the honest happy-path tests in §13.3.

* **TV-A1: Foreign adaptor mismatch.** Adversary's foreign
  Schnorr adaptor pre-sig contains `T_G_foreign ≠ T_G`. Verifier
  on the receiving side rejects per §6.0a.
* **TV-A2: Malformed `KI_share` rejected by DLEQ-2.** Party-B
  publishes `KI_share_B` inconsistent with their pre-committed
  `X_pub_B`. DLEQ-2 fails; cooperative signing aborts before
  producing any pre-sig.
* **TV-A3: Malformed `D_share` rejected by DLEQ-3** (multi-layer).
  Same shape as TV-A2 for the commitment-offset row.
* **TV-A4: DLEQ for wrong session rejected.** Take a valid
  `(T_G, T_H, π_t)` from session A, submit in session B. Verifier
  rejects because SESSION fields in the challenge transcript
  differ.
* **TV-A5: Wrong T_H base.** Pre-sig constructed with
  `T_H = t · I_agg` instead of `t · H_p(P_pi)`. Pre-sig
  verification fails (R-row computation diverges from the
  prover's).
* **TV-A6: Repeated nonce attempt rejected.** Wallet that has
  already broadcast a round-1 commitment for session S₁ refuses
  to start a new cooperative-signing session S₂ with the same
  `(joint_output, ring_hash, role)` until S₁ resolves.
* **TV-A7: Concurrent same-`session_id` rejected.** Two parallel
  sessions with the same `session_id` fail at the conflict-check
  in §4.1a.
* **TV-A8: Leaked / wrong pi rejected.** Pre-sig verifier given
  a `pi` value that doesn't match where the joint pubkey is in
  the ring rejects (the shifted-anchor walk doesn't close).
* **TV-A9: SESSION mutated after round 1 rejected.** Combiner
  receives round-2 reveals for SESSION S, then attempts to walk
  with a modified SESSION'. All commitments fail (they bound the
  original SESSION).
* **TV-A10: Public-share mutation after T_G published rejected.**
  Counterparty tries to substitute a different `X_pub_B` after
  Bob has published `T_G, T_H, π_t`. Setup phase rejects (precommit
  order violated; §4.2 hard requirement).
* **TV-A11: Zero-scalar adapt path.** Force a synthetic case
  where `s_pi == 0` after Adapt (negligible in practice; can
  construct artificially by choosing nonces). Implementation
  must detect and abort, restart with fresh nonces.
* **TV-A12: Double-broadcast nonce-leak detection.** If two
  cooperative-signing sessions over the same key ever produce
  signatures with related α values (a wallet bug), test confirms
  that the linear key-extraction
  `x_X = (ŝ_1 - ŝ_2) / (c_2 - c_1)` recovers the share. This is
  a *negative-test-of-the-protection* — the persistence layer
  in §4.1a should make this case unreachable; TV-A12 confirms
  the test infrastructure could detect it if the protection
  failed.
