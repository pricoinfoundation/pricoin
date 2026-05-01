# Adaptor-CLSAG protocol spec (revision 2 — post-review)

**Status: research draft, revision 2.** Round-1 AI review (archived
in `doc/adaptor-clsag-review-responses.md`) flagged two BROKEN items
in revision 1 plus several real spec gaps. This revision addresses
them. **NOT IMPLEMENTED. Pending re-review of revision 2 before
implementation.**

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

Every adaptor / ring / DLEQ challenge hash in this spec MUST bind a
**session transcript** that includes, at minimum:

```
SESSION = network ‖ asset_pair ‖ role_label ‖ session_id
        ‖ ring_hash ‖ pi ‖ msg_or_txdigest
        ‖ KI ‖ D_or_zero
        ‖ T_G ‖ T_H
        ‖ pric_refund_txid ‖ pric_claim_txid
        ‖ foreign_refund_txid ‖ foreign_claim_txid
```

with explicit byte-length prefixes between fields and ASCII tag
prefixes (e.g., `"pricoin/adaptor-clsag/v1"`) to prevent
cross-protocol confusion. `H_session(label, payload)` =
`SHA256(tag ‖ label ‖ SESSION ‖ payload)` with `tag` being a
per-call literal (e.g., `"dleq-challenge-v1"`,
`"step-challenge-v1"`).

This is the structural requirement raised by Findings A, B, F in
the round-1 review.

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
2. Sample nonce `α ← R`.
3. Compute `L_pi = α · G`, `R_pi = α · H_p(P_pi)`.
4. Compute the *shifted* anchors:
     `L'_pi = L_pi + T_G`
     `R'_pi = R_pi + T_H`
   Reject if either is the point at infinity.
5. Compute the key image `KI = x_pi · H_p(P_pi)`.
6. Walk the ring as in standard CLSAG, but:
   - At index `pi`, use `L'_pi` and `R'_pi` as the anchors (NOT
     the un-shifted `L_pi, R_pi`).
   - Every step-challenge hash binds the full SESSION:
     ```
     c_{pi+1} = H_session("step-challenge-v1",
                          ring ‖ msg ‖ L'_pi ‖ R'_pi ‖ KI)
     ```
     For `i = pi+1, …, pi-1` (mod N):
     ```
     s_i ← deterministic (see §4.1 for cooperative case;
                          single-party can sample fresh)
     L_i = s_i · G + c_i · P_i
     R_i = s_i · H_p(P_i) + c_i · KI
     c_{i+1} = H_session("step-challenge-v1",
                          ring ‖ msg ‖ L_i ‖ R_i ‖ KI)
     ```
7. Compute the closing scalar:
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
2. Walk the ring N steps, starting from `c_0`. At each step:
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
   c_{i+1} = H_session("step-challenge-v1",
                        ring ‖ msg ‖ L_i ‖ R_i ‖ KI)
   ```
3. Accept iff `c_N == c_0`.

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
- The resulting on-chain signature `(c_0, s_0..s_{N-1}, KI)`
  verifies under the standard CLSAG verifier (§3.4).

If either check fails, abort: something is malformed (DLEQ was
bogus, or implementation bug).

### 3.4 Standard verification of the adapted signature

The on-chain signature is standard CLSAG. Recompute the walk with
`s_pi` substituted for `ŝ_pi` and **no shift** at any index:
```
L_i = s_i · G + c_i · P_i
R_i = s_i · H_p(P_i) + c_i · KI
c_{i+1} = H_session("step-challenge-v1",
                    ring ‖ msg ‖ L_i ‖ R_i ‖ KI)
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
single party. Use:
```
s_others[i] = H_session("s-others-derivation-v1",
                         ring ‖ pi ‖ index=i)
              reduced mod n, retry on invalid scalar.
```
This eliminates the grinding vector raised by reviewer Finding E
without requiring extra round-trips. (Trade-off: deterministic
`s_others` reduces the entropy of the published signature
slightly — by ~32×N bits — which is harmless against the
distinguishing analyses we know about. Reviewer can confirm.)

All parties walk the ring with `(L'_pi, R'_pi)` and the
deterministic `s_others`, getting the same `c_pi` and `c_0`.

**Round 3 — close.** Each party computes
`ŝ_share_X = α_X - c_pi · x_X (mod n)` and broadcasts. The
combiner sums to `ŝ_pi = Σ ŝ_share_X`.

**Pre-signature object** (as in §3.1) plus the `(T_G, T_H, π_t)`
tuple. The full SESSION must be archived alongside.

### 4.2 Cooperative-share consistency (optional hardening)

The protocol above is **abort-only secure**: a malformed share by
party X causes the cooperative signature to fail verification, but
no honest party loses funds. This is acceptable for the swap
ceremony's threat model (Bob just doesn't get paid; he refunds).

For **identifiable abort** — proving on-chain that party X
misbehaved — each party should also publish DLEQ proofs that:
* `L_share_X` and `R_share_X` use the same `α_X` (across `G` and
  `H_p(P_pi)`).
* `(x_X · G)` (their public spend share, known from setup) and
  `KI_share_X` use the same `x_X` (across `G` and `H_p(P_pi)`).

Both are standard Chaum-Pedersen DLEQs of the form in §3.0a. Adds
two DLEQ proofs per party per session.

For v1, abort-only is enough; identifiable abort is a future
hardening for when reputation/slashing exists (phase 7).

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
* `µ_P = H_session("agg-P-v2", ring ‖ KI ‖ D)`, similarly `µ_C`.
* Aggregated ring: `T_i = µ_P · P_i + µ_C · W_i`.
* Aggregated priv at pi: `a = µ_P · x_pi + µ_C · z_pi`.
* Aggregated image: `I_agg = µ_P · KI + µ_C · D = a · H_p(P_pi)`.
* `α ← R`, `L_pi = α·G`, `R_pi = α·H_p(P_pi)`.

For the adaptor variant, shift `L_pi` and `R_pi` by `T_G`, `T_H`
(where `T_H = t·H_p(P_pi)`, NOT `t·I_agg` — reviewer hazard #3):
* `L'_pi = L_pi + T_G`
* `R'_pi = R_pi + T_H`

Walk uses `L'_pi`, `R'_pi`, and step challenges depend on
`(KI, D)`:
```
c_{i+1} = H_session("step-ml-v2",
                    ring ‖ msg ‖ L_i ‖ R_i ‖ KI ‖ D)
```

Closing: `ŝ_pi = α - c_pi · a`.

Adapt: `s_pi = ŝ_pi + t`. Standard verifier recomputes:
* `L_pi = s_pi · G + c_pi · T_pi = (α + t) · G = L'_pi`
* `R_pi = s_pi · H_p(P_pi) + c_pi · I_agg = (α + t) · H_p(P_pi) = R'_pi`

So the walk's `c_pi+1` is the same as the pre-sig's. `c_0`
round-trips. ✓

### 5.2 Cooperative multi-layer

Same as §4.1 but each party holds shares of BOTH `x` and `z`. The
NonceCommit MUST bind `D_share` in addition to `KI_share` —
**reviewer Section 4 hazard #9, not in current cooperative code.**
Update:
```
commit_X = H_session("nonce-commit-ml-v2",
                     L_share_X ‖ R_share_X
                  ‖ KI_share_X ‖ D_share_X)
```

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

**Mitigation in this revision:** §4.2's cooperative-share
consistency proofs (DLEQs tying x_X·G to x_X·H_p(P_pi), and
z_X·G to z_X·H_p(P_pi)) eliminate the grinding surface — once
each party's `KI_share, D_share` is provably consistent with
their public spend / commitment shares (which were committed
at swap setup, before `t` was chosen), no party can manipulate
`µ` adversarially. The optional hardening becomes mandatory for
multi-layer adaptor signing.

## 6. Atomic-swap protocol (revision 2)

This section was rewritten end-to-end after round-1 review found
the previous SHA-256-HTLC-on-BTC + adaptor-CLSAG-on-PRIC
construction unverifiable (Finding B). The fix is to use **adaptor
signatures on both legs**, sharing the same scalar `t`.

### 6.1 Foreign-chain leg: adaptor-Schnorr or adaptor-ECDSA

The foreign chain is BTC, LTC, or another Bitcoin-derived chain.

**Post-taproot chains (BTC since 2021, LTC since 2024):** use
**adaptor-Schnorr** on a P2TR output. The output is a 2-of-2
MuSig2-aggregated key `P_AB = MuSig2(P_A, P_B)`. The spend tx is
pre-signed cooperatively as a Schnorr adaptor signature with
adaptor scalar `t`. Standard, well-studied construction (Aumayr et
al. ASIACRYPT 2021 for the abstraction; Nick-Ruffing-Seurin
Crypto 2021 for the MuSig2 multi-sig layer). Implementation
references: `secp256k1-zkp` (already a dependency of this
project) has `secp256k1_ecdsa_adaptor_*` and Schnorr adaptor
helpers; rust-secp256k1's `adaptor` module is the reference.

**Pre-taproot chains (legacy BTC P2WSH/P2WPKH, DOGE, BCH non-Schnorr
paths):** use **adaptor-ECDSA** on a 2-of-2 P2WSH multisig. ECDSA
adaptors are less elegant than Schnorr (require Paillier or
class-group commitments — see Lindell-style two-party ECDSA) but
are deployed in production by Farcaster, COMIT, and others.

The existing `src/swap/btc_htlc.cpp` primitive in this codebase
implements the **plain SHA-256 HTLC** approach. **It is suitable
only for trust-based swaps** (e.g., friends-and-family, or systems
with external slashing). It is NOT suitable as the foreign-chain
leg of a trustless atomic swap as designed in this revision. We
keep `btc_htlc.cpp` as-is for its existing trust-based use, but a
new module — `src/swap/btc_adaptor_schnorr.cpp` and possibly
`src/swap/btc_adaptor_ecdsa.cpp` — is needed for trustless swaps.

That work is **out of scope for this spec**; this spec covers only
the PRIC-side adaptor primitive. The foreign-chain spec lives in
a separate document (TBD: `doc/btc-adaptor.md`) once we get there.

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

### 6.3 Atomicity argument (revision 2)

**Bob's strategies.**

* Bob refuses to participate after step 4: PRIC is still locked.
  Alice refunds at `T_pric_refund`. Bob refunds foreign coin at
  `T_foreign_refund`. Both end where they started.
* Bob completes pre-sig 1 (step 8): PRIC moves to Bob; `t` revealed
  on PRIC chain. Alice extracts and claims foreign coin (she has
  `T_foreign_refund - T_pric_refund > δ` time, by the timelock
  constraint). Both win.
* Bob does NOT complete pre-sig 1 but waits past `T_pric_refund`:
  At `T_pric_refund`, Alice refunds PRIC. The PRIC joint output
  is gone; Bob's pre-sig 1 is now a double-spend attempt and
  invalid. Bob has no claim on PRIC. Bob refunds foreign coin at
  `T_foreign_refund`. Both end at start.
* **Crucial scenario from revision-1 break:** Bob refunds foreign
  coin at `T_foreign_refund`, then attempts to complete pre-sig 1.
  This is now blocked by the timelock direction: `T_foreign_refund
  > T_pric_refund + δ`, so by the time Bob can refund foreign,
  Alice has already refunded PRIC, and the joint output is gone.
  Bob's pre-sig 1 is invalid. **Theft vector closed.**

**Alice's strategies.**

* Alice doesn't lock PRIC after step 3 (Bob locks foreign first):
  Alice has done nothing. Bob refunds foreign coin at
  `T_foreign_refund`. No loss to either.
* Alice can't complete step 9 (Bob has already revealed `t`):
  Alice has lost PRIC. She knew `t` was being revealed but couldn't
  act. Bob refunds foreign coin (no, wait — Bob has PRIC; Alice
  was supposed to claim foreign with `t`).
  In this case, Alice has lost PRIC with no recourse. **This is
  the residual liveness risk.** Mitigations: long enough δ; auto-
  retry on the PRIC node; Alice's wallet must be online during
  the swap window.

**Conclusion.** Modulo the residual liveness risk for Alice,
no party can be strictly worse off than start without their
counterparty also losing. This is the standard atomic-swap
guarantee.

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
