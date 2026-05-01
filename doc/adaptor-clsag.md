# Adaptor-CLSAG protocol spec (draft for AI review)

**Status: research draft. NOT IMPLEMENTED. NOT REVIEWED.** This document
describes the math and on-the-wire protocol for an adaptor-signature
variant of CLSAG, intended for use as the PRIC-side primitive in
trustless cross-chain atomic swaps. The construction composes three
features that are already implemented in this codebase
(`pricoin/ringsig.cpp`, `pricoin/joint_ringsig.cpp`):

1. CLSAG ring signatures (single-layer + µ-aggregated multi-layer).
2. Cooperative signing by additive secret-sharing.
3. Adaptor-signature semantics (pre-signature + adapt + extract).

The composition is straightforward in principle but has not, to our
knowledge, been published with a formal security analysis. This
document is the spec a reviewer should read before either approving
the construction or pointing out where it breaks.

## 1. Goals

The PRIC-side leg of an atomic swap needs to be cryptographically
linked to the foreign-chain leg's secret reveal. Specifically:

* Alice locks PRIC into a 2-of-2 cooperative output (joint stealth).
* Bob locks BTC into an HTLC keyed on a hash `H = SHA256(t)`.
* Alice claims the BTC HTLC by revealing `t` on the BTC chain.
* The act of `t` becoming visible on the BTC chain *atomically* lets
  Bob complete his half of the PRIC-side cooperative spend.

Without adaptor signatures, step 4 doesn't actually unlock step 5 —
the PRIC spend is independent of `t`, so Alice can claim BTC and
then refuse to cooperate on PRIC. The whole point of adaptor sigs
is to bind `t` into the PRIC-side signature.

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
* `T_H = t · H_p(P_pi)`

The DLEQ proof `π_t` proves to a verifier that the same `t` was used
in `T_G` and `T_H` (without revealing `t`).

## 3. Single-party adaptor-CLSAG (single-layer)

This is the simplest variant — one signer, no cooperative split,
single-layer ring (no commitment-offset row). Establish the math
first, then layer cooperative + multi-layer.

### 3.1 Pre-signature generation

**Inputs:**
* Ring `[P_0, …, P_{N-1}]`.
* Signer index `pi` and secret `x_pi` such that `P_pi = x_pi · G`.
* Message `msg`.
* Adaptor points `T_G`, `T_H` (publicly known) and a DLEQ proof `π_t`
  certifying their consistency.
   The signer does **not** know `t` itself. (For atomic swaps, the
   counterparty owns `t`.)

**Steps:**
1. Verify `π_t` against `(T_G, T_H)`. If invalid, abort.
2. Sample nonce `α ← R`.
3. Compute `L_pi = α · G`, `R_pi = α · H_p(P_pi)`.
4. Compute the *shifted* anchors:
     `L'_pi = L_pi + T_G`
     `R'_pi = R_pi + T_H`
5. Compute the key image `KI = x_pi · H_p(P_pi)`.
6. Walk the ring as in standard CLSAG, but using `L'_pi` and `R'_pi`
   as the signer's-row anchor instead of `L_pi` and `R_pi`:
     `c_{pi+1} = H_s(ring ‖ msg ‖ L'_pi ‖ R'_pi ‖ KI)`
   For `i = pi+1, …, pi-1` (mod N):
     `s_i ← R`
     `L_i = s_i · G + c_i · P_i`
     `R_i = s_i · H_p(P_i) + c_i · KI`
     `c_{i+1} = H_s(ring ‖ msg ‖ L_i ‖ R_i ‖ KI)`
7. Compute the closing scalar:
     `ŝ_pi = α - c_pi · x_pi   (mod n)`

**Pre-signature:** `(c_0, ŝ_pi, s_{pi+1}, …, s_{pi-1}, KI, T_G, T_H, π_t)`.

### 3.2 Pre-signature verification

The verifier knows the pre-signature and `msg`. They want to confirm
that the pre-sig was correctly formed by someone who knows `x_pi`
(but not `t`).

1. Verify `π_t` against `(T_G, T_H)`. If invalid, reject.
2. Walk the ring starting from `c_0`:
     For `i = 0, …, N-1`:
       If `i == pi`: caller doesn't know `pi`, so this is *implicit*
         in the walk — see step 3 below.
       `L_i = s_i · G + c_i · P_i`           (where `s_pi = ŝ_pi`)
       `R_i = s_i · H_p(P_i) + c_i · KI`
       For `i == pi`, additionally shift:
         `L_i ← L_i + T_G`
         `R_i ← R_i + T_H`
       `c_{i+1} = H_s(ring ‖ msg ‖ L_i ‖ R_i ‖ KI)`
3. After N steps, `c_0` should round-trip. Accept iff it does.

The verifier doesn't actually know `pi`; instead the standard CLSAG
trick makes the walk circular and the "shifted at pi" detection
implicit. The pre-sig verifier needs to know which index is shifted —
which means the pre-sig must include `pi`, OR the verifier must try
all positions, OR the protocol must put the shift in a public place
the verifier can see.

**Open question 1:** the cleanest construction is for the pre-sig to
include `pi` explicitly, BUT this leaks signer identity. Real CLSAG
sigs never reveal `pi` — that's the whole point of the ring. For
atomic swaps the pre-sig is exchanged off-chain between two parties
who both know `pi` already (they jointly chose it), so this is OK.
**But the published signature MUST not include `pi`.** The Adapt
step removes the shift, restoring the standard CLSAG verification.

### 3.3 Adapt

Given pre-sig `ŝ_pi` and the secret `t`:
   `s_pi = ŝ_pi + t   (mod n)`

The adapted signature `(c_0, s_0, …, s_{N-1}, KI)` is verifiable by
the **standard** CLSAG verifier (no T_G, T_H, no DLEQ, no shift).
Specifically:

* Recompute the walk with `s_pi` substituted for `ŝ_pi`. At index
  `pi`, the standard verifier computes:
     `L_pi = s_pi · G + c_pi · P_pi`
            = (ŝ_pi + t) · G + c_pi · P_pi
            = (α - c_pi · x_pi + t) · G + c_pi · x_pi · G
            = α · G + t · G
            = L_pi_unshifted + T_G
            = L'_pi (the shifted anchor used during pre-sig walk).
   Similarly `R_pi = R'_pi`.
* The walk reproduces the same `c_{pi+1}` as the pre-sig walk. The
  rest of the ring computes identically. `c_0` round-trips.

Therefore the adapted signature looks **byte-identical in shape** to
a non-adaptor CLSAG signature. On-chain, no observer can tell the
spend was the result of an adaptor protocol.

### 3.4 Extract

Given the on-chain `s_pi` and the held pre-signature `ŝ_pi`:
   `t = s_pi - ŝ_pi   (mod n)`

Verify `t · G == T_G` to detect tampering.

## 4. Cooperative adaptor-CLSAG (single-layer)

The cooperative variant has multiple parties X = 1..k each holding
shares `x_X` such that `Σ x_X = x_pi`. The pre-signature is built
piece-by-piece; the adaptor secret `t` is held by exactly one party
(the BTC-side party in our atomic-swap context).

### 4.1 Round protocol

**Setup:** parties have agreed on `ring`, `pi`, `msg`, and exchanged
each other's shares' pubkeys (so `Σ x_X · G = ring[pi]`). The
adaptor party (say "Bob") chooses `t`, publishes `T_G = t · G` and
`T_H = t · H_p(P_pi)` along with DLEQ proof `π_t` to the others.

**Round 1 — commit.** Each party X:
1. Samples `α_X ← R`.
2. Computes `L_share_X = α_X · G`, `R_share_X = α_X · H_p(P_pi)`,
   `KI_share_X = x_X · H_p(P_pi)`.
3. Broadcasts a hiding commitment `commit_X = H(session_id ‖
   L_share_X ‖ R_share_X ‖ KI_share_X)`.

**Round 2 — open.** Each party reveals `(L_share_X, R_share_X,
KI_share_X)`. Counterparties verify the round-1 commitments.

The combiner (any party) computes:
* `KI = Σ KI_share_X`
* `L_pi = Σ L_share_X`
* `R_pi = Σ R_share_X`
* `L'_pi = L_pi + T_G`
* `R'_pi = R_pi + T_H`

A designated party generates the non-signer `s_others[i]` (i ≠ pi)
and broadcasts. All parties walk the ring deterministically using
`L'_pi`, `R'_pi` (not `L_pi`, `R_pi`!) → c_pi.

**Round 3 — close.** Each party computes `ŝ_share_X = α_X - c_pi ·
x_X` and broadcasts. The combiner sums to `ŝ_pi = Σ ŝ_share_X`.

**Pre-signature:** as in §3.1 plus the (T_G, T_H, π_t) tuple.

### 4.2 Adapt + Extract

Bob holds `t`. He computes the adapted signature `s_pi = ŝ_pi + t`
and broadcasts. The other parties see the on-chain `s_pi` and
extract `t = s_pi - ŝ_pi` using their pre-sig copy.

## 5. Cooperative adaptor multi-layer CLSAG

Multi-layer is what v4 PRIC outputs actually use. The adaptor
extension composes with multi-layer's µ-aggregation. The key
question for the reviewer: does µ-aggregation interact safely with
the adaptor shift?

### 5.1 The composition

In multi-layer:
* Each ring member is `(P_i, W_i)`.
* The signer knows `(x_pi, z_pi)` such that `P_pi = x_pi·G`,
  `W_pi = z_pi·G`.
* `KI = x_pi · H_p(P_pi)`, `D = z_pi · H_p(P_pi)` are both published.
* `µ_P = H_s("agg/P/v2" ‖ ring ‖ KI ‖ D)`, similarly `µ_C`.
* Aggregated ring: `T_i = µ_P · P_i + µ_C · W_i`.
* Aggregated priv at pi: `a = µ_P · x_pi + µ_C · z_pi`.
* Aggregated image: `I_agg = µ_P · KI + µ_C · D = a · H_p(P_pi)`.
* `α ← R`, `L_pi = α·G`, `R_pi = α·H_p(P_pi)`.
* Walk uses `L_pi`, `R_pi`, and step challenges depend on `(KI, D)`:
    `c_{i+1} = H_s("step/v2" ‖ ring ‖ msg ‖ L_i ‖ R_i ‖ KI ‖ D)`.
* Closing: `s_pi = α - c_pi · a`.

For the adaptor variant, shift `L_pi` and `R_pi` by `T_G`, `T_H`
**exactly as in single-layer**:
* `L'_pi = L_pi + T_G`
* `R'_pi = R_pi + T_H`
* Walk uses `L'_pi`, `R'_pi`.
* `ŝ_pi = α - c_pi · a` (same as cooperative-without-adaptor).
* Adapt: `s_pi = ŝ_pi + t`. The standard verifier recomputes:
    `L_pi = s_pi · G + c_pi · T_pi = (α + t) · G = L'_pi`
    `R_pi = s_pi · H_p(P_pi) + c_pi · I_agg = (α + t) · H_p(P_pi) = R'_pi`
  So the walk's `c_pi+1` is the same as the pre-sig's. `c_0`
  round-trips. ✓

### 5.2 Why the µ-aggregation doesn't break the adaptor

The argument: `µ_P, µ_C` are deterministic functions of public data
(`ring, KI, D`). They are *not* affected by the adaptor secret `t`,
the nonce `α`, or the closing scalar `s_pi`. The adaptor's effect
is entirely additive on the *anchor points* `(L_pi, R_pi)` and the
*closing scalar*. The µ-aggregation operates on the *ring* and *priv*
sides, which are orthogonal.

**Claim (informal):** If adaptor-CLSAG single-layer is secure, then
adaptor-CLSAG multi-layer is secure under the same hardness
assumption.

**Proof sketch:** any pre-sig forger against multi-layer can be
turned into a single-layer forger by treating the µ-aggregated
quantities (`a`, `I_agg`, walk) as if they were a single-layer
signature with a fresh basis. Formal version requires careful
handling of how `µ_P, µ_C` are derived (specifically that they're
*after* `KI, D` are committed, not adversarially-chosen). **This is
the main place I want a reviewer to push back.**

## 6. Atomic-swap protocol using adaptor-CLSAG

Putting it all together:

**Setup.**
1. Alice and Bob exchange swap-identity pubkeys (out-of-band or via
   future order book).
2. Bob picks `t ← R`. Computes adaptor points and DLEQ.
3. Bob constructs BTC HTLC keyed on `H = SHA256(t)` with timelock
   `T_btc`.
4. Alice locks PRIC into joint stealth(Alice, Bob).

**Pre-sign phase.**
5. Alice and Bob run cooperative adaptor multi-layer CLSAG against
   the joint stealth output, with the pre-sig destination being a
   payment to Bob's PRIC stealth address.
   Result: a pre-signature `(ŝ_pi, …)` plus `(T_G, T_H, π_t)`.
6. Bob holds `t` and the pre-sig. Alice holds the pre-sig.

**Execution.**
7. Alice claims the BTC HTLC, revealing `t` on BTC chain.
8. Alice extracts `t` from the BTC HTLC witness.
9. Alice runs Adapt: `s_pi = ŝ_pi + t`. Broadcasts the completed PRIC
   spend.
10. Bob sees the on-chain PRIC spend, extracts `t` via
    `s_pi - ŝ_pi` (he already has both). Verifies the BTC HTLC was
    indeed claimed.

**Atomicity.** If Alice claims BTC, she MUST publish `s_pi` to claim
the PRIC. If she does, Bob extracts `t` and… wait, Bob doesn't gain
anything from `t` here. Let me re-derive.

(Hmm. The protocol direction may be flipped. Let me work it out.)

### 6.1 Correcting the protocol direction

In a swap "Alice sells PRIC, Bob sells BTC":

* The PRIC output is co-locked by Alice + Bob (joint stealth). To
  spend it to Bob's address (i.e., complete the swap from Alice's
  side), they both need to sign cooperatively. The pre-signature
  is a signature WAITING for the secret.
* The BTC HTLC is locked s.t. Bob can refund after `T_btc` or Alice
  can claim with preimage `t`. To claim it, Alice must reveal `t`.

For atomicity, the act of Alice claiming BTC must give her access
to the PRIC pre-sig completion, BUT NOT give Bob anything bad. And
the act of NOT claiming BTC must mean Alice can't spend the joint
PRIC to herself.

The protocol:
* Alice and Bob cooperatively sign **the PRIC spend that pays Bob**.
  The pre-sig is published to Bob (held off-chain).
* Bob knows the adaptor secret `t`. The pre-sig requires `t` to
  complete.
* Alice has no way to spend the PRIC unilaterally (it's joint).
* Bob spending PRIC requires the cooperative pre-sig + `t`.
* If Bob completes the pre-sig (publishes `s_pi`), the on-chain
  reveal lets Alice extract `t` (via `t = s_pi - ŝ_pi`, where Alice
  also holds the pre-sig), claim BTC HTLC, and the swap is
  successfully completed.
* If Bob doesn't complete: the PRIC stays locked. Alice has the
  refund path (a pre-signed refund tx with timelock back to Alice,
  signed cooperatively at swap setup).

This is cleaner. Let me restate:

**Setup.**
1. Pubkey exchange.
2. Bob picks `t ← R`; publishes `T_G, T_H, π_t`.
3. Alice locks PRIC into joint(Alice, Bob).
4. Bob locks BTC HTLC with hash `H = SHA256(t)` and refund timelock
   `T_btc` (back to Bob).
5. Cooperatively sign two pre-signatures:
   * `tx_claim`: PRIC spend → Bob's stealth. Adaptor pre-sig
     requiring `t` to complete.
   * `tx_refund`: PRIC spend → Alice's stealth, with nLockTime ≥
     `T_pric_refund > T_btc + safety_margin`. Standard cooperative
     pre-sig, no adaptor.

   Bob holds `tx_claim` pre-sig. Alice holds `tx_refund` pre-sig.

**Execution (happy path).**
6. Bob completes `tx_claim` using `t`: `s_pi_claim = ŝ_pi_claim + t`.
   Broadcasts.
7. Alice sees on-chain `s_pi_claim`, extracts `t = s_pi_claim -
   ŝ_pi_claim`.
8. Alice claims BTC HTLC with preimage `t`. Both parties have their
   target asset. Done.

**Refund path (Bob goes silent).**
6'. After `T_pric_refund`, Alice broadcasts `tx_refund`. PRIC
    returns to Alice.
7'. After `T_btc`, Bob broadcasts BTC HTLC refund. BTC returns to
    Bob.

**Refund timeline constraint.** `T_pric_refund > T_btc + δ` where δ
is large enough that Alice's BTC claim window (between `T_pric_refund
- δ` and `T_pric_refund`) gives her time to claim BTC if Bob does
publish. If Alice runs out of time, she's stuck refunding both
sides — though she'd still have her PRIC back, just not BTC.

**Atomicity argument.**
* If Bob publishes `tx_claim`: Bob has PRIC. Alice extracts `t`,
  claims BTC. Both win.
* If Bob doesn't publish: Alice refunds PRIC, Bob refunds BTC. Both
  end where they started.
* Bob cannot spend PRIC without the pre-sig and `t`. He has both.
  But he can ONLY spend PRIC by also revealing `t` to Alice.

This is true atomicity, gated on `t` reveal.

## 7. Security claims

### 7.1 Pre-signature unforgeability

**Claim:** No PPT adversary without `t` can convert a legitimately-
generated pre-sig `ŝ_pi` into a valid CLSAG `s_pi`. (Standard
unforgeability of adaptor-Schnorr extends to CLSAG.)

**Reduction sketch:** any forger gives us either `t` (extracting it
from the forgery via `t = s_pi - ŝ_pi`, which we then plug back into
the DLEQ to break gap-DDH) or a forgery of standard CLSAG (which
breaks discrete log). Standard adaptor-Schnorr argument generalizes.

### 7.2 Extraction soundness

**Claim:** Given `(ŝ_pi, s_pi)` with both verifying as expected,
the extracted `t = s_pi - ŝ_pi` satisfies `t · G = T_G`.

**Argument:** by construction. Computational: the only way an
adaptor party can publish a valid `s_pi` is through Adapt, which
adds exactly `t`.

### 7.3 Pre-signature indistinguishability

**Claim:** A pre-sig leaks no information about `t` beyond what's
in `T_G, T_H` (already public).

**Argument:** `ŝ_pi = α - c_pi · x_pi` is a uniform random scalar
in `[1, n-1]` (over the choice of `α`), independent of `t`.

### 7.4 Linkability

**Claim:** Linkability of the underlying CLSAG (KI matches across
all spends of the same output) is preserved.

**Argument:** `KI` is unmodified by the adaptor variant. Same as
standard CLSAG.

## 8. Open questions for reviewer (Q1–Q9)

Numbered for citation in review responses.

**Q1.** Does the pre-signature need to commit to the adaptor points
`(T_G, T_H)` via the step-challenge hash? The current spec walks the
ring with `L'_pi, R'_pi` baked in — but the published challenge
inputs at index `pi` would be `L'_pi` and `R'_pi`, which already
embed `T_G, T_H`. Subsequent steps don't see them. Is that enough?

**Q2.** DLEQ proof format. Standard Schnorr-DLEQ over secp256k1 with
two generators (G and H_p(P_pi)) is well-studied. I assume Camenisch-
Stadler. Reviewer should confirm this is the standard choice or
suggest an alternative.

**Q3.** What happens if `H_p(P_pi)` is "weak" — e.g., its discrete
log w.r.t. G is somehow extractable? Standard ring-sig assumption is
that `H_p` is a random oracle and thus `dlog_G(H_p(P_pi))` is
unknown. Confirm this assumption is sufficient for adaptor-CLSAG.

**Q4.** µ-aggregation in adaptor multi-layer. The claim in §5.2 is
that µ doesn't interact with the adaptor. **This is the most
important question.** Specifically: can an attacker with chosen
ring/KI/D inputs influence µ_P, µ_C in a way that breaks
extractability or unforgeability of the adaptor? Section 5.2's
argument is informal; a real proof needs the adversary's view of
(µ_P, µ_C) to be analyzed.

**Q5.** Multi-party adaptor protocol — Wagner-style attacks. Can a
malicious counterparty running parallel cooperative adaptor sessions
extract a party's spend share? Round-1 commitment binding (already
in cooperative-CLSAG) should help. Confirm.

**Q6.** Identifiable abort in the adaptor variant. Currently, if
Bob doesn't broadcast `tx_claim`, Alice has no way to prove fault
on-chain (he just goes silent). For a real swap-with-reputation
system, we'd need either (a) accept this and use external slashing,
or (b) extend the protocol with a publicly-verifiable "Bob committed
to publishing by deadline X" attestation.

**Q7.** Refund path safety. The `T_pric_refund > T_btc + δ` constraint
is standard. Reviewer should verify no edge case lets Alice and Bob
both end up worse than their starting position.

**Q8.** Pre-sig leaks `pi`. The pre-sig must include the signer
index in the off-chain protocol (so the verifier knows where to
shift). On-chain, the adapted sig hides `pi` as usual. But during
the off-chain pre-sig exchange, both parties learn each other's
signer index — which they already know in our setting (they jointly
chose it). Is this acceptable?

**Q9.** Side-channel and timing. The adaptor adds one scalar
addition (`s_pi = ŝ_pi + t`) — constant-time. No new branches.
Reviewer: any timing-leak surface I missed?

## 9. References / prior art

* CLSAG: Goodell, Noether, Salazar. "Concise Linkable Ring
  Signatures and Forgery Against Adversarial Keys." 2019.
* Adaptor signatures: Aumayr et al. "Generalized Channels from
  Limited Blockchain Scripts and Adaptor Signatures." Asiacrypt 2021.
* BTC ↔ XMR atomic swaps: Joël Gugger / @h4sh3d. "Bitcoin–Monero
  Cross-chain Atomic Swap." 2020.
* MuSig2: Nick, Ruffing, Seurin. "MuSig2: Simple Two-Round Schnorr
  Multi-Signatures." Crypto 2021. (Reference for cooperative-signing
  Wagner mitigation.)
* Farcaster project — open-source BTC↔XMR implementation reference.

## 10. AI review prompts

When this spec is ready for review, run the following prompts
through Claude, GPT, and Gemini in fresh sessions. Compare answers
across models — disagreements are the most interesting part.

### Prompt A: math correctness

> You are reviewing a draft cryptographic protocol. The protocol
> below describes an adaptor-signature variant of CLSAG ring
> signatures, with cooperative (multi-party) signing and µ-aggregated
> multi-layer support. Read the spec carefully, then answer:
>
> 1. Are the math derivations in §3, §4, and §5 correct? Walk through
>    each step and verify.
> 2. In §5.2 the spec claims µ-aggregation doesn't interact with the
>    adaptor. Is the informal argument convincing? Construct a
>    counter-example or confirm.
> 3. The atomicity argument in §6.1 — is it actually atomic, or is
>    there a residual scam vector?
>
> Don't just say "looks good." Find at least three things to
> question, even if they turn out to be fine.
>
> [PASTE SPEC HERE]

### Prompt B: hostile review

> You are an adversarial cryptographic reviewer trying to find any
> reason to reject the protocol below. Look for:
>
> 1. Any place where a malicious party could cheat without being
>    caught.
> 2. Any composition issue between the adaptor extension and the
>    existing cooperative-CLSAG / multi-layer features.
> 3. Any soundness / extraction failure.
> 4. Any nonce-reuse or session-replay attack.
> 5. Side-channel risks.
>
> Be uncharitable. Treat anything ambiguous as broken until proven
> safe.
>
> [PASTE SPEC HERE]

### Prompt C: implementation pitfalls

> You will be asked to implement the protocol below in C++ using
> libsecp256k1. Before you do, list:
>
> 1. Every place where a mistake in implementation could silently
>    produce a "valid-looking but insecure" signature.
> 2. Every place where input validation is critical.
> 3. Every constant-time concern.
> 4. Test cases that would catch the most common bugs.
>
> [PASTE SPEC HERE]

## 11. Change log

* 2026-05-01 — initial draft. Composes cooperative + multi-layer +
  adaptor variants. NOT IMPLEMENTED. NOT REVIEWED.
