# Pricoin atomic-swap protocol (research draft)

Status: **research / pre-deployment**. This document is the
artifact-of-record for future cryptographic review. Code paths
described here are gated behind RPCs that exist for protocol
prototyping; nothing here is consensus-critical yet.

## Motivation

We want trust-minimised cross-chain swaps between PRIC (Pricoin) and
external assets without giving up the privacy properties of v4
confidential transactions: no scriptable HTLCs leaked on chain, no
single-party recoverable spend secrets.

The construction is cooperative, two-party, two-round on each chain:

  1. **Lock**  — Alice locks PRIC into a 2-of-2 *joint stealth output*.
                 The output is on-chain indistinguishable from a normal
                 v4 send.
  2. **Unlock** — Alice and Bob jointly produce a CLSAG ring signature
                 spending the joint output. Neither party alone can sign.

For the swap to be atomic, Bob's unlock commitment to his side of the
external chain must atomically reveal a secret that lets Alice run the
PRIC unlock — or vice versa. The protocols for cross-chain atomicity
(adaptor signatures, secret-extracting variants) are **out of scope
for stage 2b** and are described under "Stage 3" below.

## Notation

| Symbol     | Meaning                                                   |
|------------|-----------------------------------------------------------|
| `G`        | secp256k1 generator                                       |
| `n`        | secp256k1 group order                                     |
| `H_p(·)`   | tagged hash-to-point (try-and-increment, 19-byte tag)     |
| `H_s(·)`   | tagged hash-to-scalar (`pricoin/ringsig/H_s-v1`)          |
| `(a_X, b_X)` | party X's view and spend privkeys                       |
| `(A_X, B_X)` | party X's view and spend pubkeys, X·G                    |
| `r`, `R`   | sender's ephemeral privkey / pubkey for an output         |

Subscripts `A`, `B` denote Alice and Bob; subscript `J` denotes the
joint key.

## Stage 2a — joint stealth address (committed in v0.1.12)

### Address construction

Alice and Bob each publish an ordinary stealth address. They construct
the joint address by point addition:

```
A_J = A_A + A_B    =  (a_A + a_B) · G
B_J = B_A + B_B    =  (b_A + b_B) · G
```

Neither party knows the joint privkey individually.

### Sender-side output

The sender treats the joint address as a normal stealth address. Per-
output ECDH:

```
shared = r · A_J
       = r · A_A + r · A_B    (additive splitting)
P_one_time = H_s("...derive...", shared) · G + B_J
```

The on-chain output is byte-identical to a single-party stealth output:
`(R, P_one_time, commitment, range_proof)`. An observer cannot tell it
was sent to a joint address.

### Receive (cooperative scan)

```
Alice computes  partial_A = a_A · R
Bob   computes  partial_B = a_B · R
Either combines  shared = partial_A + partial_B
```

Sharing a partial does NOT reveal `a_X`: extracting `a_X` from `R` and
`a_X · R` is the discrete-log problem.

Once `shared` is known, both parties run the standard rewind path
(`DeriveSharedSecret`, `DeriveOneTimePubkey`, `RewindRangeProof`) to
recover the value and blinding.

**Implementation:** `src/pricoin/joint_stealth.{h,cpp}`,
`src/wallet/rpc/pricoin_ct.cpp` (`pricoin_buildjointstealthaddress`,
`pricoin_jointscan_partial`, `pricoin_jointscan_recover`).

## Stage 2b — cooperative CLSAG signing (this commit)

### Goal

Produce a single-layer CLSAG signature where the spend pubkey
`ring[pi]` is the sum of the parties' shares:

```
ring[pi] = (x_A + x_B) · G          (joint pub)
        =  x_total · G              (implicit joint priv)
```

For the atomic-swap path, the wallet absorbs the per-output stealth
shared secret into one party's share so `joint_ringsig` only sees an
abstract additive split:

```
x_A_eff  = b_A + shared_secret
x_B_eff  = b_B
x_total = x_A_eff + x_B_eff = (b_A + b_B + shared_secret)
```

### Math

Standard single-layer CLSAG with N parties additively sharing the
spend key:

```
α      = sum(α_X)               nonce, sum of fresh per-party random
L_pi   = α · G        = sum(α_X · G)
R_pi   = α · H_p(P_pi)= sum(α_X · H_p(P_pi))
KI     = x_total · H_p(P_pi)
       = sum(x_X · H_p(P_pi))
```

For `i ≠ pi`, the walk is identical to single-party CLSAG (all
non-secret math).

Closing scalar `s_pi` is split additively:

```
s_pi   = α − c_pi · x_total
       = sum(α_X − c_pi · x_X)
       = sum(s_share_X)
```

### Protocol (3 rounds)

**Round 1 — commit.**  Each party generates `α_X`, computes
`(L_share_X, R_share_X, KI_share_X)`, and broadcasts a hiding
commitment `commit_X = H("commit-v1", session_id, L, R, KI)`.

**Round 2 — open.**  Each party reveals `(L_share_X, R_share_X,
KI_share_X)`. Counterparties recompute `commit_X` and verify it
matches the round-1 broadcast. Commit-reveal binding prevents a
malicious party from picking their nonce after seeing the others.

The combiner (any honest party) sums shares to obtain `(KI, L_pi,
R_pi)`. A designated party generates the non-signer ring closing
scalars `s_others` and broadcasts. All parties run the deterministic
ring walk on identical inputs to obtain `c_pi` and `c_0`.

**Round 3 — close.**  Each party computes `s_share_X = α_X − c_pi ·
x_X` and broadcasts. The combiner sums to `s_pi` and assembles a
standard `pricoin::ringsig::Signature`.

### Implementation

* `src/pricoin/joint_ringsig.{h,cpp}` — math primitives:
  `NonceGen`, `KeyImageShare`, `NonceCommit`, `CombinePoints`,
  `CombineScalars`, `WalkRing`, `CloseShare`.
* In-process two-party self-test in `RunSelfTest`, called from
  `pricoin::ct::RunSelfTest` at daemon startup. The test feeds the
  cooperative output through `pricoin::ringsig::Verify` to confirm
  the produced signature is byte-compatible with a single-party
  CLSAG.

### Multi-layer (RingCT) cooperative variant

v4 transactions use multi-layer CLSAG (μ-aggregated two-row), not
single-layer. The cooperative multi-layer flow extends the single-
layer protocol:

* Each party additively splits both x (spend secret) and z
  (commitment-offset secret). For atomic-swap context, z is already
  shared in the clear between parties (both know `b - b_pseudo`); the
  splitting is a protocol-implementation detail.
* Each party computes `KICommitImageShare(P_pi, x_X, z_X)` to obtain
  `(KI_share, D_share) = (x_X · H_p(P_pi), z_X · H_p(P_pi))`.
  Combiners sum to `(KI, D)`.
* `μ_P, μ_C = ComputeMu(ring, KI, D)` — public; identical for all
  parties.
* Aggregated priv share: `a_X = μ_P · x_X + μ_C · z_X`. Sum gives
  `a = μ_P · x_pi + μ_C · z_pi` as in the single-party SignMultiLayer.
* Walk anchored to `I_agg = μ_P · KI + μ_C · D` and the µ-aggregated
  ring points `T_i = μ_P · P_i + μ_C · W_i`.
* Close: `s_share_X = α_X − c_pi · a_X`. Sum to `s_pi`.

The result is byte-identical in shape to a single-party
`pricoin::ringsig::SignMultiLayer` and verifiable with
`VerifyMultiLayer`. Implementation in
`pricoin::joint_ringsig::WalkRingMultiLayer` and the multi-layer
self-test path in `RunSelfTest`.

### NOT implemented in stage 2b

* **Wallet RPC plumbing for the round protocol.** The current code is
  exercised only by the in-process self-test. A future commit will add
  RPCs for round 1 / round 2 / round 3 message flow between wallets,
  for both single-layer and multi-layer flows.
* **Identifiable abort.** If a party stalls or sends garbage in
  rounds 1–3, the protocol fails but does not produce on-chain
  evidence of who. For atomic swaps this matters (DoS blame).

## Stage 3 — adaptor signatures (deferred)

Atomicity across chains needs the unlock signature to leak a secret
on publication. The standard construction is *adaptor signatures*: a
"pre-signature" `ŝ_pi = s_pi − t` is published, and the actual
on-chain `s_pi = ŝ_pi + t` reveals `t` to anyone who already knew
`ŝ_pi`. With CLSAG that needs to be done carefully — adaptor variants
of CLSAG are **less well-studied** than adaptor Schnorr, and I do NOT
recommend deploying without third-party cryptographic review.

This stage is gated behind external review; see "Open questions" below.

## Open questions for cryptographic review

The following are the questions a reviewer should answer before this
protocol is used to secure non-trivial value. Numbered for citation.

### Q1. Wagner k-sum / generalised birthday attacks on cooperative nonces

The classical attack: a malicious party opens many parallel signing
sessions, defers committing their nonce in each, and (via Wagner's
algorithm) eventually picks combinations that cancel into a
forgery. MuSig (round-1) was vulnerable; MuSig2 fixed it with a
per-party two-nonce scheme.

Our defense: round-1 commit-reveal of `(L_share, R_share, KI_share)`
binds each party's nonce before any reveal. **Reviewer should confirm
this is sufficient for our 2-of-2 case** (i.e., that an adversary
running k parallel sessions cannot extract the spend share or forge a
signature) and recommend whether a MuSig2-style two-nonce upgrade is
warranted.

### Q2. Rogue-key resistance for `ring[pi] = sum(x_X · G)`

A naïve construction `A_J = A_A + A_B` is vulnerable to the rogue-key
attack: a malicious Bob picks `B_B = B_B' − B_A`, so that `B_J = B_B'`,
and Bob alone effectively controls `B_J`.

Our defense: `B_J` is derived from each party's published stealth
*address*. Each party's `B_X` is committed-to before the swap is set
up (it's their long-term spend pubkey, at least within the swap
session). A rogue-key attempt requires the attacker to choose `B_X`
*after* seeing the other party's `B_X` — which our protocol disallows
by exchanging stealth addresses up front.

**Reviewer should confirm:** (a) is the "exchange addresses up front"
sufficient (no race window?); (b) do we need a coefficient-prefix
construction (MuSig-style `B_J = h_A · B_A + h_B · B_B`) as belt-and-
braces?

### Q3. Nonce reuse across signing sessions

If any party reuses `α_X` across two distinct signing sessions, their
spend share `x_X` is extractable: solve the linear system
`s_X = α_X − c_pi · x_X` and `s_X' = α_X − c_pi' · x_X` for `x_X`.

Our defense: the calling code MUST use fresh randomness per session
(documented in `joint_ringsig.h`). We do not currently bind α_X to
session_id internally — `α_X` is just a fresh CSPRNG sample.

**Reviewer should advise:** whether deterministic nonces (RFC-6979
style, keyed by `(x_X, session_id, msg)`) are appropriate, or whether
a stronger session-bound construction is needed for the multi-party
case.

### Q4. Identifiable-abort and DoS resistance

Currently a malicious counterparty can stall the protocol at any
round and produce no on-chain evidence. For atomic swaps this matters:
a counterparty can grief us off-chain. Reviewer to advise on the
trade-off between protocol weight and identifiable abort.

### Q5. Adaptor CLSAG (stage 3 only)

Adaptor signatures for CLSAG are not as established as Schnorr
adaptors. Specifically:

* What is the exact construction for embedding an adaptor scalar `t`
  into the cooperative `s_pi` such that:
  - `s_pi = ŝ_pi + t` (extraction soundness),
  - `ŝ_pi` alone is unforgeable (presig unforgeability),
  - the on-chain CLSAG remains indistinguishable from non-adaptor?
* What is the security reduction (DDH? gap-DDH? generic group?)?
* How does cooperative adaptor CLSAG interact with the published
  `KI`? (The KI ties to the spend key, not the nonce, so it should be
  unaffected — but reviewer should confirm.)

This question is the gate for stage 3. The PRIC project will not
ship adaptor-CLSAG without external review answering Q5.

### Q6. Multi-layer extension (now implemented)

Stage 2b covers both single-layer and multi-layer. The multi-layer
cooperative variant additively splits `z_pi` alongside `x_pi` and
follows the µ-aggregation logic from `pricoin/ringsig.cpp`. Reviewer:
confirm the same security arguments (Q1–Q3) carry over to the
multi-layer case, and flag any new attack surface introduced by the
µ-binding to `(KI, D)` — particularly whether the µ-coefficient
binding adds or removes degrees of freedom for an active adversary.

### Q7. Independence of joint-stealth view scan from spend protocol

Stage 2a (already deployed) shares `partial_A = a_A · R` between
parties. If the spend-side protocol (stage 2b) uses `α_X · H_p(P_pi)`
in `R_share`, is there any composition path where a `(view-side
partial, spend-side R_share)` pair leaks more than each in isolation?

We believe no — the operations are over independent generators
(`R` from the sender, `H_p(P_pi)` from a hash-to-point) — but the
reviewer should confirm.

## Suggested review scope (tiered)

The PRIC project intends to commission review at the following tiers,
in order:

1. **Self-paced internal review** (current commit). Math walk-through,
   self-test, this document. Cost: time.
2. **Single-consultant review** (~$10k–$50k). One cryptographer
   reviews this document + the joint_stealth/joint_ringsig sources +
   the cooperative multi-layer extension. Output: "yes / no / needs-
   X" for each of Q1–Q7. Suitable before stage 2b is exposed via
   wallet RPC.
3. **Audit-firm review** (~$50k–$200k). Two-or-more reviewers, formal
   sketch of security argument, attack-class catalogue. Required
   before stage 3 (adaptor CLSAG) is shipped.
4. **Formal verification** (~$200k+). Out of scope for the foreseeable
   future; recommended only if the protocol carries non-trivial value
   for an extended period.

## Change log

* 2026-04-30 — initial draft, covering stages 2a and 2b.
