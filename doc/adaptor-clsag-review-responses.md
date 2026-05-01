# Adaptor-CLSAG draft spec — AI review responses

This file archives review responses obtained by running the prompt
in `doc/adaptor-clsag-review-prompt.md` against frontier AI models.
Each section below is a verbatim response. The maintainer
consolidates "real concerns" (flagged by ≥ 2 models) into spec
revisions in `doc/adaptor-clsag.md`.

> **Caveat for future readers.** None of these responses are from a
> human cryptographer. They are AI evaluations of the spec, used as
> a stand-in for a paid audit because this project has no funding.
> Treat them as a forcing function for catching obvious mistakes,
> not as a security guarantee.

---

## Round 1, response 1 — 2026-05-01

> **Summary verdict:** Do not implement this spec as written.
>
> The adaptor-CLSAG algebra looks mostly coherent, but the atomic-
> swap protocol in §6.1 is broken because the timelock direction
> gives Bob a theft window: Bob can refund BTC and still claim PRIC
> afterward. There are also important spec gaps around DLEQ
> transcript binding, adaptor-point binding, cooperative share
> validation, and concurrent-session hardening.

### Section 1 — Math walkthrough

**§3.1 / §3.3 single-layer adaptor CLSAG.** Algebra closes:
`L_verify = sG + c_π P_π = (α - c_π x + t)G + c_π xG = (α + t)G = L'`.
`R_verify = sH + c_π I = (α + t)H = R'`. Sign-sensitive hazards:
implementation must test `extracted_t · G == T_G` and (multi-layer)
also `extracted_t · H_p(P_π) == T_H`.

**§3.2 pre-signature verification.** Off-chain pre-signature object
must include π, (T_G, T_H), π_t, ring, KI, D if multi-layer, msg,
destination tx digest, session identifier. On-chain signature must
not include π or adaptor data.

**§4.1 cooperative single-layer.** Additive-share derivation is
correct provided malformed shares are rejected. Existing
`joint_ringsig.cpp` matches the shape: nonce commitment includes
`session_id, L_share, R_share, KI_share`; WalkRing seeds c[(pi+1)%N]
from provided `L_pi, R_pi`; CloseShare computes α - c·x. Single-
layer NonceCommit shape in the code is **not sufficient as a
transcript commitment for multi-layer adaptor signing** unless
extended to bind `D_share`.

**§5.1 multi-layer adaptor CLSAG.** Algebra closes provided
`T_H = t · H_p(P_π)`, NOT `t · I_agg`. The same H_p(P_π) basis is
used for both R_π and extraction checking. This matches the
existing multi-layer code where R_i uses H_p(P_i) and the image
term is I_agg.

**§5.2 µ-aggregation interaction.** No direct counter-example where
manipulating ring/KI/D changes µ in a way that breaks the adaptor
equation. The dangerous part is not "does t enter µ?" — it does
not. The dangerous part is who is allowed to choose KI, D, ring
members, and commitment shares before µ is fixed. Spec is
underspecified on cooperative-share validation; verdict
"probably algebraically safe, but the cooperative-share validation
around µ is underspecified."

### Section 2 — Q1 through Q9 verdicts

**Q1 — pre-sig commit to (T_G, T_H):** CONCERN. Shifted anchors
commit indirectly through L', R'. That suffices for adapted on-
chain verification, NOT for a robust off-chain transcript. Pre-sig
verification transcript must hash-bind: session_id, protocol label
+ version, chain ids, ring, π, msg/tx digest, KI, D if multi-layer,
T_G, T_H, DLEQ challenge transcript, refund + claim tx ids.

**Q2 — DLEQ format:** CONCERN until specified. Use non-interactive
Chaum–Pedersen / Schnorr DLEQ over secp256k1. Concrete construction
provided in the response (verbatim transferred to spec §3.0a).

**Q3 — weak H_p(P_π):** OK with standard assumptions. Try-and-
increment is not ideal by modern standards.

**Q4 — µ-aggregation × adaptor:** CONCERN, not BROKEN. No concrete
counter-example. But the spec must require rejection of degenerate
cases: KI=∞, T_π malformed, a=0, etc. Cooperative-share validation
is the underspecified gap.

**Q5 — multi-party concurrent attacks:** CONCERN. 3-round commit-
reveal pattern is closer to MuSig1's safer design than 2-round
concurrent settings (MuSig2 explicitly addresses concurrency).
Likely OK as a 3-round design but not audited enough for large
value. `s_others` generation by a "designated party" is
underspecified — must be deterministic or commit-bound.

**Q6 — identifiable abort:** OK as a known limitation.

**Q7 — refund path safety:** **BROKEN.** Stated constraint is
backwards. Spec says `T_pric_refund > T_btc + δ`; should be
`T_btc_refund > T_pric_refund + δ`. As written, Bob can refund BTC
and then claim PRIC.

**Q8 — pre-sig leaks π:** OK for cooperative setting; transcripts
must remain private.

**Q9 — side-channel and timing:** CONCERN. Adapt is constant-time
but DLEQ generation, hash-to-point on P_π, off-chain verification
that branches on π, and failure paths add new surfaces.

### Section 3 — Additional findings

**Finding A.** §6.1 atomicity is broken (same as Q7).

**Finding B.** **The BTC HTLC hash is not bound to the adaptor
point.** Bob publishes `T_G = tG` but can use `SHA256(t')` in the
BTC HTLC for any `t' ≠ t`. Alice cannot verify
`SHA256(t) == H_btc` from knowledge of T_G alone. Solutions:
adaptor-Schnorr (post-taproot BTC/LTC), adaptor-ECDSA (pre-taproot),
or a ZK proof bridging SHA256 and EC (impractical). **As written,
Alice cannot verify H = SHA256(t) from (T_G, T_H).** Likely BROKEN
depending on BTC script design.

**Finding C.** Pre-signed PRIC refund and claim tx ordering must be
exact, with explicit confirmation depths and absolute heights/
times.

**Finding D.** Share consistency proofs missing. Cooperative
protocol assumes participants publish shares matching their
public shares; protocol does not require DLEQ proofs tying x_X·G
to x_X·H_p(P_π), z_X·G to z_X·H_p(P_π), α_X·G to α_X·H_p(P_π).
Without these, malformed image shares can alter KI, D, and µ. Not
obviously a key extraction, but underspecified.

**Finding E.** s_others generation is a malleability/bias point.
A designated party generating non-signer s_i can grind to influence
c_π. Make it deterministic from session transcript plus joint
randomness, or commit-reveal it.

**Finding F.** Transcript replay/cross-session/cross-chain replay
is not addressed enough. Need domain separation for: network, asset
pair, role, txids and vouts, ring hash, claim destination, refund
destination, timelocks, adaptor points.

### Section 4 — Implementation hazards (severity ordered)

1. **Wrong timelock inequality.** Must be fixed.
2. **Unverifiable SHA256(t) ↔ T_G binding.** Protocol-level fix
   needed.
3. **Using `T_H = t·I_agg` instead of `t · H_p(P_π)`.** The shift
   must be on the same generator as R_π's nonce.
4. Sign error in close/adapt/extract: `ŝ = α - c·a`, `s = ŝ + t`,
   `t = s - ŝ`. Tests must catch sign flips.
5. Not verifying DLEQ before participating.
6. DLEQ transcript not domain-bound.
7. Failing to validate scalar ranges (zero, overflow).
8. Failing to validate points (infinity from combines).
9. Omitting D_share from multi-layer commitments.
10. Malformed share consistency (consider DLEQ proofs).
11. Incorrect µ recomputation (byte-order, tag, ring serialization,
    KI/D mismatch).
12. Publishing π accidentally on-chain.
13. Logging pre-signatures.
14. Nonce reuse: `x_X = (s_X - s'_X) / (c'_π - c_π)`.
15. Grinding s_others.
16. Inadequate tests (single-layer adapt/extract, multi-layer,
    wrong T_H, wrong DLEQ, wrong sign, wrong π, swapped KI/D,
    malformed share, zero scalar, infinity combine, concurrent
    sessions, timelock simulations).

### Section 5 — Confidence ratings

* (a) Math correctness: **4/5.** Shifted-anchor adaptor equation
  is correct. Reduced from 5 because of underdefined verification,
  DLEQ, transcript binding, malformed-share handling.
* (b) Composition with µ-aggregation: **3/5.** No algebraic break,
  but malicious image shares are underspecified.
* (c) §6.1 atomicity: **1/5.** Broken as written.
* (d) Safe to deploy with $1k if implemented verbatim: **1/5.** No.

### Section 6 — Recommendations

Split into two layers: adaptor-CLSAG primitive (plausibly sound
with revisions); atomic-swap protocol (not sound as written).

Concrete revisions:

1. Fix timelocks: `T_btc_refund > T_pric_refund + δ`.
2. Add expiry: Alice's PRIC refund must spend the same output
   before Bob can safely refund BTC. Once Alice refunds, Bob's
   PRIC claim becomes invalid by double-spend conflict.
3. Solve the SHA256(t) binding problem. Adopt a known BTC↔privacy-
   chain construction, or use adaptor-Schnorr/ECDSA on the BTC
   side.
4. Specify DLEQ exactly (Chaum-Pedersen with explicit transcript
   inputs).
5. Bind the entire swap transcript: session id, chain ids, tx
   hashes, vouts, ring hash, destinations, timelocks, KI, D, T_G,
   T_H, role labels.
6. Strengthen cooperative commitments: multi-layer must commit
   `L_share, R_share, KI_share, D_share, participant id, session
   id, adaptor points, ring hash, tx digest`.
7. Consider share-consistency DLEQs.
8. Use deterministic / session-bound nonces.
9. Have a human cryptographer review before funds. Suggested
   names: Sarang Noether or Brandon Goodell (CLSAG); Tim Ruffing
   or Jonas Nick (Schnorr multisig / concurrency); Lukas Aumayr,
   Sebastian Faust, Pedro Moreno-Sanchez (adaptor signatures);
   Joël Gugger / contributors around h4sh3d / Farcaster / COMIT
   (BTC-XMR atomic swaps). Also consider firms with prior Monero
   CLSAG audit experience (OSTIF reports JP Aumasson and Antony
   Vennard).

> Final verdict: the adaptor-CLSAG primitive is worth continuing,
> but the current atomic-swap spec should fail review until the
> timelock and BTC-hash/adaptor-secret binding issues are fixed.
