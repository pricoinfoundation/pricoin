# AI review prompt: adaptor-CLSAG draft spec

This is the prompt to paste into a fresh session of Claude, GPT,
Gemini, or another frontier model along with read-access to the
project repository. Run it through at least three different models;
disagreements between them are the highest-signal output.

When responses come back, capture them in
`doc/adaptor-clsag-review-responses-<model>.md` and use the
intersection of "real concerns" to revise `doc/adaptor-clsag.md`
before any implementation work begins.

---

## The prompt

> You are reviewing a draft cryptographic protocol spec on behalf of
> the project's sole maintainer, who is funding this work themselves
> and using AI review as the only feasible substitute for a paid
> human cryptographer. Your review will directly determine whether
> code with money-handling consequences gets written. **Be honest
> about uncertainty. If something looks plausible but you can't
> verify it, say so. Do not affirm to please.**
>
> ### Context
>
> The project is **Pricoin (PRIC)**, a privacy-coin fork of Bitcoin
> Core that has implemented confidential transactions (Pedersen
> commitments + Borromean rangeproofs), CLSAG ring signatures
> (single-layer + µ-aggregated multi-layer), CryptoNote-style
> stealth addresses, joint stealth addresses for cooperative
> receive, and cooperative CLSAG signing for cooperative spend. All
> of that is in the repo.
>
> The piece you are reviewing — `doc/adaptor-clsag.md` — is the
> design for adding adaptor-signature semantics to the cooperative
> CLSAG primitive, in order to enable trustless cross-chain atomic
> swaps between PRIC and Bitcoin-derived chains (BTC, LTC, etc.).
> **Adaptor-CLSAG is NOT YET IMPLEMENTED.** The spec is the artifact;
> the implementation will follow only after this review passes.
>
> ### Files you should read, in order
>
> 1. `doc/adaptor-clsag.md` — the spec under review. Primary focus.
> 2. `doc/atomic-swap-protocol.md` — context: cooperative CLSAG
>    (the base primitive being extended).
> 3. `src/pricoin/ringsig.h`, `src/pricoin/ringsig.cpp` — the
>    underlying single-layer + multi-layer CLSAG implementation.
>    The adaptor extension assumes these are correct; if you spot
>    a bug here, that's also relevant.
> 4. `src/pricoin/joint_ringsig.h`, `src/pricoin/joint_ringsig.cpp`
>    — the cooperative-signing extension. Same caveat: bugs here
>    propagate.
> 5. (Optional) `src/wallet/pricoin_swap_session.cpp` and
>    `src/wallet/pricoin_swap_ceremony.cpp` for orchestration
>    context, but these are state-machine plumbing without crypto
>    novelty.
>
> ### Your job
>
> Adversarial review. Assume malicious intent on the part of every
> protocol participant unless the spec explicitly rules it out, and
> assume implementation bugs in the underlying CLSAG / cooperative
> code unless your reading proves otherwise. Look specifically for:
>
> 1. **Math errors in the adaptor construction** (§3, §4, §5 of the
>    spec). The shifted-anchor approach `L'_pi = L_pi + T_G`,
>    `R'_pi = R_pi + T_H` requires the DLEQ proof to bind. Walk
>    through the algebra step-by-step and confirm the verification
>    equation closes correctly after Adapt. Identify *every step*
>    where a sign error, a typo, or an order-of-operations issue
>    would produce a "valid-looking but insecure" signature.
>
> 2. **µ-aggregation × adaptor interaction (§5.2 — flagged as Q4).**
>    The spec claims µ_P, µ_C are deterministic functions of public
>    data (ring, KI, D) and therefore "orthogonal" to the adaptor.
>    The argument is informal. Construct either a counter-example
>    (a chosen ring/KI/D pair that lets the adversary influence µ
>    in a way that breaks extractability or unforgeability) or a
>    convincing reason no such counter-example can exist. **This
>    is the highest-priority question.**
>
> 3. **The atomicity argument in §6.1.** The spec corrects mid-
>    document when the original protocol direction was found to
>    leave a residual scam vector. Verify that the corrected
>    protocol is in fact atomic — i.e., for every reachable state
>    of (Alice, Bob, BTC chain, PRIC chain), neither party can be
>    strictly worse off than their starting position without their
>    counterparty also losing equivalently. Be especially careful
>    about timelock interactions (§6.1's `T_pric_refund > T_btc + δ`
>    constraint) and edge cases involving network partitions /
>    chain reorgs.
>
> 4. **Cooperative-with-adaptor protocol vulnerabilities.** A
>    malicious counterparty running k parallel cooperative-adaptor
>    sessions: can they extract a victim's spend share, or forge
>    a pre-signature, via a Wagner-style k-sum or related attack?
>    The spec relies on the round-1 commit-reveal binding from the
>    existing cooperative-CLSAG module (`pricoin/joint_ringsig.cpp`).
>    Verify the binding is sufficient.
>
> 5. **DLEQ proof correctness.** The spec says "Camenisch-Stadler"
>    in Q2 but doesn't write out the actual DLEQ scheme. Specify
>    the exact DLEQ construction we should use (over secp256k1
>    with generators G and H_p(P_pi)), including the hash binding
>    to the protocol session, and confirm it has the standard
>    soundness/zero-knowledge properties.
>
> 6. **Pre-signature leaking pi to off-chain verifier (Q8).** The
>    spec acknowledges this and argues it's acceptable in the
>    cooperative-signing setting where both parties already know
>    pi. Verify there's no leak path to a *third* observer.
>
> 7. **Composition issues with the existing code.** Read
>    `joint_ringsig.cpp`'s WalkRing / WalkRingMultiLayer and
>    confirm that swapping `L_pi → L'_pi`, `R_pi → R'_pi` doesn't
>    break any internal invariant beyond what the spec describes.
>
> 8. **Constant-time / side-channel surface.** The Adapt operation
>    is a single scalar addition; the pre-sig generation differs
>    from non-adaptor only in the L'/R' shift before the walk.
>    Are there any new timing- or power-analysis surfaces?
>
> 9. **Anything I missed.** What attacks would a serious adversary
>    try that the spec doesn't acknowledge?
>
> ### What "good output" looks like
>
> A structured response with:
>
> **Section 1 — Math walkthrough.** For §3.1 / §3.2 / §3.3 / §4.1 /
> §5.1, restate the equations in your own notation and confirm each
> derivation. Flag any algebra that doesn't follow.
>
> **Section 2 — Q1 through Q9, point-by-point.** For each numbered
> question in §8 of the spec, your verdict: `OK` (with brief
> argument), `CONCERN` (with the specific concern), or `BROKEN`
> (with the construction that demonstrates the break).
>
> **Section 3 — Additional findings.** Anything not covered by the
> spec's own questions. Especially attacks that combine the
> adaptor construction with the existing cooperative-CLSAG
> implementation in non-obvious ways.
>
> **Section 4 — Implementation hazards.** A list of every place
> where a sloppy C++ implementation could silently produce a
> "valid-looking but insecure" signature. Order by severity.
>
> **Section 5 — Confidence rating.** How confident are you, on a
> scale of 1–5, that:
>   * (a) The math is correct.
>   * (b) The composition with µ-aggregation is safe.
>   * (c) The atomic-swap protocol in §6.1 is actually atomic.
>   * (d) A competent C++ implementation following this spec
>     verbatim would be secure to deploy with $1k of value at
>     stake. ($1k, not $1M — calibrate accordingly.)
>
> Justify each rating in one to two sentences.
>
> **Section 6 — What you would do differently.** If the protocol
> design is fundamentally sound but the spec has gaps, propose
> concrete revisions. If the protocol is fundamentally broken,
> describe the alternative construction you'd use instead.
>
> ### Caveats — please read
>
> * You are an AI, not a cryptographer. Your review is the best the
>   maintainer can afford right now, but it is not a substitute for
>   a human auditor with publication record in adaptor signatures
>   or ring signatures. Acknowledge this in your response and
>   recommend specific human reviewers (with names, if you can) the
>   maintainer should engage if the project starts handling
>   non-trivial value.
>
> * Do not invent citations. If you cite a paper, it must be a real
>   paper you can identify by author + venue + year. False
>   citations are worse than no citations.
>
> * If you are uncertain whether something is broken, say so
>   explicitly with the words "I am uncertain whether…" rather
>   than guessing in either direction.
>
> * The spec describes math + protocol but not the full C++
>   implementation. Don't try to review code that doesn't exist
>   yet. Stick to the spec, the existing related code, and the
>   composition between them.

---

## Workflow notes for the maintainer

1. Run the prompt through Claude (Opus or Sonnet), GPT (4 / 4o /
   o-series), and Gemini (1.5 / 2.0). Three is the minimum;
   five if you can.
2. Save each response verbatim under
   `doc/adaptor-clsag-review-responses-<model>-<date>.md`.
3. Build a "consensus map":
   * **Real concerns** = flagged as CONCERN or BROKEN by ≥ 2 models.
   * **Single-model concerns** = flagged by exactly one. Read
     critically; some are false positives, some are real things
     two other models missed.
   * **Affirmed-by-all** sections = treat as moderately confident
     but still suspect — confirmation bias is a thing across
     models trained on similar data.
4. Revise `doc/adaptor-clsag.md` to address all "real concerns"
   and the most credible "single-model concerns."
5. Re-run the prompt one more time on the revised spec to confirm
   the revisions actually addressed the issues.
6. Only then start implementation work.

The cost of running the prompt three times is ~$5–15 in API fees
plus an hour of your time. The cost of building a broken protocol
is unbounded. The asymmetry favors thorough review.
