# Concepts

## Pair and orientation

A **pair** is two builds of the same binary: an **older** and a **newer** one. You choose which is which; PatchTrace never infers order from file names or dates. Swapping orientation is an explicit action, and it marks earlier interpretations stale. Accepted inputs are PE AMD64 files (`.exe`, `.dll`, `.sys`) validated by header, not extension. Other formats are outside the supported contract.

## Match

A **match** relates a function in the older build to function(s) in the newer one. Relationships are `modified`, `added`, `removed`, `ambiguous`, `split`, `merged`, `unmatched` and `unchanged`. They describe how functions correspond, not how severe a change is. Ghidriff (running Ghidra) proposes matches; you can correct one with a required reason. The original engine output is kept, and the correction is a recorded override that you can undo.

Other engines (BinDiff import, rz-diff, and the experimental `unified` fusion) produce separate match sets. PatchTrace never overwrites the Ghidriff result with them and never averages their scores.

## Evidence

Evidence is a recorded observation with provenance: which engine or tool, which run, which artifact hash, which function. Examples are an engine pairing, a changed code hunk, a detector signal, a CSAF advisory fact. Rules PatchTrace follows:

- Each piece of evidence names where it came from.
- Conflicting evidence is kept and shown, not resolved by vote.
- Evidence that shares an origin (for example two engines reading the same Ghidra database) counts once.
- A missing observation is "unknown", never a vote against.
- Advisory text, strings and decompiled code are untrusted data. They are shown escaped and never executed.

Secondary-engine reconciliation gives each Ghidriff match a verdict: `corroborated`, `contested` (an engine pairs the same function differently), `single-engine`, or `insufficient`. The index shown next to it is an uncalibrated 0 to 83 triage number. The GUI offers it as an opt-in detail ("Show uncalibrated triage index"); it is not a probability.

## Attention

**Attention** is a deterministic integer score from 0 to 100 (formula `attention/1`) that orders changed functions so you read the likely security-relevant ones first. Eight detectors look at the changed hunks of decompiled text: BND (new bounds check), INT (comparison or cast change), OVF (overflow guard), VAL (new validation), ERR (new early error return), SIZE (changed size argument), WIL (feature-flag gate) and SCRUB (zeroing before copy-out). Signals on the same hunk are grouped so one edit is not counted twice. The arithmetic is exact integer math, and you can change the weights or disable detectors in the CLI.

A row showing `[ — ]` means a detector lacked the evidence it needs, such as decompiled code on one side. That is unknown, not zero.

Attention is research prioritization. It is not exploitability, not a CVE match and not vulnerability confidence. Match certainty, evidence coverage and counterevidence are separate fields. AI output never enters the score.

## Calibration

Calibration means checking that a number behaves like the probability it claims to be, measured on labelled data the model never saw. The design (SPEC-27, `docs/specs/calibration-corpus-and-model.md`) targets one question only: is this a correct function pairing. It does not target "is this a vulnerability".

Current state: the calibration runtime and tooling exist, but no calibrated model has passed its pre-registered gates, so **PatchTrace shows no confidence percentage anywhere**. Engine scores (Ghidriff ratios, BinDiff similarity, rz-diff byte similarity) are algorithm-specific and are shown as native, labelled values only.

## Tiers

The word "tier" appears in three unrelated places:

| Use | Meaning |
|---|---|
| Evidence tiers in the unified result | Ordinal strength of a pairing: M (your manual correction), A (exact or masked-exact), B (needs a second, independent corroborating atom), C (never auto-accepted). Rows without corroboration show as `tentative`. Ordinal means ordered labels, not numbers. |
| Reconciliation tier | `high`, `moderate`, `low`, `unassessed` operational ordering of the secondary-engine verdict. |
| Calibration corpus tiers | Tier R: redistributable open-source test corpus. Tier W: Windows binaries kept local only, never committed. These are developer data sets and do not affect what you see in the app. |

## What a result does and does not mean

| A result says | It does not say |
|---|---|
| These two functions were paired by this engine, with this provenance | The pairing is correct, unless several independent channels agree and you checked |
| The code changed in this hunk | The change is a security fix |
| Attention score 80 | The function is vulnerable or exploitable |
| An advisory (CSAF) lists this CVE and product | A given function contains or fixes that CVE |
| No signal was found | There is no vulnerability; absence of evidence is unknown |
| An AI finding cites valid evidence | The finding is factually correct (this establishes traceability only) |
| `unchanged` or `cosmetic` in the unified result | Safe to ignore without reading the stated proof |

Treat every output as a lead for your own analysis. Verification is your job.
