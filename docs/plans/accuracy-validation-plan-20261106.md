# Accuracy validation plan (2026-11-06)

Purpose: decide, with stated confidence bounds, how accurate PatchTrace's KB/CVE correlation and pair diffing are,
using the cheapest ground truth first and a small set of real Windows patches last. Nothing here is a result.
One live MSRC/Winbindex smoke probe has passed (one month, one CVE; docs/qa/kbc-live-probe-20261107.md). No join-accuracy,
Ghidra, BinDiff or Rizin run has happened yet; every accuracy number below is a target.

## Claims, one per layer (never one blended percentage)

| Layer | Question | Ground truth | Independent cases | Claim it can support |
|---|---|---|---|---|
| L1 advisory join | KB or CVE -> product -> file -> pair correct? | MSRC CVRF/CSAF + Winbindex records | 60+ (automated, hundreds possible) | >= 95% (60 cases, 0 errors) |
| L2 pair diff, open source | engine finds the function the fix changed | fix commit; own builds before/after | 46 projects-worth, <= 1 miss | >= 90% |
| L3 Windows reality | same, on Microsoft-shipped stripped PE | published patch analyses | 15 first, grow to 29 | >= 82% at 15/0 errors, >= 90% at 29/0 |

Bounds are one-sided exact (Clopper-Pearson, alpha 0.05): `python -m tools.research_qualification samplesize`.
Cases from one project or release are not independent; count distinct projects. Report per stratum
(compiler family, release-vs-own-build), never pooled.

## Case sources (cheapest first)

1. **S0 self-compiled fixtures** (built: `fixture_pairs.py`). Engine-bug detector only; says nothing about Windows.
2. **S1 open-source, own MSVC builds** on the Actions Windows runner at the commits before and after a fix, identical
   flags, optimized, then stripped. Cleanest truth for PE/MSVC.
3. **S2 open-source Windows apps, official releases** (candidate projects, all unverified until checked: 7-Zip,
   Notepad++, PuTTY, WinSCP, KeePass; VLC and FileZilla are MinGW and form their own stratum). Pick point releases with
   small diffs; the fixed function must be among the changed ones.
4. **S3 open-source components shipped in Windows with MSRC advisories** (curl, zlib, libarchive/tar, OpenSSH are
   candidates; unverified). Bridges L1 and L3.
5. **S4 real Windows patch pairs** with a published fixed function. Expensive; this is the L3 evidence.

## Rules that keep the numbers honest

- Freeze the case list (ids, hashes, expected function) in a manifest **before** running any engine. Keep a holdout
  set that is never used for tuning.
- Score "fixed function in the top 5 candidates" and also rank; do not score a yes/no only.
- Include no-code-change and noise-only patches to measure false positives.
- Every case records source URL, licence, commit/release, SHA-256 of each binary, compiler/flags if known.
- A case that cannot be fetched or built is BLOCKED, never dropped silently or counted as a pass.
- Unverified facts (CVE ids, mappings) stay marked `unverified` until a fetch confirms them.
- Third-party binaries are fetched in Actions (the authoring session cannot reach those hosts), never committed.

## Work items

| ID | Item | Status |
|---|---|---|
| AV-0 | Plan, sample-size tool, fixtures S0 | done (this branch) |
| AV-1 | Case manifest schema + validator (`cases.py`), frozen-before-run check | done (tested) |
| AV-2 | Candidate list: projects, CVE ids, fix commits, release pairs (all `unverified` first) | next |
| AV-3 | Actions workflow: fetch/build pairs on Windows runner, hash, emit receipts | after AV-2 |
| AV-4 | Top-k rank scorer (`scoring.py`, `score` command) | done (tested; engine output adapter still to write) |
| AV-5 | L1 automated join evaluation over several MSRC months with an independent oracle | prerequisite smoke probe passed (one month, one CVE); the join evaluation itself has not started, so the L1 claim is unchanged |
| AV-6 | S3/S4 Windows pairs, 15 then 29 | after AV-5 |
| AV-7 | Report: per-layer bound table with counts, stratified, unverified list | last |

## Done criteria

Each layer's claim is stated as "at least X% (95% one-sided), n independent cases, k errors" with the case manifest
hash and receipts attached. A layer with fewer cases than its table row says so and claims less.
