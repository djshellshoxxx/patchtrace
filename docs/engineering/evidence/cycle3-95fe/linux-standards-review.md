# CODEX-14 independent standards review

## Scope and verdict

Reviewed on 2026-11-21, read-only, at `/workspace/scratch/patchtrace-95fe-c3/linux-review`.

- Candidate: `e4854b66ae37024d734e22ae978dedca90a7f3f7`.
- Baseline: `6b6fcd3597a604212032ffc453477aeb6edc69ff`.
- Diff: `git diff 6b6fcd3597a604212032ffc453477aeb6edc69ff...HEAD`.
- Scope: 14 changed files, 270 insertions and 11 deletions. The harness runtime is unchanged; its four changed lines are documentation. The worktree was clean when inspected.

**No hard standards violation or blocking source defect found in this bounded change.** This is an independent source review, not runtime acceptance. No tests, builds, network probes, source changes, or ref changes were performed. Only this report was written.

Standards applied: `AGENTS.md:5` (specification before changed contracts, target-execution prohibition and module ownership); `AGENTS.md:7` (meaningful invariants and honest evidence); `AGENTS.md:9` and `AGENTS.md:11` (unverified acceptance and all-green merge gates); `docs/modules.md:352`, `docs/modules.md:598`, and `docs/modules.md:600` (packaging ownership and frozen CLI seam); `docs/linux.md:14` (CODEX-14 acceptance). The candidate handoff and original packaging audit were also reviewed. No separate CONTRIBUTING, CODING, or issue-tracker standard was found.

## Evidence supporting the verdict

| Concern | Source evidence and conclusion |
|---|---|
| Specification and ownership | Commit `68cfff46` establishes the contract before test commit `d34f6100` and implementation `93a6698b`. Changes stay in the packaging workflow, its static regression, and documentation. `tools/frozen_smoke.py:1` changes documentation only; the frozen seam described at `docs/modules.md:600` keeps its runtime behavior. |
| Shell ordering | `.github/workflows/qa-windows.yml:159` checks out before artifact download at line 166. SHA verification at line 173 precedes extraction and executable-bit validation at line 174. Both existing Qt probes remain at lines 181 and 184; full frozen smoke follows at line 190. Checkout cannot clean away a previously downloaded archive in this ordering. |
| Source and artifact identity | The producer checks out at `.github/workflows/qa-windows.yml:132`, uploads the archive and sidecar at line 142, and is a prerequisite of `linux-smoke` at line 149. Producer and consumer use the same workflow checkout context without a ref override. Download at line 166 has no alternate repository/run selector. The quoted `$PWD/PatchTrace/PatchTrace` at line 190 binds the harness to the extracted artifact. The unchanged builder creates the archive and its digest at `tools/build_linux.py:458`. This is workflow-level identity, not an independently validated artifact attestation. |
| Host and frozen boundary | Declared host dependencies at `.github/workflows/qa-windows.yml:165` support fixture generation. `tools/frozen_smoke.py:72`, line 80, line 210, and line 250 create synthetic host fixtures. `tools/frozen_smoke.py:322` resolves the supplied executable and line 323 passes `[exe]` with `frozen=True`; subprocess calls preserve that launcher at line 53. BinExport and intelligence checks do not inject source PYTHONPATH when frozen (lines 225 and 255). The frozen BinExport child uses `sys.executable` at `src/patchtrace/secondary/binexport_run.py:43`; the parent launches it at line 134. No submitted target binary, live analysis, or network acquisition is added. |
| Failure propagation | `tools/frozen_smoke.py:114` records failed checks; line 324 returns exit 1 if any failed. Unhandled launch, timeout, fixture, or parsing errors also fail the Python process. The workflow's smoke step at `.github/workflows/qa-windows.yml:189` has no failure-suppression condition or `continue-on-error`. The Linux worker retains the existing resource controls at `src/patchtrace/jobs.py:304` and `src/patchtrace/secondary/binexport_worker.py:18`. |
| Regression containment | Both Ubuntu versions remain at `.github/workflows/qa-windows.yml:153`; release continues to depend on `linux-smoke` at line 221. No Windows workflow behavior, runtime code, timeout, or previous Qt probe is removed. The only CODEX expected-failure marker removed is the now-implemented source assertion. |

The evidence receipt's three blob IDs at `docs/engineering/evidence/codex14-linux-smoke-static-review-20261121.json:6` match the candidate's actual Git blobs: workflow `b3a33dc2981aa85d4862c77be034c11306c224e4`, packaging test `b3876f278f789c727151faa5501d8618406fdc11`, harness `84e462135b793134720dba2125182e848f0a94fa`. This verifies identity, not the claimed execution of the author's seven mutation controls.

## Judgment calls and remaining acceptance

**Nonblocking test-quality observation:** `tests/test_codex_pkg_packaging.py:93` and line 101 inspect workflow text, rather than parsed executable steps. The assertions can establish the currently inspected fragments and ordering, but cannot independently reject every future disabling condition or prove effective step execution. Under the meaningful-invariants rule (`AGENTS.md:7`), treat these as source guards; do not elevate them to frozen-platform proof. A future semantic workflow assertion may be useful, but the current implementation has no such disabling condition and no mandatory abstraction/refactor is warranted.

The new host setup and longer harness add CI work within the unchanged 30-minute budget (`.github/workflows/qa-windows.yml:155`). No new timing failure is established by source inspection. Whether the existing resource-capped BinExport child and all frozen imports work on both Ubuntu versions requires actual jobs. Runtime failures must be recorded and repaired rather than skipped.

`docs/linux.md:34` requires both matching-source Linux smoke jobs and artifact provenance; `docs/linux.md:38`, `AGENTS.md:7`, `AGENTS.md:9`, and `AGENTS.md:11` keep applicable full QA, Qt, native/package, and merge/release gates open. This review does not provide those results. CODEX-14 remains implemented but unqualified until those receipts exist.

Historical failures are preserved, including the original packaging audit's 41 collection errors (`docs/audits/codex-packaging-1.md:100`) and PR345's NSIS feed failure (`docs/qa.md:2311`). The original CODEX-14 finding remains historically valid (`docs/audits/codex-packaging-1.md:113`). This review neither reclassifies older SIGKILL/native/Qt failures nor resolves CODEX-1/5/6, Windows manual/trust/accessibility, provenance, or separate L1/L2/L3 gates.

The supplied smell heuristics were considered as judgment aids. No actionable new mysterious naming, duplicated behavior, ownership mismatch, data clump, inappropriate primitive, repeated dispatch, scattered implementation ownership, mixed runtime responsibility, speculative abstraction, navigation chain, empty delegation, or inheritance problem was found. Existing documentation duplication is evidence tracking, not a reason to introduce a shared runtime abstraction.

## Exact retained commit list

Newest first, from `git log --format='%H %s' 6b6fcd3597a604212032ffc453477aeb6edc69ff..HEAD`:

```text
e4854b66ae37024d734e22ae978dedca90a7f3f7 docs(linux): preserve seven mutation controls and correct harness scope [no release]
363118c83103af8426bc87fb152ccc4fae536a06 docs(linux): preserve seven mutation controls and correct harness scope [no release]
396f5105862ee198e9f5d3266d0f2677c29f2369 docs(linux): preserve seven mutation controls and correct harness scope [no release]
f359cbfbad6797577ac2910ce869240dbd2afd44 docs(linux): preserve seven mutation controls and correct harness scope [no release]
fefb29fd43574e559987c4f24fcf8e6540d2d10e test(evidence): retain CODEX-14 static positive and seven mutation refusals [no release]
6ea0ff2538159bdc714d840ab1368fdecc2b6d77 test(linux): require checkout-before-artifact and frozen offscreen source binding
2af9a5c37eaf25198fada253fcc586e8fe0183ba docs(smoke): clarify existing frozen CLI harness runs on Windows and Linux [no release]
6a0a263140215408f63f2a74691d3aa659344b2a docs(linux): record CODEX-14 implementation and unqualified source gates [no release]
5c45094b352985187392d8d580f8e601e41278c9 docs(linux): record CODEX-14 implementation and unqualified source gates [no release]
fb90cb747445220423b87972f075c04696efad1b docs(linux): record CODEX-14 implementation and unqualified source gates [no release]
354300598de32009aabc1327733475703d0354b7 docs(linux): record CODEX-14 implementation and unqualified source gates [no release]
4a3255a97bc0abb29d5c45a54006034e9c52878e docs(linux): record CODEX-14 implementation and unqualified source gates [no release]
9f170935972a10d05f6b83547a50f14fb3aea74d docs(linux): record CODEX-14 implementation and unqualified source gates [no release]
e97ef0a7d804eba8227cfb39e72daf09e16fcc04 docs(linux): retain CODEX-14 source scope, static evidence and executable handoff [no release]
79097aa86bef481651c8b33b151613d47beac26f docs(linux): retain CODEX-14 source scope, static evidence and executable handoff [no release]
4d0245dc84c0824d7ed09a1764b0db5c3e5400b6 docs(ledger): track bounded CODEX-14 full Linux frozen CLI smoke and blockers [no release]
93a6698b1a8f38e26199638ee9d72d2adc985dd3 ci(linux): run complete frozen CLI harness on verified extracted archive [no release]
d34f6100c01d06c4ff2681d3b6ca6d6fca07ed8d test(packaging): require full extracted Linux CLI smoke on both distros [no release]
68cfff469618f0123df81740c4ab2a0bf3e24e00 docs(linux): specify extracted-artifact full frozen CLI smoke acceptance [no release]
```

## Narrow source-delta inspection: obsolete pytest import removal

On 2026-11-21, independently inspected commit `5fa47ac7b03451f404c2f0acd871e8700067c13f`, tree `e7b190bb34dc55da3368002d7c09ca1fe5666188`, against reviewed head `e4854b66ae37024d734e22ae978dedca90a7f3f7`.

The entire delta removes `import pytest` and its following blank line from `tests/test_codex_pkg_packaging.py:10`. No workflow, assertion, fixture, source specification, or runtime behavior changes. The CODEX-14 expected-failure removal had left that import unused. This minimal deletion introduces no standards finding and leaves the original workflow inspection conclusions applicable to the revised source.

Root reports that whole-tree Ruff on `e4854b66` found the F401 unused import, preserved the original failure receipt/log, and that Ruff passes after this repair. Those are root-owned execution results, not tests replayed by this reviewer. The original head's lint failure is not erased by this source-delta review. Root's combined-source focused gate and exact-source hosted/platform acceptance remain separate required receipts; no frozen Linux, native, merge, or release acceptance is inferred here.
