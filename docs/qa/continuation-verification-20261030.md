# Autonomous continuation verification — 2026-10-30 Pacific

Status: repairs published and independently reviewed; **project not complete**.
No integration-to-main merge, final release, source deletion or protection bypass
was performed in this continuation.

## Reviewable sources

- [PR #141](https://github.com/djshellshoxxx/patchtrace/pull/141): extraction failure
  isolation, stacked on the active #140. Head `d76d23372acef4049115e9ae176acbeb538a82e5`.
  Preserves concurrent Windows coordinator commit `fb91cff`; it does not overwrite
  that worker's branch. An attempted expected-head update did not move #140.
- [PR #142](https://github.com/djshellshoxxx/patchtrace/pull/142): current-contract
  repairs for #136's synthetic fixtures. Head `a4d1e6a38c34d1952584aa65d7f5f908c45547b3`.
  All original raw corpus bytes remain unchanged; a small separate Unicode input
  supplies actual U+0417 coverage. No production parser is changed.
- Combined source commit `601db7bca279a17e04fbbc2919667a7a2efa7337` has tree
  `fc27f77c9c822b114d3479bf36efe89aa2b32c17`, exactly matching tested local
  source commit `efc14fadfbc2bb8aeab0830d8ac98687099a0fbd`. The combined branch is
  a verification candidate, not a promotion or replacement of the active coordinator.

## Actual verification

| Check | Observed result | Scope |
|---|---|---|
| Complete combined offscreen pytest, four workers | **18,384 passed, 1 failed, 126 skipped, 7 xfailed**, 389.17 s | Exact tested tree above; one host artifact below |
| Earlier full serial run begun at b705659 | 18,349 passed, 1 failed, 126 skipped, 7 xfailed, 1083.50 s | Does not attest subsequent concurrent diagnostic repair |
| Combined backend/harness regressions | 87 passed, 3 skipped | Synthetic external processes; real project store/pipeline regression |
| KB fixture plus existing correlation regressions | 934 passed, 18.17 s | Synthetic/local parser tests |
| Discovery repetition | 30 passed in one pytest session | Linux offscreen; not Windows stability proof |
| Ruff / patch hygiene / dependency check | clean | Full source/tests/tools; no weakened rules |
| Schema regeneration | no tracked schema changes | Combined checkout |
| PR #141 native Windows Ghidriff | [41166712588](https://github.com/djshellshoxxx/patchtrace/actions/runs/41166712588): all five jobs passed | Known changed fixture, seeded symbol stores, raw cache, upstream reproduction; not Windows forced-A/A or corpus acceptance |

The one combined failure is
`tests/test_rules_actions.py::test_the_preview_is_exactly_the_file_and_never_replaces`.
The shell sandbox mounts an empty read-only `/tmp/.git`; the export protection
intentionally treats an ancestor `.git` as a repository and refuses the temporary
export. No test was skipped/removed and no export protection was relaxed. Initial
socket denials and interpreter dependency misses disappeared after enabling the
supported shell network capability and using a copied venv interpreter. A trial
temp directory outside the writable mounts remained read-only; no boundary was bypassed.

## Native evidence and limits

Pinned Ghidriff `4f5d895`, PyGhidra 3.0.2, Ghidra 12.0.4 (verified archive SHA),
OpenJDK 21.0.12.1. Authored freestanding PE fixtures compiled using Zig 0.17.0;
no target DLL was executed. The changed bounds-check pair imported and produced
`material`. Two independent identical-byte backend/GZF/IR/unified smokes produced
`unchanged`. See `gt01-native-smoke-20261030.json`.

A subsequent run called the **actual `live_pairs.analyse_pair` harness** in both
orientations with one same-image control. Each completed native analysis,
project import, two retained GZF sides, IR extraction, unified persistence and
outcome collection; both rows were `right` and `unchanged` against the
construction-known PE export endpoint at RVA 4096. Extent came from the PE
runtime table, not predicted matches. See `gt01-harness-smoke-20261030.json`.
This supplies no independent-rebuild, names-hidden, different-image orientation,
held-out accuracy, air-gap or G-U1–G-U8 corpus claim.

## Acceptance still open

1. Exact-head full Linux/Windows QA, repeated Qt and packaging for both draft
   repairs and the final integrated source. At observation, #141 QA run
   [41166731251](https://github.com/djshellshoxxx/patchtrace/actions/runs/41166731251)
   and #142 QA run [41166905336](https://github.com/djshellshoxxx/patchtrace/actions/runs/41166905336)
   were queued. Queued, skipped and advisory-parent success are not acceptance.
2. A pinned native `unified-live-gates` matrix with actual evaluated A/A, release
   and mutation denominators, G-U1–G-U8 and all mandatory thresholds. The connector
   has no workflow-dispatch operation and CLI authentication is unavailable;
   this session did not dispatch that matrix or change its triggers to bypass this.
3. Real secondary-engine and vendor correlation receipts, held-out matching and
   materiality evidence, plus applicable R1–R8 source reconciliation by their owners.
4. Clean Windows GUI/DPI/accessibility and cancel/reopen/report acceptance;
   frozen portable/installer artifacts, checksums, notices and release commit identity.
5. Merge only reviewed passing required sources, in stack order (#139/#140/#141;
   #136/#142), then verify the target and update the integration ledger. Keep
   original author branches and unproven unique work intact.
