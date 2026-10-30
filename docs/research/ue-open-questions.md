# Unified engine (SPEC-31): open questions, research and decisions (U1, 2026-10-15)

Scope: every open decision, TBD, `[unv]` item and residual risk in `docs/specs/unified-engine/` (00 s4, 03 s4/s12, 05 s9 open limits, 08, 10, 11 s6 and s8) and `docs/plans/unified-engine-plan.md` s6. Labels: [web] fetched 2026-10-15, [src] read in repo, [inf] inference. Status: RESOLVED (spec text updated), DEFAULT (safe default stays, owner may override), BLOCKED (needs a live run or an external asset).

## A. Resolved by research

| ID | Question | Decision | Evidence | Risk |
|---|---|---|---|---|
| Q1 | FID "library" marker (03 s4 [unv]) | RESOLVED. Ghidra's Function ID analyzer has no function tag and no library flag. `ApplyFidEntriesCommand` creates a label with `SourceType.ANALYSIS`, sets a plate comment that starts with `Library Function - Single Match.` (or the multi-match variants, library names after `Library: `/`Libraries: `), and sets a bookmark of type `Analysis`, category `Function ID Analyzer` (`Function ID Conflict` for ambiguous matches; conflict labels get the prefix `FID_conflict:`). The extractor should read the bookmark category (stable, no text parsing) and set `fn.flags` bit 64 only for the single-match category; conflict bookmarks leave `lib` false. | [web] [ApplyFidEntriesCommand.java](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/FunctionID/src/main/java/ghidra/feature/fid/cmd/ApplyFidEntriesCommand.java); [FidAnalyzer.java](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/FunctionID/src/main/java/ghidra/feature/fid/analyzer/FidAnalyzer.java) (the `alwaysApplyFidLabels` and bookmark options); read through the master branch, not the pinned 12.0.4 zip | Low. The analyzer is off for most x64 PE runs unless an FID database is installed, so `lib` stays false on most inputs; a master/12.0.4 difference is possible, so the script keeps its `--self-check` and a live probe with a FID database is still the proof (BLOCKED for the code change, see section C). |
| Q2 | U-07 Tier R builds on Windows runners (clang-cl/mingw/MSVC) | RESOLVED: yes. The `windows-latest` label now maps to a Windows Server 2025 image with Visual Studio 2026 whose component list includes `Llvm.Clang` and `Llvm.ClangToolset`, so MSVC `cl`/`link` and clang-cl exist without installs. The workflow prints `clang-cl --version` and `cl` banners as evidence instead of assuming versions. | [web] [runner-images release win25-vs2026/20260728.188](https://newreleases.io/project/github/actions/runner-images/release/win25-vs2026%2F20260728.188), [releases](https://github.com/actions/runner-images/releases); the date of the `windows-latest` switch is reported inconsistently, so versions are logged, not assumed | Medium: image drift changes compiler versions, which changes Tier R binaries; the manifest records tool versions, never a pin. |
| Q3 | U-01 port BinDiff with attribution | DEFAULT stays. Facts: BinDiff is Apache-2.0, section 3 grants a patent licence from each contributor for their contribution, with termination if the licensee sues over the work. The recorded notice (`third_party/notices/bindiff-v8-aecc14d/`) already pins the commit. A port of the MD-index algorithm is therefore permitted with attribution; whether the patent grant covers a derivative port is a legal question this note cannot answer. | [web] [google/bindiff LICENSE](https://github.com/google/bindiff/blob/main/LICENSE) (Apache License 2.0); [src] `docs/notices.md` row | Owner question O1. |
| Q4 | A-IND-1 (narrowed independence of corroborating atoms) | DEFAULT stays, gate G-U7 is the right control. Conditional independence of comparison fields is the classic Fellegi-Sunter assumption; violation biases the fitted parameters and the downstream classification, and loglinear interaction terms were the best fix in simulation, but explicit dependency models did not reliably improve linkage quality. That supports PatchTrace's choice not to model dependence but to merge correlated evidence into components and evidence classes, and to measure B+B error against tier A (G-U7, 2x bound, cluster CI). No change to the spec. | [web] Daggy et al., BMC Med Inform Decis Mak 13:97 (2013) <https://bmcmedinformdecismak.biomedcentral.com/articles/10.1186/1472-6947-13-97>; [Resnick, JSM 2017](https://www.norc.org/content/dam/norc-org/documents/standard-projects-pdf/Resnick_2017_JSM.pdf) (correlated fields among non-matches) | Medium until G-U7 has data on Tier R. |
| Q5 | Ghidra version pin (12.0.4) against newer releases | DEFAULT stays 12.0.4 for the alpha. Ghidra 12.1 is released; its PyGhidra change restores `sys.modules` after a script and is irrelevant to a one-shot child process. Moving the pin changes decompiler output, hence COS-PSEUDO behaviour and every recorded qa.md run, so it needs its own comparison run. Ghidra 12 needs JDK 21. | [web] [Ghidra 12.1 change history](https://ghidradocs.com/12.1_PUBLIC/docs/ChangeHistory.html) | Low. Owner question O3. |

## B. Product decisions: safe default kept, owner may overrule (00 s4)

| ID | Default | Why it is safe | Owner question |
|---|---|---|---|
| U-02 GZF retention | yes, transient | `retain_gzf` exists and is off unless a unified run asks; disk for kernel-size images is [unv] and measured by `bench_extract` | no |
| U-03 hide proven-cosmetic rows | yes, count visible | filter shows the collapse count; COS-PSEUDO stays visible | no |
| U-04 retire Evidence tab | after G-U gates | nothing removed now | no |
| U-05 flag default | OFF | G-U1..G-U6 cannot pass before S6b live runs | O2: when to flip, only after the report SHAs exist |
| U-06 tentative tier-B rows | show | never counted as matched | no |
| U-08 global IR cache | not built (A-04b NOT BUILT) | project-local IR is complete | no |
| U-09 worker cap | min(4 GiB, 50 % RAM) | prototype peak 0.3 GiB at 60k functions | no |
| U-10 auto-run after Ghidriff | no | analyst control | no |
| U-11 automatic decompile pass | yes, cancellable, `--no-decompile` | bounded by L-41 | no |
| U-12 DATA-MAP region shift | yes, guarded by the G-U2 mutant `swap-to-existing-global`; B-21 drops it | residual is a data-content change outside the verdict scope | no |

## C. Blocked on a live run or an external asset

| ID | Item | Trigger | Note |
|---|---|---|---|
| B1 | MSVC-built PE behaviour (operand typing, RVA-form switches, CFG dispatch, /GS) | first `windows-latest` Tier R run (workflow added in step 2) | Q2 makes it possible, not proven |
| B2 | GZF import time on kernel-size images | `bench_extract` on a Tier W pair (local) | unchanged |
| B3 | BinDiff oracle for G-U3 | `tools/bindiff_pin.json` has no verified assets | unchanged, not touched here |
| B4 | EH-EQ covers `__C_specific_handler` only (FH3/FH4 by length and handler) | MSVC C++ fixture | stays `review`, never cosmetic |
| B5 | Ghidriff `match_types` drift in versions after the pinned one | each pin bump | unknown names already map to tier C, E-UNKNOWN; the pin-bump checklist should diff the names |
| B6 | FID marker code change in the extractor script (Q1) | a live probe with an installed FID database | spec text updated now, code later |
| B7 | Tier W anchors (ntoskrnl, afd.sys) | USER corpus, local only | unchanged |
| B8 | 05 s9 open limits 1-5 (permuted switch targets, no block-similarity fallback, unmapped data, per-pair decode cost, MSVC) | reported, not hidden | recorded limitations, nothing to decide |

## D. Owner questions (shortest list)
- O1: legal/patent review of the BinDiff MD-index port before the first release that ships it (U-01).
- O2: the flag stays OFF until the S6b gate report exists with all of G-U1..G-U6 passing; confirm you want no earlier opt-in default.
- O3: keep Ghidra 12.0.4 for the alpha, or schedule a 12.1.x comparison run.
