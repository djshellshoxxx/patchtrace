# Outstanding bugs and verified repairs — consolidation pass

Observed 2026-11-19 UTC. Baseline main is
`9c411ca3d7b47f950be5f0c6f01b3c54184554c6`; foundation [#317](https://github.com/djshellshoxxx/patchtrace/pull/317)
is `88b0b52281dd314aa72f93819145a73135618bc4`; broad follow-up
[#316](https://github.com/djshellshoxxx/patchtrace/pull/316) is
`f2b6827fc6270b96fb241b0722f2878de5a17361`. A local repair is not a main
merge or native acceptance result. See [merge blockers](merge-blockers.md) and
[the operation record](final-consolidation-report.md) for current disposition.

## Confirmed in this pass

| Finding | Severity and affected source | Reproduction and repair | Qualification / remaining work |
| --- | --- | --- | --- |
| Unsaved profile navigation discards the draft | P2; present on main, #317 and #316 | Edit profile A, navigate to B/New/Duplicate. New controls: 8 failed, 1 passed before repair. Save/Discard/Cancel now resolves the draft; failed save/validation and Cancel preserve it. Renames and list rebuilds retain the intended selection. | Recovered as `d0c684f1` from `5997321a`; focused author and independent combined Qt checks passed. [Receipt](../qa/profile-navigation-20261119.md). Fresh hosted combined gates remain required. |
| Windows project creation compares incompatible stat timestamp views | P1 for #316 adoption; absent from the narrower #317 implementation | Same physical file is rejected when pathname and descriptor ctime families differ on Windows. Common physical fields now bind the two APIs, with full change-time checks retained within each view. New controls: 1 failed, 8 passed before repair. | [#318](https://github.com/djshellshoxxx/patchtrace/pull/318), remote `202bda41ea84784f2871289f36b9f5341c366a80`; author 117 focused real SQLite/GUI checks and independent 9 controls passed. Native Windows result is still required. |
| Restricted calibration worker resolves its home eagerly | P2; import of corpus tooling fails before an explicit root can be used | Remove HOME/USERPROFILE in the worker, import corpus tooling, and provide an explicit root. Four authored failures precede lazy fallback resolution. | Recovered as `0c417c39` and included in #318. Author 73 passed, 5 unavailable native-toolchain skips. [Receipt](../qa/corpus-home-resolution-20261119.md). |
| Strings export can overwrite a destination that arrives after the first check | P2; main/#317 | Create the destination between initial absence check and publication. Original code unconditionally replaces it. #308 supplies exclusive staging and non-replacing publication. | Selective recovery requires the additional held-source repair below; do not call the entire export ownership problem closed. |
| Strings export can publish a foreign staging replacement and remove it during cleanup | P2 data ownership; forced path already present on main/#317; selected #308 also exposed its no-force path | At fsync, rename the owned stage and put foreign bytes at its pathname. On `d436a7ec`, published bytes were the foreign replacement while the held original contained expected bytes. | Independent reviewer confirmed the defect. No-force held-source repair `6e0342ff` is recovered as `96f2f103`; 47 export/CLI/publication controls passed. Existing forced replacement remains an explicit unresolved ownership boundary; no claim that random naming or a stat precheck closes the race. |
| Windows portability fixtures fail before exercising their intended assertions | Test/CI blockers on #316 | Fixtures retained owned readers while replacing/unlinking, left SQLite handles open, changed CRLF payload length, assumed one symlink spelling, interposed host CRT WinAPI names, or used stdio state that did not reach a real read-only descriptor. | #318 retains assertions and uses correct fixture lifetimes, exact bytes, stored link target, namespaced authored C surrogates and real descriptor failure. Same-length CRLF control failed before repair. Combined selection: 312 passed, 8 skips. Independent C controls: 57 passed. These are not native Windows results. |

The overlapping test selections above must not be summed into a single suite
total. The #318 source and verification are recorded in that PR and
`docs/qa/windows-portability-repair-20261119.md` on its branch.

## Historical findings rechecked against current sources

| Tracker / finding | Current evidence and disposition |
| --- | --- |
| [#116](https://github.com/djshellshoxxx/patchtrace/issues/116): failed notes, project save and bookmark success reporting; abandoned project retry; export wording; stale inspection failure | Existing controls and reviewed implementation already address these paths. Nine existing GUI failure controls passed in this pass. Do not duplicate those fixes. Profile navigation was the remaining reproduced defect and is repaired separately above. |
| [#118](https://github.com/djshellshoxxx/patchtrace/issues/118): recorded search scope, card provenance and unrelated-month leakage | #317 includes the saved-scope/global-admission repair missing from its earlier foundation. An independent 91-test scoped run passed. Evidence includes full-index admission before finite projection and source-sensitive revision identity; see [foundation receipt](../qa/foundation-saved-scope-20261119.md). This does not establish an L1 accuracy rate. |
| #118: architecture selection and acquisition identity | Existing current product-scope and acquisition safeguards are preserved. The historical issue and older PR state are not proof of a still-open defect; neither are they grounds to close every acquisition concern without its own reproduction. |
| [#120](https://github.com/djshellshoxxx/patchtrace/issues/120): manual ambiguity, result identity and alternative provenance | Current main contains the separately reviewed identity/ambiguity repair family and later follow-ups. Historical red controls and source receipts remain in `docs/qa.md` and `docs/qa/identity-main-repair-20261101.md`. Current full-suite CI covers the retained controls. No new matching-accuracy or all-adapter qualification claim follows. |
| [#121](https://github.com/djshellshoxxx/patchtrace/issues/121): backup trust and SQLite iteration deadlines | Existing bounded fresh-byte backup verification and per-query deadline repairs are retained. Their original receipts distinguish these fixes from whole-import memory caps. Memory/resource and broader security questions remain separate. |
| [#105](https://github.com/djshellshoxxx/patchtrace/issues/105): KEV/KBC/search/rules/callgraph/enrichment/pilot findings | Retrieved all 36 returned comments, including later status corrections. The last historical status explicitly marks some rules/callgraph findings fixed and others repaired in #285. Source-pinned historical reviews and current integration lineage are retained in the inventory evidence. Findings are not re-opened solely from their original comment, and the whole issue is not blanket-closed. |
| [#104](https://github.com/djshellshoxxx/patchtrace/issues/104): KB/CVE/KEV handoff | The original #103/#106/#107/#108 queue is historical. Current ancestry and implementations govern decisions. Preserve its explicit constraints and outstanding accuracy work; no release/tag retry is part of this pass. |

## Remaining confirmed or qualification defects

| Item | Evidence / reproduction | Required next action |
| --- | --- | --- |
| Forced strings publication source ownership | Same stage substitution as above with `force=True`; inherited main/#317 path closes the file and later replaces by pathname. | Design a preserving atomic replacement protocol for each supported platform, add adversarial ownership controls and retain the current functionality. Linux precheck-plus-rename is not proof of held-source publication. Keep the failure visible. |
| Strict security gate on #316/#318 | `python -m ruff check src --isolated --select S --ignore-noqa --no-cache --no-respect-gitignore --output-format json` reports 80 findings. The code distribution is recorded in the blocker report; these are scanner findings, not 80 confirmed exploitable vulnerabilities. | Triage by trust boundary, repair real defects and substantiate any false-positive disposition under the repository policy. No gate suppression was added. |
| Windows advisory harness lacks native dependencies | #318 job `135423105494`: six zlib cards BLOCKED on missing `llvm-dwarfdump`; rz-diff evaluation BLOCKED on missing `rz-diff`; exit 3. | Provision verified native tools or retain BLOCKED. A job-level advisory name does not convert these results into native acceptance. |
| Cold GUI host timing on this executor | Raw/search selection: 1,060 passed, 1 failed. The unchanged 0.5 s host budget also failed in isolation on untouched #317; warm observations were below the budget. | Preserve both failed runs; use the fresh exact-candidate hosted gate. No threshold or assertion was changed. [Evidence](../qa/stable-raw-search-20261119/README.md). |
| Local repeated Qt attempt did not complete | Child exited with status -9 during executor stalls; no completed JUnit outcome. A separate profile review attempt was interrupted with exit 130. | BLOCKED/ABORTED, not PASS. Fresh hosted repeated Qt gates remain required. |

## Open implementation trackers

[#255](https://github.com/djshellshoxxx/patchtrace/issues/255) remains the native
research/integration tracker. [#35](https://github.com/djshellshoxxx/patchtrace/issues/35),
[#36](https://github.com/djshellshoxxx/patchtrace/issues/36) and
[#39](https://github.com/djshellshoxxx/patchtrace/issues/39) cover broader matching,
raw/layout and optional Diaphora programs. Current implementations have advanced
beyond their original issue text; their unchecked original lists are not a fresh
absence test. This pass recovers the near-complete paired raw view and preserves
the other programs' independent native, accuracy and packaging gates.

A current source search of `src` and `tools` for TODO, FIXME and
`NotImplementedError` returned eight exception-handling references and no TODO or
FIXME implementation marker. This is a bounded marker search, not proof that the
product or historical backlog is complete.

## Supplementary stable security scan

The same runtime-only unsuppressed S scan reports **66 findings on #317** and
**68 on stable `96f2f103`**. The added observations are an XML parser call in the
DTD-refusal repair (S314) and fixed-column SQL construction in retained CVRF
capture (S608). Their exact trust-boundary review is recorded with the final
source evidence; scanner output alone does not establish exploitation. An
additional `src tools` exploratory scan reported 147 findings and has a broader
scope; it must not be compared directly with the runtime-only 80-count gate.
No finding was hidden with a new suppression.

## Introduced cancellation cleanup regression — repaired

The selected #308 broadened forced staging cleanup from `OSError` to
`BaseException`, so cancellation could remove a foreign replacement that
main/#317 would retain. Six new controls reproduced this regression.
`14f0e2c9`, integrated as `6edcb34a`, restores the original exception boundary
while closing any descriptor still owned by the attempt. The affected selection
passed 53 tests and an independent reviewer passed all six new controls.
This repair does not close the inherited forced publication and OSError cleanup
ownership defects. [Source and raw red/green receipts](../qa/strings-force-cancellation-20261119/README.md).

## Native CI setup false success — repaired in the candidate

Issue #121's unconditional positive-setup `LASTEXITCODE` reset still existed.
The seed script copies PDBs; later product acceptance did not establish that
the symbol-enabled setup succeeded. The CI-only checked runner now stops if
either seed or setup exits nonzero; it preserves command arguments, environment,
matrix variants and the separately asserted intentional negative reproduction.
Seven real authored-child controls independently passed. No direct measurement
of persisted Ghidra preferences or native Windows success is claimed.
[Source and evidence](../qa/native-symbol-setup-20261119/README.md).
