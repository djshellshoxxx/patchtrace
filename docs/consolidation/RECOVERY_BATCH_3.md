# Bounded semantic recovery batch 3

Date: 2026-11-19. Review baseline:
`69fa6b8b588645a895b3edbdeff3aa4b74856be7`.

## Existing contract enforced by the numeric correction

Issue #105, comment `6783814958`, E3/E4 records untyped failures from extreme
provider decimal exponents and timestamps whose UTC instant is outside the
datetime range. The existing `enr_r11_cve.py` reproduction confirms both against
this baseline. The affected `src/patchtrace/enrichment/cve.py` has identical Git
blob `98f42bee911f8b68a2bbe4d7054efe1a3c190078` on main
`fdc2696c23bdbfe7668348f25e3b336ce33039f7`, this integration baseline, PR #319
`a56ab13aaf9916fc12bea70ba1494075991b7f09`, and PR #320
`188b4962e527c82b29e599f75cd952029b749348`.

SPEC-07 sections 3 and 8 already require typed enrichment errors and preservation
of successful provider responses when another provider fails. The correction
must translate unsupported decimal operations to `PT-ENRICH-PROVIDER`, reject
unrepresentable UTC retrieval/freshness times as `PT-ENRICH-INPUT`, preserve valid
boundary values and original timestamp text, and leave the caller's Decimal
context unchanged. No record schema, snapshot identity recipe or provider
compatibility claim changes.

Independent review reproduced three additional exactness failures in the old
multiply-before-validation path: `1e-1000100` became zero, an overprecise
`9.80000000000000000000000000000001` became 98 tenths, and a caller context with
precision one changed a valid 9.8 to 100 tenths. The final correction checks the
finite 0..10 range first, quantizes to one exact decimal place with `Inexact`
trapped, and only then scales to the integer score. A fresh local Decimal context
has sufficient precision for 100.0 and does not inherit the caller's precision,
rounding or traps. Removing redundant zeroes remains allowed. Context settings
and flags are restored on both success and failure.

The original census remains frozen. No source branch or issue was deleted or
closed, and no remote write was made by this batch.

## Verification of the numeric correction

| Run | Observed result |
| --- | --- |
| Original 30 boundary controls against the integration baseline | 20 failed, 10 passed in 2.44 seconds; no setup errors. |
| First typed-error correction with existing CVE/audit callers | 111 passed in 5.78 seconds. This intermediate result did not establish decimal exactness. |
| Expanded controls against that intermediate correction | 10 failed, 33 passed in 2.46 seconds; both providers reproduced the reviewer's exactness and caller-context findings. |
| Final boundary controls plus existing CVE/audit callers | **124 passed in 6.70 seconds**, no failures, errors or skips. |
| Ruff on `cve.py` and the new test module | Passed after correcting import layout. |
| `git diff --check` | Passed. |

The final command used `QT_QPA_PLATFORM=offscreen PYTHONPATH=src`, the dedicated
source-isolated Python environment, `-p no:cacheprovider`, and
`--basetemp=/tmp/pt-81e4-cve-numeric-final`, with these modules:

- `tests/test_enrichment_numeric_boundaries.py` (43 controls)
- `tests/test_enrichment_cve.py`
- `tests/test_audit_enrichment.py`

Controls cover both providers, representable years 1 and 9999, valid offset
timestamps without rewriting their text, zero/negative zero/10/9.8, redundant
zeroes, extreme zero exponents, low caller precision and rounding traps. Public
CLI controls verify that a malformed numeric response does not discard another
provider's valid response, and that an impossible snapshot timestamp is refused
before contextual ranking while retaining the input file. These are authored
offline controls, not live provider or CVE accuracy evidence.

The whole-repository and native/platform gates belong to the combined
integration candidate. No successful full-suite result is inferred here.

## Retained branch contributions reviewed

This is a disposition of the named contributions, not every commit on these
branches. The 139-branch semantic backlog is not declared complete.

| Retained source | Current evidence and disposition |
| --- | --- |
| `fix/remediation-b1ab7332-a8fac4`, `3feec96f6546e755061a458ce0dc6e8ee0fab640`; earlier `dbf3f40c81639c565d3dfa976e9213067cf2642d` | Do not copy the tip wholesale. On the same authored name-only Ghidriff change with ratio 0.5, current code returns only the code-changed function `b`; this retained tip returns `a, b`, reversing `test_ghidriff_non_code_diff_type_not_a_change`. The earlier nested Rizin side-type check is missing from current main/#319, but PR #320 already contains a stronger native-layout admission boundary. A malformed original side produces a spurious one-sided `f` in current code and a typed refusal in both the retained source and #320. Preserve the candidate-specific work for review; no duplicate port in this batch. |
| `claude/instance-c-research`, `6f767ccef8ebfffd1d2373c5124d8a961dc54b41`, and contribution `dce7430e` | The md-dump timeout/cancellation/output-limit exit fix and missing-ticks benchmark rejection are already present. `tests/test_unified_parity.py::test_md_dump_cli_fails_when_the_run_was_cut_short_even_with_exit_zero` and `tests/test_unified_bench.py::test_a_missing_ticks_count_fails_the_work_checks_and_is_never_read_as_zero` preserve their assertions. This review does not dispose of the branch's other contributions. |
| `fix/remediation-53088704-982db3`, `15370a0bf690ea65f49d1f6cc67c40f73fd3d77c`; earlier `4aa99f7b` | Current preregistration scanning already preserves inline code before comment scanning, rejects comment/fence examples, and requires a visible record to originate at column zero. Training verifies the recorded protocol before corpus access. `tests/test_train_prereg_selection.py` covers those boundaries, including escaped delimiters and nonrecords. The older patch must not replace the later, stricter scanner. |

Exact blob comparisons confirm that `tools/unified/parity.py`,
`tools/unified/bench.py`, and `tools/calibration/prereg_gate.py` are identical
across main `fdc2696c`, the integration baseline, PR #319 and PR #320:

| Path | Git blob |
| --- | --- |
| `tools/unified/parity.py` | `db269607be8c149f4ebed3b69ab32a4e9826759c` |
| `tools/unified/bench.py` | `66e0e68b36925ac3a6adc1798488c818f8e44fe5` |
| `tools/calibration/prereg_gate.py` | `01056fdaf6924903a2dcdf285943bb97e1460531` |

PR #320's research adapter blobs are
`9080bdd0205fe5b2d14d26ec242b4e6e0710d8c2` (Ghidriff) and
`3b68626b13a0281613b800978f89a7bba57ea02d` (Rizin). They were first inspected via
pinned REST file reads, then matched to local Git objects after fetch became
available. Their existence is not a claim that the broad draft is qualified.

## Historical issue map

Input coverage: all 10 non-PR issues in the supplied all-state snapshot are open;
39 comments were indexed (36 on #105 and one each on #104, #116 and #118).
The mappings below distinguish existing source/test coverage from reproduced
defects and remaining work. Except for the numeric correction above and the
authored adapter comparisons, these are static dispositions; naming an existing
test is not a fresh execution or an instruction to close an issue.

| Issue | Disposition at the pinned integration baseline |
| --- | --- |
| [#35 — QBinDiff-inspired matcher](https://github.com/djshellshoxxx/patchtrace/issues/35) | The current `qbindiff-inspired-matching.md` explicitly supersedes this design with SPEC-31 amendment A-10. The goals moved to the unified engine; the original `matching/*` store and message-passing solver are not a missing implementation to recreate. Existing ladder tests cover the current design. Reconcile the tracker with its successor specification; do not label the original checklist fully implemented. |
| [#36 — radiff2-inspired layers](https://github.com/djshellshoxxx/patchtrace/issues/36) | SPEC-31 amendment A-11 partially supersedes the plan: opcode/operand deltas belong to unified L2 C1/C2, file-level layers to SPEC-26. No extra radiff2 adapter or `comparison_*` tables are planned. The old issue's unimplemented checklist is not the current module boundary or proof of native qualification. |
| [#39 — Diaphora D0–D9](https://github.com/djshellshoxxx/patchtrace/issues/39) | Mode-A import, bounded SQLite reading, contracts/address/provenance checks, CLI/store and a unified Diaphora source exist (`src/patchtrace/diaphora/`, `unified/sources/diaphora.py`, their test families). The spec explicitly distinguishes synthetic layout assumptions from real Diaphora compatibility. Licensed export, external runner/GUI/patch-signal work and independent native accuracy/packaging gates cannot be marked complete from those imports. |
| [#104 — KB/CVE/KEV handoff](https://github.com/djshellshoxxx/patchtrace/issues/104) | `tests/test_kbc_kev_explain_export.py` now covers explain, Markdown export and preservation of stored JSON context despite catalog changes. The historical statement that this slice is absent is stale. Pilot/search exposure and labelled calibration still require their own scope/gate reconciliation; KEV remains context, not matching evidence. The comment's historical PR/CI states are not current-head acceptance. |
| [#105 — bug search](https://github.com/djshellshoxxx/patchtrace/issues/105) | See the detailed matrix below. Many old findings have dedicated retained regressions; E3/E4 are repaired here. Several later search/enrichment/pilot/build-environment findings still require bounded reproduction or a contract decision. |
| [#116 — GUI persistence/history](https://github.com/djshellshoxxx/patchtrace/issues/116) | Failed note/project/bookmark/finding saves have controls in `tests/test_ui.py`. Failed-create cleanup, redaction-copy qualification and stale inspection failures have `test_audit116_create_rollback.py`, `test_audit116_export_copy.py`, and `test_audit116_stale_inspection_failure.py`. The unsaved profile draft slice is a separate PR #319/#320 contribution, not established by this baseline's other GUI fixes. Native Windows and repeated Qt acceptance remain separate. |
| [#118 — KB/CVE/acquisition](https://github.com/djshellshoxxx/patchtrace/issues/118) | Saved scope, architecture and card-field provenance now have targeted coverage in `test_kbc_saved_scope_flow.py`, `test_kbc_resolver_architecture.py`, and `test_kbc_card_field_provenance.py`; malformed Winbindex rows have the hostile-entry suite. Planned index-pair identity remains a source-level residual: `service.acquire.import_current` still calls `import_pair`, which constructs `propose_manual`; the acquisition CLI test checks download plan/hash provenance but does not assert preservation of the original pair identity. No closure claim for this item. |
| [#120 — unified/adapters](https://github.com/djshellshoxxx/patchtrace/issues/120) | `test_unified_evidence_identity_20261101.py` covers manual abstention and content-bound manual/secondary identity; `test_secondary_alternative_identity_20261101.py` covers alternate-source/anchor consistency; `test_audit120_rzdiff_prep.py` covers cancellation/deadline during input copying. These current controls supersede the issue's historical lack of regression tests. Broader adapter/native acceptance belongs to the active adapter/integration owners. |
| [#121 — CI/security](https://github.com/djshellshoxxx/patchtrace/issues/121) | Partial, with important open boundaries detailed below. Source fixes and unit tests do not close the release/native acceptance or reproducibility findings. |
| [#255 — research qualification](https://github.com/djshellshoxxx/patchtrace/issues/255) | Receipt/model, stage-parser/performance-harness, adapter/parity and L1/scorerun modules/tests exist under `tools/research_qualification`. Batch 2 adds the shared facts admission guard. This does not complete Ghidriff profiling, native engine parity, ground-truth, calibration, controlled-environment or packaging experiments, and no unverified case is promoted by this batch. |

### Issue #105 finding dispositions

| Historical IDs | Current evidence / remaining disposition |
| --- | --- |
| KEV-1..3; ACQ-1..4 | Dedicated `test_kev_bugfixes_20261029.py` and `test_acquisition_hostile_20261029.py` cover future catalog dates, Markdown links, prune freshness, terminal controls, malformed siblings, date validation and callback cleanup. These cover the reported slices; they are not universal concurrency/network assurance. |
| KBC-1..11 and KBC-13 | `test_kbc_bugfixes_20261029.py` explicitly covers malformed remediations, work caps, strict scope JSON, repair/sidecar failures, timestamp ordering, Unicode digits, XML close events, pair prefixes, control separators, relative newer-schema stores and distinct scope counts. |
| KBC-12 | The distinction between a requested superseded revision and active evidence still needs an explicit user-facing status decision. Existing supersession exclusions must not be removed merely to turn the historical query into a hit. |
| STR-1..4, PE-1..3, CODE-1 | `test_binary_parsers_bugfixes_20261029.py` covers the duplicate-string, scanner/link work, typed text decoding/display limits, chunked directory reading, null name RVA, section crossing and comment-state cases. The separate PE-1 relocation RSS concern is not closed by chunked reads. |
| RULE-1..7, CG-1..3 | `test_rules_cg_bugfixes_20261029.py` contains controls for ordered cache targets, decision order, pre-write export validation, corrupt sidecars, deep JSON, FIFO/byte caps, diff work, successor budgets, numeric suffixes and capped-export disclosure. |
| S4..7, P1, B1/B2 | `test_search_pilot_buildenv_bugfixes_20261111.py` retains the address/cursor error, signature phrase/exclusion, whole-ID, invalid review-time, provenance newline and report-line-cap controls. |
| S1..3 | Still require targeted replay of `enr_r3_finding_pairing.py`, `enr_r4_rva_poison.py`, `enr_r6_hostile_ids.py` and `enr_r17_negative_addr.py`. Current `_Run.pairing`, `_rva` and `function_ref` retain the relevant direct subject/address construction paths; this audit does not mark them fixed. |
| S8/S9 | Current fuzzy counterpart matching still performs reciprocal nearest searches, and `name_words` applies its word cap after splitting names. Retain the bounded performance investigations; no slow historical timings are represented as newly measured here. |
| E1/E2 | The absurd manifest-size rejection has `test_enrichment_cache.py::test_absurd_manifest_size_is_corrupt_not_a_crash`. That does not close E2: `pipeline.load_default/load_profile` still consume derived body structure and need the specific missing-stage/non-object/corrupt-row replays. |
| E3/E4 | Reproduced and repaired in this batch, including UTC representability, Decimal exception typing, exact tenths, caller-context independence and public CLI behavior. |
| E5 | The current SPEC-07 explicitly keeps merged `feature_ids=()` and discards file-imported feature claims until a curated attributed source/versioned identity exists. Treat this as documented semantics, not a reason to restore unverified feature credit. |
| E6 | The historical altered-CVE fixture now fails its snapshot digest check. That is not proof the Unicode-digit contract concern is resolved; the model pattern still uses `\d`. A valid identity-bound fixture is required for further adjudication. |
| E7/E8/E9 | The existing WIL large-site control is useful but does not establish every historical gate-scan/signals worst case. The WIL/signals performance probes and address grammar remain separate retained work; no new timing claim or blanket closure. |
| N1/N2 | The old N2 finding records a typed `PT-NWAY-INPUT` repair. N1 terminal-safe names still needs its specific CLI replay. This batch does not change the nway owner's paths. |
| P2 | Current service documentation and `test_pilot_ranking.py::test_a_context_keeps_500_leads_and_200_queue_rows_and_counts_the_rest` explicitly count omitted rows per context. Do not silently reinterpret this as a count of unique functions; any presentation change needs that distinction. |
| P3/P4 | `counts_line` still omits queue-only counts, and `Explainer.explain` still truncates the assembled explanation from the tail; pairing names are sliced to three. Preserve these presentation findings for focused controls rather than declaring the normal footer assertion sufficient. |
| B3/B4 | `compute_delta` can still derive toolchain changes before applying comparability, and timeline `_hop` opens a pair path without the series pair-identity validation used by nway. These source-level residuals need their specific authored replays; they were not changed here. |

The historical comments labelled some additional ideas unconfirmed (for example
reserved profile names, highlight offsets and name demangling). They remain
unconfirmed; this report does not convert them into bugs or completed work.

### Issue #121 boundaries

| Finding | Current disposition |
| --- | --- |
| Release dependencies | `qa-windows.yml` now requires `qt-gate` for release. Its `needs` list still does not establish an exact-head dependency on every separate native acceptance workflow. Partial repair, not a complete release gate. |
| Backup byte integrity | `test_verified_backup_byte_integrity.py` covers same-size/restored-mtime corruption, public-save history preservation and repeat observation. A cached metadata verdict is not the current sole authority. |
| Child environment default | Baseline `BackendConfig.restrict_env` remains false. The restricted-by-default source/actual-child controls are separate PR #319/#320 work; do not claim them integrated at this baseline. |
| Diaphora deadlines | `test_diaphora_deadline.py` covers fixed query deadlines and per-row cancellation. It does not, by itself, close every importer peak-RSS concern. |
| Verified artifact reads | Current `artifact_bytes.py` uses content verification in addition to cheap stat hints, with `test_artifact_bytes.py::test_in_place_edit_with_restored_mtime_is_detected`. Linux or authored controls are not a new native Windows result. |
| Native seeding | `live-backend.yml` still resets the upstream seed invocation's exit code; the intentionally negative cached-PDB reproduction is distinct. Preserve the setup-state verification concern. |
| Toolchain reproducibility | Floating dependency/action/runner choices are not resolved by the installer asset-note recovery or this parser patch. |
| Primary backend resource caps | The primary `run_process` call still needs its separately qualified memory/output policy; existing subprocess support for caps does not prove that every caller enables them. |
| Historical four CI failures | Those records belong to the issue's old SHA. Current focused tests and other heads' green jobs cannot rewrite their result or certify the combined candidate. |
| Navigation iterator work | `NavResult.ambiguous` still traverses the entire iterable to count it while retaining only 20 items. The retained-memory test does not impose a work/time bound. |

## Durable receipts

Raw input snapshots and run receipts are retained in the task workspace;
verification files are under `verification/`. These hashes identify the exact
evidence without duplicating large issue bodies or the frozen branch inventory.

| File | SHA-256 |
| --- | --- |
| `issues-all.json` | `7635efeb973c867c6339947993cbe0e2c475ec5b8c6e1d3bdbd3784423d00326` |
| `issue_105_comments.json` | `eb699219c35fd476f3c6fb6ffd16200b5239291362ebd051155cad204a407112` |
| `issue_116_comments.json` | `95a1ebbdba68fef8dae5718131c9ef4a543db881685230288641291454f75e8e` |
| `issue_118_comments.json` | `5b3a49416d5c097a0b4ffb1c0246e90cb5ba147302844b72adb7f94d68faebfc` |
| `issue_104_comments.json` | `51a34adc7471fc8cb03fce7012545137042c3d02359f0df6056d921d4cd7d29e` |
| `cve-numeric-red.log` | `c787b494c116a9295c2995413b06fa3e76958c5aa74475aa6703a3f3f2e8248c` |
| `cve-numeric-exact-red.log` | `16a8ea1f8398587c624dfb9fbb24a22a410528b17a56d25e96c55fdcddc6e462` |
| `cve-numeric-final.log` | `d13673ace2920189c5744f507ada8a399ab8f15681e1b0aba0cdad147f50bc1f` |
| `cve-numeric-final.xml` | `868235ee0b4b397d6581c2c1fce9eac7b4f60c93353885b58f10269d7256bef6` |
| `batch3-source-dispositions.json` | `9c00e582375b0504cb976f46b86098e9bb3107782a824911919302c0c61f20a8` |
