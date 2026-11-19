# PatchTrace feature and qualification matrix — 2026-11-19

This matrix distinguishes implemented product paths, reviewed continuation slices,
and their remaining acceptance gates. The starting main is
`fdc2696c23bdbfe7668348f25e3b336ce33039f7`; the local branch is
`codex/patchtrace-completion-20261119-81e4`. The accepted source/test checkpoint is `5aebd98f`, following runtime/dependency integration `5208c758`, with 859 tracked test files; evidence checkpoint `e430309a` preserves the receipts. The separate 856-file diagnostic retains its earlier source/dependencies.
The earlier remote checkpoint `bdc929ebd3c6aaa2563c758936beb315a10eeea0` was verified
to equal local `af8772bf`, tree `424709da5b590e68262ea0a11b8f98bb52da8d4b`;
it predates the later CSAF, CVE, golden-fixture and attempt-history repairs.
Draft PR #322 last published `2511301f`, tree `f2366be08a4951880692b56ecbbefbe92a3611dd`, equal to local `7093ee68`; its five new workflows were queued at that observation. It predates retention/Pydantic integration. A preserved source checkpoint does not qualify or merge the aggregate. Main remains `fdc2696c`, and no release is claimed.

## Status vocabulary

| Status | Meaning in this matrix |
| --- | --- |
| Complete | The specifically named scope is finished and its stated checks are evidenced. It does not extend to a broader feature or release. |
| Nearly complete | The named implementation exists and focused verification passes; an explicitly listed integration or acceptance gate remains. |
| Partial | Useful paths exist, but known functional scope or required evidence remains incomplete. |
| Broken | A confirmed behavior defect remains in the accepted scope; an unaccepted proposed repair does not close it. |
| Unintegrated | Retained work has not been accepted into the current candidate or main. |
| Blocked | Required qualification cannot presently be credited because its execution, input or prerequisite is missing or incomplete. |
| Deferred | Separate work is deliberately retained outside this continuation's active scope. |

No broad product capability below is marked Complete. Source/spec links establish
implemented mechanisms and intended contracts; they are not evidence of native
execution, achieved accuracy, or release acceptance. The [module index](../modules.md)
contains historical planned rows as well as later implementations, so current
source is checked alongside those descriptions.

## Existing core capabilities

| Capability | Status | Implemented paths and source/spec proof | Remaining scope or evidence |
| --- | --- | --- | --- |
| CVE/patch correlation and evidence | Partial | [KbService](../../src/patchtrace/kbcorrelation/service.py) joins stored advisory/product scope, pair context and provenance; [evidence resolution](../../src/patchtrace/evidence.py) retains exact references. [KB/CVE contract](../specs/kb-cve-correlation-and-acquisition.md) separates remediation, association and analyst assertions. | Frozen L1 still contains failures; source coverage and aggregate qualification remain open. Correlation does not prove which function fixes a CVE. |
| Version and binary-pair discovery | Partial | [Resolver](../../src/patchtrace/kbcorrelation/resolver.py), [manual pairs](../../src/patchtrace/kbcorrelation/pairs.py) and [pair-search spec](../specs/kb-patch-search-and-pair-resolution.md) support indexed candidates, explicit product scope, verified local bytes and oriented pair creation. | Manual chronology/fix boundaries remain unverified without source evidence; missing older/Server-only index coverage is explicit. Production acquisition and native package handling require their own receipts. |
| PE metadata and byte inspection | Nearly complete | [Artifact inspection](../../src/patchtrace/artifact_inspection.py), [metadata](../../src/patchtrace/pe_overview/metadata.py), [cache store](../../src/patchtrace/pe_overview/cache_store.py) and [SPEC-51](../specs/pe-version-authenticode.md) provide verified-byte header/version/manifest/signature facts and offline cache reuse. | Portable/offscreen tests pass for the reviewed slice; native catalog/WinVerifyTrust and aggregate qualification remain open. |
| Function diff and structural comparison | Partial | [Normalization](../../src/patchtrace/normalization.py), [alignment](../../src/patchtrace/alignment.py), [unified pipeline](../../src/patchtrace/unified/pipeline.py) and [matching contract](../specs/unified-engine/04-matching-pipeline.md) support function pairs, ambiguity/one-sided observations, bounded text alignment and IR matching. | Real-tool completion, cross-platform qualification and independent real-project accuracy must be demonstrated separately. A missing or partial producer result is not a correct negative. |
| Similarity and corroboration | Partial | [Matching ladder](../../src/patchtrace/unified/ladder/engine.py), [fusion arbiter](../../src/patchtrace/unified/fusion/arbiter.py) and [fusion/noise contract](../specs/unified-engine/05-fusion-and-noise.md) implement structural/residual matching, source provenance, contested outcomes and conservative evidence classes. | Native percentages and correlated sources cannot be treated as independent proof; per-pass real-IR precision and L2/L3 evidence remain open. |
| Change significance and triage | Partial | [Signal detectors](../../src/patchtrace/enrichment/signals.py), [attention ranking](../../src/patchtrace/enrichment/ranking.py), [pilot ranking](../../src/patchtrace/pilot/ranking.py) and [enrichment spec](../specs/enrichment.md) implement deterministic grouped signals and ordinal triage. | This is implemented prioritization, not calibrated vulnerability likelihood. Mechanism claims retain the [evidence obligations](../specs/kb-cve/31-E-evidence-intent.md); the numeric CVE repair has focused checks but still needs aggregate qualification. |
| History, recorded runs and comparisons | Partial | [Persistence](../../src/patchtrace/persistence.py) retains validated revisions/backups; [project CLI](../../src/patchtrace/project_cli.py) lists runs; [compare CLI](../../src/patchtrace/compare_cli.py) records new pair analyses; [series spec](../specs/series-window.md) covers multi-build pair chains. | These paths establish stored run history, pair reruns and series views. A general run-to-run result-comparison capability is not established by those interfaces, and broader lifecycle/native acceptance remains open. |
| Reproducibility, reports and export | Partial | [Unified keys](../../src/patchtrace/unified/keys.py), [reports](../../src/patchtrace/reports.py), [report/2 export](../../src/patchtrace/report2/export.py) and [report contract](../specs/report-export-contract-v2.md) retain content identity, provenance, unknowns and escaped JSON/Markdown/HTML output. | Reproducible storage does not establish reproducible external tool output. Forced strings-export ownership races and no-clobber/empty-export metadata gaps remain explicit below. |
| GUI and CLI workflows | Partial | [Desktop](../../src/patchtrace/ui.py), [GUI host](../../src/patchtrace/gui/qt/host.py), [CLI registry](../../src/patchtrace/cli_commands/__init__.py), [project/compare contract](../specs/cli-project-compare.md) and [GUI framework](../specs/gui-framework.md) expose project, inspection, evidence and export paths over service APIs. | Offscreen/hermetic controls do not complete real desktop, accessibility, native runtime or clean-machine acceptance. The aggregate run is incomplete. |
| Engine and evidence adapters | Partial | [Secondary engines](../../src/patchtrace/secondary/registry.py), [Diaphora service](../../src/patchtrace/diaphora/service.py), [unified sources](../../src/patchtrace/unified/sources/__init__.py) and [adapter contract](../specs/unified-engine/06-adapters.md) preserve external evidence and declared limitations. | Recent text-boundary fixes pass portable controls; live BinDiff/Rizin/other producer compatibility, pins and native execution remain separate gates. |

## Reviewed continuation slices and active defects

| Scope | Status | Observed implementation/evidence | Remaining gate or limit |
| --- | --- | --- | --- |
| Frozen branch census | Complete | [Inventory](BRANCH_INVENTORY.md), observed `2026-11-19T10:34:16.394Z`: 320 heads including main, 309 PR records, every fetched head classified. | Complete only for that snapshot; 139 branches still need semantic review. Later PR320/321 are outside these frozen counts. |
| N-way path failures | Nearly complete | `24064cf6`: resolve/stat failures yield fixed per-pair unreadable reasons and preserve healthy hops; 11 red on base, then 85 passed in 21.76s. [Spec](../specs/series-window.md). | Aggregate and hosted/native qualification. |
| Installer receipt | Nearly complete | Recovery `20b54521`, root port `ef9167d2`: Setup size/SHA-256 included; 5 passed in 3.07s. [Recovery](RECOVERED_WORK.md). | Broader historical workflow scope retained; receipt tests do not build or install a package. |
| Winbindex/BinDiff parser integrity | Nearly complete | Chain ending `baf95fcd`, local merge `7610aeaa`: raw byte budgets, integer-key identity and virtual/shadow-table refusal; 29 red/4 green on base, corrected 107 passed, final 432 passed/1 Windows skip in 61.86s. [Receipt](parser-integrity-20261119.md). | Aggregate/native/live-feed qualification; classifier-unavailable paths refuse input. |
| SPEC-51 cache and signing UI | Nearly complete | `0bc41f6b` / `6bf57557`: owner-thread store, existing inspection worker, fresh hashing on hits, cancellation/corruption guards and truthful partial UI; 840 passed/2 Windows skips in 60.27s; peer 16 passed in 2.15s. [Spec](../specs/pe-version-authenticode.md). | Native trust and aggregate qualification; cache facts never supply OS trust. |
| Research facts admission | Nearly complete | `d87af037` / `69fa6b8b`: only `facts: verified` enters ranking; 11 red, 33 focused passes, final scoped/callers 140 passed in 4.59s. [Receipt](RECOVERY_BATCH_2.md). | Aggregate qualification; no real manifest facts or accuracy results were changed. |
| BinExport2/rz-diff text boundaries | Nearly complete | `d4bb5efb` / `af8772bf`: remaining BinExport2 text fields validate and rz-diff text failures stay within its typed adapter contract. Final affected selection: 414 passed in 87.86s. [BinExport spec](../specs/binexport2-support.md), [secondary spec](../specs/secondary-engine.md). | Local authored-fixture evidence; no new live producer/native acceptance. |
| CSAF malformed redirects | Nearly complete | Local correction maps malformed redirect URL failures to the typed refusal while closing the response and avoiding cache publication; 4 failed/6 passed before correction, then 33 passed in 1.08s. [Transport](../../src/patchtrace/intelligence/csaf/transport.py), [CSAF spec](../specs/csaf-cve-interpretation-engine.md). | Reviewed and integrated at `0a4bb12e`; aggregate qualification remains pending. No live MSRC claim follows. |
| CVE numeric/time integrity | Nearly complete | `93c9e395` / `a4d6dd9b`: typed decimal/UTC failures, exact CVSS tenths and caller-context independence; initial 20 failures/10 controls, 10 further exactness failures, final 124 passed in 6.70s. [Recovery](RECOVERY_BATCH_3.md). | Aggregate/native qualification remains separate; no new CVE accuracy evidence is claimed. |
| Evidence attempt-history diagnostics | Nearly complete | `254190a0` / `520b524b`: baseline 12 failed/8 passed, recovered 79 passed, two real post-write failures, final 81 passed in 37.33s. [Recovery](RECOVERED_WORK.md). | Generic exceptions say "Attempt storage unconfirmed"; returned ownership refusals can say not saved. The bounded Phase 6 correction addresses the demonstrated malformed-row cause; publication remains non-atomic. |
| Approved acquisition plan/product binding | Nearly complete | Recovery `5131bd94`, merge `d7842532`; approved scope and exact staged hashes checked before mutation, source/local pair binding retained. 255 affected and 55 integrated checks pass. [Report](RECOVERY_BATCH_5.md). | Full index proposal/window/source-entry persistence and final-head/native qualification remain open; manual grade B/tier E and unverified fix boundary remain. |
| Attempt-retention integrity | Nearly complete | `74d5f4bb` / `153f6cea`: bounded strict record admission, fail-closed engine-run eviction, explicit protection and null-safe cap accounting. 175 affected passes and independent NULL/BLOB preservation. [Batch 6](RECOVERY_BATCH_6.md). | No atomic-save or universal corrupt-database claim; concurrent mutation/aggregate hostile-DB budgets and final-head acceptance remain separate. |
| Pydantic advisory repair | Nearly complete | `b28f6971` / `5208c758`: 2.14.2/core 2.50.2 clears four assessed upstream ranges; 2,903 passes/1 existing strict xfail across 79 files, 301 unchanged schemas across 16 generators. [Qualification](PYDANTIC_SECURITY_UPGRADE_20261119.md). | Final-head/native Windows gates remain; zero automated results miss known old-pin advisories and do not prove a clean dependency closure. |
| Native Qt remediation | Blocked | Qt 6.12.0 matches seven assessed native advisory ranges. Official 6.12.1 binding wheels unavailable at retrieval; 6.11.3 is not a complete fix. [Audit](DEPENDENCY_ADVISORY_AUDIT_20261119.md). | Qualify a supported patched artifact or evidenced disposition; bounded source scan does not prove unreachability or a frozen-artifact SBOM. |
| Supplemental source/tools review | Partial | Fresh source scan at `5208c758`: 64 findings, no normalized additions/removals versus `520b524b`; configured Ruff passes. [Static record](STATIC_AUDIT.md). | Separate 70 tools findings require review; source dispositions do not classify all 134 combined findings. |
| Backup-test lifetime correction | Nearly complete | `5aebd98f`: 3 passes/3 teardown errors before correction, then 41 affected passes in 2.62s. Test-only fault scope; assertions preserved. [Harness report](TEST_HARNESS_FIXES_20261119.md). | Frozen errors remain recorded; external AF_UNIX EPERM and full current-head qualification remain open. |
| Forced strings-export ownership | Broken | Retained PR319 audit records source substitution and OSError cleanup races in [strings export](../../src/patchtrace/strings/export.py). | Current-source reproduction and ownership-safe publication/cleanup remain required; the cancellation repair is a separate boundary. |
| Other strings export gaps | Partial | Existing exports need race-safe no-clobber behavior and compatible document-level extraction/truncation/redaction metadata, including empty exports. | Separate compatible implementation and regressions; see [prior review](../qa/branch-consolidation-20261118.md). |
| Historical contributions and broad candidates | Unintegrated | 139 branches retained for semantic review; broad PR316/318 holds remain. Later PR320 `188b4962` and PR321 `976dddfb` remain separate retained observations. | No blanket adoption, supersession, branch deletion or main integration. [Promotion log](MAIN_MERGE_LOG.md). |
| Experimental automation and broader research | Deferred | Inventory retains experimental/research branches and excluded portions of recovered sources. | Separate scope, review and acceptance; no activation is implied. |

## Qualification boundaries

| Gate | Status | Current evidence and required next result |
| --- | --- | --- |
| Full aggregate suite | Blocked | Frozen 856-file diagnostic reached all files in 59 terminal processes and FAILED: 23,110 passed, 139 skipped, 6 xfailed, 4 failed, 8 teardown errors. Later `5208c758` passed 254 affected checks and test-only `5aebd98f` passed 41; no full current-859-file or unsplit pass. [Actual results](TEST_RESULTS.md). |
| Hosted aggregate and main promotion | Blocked | Draft PR #322 last observed at `2511301f` with five queued workflows; later accepted source needs publication and its own checks. Main remains `fdc2696c`; no main merge or release. |
| Native PE trust | Blocked | Real catalog/WinVerifyTrust acceptance remains open; `--trust cache|online` remains blocked. Portable metadata and skipped Windows tests do not qualify native trust. |
| Windows delivery and manual use | Blocked | Native standalone/portable/installer, clean-machine, manual desktop and accessibility acceptance require source-pinned receipts. An installer hash row is not execution evidence. |
| L1 advisory joins | Partial | Preserve frozen `f69614fa`: 73 PASS, 6 FAIL, 8 excluded. Source/expectation corrections require explicit versioning; no new successful L1 result is established here. |
| L2 open-source pair diff | Blocked | Independent-project evidence and real producer compatibility remain required. Authored tests and corpus tooling cannot establish achieved accuracy. |
| L3 real Windows pairs | Blocked | Verified function labels, real artifacts and completed native receipts remain required; unverified facts cannot be scored. |

L1/L2/L3 are separate accuracy claims, distinct from the unified engine's internal
layer names. See [accuracy handoff](../plans/accuracy-program-handoff-20261107.md)
and [frozen L1 evidence](../qa/search-anchor-integration-20261118.md). Slice test
counts overlap and are not an aggregate count. The [test record](TEST_RESULTS.md),
[remaining work](REMAINING_WORK.md) and [handoff](HANDOFF.md) retain broader gates;
this matrix records the newer interrupted-run/source status without rewriting
older receipts or claiming unobserved acceptance.
