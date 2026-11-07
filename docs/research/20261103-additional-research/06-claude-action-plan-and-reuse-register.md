# Claude action plan and reuse decision register

Date: **2026-11-03, America/Vancouver**. Research synthesis only. The experiments and acceptance below **have not been performed by this research pass**. Source inspection is not runtime qualification, native Windows evidence or permission to ship a dependency. PatchTrace's [license](../../../LICENSE) is MIT, Circuit Drift Labs 2026; each reused component and dataset retains its own terms.

This plan consolidates [engine/runtime research](02-engine-runtime-reuse.md), [metadata/provenance research](03-metadata-provenance-reuse.md), [desktop/release research](04-desktop-persistence-release-reuse.md) and [corpus/calibration research](05-corpus-calibration-reproducibility.md). Those notes hold the detailed upstream evidence, limits and source paths. Avoid reopening their already implemented features as missing work.

## 1. Baseline, owners and execution order

Main inspected: **`b77d84e5decf736b031f0a24094001274de41178`**. The following are separate active draft/open snapshots, not main or acceptance credit:

| PR | Inspected head | Preserve ownership |
| --- | --- | --- |
| #173 | `93587a0c19c654cd003938ad780520340248a87e` | Tracker/integration repair; do not independently rewrite corrupt `tasks/todo.md`. |
| #174 | `b1411fb57774233ef909fabf4afab34ab4b67dff` | Native Rizin qualification, producer controls and Java probing. |
| #175 | `dabba4aea4ba0fa19e71ede05ce4fb8ab6741942` | Windows assets, executable metadata and packaging verification. |
| #176 | `db0a0b05d48e4c8fb394ec4e221677b5efb37954` | Investigation/project adoption, retained-output replay, preregistration and related GUI/report integration. |
| #177 | `07db4ffe5f321b3522fab7ef721ee4fd00936ea9` | Parallel QA and pip caching, observed at the final refresh; do not duplicate CI optimization. |

Recheck remote heads/checks before implementation; resolve ownership before editing shared files. Preserve existing automation associated with **#170/#171**; this plan does not launch, replace or reconfigure it. Proposed packets become implementation tasks only after the integration owner reconciles them with the current tracker. Read `AGENTS.md`, `CLAUDE.md`, `docs/modules.md` and the affected spec first; amend public contracts before code.

**Sequence:** first qualify current release paths (P01–P04), establish bounded conformance/receipts and lifecycle evidence (P05–P10), then expand development sources and calibration qualification (P11–P13). P14's license/source inventory accompanies every packet. P15 consumes the resulting exact assets. This ordering permits independent work without multiple owners rewriting the same adapter. No new scanner, scheduler, database framework, GUI framework or matching engine is proposed.

## 2. Concrete packets

### P01 — Qualify frozen Windows external-child DLL search

**Priority/owner:** release-critical experiment; #175 with `jobs.py` owner, coordinate #174. **Seam:** `_windows_process`, `_WINDOWS_SPAWN_LOCK`, existing child environment construction and frozen smoke. PyInstaller documents process DLL-directory inheritance separately from PATH/environment ([04 §6](04-desktop-persistence-release-reuse.md#6-windows-native-subprocess-containment-and-frozen-launch)).

Run an authored helper and harmless private dependency under source Python, frozen portable and installed application. Capture DLL search state, loaded dependency identity and exit/cleanup. **Accept:** explain observed behavior; only if a failure reproduces, snapshot/reset/create/restore within coordinated spawning, including errors, while retaining Job Object containment. Verify later Qt loads. An unexecuted static concern is not a confirmed bug.

### P02 — Bind extraction completion to retained GZF/IR evidence

**Priority/owner:** P1; extractor owner, coordinate #176 replay. **Seam:** `unified/extract/{ghidra_script,runner}.py`, extractor provenance and existing publication boundary. An analyzed/readable GZF alone is not a completion receipt ([02 §3](02-engine-runtime-reuse.md#3-pyghidra-qualify-the-existing-worker-rather-than-adopting-another-launcher)).

Specify additive binding of input/GZF digest, completed originating run, extractor/Ghidra/PyGhidra versions, symbols/options and resulting IR. **Accept:** cancellation during import, analysis, GZF write and decompilation cannot publish completed IR/cache state; prior completed evidence survives. Test with authored synthetic inputs on qualified runtimes. Keep the isolated process boundary and authoritative parent deadline.

### P03 — Isolate potentially mutating BinExport production

**Priority/owner:** P1; C3 producer owner. **Seam:** `secondary/binexport_{producer,snapshot,identity,pipeline,worker}.py`, existing BinDiff input binding. Pinned upstream builder can promote undefined functions and writes a volatile timestamp ([02 §4](02-engine-runtime-reuse.md#4-binexportbindiff-useful-reuse-is-producer-semantics-and-reproducibility-checks)).

Export a private program snapshot; retain authoritative originals and before/after function inventories. **Accept:** two exports preserve both raw hashes; any structural comparison states its ignored volatile fields; promotions/import omissions are accounted for; reversed/mismatched hashes fail binding. Build/qualify the extension against the selected Ghidra installation. Do not pool incompatible producer features or reinterpret all `call_target` edges as calls.

### P04 — Complete the existing Rizin qualification gate

**Priority/owner:** existing blocking work; **#174**, not a competing implementation. **Seam:** `secondary/rzdiff.py`, native probe fixtures and current producer/downstream refusal gates. Version text does not distinguish stock and patched builds ([02 §5](02-engine-runtime-reuse.md#5-rizin-version-compatibility-needs-a-qualified-producer-receipt)).

Bind executable/library or build-manifest identities, patch/source, options, ordered inputs, recovered inventory and native qualification. **Accept:** existing owner supplies distinct-byte/context controls across cardinalities/orientations, explicit unmatched partitions, production JSON and downstream refusal evidence. Crash/missing output is not an expected stock-red. Retain quarantine until the actual gates pass; no acceptance inferred from this research.

### P05 — Qualify CSAF conformance coverage offline

**Priority/owner:** P1; advisory validator owner. **Seam:** `intelligence/csaf/validate.py`, synthetic fixtures and declared `TESTS_NOT_IMPLEMENTED`. Adopt a pinned **development-only** Secvisogram oracle; select a fixed CSAF 2.0 schema/mandatory-test list, with network denied. The full preset includes network checks and is unsuitable for this offline gate ([03 §3](03-metadata-provenance-reuse.md#3-validation-reuse-without-changing-advisory-meaning)).

**Accept:** all selected-case disagreements resolve to standard/test intent or explicitly unsupported coverage; compare stable test IDs/pointers. Keep PatchTrace strict JSON/bounds/cancellation. Node remains outside desktop dependencies. Draft CSAF 2.1 requires its own future dialect contract.

### P06 — Add advisory verification observations without rewriting sources

**Priority/owner:** P1; advisory/store owner after P05 contract review. **Seam:** `intelligence/{contracts,storage}.py`, `csaf/{discovery,transport}.py`, KB source import/store. Reuse existing content-addressed storage ([03 §5](03-metadata-provenance-reuse.md#5-offline-import-separate-reproducibility-authenticity-and-freshness)).

Specify append-only receipts for source hash/length, transfer identity, parser/schema/policy, signature/verifier, accepted key identity and verification result/time. **Accept:** same raw bytes share evidence identity across retrievals but retain different observations; rejected imports preserve current views/history; offline replay opens no socket. A consented MSRC sidecar/key probe may remain blocked. Never promote TLS/hash consistency or a mirror's signature into Microsoft authenticity.

### P07 — Prove complete-project backup and publication

**Priority/owner:** P1; persistence owner, coordinate #176 lifecycle. **Seam:** `ProjectStore.backup` in `persistence.py`, `verified_backup.py`, referenced sidecars and existing backup tests ([04 §5](04-desktop-persistence-release-reuse.md#5-persistence-and-recovery-reuse-sqlite-test-project-closure)).

Inject faults through staged DB/sidecar copy and publication; reopen and resolve artifacts, raw outputs, derived evidence, reviews/history and exports. **Accept:** published destinations are complete, earlier evidence survives failure, collisions do not replace destinations, and restored-mtime corruption is detected. Record SQLite runtime/source ID and journal modes: **KB `WorkspaceStore` enables WAL; `ProjectStore` does not explicitly enable it.** This establishes no WAL-defect applicability without runtime/concurrency evidence.

### P08 — Close GUI model, settings and shutdown seams

**Priority/owner:** P1; GUI host/task owner, coordinate #176 table/project adoption. **Seam:** `gui/qt/{tasks,host,layout,table}.py`, `ui.py::closeEvent`. Keep current generation/channel/thread ownership. Use shipped `QAbstractItemModelTester`; surface bounded settings-sync failure and stuck-worker diagnostics ([04 §§3–4](04-desktop-persistence-release-reuse.md#4-modelview-and-asynchronous-lifetime)).

**Accept:** sort/reset/filter preserves stable selection; project switch plus late success/failure then close cannot mutate the replacement; stores close on their owning threads; destroyed widgets receive no callbacks. Keep atomic settings sync. Layout restore accepts only compatible application-generated state; checksum agreement is not authentication.

### P09 — Add independent LLVM PE/PDB identity evidence

**Priority/owner:** P1 developer qualification; symbol/PE owner. **Seam:** `symbols/pdbid.py`, `pe_overview`, `intelligence/csaf/identity.py`, existing symbol tests and `tools/calibration/tier_w/symbols_llvm.py`.

PDB mismatch tests and an LLVM symbol comparator already exist; do not recreate them as new features. Remaining experiment: a **version-qualified independent LLVM GUID/age/header oracle**, with raw outputs and disagreements ([02 §7](02-engine-runtime-reuse.md#7-llvm-object-reader-and-libabigail-reuse-independent-observations-not-a-replacement-matcher), [03 §6](03-metadata-provenance-reuse.md#6-static-pepdb-checks-and-non-github-implementation-evidence)). **Accept:** selected authored fields agree or carry explicit unsupported/conflict status; wrong age/GUID cannot match; no silent zero inventory on dialect drift. Qualify actual COFF output rather than assume an ELF-named JSON option guarantees a PE schema.

### P10 — Verify retained-result lifecycle through existing replay

**Priority/owner:** P1; **#176**. **Seam:** its unmerged `tools/calibration/tier_r/output_store.py`, replay credits/preregistration, project publication and reports. Extend the existing implementation rather than starting an output repository ([05 §§2,8](05-corpus-calibration-reproducibility.md#8-stateful-testing-of-retained-evidence)).

Use a small bounded state model: complete synthetic run, interrupted successor, close/reopen, export and backup restore. **Accept:** last committed result/evidence IDs survive; two projects never mix; abandoned attempts earn no completion credit; model-discovered failures become deterministic regressions. This is distinct from native engine qualification and preserves preregistered evaluation selection.

### P11 — Admit one reviewed non-GitHub source origin

**Priority/owner:** P2 after #176 contract coordination; corpus owner. **Seam:** `tools/calibration/tier_r/{contracts,fetch,manifest}.py`, SPEC-32/schema. Current GitHub-only URL shape and allowlist both constrain admission ([05 §4](05-corpus-calibration-reproducibility.md#4-non-github-corpus-origins-the-concrete-integration-barrier)).

Specify narrow `git-https` origin with exact approved host/full nested path, immutable commit, selected files and license digests. **Accept:** existing recipes remain compatible; one approved nested GitLab source imports deterministically; unapproved host, missing license or changed identity cannot admit a recipe. Preserve canonical origin versus mirror. Archive/Fossil support is deferred until needed; never coerce its identity into a Git SHA field or run upstream build scripts.

### P12 — Measure repeatability separately from comparison stability

**Priority/owner:** P2; corpus/build owner after P09. **Seam:** existing `tier_r/{build,toolchain,shard}.py` nuisance factory. Reprotest supplies variation ideas, not a replacement factory ([05 §5](05-corpus-calibration-reproducibility.md#5-reproducibility-reuse-experiment-design-without-replacing-the-factory)).

Produce two bounded reports over existing nuisances plus justified missing cases: same-input artifact repeatability and correspondence stability under declared variations. **Accept:** raw hashes/argv/environment/tool identities retained; timestamp/path/order/locale differences explained; normalized views have independent rules/identity. Optional local diffoscope diagnoses differences without supplying labels or uploading artifacts.

### P13 — Execute existing calibration oracles and preserve assumptions

**Priority/owner:** P1 development evidence; calibration owner, coordinate #176 preregistration. **Seam:** `tests/test_calibration_math.py`, optional `calibration-dev`, feature extraction/train/runtime parity ([05 §7](05-corpus-calibration-reproducibility.md#7-calibration-qualify-the-oracle-already-present)).

**Accept:** existing logistic/isotonic/sigmoid cross-checks actually execute without optional skips; versions, weights/tolerances and private-API dependency are recorded. Verify stored-run feature/missingness/producer parity. Group ancestry before splitting. Preserve the unresolved R5 assumptions gate and ordinal fallback; numerical agreement does not establish population risk guarantees. No serialized estimator dependency enters runtime.

### P14 — Maintain component/source/license evidence with every packet

**Priority/owner:** release prerequisite; integration/notices owner. **Seam:** existing dependency inventory, `third_party/notices`, corpus license admission and producer receipts. Record exact upstream revision/distribution, selected files, license/notice hashes, modifications, transitive/native components and fixture/data terms separately. See register below.

**Accept:** every newly shipped byte has attributable source/terms; inaccessible source and incomplete dependency closure are explicit blockers rather than assumed permissions. Match inventory to final artifacts after signing/packaging changes. Separate subprocesses do not exempt obligations. Reading a format differs from copying its implementation. Correct stale license catalogs from inspected source.

### P15 — Accept exact Windows portable and installer assets

**Priority/owner:** final release qualification; #175 with #174 native and #176 replay/investigation owners, after applicable packets. **Seam:** existing Windows builders, NSIS installer, frozen smoke and asset verifier ([04 §§8–9](04-desktop-persistence-release-reuse.md#8-packaging-installer-and-release-acceptance)).

On clean Windows without installed Python/Qt: launch, local import, authorized comparison, cancel, reopen, backup/restore, export, upgrade and uninstall. Include Unicode/long paths, locked files, monitor/DPI recovery and user files surviving uninstall. **Accept:** exact asset hashes, Windows/filesystem/runtime identity and observed per-case outcomes. Linux/offscreen/fake-engine success cannot close this gate. Preserve current unsigned prerelease policy and existing signing ownership.

## 3. Compact source, license and reuse register

**Adopt** means bounded existing API/development use; **adapt** means a small project-specific experiment or adapter; **reference** does not authorize code copying; **defer** means no dependency proposal. Detailed source evidence and qualifications remain in the linked sibling sections.

| Source / inspected anchor | License scope and inspection limits | Decision / packet |
| --- | --- | --- |
| Ghidra/PyGhidra 12.0.4, `e40ed130…` | Apache-2.0 source; distribution dependencies separate. [02 §2](02-engine-runtime-reuse.md#2-shortlist-revisions-and-reuse-decisions) | Adapt lifecycle P02; keep child isolation. |
| BinExport `9648cacb…` | Apache-2.0 with component notices; extension compatibility unqualified. [02 §4](02-engine-runtime-reuse.md#4-binexportbindiff-useful-reuse-is-producer-semantics-and-reproducibility-checks) | Adapt P03. |
| Rizin 0.9.1 `c3a90e92…` | Inspected matching/CLI files LGPL-3.0-only; whole patched distribution needs closure. [02 §5](02-engine-runtime-reuse.md#5-rizin-version-compatibility-needs-a-qualified-producer-receipt) | Existing-owner qualification P04. |
| Secvisogram 3.0.1 `6b03f603…` | Current LICENSE/package Apache-2.0; stale catalogs say MIT. [03 §2](03-metadata-provenance-reuse.md#2-reusable-implementations-and-verified-license-pins) | Adopt offline fixed-list dev oracle P05. |
| gocsaf `2c2095b7…` | Apache-2.0 project code; separate third-party/schema notices. [03 §5](03-metadata-provenance-reuse.md#5-offline-import-separate-reproducibility-authenticity-and-freshness) | Reference staging/signature behavior P06. |
| **MetaCPAN/CPAN CSAF 0.26** | Release LICENSE Artistic-2.0; POD wording discrepancy noted; source/test routines inspected. [03 §§2–3](03-metadata-provenance-reuse.md#3-validation-reuse-without-changing-advisory-meaning) | Reference independent validation/download cases P05–P06. |
| packageurl-python 0.17.6; CVE schema 5.2.0 | MIT parser; CC0-1.0 schema, not blanket advisory-data terms. [03 §4](03-metadata-provenance-reuse.md#4-productbuild-identity-and-source-revision-ambiguity) | Optional explicit identifier/schema support; no inferred Windows PURLs. |
| pefile 2024.8.26 at inspected HEAD | MIT; no replacement production parser justified. [03 §6](03-metadata-provenance-reuse.md#6-static-pepdb-checks-and-non-github-implementation-evidence) | Development comparator P09. |
| LLVM 20.1.8 tool source; selected binaries unqualified | Apache-2.0 WITH LLVM-exception; distribution inventory separate. [02 §7](02-engine-runtime-reuse.md#7-llvm-object-reader-and-libabigail-reuse-independent-observations-not-a-replacement-matcher) | Development generators/oracles P09/P12; no mandatory C++ runtime. |
| **Debian Sources/Salsa diffoscope 297+deb13u1** | Versioned presenter/model/runner inspected; GPL-3+ plus file/fixture exceptions. [02 §6](02-engine-runtime-reuse.md#6-diffoscope-a-substantive-non-github-report-format-reference) | Optional local diagnostic P12; defer display-only importer; no wrapper copying. |
| **Debian Sources/Salsa reprotest 0.7.30** | Inspected source/copyright: GPL-3+ overall with GPL-2+ portions. [05 §3](05-corpus-calibration-reproducibility.md#3-candidate-selection) | Adapt variation taxonomy P12; no bundled framework. |
| **Sourceware libabigail / Binutils** | libabigail docs/API license statement inspected; executable/release unknown. Current Binutils source unverified; historical patch license is not a distribution audit. [02 §7](02-engine-runtime-reuse.md#7-llvm-object-reader-and-libabigail-reuse-independent-observations-not-a-replacement-matcher), [03 §6](03-metadata-provenance-reuse.md#6-static-pepdb-checks-and-non-github-implementation-evidence) | Reference evidence/status/metadata contracts; defer ELF and bundling. |
| **Qt code.qt.io / KDE Invent / SQLite Fossil** | APIs/docs inspected, some exact source views blocked. Qt/KDE component terms need exact files; SQLite deliverable public-domain status excludes some build scripts. [04 §10](04-desktop-persistence-release-reuse.md#10-primary-source-ledger-and-exact-upstream-paths) | Existing APIs P07–P08; no KF6/code copying. |
| **SourceForge NSIS 3.13** / PyInstaller 6.22.3 | NSIS core/zlib versus compression/plugin terms separate; PyInstaller GPL exception component-specific. [04 §8](04-desktop-persistence-release-reuse.md#8-packaging-installer-and-release-acceptance) | Existing tooling P01/P14/P15. |
| scikit-learn / Hypothesis | BSD-3-Clause calibration source; MPL-2.0 test framework with exceptions. Docs versions are not executed versions. [05 §3](05-corpus-calibration-reproducibility.md#3-candidate-selection) | Existing optional dev use P10/P13. |
| python-tuf / in-toto / LIEF Extended / richer docking | Pins/terms vary; Extended artifact terms and docking distribution closure unverified. [03 §§2,5–6](03-metadata-provenance-reuse.md#5-offline-import-separate-reproducibility-authenticity-and-freshness), [04 §2](04-desktop-persistence-release-reuse.md#2-reuse-decisions) | Defer until a demonstrated distribution/format/UI requirement. |

Non-GitHub hosts above supply actual sources, APIs or documented tool contracts; they are not an instruction to bypass current admission rules. Heptapod provider-index source, some Salsa views, Codeberg and certain canonical raw views were inaccessible; keep those unknowns. Each implementation packet should publish **passed/failed/blocked** with commit, input/tool/output digests, declared coverage and remaining platform limits. Preserve raw evidence and prior results on failure; no claim of complete product acceptance follows from finishing this document.
