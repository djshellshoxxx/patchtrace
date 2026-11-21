# Cycle 2: four historical UI and tooling dispositions

This is a bounded semantic review against frozen source **`3cf7ad23f66611d6bbf3e4d08e10daa2715fd300`** (tree `60ed420c11116f1b92bdbedae34e3e82269458e5`). It changes documentation and retained evidence only. It does not qualify the entire candidate or authorize a branch merge or deletion.

The reviewed runtime behavior is already present or has been superseded by later implementations. Four pre-existing packaging/workflow acceptance gaps remain explicit expected failures. One useful historical evidence set was absent from the candidate: the accessibility donor's plan and two incomplete full-suite logs. Their exact original bytes are now retained in the receipt archive, separate from this run's results.

## Baselines and scope

The local `origin/main` observation was `fdc2696c23bdbfe7668348f25e3b336ce33039f7`. No remote fetch or mutation was performed by this worker. The independent worktree was clean before testing; its runtime/test source remained at the frozen commit throughout. The [machine-readable report](cycle2-historical-ui-review-20261121-2bad.json) records full source identities, donor commits, test receipts, scope limits, and executable follow-ups.

The [frozen branch census](branch-recovery-20261120-2bad.json), observed on 2026-11-20 at 23:27:34 UTC, classified 181 heads as unmatched and 16 as patch-equivalent with semantics unreviewed. Those branch-level numbers are **unchanged by this report**. Three selected heads came from the unmatched class; the build-environment presentation head came from the patch-equivalent class. All four are nonancestors of both the observed main and this candidate. These are selection facts, not evidence of missing behavior.

The prior `95fe` semantic dispositions and this coordinator's existing desktop, CLI-help, and saved-search work were read before selecting these scopes. This slice does not repeat their tooltip, file-overview, acquisition, core-storage, AI-report, offline-bundle, or project-rollback reviews. It excludes analysis/ranking/correlation changes, search matching semantics, target execution, and exploitation behavior.

| Historical head | Reviewed scope | Disposition |
|---|---|---|
| `codex/analyst-accessibility-20261109` at `b90a2cd49fa4ba71050a378abc753fe8c90733fd` | Files announcements/focus/retry and Export keyboard actions | Behavior present; later Files worker flow supersedes the donor flow. Historical incomplete acceptance evidence recovered into this receipt. |
| `audit/runtime` at `9f32a6ecbd056249373b82bc1e814bd938da8c70` | Cleanup/error translation, diagnostic redaction, bounded runtime discovery and dependency probe | Donor fixes present; later supervisor/discovery/redaction changes retained. |
| `codex/audit-2` at `08b12f1b279d917736cfc17d4b8e447c8f552616` | Hermetic packaging/workflow regression assertions and their audit documents | Donor tests retained and evolved. CODEX-1, CODEX-5, CODEX-6 and CODEX-14 remain incomplete gates. |
| `claude/bugfix-search-pilot-20261111` at `d1f7d9aa64b28c8a8ca0a1065bb88e1e2f15b7f0` | Build-environment provenance line breaks and report technical-section capacity only | Exact donor source and relevant tests present. Other changes in this head remain outside this review. |

## Semantic evidence

### Files and Export accessibility

The minimal implementation commits are `d153e573c233fd05c49cda8aabf9ec6043ad28bc` (Files) and `2129879202a95ee3bdecfcebee7d2847956cf4cd` (Export). The donor's `src/patchtrace/ui_export_v2.py`, `tests/test_ui_export_accessibility.py`, `tests/test_ui_export_v2.py`, and `docs/specs/accessibility-baseline.md` have exactly the same Git blobs as this candidate. `_FocusedButtonDefaults` and `_configure_keyboard` preserve the donor's focus-dependent button activation, native editing/Escape behavior, tab order, and option mnemonics. Visiting Write must not leave it as the default after focus moves elsewhere; the focused tests exercise that behavior, including hide/show and combo popup handling.

Every declaration from the donor's `ui_inspection.py` remains; 46 of its 55 declarations are AST-identical. This is navigation evidence, supplemented by reading the changed call paths and tests. `FilesController._announce_state`, `focus_target`, project reset and signing callbacks retain the donor behavior. The current inspection worker already produces metadata. `_start_signing` consumes that result instead of starting the donor's separate metadata worker on held input handles. Current refresh/status handling announces both stages, reports signing failure when inspection fails, and keeps a failed state until explicit retry. The existing regression suite retains each donor test and adds recovery after the failed worker's Qt object has been deleted. The appended Files implementation section in `docs/specs/gui-framework.md` records the current flow.

The donor's final acceptance commit `b90a2cd49fa4ba71050a378abc753fe8c90733fd` also contains a plan and two full-suite attempts missing from the candidate. The original plan explicitly calls both attempts incomplete: a parallel attempt was interrupted after workers exited, and a serial attempt reached its timeout. These original files are preserved under `historical-accessibility/` in the archive, with donor blob IDs and SHA-256 values in `historical-evidence-source-map.json`. They are not current failures, completed passes, or a reason to overwrite newer runtime code. Other donor help/task/QA document differences are not fully adjudicated here. Native Windows keyboard, NVDA/Narrator, DPI, and high-contrast acceptance remains outside the offscreen evidence.

### Runtime housekeeping and diagnostics

The reviewed donor changes are `b29267e8f72bfc7578c9e5014fdaeb54180c494d` and `9f32a6ecbd056249373b82bc1e814bd938da8c70`. `tests/test_audit_runtime.py` is byte-identical to the donor. Its preserved assertions exercise both commits, including crowded-root discovery, a dependency-probe warning preceding JSON, credential redaction, cleanup failure, unreadable output, and a post-kill wait timeout.

Current `_remove_scratch`, `_output_error`, and `_output_scan` are AST-identical to the donor. Cleanup retains the five-attempt retry bound and returns the remaining path without replacing the real run status. An unreadable output tree yields the fixed `output-check-failed` reason and a typed `PT-BACKEND` failure with retained evidence. Current `run_process` still converts a POSIX post-kill wait timeout into `PT-BACKEND: terminated child did not exit`; its final cleanup suppresses that same wait timeout so it cannot replace the primary error. Later progress and containment work remains intact.

The runtime discovery `_children` implementation is AST-identical: it filters names before applying the directory limit, preserving discovery in a crowded root without following directory symlinks. Later candidate tiers and bundle paths are kept. `_probe_backend` still parses the final output line after interpreter warnings. `redact_log` preserves the donor's quoted assignment, URL credential and token handling, while later source adds more credential forms and bounded-pattern protections. No older implementation should replace those newer guards. This review validates the historical regression assertions using authored fake runtimes; it does not qualify a real native backend or broaden target analysis.

### Packaging/workflow assertions

The test donor is `08b12f1b279d917736cfc17d4b8e447c8f552616`; its two audit-document dependencies are `ee21cfc86bd44b050c9861fe31b983c853a3ec9b` and `c6479cd5524986e0fb6be591d796407b6cac7986`. Both audit documents are byte-identical in the candidate. Every donor test/helper declaration from the two test files remains. Several former strict expected failures became ordinary assertions after later implementation changes: job budgets, workflow permissions, release-gate validation, pin/bound declarations, notice rows, nonempty license-copy sets, and manifest validation.

The current bundle-policy assertion has evolved from the donor's blanket scan to checking the explicit existing component policy and stripping rule. Passing it is evidence about repository policy checks, not a legal opinion or proof of owner approval. The original dated audit documents retain their historical status descriptions; the current test results below are the present observation.

Four strict expected failures are still active and failed as expected. Source inspection confirms each underlying gap: mutable remote Action tags remain; network `pip install` steps without hash enforcement remain; the corpus workflow skips verification when extracted runtime caches hit; and Linux packaging runs a narrow CLI-help check plus GUI self-tests, rather than the full `tools/frozen_smoke.py` command sweep. No donor implementation exists in this branch to cherry-pick for these fixes. Restoring duplicate tests would add no functionality.

### Build-environment report presentation

Only B1/B2 from `d1f7d9aa64b28c8a8ca0a1065bb88e1e2f15b7f0` are reviewed. `src/patchtrace/buildenv/report.py`, `src/patchtrace/buildenv/view_model.py`, and the donor regression file are byte-identical in this candidate. `provenance_block` sanitizes individual lines, joins them with actual line breaks, and bounds the final block. Markdown preserves those lines as separate entries. The technical section accepts 160 lines, matching up to 64 entries plus 16 anomalies for each of two sides. The two selected regressions check these exact presentation contracts. The other seven collected cases in that file were deliberately deselected; their presence is not a new search/pilot qualification.

## Checks performed on the frozen source

All four invocations used `/tmp/patchtrace-2bad-cycle2-venv/bin/python`, explicit worktree `PYTHONPATH`, `QT_QPA_PLATFORM=offscreen`, no bytecode, and pytest's cache provider disabled. The imported module path was verified as `/tmp/patchtrace-2bad-historical-ui-review/src/patchtrace/__init__.py`; the shared venv's editable project binding was not used to select source. Commands, exit codes, durations, complete logs, and JUnit files are retained in the archive.

| Existing selection | Result |
|---|---|
| `test_files_announcements.py`, `test_ui_export_accessibility.py` | 47 passed; 2 existing test-helper Qt deprecation warnings |
| `test_audit_runtime.py` | 17 passed |
| `test_codex_pkg_packaging.py`, `test_codex_pkg_workflows.py` | 20 passed; 4 strict expected failures: CODEX-14, CODEX-1, CODEX-5, CODEX-6 |
| `test_search_pilot_buildenv_bugfixes_20261111.py -k 'provenance_block or technical_section'` | 2 passed; 7 deselected |

This slice therefore records **86 passes and 4 expected failures**, with all four commands exiting zero. These counts are separate from other workers' overlapping tests. No aggregate suite, native screen reader, Windows packaging, real backend, release, or complete branch qualification is claimed. No runtime fix or mirrored regression-only test was added during the source freeze.

## Concrete continuation

The next useful implementation tasks come from the four retained gates, not from importing old runtime files. Each should start from the latest integration baseline and preserve the other gates until they independently pass.

| Gate | Files and dependency | Next executable task and qualification |
|---|---|---|
| CODEX-1 | `.github/workflows/*.yml`; `test_remote_actions_are_immutable` | Resolve each currently used Action version to its reviewed upstream full commit SHA, retain the version in a comment, and update workflow pins. Remove only this strict xfail after the assertion passes; run affected workflow qualification. Never invent or reuse an unverified SHA. |
| CODEX-5 | Workflow install steps, dependency/lock inputs; `test_pip_downloads_require_hashes` | Define platform-specific resolved build/runtime wheel closures, record artifact hashes, install through the hash-checked lock, then install the local project without dependency resolution. Exercise the actual supported build paths before claiming reproducibility; host packages remain a separate boundary. |
| CODEX-6 | `.github/workflows/corpus-tier-r.yml`; `test_corpus_cache_does_not_skip_verification` | Make cache restore perform the same pinned integrity check as a download, preferably by caching original archives and verifying before extraction. Validate cache-hit and cache-miss paths with controlled fixtures. Existing donor code supplies the regression, not a missing recovery patch. |
| CODEX-14 | `.github/workflows/qa-windows.yml`, `tools/build_linux.py`, `tools/frozen_smoke.py`; `test_linux_package_runs_full_cli_smoke` | Add the full registered CLI smoke to the unpacked Linux artifact's acceptance path, keeping existing offscreen/XCB GUI checks. Qualify the built artifact on supported Linux jobs, then remove this strict xfail. A successful GUI self-test alone does not close it. |

Before whole-branch disposition or deletion, review remaining donor docs/evidence and excluded changes, resolve historical assumptions against the current baseline, and use the coordinator's current census. This standalone report does not own or replace the authoritative engineering ledger.

## Retained receipt

[Evidence archive](evidence/cycle2-historical-ui-20261121-2bad/evidence.zip): 16 members, 17,110 bytes; SHA-256 `37ca4cecd85265177d539a53ff983e90bbb50011461892c0f51a4ccdafc94a6a`. It includes exact source comparisons, test receipts/logs/JUnit, source identity, the three original historical accessibility records, and an internal member hash manifest. ZIP integrity and every manifest digest were verified after writing. All donor branch refs are preserved.
