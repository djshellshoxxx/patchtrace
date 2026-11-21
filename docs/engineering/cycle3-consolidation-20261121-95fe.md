# Cycle 3 consolidation and source qualification

Captured after 05:03 UTC on 21 November 2026. The machine authority is [task-ledger.json](task-ledger.json); previous dated reports retain their own source boundaries.

## Result and source

The isolated candidate combines CODEX-14 Linux frozen CLI acceptance, CODEX-6 original-archive cache verification and authored Bash fixtures, and a Pages push-head deployment opt-out. The application `src/` tree equals PR #348; `tools/frozen_smoke.py` has only a module-docstring change, with runtime AST equality verified. Three workflow files and five maintained test files change. No target binaries were executed.

Tested local commit: `e5a531668ef523cd6faa26d5fec59aa552749134`; complete tree: `e622ff8f5624ce73bac63c0976af01c614ce05bb`. Base PR #348: `6b6fcd3597a604212032ffc453477aeb6edc69ff`. Publication is planned on `integration/patchtrace-20261121-95fe-c3` as an ordinary main-integration PR. Its final documentation tree and REST commit mapping belong in the PR body; new-source CI is still required.

## Implemented and reviewed

| Scope | Concrete change | Review and boundary |
| --- | --- | --- |
| Linux frozen CLI / CODEX-14 | Invoke the existing full CLI harness against the checksum-verified extracted executable on both Ubuntu versions; preserve both Qt probes | Independent spec and standards reviews; source tests pass; real new-source frozen runs pending |
| Archive cache / CODEX-6 | Cache original rizin/Ghidra archives under new namespaces and verify their pinned digest before cleanup/extraction on every applicable run | Independent spec/standards reviews and actual-workflow authored Bash fixtures pass; hosted cache restore/save and Ghidriff path remain separate |
| Cache-test repair | Use the actual full rizin step name; require the original workflow to pass before each of14 negative mutations | Preserved baseline1 failure/29 passes/2xfails; repaired30 passes/2xfails; no vacuous negative controls |
| Lint | Remove two extra import separators and one obsolete pytest import | Original Ruff failures retained; whole-tree Ruff now passes |
| Pages control | Skip only deploy on push-head `[no deploy]`; preserve manual dispatch, build/test/artifact flow and permissions | Contract precedes source; independent reviews; original missing-condition regression fails; no deployment exercised |
| Records and recovery | Recover six required indexes and 14 linked documents/evidence files omitted by sibling reconciliation | All20 original Git blobs verified at recovery; original failed runs, nine historical semantic dispositions and code bundle retained |

## Verification

The clean combined source completed **458 passed, 11 skipped, 2 xfailed** across14 maintained files. All11 skips were solely missing declared site-tool dependencies. After installing pinned Pillow 12.3.0 and segno 1.6.6, exactly those11 identities passed on the same clean source. There are **469 distinct passing identities**, zero remaining skips in this selection, and the two unchanged CODEX-1/CODEX-5 expected failures. This is a bounded selection, not a full-suite result. Author/peer selections overlap and are not added.

Whole-tree Ruff, dependency validation, isolated-interpreter source binding and patch whitespace checks passed. The isolated import was observed at pre-Pages commit `487e0811` in the same dedicated checkout; the `src/` tree is unchanged through tested `e5a53166`. Final tests, Ruff and dependency receipts are clean at `e5a53166`. Nine workflow/test/tool blob comparisons equal their independently reviewed sources. All raw logs/JUnit and source receipts are preserved in [the evidence archive](evidence/cycle3-95fe/cycle3-evidence.zip); the [qualification record](evidence/cycle3-95fe/qualification.json) retains exact identities and counts.

## Baseline hosted qualification

The independent REST audit found every current non-release check on PR #345–348 successful. PR #348's synthetic merge `8b29d4d4` and head `6b6fcd35` share complete tree `9cb2ba74b088dfce7d87d37403108bcd3aa05326`. Linux:24,043 passed/53 skipped/6 xfailed; Windows:23,916 passed/181 skipped/5 xfailed. Qt/native/package checks passed on that source. The two platform counts overlap and are not summed. They do not qualify the new workflow source.

PR #345's original NSIS package-feed HTTP503 remains retained. Its single already-requested retry and downstream jobs passed; no further retry was needed. Prior local SIGKILLs remain unexplained interrupted runs; later hosted success does not rewrite them. [Exact hosted evidence](evidence/cycle3-95fe/hosted-qualification.md).

## Inventory and remaining acceptance

The fully paginated 04:55:49–04:57:48 UTC snapshot contains364 branches and338 PRs:82 open,172 merged, 84 closed-unmerged. Ten branch names were added relative to the recovered354-branch cycle95fe snapshot; none moved or disappeared. This is a reference census, not exhaustive semantic equivalence or live-worker ownership. [Census](evidence/cycle3-95fe/inventory-report.md).

New-source full Linux/Windows, Qt/native/package and both frozen Linux CLI results remain required. Preserve the CODEX-6 real cache-hit/Ghidriff acceptance boundary, CODEX-1/5, manual Windows/trust/accessibility, native Qt advisory disposition, raw index/entry membership, historical semantic review and separate L1/L2/L3 evidence gates. No new empirical accuracy or release-readiness claim is made.

A qualified main merge requires fresh head/base/check review and the REST expected-head guard. Its **actual resulting merge commit** must contain **`[no release] [no deploy]`**. PR titles or ancestor messages alone do not control the resulting push. Both publishing operations remain unauthorized; the markers preserve QA and Actions artifacts. The [publication audit](evidence/cycle3-95fe/release-side-effects.md) and [Pages contract](../specs/pages-deployment-control.md) explain the boundary. No main merge, release, deployment, branch deletion or force-push has occurred in this checkpoint.
