# Generations 2–8: workflow completion and independent reassessment

Repository: <https://github.com/djshellshoxxx/PatchTrace>.
Integration branch: `codex/maximum-completion-20261119-4c8d`.
Starting PR #322: `f2458aae22ea6177be64cfc2fb439a79950f00ff`.
Main at discovery: `fdc2696c23bdbfe7668348f25e3b336ce33039f7`.

Reviewed combined runtime/test checkpoint:
`bffcfa99d6a5044024256edbc0457ab20c92cbae`.
The required unsplit aggregate was started from a separate clean, detached
worktree at this exact commit. Its terminal result, publication mapping and
successor state belong in [task-ledger.json](../engineering/task-ledger.json)
and the aggregate receipt; do not infer a pass from a started run.

## Integrated work and evidence

| Scope | Reviewed source | Result |
|---|---|---|
| Profiles drafts | `31052db31054590c75c6c636c2ac49cc934f0668` | Save/Discard/Cancel and failed destination rollback; 221 affected passes plus six independent controls. |
| Saved Search | `f632e50655b47a71aff314cdba941641356d16a3` | GUI/CLI save/list/run/delete, six matching modes and owner/build guards; 961 affected passes plus five independent controls covering 60 query/mode combinations. |
| Paired raw offsets | `46afcb216ef2b9430ce95b32e00944e7eaaa99ac` | Bounded Hex/Binary alignment, cancellation, navigation and original-byte copy; 191 affected passes plus six independent real-task/project-adoption and copy controls. |
| Accuracy reporting | `776695170bc0a526951075e3744bcc684035cfcc` | Single layer/stratum/holdout cohorts; repeated/missing-project bounds withheld; L3 per-stratum reporting; 495 affected passes/three skips plus 48 independent controls. |
| CSV metadata | `9308cef64592a5a7e7d7fb051cffa68464277c31` | Versioned metadata preamble followed by unchanged finding table; 575 affected passes/one native skip. Independent reader/runtime review is retained separately. |
| ASM diagnostics | Donor `4c96c483295e8a43ea58ab8c5689f8c9eb40de4d`; extraction `ef6f7a33` | Unchanged production lexer and strict 150 ms gate; all five timings now survive a failure. Two unsupported optimizations were rejected. |

Generation 1 also repaired manifest DTD admission and persisted-cache reuse,
WinPairs URL/HTTP errors, and part of Strings publication ownership. Each report
under `docs/engineering/` records the original defect, unique source comparison,
changed files, implementation SHA, commands, red/green results and limits.
Independent review reports and raw controls accompany the accepted work.
Selections overlap and must not be summed into an aggregate test count.

CSV now uses `strings-export-csv/2`; header-first consumers need the documented
migration. Empty exports retain metadata and zero finding rows. JSON output and
publication routines remain unchanged. Independent review preserved a real
large-metadata reader-example failure; its correction is documentation only.

## Duplicates, retained branches and feature status

The frozen census covers 323 branch heads, 312 PR heads and 59 tags/releases:
one main baseline, 128 main-ancestry heads, two candidate-ancestry heads,
16 patch-equivalent heads, 17 research/docs, five experimental and 154 requiring
semantic review. Individual names and comparisons are in the machine inventory.
Ancestry is not proof that later code preserves all behavior. The independently
published ASM branch appeared after this snapshot.

Profiles/Search were extracted narrowly instead of importing broad #319. The
inspected Search code was identical at #310/#319. Raw navigation imported only
the #309/#319 seam, preserving newer cache/inspection paths. Strings publication
retained #322 anchor guards absent from its broad donor. All reachable aggregate
scorer versions inspected lacked the new accuracy repair. CSV audits found five
source variants with the same metadata-losing formatter. No broad PR was closed
or declared wholly superseded, and no remote branch was deleted.

The [current feature inventory](../engineering/feature-status-20261119.json)
covers CVE correlation, binary comparison, adapters, Winbindex, persistence,
GUI/CLI, reports, performance and release gates. Its broader capabilities remain
partial or blocked. The older `docs/consolidation/FEATURE_MATRIX.md` remains a
historical Phase 7 record, not a claim about this newer source.

## Test, CI and performance state

The dedicated Python 3.12 environment contains declared dev dependencies plus
site extras, scikit-learn and psutil. psutil was added after the accuracy
worker's historical three-skip run; that receipt still correctly contains two
native Windows skips and one optional measurement skip. Sixteen schema
generators completed without drift before the final plain-report encoding
change; the CSV worker also regenerated the unchanged Strings schemas.

Original harness failures are retained and distinguished from product defects:
the reviewer used invalid Search syntax `is:changed`, and a lightweight raw-view
test owner lacked the new invalidation dependency. Neither correction weakens
the existing assertions. The full suite retains the unchanged timing gates.

Earlier PR #322 has 26 successful check records and two intentional release
skips after a targeted Linux rz-diff retry. The cancelled job stopped during
MinGW installation before a receipt. Actual Linux/Windows Rizin 0.9.1 fixture
receipts and matching ZIP digests are retained. They qualify that earlier
source and authored fixture only, not the new candidate or general accuracy.

The ASM report preserves the original 0.156169465-second failure and later
exact hosted passes. No cause is inferred from host load or GC; no runtime
speedup is claimed. Current combined qualification is recorded separately.

## Open defects, security findings and release blockers

See the separate [release assessment](../engineering/release-readiness-20261119.md).
The final Linux forced-source substitution interval remains reproduced: foreign
bytes can become visible before postcondition refusal. Native Windows held-source
acceptance, PE trust, clean-machine/manual desktop and accessibility, supported
Qt remediation/disposition and final-source native receipts remain separate.
Official binding release evidence still lacks 6.12.1 wheels; advisory version
matches alone do not prove application exploitability.

L1/L2/L3 remain separate empirical claims. Frozen L1 remains 73 pass, six fail,
eight excluded. Reporting repairs do not promote facts, replace ground truth or
establish a new accuracy result. L2/L3 still need independently established
labels, sufficient independent projects and real producer evidence.

## Ownership, conflicts and next priorities

No unresolved integration conflict exists at the combined checkpoint. Root owns
aggregate qualification, publication and scheduling. The ledger gives actual
worker/successor state; historical agent mentions are not active assignments.
Before overlapping work, reconcile current ownership and remote branch changes.

1. Fix concrete combined-suite failures without discarding the original run.
2. Close or precisely disposition the final Linux forced-publication interval.
3. Obtain a supported patched Qt artifact or component-specific disposition,
   then source-pinned native Windows/package/trust/manual acceptance.
4. Complete index proposal/window/source-entry persistence; preserve the
   approved-plan/product binding already repaired.
5. Continue the 154-head semantic-review queue with behavioral proof, and
   obtain verified layer-specific accuracy evidence under frozen protocols.

## Resume commands

Use the current remote candidate in the ledger. Recreate dependencies from
repository declarations if this session's interpreter is gone. Never blindly
reuse old absolute worktree paths.

```sh
git fetch origin --tags '+refs/heads/*:refs/remotes/origin/*'
git fetch origin '+refs/pull/*/head:refs/remotes/pull/*'
python -m pip install --only-binary=:all: -e '.[dev,search,rules]'
python -m pip install --only-binary=:all: -r tools/site/requirements.txt 'scikit-learn>=1.5,<2' psutil
QT_QPA_PLATFORM=offscreen python -m pytest -q --junitxml=qa-results.xml
python -m ruff check src tests tools
python -m pip check
```

Keep raw full-suite logs and JUnit on failure. Publish with verified local/remote
tree equality. Merge only with all applicable checks green, no blockers and a
fresh expected-head REST guard. Do not automatically publish a release. Update
this index, the ledger and the next generation's handoff after each cycle.
