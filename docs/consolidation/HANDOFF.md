# Consolidation handoff

## Authoritative state

- Repository: `https://github.com/djshellshoxxx/patchtrace`.
- Integration branch: `integration/exhaustive-patchtrace-consolidation-20261119`.
- Draft PR: [#320](https://github.com/djshellshoxxx/patchtrace/pull/320).
- Recorded code: `7e610c03043b4d2b3ba4893b133993fd7b020109`, tree
  `3a77280f87714329e7f89339762b84250e1e52e7`. This record accompanies a subsequent
  evidence/documentation checkpoint.
- Prior verified remote: `1341dc217b32081b3a9652642106d8680deba8a3`, tree
  `39402d93f3a704dbcf841175dc52c9c695d182f2`, exactly equal to local `65043fe8`.
  Source backup: `checkpoint/exhaustive-local-source-65043fe8`.
- Earlier remote/local equivalences: `087f50aa`/`bb4f8310`,
  `bc7eb632`/`11bc7014`, `188b4962`/`edb6f20f`. The first remote checkpoint
  preserves both original recovery-stack parents.
- Observed main remains `fdc2696c23bdbfe7668348f25e3b336ce33039f7`.
  No default-branch merge, release or deployment occurred.

## Completed recovery

The candidate retains reviewed #319 and all #316/#318 work, with eleven original
conflicts resolved. It adds bounded Calls layout, SQLite/export/input/runner
ownership, managed Tier-R transfer, accessible controls, research workflows,
Tier-W offline review/report/hidden execution, Search/shared stored sources,
Strings parity/source selection and normalized provenance, strict saved fetch
plans and bounded transport, version observations, and creation lifecycle repair.

After remote `1341dc21`, reviewed code adds explicit incomplete-project retry
with repaired stage ownership, a saved-plan executor with digest-bound PDB
receipts, packaged build records with corrected exact Git-root attribution,
production PE metadata cache/worker integration, and seven typed/bounded parser
corrections. `RECOVERED_WORK.md` maps exact source and integrated commits.

The refreshed census records 323 branches, 312 PRs and 59 tags; all 415 distinct
recorded targets resolve locally. Supplemental records are committed as
`4966840b`. The original census/semantic decisions remain frozen. New #321/#322
and the advanced #319 are preserved and reviewed in isolated snapshots.

## Active isolated work

| Worktree | Current scope |
|---|---|
| `PatchTrace` | Integration authority, source-bound verification, durable records and guarded publication. Code is fixed at 7e610c03 while this checkpoint is prepared. |
| `pt-adapters` | Bounded analyst journey gate and fetch CLI independent review. Journey b7aa97f5/1f13d0bf has a reproduced Git index-flag source-admission blocker under repair. |
| `pt-security` | Fetch CLI 883cc6b7 plus typed home-path follow-up b8bf47a1 is independently approved and awaits integration. Reproduced BinDiff parser/digest and preservation ownership repair is active. |
| `pt-inventory` | New-head semantic recovery; frozen BinDiff schema/key slice 8a3a4255 is independently approved. Facts gate 708f07e4 awaits independent review; selected-series-root path follow-up continues. |

Only immutable reviewed snapshots may be integrated. Preserve later unreviewed
worktree edits. BinDiff schema/key acceptance does not waive its separately
reproduced pathname/hash-to-SQLite binding defect. The historical native-receipt
converter remains excluded after demonstrated source/digest false-PASS cases.

## Verification and open gates

Recent integrated results: retry/lifecycle 74 passed; saved executor/plan/schema/
offline CLI 179 passed; cache/Qt/retry 85 passed; parser boundaries plus current
executor 191 passed. Producer adjacent controls passed 233; Git-root correction
passed 70 and independently 43. Counts overlap and remain source-scoped.

An actual Linux PyInstaller 6.22.3 consumer probe at 7e610c03 passed exact record
round-trip and modified-metadata refusal in 7.99 seconds. Qt/UI were excluded;
this is not a full desktop or Windows package. Earlier real Rizin 0.9.1 control
on 087f50aa's tree produced 30 matches. Both have retained source/tree/digest
records and separate qualification limits.

Frozen broad QA at 7dfba50f attempted 953 files: 26,106 disjoint completed cases
contain 25,943 passes, 150 skips, three expected failures, nine later-fixed KEV
errors and one host-denied AF_UNIX failure. Three 60k benchmark cases were killed
without results. Complete attempts and coverage rules are archived; do not
restart completed groups or relabel that source as current qualification.

Normal full Ruff passes at 7e610c03. Strict source security still fails with 80
findings (a different set from earlier same-count observations). Installed Linux
dev audit previously found zero advisories across 32 distributions; fresh profiles
and native platforms remain separate. Latest inspected 1341dc21 CI snapshot has
28 queued and three skipped checks, with no passing acceptance evidence yet.

Open gates include final-source complete QA, strict security, actual native/
platform/package/dependency acceptance, real-data accuracy, remaining semantic
recovery and Linux force publication's final source-name race. Main merge is
not qualified.

## Durable source history and resume commands

`evidence/local-source-history-through-7e610c03.bundle` preserves recorded local
source commits and intermediate history omitted by metadata-equivalent REST
publication. Its adjacent JSON records hashes, heads and required prerequisites.
The archive does not imply acceptance of rejected intermediate implementations.
Fetch the public integration history before importing it into a fresh checkout.

```bash
cd /workspace/scratch/792fd5ca6555/PatchTrace
git status --short
git log -15 --oneline
git worktree list
git fetch origin
git rev-parse HEAD origin/integration/exhaustive-patchtrace-consolidation-20261119
git bundle verify docs/consolidation/evidence/local-source-history-through-7e610c03.bundle
git bundle list-heads docs/consolidation/evidence/local-source-history-through-7e610c03.bundle
# Fresh checkout only, if recorded local source objects are absent:
git fetch docs/consolidation/evidence/local-source-history-through-7e610c03.bundle 'refs/heads/checkpoint/*:refs/remotes/recovered/*'
QT_QPA_PLATFORM=offscreen PYTHONPATH=src ../.venv/bin/python -m pytest -q tests/test_tier_w_fetch_execute.py tests/test_project_retry_recovery.py
../.venv/bin/python -m ruff check src tests tools
```

The actual virtualenv is persistent at `/workspace/scratch/792fd5ca6555/.venv`.
Three host interruptions lost home/tmp state but preserved workspace Git. Do not
remove other tasks' data or modify hardlinked immutable archives in place.

## Guarded publication

Pin the clean local documentation commit. Compare its tree with the observed
remote 1341dc21, upload changed blobs, construct the tree and require exact SHA
equality with local `HEAD^{tree}`. Create a child of the observed remote head;
update only this integration ref using expected_sha and force=false. Read back
ref/tree/parents, update draft #320 and preserve the original local source branch
before aligning equivalent metadata. Never move the ref to a partial tree.

Continue safe independent work while platform gates are blocked. No semantic
exhaustion or unattended future continuation is claimed.
