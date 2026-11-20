# Generation 1 handoff: verified narrow repairs

Repository: https://github.com/djshellshoxxx/patchtrace

Integration branch: `codex/maximum-completion-20261119-4c8d`.
Generation 1 code checkpoint: `afa1af3c`.
Starting candidate: PR #322, `f2458aae22ea6177be64cfc2fb439a79950f00ff`.
Main at discovery: `fdc2696c23bdbfe7668348f25e3b336ce33039f7`.

The [master directive](master-directive.md) preserves the owner's authorized
scope. The [reference inventory](../engineering/consolidation-inventory.json)
and [human handoff](../engineering/consolidation-inventory.md) contain 323 branch
heads, 312 PR heads, and 59 tags/releases. All referenced Git objects were fetched.
154 branches still require semantic review; unmatched commits do not establish
missing behavior, and ancestry does not prove later behavioral preservation.

## Accepted work

| Task | Integration evidence | Original failure and resulting behavior |
|---|---|---|
| Manifest DTD recovery | `0ac15cbc`; independent review in `f5807559` | Eight recovered cases fail on #322. Parser-level doctype refusal handles hidden UTF-16 declarations and the pure-Python fallback. |
| Metadata-cache invalidation | `0ac15cbc` | A real persisted v2 row bypasses the recovered parser. Cache version 3 reparses verified bytes and preserves historical rows. Together, 249 focused tests pass; four independent controls include 126 parser variants. |
| WinPairs URL boundary | `40a1f976`, integrated through `1f18fb9a` | 39 failing controls demonstrate raw URL normalization, malformed authority and typed-error gaps. The corrected affected selection has 153 passes and two native Windows skips. |
| WinPairs HTTP boundary | `afa1af3c`, source `6a778ebe` | Independent review finds nine malformed HTTP open/read/CLI failures. Catching `HTTPException` preserves redacted diagnostics, response closure and the healthy side. 162 affected passes/two native skips; coordinator replay 97 passes/two skips. |
| Strings publication | `c9fd0779`, source `88a82576` | Extracted unique PR #320 improvements while retaining newer #322 anchor guards. Anonymous staging, held directories, bounded byte checks, Windows native replacement and owned cleanup have 264 affected passes/three native skips. Independent coordinator replay: 105 passes/three skips plus symlink/empty-export/cleanup controls. |

Test selections overlap and must not be summed. Reports and immutable baseline
failures are under `docs/engineering/`. The candidate has not been promoted to
main, released, or declared fully qualified.

## CI work completed

PR #322's cancelled Linux rz-diff job was cancelled during MinGW package
installation before producing a receipt. A targeted retry succeeded. The fresh
28-check snapshot now has 26 successes and two intentionally skipped release
gates. These are check records, including repeated native names, not test counts.
Downloaded Linux and Windows Rizin 0.9.1 receipts both say `status: passed`,
`mocked: false`, with no engine errors. Artifact ZIP SHA-256 values match the
GitHub metadata. JSON receipts are retained in `../engineering/evidence/`.
This qualifies only the earlier head/merge reference, not this new code.

## Started successor generations

- Generation 2 profile worker: recover dirty-profile Save/Discard/Cancel and
  preserve drafts on validation/storage/destination failures. Candidate
  `31052db` awaits independent qualification review before integration.
- Generation 2 saved-search worker: recover missing saved-query GUI/CLI flows
  from #310/#319, preserving existing contracts and current security fixes.
- Generation 3 qualification worker: fresh official Qt release evidence,
  independent profile review, and newly integrated security boundaries.
- Generation 3 raw-alignment worker: recover the absent paired-offset desktop
  controller, including worker cancellation, stale results and original-byte copy.

These workers were actually started. Their later results supersede this activity
snapshot; consult the newest handoff and task ledger before assuming ownership.

## Remaining blockers and continuation order

1. Linux forced export still has a final named-source substitution interval.
   Foreign bytes may become visible before postcondition refusal. The regression
   preserves this outcome; no rollback or complete ownership claim is made.
2. Native Windows publication acceptance, Windows packages/trust, manual desktop
   and accessibility gates remain separate from Linux/offscreen tests.
3. Native Qt advisory remediation remains open. Fresh official PyPI records at
   23:40:56 UTC still list 6.12.0 and no 6.12.1 files. Vendor version matches do
   not establish reachable exploitation in PatchTrace.
4. Complete independent review and integration of current successor work, then
   run the exact final-source aggregate suite, lint and relevant schemas.
5. Continue semantic recovery of retained branches. Saved inventories/acquisition
   provenance and empty CSV extraction metadata remain unfinished scopes.
6. Keep L1/L2/L3 accuracy evidence separate. Never score `facts: unverified`.

## Resuming

Fetch all branches, tags and pull heads. Compare current refs with the inventory
and this exact code checkpoint. Read the latest task ledger, claim an isolated
scope, and revalidate uniqueness before editing. The prepared interpreter for
this session is `/workspace/scratch/4c8dc848d760/venv/bin/python`; an enduring
successor must recreate dependencies from repository declarations if absent.
Do not modify other active workspaces or reuse stale interpreter paths blindly.

```sh
QT_QPA_PLATFORM=offscreen python -m pytest -q
python -m ruff check src tests tools
python -m pip check
```

The individual reports provide bounded reproductions. Only an exact-head,
reviewed candidate with applicable checks green and no blocking findings is
eligible for a guarded REST merge. Do not publish a release automatically.
