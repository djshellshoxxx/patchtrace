# PatchTrace branch consolidation — 2026-11-18

Baseline: `main` at `9c411ca3d7b47f950be5f0c6f01b3c54184554c6` (after #300). Integration head carried:
`codex/release-integration-20261116` (PR [#297](https://github.com/djshellshoxxx/patchtrace/pull/297)) at
`95db052a11cce162d2d633cae805f28119f783a1`. Consolidation branch: `claude/patchtraces-consolidation-trngn0`.
Supersedes the scope note of [branch-consolidation-20261114.md](branch-consolidation-20261114.md), which reviewed
only the first two inventory pages; this pass covers every remote branch.

Per-branch data (tip SHA, PR, category, whether it is safe to delete, reason):
[branch-disposition-20261118.tsv](branch-disposition-20261118.tsv). Owner-run archiver:
`tools/archive_branches.sh` (dry run by default).

## Method

1. Fetched all 299 remote branches (300 refs including `main`).
2. Ancestry: `git merge-base --is-ancestor` against `main` and against the #297 head.
3. Merge effect: `git merge-tree --write-tree main <branch>`; a result equal to `main`'s tree means the branch adds
   nothing ("superseded").
4. Content containment: for each unmerged branch, the non-trivial lines (8+ characters, whitespace-normalised) it
   adds relative to its fork point, checked against every text file of `main`, then of `main` merged with #297.
   52 branches predate the 2026-10-14 history squash (#57 root `0fb25d8e`) and share no merge base with `main`;
   their own commits were found as commits not reachable from any other pre-squash branch.
5. Five read-only review passes over the code-bearing residues (function-level comparison against `main` + #297),
   then my own check of each port: red test first where it was a bug, conflicts resolved by hand, focused and full
   test runs.

Containment is evidence that content exists, not proof of identical behaviour; every port below was re-tested.

## Result by category

| Category | Branches | Delete safe | Meaning |
|---|---:|---|---|
| merged-into-main | 102 | yes | tip is an ancestor of `main` |
| content-in-main | 90 | yes | ≥97% of added lines (or ≤20 lines absent) already in `main` |
| superseded | 12 | yes | merging changes no file of `main` |
| pre-squash-integrated | 14 | yes | pre-2026-10-14 history, integrated by the squash and evolved since |
| contained-in-kept-branch | 18 | yes | tip is an ancestor of a branch that is kept (chain intermediates) |
| close-pr-first | (13 of the rows above) | after closing the PR | an open draft PR still uses the branch |
| contained-in-#297 / content-in-#297 | 12 | after this PR merges | #290–#295, #298, #299, #283, #268 and #297 itself |
| partly-ported | 8 | no | useful parts ported here; a listed remainder stays |
| held | 35 | no | owner decision, research, docs or a behaviour change needing a spec |
| review | 8 | no | small doc/CI residues not reviewed in depth |
| this-consolidation | 1 | no | this branch |

223 branches are safe to archive now; with the 13 PR-bound and 12 post-merge branches, 248 of 299 can go.

## Ported in this consolidation

| Commit | Source (never merged) | What |
|---|---|---|
| merge of #297 | `codex/release-integration-20261116` | #290–#295, #298, #299, R7 prototypes, KEV/KB CLI, path fixes; its 36 hosted check runs on `95db052a` passed or were skipped (release, release-gate and the MSVC advisory are skipped on PRs) |
| `release: port offline prerelease verifier` | #289 `96fca172`, `3b501c04`, `a7bc728a` | `tools/verify_release.py` (A-I-2), stdlib/offline; asset names re-checked against `qa-windows.yml` |
| `test: port hostile-input parser fuzz harness` | #289 `928feceb`, `e9ad3fc8` | `tools/fuzz_parsers.py` over 11 untrusted-input parsers + non-gating nightly job |
| `fix(kb): keep a recorded search's document scope` | #176 `5984511c` (re-applied by hand) | #118 P1a: a scoped search no longer widens to the whole cache for leads, cards, pairs and the context bundle |
| `fix(unified): keep C literal types in canon/2 ...` | #144 `17210eb7`..`c592b680` | R8: `2147483648U`, `16L`, `0.1f`, octal no longer prove cosmetic; IR COS-PSEUDO needs EH-EQ (`canon` 2, `COS-PSEUDO/1` 3) |
| `jobs: refuse cmd.exe metacharacters ...` | #289 `0483db36` | Windows `.bat/.cmd` launch injection guard, env-block validation, Job flags |
| `search: port saved searches and recent queries` | `claude/instance-b-features` `06b26d83` | WB1 S7 pure stores; duplicate model replaced by the frozen contract |
| `representations: port RD-F03 ...` | #168 chain `953c0e9a`, `51a9b4af` | bounded raw-offset alignment core and Qt-free paired-row model (desktop wiring pending) |
| `fix(normalization): Ghidriff one-to-many abstains ...` | #289 `685ac689`, `f58f0029`, `5f2afa7d`, `9e852a42` (same work on #174) | SPEC-31 **A-32** (renumbered from A-28): a repeated upstream function abstains per group instead of failing the whole comparison (RB-01 lua pair); live rerun still open |
| `secondary: stop rz-diff stdout floods ...` | #289 `a1a98af4` | `max_output_bytes` on rz-diff runs; `PT-SECONDARY-LIMIT`; AST child-launch policy inventory test |
| `fix(bundle-acceptance): always write complete evidence ...` | #289 `0ad36225`, `3256c0d7` | evidence JSON always written, narrowed Windows deny, cleanup argv recorded |

## Held, with the reason (owner decisions marked)

* **Paid-API automation** (#167, #170, #171, #186) — *owner decision*: #170 and #171 run on a schedule and would spend
  API credit automatically; nothing merged.
* **Skills** (#61; `haiku/skills-manifest-import-20261027`) — *owner decision*: #61's Caveman skill is Apache-2.0 with
  NOTICE; the manifest import lists two CC-BY-SA-4.0 entries, a blocker for bundling.
* **Devcontainer** (#279, open, non-draft): small and self-contained; review on its own.
* **Remaining quarries**: #174 (rz-diff producer research workflow only), #289 (UE-R7 arbiter cut, BinDiff row caps,
  GUI accessibility and KB slices, Tier W runner), #144 (R2 D-32 corroboration witness + `matching/2`, a behaviour
  change), #168 chain (RD-F03 desktop controls, GUI creation-retry acceptance test), #176 (table header tooltips and
  keyboard sort; Alt+Up/Down collides with diff navigation), `instance-b-features` (call-graph ego layout, capa
  raw cache).
* **Docs and research** (#183, #129–#135, R1/R2 research branches): not imported; their numbers predate the merged
  unified-soundness and accuracy-program work and need a stale-claims review first.
* `claude/patchtrace-cli-dotpath-spec-er6hha`: keep; cited as CLI-DRAFT-05 by the spec-gaps audit.

## Open PRs the owner can close as superseded

After the consolidation PR merges: #290, #291, #292, #293, #294, #295 (all ancestors of #297), #297 itself, #283 and
#268 (content present), #282 (R7 recovered by #297). Already now: #281 and #78, #79, #82, #85, #86, #70 (content on
`main`), #139, #140, #141, #143, #164, #165 (intermediates contained in the kept #168 chain), #187 (superseded by
this record). Closing them is left to the owner; nothing was closed or deleted by this session.

## Archiving the branches

```bash
tools/archive_branches.sh docs/qa/branch-disposition-20261118.tsv
```

prints the plan. With `--apply` it re-checks that each branch still points at the recorded SHA (a moved branch is
skipped), pushes `archive/20261118/<branch>` at that SHA and deletes the branch. Restore with
`git push origin archive/20261118/<branch>:refs/heads/<branch>`. Rows marked `close-pr-first`, `after-merge`,
`review` or `no` are never touched.

## Verification limits

No Windows desktop, real binary pair, native Ghidra/Ghidriff run or manual GUI session was available. Local runs
used Linux, Python 3.13 and pytest-xdist (CI uses 3.12, serial). The Windows-only cases of the ported jobs.py tests
run only in `qa-windows`. Release acceptance gates from earlier records stay open.
