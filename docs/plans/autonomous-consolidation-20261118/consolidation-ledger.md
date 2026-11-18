# Autonomous consolidation ledger — 2026-11-18

## Decision and scope

The priority chain is preserved by actual commit ancestry. Consolidation into canonical `main` remains blocked by qualification, not by a missing ancestry link. No merge, PR closure, branch deletion, history rewrite, tag or release is performed by this inventory worker.

This is a fresh complete mechanical inventory of all 307 live branch tips and 297 PR records. It includes merge bases, nonmerge patch IDs, changed-file projections and merge-conflict previews. It is **not an exhaustive semantic review of every historical implementation**. Unresolved behavior is explicitly retained for scoped review. The current CI/review worker owns fresh acceptance checks; historical checks in older ledgers are not current approval.

## Exact references

| Role | SHA |
|---|---|
| Canonical main | `9c411ca3d7b47f950be5f0c6f01b3c54184554c6` |
| PR #304 | `75ffee3840894adb52aff7f3df28043cc8e832ba` |
| PR #307 candidate | `1418617a80d6057de11f985488cfe6043a7787a2` |
| REST snapshot observation | `2026-11-18T13:50:56.954Z` |

Every branch, PR association and exact source tip is recorded in [branch-inventory.json](branch-inventory.json). The feature matrix is [one directory above](../patchtrace-completion-matrix.md). All counts below belong to this snapshot; subsequent changes require a dated append.

## Required ancestry verified

| Source PR | Source tip | Target PR | Result |
|---|---|---|---|
| #297 | `95db052a11cce162d2d633cae805f28119f783a1` | #304 | Exact source is ancestor; merge base equals source |
| #301 | `faddea300daf4058d38d24ff04a270be6f3d832b` | #304 | Exact source is ancestor; merge base equals source |
| #302 | `121ffb0bcdd6af4f24e5035389d4709dffddf263` | #304 | Exact source is ancestor; merge base equals source |
| #305 | `16ab88b0626ef05700c4199e926103932312e5c7` | #304 | Exact source is ancestor; merge base equals source |
| #306 | `f6ef1528c15b2281ee7b6f32625d02a5211c926d` | #304 | Exact source is ancestor; merge base equals source |
| #303 | `2b697222b34359bb46adc90aad69fd0a12708601` | #307 | Exact source is ancestor; merge base equals source |
| #304 | `75ffee3840894adb52aff7f3df28043cc8e832ba` | #307 | Exact source is ancestor; merge base equals source |

PR #307 remains stacked on the #304 branch. Qualify and merge #304 to `main` first; then retarget #307, recompute its effective base/tree and qualify the actual candidate before merging. Never merge #307 into the topic branch as a substitute for canonical integration. The seven ancestry checks above do not establish product correctness or hosted qualification.

## Inventory and conservative disposition

| Measurement | Count |
|---|---:|
| Live remote branches, including main | 307 |
| Topic branches | 306 |
| PR records, all states | 297 |
| Open / closed PRs | 54 / 243 |
| Topic tips already reachable from main | 113 |
| Topic tips reachable from #307 | 129 |
| Additional tips in candidate but not main | 16 |
| Other tips without unmatched nonmerge patches | 16 |
| Tips with unmatched nonmerge patch evidence | 161 |
| Clean / conflicting topic merge previews against main | 164 / 142 |

The 161 unmatched-patch branches are not 161 missing features. Squashed, selectively ported, reverted and evolved changes can retain unmatched patch IDs. A clean merge is not a correctness result. An all-path projection match is a useful review lead, not authorization to close a PR.

| Classification | Topics | Meaning |
|---|---:|
| `already_incorporated` | 113 | Exact tip is reachable from recorded main. |
| `blocked_by_qualification` | 16 | Exact tip is in #307 but not main; fresh required gates and independent review remain. |
| `documentation_only` | 25 | Remaining differences within the branch change footprint are documentation; original branches can also contain already-matching code. Historical claims need review. |
| `needs_reconciliation` | 131 | Residual patches or dependencies have no complete current semantic disposition. This includes six tips whose entire changed-path projection matches candidate but whose behavior is not independently certified. |
| `research_only_or_quarantined` | 15 | Research/native evidence, development environment, skill imports or paid automation are outside automatic production adoption. |
| `valuable_but_incomplete` | 6 | Known selective recovery leaves documented production/UI/research residue. |

No branch is labelled a safe integration candidate solely because it merges cleanly. No new superseded declaration is made from similarity or patch IDs. All 306 topic branches retain their remote names and history.

## Highest-priority residue and narrow port decisions

| Source | Fresh evidence / retained work | Action |
|---|---|
| #304/#307 chain | Exact sources and all required ancestry above preserved. Production and research receipts remain separate. | Complete actual-head qualification first; keep `[no release]` in guarded REST merge messages. |
| #168 at `b304034e3c310528f7e0a3206eda48c94e0a6873` | Core `raw_alignment_view.py` and `representations/alignment.py` exist in #307; source `ui_raw_alignment.py` does not. #139/#140/#141/#143/#164/#165 are historical intermediates retained in #168. | Review/adapt only the current-contract desktop wiring and lifecycle tests. Do not replace current native ownership refusals with historical producer experiments. |
| #164/#165/#168 | Source-only paths additionally include `project_creation.py`, `project_retry.py`, `ui_new_project.py`, `gui/qt/kb_selftest.py` and `kbcorrelation/adapters/panel_snapshot.py`. | Missing filenames are review leads, not proof of missing functionality. Compare with existing project services, retry and panel ownership before any port. |
| `claude/instance-b-features` | `search/saved.py` backend store is in #307; no saved-store reference was found in current search Qt/CLI wiring. Historical layout/raw-cache scope remains. | Complete documented saved/recent-query user flow through existing stores; review graph-layout/capa-cache residue separately. |
| #176 | Search document-scope fix is already selectively recovered. Keyboard sorting/header help remains historically unresolved against current Alt+Up/Down navigation and accessibility work. | Review exact event ownership and current keyboard contracts before a focused UI port. |
| #144 | Typed-literal safety was recovered; R2 corroboration and `matching/2` residue are not thereby certified. | Preserve uncertainty and require current contract/tests before independent integration. |
| #174/#289 | One-to-many abstention, bounded output and other core fixes are recovered. #289 still contains source-only `gui/access_names.py`, `search/wiring.py`, `strings/compose.py` and `ui_inspection_session.py`. | Review behavior rather than copying missing paths. Current services can already provide parts of the old scope. |
| Strings export on #307 | `strings/export.py` checks existence before unconditionally using `os.replace`; task tracker already lists no-clobber publication and export metadata as unfinished. | Root/security worker should reproduce a concurrent destination creation, fix with regression proof, and obtain independent review. Inventory worker has not reproduced exploitability. |
| #268/#281/#282/#283 | Earlier scoped port reviews are preserved in `docs/qa/branch-consolidation-20261118.md`; source heads have not changed. | Refresh relevant file/hunk/behavior proof against qualified main before closure. An ancestor of the old replacement does not by itself transfer the old semantic review to later edits. |
| #70/#78/#79/#82/#85/#86 | Historical help, output persistence, recipe controls, preregistration and decompilation code have selective successor implementations. | Continue source-to-current behavior mapping; neither branch age nor test similarity establishes full supersession. |
| #279, paid automation and skill imports | Development/native fixture changes and third-party/paid workflow scope remain outside production chain. | Preserve refs, review separately; do not activate paid external automation. |

## All currently open PRs

The table records fresh source identity and mechanical review state. Main/candidate columns indicate exact ancestry, not equivalence. `+N` is unmatched nonmerge patches relative to #307. Current check results and inline-thread resolution were not refreshed by this inventory worker; REST review/comment state and actual-head CI must be rechecked before every merge or closure. The complete all-state PR list is in the JSON artifact.

| PR | Head SHA | Main / candidate ancestry | Unmatched patches | Merge preview to main | Disposition / scope |
|---|---|---|---:|---|---|
| [#61](https://github.com/djshellshoxxx/patchtrace/pull/61) | `4467d1f3c6e113a7da808a67e8dee9d4aa5083d8` | no / no | 1 | conflict | `research_only_or_quarantined` — Add Caveman and PatchTrace agent skills with spec-first workflow (SPEC-56) |
| [#68](https://github.com/djshellshoxxx/patchtrace/pull/68) | `b7a0f0a45d2de1462367d877b7386091b4d275ce` | no / no | 25 | clean | `research_only_or_quarantined` — Corpus batch 1: 24 candidate recipes and continuation plan |
| [#70](https://github.com/djshellshoxxx/patchtrace/pull/70) | `e5bee6fe157c90a40f2d9f458768e2169ce123e5` | no / no | 25 | conflict | `documentation_only` — docs: add first 25 Prompt 5 help topics |
| [#72](https://github.com/djshellshoxxx/patchtrace/pull/72) | `cfd7cfff52f4f9b8b1264e8b7d70ef1bbef2d63f` | no / no | 10 | clean | `documentation_only` — docs: specify Program E panels and coordinated build plan |
| [#78](https://github.com/djshellshoxxx/patchtrace/pull/78) | `2019a37fa65fc37f4758469143c2daadc07e0098` | no / no | 33 | conflict | `needs_reconciliation` — LBL-31: persist Tier R engine outputs and transfer verified training artifacts |
| [#79](https://github.com/djshellshoxxx/patchtrace/pull/79) | `9513bc05229dd7a8460fc229d7420154d61498db` | no / no | 36 | conflict | `needs_reconciliation` — LBL-32: run pinned recipe-card A/A and noise controls on both sides |
| [#82](https://github.com/djshellshoxxx/patchtrace/pull/82) | `eaa30013794a9bd0fedc9ec34bbe374d6db0cfc9` | no / no | 51 | conflict | `needs_reconciliation` — LBL-32: two-sided recipe A/A and noise cases in Tier R planner |
| [#85](https://github.com/djshellshoxxx/patchtrace/pull/85) | `6ae2c079e6cafa2b7bd5396cac443cd34ba7138a` | no / no | 43 | conflict | `needs_reconciliation` — LBL-30: verify preregistration and enforce single-use final training |
| [#86](https://github.com/djshellshoxxx/patchtrace/pull/86) | `ebbd621d4f557905892aee5f7cf8cb7b0e2addc2` | no / no | 11 | conflict | `needs_reconciliation` — UE-R3: persist bounded on-demand Ghidra C into unified result sidecars |
| [#98](https://github.com/djshellshoxxx/patchtrace/pull/98) | `ad8fbe9f2f041653760c02e9d18a91a66dd11c39` | no / no | 1 | clean | `documentation_only` — Add wiki pages and link them from README |
| [#125](https://github.com/djshellshoxxx/patchtrace/pull/125) | `198eb21e8813b28de361422cfe3c002bdb9e3970` | no / no | 1 | clean | `documentation_only` — docs: next-milestone dev prompt for integrated essential alpha |
| [#129](https://github.com/djshellshoxxx/patchtrace/pull/129) | `2698b9a04d33b2d04f49c1ab737636539c6ef6f7` | no / no | 14 | conflict | `needs_reconciliation` — R3 research: semantic-change proofs, compiler noise and guarded PE comparisons |
| [#130](https://github.com/djshellshoxxx/patchtrace/pull/130) | `ff570bdd784d02f745e4ad21d8aa7b4f1f776344` | no / no | 12 | clean | `documentation_only` — R4 research: CVE/KB/product/build/binary provenance and function evidence |
| [#133](https://github.com/djshellshoxxx/patchtrace/pull/133) | `3010f289dbb46a1db62218a35cca03420090e306` | no / no | 12 | clean | `documentation_only` — R6: comprehensive engineer-ready final integration and release acceptance notes |
| [#134](https://github.com/djshellshoxxx/patchtrace/pull/134) | `c9d1aab6a78847ce1632fe833d15af2e3b9c6e9b` | no / no | 29 | conflict | `research_only_or_quarantined` — R7 research: bounded semantic slicing and evidence-grounded security interpretation |
| [#135](https://github.com/djshellshoxxx/patchtrace/pull/135) | `12dd4f2b41b468b0eb566bd502219daa821012df` | no / no | 16 | conflict | `needs_reconciliation` — R8 (draft): adversarial proof and literal-type normalization research |
| [#137](https://github.com/djshellshoxxx/patchtrace/pull/137) | `61b5c2bade71a8cec58ca9e1514141f4508b7c79` | no / no | 20 | conflict | `documentation_only` — docs: post-consolidation 20-feature gap audit and parallel development roadmap |
| [#139](https://github.com/djshellshoxxx/patchtrace/pull/139) | `c04ad725551fe8daa139b37aa2cdf46d6d161b65` | no / no | 12 | conflict | `needs_reconciliation` — fix(GT-01): consolidate R1 native recovery and PR #138 regressions |
| [#140](https://github.com/djshellshoxxx/patchtrace/pull/140) | `fb91cff6d91c77a2c539c896b670d81180dcc637` | no / no | 14 | conflict | `needs_reconciliation` — fix(GT-01): run native identical controls and distinguish output rejections |
| [#141](https://github.com/djshellshoxxx/patchtrace/pull/141) | `d76d23372acef4049115e9ae176acbeb538a82e5` | no / no | 15 | conflict | `needs_reconciliation` — fix: isolate native extraction failures between comparisons |
| [#143](https://github.com/djshellshoxxx/patchtrace/pull/143) | `a7f13e13ffb512f8e9621753a0ae162d78942f3b` | no / no | 18 | conflict | `needs_reconciliation` — Draft: combined verification of native recovery and KB fixture repairs |
| [#144](https://github.com/djshellshoxxx/patchtrace/pull/144) | `745e93426a16e0a91a961b6e0bbcb71be69f2a7e` | no / no | 26 | conflict | `valuable_but_incomplete` — fix: reconcile matching evidence, semantic uncertainty and typed literals |
| [#150](https://github.com/djshellshoxxx/patchtrace/pull/150) | `2fdac2ea9042985ac3c98545d38ac3461d00f4cc` | no / no | 9 | conflict | `research_only_or_quarantined` — Anchor research receipts against parent replacement and preserve completed evidence |
| [#164](https://github.com/djshellshoxxx/patchtrace/pull/164) | `b58bb53debcb3323e5d8d634e09397cb7e02965f` | no / no | 46 | conflict | `needs_reconciliation` — Consolidate build provenance and saved-rule integrity repairs |
| [#165](https://github.com/djshellshoxxx/patchtrace/pull/165) | `4d66af5577e6f6ad8f6e21440f6fe4187e0c8fe5` | no / no | 48 | conflict | `needs_reconciliation` — Repair Rizin singleton result ownership in pinned research producer; retain quarantine |
| [#168](https://github.com/djshellshoxxx/patchtrace/pull/168) | `b304034e3c310528f7e0a3206eda48c94e0a6873` | no / no | 49 | conflict | `valuable_but_incomplete` — test(rzdiff): require complete stock-native red controls and preserve failure evidence |
| [#172](https://github.com/djshellshoxxx/patchtrace/pull/172) | `7ed5cebfdaee4dc508b0cc739e86c18c1ff34a97` | no / no | 1 | clean | `documentation_only` — docs: autonomous finish prompt (launch record) |
| [#174](https://github.com/djshellshoxxx/patchtrace/pull/174) | `e1193c8896e009930dae4edec974d9795876f0e0` | no / no | 21 | conflict | `valuable_but_incomplete` — GT-01 live-gate harness repairs and rz-diff producer controls, ported onto main (WS-B/C) |
| [#176](https://github.com/djshellshoxxx/patchtrace/pull/176) | `597a8b106491cd587cedf1273ee5ef6d56d71508` | no / no | 23 | conflict | `valuable_but_incomplete` — Offline KB investigation, calibration replay identity, GUI tiny wins, audit dispositions (WS-D/F/G/H) |
| [#179](https://github.com/djshellshoxxx/patchtrace/pull/179) | `ca10acb506fbf61db8142a836acfbd1e50a2aeb3` | no / no | 8 | clean | `research_only_or_quarantined` — Consolidate-and-build prompt, branch inventory tool and C0 ledger |
| [#187](https://github.com/djshellshoxxx/patchtrace/pull/187) | `fbd9595351bf50217402b7a62b3e057de79f45f0` | no / no | 2 | conflict | `documentation_only` — Audit open PatchTrace consolidation branches and identify integration order |
| [#222](https://github.com/djshellshoxxx/patchtrace/pull/222) | `c50ab287de13982b132716d67f9e5fabe22799cb` | no / no | 4 | clean | `research_only_or_quarantined` — test(rzdiff): execute pinned-native API ownership and IO controls |
| [#224](https://github.com/djshellshoxxx/patchtrace/pull/224) | `8fae317bcac6cb125956965cd3ebbb39e9f9bbd2` | no / no | 5 | clean | `research_only_or_quarantined` — docs(native): retain CLI baseline failures and isolated seeding experiment |
| [#268](https://github.com/djshellshoxxx/patchtrace/pull/268) | `b29351d41060f8e9330fc9673457d835e188f993` | no / no | 2 | conflict | `needs_reconciliation` — Narrow #174: fix two RB-01 measurement defects in the unified live gates (G-U2, G-U3) |
| [#279](https://github.com/djshellshoxxx/patchtrace/pull/279) | `a5f049cd777d3d885ec8e1572f94ea8935c9cbb6` | no / no | 8 | clean | `research_only_or_quarantined` — codespaces: bootstrap the PatchTrace accuracy lab |
| [#281](https://github.com/djshellshoxxx/patchtrace/pull/281) | `cbabc09e9df8a8190c769164ef0fae44f9c5cb1b` | no / no | 14 | clean | `needs_reconciliation` — ci: name tag releases after the tag and pin the release action (alpha precondition) |
| [#282](https://github.com/djshellshoxxx/patchtrace/pull/282) | `552c29453c5de93e22c65e47ad4187ded91e993a` | no / no | 2 | clean | `needs_reconciliation` — Consolidate R7 research prototypes: bounded semantic slicing and patch patterns (from #134) |
| [#283](https://github.com/djshellshoxxx/patchtrace/pull/283) | `6f767ccef8ebfffd1d2373c5124d8a961dc54b41` | no / no | 13 | clean | `needs_reconciliation` — unified bench: a missing ticks count fails the work checks (UE-B-07) |
| [#284](https://github.com/djshellshoxxx/patchtrace/pull/284) | `160a60e838742b21f70effedb8e7bb48886d9266` | no / no | 4 | clean | `research_only_or_quarantined` — Completion session record: ledger, status roll-up, slice cards and handoff (session stopped by owner) |
| [#289](https://github.com/djshellshoxxx/patchtrace/pull/289) | `ad4c49282a65d17d2ef23dfcc03e82be065c9021` | no / no | 122 | conflict | `valuable_but_incomplete` — Handoff record: autonomous-finish integration branch (paused; do not merge as-is) |
| [#290](https://github.com/djshellshoxxx/patchtrace/pull/290) | `1d5a022d2840c5c071ccece503664c8c961d63f1` | no / yes | 0 | conflict | `blocked_by_qualification` — Security hardening: deep JSON, hostile text, path, archive and environment boundaries, PE bounds (draft, stopped mid-review) |
| [#291](https://github.com/djshellshoxxx/patchtrace/pull/291) | `53f5dd2611b38e3f69f8d72c3ca7cf73e9e896ab` | no / yes | 0 | clean | `blocked_by_qualification` — KB/CVE correlation: KBA-06, KBA-07, KBA-08, kb leads state text, KB context in report/2 (draft) |
| [#292](https://github.com/djshellshoxxx/patchtrace/pull/292) | `cf50b4e8725cb1291ac6150667f2e136f023aff3` | no / yes | 0 | clean | `blocked_by_qualification` — Headless CLI: project, compare, profile, doctor (GUI/CLI parity, draft) |
| [#293](https://github.com/djshellshoxxx/patchtrace/pull/293) | `aacb984e9d627be051ca8c8c3b88d5ceca0ff505` | no / yes | 0 | clean | `blocked_by_qualification` — rz-diff: refuse results with ambiguous side ownership (Rizin singleton swap) (draft, 8 existing tests red) |
| [#294](https://github.com/djshellshoxxx/patchtrace/pull/294) | `e88d748cf9846e04c0c81449976f530519da83a9` | no / yes | 0 | clean | `blocked_by_qualification` — L1 advisory-join runner over a frozen manifest (mechanics only, no accuracy figure; draft) |
| [#295](https://github.com/djshellshoxxx/patchtrace/pull/295) | `37d9e47ca202b33f737b15f7af724649db8c3e15` | no / yes | 0 | clean | `blocked_by_qualification` — test(rq): pathguard escape test independent of tmp_path depth (fails only under xdist) |
| [#297](https://github.com/djshellshoxxx/patchtrace/pull/297) | `95db052a11cce162d2d633cae805f28119f783a1` | no / yes | 0 | clean | `blocked_by_qualification` — Consolidate PatchTrace, complete CLI and timeout controls, and repair evidence integrity |
| [#301](https://github.com/djshellshoxxx/patchtrace/pull/301) | `faddea300daf4058d38d24ff04a270be6f3d832b` | no / yes | 0 | clean | `blocked_by_qualification` — Consolidate all remote branches: carry #297 and port ten never-merged fixes and features |
| [#302](https://github.com/djshellshoxxx/patchtrace/pull/302) | `121ffb0bcdd6af4f24e5035389d4709dffddf263` | no / yes | 0 | clean | `blocked_by_qualification` — Consolidate reviewed branch history and repair boundary defects |
| [#303](https://github.com/djshellshoxxx/patchtrace/pull/303) | `2b697222b34359bb46adc90aad69fd0a12708601` | no / yes | 0 | clean | `blocked_by_qualification` — Add scoped KB file inventories with offline import and exact source consent |
| [#304](https://github.com/djshellshoxxx/patchtrace/pull/304) | `75ffee3840894adb52aff7f3df28043cc8e832ba` | no / yes | 0 | clean | `blocked_by_qualification` — Consolidate reviewed CVE fixes and preserve source-backed qualification evidence |
| [#305](https://github.com/djshellshoxxx/patchtrace/pull/305) | `16ab88b0626ef05700c4199e926103932312e5c7` | no / yes | 0 | clean | `blocked_by_qualification` — test(cve/kb): spec-mandated NEW guard-lock tests (FP control, OSV scope, source lineage, worker-thread) |
| [#306](https://github.com/djshellshoxxx/patchtrace/pull/306) | `f6ef1528c15b2281ee7b6f32625d02a5211c926d` | no / yes | 0 | clean | `blocked_by_qualification` — fix(search): restrict advisory anchors to binary-evidence kinds (§5.1 circularity) |
| [#307](https://github.com/djshellshoxxx/patchtrace/pull/307) | `1418617a80d6057de11f985488cfe6043a7787a2` | no / yes | 0 | clean | `blocked_by_qualification` — Complete retained inventories and guard native qualification identities |

## Reproducible method and limits

Fresh GitHub REST requests read `/branches?per_page=100&page=N` for pages 1–4 (100/100/100/7) and `/pulls?state=all&per_page=100&page=N` for pages 1–4 (100/100/97/0). The exact branch snapshot was replayed through the existing read-only inventory tool. All histories share a merge base with main; no shallow-history inference was used.

```bash
python tools/branch_inventory.py \
  --main 9c411ca3d7b47f950be5f0c6f01b3c54184554c6 \
  --candidate 1418617a80d6057de11f985488cfe6043a7787a2 \
  --pulls-json /path/to/all-pages-pulls.json \
  --refs-tsv /path/to/exact-branch-snapshot.tsv \
  --output /path/to/replayed-evidence.tsv
```

`branch-inventory.json` records the exact all-state PR/branch fields needed to reconstruct minimal tool input, plus the raw snapshot input digests. For each branch, it records `git cherry` unmatched/equivalent nonmerge commit IDs, both merge bases and exact changed-file lists. File projection uses `git diff --raw --no-abbrev --no-renames MAIN_MERGE_BASE TIP` and compares each new blob with the exact candidate tree. Deletions are compared as absent states. This does not evaluate unchanged dependencies or later semantic effects.

Conflict previews use `git merge-tree --write-tree --name-only --no-messages MAIN TIP`. They write local Git objects only, change no checkout/ref and do not authorize a merge. Conflict paths and resulting preview tree IDs are retained. Git evidence and JSON consistency were executed in this session; no product/native/Windows test execution is claimed by this worker.

A later integration append must identify new heads, review results, commands, merge SHAs and remaining blockers. Preserve this observation rather than silently changing frozen evidence.

## Follow-up observations in this session

The first consistency check found 26 closed-PR source objects absent from the
ordinary branch fetch. Their recorded `refs/pull/N/head` refs were then fetched
into local `refs/inventory/pr/N`; no remote ref changed. The final JSON includes
all 297 available PR source heads and their actual ancestry/merge bases. The
original completeness assertion failed before this repair; no success was
inferred from the earlier partial object set. Final JSON checks confirm 307
unique branches, 297 PR source objects, all seven required ancestry links,
306 classified topics and no deletion authorization.

After this frozen branch snapshot, the integration coordinator reported an
append-only #304 update to
`d8c02caea407f6d323eecd636735849c1eb31a2d`, carrying independently reviewed
Windows and chronology corrections with new hosted workflows queued. That is
a later candidate, not a retroactive change to this inventory. Reconcile the
new #304 history into the #307 continuation and re-evaluate combined-tree gates.
Queued workflows are unverified; neither canonical integration nor a release
is implied by this update.

## Later qualification and focused-work checkpoint

The published #304 head is now `d8c02caea407f6d323eecd636735849c1eb31a2d`;
canonical main is still `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`.
Local reviewed #307 successor source `9002a1f44c6aebcf2c49b29d631aacf20e7ce9e3`
preserves both that head and original #307 as actual ancestors. It adds reviewed
object ownership, fixture/tooltip and research Ghidriff repairs. Combined
verification is 2,866 passed/four unverified skips; full/native/package/security
acceptance is not complete. No PR merge or superseded closure has occurred.

A later REST capture inspected all **55 then-open PRs**, including new focused
strings-publication #308 at `92a411bf02fc8beb00b7a148e39db2bf68efa061`.
Every review and inline review-comment collection was empty; each head's check
runs are captured without crediting stale or incomplete checks. The original
inventory remains its explicitly dated 307-branch/297-PR snapshot, not a claim
that no branch or PR was added afterward. Paired raw-offset desktop and
saved/recent search are separate focused follow-on slices; neither historical
#168 nor #289 is eligible for blanket closure from that selective work.
See the [complete repair checkpoint](../../qa/autonomous-consolidation-20261118/checkpoint/README.md)
for source/receipt mapping, native fixture limits and next assignments.
