# PatchTrace branch consolidation — corrected 2026-11-18 inventory

This is a fixed snapshot and decision record, not a claim that every branch has
been semantically reviewed or merged. It replaces the inaccurate inventory and
archive recommendations previously committed at this path. All remote branches
must remain intact. No archive refs, deletion, force push or history rewrite is
authorized by this record.

## Reviewed references

Current continuation: the [correctness follow-up](consolidation-correctness-20261118.md)
records the selective #304 ports, independent red/green review, exact local/REST
tree mappings and current merge gates. #304 is retained for its remaining work;
the newly concurrent #305 and #306 also remain open. The original 300-topic TSV
is a fixed evidence snapshot, not the present live branch count.

| Reference | Exact commit |
|---|---|
| Starting `main` | `9c411ca3d7b47f950be5f0c6f01b3c54184554c6` |
| PR #297 | `95db052a11cce162d2d633cae805f28119f783a1` |
| PR #301 candidate | `faddea300daf4058d38d24ff04a270be6f3d832b` |
| Preserved PR #168 stack | `b304034e3c310528f7e0a3206eda48c94e0a6873` |

PR #301 includes the current main and #297, with 88 commits ahead and none behind
this main. It changes 402 files. Its ten additional ports are not its complete
diff: the #297 consolidation is part of the candidate and must be reviewed too.
Any moved candidate or base requires refreshed qualification before a merge.

The fresh all-pages REST snapshot was captured at 2026-11-18T06:00:36+00:00. Requests were
`GET /repos/djshellshoxxx/patchtrace/pulls?state=all&per_page=100&page=N` for
N=1,2,3: 100, 100 and 91 results, respectively. There were 291 PR records,
including 48 open PRs. Main/candidate tips were cross-checked against the freshly
fetched Git refs. The PR table below records all 48 open entries. Review
submissions, discussions and current merge gates require separate current-head
checks; this inventory does not stand in for independent code approval.

## Reproducible method

`tools/branch_inventory.py` is a read-only, offline Git evidence generator. It
uses no network, executes no target input and changes no Git ref. Supply a full
clone, exact baseline commits and a saved all-pages REST PR array. It rejects
shallow history. Its only writes are the requested report, published after
successful generation so failures preserve the previous report.

1. Enumerate `refs/remotes/origin/`, excluding symbolic refs such as `origin/HEAD`
   and excluding `main` from topic counts. Pin every tip before comparing it.
2. Record main/candidate reachability using their complete `git rev-list`
   histories and record each `git merge-base`.
3. Run `git cherry MAIN TIP` and `git cherry CANDIDATE TIP`. Store the exact
   unmatched and patch-equivalent non-merge commit IDs. This uses Git patch-ID
   equivalence, not textual similarity thresholds.
4. Record unique commit counts, files touched by each unmatched patch and the
   net files changed between the candidate merge base and branch tip. These
   are residual review leads; overlapping, reverted and evolved changes can
   remain in those sets without representing missing features.
5. Group known stack intermediates by proven ancestry to a surviving open PR.
   Record narrowly reviewed ports separately, tied to their exact source and
   candidate SHA. A changed head invalidates those scoped review receipts.
6. Retain every branch. The existing seven TSV columns remain compatible with
   existing readers; **every `delete_safe` value is `no`**. The `note` column is
   a JSON object containing the evidence. No similarity percentage can authorize
   closure, archiving or deletion. The successor excludes the archive/delete
   helper from #301: its preflight snapshot did not protect a later deletion
   against concurrent branch movement, and ref removal is outside this task.
   The read-only inventory generator is the retained operational tool.

Generation command (the PR JSON is an operator-saved REST snapshot):

```bash
python tools/branch_inventory.py \
  --main 9c411ca3d7b47f950be5f0c6f01b3c54184554c6 \
  --candidate faddea300daf4058d38d24ff04a270be6f3d832b \
  --pulls-json /path/to/all-pages-pulls.json \
  --output docs/qa/branch-disposition-20261118.tsv
```

The [TSV](branch-disposition-20261118.tsv) contains all source tips and the PR
fields used by the tool. To replay a fixed snapshot after remote branches move,
use `--refs-tsv` and reconstruct the minimal PR input from those recorded fields:

```python
import csv
import json
from pathlib import Path

snapshot = Path("docs/qa/branch-disposition-20261118.tsv")
pulls = []
with snapshot.open(encoding="utf-8", newline="") as stream:
    for row in csv.DictReader(stream, delimiter="\t"):
        for pr in json.loads(row["note"])["pull_requests"]:
            pulls.append({
                "number": pr["number"], "state": pr["state"],
                "head": {"ref": row["branch"], "sha": pr["head"],
                         "repo": {"full_name": "djshellshoxxx/patchtrace"}},
                "base": {"sha": pr["base"]},
            })
Path("branch-pr-input.json").write_text(json.dumps(pulls), encoding="utf-8")
```

Use the same generation command with `--refs-tsv` pointing to the recorded TSV,
`--pulls-json branch-pr-input.json`, and a separate `--output` file. Exact source
hunks are reproducible using `git show --format=fuller COMMIT -- PATH` for any
recorded unmatched SHA; net branch hunks use
`git diff CANDIDATE_MERGE_BASE TIP -- PATH`. Do not substitute a current moving
branch name when reproducing historical evidence.

## Corrected counts and previous errors

| Finding | Verified count |
|---|---:|
| Remote branches including main, excluding symbolic HEAD | 301 |
| Topic branch rows | 300 |
| Topic tips reachable from main | 113 |
| Topic tips reachable from #301, including #301 itself | 123 |
| Additional nonancestor branches with no unmatched non-merge patch against #301 | 16 |
| Branches retaining at least one unmatched patch against #301 | 161 |
| Topic branches with a merge base with main | 300 |

These 161 branches are not 161 missing features. Unmatched patches include
squashes, ports and evolved implementations that require scoped content review.
The previous 299-topic prose contradicted its own 300-row TSV. The previous
102-main-ancestor count is replaced by 113. None of the claimed 52 unrelated
histories was reproduced in the full clone. Commit
`0fb25d8e2ad52d4bfe079c7d31b706d55569c8af` has parent
`78154a9d0717153c1d959ffef82b37ebb9f10974`; it is not a root commit. The cause of
the previous bad history result is unknown and is not inferred here.

The former rule "97% of added lines present or at most 20 absent" cannot prove
semantic supersession and is removed. The former claim that #281 was already
fully present in main was also false: its release action pin and tag-derived
release title are present in #297/#301, but absent from the starting main.

## Disposition summary

| Disposition | Branches | Meaning |
|---|---:|---|
| `already-integrated` | 113 | Tip is an ancestor of the recorded main; retain branch. |
| `contained-in-unmerged-candidate` | 10 | Tip is reachable from #301 but not main; wait for verified consolidation. |
| `port-verified-in-candidate` | 4 | Full scoped PR change reviewed against the exact #301 tree; close only after verified main integration. |
| `contained-in-retained-unmerged-branch` | 6 | Old PR head is an ancestor of retained open #168; its remaining work is still unmerged. |
| `patch-equivalent-review-required` | 16 | No unmatched non-merge patch; evolved semantics and merge-only effects still require review. |
| `partial-recovery-required` | 6 | Known useful slices were recovered; specified residual work remains. |
| `experimental-deferred` | 7 | Environment, paid-automation or skill work requires separate review; not a CSV prerequisite. |
| `historical-documentation-review` | 6 | Historical documentation claims need validation before use. |
| `research-tools-review-required` | 12 | Research, tooling or recorded evidence requires scoped review; not all content is documentation. |
| `unresolved` | 120 | Residual patch/files recorded; no semantic supersession or deletion claim. |

## Duplicate-history review groups

The 300 topic rows have 299 distinct tips. The 161 rows with unmatched patches
reduce to 152 distinct ordered sets of unmatched commit IDs. These nine pairs
can share patch review; each branch still needs its own net-diff/merge-effect
check. This groups identical history, not merely similar text:

- `access-test-noprefix` and `claude/access-test-1791773355`.
- `claude/modest-hamilton-kz2gta` and `codex/coordinator-rule-repairs-20261031`.
- `codex/autonomous-reconcile-20261101` and `codex/msrc-reconcile-integration-20261102`.
- `codex/consolidate-prereg-prefix-20261102` and `codex/training-prereg-identity-20261101`.
- `codex/consolidate-replay-schema-20261102` and `codex/corpus-output-main-20261101`.
- `codex/consolidation-evidence-20261102` and `codex/consolidation-integrity-20261103`.
- `codex/pr110-kb-arch-scope-20261029` and `codex/pr111-bounded-nav-into-integration-20261029`.
- `codex/r1-ground-truth-research-20261030` and `codex/r1-receipt-publication-20261031`.
- `repair/rzdiff-native-callback-size-20261103` and `repair/rzdiff-producer-ownership`.

## Consolidation backbone

The exact heads of #290, #291, #292, #293, #294, #295 and #297 are ancestors of
#301. Do not replay them separately. Once a reviewed #301 or a documented
successor is merged and resulting main is qualified, these seven PRs may close
with the final replacement PR/commit cited. Their remote branches remain.
The continuation branch `codex/consolidation-reviewed-20261118` is based directly
on #301 and preserves its complete ancestry. Close #301 only after this
successor is merged and resulting main is qualified. The branch removes the
unsafe archive/delete helper; it does not remove any remote branch or create
archive refs.

## Candidate content under independent review

The original consolidation records the following sources and ports. This scope
list preserves provenance; the lead's full-diff review and integration gates
remain required. Native/live statements in historical source notes do not
transfer automatically to a new candidate.

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

## Verified selective ports

These are content/hunk reviews in addition to patch-ID evidence. They do not
claim native acceptance or main integration before the consolidation lands.

| Source PR and head | Replacement inside #301 | Scoped evidence and closure condition |
|---|---|---|
| #268 `b29351d41060f8e9330fc9673457d835e188f993` | `f64620f7771b205558871fe09448eb1dd6df715a` | Reviewed all 10 changed files. `evaluators.py`, `gates_u.py`, mutation templates, `debuginfo.py` and gate-eval tests are identical. Evolved files preserve the fixes and add refusal of both-empty inventories, receipt retention, forced native A/A controls and failure diagnostics. Close after verified main integration; the targeted RB-01 live rerun remains tracked separately. |
| #281 `cbabc09e9df8a8190c769164ef0fae44f9c5cb1b` | `2d330075fbe00209fbe096ee29b60dcfd0e347b4` | Reviewed all four changed files. Release tests are identical; workflow difference is only the pin provenance comment. The two specs correct provenance and release-notes wording. The exact action pin and tag-aware release title are absent from starting main. Close only after the replacement reaches verified main. |
| #282 `552c29453c5de93e22c65e47ad4187ded91e993a` | `909cd5f2259bb9caf8afcb681d01589cb4e49244` | All 11 changed files are byte-identical: research docs/index, synthetic benchmark, three prototype tools and two tests. The complete scoped change is preserved; product wiring and real accuracy are not claimed. Close after verified main integration. |
| #283 `6f767ccef8ebfffd1d2373c5124d8a961dc54b41` | `2d330075fbe00209fbe096ee29b60dcfd0e347b4` | Reviewed all four changed files. Parity tool/tests are identical. Benchmark changes strengthen tick validation to reject booleans, negative and missing counts and use exact ratio comparisons. The newer tests preserve the original assertions and add boundary cases. Close after verified main integration. |

Relevant local candidate tests: `test_release_gate.py`, `test_r7_patterns.py`,
`test_r7_slicing.py`, `test_unified_bench.py`, `test_unified_parity.py`,
`test_unified_gate_eval.py` and `test_unified_rb01_harness.py`: **258 passed,
2 skipped**. The two existing MSVC-free live fixture cases were blocked by the
missing clang/lld/LLVM toolchain in this executor. No skipped test was converted
into a pass and no live compatibility result is inferred.

## Retained stack and residual work

#139, #140, #141, #143, #164 and #165 are all proven ancestors of open #168,
`repair/rzdiff-native-red-control-20261103` at
`b304034e3c310528f7e0a3206eda48c94e0a6873`. They may be closed as stack
intermediates only with a comment naming #168 and explaining that its remaining
scope is still unmerged. Keep #168 open and preserve every source branch. This
is tracking consolidation, not proof that their behavior is in main.

| Retained source | Remaining work or reason |
|---|---|
| #144 | R8 typed-literal changes were ported; R2 corroboration and `matching/2` require current specification and review. |
| #168 stack | Raw-offset core and Qt-free paired-row model were ported. RD-F03 desktop wiring remains a separate UI slice. Historical native producer work is not permission to replace singleton refusal. |
| #174 | One-to-many and harness changes overlap the candidate; retain research producer workflow/evidence residue for review. |
| #176 | Search document-scope repair was ported. Keyboard sorting/header help needs conflict review against existing Alt+Up/Down navigation and #300 accessibility. |
| #289 | Preserve the source branch. UE-R7/L-39 cap symmetry from `7237c55cba6e134c58df7936f273fd269aa864c5` was reproduced and minimally repaired in successor commit `81942db9`, preserving newer registry/config-digest fixes. Other UI/research residue remains separate. |
| `claude/instance-b-features` | Saved-search/recent-query stores were ported. Call-graph layout and capa raw-cache work remain separate. |
| #279 | Review devcontainer configuration, Rizin fixtures and research parser tests independently. Historical identical forward/reverse results cannot establish compatibility after ownership refusal. |
| #70, #78, #79, #82, #85, #86 | Historical help, corpus/persistence/card-control/preregistration and decompilation work needs full behavior-to-replacement mapping. Their source tips are not ancestors of main. The prior similarity-based closure claims are withdrawn. |
| Other research/spec/tool records | Preserve source claims and review their age, inputs, labels and evidence before reuse. Tool-containing branches are not represented as documentation-only. |
| Paid API automation and broad skill imports | Excluded from automatic consolidation. No scheduled paid workflow or third-party bundle is added. |

## All 48 open PRs at snapshot

Exact source/base SHA and PR association are also recorded in each TSV row.
"Retain" means the PR remains a tracked review scope, not that every historical
change should eventually be merged. No PR was closed by the inventory worker.

| PR | Head SHA | Disposition | Remaining condition or surviving scope |
|---|---|---|---|
| [#61](https://github.com/djshellshoxxx/patchtrace/pull/61) | `4467d1f3c6e113a7da808a67e8dee9d4aa5083d8` | `experimental-deferred` | Retain; separate skill/license review. |
| [#68](https://github.com/djshellshoxxx/patchtrace/pull/68) | `b7a0f0a45d2de1462367d877b7386091b4d275ce` | `research-tools-review-required` | Retain; corpus recipes need provenance and current labels. |
| [#70](https://github.com/djshellshoxxx/patchtrace/pull/70) | `e5bee6fe157c90a40f2d9f458768e2169ce123e5` | `unresolved` | Retain; historical help needs behavior/content mapping. |
| [#72](https://github.com/djshellshoxxx/patchtrace/pull/72) | `cfd7cfff52f4f9b8b1264e8b7d70ef1bbef2d63f` | `historical-documentation-review` | Retain; reconcile panel specifications with implemented UI. |
| [#78](https://github.com/djshellshoxxx/patchtrace/pull/78) | `2019a37fa65fc37f4758469143c2daadc07e0098` | `unresolved` | Retain; map output persistence and training-artifact behavior. |
| [#79](https://github.com/djshellshoxxx/patchtrace/pull/79) | `9513bc05229dd7a8460fc229d7420154d61498db` | `unresolved` | Retain; verify two-sided recipe-card controls. |
| [#82](https://github.com/djshellshoxxx/patchtrace/pull/82) | `eaa30013794a9bd0fedc9ec34bbe374d6db0cfc9` | `unresolved` | Retain; verify recipe A/A and nuisance controls. |
| [#85](https://github.com/djshellshoxxx/patchtrace/pull/85) | `6ae2c079e6cafa2b7bd5396cac443cd34ba7138a` | `unresolved` | Retain; verify preregistration and single-use training behavior. |
| [#86](https://github.com/djshellshoxxx/patchtrace/pull/86) | `ebbd621d4f557905892aee5f7cf8cb7b0e2addc2` | `unresolved` | Retain; verify bounded decompilation sidecars and ownership. |
| [#98](https://github.com/djshellshoxxx/patchtrace/pull/98) | `ad8fbe9f2f041653760c02e9d18a91a66dd11c39` | `research-tools-review-required` | Retain; wiki/README content review. |
| [#125](https://github.com/djshellshoxxx/patchtrace/pull/125) | `198eb21e8813b28de361422cfe3c002bdb9e3970` | `historical-documentation-review` | Retain as historical milestone prompt. |
| [#129](https://github.com/djshellshoxxx/patchtrace/pull/129) | `2698b9a04d33b2d04f49c1ab737636539c6ef6f7` | `research-tools-review-required` | Retain; semantic-proof research is not validated accuracy. |
| [#130](https://github.com/djshellshoxxx/patchtrace/pull/130) | `ff570bdd784d02f745e4ad21d8aa7b4f1f776344` | `historical-documentation-review` | Retain; provenance/revision research requires current contract review. |
| [#133](https://github.com/djshellshoxxx/patchtrace/pull/133) | `3010f289dbb46a1db62218a35cca03420090e306` | `historical-documentation-review` | Retain; release notes are historical, not acceptance. |
| [#134](https://github.com/djshellshoxxx/patchtrace/pull/134) | `c9d1aab6a78847ce1632fe833d15af2e3b9c6e9b` | `research-tools-review-required` | Retain; #282 ports the isolated prototype subset only. |
| [#135](https://github.com/djshellshoxxx/patchtrace/pull/135) | `12dd4f2b41b468b0eb566bd502219daa821012df` | `research-tools-review-required` | Retain; distinguish recovered literal fixes from broader research. |
| [#137](https://github.com/djshellshoxxx/patchtrace/pull/137) | `61b5c2bade71a8cec58ca9e1514141f4508b7c79` | `research-tools-review-required` | Retain; gap audit needs current implementation reconciliation. |
| [#139](https://github.com/djshellshoxxx/patchtrace/pull/139) | `c04ad725551fe8daa139b37aa2cdf46d6d161b65` | `contained-in-retained-unmerged-branch` | May close only naming retained open #168 and its unmerged remainder. |
| [#140](https://github.com/djshellshoxxx/patchtrace/pull/140) | `fb91cff6d91c77a2c539c896b670d81180dcc637` | `contained-in-retained-unmerged-branch` | May close only naming retained open #168 and its unmerged remainder. |
| [#141](https://github.com/djshellshoxxx/patchtrace/pull/141) | `d76d23372acef4049115e9ae176acbeb538a82e5` | `contained-in-retained-unmerged-branch` | May close only naming retained open #168 and its unmerged remainder. |
| [#143](https://github.com/djshellshoxxx/patchtrace/pull/143) | `a7f13e13ffb512f8e9621753a0ae162d78942f3b` | `contained-in-retained-unmerged-branch` | May close only naming retained open #168 and its unmerged remainder. |
| [#144](https://github.com/djshellshoxxx/patchtrace/pull/144) | `745e93426a16e0a91a961b6e0bbcb71be69f2a7e` | `partial-recovery-required` | Retain R2 corroboration/matching remainder. |
| [#150](https://github.com/djshellshoxxx/patchtrace/pull/150) | `2fdac2ea9042985ac3c98545d38ac3461d00f4cc` | `research-tools-review-required` | Retain; parent-race receipt tooling requires separate scope review. |
| [#164](https://github.com/djshellshoxxx/patchtrace/pull/164) | `b58bb53debcb3323e5d8d634e09397cb7e02965f` | `contained-in-retained-unmerged-branch` | May close only naming retained open #168 and its unmerged remainder. |
| [#165](https://github.com/djshellshoxxx/patchtrace/pull/165) | `4d66af5577e6f6ad8f6e21440f6fe4187e0c8fe5` | `contained-in-retained-unmerged-branch` | May close only naming retained open #168 and its unmerged remainder. |
| [#168](https://github.com/djshellshoxxx/patchtrace/pull/168) | `b304034e3c310528f7e0a3206eda48c94e0a6873` | `partial-recovery-required` | Keep open as surviving stack; desktop/native residue. |
| [#172](https://github.com/djshellshoxxx/patchtrace/pull/172) | `7ed5cebfdaee4dc508b0cc739e86c18c1ff34a97` | `historical-documentation-review` | Retain as historical launch record. |
| [#174](https://github.com/djshellshoxxx/patchtrace/pull/174) | `e1193c8896e009930dae4edec974d9795876f0e0` | `partial-recovery-required` | Retain research producer/workflow remainder. |
| [#176](https://github.com/djshellshoxxx/patchtrace/pull/176) | `597a8b106491cd587cedf1273ee5ef6d56d71508` | `partial-recovery-required` | Retain keyboard sorting/header-help remainder. |
| [#179](https://github.com/djshellshoxxx/patchtrace/pull/179) | `ca10acb506fbf61db8142a836acfbd1e50a2aeb3` | `research-tools-review-required` | Retain historical tool/prompt/ledger review. |
| [#187](https://github.com/djshellshoxxx/patchtrace/pull/187) | `fbd9595351bf50217402b7a62b3e057de79f45f0` | `historical-documentation-review` | Retain; newer inventory does not automatically supersede all historical evidence. |
| [#222](https://github.com/djshellshoxxx/patchtrace/pull/222) | `c50ab287de13982b132716d67f9e5fabe22799cb` | `research-tools-review-required` | Retain; native source/IO experiments have scoped recoveries. |
| [#224](https://github.com/djshellshoxxx/patchtrace/pull/224) | `8fae317bcac6cb125956965cd3ebbb39e9f9bbd2` | `research-tools-review-required` | Retain; native baseline/seeding evidence requires current validation. |
| [#268](https://github.com/djshellshoxxx/patchtrace/pull/268) | `b29351d41060f8e9330fc9673457d835e188f993` | `port-verified-in-candidate` | Close after verified #301 replacement; live RB-01 rerun remains separate. |
| [#279](https://github.com/djshellshoxxx/patchtrace/pull/279) | `a5f049cd777d3d885ec8e1572f94ea8935c9cbb6` | `experimental-deferred` | Retain; separate environment/native-fixture review. |
| [#281](https://github.com/djshellshoxxx/patchtrace/pull/281) | `cbabc09e9df8a8190c769164ef0fae44f9c5cb1b` | `port-verified-in-candidate` | Close only after release pin/title replacement is on verified main. |
| [#282](https://github.com/djshellshoxxx/patchtrace/pull/282) | `552c29453c5de93e22c65e47ad4187ded91e993a` | `port-verified-in-candidate` | Close after verified #301 replacement; all 11 files preserved. |
| [#283](https://github.com/djshellshoxxx/patchtrace/pull/283) | `6f767ccef8ebfffd1d2373c5124d8a961dc54b41` | `port-verified-in-candidate` | Close after verified #301 replacement; stronger tick checks retained. |
| [#284](https://github.com/djshellshoxxx/patchtrace/pull/284) | `160a60e838742b21f70effedb8e7bb48886d9266` | `research-tools-review-required` | Retain as stopped-session history; no implementation claim. |
| [#289](https://github.com/djshellshoxxx/patchtrace/pull/289) | `ad4c49282a65d17d2ef23dfcc03e82be065c9021` | `partial-recovery-required` | Retain; targeted cap-symmetry repair and other residual slices. |
| [#290](https://github.com/djshellshoxxx/patchtrace/pull/290) | `1d5a022d2840c5c071ccece503664c8c961d63f1` | `contained-in-unmerged-candidate` | Close after verified main integration of #301; exact ancestor. |
| [#291](https://github.com/djshellshoxxx/patchtrace/pull/291) | `53f5dd2611b38e3f69f8d72c3ca7cf73e9e896ab` | `contained-in-unmerged-candidate` | Close after verified main integration of #301; exact ancestor. |
| [#292](https://github.com/djshellshoxxx/patchtrace/pull/292) | `cf50b4e8725cb1291ac6150667f2e136f023aff3` | `contained-in-unmerged-candidate` | Close after verified main integration of #301; exact ancestor. |
| [#293](https://github.com/djshellshoxxx/patchtrace/pull/293) | `aacb984e9d627be051ca8c8c3b88d5ceca0ff505` | `contained-in-unmerged-candidate` | Close after verified main integration of #301; exact ancestor. |
| [#294](https://github.com/djshellshoxxx/patchtrace/pull/294) | `e88d748cf9846e04c0c81449976f530519da83a9` | `contained-in-unmerged-candidate` | Close after verified main integration of #301; exact ancestor. |
| [#295](https://github.com/djshellshoxxx/patchtrace/pull/295) | `37d9e47ca202b33f737b15f7af724649db8c3e15` | `contained-in-unmerged-candidate` | Close after verified main integration of #301; exact ancestor. |
| [#297](https://github.com/djshellshoxxx/patchtrace/pull/297) | `95db052a11cce162d2d633cae805f28119f783a1` | `contained-in-unmerged-candidate` | Close after verified main integration of #301; exact ancestor. |
| [#301](https://github.com/djshellshoxxx/patchtrace/pull/301) | `faddea300daf4058d38d24ff04a270be6f3d832b` | `contained-in-unmerged-candidate` | Review and merge candidate or a documented successor. |

## Verification and limits

The generator tests use real temporary Git graphs to check an unmerged candidate,
independent equivalent patches with subsequently evolved content, unrelated
residue, symbolic HEAD filtering, exact-tip replay after branch movement,
shallow-history refusal and prior-report preservation on failure. The generator
and its tests passed Ruff and their focused pytest run: **7 passed**. Replaying
the exact recorded tips with PR input reconstructed from the TSV produced a
byte-identical TSV. No network or Git mutation was needed for replay.

```bash
python -m ruff check tools/branch_inventory.py tests/test_branch_inventory.py
QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_branch_inventory.py
git diff --check
```

Previous hosted evidence for #301 belongs to its exact historical head: Linux
22,476 passed / 48 skipped / 6 xfailed; Windows 22,399 passed / 126 skipped /
5 xfailed. The author's different local count of 22,477 belongs to a separate
run and is not substituted here. The seven successful PR workflows comprised
28 successful checks and three intentional skips (release, release-gate and
MSVC advisory). This inventory does not rerun or independently establish those
historical hosted results, and passing workflows do not constitute a submitted
independent code review.

No Windows desktop session, clean-machine packaging acceptance, RB-01 targeted
live rerun or owner timeout-pair acceptance is established by this inventory.
The product remains subject to the separate release and L1/L2/L3 accuracy gates.
A final integration record must refresh main/head/check identities, report exact
merged and closed PR mappings, and distinguish any automatic prerelease from
completed release acceptance.

## Successor review and repairs

The lead assigned independent, non-overlapping core and security/evidence reviews
of the full `9c411ca3..faddea30` change set. The core review covered unified
soundness, KB scope, CLI/UI boundaries, reports, research tooling and CI/release.
The security review covered process/environment/path handling, backend setup,
normalization, secondary engines, persistence, raw output ownership and retained
native receipts. The inventory review separately mapped all branch tips and all
48 open PRs. The REST discussion timeline was fetched for all 48; no submitted
review was returned. These agent reviews are independent engineering review,
not invented GitHub approval submissions.

| Finding | Reproduced behavior | Successor disposition |
|---|---|---|
| Ghidriff zero address | One-to-many identity sorting compared a string from address zero with a nonzero integer and raised `TypeError`. Four orientation/order cases failed before repair. | `81942db9` preserves zero as an integer and separately orders unavailable addresses; stable abstention/group identity is tested. |
| UE-R7/L-39 mirror cap | At the real 64-atom cap, swapping older/newer changed which equally strong atoms survived. | `81942db9` ports the smallest orientation-independent cut from #289, retains current native tie-breaks and bumps only `arbiter` to 2. Current `ude/2`, proof and channel versions remain. |
| Recent-query JSON | A 10,000-level array propagated `RecursionError`; oversized settings reached the decoder before output limits. | `81942db9` adds the 64 KiB pre-decode bound and lenient recursion recovery. |
| Release ZIP special files | A required executable with FIFO mode passed the regular-file predicate. | `ca76368c` rejects explicit FIFO/device/socket types, while accepting ordinary regular or unspecified ZIP type bits. |
| Composed archive links | Individually in-root link strings composed to an escape through a linked ancestor. | `ca76368c` validates normalized member identities and resolves link compositions within bounded budgets, without extracting or executing archive contents. |
| Archive helper race | A post-snapshot remote update could be deleted by an unconditional deletion. An isolated temporary local-repository reproduction confirmed the race; the actual origin was never targeted. | `b60a0cff` excludes `tools/archive_branches.sh` from the successor. Only the read-only inventory generator remains. No further helper execution is authorized or needed. |

The independent core reviewer reran the normalization, cap, recent-query and
current soundness neighbours against the repaired source: **281 passed**.
The lead's combined normalization/fusion/registry/search selection: **198 passed**.
These overlap and must not be summed. The separately authored release-verifier
repair has **130 passing tests**; the lead inspected its complete diff and ran
the original independent reproducers with the verifier suite: **133 passed,
1 unrelated case deselected**. The inventory generator has **7 passing tests**.
Whole-tree Ruff, dependency compatibility, protobuf runtime and whitespace checks
passed before this documentation update. Full local QA completed with **22,461
passed, 137 skipped, 6 xfailed and 1 failed in 1,794.23 seconds**. The failure is
the existing `test_a_local_unix_socket_is_not_network`: `_socket.socket(AF_UNIX)`
raises `PermissionError: [Errno 1] Operation not permitted` in this executor.
The test was neither changed nor skipped. Additional native/LLVM capability
skips remain explicit. The run began on local code `64f05310` (published as
`ca76368c`); only documentation changed during that run. Current successor
head `f7e075480999e2f5a3681ddd429dca0fd9cac986`, tree
`61882fa5630ba5cc32b300e802fb6738d758c94f`, has its own hosted qualification in
[PR #302](https://github.com/djshellshoxxx/patchtrace/pull/302). Exact-successor
Linux/Windows/package/native checks are recorded separately; historical #301
green checks are not reused for the successor.

Retained historical native manifests and receipts were checked against their raw
digests and recorded semantics. That is artifact review, not a new native run.
The separate manual Windows desktop/accessibility, clean-machine package,
targeted RB-01 rerun, original timeout-pair and L1/L2/L3 acceptance gates remain
open. Existing automatic prerelease policy is unchanged.

Adjacent strings-export issues remain tracked outside PW-01: `write_atomic`
with `force=False` has an existence-check/replace no-clobber race, and CSV export
omits document-level extraction-basis and truncation/redaction metadata including
empty exports. No strings-export behavior was changed in this continuation.

### Publication identity

The checkout has no GitHub push credential. The connected GitHub REST Git-data
interface published the reviewed changes as new commits, preserving #301 as the
first parent and preserving every exact local tree. No existing remote history
was rewritten. The local-to-published mappings are:

| Local implementation | Published commit | Exact shared tree |
|---|---|---|
| `3ad941c1023cc314fd7603f0ef9bc71c53e8dcec` | `81942db9dec05c90c926978328b4f3b7308caaf3` | `c12f6f65a885649c31a7ace9a09d98a8121afed1` |
| `5df3a0f7bce10e23ba6204aa3802ab10ed5dac51` | `5a3a6ad40453563159c825c75dbd37871ff85dae` | `d68eb87bcbc82bd3b37c726110036ed32bbb0611` |
| `0b89be7f2b77c5716b7122e6537d95fd17884293` | `b60a0cffb37935d201a3ccd7a11dd1dfcc17647e` | `571ace7426f1eb89d6ee361aacce1c393c771783` |
| `64f05310a196aee396772b62d03725171eb8cd22` | `ca76368cd7a7d24f6201af91f4b03bb56fc6c7e5` | `4da195ed54646340ec8dbe911133f260ee6977a1` |
| `4f0730b8085b9d81c34cf0298ba8c90fa0438411` | `5b33d2db017acfb9522549d1e22322c34b211bb4` | `f88cb0f677bc2c003b7cadd593f57ee3143b331b` |
