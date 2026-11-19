# PatchTrace branch consolidation inventory

Observed UTC: 2026-11-19T07:48:47.853100+00:00. All comparisons are pinned; refresh after any merge or source movement.

Main: `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`. Foundation #317: `88b0b52281dd314aa72f93819145a73135618bc4`. Follow-up #316: `f2b6827fc6270b96fb241b0722f2878de5a17361`.

## Post-foundation operation

The frozen inventory below is preserved. #317 was subsequently merged as
`fdc2696c23bdbfe7668348f25e3b336ce33039f7` after all applicable source gates
completed; its tree exactly equals the tested foundation. A complete refreshed
REST census observed 318 branches and 52 open PRs at 08:39:01 UTC. The 12
contained PRs closed automatically; no branch was deleted. See
[the operation receipt](consolidation-20261119/foundation-merge.json) and
[consolidation report](final-consolidation-report.md) for current actions.

The refreshed per-branch comparison is [recorded separately](consolidation-20261119/post-foundation-inventory.md), with [complete machine evidence](consolidation-20261119/post-foundation-evidence.zip) and [hash manifest](consolidation-20261119/post-foundation-manifest.json). After #317: **144 integrated topics** (128 ancestors + 16 patch-equivalent), 11 dependent topics, and 162 requiring review; 164 conflicting / 153 clean topic merge simulations. The new #318 repair branch is included in those counts.

## Coverage and findings

- REST branches: pages 100/100/100/17, followed by an empty page: **317 branch names, including main; 316 topic branches**.
- All PRs: pages 100/100/100/7: **307 PRs**, including **64 open PRs**.
- Exact-head current open PR checks: **1,257 check runs** and **54 legacy commit statuses**. All check/status pages fit within 100 rows. Review pages are complete; no formal submitted GitHub reviews were returned.
- Branch inventory ran against complete Git history. Every branch has main/foundation/follow-up ancestry, patch-equivalence lists, merge base, head SHA, last commit, open/historical PR associations and simulated main merge conflicts.
- **113 topic heads** are exact ancestors of main. **16 further topic heads** have all non-merge patches equivalent to main and no unique merge commits. This supports 129 already-integrated topic classifications; it does not revalidate every historical native execution.
- **26 topic heads** are contained in at least one unmerged consolidation candidate. **161 topic heads** retain review or retention work.
- Main merge simulations: **142 topic branches conflict**, **174 do not**. A clean merge is not test or semantic qualification. Actual open PR metadata reports 14 conflicts against their own possibly different bases.
- Seven prior semantic audit batches retained by #316 cover 131 historical focal names at their recorded sources. These are scoped prior observations, not newly executed tests and not whole-branch merge proof.
- Worker activity outside this run cannot be reliably inferred. Remote branches are preserved. No branch deletions, force-pushes or remote writes occurred in this inventory worker.

## Integration order and exclusions

1. Repair/qualify #317, whose 139 commits include the reviewed #304 foundation plus saved-scope/global-admission repair. It is 0 behind pinned main. Its exact ancestry contains 15 extra branch heads and 12 other open PRs.
2. Recover stable standalone changes on a new #317-based branch: strings export #308; primary environment #311; bounded advisory reads #313; parser-level DTD refusal #315; paired raw alignment #309; saved search #310. Their original PR test failures mean they are not MERGE NOW.
3. Revalidate the reconstructed combination, including fresh hosted platform gates. #309 and #311 share ui.py but add separate seams. #308/#310/#313/#315 source/tests have no later changes at pinned #316. #309 module/tests are also unchanged; shared ui.py later has environment and unrelated navigation edits.
4. #314 can be reviewed separately after #313: carry the complete current-evidence/retained-CVRF changes and later staging ownership fix `028a67abc5c1a48ef27f9d218179ce095bead798`; reconcile the saved-scope fixture adjustment from `a07fc1cf1c8d618d8d4b451888c286815a4e02de`.
5. #307 must be selectively reconstructed: its inventory feature is mixed with native research identity/provenance work. Later saved-scope preflight `d909ec5b7b2c65efaa50384215027c7e4dfaa753` and contract `fea6d6efbe` must accompany any inventory port. Later held-reader/workspace admission changes remain a separate qualification boundary.
6. Retain the remainder of #316 as PARTIAL INTEGRATION candidate. Its 465 commits are 0 behind main but diverge from #317 by 327 versus 1 commits. Windows project identity, native containment and security failures block wholesale merge. A large green subset does not establish release readiness.
7. Retain historical research, automation, skills and documentation branches unless a scoped current gap is established. Older docs and active automation proposals are not automatically product improvements.

## Evidence files

All files listed below are preserved as exact members of
[the evidence archive](consolidation-20261119/inventory-and-integration-evidence.zip),
with member SHA-256 values in [the manifest](consolidation-20261119/manifest.json).
This is the frozen baseline; later operations are appended in
[the consolidation report](final-consolidation-report.md).


- `branch-inventory-remote.json`: original all-page branch snapshot and 64 open PR bodies.
- `branch-all-prs.json`: compact complete 307-PR snapshot.
- `branch-residue.json`: full per-baseline ancestry and exact unmatched/equivalent commit arrays.
- `branch-merge-simulations.json`: full conflict path lists for all branch heads against pinned main.
- `branch-pr-gates.json`: full source-pinned current check/status/review/mergeability observations.
- `historical-semantic-summary.json`: prior focal-review cross-reference; source scope is retained explicitly.
- `standalone-pr-slice-map.json`: exact standalone commits, paths and later follow-ups.

## Every branch

M = exact main ancestor; P = all patches equivalent to main with no unique merge commits; F = contained in #317; V = contained in #316. Residual counts are unmatched non-merge patches versus #316, not missing-feature counts. CI is tied to the recorded head, not to a hypothetical merge.

| Branch | Head SHA | Disposition / evidence | Ahead / behind main | #316 residual patches | Main merge conflicts | Open PR / head CI | Last commit UTC |
|---|---|---|---:|---:|---|---|---|
| `access-test-noprefix` | `726a371ab34d4589b0456d059865ade6b82fac88` | REQUIRES REVIEW; review; prior focal batch 5 | 29 / 923 | 28 | yes (11 paths) | none / not rerun | 2026-10-12T02:49:41Z |
| `audit/ai-reports` | `dd6402b9c00d5aae79f152f4fe5ce0fa8597dc24` | REQUIRES REVIEW; review; prior focal batch 3 | 1 / 917 | 1 | yes (3 paths) | none / not rerun | 2026-10-12T05:19:02Z |
| `audit/core` | `fae13b2ed3043ddce00bbf387e386e93e7b3ee06` | REQUIRES REVIEW; review; prior focal batch 3 | 2 / 917 | 2 | yes (1 paths) | none / not rerun | 2026-10-12T05:22:06Z |
| `audit/desktop` | `4d5e48ab7df30f6318a8f3177b37ac98741e2b1f` | REQUIRES REVIEW; review; prior focal batch 3 | 1 / 917 | 1 | yes (3 paths) | none / not rerun | 2026-10-12T05:54:50Z |
| `audit/enrichment` | `cbc5b079ad2c8cdea4ec161b1afe9ac554b8ed39` | REQUIRES REVIEW; review; prior focal batch 2 | 3 / 917 | 3 | yes (9 paths) | none / not rerun | 2026-10-12T05:32:37Z |
| `audit/integration` | `f6505928d8264343caa33f878deb253626752944` | REQUIRES REVIEW; review; prior focal batch 2 | 24 / 917 | 18 | yes (35 paths) | none / not rerun | 2026-10-12T05:56:56Z |
| `audit/kb-correlation-20261107` | `c760e6ccea0d3e4df04bf76e58139d9a7fc9e9e6` | ALREADY INTEGRATED; M | 0 / 126 | 0 | no | none / not rerun | 2026-11-06T23:32:02-08:00 |
| `audit/random-boundaries-20261105` | `802b5b1bb5f5e64118256e75414b7ca74ad61fcc` | ALREADY INTEGRATED; M | 0 / 403 | 0 | no | none / not rerun | 2026-11-05T21:14:36Z |
| `audit/random-invariants-20261105` | `7716e2b02feaa04e59dce302c1c6cacbe800634b` | ALREADY INTEGRATED; M | 0 / 204 | 0 | no | none / not rerun | 2026-11-05T22:56:26Z |
| `audit/random-lifecycle-20261105` | `f2b7d1786f60df27b0228f247aab9a00bd7c1078` | ALREADY INTEGRATED; M | 0 / 403 | 0 | no | none / not rerun | 2026-11-05T21:21:23Z |
| `audit/runtime` | `9f32a6ecbd056249373b82bc1e814bd938da8c70` | REQUIRES REVIEW; review; prior focal batch 3 | 2 / 917 | 2 | yes (3 paths) | none / not rerun | 2026-10-12T05:22:42Z |
| `audit/trust-boundaries-20261107` | `d75c0490aa0109e3a983c5e6baea2cea1855f956` | ALREADY INTEGRATED; M | 0 / 123 | 0 | no | none / not rerun | 2026-11-06T23:32:32-08:00 |
| `automation/api-funded-persistent-codex-20261103` | `6fe6c4b1be060eb6e9d5208a68f0d68e1082b59c` | REQUIRES REVIEW; review | 9 / 408 | 9 | no | none / not rerun | 2026-11-03T17:19:02-07:00 |
| `automation/parallel-api-eight-agents-20261103` | `f8050a1fef23b71fd3a02b216c5035bcac3f4889` | REQUIRES REVIEW; review | 23 / 408 | 23 | no | none / not rerun | 2026-11-03T17:53:42-07:00 |
| `automation/patchtrace-api-agent-pilot-20261103` | `def36c822a80c77ae94b8e9a77da6f1ee9de1160` | REQUIRES REVIEW; review | 2 / 412 | 2 | no | none / not rerun | 2026-11-02T21:08:05-07:00 |
| `chatgpt/corpus-1` | `b7a0f0a45d2de1462367d877b7386091b4d275ce` | REQUIRES REVIEW; review | 25 / 707 | 25 | no | [#68](https://github.com/djshellshoxxx/patchtrace/pull/68) / nonpassing | 2026-10-14T22:04:43-07:00 |
| `chatgpt/deferred-audit-fixes-1` | `2174837f3172c3ff2a3c676da106f42b55648a70` | REQUIRES REVIEW; review; prior focal batch 3 | 8 / 710 | 8 | yes (7 paths) | none / not rerun | 2026-10-14T22:01:08-07:00 |
| `chatgpt/ghidriff-sequential-lock-fix-20261017` | `f6b7545bcc7a161440ab7119233c204510571370` | REQUIRES REVIEW; review; prior focal batch 3 | 5 / 858 | 5 | yes (2 paths) | none / not rerun | 2026-10-17T22:07:07-07:00 |
| `chatgpt/help-docs-1` | `e5bee6fe157c90a40f2d9f458768e2169ce123e5` | REQUIRES REVIEW; review | 25 / 706 | 25 | yes (1 paths) | [#70](https://github.com/djshellshoxxx/patchtrace/pull/70) / nonpassing | 2026-10-14T22:05:06-07:00 |
| `chatgpt/java-probe-boundaries-20261016` | `09bb4519d7d8e9ff8f40abcba7e11cb297d8b61e` | REQUIRES REVIEW; review; prior focal batch 6 | 2 / 857 | 2 | yes (1 paths) | none / not rerun | 2026-10-16T03:47:04-07:00 |
| `chatgpt/java-probe-ci-fix-20261016` | `0254841e3e635ed717e35abcf83021f001d7df29` | REQUIRES REVIEW; review; prior focal batch 6 | 1 / 857 | 1 | no | none / not rerun | 2026-10-16T03:44:36-07:00 |
| `chatgpt/java-probe-qa-fix-20261016` | `89500e12068656fa1958443ef634064effcbc40b` | ALREADY INTEGRATED; M | 0 / 855 | 0 | no | none / not rerun | 2026-10-16T03:48:40-07:00 |
| `chatgpt/kb-fixtures-1` | `781b36fb60e775ce01bf0c114e6a17b609fdb475` | REQUIRES REVIEW; review; prior focal batch 6 | 24 / 706 | 24 | yes (9 paths) | none / not rerun | 2026-10-14T22:04:45-07:00 |
| `chatgpt/lbl30-prereg-guard-20261016` | `6ae2c079e6cafa2b7bd5396cac443cd34ba7138a` | REQUIRES REVIEW; review; prior focal batch 5 | 43 / 532 | 43 | yes (11 paths) | [#85](https://github.com/djshellshoxxx/patchtrace/pull/85) / nonpassing | 2026-10-16T04:01:23-07:00 |
| `chatgpt/lbl31-coff-quoted-rip-20261016` | `6e71bfabbf5ef75449b46981e9e822f7e555a6bf` | REQUIRES REVIEW; review; prior focal batch 5 | 23 / 532 | 23 | yes (8 paths) | none / not rerun | 2026-10-16T03:54:27-07:00 |
| `chatgpt/lbl31-coff-symbol-mask-20261016` | `9622704d5c751d55700c4b642111131a7135d139` | REQUIRES REVIEW; review; prior focal batch 5 | 25 / 532 | 25 | yes (8 paths) | none / not rerun | 2026-10-16T03:54:33-07:00 |
| `chatgpt/lbl31-output-persistence-20261015` | `2019a37fa65fc37f4758469143c2daadc07e0098` | REQUIRES REVIEW; review; prior focal batch 5 | 33 / 532 | 33 | yes (8 paths) | [#78](https://github.com/djshellshoxxx/patchtrace/pull/78) / nonpassing | 2026-10-16T03:59:46-07:00 |
| `chatgpt/lbl31-windows-qa-fixes-20261016-a` | `ddb2ff077a21c1f0053ba8079564f6f86c3e155f` | REQUIRES REVIEW; review; prior focal batch 6 | 26 / 532 | 26 | yes (7 paths) | none / not rerun | 2026-10-16T03:56:19-07:00 |
| `chatgpt/lbl32-card-controls-20261016` | `9513bc05229dd7a8460fc229d7420154d61498db` | REQUIRES REVIEW; review; prior focal batch 5 | 36 / 532 | 36 | yes (8 paths) | [#79](https://github.com/djshellshoxxx/patchtrace/pull/79) / nonpassing | 2026-10-16T03:58:24-07:00 |
| `chatgpt/lbl32-recipe-aa-noise-20261016` | `eaa30013794a9bd0fedc9ec34bbe374d6db0cfc9` | REQUIRES REVIEW; review; prior focal batch 5 | 52 / 532 | 51 | yes (9 paths) | [#82](https://github.com/djshellshoxxx/patchtrace/pull/82) / nonpassing | 2026-10-16T04:07:44-07:00 |
| `chatgpt/merge-first-handoff-20261016` | `19153f10780e783bc931739dd26db97d8eaf2b92` | REQUIRES REVIEW; review; prior focal batch 7 | 5 / 858 | 5 | no | none / not rerun | 2026-10-16T04:01:53-07:00 |
| `chatgpt/nway-external-note-qa-20261016` | `8c7288276d3e49b7794b7fd80db4b02d5891cf00` | ALREADY INTEGRATED; M | 0 / 529 | 0 | no | none / not rerun | 2026-10-16T03:51:08-07:00 |
| `chatgpt/panels-1` | `cfd7cfff52f4f9b8b1264e8b7d70ef1bbef2d63f` | REQUIRES REVIEW; review | 10 / 709 | 10 | no | [#72](https://github.com/djshellshoxxx/patchtrace/pull/72) / nonpassing | 2026-10-14T22:12:06-07:00 |
| `chatgpt/patchwatch-reuse-roadmap-20261026` | `4eabf8dff2c4094681da70c7bd85ecd0da5aed9f` | ALREADY INTEGRATED; M | 0 / 851 | 0 | no | none / not rerun | 2026-10-26T12:48:24-07:00 |
| `chatgpt/r5-calibration-research-20261030` | `4d9d9051aea87319847a0b321a14d37b95cb8abd` | REQUIRES REVIEW; review | 11 / 438 | 11 | yes (3 paths) | none / not rerun | 2026-10-30T16:00:52-07:00 |
| `chatgpt/semantic-analysis-r3-20261030` | `2698b9a04d33b2d04f49c1ab737636539c6ef6f7` | REQUIRES REVIEW; review; prior focal batch 4 | 14 / 438 | 14 | yes (4 paths) | [#129](https://github.com/djshellshoxxx/patchtrace/pull/129) / passing observed checks | 2026-10-30T15:52:33-07:00 |
| `chatgpt/ue-r3-retain-decompiled-20261016` | `ebbd621d4f557905892aee5f7cf8cb7b0e2addc2` | REQUIRES REVIEW; review; prior focal batch 4 | 11 / 532 | 11 | yes (2 paths) | [#86](https://github.com/djshellshoxxx/patchtrace/pull/86) / nonpassing | 2026-10-16T03:58:45-07:00 |
| `chatgpt/ue-r7-p15-unresolved-20261016-a` | `292dc3953dd2b8f157752d12251aff68b6e5bda5` | ALREADY INTEGRATED; M | 0 / 527 | 0 | no | none / not rerun | 2026-10-16T03:51:10-07:00 |
| `chatgpt/ue-r7-strict-worker-report-20261016-a` | `9c5f9a42b499133b842b14b9619bf8390010e1ff` | ALREADY INTEGRATED; M | 0 / 528 | 0 | no | none / not rerun | 2026-10-16T03:50:34-07:00 |
| `chatgpt/unified-fixture-collection-fix-20261016` | `941c617b6854291e2448cad6d7d5710a24a8543d` | REQUIRES REVIEW; review; prior focal batch 6 | 30 / 707 | 30 | yes (5 paths) | none / not rerun | 2026-10-16T03:53:38-07:00 |
| `chatgpt/unified-fixtures-1` | `161a88345efc6484f4d7809fc6963a0193bd0057` | REQUIRES REVIEW; review; prior focal batch 6 | 25 / 707 | 25 | yes (5 paths) | none / not rerun | 2026-10-14T22:09:41-07:00 |
| `chatgpt/unified-sort-perf-qa-20261016` | `27b0a48bb8007f504b4a127a099136a6ea5c00b7` | REQUIRES REVIEW; review; prior focal batch 6 | 22 / 532 | 22 | yes (8 paths) | none / not rerun | 2026-10-16T03:58:14-07:00 |
| `claude/access-test-1791773355` | `726a371ab34d4589b0456d059865ade6b82fac88` | REQUIRES REVIEW; review; prior focal batch 6 | 29 / 923 | 28 | yes (11 paths) | none / not rerun | 2026-10-12T02:49:41Z |
| `claude/affectionate-galileo-bqd3tw` | `b29351d41060f8e9330fc9673457d835e188f993` | REQUIRES REVIEW; review; prior focal batch 4 | 2 / 132 | 2 | yes (1 paths) | [#268](https://github.com/djshellshoxxx/patchtrace/pull/268) / nonpassing | 2026-11-07T06:47:44Z |
| `claude/audit-beta` | `c93ff945b9b523abe0b829247137105788a5ea27` | REQUIRES REVIEW; review; prior focal batch 2 | 1 / 895 | 1 | yes (20 paths) | none / not rerun | 2026-10-14T05:39:33Z |
| `claude/autonomous-finish-20261104` | `ad4c49282a65d17d2ef23dfcc03e82be065c9021` | REQUIRES REVIEW; review | 132 / 406 | 122 | yes (56 paths) | [#289](https://github.com/djshellshoxxx/patchtrace/pull/289) / no checks | 2026-11-11T01:18:53Z |
| `claude/awesome-ramanujan-o3pxx3-ci` | `0bf1f8309e8425ba34199657009d3055215336f1` | REQUIRES REVIEW; review; prior focal batch 5 | 1 / 448 | 1 | yes (2 paths) | none / not rerun | 2026-10-30T05:11:51Z |
| `claude/awesome-ramanujan-o3pxx3-hostile` | `077b04e681ac74b20c0ff8bf367aa720c277f2d2` | ALREADY INTEGRATED; M | 0 / 446 | 0 | no | none / not rerun | 2026-10-30T04:59:29Z |
| `claude/awesome-ramanujan-o3pxx3-win1` | `7ac57759f3b9b332eaafb48c82f366566892f1b1` | REQUIRES REVIEW; review; prior focal batch 6 | 1 / 448 | 1 | yes (8 paths) | none / not rerun | 2026-10-30T04:55:02Z |
| `claude/bugfix-kbc-20261029` | `653f384d1ca60b7e943bd658698e0989d826b696` | ALREADY INTEGRATED; M | 0 / 851 | 0 | no | none / not rerun | 2026-10-29T03:35:43Z |
| `claude/bugfix-kev-acq-20261029` | `fbe58d800da27aff2544c6a478f0a591ff7dad3b` | ALREADY INTEGRATED; M | 0 / 852 | 0 | no | none / not rerun | 2026-10-29T03:15:26Z |
| `claude/bugfix-rules-cg-20261029` | `78d48cf80bf9a8c698e604dc1ce58e8aecedca45` | REQUIRES REVIEW; review; prior focal batch 2 | 1 / 853 | 1 | yes (6 paths) | none / not rerun | 2026-11-11T00:58:02Z |
| `claude/bugfix-rules-cg-rest-20261111` | `67b2bc456c59a510b854b0cdd9e85ed29d00b17d` | ALREADY INTEGRATED; P; prior focal batch 2 | 1 / 9 | 0 | no | none / not rerun | 2026-11-11T01:01:42Z |
| `claude/bugfix-search-pilot-20261111` | `d1f7d9aa64b28c8a8ca0a1065bb88e1e2f15b7f0` | ALREADY INTEGRATED; P; prior focal batch 1 | 1 / 9 | 0 | no | none / not rerun | 2026-11-11T01:11:22Z |
| `claude/bugfix-strings-pe-20261029` | `7ae041e79e419159299c32df98b8e69ab176e859` | ALREADY INTEGRATED; M | 0 / 849 | 0 | no | none / not rerun | 2026-10-29T03:28:26Z |
| `claude/bundle-license-gate` | `d3617acf9af7834582b4962a8c149969a7d55a22` | REQUIRES REVIEW; review; prior focal batch 5 | 4 / 865 | 3 | yes (5 paths) | none / not rerun | 2026-10-15T04:07:24Z |
| `claude/clever-clarke-s4nhi6` | `502402684b0d0aa35d7719bb5a3467de035982bc` | ALREADY INTEGRATED; P; prior focal batch 7 | 1 / 867 | 0 | yes (1 paths) | none / not rerun | 2026-10-15T01:45:41Z |
| `claude/compassionate-goldberg-5uuqks` | `198eb21e8813b28de361422cfe3c002bdb9e3970` | REQUIRES REVIEW; review | 1 / 843 | 1 | no | [#125](https://github.com/djshellshoxxx/patchtrace/pull/125) / passing observed checks | 2026-10-30T12:55:39Z |
| `claude/fix-deadline-test` | `22ff025a7710d07d7ad74be2c8f7cc0b4db0daf7` | ALREADY INTEGRATED; P; prior focal batch 7 | 1 / 857 | 0 | no | none / not rerun | 2026-10-21T09:20:14Z |
| `claude/funny-feynman-d2m0b5` | `770c11f40ef70e11dfeb3fbc2f5646cc2b4b97b9` | REQUIRES REVIEW; review; prior focal batch 4 | 19 / 9 | 18 | no | none / not rerun | 2026-11-11T01:20:11Z |
| `claude/gallant-knuth-8gxuzd` | `f249edc8ee70ae003a1478eae5418d85ed629d87` | REQUIRES REVIEW; review; prior focal batch 4 | 5 / 143 | 5 | no | none / not rerun | 2026-11-07T06:27:23Z |
| `claude/instance-b-features` | `9237c2601c0f25d306b51883875c339bab8ed82b` | REQUIRES REVIEW; review | 107 / 9 | 97 | no | none / not rerun | 2026-11-11T00:54:14Z |
| `claude/instance-c-research` | `6f767ccef8ebfffd1d2373c5124d8a961dc54b41` | REQUIRES REVIEW; review; prior focal batch 4 | 21 / 9 | 13 | no | [#283](https://github.com/djshellshoxxx/patchtrace/pull/283) / passing observed checks | 2026-11-11T00:54:42Z |
| `claude/instance-d-gui` | `2fa113889d1ffee6b68496993d3b3b6ebb0ba035` | ALREADY INTEGRATED; M | 0 / 507 | 0 | no | none / not rerun | 2026-10-22T07:56:15-07:00 |
| `claude/java-version-retry-integration` | `45fa67ad7e924cb4e2df1cd487c04a2c0ddab381` | ALREADY INTEGRATED; M | 0 / 847 | 0 | no | none / not rerun | 2026-10-29T03:02:55Z |
| `claude/jolly-fermi-eghaxy` | `99f8328ce89d02f200cf9fbc5852d9801761af28` | ALREADY INTEGRATED; M | 0 / 448 | 0 | no | none / not rerun | 2026-10-30T04:40:10Z |
| `claude/live-harness-infra-20261111` | `c59ccada97b649366af808a6d83bb465078c9011` | REQUIRES REVIEW; review; prior focal batch 6 | 6 / 9 | 6 | no | none / not rerun | 2026-11-11T00:38:50Z |
| `claude/live-proof-20261111` | `18efb7ef6d196775645f195552a32ad08e277459` | REQUIRES REVIEW; review; prior focal batch 6 | 8 / 9 | 8 | yes (1 paths) | none / not rerun | 2026-11-11T00:40:54Z |
| `claude/modest-hamilton-kz2gta` | `280bf05856eb60f4ddb0d58210616f65a3735816` | REQUIRES REVIEW; review; prior focal batch 2 | 12 / 438 | 5 | yes (6 paths) | none / not rerun | 2026-11-02T16:26:14-07:00 |
| `claude/patchtrace-cli-dotpath-spec-er6hha` | `62b9a3de4d1036a6e4b9bd2618372f4042b15f7f` | REQUIRES REVIEW; review; prior focal batch 5 | 5 / 927 | 3 | yes (8 paths) | none / not rerun | 2026-10-11T14:57:17Z |
| `claude/patchtrace-features` | `66e9adc50fb118c04e5e24eacd0c221ca483a130` | REQUIRES REVIEW; review; prior focal batch 1 | 8 / 854 | 8 | yes (22 paths) | none / not rerun | 2026-10-21T13:57:44Z |
| `claude/patchtrace-haiku-agent-motpbx` | `cbabc09e9df8a8190c769164ef0fae44f9c5cb1b` | REQUIRES REVIEW; review; prior focal batch 7 | 15 / 9 | 14 | no | [#281](https://github.com/djshellshoxxx/patchtrace/pull/281) / passing observed checks | 2026-11-11T00:42:14Z |
| `claude/patchtrace-kbf04-fp-tests-20261118` | `16ab88b0626ef05700c4199e926103932312e5c7` | DEPENDENCY BLOCKED; F | 4 / 0 | 0 | no | [#305](https://github.com/djshellshoxxx/patchtrace/pull/305) / passing observed checks | 2026-11-18T08:34:26Z |
| `claude/patchtrace-multi-worker-consolidate-24ct7v` | `ca10acb506fbf61db8142a836acfbd1e50a2aeb3` | REQUIRES REVIEW; review | 10 / 9 | 8 | no | [#179](https://github.com/djshellshoxxx/patchtrace/pull/179) / passing observed checks | 2026-11-11T00:48:56Z |
| `claude/patchtrace-search-anchors-circularity-20261118` | `f6ef1528c15b2281ee7b6f32625d02a5211c926d` | DEPENDENCY BLOCKED; F | 1 / 0 | 0 | no | [#306](https://github.com/djshellshoxxx/patchtrace/pull/306) / passing observed checks | 2026-11-18T08:56:39Z |
| `claude/patchtraces-consolidation-trngn0` | `faddea300daf4058d38d24ff04a270be6f3d832b` | DEPENDENCY BLOCKED; F | 88 / 0 | 0 | no | [#301](https://github.com/djshellshoxxx/patchtrace/pull/301) / passing observed checks | 2026-11-18T03:33:57Z |
| `claude/quirky-curie-n5pxf5` | `a5593fa58b2ead6ecf6adfe045db242232cd52a3` | ALREADY INTEGRATED; M | 0 / 845 | 0 | no | none / not rerun | 2026-10-29T03:00:33Z |
| `claude/serene-heisenberg-2y5kz6` | `7ed5cebfdaee4dc508b0cc739e86c18c1ff34a97` | REQUIRES REVIEW; review | 3 / 9 | 1 | no | [#172](https://github.com/djshellshoxxx/patchtrace/pull/172) / passing observed checks | 2026-11-11T00:38:03Z |
| `claude/sleepy-fermi-cli-parity-1` | `cf50b4e8725cb1291ac6150667f2e136f023aff3` | DEPENDENCY BLOCKED; F | 17 / 9 | 0 | no | [#292](https://github.com/djshellshoxxx/patchtrace/pull/292) / nonpassing | 2026-11-11T04:34:19Z |
| `claude/sleepy-fermi-kbc-1` | `53f5dd2611b38e3f69f8d72c3ca7cf73e9e896ab` | DEPENDENCY BLOCKED; F | 9 / 9 | 0 | no | [#291](https://github.com/djshellshoxxx/patchtrace/pull/291) / passing observed checks | 2026-11-11T01:42:27Z |
| `claude/sleepy-fermi-na-rzdiff-ownership` | `aacb984e9d627be051ca8c8c3b88d5ceca0ff505` | DEPENDENCY BLOCKED; F | 9 / 9 | 0 | no | [#293](https://github.com/djshellshoxxx/patchtrace/pull/293) / passing observed checks | 2026-11-11T04:35:52Z |
| `claude/sleepy-fermi-rq-l1-runner` | `e88d748cf9846e04c0c81449976f530519da83a9` | DEPENDENCY BLOCKED; F | 4 / 9 | 0 | no | [#294](https://github.com/djshellshoxxx/patchtrace/pull/294) / passing observed checks | 2026-11-11T04:31:05Z |
| `claude/sleepy-fermi-security-1` | `1d5a022d2840c5c071ccece503664c8c961d63f1` | DEPENDENCY BLOCKED; F | 20 / 9 | 0 | yes (1 paths) | [#290](https://github.com/djshellshoxxx/patchtrace/pull/290) / passing observed checks | 2026-11-11T04:32:43Z |
| `claude/sleepy-fermi-test-reliability` | `37d9e47ca202b33f737b15f7af724649db8c3e15` | DEPENDENCY BLOCKED; F | 2 / 9 | 0 | no | [#295](https://github.com/djshellshoxxx/patchtrace/pull/295) / nonpassing | 2026-11-11T04:29:41Z |
| `claude/sleepy-fermi-y3z4yj` | `160a60e838742b21f70effedb8e7bb48886d9266` | REQUIRES REVIEW; review | 5 / 9 | 4 | no | [#284](https://github.com/djshellshoxxx/patchtrace/pull/284) / passing observed checks | 2026-11-11T01:55:20Z |
| `claude/spec53-diagnose-launcher` | `a00fcc14ea11751ce5ca05271e2be32d06dd4535` | ALREADY INTEGRATED; P; prior focal batch 1 | 1 / 9 | 0 | no | none / not rerun | 2026-11-11T00:31:34Z |
| `claude/symbol-policy-isolated-settings` | `5db597257decc219db520c0dab8369b4d4e2ea5e` | REQUIRES REVIEW; review; prior focal batch 3 | 7 / 921 | 6 | yes (8 paths) | none / not rerun | 2026-10-12T03:55:44Z |
| `claude/ws-a2-ci-speed-20261104` | `bef720fdd50c0ab7c93a10955b3e5ec7d2a5f992` | REQUIRES REVIEW; review; prior focal batch 7 | 7 / 407 | 3 | yes (2 paths) | none / not rerun | 2026-11-04T08:04:26Z |
| `claude/ws-a-20261104` | `dabba4aea4ba0fa19e71ede05ce4fb8ab6741942` | REQUIRES REVIEW; review; prior focal batch 6 | 8 / 408 | 8 | yes (3 paths) | none / not rerun | 2026-11-04T01:50:33Z |
| `claude/ws-bc-20261104` | `e1193c8896e009930dae4edec974d9795876f0e0` | REQUIRES REVIEW; review | 29 / 406 | 21 | yes (15 paths) | [#174](https://github.com/djshellshoxxx/patchtrace/pull/174) / nonpassing | 2026-11-04T08:34:01Z |
| `claude/ws-i-20261104` | `b03a77b8a2fe9e4fa65fbe43889e06f4e68180e9` | REQUIRES REVIEW; review | 8 / 407 | 7 | yes (4 paths) | none / not rerun | 2026-11-04T04:00:41Z |
| `claude/ws-p-20261104` | `597a8b106491cd587cedf1273ee5ef6d56d71508` | REQUIRES REVIEW; review | 26 / 406 | 23 | yes (16 paths) | [#176](https://github.com/djshellshoxxx/patchtrace/pull/176) / nonpassing | 2026-11-04T05:52:47Z |
| `codex/advisory-read-bounds-20261118` | `a4061979547ef88855fbdb085228a42c3be21603` | DEPENDENCY BLOCKED; V | 199 / 0 | 0 | no | [#313](https://github.com/djshellshoxxx/patchtrace/pull/313) / nonpassing | 2026-11-18T07:36:31-08:00 |
| `codex/agent-skills-spec56-20261014` | `4467d1f3c6e113a7da808a67e8dee9d4aa5083d8` | REQUIRES REVIEW; review | 1 / 868 | 1 | yes (2 paths) | [#61](https://github.com/djshellshoxxx/patchtrace/pull/61) / nonpassing | 2026-10-14T18:13:44-07:00 |
| `codex/analyst-accessibility-20261109` | `b90a2cd49fa4ba71050a378abc753fe8c90733fd` | REQUIRES REVIEW; review; prior focal batch 1 | 5 / 9 | 5 | yes (2 paths) | none / not rerun | 2026-11-09T05:31:14-07:00 |
| `codex/audit-1` | `c2070cf8b4e7b0ade76cb000a5805009754eec55` | ALREADY INTEGRATED; M | 0 / 871 | 0 | no | none / not rerun | 2026-10-14T16:35:46-07:00 |
| `codex/audit-2` | `08b12f1b279d917736cfc17d4b8e447c8f552616` | REQUIRES REVIEW; review; prior focal batch 7 | 3 / 871 | 3 | yes (2 paths) | none / not rerun | 2026-10-14T16:47:04-07:00 |
| `codex/autonomous-checkpoint-20261102-0945` | `d038ddea43182b8709afd447140dc74fded487c5` | REQUIRES REVIEW; review; prior focal batch 1 | 38 / 431 | 33 | yes (57 paths) | none / not rerun | 2026-11-02T02:48:09-07:00 |
| `codex/autonomous-checkpoint-20261102-1020` | `c13d3257c88140c23fb585a8a59a4dce81e81928` | REQUIRES REVIEW; review; prior focal batch 1 | 39 / 431 | 34 | yes (57 paths) | none / not rerun | 2026-11-02T03:23:49-07:00 |
| `codex/autonomous-reconcile-20261101` | `0130bf81e2fe3154f30af7b68a0e6ab197946040` | REQUIRES REVIEW; review; prior focal batch 5 | 41 / 431 | 36 | yes (58 paths) | none / not rerun | 2026-11-02T11:47:01-07:00 |
| `codex/codespaces-cs1-20261109` | `a5f049cd777d3d885ec8e1572f94ea8935c9cbb6` | REQUIRES REVIEW; review | 8 / 12 | 8 | no | [#279](https://github.com/djshellshoxxx/patchtrace/pull/279) / passing observed checks | 2026-11-09T11:20:37Z |
| `codex/consolidate-backup-stability-20261102` | `f1a55c4cf21ddb0dea243bd417b74f86caaed142` | ALREADY INTEGRATED; M | 0 / 413 | 0 | no | none / not rerun | 2026-11-02T15:52:48-07:00 |
| `codex/consolidate-prereg-prefix-20261102` | `9b9452b4677ee3809a6e0f43d49567a8d15602e6` | REQUIRES REVIEW; review; prior focal batch 5 | 3 / 436 | 3 | yes (2 paths) | none / not rerun | 2026-11-02T15:45:16-07:00 |
| `codex/consolidate-replay-schema-20261102` | `ca411e77f43a9fd95ca5e0bcc7d2b58071ccae37` | REQUIRES REVIEW; review; prior focal batch 5 | 8 / 425 | 6 | yes (2 paths) | none / not rerun | 2026-11-02T15:44:54-07:00 |
| `codex/consolidated-reviewed-20261102` | `6e82fd70f315b99c6798a42c9061a1424a02933e` | REQUIRES REVIEW; review; prior focal batch 6 | 54 / 413 | 45 | yes (37 paths) | none / not rerun | 2026-11-02T16:05:55-07:00 |
| `codex/consolidation-audit-20261104` | `fbd9595351bf50217402b7a62b3e057de79f45f0` | REQUIRES REVIEW; review | 2 / 404 | 2 | yes (2 paths) | [#187](https://github.com/djshellshoxxx/patchtrace/pull/187) / nonpassing | 2026-11-04T23:43:01Z |
| `codex/consolidation-cve-reviewed-20261118` | `d8c02caea407f6d323eecd636735849c1eb31a2d` | DEPENDENCY BLOCKED; F | 138 / 0 | 0 | no | [#304](https://github.com/djshellshoxxx/patchtrace/pull/304) / passing observed checks | 2026-11-18T05:59:31-08:00 |
| `codex/consolidation-evidence-20261102` | `44c320e37b84a38259f13fa8f0f444b542b96f2c` | REQUIRES REVIEW; review; prior focal batch 6 | 55 / 413 | 46 | yes (37 paths) | none / not rerun | 2026-11-02T16:53:20-07:00 |
| `codex/consolidation-integrity-20261103` | `b58bb53debcb3323e5d8d634e09397cb7e02965f` | REQUIRES REVIEW; review; prior focal batch 6 | 58 / 412 | 46 | yes (42 paths) | [#164](https://github.com/djshellshoxxx/patchtrace/pull/164) / nonpassing | 2026-11-02T17:40:53-07:00 |
| `codex/consolidation-reviewed-20261118` | `121ffb0bcdd6af4f24e5035389d4709dffddf263` | DEPENDENCY BLOCKED; F | 105 / 0 | 0 | no | [#302](https://github.com/djshellshoxxx/patchtrace/pull/302) / nonpassing | 2026-11-18T01:07:01-08:00 |
| `codex/coordinator-rule-repairs-20261031` | `798e11ef345ed7a7a65508a466eaf77ee85ef77c` | REQUIRES REVIEW; review; prior focal batch 2 | 11 / 438 | 5 | yes (6 paths) | none / not rerun | 2026-10-31T05:25:05Z |
| `codex/corpus-integrity-20261116` | `6a5b6f2609604fe34a8da9cf347c713b21578834` | DEPENDENCY BLOCKED; F | 67 / 2 | 0 | no | none / not rerun | 2026-11-16T03:20:35-07:00 |
| `codex/corpus-output-main-20261101` | `874e9a267fdc589a796ce573f2958e1aa84ea0f6` | REQUIRES REVIEW; review; prior focal batch 6 | 9 / 425 | 6 | yes (2 paths) | none / not rerun | 2026-11-02T16:41:47-07:00 |
| `codex/deep-review-consolidation-20261030` | `95e09548a82202ae4cfd9380522f36513da87a66` | ALREADY INTEGRATED; M | 0 / 439 | 0 | no | none / not rerun | 2026-10-30T03:32:10-07:00 |
| `codex/essential-combined-verification-20261030` | `a7f13e13ffb512f8e9621753a0ae162d78942f3b` | REQUIRES REVIEW; review; prior focal batch 6 | 20 / 438 | 18 | yes (5 paths) | [#143](https://github.com/djshellshoxxx/patchtrace/pull/143) / passing observed checks | 2026-10-30T21:11:53-07:00 |
| `codex/essential-integration-20261029` | `5ed624e91468c410f2cf738ed4e36c2be3e0201d` | ALREADY INTEGRATED; M | 0 / 464 | 0 | no | none / not rerun | 2026-10-28T21:54:42-07:00 |
| `codex/essential-project-safety-20261031` | `c3868d8335a8f32f676905032dc1a6d0e9f22fd6` | REQUIRES REVIEW; review; prior focal batch 1 | 1 / 438 | 1 | yes (14 paths) | none / not rerun | 2026-10-31T22:47:36-07:00 |
| `codex/fix-pr110-ci-gates-20261029` | `c0d1c38aee74461969ff0a8b4d61179c3dbb9b0b` | REQUIRES REVIEW; review; prior focal batch 2 | 9 / 464 | 9 | yes (6 paths) | none / not rerun | 2026-10-29T20:57:01-07:00 |
| `codex/gt01-extraction-recovery-20261030` | `d76d23372acef4049115e9ae176acbeb538a82e5` | REQUIRES REVIEW; review; prior focal batch 4 | 16 / 438 | 15 | yes (5 paths) | [#141](https://github.com/djshellshoxxx/patchtrace/pull/141) / passing observed checks | 2026-10-30T21:00:03-07:00 |
| `codex/gui-bounded-ambiguous-candidates-20261029` | `3287cb3d36052bd6e44420f631ed033baf939d64` | REQUIRES REVIEW; review; prior focal batch 1 | 3 / 844 | 2 | no | none / not rerun | 2026-10-29T20:43:58-07:00 |
| `codex/identity-main-repair-20261101` | `4eebea4a5389af16bffe32a2bf9285c406d95fb1` | ALREADY INTEGRATED; M | 0 / 434 | 0 | no | none / not rerun | 2026-11-01T07:27:46-07:00 |
| `codex/java-version-retry-20261015` | `8ee61c623fa37c5a219f912cf7870bfeddcb1f70` | ALREADY INTEGRATED; M | 0 / 857 | 0 | no | none / not rerun | 2026-10-15T13:29:14-07:00 |
| `codex/kb-explicit-filename-selection-20261104` | `761b6b885f00143597c74f0457b1165a144fbdd4` | ALREADY INTEGRATED; P; prior focal batch 1 | 1 / 404 | 0 | yes (2 paths) | none / not rerun | 2026-11-04T23:40:04Z |
| `codex/kb-fixture-contract-repairs-20261030` | `a4d1e6a38c34d1952584aa65d7f5f908c45547b3` | REQUIRES REVIEW; review | 13 / 438 | 13 | yes (2 paths) | none / not rerun | 2026-10-30T21:02:26-07:00 |
| `codex/manifest-dtd-reviewed-20261118` | `23fbe4a54880319f62f40f3196794f85b6cdaec5` | DEPENDENCY BLOCKED; V | 199 / 0 | 0 | no | [#315](https://github.com/djshellshoxxx/patchtrace/pull/315) / nonpassing | 2026-11-18T07:59:45-08:00 |
| `codex/manual-correction-completeness-20261104` | `65f979a163a88ec5b32b3eb4173fa4a50ee9c920` | ALREADY INTEGRATED; M | 0 / 297 | 0 | no | none / not rerun | 2026-11-04T23:50:43Z |
| `codex/master-foundation-scope-20261118-4a7` | `88b0b52281dd314aa72f93819145a73135618bc4` | DEPENDENCY BLOCKED; F | 139 / 0 | 1 | no | [#317](https://github.com/djshellshoxxx/patchtrace/pull/317) / pending | 2026-11-18T22:38:32-08:00 |
| `codex/msrc-mixed-format-revision-20261102` | `e1b79e048d3963d747bc9f07448b039a250180ed` | REQUIRES REVIEW; review; prior focal batch 1 | 3 / 416 | 3 | yes (1 paths) | none / not rerun | 2026-11-02T12:11:45-07:00 |
| `codex/msrc-reconcile-integration-20261102` | `56374f867594dd923383c91ea71970cb7d24d173` | REQUIRES REVIEW; review; prior focal batch 1 | 42 / 426 | 36 | yes (50 paths) | none / not rerun | 2026-11-02T12:22:05-07:00 |
| `codex/parser-test-cpu-budget-20261104` | `cb204f7625d4de496642926bbda37d07e2888131` | ALREADY INTEGRATED; P; prior focal batch 7 | 5 / 406 | 0 | yes (4 paths) | none / not rerun | 2026-11-04T23:37:08Z |
| `codex/patchtrace-beta` | `c7937246a5bf3f1a09c7d121c0d438088b02040c` | ALREADY INTEGRATED; M | 0 / 930 | 0 | no | none / not rerun | 2026-10-11T02:11:31-07:00 |
| `codex/pilot-current-evidence-reviewed-20261118` | `b41d6631e679ad2777d248fa087ea71582a5bf63` | DEPENDENCY BLOCKED; V | 219 / 0 | 0 | no | [#314](https://github.com/djshellshoxxx/patchtrace/pull/314) / nonpassing | 2026-11-18T07:52:12-08:00 |
| `codex/post-consolidation-20261116` | `2d330075fbe00209fbe096ee29b60dcfd0e347b4` | DEPENDENCY BLOCKED; F | 65 / 2 | 0 | no | none / not rerun | 2026-11-16T02:58:49-07:00 |
| `codex/pr110-ci-repairs-20261029` | `bb42828d05b775c59b73a7bbd02c0113b9b9bb3b` | REQUIRES REVIEW; review; prior focal batch 2 | 7 / 464 | 7 | yes (6 paths) | none / not rerun | 2026-10-29T22:02:23-07:00 |
| `codex/pr110-kb-arch-scope-20261029` | `40e02daf93c8e13a94b74f5b80d86c1680fea7ad` | REQUIRES REVIEW; review; prior focal batch 1 | 8 / 464 | 6 | yes (5 paths) | none / not rerun | 2026-10-29T21:08:51-07:00 |
| `codex/pr110-persistence-feedback-20261029` | `3e9cedb012b4c82da3b0e5f9bc977ecd7313b64c` | REQUIRES REVIEW; review; prior focal batch 1 | 9 / 464 | 7 | yes (5 paths) | none / not rerun | 2026-10-29T21:07:07-07:00 |
| `codex/pr110-qa-wbjson-diaphora-help-20261029` | `aba4c2001a6b093f7f8cdc8b0ac20ab074ed57b8` | REQUIRES REVIEW; review; prior focal batch 2 | 6 / 464 | 6 | yes (4 paths) | none / not rerun | 2026-10-29T20:54:50-07:00 |
| `codex/pr111-bounded-nav-into-integration-20261029` | `025300f8e169556f84b6a8cfed20413e0a26b019` | REQUIRES REVIEW; review; prior focal batch 1 | 8 / 464 | 6 | yes (5 paths) | none / not rerun | 2026-10-29T21:05:00-07:00 |
| `codex/primary-environment-20261118` | `09b032f205f4ffa1838bef56007ebdb7a2308420` | DEPENDENCY BLOCKED; V | 199 / 0 | 0 | no | [#311](https://github.com/djshellshoxxx/patchtrace/pull/311) / nonpassing | 2026-11-18T07:17:09-08:00 |
| `codex/project-safe-export-20261101` | `e90254424c26ecd00e4c10c3c638e76d11b35841` | ALREADY INTEGRATED; M | 0 / 437 | 0 | no | none / not rerun | 2026-11-01T04:54:38-07:00 |
| `codex/pw01-kb-inventory-20261118` | `2b697222b34359bb46adc90aad69fd0a12708601` | DEPENDENCY BLOCKED; V | 131 / 0 | 0 | no | [#303](https://github.com/djshellshoxxx/patchtrace/pull/303) / nonpassing | 2026-11-18T01:44:12-08:00 |
| `codex/pw01-retained-source-pages-20261118` | `58fc130631f602b6e907bb054d30c21d810551d4` | DEPENDENCY BLOCKED; V | 195 / 0 | 0 | no | [#307](https://github.com/djshellshoxxx/patchtrace/pull/307) / nonpassing | 2026-11-18T06:43:08-08:00 |
| `codex/r1-ground-truth-research-20261030` | `10856edf05afae8166291f09fb3ead92f297360d` | REQUIRES REVIEW; review; prior focal batch 4 | 9 / 438 | 8 | yes (6 paths) | none / not rerun | 2026-11-02T17:50:54-07:00 |
| `codex/r1-receipt-publication-20261031` | `8c9eafc79b007a963453d8edf6cb40c804c9bc3d` | REQUIRES REVIEW; review; prior focal batch 5 | 8 / 438 | 8 | yes (6 paths) | none / not rerun | 2026-10-31T05:13:51Z |
| `codex/r2-unified-matching-research-20261030` | `b3ceb8b30d7a83da5e22c231c3b8c28179246816` | REQUIRES REVIEW; review; prior focal batch 4 | 4 / 438 | 4 | yes (7 paths) | none / not rerun | 2026-10-30T16:37:21-07:00 |
| `codex/raw-alignment-reviewed-20261118` | `3c9d3f074481b2f609330fa49ab9019eb6637849` | DEPENDENCY BLOCKED; V | 199 / 0 | 0 | no | [#309](https://github.com/djshellshoxxx/patchtrace/pull/309) / nonpassing | 2026-11-18T06:57:33-08:00 |
| `codex/real-msrc-adapter-20261101` | `d99cd7712b76e9e42661ef0b268417d7ca322d3e` | ALREADY INTEGRATED; M | 0 / 415 | 0 | no | none / not rerun | 2026-11-02T12:30:50-07:00 |
| `codex/receipt-parent-race-20261101` | `2fdac2ea9042985ac3c98545d38ac3461d00f4cc` | REQUIRES REVIEW; review | 9 / 438 | 9 | yes (6 paths) | [#150](https://github.com/djshellshoxxx/patchtrace/pull/150) / nonpassing | 2026-11-01T04:58:02-07:00 |
| `codex/release-integration-20261116` | `95db052a11cce162d2d633cae805f28119f783a1` | DEPENDENCY BLOCKED; F | 72 / 2 | 0 | no | [#297](https://github.com/djshellshoxxx/patchtrace/pull/297) / passing observed checks | 2026-11-16T11:27:34-07:00 |
| `codex/release-qualification-reviewed-20261118` | `573829f33c84e9b2d53ba51ebd7f699e39f406fe` | DEPENDENCY BLOCKED; V | 200 / 0 | 0 | no | [#312](https://github.com/djshellshoxxx/patchtrace/pull/312) / nonpassing | 2026-11-18T07:34:20-08:00 |
| `codex/repair-openai-agent-20261104` | `f019606665a740dc252e745913924debf73adc48` | REQUIRES REVIEW; review | 2 / 404 | 2 | no | none / not rerun | 2026-11-04T14:26:24-07:00 |
| `codex/rzdiff-164-investigation` | `20ef68eaab59a2941bd2fb0db918eee36107c75f` | REQUIRES REVIEW; review; prior focal batch 6 | 59 / 412 | 47 | yes (42 paths) | none / not rerun | 2026-11-02T20:50:26-07:00 |
| `codex/saved-search-reviewed-20261118` | `26558cd0723aa5fa6d883f2935ad3c43cef94a86` | DEPENDENCY BLOCKED; V | 201 / 0 | 0 | no | [#310](https://github.com/djshellshoxxx/patchtrace/pull/310) / nonpassing | 2026-11-18T07:09:14-08:00 |
| `codex/semantic-proof-reconciliation-20261031` | `745e93426a16e0a91a961b6e0bbcb71be69f2a7e` | REQUIRES REVIEW; review | 28 / 438 | 26 | yes (14 paths) | [#144](https://github.com/djshellshoxxx/patchtrace/pull/144) / nonpassing | 2026-10-31T05:50:08Z |
| `codex/storage-integrity-20261101` | `9911af4d9130b81b1875f82179e03e0a89e89794` | ALREADY INTEGRATED; M | 0 / 426 | 0 | no | none / not rerun | 2026-11-02T03:46:29-07:00 |
| `codex/strings-export-publication-20261118` | `92a411bf02fc8beb00b7a148e39db2bf68efa061` | DEPENDENCY BLOCKED; V | 2 / 0 | 0 | no | [#308](https://github.com/djshellshoxxx/patchtrace/pull/308) / nonpassing | 2026-11-18T06:08:18-08:00 |
| `codex/t9-qa-20261020` | `ecc4f2054c00dc2b324bb71134595c48dc4b6a18` | REQUIRES REVIEW; review; prior focal batch 5 | 6 / 855 | 4 | yes (1 paths) | none / not rerun | 2026-10-21T11:00:15Z |
| `codex/tier-w-fetch-20261015` | `5b7b2591e616e8c28c05c7070661b33e2ca0435c` | REQUIRES REVIEW; review; prior focal batch 4 | 6 / 859 | 6 | yes (2 paths) | none / not rerun | 2026-10-15T15:28:19-07:00 |
| `codex/training-prereg-identity-20261101` | `dfe8f421db390ccd3158393a60205fa5dd25df0b` | REQUIRES REVIEW; review; prior focal batch 6 | 4 / 436 | 3 | yes (2 paths) | none / not rerun | 2026-11-02T16:50:46-07:00 |
| `codex/verified-followup-integration-20261118` | `f2b6827fc6270b96fb241b0722f2878de5a17361` | DEPENDENCY BLOCKED; V | 465 / 0 | 0 | no | [#316](https://github.com/djshellshoxxx/patchtrace/pull/316) / nonpassing | 2026-11-18T17:00:13-08:00 |
| `codex/windows-branding-reconcile-20261030` | `8f4c4a2e0021d424d403317c6780b6db026ad76b` | REQUIRES REVIEW; review; prior focal batch 5 | 4 / 438 | 4 | yes (6 paths) | none / not rerun | 2026-10-31T00:48:50-07:00 |
| `codex/windows-setup-installer-20261017` | `9c5fe67bd10a5d1342440bb8ea6a524cca3ce1f2` | REQUIRES REVIEW; review; prior focal batch 5 | 32 / 856 | 31 | yes (7 paths) | none / not rerun | 2026-10-21T03:02:44-07:00 |
| `consolidate/docs-20261104` | `ed70e6ddac449a42f843f1c60aa878416ab31727` | REQUIRES REVIEW; review | 13 / 406 | 13 | yes (2 paths) | none / not rerun | 2026-11-04T08:37:54Z |
| `consolidate/kb-fixtures-20261104` | `820d70744dff58ef484299791d073b2e712f0524` | ALREADY INTEGRATED; P; prior focal batch 7 | 4 / 406 | 0 | yes (1 paths) | none / not rerun | 2026-11-04T08:40:04Z |
| `consolidate/research-r7-20261104` | `552c29453c5de93e22c65e47ad4187ded91e993a` | REQUIRES REVIEW; review; prior focal batch 4 | 3 / 9 | 2 | no | [#282](https://github.com/djshellshoxxx/patchtrace/pull/282) / passing observed checks | 2026-11-11T00:40:37Z |
| `consolidate/rules-callgraph-20261104` | `7b3fcbaca88256971eafd55b8fb8fe9f44634a9e` | ALREADY INTEGRATED; P; prior focal batch 2 | 9 / 406 | 0 | yes (4 paths) | none / not rerun | 2026-11-04T08:40:01Z |
| `consolidate/test-stability-20261104` | `64e8374d5d3ae97a719a2bb3ac800497c50892af` | ALREADY INTEGRATED; P; prior focal batch 7 | 4 / 406 | 0 | yes (2 paths) | none / not rerun | 2026-11-04T09:07:58Z |
| `consolidation/desktop-keyboard-accessibility-20261116` | `45997cfc997b06996a982705e6cd60dc73a8fae1` | ALREADY INTEGRATED; M | 0 / 1 | 0 | no | none / not rerun | 2026-11-16T17:01:18-07:00 |
| `docs/claude-autonomous-alpha-handoff-20261013` | `1038d3f13f214d55c28ceeb51c1c13c9b43b1d3f` | REQUIRES REVIEW; review | 2 / 905 | 2 | yes (1 paths) | none / not rerun | 2026-10-13T18:23:26-07:00 |
| `docs/codespaces-plan-20261107` | `c3536288ee3745826be814afb4d8fd07a53c526b` | ALREADY INTEGRATED; M | 0 / 131 | 0 | no | none / not rerun | 2026-11-06T23:20:06-08:00 |
| `docs/csaf-patch-intelligence-specs` | `24244831ec443fa19555586835e71da6dd4aac98` | REQUIRES REVIEW; review | 5 / 913 | 5 | yes (3 paths) | none / not rerun | 2026-10-12T03:08:13-07:00 |
| `docs/diaphora-optional-engine-20261014` | `b75ac57d85c75e8d61c61af8d104119bb1c65587` | REQUIRES REVIEW; review | 3 / 886 | 3 | yes (1 paths) | none / not rerun | 2026-10-14T01:28:54-07:00 |
| `docs/dockable-workspace-spec-20261030` | `6a1e3ce348a7e5f67bbabfe388315812cc830b03` | REQUIRES REVIEW; review | 1 / 438 | 1 | yes (1 paths) | none / not rerun | 2026-10-30T07:43:36-07:00 |
| `docs/findings-20261107` | `9d72402cc3fd884203c7a759f714fd0a4bd2c51f` | ALREADY INTEGRATED; M | 0 / 131 | 0 | no | none / not rerun | 2026-11-06T22:58:48-08:00 |
| `docs/handoff-20261107` | `39db34c5beaaf16cc60fec30f084acfde4035316` | ALREADY INTEGRATED; M | 0 / 130 | 0 | no | none / not rerun | 2026-11-06T23:12:18-08:00 |
| `docs/kbc-live-probe-result-20261107` | `c21d0ab8471ac1a541eb6d2ff929cce1fb34a2fd` | ALREADY INTEGRATED; M | 0 / 130 | 0 | no | none / not rerun | 2026-11-06T22:16:56-08:00 |
| `docs/nway-matches` | `f748cc48ea07b9af189d967979aa078610550eea` | REQUIRES REVIEW; review | 1 / 915 | 1 | no | none / not rerun | 2026-10-12T06:19:10Z |
| `docs/post-consolidation-gap-analysis-20261030` | `61b5c2bade71a8cec58ca9e1514141f4508b7c79` | REQUIRES REVIEW; review | 20 / 438 | 20 | yes (2 paths) | [#137](https://github.com/djshellshoxxx/patchtrace/pull/137) / passing observed checks | 2026-10-30T17:21:18-07:00 |
| `docs/r8-reconciliation-20261106` | `5e1e19828b3801a2f0f7d50b4250ff9a273264ef` | ALREADY INTEGRATED; M | 0 / 120 | 0 | no | none / not rerun | 2026-11-06T02:57:36-07:00 |
| `docs/ranking-reuse-20261105` | `bc52940fb32d5b5f6d1a58a860062ec60d423d1e` | ALREADY INTEGRATED; M | 0 / 184 | 0 | no | none / not rerun | 2026-11-05T23:33:18Z |
| `docs/readme-and-wiki` | `ad8fbe9f2f041653760c02e9d18a91a66dd11c39` | REQUIRES REVIEW; review | 1 / 857 | 1 | no | [#98](https://github.com/djshellshoxxx/patchtrace/pull/98) / passing observed checks | 2026-10-21T09:16:58Z |
| `docs/refresh-accuracy-handoff-20261109` | `2e408e3c24c2efad6144bf8953d639edcf9fc489` | ALREADY INTEGRATED; M | 0 / 10 | 0 | no | none / not rerun | 2026-11-09T01:21:08-07:00 |
| `docs/research-reconciliation-20261105` | `febc9de57e61162da12fb1cc9280aef9b3ec2a99` | ALREADY INTEGRATED; M | 0 / 184 | 0 | no | none / not rerun | 2026-11-05T23:35:00Z |
| `docs/research-tools-execution-plan-20261106` | `40da817650498eb7b87502016d2be90062467c50` | REQUIRES REVIEW; review | 2 / 393 | 2 | no | none / not rerun | 2026-11-06T18:24:44-07:00 |
| `docs/semantic-ghidra-roadmap` | `8b9ebc01bb221a60ee65838dfdafd59d66e15f5d` | ALREADY INTEGRATED; P | 1 / 913 | 0 | yes (1 paths) | none / not rerun | 2026-10-12T02:08:49-07:00 |
| `docs/sonar235-package-path-20261105` | `c30f11fb6f94ab3325e3bf6252326004f792294d` | ALREADY INTEGRATED; M | 0 / 183 | 0 | no | none / not rerun | 2026-11-05T23:52:33Z |
| `docs/spec-31-kb-cve-correlation-20261014` | `9088bf0e2e452c5d792f2a9e6e879f417e9fc120` | REQUIRES REVIEW; review | 12 / 883 | 12 | yes (6 paths) | none / not rerun | 2026-10-14T03:30:24-07:00 |
| `docs/spec-32-kb-patch-search-20261014` | `d0ceb56f30f81f881f1f25fb4d1dba772ff476b9` | REQUIRES REVIEW; review | 17 / 883 | 17 | yes (2 paths) | none / not rerun | 2026-10-14T03:36:26-07:00 |
| `docs/specs-plan` | `a5194581396b67395a0ae8453d73eec5ab024e54` | REQUIRES REVIEW; review | 5 / 917 | 5 | yes (9 paths) | none / not rerun | 2026-10-12T05:42:59Z |
| `docs/workbench-search-graph-floss-20261014` | `af15701d13b516662a36f20a00ece01b8462160f` | REQUIRES REVIEW; review | 6 / 883 | 6 | yes (3 paths) | none / not rerun | 2026-10-14T04:00:49-07:00 |
| `feat/acquisition` | `293362a2d8cee7d5cc373439436945888b3b805a` | REQUIRES REVIEW; review; prior focal batch 1 | 14 / 917 | 11 | yes (24 paths) | none / not rerun | 2026-10-12T05:52:11Z |
| `feat/acquisition-gui` | `7ae34d8fa26a6b6c8b7acf40f5c16d99643151ce` | REQUIRES REVIEW; review; prior focal batch 1 | 1 / 915 | 1 | yes (1 paths) | none / not rerun | 2026-10-12T06:21:08Z |
| `feat/alpha-ui-integration` | `c7ed1d90a890afa9eb67c238f9f52f458db96432` | REQUIRES REVIEW; review; prior focal batch 3 | 2 / 899 | 2 | yes (8 paths) | none / not rerun | 2026-10-13T19:36:06-07:00 |
| `feat/artifact-bytes-seam` | `91b35d09afd29e9c78169a3b095d9ea3be6c31b1` | ALREADY INTEGRATED; P; prior focal batch 3 | 1 / 903 | 0 | yes (4 paths) | none / not rerun | 2026-10-13T19:04:00-07:00 |
| `feat/byte-representations` | `303bc452d0bb6cd46ee67f731f64ec951e1ee215` | ALREADY INTEGRATED; P; prior focal batch 3 | 1 / 902 | 0 | yes (2 paths) | none / not rerun | 2026-10-13T19:14:46-07:00 |
| `feat/diffscore-workflow-20261107` | `a3aa53744006845e782c154ca6b51eb4ffcb6e1e` | ALREADY INTEGRATED; M | 0 / 125 | 0 | no | none / not rerun | 2026-11-06T23:15:42-08:00 |
| `feat/enrichment-cache` | `0368fd9b5453ab50166c08cf8dfc493e57b0ee52` | REQUIRES REVIEW; review; prior focal batch 2 | 2 / 921 | 2 | yes (8 paths) | none / not rerun | 2026-10-12T03:49:09Z |
| `feat/enrichment-contracts` | `010d809d2581d3a8ed8208e83325ba29f91b2419` | REQUIRES REVIEW; review; prior focal batch 2 | 30 / 919 | 23 | yes (31 paths) | none / not rerun | 2026-10-12T04:48:27Z |
| `feat/enrichment-cve` | `49bf245583d040a8b29d80daee8666d8c7f7b8d4` | REQUIRES REVIEW; review; prior focal batch 1 | 2 / 921 | 2 | yes (10 paths) | none / not rerun | 2026-10-12T03:52:25Z |
| `feat/enrichment-signals` | `e96441a1a90478d5b06e7b0d9b4320695a2018ed` | REQUIRES REVIEW; review; prior focal batch 2 | 3 / 921 | 3 | yes (8 paths) | none / not rerun | 2026-10-12T03:53:11Z |
| `feat/enrichment-wil` | `9a6999a0e644ef03670d10fc0b08524345c6c709` | REQUIRES REVIEW; review; prior focal batch 2 | 2 / 921 | 2 | yes (8 paths) | none / not rerun | 2026-10-12T03:48:33Z |
| `feat/local-runtime-discovery` | `b9198705ab4c144746214c1e42c15b6098063009` | REQUIRES REVIEW; review; prior focal batch 3 | 9 / 925 | 9 | yes (6 paths) | none / not rerun | 2026-10-11T05:59:51-07:00 |
| `feat/nway` | `44d431788bcc55429a033049ed997fa33c92289b` | REQUIRES REVIEW; review; prior focal batch 2 | 31 / 916 | 23 | yes (15 paths) | none / not rerun | 2026-10-12T06:22:11Z |
| `feat/pe-overview` | `4b78a6d3c0015a5fd46d557cde6cc8f0a583795b` | ALREADY INTEGRATED; P; prior focal batch 2 | 1 / 902 | 0 | yes (9 paths) | none / not rerun | 2026-10-13T19:14:46-07:00 |
| `feat/phase2-finish` | `86afe3f6563b71e1fff5ed56a907f29c6703b96e` | REQUIRES REVIEW; review; prior focal batch 2 | 30 / 916 | 22 | yes (11 paths) | none / not rerun | 2026-10-12T06:08:30Z |
| `feat/phase3-batch` | `3581b520207b464b35a7baa39d188fb4f2a08cf1` | REQUIRES REVIEW; review; prior focal batch 1 | 42 / 915 | 31 | yes (20 paths) | none / not rerun | 2026-10-12T06:53:59Z |
| `feat/profiles` | `d21b5917a66041cb1ffa4f46931e551e55f3165a` | REQUIRES REVIEW; review; prior focal batch 1 | 25 / 917 | 19 | yes (40 paths) | none / not rerun | 2026-10-12T06:03:54Z |
| `feat/raw-cache` | `28bc476713fc9b77b876cfc8f5454760ea23d4e0` | REQUIRES REVIEW; review; prior focal batch 1 | 25 / 917 | 19 | yes (35 paths) | none / not rerun | 2026-10-12T06:00:54Z |
| `feat/rq-engine-adapters-20261107` | `b561ed60db9e9bed77b37faa76d875c93e7f3364` | ALREADY INTEGRATED; M | 0 / 130 | 0 | no | none / not rerun | 2026-11-06T23:04:47-08:00 |
| `feat/rq-parity-20261107` | `f8806bb7210793efdc8d0e2f8848c3452afd5d69` | ALREADY INTEGRATED; M | 0 / 131 | 0 | no | none / not rerun | 2026-11-06T22:59:29-08:00 |
| `feat/secondary` | `b932ae1a1c8916aeac7be2d49ce27c24717f2846` | REQUIRES REVIEW; review; prior focal batch 2 | 1 / 915 | 1 | yes (12 paths) | none / not rerun | 2026-10-12T06:24:01Z |
| `feat/tooltip-registry` | `0a3843ea2abe37d42ff0291d621fa9a7c9744bbc` | ALREADY INTEGRATED; P; prior focal batch 3 | 1 / 902 | 0 | yes (4 paths) | none / not rerun | 2026-10-13T19:14:56-07:00 |
| `feat/verified-offline-runtime-bundle` | `1724503d01be7aee13cb43a3a7a28b8a9ff54ece` | REQUIRES REVIEW; review; prior focal batch 4 | 32 / 920 | 29 | yes (11 paths) | none / not rerun | 2026-10-12T04:03:15Z |
| `feat/winpairs-workflow-20261107` | `2e43d3f4d7ee6327f1f95e20c5f5b505bcd8b624` | ALREADY INTEGRATED; M | 0 / 131 | 0 | no | none / not rerun | 2026-11-06T23:10:58-08:00 |
| `feature/alpha-file-overview-20261013` | `476016590be5cd1315613759af18ff61c7c27851` | REQUIRES REVIEW; review; prior focal batch 3 | 4 / 905 | 4 | yes (3 paths) | none / not rerun | 2026-10-13T18:19:34-07:00 |
| `feature/current-project-investigation-20261105` | `ef70e0bdf02a202cf7ce4780da37bba8ed63fafd` | ALREADY INTEGRATED; M | 0 / 229 | 0 | no | none / not rerun | 2026-11-05T22:03:42Z |
| `feature/evidence-reconciliation-confidence` | `ddda35f40b94c145b2a9a9b68509b4ddb76a090a` | REQUIRES REVIEW; review; prior focal batch 2 | 6 / 913 | 6 | yes (4 paths) | none / not rerun | 2026-10-12T02:49:14-07:00 |
| `feature/gui-inspection-preview` | `8b94227a81b71841c65783c775f704a538d35710` | REQUIRES REVIEW; review; prior focal batch 3 | 5 / 913 | 5 | yes (2 paths) | none / not rerun | 2026-10-13T18:14:21-07:00 |
| `fix/backend-exit-diagnostics` | `bc00a6912dde57482a301bf64ef6fbc3f324cb92` | REQUIRES REVIEW; review; prior focal batch 3 | 7 / 924 | 6 | yes (5 paths) | none / not rerun | 2026-10-11T06:06:36-07:00 |
| `fix/codetext-budget-wave3` | `c7fb422c750f1d0e5591277b91492874afd79af7` | REQUIRES REVIEW; review; prior focal batch 3 | 7 / 185 | 6 | yes (3 paths) | none / not rerun | 2026-11-05T23:28:51Z |
| `fix/codex-cloud-secret-preflight-20261103` | `bd3dbcae9254853f534b735864c0709f6766ced3` | ALREADY INTEGRATED; M | 0 / 409 | 0 | no | none / not rerun | 2026-11-03T11:02:05-07:00 |
| `fix/explicit-offline-symbol-policy` | `2e6618762ab6e15e5be0be60aec3fb8f56af44f3` | REQUIRES REVIEW; review; prior focal batch 3 | 12 / 926 | 12 | yes (9 paths) | none / not rerun | 2026-10-11T05:51:42-07:00 |
| `fix/ghidra-dot-paths` | `5c3b1df94c0d2a908bb0459caceb336912527555` | REQUIRES REVIEW; review; prior focal batch 3 | 6 / 928 | 6 | yes (4 paths) | none / not rerun | 2026-10-11T05:16:48-07:00 |
| `fix/ghidriff-timeout-progress-20261106` | `7e5d981935e2f8190790de90c2cc261834f9b519` | ALREADY INTEGRATED; M | 0 / 394 | 0 | no | none / not rerun | 2026-11-06T08:54:11-07:00 |
| `fix/isolate-ghidra-scratch` | `7ea7272311271a540a188e5d0de6d3aaa8864611` | REQUIRES REVIEW; review; prior focal batch 3 | 8 / 927 | 8 | yes (6 paths) | none / not rerun | 2026-10-11T05:32:01-07:00 |
| `fix/pe-inspection-row-tooltips-20261013` | `0182a8035d64071fc88b5f299edc3ef3760946b5` | REQUIRES REVIEW; review; prior focal batch 3 | 6 / 898 | 6 | yes (2 paths) | none / not rerun | 2026-10-13T20:32:20-07:00 |
| `fix/pr110-ci-regressions-20261029` | `979ddfad860c95ceabeb5b670b771900b5617098` | ALREADY INTEGRATED; M | 0 / 456 | 0 | no | none / not rerun | 2026-10-29T20:58:10-07:00 |
| `fix/pr205-partial-pe-inspect-20261106` | `cce47934dfc4184bc33df63b712e188e9bca25ac` | ALREADY INTEGRATED; M | 0 / 196 | 0 | no | none / not rerun | 2026-11-06T16:53:40-07:00 |
| `fix/pr205-review-contracts-20261106` | `4f3e62c4f130227b6ff1201f798b3f449ab89c60` | ALREADY INTEGRATED; M | 0 / 187 | 0 | no | none / not rerun | 2026-11-06T17:55:36-07:00 |
| `fix/pr205-ui-seam-help-extraction-20261106` | `a53c7d1bd360f2dbc3c75ead8da8e978cbb4c314` | ALREADY INTEGRATED; M | 0 / 194 | 0 | no | none / not rerun | 2026-11-06T17:42:34-07:00 |
| `fix/remediation-53088704-982db3` | `15370a0bf690ea65f49d1f6cc67c40f73fd3d77c` | REQUIRES REVIEW; review; prior focal batch 5 | 2 / 436 | 2 | yes (5 paths) | none / not rerun | 2026-11-01T13:18:14Z |
| `fix/remediation-a58defa8-139db0` | `6d9c06c2d82cb778712cf2e3c963b63c6363f7c9` | REQUIRES REVIEW; review; prior focal batch 4 | 1 / 131 | 1 | yes (3 paths) | none / not rerun | 2026-11-07T06:47:11Z |
| `fix/remediation-b1ab7332-a8fac4` | `3feec96f6546e755061a458ce0dc6e8ee0fab640` | REQUIRES REVIEW; review; prior focal batch 4 | 2 / 130 | 2 | no | none / not rerun | 2026-11-07T07:05:01Z |
| `fix/windows-posix-mingw-workflow-20261115` | `3b3ad32f60df9fd6994e25a8920cfb335cc3d602` | ALREADY INTEGRATED; P; prior focal batch 6 | 1 / 3 | 0 | no | none / not rerun | 2026-11-15T18:13:58-07:00 |
| `haiku/cli-help-suppress-20261027` | `37940b706f117f9786109433aed7751eca4e52a6` | REQUIRES REVIEW; review; prior focal batch 4 | 1 / 854 | 1 | yes (1 paths) | none / not rerun | 2026-10-27T22:05:22Z |
| `haiku/phase2-handoff-import-20261027` | `4522030ff3ff76d720a5efc33953aaa5e5837398` | REQUIRES REVIEW; review; prior focal batch 7 | 1 / 854 | 1 | yes (1 paths) | none / not rerun | 2026-10-27T23:29:01Z |
| `haiku/skills-manifest-import-20261027` | `039b0ef8a5d0cb5136aca72be5c65d11867c19af` | REQUIRES REVIEW; review | 1 / 854 | 1 | no | none / not rerun | 2026-10-27T23:29:58Z |
| `integrate/autonomous-20261105` | `3d6c37e665bd3039aa374dbb58e1dde4e8dd7d0e` | ALREADY INTEGRATED; M | 0 / 395 | 0 | no | none / not rerun | 2026-11-05T20:58:16Z |
| `integrate/calibration-prereg-20261105` | `57f95e09d8a924b8469490cfa08387b849065179` | ALREADY INTEGRATED; M | 0 / 204 | 0 | no | none / not rerun | 2026-11-05T22:51:07Z |
| `integrate/calibration-replay-20261105` | `f8ed23564166f1952512ae004543c91e85c4a6ee` | ALREADY INTEGRATED; M | 0 / 203 | 0 | no | none / not rerun | 2026-11-05T22:56:39Z |
| `integrate/continuation-20261106` | `37b771300053e8872febead1fc384fea9126ae90` | ALREADY INTEGRATED; M | 0 / 123 | 0 | no | none / not rerun | 2026-11-06T01:22:45-07:00 |
| `integrate/gui-inspection-20261105` | `3fa22c611697d7593755c329fd762bfb47b39b84` | ALREADY INTEGRATED; M | 0 / 403 | 0 | no | none / not rerun | 2026-11-05T20:49:58Z |
| `integrate/independent-wave4-20261105` | `6e9f4524776abb95a7da7f4f49de01483a2c5330` | ALREADY INTEGRATED; M | 0 / 66 | 0 | no | none / not rerun | 2026-11-06T22:43:04-08:00 |
| `integrate/kb-20261105` | `75c01a29ea791a2a5859d18d54f8e6db06f255b8` | ALREADY INTEGRATED; M | 0 / 399 | 0 | no | none / not rerun | 2026-11-05T20:47:10Z |
| `integrate/kb-investigation-20261105` | `bdbfd7dc45083dd7439f4591f17724b6de651412` | ALREADY INTEGRATED; M | 0 / 394 | 0 | no | none / not rerun | 2026-11-05T21:17:38Z |
| `integrate/merge-readiness-20261106` | `f393bb68ddc11eabb95a6598aa6f86650bd9aa37` | ALREADY INTEGRATED; M | 0 / 132 | 0 | no | none / not rerun | 2026-11-05T23:32:44-07:00 |
| `integrate/native-controls-20261105` | `a0f417466da80ddc18ee05cc31b8d3492e7cb98b` | ALREADY INTEGRATED; M | 0 / 396 | 0 | no | none / not rerun | 2026-11-05T20:49:59Z |
| `integrate/project-adoption-20261105` | `1c97defacd54a593a8ecdcda2b9c11c85b073791` | ALREADY INTEGRATED; M | 0 / 402 | 0 | no | none / not rerun | 2026-11-05T20:54:31Z |
| `integrate/recovery-forward-wave3-20261106` | `a1ed8c9167529fbf855d7dc088132379ee385cf4` | ALREADY INTEGRATED; M | 0 / 181 | 0 | no | none / not rerun | 2026-11-06T02:13:20-07:00 |
| `integrate/rules-20261105` | `c849d0087b7dbb647d887a2501259a87c79579f4` | ALREADY INTEGRATED; M | 0 / 394 | 0 | no | none / not rerun | 2026-11-05T20:46:05Z |
| `integrate/secondary-prep-20261105` | `b6b5bf6c65611f50b9fa6524ce980a0ff07511ee` | ALREADY INTEGRATED; M | 0 / 402 | 0 | no | none / not rerun | 2026-11-05T20:53:50Z |
| `integrate/swarm-followups-20261105` | `c6691ab1ca143930f746f5c5087d3f492fd544d1` | ALREADY INTEGRATED; M | 0 / 211 | 0 | no | none / not rerun | 2026-11-05T22:08:30Z |
| `integrate/swarm-qualified-20261105` | `4e9f1d5d71cf1f193fb7ed500daf852e5156304f` | ALREADY INTEGRATED; M | 0 / 178 | 0 | no | none / not rerun | 2026-11-06T19:53:48-07:00 |
| `integrate/swarm-wave3-20261105` | `a0e2c80eda74b70be370bf5f6a93424365230b89` | ALREADY INTEGRATED; M | 0 / 180 | 0 | no | none / not rerun | 2026-11-06T03:27:41-07:00 |
| `integration/controlled-consolidation-20261030` | `f18687fd035b67961c1072af84f8c2b3442979e0` | REQUIRES REVIEW; review | 11 / 438 | 11 | yes (2 paths) | none / not rerun | 2026-10-30T16:29:34-07:00 |
| `integration/kb-fixtures-pr69-20261030` | `2fcd627e52a6d784d5c2e5b4ea8105e90b8589b3` | REQUIRES REVIEW; review; prior focal batch 7 | 12 / 438 | 12 | yes (11 paths) | none / not rerun | 2026-10-30T16:30:26-07:00 |
| `main` | `9c411ca3d7b47f950be5f0c6f01b3c54184554c6` | ALREADY INTEGRATED; M | 0 / 0 | 0 | no | none / not rerun | 2026-11-16T17:01:30-07:00 |
| `qualify/native-cli-seeding-20261105` | `8fae317bcac6cb125956965cd3ebbb39e9f9bbd2` | REQUIRES REVIEW; review | 5 / 204 | 5 | no | [#224](https://github.com/djshellshoxxx/patchtrace/pull/224) / nonpassing | 2026-11-05T23:26:11Z |
| `qualify/native-controls-20261105` | `dc3bf773fead3f10d3e825d56ccf035741f29c28` | ALREADY INTEGRATED; M | 0 / 394 | 0 | no | none / not rerun | 2026-11-05T21:32:41Z |
| `qualify/native-provision-20261105` | `c50ab287de13982b132716d67f9e5fabe22799cb` | REQUIRES REVIEW; review | 4 / 204 | 4 | no | [#222](https://github.com/djshellshoxxx/patchtrace/pull/222) / nonpassing | 2026-11-05T23:17:21Z |
| `qualify/offline-tooling-20261105` | `c3370578086cbfda7b971a031d173b82e860a1f5` | ALREADY INTEGRATED; M | 0 / 403 | 0 | no | none / not rerun | 2026-11-05T21:34:34Z |
| `repair/gt01-consolidated-native-evidence-20261030` | `c04ad725551fe8daa139b37aa2cdf46d6d161b65` | REQUIRES REVIEW; review; prior focal batch 4 | 12 / 438 | 12 | yes (5 paths) | [#139](https://github.com/djshellshoxxx/patchtrace/pull/139) / nonpassing | 2026-10-30T17:45:21-07:00 |
| `repair/gt01-native-identical-controls-20261030` | `fb91cff6d91c77a2c539c896b670d81180dcc637` | REQUIRES REVIEW; review; prior focal batch 4 | 14 / 438 | 14 | yes (6 paths) | [#140](https://github.com/djshellshoxxx/patchtrace/pull/140) / passing observed checks | 2026-10-30T20:44:38-07:00 |
| `repair/gt01-unified-live-gates-20261030` | `ca1a36c0caea44a9225e487f3ba7b0828c90a567` | REQUIRES REVIEW; review; prior focal batch 4 | 15 / 438 | 15 | yes (4 paths) | none / not rerun | 2026-10-30T17:33:04-07:00 |
| `repair/kb-ui-import-boundary-20261105` | `226ac7e514fd90ddb71ec7e3d295bb4aa5bc06b6` | ALREADY INTEGRATED; M | 0 / 231 | 0 | no | none / not rerun | 2026-11-05T21:52:55Z |
| `repair/native-input-open-20261105` | `0526d546a247f47411b088ac083d6f1fe1e10781` | ALREADY INTEGRATED; M | 0 / 400 | 0 | no | none / not rerun | 2026-11-05T21:28:46Z |
| `repair/native-normalizer-wave3-20261105` | `cf9cefff88b71dbae6af9131b8f59a1fbb82c894` | ALREADY INTEGRATED; M | 0 / 195 | 0 | no | none / not rerun | 2026-11-05T23:04:20Z |
| `repair/native-source-identity-20261105` | `c3be348b544b5022b3f92858923d6d890538aa53` | ALREADY INTEGRATED; M | 0 / 231 | 0 | no | none / not rerun | 2026-11-05T21:40:13Z |
| `repair/normalizer-address-identity-20261105` | `631b5e919699e722e0ce3e3dee11b29c9c40ce10` | ALREADY INTEGRATED; M | 0 / 189 | 0 | no | none / not rerun | 2026-11-05T23:08:43Z |
| `repair/parity-parser-budget-20261105` | `c923039bd311449d8c97bee8ed09e97b339b6653` | ALREADY INTEGRATED; M | 0 / 231 | 0 | no | none / not rerun | 2026-11-05T21:41:32Z |
| `repair/pr205-main-reconciliation-20261106` | `96e8e085cb95f2b75bd75b63c8ede436e2152499` | ALREADY INTEGRATED; M | 0 / 199 | 0 | no | none / not rerun | 2026-11-06T03:36:42-07:00 |
| `repair/pr205-qualification-20261106` | `4465a0492367d08f324e80b290a594791921691c` | ALREADY INTEGRATED; M | 0 / 204 | 0 | no | none / not rerun | 2026-11-05T22:37:31-07:00 |
| `repair/project-create-rollback-20261105` | `2a3639adde50585dd7ac6dbcb029f085ac0856c6` | ALREADY INTEGRATED; M | 0 / 403 | 0 | no | none / not rerun | 2026-11-05T21:35:52Z |
| `repair/rzdiff-native-callback-size-20261103` | `edab7d916970144b33c98384834369773e5b0e62` | REQUIRES REVIEW; review; prior focal batch 5 | 61 / 412 | 48 | yes (45 paths) | none / not rerun | 2026-11-02T21:06:22-07:00 |
| `repair/rzdiff-native-red-control-20261103` | `b304034e3c310528f7e0a3206eda48c94e0a6873` | REQUIRES REVIEW; review | 63 / 412 | 49 | yes (47 paths) | [#168](https://github.com/djshellshoxxx/patchtrace/pull/168) / nonpassing | 2026-11-02T21:15:11-07:00 |
| `repair/rzdiff-producer-ownership` | `4d66af5577e6f6ad8f6e21440f6fe4187e0c8fe5` | REQUIRES REVIEW; review; prior focal batch 5 | 60 / 412 | 48 | yes (45 paths) | [#165](https://github.com/djshellshoxxx/patchtrace/pull/165) / nonpassing | 2026-11-02T20:57:22-07:00 |
| `repair/streamed-series-recovery-20261105` | `20a60f9d12d75b8df9d4f70f96a0fd27bd038331` | ALREADY INTEGRATED; M | 0 / 402 | 0 | no | none / not rerun | 2026-11-05T21:28:44Z |
| `repair/subprocess-venv-20261106` | `c804e4d94430368c0eafe1da899493a8cf6520aa` | ALREADY INTEGRATED; M | 0 / 401 | 0 | no | none / not rerun | 2026-11-06T00:48:44-07:00 |
| `repair/unified-ci-20261105` | `b5f6e1381dfbe98ccc71d1e126a6fd02fc95aa81` | ALREADY INTEGRATED; M | 0 / 295 | 0 | no | none / not rerun | 2026-11-05T20:48:25Z |
| `repair/unified-support-evidence-20261105` | `95749419783e6be7548be613e1000113497c6d2a` | ALREADY INTEGRATED; M | 0 / 293 | 0 | no | none / not rerun | 2026-11-05T21:21:32Z |
| `repair/verified-bytes-20261105` | `e5f9302e20ee37e8e3323a8d8b177fd8b0649e6a` | ALREADY INTEGRATED; M | 0 / 403 | 0 | no | none / not rerun | 2026-11-05T20:57:00Z |
| `repair/winbindex-metadata-budget-20261105` | `64eb58ece2f44914e8f94135ab1caefbb5a83f6b` | ALREADY INTEGRATED; M | 0 / 160 | 0 | no | none / not rerun | 2026-11-05T23:47:45Z |
| `repair/wizard-lock-retry-20261105` | `38be184cda6fbe6f79a6f265b04e2efc6a2688dd` | ALREADY INTEGRATED; M | 0 / 204 | 0 | no | none / not rerun | 2026-11-05T23:01:09Z |
| `repair/workflow-fragment-20261105` | `1229ca3bba6bc099d040c279ed9ebc8b91ae913e` | ALREADY INTEGRATED; M | 0 / 403 | 0 | no | none / not rerun | 2026-11-05T21:24:01Z |
| `research/additional-reuse-claude-20261103` | `be4a58ff7d8facc57e99faac9c743cb8d60b36f4` | REQUIRES REVIEW; review | 1 / 408 | 1 | yes (1 paths) | none / not rerun | 2026-11-03T19:35:28-07:00 |
| `research/kbc-live-probe-20261106` | `3839f3b62c923a80340c40c44855305890604f78` | ALREADY INTEGRATED; M | 0 / 391 | 0 | no | none / not rerun | 2026-11-06T19:39:22-08:00 |
| `research/l1-join-corpus-20261107` | `ca3572e7d7a5cf78d45732c18af7ebfe4922d350` | ALREADY INTEGRATED; M | 0 / 131 | 0 | no | none / not rerun | 2026-11-06T23:08:53-08:00 |
| `research/qualification-tools-rq00-rq01-20261106` | `941c0da4431f682537e99aa230df0da04013b4e1` | ALREADY INTEGRATED; M | 0 / 383 | 0 | no | none / not rerun | 2026-11-06T20:20:53-08:00 |
| `research/r4-vulnerability-correlation-20261030` | `ff570bdd784d02f745e4ad21d8aa7b4f1f776344` | REQUIRES REVIEW; review | 12 / 438 | 12 | no | [#130](https://github.com/djshellshoxxx/patchtrace/pull/130) / passing observed checks | 2026-10-30T15:57:42-07:00 |
| `research/r6-final-integration-engineering-notes-20261030` | `3010f289dbb46a1db62218a35cca03420090e306` | REQUIRES REVIEW; review | 12 / 438 | 12 | no | [#133](https://github.com/djshellshoxxx/patchtrace/pull/133) / nonpassing | 2026-10-30T16:22:59-07:00 |
| `research/r7-advanced-binary-analysis-20261030` | `c9d1aab6a78847ce1632fe833d15af2e3b9c6e9b` | REQUIRES REVIEW; review | 29 / 438 | 29 | yes (1 paths) | [#134](https://github.com/djshellshoxxx/patchtrace/pull/134) / nonpassing | 2026-10-30T16:31:37-07:00 |
| `research/r8-deep-uncertainty-20261030` | `12dd4f2b41b468b0eb566bd502219daa821012df` | REQUIRES REVIEW; review; prior focal batch 4 | 16 / 438 | 16 | yes (5 paths) | [#135](https://github.com/djshellshoxxx/patchtrace/pull/135) / nonpassing | 2026-10-30T16:31:46-07:00 |
| `research/windows-candidates-gaps-20261107` | `1f11a43ba1904e5c6c9d5d4f261fa606347da6ca` | ALREADY INTEGRATED; M | 0 / 131 | 0 | no | none / not rerun | 2026-11-06T23:30:40-08:00 |
| `research/windows-candidates-github-20261107` | `35d7e3c980c0e04c7b6319bfd8fc6c7898c31226` | ALREADY INTEGRATED; M | 0 / 131 | 0 | no | none / not rerun | 2026-11-06T23:02:02-08:00 |
| `research/windows-candidates-sources-20261107` | `740961828e22ca8048cd881f21ef9c028955ab73` | ALREADY INTEGRATED; M | 0 / 131 | 0 | no | none / not rerun | 2026-11-06T23:00:42-08:00 |
| `research/windows-pair-candidates-20261107` | `e5e783f6b8ffae83341092f5915ba02b9856ecc1` | ALREADY INTEGRATED; M | 0 / 127 | 0 | no | none / not rerun | 2026-11-06T22:51:30-08:00 |
| `research/windows-pins-20261107` | `ac826a2efe428de7dbf290aa5894a2d357d7da0c` | ALREADY INTEGRATED; M | 0 / 130 | 0 | no | none / not rerun | 2026-11-06T23:34:22-08:00 |
| `resume/desktop-index-refresh-20261106` | `c9cea0671442a6051b068acfb69d17aabcf674ae` | ALREADY INTEGRATED; M | 0 / 148 | 0 | no | none / not rerun | 2026-11-05T23:59:14Z |
| `resume/kb-acquire-lifecycle-20261106` | `b8bda98452b2f742ad55064aa2e1452700658a33` | ALREADY INTEGRATED; M | 0 / 144 | 0 | no | none / not rerun | 2026-11-06T00:02:54Z |
| `security/offline-bundle-no-overwrite-20261013` | `a39cab81de3e0eeadf57e6255d2fe3e131b3294a` | REQUIRES REVIEW; review; prior focal batch 4 | 2 / 909 | 2 | no | none / not rerun | 2026-10-13T15:23:04-07:00 |
| `test/advisory-acceptance-20261105` | `69c705d052e6b6fb3c96ea49062d6a207829c1b8` | ALREADY INTEGRATED; M | 0 / 184 | 0 | no | none / not rerun | 2026-11-05T23:35:43Z |
| `test/product-acceptance-20261106` | `81825ee9638454737d3fb7efa3e6c73b8f3eb105` | ALREADY INTEGRATED; M | 0 / 124 | 0 | no | none / not rerun | 2026-11-06T01:22:33-07:00 |
| `test/recovery-diagnostics-20261106` | `064f1c0075a4cfe5ec1eba2f9a04d3f1058ecf0c` | ALREADY INTEGRATED; M | 0 / 131 | 0 | no | none / not rerun | 2026-11-06T00:54:29-07:00 |
| `work/calibration-invariants-20261105` | `a6948be8049591247f0bc19a601645b85bc03eb7` | ALREADY INTEGRATED; M | 0 / 184 | 0 | no | none / not rerun | 2026-11-05T23:31:31Z |
| `work/candidate-correlation-20261105` | `fee7c3664a2050aed30a3c3d43ea28c0c3621ee3` | ALREADY INTEGRATED; M | 0 / 184 | 0 | no | none / not rerun | 2026-11-05T23:30:15Z |
| `work/consented-winbindex-refresh-20261105` | `83320a32c7249f92a1d7ba708c8fc8e12e4aa15c` | ALREADY INTEGRATED; M | 0 / 160 | 0 | no | none / not rerun | 2026-11-05T23:47:34Z |
| `work/investigation-accessibility-20261105` | `b5d4bceabdc34f520120d9dc336d975768e20483` | ALREADY INTEGRATED; M | 0 / 184 | 0 | no | none / not rerun | 2026-11-05T23:26:11Z |
| `work/investigation-candidates-20261105` | `bf3661966785a971f484b6339af81274278d1434` | ALREADY INTEGRATED; M | 0 / 181 | 0 | no | none / not rerun | 2026-11-05T23:51:47Z |
| `work/online-adapter-20261105` | `e14b4445fd0705e2ecffa1bc4842ab73bce373e9` | ALREADY INTEGRATED; M | 0 / 184 | 0 | no | none / not rerun | 2026-11-05T23:25:35Z |
| `work/online-investigation-20261105` | `bf46954ef2c6c9a278d9b78f5b4274242e617e09` | ALREADY INTEGRATED; M | 0 / 183 | 0 | no | none / not rerun | 2026-11-05T23:35:30Z |
| `work/pe-parser-security-20261105` | `8975c517af22aca0c0f90eb931b8a06ab18687b5` | ALREADY INTEGRATED; M | 0 / 184 | 0 | no | none / not rerun | 2026-11-05T23:39:16Z |
| `work/persistence-security-20261105` | `1a1e1951c55cdef46ff248145031639674ce1c63` | ALREADY INTEGRATED; M | 0 / 184 | 0 | no | none / not rerun | 2026-11-05T23:25:38Z |
| `work/product-start-20261106` | `0b7d858149db0c88ffcf8f3e6ba474d99f39afeb` | ALREADY INTEGRATED; M | 0 / 131 | 0 | no | none / not rerun | 2026-11-06T01:13:08-07:00 |
| `work/product-start-wave3` | `7e7a52ebf4de1529cfc5da7274820a5e955126fc` | ALREADY INTEGRATED; M | 0 / 195 | 0 | no | none / not rerun | 2026-11-05T23:05:11Z |
| `work/winbindex-publication-20261105` | `2afe874d6be17a4596d3955b71b493d5e0e4ed00` | ALREADY INTEGRATED; M | 0 / 159 | 0 | no | none / not rerun | 2026-11-05T23:49:17Z |
| `work/windows-package-preflight-20261105` | `93b4b9a80d31c97659269429e0b680c9218fdf70` | ALREADY INTEGRATED; M | 0 / 184 | 0 | no | none / not rerun | 2026-11-05T23:31:34Z |
| `worker/patchtrace-cli-help-20261104` | `81a9fb28f30630e2fd168422dc4672af3a34aa52` | ALREADY INTEGRATED; M | 0 / 301 | 0 | no | none / not rerun | 2026-11-04T10:12:45-07:00 |

## Limits

This mechanical inventory does not label a conflict-free branch as qualified, reuse stale native passes as current evidence, or equate patch-equivalence with a complete semantic audit of changed contracts. Original PR source heads remain intact. Fresh integration tests and independent review are required before each remote merge. No new test suite was run by the inventory stage.
