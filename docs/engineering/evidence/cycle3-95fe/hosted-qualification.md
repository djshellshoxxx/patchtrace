# Cycle 3 exact-source hosted qualification

Observed 2026-11-21 04:36–04:40 UTC. Read-only GitHub REST/local Git; no repository source, refs, workflows or PRs changed. Receipts were reconstructed in the new scratch filesystem after the previous temporary filesystem disappeared.

## Current result

All current non-release checks on PRs 345–348 are successful. No relevant job remained queued/in-progress at capture. All four Snyk statuses are successful. Release and release-gate jobs are intentionally skipped.

| PR | Head | QA/Qt/package/smoke run | Native PR run |
| --- | --- | --- | --- |
| 345 | 39c38a02f126963fc03827fa49741255590227ad | 44840721370, attempt 2 success | 44840721268 success |
| 346 | c07774ecf5a3f7337834f95a9a4c51c8ec5fad44 | 44841261805 success | 44841261831 success |
| 347 | b461ac64eb9beb74449ce2b18b6795a2af34a02a | 44843482603 success | 44843482467 success |
| 348 | 6b6fcd3597a604212032ffc453477aeb6edc69ff | 44858504288 success | 44858504326 success |

All four are open draft PRs, mergeable=true, mergeable_state=clean. Each QA run contains successful Linux/Windows full pytest/Ruff, five Qt jobs, Linux package and two Ubuntu smoke jobs. Inspected Windows steps include frozen/portable checks, NSIS install, installer build and install/launch/uninstall. Each native PR run has five successful scenarios. Duplicate push-native runs for 345/348 also passed; do not add them to test counts.

## PR348 source and full-suite proof

Both QA logs identify synthetic checkout **8b29d4d48274a250cc63f3795d322430b237313d**, parents b461ac64eb9beb74449ce2b18b6795a2af34a02a and 6b6fcd3597a604212032ffc453477aeb6edc69ff. Independent GitHub commit GETs confirm checkout and head share complete tree **9cb2ba74b088dfce7d87d37403108bcd3aa05326**.

- [Linux job 136706199528](https://github.com/djshellshoxxx/patchtrace/actions/runs/44858504288/job/136706199528): **24,043 passed, 53 skipped, 6 xfailed**, 21 warnings; 2442.94 seconds.
- [Windows job 136706199689](https://github.com/djshellshoxxx/patchtrace/actions/runs/44858504288/job/136706199689): **23,916 passed, 181 skipped, 5 xfailed**, 22 warnings; 3384.88 seconds.

These platform results overlap and are not summed. Expected failures remain unresolved gates.

Before the filesystem reset, local Git verified main **fdc2696c23bdbfe7668348f25e3b336ce33039f7** is an ancestor of 6b6fcd and their merge base. Merging onto unchanged main should retain the same tree; verify the new PR's actual synthetic merge tree before relying on that inference.

## PR345 original failure and successful retry

Original [Windows job 136648122555](https://github.com/djshellshoxxx/patchtrace/actions/runs/44840721370/job/136648122555), attempt 1, passed pytest (23,847 passed / 181 skipped / 5 xfailed), Ruff, build, frozen and portable checks, then failed on Chocolatey's NSIS 3.13.0 package-feed **HTTP 503**. This is directly confirmed by the log excerpt.

The already requested single retry, [Windows job 136700047285](https://github.com/djshellshoxxx/patchtrace/actions/runs/44840721370/job/136700047285), passed the same full pytest count and every NSIS/installer step, completing 03:35:55 UTC. Downstream package/smokes completed by 03:48:45 UTC. Preserve the original failure; **no further retry is needed**.

## Qualified integration boundary

All current observed CI gates pass. Main's branch endpoint reports protected=false and required-status enforcement off; rulesets are empty. No formal GitHub PR reviews are submitted. These facts do not supersede AGENTS.md's all-applicable-checks/no-blocking-findings rule.

The current ledger still records main_merge_eligible=false and final_source_hosted=pending from its earlier snapshot. Explicitly reconcile these with the new evidence. Keep native Qt advisory disposition, Windows manual/trust/accessibility, complete raw membership, remaining help mappings, historical semantics and separate L1/L2/L3 acceptance open. CODEX-1/5/6/14 remain strict expected-failure audit gaps; successful pytest does not close them. This audit does not authorize a release.

A new ordinary main-integration PR from a separate branch at unchanged 6b6fcd is consistent with verified source/ancestry and preserves current drafts. Refresh main/head, verify its actual merge tree and current applicable checks, and resolve any blocking review/ledger disposition before a guarded REST merge. No GraphQL draft conversion, UI operation, ref mutation or merge was attempted.

[Machine receipt with exact API/run/job URLs, steps and log excerpts](hosted-qualification.json).
