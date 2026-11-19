# PatchTrace branch inventory

Observed UTC: **2026-11-19T10:34:16.394Z**. Pinned main: `fdc2696c23bdbfe7668348f25e3b336ce33039f7`. PR319: `a56ab13aaf9916fc12bea70ba1494075991b7f09`. Broad PR318: `c4ace2088ce8dc9ce78a0bf3036b81096accbdb5`.

The complete REST branch pages contain **320 branches including main** (319 topics); page sizes are 100 / 100 / 100 / 20 / 0. The supplied all-state PR snapshot contains **309 PR records**. Every fetched branch has a documented disposition below. Retained work is not counted as recovered.

## Classification

| Disposition | Branches | Meaning |
|---|---:|---|
| baseline | 1 | Pinned main, not a topic branch. |
| contained-in-broad-candidate | 12 | Exact head is in mixed PR316/318 work with unresolved qualification. |
| contained-in-pr319 | 1 | Exact head is in the unmerged selective candidate. |
| integrated-by-ancestry | 129 | Exact head already belongs to pinned main history. |
| patch-equivalent-only | 16 | Nonmerge patches match main; no unique merge commits; semantic context remains retained. |
| retained-experimental | 5 | Preserved automation/skill scope; no activation or production adoption. |
| retained-for-semantic-review | 139 | Unmatched patch evidence remains; compare behavior and port selectively. |
| retained-research-or-docs | 17 | Preserved historical research/documentation; current-contract review remains. |

## Evidence and scope

The previous complete 318-branch census uses the same main SHA. **317 exact-name/exact-head rows** were reused only after that identity check; **3 changed or new rows** were independently compared. One current main-history read cross-checked every ancestry claim. Existing merge simulations were reused only for the identical main and topic head. Path footprints were reused only for identical topic head and merge base; absent footprints were read directly.

The earlier attempt to recompute every branch with `tools/branch_inventory.py` timed out during `git cherry` and published no result. The execution environment then became unavailable. This report comes from the completed reuse-and-delta pass after recovery; it does not relabel the interrupted attempt as passing.

[BRANCH_INVENTORY.json](BRANCH_INVENTORY.json) retains full heads, merge bases, unique and patch-equivalent commit lists, source file footprints, conflict paths, PR associations, evidence identities and limitations. Its integer file IDs index the complete `file_catalog` to avoid duplicating long paths across hundreds of rows. Source file changes are review leads, not proof that the corresponding current feature is missing.

The prior source-pinned census is [a56ab13aaf99:docs/audits/consolidation-20261119/post-foundation-evidence.zip](https://github.com/djshellshoxxx/patchtrace/blob/a56ab13aaf9916fc12bea70ba1494075991b7f09/docs/audits/consolidation-20261119/post-foundation-evidence.zip). The JSON records the archive and input SHA-256 values. Current-head CI/review was not refreshed by this census. No branch, PR, protection or remote ref was changed by the inventory worker.

## Changed and new references

| Branch | Previous head | Current head |
|---|---|---|
| `codex/patchtrace-checkpoint-20261119-81e4` | `new` | `fdc2696c23bdbfe7668348f25e3b336ce33039f7` |
| `codex/patchtrace-stabilization-20261119` | `2e301a74649e59e27b19a83bc283d646109ccd09` | `c4ace2088ce8dc9ce78a0bf3036b81096accbdb5` |
| `consolidation/patchtrace-reviewed-20261119` | `new` | `a56ab13aaf9916fc12bea70ba1494075991b7f09` |

The new checkpoint branch at the main SHA contains no additional product work. Its ancestry classification is not a newly recovered feature.

## Complete disposition

`Unique` is the number of commits outside main; `Patches` counts unmatched nonmerge patches. `Files` counts the source delta footprint, including documentation/tests. A clean merge simulation is not approval. The main row is the baseline.

| Branch | Head | Unique | Patches | Files | PRs | Disposition | Conflicts |
|---|---|---:|---:|---:|---|---|---|
| `access-test-noprefix` | `726a371ab34d` | 29 | 28 | 16 | — | retained-for-semantic-review | yes |
| `audit/ai-reports` | `dd6402b9c00d` | 1 | 1 | 4 | — | retained-for-semantic-review | yes |
| `audit/core` | `fae13b2ed304` | 2 | 2 | 3 | — | retained-for-semantic-review | yes |
| `audit/desktop` | `4d5e48ab7df3` | 1 | 1 | 4 | — | retained-for-semantic-review | yes |
| `audit/enrichment` | `cbc5b079ad2c` | 3 | 3 | 12 | — | retained-for-semantic-review | yes |
| `audit/integration` | `f6505928d826` | 24 | 18 | 57 | [#11](https://github.com/djshellshoxxx/patchtrace/pull/11) | retained-for-semantic-review | yes |
| `audit/kb-correlation-20261107` | `c760e6ccea0d` | 0 | 0 | 0 | [#276](https://github.com/djshellshoxxx/patchtrace/pull/276) | integrated-by-ancestry | no |
| `audit/random-boundaries-20261105` | `802b5b1bb5f5` | 0 | 0 | 0 | [#200](https://github.com/djshellshoxxx/patchtrace/pull/200) | integrated-by-ancestry | no |
| `audit/random-invariants-20261105` | `7716e2b02fea` | 0 | 0 | 0 | [#216](https://github.com/djshellshoxxx/patchtrace/pull/216) | integrated-by-ancestry | no |
| `audit/random-lifecycle-20261105` | `f2b7d1786f60` | 0 | 0 | 0 | [#202](https://github.com/djshellshoxxx/patchtrace/pull/202) | integrated-by-ancestry | no |
| `audit/runtime` | `9f32a6ecbd05` | 2 | 2 | 5 | — | retained-for-semantic-review | yes |
| `audit/trust-boundaries-20261107` | `d75c0490aa01` | 0 | 0 | 0 | [#275](https://github.com/djshellshoxxx/patchtrace/pull/275) | integrated-by-ancestry | no |
| `automation/api-funded-persistent-codex-20261103` | `6fe6c4b1be06` | 9 | 9 | 1 | [#170](https://github.com/djshellshoxxx/patchtrace/pull/170) | retained-experimental | no |
| `automation/parallel-api-eight-agents-20261103` | `f8050a1fef23` | 23 | 23 | 4 | [#171](https://github.com/djshellshoxxx/patchtrace/pull/171) | retained-experimental | no |
| `automation/patchtrace-api-agent-pilot-20261103` | `def36c822a80` | 2 | 2 | 2 | [#167](https://github.com/djshellshoxxx/patchtrace/pull/167) | retained-experimental | no |
| `chatgpt/corpus-1` | `b7a0f0a45d2d` | 25 | 25 | 25 | [#68](https://github.com/djshellshoxxx/patchtrace/pull/68) | retained-for-semantic-review | no |
| `chatgpt/deferred-audit-fixes-1` | `2174837f3172` | 8 | 8 | 19 | [#67](https://github.com/djshellshoxxx/patchtrace/pull/67) | retained-for-semantic-review | yes |
| `chatgpt/ghidriff-sequential-lock-fix-20261017` | `f6b7545bcc7a` | 5 | 5 | 3 | [#96](https://github.com/djshellshoxxx/patchtrace/pull/96) | retained-for-semantic-review | yes |
| `chatgpt/help-docs-1` | `e5bee6fe157c` | 25 | 25 | 25 | [#70](https://github.com/djshellshoxxx/patchtrace/pull/70) | retained-for-semantic-review | yes |
| `chatgpt/java-probe-boundaries-20261016` | `09bb4519d7d8` | 2 | 2 | 1 | [#84](https://github.com/djshellshoxxx/patchtrace/pull/84) | retained-for-semantic-review | yes |
| `chatgpt/java-probe-ci-fix-20261016` | `0254841e3e63` | 1 | 1 | 1 | [#81](https://github.com/djshellshoxxx/patchtrace/pull/81) | retained-for-semantic-review | no |
| `chatgpt/java-probe-qa-fix-20261016` | `89500e120686` | 0 | 0 | 0 | [#80](https://github.com/djshellshoxxx/patchtrace/pull/80) | integrated-by-ancestry | no |
| `chatgpt/kb-fixtures-1` | `781b36fb60e7` | 24 | 24 | 24 | [#69](https://github.com/djshellshoxxx/patchtrace/pull/69) | retained-for-semantic-review | yes |
| `chatgpt/lbl30-prereg-guard-20261016` | `6ae2c079e6ca` | 43 | 43 | 21 | [#85](https://github.com/djshellshoxxx/patchtrace/pull/85) | retained-for-semantic-review | yes |
| `chatgpt/lbl31-coff-quoted-rip-20261016` | `6e71bfabbf5e` | 23 | 23 | 15 | [#92](https://github.com/djshellshoxxx/patchtrace/pull/92) | retained-for-semantic-review | yes |
| `chatgpt/lbl31-coff-symbol-mask-20261016` | `9622704d5c75` | 25 | 25 | 15 | [#91](https://github.com/djshellshoxxx/patchtrace/pull/91) | retained-for-semantic-review | yes |
| `chatgpt/lbl31-output-persistence-20261015` | `2019a37fa65f` | 33 | 33 | 18 | [#78](https://github.com/djshellshoxxx/patchtrace/pull/78) | retained-for-semantic-review | yes |
| `chatgpt/lbl31-windows-qa-fixes-20261016-a` | `ddb2ff077a21` | 26 | 26 | 18 | [#93](https://github.com/djshellshoxxx/patchtrace/pull/93) | retained-for-semantic-review | yes |
| `chatgpt/lbl32-card-controls-20261016` | `9513bc05229d` | 36 | 36 | 18 | [#79](https://github.com/djshellshoxxx/patchtrace/pull/79) | retained-for-semantic-review | yes |
| `chatgpt/lbl32-recipe-aa-noise-20261016` | `eaa30013794a` | 52 | 51 | 20 | [#82](https://github.com/djshellshoxxx/patchtrace/pull/82) | retained-for-semantic-review | yes |
| `chatgpt/merge-first-handoff-20261016` | `19153f10780e` | 5 | 5 | 2 | [#87](https://github.com/djshellshoxxx/patchtrace/pull/87) | retained-for-semantic-review | no |
| `chatgpt/nway-external-note-qa-20261016` | `8c7288276d3e` | 0 | 0 | 0 | [#89](https://github.com/djshellshoxxx/patchtrace/pull/89) | integrated-by-ancestry | no |
| `chatgpt/panels-1` | `cfd7cfff52f4` | 10 | 10 | 10 | [#72](https://github.com/djshellshoxxx/patchtrace/pull/72) | retained-for-semantic-review | no |
| `chatgpt/patchwatch-reuse-roadmap-20261026` | `4eabf8dff2c4` | 0 | 0 | 0 | [#101](https://github.com/djshellshoxxx/patchtrace/pull/101) | integrated-by-ancestry | no |
| `chatgpt/r5-calibration-research-20261030` | `4d9d9051aea8` | 11 | 11 | 8 | [#132](https://github.com/djshellshoxxx/patchtrace/pull/132) | retained-for-semantic-review | yes |
| `chatgpt/semantic-analysis-r3-20261030` | `2698b9a04d33` | 14 | 14 | 10 | [#129](https://github.com/djshellshoxxx/patchtrace/pull/129) | retained-for-semantic-review | yes |
| `chatgpt/ue-r3-retain-decompiled-20261016` | `ebbd621d4f55` | 11 | 11 | 7 | [#86](https://github.com/djshellshoxxx/patchtrace/pull/86) | retained-for-semantic-review | yes |
| `chatgpt/ue-r7-p15-unresolved-20261016-a` | `292dc3953dd2` | 0 | 0 | 0 | [#83](https://github.com/djshellshoxxx/patchtrace/pull/83) | integrated-by-ancestry | no |
| `chatgpt/ue-r7-strict-worker-report-20261016-a` | `9c5f9a42b499` | 0 | 0 | 0 | [#88](https://github.com/djshellshoxxx/patchtrace/pull/88) | integrated-by-ancestry | no |
| `chatgpt/unified-fixture-collection-fix-20261016` | `941c617b6854` | 30 | 30 | 23 | [#90](https://github.com/djshellshoxxx/patchtrace/pull/90) | retained-for-semantic-review | yes |
| `chatgpt/unified-fixtures-1` | `161a88345efc` | 25 | 25 | 25 | [#71](https://github.com/djshellshoxxx/patchtrace/pull/71) | retained-for-semantic-review | yes |
| `chatgpt/unified-sort-perf-qa-20261016` | `27b0a48bb800` | 22 | 22 | 16 | [#94](https://github.com/djshellshoxxx/patchtrace/pull/94) | retained-for-semantic-review | yes |
| `claude/access-test-1791773355` | `726a371ab34d` | 29 | 28 | 16 | — | retained-for-semantic-review | yes |
| `claude/affectionate-galileo-bqd3tw` | `b29351d41060` | 2 | 2 | 10 | [#268](https://github.com/djshellshoxxx/patchtrace/pull/268) | retained-for-semantic-review | yes |
| `claude/audit-beta` | `c93ff945b9b5` | 1 | 1 | 37 | — | retained-for-semantic-review | yes |
| `claude/autonomous-finish-20261104` | `ad4c49282a65` | 132 | 122 | 331 | [#289](https://github.com/djshellshoxxx/patchtrace/pull/289) | retained-for-semantic-review | yes |
| `claude/awesome-ramanujan-o3pxx3-ci` | `0bf1f8309e84` | 1 | 1 | 11 | — | retained-for-semantic-review | yes |
| `claude/awesome-ramanujan-o3pxx3-hostile` | `077b04e681ac` | 0 | 0 | 0 | — | integrated-by-ancestry | no |
| `claude/awesome-ramanujan-o3pxx3-win1` | `7ac57759f3b9` | 1 | 1 | 13 | — | retained-for-semantic-review | yes |
| `claude/bugfix-kbc-20261029` | `653f384d1ca6` | 0 | 0 | 0 | [#109](https://github.com/djshellshoxxx/patchtrace/pull/109) | integrated-by-ancestry | no |
| `claude/bugfix-kev-acq-20261029` | `fbe58d800da2` | 0 | 0 | 0 | [#107](https://github.com/djshellshoxxx/patchtrace/pull/107) | integrated-by-ancestry | no |
| `claude/bugfix-rules-cg-20261029` | `78d48cf80bf9` | 1 | 1 | 67 | — | retained-for-semantic-review | yes |
| `claude/bugfix-rules-cg-rest-20261111` | `67b2bc456c59` | 1 | 0 | 64 | [#285](https://github.com/djshellshoxxx/patchtrace/pull/285) | patch-equivalent-only | no |
| `claude/bugfix-search-pilot-20261111` | `d1f7d9aa64b2` | 1 | 0 | 5 | [#288](https://github.com/djshellshoxxx/patchtrace/pull/288) | patch-equivalent-only | yes |
| `claude/bugfix-strings-pe-20261029` | `7ae041e79e41` | 0 | 0 | 0 | [#108](https://github.com/djshellshoxxx/patchtrace/pull/108) | integrated-by-ancestry | no |
| `claude/bundle-license-gate` | `d3617acf9af7` | 4 | 3 | 11 | [#65](https://github.com/djshellshoxxx/patchtrace/pull/65) | retained-for-semantic-review | yes |
| `claude/clever-clarke-s4nhi6` | `502402684b0d` | 1 | 0 | 1 | [#63](https://github.com/djshellshoxxx/patchtrace/pull/63), [#62](https://github.com/djshellshoxxx/patchtrace/pull/62), [#57](https://github.com/djshellshoxxx/patchtrace/pull/57), [#53](https://github.com/djshellshoxxx/patchtrace/pull/53), [#52](https://github.com/djshellshoxxx/patchtrace/pull/52), [#50](https://github.com/djshellshoxxx/patchtrace/pull/50), [#49](https://github.com/djshellshoxxx/patchtrace/pull/49), [#46](https://github.com/djshellshoxxx/patchtrace/pull/46), [#42](https://github.com/djshellshoxxx/patchtrace/pull/42), [#38](https://github.com/djshellshoxxx/patchtrace/pull/38), [#34](https://github.com/djshellshoxxx/patchtrace/pull/34), [#33](https://github.com/djshellshoxxx/patchtrace/pull/33), [#32](https://github.com/djshellshoxxx/patchtrace/pull/32), [#31](https://github.com/djshellshoxxx/patchtrace/pull/31), [#30](https://github.com/djshellshoxxx/patchtrace/pull/30), [#29](https://github.com/djshellshoxxx/patchtrace/pull/29), [#28](https://github.com/djshellshoxxx/patchtrace/pull/28), [#27](https://github.com/djshellshoxxx/patchtrace/pull/27) | patch-equivalent-only | yes |
| `claude/compassionate-goldberg-5uuqks` | `198eb21e8813` | 1 | 1 | 1 | [#125](https://github.com/djshellshoxxx/patchtrace/pull/125) | retained-for-semantic-review | no |
| `claude/fix-deadline-test` | `22ff025a7710` | 1 | 0 | 1 | [#99](https://github.com/djshellshoxxx/patchtrace/pull/99) | patch-equivalent-only | no |
| `claude/funny-feynman-d2m0b5` | `770c11f40ef7` | 19 | 18 | 45 | [#287](https://github.com/djshellshoxxx/patchtrace/pull/287) | retained-for-semantic-review | yes |
| `claude/gallant-knuth-8gxuzd` | `f249edc8ee70` | 5 | 5 | 14 | [#259](https://github.com/djshellshoxxx/patchtrace/pull/259), [#180](https://github.com/djshellshoxxx/patchtrace/pull/180) | retained-for-semantic-review | no |
| `claude/instance-b-features` | `9237c2601c0f` | 107 | 97 | 9 | [#59](https://github.com/djshellshoxxx/patchtrace/pull/59), [#47](https://github.com/djshellshoxxx/patchtrace/pull/47), [#44](https://github.com/djshellshoxxx/patchtrace/pull/44) | retained-for-semantic-review | yes |
| `claude/instance-c-research` | `6f767ccef8eb` | 21 | 13 | 4 | [#283](https://github.com/djshellshoxxx/patchtrace/pull/283), [#77](https://github.com/djshellshoxxx/patchtrace/pull/77), [#75](https://github.com/djshellshoxxx/patchtrace/pull/75), [#74](https://github.com/djshellshoxxx/patchtrace/pull/74), [#73](https://github.com/djshellshoxxx/patchtrace/pull/73), [#66](https://github.com/djshellshoxxx/patchtrace/pull/66), [#60](https://github.com/djshellshoxxx/patchtrace/pull/60), [#55](https://github.com/djshellshoxxx/patchtrace/pull/55), [#54](https://github.com/djshellshoxxx/patchtrace/pull/54), [#51](https://github.com/djshellshoxxx/patchtrace/pull/51), [#48](https://github.com/djshellshoxxx/patchtrace/pull/48), [#45](https://github.com/djshellshoxxx/patchtrace/pull/45) | retained-for-semantic-review | yes |
| `claude/instance-d-gui` | `2fa113889d1f` | 0 | 0 | 0 | [#64](https://github.com/djshellshoxxx/patchtrace/pull/64), [#58](https://github.com/djshellshoxxx/patchtrace/pull/58) | integrated-by-ancestry | no |
| `claude/java-version-retry-integration` | `45fa67ad7e92` | 0 | 0 | 0 | [#106](https://github.com/djshellshoxxx/patchtrace/pull/106) | integrated-by-ancestry | no |
| `claude/jolly-fermi-eghaxy` | `99f8328ce89d` | 0 | 0 | 0 | [#123](https://github.com/djshellshoxxx/patchtrace/pull/123) | integrated-by-ancestry | no |
| `claude/live-harness-infra-20261111` | `c59ccada97b6` | 6 | 6 | 6 | [#286](https://github.com/djshellshoxxx/patchtrace/pull/286) | retained-for-semantic-review | yes |
| `claude/live-proof-20261111` | `18efb7ef6d19` | 8 | 8 | 15 | — | retained-for-semantic-review | yes |
| `claude/modest-hamilton-kz2gta` | `280bf05856eb` | 12 | 5 | 16 | [#126](https://github.com/djshellshoxxx/patchtrace/pull/126) | retained-for-semantic-review | yes |
| `claude/patchtrace-cli-dotpath-spec-er6hha` | `62b9a3de4d10` | 5 | 3 | 20 | — | retained-for-semantic-review | yes |
| `claude/patchtrace-features` | `66e9adc50fb1` | 8 | 8 | 52 | [#100](https://github.com/djshellshoxxx/patchtrace/pull/100) | retained-for-semantic-review | yes |
| `claude/patchtrace-haiku-agent-motpbx` | `cbabc09e9df8` | 15 | 14 | 4 | [#281](https://github.com/djshellshoxxx/patchtrace/pull/281), [#102](https://github.com/djshellshoxxx/patchtrace/pull/102) | retained-for-semantic-review | yes |
| `claude/patchtrace-kbf04-fp-tests-20261118` | `16ab88b0626e` | 0 | 0 | 0 | [#305](https://github.com/djshellshoxxx/patchtrace/pull/305) | integrated-by-ancestry | no |
| `claude/patchtrace-multi-worker-consolidate-24ct7v` | `ca10acb506fb` | 10 | 8 | 5 | [#179](https://github.com/djshellshoxxx/patchtrace/pull/179) | retained-for-semantic-review | yes |
| `claude/patchtrace-search-anchors-circularity-20261118` | `f6ef1528c15b` | 0 | 0 | 0 | [#306](https://github.com/djshellshoxxx/patchtrace/pull/306) | integrated-by-ancestry | no |
| `claude/patchtraces-consolidation-trngn0` | `faddea300daf` | 0 | 0 | 0 | [#301](https://github.com/djshellshoxxx/patchtrace/pull/301) | integrated-by-ancestry | no |
| `claude/quirky-curie-n5pxf5` | `a5593fa58b2e` | 0 | 0 | 0 | [#103](https://github.com/djshellshoxxx/patchtrace/pull/103) | integrated-by-ancestry | no |
| `claude/serene-heisenberg-2y5kz6` | `7ed5cebfdaee` | 3 | 1 | 1 | [#172](https://github.com/djshellshoxxx/patchtrace/pull/172) | retained-for-semantic-review | no |
| `claude/sleepy-fermi-cli-parity-1` | `cf50b4e8725c` | 0 | 0 | 0 | [#292](https://github.com/djshellshoxxx/patchtrace/pull/292) | integrated-by-ancestry | no |
| `claude/sleepy-fermi-kbc-1` | `53f5dd2611b3` | 0 | 0 | 0 | [#291](https://github.com/djshellshoxxx/patchtrace/pull/291) | integrated-by-ancestry | no |
| `claude/sleepy-fermi-na-rzdiff-ownership` | `aacb984e9d62` | 0 | 0 | 0 | [#293](https://github.com/djshellshoxxx/patchtrace/pull/293) | integrated-by-ancestry | no |
| `claude/sleepy-fermi-rq-l1-runner` | `e88d748cf984` | 0 | 0 | 0 | [#294](https://github.com/djshellshoxxx/patchtrace/pull/294) | integrated-by-ancestry | no |
| `claude/sleepy-fermi-security-1` | `1d5a022d2840` | 0 | 0 | 0 | [#290](https://github.com/djshellshoxxx/patchtrace/pull/290) | integrated-by-ancestry | no |
| `claude/sleepy-fermi-test-reliability` | `37d9e47ca202` | 0 | 0 | 0 | [#295](https://github.com/djshellshoxxx/patchtrace/pull/295) | integrated-by-ancestry | no |
| `claude/sleepy-fermi-y3z4yj` | `160a60e83874` | 5 | 4 | 82 | [#284](https://github.com/djshellshoxxx/patchtrace/pull/284) | retained-for-semantic-review | yes |
| `claude/spec53-diagnose-launcher` | `a00fcc14ea11` | 1 | 0 | 3 | [#280](https://github.com/djshellshoxxx/patchtrace/pull/280) | patch-equivalent-only | no |
| `claude/symbol-policy-isolated-settings` | `5db597257dec` | 7 | 6 | 12 | [#9](https://github.com/djshellshoxxx/patchtrace/pull/9) | retained-for-semantic-review | yes |
| `claude/ws-a-20261104` | `dabba4aea4ba` | 8 | 8 | 28 | [#175](https://github.com/djshellshoxxx/patchtrace/pull/175) | retained-for-semantic-review | yes |
| `claude/ws-a2-ci-speed-20261104` | `bef720fdd50c` | 7 | 3 | 8 | [#177](https://github.com/djshellshoxxx/patchtrace/pull/177) | retained-for-semantic-review | yes |
| `claude/ws-bc-20261104` | `e1193c8896e0` | 29 | 21 | 57 | [#174](https://github.com/djshellshoxxx/patchtrace/pull/174) | retained-for-semantic-review | yes |
| `claude/ws-i-20261104` | `b03a77b8a2fe` | 8 | 7 | 7 | [#173](https://github.com/djshellshoxxx/patchtrace/pull/173) | retained-for-semantic-review | yes |
| `claude/ws-p-20261104` | `597a8b106491` | 26 | 23 | 98 | [#176](https://github.com/djshellshoxxx/patchtrace/pull/176) | retained-for-semantic-review | yes |
| `codex/advisory-read-bounds-20261118` | `a4061979547e` | 61 | 53 | 229 | [#313](https://github.com/djshellshoxxx/patchtrace/pull/313) | contained-in-broad-candidate | yes |
| `codex/agent-skills-spec56-20261014` | `4467d1f3c6e1` | 1 | 1 | 22 | [#61](https://github.com/djshellshoxxx/patchtrace/pull/61) | retained-experimental | yes |
| `codex/analyst-accessibility-20261109` | `b90a2cd49fa4` | 5 | 5 | 25 | — | retained-for-semantic-review | yes |
| `codex/audit-1` | `c2070cf8b4e7` | 0 | 0 | 0 | — | integrated-by-ancestry | no |
| `codex/audit-2` | `08b12f1b279d` | 3 | 3 | 4 | [#56](https://github.com/djshellshoxxx/patchtrace/pull/56) | retained-for-semantic-review | yes |
| `codex/autonomous-checkpoint-20261102-0945` | `d038ddea4318` | 38 | 33 | 475 | — | retained-for-semantic-review | yes |
| `codex/autonomous-checkpoint-20261102-1020` | `c13d3257c881` | 39 | 34 | 515 | — | retained-for-semantic-review | yes |
| `codex/autonomous-reconcile-20261101` | `0130bf81e2fe` | 41 | 36 | 517 | [#152](https://github.com/djshellshoxxx/patchtrace/pull/152) | retained-for-semantic-review | yes |
| `codex/codespaces-cs1-20261109` | `a5f049cd777d` | 8 | 8 | 5 | [#279](https://github.com/djshellshoxxx/patchtrace/pull/279) | retained-for-semantic-review | no |
| `codex/consolidate-backup-stability-20261102` | `f1a55c4cf21d` | 0 | 0 | 0 | [#162](https://github.com/djshellshoxxx/patchtrace/pull/162) | integrated-by-ancestry | no |
| `codex/consolidate-prereg-prefix-20261102` | `9b9452b4677e` | 3 | 3 | 23 | [#161](https://github.com/djshellshoxxx/patchtrace/pull/161) | retained-for-semantic-review | yes |
| `codex/consolidate-replay-schema-20261102` | `ca411e77f43a` | 8 | 6 | 44 | [#160](https://github.com/djshellshoxxx/patchtrace/pull/160) | retained-for-semantic-review | yes |
| `codex/consolidated-reviewed-20261102` | `6e82fd70f315` | 54 | 45 | 491 | [#163](https://github.com/djshellshoxxx/patchtrace/pull/163) | retained-for-semantic-review | yes |
| `codex/consolidation-audit-20261104` | `fbd9595351bf` | 2 | 2 | 4 | [#187](https://github.com/djshellshoxxx/patchtrace/pull/187) | retained-for-semantic-review | yes |
| `codex/consolidation-cve-reviewed-20261118` | `d8c02caea407` | 0 | 0 | 0 | [#304](https://github.com/djshellshoxxx/patchtrace/pull/304) | integrated-by-ancestry | no |
| `codex/consolidation-evidence-20261102` | `44c320e37b84` | 55 | 46 | 514 | — | retained-for-semantic-review | yes |
| `codex/consolidation-integrity-20261103` | `b58bb53debcb` | 58 | 46 | 537 | [#164](https://github.com/djshellshoxxx/patchtrace/pull/164) | retained-for-semantic-review | yes |
| `codex/consolidation-reviewed-20261118` | `121ffb0bcdd6` | 0 | 0 | 0 | [#302](https://github.com/djshellshoxxx/patchtrace/pull/302) | integrated-by-ancestry | no |
| `codex/coordinator-rule-repairs-20261031` | `798e11ef345e` | 11 | 5 | 16 | [#146](https://github.com/djshellshoxxx/patchtrace/pull/146) | retained-for-semantic-review | yes |
| `codex/corpus-integrity-20261116` | `6a5b6f260960` | 0 | 0 | 0 | [#299](https://github.com/djshellshoxxx/patchtrace/pull/299) | integrated-by-ancestry | no |
| `codex/corpus-output-main-20261101` | `874e9a267fdc` | 9 | 6 | 44 | [#157](https://github.com/djshellshoxxx/patchtrace/pull/157) | retained-for-semantic-review | yes |
| `codex/deep-review-consolidation-20261030` | `95e09548a822` | 0 | 0 | 0 | [#124](https://github.com/djshellshoxxx/patchtrace/pull/124) | integrated-by-ancestry | no |
| `codex/essential-combined-verification-20261030` | `a7f13e13ffb5` | 20 | 18 | 58 | [#143](https://github.com/djshellshoxxx/patchtrace/pull/143) | retained-for-semantic-review | yes |
| `codex/essential-integration-20261029` | `5ed624e91468` | 0 | 0 | 0 | [#110](https://github.com/djshellshoxxx/patchtrace/pull/110) | integrated-by-ancestry | no |
| `codex/essential-project-safety-20261031` | `c3868d8335a8` | 1 | 1 | 28 | [#148](https://github.com/djshellshoxxx/patchtrace/pull/148) | retained-for-semantic-review | yes |
| `codex/fix-pr110-ci-gates-20261029` | `c0d1c38aee74` | 9 | 9 | 7 | [#114](https://github.com/djshellshoxxx/patchtrace/pull/114) | retained-for-semantic-review | yes |
| `codex/gt01-extraction-recovery-20261030` | `d76d23372ace` | 16 | 15 | 30 | [#141](https://github.com/djshellshoxxx/patchtrace/pull/141) | retained-for-semantic-review | yes |
| `codex/gui-bounded-ambiguous-candidates-20261029` | `3287cb3d3605` | 3 | 2 | 2 | [#111](https://github.com/djshellshoxxx/patchtrace/pull/111) | retained-for-semantic-review | no |
| `codex/identity-main-repair-20261101` | `4eebea4a5389` | 0 | 0 | 0 | [#156](https://github.com/djshellshoxxx/patchtrace/pull/156) | integrated-by-ancestry | no |
| `codex/java-version-retry-20261015` | `8ee61c623fa3` | 0 | 0 | 0 | [#76](https://github.com/djshellshoxxx/patchtrace/pull/76) | integrated-by-ancestry | no |
| `codex/kb-explicit-filename-selection-20261104` | `761b6b885f00` | 1 | 0 | 7 | [#190](https://github.com/djshellshoxxx/patchtrace/pull/190) | patch-equivalent-only | yes |
| `codex/kb-fixture-contract-repairs-20261030` | `a4d1e6a38c34` | 13 | 13 | 42 | [#142](https://github.com/djshellshoxxx/patchtrace/pull/142) | retained-for-semantic-review | yes |
| `codex/manifest-dtd-reviewed-20261118` | `23fbe4a54880` | 61 | 53 | 231 | [#315](https://github.com/djshellshoxxx/patchtrace/pull/315) | contained-in-broad-candidate | yes |
| `codex/manual-correction-completeness-20261104` | `65f979a163a8` | 0 | 0 | 0 | [#188](https://github.com/djshellshoxxx/patchtrace/pull/188) | integrated-by-ancestry | no |
| `codex/master-foundation-scope-20261118-4a7` | `88b0b52281dd` | 0 | 0 | 0 | [#317](https://github.com/djshellshoxxx/patchtrace/pull/317) | integrated-by-ancestry | no |
| `codex/msrc-mixed-format-revision-20261102` | `e1b79e048d39` | 3 | 3 | 2 | [#158](https://github.com/djshellshoxxx/patchtrace/pull/158) | retained-for-semantic-review | yes |
| `codex/msrc-reconcile-integration-20261102` | `56374f867594` | 42 | 36 | 481 | [#159](https://github.com/djshellshoxxx/patchtrace/pull/159) | retained-for-semantic-review | yes |
| `codex/parser-test-cpu-budget-20261104` | `cb204f7625d4` | 5 | 0 | 9 | [#189](https://github.com/djshellshoxxx/patchtrace/pull/189) | patch-equivalent-only | yes |
| `codex/patchtrace-beta` | `c7937246a5bf` | 0 | 0 | 0 | [#1](https://github.com/djshellshoxxx/patchtrace/pull/1) | integrated-by-ancestry | no |
| `codex/patchtrace-checkpoint-20261119-81e4` | `fdc2696c23bd` | 0 | 0 | 0 | — | integrated-by-ancestry | no |
| `codex/patchtrace-stabilization-20261119` | `c4ace2088ce8` | 330 | 315 | 842 | [#318](https://github.com/djshellshoxxx/patchtrace/pull/318) | contained-in-broad-candidate | yes |
| `codex/pilot-current-evidence-reviewed-20261118` | `b41d6631e679` | 81 | 72 | 273 | [#314](https://github.com/djshellshoxxx/patchtrace/pull/314) | contained-in-broad-candidate | yes |
| `codex/post-consolidation-20261116` | `2d330075fbe0` | 0 | 0 | 0 | [#298](https://github.com/djshellshoxxx/patchtrace/pull/298) | integrated-by-ancestry | no |
| `codex/pr110-ci-repairs-20261029` | `bb42828d05b7` | 7 | 7 | 7 | [#115](https://github.com/djshellshoxxx/patchtrace/pull/115) | retained-for-semantic-review | yes |
| `codex/pr110-kb-arch-scope-20261029` | `40e02daf93c8` | 8 | 6 | 8 | [#122](https://github.com/djshellshoxxx/patchtrace/pull/122) | retained-for-semantic-review | yes |
| `codex/pr110-persistence-feedback-20261029` | `3e9cedb012b4` | 9 | 7 | 8 | [#119](https://github.com/djshellshoxxx/patchtrace/pull/119) | retained-for-semantic-review | yes |
| `codex/pr110-qa-wbjson-diaphora-help-20261029` | `aba4c2001a6b` | 6 | 6 | 4 | [#112](https://github.com/djshellshoxxx/patchtrace/pull/112) | retained-for-semantic-review | yes |
| `codex/pr111-bounded-nav-into-integration-20261029` | `025300f8e169` | 8 | 6 | 8 | [#117](https://github.com/djshellshoxxx/patchtrace/pull/117) | retained-for-semantic-review | yes |
| `codex/primary-environment-20261118` | `09b032f205f4` | 61 | 53 | 236 | [#311](https://github.com/djshellshoxxx/patchtrace/pull/311) | contained-in-broad-candidate | yes |
| `codex/project-safe-export-20261101` | `e90254424c26` | 0 | 0 | 0 | [#149](https://github.com/djshellshoxxx/patchtrace/pull/149) | integrated-by-ancestry | no |
| `codex/pw01-kb-inventory-20261118` | `2b697222b343` | 26 | 24 | 68 | [#303](https://github.com/djshellshoxxx/patchtrace/pull/303) | contained-in-broad-candidate | yes |
| `codex/pw01-retained-source-pages-20261118` | `58fc130631f6` | 57 | 49 | 222 | [#307](https://github.com/djshellshoxxx/patchtrace/pull/307) | contained-in-broad-candidate | yes |
| `codex/r1-ground-truth-research-20261030` | `10856edf05af` | 9 | 8 | 154 | [#128](https://github.com/djshellshoxxx/patchtrace/pull/128) | retained-for-semantic-review | yes |
| `codex/r1-receipt-publication-20261031` | `8c9eafc79b00` | 8 | 8 | 154 | [#145](https://github.com/djshellshoxxx/patchtrace/pull/145) | retained-for-semantic-review | yes |
| `codex/r2-unified-matching-research-20261030` | `b3ceb8b30d7a` | 4 | 4 | 104 | [#131](https://github.com/djshellshoxxx/patchtrace/pull/131) | retained-for-semantic-review | yes |
| `codex/raw-alignment-reviewed-20261118` | `3c9d3f074481` | 61 | 53 | 233 | [#309](https://github.com/djshellshoxxx/patchtrace/pull/309) | contained-in-broad-candidate | yes |
| `codex/real-msrc-adapter-20261101` | `d99cd7712b76` | 0 | 0 | 0 | [#153](https://github.com/djshellshoxxx/patchtrace/pull/153) | integrated-by-ancestry | no |
| `codex/receipt-parent-race-20261101` | `2fdac2ea9042` | 9 | 9 | 156 | [#150](https://github.com/djshellshoxxx/patchtrace/pull/150) | retained-for-semantic-review | yes |
| `codex/release-integration-20261116` | `95db052a11cc` | 0 | 0 | 0 | [#297](https://github.com/djshellshoxxx/patchtrace/pull/297) | integrated-by-ancestry | no |
| `codex/release-qualification-reviewed-20261118` | `573829f33c84` | 62 | 54 | 237 | [#312](https://github.com/djshellshoxxx/patchtrace/pull/312) | contained-in-broad-candidate | yes |
| `codex/repair-openai-agent-20261104` | `f019606665a7` | 2 | 2 | 2 | [#186](https://github.com/djshellshoxxx/patchtrace/pull/186) | retained-for-semantic-review | no |
| `codex/rzdiff-164-investigation` | `20ef68eaab59` | 59 | 47 | 538 | — | retained-for-semantic-review | yes |
| `codex/saved-search-reviewed-20261118` | `26558cd0723a` | 63 | 55 | 241 | [#310](https://github.com/djshellshoxxx/patchtrace/pull/310) | contained-in-broad-candidate | yes |
| `codex/semantic-proof-reconciliation-20261031` | `745e93426a16` | 28 | 26 | 85 | [#144](https://github.com/djshellshoxxx/patchtrace/pull/144) | retained-for-semantic-review | yes |
| `codex/storage-integrity-20261101` | `9911af4d9130` | 0 | 0 | 0 | [#151](https://github.com/djshellshoxxx/patchtrace/pull/151) | integrated-by-ancestry | no |
| `codex/strings-export-publication-20261118` | `92a411bf02fc` | 2 | 2 | 15 | [#308](https://github.com/djshellshoxxx/patchtrace/pull/308) | contained-in-broad-candidate | yes |
| `codex/t9-qa-20261020` | `ecc4f2054c00` | 6 | 4 | 11 | [#97](https://github.com/djshellshoxxx/patchtrace/pull/97) | retained-for-semantic-review | yes |
| `codex/tier-w-fetch-20261015` | `5b7b2591e616` | 6 | 6 | 5 | — | retained-for-semantic-review | yes |
| `codex/training-prereg-identity-20261101` | `dfe8f421db39` | 4 | 3 | 23 | [#154](https://github.com/djshellshoxxx/patchtrace/pull/154) | retained-for-semantic-review | yes |
| `codex/verified-followup-integration-20261118` | `f2b6827fc627` | 327 | 312 | 827 | [#316](https://github.com/djshellshoxxx/patchtrace/pull/316) | contained-in-broad-candidate | yes |
| `codex/windows-branding-reconcile-20261030` | `8f4c4a2e0021` | 4 | 4 | 28 | [#147](https://github.com/djshellshoxxx/patchtrace/pull/147) | retained-for-semantic-review | yes |
| `codex/windows-setup-installer-20261017` | `9c5fe67bd10a` | 32 | 31 | 13 | [#95](https://github.com/djshellshoxxx/patchtrace/pull/95) | retained-for-semantic-review | yes |
| `consolidate/docs-20261104` | `ed70e6ddac44` | 13 | 13 | 144 | [#183](https://github.com/djshellshoxxx/patchtrace/pull/183) | retained-for-semantic-review | yes |
| `consolidate/kb-fixtures-20261104` | `820d70744dff` | 4 | 0 | 28 | [#182](https://github.com/djshellshoxxx/patchtrace/pull/182) | patch-equivalent-only | yes |
| `consolidate/research-r7-20261104` | `552c29453c5d` | 3 | 2 | 11 | [#282](https://github.com/djshellshoxxx/patchtrace/pull/282) | retained-for-semantic-review | no |
| `consolidate/rules-callgraph-20261104` | `7b3fcbaca882` | 9 | 0 | 13 | [#181](https://github.com/djshellshoxxx/patchtrace/pull/181) | patch-equivalent-only | yes |
| `consolidate/test-stability-20261104` | `64e8374d5d3a` | 4 | 0 | 5 | [#184](https://github.com/djshellshoxxx/patchtrace/pull/184) | patch-equivalent-only | yes |
| `consolidation/desktop-keyboard-accessibility-20261116` | `45997cfc997b` | 0 | 0 | 0 | [#300](https://github.com/djshellshoxxx/patchtrace/pull/300) | integrated-by-ancestry | no |
| `consolidation/patchtrace-reviewed-20261119` | `a56ab13aaf99` | 2 | 2 | 220 | [#319](https://github.com/djshellshoxxx/patchtrace/pull/319) | contained-in-pr319 | no |
| `docs/claude-autonomous-alpha-handoff-20261013` | `1038d3f13f21` | 2 | 2 | 2 | [#20](https://github.com/djshellshoxxx/patchtrace/pull/20) | retained-research-or-docs | yes |
| `docs/codespaces-plan-20261107` | `c3536288ee37` | 0 | 0 | 0 | [#273](https://github.com/djshellshoxxx/patchtrace/pull/273) | integrated-by-ancestry | no |
| `docs/csaf-patch-intelligence-specs` | `24244831ec44` | 5 | 5 | 4 | [#17](https://github.com/djshellshoxxx/patchtrace/pull/17) | retained-research-or-docs | yes |
| `docs/diaphora-optional-engine-20261014` | `b75ac57d85c7` | 3 | 3 | 3 | [#37](https://github.com/djshellshoxxx/patchtrace/pull/37) | retained-research-or-docs | yes |
| `docs/dockable-workspace-spec-20261030` | `6a1e3ce348a7` | 1 | 1 | 1 | [#127](https://github.com/djshellshoxxx/patchtrace/pull/127) | retained-research-or-docs | yes |
| `docs/findings-20261107` | `9d72402cc3fd` | 0 | 0 | 0 | [#262](https://github.com/djshellshoxxx/patchtrace/pull/262) | integrated-by-ancestry | no |
| `docs/handoff-20261107` | `39db34c5beaa` | 0 | 0 | 0 | [#270](https://github.com/djshellshoxxx/patchtrace/pull/270) | integrated-by-ancestry | no |
| `docs/kbc-live-probe-result-20261107` | `c21d0ab8471a` | 0 | 0 | 0 | [#258](https://github.com/djshellshoxxx/patchtrace/pull/258) | integrated-by-ancestry | no |
| `docs/nway-matches` | `f748cc48ea07` | 1 | 1 | 1 | — | retained-research-or-docs | no |
| `docs/post-consolidation-gap-analysis-20261030` | `61b5c2bade71` | 20 | 20 | 20 | [#137](https://github.com/djshellshoxxx/patchtrace/pull/137) | retained-research-or-docs | yes |
| `docs/r8-reconciliation-20261106` | `5e1e19828b38` | 0 | 0 | 0 | [#249](https://github.com/djshellshoxxx/patchtrace/pull/249) | integrated-by-ancestry | no |
| `docs/ranking-reuse-20261105` | `bc52940fb32d` | 0 | 0 | 0 | [#232](https://github.com/djshellshoxxx/patchtrace/pull/232) | integrated-by-ancestry | no |
| `docs/readme-and-wiki` | `ad8fbe9f2f04` | 1 | 1 | 7 | [#98](https://github.com/djshellshoxxx/patchtrace/pull/98) | retained-research-or-docs | no |
| `docs/refresh-accuracy-handoff-20261109` | `2e408e3c24c2` | 0 | 0 | 0 | [#278](https://github.com/djshellshoxxx/patchtrace/pull/278) | integrated-by-ancestry | no |
| `docs/research-reconciliation-20261105` | `febc9de57e61` | 0 | 0 | 0 | [#231](https://github.com/djshellshoxxx/patchtrace/pull/231) | integrated-by-ancestry | no |
| `docs/research-tools-execution-plan-20261106` | `40da81765049` | 2 | 2 | 1 | — | retained-research-or-docs | no |
| `docs/semantic-ghidra-roadmap` | `8b9ebc01bb22` | 1 | 0 | 1 | [#14](https://github.com/djshellshoxxx/patchtrace/pull/14) | patch-equivalent-only | yes |
| `docs/sonar235-package-path-20261105` | `c30f11fb6f94` | 0 | 0 | 0 | [#241](https://github.com/djshellshoxxx/patchtrace/pull/241) | integrated-by-ancestry | no |
| `docs/spec-31-kb-cve-correlation-20261014` | `9088bf0e2e45` | 12 | 12 | 10 | [#40](https://github.com/djshellshoxxx/patchtrace/pull/40) | retained-research-or-docs | yes |
| `docs/spec-32-kb-patch-search-20261014` | `d0ceb56f30f8` | 17 | 17 | 8 | [#41](https://github.com/djshellshoxxx/patchtrace/pull/41) | retained-research-or-docs | yes |
| `docs/specs-plan` | `a5194581396b` | 5 | 5 | 14 | — | retained-research-or-docs | yes |
| `docs/workbench-search-graph-floss-20261014` | `af15701d13b5` | 6 | 6 | 6 | [#43](https://github.com/djshellshoxxx/patchtrace/pull/43) | retained-research-or-docs | yes |
| `feat/acquisition` | `293362a2d8ce` | 14 | 11 | 42 | — | retained-for-semantic-review | yes |
| `feat/acquisition-gui` | `7ae34d8fa26a` | 1 | 1 | 2 | — | retained-for-semantic-review | yes |
| `feat/alpha-ui-integration` | `c7ed1d90a890` | 2 | 2 | 10 | [#25](https://github.com/djshellshoxxx/patchtrace/pull/25) | retained-for-semantic-review | yes |
| `feat/artifact-bytes-seam` | `91b35d09afd2` | 1 | 0 | 4 | [#21](https://github.com/djshellshoxxx/patchtrace/pull/21) | patch-equivalent-only | yes |
| `feat/byte-representations` | `303bc452d0bb` | 1 | 0 | 8 | [#23](https://github.com/djshellshoxxx/patchtrace/pull/23) | patch-equivalent-only | yes |
| `feat/diffscore-workflow-20261107` | `a3aa53744006` | 0 | 0 | 0 | [#272](https://github.com/djshellshoxxx/patchtrace/pull/272) | integrated-by-ancestry | no |
| `feat/enrichment-cache` | `0368fd9b5453` | 2 | 2 | 11 | — | retained-for-semantic-review | yes |
| `feat/enrichment-contracts` | `010d809d2581` | 30 | 23 | 57 | [#10](https://github.com/djshellshoxxx/patchtrace/pull/10) | retained-for-semantic-review | yes |
| `feat/enrichment-cve` | `49bf245583d0` | 2 | 2 | 16 | — | retained-for-semantic-review | yes |
| `feat/enrichment-signals` | `e96441a1a904` | 3 | 3 | 11 | — | retained-for-semantic-review | yes |
| `feat/enrichment-wil` | `9a6999a0e644` | 2 | 2 | 11 | — | retained-for-semantic-review | yes |
| `feat/local-runtime-discovery` | `b9198705ab4c` | 9 | 9 | 9 | [#5](https://github.com/djshellshoxxx/patchtrace/pull/5) | retained-for-semantic-review | yes |
| `feat/nway` | `44d431788bcc` | 31 | 23 | 21 | — | retained-for-semantic-review | yes |
| `feat/pe-overview` | `4b78a6d3c001` | 1 | 0 | 17 | [#22](https://github.com/djshellshoxxx/patchtrace/pull/22) | patch-equivalent-only | yes |
| `feat/phase2-finish` | `86afe3f6563b` | 30 | 22 | 16 | [#12](https://github.com/djshellshoxxx/patchtrace/pull/12) | retained-for-semantic-review | yes |
| `feat/phase3-batch` | `3581b520207b` | 42 | 31 | 28 | [#13](https://github.com/djshellshoxxx/patchtrace/pull/13) | retained-for-semantic-review | yes |
| `feat/profiles` | `d21b5917a660` | 25 | 19 | 62 | — | retained-for-semantic-review | yes |
| `feat/raw-cache` | `28bc476713fc` | 25 | 19 | 58 | — | retained-for-semantic-review | yes |
| `feat/rq-engine-adapters-20261107` | `b561ed60db9e` | 0 | 0 | 0 | [#265](https://github.com/djshellshoxxx/patchtrace/pull/265) | integrated-by-ancestry | no |
| `feat/rq-parity-20261107` | `f8806bb72107` | 0 | 0 | 0 | [#263](https://github.com/djshellshoxxx/patchtrace/pull/263) | integrated-by-ancestry | no |
| `feat/secondary` | `b932ae1a1c89` | 1 | 1 | 13 | — | retained-for-semantic-review | yes |
| `feat/tooltip-registry` | `0a3843ea2abe` | 1 | 0 | 4 | [#24](https://github.com/djshellshoxxx/patchtrace/pull/24) | patch-equivalent-only | yes |
| `feat/verified-offline-runtime-bundle` | `1724503d01be` | 32 | 29 | 16 | [#7](https://github.com/djshellshoxxx/patchtrace/pull/7) | retained-for-semantic-review | yes |
| `feat/winpairs-workflow-20261107` | `2e43d3f4d7ee` | 0 | 0 | 0 | [#271](https://github.com/djshellshoxxx/patchtrace/pull/271) | integrated-by-ancestry | no |
| `feature/alpha-file-overview-20261013` | `476016590be5` | 4 | 4 | 4 | [#19](https://github.com/djshellshoxxx/patchtrace/pull/19) | retained-for-semantic-review | yes |
| `feature/current-project-investigation-20261105` | `ef70e0bdf02a` | 0 | 0 | 0 | [#214](https://github.com/djshellshoxxx/patchtrace/pull/214) | integrated-by-ancestry | no |
| `feature/evidence-reconciliation-confidence` | `ddda35f40b94` | 6 | 6 | 4 | [#16](https://github.com/djshellshoxxx/patchtrace/pull/16) | retained-for-semantic-review | yes |
| `feature/gui-inspection-preview` | `8b94227a81b7` | 5 | 5 | 3 | [#15](https://github.com/djshellshoxxx/patchtrace/pull/15) | retained-for-semantic-review | yes |
| `fix/backend-exit-diagnostics` | `bc00a6912dde` | 7 | 6 | 6 | [#6](https://github.com/djshellshoxxx/patchtrace/pull/6) | retained-for-semantic-review | yes |
| `fix/codetext-budget-wave3` | `c7fb422c750f` | 7 | 6 | 55 | — | retained-for-semantic-review | yes |
| `fix/codex-cloud-secret-preflight-20261103` | `bd3dbcae9254` | 0 | 0 | 0 | [#169](https://github.com/djshellshoxxx/patchtrace/pull/169) | integrated-by-ancestry | no |
| `fix/explicit-offline-symbol-policy` | `2e6618762ab6` | 12 | 12 | 10 | [#4](https://github.com/djshellshoxxx/patchtrace/pull/4) | retained-for-semantic-review | yes |
| `fix/ghidra-dot-paths` | `5c3b1df94c0d` | 6 | 6 | 6 | [#2](https://github.com/djshellshoxxx/patchtrace/pull/2) | retained-for-semantic-review | yes |
| `fix/ghidriff-timeout-progress-20261106` | `7e5d981935e2` | 0 | 0 | 0 | [#251](https://github.com/djshellshoxxx/patchtrace/pull/251) | integrated-by-ancestry | no |
| `fix/isolate-ghidra-scratch` | `7ea727231127` | 8 | 8 | 7 | [#3](https://github.com/djshellshoxxx/patchtrace/pull/3) | retained-for-semantic-review | yes |
| `fix/pe-inspection-row-tooltips-20261013` | `0182a8035d64` | 6 | 6 | 4 | [#26](https://github.com/djshellshoxxx/patchtrace/pull/26) | retained-for-semantic-review | yes |
| `fix/pr110-ci-regressions-20261029` | `979ddfad860c` | 0 | 0 | 0 | [#113](https://github.com/djshellshoxxx/patchtrace/pull/113) | integrated-by-ancestry | no |
| `fix/pr205-partial-pe-inspect-20261106` | `cce47934dfc4` | 0 | 0 | 0 | [#253](https://github.com/djshellshoxxx/patchtrace/pull/253) | integrated-by-ancestry | no |
| `fix/pr205-review-contracts-20261106` | `4f3e62c4f130` | 0 | 0 | 0 | [#252](https://github.com/djshellshoxxx/patchtrace/pull/252) | integrated-by-ancestry | no |
| `fix/pr205-ui-seam-help-extraction-20261106` | `a53c7d1bd360` | 0 | 0 | 0 | [#254](https://github.com/djshellshoxxx/patchtrace/pull/254) | integrated-by-ancestry | no |
| `fix/remediation-53088704-982db3` | `15370a0bf690` | 2 | 2 | 18 | [#155](https://github.com/djshellshoxxx/patchtrace/pull/155) | retained-for-semantic-review | yes |
| `fix/remediation-a58defa8-139db0` | `6d9c06c2d82c` | 1 | 1 | 4 | [#261](https://github.com/djshellshoxxx/patchtrace/pull/261) | retained-for-semantic-review | yes |
| `fix/remediation-b1ab7332-a8fac4` | `3feec96f6546` | 2 | 2 | 2 | [#267](https://github.com/djshellshoxxx/patchtrace/pull/267) | retained-for-semantic-review | no |
| `fix/windows-posix-mingw-workflow-20261115` | `3b3ad32f60df` | 1 | 0 | 1 | [#296](https://github.com/djshellshoxxx/patchtrace/pull/296) | patch-equivalent-only | no |
| `haiku/cli-help-suppress-20261027` | `37940b706f11` | 1 | 1 | 2 | — | retained-for-semantic-review | yes |
| `haiku/phase2-handoff-import-20261027` | `4522030ff3ff` | 1 | 1 | 7 | — | retained-for-semantic-review | yes |
| `haiku/skills-manifest-import-20261027` | `039b0ef8a5d0` | 1 | 1 | 30 | — | retained-experimental | no |
| `integrate/autonomous-20261105` | `3d6c37e665bd` | 0 | 0 | 0 | [#194](https://github.com/djshellshoxxx/patchtrace/pull/194) | integrated-by-ancestry | no |
| `integrate/calibration-prereg-20261105` | `57f95e09d8a9` | 0 | 0 | 0 | [#215](https://github.com/djshellshoxxx/patchtrace/pull/215) | integrated-by-ancestry | no |
| `integrate/calibration-replay-20261105` | `f8ed23564166` | 0 | 0 | 0 | [#217](https://github.com/djshellshoxxx/patchtrace/pull/217) | integrated-by-ancestry | no |
| `integrate/continuation-20261106` | `37b771300053` | 0 | 0 | 0 | [#247](https://github.com/djshellshoxxx/patchtrace/pull/247) | integrated-by-ancestry | no |
| `integrate/gui-inspection-20261105` | `3fa22c611697` | 0 | 0 | 0 | [#196](https://github.com/djshellshoxxx/patchtrace/pull/196) | integrated-by-ancestry | no |
| `integrate/independent-wave4-20261105` | `6e9f4524776a` | 0 | 0 | 0 | [#235](https://github.com/djshellshoxxx/patchtrace/pull/235) | integrated-by-ancestry | no |
| `integrate/kb-20261105` | `75c01a29ea79` | 0 | 0 | 0 | [#193](https://github.com/djshellshoxxx/patchtrace/pull/193) | integrated-by-ancestry | no |
| `integrate/kb-investigation-20261105` | `bdbfd7dc4508` | 0 | 0 | 0 | [#201](https://github.com/djshellshoxxx/patchtrace/pull/201) | integrated-by-ancestry | no |
| `integrate/merge-readiness-20261106` | `f393bb68ddc1` | 0 | 0 | 0 | [#244](https://github.com/djshellshoxxx/patchtrace/pull/244) | integrated-by-ancestry | no |
| `integrate/native-controls-20261105` | `a0f417466da8` | 0 | 0 | 0 | [#195](https://github.com/djshellshoxxx/patchtrace/pull/195) | integrated-by-ancestry | no |
| `integrate/project-adoption-20261105` | `1c97defacd54` | 0 | 0 | 0 | [#198](https://github.com/djshellshoxxx/patchtrace/pull/198) | integrated-by-ancestry | no |
| `integrate/recovery-forward-wave3-20261106` | `a1ed8c916752` | 0 | 0 | 0 | [#248](https://github.com/djshellshoxxx/patchtrace/pull/248) | integrated-by-ancestry | no |
| `integrate/rules-20261105` | `c849d0087b7d` | 0 | 0 | 0 | [#191](https://github.com/djshellshoxxx/patchtrace/pull/191) | integrated-by-ancestry | no |
| `integrate/secondary-prep-20261105` | `b6b5bf6c6561` | 0 | 0 | 0 | [#197](https://github.com/djshellshoxxx/patchtrace/pull/197) | integrated-by-ancestry | no |
| `integrate/swarm-followups-20261105` | `c6691ab1ca14` | 0 | 0 | 0 | [#213](https://github.com/djshellshoxxx/patchtrace/pull/213) | integrated-by-ancestry | no |
| `integrate/swarm-qualified-20261105` | `4e9f1d5d71cf` | 0 | 0 | 0 | [#205](https://github.com/djshellshoxxx/patchtrace/pull/205) | integrated-by-ancestry | no |
| `integrate/swarm-wave3-20261105` | `a0e2c80eda74` | 0 | 0 | 0 | [#218](https://github.com/djshellshoxxx/patchtrace/pull/218) | integrated-by-ancestry | no |
| `integration/controlled-consolidation-20261030` | `f18687fd035b` | 11 | 11 | 16 | — | retained-for-semantic-review | yes |
| `integration/kb-fixtures-pr69-20261030` | `2fcd627e52a6` | 12 | 12 | 40 | [#136](https://github.com/djshellshoxxx/patchtrace/pull/136) | retained-for-semantic-review | yes |
| `main` | `fdc2696c23bd` | 0 | 0 | 0 | — | baseline | no |
| `qualify/native-cli-seeding-20261105` | `8fae317bcac6` | 5 | 5 | 174 | [#224](https://github.com/djshellshoxxx/patchtrace/pull/224) | retained-for-semantic-review | yes |
| `qualify/native-controls-20261105` | `dc3bf773fead` | 0 | 0 | 0 | [#208](https://github.com/djshellshoxxx/patchtrace/pull/208) | integrated-by-ancestry | no |
| `qualify/native-provision-20261105` | `c50ab287de13` | 4 | 4 | 50 | [#222](https://github.com/djshellshoxxx/patchtrace/pull/222) | retained-for-semantic-review | yes |
| `qualify/offline-tooling-20261105` | `c3370578086c` | 0 | 0 | 0 | [#209](https://github.com/djshellshoxxx/patchtrace/pull/209) | integrated-by-ancestry | no |
| `repair/gt01-consolidated-native-evidence-20261030` | `c04ad725551f` | 12 | 12 | 23 | [#139](https://github.com/djshellshoxxx/patchtrace/pull/139) | retained-for-semantic-review | yes |
| `repair/gt01-native-identical-controls-20261030` | `fb91cff6d91c` | 14 | 14 | 29 | [#140](https://github.com/djshellshoxxx/patchtrace/pull/140) | retained-for-semantic-review | yes |
| `repair/gt01-unified-live-gates-20261030` | `ca1a36c0caea` | 15 | 15 | 20 | [#138](https://github.com/djshellshoxxx/patchtrace/pull/138) | retained-for-semantic-review | yes |
| `repair/kb-ui-import-boundary-20261105` | `226ac7e514fd` | 0 | 0 | 0 | — | integrated-by-ancestry | no |
| `repair/native-input-open-20261105` | `0526d546a247` | 0 | 0 | 0 | [#206](https://github.com/djshellshoxxx/patchtrace/pull/206) | integrated-by-ancestry | no |
| `repair/native-normalizer-wave3-20261105` | `cf9cefff88b7` | 0 | 0 | 0 | [#220](https://github.com/djshellshoxxx/patchtrace/pull/220) | integrated-by-ancestry | no |
| `repair/native-source-identity-20261105` | `c3be348b544b` | 0 | 0 | 0 | [#212](https://github.com/djshellshoxxx/patchtrace/pull/212) | integrated-by-ancestry | no |
| `repair/normalizer-address-identity-20261105` | `631b5e919699` | 0 | 0 | 0 | [#223](https://github.com/djshellshoxxx/patchtrace/pull/223) | integrated-by-ancestry | no |
| `repair/parity-parser-budget-20261105` | `c923039bd311` | 0 | 0 | 0 | [#211](https://github.com/djshellshoxxx/patchtrace/pull/211) | integrated-by-ancestry | no |
| `repair/pr205-main-reconciliation-20261106` | `96e8e085cb95` | 0 | 0 | 0 | [#250](https://github.com/djshellshoxxx/patchtrace/pull/250) | integrated-by-ancestry | no |
| `repair/pr205-qualification-20261106` | `4465a0492367` | 0 | 0 | 0 | [#245](https://github.com/djshellshoxxx/patchtrace/pull/245) | integrated-by-ancestry | no |
| `repair/project-create-rollback-20261105` | `2a3639adde50` | 0 | 0 | 0 | [#210](https://github.com/djshellshoxxx/patchtrace/pull/210) | integrated-by-ancestry | no |
| `repair/rzdiff-native-callback-size-20261103` | `edab7d916970` | 61 | 48 | 546 | [#166](https://github.com/djshellshoxxx/patchtrace/pull/166) | retained-for-semantic-review | yes |
| `repair/rzdiff-native-red-control-20261103` | `b304034e3c31` | 63 | 49 | 553 | [#168](https://github.com/djshellshoxxx/patchtrace/pull/168) | retained-for-semantic-review | yes |
| `repair/rzdiff-producer-ownership` | `4d66af5577e6` | 60 | 48 | 546 | [#165](https://github.com/djshellshoxxx/patchtrace/pull/165) | retained-for-semantic-review | yes |
| `repair/streamed-series-recovery-20261105` | `20a60f9d12d7` | 0 | 0 | 0 | [#207](https://github.com/djshellshoxxx/patchtrace/pull/207) | integrated-by-ancestry | no |
| `repair/subprocess-venv-20261106` | `c804e4d94430` | 0 | 0 | 0 | [#246](https://github.com/djshellshoxxx/patchtrace/pull/246) | integrated-by-ancestry | no |
| `repair/unified-ci-20261105` | `b5f6e1381dfb` | 0 | 0 | 0 | [#192](https://github.com/djshellshoxxx/patchtrace/pull/192) | integrated-by-ancestry | no |
| `repair/unified-support-evidence-20261105` | `95749419783e` | 0 | 0 | 0 | [#203](https://github.com/djshellshoxxx/patchtrace/pull/203) | integrated-by-ancestry | no |
| `repair/verified-bytes-20261105` | `e5f9302e20ee` | 0 | 0 | 0 | [#199](https://github.com/djshellshoxxx/patchtrace/pull/199) | integrated-by-ancestry | no |
| `repair/winbindex-metadata-budget-20261105` | `64eb58ece2f4` | 0 | 0 | 0 | [#237](https://github.com/djshellshoxxx/patchtrace/pull/237) | integrated-by-ancestry | no |
| `repair/wizard-lock-retry-20261105` | `38be184cda6f` | 0 | 0 | 0 | [#219](https://github.com/djshellshoxxx/patchtrace/pull/219) | integrated-by-ancestry | no |
| `repair/workflow-fragment-20261105` | `1229ca3bba6b` | 0 | 0 | 0 | [#204](https://github.com/djshellshoxxx/patchtrace/pull/204) | integrated-by-ancestry | no |
| `research/additional-reuse-claude-20261103` | `be4a58ff7d8f` | 1 | 1 | 11 | [#178](https://github.com/djshellshoxxx/patchtrace/pull/178) | retained-research-or-docs | yes |
| `research/kbc-live-probe-20261106` | `3839f3b62c92` | 0 | 0 | 0 | [#257](https://github.com/djshellshoxxx/patchtrace/pull/257) | integrated-by-ancestry | no |
| `research/l1-join-corpus-20261107` | `ca3572e7d7a5` | 0 | 0 | 0 | [#269](https://github.com/djshellshoxxx/patchtrace/pull/269) | integrated-by-ancestry | no |
| `research/qualification-tools-rq00-rq01-20261106` | `941c0da4431f` | 0 | 0 | 0 | [#256](https://github.com/djshellshoxxx/patchtrace/pull/256) | integrated-by-ancestry | no |
| `research/r4-vulnerability-correlation-20261030` | `ff570bdd784d` | 12 | 12 | 9 | [#130](https://github.com/djshellshoxxx/patchtrace/pull/130) | retained-research-or-docs | no |
| `research/r6-final-integration-engineering-notes-20261030` | `3010f289dbb4` | 12 | 12 | 9 | [#133](https://github.com/djshellshoxxx/patchtrace/pull/133) | retained-research-or-docs | no |
| `research/r7-advanced-binary-analysis-20261030` | `c9d1aab6a788` | 29 | 29 | 12 | [#134](https://github.com/djshellshoxxx/patchtrace/pull/134) | retained-research-or-docs | yes |
| `research/r8-deep-uncertainty-20261030` | `12dd4f2b41b4` | 16 | 16 | 10 | [#135](https://github.com/djshellshoxxx/patchtrace/pull/135) | retained-research-or-docs | yes |
| `research/windows-candidates-gaps-20261107` | `1f11a43ba190` | 0 | 0 | 0 | [#274](https://github.com/djshellshoxxx/patchtrace/pull/274) | integrated-by-ancestry | no |
| `research/windows-candidates-github-20261107` | `35d7e3c980c0` | 0 | 0 | 0 | [#266](https://github.com/djshellshoxxx/patchtrace/pull/266) | integrated-by-ancestry | no |
| `research/windows-candidates-sources-20261107` | `740961828e22` | 0 | 0 | 0 | [#264](https://github.com/djshellshoxxx/patchtrace/pull/264) | integrated-by-ancestry | no |
| `research/windows-pair-candidates-20261107` | `e5e783f6b8ff` | 0 | 0 | 0 | [#260](https://github.com/djshellshoxxx/patchtrace/pull/260) | integrated-by-ancestry | no |
| `research/windows-pins-20261107` | `ac826a2efe42` | 0 | 0 | 0 | [#277](https://github.com/djshellshoxxx/patchtrace/pull/277) | integrated-by-ancestry | no |
| `resume/desktop-index-refresh-20261106` | `c9cea0671442` | 0 | 0 | 0 | [#243](https://github.com/djshellshoxxx/patchtrace/pull/243) | integrated-by-ancestry | no |
| `resume/kb-acquire-lifecycle-20261106` | `b8bda98452b2` | 0 | 0 | 0 | [#242](https://github.com/djshellshoxxx/patchtrace/pull/242) | integrated-by-ancestry | no |
| `security/offline-bundle-no-overwrite-20261013` | `a39cab81de3e` | 2 | 2 | 2 | [#18](https://github.com/djshellshoxxx/patchtrace/pull/18) | retained-for-semantic-review | yes |
| `test/advisory-acceptance-20261105` | `69c705d052e6` | 0 | 0 | 0 | [#233](https://github.com/djshellshoxxx/patchtrace/pull/233) | integrated-by-ancestry | no |
| `test/product-acceptance-20261106` | `81825ee96384` | 0 | 0 | 0 | — | integrated-by-ancestry | no |
| `test/recovery-diagnostics-20261106` | `064f1c0075a4` | 0 | 0 | 0 | — | integrated-by-ancestry | no |
| `work/calibration-invariants-20261105` | `a6948be80495` | 0 | 0 | 0 | [#230](https://github.com/djshellshoxxx/patchtrace/pull/230) | integrated-by-ancestry | no |
| `work/candidate-correlation-20261105` | `fee7c3664a20` | 0 | 0 | 0 | [#229](https://github.com/djshellshoxxx/patchtrace/pull/229) | integrated-by-ancestry | no |
| `work/consented-winbindex-refresh-20261105` | `83320a32c724` | 0 | 0 | 0 | [#239](https://github.com/djshellshoxxx/patchtrace/pull/239) | integrated-by-ancestry | no |
| `work/investigation-accessibility-20261105` | `b5d4bceabdc3` | 0 | 0 | 0 | [#226](https://github.com/djshellshoxxx/patchtrace/pull/226) | integrated-by-ancestry | no |
| `work/investigation-candidates-20261105` | `bf3661966785` | 0 | 0 | 0 | [#240](https://github.com/djshellshoxxx/patchtrace/pull/240) | integrated-by-ancestry | no |
| `work/online-adapter-20261105` | `e14b4445fd07` | 0 | 0 | 0 | [#225](https://github.com/djshellshoxxx/patchtrace/pull/225) | integrated-by-ancestry | no |
| `work/online-investigation-20261105` | `bf46954ef2c6` | 0 | 0 | 0 | [#234](https://github.com/djshellshoxxx/patchtrace/pull/234) | integrated-by-ancestry | no |
| `work/pe-parser-security-20261105` | `8975c517af22` | 0 | 0 | 0 | [#236](https://github.com/djshellshoxxx/patchtrace/pull/236) | integrated-by-ancestry | no |
| `work/persistence-security-20261105` | `1a1e1951c55c` | 0 | 0 | 0 | [#227](https://github.com/djshellshoxxx/patchtrace/pull/227) | integrated-by-ancestry | no |
| `work/product-start-20261106` | `0b7d858149db` | 0 | 0 | 0 | — | integrated-by-ancestry | no |
| `work/product-start-wave3` | `7e7a52ebf4de` | 0 | 0 | 0 | [#221](https://github.com/djshellshoxxx/patchtrace/pull/221) | integrated-by-ancestry | no |
| `work/winbindex-publication-20261105` | `2afe874d6be1` | 0 | 0 | 0 | [#238](https://github.com/djshellshoxxx/patchtrace/pull/238) | integrated-by-ancestry | no |
| `work/windows-package-preflight-20261105` | `93b4b9a80d31` | 0 | 0 | 0 | [#228](https://github.com/djshellshoxxx/patchtrace/pull/228) | integrated-by-ancestry | no |
| `worker/patchtrace-cli-help-20261104` | `81a9fb28f306` | 0 | 0 | 0 | [#185](https://github.com/djshellshoxxx/patchtrace/pull/185) | integrated-by-ancestry | no |

## Recovery and next action

[RECOVERED_WORK.md](RECOVERED_WORK.md) documents the confirmed installer-receipt contribution, its source attribution and verification. The source branch retains separate workflow redesign work; it is not declared wholly recovered.

For retained topics, inspect the recorded unmatched commits and paths against current behavior, then recover only compatible changes with focused tests and independent review. For candidate-contained topics, finish the exact candidate gates before guarded main integration. After a main merge or source movement, refresh this snapshot. Preserve source branches and original failure evidence.
