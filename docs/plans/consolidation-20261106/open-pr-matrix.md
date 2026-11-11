# PatchTrace branch merge matrix — snapshot 2026-11-06 UTC

User-facing audit date: November 5, 2026 (America/Los_Angeles). See [the execution plan](../branch-merge-plan-20261106.md) for gates and current actions.

A graph disposition is not a source review or authorization to merge.

Frozen inventory: 242 remote branch names, 241 distinct branch heads, 112 open pull requests. Local integration work is excluded.

## Coverage counts

| Earliest ancestry carrier | Branch heads | Open PR heads |
|---|---:|---:|
| main | 26 | 0 |
| #205 | 28 | 23 |
| #218 | 8 | 5 |
| #235 | 17 | 13 |
| Outside #235 ancestry | 163 | 71 |

79 branches / 41 open PR heads are already in #235 ancestry. Another 12 branches / 5 open PR heads have every unique nonmerge commit represented by an exact stable patch ID in #235 history. Patch equivalence is not ancestry or proof that merge resolutions/current trees agree. The remaining 151 branches / 66 open PR heads retain nonmatching nonmerge patches that need content-level review.

## Minimum current merge set

By ancestry, #235 plus the two current slices #242 and #243 carry the current staged consolidation. Preserve the qualification sequence #205 → #218 → updated #235 when promoting to main. Do not separately merge the 38 additional source PR heads already included through the three carriers. #224 contains #222 and is a separate native qualification lane. #183 docs and #186 workflow repairs are independent candidates, each needing their own content/ownership review.

## #243 merge-base anomaly

#243 has multiple merge bases with #235. A triple-dot diff selects one base and can exaggerate changes by displaying already-integrated files. Git 2.52 ort merge-tree resolves the virtual merge base cleanly; true net addition is 5 files, 410 insertions, 11 deletions. #242 independently merges cleanly with 4 files, 340 insertions, 5 deletions. Their changed file sets do not overlap.

## Complete open PR matrix

| PR | Source branch | Declared base PR | Earliest carrier | Unique commits vs #235 | Nonmatching nonmerge patches | Nearest open carriers | Disposition |
|---|---|---:|---|---:|---:|---|---|
| [#61](https://github.com/djshellshoxxx/patchtrace/pull/61) | `codex/agent-skills-spec56-20261014` | — | outside_pr235 | 1 | 1 | — | Unique historical patches require selective relevance/content review |
| [#67](https://github.com/djshellshoxxx/patchtrace/pull/67) | `chatgpt/deferred-audit-fixes-1` | — | outside_pr235 | 8 | 8 | — | Unique historical patches require selective relevance/content review |
| [#68](https://github.com/djshellshoxxx/patchtrace/pull/68) | `chatgpt/corpus-1` | — | outside_pr235 | 25 | 25 | — | Unique historical patches require selective relevance/content review |
| [#69](https://github.com/djshellshoxxx/patchtrace/pull/69) | `chatgpt/kb-fixtures-1` | — | outside_pr235 | 24 | 24 | — | Unique historical patches require selective relevance/content review |
| [#70](https://github.com/djshellshoxxx/patchtrace/pull/70) | `chatgpt/help-docs-1` | — | outside_pr235 | 25 | 25 | — | Unique historical patches require selective relevance/content review |
| [#71](https://github.com/djshellshoxxx/patchtrace/pull/71) | `chatgpt/unified-fixtures-1` | — | outside_pr235 | 25 | 25 | #90 | Contained in another open head; choose reviewed carrier, avoid duplicate merge |
| [#72](https://github.com/djshellshoxxx/patchtrace/pull/72) | `chatgpt/panels-1` | — | outside_pr235 | 10 | 10 | — | Unique historical patches require selective relevance/content review |
| [#78](https://github.com/djshellshoxxx/patchtrace/pull/78) | `chatgpt/lbl31-output-persistence-20261015` | — | outside_pr235 | 33 | 33 | #82 | Contained in another open head; choose reviewed carrier, avoid duplicate merge |
| [#79](https://github.com/djshellshoxxx/patchtrace/pull/79) | `chatgpt/lbl32-card-controls-20261016` | 78 | outside_pr235 | 36 | 36 | — | Unique historical patches require selective relevance/content review |
| [#82](https://github.com/djshellshoxxx/patchtrace/pull/82) | `chatgpt/lbl32-recipe-aa-noise-20261016` | — | outside_pr235 | 52 | 51 | — | Unique historical patches require selective relevance/content review |
| [#85](https://github.com/djshellshoxxx/patchtrace/pull/85) | `chatgpt/lbl30-prereg-guard-20261016` | — | outside_pr235 | 43 | 43 | — | Unique historical patches require selective relevance/content review |
| [#86](https://github.com/djshellshoxxx/patchtrace/pull/86) | `chatgpt/ue-r3-retain-decompiled-20261016` | — | outside_pr235 | 11 | 11 | — | Unique historical patches require selective relevance/content review |
| [#90](https://github.com/djshellshoxxx/patchtrace/pull/90) | `chatgpt/unified-fixture-collection-fix-20261016` | 71 | outside_pr235 | 30 | 30 | — | Unique historical patches require selective relevance/content review |
| [#94](https://github.com/djshellshoxxx/patchtrace/pull/94) | `chatgpt/unified-sort-perf-qa-20261016` | 78 | outside_pr235 | 22 | 22 | — | Unique historical patches require selective relevance/content review |
| [#98](https://github.com/djshellshoxxx/patchtrace/pull/98) | `docs/readme-and-wiki` | — | outside_pr235 | 1 | 1 | — | Unique historical patches require selective relevance/content review |
| [#100](https://github.com/djshellshoxxx/patchtrace/pull/100) | `claude/patchtrace-features` | — | outside_pr235 | 8 | 8 | — | Unique historical patches require selective relevance/content review |
| [#102](https://github.com/djshellshoxxx/patchtrace/pull/102) | `claude/patchtrace-haiku-agent-motpbx` | — | outside_pr235 | 13 | 13 | — | Unique historical patches require selective relevance/content review |
| [#125](https://github.com/djshellshoxxx/patchtrace/pull/125) | `claude/compassionate-goldberg-5uuqks` | — | outside_pr235 | 1 | 1 | — | Unique historical patches require selective relevance/content review |
| [#126](https://github.com/djshellshoxxx/patchtrace/pull/126) | `claude/modest-hamilton-kz2gta` | — | outside_pr235 | 12 | 5 | — | Unique historical patches require selective relevance/content review |
| [#127](https://github.com/djshellshoxxx/patchtrace/pull/127) | `docs/dockable-workspace-spec-20261030` | — | outside_pr235 | 1 | 1 | — | Unique historical patches require selective relevance/content review |
| [#128](https://github.com/djshellshoxxx/patchtrace/pull/128) | `codex/r1-ground-truth-research-20261030` | — | outside_pr235 | 9 | 8 | — | Unique historical patches require selective relevance/content review |
| [#129](https://github.com/djshellshoxxx/patchtrace/pull/129) | `chatgpt/semantic-analysis-r3-20261030` | — | outside_pr235 | 14 | 14 | — | Unique historical patches require selective relevance/content review |
| [#130](https://github.com/djshellshoxxx/patchtrace/pull/130) | `research/r4-vulnerability-correlation-20261030` | — | outside_pr235 | 12 | 12 | — | Unique historical patches require selective relevance/content review |
| [#131](https://github.com/djshellshoxxx/patchtrace/pull/131) | `codex/r2-unified-matching-research-20261030` | — | outside_pr235 | 4 | 4 | — | Unique historical patches require selective relevance/content review |
| [#132](https://github.com/djshellshoxxx/patchtrace/pull/132) | `chatgpt/r5-calibration-research-20261030` | — | outside_pr235 | 11 | 11 | — | Unique historical patches require selective relevance/content review |
| [#133](https://github.com/djshellshoxxx/patchtrace/pull/133) | `research/r6-final-integration-engineering-notes-20261030` | — | outside_pr235 | 12 | 12 | — | Unique historical patches require selective relevance/content review |
| [#134](https://github.com/djshellshoxxx/patchtrace/pull/134) | `research/r7-advanced-binary-analysis-20261030` | — | outside_pr235 | 29 | 29 | — | Unique historical patches require selective relevance/content review |
| [#135](https://github.com/djshellshoxxx/patchtrace/pull/135) | `research/r8-deep-uncertainty-20261030` | — | outside_pr235 | 16 | 16 | — | Unique historical patches require selective relevance/content review |
| [#136](https://github.com/djshellshoxxx/patchtrace/pull/136) | `integration/kb-fixtures-pr69-20261030` | — | outside_pr235 | 12 | 12 | #142 | Contained in another open head; choose reviewed carrier, avoid duplicate merge |
| [#137](https://github.com/djshellshoxxx/patchtrace/pull/137) | `docs/post-consolidation-gap-analysis-20261030` | — | outside_pr235 | 20 | 20 | — | Unique historical patches require selective relevance/content review |
| [#138](https://github.com/djshellshoxxx/patchtrace/pull/138) | `repair/gt01-unified-live-gates-20261030` | — | outside_pr235 | 15 | 15 | — | Unique historical patches require selective relevance/content review |
| [#139](https://github.com/djshellshoxxx/patchtrace/pull/139) | `repair/gt01-consolidated-native-evidence-20261030` | — | outside_pr235 | 12 | 12 | #140 | Contained in another open head; choose reviewed carrier, avoid duplicate merge |
| [#140](https://github.com/djshellshoxxx/patchtrace/pull/140) | `repair/gt01-native-identical-controls-20261030` | 139 | outside_pr235 | 14 | 14 | #141 | Contained in another open head; choose reviewed carrier, avoid duplicate merge |
| [#141](https://github.com/djshellshoxxx/patchtrace/pull/141) | `codex/gt01-extraction-recovery-20261030` | 140 | outside_pr235 | 16 | 15 | #143 | Contained in another open head; choose reviewed carrier, avoid duplicate merge |
| [#142](https://github.com/djshellshoxxx/patchtrace/pull/142) | `codex/kb-fixture-contract-repairs-20261030` | 136 | outside_pr235 | 13 | 13 | #143 | Contained in another open head; choose reviewed carrier, avoid duplicate merge |
| [#143](https://github.com/djshellshoxxx/patchtrace/pull/143) | `codex/essential-combined-verification-20261030` | — | outside_pr235 | 20 | 18 | #144 | Contained in another open head; choose reviewed carrier, avoid duplicate merge |
| [#144](https://github.com/djshellshoxxx/patchtrace/pull/144) | `codex/semantic-proof-reconciliation-20261031` | 143 | outside_pr235 | 28 | 26 | #152 | Contained in another open head; choose reviewed carrier, avoid duplicate merge |
| [#147](https://github.com/djshellshoxxx/patchtrace/pull/147) | `codex/windows-branding-reconcile-20261030` | — | outside_pr235 | 4 | 4 | #152 | Contained in another open head; choose reviewed carrier, avoid duplicate merge |
| [#148](https://github.com/djshellshoxxx/patchtrace/pull/148) | `codex/essential-project-safety-20261031` | — | outside_pr235 | 1 | 1 | #152 | Contained in another open head; choose reviewed carrier, avoid duplicate merge |
| [#150](https://github.com/djshellshoxxx/patchtrace/pull/150) | `codex/receipt-parent-race-20261101` | — | outside_pr235 | 9 | 9 | — | Unique historical patches require selective relevance/content review |
| [#152](https://github.com/djshellshoxxx/patchtrace/pull/152) | `codex/autonomous-reconcile-20261101` | — | outside_pr235 | 41 | 36 | #159 | Contained in another open head; choose reviewed carrier, avoid duplicate merge |
| [#154](https://github.com/djshellshoxxx/patchtrace/pull/154) | `codex/training-prereg-identity-20261101` | — | outside_pr235 | 4 | 3 | #164 | Contained in another open head; choose reviewed carrier, avoid duplicate merge |
| [#157](https://github.com/djshellshoxxx/patchtrace/pull/157) | `codex/corpus-output-main-20261101` | — | outside_pr235 | 9 | 6 | #164 | Contained in another open head; choose reviewed carrier, avoid duplicate merge |
| [#158](https://github.com/djshellshoxxx/patchtrace/pull/158) | `codex/msrc-mixed-format-revision-20261102` | — | outside_pr235 | 3 | 3 | — | Unique historical patches require selective relevance/content review |
| [#159](https://github.com/djshellshoxxx/patchtrace/pull/159) | `codex/msrc-reconcile-integration-20261102` | 152 | outside_pr235 | 42 | 36 | #163 | Contained in another open head; choose reviewed carrier, avoid duplicate merge |
| [#163](https://github.com/djshellshoxxx/patchtrace/pull/163) | `codex/consolidated-reviewed-20261102` | — | outside_pr235 | 54 | 45 | #164 | Divergent recovery history; preserve and selectively audit |
| [#164](https://github.com/djshellshoxxx/patchtrace/pull/164) | `codex/consolidation-integrity-20261103` | 163 | outside_pr235 | 58 | 46 | #165 | Divergent recovery history; preserve and selectively audit |
| [#165](https://github.com/djshellshoxxx/patchtrace/pull/165) | `repair/rzdiff-producer-ownership` | 164 | outside_pr235 | 60 | 48 | #166 | Contained in another open head; choose reviewed carrier, avoid duplicate merge |
| [#166](https://github.com/djshellshoxxx/patchtrace/pull/166) | `repair/rzdiff-native-callback-size-20261103` | 165 | outside_pr235 | 61 | 48 | #168 | Contained in another open head; choose reviewed carrier, avoid duplicate merge |
| [#167](https://github.com/djshellshoxxx/patchtrace/pull/167) | `automation/patchtrace-api-agent-pilot-20261103` | — | outside_pr235 | 2 | 2 | — | Separate automation policy/design; do not bulk enable |
| [#168](https://github.com/djshellshoxxx/patchtrace/pull/168) | `repair/rzdiff-native-red-control-20261103` | 166 | outside_pr235 | 63 | 49 | — | Divergent recovery history; preserve and selectively audit |
| [#170](https://github.com/djshellshoxxx/patchtrace/pull/170) | `automation/api-funded-persistent-codex-20261103` | — | outside_pr235 | 9 | 9 | — | Separate automation policy/design; do not bulk enable |
| [#171](https://github.com/djshellshoxxx/patchtrace/pull/171) | `automation/parallel-api-eight-agents-20261103` | — | outside_pr235 | 23 | 23 | — | Separate automation policy/design; do not bulk enable |
| [#172](https://github.com/djshellshoxxx/patchtrace/pull/172) | `claude/serene-heisenberg-2y5kz6` | — | outside_pr235 | 2 | 1 | — | Unique historical patches require selective relevance/content review |
| [#174](https://github.com/djshellshoxxx/patchtrace/pull/174) | `claude/ws-bc-20261104` | — | outside_pr235 | 29 | 21 | — | Unique historical patches require selective relevance/content review |
| [#176](https://github.com/djshellshoxxx/patchtrace/pull/176) | `claude/ws-p-20261104` | — | outside_pr235 | 26 | 23 | — | Unique historical patches require selective relevance/content review |
| [#177](https://github.com/djshellshoxxx/patchtrace/pull/177) | `claude/ws-a2-ci-speed-20261104` | — | outside_pr235 | 7 | 3 | — | Unique historical patches require selective relevance/content review |
| [#178](https://github.com/djshellshoxxx/patchtrace/pull/178) | `research/additional-reuse-claude-20261103` | — | outside_pr235 | 1 | 1 | — | Unique historical patches require selective relevance/content review |
| [#179](https://github.com/djshellshoxxx/patchtrace/pull/179) | `claude/patchtrace-multi-worker-consolidate-24ct7v` | — | outside_pr235 | 7 | 5 | — | Unique historical patches require selective relevance/content review |
| [#180](https://github.com/djshellshoxxx/patchtrace/pull/180) | `claude/gallant-knuth-8gxuzd` | — | pr205 | 0 | — | #185 | Ancestry already in #235; no additional code merge |
| [#181](https://github.com/djshellshoxxx/patchtrace/pull/181) | `consolidate/rules-callgraph-20261104` | — | outside_pr235 | 9 | 0 | — | All distinct nonmerge patches in #235; verify resolutions then no duplicate code merge |
| [#182](https://github.com/djshellshoxxx/patchtrace/pull/182) | `consolidate/kb-fixtures-20261104` | — | outside_pr235 | 4 | 0 | — | All distinct nonmerge patches in #235; verify resolutions then no duplicate code merge |
| [#183](https://github.com/djshellshoxxx/patchtrace/pull/183) | `consolidate/docs-20261104` | — | outside_pr235 | 13 | 13 | — | Independent docs carrier; review stale claims before importing |
| [#184](https://github.com/djshellshoxxx/patchtrace/pull/184) | `consolidate/test-stability-20261104` | — | outside_pr235 | 4 | 0 | #189 | All distinct nonmerge patches in #235; verify resolutions then no duplicate code merge |
| [#185](https://github.com/djshellshoxxx/patchtrace/pull/185) | `worker/patchtrace-cli-help-20261104` | 180 | pr205 | 0 | — | #188 | Ancestry already in #235; no additional code merge |
| [#186](https://github.com/djshellshoxxx/patchtrace/pull/186) | `codex/repair-openai-agent-20261104` | — | outside_pr235 | 2 | 2 | — | Independent workflow repair; separate permissions/execution review |
| [#187](https://github.com/djshellshoxxx/patchtrace/pull/187) | `codex/consolidation-audit-20261104` | — | outside_pr235 | 2 | 2 | — | Unique historical patches require selective relevance/content review |
| [#188](https://github.com/djshellshoxxx/patchtrace/pull/188) | `codex/manual-correction-completeness-20261104` | 185 | pr205 | 0 | — | #192 | Ancestry already in #235; no additional code merge |
| [#189](https://github.com/djshellshoxxx/patchtrace/pull/189) | `codex/parser-test-cpu-budget-20261104` | 184 | outside_pr235 | 5 | 0 | — | All distinct nonmerge patches in #235; verify resolutions then no duplicate code merge |
| [#190](https://github.com/djshellshoxxx/patchtrace/pull/190) | `codex/kb-explicit-filename-selection-20261104` | — | outside_pr235 | 1 | 0 | — | All distinct nonmerge patches in #235; verify resolutions then no duplicate code merge |
| [#191](https://github.com/djshellshoxxx/patchtrace/pull/191) | `integrate/rules-20261105` | — | pr205 | 0 | — | #205 | Ancestry already in #235; no additional code merge |
| [#192](https://github.com/djshellshoxxx/patchtrace/pull/192) | `repair/unified-ci-20261105` | 188 | pr205 | 0 | — | #203 | Ancestry already in #235; no additional code merge |
| [#193](https://github.com/djshellshoxxx/patchtrace/pull/193) | `integrate/kb-20261105` | — | pr205 | 0 | — | #201 | Ancestry already in #235; no additional code merge |
| [#194](https://github.com/djshellshoxxx/patchtrace/pull/194) | `integrate/autonomous-20261105` | — | pr205 | 0 | — | #205 | Ancestry already in #235; no additional code merge |
| [#195](https://github.com/djshellshoxxx/patchtrace/pull/195) | `integrate/native-controls-20261105` | — | pr205 | 0 | — | #208 | Ancestry already in #235; no additional code merge |
| [#196](https://github.com/djshellshoxxx/patchtrace/pull/196) | `integrate/gui-inspection-20261105` | — | pr205 | 0 | — | #205 | Ancestry already in #235; no additional code merge |
| [#197](https://github.com/djshellshoxxx/patchtrace/pull/197) | `integrate/secondary-prep-20261105` | — | pr205 | 0 | — | #206 | Ancestry already in #235; no additional code merge |
| [#198](https://github.com/djshellshoxxx/patchtrace/pull/198) | `integrate/project-adoption-20261105` | — | pr205 | 0 | — | #201 | Ancestry already in #235; no additional code merge |
| [#199](https://github.com/djshellshoxxx/patchtrace/pull/199) | `repair/verified-bytes-20261105` | — | pr205 | 0 | — | #205 | Ancestry already in #235; no additional code merge |
| [#200](https://github.com/djshellshoxxx/patchtrace/pull/200) | `audit/random-boundaries-20261105` | — | pr205 | 0 | — | #205 | Ancestry already in #235; no additional code merge |
| [#201](https://github.com/djshellshoxxx/patchtrace/pull/201) | `integrate/kb-investigation-20261105` | — | pr205 | 0 | — | #205 | Ancestry already in #235; no additional code merge |
| [#202](https://github.com/djshellshoxxx/patchtrace/pull/202) | `audit/random-lifecycle-20261105` | — | pr205 | 0 | — | #207 | Ancestry already in #235; no additional code merge |
| [#203](https://github.com/djshellshoxxx/patchtrace/pull/203) | `repair/unified-support-evidence-20261105` | 192 | pr205 | 0 | — | #205 | Ancestry already in #235; no additional code merge |
| [#204](https://github.com/djshellshoxxx/patchtrace/pull/204) | `repair/workflow-fragment-20261105` | — | pr205 | 0 | — | #205 | Ancestry already in #235; no additional code merge |
| [#205](https://github.com/djshellshoxxx/patchtrace/pull/205) | `integrate/swarm-qualified-20261105` | — | pr205 | 0 | — | #219, #215, #216 | Predecessor qualification carrier; retain staged promotion order |
| [#206](https://github.com/djshellshoxxx/patchtrace/pull/206) | `repair/native-input-open-20261105` | 197 | pr205 | 0 | — | #205 | Ancestry already in #235; no additional code merge |
| [#207](https://github.com/djshellshoxxx/patchtrace/pull/207) | `repair/streamed-series-recovery-20261105` | 202 | pr205 | 0 | — | #205 | Ancestry already in #235; no additional code merge |
| [#208](https://github.com/djshellshoxxx/patchtrace/pull/208) | `qualify/native-controls-20261105` | 195 | pr205 | 0 | — | #205 | Ancestry already in #235; no additional code merge |
| [#209](https://github.com/djshellshoxxx/patchtrace/pull/209) | `qualify/offline-tooling-20261105` | — | pr205 | 0 | — | #205 | Ancestry already in #235; no additional code merge |
| [#210](https://github.com/djshellshoxxx/patchtrace/pull/210) | `repair/project-create-rollback-20261105` | — | pr205 | 0 | — | #205 | Ancestry already in #235; no additional code merge |
| [#215](https://github.com/djshellshoxxx/patchtrace/pull/215) | `integrate/calibration-prereg-20261105` | 205 | pr218 | 0 | — | #217 | Ancestry already in #235; no additional code merge |
| [#216](https://github.com/djshellshoxxx/patchtrace/pull/216) | `audit/random-invariants-20261105` | 205 | pr218 | 0 | — | #218 | Ancestry already in #235; no additional code merge |
| [#217](https://github.com/djshellshoxxx/patchtrace/pull/217) | `integrate/calibration-replay-20261105` | 215 | pr218 | 0 | — | #218 | Ancestry already in #235; no additional code merge |
| [#218](https://github.com/djshellshoxxx/patchtrace/pull/218) | `integrate/swarm-wave3-20261105` | 205 | pr218 | 0 | — | #236, #233, #232, #231, #230, #229, #228, #225, #226, #227 | Predecessor qualification carrier; retain staged promotion order |
| [#219](https://github.com/djshellshoxxx/patchtrace/pull/219) | `repair/wizard-lock-retry-20261105` | 205 | pr218 | 0 | — | #218 | Ancestry already in #235; no additional code merge |
| [#222](https://github.com/djshellshoxxx/patchtrace/pull/222) | `qualify/native-provision-20261105` | 205 | outside_pr235 | 4 | 4 | #224 | Subsumed by #224; preserve native qualification ownership |
| [#224](https://github.com/djshellshoxxx/patchtrace/pull/224) | `qualify/native-cli-seeding-20261105` | 222 | outside_pr235 | 5 | 5 | — | Native evidence/control work; hold for independent acceptance |
| [#225](https://github.com/djshellshoxxx/patchtrace/pull/225) | `work/online-adapter-20261105` | 218 | pr235 | 0 | — | #243 | Ancestry already in #235; no additional code merge |
| [#226](https://github.com/djshellshoxxx/patchtrace/pull/226) | `work/investigation-accessibility-20261105` | 218 | pr235 | 0 | — | #234 | Ancestry already in #235; no additional code merge |
| [#227](https://github.com/djshellshoxxx/patchtrace/pull/227) | `work/persistence-security-20261105` | 218 | pr235 | 0 | — | #243 | Ancestry already in #235; no additional code merge |
| [#228](https://github.com/djshellshoxxx/patchtrace/pull/228) | `work/windows-package-preflight-20261105` | 218 | pr235 | 0 | — | #243 | Ancestry already in #235; no additional code merge |
| [#229](https://github.com/djshellshoxxx/patchtrace/pull/229) | `work/candidate-correlation-20261105` | 218 | pr235 | 0 | — | #243 | Ancestry already in #235; no additional code merge |
| [#230](https://github.com/djshellshoxxx/patchtrace/pull/230) | `work/calibration-invariants-20261105` | 218 | pr235 | 0 | — | #243 | Ancestry already in #235; no additional code merge |
| [#231](https://github.com/djshellshoxxx/patchtrace/pull/231) | `docs/research-reconciliation-20261105` | 218 | pr235 | 0 | — | #243 | Ancestry already in #235; no additional code merge |
| [#232](https://github.com/djshellshoxxx/patchtrace/pull/232) | `docs/ranking-reuse-20261105` | 218 | pr235 | 0 | — | #243 | Ancestry already in #235; no additional code merge |
| [#233](https://github.com/djshellshoxxx/patchtrace/pull/233) | `test/advisory-acceptance-20261105` | 218 | pr235 | 0 | — | #243 | Ancestry already in #235; no additional code merge |
| [#234](https://github.com/djshellshoxxx/patchtrace/pull/234) | `work/online-investigation-20261105` | 226 | pr235 | 0 | — | #240 | Ancestry already in #235; no additional code merge |
| [#235](https://github.com/djshellshoxxx/patchtrace/pull/235) | `integrate/independent-wave4-20261105` | 218 | pr235 | 0 | — | — | Final staged carrier; pending qualification; stage #242/#243 here; main merge waits gates |
| [#236](https://github.com/djshellshoxxx/patchtrace/pull/236) | `work/pe-parser-security-20261105` | 218 | pr235 | 0 | — | #243 | Ancestry already in #235; no additional code merge |
| [#240](https://github.com/djshellshoxxx/patchtrace/pull/240) | `work/investigation-candidates-20261105` | 234 | pr235 | 0 | — | #243 | Ancestry already in #235; no additional code merge |
| [#242](https://github.com/djshellshoxxx/patchtrace/pull/242) | `resume/kb-acquire-lifecycle-20261106` | 235 | outside_pr235 | 2 | 2 | — | Current unique slice; merge into #235 after targeted validation |
| [#243](https://github.com/djshellshoxxx/patchtrace/pull/243) | `resume/desktop-index-refresh-20261106` | 235 | outside_pr235 | 2 | 1 | — | Current unique slice; merge into #235 after targeted validation |
