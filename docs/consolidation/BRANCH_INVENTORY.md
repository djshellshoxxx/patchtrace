# PatchTrace branch, tag and pull-request inventory

## Later recovery checkpoint

Source `eb595b82` additionally recovers managed training transfer, paired runner
publication, GUI accessible control identities and five research workflow
modules. See `RECOVERED_WORK.md` for source hashes and review evidence. The
machine census and classifications below remain explicitly frozen at their
original comparison (`77204ef5`); they have not been relabeled as a refreshed
full semantic review. Search and Strings parity are active recovery queues.


## Scope and baseline

This record covers the frozen 2026-11-19 census of **319 branches, 59 tags and 309 pull requests**. The comparison main is `fdc2696c23bdbfe7668348f25e3b336ce33039f7` and the isolated candidate is `77204ef5c9623545d81b0eb73d5cd14f80b2d0e7` (tree `fb5d56464b9a951add6fddbe4731dcd7388a9a27`). Session-created publication branches are outside this frozen census.

All branch tips, tag targets and PR heads are retained in the machine records under `inventory/`. Every branch has a disposition below. These dispositions distinguish actual ancestry and patch identity from the narrower historical semantic reviews. A branch with unmatched patches is not automatically missing a feature; a matching path or marker is not proof that its complete behavior is preserved. **Semantic exhaustion remains open. No branch deletion or PR closure is authorized by this inventory.**

The branch and PR APIs were paginated to their final short pages: branch pages contained 100, 100, 100 and 19 rows; PR pages contained 100, 100, 100 and 9 rows. The Git matching-refs endpoint returned all 59 tag refs. PR states are the frozen observation, not an assertion about later GitHub activity.

## Evidence and remaining work

- PR metadata: 53 open, 84 closed unmerged and 172 merged.
- Historical focal scopes rechecked: 131; frozen source-tip mismatches: 0.
- Historical source path/blob checks: 3030; mismatches: 0. Checks include repeated paths across branch scopes and are not independent test cases.
- Historical replacement markers rechecked: 298; absent markers needing interpretation: 10.
- Previously absent Python paths: 60; still absent by name: 33. The path ledger records exact source heads and blobs; a renamed replacement may already provide the behavior.

Of branches without a historical focal-scope receipt, 13 have source/tool path deltas and 30 have only other path deltas. These are review queues, not missing-feature counts.

| Disposition | Branches | Meaning |
|---|---:|---|
| ancestor-of-candidate | 13 | Exact tip belongs to the isolated candidate history; main qualification is pending. |
| ancestor-of-main | 128 | Exact tip belongs to main history; this is ancestry evidence. |
| historical-scope-checked-residue-open | 116 | A historical focal-scope record was rechecked; unreviewed residue remains. |
| main-baseline | 1 | Frozen default-branch baseline. |
| patch-equivalent-scope-review-open | 16 | No unmatched nonmerge patch under git cherry; semantic review remains open. |
| scoped-port-with-open-residue | 2 | A named feature was recovered; the rest of the branch remains scoped review work. |
| unreviewed-semantic-residue | 43 | Enumerated with structural evidence; no current full semantic review is claimed. |

### Historical marker drift

10 of the ten absent historical literals have explicit current-source interpretations in `inventory/marker-source-interpretations.json`. Shared publication helpers and owned self-test cleanup moved to dedicated modules; code-window guards retain dedicated regression controls; three old strict expected-failure decorators became ordinary required tests. Independent KB source review confirms that the other three markers were replaced by explicit saved selectors, global conflict admission and scoped context digests. Literal absence alone is not a regression. The source interpretations do not manufacture passing test results or close unrelated branch residue.

### Recovered contributions and highest-value residuals

| Contribution | Exact historical source | Candidate disposition |
|---|---|---|
| Calls node layout | `6e1e153bd90b251b81b9cc919b0cbbb7f1d8d9ac` | Recovered as `77204ef5`; active worker/canvas consumer, strict budgets and cancellation. Existing straight-edge renderer retained. See `CALLGRAPH_LAYOUT_RECOVERY.md`. Broad feature-branch residue remains open. |
| Tier-W CLI | `ce02504a`, `bff635ff` on `claude/autonomous-finish-20261104` | CLI and verifier repairs present through `2d14db8e`. Native runner recovery from `c1a46beb` is separate work. |
| Tier-R training artifacts | Newer manifest-last implementation at `c13d3257c88140c23fb585a8a59a4dce81e81928`, through checkpoints `51a9b4af` and `d038ddea`; older origins `17576698`, `6808f438`, `0843de5f` | Missing at this checkpoint. Prefer the newer managed report-credit and strict manifest implementation for bounded recovery; do not copy the obsolete helper solely because it was the original contribution. |
| Research runners and receipts | `2fdac2ea9042985ac3c98545d38ac3461d00f4cc`; contributions `8c9eafc7`, `fc1a9c2d`, `0d14548e`, `a02a1774` | Review runnable entry points and current receipt contracts before recovery. No blanket experimental exclusion and no blanket acceptance. |
| Older build/config, GUI wiring and automation paths | Exact heads and blobs in `inventory/python-path-residue.json` | Determine whether current modules replace each behavior; absent filenames alone do not justify copying obsolete integration code. |

The complete #318/#316 history is retained in the isolated integration candidate with #319. This inventory does not blanket-defer those snapshots. Their source ancestry is measured below. Native Windows, full integrated tests, security qualification and release acceptance remain separate coordinator gates.

### PR heads no longer equal to a current branch tip

35 recorded PR heads no longer equal any current branch tip. The machine ledger includes every such head, including merged historical heads. Only 2 are closed unmerged: #60 and #102. Both remain ancestors of their reused current named branches. #60 is patch-equivalent to the candidate; #102 retains unmatched historical packaging/parser work and is covered by the named-branch residual review. All 309 recorded PR heads are available locally after fetching 26 old merged heads into a separate archival namespace. Each orphan head has explicit patch evidence. The orphan trees contain 0 missing named Python paths not previously seen in the branch-tip residue scan; exact source PRs and blobs are in `inventory/orphan-path-residue.json`.

### Merged into another branch

Four PRs have GitHub merged status while their recorded merge commits are not ancestors of this candidate. Merged status is therefore not used as an integration shortcut.

| PR | Original target | Current scoped observation |
|---|---|---|
| #145 | `codex/r1-ground-truth-research-20261030` | Research runner/receipt preservation is still a concrete missing module family. The source branch and latest receipt repair remain retained. |
| #146 | `claude/modest-hamilton-kz2gta` | The historical warning-only gap is no longer a missing literal: current `index.py` emits `NAMED_SUPERSEDED`. Existing duplicate-content rule hardening remains subject to its own current tests. |
| #160 | `codex/corpus-output-main-20261101` | Replay/output-store/report-schema focal markers remain present; broader branch closure is not inferred. |
| #161 | `codex/training-prereg-identity-20261101` | Bounded preregistration and training-selection focal markers remain present; broader branch closure is not inferred. |

## Per-branch disposition

Full SHAs, exact unmatched/equivalent nonmerge commits, changed paths and PR head matches are in `inventory/branches.json`. The compact table below uses eight-character commit prefixes only for readability.

| Branch | Tip | PRs | Unmatched patches | Disposition | Historical focal scope |
|---|---|---|---:|---|---|
| `access-test-noprefix` | `726a371a` | — | 28 | historical-scope-checked-residue-open | Verified offline runtime import and private JDK discovery |
| `audit/ai-reports` | `dd6402b9` | — | 1 | historical-scope-checked-residue-open | Total provider deadline and report path redaction |
| `audit/core` | `fae13b2e` | — | 2 | historical-scope-checked-residue-open | Strict JSON, transactional ownership, backup and manual-correction guards |
| `audit/desktop` | `4d5e48ab` | — | 1 | historical-scope-checked-residue-open | Plain untrusted tooltips/consent, empty export path, self-test cleanup |
| `audit/enrichment` | `cbc5b079` | — | 3 | historical-scope-checked-residue-open | The three enrichment audit commits: predicate/dereference and temporary-spill negatives, WIL noise filtering, partial provider success, snapshot selection and cache lease recovery. |
| `audit/integration` | `f6505928` | #11 merged | 18 | historical-scope-checked-residue-open | The integrated audit's cancellation/publication, settings validation, report escaping, acquisition and ownership behavior. |
| `audit/kb-correlation-20261107` | `c760e6cc` | #276 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `audit/random-boundaries-20261105` | `802b5b1b` | #200 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `audit/random-invariants-20261105` | `7716e2b0` | #216 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `audit/random-lifecycle-20261105` | `f2b7d178` | #202 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `audit/runtime` | `9f32a6ec` | — | 2 | historical-scope-checked-residue-open | Runtime probe parsing, bounded scratch cleanup, process failure and diagnostic filtering |
| `audit/trust-boundaries-20261107` | `d75c0490` | #275 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `automation/api-funded-persistent-codex-20261103` | `6fe6c4b1` | #170 closed | 9 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `automation/parallel-api-eight-agents-20261103` | `f8050a1f` | #171 closed | 23 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `automation/patchtrace-api-agent-pilot-20261103` | `def36c82` | #167 closed | 2 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `chatgpt/corpus-1` | `b7a0f0a4` | #68 open | 25 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `chatgpt/deferred-audit-fixes-1` | `2174837f` | #67 closed | 8 | historical-scope-checked-residue-open | Isolated backend probes/input copies, explicit acquisition consent and storage guards |
| `chatgpt/ghidriff-sequential-lock-fix-20261017` | `f6b7545b` | #96 merged | 5 | historical-scope-checked-residue-open | Serial native Ghidriff analysis in every launcher mode |
| `chatgpt/help-docs-1` | `e5bee6fe` | #70 open | 25 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `chatgpt/java-probe-boundaries-20261016` | `09bb4519` | #84 closed | 2 | historical-scope-checked-residue-open | Bounded Java runtime-version probing |
| `chatgpt/java-probe-ci-fix-20261016` | `0254841e` | #81 closed | 1 | historical-scope-checked-residue-open | Bounded Java runtime-version probing |
| `chatgpt/java-probe-qa-fix-20261016` | `89500e12` | #80 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `chatgpt/kb-fixtures-1` | `781b36fb` | #69 closed | 24 | historical-scope-checked-residue-open | Offline synthetic KB corpus and fixture boundaries |
| `chatgpt/lbl30-prereg-guard-20261016` | `6ae2c079` | #85 open | 43 | historical-scope-checked-residue-open | Protocol identity versus single-use final-run wrapper |
| `chatgpt/lbl31-coff-quoted-rip-20261016` | `6e71bfab` | #92 closed | 23 | historical-scope-checked-residue-open | Quoted COFF RIP symbols and function-body boundaries |
| `chatgpt/lbl31-coff-symbol-mask-20261016` | `9622704d` | #91 closed | 25 | historical-scope-checked-residue-open | Quoted COFF RIP symbols and function-body boundaries |
| `chatgpt/lbl31-output-persistence-20261015` | `2019a37f` | #78 open | 33 | historical-scope-checked-residue-open | Normalized output retention, COFF masking and default sorting |
| `chatgpt/lbl31-windows-qa-fixes-20261016-a` | `ddb2ff07` | #93 closed | 26 | historical-scope-checked-residue-open | Quoted COFF and default-sort QA with inherited replay work |
| `chatgpt/lbl32-card-controls-20261016` | `9513bc05` | #79 open | 36 | historical-scope-checked-residue-open | A/A failure credit and per-card side controls |
| `chatgpt/lbl32-recipe-aa-noise-20261016` | `eaa30013` | #82 open | 51 | historical-scope-checked-residue-open | Recipe-pin A/A/noise enumeration and metadata guards |
| `chatgpt/merge-first-handoff-20261016` | `19153f10` | #87 merged | 5 | historical-scope-checked-residue-open | Historical integration handoff and supersession notes |
| `chatgpt/nway-external-note-qa-20261016` | `8c728827` | #89 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `chatgpt/panels-1` | `cfd7cfff` | #72 open | 10 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `chatgpt/patchwatch-reuse-roadmap-20261026` | `4eabf8df` | #101 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `chatgpt/r5-calibration-research-20261030` | `4d9d9051` | #132 closed | 11 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `chatgpt/semantic-analysis-r3-20261030` | `2698b9a0` | #129 open | 14 | historical-scope-checked-residue-open | IR cosmetic proof requires EH evidence and rejects register changes |
| `chatgpt/ue-r3-retain-decompiled-20261016` | `ebbd621d` | #86 open | 11 | historical-scope-checked-residue-open | Persist and validate decompiled text for the paired code view |
| `chatgpt/ue-r7-p15-unresolved-20261016-a` | `292dc395` | #83 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `chatgpt/ue-r7-strict-worker-report-20261016-a` | `9c5f9a42` | #88 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `chatgpt/unified-fixture-collection-fix-20261016` | `941c617b` | #90 closed | 30 | historical-scope-checked-residue-open | Collected synthetic unified-engine fixtures |
| `chatgpt/unified-fixtures-1` | `161a8834` | #71 closed | 25 | historical-scope-checked-residue-open | Collected synthetic unified-engine fixtures |
| `chatgpt/unified-sort-perf-qa-20261016` | `27b0a48b` | #94 closed | 22 | historical-scope-checked-residue-open | Quoted COFF and default-sort QA with inherited replay work |
| `claude/access-test-1791773355` | `726a371a` | — | 28 | historical-scope-checked-residue-open | Offline runtime importer and private JDK alias |
| `claude/affectionate-galileo-bqd3tw` | `b29351d4` | #268 open | 2 | historical-scope-checked-residue-open | RB01 source-path provenance and conservative ground-truth labels |
| `claude/audit-beta` | `c93ff945` | — | 1 | historical-scope-checked-residue-open | The original multi-area audit repair, including analyst-facing error handling and byte/PE boundary correctness. |
| `claude/autonomous-finish-20261104` | `ad4c4928` | #289 open | 120 | scoped-port-with-open-residue | Named recovery above; broad residue open. |
| `claude/awesome-ramanujan-o3pxx3-ci` | `0bf1f830` | — | 1 | historical-scope-checked-residue-open | Windows build/validation job split and release-note asset provenance |
| `claude/awesome-ramanujan-o3pxx3-hostile` | `077b04e6` | — | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `claude/awesome-ramanujan-o3pxx3-win1` | `7ac57759` | — | 1 | historical-scope-checked-residue-open | Packaged desktop and executable identity |
| `claude/bugfix-kbc-20261029` | `653f384d` | #109 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `claude/bugfix-kev-acq-20261029` | `fbe58d80` | #107 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `claude/bugfix-rules-cg-20261029` | `78d48cf8` | — | 1 | historical-scope-checked-residue-open | All seven rule fixes and three callgraph fixes in the original round-2 audit patch. |
| `claude/bugfix-rules-cg-rest-20261111` | `67b2bc45` | #285 merged | 0 | patch-equivalent-scope-review-open | The later remaining-rule fixes and capped graph-export truth. |
| `claude/bugfix-search-pilot-20261111` | `d1f7d9aa` | #288 merged | 0 | patch-equivalent-scope-review-open | PR #288 unsigned address/cursor guards, signature phrase/exclude semantics, exact CVE-ID matching, real UTC timestamp validation and bounded multiline buildenv provenance. |
| `claude/bugfix-strings-pe-20261029` | `7ae041e7` | #108 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `claude/bundle-license-gate` | `d3617acf` | #65 merged | 3 | historical-scope-checked-residue-open | Strict backend manifest and explicit release license-policy gate |
| `claude/clever-clarke-s4nhi6` | `50240268` | #27 merged, #28 merged, #29 merged, #30 merged, #31 merged, #32 merged, #33 merged, #34 merged, #38 merged, #42 merged, #46 merged, #49 merged, #50 merged, #52 merged, #53 merged, #57 merged, #62 merged, #63 merged | 0 | patch-equivalent-scope-review-open | QA job execution budget |
| `claude/compassionate-goldberg-5uuqks` | `198eb21e` | #125 open | 1 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `claude/fix-deadline-test` | `22ff025a` | #99 merged | 0 | patch-equivalent-scope-review-open | Floating-point tolerance in remaining-time assertion |
| `claude/funny-feynman-d2m0b5` | `770c11f4` | #287 merged | 18 | historical-scope-checked-residue-open | Conservative DATA-MAP consensus, alignment and IR-only leftovers |
| `claude/gallant-knuth-8gxuzd` | `f249edc8` | #180 merged, #259 closed | 5 | historical-scope-checked-residue-open | Manual/IR cache identity, timeout partials and PE scope evidence |
| `claude/instance-b-features` | `9237c260` | #44 merged, #47 merged, #59 merged | 97 | scoped-port-with-open-residue | Named recovery above; broad residue open. |
| `claude/instance-c-research` | `6f767cce` | #45 merged, #48 merged, #51 merged, #54 merged, #55 merged, #60 closed, #66 merged, #73 merged, #74 merged, #75 merged, #77 merged, #283 open | 13 | historical-scope-checked-residue-open | Fail closed on missing benchmark ticks and incomplete parity output |
| `claude/instance-d-gui` | `2fa11388` | #58 merged, #64 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `claude/java-version-retry-integration` | `45fa67ad` | #106 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `claude/jolly-fermi-eghaxy` | `99f8328c` | #123 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `claude/live-harness-infra-20261111` | `c59ccada` | #286 merged | 6 | historical-scope-checked-residue-open | Honest native-harness completion and failure semantics |
| `claude/live-proof-20261111` | `18efb7ef` | — | 8 | historical-scope-checked-residue-open | Recorded source roots and honest live-gate measurement |
| `claude/modest-hamilton-kz2gta` | `280bf058` | #126 closed | 5 | historical-scope-checked-residue-open | The coordinator rule/cache fixes plus an overlapping KB selected-source warning. |
| `claude/patchtrace-cli-dotpath-spec-er6hha` | `62b9a3de` | — | 3 | historical-scope-checked-residue-open | Shared typed configuration and build provenance proposal |
| `claude/patchtrace-features` | `66e9adc5` | #100 closed | 8 | historical-scope-checked-residue-open | PR #100 local/off/online PDB policy and private launcher plus Diaphora Mode A import. |
| `claude/patchtrace-haiku-agent-motpbx` | `cbabc09e` | #102 closed, #281 open | 14 | historical-scope-checked-residue-open | Pinned release action and tag-derived release naming |
| `claude/patchtrace-kbf04-fp-tests-20261118` | `16ab88b0` | #305 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `claude/patchtrace-multi-worker-consolidate-24ct7v` | `ca10acb5` | #179 open | 8 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `claude/patchtrace-search-anchors-circularity-20261118` | `f6ef1528` | #306 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `claude/patchtraces-consolidation-trngn0` | `faddea30` | #301 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `claude/quirky-curie-n5pxf5` | `a5593fa5` | #103 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `claude/serene-heisenberg-2y5kz6` | `7ed5cebf` | #172 open | 1 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `claude/sleepy-fermi-cli-parity-1` | `cf50b4e8` | #292 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `claude/sleepy-fermi-kbc-1` | `53f5dd26` | #291 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `claude/sleepy-fermi-na-rzdiff-ownership` | `aacb984e` | #293 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `claude/sleepy-fermi-rq-l1-runner` | `e88d748c` | #294 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `claude/sleepy-fermi-security-1` | `1d5a022d` | #290 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `claude/sleepy-fermi-test-reliability` | `37d9e47c` | #295 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `claude/sleepy-fermi-y3z4yj` | `160a60e8` | #284 open | 4 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `claude/spec53-diagnose-launcher` | `a00fcc14` | #280 merged | 0 | patch-equivalent-scope-review-open | PR #280 backend diagnose showing the private launcher Ghidriff revision as tested/untested. |
| `claude/symbol-policy-isolated-settings` | `5db59725` | #9 merged | 6 | historical-scope-checked-residue-open | Per-run Ghidra settings isolation and cached-PDB diagnosis |
| `claude/ws-a-20261104` | `dabba4ae` | #175 merged | 8 | historical-scope-checked-residue-open | Packaged desktop and executable identity |
| `claude/ws-a2-ci-speed-20261104` | `bef720fd` | #177 closed | 3 | historical-scope-checked-residue-open | Fixture isolation plus unretained CI parallelism experiment |
| `claude/ws-bc-20261104` | `e1193c88` | #174 open | 21 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `claude/ws-i-20261104` | `b03a77b8` | #173 merged | 7 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `claude/ws-p-20261104` | `597a8b10` | #176 open | 23 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `codex/advisory-read-bounds-20261118` | `a4061979` | #313 open | 0 | ancestor-of-candidate | No focal-scope receipt claimed. |
| `codex/agent-skills-spec56-20261014` | `4467d1f3` | #61 open | 1 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `codex/analyst-accessibility-20261109` | `b90a2cd4` | — | 5 | historical-scope-checked-residue-open | Export keyboard/focus behavior and Files-pane announcements and accessibility controls. |
| `codex/audit-1` | `c2070cf8` | — | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `codex/audit-2` | `08b12f1b` | #56 merged | 3 | historical-scope-checked-residue-open | Historical workflow/packaging audit and remaining explicit gaps |
| `codex/autonomous-checkpoint-20261102-0945` | `d038ddea` | — | 33 | historical-scope-checked-residue-open | Project-safe export/adoption, owner-thread KB panel loading, frozen KB journey, creation staging, and bounded callgraph exploration in the broad checkpoint. |
| `codex/autonomous-checkpoint-20261102-1020` | `c13d3257` | — | 34 | historical-scope-checked-residue-open | The previous checkpoint plus bounded, identity-aware incomplete-creation retry and its desktop adapter. |
| `codex/autonomous-reconcile-20261101` | `0130bf81` | #152 closed | 36 | historical-scope-checked-residue-open | Saved KB advisory scope and selected-document context identity |
| `codex/codespaces-cs1-20261109` | `a5f049cd` | #279 open | 8 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `codex/consolidate-backup-stability-20261102` | `f1a55c4c` | #162 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `codex/consolidate-prereg-prefix-20261102` | `9b9452b4` | #161 merged | 3 | historical-scope-checked-residue-open | Visible complete protocol row and bounded fence-prefix parsing |
| `codex/consolidate-replay-schema-20261102` | `ca411e77` | #160 merged | 6 | historical-scope-checked-residue-open | Report-bound normalized output replay and bounded metadata |
| `codex/consolidated-reviewed-20261102` | `6e82fd70` | #163 closed | 45 | historical-scope-checked-residue-open | Checkpoint replay/protocol composition and preserved ancestry |
| `codex/consolidation-audit-20261104` | `fbd95953` | #187 open | 2 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `codex/consolidation-cve-reviewed-20261118` | `d8c02cae` | #304 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `codex/consolidation-evidence-20261102` | `44c320e3` | — | 46 | historical-scope-checked-residue-open | Checkpoint replay/protocol composition and preserved ancestry |
| `codex/consolidation-integrity-20261103` | `b58bb53d` | #164 open | 46 | historical-scope-checked-residue-open | Rule/build integrity and explicit native quarantine obligations |
| `codex/consolidation-reviewed-20261118` | `121ffb0b` | #302 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `codex/coordinator-rule-repairs-20261031` | `798e11ef` | #146 merged | 5 | historical-scope-checked-residue-open | The nonmerge coordinator tip underlying the merged rule-repair branch. |
| `codex/corpus-integrity-20261116` | `6a5b6f26` | #299 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `codex/corpus-output-main-20261101` | `874e9a26` | #157 closed | 6 | historical-scope-checked-residue-open | Merged normalized-output and replay-schema lineage |
| `codex/deep-review-consolidation-20261030` | `95e09548` | #124 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `codex/essential-combined-verification-20261030` | `a7f13e13` | #143 open | 18 | historical-scope-checked-residue-open | Honest native-harness completion and failure semantics |
| `codex/essential-integration-20261029` | `5ed624e9` | #110 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `codex/essential-project-safety-20261031` | `c3868d83` | #148 closed | 1 | historical-scope-checked-residue-open | PR #148 project-safe legacy export, explicit offline KB investigation/pair preview, and transactional GUI adoption. |
| `codex/fix-pr110-ci-gates-20261029` | `c0d1c38a` | #114 closed | 9 | historical-scope-checked-residue-open | Winbindex per-entry Unicode isolation, local-symbol consent ceilings and Diaphora help linkage. |
| `codex/gt01-extraction-recovery-20261030` | `d76d2337` | #141 open | 15 | historical-scope-checked-residue-open | Per-pair extraction roots and actionable bounded backend failure detail |
| `codex/gui-bounded-ambiguous-candidates-20261029` | `3287cb3d` | #111 merged | 2 | historical-scope-checked-residue-open | PR #111 bounded memory when an ambiguous anchor returns many navigation candidates. |
| `codex/identity-main-repair-20261101` | `4eebea4a` | #156 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `codex/java-version-retry-20261015` | `8ee61c62` | #76 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `codex/kb-explicit-filename-selection-20261104` | `761b6b88` | #190 closed | 0 | patch-equivalent-scope-review-open | PR #190 an explicit analyst filename surviving a conflicting advisory-title mention and candidate cap. |
| `codex/kb-fixture-contract-repairs-20261030` | `a4d1e6a3` | #142 closed | 13 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `codex/manifest-dtd-reviewed-20261118` | `23fbe4a5` | #315 open | 0 | ancestor-of-candidate | No focal-scope receipt claimed. |
| `codex/manual-correction-completeness-20261104` | `65f979a1` | #188 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `codex/master-foundation-scope-20261118-4a7` | `88b0b522` | #317 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `codex/msrc-mixed-format-revision-20261102` | `e1b79e04` | #158 closed | 3 | historical-scope-checked-residue-open | PR #158 native/synthetic ambiguous MSRC revision conflict handling. |
| `codex/msrc-reconcile-integration-20261102` | `56374f86` | #159 closed | 36 | historical-scope-checked-residue-open | PR #159 card field provenance and saved investigation scope, plus inherited broad checkpoint source. |
| `codex/parser-test-cpu-budget-20261104` | `cb204f76` | #189 closed | 0 | patch-equivalent-scope-review-open | CPU work budget distinct from wall-clock parser scheduling |
| `codex/patchtrace-beta` | `c7937246` | #1 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `codex/patchtrace-stabilization-20261119` | `c4ace208` | #318 open | 0 | ancestor-of-candidate | No focal-scope receipt claimed. |
| `codex/pilot-current-evidence-reviewed-20261118` | `b41d6631` | #314 open | 0 | ancestor-of-candidate | No focal-scope receipt claimed. |
| `codex/post-consolidation-20261116` | `2d330075` | #298 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `codex/pr110-ci-repairs-20261029` | `bb42828d` | #115 closed | 7 | historical-scope-checked-residue-open | An alternate PR110 Unicode/symbol-policy repair branch. |
| `codex/pr110-kb-arch-scope-20261029` | `40e02daf` | #122 closed | 6 | historical-scope-checked-residue-open | PR #122 reject incompatible product architectures before Winbindex pair resolution, including inherited integration fixes. |
| `codex/pr110-persistence-feedback-20261029` | `3e9cedb0` | #119 closed | 7 | historical-scope-checked-residue-open | PR #119 failed save/bookmark/review/note operations must preserve analyst drafts and avoid false success. |
| `codex/pr110-qa-wbjson-diaphora-help-20261029` | `aba4c200` | #112 closed | 6 | historical-scope-checked-residue-open | The narrow strict-JSON/per-entry Unicode and Diaphora help variant. |
| `codex/pr111-bounded-nav-into-integration-20261029` | `025300f8` | #117 closed | 6 | historical-scope-checked-residue-open | PR #117 the bounded ambiguous-navigation repair carried onto its integration parent. |
| `codex/primary-environment-20261118` | `09b032f2` | #311 open | 0 | ancestor-of-candidate | No focal-scope receipt claimed. |
| `codex/project-safe-export-20261101` | `e9025442` | #149 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `codex/pw01-kb-inventory-20261118` | `2b697222` | #303 open | 0 | ancestor-of-candidate | No focal-scope receipt claimed. |
| `codex/pw01-retained-source-pages-20261118` | `58fc1306` | #307 open | 0 | ancestor-of-candidate | No focal-scope receipt claimed. |
| `codex/r1-ground-truth-research-20261030` | `10856edf` | #128 closed | 8 | historical-scope-checked-residue-open | Build/session truth provenance retained; multi-profile research runners absent |
| `codex/r1-receipt-publication-20261031` | `8c9eafc7` | #145 merged | 8 | historical-scope-checked-residue-open | Retain completed research-build matrix on receipt write failure |
| `codex/r2-unified-matching-research-20261030` | `b3ceb8b3` | #131 closed | 4 | historical-scope-checked-residue-open | Lost B+B witness atoms and manual group Decision attribution |
| `codex/raw-alignment-reviewed-20261118` | `3c9d3f07` | #309 open | 0 | ancestor-of-candidate | No focal-scope receipt claimed. |
| `codex/real-msrc-adapter-20261101` | `d99cd771` | #153 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `codex/receipt-parent-race-20261101` | `2fdac2ea` | #150 open | 9 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `codex/release-integration-20261116` | `95db052a` | #297 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `codex/release-qualification-reviewed-20261118` | `573829f3` | #312 open | 0 | ancestor-of-candidate | No focal-scope receipt claimed. |
| `codex/repair-openai-agent-20261104` | `f0196066` | #186 closed | 2 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `codex/rzdiff-164-investigation` | `20ef68ea` | — | 47 | historical-scope-checked-residue-open | Rule/build integrity and explicit native quarantine obligations |
| `codex/saved-search-reviewed-20261118` | `26558cd0` | #310 open | 0 | ancestor-of-candidate | No focal-scope receipt claimed. |
| `codex/semantic-proof-reconciliation-20261031` | `745e9342` | #144 open | 26 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `codex/storage-integrity-20261101` | `9911af4d` | #151 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `codex/strings-export-publication-20261118` | `92a411bf` | #308 open | 0 | ancestor-of-candidate | No focal-scope receipt claimed. |
| `codex/t9-qa-20261020` | `ecc4f205` | #97 merged | 4 | historical-scope-checked-residue-open | Extern linkage definitions and mutation usage validation |
| `codex/tier-w-fetch-20261015` | `5b7b2591` | — | 6 | historical-scope-checked-residue-open | Bounded exact-consent fetch library retained; saved plan/CLI orchestration absent |
| `codex/training-prereg-identity-20261101` | `dfe8f421` | #154 closed | 3 | historical-scope-checked-residue-open | Merged protocol identity guard |
| `codex/verified-followup-integration-20261118` | `f2b6827f` | #316 open | 0 | ancestor-of-candidate | No focal-scope receipt claimed. |
| `codex/windows-branding-reconcile-20261030` | `8f4c4a2e` | #147 closed | 4 | historical-scope-checked-residue-open | Exact executable/icon identity and exclusive resource staging |
| `codex/windows-setup-installer-20261017` | `9c5fe67b` | #95 merged | 31 | historical-scope-checked-residue-open | Per-user Windows setup, safe uninstall manifest and portable alias |
| `consolidate/docs-20261104` | `ed70e6dd` | #183 closed | 13 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `consolidate/kb-fixtures-20261104` | `820d7074` | #182 closed | 0 | patch-equivalent-scope-review-open | Corrected KB fixture imports and byte-preserving attributes |
| `consolidate/research-r7-20261104` | `552c2945` | #282 open | 2 | historical-scope-checked-residue-open | Bounded offline slicing and guard-to-sink candidate motifs |
| `consolidate/rules-callgraph-20261104` | `7b3fcbac` | #181 closed | 0 | patch-equivalent-scope-review-open | The staged rule/callgraph repair consolidation and platform-test compatibility support. |
| `consolidate/test-stability-20261104` | `64e8374d` | #184 closed | 0 | patch-equivalent-scope-review-open | Private test roots and deterministic asynchronous completion |
| `consolidation/desktop-keyboard-accessibility-20261116` | `45997cfc` | #300 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `consolidation/patchtrace-reviewed-20261119` | `a56ab13a` | #319 open | 0 | ancestor-of-candidate | No focal-scope receipt claimed. |
| `docs/claude-autonomous-alpha-handoff-20261013` | `1038d3f1` | #20 merged | 2 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `docs/codespaces-plan-20261107` | `c3536288` | #273 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `docs/csaf-patch-intelligence-specs` | `24244831` | #17 merged | 5 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `docs/diaphora-optional-engine-20261014` | `b75ac57d` | #37 merged | 3 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `docs/dockable-workspace-spec-20261030` | `6a1e3ce3` | #127 closed | 1 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `docs/findings-20261107` | `9d72402c` | #262 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `docs/handoff-20261107` | `39db34c5` | #270 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `docs/kbc-live-probe-result-20261107` | `c21d0ab8` | #258 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `docs/nway-matches` | `f748cc48` | — | 1 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `docs/post-consolidation-gap-analysis-20261030` | `61b5c2ba` | #137 open | 20 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `docs/r8-reconciliation-20261106` | `5e1e1982` | #249 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `docs/ranking-reuse-20261105` | `bc52940f` | #232 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `docs/readme-and-wiki` | `ad8fbe9f` | #98 open | 1 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `docs/refresh-accuracy-handoff-20261109` | `2e408e3c` | #278 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `docs/research-reconciliation-20261105` | `febc9de5` | #231 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `docs/research-tools-execution-plan-20261106` | `40da8176` | — | 2 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `docs/semantic-ghidra-roadmap` | `8b9ebc01` | #14 merged | 0 | patch-equivalent-scope-review-open | No focal-scope receipt claimed. |
| `docs/sonar235-package-path-20261105` | `c30f11fb` | #241 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `docs/spec-31-kb-cve-correlation-20261014` | `9088bf0e` | #40 closed | 12 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `docs/spec-32-kb-patch-search-20261014` | `d0ceb56f` | #41 closed | 17 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `docs/specs-plan` | `a5194581` | — | 5 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `docs/workbench-search-graph-floss-20261014` | `af15701d` | #43 closed | 6 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `feat/acquisition` | `293362a2` | — | 11 | historical-scope-checked-residue-open | Original acquisition contracts, transport, quarantine, Winbindex resolution, delta integration and CLI. |
| `feat/acquisition-gui` | `7ae34d8f` | — | 1 | historical-scope-checked-residue-open | Desktop acquisition dialog, explicit pair selection, background acquisition and owner-thread adoption. |
| `feat/alpha-ui-integration` | `c7ed1d90` | #25 merged | 2 | historical-scope-checked-residue-open | Verified PE overview and Hex/Binary/Base64 desktop wiring |
| `feat/artifact-bytes-seam` | `91b35d09` | #21 merged | 0 | patch-equivalent-scope-review-open | Shared verified, bounded artifact reader |
| `feat/byte-representations` | `303bc452` | #23 merged | 0 | patch-equivalent-scope-review-open | Pure byte scopes, exact encodings, bounded pages and offset comparison |
| `feat/diffscore-workflow-20261107` | `a3aa5374` | #272 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `feat/enrichment-cache` | `0368fd9b` | — | 2 | historical-scope-checked-residue-open | Directional derived/raw cache, lease and crash recovery, plus common ranking/identity prerequisites. |
| `feat/enrichment-contracts` | `010d809d` | #10 merged | 23 | historical-scope-checked-residue-open | The phase-2 enrichment integration and review fixes, rather than its temporary CI diagnosis branches. |
| `feat/enrichment-cve` | `49bf2455` | — | 2 | historical-scope-checked-residue-open | B3 CVE normalization, contextual reranking, exact consented MSRC/NVD request planning and provider transport. |
| `feat/enrichment-signals` | `e96441a1` | — | 3 | historical-scope-checked-residue-open | B1 lexical change signals and shared edit-group identity. |
| `feat/enrichment-wil` | `9a6999a0` | — | 2 | historical-scope-checked-residue-open | WIL feature-site identification and bounded transition classification. |
| `feat/local-runtime-discovery` | `b9198705` | #5 merged | 9 | historical-scope-checked-residue-open | Bounded read-only installed-runtime discovery and non-destructive Setup prefill |
| `feat/nway` | `44d43178` | — | 23 | historical-scope-checked-residue-open | N-way chain extraction from verified adjacent pair projects and untouched-function raw address matches. |
| `feat/pe-overview` | `4b78a6d3` | #22 merged | 0 | patch-equivalent-scope-review-open | The original bounded PE overview, mapping, comparison and optional Authenticode probe. |
| `feat/phase2-finish` | `86afe3f6` | #12 merged | 22 | historical-scope-checked-residue-open | Profile-selected cache/symbol behavior and the historical native Windows cache acceptance workflow. |
| `feat/phase3-batch` | `3581b520` | #13 merged | 31 | historical-scope-checked-residue-open | PR #13 N-way series and unchanged-hop raw-address matches, acquisition GUI, and secondary engine import/reconciliation. |
| `feat/profiles` | `d21b5917` | — | 19 | historical-scope-checked-residue-open | Persistent named enrichment profiles, validation/digest and desktop selection; inherited acquisition/audit foundation. |
| `feat/raw-cache` | `28bc4767` | — | 19 | historical-scope-checked-residue-open | Ghidriff raw-output cache keyed by input/runtime identity, cache hit/miss/no-cache/refresh behavior. |
| `feat/rq-engine-adapters-20261107` | `b561ed60` | #265 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `feat/rq-parity-20261107` | `f8806bb7` | #263 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `feat/secondary` | `b932ae1a` | — | 1 | historical-scope-checked-residue-open | BinDiff import, BinExport validation, optional rz-diff execution interfaces and conservative reconciliation. |
| `feat/tooltip-registry` | `0a3843ea` | #24 merged | 0 | patch-equivalent-scope-review-open | Semantic static/dynamic tooltip registry and actual widget application |
| `feat/verified-offline-runtime-bundle` | `1724503d` | #7 merged | 29 | historical-scope-checked-residue-open | Strict offline runtime archive validation and explicit installation |
| `feat/winpairs-workflow-20261107` | `2e43d3f4` | #271 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `feature/alpha-file-overview-20261013` | `47601659` | #19 merged | 4 | historical-scope-checked-residue-open | Backend-independent recorded artifact overview |
| `feature/current-project-investigation-20261105` | `ef70e0bd` | #214 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `feature/evidence-reconciliation-confidence` | `ddda35f4` | #16 merged | 6 | historical-scope-checked-residue-open | Conservative per-match cross-engine evidence adjudication and CLI presentation. |
| `feature/gui-inspection-preview` | `8b94227a` | #15 merged | 5 | historical-scope-checked-residue-open | Cross-function previous/next hunk navigation and source explanations |
| `fix/backend-exit-diagnostics` | `bc00a691` | #6 merged | 6 | historical-scope-checked-residue-open | Fixed-text actionable Ghidriff failure classification |
| `fix/codetext-budget-wave3` | `c7fb422c` | — | 6 | historical-scope-checked-residue-open | Avoid per-row span dispatch outside the visible code window during bulk load |
| `fix/codex-cloud-secret-preflight-20261103` | `bd3dbcae` | #169 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `fix/explicit-offline-symbol-policy` | `2e661876` | #4 merged | 12 | historical-scope-checked-residue-open | Default-off symbol downloads and explicit analyst policy |
| `fix/ghidra-dot-paths` | `5c3b1df9` | #2 merged | 6 | historical-scope-checked-residue-open | Ghidra output-path refusal and visible quarantine paths |
| `fix/ghidriff-timeout-progress-20261106` | `7e5d9819` | #251 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `fix/isolate-ghidra-scratch` | `7ea72723` | #3 merged | 8 | historical-scope-checked-residue-open | Private native engine work directories outside the case |
| `fix/pe-inspection-row-tooltips-20261013` | `0182a803` | #26 merged | 6 | historical-scope-checked-residue-open | Source-safe PE/trust/unavailable row explanations |
| `fix/pr110-ci-regressions-20261029` | `979ddfad` | #113 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `fix/pr205-partial-pe-inspect-20261106` | `cce47934` | #253 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `fix/pr205-review-contracts-20261106` | `4f3e62c4` | #252 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `fix/pr205-ui-seam-help-extraction-20261106` | `a53c7d1b` | #254 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `fix/remediation-53088704-982db3` | `15370a0b` | #155 closed | 2 | historical-scope-checked-residue-open | Earlier visible-row and inline-code preregistration repair |
| `fix/remediation-a58defa8-139db0` | `6d9c06c2` | #261 closed | 1 | historical-scope-checked-residue-open | Score against bounded accepted function alternatives |
| `fix/remediation-b1ab7332-a8fac4` | `3feec96f` | #267 closed | 2 | historical-scope-checked-residue-open | Research adapters now require strict code and native identity |
| `fix/windows-posix-mingw-workflow-20261115` | `3b3ad32f` | #296 merged | 0 | patch-equivalent-scope-review-open | POSIX path semantics in the Linux MinGW workflow assertion |
| `haiku/cli-help-suppress-20261027` | `37940b70` | — | 1 | historical-scope-checked-residue-open | Keep internal worker parseable without help-list leakage |
| `haiku/phase2-handoff-import-20261027` | `4522030f` | — | 1 | historical-scope-checked-residue-open | Unretained provenance-pinned Phase 2 reference schema package |
| `haiku/skills-manifest-import-20261027` | `039b0ef8` | — | 1 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `integrate/autonomous-20261105` | `3d6c37e6` | #194 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `integrate/calibration-prereg-20261105` | `57f95e09` | #215 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `integrate/calibration-replay-20261105` | `f8ed2356` | #217 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `integrate/continuation-20261106` | `37b77130` | #247 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `integrate/gui-inspection-20261105` | `3fa22c61` | #196 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `integrate/independent-wave4-20261105` | `6e9f4524` | #235 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `integrate/kb-20261105` | `75c01a29` | #193 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `integrate/kb-investigation-20261105` | `bdbfd7dc` | #201 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `integrate/merge-readiness-20261106` | `f393bb68` | #244 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `integrate/native-controls-20261105` | `a0f41746` | #195 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `integrate/project-adoption-20261105` | `1c97defa` | #198 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `integrate/recovery-forward-wave3-20261106` | `a1ed8c91` | #248 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `integrate/rules-20261105` | `c849d008` | #191 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `integrate/secondary-prep-20261105` | `b6b5bf6c` | #197 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `integrate/swarm-followups-20261105` | `c6691ab1` | #213 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `integrate/swarm-qualified-20261105` | `4e9f1d5d` | #205 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `integrate/swarm-wave3-20261105` | `a0e2c80e` | #218 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `integration/controlled-consolidation-20261030` | `f18687fd` | — | 11 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `integration/kb-fixtures-pr69-20261030` | `2fcd627e` | #136 closed | 12 | historical-scope-checked-residue-open | Original KB corpus plus historical PR/wiki checkpoint |
| `main` | `fdc2696c` | — | 0 | main-baseline | No focal-scope receipt claimed. |
| `qualify/native-cli-seeding-20261105` | `8fae317b` | #224 open | 5 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `qualify/native-controls-20261105` | `dc3bf773` | #208 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `qualify/native-provision-20261105` | `c50ab287` | #222 open | 4 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `qualify/offline-tooling-20261105` | `c3370578` | #209 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `repair/gt01-consolidated-native-evidence-20261030` | `c04ad725` | #139 open | 12 | historical-scope-checked-residue-open | Persist completed raw runs before unified analysis and retain failure detail |
| `repair/gt01-native-identical-controls-20261030` | `fb91cff6` | #140 open | 14 | historical-scope-checked-residue-open | Explicit native identical-image controls without weakening ordinary shortcut |
| `repair/gt01-unified-live-gates-20261030` | `ca1a36c0` | #138 closed | 15 | historical-scope-checked-residue-open | Live gate apply-before-unified ordering and Linux Qt dependency |
| `repair/kb-ui-import-boundary-20261105` | `226ac7e5` | — | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `repair/native-input-open-20261105` | `0526d546` | #206 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `repair/native-normalizer-wave3-20261105` | `cf9cefff` | #220 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `repair/native-source-identity-20261105` | `c3be348b` | #212 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `repair/normalizer-address-identity-20261105` | `631b5e91` | #223 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `repair/parity-parser-budget-20261105` | `c923039b` | #211 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `repair/pr205-main-reconciliation-20261106` | `96e8e085` | #250 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `repair/pr205-qualification-20261106` | `4465a049` | #245 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `repair/project-create-rollback-20261105` | `2a3639ad` | #210 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `repair/rzdiff-native-callback-size-20261103` | `edab7d91` | #166 closed | 48 | historical-scope-checked-residue-open | Rizin native callback uses the API size_t signature |
| `repair/rzdiff-native-red-control-20261103` | `b304034e` | #168 open | 49 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `repair/rzdiff-producer-ownership` | `4d66af55` | #165 open | 48 | historical-scope-checked-residue-open | Pinned singleton producer ownership correction and bounded harness |
| `repair/streamed-series-recovery-20261105` | `20a60f9d` | #207 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `repair/subprocess-venv-20261106` | `c804e4d9` | #246 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `repair/unified-ci-20261105` | `b5f6e138` | #192 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `repair/unified-support-evidence-20261105` | `95749419` | #203 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `repair/verified-bytes-20261105` | `e5f9302e` | #199 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `repair/winbindex-metadata-budget-20261105` | `64eb58ec` | #237 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `repair/wizard-lock-retry-20261105` | `38be184c` | #219 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `repair/workflow-fragment-20261105` | `1229ca3b` | #204 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `research/additional-reuse-claude-20261103` | `be4a58ff` | #178 closed | 1 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `research/kbc-live-probe-20261106` | `3839f3b6` | #257 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `research/l1-join-corpus-20261107` | `ca3572e7` | #269 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `research/qualification-tools-rq00-rq01-20261106` | `941c0da4` | #256 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `research/r4-vulnerability-correlation-20261030` | `ff570bdd` | #130 open | 12 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `research/r6-final-integration-engineering-notes-20261030` | `3010f289` | #133 open | 12 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `research/r7-advanced-binary-analysis-20261030` | `c9d1aab6` | #134 open | 29 | unreviewed-semantic-residue | No focal-scope receipt claimed. |
| `research/r8-deep-uncertainty-20261030` | `12dd4f2b` | #135 open | 16 | historical-scope-checked-residue-open | Type-sensitive C literals and opaque numeral collision resistance |
| `research/windows-candidates-gaps-20261107` | `1f11a43b` | #274 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `research/windows-candidates-github-20261107` | `35d7e3c9` | #266 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `research/windows-candidates-sources-20261107` | `74096182` | #264 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `research/windows-pair-candidates-20261107` | `e5e783f6` | #260 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `research/windows-pins-20261107` | `ac826a2e` | #277 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `resume/desktop-index-refresh-20261106` | `c9cea067` | #243 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `resume/kb-acquire-lifecycle-20261106` | `b8bda984` | #242 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `security/offline-bundle-no-overwrite-20261013` | `a39cab81` | #18 merged | 2 | historical-scope-checked-residue-open | No-overwrite publication of the produced archive file |
| `test/advisory-acceptance-20261105` | `69c705d0` | #233 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `test/product-acceptance-20261106` | `81825ee9` | — | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `test/recovery-diagnostics-20261106` | `064f1c00` | — | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `work/calibration-invariants-20261105` | `a6948be8` | #230 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `work/candidate-correlation-20261105` | `fee7c366` | #229 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `work/consented-winbindex-refresh-20261105` | `83320a32` | #239 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `work/investigation-accessibility-20261105` | `b5d4bcea` | #226 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `work/investigation-candidates-20261105` | `bf366196` | #240 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `work/online-adapter-20261105` | `e14b4445` | #225 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `work/online-investigation-20261105` | `bf46954e` | #234 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `work/pe-parser-security-20261105` | `8975c517` | #236 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `work/persistence-security-20261105` | `1a1e1951` | #227 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `work/product-start-20261106` | `0b7d8581` | — | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `work/product-start-wave3` | `7e7a52eb` | #221 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `work/winbindex-publication-20261105` | `2afe874d` | #238 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `work/windows-package-preflight-20261105` | `93b4b9a8` | #228 closed | 0 | ancestor-of-main | No focal-scope receipt claimed. |
| `worker/patchtrace-cli-help-20261104` | `81a9fb28` | #185 merged | 0 | ancestor-of-main | No focal-scope receipt claimed. |

## Open and closed-unmerged pull requests

Merged PR metadata is preserved in the complete machine list. Every active or closed-unmerged PR is listed here.

| PR | State | Recorded head | Head SHA | Title |
|---|---|---|---|---|
| [#40](https://github.com/djshellshoxxx/patchtrace/pull/40) | closed | `docs/spec-31-kb-cve-correlation-20261014` | `9088bf0e` | docs: SPEC-31 KB/CVE correlation and verified binary acquisition |
| [#41](https://github.com/djshellshoxxx/patchtrace/pull/41) | closed | `docs/spec-32-kb-patch-search-20261014` | `d0ceb56f` | docs: expand SPEC-32 KB patch search into implementation-ready architecture and QA contracts |
| [#43](https://github.com/djshellshoxxx/patchtrace/pull/43) | closed | `docs/workbench-search-graph-floss-20261014` | `af15701d` | docs: developer-ready search, call graph and FLOSS workbench integrations |
| [#60](https://github.com/djshellshoxxx/patchtrace/pull/60) | closed | `claude/instance-c-research` | `785998a0` | Bundle: validate full payloads before attaching (CODEX-13) and enforce an explicit GPL-family licence policy (CODEX-15) |
| [#61](https://github.com/djshellshoxxx/patchtrace/pull/61) | open | `codex/agent-skills-spec56-20261014` | `4467d1f3` | Add Caveman and PatchTrace agent skills with spec-first workflow (SPEC-56) |
| [#67](https://github.com/djshellshoxxx/patchtrace/pull/67) | closed | `chatgpt/deferred-audit-fixes-1` | `2174837f` | Deferred audit fixes: Ghidriff integrity, isolated launches and consent |
| [#68](https://github.com/djshellshoxxx/patchtrace/pull/68) | open | `chatgpt/corpus-1` | `b7a0f0a4` | Corpus batch 1: 24 candidate recipes and continuation plan |
| [#69](https://github.com/djshellshoxxx/patchtrace/pull/69) | closed | `chatgpt/kb-fixtures-1` | `781b36fb` | Add synthetic KB patch-search fixtures and QA |
| [#70](https://github.com/djshellshoxxx/patchtrace/pull/70) | open | `chatgpt/help-docs-1` | `e5bee6fe` | docs: add first 25 Prompt 5 help topics |
| [#71](https://github.com/djshellshoxxx/patchtrace/pull/71) | closed | `chatgpt/unified-fixtures-1` | `161a8834` | Draft: unified synthetic fixtures and gate evaluator tests (partial, unverified) |
| [#72](https://github.com/djshellshoxxx/patchtrace/pull/72) | open | `chatgpt/panels-1` | `cfd7cfff` | docs: specify Program E panels and coordinated build plan |
| [#78](https://github.com/djshellshoxxx/patchtrace/pull/78) | open | `chatgpt/lbl31-output-persistence-20261015` | `2019a37f` | LBL-31: persist Tier R engine outputs and transfer verified training artifacts |
| [#79](https://github.com/djshellshoxxx/patchtrace/pull/79) | open | `chatgpt/lbl32-card-controls-20261016` | `9513bc05` | LBL-32: run pinned recipe-card A/A and noise controls on both sides |
| [#80](https://github.com/djshellshoxxx/patchtrace/pull/80) | closed | `chatgpt/java-probe-qa-fix-20261016` | `89500e12` | test: unblock Java probe QA and cover bounded retry failures |
| [#81](https://github.com/djshellshoxxx/patchtrace/pull/81) | closed | `chatgpt/java-probe-ci-fix-20261016` | `0254841e` | Fix Java version retry and import-order CI failure |
| [#82](https://github.com/djshellshoxxx/patchtrace/pull/82) | open | `chatgpt/lbl32-recipe-aa-noise-20261016` | `eaa30013` | LBL-32: two-sided recipe A/A and noise cases in Tier R planner |
| [#83](https://github.com/djshellshoxxx/patchtrace/pull/83) | closed | `chatgpt/ue-r7-p15-unresolved-20261016-a` | `292dc395` | UE-R7: prevent P15 exact matching through unknown callees |
| [#84](https://github.com/djshellshoxxx/patchtrace/pull/84) | closed | `chatgpt/java-probe-boundaries-20261016` | `09bb4519` | test: extend Java probe retry and cancellation coverage |
| [#85](https://github.com/djshellshoxxx/patchtrace/pull/85) | open | `chatgpt/lbl30-prereg-guard-20261016` | `6ae2c079` | LBL-30: verify preregistration and enforce single-use final training |
| [#86](https://github.com/djshellshoxxx/patchtrace/pull/86) | open | `chatgpt/ue-r3-retain-decompiled-20261016` | `ebbd621d` | UE-R3: persist bounded on-demand Ghidra C into unified result sidecars |
| [#88](https://github.com/djshellshoxxx/patchtrace/pull/88) | closed | `chatgpt/ue-r7-strict-worker-report-20261016-a` | `9c5f9a42` | UE-R7: fail closed on malformed and ambiguous worker reports |
| [#89](https://github.com/djshellshoxxx/patchtrace/pull/89) | closed | `chatgpt/nway-external-note-qa-20261016` | `8c728827` | test: verify N-way EXTERNAL skip notes survive persistence |
| [#90](https://github.com/djshellshoxxx/patchtrace/pull/90) | closed | `chatgpt/unified-fixture-collection-fix-20261016` | `941c617b` | test: replace two defective unified fixture originals |
| [#91](https://github.com/djshellshoxxx/patchtrace/pull/91) | closed | `chatgpt/lbl31-coff-symbol-mask-20261016` | `9622704d` | LBL-31 Windows COFF masked-body correction (fix failing acceptance gate) |
| [#92](https://github.com/djshellshoxxx/patchtrace/pull/92) | closed | `chatgpt/lbl31-coff-quoted-rip-20261016` | `6e71bfab` | LBL-31: mask quoted Windows COFF RIP relocation symbols |
| [#93](https://github.com/djshellshoxxx/patchtrace/pull/93) | closed | `chatgpt/lbl31-windows-qa-fixes-20261016-a` | `ddb2ff07` | Superseded: LBL-31 Windows QA fixes (implemented directly in PR #78) |
| [#94](https://github.com/djshellshoxxx/patchtrace/pull/94) | closed | `chatgpt/unified-sort-perf-qa-20261016` | `27b0a48b` | QA: make Unified 100k-row sort budget resilient to runner descheduling |
| [#98](https://github.com/djshellshoxxx/patchtrace/pull/98) | open | `docs/readme-and-wiki` | `ad8fbe9f` | Add wiki pages and link them from README |
| [#100](https://github.com/djshellshoxxx/patchtrace/pull/100) | closed | `claude/patchtrace-features` | `66e9adc5` | SPEC-53 local symbol mode + launcher; SPEC-DA-01 Diaphora Mode A import |
| [#102](https://github.com/djshellshoxxx/patchtrace/pull/102) | closed | `claude/patchtrace-haiku-agent-motpbx` | `9fddf99e` | Windows alpha: exe version resource and icon, CI split, release integrity and parser hardening, SPEC-26 A tooltips |
| [#112](https://github.com/djshellshoxxx/patchtrace/pull/112) | closed | `codex/pr110-qa-wbjson-diaphora-help-20261029` | `aba4c200` | fix: unblock Winbindex hostile-entry and Diaphora help QA |
| [#113](https://github.com/djshellshoxxx/patchtrace/pull/113) | closed | `fix/pr110-ci-regressions-20261029` | `979ddfad` | fix: address PR #110 Linux/Windows QA regressions |
| [#114](https://github.com/djshellshoxxx/patchtrace/pull/114) | closed | `codex/fix-pr110-ci-gates-20261029` | `c0d1c38a` | fix: unblock PR #110 Linux/Windows QA failures |
| [#115](https://github.com/djshellshoxxx/patchtrace/pull/115) | closed | `codex/pr110-ci-repairs-20261029` | `bb42828d` | fix(ci): repair Winbindex Unicode, GUI seam, docs and symbol-consent regression |
| [#117](https://github.com/djshellshoxxx/patchtrace/pull/117) | closed | `codex/pr111-bounded-nav-into-integration-20261029` | `025300f8` | fix(gui): integrate bounded ambiguous navigation onto essential integration |
| [#119](https://github.com/djshellshoxxx/patchtrace/pull/119) | closed | `codex/pr110-persistence-feedback-20261029` | `3e9cedb0` | fix(gui): never discard notes or claim successful saves after persistence failure |
| [#122](https://github.com/djshellshoxxx/patchtrace/pull/122) | closed | `codex/pr110-kb-arch-scope-20261029` | `40e02daf` | fix(kb): block incompatible product architectures in Winbindex pair resolution |
| [#123](https://github.com/djshellshoxxx/patchtrace/pull/123) | closed | `claude/jolly-fermi-eghaxy` | `99f8328c` | fix(ci): consolidated PR #110 repair stack (#113 + #117/#119/#122 fixes) |
| [#125](https://github.com/djshellshoxxx/patchtrace/pull/125) | open | `claude/compassionate-goldberg-5uuqks` | `198eb21e` | docs: next-milestone dev prompt for integrated essential alpha |
| [#126](https://github.com/djshellshoxxx/patchtrace/pull/126) | closed | `claude/modest-hamilton-kz2gta` | `280bf058` | docs: integrated essential alpha milestone ledger and handoff |
| [#127](https://github.com/djshellshoxxx/patchtrace/pull/127) | closed | `docs/dockable-workspace-spec-20261030` | `6a1e3ce3` | Specify modular dockable workspaces and simpler default layouts |
| [#128](https://github.com/djshellshoxxx/patchtrace/pull/128) | closed | `codex/r1-ground-truth-research-20261030` | `10856edf` | R1: validate ground truth, run native pilot, and preserve corpus provenance |
| [#129](https://github.com/djshellshoxxx/patchtrace/pull/129) | open | `chatgpt/semantic-analysis-r3-20261030` | `2698b9a0` | R3 research: semantic-change proofs, compiler noise and guarded PE comparisons |
| [#130](https://github.com/djshellshoxxx/patchtrace/pull/130) | open | `research/r4-vulnerability-correlation-20261030` | `ff570bdd` | R4 research: CVE/KB/product/build/binary provenance and function evidence |
| [#131](https://github.com/djshellshoxxx/patchtrace/pull/131) | closed | `codex/r2-unified-matching-research-20261030` | `b3ceb8b3` | R2: unified matching research, evidence preservation and measured scaling fixes |
| [#132](https://github.com/djshellshoxxx/patchtrace/pull/132) | closed | `chatgpt/r5-calibration-research-20261030` | `4d9d9051` | R5: calibration research, statistical validation audit and developer handoff |
| [#133](https://github.com/djshellshoxxx/patchtrace/pull/133) | open | `research/r6-final-integration-engineering-notes-20261030` | `3010f289` | R6: comprehensive engineer-ready final integration and release acceptance notes |
| [#134](https://github.com/djshellshoxxx/patchtrace/pull/134) | open | `research/r7-advanced-binary-analysis-20261030` | `c9d1aab6` | R7 research: bounded semantic slicing and evidence-grounded security interpretation |
| [#135](https://github.com/djshellshoxxx/patchtrace/pull/135) | open | `research/r8-deep-uncertainty-20261030` | `12dd4f2b` | R8 (draft): adversarial proof and literal-type normalization research |
| [#136](https://github.com/djshellshoxxx/patchtrace/pull/136) | closed | `integration/kb-fixtures-pr69-20261030` | `2fcd627e` | Integration QA candidate: preserve PR #69 synthetic KB fixtures and regressions |
| [#137](https://github.com/djshellshoxxx/patchtrace/pull/137) | open | `docs/post-consolidation-gap-analysis-20261030` | `61b5c2ba` | docs: post-consolidation 20-feature gap audit and parallel development roadmap |
| [#138](https://github.com/djshellshoxxx/patchtrace/pull/138) | closed | `repair/gt01-unified-live-gates-20261030` | `ca1a36c0` | fix(GT-01): commit native runs for unified gates and provision Ubuntu EGL |
| [#139](https://github.com/djshellshoxxx/patchtrace/pull/139) | open | `repair/gt01-consolidated-native-evidence-20261030` | `c04ad725` | fix(GT-01): consolidate R1 native recovery and PR #138 regressions |
| [#140](https://github.com/djshellshoxxx/patchtrace/pull/140) | open | `repair/gt01-native-identical-controls-20261030` | `fb91cff6` | fix(GT-01): run native identical controls and distinguish output rejections |
| [#141](https://github.com/djshellshoxxx/patchtrace/pull/141) | open | `codex/gt01-extraction-recovery-20261030` | `d76d2337` | fix: isolate native extraction failures between comparisons |
| [#142](https://github.com/djshellshoxxx/patchtrace/pull/142) | closed | `codex/kb-fixture-contract-repairs-20261030` | `a4d1e6a3` | test: repair synthetic KB fixture imports and Unicode coverage |
| [#143](https://github.com/djshellshoxxx/patchtrace/pull/143) | open | `codex/essential-combined-verification-20261030` | `a7f13e13` | Draft: combined verification of native recovery and KB fixture repairs |
| [#144](https://github.com/djshellshoxxx/patchtrace/pull/144) | open | `codex/semantic-proof-reconciliation-20261031` | `745e9342` | fix: reconcile matching evidence, semantic uncertainty and typed literals |
| [#147](https://github.com/djshellshoxxx/patchtrace/pull/147) | closed | `codex/windows-branding-reconcile-20261030` | `8f4c4a2e` | Reconcile Windows executable identity and verify generated resources |
| [#148](https://github.com/djshellshoxxx/patchtrace/pull/148) | closed | `codex/essential-project-safety-20261031` | `c3868d83` | Complete project-safe export and offline KB investigation workflow |
| [#150](https://github.com/djshellshoxxx/patchtrace/pull/150) | open | `codex/receipt-parent-race-20261101` | `2fdac2ea` | Anchor research receipts against parent replacement and preserve completed evidence |
| [#152](https://github.com/djshellshoxxx/patchtrace/pull/152) | closed | `codex/autonomous-reconcile-20261101` | `0130bf81` | Reconcile investigation workflow, native candidate and lifecycle evidence |
| [#154](https://github.com/djshellshoxxx/patchtrace/pull/154) | closed | `codex/training-prereg-identity-20261101` | `dfe8f421` | Validate recorded protocol identity before training reads corpus inputs |
| [#155](https://github.com/djshellshoxxx/patchtrace/pull/155) | closed | `fix/remediation-53088704-982db3` | `15370a0b` | Fix: [for cherry-picking] Updated preregistration QA scanning to base r |
| [#157](https://github.com/djshellshoxxx/patchtrace/pull/157) | closed | `codex/corpus-output-main-20261101` | `874e9a26` | Retain normalized evaluation outputs and faithful replay metadata |
| [#158](https://github.com/djshellshoxxx/patchtrace/pull/158) | closed | `codex/msrc-mixed-format-revision-20261102` | `e1b79e04` | fix(kb): dispute mixed-format ambiguous MSRC revisions |
| [#159](https://github.com/djshellshoxxx/patchtrace/pull/159) | closed | `codex/msrc-reconcile-integration-20261102` | `56374f86` | Integrate MSRC card provenance with saved-scope investigation |
| [#163](https://github.com/djshellshoxxx/patchtrace/pull/163) | closed | `codex/consolidated-reviewed-20261102` | `6e82fd70` | Consolidate investigation, replay and protocol branches with reviewed integration repairs |
| [#164](https://github.com/djshellshoxxx/patchtrace/pull/164) | open | `codex/consolidation-integrity-20261103` | `b58bb53d` | Consolidate build provenance and saved-rule integrity repairs |
| [#165](https://github.com/djshellshoxxx/patchtrace/pull/165) | open | `repair/rzdiff-producer-ownership` | `4d66af55` | Repair Rizin singleton result ownership in pinned research producer; retain quarantine |
| [#166](https://github.com/djshellshoxxx/patchtrace/pull/166) | closed | `repair/rzdiff-native-callback-size-20261103` | `edab7d91` | fix(rzdiff): correct native API read callback length type |
| [#167](https://github.com/djshellshoxxx/patchtrace/pull/167) | closed | `automation/patchtrace-api-agent-pilot-20261103` | `def36c82` | ci: introduce bounded OpenAI Responses API cloud pilot |
| [#168](https://github.com/djshellshoxxx/patchtrace/pull/168) | open | `repair/rzdiff-native-red-control-20261103` | `b304034e` | test(rzdiff): require complete stock-native red controls and preserve failure evidence |
| [#170](https://github.com/djshellshoxxx/patchtrace/pull/170) | closed | `automation/api-funded-persistent-codex-20261103` | `6fe6c4b1` | Enable scheduled API-funded PatchTrace cloud development with persistent PRs |
| [#171](https://github.com/djshellshoxxx/patchtrace/pull/171) | closed | `automation/parallel-api-eight-agents-20261103` | `f8050a1f` | ci: eight isolated API-funded PatchTrace agents, four daily batches |
| [#172](https://github.com/djshellshoxxx/patchtrace/pull/172) | open | `claude/serene-heisenberg-2y5kz6` | `7ed5cebf` | docs: autonomous finish prompt (launch record) |
| [#174](https://github.com/djshellshoxxx/patchtrace/pull/174) | open | `claude/ws-bc-20261104` | `e1193c88` | GT-01 live-gate harness repairs and rz-diff producer controls, ported onto main (WS-B/C) |
| [#176](https://github.com/djshellshoxxx/patchtrace/pull/176) | open | `claude/ws-p-20261104` | `597a8b10` | Offline KB investigation, calibration replay identity, GUI tiny wins, audit dispositions (WS-D/F/G/H) |
| [#177](https://github.com/djshellshoxxx/patchtrace/pull/177) | closed | `claude/ws-a2-ci-speed-20261104` | `bef720fd` | ci: parallel QA suite (pytest-xdist) and pip cache (WS-A) |
| [#178](https://github.com/djshellshoxxx/patchtrace/pull/178) | closed | `research/additional-reuse-claude-20261103` | `be4a58ff` | docs: deep additional reuse research and Claude handoff |
| [#179](https://github.com/djshellshoxxx/patchtrace/pull/179) | open | `claude/patchtrace-multi-worker-consolidate-24ct7v` | `ca10acb5` | Consolidate-and-build prompt, branch inventory tool and C0 ledger |
| [#181](https://github.com/djshellshoxxx/patchtrace/pull/181) | closed | `consolidate/rules-callgraph-20261104` | `7b3fcbac` | Consolidate rules/callgraph repairs: RULE-1/3/4/6, cache identity, CG-1/2 (from #126) |
| [#182](https://github.com/djshellshoxxx/patchtrace/pull/182) | closed | `consolidate/kb-fixtures-20261104` | `820d7074` | Consolidate synthetic KB fixture corpus and contract tests (from #69/#136/#142) |
| [#183](https://github.com/djshellshoxxx/patchtrace/pull/183) | closed | `consolidate/docs-20261104` | `ed70e6dd` | Consolidate docs: research R2-R6/R8, panel and dockable specs, gap analysis and wiki (C7) |
| [#184](https://github.com/djshellshoxxx/patchtrace/pull/184) | closed | `consolidate/test-stability-20261104` | `64e8374d` | test: fix four load races in the QA suite (ports from the integration branch) |
| [#186](https://github.com/djshellshoxxx/patchtrace/pull/186) | closed | `codex/repair-openai-agent-20261104` | `f0196066` | Repair manual OpenAI agent workflow and add PatchTrace scope |
| [#187](https://github.com/djshellshoxxx/patchtrace/pull/187) | open | `codex/consolidation-audit-20261104` | `fbd95953` | Audit open PatchTrace consolidation branches and identify integration order |
| [#188](https://github.com/djshellshoxxx/patchtrace/pull/188) | closed | `codex/manual-correction-completeness-20261104` | `65f979a1` | fix(unified): reject manual corrections with unresolved members |
| [#189](https://github.com/djshellshoxxx/patchtrace/pull/189) | closed | `codex/parser-test-cpu-budget-20261104` | `cb204f76` | test: isolate hostile PE work budgets from runner delays |
| [#190](https://github.com/djshellshoxxx/patchtrace/pull/190) | closed | `codex/kb-explicit-filename-selection-20261104` | `761b6b88` | fix(kb): keep analyst filename selections when advisory titles collide |
| [#192](https://github.com/djshellshoxxx/patchtrace/pull/192) | closed | `repair/unified-ci-20261105` | `b5f6e138` | fix: repair unified QA lifecycle and preserve pilot comparison options |
| [#203](https://github.com/djshellshoxxx/patchtrace/pull/203) | closed | `repair/unified-support-evidence-20261105` | `95749419` | test(unified): correct component-support property against accepted spec |
| [#206](https://github.com/djshellshoxxx/patchtrace/pull/206) | closed | `repair/native-input-open-20261105` | `0526d546` | fix(secondary): reject replaced input handles before copying |
| [#207](https://github.com/djshellshoxxx/patchtrace/pull/207) | closed | `repair/streamed-series-recovery-20261105` | `20a60f9d` | Stream corrupt-series recovery with verified copy receipts |
| [#208](https://github.com/djshellshoxxx/patchtrace/pull/208) | closed | `qualify/native-controls-20261105` | `dc3bf773` | docs(qa): retain local native-control provisioning diagnostics |
| [#215](https://github.com/djshellshoxxx/patchtrace/pull/215) | closed | `integrate/calibration-prereg-20261105` | `57f95e09` | Validate recorded protocol identity before calibration input access |
| [#216](https://github.com/djshellshoxxx/patchtrace/pull/216) | closed | `audit/random-invariants-20261105` | `7716e2b0` | Clean acquisition version display labels without losing source identity |
| [#217](https://github.com/djshellshoxxx/patchtrace/pull/217) | closed | `integrate/calibration-replay-20261105` | `f8ed2356` | Bind retained calibration output replay to successful report credit |
| [#219](https://github.com/djshellshoxxx/patchtrace/pull/219) | closed | `repair/wizard-lock-retry-20261105` | `38be184c` | Permit safe wizard retry with retained persistent lock |
| [#222](https://github.com/djshellshoxxx/patchtrace/pull/222) | open | `qualify/native-provision-20261105` | `c50ab287` | test(rzdiff): execute pinned-native API ownership and IO controls |
| [#224](https://github.com/djshellshoxxx/patchtrace/pull/224) | open | `qualify/native-cli-seeding-20261105` | `8fae317b` | docs(native): retain CLI baseline failures and isolated seeding experiment |
| [#225](https://github.com/djshellshoxxx/patchtrace/pull/225) | closed | `work/online-adapter-20261105` | `e14b4445` | Bound monthly CVRF redirects and retries to the operation budget |
| [#226](https://github.com/djshellshoxxx/patchtrace/pull/226) | closed | `work/investigation-accessibility-20261105` | `b5d4bcea` | Restore investigation label shortcuts and keyboard focus order |
| [#227](https://github.com/djshellshoxxx/patchtrace/pull/227) | closed | `work/persistence-security-20261105` | `1a1e1951` | Reject aliased and replaced project lock files before writes |
| [#228](https://github.com/djshellshoxxx/patchtrace/pull/228) | closed | `work/windows-package-preflight-20261105` | `93b4b9a8` | Verify desktop archive identity and prepare clean Windows evidence |
| [#229](https://github.com/djshellshoxxx/patchtrace/pull/229) | closed | `work/candidate-correlation-20261105` | `fee7c366` | Keep candidate component identity and chronology evidence explicit |
| [#230](https://github.com/djshellshoxxx/patchtrace/pull/230) | closed | `work/calibration-invariants-20261105` | `a6948be8` | Preserve score ties and class mass in calibration metrics |
| [#231](https://github.com/djshellshoxxx/patchtrace/pull/231) | closed | `docs/research-reconciliation-20261105` | `febc9de5` | Preserve historical reuse research with source receipts and current dispositions |
| [#232](https://github.com/djshellshoxxx/patchtrace/pull/232) | closed | `docs/ranking-reuse-20261105` | `bc52940f` | Define source-backed ranking and calibration fixture packets |
| [#233](https://github.com/djshellshoxxx/patchtrace/pull/233) | closed | `test/advisory-acceptance-20261105` | `69c705d0` | Verify advisory revision and failed refresh preservation through real stores |
| [#234](https://github.com/djshellshoxxx/patchtrace/pull/234) | closed | `work/online-investigation-20261105` | `bf46954e` | Add explicit consented advisory sync to the investigation desktop |
| [#236](https://github.com/djshellshoxxx/patchtrace/pull/236) | closed | `work/pe-parser-security-20261105` | `8975c517` | Withhold PE manifest facts when resource backing is incomplete |
| [#240](https://github.com/djshellshoxxx/patchtrace/pull/240) | closed | `work/investigation-candidates-20261105` | `bf366196` | Inspect and explicitly preview saved patch candidates with stable provenance |
| [#259](https://github.com/djshellshoxxx/patchtrace/pull/259) | closed | `claude/gallant-knuth-8gxuzd` | `f249edc8` | Unified engine follow-up: fixes from the final audit (GS handler regression, result-key gaps, wall-clock cache rule) |
| [#261](https://github.com/djshellshoxxx/patchtrace/pull/261) | closed | `fix/remediation-a58defa8-139db0` | `6d9c06c2` | Fix: [for cherry-picking] Added an optional expected.accept list to the |
| [#267](https://github.com/djshellshoxxx/patchtrace/pull/267) | closed | `fix/remediation-b1ab7332-a8fac4` | `3feec96f` | Fix: [for cherry-picking] Rizin JSON adapter now extracts names from th |
| [#268](https://github.com/djshellshoxxx/patchtrace/pull/268) | open | `claude/affectionate-galileo-bqd3tw` | `b29351d4` | Narrow #174: fix two RB-01 measurement defects in the unified live gates (G-U2, G-U3) |
| [#279](https://github.com/djshellshoxxx/patchtrace/pull/279) | open | `codex/codespaces-cs1-20261109` | `a5f049cd` | codespaces: bootstrap the PatchTrace accuracy lab |
| [#281](https://github.com/djshellshoxxx/patchtrace/pull/281) | open | `claude/patchtrace-haiku-agent-motpbx` | `cbabc09e` | ci: name tag releases after the tag and pin the release action (alpha precondition) |
| [#282](https://github.com/djshellshoxxx/patchtrace/pull/282) | open | `consolidate/research-r7-20261104` | `552c2945` | Consolidate R7 research prototypes: bounded semantic slicing and patch patterns (from #134) |
| [#283](https://github.com/djshellshoxxx/patchtrace/pull/283) | open | `claude/instance-c-research` | `6f767cce` | unified bench: a missing ticks count fails the work checks (UE-B-07) |
| [#284](https://github.com/djshellshoxxx/patchtrace/pull/284) | open | `claude/sleepy-fermi-y3z4yj` | `160a60e8` | Completion session record: ledger, status roll-up, slice cards and handoff (session stopped by owner) |
| [#289](https://github.com/djshellshoxxx/patchtrace/pull/289) | open | `claude/autonomous-finish-20261104` | `ad4c4928` | Handoff record: autonomous-finish integration branch (paused; do not merge as-is) |
| [#299](https://github.com/djshellshoxxx/patchtrace/pull/299) | closed | `codex/corpus-integrity-20261116` | `6a5b6f26` | Recover corpus provenance, immutable receipts and native IO research controls |
| [#303](https://github.com/djshellshoxxx/patchtrace/pull/303) | open | `codex/pw01-kb-inventory-20261118` | `2b697222` | Add scoped KB file inventories with offline import and exact source consent |
| [#307](https://github.com/djshellshoxxx/patchtrace/pull/307) | open | `codex/pw01-retained-source-pages-20261118` | `58fc1306` | Complete retained inventories and guard native qualification identities |
| [#308](https://github.com/djshellshoxxx/patchtrace/pull/308) | open | `codex/strings-export-publication-20261118` | `92a411bf` | Preserve concurrent files and evidence during strings export [no release] |
| [#309](https://github.com/djshellshoxxx/patchtrace/pull/309) | open | `codex/raw-alignment-reviewed-20261118` | `3c9d3f07` | Restore reviewed paired raw-offset desktop workflow [no release] |
| [#310](https://github.com/djshellshoxxx/patchtrace/pull/310) | open | `codex/saved-search-reviewed-20261118` | `26558cd0` | Complete reviewed saved-search GUI and CLI workflows [no release] |
| [#311](https://github.com/djshellshoxxx/patchtrace/pull/311) | open | `codex/primary-environment-20261118` | `09b032f2` | Restrict primary engine environment by default [no release] |
| [#312](https://github.com/djshellshoxxx/patchtrace/pull/312) | open | `codex/release-qualification-reviewed-20261118` | `573829f3` | Require exact-source publication qualification [no release] |
| [#313](https://github.com/djshellshoxxx/patchtrace/pull/313) | open | `codex/advisory-read-bounds-20261118` | `a4061979` | Bound retained advisory reads and preserve verified recovery [no release] |
| [#314](https://github.com/djshellshoxxx/patchtrace/pull/314) | open | `codex/pilot-current-evidence-reviewed-20261118` | `b41d6631` | Connect retained CVRF leads to current evidence and reports [no release] |
| [#315](https://github.com/djshellshoxxx/patchtrace/pull/315) | open | `codex/manifest-dtd-reviewed-20261118` | `23fbe4a5` | Refuse PE manifest doctypes at the parser boundary [no release] |
| [#316](https://github.com/djshellshoxxx/patchtrace/pull/316) | open | `codex/verified-followup-integration-20261118` | `f2b6827f` | Consolidate reviewed analyst workflows and security fixes [no release] |
| [#318](https://github.com/djshellshoxxx/patchtrace/pull/318) | open | `codex/patchtrace-stabilization-20261119` | `c4ace208` | Repair Windows consolidation failures and restricted corpus startup [no release] |
| [#319](https://github.com/djshellshoxxx/patchtrace/pull/319) | open | `consolidation/patchtrace-reviewed-20261119` | `a56ab13a` | Recover reviewed product fixes and strengthen native qualification [no release] |

## Tag retention

All 59 frozen refs are lightweight commit tags. Tag names do not imply current release qualification.

| Tag | Target | In main history | In candidate history |
|---|---|---|---|
| `v0.1.0-beta.101` | `4d9fa9f0` | true | true |
| `v0.1.0-beta.103` | `0a4bc09b` | true | true |
| `v0.1.0-beta.1035` | `1836eb12` | true | true |
| `v0.1.0-beta.109` | `3c1e81cb` | true | true |
| `v0.1.0-beta.110` | `f0086f79` | true | true |
| `v0.1.0-beta.112` | `0ec47101` | true | true |
| `v0.1.0-beta.116` | `f1d95e15` | true | true |
| `v0.1.0-beta.117` | `34d2b480` | true | true |
| `v0.1.0-beta.118` | `1e6703a8` | true | true |
| `v0.1.0-beta.120` | `58578e17` | true | true |
| `v0.1.0-beta.127` | `7cdb1205` | true | true |
| `v0.1.0-beta.129` | `df6004ff` | true | true |
| `v0.1.0-beta.13` | `5667b759` | true | true |
| `v0.1.0-beta.131` | `b7e819a3` | true | true |
| `v0.1.0-beta.142` | `ac97541b` | true | true |
| `v0.1.0-beta.144` | `f689d33f` | true | true |
| `v0.1.0-beta.146` | `cda7fe86` | true | true |
| `v0.1.0-beta.148` | `29a4d3f3` | true | true |
| `v0.1.0-beta.158` | `011e20c3` | true | true |
| `v0.1.0-beta.162` | `b38ad2bc` | true | true |
| `v0.1.0-beta.163` | `4fa554a0` | true | true |
| `v0.1.0-beta.167` | `cb25132b` | true | true |
| `v0.1.0-beta.176` | `9403d1dc` | true | true |
| `v0.1.0-beta.177` | `1560531c` | true | true |
| `v0.1.0-beta.202` | `67e5a6c6` | true | true |
| `v0.1.0-beta.21` | `97dda866` | true | true |
| `v0.1.0-beta.211` | `46dfac17` | true | true |
| `v0.1.0-beta.220` | `ea5be5ea` | true | true |
| `v0.1.0-beta.222` | `0142c5de` | true | true |
| `v0.1.0-beta.225` | `98182e51` | true | true |
| `v0.1.0-beta.243` | `c2070cf8` | true | true |
| `v0.1.0-beta.281` | `21a005e2` | true | true |
| `v0.1.0-beta.29` | `0f1b4ce5` | true | true |
| `v0.1.0-beta.36` | `736332cf` | true | true |
| `v0.1.0-beta.372` | `eb096071` | true | true |
| `v0.1.0-beta.402` | `70e33fd7` | true | true |
| `v0.1.0-beta.505` | `08f6a5ff` | true | true |
| `v0.1.0-beta.541` | `94bd6a41` | true | true |
| `v0.1.0-beta.543` | `f4063c3c` | true | true |
| `v0.1.0-beta.62` | `4848c547` | true | true |
| `v0.1.0-beta.63` | `615b9354` | true | true |
| `v0.1.0-beta.698` | `6579ed83` | true | true |
| `v0.1.0-beta.70` | `2148a3fb` | true | true |
| `v0.1.0-beta.72` | `2d889417` | true | true |
| `v0.1.0-beta.736` | `ce8c65bf` | true | true |
| `v0.1.0-beta.751` | `b77d84e5` | true | true |
| `v0.1.0-beta.8` | `e7bd3dd4` | true | true |
| `v0.1.0-beta.80` | `0d22e9cd` | true | true |
| `v0.1.0-beta.82` | `1223cdd5` | true | true |
| `v0.1.0-beta.85` | `20a84334` | true | true |
| `v0.1.0-beta.90` | `7eea0014` | true | true |
| `v0.1.0-beta.907` | `d02b94bc` | true | true |
| `v0.1.0-beta.926` | `365bf1f2` | true | true |
| `v0.1.0-beta.95` | `cae86740` | true | true |
| `v0.1.0-beta.96` | `6764acb5` | true | true |
| `v0.1.0-beta.97` | `e4361165` | true | true |
| `v0.1.0-beta.972` | `a6f6eb11` | true | true |
| `v0.1.0-beta.98` | `be8577c0` | true | true |
| `v0.1.0-beta.991` | `77055d4f` | true | true |

## Reproduction and interpretation

The structural pass uses `tools/branch_inventory.py` with complete local history, the frozen all-page PR metadata and the frozen branch-tip TSV. `git rev-list`, `git merge-base`, `git cherry`, `git diff-tree` and exact tree/blob reads supply the evidence. The legacy classifier is not adopted as a semantic verdict: in particular, its automatic experimental deferral is replaced by explicit open review states here.

Historical records are immutable source evidence at `f2b6827fc6270b96fb241b0722f2878de5a17361:docs/plans/autonomous-consolidation-20261118/semantic-disposition-batch1.json` through `semantic-disposition-batch7.json`. Each receipt is tied to its original comparison commit. The recheck verifies source blobs and current literal markers; it does not silently carry old test results onto the candidate. Re-run runtime/native gates on the exact final integration head.
