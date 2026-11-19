# External branch focal review — 2026-11-19

Review finished: **2026-11-19 11:19:34 UTC**. Ref refresh: **11:13:43 UTC**; CI reads were made around that refresh and before the review finished. Repository: [djshellshoxxx/PatchTrace](https://github.com/djshellshoxxx/PatchTrace).

**Disposition: retain both as active, distinct external work. Neither is integrated or approved for a whole-branch merge by this review.** This was a bounded read of source, specifications, exact Git ancestry/blobs and GitHub CI metadata. No external source was edited, executed or merged.

## Pinned heads and observed drift

| Branch | Reviewed head | Tree | Disposition |
| --- | --- | --- | --- |
| `integration/exhaustive-patchtrace-consolidation-20261119` — [draft PR320](https://github.com/djshellshoxxx/PatchTrace/pull/320) | [bc7eb6328b477e2ff19cfe36317279eaf5856fb6](https://github.com/djshellshoxxx/PatchTrace/commit/bc7eb6328b477e2ff19cfe36317279eaf5856fb6) | `0533d0aa0db6350a07ae5738bf88c693a2c7e49a` | Active mixed-stack integration and selective recovery |
| `codex/patchtrace-checkpoint-20261119-81e4` | [bdc929ebd3c6aaa2563c758936beb315a10eeea0](https://github.com/djshellshoxxx/PatchTrace/commit/bdc929ebd3c6aaa2563c758936beb315a10eeea0) | `424709da5b590e68262ea0a11b8f98bb52da8d4b` | Active unique source checkpoint; no PR found by exact head filter |

The checkpoint branch initially equaled main `fdc2696c23bdbfe7668348f25e3b336ce33039f7`. It moved to `bdc929eb` during this review. That new commit has main as its parent and changes **43 paths**. The earlier equal-main/cleanup-candidate observation is historical; **do not add this branch to the current integrated tally**.

The integration branch moved from the initially supplied `188b4962e527c82b29e599f75cd952029b749348` to `bc7eb632`. The latter was fetched once with authorization and remained the pinned head at the final ref refresh. Later movement belongs in a separate census or receipt.

## Ancestry

Counts are **baseline-only / reviewed-head-only** commits, not unique semantic contributions.

| Reviewed head | Main `fdc2696c` | PR319 `a56ab13aaf9916fc12bea70ba1494075991b7f09` | PR318 `c4ace2088ce8dc9ce78a0bf3036b81096accbdb5` |
| --- | --- | --- | --- |
| Integration `bc7eb632` | 0 / 334; contains main | 0 / 332; contains PR319 | 0 / 6; contains PR318 |
| Checkpoint `bdc929eb` | 0 / 1; contains main | 2 / 1; diverged at main | 330 / 3; diverged at `d8c02caea407f6d323eecd636735849c1eb31a2d` |

Integration changes 970 paths versus main, 767 versus PR319 and 170 versus PR318. Only two commits are outside the union of the two parent stacks, but the merge/recovery content is substantive: **76 paths differ from both stacks**, including **16 runtime/tooling/workflow paths**. These counts are mechanical evidence, not 76 semantic approvals.

## Integration: useful unique scope and remaining gates

| Focal family | Actual source observation | Disposition |
| --- | --- | --- |
| Calls layout | Bounded layout is wired into `panel_data.query` and consumed by Qt. Diagram refusal leaves the table usable. Limits include 10,000 input nodes, 40,000 edges, default 500/max 2,000 displayed nodes, 20,000 dummies, eight sweeps and periodic cancellation. Historical source `6e1e153bd90b251b81b9cc919b0cbbb7f1d8d9ac` is identified. | Retain distinct recovery; no native/performance or full combined qualification from this review. |
| Tier-W CLI and runner | CLI entry point and offline catalogue, pair, fetch-plan, symbol, label, evaluation, status and guard dispatch are wired. Input/provenance admission is tightened. The imported runner exists, but CLI `run`, audit/review/audit-report remain blocked. Sources include `ce02504a266929a2648297a6f4d488523b3c48f1`, `bff635ffab2a5900ac3086bac9bac782cc52bfd2` and `c1a46beb46a8cd100c262d9e2143c47c0a892f3b`. | Retain active work. Documented cancellation and paired summary/matches publication obligations remain. No real-adapter or accuracy qualification. |
| Workspace SQLite cleanup | Constructor failure closes acquired connection, cleanup faults preserve the primary exception, and rollback checks transaction state. | Useful distinct repair requiring independent combined qualification. |
| Forced Strings/shared publication | Linux anonymous initial stage, held directory and post-publication identity checking; explicit Windows replacement path. These go beyond our earlier cancellation-only restoration. | Partial ownership repair. The documented final Linux name-substitution race remains: post-rename refusal does not restore overwritten destination bytes. Preserve this work and its open gate. |
| Broad reconciliation | PR318 native/package/qualification changes remain present alongside PR319; eleven conflicts are documented in the external source. | Active mixed stack. No automatic merge, PR closure or branch deletion recommendation. |

The external inventory and recovery records explicitly retain unfinished work. Their structural census and semantic claims have different pins/scope from our frozen 318-branch census; totals must not be combined.

## Checkpoint: bounded actual source review

The new checkpoint adds five useful families on main:

- **SPEC-51 metadata cache:** new exact-row `EnrichmentStore.entry`, `pe-metadata` registration, strict cache codec and owner-thread snapshot/publication. It verifies the artifact on each use, passes frozen metadata to the existing inspection worker and removes the second reader of the same held handles. Cached OS trust is excluded. The 8 MiB row, depth-32 and 250,000-node controls do not bound SQLite's internal allocation.
- **Parser integrity:** raw Winbindex bytes now enter the existing decoded-byte budget. BinDiff validates integer/duplicate keys and uses a bounded SQLite `table_list` classification to reject disguised virtual/shadow tables. Unsupported old SQLite gets a typed refusal.
- **N-way failure isolation:** resolve/stat failures become per-pair unreadable/missing results; healthy hops remain available.
- **Research facts guard:** scoring unverified or absent facts produces BLOCKED; malformed candidate shapes still refuse. Synthetic controls do not establish real accuracy.
- **Adapter text and asset receipts:** BinExport nested names/symbols are validated; rz-diff invalid Unicode produces a typed error with encodable diagnostic tails; milestone notes include the Windows Setup executable.

Read scope includes every changed-path record, the named runtime patches, cache/spec contracts and relevant test definitions. No test was executed here. Shared storage and UI changes need integration review; native trust, actual adapters and combined qualification remain separate.

## Overlap with our sealed recoveries

Comparison pins:

- Inventory: `0afd6f5410f8a527d697f79e415b31efcc84407a`.
- Strings: `2f8f69c268dcc03750596114ef891ad651c59506`.
- Search: `b5aace25a36809ae7e4ab044e692c12015772a7d`.

| Recovery | Integration `bc7eb632` | Checkpoint `bdc929eb` |
| --- | --- | --- |
| Production Search bridge | `search/wiring.py` absent. Search CLI/Qt are byte-identical to both parent stacks. | No Search change from main; new bridge absent. |
| Shared Strings composition/admission | `strings/compose.py` and `intelligence/tools/admission.py` absent. Strings CLI/Qt equal parent stacks. Export/publication changes are distinct. | No Strings change from main; composition/admission absent. |
| Inventory semantic decision reader | Contracts/CSV/Qt/service/store match our recovered modules, but selection retains `12d931d3ce918fba442dec658b045a9a48c81d7a`, including canonical-text `instr` filtering. Our semantic projection blob `c5e44e5c427005318a5efda96fca70a81e687270` is absent. | No inventory recovery from main. |

This establishes source overlap and missing fixes. It is not a new external runtime reproduction. The checkpoint's new optional exact-row API leaves existing `entries` and public ToolStore behavior unchanged.

## Actual hosted CI versus reported local tests

| Pin | GitHub check-runs | Workflow runs | Other evidence |
| --- | --- | --- | --- |
| `bc7eb632` | 31 total: 28 queued, 3 skipped; page sizes 31/0 | 9 total: 8 queued, 1 pending; page sizes 9/0 | One legacy Snyk success; zero submitted PR reviews observed. This is not overall CI success. |
| `bdc929eb` | 5 queued; page sizes 5/0 | One queued Native Windows Ghidriff push run; page sizes 1/0 | No legacy statuses; no matching PR at read time. Historical main CI does not qualify this new head. |

The external PR/docs report earlier local focused results, including 742 passed/1 skipped, 214 passed, 145 passed/2 xfailed and narrower security/runner selections. They also retain an exit-137 full attempt and an unfinished grouped full run. The checkpoint reports overlapping N-way 85, installer 5, parser 432/1 skip, metadata 840/2 skips, scorer 140 and adapter 414 results; its first combined attempt exited 137 without final summary/JUnit. **Those are author-reported, earlier local-source results, not independently replayed or current-head hosted passes.** They are not additive totals.

## Evidence and census boundary

- `external-branch-focal-review-20261119.json`: structured dispositions and exact pins.
- `external-branch-remote-raw-20261119.json`: parsed raw REST responses, source URLs, checks, workflows, compares and PR metadata.
- `external-branch-local-evidence-20261119.json`: local Git ancestry and blob differences. Its checkpoint rows intentionally retain the initial main-equal observation.
- `external-branch-overlap-evidence-20261119.json`: exact path/blob comparison against our recovery pins.
- `external-branch-focal-manifest-20261119.json`: hashes of this receipt set.

The frozen historical result remains **318 branches / 317 topics: 144 integrated (128 ancestry + 16 patch-equivalent), 11 dependency-blocked, 162 requiring focal review**. Completed focal dispositions cover the 162 historical heads; they do not constitute exhaustive every-commit or whole-branch approval. Both new external heads require separate active-work classifications in the fresh census.

