# Remote reference census — 2026-11-21

REST capture window: **2026-11-21T04:55:49.621Z through 2026-11-21T04:57:48.373Z**.

Observed **364 distinct remote branch names** and **338 distinct all-state PRs**: **82 open**, **172 merged**, **84 closed without merging**. Open PRs comprise **66 drafts** and **16 non-draft PRs**; non-draft does not mean merge-qualified.

Complete numbered REST pages 1–4 were retained for each collection, followed by an empty page 5. Branch page counts: 100, 100, 100, 64, 0. PR page counts: 100, 100, 100, 38, 0.

## Snapshot comparison

| Explicit snapshot | Branches then | New names | Moved heads | Missing names | Unchanged heads |
| --- | ---: | ---: | ---: | ---: | ---: |
| g30_at_pr348 | 341 | 23 | 0 | 0 | 341 |
| recovered_cycle95fe | 354 | 10 | 0 | 0 | 354 |

The g30 snapshot was read from immutable PR348 commit `6b6fcd3597a604212032ffc453477aeb6edc69ff`. The recovered cycle95fe ZIP is absent from that commit and was read from immutable local recovery commit `487e08113c86636ef9a87aaae8a1b88b224d9f04`, with its retained archive SHA-256 verified. Neither input was read from a moving working tree. g30 records observation at `2026-11-20 15:40:23 UTC`. Recovered cycle95fe inputs have no API capture timestamp; their associated inventory replay ran from `2026-11-20T23:29:41.057671+00:00` through `2026-11-20T23:30:35.925056+00:00`. Those replay timestamps are not substituted for a collection timestamp.

### Branch changes versus recovered_cycle95fe

| New remote name | Exact observed head |
| --- | --- |
| `codex/autonomous-consolidation-20261120-2bad` | `39c38a02f126963fc03827fa49741255590227ad` |
| `codex/patchtrace-codex6-cache-hit-fixture-tests-20261121` | `d2507b1415fd0917fcda6b9f26565d0467d7b9ba` |
| `codex/patchtrace-corpus-archive-integrity-20261121` | `658cc814aa74d1eaebf0d7e6dd4553d06aaef0eb` |
| `codex/patchtrace-integration-20261121-2bad` | `6b6fcd3597a604212032ffc453477aeb6edc69ff` |
| `codex/patchtrace-inventory-tip-oid-20261120` | `a63a20b2a272d53a09422222050080823fc3c664` |
| `codex/patchtrace-inventory-tsv-shape-20261120` | `eaae7e504f8b43051f0c0d6d57c314d37c66d7ff` |
| `codex/patchtrace-linux-frozen-cli-smoke-20261121` | `e4854b66ae37024d734e22ae978dedca90a7f3f7` |
| `codex/patchtrace-pr-snapshot-json-strict-20261120` | `e2385c22c0397a547b15b2fbca9f0c07dc4ac199` |
| `codex/patchtrace-pr345-346-unique-recovery-20261120` | `b461ac64eb9beb74449ce2b18b6795a2af34a02a` |
| `consolidation/patchtrace-20261120-95fe` | `c07774ecf5a3f7337834f95a9a4c51c8ec5fad44` |

No snapshot names are missing from the current collection.

### Branch changes versus g30_at_pr348

| New remote name | Exact observed head |
| --- | --- |
| `codex/autonomous-consolidation-20261120-2bad` | `39c38a02f126963fc03827fa49741255590227ad` |
| `codex/patchtrace-acquire-destination-symlink-20261120-g30` | `20d3bb173c9f6d65a144fe26ebed8f22e3c79a00` |
| `codex/patchtrace-acquire-poststage-destination-20261120-g31` | `e22ab7dfbb440d635b5829bde1fec4ee2c149c8d` |
| `codex/patchtrace-acquire-windows-junction-20261120-g32` | `ae67122c69f05715afa622b7e4050b73ca155967` |
| `codex/patchtrace-advisory-lead-type-20261120-g40` | `371b067068da3c4898ebb7b6eae5d0dd13ebea00` |
| `codex/patchtrace-candidate-component-type-20261120-g41` | `67f7e08ea9bee61653f8ab5ad66048d3e7141810` |
| `codex/patchtrace-codex6-cache-hit-fixture-tests-20261121` | `d2507b1415fd0917fcda6b9f26565d0467d7b9ba` |
| `codex/patchtrace-corpus-archive-integrity-20261121` | `658cc814aa74d1eaebf0d7e6dd4553d06aaef0eb` |
| `codex/patchtrace-csv-crosscolumn-review-20261120-g36` | `f48d25eb22e019bda9f3f258ae8208e85ad45f19` |
| `codex/patchtrace-csv-fixture-escape-20261120-g35` | `09af21b0419fe06cce6fdd031355e274e6deb5d0` |
| `codex/patchtrace-csv-formula-prefix-20261120-g33` | `f196443ce59c740fe022875ffc00e71349c15dc8` |
| `codex/patchtrace-csv-formula-prefix-20261120-g34` | `599e1ee1bc7bec095b4e6fa28d5cfc25c4d6f7df` |
| `codex/patchtrace-integration-20261121-2bad` | `6b6fcd3597a604212032ffc453477aeb6edc69ff` |
| `codex/patchtrace-inventory-tip-oid-20261120` | `a63a20b2a272d53a09422222050080823fc3c664` |
| `codex/patchtrace-inventory-tsv-shape-20261120` | `eaae7e504f8b43051f0c0d6d57c314d37c66d7ff` |
| `codex/patchtrace-investigation-destination-junction-20261120-g39` | `fc2c038ad1c21ddfcdfb5cd943307c3195d631ec` |
| `codex/patchtrace-linux-frozen-cli-smoke-20261121` | `e4854b66ae37024d734e22ae978dedca90a7f3f7` |
| `codex/patchtrace-native-cache-receipt-20261120-g37` | `fc641a97846c03ebdbf70b5c8248e5685e4853b2` |
| `codex/patchtrace-pr-snapshot-json-strict-20261120` | `e2385c22c0397a547b15b2fbca9f0c07dc4ac199` |
| `codex/patchtrace-pr345-346-unique-recovery-20261120` | `b461ac64eb9beb74449ce2b18b6795a2af34a02a` |
| `codex/patchtrace-verified-integration-20261120-g30` | `5f34fb57267637b986814ddc81dba11550992fff` |
| `codex/patchtrace-windows-qt-timeout-evidence-20261120-g38` | `1c60d91ab1d2038ba481d21d58611137f21b8454` |
| `consolidation/patchtrace-20261120-95fe` | `c07774ecf5a3f7337834f95a9a4c51c8ec5fad44` |

No snapshot names are missing from the current collection.

## Pull requests

| Snapshot | All | Open | Merged | Closed unmerged | New PR numbers | Existing PRs with tracked metadata changes |
| --- | ---: | ---: | ---: | ---: | --- | ---: |
| g30_at_pr348 | 330 | 74 | 172 | 84 | #341, #342, #343, #344, #345, #346, #347, #348 | 0 |
| recovered_cycle95fe | 334 | 78 | 172 | 84 | #345, #346, #347, #348 | 0 |

Latest 12 PRs by number (all states); the complete normalized file includes every PR:

| PR | State | Draft | Base | Head branch | Exact head |
| --- | --- | --- | --- | --- | --- |
| [#348](https://github.com/djshellshoxxx/patchtrace/pull/348) | open | True | `codex/patchtrace-pr345-346-unique-recovery-20261120` | `codex/patchtrace-integration-20261121-2bad` | `6b6fcd3597a604212032ffc453477aeb6edc69ff` |
| [#347](https://github.com/djshellshoxxx/patchtrace/pull/347) | open | True | `codex/autonomous-consolidation-20261120-2bad` | `codex/patchtrace-pr345-346-unique-recovery-20261120` | `b461ac64eb9beb74449ce2b18b6795a2af34a02a` |
| [#346](https://github.com/djshellshoxxx/patchtrace/pull/346) | open | True | `codex/patchtrace-candidate-component-type-20261120-g41` | `consolidation/patchtrace-20261120-95fe` | `c07774ecf5a3f7337834f95a9a4c51c8ec5fad44` |
| [#345](https://github.com/djshellshoxxx/patchtrace/pull/345) | open | True | `codex/patchtrace-candidate-component-type-20261120-g41` | `codex/autonomous-consolidation-20261120-2bad` | `39c38a02f126963fc03827fa49741255590227ad` |
| [#344](https://github.com/djshellshoxxx/patchtrace/pull/344) | open | True | `codex/patchtrace-advisory-lead-type-20261120-g40` | `codex/patchtrace-candidate-component-type-20261120-g41` | `67f7e08ea9bee61653f8ab5ad66048d3e7141810` |
| [#343](https://github.com/djshellshoxxx/patchtrace/pull/343) | open | True | `codex/patchtrace-native-cache-receipt-20261120-g37` | `codex/patchtrace-windows-qt-timeout-evidence-20261120-g38` | `1c60d91ab1d2038ba481d21d58611137f21b8454` |
| [#342](https://github.com/djshellshoxxx/patchtrace/pull/342) | open | True | `codex/patchtrace-qa-ruff-imports-20261120-g29` | `codex/patchtrace-verified-integration-20261120-g30` | `5f34fb57267637b986814ddc81dba11550992fff` |
| [#341](https://github.com/djshellshoxxx/patchtrace/pull/341) | open | True | `codex/patchtrace-qa-ruff-imports-20261120-g29` | `codex/patchtrace-acquire-destination-symlink-20261120-g30` | `20d3bb173c9f6d65a144fe26ebed8f22e3c79a00` |
| [#340](https://github.com/djshellshoxxx/patchtrace/pull/340) | open | True | `codex/patchtrace-hosted-qa-fixture-20261120-g28` | `codex/patchtrace-qa-ruff-imports-20261120-g29` | `6c8b33b851a22fb16d39b31693922359cd34ad12` |
| [#339](https://github.com/djshellshoxxx/patchtrace/pull/339) | open | True | `codex/patchtrace-newer-source-ambiguity-20261120-g27` | `codex/patchtrace-hosted-qa-fixture-20261120-g28` | `a5c6ff87ececcaffce01404f723aac455ee17e0c` |
| [#338](https://github.com/djshellshoxxx/patchtrace/pull/338) | open | True | `codex/patchtrace-older-source-ambiguity-20261120-g26` | `codex/patchtrace-newer-source-ambiguity-20261120-g27` | `9897ae5b70cee209787d1ebb1902031c186667ec` |
| [#337](https://github.com/djshellshoxxx/patchtrace/pull/337) | open | True | `codex/patchtrace-acquire-window-anchor-20261120-g25` | `codex/patchtrace-older-source-ambiguity-20261120-g26` | `30a9c9dab2449919941fd397f6442ae8cd225111` |

## Boundaries and evidence

- This is a reference census. Exact name/head changes do not establish semantic supersession, successful integration, or permission to delete a branch.
- Branch names, commit subjects, PR authors, and draft flags do not identify a live worker. No live-worker ownership is assigned.
- Paginated API reads cover a bounded interval and are not an atomic transaction. Later ref or PR updates require a new receipt.
- REST GET collections were used through the authorized GitHub connector. Local `gh api` had no authentication; no login, GraphQL, dispatch, push, deletion, package, or test operation was performed.
- No repository working tree, source file, local integration branch, or remote ref was changed. No Git fetch was needed.
- PR CI results, native/manual acceptance, release readiness, and semantic donor review are outside this census.

Evidence: `capture-manifest.json` binds URLs, per-page timestamps, sizes and SHA-256 values to unchanged REST JSON bodies in `raw/`. `branches.normalized.json`, `pulls.normalized.json`, and `comparison.normalized.json` retain every normalized record and exact comparison. `snapshot-identities.json` binds the two frozen inputs to their respective commits and preserves the recovered timestamp limitation.
