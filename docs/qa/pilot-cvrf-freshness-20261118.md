# Retained CVRF assessment freshness: combined source qualification

**Source:** `3207f9624536ad88af4066a846490abfd0194a9d`.
**Result:** 1,764 passed, no failures/errors/skips, in 42.48 seconds on that exact
committed source. Whole-tree Ruff and the source diff check pass. These are authored
local data, source-pinned CLI, offscreen desktop and pure comparison controls;
they do not qualify native analysis or real CVE attribution.

**Combined acceptance remains open.** After this exact-source gate, root's
independent bridge review reproduced three malformed SQLite storage-class
failures against bridge source `353902677e6d59961e808a90b2a3dd96d2b43269`.
Those are tracked below and are not waived by this hook's passing controls.

## Scope and lineage

Dedicated worktree: `/workspace/scratch/c7a9e8d98848/cvrf-freshness`.
Branch: `codex/cvrf-pilot-freshness-20261118`.

The tree starts from the integration owner's
`6637f6f5eed51d4a5f0eb469b7a382c0facd97cb`, which carries the earlier reviewed
staleness/report chain on actual published PR307 source
`58fc130631f602b6e907bb054d30c21d810551d4`. The bridge was cherry-picked into this
isolated tree before the hook:

| Role | Commit |
| --- | --- |
| Original bridge source | `353902677e6d59961e808a90b2a3dd96d2b43269` |
| Ported bridge spec/tests | `99ff24048ecf9f7ba9fd51987e6d4b1f85739232` |
| Ported bridge source / pre-hook baseline | `33f746ad2d96ecf4021a95082ad417087a8148a5` |
| Hook spec/tests first | `d42c29d0370ddd92fb901e98c96afdc50f64e7d4` |
| Authored transaction/assertion correction, still no hook source | `78472c5f437c178e1baebfcbd9af76dc31c0e48d` |
| Final hook source | `3207f9624536ad88af4066a846490abfd0194a9d` |

The hook changes only `src/patchtrace/pilot/current_inputs.py` in production:
27 added and 15 removed lines; the module is 140 lines. The bridge's source,
collector, ports and service files were compared byte-for-byte with their original
committed source and remain identical. No store, CLI, UI, report adapter, schema,
ranking policy, corpus or frozen outcome was changed by this hook. The integration
owner and original author's worktrees were not edited.

## Behavior and reasoning

The existing owner-thread capture now includes the bridge's immutable
`ContextSnapshot`, using the exact project snapshot supplied to the freshness
check. Its `kb_link_digest` is compared with the assessment input even when every
selected CVE is also covered by CSAF. Replacement, withdrawal, removal, corrupt
metadata and unavailable context therefore cannot leave an earlier receipt
current solely because its CSAF facts and project revision stayed unchanged.

Per-assessment comparison uses the same `available_cves` and
`fallback_facts_ids` helpers as collection. CSAF tracking groups still contribute
all selected group revisions, and CSAF retains overlap precedence. Selected
CVRF-only source SHA values join that exact identity set. At or below P-03 the
assessment covers the complete current universe; above P-03 its recorded explicit
subset is valid, while the global retained-context digest still detects changes
to unselected cards or other investigations. Source limits refuse qualification
instead of accepting a convenient prefix.

Advisory identity recovery and CVRF admission remain distinct. A missing derived
CSAF cache can be recovered from verified raw source and preserve a CSAF-only
receipt. Any AdvisoryStore warning suppresses CVRF fallback, matching the bridge
collector. Unreadable required CSAF remains unqualified under the earlier shared
current-input policy. No retained rows means digest `None`, preserving the legacy
CSAF-only input identity.

The CLI and desktop loaders/publication paths, desktop action-time navigation,
and report lead export already call this shared capture. They receive the change
through that boundary. Historical assessment sidecars and explanations remain
readable. The tests verify no read-time mutation of those sidecars. Per-assessment
comparison consumes captured immutable data and works after the store closes on
another thread; it does not reach SQLite or reopen the project.

## Red-first and intermediate evidence

The final corrected authored controls were run against a **clean detached
pre-hook checkout at `78472c5f437c178e1baebfcbd9af76dc31c0e48d`** in
`/workspace/scratch/c7a9e8d98848/cvrf-freshness-red`. They produced **20 failed,
2 passed in 3.18 seconds**, with no setup errors or skips. `red-context.json`
records the baseline, exact clean HEAD, file hashes and source-pinned command.
`red.log` and `red.xml` preserve the failures.

The failures cover valid CVRF receipts initially marked stale, context changes
incorrectly kept current under CSAF overlap, late publication, report export,
the named subset above 64 CVEs, overlapping investigations, fallback suppression,
pure captured comparison and an actual headless CLI child after committed
context removal. The two passing controls retain a valid CSAF recovery case and
the current report export.

The first hook run produced **19 passed and 3 failed**. Two report assertions had
expected a raw field name, while the existing report deliberately renders the
`inputs-changed` reason. The headless test had issued an uncommitted SQL deletion,
so the separate child correctly reopened the original retained row. The controls
were corrected to match the existing report contract and commit the authored
withdrawal before reopening. The product hook was unchanged. That intermediate
run, its source patch, the initial/pre-correction reds and their exact test sources
are preserved, and are not substituted for the final clean red reproduction.

All 22 corrected new controls then passed in 2.91 seconds. The final affected run
was repeated after the production source commit, with no working-tree edits.

## Exact-source verification

Runtime: `/workspace/scratch/3a6632a6e5ff/venv/bin/python`.
`QT_QPA_PLATFORM=offscreen` and absolute
`PYTHONPATH=/workspace/scratch/c7a9e8d98848/cvrf-freshness/src` were set for the final
run. The shared venv's unrelated older editable install was not used. The actual
CLI child additionally asserts its imported source location, denies network
connects, and checks that Qt/UI modules were not loaded.

`final-context.json` lists the exact command and all 34 selected files:
`tests/test_pilot*.py`, `tests/test_ui_leads*.py`, and `tests/test_report2*.py`.
This includes the bridge's admitted-source/withdrawal controls and earlier
project/advisory/KEV staleness controls, preserving valid no-KB behavior.
`final-affected.log` and XML report **1,764 passed, 0 failures, 0 errors, 0 skips**.
`final-ruff.log` records a clean `ruff check src tests tools`.

The adjacent `pilot-cvrf-freshness-20261118/manifest.json` and `evidence.zip`
retain commands, original reds, intermediate results, the final green gate,
source hashes, exact source/test snapshots and the hook patch. Every archive
member was reopened and checked against its manifest byte count and SHA-256.

## Limits and handoff

The combined tree does not reverify raw CVRF source bytes, upstream freshness or
authenticity. It preserves the bridge's explicit documentary-context limitations,
unknown binary applicability and absent code-locality claims. No source was
downloaded, no target or analyzer ran, and no paid/native/hosted experiment or
remote mutation occurred.

This capture uses the existing advisory reader and the bridge's bounded retained
context reader. It adds no alternative source reader and makes no total-store
I/O, responsiveness or native accuracy claim. The integration owner's separate
advisory-sidecar bounds repair is outside this source chain. The prior assessment
history/retention and partial-known low-level store API remain unchanged.

Root must independently review the combined bridge and hook before integration
or publication. The three hook commits above are separate from the bridge's
original source and QA commits, so integration can preserve their ownership and
evidence lineage.

At this checkpoint, root separately reproduced three malformed SQLite row cases
in `qa/cvrf-independent/test_cvrf_row_types.py` and `storage-class-red.*`:
a BLOB body reaches an unsupported `.encode` call, and BLOB `id`/`body_sha256`
metadata can reach the fallback digest and raise instead of producing an
unavailable snapshot. The bridge author owns the `kb_context.py` repair after
its QA tip `7cc6a0392c9af5844f226deadcf20ff16f4dc96c`. This hook does not change
that module or claim those cases pass. Root will include the corrected bridge
and its independent verification before accepting or publishing the combined
CVE slice. The source/hash receipts here remain tied to the earlier exact tree.
