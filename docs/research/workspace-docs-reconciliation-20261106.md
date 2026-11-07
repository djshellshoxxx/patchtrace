# Workspace documentation reconciliation, 2026-11-06

Status: source-preserving documentation reconciliation; no product or release acceptance.

This slice examines seven files from [PR #183](https://github.com/djshellshoxxx/patchtrace/pull/183), pinned at `ed70e6ddac449a42f843f1c60aa878416ab31727`, against main `5d504ff5c046bfb758623182b472976003632bba` and candidate #235 `ccfe175d44a70947203c75bbd033a9a9e2633f0f`. The candidate adds implementation beyond main; neither is treated as proof of a downloadable package or native acceptance. The broader [November 5 research reconciliation](reconciliation-20261105.md) remains a separate receipt.

## Disposition of each source

| Source path in #183 | Disposition and useful destination |
|---|---|
| `docs/specs/DOCKABLE-WORKSPACE-SPEC.md` | Adapted into the [draft dockable workspace proposal](../specs/DOCKABLE-WORKSPACE-SPEC.md). The source's future core extraction, state preservation, migration and acceptance requirements remain proposed. Its detailed original is retained by immutable reference and hash, not replaced by a claim of whole-PR integration. |
| `docs/wiki/Home.md` | Reference only. [Documentation index](../README.md) and [guide index](../guide/00-index.md) already provide repository navigation with working file links. |
| `docs/wiki/User-Guide.md` | Reference only. [User guide](../user-guide.md), [getting started](../guide/10-getting-started.md) and [help index](../help/README.md) cover its short walkthrough with more precise scope and availability notes. |
| `docs/wiki/Developer-Guide.md` | Reference only. [How to extend](../internals/32-how-to-extend.md), [testing and CI](../internals/27-testing-and-ci.md), [Windows setup](../windows.md) and [engineering instructions](../../AGENTS.md) cover the contributor workflow. |
| `docs/wiki/Architecture-and-Design-Rationale.md` | Reference only. [Architecture](../internals/20-architecture.md), [decisions and tradeoffs](../internals/31-decisions-and-tradeoffs.md) and [SPEC-01](../specs/architecture.md) contain the useful material. The old claim that only `ui.py` and `ui_*.py` are Qt-facing is incomplete: current `gui/qt/` and feature presentation modules also contain Qt code. |
| `docs/wiki/Codebase-Map.md` | Reference only. [Module index](../modules.md) and [internals map](../internals.md) cover the same navigation. The old `gui/` label “Qt code only” is inaccurate; its registry/ports and other core modules are Qt-free. The historical approximate test-file count is not carried forward. |
| `docs/wiki/_Sidebar.md` | Reference only. Its extensionless wiki links assume a separately published GitHub Wiki; the current repository guides already have explicit `.md` navigation. No Wiki publication is part of this slice. |

The [machine-readable receipt](workspace-docs-reconciliation-20261106-sources.json) contains all seven original Git blob IDs, SHA-256 digests, byte counts, immutable source URLs and dispositions. Hashes identify the original source bytes, not the adapted destination. No source PR or branch can be deleted or considered fully merged from this receipt.

## Reconciled facts and open decisions

- Source inspection confirms existing feature docks and a fixed central core workspace at both inspected refs. Reintroducing the core-extraction proposal therefore adds a missing design document; it does not assert that all docking is absent or complete.
- Current `layout/schema=1` validation, reset and controller ownership are baseline code. Named presets/layouts, the `workspace_layout/` envelope, generation conflict handling and the source's DW-01-DW-18 gates remain proposals.
- The alias **SPEC-DW-01** is proposed and registered as draft. No numeric identifier is allocated: the old registry's “next free SPEC-56” conflicts with [the recorded #61 claim](../handoff/owner-actions.md). Cite the path until alias confirmation.
- The original source retains the detailed inventory, preset definitions, numeric bounds, implementation slices and acceptance fixtures. The shorter adaptation preserves their scope and points back to them; it is not a lossless replacement for that document.
- All other #183 research, panel specs, planning and wiki history remain at their pinned source. This slice does not settle those dispositions or change the existing QA, ownership or release ledgers.

## Verification scope

Review the original-byte receipt against Git objects, the adaptation's relative links and code references, and the spec index/registry. Existing documentation/registry checks are appropriate for this change. A later implementation must independently satisfy the repository test requirements and the proposed workspace's native/manual acceptance gates; source inspection and documentation checks do not satisfy them.

Validation performed for this documentation slice with the provisioned development interpreter:

- All seven source receipts match the original Git blob ID, SHA-256 and byte count; every mapped destination exists.
- All 43 relative links in the new Markdown documents and added index entries resolve.
- The six core builder/preference/close methods cited in the comparison have identical ASTs at the inspected main and candidate refs. Manifest, dock, layout and command modules are byte-identical across those refs. The manifest has 14 declarations, 13 present modules and absent `guide`.
- `QT_QPA_PLATFORM=offscreen python -m pytest -q -p no:cacheprovider tests/test_spec_registry.py tests/test_help_docs.py`: **294 passed**.
- `python -m ruff check src tests tools` and `git diff --check`: **passed**.

The full application suite and Windows GUI/manual acceptance were not run for this documentation-only slice. No source, test, workflow or packaging files changed.
