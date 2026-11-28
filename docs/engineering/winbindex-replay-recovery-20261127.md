# Complete retained Winbindex source replay

Date: 2026-11-27 (America/Vancouver).

## Confirmed gap and incremental plan

Current acquisition discarded the original index bytes after parsing and read
resolver and delivery rows separately. Its existing evidence retained normalized
rows and entry hashes, but omitted complete source bytes, resolver arguments and
actual endpoint membership. SPEC-31-D and the task ledger left this capability
open. Auditing the unmerged acquisition paths found no reusable complete replay
implementation; no broad donor merge was performed.

The implementation proceeded in three independently checked slices:

1. Specify immutable complete-source/replay records and actual resolver endpoint
   membership; enforce original and potential expanded row budgets.
2. Capture original plain/gzip bytes once, bind exact consent and evidence to the
   capture, and retain immutable raw objects in workspace and project before
   project creation or journal mutation.
3. Add offline CLI replay, backup acceptance, explicit legacy/future-version
   handling and recovery guards while retaining copied-row ambiguity refusal.

## Resulting behavior

`kb acquisition replay --project DIR --evidence SHA --json` reads only the project
sidecars, reconstructs normalized rows through the production parser, and compares
the complete captured inputs and resolver result. Backup replay works after the
original project and mutable workspace are removed. Missing or damaged project
source is a failure; replay does not substitute a workspace copy. Historical
records report unavailable raw provenance, and unsupported future versions are
identified explicitly. Existing legacy serialization and content identities stay
unchanged.

Original bytes have a 64 MiB bound, replay rows have a 1,000,000 bound, and copied
version keys have a 4,096 per-row bound. Multi-file acquisition applies aggregate
capture budgets before retention. Raw-only changes, including a gzip header,
change source identity and consent. The selected predecessor's actual membership
is retained, while conflicting same-priority copied claims remain refused.

All project/source ownership checks use the existing held-reader and immutable
publication boundaries. No SQLite contract migration was introduced. Replay proves
consistency of retained evidence and the resolver; it does not prove Microsoft
authorship, signature trust, vulnerability attribution or L1/L2/L3 accuracy.

## Source and verification

Implementation commits are `d9dcc72f` (records/membership), `26e439b2`
(one-read acquisition/retention) and
`8912e034ed9d15d1fb2daeabab5d3dc1518b4e28` (offline replay/recovery).
The complete author receipt preserves all intermediate failures and fixes,
including a journal-resume ordering bug and an initially missed conflicting-copy
refusal. The final author lane passed **616**, with one explicit native Windows
junction skip. That selection is not additive with later lanes.

Root independently reviewed the implementation and passed **74** checks with no
failures or skips: the 66 new feature checks plus eight independent controls. The
additional controls cover aliased source/evidence paths, gzip-only consent change,
retained unusable rows and gaps, unavailable project bytes despite an intact
workspace copy, and unsupported replay contracts. They are retained in
`tests/test_kbc_replay_boundary_controls.py`.

The current inventory candidate
`f301d54b2d38b93c41c2215aebb8a73fb719dbcf` was merged normally into the reviewed
replay branch, preserving both histories. Shared service/store/CLI/contracts and
schema-generator changes merged without conflicts. At combined source
`ea80552ed094a874a68f6aa0979a2b73a3dece89`, tree
`8b90c6cfefa0808b8b5fee90d92c1a0a1cfb6aa4`, the **92-module** KB, inventory,
acquisition parser and desktop lane plus independent controls passed **2,408**
tests, with **3** explicit native Windows skips, in 95.21 seconds. The worktree
remained clean and unchanged. Schema regeneration check and whole-tree Ruff passed.
After retaining the eight independent controls in the repository, the final replay,
contract and schema lane passed **201** tests without skips. Whole-tree Ruff
and whitespace checks passed again. Exact receipts, original observed failures,
JUnit and combined output are committed
under `docs/engineering/evidence/winbindex-replay-20261127/`.

Independent source review is approved without blockers. Exact publication-head
hosted full-suite, native Windows and frozen-package checks remain separate gates.
All exercised provider/index/PE data were authored and transports injected;
no live provider or target binary was executed. Keep `[no release] [no deploy]`.
