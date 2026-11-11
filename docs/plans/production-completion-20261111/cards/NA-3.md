# Slice card NA-3 - Diaphora result import: the SQLite guard must refuse executable and indirect objects (B-D03)

Evidence and design: `jq '.actionable_now[] | select(.id=="B-T03")' docs/status/inventory/B.json`,
`jq '.features[].defects[]? | select(.id=="B-D03")' docs/status/inventory/B.json`, feature row B-F11.
Spec: docs/specs/diaphora-optional-engine.md (SPEC-DA-01). Compare with the stricter BinDiff importer in
src/patchtrace/secondary/bindiff.py and with the project-database rule TB-07 on main (commit fd32e2d "Refuse project
databases that contain views or triggers") - reuse the same idea and wording.

## Defect (reproduced by the analyst on main)
src/patchtrace/diaphora/sqlite_guard.py accepts a database whose `results` table is a VIEW (and does not refuse
triggers or virtual tables), which contradicts the module's own contract: a view can make a read execute arbitrary
SQL expressions over other tables, and a virtual table can load code paths the guard never reviewed.

## Required
Spec first (one paragraph in the spec's import section). Then: before reading, inspect sqlite_master and refuse views,
triggers and virtual tables with DiaphoraError PT-DIAPHORA-DB (use the existing typed error and message style); install a
SQLite authorizer (`set_authorizer`) that allows only SELECT/READ on the fixed tables and columns of the expected schema
and denies everything else (functions that are not on a small allow-list, ATTACH, PRAGMA other than the ones the guard
itself issues, writes). Plain tables and their ordinary indexes stay allowed - real Diaphora result files may carry
indexes or extra plain tables; no real result file is available here, say so under unverified.
Tests (tests/test_diaphora_import.py, red first): a view-backed `results`, a trigger, a virtual table (FTS5 or
`CREATE VIRTUAL TABLE ... USING rtree` if compiled in - skip that one case with a stated reason if the module is not
available in this SQLite build) each raise PT-DIAPHORA-DB; a read of a table outside the expected schema is denied by the
authorizer; an honest fixture with an extra index and an extra plain table still imports; the deadline behaviour
(tests/test_diaphora_deadline.py) is unchanged. Existing 38 + 14 tests stay green.

## Owned files
src/patchtrace/diaphora/sqlite_guard.py (and other files inside src/patchtrace/diaphora/ only if the guard's caller must
pass something new), docs/specs/diaphora-optional-engine.md, tests/test_diaphora_import.py, tests/test_diaphora_deadline.py,
tests/test_diaphora_cli.py.
NOT yours: src/patchtrace/diaphora/provenance.py (slice SEC-A is changing its JSON handling).
