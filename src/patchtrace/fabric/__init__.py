"""Anchor fabric (contract `fabric/1`; plan: docs/specs/program-e/FAB-integration-plan.md).

FAB-0 pure core: `limits` (numbers F-01..F-15, `FabricError` codes `PT-FAB-*`), `contracts` (strict frozen records
`Anchor`, `Witness`, `PairRef`, `Ref`, the closed vocabularies and the in-process values), `ids` (identities, key
grammars, `make_*`, `check_anchor`, `verify_anchor`, the orientation check), `origins` (origin tags and the
shared-origin calculus, so correlated evidence counts once), `ports` (Protocols only) and `memory` (in-memory and null
sink and reader for tests and until the store lands). Pure Python: no Qt, I/O, sqlite, network or process code, and no
import of another feature's internals. Persisted contracts are additive only from here on.
"""
