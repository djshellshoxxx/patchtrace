"""Source adapters of the patch-intent localization core (docs/specs/program-e/PIL-integration-plan.md s4, s9).

Each module adapts one source of stored feature data into `pilot/1` inputs: the advisory side (PIL-A2: K reports,
KEV, the confounded window, the pairing verdict map, B3 snapshots) and the code side (PIL-A3: Ghidriff, the unified
engine, B1 evidence, tool deltas). Adapters work on LOADED inputs and are pure: no Qt, no I/O, no network, no target
execution, and a source that is missing or failed reports it (an unknown), never a negative vote. Loading from the
store stays with the owner thread that calls these adapters.
"""
