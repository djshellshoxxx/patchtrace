"""Patch-intent localization (SPEC-30, contract `pilot/1`; plan: docs/specs/program-e/PIL-integration-plan.md).

PIL-A1 contract freeze: `limits` (numbers P-01..P-11, `PilotError` codes `PT-PILOT-*`, cooperative `Budget`),
`contracts` (strict frozen persisted records), `keys` (identities and verification helpers), `origins` (shared-origin
components, so correlated evidence counts once) and `ports` (Protocols only). Pure Python: no Qt, I/O, sqlite, network
or process code, and no import of another feature's internals. Persisted contracts are additive only from here on.
"""
