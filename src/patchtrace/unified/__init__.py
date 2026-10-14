"""SPEC-31 unified binary-diff engine (derived; Ghidriff stays primary). Spec: docs/specs/unified-engine/.

S0a contract freeze: `limits` (numbers L-xx, error base, budget), `contracts` (persisted records), `keys`
(identities and cache keys) and `store` (sidecar result directories and pointer rows). Pure Python: no Qt,
network or process code anywhere in this package.
"""
