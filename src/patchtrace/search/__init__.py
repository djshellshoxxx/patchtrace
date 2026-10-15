"""WB1 unified indexed search (find anything). Spec: docs/specs/program-e/WB1-integration-plan.md.

S0 foundation: `limits` (numbers), `errors` (PT-SEARCH-* codes), `capability` (SQLite FTS5 probe) and `paths`
(per-user cache layout). Pure Python: no Qt, network or process code anywhere in this package.
"""
