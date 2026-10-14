"""Patch-intent rule table (SPEC-30 30b; plan docs/specs/program-e/PIL-integration-plan.md s7 "Rule data").

PIL-B1: `contracts` (closed leaf vocabulary, validated rule records, versioned digest), `data` (the table for every K
rule, as Python literals) and `evaluate` (three-valued expected changes of one rule against one candidate's evidence).
Pure Python like the rest of `pilot`: no Qt, I/O, sqlite, network or process code and no import of another feature's
internals. Fusion, tiers and ranking belong to PIL-B2.
"""
