"""SPEC-31 L1 matching ladder (04-matching-pipeline): uniqueness-gated passes P00-P15, propagation, groups.

Pure Python, stdlib only, no Qt/network/process code. Entry points: `engine.run_ladder` (rows of an `IrSide` port)
and `engine.run_ladder_data` (prepared `side.SideData`). Layering inside the package:
`ports` <- `side` <- `types` <- `state` <- `passes` <- `propagate` <- `groups` <- `engine`.
"""
