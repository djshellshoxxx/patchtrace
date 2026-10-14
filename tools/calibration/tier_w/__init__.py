"""Tier W: local-only Windows calibration corpus (docs/specs/tier-w-local-corpus.md, SPEC-33). Dev-only.

Decision O1 = local-only: Microsoft binaries, PDBs and everything derived from them (symbol maps, labels,
review queues, engine outputs, reports, Winbindex catalogue snapshots) live under PATCHTRACE_CALIB_ROOT on the
owner's machine and never enter git, CI artifacts or any upload. Nothing fetched is ever executed. Network
access happens only in the explicit, consented `catalogue`, `resolve` and `fetch` subcommands.

Run from the repository root: `PYTHONPATH=src python -m tools.calibration.tier_w --help`.
"""
