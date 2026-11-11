"""Dev-only research qualification tools (docs/plans/research-tools-execution-plan-20261106.md).

Never imported by `src/`, never frozen into the desktop bundle. Run from the repository root:

    python -m tools.research_qualification --help

Every tool emits an immutable JSON receipt (see `receipt.py`). A receipt records what was actually run and
measured; anything not measured is listed under `result.unverified` and is never reported as success.
"""
