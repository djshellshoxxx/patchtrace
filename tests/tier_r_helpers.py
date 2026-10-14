"""Shared helpers for the SPEC-32 factory tests: toolchain gate (BLOCKED, never a silent skip) and tiny C trees."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.calibration.tier_r import toolchain as T  # noqa: E402

_PROBED: dict[str, T.Toolchain] = {}


def tools() -> T.Toolchain:
    if 'chain' not in _PROBED:
        _PROBED['chain'] = T.probe()
    return _PROBED['chain']


def require(record_live_status, *profiles: str) -> T.Toolchain:
    """Return the toolchain or record `blocked` (fail when PATCHTRACE_REQUIRE_TIER_R=1, as in corpus-tier-r CI)."""
    chain = tools()
    reasons = [f'{p}: {chain.profile_status(p)}' for p in profiles if chain.profile_status(p)]
    if reasons:
        reason = '; '.join(reasons)
        required = os.environ.get('PATCHTRACE_REQUIRE_TIER_R') == '1'
        record_live_status('tier-r-' + '-'.join(profiles), 'failed' if required else 'blocked', reason)
        if required:
            pytest.fail(f'required toolchain missing: {reason}')
        pytest.skip(f'BLOCKED (recorded, not a pass): {reason}')
    return chain


def write_tree(root: Path, files: dict[str, str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8', newline='\n')
    return root
