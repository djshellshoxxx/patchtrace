"""Pinned upstream executables (SPEC-29 tools T1, T9; audit TA-6).

`PINNED_EXECUTABLES` lists the SHA-256 of the executable of every release the adapters were verified against
(capa 9.4.0, FLOSS 3.1.1, diec 3.21). A probe marks a build `pinned` only when its digest is listed; any other
build is `unsupported` unless the caller opts in explicitly (`accept_untested`), so "FLOSS 3.x" or "capa 9.x" is
never trusted by version text alone. The same values live in `tools/intel_tools_pin.json`, which the provisioning
script uses to download and verify the release assets; a test keeps the two equal.

Measured 2026-10-14 by downloading each release asset once and hashing its executable member without executing it
(trust on first use: the upstream release API is not reachable from the authoring sandbox, so no upstream
per-asset digest was compared).
"""
from __future__ import annotations

PINNED_EXECUTABLES: dict[str, dict[str, str]] = {
    'capa': {
        'cb57c9ea27dda4a6aefb368caca35c3177495e611ad9af64c801d51561035218': 'capa 9.4.0 linux',
        '356db59a7f0d22b00ee63bda6ebb5b05149530eec5dd84101caef6d6bae94dfd': 'capa 9.4.0 windows',
    },
    'floss': {
        'd71b9ea4fe3b2de974dc1ae3c5d0f67569921bc118dcb02ed72e905a662411cb': 'floss 3.1.1 linux',
        '3a208ab834b4791e81592d66e91a7f07b3458504484d87c44ed32bc7384df7ef': 'floss 3.1.1 windows',
    },
    'diec': {
        '35e4cfa45de2c1299933444673feea474ed9ad17f2368e68fce43a64d8bdab15': 'diec 3.21 ubuntu-22.04 deb',
        'dda171a904f6dc3a2c414e99e9d718c8d7500bc26c3dcdc1a72ec0e7d718cfe7': 'diec 3.21 windows portable',
    },
}


def is_pinned(engine: str, executable_sha256: str | None) -> bool:
    return bool(executable_sha256) and executable_sha256 in PINNED_EXECUTABLES.get(engine, {})


def pin_label(engine: str, executable_sha256: str | None) -> str | None:
    return PINNED_EXECUTABLES.get(engine, {}).get(executable_sha256 or '')
