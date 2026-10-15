"""Shared helpers of the K3 tests (KB-CVE correlator slice K3). SYNTHETIC data only; offline.

* ``FixedClock`` and ``NOW``: a fixed UTC clock so coverage never goes stale in a test.
* ``Kb``: runs ``kbcorrelation.cli.main`` with the production wiring against a temporary workspace and parses the single
  ``enrichment-cli/1`` document it writes.
* ``write_pair`` / ``arm64_pe``: synthetic PE files (``patchtrace.sample.synthetic_pe``), never executed.
"""
from __future__ import annotations

import json
import struct
from pathlib import Path

import kbc_helpers as h

from patchtrace.kbcorrelation import cli, wiring
from patchtrace.sample import synthetic_pe

NOW = '2099-02-15T00:00:00Z'
BASELINE = 'cvrf-2099-Feb.json'


class FixedClock:
    def now_utc(self) -> str:
        return NOW


def arm64_pe(variant: int = 0) -> bytes:
    """The synthetic PE with its COFF machine field changed to ARM64 (header bytes only)."""
    image = bytearray(synthetic_pe(variant))
    struct.pack_into('<H', image, 0x84, 0xAA64)
    return bytes(image)


def write_pair(root: Path, *, older_name: str = 'exampledrv.sys', newer_name: str = 'exampledrv.sys',
               older: bytes | None = None, newer: bytes | None = None) -> tuple[Path, Path]:
    (root / 'old').mkdir(parents=True, exist_ok=True)
    (root / 'new').mkdir(parents=True, exist_ok=True)
    old_path, new_path = root / 'old' / older_name, root / 'new' / newer_name
    old_path.write_bytes(synthetic_pe(0) if older is None else older)
    new_path.write_bytes(synthetic_pe(1) if newer is None else newer)
    return old_path, new_path


def fixture(name: str) -> str:
    return str(h.fixture_path(name))


class Kb:
    """``kb <argv> --workspace W --json`` -> (exit code, parsed document or None, stderr)."""

    def __init__(self, tmp_path: Path, capsys, *, env=None):
        self.workspace = tmp_path / 'ws'
        self.capsys = capsys
        self.env = env or wiring.build_env(clock=FixedClock())

    def __call__(self, *argv: str, as_json: bool = True):
        extra = ['--workspace', str(self.workspace)] + (['--json'] if as_json else [])
        code = cli.main([*argv, *extra], env=self.env)
        out = self.capsys.readouterr()
        return code, (json.loads(out.out) if as_json and out.out.strip() else out.out), out.err

    def search(self, lead: str = 'KB5099001', *extra: str):
        code, doc, _ = self('search', lead, '--offline', *extra)
        return code, doc

    def loaded(self, *names: str) -> Kb:
        code, _, _ = self('index', 'import', *(fixture(n) for n in (names or (BASELINE,))))
        assert code == 0
        return self
