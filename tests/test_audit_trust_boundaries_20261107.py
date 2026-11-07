"""Regression tests from the 2026-11-07 trust-boundary audit (docs/qa/audit-trust-boundaries-20261107.md).

Synthetic hostile inputs only; nothing here executes or loads a target binary."""
from __future__ import annotations

import os
import stat
import struct
import time

import pytest
from test_offline_bundle import FILES, make_bundle

from patchtrace import artifact_inspection
from patchtrace.acquisition import quarantine
from patchtrace.acquisition import transport as tr
from patchtrace.hostile_text import is_hostile
from patchtrace.ingestion import display_text, inspect_artifact
from patchtrace.offline_bundle import OfflineBundleError, inspect_offline_bundle


# TB-01 sweep_staging followed a symlink named like a staging directory and chmod-ed its target
@pytest.mark.skipif(os.name == 'nt', reason='symlink and POSIX mode assertions')
def test_sweep_staging_ignores_symlinked_staging_names(tmp_path):
    parent = tmp_path / 'shared-tmp'
    parent.mkdir()
    victim = tmp_path / 'victim'
    victim.mkdir()
    victim.chmod(0o755)
    keepsake = tmp_path / 'keepsake.txt'
    keepsake.write_text('x')
    keepsake.chmod(0o444)
    old = time.time() - 3 * 24 * 3600
    for target in (victim, keepsake):
        os.utime(target, (old, old))
    os.symlink(victim, parent / (quarantine.STAGING_PREFIX + 'dir'))
    os.symlink(keepsake, parent / (quarantine.STAGING_PREFIX + 'file'))
    quarantine.sweep_staging(parent)
    assert stat.S_IMODE(victim.stat().st_mode) == 0o755
    assert stat.S_IMODE(keepsake.stat().st_mode) == 0o444


# TB-02 a Last-Modified header at the edge of the date range raised OverflowError out of fetch_metadata
@pytest.mark.parametrize('value', ['Fri, 31 Dec 9999 23:59:59 -0100', 'Fri, 31 Dec 9999 23:59:59 -2359'])
def test_last_modified_out_of_range_is_ignored_not_raised(value):
    assert tr._date(value) is None


# TB-03 U+2028 / U+2029 split a one-line GUI label into two lines but were not treated as hostile
@pytest.mark.parametrize('char', ['\u2028', '\u2029'])
def test_line_and_paragraph_separators_are_hostile(char):
    assert is_hostile(char)
    assert display_text(f'good{char}FAKE') == 'good?FAKE'


# TB-04 compare_overviews failure leaked the open readers of both sides
def _pe(size: int = 0x400) -> bytes:
    raw = bytearray(size)
    raw[0:2] = b'MZ'
    struct.pack_into('<I', raw, 0x3C, 0x80)
    raw[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HH', raw, 0x84, 0x8664, 1)
    struct.pack_into('<H', raw, 0x80 + 20, 240)
    struct.pack_into('<H', raw, 0x80 + 24, 0x20B)
    struct.pack_into('<I', raw, 0x80 + 24 + 108, 16)
    return bytes(raw)


def test_inspection_closes_readers_when_comparison_raises(tmp_path, monkeypatch):
    older, newer = tmp_path / 'a.bin', tmp_path / 'b.bin'
    older.write_bytes(_pe())
    newer.write_bytes(_pe() + b'\0' * 16)
    root = tmp_path / 'case'
    artifacts = [inspect_artifact(older, 'older', root), inspect_artifact(newer, 'newer', root)]
    closed = []
    original = artifact_inspection.VerifiedArtifactReader.close

    def counting_close(self):
        closed.append(self.label)
        original(self)

    monkeypatch.setattr(artifact_inspection.VerifiedArtifactReader, 'close', counting_close)
    monkeypatch.setattr(artifact_inspection, 'compare_overviews',
                        lambda *_: (_ for _ in ()).throw(RuntimeError('synthetic comparison defect')))
    with pytest.raises(RuntimeError):
        artifact_inspection.inspect_project_artifacts('p', artifacts, root, verify_trust=lambda _p: None)
    assert len(closed) == 2


# TB-05 a manifest listing both a file and a path beneath it passed inspection and only failed during install
def test_manifest_file_and_directory_path_conflict_is_rejected_at_inspection(tmp_path):
    files = dict(FILES) | {'python/python.exe/child.txt': b'x'}
    archive = make_bundle(tmp_path, files)
    with pytest.raises(OfflineBundleError):
        inspect_offline_bundle(archive)


# TB-06 the launcher report was parsed with plain json.loads: deep nesting escaped as RecursionError and a duplicate
# key or a boolean `setup_calls` was accepted as a valid handshake
def _report(**changes):
    import json
    base = {'contract': 'ptlaunch/1', 'mode': 'local', 'setup_calls': 1, 'server_urls_forced_empty': True,
            'pdbs_staged': []}
    return json.dumps(base | changes)


@pytest.mark.parametrize('text', [
    '[' * 20000 + ']' * 20000,
    _report().replace('"mode": "local"', '"mode": "off", "mode": "local"'),
    _report(setup_calls=True),
    _report(setup_calls=float('nan')),
], ids=['deep-nesting', 'duplicate-key', 'bool-as-count', 'nan'])
def test_launcher_report_is_strict_json(tmp_path, text):
    from patchtrace.ghidriff_launch.validate import validate_run
    from patchtrace.symbols.modes import SymbolError
    path = tmp_path / 'report.json'
    path.write_text(text, encoding='utf-8')
    with pytest.raises(SymbolError):
        validate_run('local', path, '', ())


def test_launcher_report_valid_example_still_accepted(tmp_path):
    from patchtrace.ghidriff_launch.validate import validate_run
    path = tmp_path / 'report.json'
    path.write_text(_report(), encoding='utf-8')
    assert validate_run('local', path, '', ())['mode'] == 'local'
