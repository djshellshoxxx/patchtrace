"""Regressions from the 2026-10-28 hostile-input sweep (SECURITY_REVIEW.md F1, F3, F4, F6, F7, F8).

Each input used to escape its parser as an untagged exception (or, for F1, cost seconds and gigabytes before
failing). Every case must now fail closed with the module's own error type, and an import must stage nothing.
"""
from __future__ import annotations

import json
import struct

import pytest

from patchtrace.acquisition import winbindex
from patchtrace.ingestion import safe_path
from patchtrace.pe_overview import tables
from patchtrace.persistence import MAX_JSON_DEPTH, strict_json
from patchtrace.sample import synthetic_pe
from patchtrace.secondary import bindiff_probe, rzdiff
from patchtrace.secondary.contracts import SecondaryError
from patchtrace.service import ProjectService

SHA_A, SHA_B = 'a' * 64, 'b' * 64


def nested(depth: int) -> str:
    return '[' * depth + '0' + ']' * depth


# ---- F4: nesting depth is bounded at the shared strict-JSON boundary --------------------------------------------

def test_strict_json_accepts_the_depth_limit_and_refuses_one_more():
    assert strict_json(nested(MAX_JSON_DEPTH))
    with pytest.raises(ValueError, match=f'PT-SCHEMA: JSON nesting exceeds {MAX_JSON_DEPTH} levels'):
        strict_json(nested(MAX_JSON_DEPTH + 1))
    with pytest.raises(ValueError, match='PT-SCHEMA'):
        strict_json('{"a": ' * 200 + '0' + '}' * 200)


@pytest.fixture
def service(tmp_path):
    (tmp_path / 'o.dll').write_bytes(synthetic_pe(0))
    (tmp_path / 'n.dll').write_bytes(synthetic_pe(1))
    svc = ProjectService.create(tmp_path / 'o.dll', tmp_path / 'n.dll', 'T', tmp_path / 'proj')
    yield svc
    svc.close()


def ghidriff(service, modified_old: dict, **extra) -> str:
    sha = {artifact.side: artifact.sha256 for artifact in service.project.artifacts}
    return json.dumps({'old_meta': {'Executable SHA256': sha['older']}, 'new_meta': {'Executable SHA256': sha['newer']},
                       'functions': {'added': [], 'deleted': [], 'modified': [
                           {'old': modified_old, 'new': {'name': 'f'}, **extra}]}})


@pytest.mark.parametrize('depth', [330, 600])  # used to fail in pydantic dump (330) and deepcopy (600)
def test_deeply_nested_ghidriff_metadata_is_refused_before_anything_is_staged(tmp_path, service, depth):
    text = ghidriff(service, {'name': 'f', 'x': 'DEEP'}).replace('"DEEP"', nested(depth))
    raw = tmp_path / 'diff.json'
    raw.write_text(text, encoding='utf-8')
    with pytest.raises(ValueError, match='PT-SCHEMA'):
        service.import_diff(raw)
    runs = service.root / 'runs'
    assert not runs.exists() or not [path for path in runs.rglob('*') if path.is_file()]


# ---- F3: a huge integer ratio is a schema error, not an OverflowError -------------------------------------------

def test_a_huge_integer_ratio_is_a_schema_error(tmp_path, service):
    raw = tmp_path / 'diff.json'
    raw.write_text(ghidriff(service, {'name': 'f'}).replace('{"name": "f"}}]', '{"name": "f"}, "ratio": '
                                                            + '1' + '0' * 400 + '}]', 1), encoding='utf-8')
    assert '"ratio": 1000' in raw.read_text(encoding='utf-8')
    with pytest.raises(ValueError, match='PT-SCHEMA: upstream ratio'):
        service.import_diff(raw)


# ---- F6: Winbindex records with a lone surrogate escape -----------------------------------------------------------

def test_winbindex_lone_surrogate_skips_the_entry_instead_of_escaping_untagged():
    # Entry-local policy (docs/specs/acquisition.md, 2026-10-29): the entry is skipped and counted; no
    # UnicodeEncodeError escapes when the record is hashed.
    document = ('{"' + SHA_A + '": {"fileInfo": {"sha256": "' + SHA_A + '", "size": 1, "timestamp": 1, '
                '"machineType": 34404}, "x": "\\ud800"}}').encode('ascii')
    result = winbindex.parse(document, 'afd.sys', '2026-01-01', compressed=False)
    assert result.candidates == () and result.skipped == 1


# ---- F8: crafted relative paths inside a project file -------------------------------------------------------------

@pytest.mark.parametrize('relative', ['artifacts/a\x00b', 'artifacts/' + 'x' * 300, 'artifacts/\ud800',
                                      'artifacts/' + 'é' * 128])  # 256 UTF-8 bytes
def test_safe_path_refuses_unusable_components_with_a_storage_error(tmp_path, relative):
    # Refused by PatchTrace itself on every OS; Windows would accept the lone surrogate (qa-windows on ebbef02).
    with pytest.raises(ValueError, match='PT-STORAGE: project path has an invalid or over-long component'):
        safe_path(tmp_path, relative)


@pytest.mark.parametrize('relative', ['artifacts/older.bin', 'artifacts/' + 'é' * 127 + 'x'])  # 255 bytes
def test_safe_path_still_accepts_a_normal_relative_path(tmp_path, relative):
    assert safe_path(tmp_path, relative) == tmp_path.resolve() / relative


# ---- F7: rz-diff and BinDiff tool output ----------------------------------------------------------------------------

def test_rzdiff_deeply_nested_output_is_an_input_error():
    with pytest.raises(SecondaryError, match='not valid strict JSON'):
        rzdiff.parse_output(nested(20_000), '0.9.1', SHA_A, SHA_B)


def test_rzdiff_lone_surrogate_name_is_an_input_error():
    stdout = '[{"similarity":0,"type":"UNLIKE","original":{"addr":0,"name":"\\ud800","size":0},"modified":null}]'
    with pytest.raises(SecondaryError, match='not valid strict JSON'):
        rzdiff.parse_output(stdout, '0.9.1', SHA_A, SHA_B)


def test_tool_versions_with_absurd_digit_runs_are_unrecognised_not_crashes():
    digits = '9' * 4400  # beyond int()'s default 4300-digit conversion limit
    assert rzdiff.parse_version(f'rz-diff {digits}.1.2\n') is None
    assert bindiff_probe.parse_version(f'BinDiff {digits} (whatever)\n') is None
    assert rzdiff.parse_version('rz-diff 0.9.1\n') == ('0.9.1', (0, 9, 1))
    assert bindiff_probe.parse_version('BinDiff 8 (@1234)\n')[0] == 8


# ---- F1: base relocation blocks are bounded before they are walked ----------------------------------------------

def block(page: int, entries: list[int]) -> bytes:
    return struct.pack('<II', page, 8 + 2 * len(entries)) + b''.join(struct.pack('<H', e) for e in entries)


def test_a_block_declaring_more_entries_than_the_cap_is_refused_before_it_is_walked(monkeypatch):
    monkeypatch.setattr(tables, 'MAX_RELOCS', 4)
    warnings: list[str] = []
    with pytest.raises(tables.PeTableError, match='too many base relocations'):
        tables.parse_base_relocations(block(0x1000, [0] * 6), warnings)  # zero-width ABSOLUTE padding counts
    assert warnings == []


def test_unknown_relocation_types_are_reported_once_and_known_ones_kept():
    unknown = next(kind for kind in range(16) if kind not in tables.RELOC_WIDTH)
    known = next(kind for kind, width in tables.RELOC_WIDTH.items() if width)
    warnings: list[str] = []
    entries = tables.parse_base_relocations(
        block(0x2000, [(unknown << 12) | 0x10] * 50 + [(known << 12) | 0x20]), warnings)
    assert warnings == [f'relocation type {unknown} masked as 8 bytes']
    assert (0x2010, 8) in entries and (0x2020, tables.RELOC_WIDTH[known]) in entries and len(entries) == 51
