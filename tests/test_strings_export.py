"""WB3-S6 export: redacted by default, atomic, no clobber without --force, CSV formula guard, basis recorded."""
from __future__ import annotations

import csv
import io
import json

import pytest
from test_strings_delta import PAIRING, sha, table

from patchtrace.strings import export
from patchtrace.strings.contracts import StringsDelta, StringsError
from patchtrace.strings.delta import compute_delta

SECRET = 'AKIAIOSFODNN7EXAMPLE'


@pytest.fixture(scope='module')
def delta():
    older = table('older', ['kept string one', 'Old message here'])
    newer = table('newer', ['kept string one', 'index %u exceeds length %u', SECRET, '=cmd|calc!A1 injected'])
    return compute_delta(older, newer, pairing=PAIRING)


def read(path):
    return path.read_bytes().decode('utf-8')


@pytest.mark.parametrize('fmt', ['json', 'csv'])
def test_secret_is_redacted_in_every_format(delta, tmp_path, fmt):
    result = export.export_delta(delta, tmp_path / f'out.{fmt}', fmt=fmt)
    assert SECRET not in read(tmp_path / f'out.{fmt}') and result.redacted and result.rows == 4


def test_show_secrets_reveals_only_the_given_values(delta, tmp_path):
    reveal = {sha(SECRET).hex(): SECRET}
    result = export.export_delta(delta, tmp_path / 'out.json', fmt='json', reveal=reveal)
    document = json.loads(read(tmp_path / 'out.json'))
    assert not result.redacted and document['redacted'] is False
    assert SECRET in {c['display'] for c in document['changes']}


def test_json_records_basis_and_lineage(delta, tmp_path):
    export.export_delta(delta, tmp_path / 'out.json', fmt='json')
    document = json.loads(read(tmp_path / 'out.json'))
    assert document['contract'] == 'strings-export/1' and document['scope'] == 'changed'
    assert document['basis']['older_basis_digest'] == delta.older_basis_digest
    assert document['basis']['harmonized']['min_length'] >= 1 and 'lineage_groups' in document


def test_csv_neutralises_formulas_and_round_trips(delta, tmp_path):
    export.export_delta(delta, tmp_path / 'out.csv', fmt='csv')
    rows = list(csv.DictReader(io.StringIO(read(tmp_path / 'out.csv'), newline='')))
    shown = {r['display'] for r in rows}
    assert "'=cmd|calc!A1 injected" in shown and 'Old message here' in shown
    assert list(rows[0]) == list(export.CSV_COLUMNS) and b'\r\n' not in (tmp_path / 'out.csv').read_bytes()


def test_output_is_deterministic(delta, tmp_path):
    first = export.export_delta(delta, tmp_path / 'a.json', fmt='json')
    second = export.export_delta(delta, tmp_path / 'b.json', fmt='json')
    assert first.sha256 == second.sha256


def test_never_overwrites_without_force(delta, tmp_path):
    target = tmp_path / 'out.json'
    target.write_text('precious', encoding='utf-8')
    with pytest.raises(StringsError) as raised:
        export.export_delta(delta, target, fmt='json')
    assert raised.value.code == 'PT-STR-EXPORT' and read(target) == 'precious'
    export.export_delta(delta, target, fmt='json', force=True)
    assert json.loads(read(target))['contract'] == 'strings-export/1'


def test_failed_write_leaves_no_partial_file(delta, tmp_path, monkeypatch):
    target = tmp_path / 'out.json'

    def broken(src, dst):
        raise OSError(13, 'denied')
    monkeypatch.setattr(export.os, 'replace', broken)
    with pytest.raises(StringsError) as raised:
        export.export_delta(delta, target, fmt='json')
    assert raised.value.code == 'PT-STR-EXPORT' and list(tmp_path.iterdir()) == []


def test_missing_folder_and_folder_target_are_typed_errors(delta, tmp_path):
    for target in (tmp_path / 'no' / 'out.json', tmp_path):
        with pytest.raises(StringsError) as raised:
            export.export_delta(delta, target, fmt='json', force=True)
        assert raised.value.code == 'PT-STR-EXPORT' and str(tmp_path) not in raised.value.message


def test_scope_changed_leaves_out_moved_strings(delta):
    first = delta.changes[0]
    moved = first.model_copy(update={'status': 'both', 'older': first.newer})
    mixed = delta.model_copy(update={'changes': (moved, *delta.changes[1:])})
    assert len(export.selected(mixed, 'all')) == 4 and len(export.selected(mixed, 'changed')) == 3


def test_not_comparable_delta_is_refused(tmp_path):
    refused = StringsDelta(older_basis_digest='a' * 64, newer_basis_digest='b' * 64, comparable=False)
    with pytest.raises(StringsError) as raised:
        export.export_delta(refused, tmp_path / 'out.json', fmt='json')
    assert raised.value.code == 'PT-STR-BASIS' and not (tmp_path / 'out.json').exists()
