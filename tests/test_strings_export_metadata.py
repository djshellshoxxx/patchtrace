"""CSV provenance survives empty selections without inventing a string finding."""
from __future__ import annotations

import csv
import hashlib
import io
import json

import pytest

from patchtrace.strings import contracts as c
from patchtrace.strings import export

SECRET = 'AKIAIOSFODNN7EXAMPLE'


def empty():
    return c.StringsDelta(
        older_basis_digest='a' * 64, newer_basis_digest='b' * 64, comparable=True,
        harmonized=c.Harmonized(min_length=4, types=('static',)),
        counts={'only-older': 0, 'only-newer': 0},
    )


def read_csv(path):
    source = io.StringIO(path.read_bytes().decode('utf-8'), newline='')
    preamble = next(csv.reader(source))
    assert len(preamble) == 2 and preamble[0] == 'strings-export-csv/2'
    metadata = json.loads(preamble[1])
    reader = csv.DictReader(source)
    assert reader.fieldnames == list(export.CSV_COLUMNS)
    return metadata, list(reader), preamble


@pytest.mark.parametrize('difference', ['basis', 'truncated', 'redaction'])
def test_empty_csv_preserves_distinct_document_provenance(tmp_path, difference):
    original = empty()
    altered, reveal = original, None
    if difference == 'basis':
        altered = original.model_copy(update={'older_basis_digest': 'c' * 64, 'newer_basis_digest': 'd' * 64})
    elif difference == 'truncated':
        altered = original.model_copy(update={'truncated': True})
    else:
        reveal = {}
    assert export.document(original) != export.document(altered, reveal=reveal)
    first, second = tmp_path / 'first.csv', tmp_path / 'second.csv'
    left = export.export_delta(original, first, fmt='csv')
    right = export.export_delta(altered, second, fmt='csv', reveal=reveal)
    assert left.rows == right.rows == 0
    assert first.read_bytes() != second.read_bytes()
    assert read_csv(first)[1] == read_csv(second)[1] == []


@pytest.fixture
def populated():
    observations = c.SideObservation(types=('static',), encodings=('ASCII',), offsets=(0x600,))
    link = c.StringLink(tier='L1', function=c.FunctionRef(side='newer', rva=0x2000, name='parse'),
                        pair_status='modified', lineage_group='ghidra:one', evidence_ref='run-1#0')
    change = c.StringChange(
        id='1' * 64, value_sha256=hashlib.sha256(SECRET.encode()).hexdigest(),
        display='[redacted secret-like string]', length=len(SECRET), status='only-newer',
        newer=observations, links=(link,), review_tier=5, cues=('secret-like',), reasons=('test fixture',),
    )
    moved = c.StringChange(
        id='2' * 64, value_sha256='3' * 64, display='moved string', length=12, status='both',
        older=observations, newer=observations, review_tier=7,
        links=(link.model_copy(update={'lineage_group': 'bytes:two'}),),
    )
    anchor = c.StringAnchorHit(anchor_id='anchor-1', kind='api-name', match='exact', string_id='3' * 64,
                               presence_older=True, presence_newer=True, lineage_group='advisory:one')
    return c.StringsDelta(
        older_basis_digest='a' * 64, newer_basis_digest='b' * 64, comparable=True,
        harmonized=c.Harmonized(min_length=6, types=('static',)),
        basis_notes=('different minima',), counts={'only-newer': 1, 'both': 1},
        changes=(change, moved), truncated=True, anchors=c.AnchorJoin(digest='e' * 64, hits=(anchor,)),
    )


@pytest.mark.parametrize('scope, count', [('changed', 1), ('all', 2)])
@pytest.mark.parametrize('has_rows', [False, True])
def test_metadata_and_data_rows_round_trip_for_empty_and_scoped_exports(populated, tmp_path, scope, count, has_rows):
    delta = populated if has_rows else populated.model_copy(update={'changes': ()})
    target = tmp_path / 'out.csv'
    result = export.export_delta(delta, target, fmt='csv', scope=scope)
    metadata, rows, _preamble = read_csv(target)
    assert metadata['contract'] == 'strings-export/1'
    assert metadata['scope'] == scope and metadata['redacted'] is True
    assert metadata['basis'] == {
        'older_basis_digest': 'a' * 64, 'newer_basis_digest': 'b' * 64,
        'harmonized': {'min_length': 6, 'types': ['static']}, 'notes': ['different minima'],
    }
    assert metadata['counts'] == {'only-newer': 1, 'both': 1}
    assert metadata['truncated'] is True
    assert metadata['anchors'] == {'digest': 'e' * 64, 'hits': 1}
    expected_lineage = ([] if not has_rows else ['ghidra:one'] if scope == 'changed'
                        else ['bytes:two', 'ghidra:one'])
    assert metadata['lineage_groups'] == expected_lineage and 'changes' not in metadata
    assert len(rows) == result.rows == (count if has_rows else 0)
    assert [r['id'] for r in rows] == [c.id for c in export.selected(delta, scope)]
    assert len(list(csv.reader(io.StringIO(target.read_text())))) == len(rows) + 2
    assert result.sha256 == hashlib.sha256(target.read_bytes()).hexdigest()
    assert SECRET not in target.read_text()


@pytest.mark.parametrize('reveal', [None, {}, {hashlib.sha256(SECRET.encode()).hexdigest(): SECRET}])
def test_metadata_records_redaction_without_duplicating_revealed_values(populated, tmp_path, reveal):
    target = tmp_path / 'out.csv'
    result = export.export_delta(populated, target, fmt='csv', reveal=reveal)
    metadata, rows, preamble = read_csv(target)
    assert result.redacted == metadata['redacted'] == (reveal is None)
    assert SECRET not in preamble[1] and '[redacted' not in preamble[1]
    assert (SECRET in rows[0]['display']) == bool(reveal)


@pytest.mark.parametrize('prefix', ['=', '+', '-', '@', '\t', '\r'])
def test_metadata_quoting_and_finding_formula_guard_are_independent(populated, tmp_path, prefix):
    text = prefix + 'HYPERLINK("x,y")\r\nquote " and Unicode 雪'
    delta = populated.model_copy(update={'basis_notes': (text,)})
    target = tmp_path / 'out.csv'
    export.export_delta(delta, target, fmt='csv', reveal={populated.changes[0].value_sha256: text})
    metadata, rows, preamble = read_csv(target)
    assert metadata['basis']['notes'] == [text]
    assert all(not cell.startswith(('=', '+', '-', '@', '\t', '\r')) for cell in preamble)
    assert preamble[1].startswith('{') and '\r' not in preamble[1] and '\n' not in preamble[1]
    assert rows[0]['display'] == "'" + text
    assert len(rows) == 1


def test_csv_bytes_are_deterministic_and_json_encoding_is_unchanged(populated, tmp_path):
    first, second = tmp_path / 'first.csv', tmp_path / 'second.csv'
    one = export.export_delta(populated, first, fmt='csv')
    two = export.export_delta(populated, second, fmt='csv')
    assert one.sha256 == two.sha256 and first.read_bytes() == second.read_bytes()
    doc = export.document(populated)
    assert export.render(doc, 'json') == (json.dumps(doc, sort_keys=True, indent=2) + '\n').encode('utf-8')


def test_legacy_header_first_consumption_cannot_mistake_preamble_for_a_finding(populated, tmp_path):
    target = tmp_path / 'out.csv'
    export.export_delta(populated, target, fmt='csv')
    old_reader = csv.DictReader(io.StringIO(target.read_text(), newline=''))
    assert old_reader.fieldnames[0] == 'strings-export-csv/2'
    assert 'id' not in old_reader.fieldnames and 'display' not in old_reader.fieldnames
