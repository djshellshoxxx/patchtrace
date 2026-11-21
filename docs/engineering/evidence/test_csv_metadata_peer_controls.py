"""Independent public CSV v2 controls, including the documented reader."""
from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path

import pytest
from test_strings_delta import PAIRING, sha, table

from patchtrace.strings import contracts as c
from patchtrace.strings import export
from patchtrace.strings.delta import compute_delta
from patchtrace.strings.table import FLAG_SECRET


def records(path):
    parsed = list(csv.reader(io.StringIO(path.read_bytes().decode(), newline='')))
    assert len(parsed[0]) == 2 and parsed[0][0] == 'strings-export-csv/2'
    assert parsed[1] == list(export.CSV_COLUMNS)
    assert all(len(row) == len(export.CSV_COLUMNS) for row in parsed[2:])
    return json.loads(parsed[0][1]), [dict(zip(parsed[1], row, strict=True)) for row in parsed[2:]]


@pytest.mark.parametrize('secret,flags', [
    ('AKIAIOSFODNN7EXAMPLE', 0), ('reviewer private passphrase', FLAG_SECRET),
])
@pytest.mark.parametrize('reveal', [False, True])
def test_actual_delta_redaction_and_reveal_do_not_duplicate_raw_values_in_metadata(tmp_path, secret, flags, reveal):
    delta = compute_delta(table('older', []), table('newer', [secret], flags=flags), pairing=PAIRING)
    assert secret not in delta.changes[0].display
    target = tmp_path / 'public.csv'
    result = export.export_delta(delta, target, fmt='csv', reveal={sha(secret).hex(): secret} if reveal else None)
    metadata, rows = records(target)
    assert secret not in json.dumps(metadata)
    assert metadata['redacted'] is result.redacted is (not reveal)
    assert len(rows) == result.rows == 1
    assert (rows[0]['display'] == secret) is reveal
    assert (secret in target.read_text()) is reveal
    assert result.sha256 == hashlib.sha256(target.read_bytes()).hexdigest()


def test_actual_no_change_delta_has_only_metadata_and_header(tmp_path):
    delta = compute_delta(table('older', ['unchanged item']), table('newer', ['unchanged item']), pairing=PAIRING)
    assert delta.changes == ()
    target = tmp_path / 'empty.csv'
    result = export.export_delta(delta, target, fmt='csv')
    metadata, rows = records(target)
    assert rows == [] and result.rows == 0
    assert metadata['counts']['both'] == 1
    assert metadata['basis']['older_basis_digest'] == delta.older_basis_digest
    assert metadata['basis']['newer_basis_digest'] == delta.newer_basis_digest
    assert metadata['truncated'] is False and metadata['lineage_groups'] == []


def linked_delta(count=1, label=None):
    changes = []
    for i in range(count):
        group = label if label is not None else f'{i:08d}:' + 'x' * 119
        link = c.StringLink(tier='L1', function=c.FunctionRef(side='newer', rva=i, name='function'),
                            pair_status='modified', lineage_group=group, evidence_ref=f'run#{i}')
        changes.append(c.StringChange(
            id=hashlib.sha256(f'change{i}'.encode()).hexdigest(),
            value_sha256=hashlib.sha256(f'value{i}'.encode()).hexdigest(), display=f'value{i}', length=6,
            status='only-newer', newer=c.SideObservation(types=('static',), encodings=('ASCII',), offsets=(i,)),
            links=(link,), review_tier=5,
        ))
    return c.StringsDelta(older_basis_digest='a' * 64, newer_basis_digest='b' * 64, comparable=True,
                         harmonized=c.Harmonized(min_length=4, types=('static',)),
                         counts={'only-newer': count}, changes=tuple(changes))


def test_control_and_formula_like_lineage_remains_data_in_both_csv_sections(tmp_path):
    text = '@SUM(1,2)\r\n"quoted"\x00\u2028雪'
    delta = linked_delta(label=text).model_copy(update={'basis_notes': (text,)})
    target = tmp_path / 'quoted.csv'
    export.export_delta(delta, target, fmt='csv')
    metadata, rows = records(target)
    assert metadata['lineage_groups'] == [text] and metadata['basis']['notes'] == [text]
    assert rows[0]['lineage_groups'] == "'" + text
    first_line = target.read_text().splitlines()[0]
    assert '\x00' not in first_line and '\u2028' not in first_line and '雪' not in first_line
    assert len(rows) == 1


def test_documented_reader_handles_valid_large_lineage_metadata(tmp_path):
    delta = linked_delta(count=1200)
    target = tmp_path / 'large.csv'
    result = export.export_delta(delta, target, fmt='csv')
    specification = Path('docs/specs/program-e/WB3-integration-plan.md').read_text()
    section = specification.split('### Export encoding (CSV metadata repair, 2026-11-19)', 1)[1]
    example = section.split('```python\n', 1)[1].split('```', 1)[0]
    namespace = {'path': target}
    before = csv.field_size_limit()
    try:
        exec(compile(example, '<documented local-export reader>', 'exec'), namespace)
        after = csv.field_size_limit()
    finally:
        csv.field_size_limit(before)
    assert after == before
    assert len(namespace['metadata']['lineage_groups']) == 1200
    assert len(namespace['rows']) == result.rows == 1200


def reader_example():
    specification = Path('docs/specs/program-e/WB3-integration-plan.md').read_text()
    section = specification.split('### Export encoding (CSV metadata repair, 2026-11-19)', 1)[1]
    return section.split('```python\n', 1)[1].split('```', 1)[0]


def test_documented_reader_refuses_file_beyond_its_explicit_budget(tmp_path):
    target = tmp_path / 'over-budget.csv'
    with target.open('wb') as stream:
        stream.truncate(8 * 1024 * 1024 + 1)
    before = csv.field_size_limit()
    try:
        with pytest.raises(ValueError, match='budget'):
            exec(compile(reader_example(), '<documented local-export reader>', 'exec'), {'path': target})
        after = csv.field_size_limit()
    finally:
        csv.field_size_limit(before)
    assert after == before


@pytest.mark.parametrize('previous_limit', [17, 16 * 1024 * 1024])
def test_documented_reader_restores_global_limit_after_invalid_marker(tmp_path, previous_limit):
    target = tmp_path / 'unsupported.csv'
    target.write_text('strings-export-csv/999,{}\nid,status\n')
    original = csv.field_size_limit(previous_limit)
    try:
        with pytest.raises(ValueError, match='Unsupported strings CSV encoding'):
            exec(compile(reader_example(), '<documented local-export reader>', 'exec'), {'path': target})
        assert csv.field_size_limit() == previous_limit
    finally:
        csv.field_size_limit(original)
