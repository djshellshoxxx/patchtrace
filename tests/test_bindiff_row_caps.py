"""SPEC-29 §7.2 / bindiff-plan S6-D5: per-table row caps in the `.BinDiff` importer.

Rows are counted before any is turned into a record, so a hostile database with millions of `function` rows
is refused as `PT-SECONDARY-LIMIT` instead of becoming millions of objects. Caps are monkeypatched small.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from bindiff_builder import NEW, OLD, build

from patchtrace import cli
from patchtrace.secondary import bindiff
from patchtrace.secondary.bindiff import import_bindiff
from patchtrace.secondary.contracts import SecondaryError
from patchtrace.service import ProjectService

FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'secondary'
REAL = json.loads((FIXTURES / 'bindiff-v8-real-on-synthetic.json').read_text(encoding='utf-8'))
SYNTHETIC = json.loads((FIXTURES / 'bindiff-synthetic.json').read_text(encoding='utf-8'))


def functions(count, name='f'):
    return [(i, 0x140000000 + i * 16, f'{name}{i}', 0x150000000 + i * 16, f'{name}{i}', 0.5, 0.5, 0, 7)
            for i in range(1, count + 1)]


def limit(path, *pair):
    with pytest.raises(SecondaryError) as info:
        import_bindiff(path, *(pair or (OLD, NEW)))
    assert info.value.code == 'PT-SECONDARY-LIMIT'
    return info.value


@pytest.mark.parametrize('rows, refused', [(3, False), (4, True)], ids=['at-cap', 'over-cap'])
def test_function_rows_are_capped(tmp_path, monkeypatch, rows, refused):
    monkeypatch.setattr(bindiff, 'MAX_FUNCTION_ROWS', 3)
    path = build(tmp_path / 'x.BinDiff', functions=functions(rows))
    if refused:
        assert limit(path).message == 'BinDiff table function exceeds 3 rows'
    else:
        assert len(import_bindiff(path, OLD, NEW).matches) == 3


@pytest.mark.parametrize('instructions, refused', [(1, False), (2, True)], ids=['at-cap', 'over-cap'])
def test_basicblock_and_instruction_rows_count_toward_the_total(tmp_path, monkeypatch, instructions, refused):
    monkeypatch.setattr(bindiff, 'MAX_DETAIL_ROWS', 5)  # 2 function + 2 basicblock + n instruction rows
    extra = ['INSERT INTO basicblock VALUES(1, 1, 1, 1, 1, 0)', 'INSERT INTO basicblock VALUES(2, 2, 2, 2, 1, 0)']
    extra += [f'INSERT INTO instruction VALUES(1, {i}, {i})' for i in range(instructions)]
    path = build(tmp_path / 'x.BinDiff', extra=extra)
    if refused:
        assert limit(path).message == 'BinDiff tables function, basicblock, instruction exceed 5 rows in total'
    else:
        assert len(import_bindiff(path, OLD, NEW).matches) == 2


@pytest.mark.parametrize('table', ['functionalgorithm', 'basicblockalgorithm'], ids=['fn', 'bb'])
def test_algorithm_tables_are_capped(tmp_path, monkeypatch, table):
    monkeypatch.setattr(bindiff, 'MAX_ALGORITHM_ROWS', 2)
    assert len(import_bindiff(build(tmp_path / 'ok.BinDiff'), OLD, NEW).matches) == 2  # 2 algorithm rows: at cap
    path = build(tmp_path / 'x.BinDiff', extra=[f"INSERT INTO {table} VALUES({i}, 'a{i}')" for i in (20, 21, 22)])
    assert limit(path).message == f'BinDiff table {table} exceeds 2 rows'


def test_caps_apply_before_any_row_is_read(tmp_path, monkeypatch):
    monkeypatch.setattr(bindiff, 'MAX_FUNCTION_ROWS', 1)
    rows = [(i, a, n, a, n, 0.5, 0.5, 0, 99) for i, a, n, *_ in functions(2)]  # algorithm 99 has no row
    path = build(tmp_path / 'x.BinDiff', version='not bindiff', functions=rows)
    assert limit(path).message == 'BinDiff table function exceeds 1 rows'  # not the metadata/algorithm INPUT


def test_limit_message_holds_no_path_or_function_name(tmp_path, monkeypatch):
    monkeypatch.setattr(bindiff, 'MAX_FUNCTION_ROWS', 1)
    folder = tmp_path / 'SecretFolder'
    folder.mkdir()
    error = limit(build(folder / 'SecretFile.BinDiff', functions=functions(2, name='SecretName')))
    assert 'secret' not in str(error).lower() and str(tmp_path) not in str(error)


@pytest.mark.parametrize('table, cap', [('functionalgorithm', 'MAX_ALGORITHM_ROWS'), ('function', 'MAX_FUNCTION_ROWS')],
                         ids=['fn-alg', 'fn'])
def test_running_counter_backstops_a_count_that_disagrees_with_the_rows(tmp_path, monkeypatch, table, cap):
    monkeypatch.setattr(bindiff, cap, 1)
    monkeypatch.setattr(bindiff, '_row_counts', lambda db: dict.fromkeys(bindiff._COUNTED, 0))  # corrupt COUNT(*)
    assert limit(build(tmp_path / 'x.BinDiff')).message == f'BinDiff table {table} exceeds 1 rows'


@pytest.mark.parametrize('name, pair, counts', [
    ('bindiff-v8-real-on-synthetic.BinDiff', (REAL['inputs']['older_sha256'], REAL['inputs']['newer_sha256']),
     (20, 20, 190)),
    ('bindiff-synthetic-pair.BinDiff', (SYNTHETIC['older_sha256'], SYNTHETIC['newer_sha256']), (5, 4, 5)),
], ids=['real-v8', 'synthetic'])
def test_committed_goldens_import_unchanged_and_sit_exactly_at_tight_caps(monkeypatch, name, pair, counts):
    golden = FIXTURES / name
    assert len(import_bindiff(golden, *pair).matches) == counts[0]  # default caps
    caps = dict(zip(('MAX_FUNCTION_ROWS', 'MAX_ALGORITHM_ROWS', 'MAX_DETAIL_ROWS'), counts, strict=True))
    for constant, value in caps.items():
        monkeypatch.setattr(bindiff, constant, value)
    assert len(import_bindiff(golden, *pair).matches) == counts[0]  # every cap exactly at the file's counts
    for constant, value in caps.items():
        monkeypatch.setattr(bindiff, constant, value - 1)
        assert f' {value - 1} rows' in limit(golden, *pair).message
        monkeypatch.setattr(bindiff, constant, value)


def test_cli_import_over_cap_exits_3_and_stores_nothing(tmp_path, capsys, monkeypatch):
    service = ProjectService.sample(tmp_path / 'case')
    sides = {a.side: a.sha256 for a in service.project.artifacts}
    root = service.root
    service.close()
    monkeypatch.setattr(bindiff, 'MAX_FUNCTION_ROWS', 1)
    db = build(tmp_path / 'x.BinDiff', hashes=(sides['older'], sides['newer']))
    assert cli.main(['secondary', 'import-bindiff', str(root), str(db), '--json']) == 3
    assert 'PT-SECONDARY-LIMIT' in json.loads(capsys.readouterr().out)['error']
    assert cli.main(['secondary', 'reconcile', str(root), '--json']) == 4  # no match set was stored
