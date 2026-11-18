"""Bounded authored SQLite fixtures; no native BinDiff execution."""
from __future__ import annotations

import threading
from pathlib import Path

import pytest
from bindiff_builder import NEW, OLD, build
from test_bindiff_inputs import accepted

from patchtrace.jobs import ProcessResult
from patchtrace.secondary import bindiff, bindiff_run
from patchtrace.secondary.bindiff_inputs import bind_pair
from patchtrace.secondary.contracts import Capability, SecondaryError


def test_function_count_rejected_before_model_allocation(tmp_path, monkeypatch):
    path = build(tmp_path / 'x.BinDiff', functions=[(i, i, 'a', i, 'b', 1., 1., 0, 7) for i in range(4)])
    monkeypatch.setattr(bindiff, 'MAX_FUNCTIONS', 3, raising=False)
    def forbidden(**kwargs):
        pytest.fail('function models allocated before the bounded row-count check')
    monkeypatch.setattr(bindiff, 'SecondaryMatch', forbidden)
    with pytest.raises(SecondaryError) as exc:
        bindiff.import_bindiff(path, OLD, NEW)
    assert exc.value.code == 'PT-SECONDARY-LIMIT'


@pytest.mark.parametrize('limit,value', [('MAX_SCHEMA_OBJECTS', 1), ('MAX_ALGORITHMS', 1),
                                         ('MAX_TOTAL_NAME_CHARS', 2)])
def test_metadata_and_text_budgets(tmp_path, monkeypatch, limit, value):
    monkeypatch.setattr(bindiff, limit, value, raising=False)
    with pytest.raises(SecondaryError) as exc:
        bindiff.import_bindiff(build(tmp_path / 'x.BinDiff'), OLD, NEW)
    assert exc.value.code == 'PT-SECONDARY-LIMIT'


def test_post_exit_output_directory_replacement_is_typed(tmp_path):
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    pair = bind_pair(accepted(inputs, 'older', OLD), accepted(inputs, 'newer', NEW), OLD, NEW)
    cap = Capability(engine='bindiff', supported=True, version='8', path='/fake/bindiff', supports_json=False)
    def runner(argv, **kwargs):
        out = Path(kwargs['cwd']).parent / 'out'
        out.rmdir()
        out.write_bytes(b'not a directory')
        return ProcessResult(0, '')
    with pytest.raises(SecondaryError) as exc:
        bindiff_run.execute(cap, pair, tmp_path / 'raw', cancel=threading.Event(), timeout_seconds=60,
                            runner=runner, parent_dir=tmp_path)
    assert exc.value.code == 'PT-SECONDARY-RUN' and exc.value.kind == 'output-invalid'
    assert not (tmp_path / 'raw').exists()


def test_missing_cli_import_is_rejected_without_project_writes(tmp_path, capsys):
    from patchtrace import cli
    from patchtrace.service import ProjectService
    service = ProjectService.sample(tmp_path / 'case')
    root = service.root
    service.close()
    def snapshot():
        return {p.relative_to(root).as_posix(): p.read_bytes() if p.is_file() else None
                for p in root.rglob('*')}
    before = snapshot()
    assert cli.main(['secondary', 'import-bindiff', str(root), str(tmp_path / 'missing.BinDiff'), '--json']) == 2
    capsys.readouterr()
    assert snapshot() == before


def test_final_output_limit_is_checked_even_between_supervision_polls(tmp_path):
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    pair = bind_pair(accepted(inputs, 'older', OLD), accepted(inputs, 'newer', NEW), OLD, NEW)
    cap = Capability(engine='bindiff', supported=True, version='8', path='/fake/bindiff', supports_json=False)
    def runner(argv, **kwargs):
        (Path(kwargs['cwd']).parent / 'out' / bindiff_run.EXPECTED_NAME).write_bytes(b'x' * 9)
        return ProcessResult(0, '')
    with pytest.raises(SecondaryError) as exc:
        bindiff_run.execute(cap, pair, tmp_path / 'raw', cancel=threading.Event(), timeout_seconds=60,
                            runner=runner, parent_dir=tmp_path, output_limit=8)
    assert exc.value.code == 'PT-SECONDARY-LIMIT' and exc.value.kind == 'output-limit'
    assert not (tmp_path / 'raw').exists()


def test_sqlite_record_size_is_bounded_before_python_materialization(tmp_path, monkeypatch):
    monkeypatch.setattr(bindiff, 'MAX_SQLITE_RECORD_BYTES', 1024)
    path = build(tmp_path / 'x.BinDiff', functions=[(1, 1, 'x' * 2048, 2, 'b', 1., 1., 0, 7)])
    with pytest.raises(SecondaryError) as exc:
        bindiff.import_bindiff(path, OLD, NEW)
    assert exc.value.code == 'PT-SECONDARY-LIMIT'


def test_exact_count_and_text_budgets_accept_complete_fixture(tmp_path, monkeypatch):
    import sqlite3
    path = build(tmp_path / 'x.BinDiff')
    with sqlite3.connect(path) as database:
        objects = database.execute('SELECT COUNT(*) FROM sqlite_master').fetchone()[0]
    monkeypatch.setattr(bindiff, 'MAX_FUNCTIONS', 2)
    monkeypatch.setattr(bindiff, 'MAX_SCHEMA_OBJECTS', objects)
    monkeypatch.setattr(bindiff, 'MAX_ALGORITHMS', 2)
    monkeypatch.setattr(bindiff, 'MAX_TOTAL_NAME_CHARS', 12)  # Foo/Foo + Bar/Bar
    result = bindiff.import_bindiff(path, OLD, NEW)
    assert len(result.matches) == 2
    assert [(row.older_name, row.newer_name) for row in result.matches] == [('Foo', 'Foo'), ('Bar', 'Bar')]
