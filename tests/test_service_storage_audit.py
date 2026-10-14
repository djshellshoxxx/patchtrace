"""Regression tests from the service/storage bug hunt (docs/audits/service-storage-20261014.md)."""
from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest

import patchtrace.service as service_module
from patchtrace.models import AnalysisRun
from patchtrace.persistence import ProjectStore
from patchtrace.sample import sample_diff, synthetic_pe
from patchtrace.service import ProjectService


@pytest.fixture
def pair(tmp_path):
    older, newer = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    return older, newer


@pytest.fixture
def service(tmp_path, pair):
    with ProjectService.create(*pair, 'Audit', tmp_path / 'case') as svc:
        yield svc


def _rewrite_snapshot(root, mutate):
    connection = sqlite3.connect(root / 'project.sqlite3')
    try:
        data = json.loads(connection.execute('SELECT payload FROM current_snapshot').fetchone()[0])
        mutate(data)
        text = json.dumps(data, separators=(',', ':'))
        connection.execute('UPDATE current_snapshot SET payload=?, sha256=?',
                           (text, hashlib.sha256(text.encode()).hexdigest()))
        connection.commit()
    finally:
        connection.close()


# F1: a creation that never committed its first snapshot must not brick the directory.
def test_interrupted_creation_leftover_is_recycled_by_the_next_create(tmp_path, pair):
    root = tmp_path / 'case'
    ProjectStore(root, create=True).close()  # tables exist, no snapshot: the state a kill leaves behind
    with pytest.raises(ValueError, match='PT-STORAGE'):
        ProjectService.open(root)
    with ProjectService.create(*pair, 'Retry', root) as created:
        assert created.project.name == 'Retry'
    with ProjectService.open(root) as reopened:
        assert reopened.project.name == 'Retry'


def test_zero_byte_database_leftover_is_recycled(tmp_path, pair):
    root = tmp_path / 'case'
    root.mkdir()
    (root / 'project.sqlite3').write_bytes(b'')
    with ProjectService.create(*pair, 'Retry', root) as created:
        assert created.project.name == 'Retry'


def test_create_never_recycles_a_database_that_holds_a_snapshot(service, tmp_path, pair):
    root = service.root
    service.close()
    before = (root / 'project.sqlite3').read_bytes()
    with pytest.raises(ValueError, match='already exists'):
        ProjectService.create(*pair, 'Other', root)
    assert (root / 'project.sqlite3').read_bytes() == before
    with ProjectService.open(root) as reopened:
        assert reopened.project.name == 'Audit'


def test_ctrl_c_during_creation_removes_the_half_initialised_database(tmp_path, pair, monkeypatch):
    root = tmp_path / 'case'
    real = service_module.inspect_artifact

    def interrupted(path, side, project_root):
        artifact = real(path, side, project_root)
        if side == 'newer':
            raise KeyboardInterrupt
        return artifact

    monkeypatch.setattr(service_module, 'inspect_artifact', interrupted)
    with pytest.raises(KeyboardInterrupt):
        ProjectService.create(*pair, 'x', root)
    assert not (root / 'project.sqlite3').exists()
    monkeypatch.setattr(service_module, 'inspect_artifact', real)
    with ProjectService.create(*pair, 'Retry', root) as created:
        assert created.project.name == 'Retry'


# F2: every committed snapshot must be loadable again.
def test_save_refuses_free_form_value_that_load_could_not_parse(service):
    before = service.store.connection.execute('SELECT sha256 FROM current_snapshot').fetchone()[0]
    candidate = service.project.model_copy(deep=True)
    candidate.runs.append(AnalysisRun(status='failed', error='e', settings={'huge': 10 ** 5000}))
    with pytest.raises(ValueError, match='PT-SCHEMA'):
        service._commit(candidate)
    assert service.store.connection.execute('SELECT sha256 FROM current_snapshot').fetchone()[0] == before
    assert service.store.load() == service.project


def test_save_refuses_non_finite_typed_float_that_would_serialise_as_null(tmp_path):
    with ProjectService.sample(tmp_path / 'sample') as sample:
        candidate = sample.project.model_copy(deep=True)
        candidate.interpretations[0].duration_seconds = float('inf')
        with pytest.raises(ValueError, match='PT-SCHEMA') as caught:
            sample._commit(candidate)
        assert 'duration_seconds' in str(caught.value)
        assert sample.store.load() == sample.project
        root = sample.root
    ProjectService.open(root).close()


# F3: names that cannot be written as UTF-8 stay visible and storable.
def test_display_text_keeps_unencodable_code_units_visible():
    from patchtrace.ingestion import display_text
    assert display_text('plain ü.dll') == 'plain ü.dll'
    assert display_text('bad\udcff.dll') == 'bad\\udcff.dll'


def test_project_name_with_lone_surrogate_is_stored_escaped(tmp_path, pair):
    with ProjectService.create(*pair, 'a\ud800b', tmp_path / 'case') as created:
        assert created.project.name == 'a\\ud800b'
    with ProjectService.open(tmp_path / 'case') as reopened:
        assert reopened.project.name == 'a\\ud800b'


def test_input_file_name_with_lone_surrogate_is_stored_escaped(tmp_path, pair):
    bad = tmp_path / 'bad\udcff.dll'
    try:
        bad.write_bytes(synthetic_pe(2))
    except (OSError, UnicodeError):
        pytest.skip('this platform cannot create a file name containing a lone surrogate')
    with ProjectService.create(bad, pair[1], 'x', tmp_path / 'case') as created:
        assert created.project.artifacts[0].name == 'bad\\udcff.dll'


# F4: a rejected stale import must not leave its staged raw copy behind.
def test_stale_import_removes_its_staged_raw_copy(service, tmp_path):
    raw = tmp_path / 'diff.json'
    raw.write_text(json.dumps(sample_diff(service.project)))
    run = AnalysisRun(status='completed', backend='b', backend_version='1')
    prepared = service.prepare_analysis(raw, run)
    staged = service.root / 'runs' / run.id / 'raw' / 'result.ghidriff.json'
    assert staged.is_file()
    service.swap_orientation()
    with pytest.raises(ValueError, match='project changed during import'):
        service.apply_import(prepared)
    assert not staged.exists()


# F5: environment failures keep the PT-STORAGE contract instead of leaking raw OSError.
def test_unusable_roots_and_backup_destinations_raise_pt_storage(service, tmp_path, pair):
    blocker = tmp_path / 'blocker'
    blocker.write_text('x')
    with pytest.raises(ValueError, match='PT-STORAGE'):
        ProjectStore(blocker, create=True)
    with pytest.raises(ValueError, match='PT-STORAGE'):
        ProjectService.create(*pair, 'x', blocker / 'child')
    with pytest.raises(ValueError, match='PT-STORAGE'):
        service.backup(blocker / 'sub')
    assert not list(tmp_path.glob('.patchtrace-backup-*'))


# F6: a snapshot from a different contract version fails closed with the documented tag.
@pytest.mark.parametrize('mutate', [lambda d: d.update(schema_version=2),
                                    lambda d: d.update(future_field=1)])
def test_future_snapshot_fails_with_pt_schema_and_does_not_echo_values(service, mutate):
    root = service.root
    service.close()
    _rewrite_snapshot(root, mutate)
    with pytest.raises(ValueError, match='PT-SCHEMA') as caught:
        ProjectService.open(root)
    assert 'input_value' not in str(caught.value)
