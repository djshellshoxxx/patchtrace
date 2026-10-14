"""KB integration plan A-6: `ProjectStore.backup()` also copies the `kb/` and `intelligence/` sidecar
directories (the CSAF advisory sidecars under `intelligence/csaf/` were not backed up before). A backup is a
complete project, so opening it is the restore. Synthetic sample project and fixtures only."""
from __future__ import annotations

import gzip
import hashlib
from pathlib import Path

import pytest

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.storage import AdvisoryStore
from patchtrace.service import ProjectService

ADVISORY = Path(__file__).parent / 'fixtures' / 'csaf' / 'synthetic-advisory-rev1.json'
SIDECARS = ('kb', 'intelligence')


@pytest.fixture
def service(tmp_path):
    with ProjectService.sample(tmp_path / 'case') as svc:
        yield svc


def _digests(root: Path) -> dict[str, str]:
    """Relative POSIX path -> SHA-256 of every file in the `kb` and `intelligence` trees of a project."""
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for name in SIDECARS if (root / name).is_dir() for path in sorted((root / name).rglob('*'))
            if path.is_file()}


def _write_sidecars(root: Path) -> None:
    files = {f'kb/sources/{"a" * 64}.json.gz': gzip.compress(b'{"synthetic": "cvrf"}', mtime=0),
             'kb/investigations/inv-1.json': b'{"synthetic": "investigation"}\n',
             f'intelligence/csaf/sources/{"b" * 64}.json': b'{"synthetic": "csaf"}',
             'intelligence/other/empty.bin': b''}
    for relative, data in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def _advisories(svc: ProjectService) -> AdvisoryStore:
    return AdvisoryStore(svc.root, EnrichmentStore(svc.store), svc.project.id, svc.project.revision)


def test_backup_round_trips_kb_and_intelligence_sidecars_by_sha256(service, tmp_path):
    _write_sidecars(service.root)
    expected = _digests(service.root)
    assert len(expected) == 4
    copy = service.backup(tmp_path / 'copy')
    assert _digests(copy) == expected
    with ProjectService.open(copy) as restored:
        assert restored.project.id == service.project.id
        assert _digests(restored.root) == expected


def test_backup_restores_csaf_advisories_through_their_recorded_hashes(service, tmp_path):
    raw = ADVISORY.read_bytes()
    store = _advisories(service)
    store.add(raw, origin='local-import', uri=None, file_name='advisory.json',
              retrieved_at='2099-03-01T00:00:00Z')
    stored, warnings = store.advisories()
    assert len(stored) == 1 and warnings == []
    copy = service.backup(tmp_path / 'copy')
    with ProjectService.open(copy) as restored:
        again = _advisories(restored)
        assert again.advisories() == (stored, [])
        assert again.read_verified(stored[0].source.raw_path, stored[0].source.sha256) == raw


def test_backup_without_sidecars_keeps_the_previous_layout(service, tmp_path):
    copy = service.backup(tmp_path / 'copy')
    assert not any((copy / name).exists() for name in SIDECARS)
    assert {path.name for path in copy.iterdir()} == {'artifacts', 'project.sqlite3', 'runs'}


@pytest.mark.parametrize('name', ['kb', 'intelligence'], ids=['kb', 'intel'])
def test_backup_refuses_a_symlink_inside_the_new_sidecars(service, tmp_path, name):
    outside = tmp_path / 'outside.txt'
    outside.write_text('not part of the project', encoding='utf-8')
    folder = service.root / name / 'sources'
    folder.mkdir(parents=True)
    try:
        (folder / 'link.json').symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip('this host cannot create symlinks')
    destination = tmp_path / 'copy'
    with pytest.raises(ValueError, match='symlink'):
        service.backup(destination)
    assert not destination.exists() and not list(tmp_path.glob('.patchtrace-backup-*'))
