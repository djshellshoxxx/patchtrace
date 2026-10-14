"""K7: the Qt-free acquisition workflow and the KB acquire step, through a fake transport. Hermetic: nothing opens a
socket, no Microsoft binary is used, and the synthetic PE files are never run."""
from __future__ import annotations

import hashlib
import json
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from kbc_k5_support import scope

from patchtrace.acquisition import transport as tr
from patchtrace.acquisition import winbindex as wb
from patchtrace.acquisition import workflow as wf
from patchtrace.acquisition.contracts import AcquisitionError, symbol_server_url
from patchtrace.kbcorrelation import acquire as acq
from patchtrace.kbcorrelation import resolver
from patchtrace.kbcorrelation.lineage import index_rows
from patchtrace.kbcorrelation.store import KbcStoreError
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService

NAME = 'demo.sys'
OLDER, NEWER = synthetic_pe(0), synthetic_pe(1)
SHA_O, SHA_N = hashlib.sha256(OLDER).hexdigest(), hashlib.sha256(NEWER).hexdigest()
URL_O = symbol_server_url(NAME, 0x100, 0x4000)
URL_N = symbol_server_url(NAME, 0x101, 0x4000)
BODIES = {URL_O: OLDER, URL_N: NEWER}
HOSTS = ['msdl.microsoft.com']


class Resp:
    def __init__(self, status, body=b'', headers=None):
        self.status, self.headers, self._body = status, headers or {}, body

    def read(self, size):
        out, self._body = self._body[:size], self._body[size:]
        return out

    def close(self):
        pass


class Server:
    """Symbol server: 302 to a blob for known URLs, 404 otherwise; the blob serves the bytes."""

    def __init__(self, bodies=None, on_blob=None):
        self.calls, self.bodies, self.on_blob = [], dict(BODIES if bodies is None else bodies), on_blob

    def __call__(self, method, url, headers, timeout):
        self.calls.append((method, url))
        path = url.split('/', 3)[3]
        if url.startswith('https://s.blob.core.windows.net/'):
            if self.on_blob:
                self.on_blob()
            return Resp(200, self.bodies['https://msdl.microsoft.com/' + path])
        if url not in self.bodies:
            return Resp(404)
        return Resp(302, headers={'Location': 'https://s.blob.core.windows.net/' + path})


def transport(server, cancel=None):
    return tr.Transport(opener=server, cancel=cancel, sleep=lambda s, c: None)


def record() -> dict:
    doc = {}
    for i, data in enumerate((OLDER, NEWER)):
        sha = hashlib.sha256(data).hexdigest()
        info = {'sha256': sha, 'size': len(data), 'machineType': 34404, 'timestamp': 0x100 + i,
                'virtualSize': 0x4000, 'version': f'10.0.{i}'}
        doc[sha] = {'fileInfo': info, 'windowsVersions': {'11-24H2': {f'KB510000{i + 1}': {'updateInfo': {
            'releaseDate': f'2099-0{i + 1}-14', 'releaseVersion': f'26100.{1000 * (i + 1)}'}}}}}
    return doc


def mappings() -> list[dict]:
    parsed = wb.parse_rows(json.dumps(record()).encode(), NAME, '2099-03-01', compressed=False)
    return [r.as_mapping() for r in parsed.rows]


def row_of(rows, sha):
    return acq.row_for(rows, sha, NAME)


@pytest.fixture
def staging_root(tmp_path, monkeypatch):
    """Redirect staging so a leak is visible as a leftover directory."""
    base = tmp_path / 'tmp'
    base.mkdir()
    monkeypatch.setattr(tempfile, 'tempdir', str(base))
    return base


def candidates():
    rows = mappings()
    return wf.candidate_from_row(row_of(rows, SHA_O)), wf.candidate_from_row(row_of(rows, SHA_N))


# -- acquisition/workflow.py --------------------------------------------------------------------------------------

def test_plan_for_direct_builds_is_one_get_each_to_the_symbol_server():
    older, newer = candidates()
    plan = wf.plan_requests(older, newer)
    assert plan.requests == (('GET', URL_O), ('GET', URL_N)) and plan.hosts == ('msdl.microsoft.com',)


def test_plan_for_delta_only_build_lists_head_probes_then_one_get():
    older, newer = candidates()
    delta = older.model_copy(update={'virtual_size': None, 'last_section_va': 0x1000, 'last_section_raw': 0x200,
                                     'download': 'candidates', 'size': 0x1400})
    plan = wf.plan_requests(delta, newer)
    heads = [r for r in plan.requests if r[0] == 'HEAD']
    assert heads and len(heads) == len(plan.urls[delta.sha256]) and ('GET', wf.PROBED) in plan.requests


@pytest.mark.parametrize('field', ['size', 'timestamp', 'machine_type'], ids=['size', 'stamp', 'machine'])
def test_row_without_file_facts_is_not_downloadable(field):
    row = dict(row_of(mappings(), SHA_O), **{field: None})
    with pytest.raises(AcquisitionError) as exc:
        wf.candidate_from_row(row)
    assert exc.value.code == 'PT-ACQ-NOTFOUND'


def test_update_package_only_build_cannot_be_planned():
    older, newer = candidates()
    gone = older.model_copy(update={'virtual_size': None, 'download': 'unavailable'})
    with pytest.raises(AcquisitionError) as exc:
        wf.plan_requests(gone, newer)
    assert exc.value.code == 'PT-ACQ-NOTFOUND'


def test_pair_is_acquired_through_a_fake_transport_into_a_normal_project(tmp_path, staging_root):
    older, newer = candidates()
    server, events = Server(), []
    service = wf.acquire_project(older, newer, 'demo', tmp_path / 'proj', transport(server), emit=events.append)
    try:
        assert {a.side: a.sha256 for a in service.project.artifacts} == {'older': SHA_O, 'newer': SHA_N}
    finally:
        service.close()
    assert {u for _, u in server.calls if u.startswith('https://msdl')} == {URL_O, URL_N}
    assert any(e[0] and 'verified' in e[0] for e in events)
    assert list(staging_root.iterdir()) == []


def test_cancel_during_download_leaves_no_project_and_no_staging(tmp_path, staging_root):
    older, newer = candidates()
    cancel = threading.Event()
    server = Server(on_blob=cancel.set)
    with pytest.raises(AcquisitionError) as exc:
        wf.acquire_project(older, newer, 'demo', tmp_path / 'proj', transport(server, cancel))
    assert exc.value.code == 'PT-ACQ-CANCEL'
    assert not (tmp_path / 'proj').exists() and list(staging_root.iterdir()) == []


def test_cancel_after_both_downloads_still_creates_no_project(tmp_path, staging_root):
    older, newer = candidates()
    cancel = threading.Event()
    staged = wf.stage(older, newer, transport(Server(), cancel))
    cancel.set()
    with pytest.raises(AcquisitionError) as exc:
        wf.create_project(staged, 'demo', tmp_path / 'proj', cancel=cancel)
    assert exc.value.code == 'PT-ACQ-CANCEL'
    assert not (tmp_path / 'proj').exists() and list(staging_root.iterdir()) == []


def test_download_that_does_not_match_the_index_hash_is_discarded(tmp_path, staging_root):
    older, newer = candidates()
    server = Server({URL_O: OLDER, URL_N: NEWER[:-1] + b'\x01'})
    with pytest.raises(AcquisitionError) as exc:
        wf.acquire_project(older, newer, 'demo', tmp_path / 'proj', transport(server))
    assert exc.value.code == 'PT-ACQ-VERIFY'
    assert not (tmp_path / 'proj').exists() and list(staging_root.iterdir()) == []


def test_non_empty_project_directory_is_refused_before_any_request(tmp_path):
    older, newer = candidates()
    (tmp_path / 'proj').mkdir()
    (tmp_path / 'proj' / 'keep.txt').write_text('x', encoding='utf-8')
    server = Server()
    with pytest.raises(AcquisitionError) as exc:
        wf.acquire_project(older, newer, 'demo', tmp_path / 'proj', transport(server))
    assert exc.value.code == 'PT-ACQ-INPUT' and server.calls == []


# -- kbcorrelation/acquire.py -------------------------------------------------------------------------------------

def pair_and_rows():
    rows = mappings()
    parsed, _ = index_rows(rows, file_name=NAME)
    found = resolver.resolve(parsed, kb='KB5100002', scope=scope(), file_name=NAME)
    (pair,) = found.pairs
    return pair, row_of(rows, SHA_O), row_of(rows, SHA_N)


class Importer:
    """Stands for ``KbService.import_pair``: creates the real project so the staged paths are proven readable."""

    def __init__(self, exit_code=0, fail=None):
        self.exit_code, self.fail, self.seen = exit_code, fail, []

    def __call__(self, older, newer, directory):
        self.seen.append((older, newer, directory))
        if self.fail:
            raise self.fail
        assert Path(older).read_bytes() == OLDER and Path(newer).read_bytes() == NEWER
        ProjectService.create(Path(older), Path(newer), 'demo', Path(directory)).close()
        return SimpleNamespace(exit=self.exit_code, status='complete', result={}, text='', warnings=[])


def run(tmp_path, server, *, importer=None, cancel=None, **consent):
    pair, older_row, newer_row = pair_and_rows()
    port = wf.Acquirer(lambda cancel: transport(server, cancel))
    plan = acq.build_plan(pair, older_row, newer_row, port)
    options = {'consent_hosts': HOSTS, 'consent_plan': plan.plan_sha, 'offline': False} | consent
    importer = importer or Importer()
    try:
        return plan, importer, acq.acquire_pair(plan, older_row, newer_row, port=port, import_pair=importer,
                                                directory=str(tmp_path / 'proj'), cancel=cancel, **options)
    except KbcStoreError as exc:
        return plan, importer, exc


def test_plan_is_bound_to_pair_hosts_and_requests():
    pair, older_row, newer_row = pair_and_rows()
    plan = acq.build_plan(pair, older_row, newer_row, wf.Acquirer())
    assert plan.hosts == ('msdl.microsoft.com',) and [m for m, _ in plan.requests] == ['GET', 'GET']
    assert 'never run' in plan.text and plan.plan_sha in plan.text
    again = acq.build_plan(pair, older_row, newer_row, wf.Acquirer())
    other = acq.build_plan(pair, dict(older_row, timestamp=0x200), newer_row, wf.Acquirer())
    assert again.plan_sha == plan.plan_sha != other.plan_sha


def test_blocked_pair_and_foreign_row_are_refused_while_planning():
    pair, older_row, newer_row = pair_and_rows()
    blocked = pair.model_copy(update={'grade': 'X', 'reason_codes': ('ARCH',), 'bytes_state': 'incompatible'})
    with pytest.raises(KbcStoreError) as exc:
        acq.build_plan(blocked, older_row, newer_row, wf.Acquirer())
    assert exc.value.code == 'PT-KBC-UNSUPPORTED'
    with pytest.raises(KbcStoreError) as exc:
        acq.build_plan(pair, newer_row, newer_row, wf.Acquirer())
    assert exc.value.code == 'PT-KBC-INPUT'


@pytest.mark.parametrize('consent', [
    {'offline': True}, {'consent_hosts': ['winbindex.m417z.com']}, {'consent_hosts': []},
    {'consent_hosts': HOSTS + ['api.msrc.microsoft.com']}, {'consent_plan': '0' * 64}],
    ids=['offline', 'wrong-host', 'no-host', 'extra-host', 'wrong-plan'])
def test_no_request_without_consent_for_exactly_this_plan(tmp_path, consent):
    server = Server()
    _, importer, got = run(tmp_path, server, **consent)
    assert isinstance(got, KbcStoreError) and got.code == 'PT-KBC-CONSENT'
    assert server.calls == [] and importer.seen == [] and not (tmp_path / 'proj').exists()


def test_consented_pair_is_downloaded_verified_imported_and_staging_removed(tmp_path, staging_root):
    server = Server()
    plan, importer, got = run(tmp_path, server)
    assert isinstance(got, acq.AcquireResult) and got.plan_sha == plan.plan_sha
    assert [d['sha256'] for d in got.downloads] == [SHA_O, SHA_N]
    assert got.downloads[0]['source_url'] == URL_O and got.downloads[0]['redirect_host'] == 's.blob.core.windows.net'
    ((older_path, _, directory),) = importer.seen
    assert directory == str(tmp_path / 'proj') and (tmp_path / 'proj' / 'project.sqlite3').is_file()
    assert not Path(older_path).exists() and list(staging_root.iterdir()) == []


def test_cancel_leaves_no_project_and_maps_to_the_kb_cancel_code(tmp_path, staging_root):
    cancel = threading.Event()
    _, importer, got = run(tmp_path, Server(on_blob=cancel.set), cancel=cancel)
    assert isinstance(got, KbcStoreError) and got.code == 'PT-KBC-CANCEL'
    assert got.details == {'acquisition_code': 'PT-ACQ-CANCEL'}
    assert importer.seen == [] and not (tmp_path / 'proj').exists() and list(staging_root.iterdir()) == []


def test_bad_download_hash_is_a_verify_failure_with_nothing_imported(tmp_path, staging_root):
    server = Server({URL_O: OLDER, URL_N: NEWER[:-1] + b'\x01'})
    _, importer, got = run(tmp_path, server)
    assert isinstance(got, KbcStoreError) and got.code == 'PT-KBC-VERIFY'
    assert importer.seen == [] and not (tmp_path / 'proj').exists() and list(staging_root.iterdir()) == []


def test_import_failure_removes_staging_and_surfaces_the_error(tmp_path, staging_root):
    boom = KbcStoreError('PT-KBC-STORAGE', 'the project cannot be created')
    _, importer, got = run(tmp_path, Server(), importer=Importer(fail=boom))
    assert got is boom and len(importer.seen) == 1 and list(staging_root.iterdir()) == []


def test_blocked_import_outcome_is_an_acquire_error_not_a_success(tmp_path, staging_root):
    _, _, got = run(tmp_path, Server(), importer=Importer(exit_code=2))
    assert isinstance(got, KbcStoreError) and got.code == 'PT-KBC-ACQUIRE' and got.details == {'import_exit': 2}
    assert list(staging_root.iterdir()) == []


def test_pending_context_import_still_counts_as_a_created_project(tmp_path):
    _, _, got = run(tmp_path, Server(), importer=Importer(exit_code=3))
    assert isinstance(got, acq.AcquireResult) and got.outcome.exit == 3


def test_missing_index_row_is_an_input_error():
    with pytest.raises(KbcStoreError) as exc:
        acq.row_for(mappings(), 'f' * 64, NAME)
    assert exc.value.code == 'PT-KBC-INPUT'
