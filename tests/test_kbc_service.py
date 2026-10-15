"""K3: `KbService`, the production `ProjectPort` binding and the Qt-free guarantees (KB-integration-plan 7.3, 8.1, 9).
Synthetic; offline (sockets denied)."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import kbc_helpers as h
import pytest
from kbc_k1_support import import_fixture, no_sockets  # noqa: F401
from kbc_k3_support import FixedClock, arm64_pe, write_pair

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.service import KbService
from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore
from patchtrace.sample import synthetic_pe

pytestmark = pytest.mark.usefixtures('no_sockets')
SRC = Path(__file__).resolve().parent.parent / 'src'
DOMAIN = ('components', 'pairs', 'plan', 'context', 'export')


@pytest.fixture
def service(tmp_path):
    svc = wiring.build_service(tmp_path / 'ws', clock=FixedClock())
    with WorkspaceStore(svc.root) as ws:
        ws.add_document(import_fixture('cvrf-2099-Feb.json'), h.read_fixture_bytes('cvrf-2099-Feb.json'))
    return svc


def search(svc: KbService, lead='KB5099001', **kw):
    out = svc.search(lead, **kw)
    return out, out.result['investigation_id']


# ------------------------------------------------------------------------------------------------ search and state

def test_search_creates_an_investigation_at_metadata_ready_with_stored_coverage(service):
    out, inv = search(service)
    assert (out.exit, out.status, out.result['state']) == (0, 'complete', 'METADATA_READY')
    assert len(out.result['scopes']) == 2 and out.result['next'] == 'kb.next.choose_product'
    with WorkspaceStore(service.root) as ws:
        rev = ws.current_revision(inv)
        assert rev.coverage_ids and ws.get_coverage(rev.coverage_ids[0]).state == 'complete_in_scope'


def test_choosing_a_product_moves_other_scopes_to_not_applicable_and_selects_it(service):
    out, inv = search(service)
    amd64 = next(s['scope_id'] for s in out.result['scopes'] if s['architecture'] == 'amd64')
    again = service.search('KB5099001', product=amd64, investigation=inv)
    assert again.result['state'] == 'PRODUCT_SELECTED' and again.result['next'] is None
    assert [e['scope_id'] for e in again.result['edges']] == [amd64]
    assert len(again.result['not_applicable']) == 1 and 'left out of the leads' in again.text


def test_an_unknown_product_or_investigation_is_an_input_error_and_changes_nothing(service):
    with pytest.raises(KbcStoreError) as product:
        service.search('KB5099001', product='f' * 64)
    with pytest.raises(KbcStoreError) as inv:
        service.search('KB5099001', investigation='00000000-0000-4000-8000-000000000000')
    assert product.value.code == inv.value.code == 'PT-KBC-INPUT'
    with WorkspaceStore(service.root) as ws:
        assert ws.db.execute('SELECT COUNT(*) FROM investigations').fetchone()[0] == 0


@pytest.mark.parametrize('lead', ['KB12', 'CVE-1', 'hello', ''], ids=['short-kb', 'short-cve', 'word', 'empty'])
def test_a_bad_lead_is_refused(service, lead):
    with pytest.raises(KbcStoreError) as caught:
        service.search(lead)
    assert caught.value.code == 'PT-KBC-INPUT'


def test_more_than_24_months_is_a_scope_error(service):
    months = ','.join(f'2098-{m}' for m in ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'))
    months += ',' + ','.join(f'2097-{m}' for m in ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct',
                                                     'Nov', 'Dec')) + ',2096-Jan'
    with pytest.raises(KbcStoreError) as caught:
        service.search('KB5099001', months=months)
    assert caught.value.code == 'PT-KBC-SCOPE'


def test_a_month_that_is_not_loaded_makes_the_answer_partial_not_negative(service):
    out = service.search('KB5099777', months='2099-Feb,2099-Jan')
    assert (out.exit, out.status) == (3, 'partial') and out.result['coverage']['state'] == 'partial_in_scope'
    clean = service.search('KB5099777', months='2099-Feb')
    assert (clean.exit, clean.status) == (4, 'unavailable') and 'does not mean it has no security updates' in clean.text


# ------------------------------------------------------------------------------------------------ components

def test_components_need_a_product_then_record_analyst_names(service):
    out, inv = search(service)
    with pytest.raises(KbcStoreError) as caught:
        service.components(inv, product=None, files=['clfs.sys'])
    assert caught.value.code == 'PT-KBC-INPUT' and 'Choose the product' in caught.value.message
    amd64 = next(s['scope_id'] for s in out.result['scopes'] if s['architecture'] == 'amd64')
    first = service.components(inv, product=amd64, files=['ExampleDrv.sys'])
    assert (first.exit, first.result['state']) == (0, 'COMPONENTS_READY')
    assert [(x['basename'], x['tier']) for x in first.result['hints']] == [('exampledrv.sys', 'E')]
    later = service.components(inv, product=None, files=[])  # the name is remembered from the decision log
    assert [x['basename'] for x in later.result['hints']] == ['exampledrv.sys']
    with WorkspaceStore(service.root) as ws:
        assert [d.op for d in ws.decisions(inv)].count('component-name') == 1


def test_without_a_name_the_state_is_needs_filename_and_the_copy_says_so(service):
    out, inv = search(service)
    amd64 = next(s['scope_id'] for s in out.result['scopes'] if s['architecture'] == 'amd64')
    res = service.components(inv, product=amd64, files=[])
    assert (res.exit, res.result['state']) == (4, 'NEEDS_FILENAME') and 'does not name the changed file' in res.text


def test_pairs_without_the_file_index_say_so(service):
    _, inv = search(service)
    res = service.pairs(inv)
    assert (res.exit, res.status, res.result['pairs']) == (4, 'unavailable', []) and 'import-pair' in res.text


# ------------------------------------------------------------------------------------------------ import-pair

def test_import_pair_dry_run_creates_nothing(service, tmp_path):
    _, inv = search(service)
    older, newer = write_pair(tmp_path)
    res = service.import_pair(inv, str(older), str(newer), str(tmp_path / 'P'), dry_run=True)
    assert res.exit == 0 and res.result['plan']['network_requests'] == 0 and not (tmp_path / 'P').exists()
    with WorkspaceStore(service.root) as ws:
        assert ws.current_revision(inv).state == 'METADATA_READY'


def test_import_pair_blocks_are_typed_and_leave_no_project(service, tmp_path):
    _, inv = search(service)
    old, new = write_pair(tmp_path / 'a', newer=synthetic_pe(0))
    ident = service.import_pair(inv, str(old), str(new), str(tmp_path / 'P1'))
    assert (ident.exit, ident.status) == (4, 'unavailable') and 'byte-identical' in ident.text
    old, new = write_pair(tmp_path / 'b', newer_name='renamed.sys')
    renamed = service.import_pair(inv, str(old), str(new), str(tmp_path / 'P2'))
    assert (renamed.exit, renamed.status) == (2, 'failed') and renamed.error.startswith('NAME_MISMATCH')
    old, arm = write_pair(tmp_path / 'c', newer=arm64_pe(1))
    arch = service.import_pair(inv, str(old), str(arm), str(tmp_path / 'P3'))
    assert arch.exit == 2 and 'AMD64' in arch.text
    assert not any((tmp_path / name).exists() for name in ('P1', 'P2', 'P3'))


def test_import_pair_on_a_new_investigation_records_a_pair_lead(service, tmp_path):
    older, newer = write_pair(tmp_path)
    res = service.import_pair('new', str(older), str(newer), str(tmp_path / 'P'), name='demo')
    assert res.exit == 0 and res.result['pair']['grade'] == 'B'
    with WorkspaceStore(service.root) as ws:
        rev = ws.current_revision(res.result['investigation_id'])
        assert rev.lead.kind == 'pair' and rev.state == 'CONTEXT_ATTACHED'
        assert {d.op for d in ws.decisions(rev.investigation_id)} == {'orientation', 'pair-approval'}


def test_a_non_pe_file_is_an_input_error(service, tmp_path):
    bad = tmp_path / 'x.sys'
    bad.write_bytes(b'not a pe file' * 10)
    older, _ = write_pair(tmp_path)
    with pytest.raises(KbcStoreError) as caught:
        service.import_pair('new', str(older), str(bad), str(tmp_path / 'P'))
    assert caught.value.code == 'PT-KBC-INPUT'


def test_attaching_to_a_project_this_workspace_did_not_create_is_unsupported(service, tmp_path):
    _, inv = search(service)
    with pytest.raises(KbcStoreError) as caught:
        service.attach(str(tmp_path / 'elsewhere'), inv, repair_it=True)
    assert caught.value.code == 'PT-KBC-UNSUPPORTED'


def test_export_refuses_a_bad_extension_and_an_existing_file(service, tmp_path):
    older, newer = write_pair(tmp_path)
    service.import_pair('new', str(older), str(newer), str(tmp_path / 'P'))
    with pytest.raises(KbcStoreError):
        service.export(str(tmp_path / 'P'), str(tmp_path / 'out.txt'), overwrite=False)
    target = tmp_path / 'out.json'
    assert service.export(str(tmp_path / 'P'), str(target), overwrite=False).exit == 0
    with pytest.raises(KbcStoreError):
        service.export(str(tmp_path / 'P'), str(target), overwrite=False)
    assert service.export(str(tmp_path / 'P'), str(target), overwrite=True).exit == 0


# ------------------------------------------------------------------------------------------------ project port

def test_create_project_returns_the_existing_project_for_the_same_bytes(tmp_path):
    older, newer = write_pair(tmp_path)
    port = wiring.RealProjectPort(None)
    first = port.create_project(str(older), str(newer), directory=str(tmp_path / 'P'))
    again = wiring.RealProjectPort(None).create_project(str(older), str(newer), directory=str(tmp_path / 'P'))
    assert first == again and first['older_sha256'] == h.sha256_hex(older.read_bytes())


def test_rows_round_trip_and_the_registry_survives_a_new_process_object(tmp_path):
    older, newer = write_pair(tmp_path)
    with WorkspaceStore(tmp_path / 'ws') as ws:
        made = wiring.RealProjectPort(ws).create_project(str(older), str(newer), directory=str(tmp_path / 'P'))
        pid = made['project_id']
        fresh = wiring.RealProjectPort(ws)  # no in-memory registry: the journal must resolve the directory
        with pytest.raises(KbcStoreError):
            fresh.put_row(pid, 'kb-context', 'k', b'{"a": 1}')
        ws.journal_put('op', 'created', {'project_id': pid, 'directory': (tmp_path / 'P').as_posix()})
        fresh.put_row(pid, 'kb-context', 'k', b'{"a": 1}')
        assert fresh.get_row(pid, 'kb-context', 'k') == b'{"a": 1}' and fresh.get_row(pid, 'kb-context', 'z') is None
        fresh.put_row(pid, 'kb-context', 'k', b'{"a": 1}')  # a resumed write is idempotent
        assert list(fresh.list_rows(pid, 'kb-context')) == ['k']


# ------------------------------------------------------------------------------------------------ boundaries

def test_domain_modules_import_no_qt_sqlite_or_network_code():
    for name in DOMAIN:
        text = (SRC / 'patchtrace' / 'kbcorrelation' / f'{name}.py').read_text(encoding='utf-8')
        for banned in ('PySide6', 'sqlite3', 'urllib', 'socket', 'http.client', 'requests'):
            assert f'import {banned}' not in text and f'from {banned}' not in text, (name, banned)


def test_the_cli_path_never_imports_qt():
    code = ('import sys\n'
            'from patchtrace.kbcorrelation import cli, wiring, service\n'
            'wiring.build_env()\n'
            'bad = [m for m in sys.modules if m.split(".")[0] in ("PySide6", "PyQt5", "PyQt6", "shiboken6")]\n'
            'print(bad)\n'
            'sys.exit(1 if bad else 0)\n')
    proc = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=120,
                          env={**os.environ, 'PYTHONPATH': str(SRC)}, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
