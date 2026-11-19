"""Current retained CVRF identity across production reads, publication and exports.

Authored real stores and source-pinned children only; no target or analyzer runs.
The retained-context suite supplies its admitted native-field fixture builders.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from kbc_k3_support import Kb
from kbc_k4a_support import analysed_project
from pilot_freshness_support import loaded, sidecar_bytes
from test_pilot_kb_context import CVE, OTHER, import_csaf, native_bundle, only, original, publish, revised

from patchtrace import cli
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.storage import FACTS_DIR, AdvisoryStore
from patchtrace.kev import store as kev_store
from patchtrace.pilot import collect, current_inputs, keys, store
from patchtrace.pilot.service import localize
from patchtrace.report2.adapters import collect_from_service
from patchtrace.service import ProjectService

SRC = str(Path(cli.__file__).resolve().parents[1])


@pytest.fixture(autouse=True)
def offline(tmp_path, monkeypatch):
    monkeypatch.setattr(kev_store, 'default_kev_dir', lambda: tmp_path / 'kev')

    def denied(*_args, **_kwargs):
        raise AssertionError('freshness controls must not use the network')

    for name in ('connect', 'connect_ex'):
        monkeypatch.setattr(socket.socket, name, denied)
    for name in ('create_connection', 'getaddrinfo'):
        monkeypatch.setattr(socket, name, denied)


@pytest.fixture
def case(tmp_path, capsys):
    return analysed_project(Kb(tmp_path, capsys), tmp_path, capsys)


def install_native(service, **kwargs):
    service.store.connection.execute("DELETE FROM enrichment_entries WHERE kind='kb-context'")
    bundle, raw = native_bundle(service, **kwargs)
    publish(service, bundle)
    return bundle, raw


def compute(root, capsys, *extra):
    assert cli.main(['pilot', 'leads', str(root), '--json', *extra]) == 0
    return json.loads(capsys.readouterr().out)['result']


@pytest.fixture
def overlap(case, capsys):
    with ProjectService.open(case) as service:
        install_native(service)
        import_csaf(service)
    return case, compute(case, capsys)


def change_context(service, change):
    bundle = original(service)
    if change == 'replacement':
        newer, _ = native_bundle(service, title='Authored updated out-of-bounds read')
        publish(service, revised(newer, investigation_id=bundle.investigation_id,
                                 base_revision=bundle.base_revision + 1))
    elif change == 'withdrawal':
        publish(service, only(bundle, ()))
    elif change == 'removal':
        with service.store.connection as db:
            db.execute("DELETE FROM enrichment_entries WHERE kind='kb-context'")
    elif change == 'corruption':
        with service.store.connection as db:
            db.execute("UPDATE enrichment_entries SET body_sha256=? WHERE kind='kb-context'", ('0' * 64,))
    else:
        raise AssertionError(change)


@pytest.mark.parametrize('route', ['cli', 'desktop'])
def test_cvrf_publication_and_reopen_keep_a_current_receipt(case, capsys, route, monkeypatch):
    result = compute(case, capsys, '--cve', CVE)
    assert result['stored'] and not result['stale']
    with ProjectService.open(case) as service:
        before = sidecar_bytes(service)

        def no_extra_open(*_args, **_kwargs):
            raise AssertionError('capture must use the already owned connection')

        monkeypatch.setattr(ProjectService, 'open', no_extra_open)
        value = loaded(service, route)
        assert (value.state, value.changed) == ('current', ())
        assert value.assessment.inputs.kb_link_digest
        assert value.assessment.result_id == result['result_id']
        assert sidecar_bytes(service) == before


@pytest.mark.parametrize('route', ['cli', 'desktop'])
@pytest.mark.parametrize('change', ['replacement', 'withdrawal', 'removal', 'corruption'])
def test_context_identity_drift_is_stale_even_when_csaf_covers_the_cve(overlap, route, change):
    root, _result = overlap
    with ProjectService.open(root) as service:
        before = loaded(service, route)
        assert before.state == 'current'
        files = sidecar_bytes(service)
        revision = service.project.revision
        change_context(service, change)
        after = loaded(service, route)
        assert service.project.revision == revision
        assert after.state == 'stale' and 'kb_link_digest' in after.changed
        assert after.assessment == before.assessment and sidecar_bytes(service) == files


@pytest.mark.parametrize('route', ['cli', 'desktop'])
def test_named_subset_above_64_is_current_but_cannot_hide_unselected_context_drift(case, capsys, route):
    cves = (CVE, *(f'CVE-2099-{80000 + i}' for i in range(65)))
    with ProjectService.open(case) as service:
        install_native(service, additional=cves[1:])
    compute(case, capsys, '--cve', CVE)
    with ProjectService.open(case) as service:
        before = loaded(service, route)
        assert before.state == 'current' and tuple(c.cve for c in before.assessment.cves) == (CVE,)
        bundle = original(service)
        publish(service, only(bundle, cves[:-1]))  # 65 still exceed P-03; selected CVE and source SHA stay equal
        after = loaded(service, route)
        assert after.state == 'stale' and 'kb_link_digest' in after.changed
        assert after.assessment.inputs.advisory_facts_ids == before.assessment.inputs.advisory_facts_ids


def test_overlapping_context_withdrawal_cannot_be_hidden_by_the_other_copy(case, capsys):
    with ProjectService.open(case) as service:
        bundle, _ = install_native(service)
        publish(service, revised(bundle, investigation_id=str(uuid.uuid4()), base_revision=1))
    compute(case, capsys)
    with ProjectService.open(case) as service:
        before = loaded(service, 'cli')
        assert before.state == 'current'
        publish(service, only(bundle, ()))
        after = loaded(service, 'cli')
        assert after.state == 'stale' and {'kb_link_digest', 'advisory_facts_ids'} <= set(after.changed)
        assert after.assessment == before.assessment


@pytest.mark.parametrize('fallback', [False, True])
def test_verified_csaf_cache_recovery_preserves_csaf_but_cannot_authorize_cvrf_fallback(case, capsys, fallback):
    with ProjectService.open(case) as service:
        install_native(service, cve=OTHER if fallback else CVE)
        import_csaf(service)
    compute(case, capsys)
    with ProjectService.open(case) as service:
        before = loaded(service, 'cli')
        assert before.state == 'current'
        for path in (service.root / FACTS_DIR).glob('*.json'):
            path.unlink()
        docs, warnings = AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id,
                                       service.project.revision).advisories()
        assert docs and warnings  # complete verified recovery, but fallback admission must match collection
        after = loaded(service, 'cli')
        assert after.assessment == before.assessment
        if fallback:
            assert after.state == 'stale' and 'advisory_facts_ids' in after.changed
        else:
            assert (after.state, after.changed) == ('current', ())


@pytest.mark.parametrize('route', ['cli', 'desktop'])
def test_late_publication_rechecks_context_identity_with_the_same_project_revision(overlap, route):
    root, _result = overlap
    with ProjectService.open(root) as service:
        old = loaded(service, route).assessment
        change_context(service, 'replacement')
        assert service.project.revision == old.revision
        if route == 'cli':
            from patchtrace.pilot.cli import _persist
            warnings = []
            assert _persist(EnrichmentStore(service.store), service, old, warnings).entry.stale
            assert warnings
        else:
            from patchtrace.ui_leads import publish_result
            publish_result(service, old, None)
        assert store.load(EnrichmentStore(service.store)).entry.stale
        assert loaded(service, route).state == 'stale'


@pytest.mark.parametrize('change', ['none', 'replacement', 'removal'])
def test_report_export_uses_current_retained_context_identity(overlap, change):
    root, _result = overlap
    with ProjectService.open(root) as service:
        assert collect_from_service(service).leads
        before = sidecar_bytes(service)
        if change != 'none':
            change_context(service, change)
        sections = collect_from_service(service)
        if change == 'none':
            assert sections.leads and not any(u.startswith('leads:') for u in sections.unknowns)
        else:
            assert sections.leads is None
            assert any('stored pilot result is stale' in u and 'inputs-changed' in u and
                       'leads omitted' in u for u in sections.unknowns)
        assert sidecar_bytes(service) == before


def test_captured_comparison_works_after_store_close_on_another_thread(case):
    with ProjectService.open(case) as service:
        enrichment = EnrichmentStore(service.store)
        assessment = localize(collect.collect(service, enrichment, cancel=threading.Event()),
                              keys.default_config(), threading.Event())
        snapshot = current_inputs.capture(service, enrichment, service.project)
    with ThreadPoolExecutor(max_workers=1) as executor:
        assert executor.submit(snapshot.changed, assessment).result(timeout=10) == ()


def test_current_source_headless_why_reports_removal_without_losing_history(overlap, tmp_path):
    root, result = overlap
    candidate = next(row['candidate_key'] for row in result['leads'] if row['cve'] == CVE)
    child = ('import os, pathlib, socket, sys\n'
             'def denied(*a, **k): raise AssertionError("offline child attempted network")\n'
             'socket.create_connection = socket.getaddrinfo = denied\n'
             'socket.socket.connect = socket.socket.connect_ex = denied\n'
             'from patchtrace import cli\n'
             'assert str(pathlib.Path(cli.__file__).resolve().parents[1]) == os.environ["PYTHONPATH"]\n'
             'rc = cli.main(sys.argv[1:])\n'
             'assert not [m for m in sys.modules if m.startswith(("PySide6", "shiboken6", "patchtrace.ui"))]\n'
             'raise SystemExit(rc)\n')
    environment = dict(os.environ, PYTHONPATH=SRC, QT_QPA_PLATFORM='offscreen',
                       XDG_DATA_HOME=str(tmp_path / 'data'), LOCALAPPDATA=str(tmp_path / 'data'))
    for removed in (False, True):
        if removed:
            with ProjectService.open(root) as service:
                change_context(service, 'removal')
        completed = subprocess.run([sys.executable, '-c', child, 'pilot', 'why', str(root), '--json',
                                    '--candidate', candidate, '--cve', CVE],
                                   capture_output=True, text=True, timeout=30, env=environment)
        assert completed.returncode == 0, completed.stderr
        value = json.loads(completed.stdout)
        assert value['result']['result_id'] == result['result_id'] and value['result']['leads']
        assert value['result']['stale'] is removed
        assert ('kb_link_digest' in value['result']['changed']) is removed
