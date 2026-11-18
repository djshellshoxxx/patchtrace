"""Freshness over real stores, owner-thread loaders and the actual headless CLI.

All inputs are authored local fixtures. These controls prove current/historical
state and publication mechanics, not native attribution or accuracy.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from kev_helpers import document, entry, parse_bytes, render
from pilot_freshness_support import CVE, add_advisory, loaded, sidecar_bytes, withdraw_pair

from patchtrace import cli
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.kev import store as kev_store
from patchtrace.pilot import collect, keys, review, store
from patchtrace.pilot.limits import PilotError
from patchtrace.pilot.service import localize
from patchtrace.service import ProjectService

SRC = str(Path(cli.__file__).resolve().parents[1])


@pytest.fixture(autouse=True)
def offline(tmp_path, monkeypatch):
    monkeypatch.setattr(kev_store, 'default_kev_dir', lambda: tmp_path / 'catalog')

    def denied(*args, **kwargs):
        raise AssertionError('freshness controls must not use the network')

    for name in ('connect', 'connect_ex'):
        monkeypatch.setattr(socket.socket, name, denied)
    for name in ('create_connection', 'getaddrinfo'):
        monkeypatch.setattr(socket, name, denied)


def compute(root, capsys, *extra):
    assert cli.main(['pilot', 'leads', str(root), '--json', *extra]) == 0
    return json.loads(capsys.readouterr().out)['result']


@pytest.fixture
def localized(tmp_path, capsys):
    with ProjectService.sample(tmp_path / 'case') as service:
        add_advisory(service)
        root = service.root
    return root, compute(root, capsys)


@pytest.mark.parametrize('route', ['cli', 'desktop'])
def test_publish_reopen_save_and_reviews_keep_a_current_assessment(localized, route, monkeypatch):
    root, result = localized
    with ProjectService.open(root) as service:
        before = sidecar_bytes(service)
        revision = service.project.revision
        assessment = loaded(service, route).assessment
        assert assessment.result_id == result['result_id'] and assessment.revision == revision
        review.append(EnrichmentStore(service.store), project_id=service.project.id, revision=revision,
                      candidate_key=assessment.leads[0].candidate_key, cve=assessment.leads[0].cve,
                      action='note', text='Historical and current reviews remain independent of evidence.')
        service.review_match(service.project.matches[0].id, 'accepted')
        service.save()
        assert service.project.revision == revision

        def reopened(*args, **kwargs):
            raise AssertionError('freshness must use the already owned project connection')

        monkeypatch.setattr(ProjectService, 'open', reopened)
        now = loaded(service, route)
        assert (now.state, now.changed) == ('current', ())
        assert sidecar_bytes(service) == before and now.assessment == assessment


@pytest.mark.parametrize('route', ['cli', 'desktop'])
def test_withdrawn_function_pair_is_stale_with_unchanged_run_and_raw(localized, route):
    root, _result = localized
    with ProjectService.open(root) as service:
        before = loaded(service, route)
        bytes_before = sidecar_bytes(service)
        withdraw_pair(service)
        after = loaded(service, route)
        assert after.assessment == before.assessment
        assert after.assessment.inputs.raw_sha256 == store.completed_run(service.project).raw_sha256
        assert after.state == 'stale' and 'project_revision' in after.changed
        assert sidecar_bytes(service) == bytes_before


@pytest.mark.parametrize('route', ['cli', 'desktop'])
@pytest.mark.parametrize('withdrawn', [False, True])
def test_replaced_or_withdrawing_advisory_invalidates_its_prior_result(localized, route, withdrawn):
    root, result = localized
    with ProjectService.open(root) as service:
        revision = service.project.revision
        add_advisory(service, revision=2, cves=('CVE-2099-39999',) if withdrawn else (CVE,))
        after = loaded(service, route)
        assert service.project.revision == revision
        assert after.assessment.result_id == result['result_id']
        assert after.state == 'stale' and 'advisory_facts_ids' in after.changed


@pytest.mark.parametrize('route', ['cli', 'desktop'])
def test_import_after_code_only_result_invalidates_the_empty_advisory_input(tmp_path, capsys, route):
    with ProjectService.sample(tmp_path / 'case') as service:
        root = service.root
    result = compute(root, capsys)
    assert result['cves'] == []
    with ProjectService.open(root) as service:
        assert loaded(service, route).state == 'current'
        add_advisory(service)
        after = loaded(service, route)
        assert after.state == 'stale' and 'advisory_facts_ids' in after.changed
        assert after.assessment.result_id == result['result_id']


@pytest.mark.parametrize('route', ['cli', 'desktop'])
def test_unreadable_required_advisory_keeps_history_but_never_current(localized, route):
    root, result = localized
    with ProjectService.open(root) as service:
        for path in (service.root / 'intelligence' / 'csaf').rglob('*.json'):
            path.write_bytes(b'{"unreadable-authored-control":true}')
        after = loaded(service, route)
        assert after.assessment.result_id == result['result_id']
        assert after.state == 'stale' and 'advisory_facts_ids' in after.changed


@pytest.mark.parametrize('route', ['cli', 'desktop'])
def test_local_kev_changes_are_shared_by_cli_and_desktop(localized, tmp_path, route):
    root, _result = localized
    raw = render(document([entry(cveID=CVE)]))
    kev_store.KevStore(tmp_path / 'catalog').install(raw, parse_bytes(raw), now='2099-03-02T00:00:00Z')
    with ProjectService.open(root) as service:
        after = loaded(service, route)
        assert after.state == 'stale' and 'kev_snapshot_id' in after.changed


@pytest.mark.parametrize('route', ['cli', 'desktop'])
def test_unreadable_kev_is_not_the_same_as_an_intentionally_absent_catalog(localized, tmp_path, route):
    root, _result = localized
    folder = tmp_path / 'catalog'
    folder.mkdir()
    (folder / 'current.json').write_text('{broken catalog pointer', encoding='utf-8')
    with ProjectService.open(root) as service:
        after = loaded(service, route)
        assert after.assessment.inputs.kev_snapshot_id is None
        assert after.state == 'stale' and 'kev_snapshot_id' in after.changed


@pytest.mark.parametrize('route', ['cli', 'desktop'])
def test_named_subset_over_the_cve_cap_stays_current(tmp_path, capsys, route):
    with ProjectService.sample(tmp_path / 'case') as service:
        add_advisory(service, cves=tuple(f'CVE-2099-{30001 + i}' for i in range(65)))
        root = service.root
    result = compute(root, capsys, '--cve', CVE)
    assert [context['cve'] for context in result['cves']] == [CVE]
    with ProjectService.open(root) as service:
        after = loaded(service, route)
        assert (after.state, after.changed) == ('current', ())


def test_publication_marks_old_revision_work_stale_and_a_fresh_recompute_is_current(localized):
    root, _result = localized
    with ProjectService.open(root) as service:
        enrichment = EnrichmentStore(service.store)
        old = loaded(service, 'cli').assessment
        withdraw_pair(service)
        stale = store.publish(enrichment, old, keys.default_config(),
                              current=store.current_guard(service.project, old.result_id))
        assert stale.entry.stale
        fresh = localize(collect.collect(service, enrichment, cancel=threading.Event()), keys.default_config(),
                         threading.Event())
        assert fresh.result_id == old.result_id and fresh.revision > old.revision
        current = store.publish(enrichment, fresh, keys.default_config(),
                                current=store.current_guard(service.project, fresh.result_id))
        assert not current.entry.stale and loaded(service, 'cli').state == 'current'
        before = sidecar_bytes(service)
        with pytest.raises(PilotError, match='newer'):
            store.publish(enrichment, old, keys.default_config(),
                          current=store.current_guard(service.project, old.result_id))
        assert sidecar_bytes(service) == before and loaded(service, 'cli').assessment == fresh


def test_a_late_same_id_old_revision_cannot_replace_the_current_receipt(localized):
    root, _result = localized
    with ProjectService.open(root) as service:
        enrichment = EnrichmentStore(service.store)
        old = loaded(service, 'cli').assessment
        withdraw_pair(service)
        fresh = localize(collect.collect(service, enrichment, cancel=threading.Event()), keys.default_config(),
                         threading.Event())
        assert fresh.result_id == old.result_id and fresh.revision > old.revision
        store.publish(enrichment, fresh, keys.default_config(),
                      current=store.current_guard(service.project, fresh.result_id))
        before = sidecar_bytes(service)
        with pytest.raises(PilotError, match='newer'):
            store.publish(enrichment, old, keys.default_config(),
                          current=store.current_guard(service.project, old.result_id))
        assert sidecar_bytes(service) == before and loaded(service, 'cli').assessment == fresh


@pytest.mark.parametrize('route', ['cli', 'desktop'])
def test_saved_revision_wins_over_an_outdated_in_memory_project(localized, route):
    root, _result = localized
    with ProjectService.open(root) as service:
        earlier = service.project
        withdraw_pair(service)
        service.project = earlier
        after = loaded(service, route)
        assert after.state == 'stale' and 'project_revision' in after.changed


def test_actual_headless_why_and_review_report_historical_localization(localized, tmp_path):
    root, result = localized
    candidate = next(row['candidate_key'] for row in result['leads'] if row['cve'] == CVE)
    with ProjectService.open(root) as service:
        withdraw_pair(service)
    child = ('import sys\nfrom patchtrace import cli\n'
             'rc = cli.main(sys.argv[1:])\n'
             'bad = [m for m in sys.modules if m.startswith(("PySide6", "shiboken6", "patchtrace.ui"))]\n'
             'assert not bad, bad\nraise SystemExit(rc)\n')
    environment = dict(os.environ, PYTHONPATH=SRC, QT_QPA_PLATFORM='offscreen',
                       XDG_DATA_HOME=str(tmp_path / 'data'), LOCALAPPDATA=str(tmp_path / 'data'))
    for verb, extra in [('why', []), ('review', ['--action', 'note', '--text', 'Historical review'])]:
        completed = subprocess.run([sys.executable, '-c', child, 'pilot', verb, str(root), '--json',
                                    '--candidate', candidate, '--cve', CVE, *extra],
                                   capture_output=True, text=True, timeout=60, env=environment)
        assert completed.returncode == 0, completed.stderr
        value = json.loads(completed.stdout)
        assert value['result']['stale'] and 'project_revision' in value['result']['changed']
        assert any('out of date' in warning for warning in value['warnings'])
