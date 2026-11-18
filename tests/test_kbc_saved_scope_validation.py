"""Saved coverage refusal before actual service/store writes; authored offline data."""
from __future__ import annotations

import json
from dataclasses import replace

import kbc_helpers as h
import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import NOW, FixedClock, write_pair
from kbc_saved_scope_support import add, document, file_index, refused_without_writes, saved, seeded

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.context import build_bundle
from patchtrace.kbcorrelation.contracts import Lead
from patchtrace.kbcorrelation.sources.scope import build_coverage, months_scope
from patchtrace.kbcorrelation.store import WorkspaceStore
from patchtrace.kbcorrelation.workflow import Event

pytestmark = pytest.mark.usefixtures('no_sockets')


def damage_scope(service, investigation, source, damage):
    with WorkspaceStore(service.root) as store:
        rev = store.current_revision(investigation)
        key, = rev.coverage_ids
        coverage = store.get_coverage(key)
        if damage == 'missing':
            store.db.execute('DELETE FROM coverage WHERE coverage_id=?', (key,))
        elif damage in {'invalid-json', 'wrong-body-id', 'wrong-content-id'}:
            body = coverage.model_dump(mode='json')
            if damage == 'wrong-body-id':
                body['coverage_id'] = 'f' * 64
            elif damage == 'wrong-content-id':
                body['watermark_current_release_date'] = '2099-01-01T00:00:00Z'
            store.db.execute('UPDATE coverage SET body=? WHERE coverage_id=?',
                             ('{' if damage == 'invalid-json' else json.dumps(body), key))
        elif damage in {'contradictory-selector', 'multiple', 'none'}:
            ids = ()
            if damage != 'none':
                other = build_coverage(source_kind='cvrf-month', scope=months_scope(('2099-Feb',)),
                    requested=coverage.requested_ids, inspected=coverage.inspected_ids,
                    watermark=coverage.watermark_current_release_date, retrieved_at=coverage.retrieved_at)
                store.put_coverage(other)
                ids = (other.coverage_id,) if damage == 'contradictory-selector' else (key, other.coverage_id)
            store.apply(rev, Event('search_done', rev.revision, outcome='METADATA_READY',
                                  scope_ids=rev.scope_ids, coverage_ids=tuple(sorted(ids))))
        elif damage == 'source-missing':
            (store.root / source.source.object_path).unlink()
        else:
            raise AssertionError(damage)


@pytest.mark.parametrize('damage', ['missing', 'invalid-json', 'wrong-body-id', 'wrong-content-id',
                                   'contradictory-selector', 'multiple', 'none', 'source-missing'])
@pytest.mark.parametrize('operation', ['components', 'products', 'pairs', 'import'])
def test_saved_scope_refuses_before_decisions_approval_or_project_mutation(tmp_path, monkeypatch, damage, operation):
    service, doc, investigation, product = seeded(tmp_path)
    file_index(service)
    older, newer = write_pair(tmp_path)
    project = tmp_path / 'project'
    damage_scope(service, investigation, doc, damage)
    calls = {
        'components': lambda: service.components(investigation, product=product, files=['user.sys']),
        'products': lambda: service.products(investigation),
        'pairs': lambda: service.pairs(investigation, product=product, files=['exampledrv.sys']),
        'import': lambda: service.import_pair(investigation, str(older), str(newer), str(project)),
    }
    refused_without_writes(calls[operation], service, project, monkeypatch)
    assert not project.exists()


@pytest.mark.parametrize('operation', ['pairs-without-index', 'plan', 'acquire', 'preview'])
def test_saved_scope_preflight_precedes_unavailable_plans_requests_and_preview(tmp_path, monkeypatch, operation):
    service, doc, investigation, product = seeded(tmp_path)
    older, newer = write_pair(tmp_path)
    if operation != 'pairs-without-index':
        file_index(service)
    service.env = replace(service.env, acquirer=object())  # any attempted use fails; no request port is called
    damage_scope(service, investigation, doc, 'missing')
    destination = tmp_path / 'not-created'
    calls = {
        'pairs-without-index': lambda: service.pairs(investigation, product=product),
        'plan': lambda: service.plan(investigation, product=product, files=['exampledrv.sys']),
        'acquire': lambda: service.acquire(investigation, str(destination), product=product,
                                           files=['exampledrv.sys'], offline=True),
        'preview': lambda: service.import_pair(investigation, str(older), str(newer), str(destination), dry_run=True),
    }
    refused_without_writes(calls[operation], service, destination, monkeypatch)


@pytest.mark.parametrize('whose', ['current', 'journal', 'both'])
def test_repair_validates_current_and_captured_scope_before_mark_interrupted(tmp_path, monkeypatch, whose):
    def interrupt(point):
        if point == 'after_sidecar_write':
            raise RuntimeError('authored interruption after sidecars')

    service, _doc, investigation, _product = seeded(tmp_path, fault=interrupt)
    older, newer = write_pair(tmp_path)
    project = tmp_path / 'project'
    with pytest.raises(RuntimeError, match='authored interruption'):
        service.import_pair(investigation, str(older), str(newer), str(project))
    service = wiring.build_service(service.root, clock=FixedClock())
    with WorkspaceStore(service.root) as store:
        current = store.current_revision(investigation)
        original_key, = current.coverage_ids
        other = store.load_index().coverage(months_scope(('2099-Feb',)), now=NOW)
        store.put_coverage(other)
        # Use the store's actual CAS append: the selected journal keeps the older
        # captured revision while the current revision refers to a different valid scope.
        changed = current.model_copy(update={'revision': current.revision + 1, 'parent': current.revision,
                                             'coverage_ids': (other.coverage_id,)})
        store.append_revision(changed, expected_current=current.revision)
        for key in ((other.coverage_id,) if whose == 'current' else
                    (original_key,) if whose == 'journal' else (original_key, other.coverage_id)):
            store.db.execute('UPDATE coverage SET body=? WHERE coverage_id=?', ('{', key))
        assert not store.journal_ops()[0][2]['interrupted']
    refused_without_writes(lambda: service.attach(str(project), investigation, repair_it=True),
                           service, project, monkeypatch)


def test_repair_preflights_every_selected_journal_before_resuming_the_first(tmp_path, monkeypatch):
    def interrupt(point):
        if point == 'after_sidecar_write':
            raise RuntimeError('authored interruption')

    service, _doc, investigation, _product = seeded(tmp_path, fault=interrupt)
    older, newer = write_pair(tmp_path)
    project = tmp_path / 'project'
    with pytest.raises(RuntimeError, match='authored interruption'):
        service.import_pair(investigation, str(older), str(newer), str(project))
    service = wiring.build_service(service.root, clock=FixedClock())
    with WorkspaceStore(service.root) as store:
        op, state, body = store.journal_ops()[0]
        store.journal_put('0' * 64, state, body)
        bad = {**body, 'revision': {**body['revision'], 'coverage_ids': ['f' * 64]}}
        store.journal_put(op, state, bad)
        assert [key for key, _, _ in store.journal_ops()] == ['0' * 64, op]
    refused_without_writes(lambda: service.attach(str(project), investigation, repair_it=True),
                           service, project, monkeypatch)


def test_captured_advisory_still_needs_full_source_admission_when_current_lead_is_pair_only(tmp_path, monkeypatch):
    def interrupt(point):
        if point == 'after_sidecar_write':
            raise RuntimeError('authored interruption')

    service, _doc, investigation, _product = seeded(tmp_path, mode='files', fault=interrupt)
    older, newer = write_pair(tmp_path)
    project = tmp_path / 'project'
    with pytest.raises(RuntimeError, match='authored interruption'):
        service.import_pair(investigation, str(older), str(newer), str(project))
    service = wiring.build_service(service.root, clock=FixedClock())
    withdrawn = document(date='2099-02-14')
    withdrawn['vulnerabilities'] = []
    latest = add(service, withdrawn)
    (service.root / latest.source.object_path).unlink()
    with WorkspaceStore(service.root) as store:
        current = store.current_revision(investigation)
        changed = current.model_copy(update={'revision': current.revision + 1, 'parent': current.revision,
            'lead': Lead(kind='pair', value=older.name, raw=older.name), 'coverage_ids': ()})
        store.append_revision(changed, expected_current=current.revision)
        assert store.journal_ops()[0][2]['revision']['lead']['kind'] == 'kb'
    refused_without_writes(lambda: service.attach(str(project), investigation, repair_it=True),
                           service, project, monkeypatch)


@pytest.mark.parametrize('change', ['missing-month-arrives', 'month-watermark-changes', 'source-disappears'])
def test_detectable_month_drift_requires_explicit_repeat_search_before_writes(tmp_path, monkeypatch, change):
    service, doc, investigation, product = seeded(tmp_path)
    if change == 'missing-month-arrives':
        service.search(h.KB_CLIENT, months='2099-Jan,2099-Feb', investigation=investigation)
        add(service, document('2099-Feb', h.CVE_B, 'february.sys flaw', date='2099-02-13'))
    elif change == 'month-watermark-changes':
        add(service, document(title='replacement.sys flaw', date='2099-02-14'))
    else:
        (service.root / doc.source.object_path).unlink()
    refused_without_writes(lambda: service.components(investigation, product=product, files=['user.sys']),
                           service, tmp_path / 'not-created', monkeypatch)


@pytest.mark.parametrize('damage', ['none', 'multiple', 'different-scope', 'incoherent-scope', 'wrong-id',
                                   'text-record', 'mapping-record'])
def test_direct_builder_requires_one_consistent_saved_advisory_scope(tmp_path, damage):
    service, _doc, investigation, _product = seeded(tmp_path)
    rev, coverage = saved(service, investigation)
    scope = None
    if damage == 'none':
        coverage = ()
    elif damage == 'multiple':
        coverage = (*coverage, *coverage)
    elif damage == 'different-scope':
        scope = months_scope(('2099-Feb',))
    elif damage == 'incoherent-scope':
        first, = coverage
        coverage = (build_coverage(source_kind=first.source_kind, scope=months_scope(('2099-Feb',)),
                                  requested=first.requested_ids, inspected=first.inspected_ids,
                                  retrieved_at=first.retrieved_at),)
    elif damage in {'text-record', 'mapping-record'}:
        coverage = (coverage[0].model_dump_json() if damage == 'text-record' else
                    coverage[0].model_dump(mode='json'),)
    else:
        coverage = (coverage[0].model_copy(update={'coverage_id': 'f' * 64}),)
    with WorkspaceStore(service.root) as store, pytest.raises(ValueError, match='saved search coverage'):
        build_bundle(investigation_id=investigation, base_revision=rev.revision, lead=rev.lead,
            cves=(h.CVE_A,), index=store.load_index(), rules=service.env.rules, now=NOW, coverage=coverage,
            scope_id=None, pair_id=None, older_sha=None, newer_sha=None, scope=scope)
