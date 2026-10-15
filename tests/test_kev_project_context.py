"""KEV K5 project row: build from the loaded catalog, publish through the enrichment store, read back, report drift.

Synthetic throughout (the 2099 catalog and the sample project); no network. The row kind ``kev-context`` is a plain
project row: not derived, so retention never deletes it, and a reader from before KEV ignores it.
"""
from __future__ import annotations

import ast
import hashlib
import json
import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from kev_helpers import (
    NOW,
    SYNTHETIC,
    at,
    document,
    entry,
    fixture_document,
    mutated,
    parse_document,
    parse_fixture,
    socket_guard,
)

import patchtrace
from patchtrace.enrichment import storage
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.kev import limits, project_context
from patchtrace.kev.contracts import KevContext, KevError
from patchtrace.kev.project_context import build_context, drift_lines, load_contexts, publish_context
from patchtrace.kev.view_model import KevColumnProvider
from patchtrace.sample import create_sample
from patchtrace.secondary import load_secondary
from patchtrace.secondary.store import current_sets

no_sockets = pytest.fixture(autouse=True, scope='module')(socket_guard)
STAMP, FUTURE = '2099-03-02T08:00:00Z', '9999-01-01T00:00:00+00:00'
KB = 'KB5000001'
KNOWN, NOT_LISTED, UNKNOWN, PADDED = 'CVE-2099-10001', 'CVE-2099-10002', 'CVE-2099-10004', 'CVE-2099-10010'
CVES = (KNOWN, NOT_LISTED, UNKNOWN)
HEADLINE = 'KEV data changed since recorded: '


@pytest.fixture(scope='module')
def catalog():
    return parse_fixture(SYNTHETIC)


@pytest.fixture
def case(tmp_path):
    svc = create_sample(tmp_path / 'p')
    yield svc
    if not svc.store.closed:
        svc.close()


def provider(source, now=NOW):
    return KevColumnProvider(source, now)


def build(kev, cves=CVES, **overrides):
    fields = {'created_at': STAMP, 'kb': KB, 'release_date': '2099-02-11', 'orientation_verified': True} | overrides
    return build_context(kev, cves, **fields)


def newer(*, flip=False, reword=False, ransomware=None, drop=None):
    """The synthetic catalog a week later: 10002 may be listed now, 10004 may change a tracked field, 10001 may be
    gone, and a description may be reworded."""
    doc = fixture_document(SYNTHETIC)
    doc['catalogVersion'], doc['dateReleased'] = '2099.03.08', '2099-03-08T18:00:00.0000Z'
    if flip:
        doc['vulnerabilities'].append(entry(1, cveID=NOT_LISTED, vendorProject='Microsoft', product='Windows',
                                            dateAdded='2099-03-05', dueDate='2099-03-26'))
    if ransomware:
        doc = mutated(doc, ('vulnerabilities', 1, 'knownRansomwareCampaignUse'), ransomware)
    if reword:
        doc = mutated(doc, ('vulnerabilities', 1, 'shortDescription'), 'SYNTHETIC: reworded text.')
    if drop:
        doc['vulnerabilities'] = [row for row in doc['vulnerabilities'] if row['cveID'] != drop]
    doc['count'] = len(doc['vulnerabilities'])
    return parse_document(doc)


def row_ids(svc, kinds=('kev-context',)):
    marks = ','.join('?' * len(kinds))
    found = svc.store.connection.execute(f'SELECT id FROM enrichment_entries WHERE kind IN ({marks})', kinds)
    return {row[0] for row in found.fetchall()}


# --- building the row ------------------------------------------------------------------------------------------------

def test_build_context_records_the_answered_cves_with_slim_entries(catalog):
    context = build(provider(catalog), (UNKNOWN, 'not-a-cve', KNOWN, NOT_LISTED, KNOWN, 'CVE-２０９９-1'))
    assert [row.cve_id for row in context.lookups] == [KNOWN, NOT_LISTED, UNKNOWN]      # sorted, unique, answered only
    assert [row.status for row in context.lookups] == ['listed', 'not-listed', 'listed']
    assert type(context.lookups[0].entry).__name__ == 'KevEntrySlim' and context.lookups[1].entry is None
    assert (context.snapshot_id, context.catalog_version, context.date_released, context.source) == (
        catalog.meta.snapshot_id, '2099.03.01', '2099-03-01T18:00:00Z', 'local-import')
    assert (context.content_digest, context.kb, context.release_date, context.orientation_verified,
            context.created_at) == (catalog.meta.content_digest, KB, '2099-02-11', True, STAMP)
    assert {row.snapshot_id for row in context.lookups} == {catalog.meta.snapshot_id}
    shuffled = build(provider(catalog), (NOT_LISTED, UNKNOWN, KNOWN))
    assert shuffled.context_id == context.context_id                                 # the order is not identity


def test_a_row_records_the_age_it_was_seen_at(catalog):
    context = build(provider(catalog, at(2099, 3, 20)), (KNOWN, NOT_LISTED))
    assert {(row.freshness, row.age_days) for row in context.lookups} == {('stale', 19)}


@pytest.mark.parametrize(('cves', 'code', 'text'), [
    ((), 'PT-KEV-INPUT', 'none of the CVE IDs'), (('not-a-cve', 'CVE-２０９９-1'), 'PT-KEV-INPUT', 'none of the CVE IDs'),
    (tuple(f'CVE-2099-{n:05d}' for n in range(limits.MAX_CONTEXT_CVES + 1)), 'PT-KEV-LIMIT', 'more than 256 CVEs'),
    (tuple(f'bad-{n}' for n in range(limits.MAX_LOOKUP_CVES + 1)), 'PT-KEV-LIMIT', 'more than 5000 CVE IDs')],
    ids=['no-cves', 'no-valid-cve', 'too-many-for-a-row', 'too-many-to-look-up'])
def test_build_context_refuses_what_cannot_be_recorded(catalog, cves, code, text):
    with pytest.raises(KevError) as raised:
        build(provider(catalog), cves)
    assert raised.value.code == code and text in raised.value.message


def test_the_limits_are_inclusive(catalog):
    full = tuple(f'CVE-2099-{n:05d}' for n in range(limits.MAX_CONTEXT_CVES))
    assert len(build(provider(catalog), full).lookups) == limits.MAX_CONTEXT_CVES
    many_unusable = (*(f'bad-{n}' for n in range(limits.MAX_LOOKUP_CVES - 1)), KNOWN)      # 5,000 IDs, one answerable
    assert [row.cve_id for row in build(provider(catalog), many_unusable).lookups] == [KNOWN]


def test_answers_from_another_catalog_cannot_form_a_row(catalog):
    class Mixed:
        """A port whose answers do not come from the snapshot it reports: the row must not be built."""
        meta = catalog.meta

        def lookup(self, cve):
            return provider(catalog).lookup(cve).model_copy(update={'snapshot_id': 'f' * 64})

    with pytest.raises(KevError) as raised:
        build(Mixed(), (KNOWN,))
    assert raised.value.code == 'PT-KEV-INPUT' and raised.value.message == 'the KEV context is not valid: context'


def test_build_context_needs_a_catalog():
    with pytest.raises(KevError) as raised:
        build(provider(None))
    assert raised.value.code == 'PT-KEV-NOTFOUND'


@pytest.mark.parametrize('overrides', [{'kb': 'KB123'}, {'release_date': '2099-2-11'}, {'created_at': '2099-03-02'}],
                         ids=['short-kb', 'unpadded-date', 'date-only-stamp'])
def test_build_context_names_the_invalid_field_not_its_value(catalog, overrides):
    with pytest.raises(KevError) as raised:
        build(provider(catalog), **overrides)
    assert raised.value.code == 'PT-KEV-INPUT' and next(iter(overrides)) in raised.value.message
    assert not any(str(value) in raised.value.message for value in overrides.values())


def test_a_row_over_the_size_limit_is_refused_before_it_exists():
    longest = {'vendorProject': 'V' * limits.MAX_VENDOR_CHARS, 'product': 'P' * limits.MAX_PRODUCT_CHARS,
               'vulnerabilityName': 'N' * limits.MAX_NAME_CHARS, 'cwes': ['CWE-999999'] * limits.MAX_CWES}
    entries = [entry(n, cveID=f'CVE-2099-{n:05d}', **longest) for n in range(1, limits.MAX_CONTEXT_CVES + 1)]
    heavy = parse_document(document(entries, catalogVersion='2099.03.01', dateReleased='2099-03-01T18:00:00.0000Z'))
    cves = [f'CVE-2099-{n:05d}' for n in range(1, limits.MAX_CONTEXT_CVES + 1)]
    with pytest.raises(KevError) as raised:
        build(provider(heavy), cves)
    assert raised.value.code == 'PT-KEV-LIMIT' and '256 KiB' in raised.value.message
    assert len(build(provider(heavy), cves[:100]).model_dump_json()) < limits.MAX_CONTEXT_ROW_BYTES


# --- the project row -------------------------------------------------------------------------------------------------

def test_context_row_roundtrip_and_v1_client_ignores_it(case, catalog, monkeypatch):
    enrichment = EnrichmentStore(case.store)
    enrichment.ensure()
    before = (load_secondary(enrichment), current_sets(enrichment))
    context = build(provider(catalog))
    written = publish_context(enrichment, case.project.id, case.project.revision, context,
                              loaded_snapshot_id=catalog.meta.snapshot_id)
    assert (written.id, written.kind, written.status, written.stale) == (
        f'kev-context:{context.context_id}', 'kev-context', 'complete', False)
    assert written.guard == Guard(case.project.id, '', '', context.context_id)
    version = case.store.connection.execute("SELECT value FROM enrichment_meta WHERE key='extension_version'")
    assert version.fetchone()[0] == '1'                          # no bump: a v1 client keeps full access
    recorded, warnings = load_contexts(enrichment)
    assert warnings == () and len(recorded) == 1
    assert recorded[0].context == context and recorded[0].entry == written
    assert KevContext.model_validate_json(json.dumps(written.body)) == context
    assert written.body['contract'] == 'kev/1' and 'kev-context' in storage.KINDS
    assert 'kev-context' not in storage.DERIVED_KINDS
    # a reader from before KEV queries the kinds it knows and never sees the row
    old_kinds = frozenset(storage.KINDS) - {'kev-context'}
    monkeypatch.setattr(storage, 'KINDS', old_kinds)
    old = EnrichmentStore(case.store)
    for kind in sorted(old_kinds):
        assert all(item.kind == kind for item in old.entries(kind))
    assert (load_secondary(old), current_sets(old)) == before
    old.apply_retention(Guard(case.project.id, 'r', 'a' * 64, 'b' * 64), started=FUTURE)
    assert row_ids(case) == {written.id}
    case.store.save(case.store.load())                           # the v1 project contract still opens and saves
    assert row_ids(case) == {written.id}


def test_the_row_survives_retention_pruning_and_the_size_cap_fallback(case, catalog):
    enrichment = EnrichmentStore(case.store)
    written = publish_context(enrichment, case.project.id, case.project.revision, build(provider(catalog)),
                              loaded_snapshot_id=catalog.meta.snapshot_id)
    g = Guard(case.project.id, 'r', 'a' * 64, 'b' * 64)
    for n in range(12):
        for kind in ('signals', 'ranking', 'wil'):
            enrichment.publish(kind, g, g, 0, 'complete', {'pad': 'x' * 64}, f'{kind}:r{n}')
        enrichment.publish('pipeline', g, g, 0, 'complete', {'stage_ids': {'ranking': f'r{n}', 'wil': f'r{n}'},
                                                             'config_digest': 'c'}, f'pipeline:r{n}')
    assert enrichment.apply_retention(g, started=FUTURE) > 0
    enrichment.prune_runs(keep=0)
    enrichment.make_room(1, g)
    assert row_ids(case) == {written.id}


@pytest.mark.parametrize(('loaded', 'stale'), [('same', False), ('other', True), (None, True)],
                         ids=['same-catalog', 'other-catalog', 'no-catalog'])
def test_a_row_is_stored_stale_when_another_catalog_is_loaded_at_publication(case, catalog, loaded, stale):
    snapshot = {'same': catalog.meta.snapshot_id, 'other': 'f' * 64, None: None}[loaded]
    enrichment = EnrichmentStore(case.store)
    written = publish_context(enrichment, case.project.id, case.project.revision, build(provider(catalog)),
                              loaded_snapshot_id=snapshot)
    assert written.stale is stale
    assert [recorded.entry.stale for recorded in load_contexts(enrichment)[0]] == [stale]


def test_recording_the_same_cves_again_replaces_the_row_and_another_set_adds_one(case, catalog):
    enrichment, kev = EnrichmentStore(case.store), provider(catalog)

    def publish(context):
        return publish_context(enrichment, case.project.id, case.project.revision, context,
                               loaded_snapshot_id=catalog.meta.snapshot_id)

    first, second = build(kev), build(kev, kb='KB5000009', created_at='2099-03-03T00:00:00Z')
    assert first.context_id == second.context_id and publish(first).id == publish(second).id
    recorded = load_contexts(enrichment)[0]
    assert [(item.context.kb, item.context.created_at) for item in recorded] == [('KB5000009', '2099-03-03T00:00:00Z')]
    publish(build(kev, (KNOWN,)))
    assert len(load_contexts(enrichment)[0]) == 2


def test_damaged_rows_are_skipped_with_a_warning_and_good_rows_are_kept(case, catalog):
    enrichment = EnrichmentStore(case.store)
    context = build(provider(catalog))
    publish_context(enrichment, case.project.id, case.project.revision, context,
                    loaded_snapshot_id=catalog.meta.snapshot_id)
    db = case.store.connection
    wrong_body = json.dumps({'contract': 'kev/1', 'context_id': 'x'})
    for row_id, body, digest in (('kev-context:corrupt', '{}', '00'),
                                 ('kev-context:invalid', wrong_body, hashlib.sha256(wrong_body.encode()).hexdigest())):
        db.execute("insert into enrichment_entries values(?,'kev-context',?,1,'',?,?,'complete',0,'2099',?,?)",
                   (row_id, case.project.id, '', 'a' * 64, body, digest))
    db.commit()
    recorded, warnings = load_contexts(enrichment)
    assert [item.context for item in recorded] == [context]
    assert len(warnings) == 2 and any('integrity hash' in text for text in warnings)
    assert any('not a valid kev/1 row' in text for text in warnings)


def test_a_database_failure_becomes_a_typed_error_without_its_text(case, catalog, monkeypatch):
    enrichment = EnrichmentStore(case.store)

    def locked(*args, **kwargs):
        raise sqlite3.OperationalError('database is locked: C:\\Users\\someone\\project.sqlite3')

    monkeypatch.setattr(enrichment, 'publish', locked)
    with pytest.raises(KevError) as raised:
        publish_context(enrichment, case.project.id, case.project.revision, build(provider(catalog)),
                        loaded_snapshot_id=catalog.meta.snapshot_id)
    assert raised.value.code == 'PT-KEV-STORAGE'
    assert raised.value.message == 'cannot record the KEV context: OperationalError'

    def unreadable(*args, **kwargs):
        raise sqlite3.DatabaseError('file is not a database: C:\\Users\\someone\\project.sqlite3')

    monkeypatch.setattr(enrichment, 'entries', unreadable)
    with pytest.raises(KevError) as read_failure:
        load_contexts(enrichment)
    assert read_failure.value.code == 'PT-KEV-STORAGE'
    assert read_failure.value.message == 'cannot read the KEV contexts: DatabaseError'


def test_a_newer_project_store_refuses_the_row_with_a_typed_error(case, catalog):
    EnrichmentStore(case.store).ensure()
    case.store.connection.execute("UPDATE enrichment_meta SET value='3' WHERE key='extension_version'")
    case.store.connection.commit()
    with pytest.raises(KevError) as raised:
        publish_context(EnrichmentStore(case.store), case.project.id, case.project.revision, build(provider(catalog)),
                        loaded_snapshot_id=catalog.meta.snapshot_id)
    assert raised.value.code == 'PT-KEV-STORAGE' and row_ids(case) == set()
    assert raised.value.message == ('cannot record the KEV context: project enrichment data was written by a newer '
                                    'PatchTrace')


# --- drift -----------------------------------------------------------------------------------------------------------

def test_flip_not_listed_to_listed_is_reported(catalog):
    recorded = build(provider(catalog))
    lines = drift_lines(recorded, provider(newer(flip=True), at(2099, 3, 9)))
    assert lines == (f'{HEADLINE}{NOT_LISTED} was not listed on 2099-03-01 and is listed now (added 2099-03-05).',)


def test_the_headline_comes_first_then_changes_then_removals(catalog):
    recorded = build(provider(catalog))
    later = provider(newer(flip=True, ransomware='Known', drop=KNOWN), at(2099, 3, 9))
    assert drift_lines(recorded, later) == (
        f'{HEADLINE}{NOT_LISTED} was not listed on 2099-03-01 and is listed now (added 2099-03-05).',
        f'{HEADLINE}{UNKNOWN} changed: Known ransomware campaign use was Unknown, now Known.',
        f'{HEADLINE}{KNOWN} was listed on 2099-03-01 and is not listed now.')


@pytest.mark.parametrize(('later', 'expected'), [
    (lambda: newer(reword=True), ()),                                     # a reworded description is not a change
    (lambda: parse_fixture(SYNTHETIC), ()),                               # the very same catalog
    (lambda: None, ()),                                                   # nothing loaded: nothing to compare with
    (lambda: newer(), ())],                                               # a newer catalog with the same facts
    ids=['reworded', 'same-snapshot', 'no-catalog', 'same-facts'])
def test_no_drift_when_the_recorded_facts_still_hold(catalog, later, expected):
    assert drift_lines(build(provider(catalog)), provider(later())) == expected


def test_a_cve_the_new_catalog_cannot_judge_is_not_reported(catalog):
    recorded = build(provider(catalog), (KNOWN,))
    document = fixture_document(SYNTHETIC)
    document['vulnerabilities'] = document['vulnerabilities'][:-1]
    document['count'] = len(document['vulnerabilities'])
    assert drift_lines(recorded, provider(parse_document(document))) == (
        f'{HEADLINE}{KNOWN} was listed on 2099-03-01 and is not listed now.',)


def test_drift_names_every_changed_tracked_field(catalog):
    recorded = build(provider(catalog), (UNKNOWN,))
    document = mutated(fixture_document(SYNTHETIC), ('vulnerabilities', 1, 'forensicTriage'), 'Yes')
    document = mutated(document, ('vulnerabilities', 1, 'dueDate'), '2099-04-01')
    document = mutated(document, ('vulnerabilities', 1, 'cwes'), ['CWE-416', 'CWE-20'])
    document['catalogVersion'], document['dateReleased'] = '2099.03.08', '2099-03-08T18:00:00.0000Z'
    (line,) = drift_lines(recorded, provider(parse_document(document)))
    assert line == (f'{HEADLINE}{UNKNOWN} changed: CISA due date was 2099-03-13, now 2099-04-01; Forensic triage '
                    'required by CISA was No, now Yes; CISA weakness list was CWE-416, now CWE-416, CWE-20.')


# --- boundaries (the pure-module test skips the modules that touch the project store) ------------------------------

PACKAGE = Path(patchtrace.__file__).resolve().parent
MODULE = PACKAGE / 'kev' / 'project_context.py'
RANKING = ('patchtrace.enrichment.ranking', 'patchtrace.enrichment.cve', 'patchtrace.enrichment.signals',
           'patchtrace.enrichment.pipeline', 'patchtrace.enrichment.views', 'patchtrace.evidence')
NETWORK_AND_QT = {'PySide6', 'shiboken6', 'urllib', 'urllib3', 'socket', 'ssl', 'http', 'requests', 'httpx', 'ftplib',
                  'smtplib', 'subprocess', 'ctypes'}
NEVER_LOADED = {'PySide6', 'shiboken6', 'urllib3', 'requests', 'httpx', 'ssl', 'http', 'ftplib', 'smtplib'}


def imports_of(path: Path, module: str) -> list[str]:
    """Absolute dotted names imported anywhere in the file, lazy imports included."""
    package = module.split('.')[:-1]
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
        if isinstance(node, ast.Import):
            found += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = package[:len(package) - (node.level - 1)] if node.level else []
            name = '.'.join([*base, *(node.module.split('.') if node.module else [])]) if node.level else node.module
            found.append(name)
            found += [f'{name}.{alias.name}' for alias in node.names]
    return found


def test_project_context_touches_the_project_store_but_neither_the_ranking_nor_the_network():
    named = imports_of(MODULE, 'patchtrace.kev.project_context')
    assert 'patchtrace.enrichment.storage.EnrichmentStore' in named
    assert not {name.split('.')[0] for name in named} & NETWORK_AND_QT
    assert not [name for name in named if any(name == bad or name.startswith(bad + '.') for bad in RANKING)]
    assert not [name for name in named if name.startswith('patchtrace.ui')]
    code = textwrap.dedent(f'''
        import json, sys
        sys.path.insert(0, {str(PACKAGE.parent)!r})
        import patchtrace.kev.project_context
        top = lambda module: module.split('.')[0]
        print(json.dumps(sorted([m for m in sys.modules if top(m) in {sorted(NEVER_LOADED)!r} or m == 'urllib.request']
                                + [m for m in {RANKING!r} if m in sys.modules])))
    ''')
    result = subprocess.run([sys.executable, '-I', '-c', code], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == []


def test_project_context_reads_no_clock():
    tree = ast.parse(MODULE.read_text(encoding='utf-8'))
    clock = {'now', 'utcnow', 'today', 'monotonic', 'perf_counter', 'time_ns'}
    assert [node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute) and node.attr in clock] == []
    assert project_context.KIND == 'kev-context'
