"""SPEC-50 RPT2-6: headless section adapters over a real (synthetic sample) project; hermetic, no Qt."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from test_pilot_store import put as put_pilot_result
from test_secondary_store import _set

from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.intelligence.storage import AdvisoryStore
from patchtrace.report2.adapters import UnifiedReferencePort, _Rows, collect_from_service
from patchtrace.secondary import publish_secondary
from patchtrace.service import ProjectService

CSAF = Path(__file__).parent / 'fixtures' / 'csaf' / 'synthetic-advisory-rev1.json'


@pytest.fixture(autouse=True)
def no_artifact(tmp_path_factory, monkeypatch):
    monkeypatch.setattr('patchtrace.calibration.artifact.BUNDLED_DIR', tmp_path_factory.mktemp('nocal'))


@pytest.fixture
def service(tmp_path):
    with ProjectService.sample(tmp_path / 'case') as opened:
        yield opened


def publish_engine(service, engine: str, sha: str):
    sides = {a.side: a.sha256 for a in service.project.artifacts}
    run = next(r for r in service.project.runs if r.status == 'completed' and r.raw_sha256)
    guard = Guard(service.project.id, run.id, run.raw_sha256, sha)
    match_set = _set(sides['older'], sides['newer'], sha)
    if engine == 'bindiff':
        row = match_set.matches[0].model_copy(update={'engine': 'bindiff', 'confidence_milli': 900,
                                                      'confidence_text': '0.9'})
        match_set = match_set.model_copy(update={'engine': 'bindiff', 'matches': (row,)})
    return publish_secondary(EnrichmentStore(service.store), guard, guard, service.project.revision, match_set)


def test_empty_project_has_no_optional_sections(service):
    sections = collect_from_service(service)
    assert (sections.engine_evidence, sections.advisories, sections.leads, sections.series) == (None,) * 4
    assert not any('engine_evidence' in u or 'advisories' in u or 'leads' in u for u in sections.unknowns)


def test_collecting_never_writes_to_the_project(tmp_path):
    with ProjectService.sample(tmp_path / 'ro') as opened:
        before = (opened.root / 'project.sqlite3').read_bytes()
        collect_from_service(opened)
        assert (opened.root / 'project.sqlite3').read_bytes() == before


def test_series_stays_none_because_no_project_scoped_record_exists(service):
    assert collect_from_service(service).series is None


def test_engine_evidence_lists_each_engine_and_never_scores_a_missing_one(service):
    publish_engine(service, 'rz-diff', '1' * 64)
    sections = collect_from_service(service)
    evidence = sections.engine_evidence
    assert [e.name for e in evidence.engines] == ['rz-diff'] and len(evidence.rows) == len(service.project.matches)
    assert not evidence.stale
    assert all(c.engine != 'bindiff' for row in evidence.rows for c in row.channels)
    assert 'engine_evidence: bindiff has no stored match set; unknown, not a negative result' in sections.unknowns


def test_engine_evidence_two_engines_stay_separate(service):
    publish_engine(service, 'rz-diff', '1' * 64)
    publish_engine(service, 'bindiff', '2' * 64)
    sections = collect_from_service(service)
    assert sorted(e.name for e in sections.engine_evidence.engines) == ['bindiff', 'rz-diff']
    assert not any('has no stored match set' in u for u in sections.unknowns)


def test_advisories_are_vendor_claims_with_inert_text(service):
    AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id, service.project.revision).add(
        CSAF.read_bytes(), origin='local-import', uri=None, file_name='a.json', retrieved_at='2099-03-01T00:00:00Z')
    advisories = collect_from_service(service).advisories
    assert advisories and {a.kind for a in advisories} >= {'cve'}
    assert all(a.claim_level == 'vendor-claim' and a.snapshot_digest and a.fetched_at for a in advisories)
    assert all(a.id.startswith(('CVE-', 'CWE-')) for a in advisories)
    assert all('\u202e' not in a.text for a in advisories)


def test_failing_producer_gives_none_and_a_recorded_unknown(service, monkeypatch):
    publish_engine(service, 'rz-diff', '1' * 64)

    def boom(self):
        raise RuntimeError('disk on fire')
    monkeypatch.setattr(AdvisoryStore, 'advisories', boom)
    sections = collect_from_service(service)
    assert sections.advisories is None and sections.engine_evidence is not None
    assert any(u.startswith('advisories: producer failed (RuntimeError)') for u in sections.unknowns)
    assert not any('disk on fire' in u for u in sections.unknowns)


def test_build_facts_are_observed_in_file_and_timestamps_are_claims(service):
    facts = collect_from_service(service).build_facts
    assert facts, 'expected at least the claimed COFF timestamp'
    assert {f.side for f in facts} == {'older', 'newer'}
    assert all(f.claim_level == 'observed-in-file' for f in facts)
    stamps = [f for f in facts if f.fact == 'timestamp_claim']
    assert stamps and all(f.value.startswith('claimed ') for f in stamps)


def test_unreadable_artifact_is_unknown_not_fatal(service):
    for artifact in service.project.artifacts:
        path = service.root / artifact.relative_path
        path.chmod(0o600)  # ingested artifacts are deliberately read-only on both supported platforms
        path.write_bytes(b'tampered')
    sections = collect_from_service(service)
    assert sections.build_facts is None
    assert sum('could not be read' in u for u in sections.unknowns) == 2


def test_leads_come_from_a_current_stored_pilot_result(service):
    put_pilot_result(service, EnrichmentStore(service.store))
    sections = collect_from_service(service)
    assert sections.leads
    for lead in sections.leads:
        assert lead.channels and 'not a probability' in lead.statement


def test_stale_pilot_result_is_omitted_with_a_reason(service):
    put_pilot_result(service, EnrichmentStore(service.store), swapped=True)
    sections = collect_from_service(service)
    assert sections.leads is None
    assert any(u.startswith('leads: the stored pilot result is stale') for u in sections.unknowns)


def test_unified_reference_uses_the_read_model_not_the_default_plan(service, monkeypatch):
    seen = []
    from patchtrace.unified import read_model
    monkeypatch.setattr(read_model, 'capture_candidates', lambda s: seen.append('capture') or 'candidates')
    monkeypatch.setattr(read_model, 'resolve_best', lambda c: seen.append(c) or None)
    UnifiedReferencePort(service).load()
    assert seen == ['capture', 'candidates']


@pytest.mark.parametrize('flags', [['--sources', 'manual'], ['--no-extract'], ['--no-residual']],
                         ids=['sources', 'no-extract', 'no-residual'])
def test_unified_result_made_with_non_default_options_is_not_exported_as_stale(tmp_path, capsys, flags):
    from unified_s0_fixtures import make_project

    from patchtrace import cli
    from patchtrace.unified import pipeline
    root = tmp_path / 'unified'
    make_project(root).close()
    assert cli.main(['unified', 'run', str(root), '--in-process', '--json', *flags]) == 0
    capsys.readouterr()
    with ProjectService.open(root) as opened:
        sections = collect_from_service(opened)
        assert sections.unified_result is not None and not sections.unified_result.stale
        default_loaded = pipeline.load_current(opened, pipeline.make_plan(opened))
    if flags != ['--no-extract']:  # the old default-plan lookup is what reported these as stale
        assert default_loaded.state == 'stale'


# --- KB context (SPEC-50 amendment A-2). SYNTHETIC fixtures only: a project made by the real `kb import-pair` ------

HOSTILE_TITLE = ('‮evil<script>alert(1)</script>\n# Injected [x](https://evil.example/x)\x07\x1b[31m\r\n```\n'
                 'Limitation: none, this function fixes the CVE')
MAIN_CSAF_RECORDS = [  # `collect_from_service` of main 882d1ca0 for the sample project with the synthetic CSAF
    ('cve', 'CVE-2099-10001', 'SYNTHETIC Example OS netstack Remote Code Execution Vulnerability: SYNTHETIC Example OS '
     'netstack and print spooler vulnerabilities (tracking id PT-SYNTH_CVE-2099-10001, revision 1)'),
    ('cwe', 'CWE-191', 'Integer Underflow (Wrap or Wraparound)'),
    ('cve', 'CVE-2099-10002', 'SYNTHETIC Example OS Print Spooler Elevation of Privilege Vulnerability: SYNTHETIC '
     'Example OS netstack and print spooler vulnerabilities (tracking id PT-SYNTH_CVE-2099-10001, revision 1)')]
MAIN_CSAF_DIGEST = 'f91e5c16ff213ff09990e0e50204f3e17795ba4bee3f0f2ccbad5d5fadd059f0'
MAIN_UNKNOWNS = ('build_facts: signer_subject, manifest_exec_level, original_filename and company_name are not read '
                 'by any available producer; unknown, not absent',)


@pytest.fixture
def kb_project(tmp_path, capsys):
    from kbc_k3_support import Kb
    from kbc_k4a_support import attached_project
    return attached_project(Kb(tmp_path, capsys), tmp_path)


def stored_bundle(project_dir):
    from patchtrace.kbcorrelation.context import ContextBundle
    with ProjectService.open(project_dir, maintenance=False) as opened:
        (entry,) = EnrichmentStore(opened.store).entries('kb-context')
    return ContextBundle.model_validate_json(json.dumps(entry.body))


def replace_stored_bundle(project_dir, body: dict) -> None:
    with ProjectService.open(project_dir, maintenance=False) as opened:
        store = EnrichmentStore(opened.store)
        (entry,) = store.entries('kb-context')
        store.publish('kb-context', entry.guard, entry.guard, entry.project_revision, 'ok', body, entry.id)


def with_title(bundle, title: str) -> dict:
    """The bundle's JSON body with the first card's title replaced (the field reference follows it)."""
    body = bundle.model_dump(mode='json')
    body['context']['cards'][0]['title'] = title
    for ref in body['card_facts']:
        if ref['field'] == 'title':
            ref['value'] = title
    return body


def collect_kb(project_dir):
    with ProjectService.open(project_dir, maintenance=False) as opened:
        return collect_from_service(opened)


def test_kb_context_exports_the_lead_kb_and_one_cve_record_per_card(kb_project):
    from patchtrace.kbcorrelation.context import LIMITATION
    bundle = stored_bundle(kb_project)
    (source,) = bundle.sources
    sections = collect_kb(kb_project)
    advisories = sections.advisories
    assert [(a.kind, a.id, a.snapshot_digest) for a in advisories] == [
        ('kb', 'KB5099001', source.sha256), ('cve', 'CVE-2099-20001', source.sha256)]
    assert [a.id for a in advisories if a.kind == 'cve'] == [c.cve for c in bundle.context.cards]
    assert all(a.claim_level == 'vendor-claim' and not a.truncated for a in advisories)
    assert all(a.text.endswith(f'\nLimitation: {LIMITATION}') for a in advisories)
    kb, cve = advisories
    assert 'CVE-2099-20001' in kb.text and bundle.context_key in kb.text and bundle.investigation_id in kb.text
    assert cve.text.split('\n')[:3] == [
        'Title: Out-of-bounds read in the item reader', 'CWE: CWE-125 (stated by vendor, CVRF)',
        'Applicability: unknown (no loaded document states applicability to these two files)']
    assert f'Source: cvrf-month 2099-Feb SHA-256 {source.sha256}' in cve.text.split('\n')
    assert cve.kev_listed is None and (kb.vendor, kb.url_text, kb.fetched_at) == ('', '', '')
    assert any('vendor, address and retrieval time are not stored' in u for u in sections.unknowns)
    assert any(u.startswith('advisories (KB context): CVE-2099-20003 is mentioned in advisory text only')
               for u in sections.unknowns)


def test_collecting_never_writes_to_a_kb_project(kb_project):
    def state():  # every file but the open lock, which Windows byte-range locks against readers
        return {p.relative_to(kb_project).as_posix(): p.read_bytes() for p in sorted(kb_project.rglob('*'))
                if p.is_file() and p.name != '.patchtrace.lock'}
    with ProjectService.open(kb_project, maintenance=False) as opened:
        before = state()
        assert 'project.sqlite3' in before and collect_from_service(opened).advisories
        assert state() == before


def test_project_without_a_kb_context_exports_what_main_exports(service, monkeypatch):
    from patchtrace.report2 import adapters
    AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id, service.project.revision).add(
        CSAF.read_bytes(), origin='local-import', uri=None, file_name='a.json', retrieved_at='2099-03-01T00:00:00Z')
    sections = collect_from_service(service)
    assert [(a.kind, a.id, a.text) for a in sections.advisories] == MAIN_CSAF_RECORDS
    assert {a.snapshot_digest for a in sections.advisories} == {MAIN_CSAF_DIGEST}
    assert sections.unknowns == MAIN_UNKNOWNS
    monkeypatch.setattr(adapters, '_kb_context', lambda service, unknowns: ())
    assert collect_from_service(service) == sections


def test_kb_context_records_follow_the_csaf_records(kb_project):
    with ProjectService.open(kb_project, maintenance=False) as opened:
        AdvisoryStore(opened.root, EnrichmentStore(opened.store), opened.project.id, opened.project.revision).add(
            CSAF.read_bytes(), origin='local-import', uri=None, file_name='a.json',
            retrieved_at='2099-03-01T00:00:00Z')
        advisories = collect_from_service(opened).advisories
    assert [(a.kind, a.id) for a in advisories] == [(k, i) for k, i, _ in MAIN_CSAF_RECORDS] + [
        ('kb', 'KB5099001'), ('cve', 'CVE-2099-20001')]


def test_kb_context_of_another_file_pair_is_omitted_with_a_reason(kb_project):
    bundle = stored_bundle(kb_project)
    replace_stored_bundle(kb_project, bundle.model_dump(mode='json') | {'older_sha': bundle.newer_sha,
                                                                       'newer_sha': bundle.older_sha})
    sections = collect_kb(kb_project)
    assert sections.advisories is None
    assert [u for u in sections.unknowns if 'KB context' in u] == [
        'advisories: the stored KB context was prepared for another file pair than this project holds; its kb and '
        'cve records are omitted']


@pytest.mark.parametrize('change', [{'surprise': '<b>x</b>'}, {'lead': {'kind': 'kb', 'value': 'KB12', 'raw': 'x'}}],
                         ids=['schema', 'kb-id'])
def test_invalid_kb_context_is_unknown_and_never_refuses_the_export(kb_project, change):
    replace_stored_bundle(kb_project, stored_bundle(kb_project).model_dump(mode='json') | change)
    sections = collect_kb(kb_project)
    assert sections.advisories is None and sections.build_facts
    (line,) = [u for u in sections.unknowns if 'KB context' in u]
    assert line.startswith('advisories (KB context): producer failed (')
    assert line.endswith('; its kb and cve records are omitted') and '<b>' not in line and 'KB12' not in line


def test_hostile_kb_context_text_is_inert_in_markdown_and_html(kb_project):
    from test_report2_render import _outside_fences
    from test_report2_support import FIXED_TIME

    from patchtrace.kbcorrelation.context import LIMITATION
    from patchtrace.report2.assemble import build_report
    from patchtrace.report2.render_html import render_html
    from patchtrace.report2.render_json import finalize
    from patchtrace.report2.render_md import render_md
    from patchtrace.reports import _snapshot
    replace_stored_bundle(kb_project, with_title(stored_bundle(kb_project), HOSTILE_TITLE))
    with ProjectService.open(kb_project, maintenance=False) as opened:
        sections = collect_from_service(opened)
        data = finalize(build_report(_snapshot(opened.project, False, True, None), include_code=False,
                                     include_notes=True, sections=sections, generated_at=FIXED_TIME))
    record = next(a for a in data['advisories'] if a['kind'] == 'cve')
    lines = record['text'].split('\n')
    # one stored field is one line: the title cannot forge a second "Limitation:" line or close the record
    assert lines[0].startswith('Title: <U+202E>evil<script>alert(1)</script>?# Injected')
    assert [line for line in lines if line.startswith('Limitation:')] == [f'Limitation: {LIMITATION}']
    assert not any(ord(c) < 0x20 and c != '\n' for c in record['text']) and '‮' not in record['text']
    page, md = render_html(data), render_md(data)
    assert '<script' not in page and ' href=' not in page and '&lt;script&gt;alert(1)&lt;/script&gt;' in page
    assert not any(c in page or c in md for c in ('‮', '\x07', '\x1b'))
    outside = '\n'.join(_outside_fences(md))
    assert '](' not in outside and '<' not in outside and 'Injected' not in outside
    assert 'evil<script>alert(1)</script>' in md  # inside the fence, as inert text
    fence = max(re.findall(r'(?m)^(`{3,})$', md), key=len)
    assert len(fence) >= 4  # longer than the backtick run the title carries


def _derived(bundle, **update):
    return bundle.model_copy(update=update)


def test_kb_record_without_a_single_source_has_no_digest_and_lists_each(kb_project):
    from patchtrace.report2 import kb_context
    bundle = stored_bundle(kb_project)
    (source,) = bundle.sources
    other = source.model_copy(update={'doc_id': 'd' * 64, 'sha256': 'e' * 64, 'release_id': '2099-Mar'})
    records, notes = kb_context.records(_derived(bundle, sources=(source, other)))
    kb, cve = records
    assert kb.snapshot_digest is None and cve.snapshot_digest == source.sha256  # the card names its own document
    assert [line for line in kb.text.split('\n') if line.startswith('Source: ')] == [
        f'Source: cvrf-month 2099-Feb SHA-256 {source.sha256}', f'Source: cvrf-month 2099-Mar SHA-256 {"e" * 64}']
    assert any('1 KB context record(s) rest on more than one source document' in n for n in notes)
    legacy, _ = kb_context.records(_derived(bundle, sources=(source, other), card_facts=()))
    assert [r.snapshot_digest for r in legacy] == [None, None]
    single, _ = kb_context.records(_derived(bundle, card_facts=()))
    assert [r.snapshot_digest for r in single] == [source.sha256, source.sha256]


def test_a_lead_that_is_not_a_kb_gives_no_kb_record_and_says_so(kb_project):
    from patchtrace.report2 import kb_context
    bundle = stored_bundle(kb_project)
    lead = bundle.lead.model_copy(update={'kind': 'cve', 'value': 'CVE-2099-20001'})
    records, notes = kb_context.records(_derived(bundle, lead=lead))
    assert [(r.kind, r.id) for r in records] == [('cve', 'CVE-2099-20001')]
    assert any('has a cve lead and the project stores no KB id for it' in n for n in notes)


@pytest.mark.parametrize('ident', ['KB1234', 'KB1234567890'], ids=['4', '10'])
def test_a_canonical_kb_lead_of_any_width_is_exported(kb_project, ident):
    """KBA-07 end to end: such a lead used to refuse the whole export with PT-EXPORT-SECTION."""
    from patchtrace.report2 import kb_context
    from patchtrace.report2.sections.advisories import build_advisories
    bundle = stored_bundle(kb_project)
    records, _ = kb_context.records(_derived(bundle, lead=bundle.lead.model_copy(update={'value': ident})))
    assert build_advisories(_Rows(records)).value[0].id == ident


@pytest.mark.parametrize('stored,expected', [('listed', True), ('not-in-snapshot', False), ('not-loaded', None)],
                         ids=['listed', 'not-in-snapshot', 'not-loaded'])
def test_kb_context_kev_state_is_restated_and_unknown_stays_unknown(kb_project, stored, expected):
    from patchtrace.report2 import kb_context
    bundle = stored_bundle(kb_project)
    card = bundle.context.cards[0].model_copy(update={'kev': stored})
    records, _ = kb_context.records(_derived(bundle, context=bundle.context.model_copy(update={'cards': (card,)})))
    assert [r.kev_listed for r in records] == [None, expected]


def test_the_largest_stored_fields_never_push_the_limitation_out(kb_project):
    from patchtrace.kbcorrelation.context import LIMITATION
    from patchtrace.report2 import kb_context
    from patchtrace.report2.sections.advisories import build_advisories
    bundle = stored_bundle(kb_project)
    (source,) = bundle.sources
    wide = '‮' * 1000  # every character grows to 8 when it is neutralized
    sources = tuple(source.model_copy(update={'doc_id': f'{i:064x}', 'sha256': f'{i + 16:064x}', 'kind': wide,
                                              'release_id': wide}) for i in range(12))
    cards = tuple(bundle.context.cards[0].model_copy(update={'cve': f'CVE-2099-{30000 + i}', 'title': wide,
                                                             'applicability': wide}) for i in range(40))
    worst = _derived(bundle, sources=sources, card_facts=(),
                     context=bundle.context.model_copy(update={'cards': cards}))
    records, _ = kb_context.records(worst)
    built = build_advisories(_Rows(records)).value
    assert len(built) == 41 and not any(a.truncated for a in built)
    assert all(a.text.endswith(f'\nLimitation: {LIMITATION}') for a in built)
    assert all('more source document(s)' in a.text for a in built)


def test_the_latest_kb_context_is_the_one_kb_export_uses(kb_project):
    from patchtrace.report2 import kb_context
    body = stored_bundle(kb_project).model_dump(mode='json')
    older = body | {'base_revision': body['base_revision'] - 1, 'context_key': 'f' * 64}
    newer = body | {'base_revision': body['base_revision'] + 1, 'context_key': '0' * 64}
    chosen = kb_context.latest(json.dumps(b) for b in (newer, older, body))
    assert (chosen.base_revision, chosen.context_key) == (newer['base_revision'], '0' * 64)
    assert kb_context.latest(()) is None
