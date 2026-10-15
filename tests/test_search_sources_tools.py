"""WB1 S8: tool, advisory and CVE source groups over synthetic stores (presence/delta semantics, secret redaction)."""
from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path
from types import SimpleNamespace

import pytest
from search_synergy_builders import attention, make_project

from patchtrace.enrichment.contracts import AttributedText, AttributedValue, CveSnapshot
from patchtrace.intelligence.csaf import normalize, validate
from patchtrace.intelligence.tools.common import (
    CapabilityEvidence,
    EnvironmentEvidence,
    EvidenceLink,
    StringEvidence,
    TaxonomyLabel,
    ToolEvidenceSet,
    ToolManifest,
    ToolRun,
)
from patchtrace.search.contracts import SearchRequest
from patchtrace.search.query import parse_query
from patchtrace.search.segment import Flag, open_segment
from patchtrace.search.service import SearchService
from patchtrace.search.sources.advisory import advisory_specs, plain
from patchtrace.search.sources.tools import tool_specs

FIXTURES = Path(__file__).parent / 'fixtures' / 'csaf'
SHA = {'older': 'a' * 64, 'newer': 'b' * 64}
SECRET = 'password=hunter2hunter2'
MANIFEST = ToolManifest(engine='floss', version='3.1.1', executable_sha256='e' * 64, license='Apache-2.0',
                        rules_source='embedded', supported=True)


def link(side: str, function: str | None = None, rva: int | None = None) -> EvidenceLink:
    return EvidenceLink(tool_run_id=f'run-{side}', artifact_sha256=SHA[side], project_function_id=None if function is None
                        else function, function_id=None if function is None else f'rva:0x{rva or 0:x}', rva=rva)


def string(side: str, text: str, function: str | None = None, rva: int | None = None) -> StringEvidence:
    return StringEvidence(value_hash=hashlib.sha256(text.encode()).hexdigest(), length=len(text), display_value=text,
                          encoding='ASCII', type='static', source_location=link(side, function, rva),
                          confidence_class='tool-reported', extraction_method='floss-static',
                          source_run_id=f'run-{side}')


def evidence(side: str, engine: str = 'floss', *, strings=(), capabilities=(), environment=(), truncated=False):
    return ToolEvidenceSet(run_id=f'run-{side}', engine=engine, side=side, artifact_sha256=SHA[side], cache_key='c' * 64,
                           config_digest='d' * 64, strings=tuple(strings), capabilities=tuple(capabilities),
                           environment=tuple(environment), truncated=truncated)


def run(side: str, engine: str = 'floss', status: str = 'ok') -> ToolRun:
    produced = status in ('ok', 'none-found')
    return ToolRun(run_id=f'run-{side}', engine=engine, side=side, input_artifact_hash=SHA[side], config_digest='d' * 64,
                   cache_key='c' * 64, started_at='t', elapsed=0, status=status, profile='context',
                   manifest=MANIFEST.model_copy(update={'engine': engine}),
                   error_code=None if produced else 'PT-TOOL-OUTPUT')


class Port:
    """`ToolStore.latest` shape: {(engine, side): (run, evidence)}."""

    def __init__(self, entries):
        self.entries = entries

    def latest(self, engine, side):
        return self.entries.get((engine, side))


def pair(engine, side, **kwargs):
    return (engine, side), (run(side, engine), evidence(side, engine, **kwargs))


def spec(port, group):
    return next(s for s in tool_specs(port) if s.group == group)


def docs(port, group):
    return list(spec(port, group).documents())


def capability(side, rule='write file', *, function='f-new-1', rva=0x1000, namespace='host-interaction/file-system'):
    return CapabilityEvidence(
        rule_id=rule, rule_sha256='f' * 64, namespace=namespace, scope='function', address_space='relative', address=rva,
        location=link(side, function, rva).model_copy(update={'attribution': 'function-start'}), kind='capability',
        source_run_id=f'run-{side}', attack=('T1055',),
        labels=(TaxonomyLabel(scheme='attack', group='Defense Evasion', name='Process Injection', ident='T1055'),))


# ---------------------------------------------------------------------------------------------------- tools

def test_six_tool_groups_with_engine_kinds():
    groups = {s.group: s.kinds for s in tool_specs(Port({}))}
    assert groups == {f'tool:{e}:{s}': (k,) for e, k in (('floss', 'string'), ('capa', 'capability'), ('diec', 'build'))
                      for s in ('older', 'newer')}


@pytest.mark.parametrize('port', [None, Port({})], ids=['no-port', 'no-run'])
def test_missing_store_or_run_is_unavailable_never_empty(port):
    for item in tool_specs(port):
        assert (item.status, item.buildable, item.digest16) == ('unavailable', False, None)
        assert item.reason


def test_failed_run_is_unavailable():
    port = Port({('floss', 'older'): (run('older', status='timeout'), evidence('older'))})
    assert spec(port, 'tool:floss:older').status == 'unavailable'


def test_none_found_is_an_empty_but_indexed_group():
    port = Port({('floss', 'older'): (run('older', status='none-found'), evidence('older'))})
    item = spec(port, 'tool:floss:older')
    assert item.buildable and list(item.documents()) == []


def test_string_subject_is_the_function_id_and_hash_is_searchable():
    port = Port(dict([pair('floss', 'newer', strings=[string('newer', 'Container size', 'm-f1-new', 0x1010),
                                                    string('newer', 'loose text')])]))
    items = {d.display: d for d in docs(port, 'tool:floss:newer')}
    located = items['Container size']
    assert (located.kind, located.side, located.subject, located.rva) == ('string', 'newer', 'm-f1-new', 0x1010)
    assert located.value_sha == hashlib.sha256(b'Container size').hexdigest()
    assert items['loose text'].subject == hashlib.sha256(b'loose text').hexdigest()[:16]


def test_secrets_are_redacted_but_keep_their_hash():
    port = Port(dict([pair('floss', 'newer', strings=[string('newer', SECRET, 'f1')])]))
    (doc,) = docs(port, 'tool:floss:newer')
    assert doc.display == '[redacted: credential-assignment]' and doc.flags & Flag.SECRET
    assert doc.value_sha == hashlib.sha256(SECRET.encode()).hexdigest()
    assert 'hunter2' not in repr(doc)


def test_capability_doc_has_rule_name_namespace_and_taxonomy():
    port = Port(dict([pair('capa', 'newer', capabilities=[capability('newer')])]))
    (doc,) = docs(port, 'tool:capa:newer')
    assert (doc.kind, doc.subject, doc.rva, doc.extra) == ('capability', 'f-new-1', 0x1000, 'host-interaction/file-system')
    assert doc.name_raw == 'write file' and 'T1055' in doc.text_body and 'Process Injection' in doc.text_body
    assert spec(port, 'tool:capa:newer').table_sets == ('name', 'text')


def test_library_and_limitation_capabilities_are_not_indexed():
    odd = capability('newer', 'ignored').model_copy(update={'kind': 'limitation'})
    port = Port(dict([pair('capa', 'newer', capabilities=[odd])]))
    assert docs(port, 'tool:capa:newer') == []


def test_environment_doc_keeps_certainty_visible():
    item = EnvironmentEvidence(category='compiler', toolchain='Synthetic C 1.0', detector_rule='rule-x', heuristic=True,
                               certainty='heuristic', version='19.3', source_run_id='run-older')
    port = Port(dict([pair('diec', 'older', environment=[item])]))
    (doc,) = docs(port, 'tool:diec:older')
    assert (doc.kind, doc.subject, doc.extra) == ('build', 'compiler', 'heuristic')
    assert 'Synthetic C 1.0 19.3' in doc.display


def test_truncated_output_is_stated_in_the_coverage_reason():
    port = Port(dict([pair('floss', 'older', truncated=True)]))
    assert 'only part' in spec(port, 'tool:floss:older').reason


def test_documents_and_digest_ignore_evidence_order():
    items = [string('newer', f's{i}', f'f{i % 2}', i) for i in range(8)]
    shuffled = list(items)
    random.Random(4).shuffle(shuffled)
    first = Port(dict([pair('floss', 'newer', strings=items)]))
    second = Port(dict([pair('floss', 'newer', strings=shuffled)]))
    assert docs(first, 'tool:floss:newer') == docs(second, 'tool:floss:newer')
    assert spec(first, 'tool:floss:newer').digest16 == spec(second, 'tool:floss:newer').digest16


def test_digest_follows_the_cache_key():
    one = Port(dict([pair('floss', 'newer')]))
    changed = evidence('newer').model_copy(update={'cache_key': '9' * 64})
    two = Port({('floss', 'newer'): (run('newer'), changed)})
    assert spec(one, 'tool:floss:newer').digest16 != spec(two, 'tool:floss:newer').digest16


# -------------------------------------------------------------------------------------- presence and delta

def ask(text: str) -> SearchRequest:
    return SearchRequest(plan=parse_query(text))


def with_tools(tmp_path, older_strings, newer_strings, comparable=True):
    port = Port({**dict([pair('floss', 'older', strings=older_strings)]),
                 **dict([pair('floss', 'newer', strings=newer_strings)])})
    return SearchService(make_project(tmp_path / 'project'), tmp_path / 'cache', attention=attention,
                         comparable=lambda engine: comparable, extra_specs=lambda _request: tool_specs(port))


def string_hit(service, text):
    result = service.search(ask(f'kind:string "{text}"'))
    return next(h for h in result.hits if any(e.kind == 'string' for e in h.evidence))


def test_presence_absent_only_when_the_other_run_is_comparable(tmp_path):
    new_only = [string('newer', 'Container size exceeds limit', 'm-f1-new', 0x1010)]
    hit = string_hit(with_tools(tmp_path / 'a', [], new_only), 'Container size exceeds limit')
    assert (hit.presence.older, hit.presence.newer) == ('absent', 'present')
    unknown = string_hit(with_tools(tmp_path / 'b', [], new_only, comparable=False), 'Container size exceeds limit')
    assert (unknown.presence.older, unknown.presence.newer) == ('unknown', 'unknown')


def test_presence_present_when_both_runs_hold_the_string(tmp_path):
    both = lambda side: [string(side, 'Container size exceeds limit', f'm-f1-{side}', 0x1010)]  # noqa: E731
    hit = string_hit(with_tools(tmp_path, both('older'), both('newer')), 'Container size exceeds limit')
    assert (hit.presence.older, hit.presence.newer) == ('present', 'present')


def test_missing_sibling_run_leaves_presence_unknown(tmp_path):
    port = Port(dict([pair('floss', 'newer', strings=[string('newer', 'Container size exceeds limit', 'm-f1-new')])]))
    service = SearchService(make_project(tmp_path / 'project'), tmp_path / 'cache', attention=attention,
                            comparable=lambda engine: True, extra_specs=lambda _request: tool_specs(port))
    hit = string_hit(service, 'Container size exceeds limit')
    assert (hit.presence.older, hit.presence.newer) == ('unknown', 'unknown')


def test_secret_text_is_not_searchable_but_its_hash_is(tmp_path):
    service = with_tools(tmp_path, [], [string('newer', SECRET, 'm-f1-new')])
    assert service.search(ask('hunter2hunter2')).status in ('no-results', 'partial')
    found = service.search(ask(hashlib.sha256(SECRET.encode()).hexdigest()))
    assert found.hits and found.hits[0].evidence[0].title == '[redacted: credential-assignment]'
    blobs = b''.join(p.read_bytes() for p in (tmp_path / 'cache').rglob('*.sqlite3'))
    assert blobs and b'hunter2' not in blobs


# ----------------------------------------------------------------------------------------------- advisories

def facts(name):
    raw = (FIXTURES / name).read_bytes()
    parsed, report = validate.load_document(raw)
    return normalize.normalize(parsed, report, hashlib.sha256(raw).hexdigest())


class Advisories:
    def __init__(self, items, warnings=()):
        self.items, self.warnings = items, list(warnings)

    def advisories(self):
        return self.items, self.warnings


def stored(name, superseded=False, retrieved='2099-02-01T00:00:00Z'):
    return SimpleNamespace(source=SimpleNamespace(retrieved_at=retrieved), facts=facts(name), superseded=superseded,
                           retrievals=1)


def adv_docs(*items, warnings=()):
    found = advisory_specs(Advisories(list(items), warnings), None)[0]
    return found, list(found.documents())


def test_every_revision_is_indexed_and_the_superseded_one_is_flagged():
    _, found = adv_docs(stored('synthetic-advisory-rev1.json', superseded=True), stored('synthetic-advisory-rev2.json'))
    advisories = [d for d in found if d.kind == 'advisory']
    assert len(advisories) == 2
    flagged = [d for d in advisories if d.extra.startswith('superseded')]
    assert len(flagged) == 1 and 'CVE-2099-10001' in flagged[0].extra


def test_advisory_markup_is_stripped_and_text_is_capped():
    _, found = adv_docs(stored('synthetic-advisory-rev1.json'))
    body = next(d for d in found if d.kind == 'advisory').text_body
    assert '<script>' not in body and '<img' not in body and 'alert(1)' in body
    assert len(plain('x' * 200_000).encode()) <= 64 * 1024
    assert plain('a<b>c</b>d') == 'a c d'


def test_cwe_documents_and_group_status():
    spec_adv, found = adv_docs(stored('synthetic-advisory-rev1.json'))
    cwe = [d for d in found if d.kind == 'cwe']
    assert cwe and cwe[0].subject == 'CWE-191' and 'Integer Underflow' in cwe[0].display
    assert spec_adv.buildable and spec_adv.kinds == ('advisory', 'cwe', 'kb')


def test_kb_ids_become_documents():
    item = stored('synthetic-advisory-rev1.json')
    vuln = item.facts.vulnerabilities[0]
    fix = vuln.remediations[0].model_copy(update={'details': 'Install update kb5012345 now'})
    patched = vuln.model_copy(update={'remediations': (fix, *vuln.remediations[1:])})
    item.facts = item.facts.model_copy(update={'vulnerabilities': (patched, *item.facts.vulnerabilities[1:])})
    _, found = adv_docs(item)
    kb = [d for d in found if d.kind == 'kb']
    assert [d.subject for d in kb] == ['KB5012345'] and 'PT-SYNTH_CVE-2099-10001' in kb[0].extra


def test_order_and_digest_ignore_store_order():
    first = advisory_specs(Advisories([stored('synthetic-advisory-rev1.json'), stored('synthetic-advisory-rev2.json')]), None)
    second = advisory_specs(Advisories([stored('synthetic-advisory-rev2.json'), stored('synthetic-advisory-rev1.json')]), None)
    assert first[0].digest16 == second[0].digest16
    assert list(first[0].documents()) == list(second[0].documents())


def test_skipped_advisories_are_reported_in_the_reason():
    spec_adv, _ = adv_docs(stored('synthetic-advisory-rev1.json'), warnings=['broken row'])
    assert '1 advisory file(s)' in spec_adv.reason


def test_missing_ports_make_both_groups_unavailable():
    adv, cve = advisory_specs(None, None)
    assert [(s.group, s.status) for s in (adv, cve)] == [('adv', 'unavailable'), ('cve', 'unavailable')]


# --------------------------------------------------------------------------------------------- cve snapshots

def snapshot(cve='CVE-2099-10001', retrieved='2099-02-01T00:00:00Z', text='An oversized container size.', **extra):
    sid = hashlib.sha256(f'{cve}{retrieved}{text}'.encode()).hexdigest()
    return CveSnapshot(snapshot_id=sid, cve_id=cve, normalization_version=1, response_digests={'nvd': 'a' * 64},
                       retrieved_at=retrieved, descriptions=(AttributedText(source='nvd', text=text),), **extra)


class Snapshots:
    def __init__(self, rows):
        self.rows = rows

    def snapshots(self):
        return self.rows


def cve_docs(rows):
    spec_cve = advisory_specs(None, Snapshots(rows))[1]
    return spec_cve, list(spec_cve.documents())


def test_cve_description_and_cwe_documents():
    row = snapshot(cwes=(AttributedValue(source='nvd', value='CWE-787'),),
                   products=(AttributedValue(source='nvd', value='synthetic netstack'),))
    spec_cve, found = cve_docs([row])
    cve = next(d for d in found if d.kind == 'cve')
    assert (cve.subject, cve.display) == ('CVE-2099-10001', 'CVE-2099-10001 An oversized container size.')
    assert 'nvd: An oversized' in cve.text_body and 'synthetic netstack' in cve.text_body
    assert [(d.kind, d.subject) for d in found if d.kind == 'cwe'] == [('cwe', 'CWE-787')]
    assert spec_cve.buildable


def test_older_snapshots_stay_indexed_but_flagged_and_conflicts_are_kept():
    old = snapshot(retrieved='2099-01-01T00:00:00Z', text='first reading')
    new = snapshot(conflicts=('nvd and msrc disagree',))
    spec_cve, found = cve_docs([new, old])
    flags = {d.text_body.partition(': ')[2]: d.extra for d in found if d.kind == 'cve'}
    assert flags['first reading'].startswith('older snapshot')
    assert 'older snapshot' not in flags['An oversized container size.'] and 'conflict' in flags[
        'An oversized container size.']
    assert spec_cve.digest16 == cve_docs([old, new])[0].digest16


# ----------------------------------------------------------------------------- end to end through the engine

def test_advisory_and_cve_leads_find_by_identity_and_text(tmp_path):
    adv = Advisories([stored('synthetic-advisory-rev1.json')])
    cves = Snapshots([snapshot(cve='CVE-2099-10002', text='a use after free in the spooler')])
    service = SearchService(make_project(tmp_path / 'project'), tmp_path / 'cache', attention=attention,
                            comparable=lambda engine: True, extra_specs=lambda _r: advisory_specs(adv, cves))
    by_id = service.search(ask('CVE-2099-10001'))
    assert by_id.hits[0].tier == 0 and by_id.hits[0].evidence[0].kind == 'advisory'
    by_text = service.search(ask('spooler kind:cve'))
    assert [h.evidence[0].title for h in by_text.hits][0].startswith('CVE-2099-10002')
    assert {e.group for e in by_text.coverage} >= {'adv', 'cve'}
    segment = next((tmp_path / 'cache').rglob('cve-*.sqlite3'))
    with open_segment(segment) as opened:
        assert opened.info.docs == 1
    assert json.loads(by_text.model_dump_json())['status'] in ('ok', 'partial')
