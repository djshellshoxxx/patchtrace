"""Bounded anchor queries and default stored-advisory CLI, using authored offline data."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import pytest
from search_builders import make_service

from patchtrace.enrichment.identity import domain_id
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.anchors import anchors_for
from patchtrace.intelligence.contracts import Anchor
from patchtrace.intelligence.csaf import normalize, validate
from patchtrace.intelligence.storage import AdvisoryStore
from patchtrace.search import cli
from patchtrace.search.anchors import coverage_for, plan_for
from patchtrace.search.contracts import QueryPlan
from patchtrace.search.errors import SearchError
from patchtrace.search.query import parse_query
from patchtrace.search.service import SearchService
from patchtrace.service import ProjectService

CVE = 'CVE-2099-10001'
FIXTURE = Path(__file__).parent / 'fixtures/csaf/synthetic-advisory-rev1.json'
BINARY = ('asm', 'build', 'capability', 'code', 'export', 'function', 'import', 'rule', 'string')


def _anchor(kind, value):
    return Anchor(anchor_id=domain_id('anchor', 1, {'kind': kind, 'value': value}), kind=kind,
                  value=value, source='csaf-title', pointer='/vulnerabilities/0/title',
                  quality='derived', label='authored compatibility control')


def _advisory(value):
    document = json.loads(FIXTURE.read_bytes())
    document['vulnerabilities'][0]['title'] = f'{value} Elevation of Privilege Vulnerability'
    raw = json.dumps(document).encode()
    parsed, validation = validate.load_document(raw)
    return raw, normalize.normalize(parsed, validation, hashlib.sha256(raw).hexdigest())


@pytest.mark.parametrize('length', [134, 135, 160, 240])
def test_component_keeps_original_payload_budget(length):
    value = 'A' * length
    item = plan_for(_anchor('component', value))
    assert item.plan is not None, item.reason
    assert item.plan.phrases == (value,)
    assert item.plan.kinds == BINARY
    assert len(item.plan.text) <= 256
    assert QueryPlan.model_validate_json(item.plan.model_dump_json()) == item.plan


def test_component_over_original_budget_stays_unsearchable():
    item = plan_for(_anchor('component', 'A' * 241))
    assert item.plan is None and '256 characters' in item.reason
    with pytest.raises(SearchError, match='256 characters'):
        parse_query('A' * 257)


@pytest.mark.parametrize('kind, expected', [
    ('module', BINARY), ('feature', BINARY), ('component', BINARY), ('api', BINARY),
    ('pdb', ('build',)), ('string', ('string',)),
])
def test_closed_kinds_are_canonical_and_bound_to_query_digest(kind, expected):
    item = plan_for(_anchor(kind, 'literal kind:advisory -token " OR code'))
    assert item.plan is not None
    assert item.plan.kinds == expected
    assert item.plan.terms == item.plan.excludes == ()
    assert item.plan.phrases == ('literal kind:advisory -token OR code',)
    explicit = parse_query(' '.join(f'kind:{value}' for value in expected)
                           + ' scope:changed "literal kind:advisory -token OR code"', mode='words')
    assert item.plan.digest() == explicit.digest()
    unrestricted = parse_query('scope:changed "literal kind:advisory -token OR code"', mode='words')
    assert item.plan.digest() != unrestricted.digest()


@pytest.mark.parametrize('length', [160, 240])
def test_long_component_from_valid_csaf_is_found_in_changed_code(tmp_path, length):
    value = 'Component' + 'A' * (length - len('Component'))
    _, facts = _advisory(value)
    anchor = next(item for item in anchors_for(CVE, [facts]).anchors
                  if item.kind == 'component' and item.value == value)
    project = make_service(tmp_path / 'project')
    function = next(match for match in project.project.matches if match.id == 'm-add').newer[0]
    function.code = f'int CheckLength(int n) {{ const char *component = "{value}"; return n; }}'
    search = SearchService(project, tmp_path / 'cache')
    search.build()
    (result,) = coverage_for([plan_for(anchor)], lambda request: search.search(request, build=False))
    assert result.status == 'changed' and result.hits == 1


def _cli(project, cache, **ports):
    out, err = io.StringIO(), io.StringIO()
    code = cli.main([str(project), '--anchors-from', CVE, '--cache-dir', str(cache), '--json'],
                    stdout=out, stderr=err, **ports)
    return code, json.loads(out.getvalue()), err.getvalue()


def test_default_cli_reads_real_stored_advisory_and_releases_project(tmp_path):
    root, cache = tmp_path / 'project', tmp_path / 'cache'
    raw, _ = _advisory('AbsentReviewModule.sys')
    with ProjectService.sample(root) as service:
        AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id,
                      service.project.revision).add(raw, origin='local-import', uri=None,
                                                    file_name='authored.json', retrieved_at='2099-03-01T00:00:00Z')
    for _ in range(2):
        code, document, error = _cli(root, cache)
        assert code in (0, 3) and 'error' not in document, (document, error)
        assert document['contract'] == 'enrichment-cli/1'
        assert document['result']['cve'] == CVE
        module = next(item for item in document['result']['anchors'] if item['kind'] == 'module')
        assert module['value'] == 'absentreviewmodule.sys'
        assert module['hits'] == 0 and module['status'] in ('none', 'unknown')
    with ProjectService.open(root) as reopened:
        assert reopened.project.id


def test_default_cli_empty_store_keeps_exit_four(tmp_path):
    root = tmp_path / 'project'
    with ProjectService.sample(root):
        pass
    code, document, error = _cli(root, tmp_path / 'cache')
    assert code == 4 and document['result']['anchors'] == [], (document, error)
    assert 'no stored advisory' in document['result']['limitations'][0]


def test_injected_anchor_port_still_receives_search_facade(tmp_path):
    root = tmp_path / 'project'
    with ProjectService.sample(root):
        pass
    seen = []

    def source(service, cve):
        assert isinstance(service, SearchService)
        assert service.service.root == root and cve == CVE
        seen.append(service)
        return None, []

    code, document, error = _cli(root, tmp_path / 'cache', anchors=source)
    assert code == 4 and document['result']['anchors'] == [], (document, error)
    assert len(seen) == 1
