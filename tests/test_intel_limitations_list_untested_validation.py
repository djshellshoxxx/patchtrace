"""CSAF validation limits are visible (KBF-02 vendor-feeds spec s4 and s11, gameplan KBB-13).

The validator does not run every CSAF 2.0 test (`validate.TESTS_NOT_IMPLEMENTED`), so a document that violates one
of them is accepted. The explain report (and so its JSON and Markdown exports) and the `intelligence import` text
name those tests. Written red against the pre-fix code. Real import -> store -> explain path on SYNTHETIC fixtures;
no network."""
from __future__ import annotations

import dataclasses
import json
import re
import socket
from pathlib import Path

import pytest

from patchtrace import cli
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence import cli as intel_cli
from patchtrace.intelligence import reports
from patchtrace.intelligence.csaf.identity import project_identities
from patchtrace.intelligence.csaf.validate import TESTS_NOT_IMPLEMENTED
from patchtrace.intelligence.explain import build_report
from patchtrace.intelligence.storage import AdvisoryStore
from patchtrace.service import ProjectService

FIXTURES = Path(__file__).parent / 'fixtures' / 'csaf'
REV1 = FIXTURES / 'synthetic-advisory-rev1.json'
CVE = 'CVE-2099-10001'
LINE = re.compile(r'CSAF validation did not run tests (?P<ids>[^;]+); a document that violates one of them was '
                  r'accepted\.')


@pytest.fixture(autouse=True)
def hermetic(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise AssertionError('a test tried to open a real socket')
    monkeypatch.setattr(socket.socket, 'connect', refuse)
    monkeypatch.setattr(socket, 'create_connection', refuse)
    monkeypatch.setattr(intel_cli, '_now', lambda: '2099-03-01T00:00:00Z')


@pytest.fixture
def explained(tmp_path):
    """(report, advisories, identities) for REV1 imported into a sample project."""
    with ProjectService.sample(tmp_path / 'case') as service:
        store = AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id,
                              service.project.revision)
        store.add(REV1.read_bytes(), origin='local-import', uri=None, file_name=REV1.name,
                  retrieved_at='2099-03-01T00:00:00Z')
        advisories, _ = store.for_cve(CVE)
        identities = project_identities(service.project.artifacts, service.root)
        return build_report(CVE, advisories, *identities), advisories, identities


def with_untested(advisory, ids: tuple[str, ...]):
    """The stored advisory as if its validation had recorded `ids` as not run (a store written by another build)."""
    validation = advisory.facts.validation.model_copy(update={'tests_not_implemented': ids})
    return dataclasses.replace(advisory, facts=advisory.facts.model_copy(update={'validation': validation}))


def untested(lines) -> list[tuple[str, ...]]:
    return [tuple(m.group('ids').split(', ')) for m in map(LINE.fullmatch, lines) if m]


def test_report_names_the_tests_validation_did_not_run(explained):
    report, advisories, _ = explained
    assert advisories[0].facts.validation.tests_not_implemented == TESTS_NOT_IMPLEMENTED
    assert untested(report.limitations) == [TESTS_NOT_IMPLEMENTED]


def test_json_and_markdown_exports_carry_the_line(explained):
    report = explained[0]
    exported = json.loads(reports.render(report, 'json'))
    assert untested(exported['limitations']) == [TESTS_NOT_IMPLEMENTED]
    assert 'CSAF validation did not run tests 6' in reports.render(report, 'md').decode('utf-8')


def test_no_line_when_every_test_ran(explained):
    _, advisories, identities = explained
    report = build_report(CVE, [with_untested(a, ()) for a in advisories], *identities)
    assert untested(report.limitations) == []
    assert not any('did not run tests' in line for line in report.limitations)


def test_a_stored_list_that_is_not_test_ids_is_not_echoed(explained):
    _, advisories, identities = explained
    hostile = ('6.1.8', '6.1.9‮', '<script>', 'x' * 100, '6.1.8', '6.2.2-6.2.19')
    report = build_report(CVE, [with_untested(a, hostile) for a in advisories], *identities)
    assert untested(report.limitations) == [('6.1.8', '6.2.2-6.2.19')]


def test_import_text_prints_the_line_and_stays_one_line(tmp_path, capsys):
    with ProjectService.sample(tmp_path / 'case') as service:
        project = service.root
    code = cli.main(['intelligence', 'import', str(project), str(REV1), '--cve', CVE])
    out, err = capsys.readouterr()
    assert code == 0 and err == '' and out.count('\n') == 1
    assert out.startswith('imported PT-SYNTH_CVE-2099-10001 revision 1')
    ids = [tuple(m.group('ids').split(', ')) for m in LINE.finditer(out)]
    assert ids == [TESTS_NOT_IMPLEMENTED]
