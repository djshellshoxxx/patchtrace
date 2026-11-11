"""KB-integration-plan A-13: ``kb explain`` and the Markdown ``kb export`` apply the KEV catalog in use when they are
read; the stored context and the JSON export never change. Offline (sockets denied), synthetic data only."""
from __future__ import annotations

import io
import json

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import Kb
from kbc_k4a_support import attached_project

from patchtrace.intelligence.reports import escape_md
from patchtrace.kbcorrelation import cli
from patchtrace.kbcorrelation.leads import KevFact, KevSource

pytestmark = pytest.mark.usefixtures('no_sockets')
CVE_A = 'CVE-2099-20001'
SOURCE = KevSource(state='loaded', text='KEV: catalog 2099.02.14 (1 day old; from a local file, unverified).',
                   snapshot_id='b' * 64, catalog_version='2099.02.14', freshness='fresh', age_days=1)


class Listed:
    """A loaded catalog that lists CVE_A only."""
    source = SOURCE

    def status(self, cve):
        if cve == CVE_A:
            return KevFact('listed', '2099-02-12', 'b' * 64, catalog_version='2099.02.14', freshness='fresh',
                           age_days=1)
        return KevFact('not-listed', None, 'b' * 64, catalog_version='2099.02.14', freshness='fresh', age_days=1)


@pytest.fixture
def kb(tmp_path, capsys):
    return Kb(tmp_path, capsys)


@pytest.fixture
def project(kb, tmp_path):
    return attached_project(kb, tmp_path)


def run(kb, *argv, kev=None, as_json=True):
    out = io.StringIO()
    extra = ['--workspace', str(kb.workspace)] + (['--json'] if as_json else [])
    code = cli.main([*argv, *extra], env=kb.env, kev=kev, stdout=out)
    return code, (json.loads(out.getvalue()) if as_json else out.getvalue())


def test_explain_applies_the_catalog_in_use_and_names_it(kb, project):
    code, doc = run(kb, 'explain', str(project), '--cve', CVE_A, kev=Listed())
    row = doc['result']['cves'][0]
    assert code == 0 and row['card']['kev'] == 'listed'
    assert row['kev_text'].startswith('KEV listed 2099-02-12 (catalog 2099.02.14, 1 day old)')
    assert doc['result']['kev_source']['snapshot_id'] == 'b' * 64
    plain = run(kb, 'explain', str(project), kev=Listed(), as_json=False)[1]
    assert 'KEV listed 2099-02-12' in plain and SOURCE.text in plain


def test_explain_without_a_catalog_says_not_loaded(kb, project):
    code, doc = run(kb, 'explain', str(project), '--cve', CVE_A, '--kev-dir', str(project / 'absent'))
    row = doc['result']['cves'][0]
    assert code == 0 and row['card']['kev'] == 'not-loaded' and row['kev_text'] == 'KEV: not loaded'
    assert doc['result']['kev_source']['state'] == 'not-loaded'


def test_json_export_is_the_stored_context_whatever_kev_says(kb, project, tmp_path):
    plain, with_kev = tmp_path / 'a.json', tmp_path / 'b.json'
    assert run(kb, 'export', str(project), str(plain))[0] == 0
    assert run(kb, 'export', str(project), str(with_kev), kev=Listed())[0] == 0
    assert plain.read_bytes() == with_kev.read_bytes()
    cards = json.loads(plain.read_text(encoding='utf-8'))['context']['cards']
    assert {card['kev'] for card in cards} == {'not-loaded'}


def test_markdown_export_names_the_kev_state_and_snapshot(kb, project, tmp_path):
    target = tmp_path / 'ctx.md'
    assert run(kb, 'export', str(project), str(target), kev=Listed())[0] == 0
    text = target.read_text(encoding='utf-8')
    assert f'- KEV source: {escape_md(SOURCE.text)} Snapshot {"b" * 64}.' in text
    assert f'- KEV: {escape_md("KEV listed 2099-02-12")}' in text            # advisory and KEV text stay escaped


def test_explain_does_not_change_the_stored_context(kb, project):
    before = run(kb, 'explain', str(project))[1]['result']['context_key']
    run(kb, 'explain', str(project), kev=Listed())
    _, after = run(kb, 'explain', str(project))
    assert after['result']['context_key'] == before
    assert {row['card']['kev'] for row in after['result']['cves']} == {'not-loaded'}
