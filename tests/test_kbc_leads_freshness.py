"""`kb leads` freshness beyond the ordered file pair: a replaced advisory revision and a ranking from an earlier
analysis run (KB-integration-plan 7.4, slice K4a follow-up). Offline (sockets denied), synthetic data only.

The file-pair check (``test_kbc_leads.py``, swapped orientation) is unchanged; these cases add the two inputs it does
not cover. A replaced advisory makes the context stale without claiming the files changed; a ranking the project has
moved past is reported as such, never as "not ranked yet".
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import BASELINE, Kb, fixture
from kbc_k4a_support import analysed_project, apply_diff

from patchtrace import cli as main_cli
from patchtrace.kbcorrelation.leads import TEXT_STALE_ADVISORY, TEXT_STALE_PAIR

pytestmark = pytest.mark.usefixtures('no_sockets')


@pytest.fixture
def kb(tmp_path, capsys):
    return Kb(tmp_path, capsys)


@pytest.fixture
def project(kb, tmp_path, capsys):
    return analysed_project(kb, tmp_path, capsys)


def leads(kb, project):
    code, doc, _ = kb('leads', str(project))
    return code, doc['result']


def import_revision(kb, tmp_path, *, current='2099-03-05'):
    """A later revision of the month the context was prepared from (same release id, newer release date)."""
    document = json.loads(Path(fixture(BASELINE)).read_text(encoding='utf-8'))
    document['document']['current_release_date'] = current
    path = tmp_path / f'cvrf-2099-Feb-rev-{current}.json'
    path.write_text(json.dumps(document), encoding='utf-8')
    code, _, _ = kb('index', 'import', str(path))
    assert code == 0


def test_fresh_context_is_ready(kb, project):
    code, result = leads(kb, project)
    assert code == 0
    assert (result['state'], result['stale'], result['stale_reasons']) == ('ready', False, [])


def test_replaced_advisory_revision_makes_the_context_stale(kb, project, tmp_path):
    import_revision(kb, tmp_path)
    code, result = leads(kb, project)
    assert result['state'] == 'stale' and result['stale'] is True
    assert result['stale_reasons'] == ['advisory-revision']
    assert TEXT_STALE_ADVISORY in result['text']
    assert TEXT_STALE_PAIR not in result['text']               # the files did not change
    leads_ = [lead for g in result['groups'] for lead in g['leads']] + result['unattributed']
    assert leads_ and all(lead['nav']['match_id'] is None for lead in leads_)
    identity = [c for lead in leads_ for c in lead['chips'] if c['channel'] == 'binary-identity']
    assert all(c['state'] == 'supports' for c in identity)     # the pair is still the one the context was made for


def test_an_older_revision_imported_later_does_not_make_it_stale(kb, project, tmp_path):
    import_revision(kb, tmp_path, current='2099-02-01')
    code, result = leads(kb, project)
    assert (result['state'], result['stale_reasons']) == ('ready', [])


def test_ranking_from_an_earlier_analysis_run_is_not_reported_as_never_ranked(kb, project, tmp_path, capsys):
    apply_diff(project, tmp_path)                               # a new analysis run; the stored ranking is now behind
    code, result = leads(kb, project)
    assert code == 4 and result['state'] == 'no-comparison'
    assert 'stale' in result['text'].lower() and 'not been ranked' not in result['text']
    assert main_cli.main(['rank', str(project)]) == 0
    capsys.readouterr()
    code, result = leads(kb, project)
    assert (code, result['state']) == (0, 'ready')


def test_never_ranked_project_keeps_the_original_text(kb, tmp_path, capsys):
    project = analysed_project(kb, tmp_path, capsys, rank=False)
    code, result = leads(kb, project)
    assert result['state'] == 'no-comparison'
    assert 'No comparison has been ranked for this project yet' in result['text']
