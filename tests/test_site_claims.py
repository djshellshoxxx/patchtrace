"""Every claim on the site is backed by repository files (tests/site_claims.md is generated from the same
data, so it cannot drift) and 'working' is never used for something the same text calls unbuilt."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from site_helpers import ROOT, SITE, copy_site, quiet_build  # noqa: E402

from tools.site import build_site  # noqa: E402

CONTENT = json.loads((SITE / 'content.json').read_text(encoding='utf-8'))
WORKING = [item for item in CONTENT['features'] if item['status'] == 'working']
UNBUILT_WORDS = ('not built', 'designed, not', 'specification is not written', 'no command, report or window')


def test_every_cited_evidence_path_exists():
    cited = [(item['id'], path) for section in ('works_today', 'features') for item in CONTENT[section]
             for path in item['evidence']]
    assert cited
    missing = [(name, path) for name, path in cited if not (ROOT / path).is_file()]
    assert not missing, f'claims cite files that do not exist: {missing}'


@pytest.mark.parametrize('claim', CONTENT['works_today'], ids=[c['id'] for c in CONTENT['works_today']])
def test_each_works_today_claim_cites_code_and_a_test(claim):
    paths = claim['evidence']
    assert any(p.startswith(('src/', 'tools/')) for p in paths), 'a working claim needs implementing code'
    assert any(p.startswith('tests/') or p.startswith('.github/workflows/') for p in paths), \
        'a working claim needs a test or a recorded check'


@pytest.mark.parametrize('feature', WORKING, ids=[f['id'] for f in WORKING])
def test_working_features_are_evidenced_and_not_described_as_unbuilt(feature):
    assert feature['evidence'], 'working needs evidence; when unsure use in-progress'
    assert not any(word in feature['note'].lower() for word in UNBUILT_WORDS)


def test_planned_and_in_progress_rows_have_a_basis():
    for item in CONTENT['features']:
        if item['status'] != 'working':
            assert item['evidence'] or item.get('basis'), item['id']


def test_unverified_items_are_listed_not_hidden():
    text = ' '.join(CONTENT['not_verified']).lower()
    for topic in ('ai interpretation', 'nvd and msrc', 'bindiff', 'windows'):
        assert topic in text
    statuses = {item['id']: item['status'] for item in CONTENT['features']}
    for unverified in ('ai', 'nvd', 'msrc', 'bindiff-run', 'binexport'):
        assert statuses[unverified] == 'in-progress'  # never promoted to working without live evidence


def test_the_integrations_the_owner_asked_for_are_all_listed():
    names = ' '.join(item['name'].lower() for item in CONTENT['features'])
    for required in ('ghidra', 'bindiff', 'rz-diff', 'binexport2', 'nvd', 'msrc', 'csaf', 'winbindex', 'capa',
                     'floss', 'detect it easy', 'yara-x', 'cisa kev', 'fts5', 'call graph', 'unified diff',
                     'calibrated ranking'):
        assert required in names, required


def test_claims_document_matches_the_data_and_is_regenerable():
    committed = (ROOT / 'tests' / 'site_claims.md').read_text(encoding='utf-8')
    assert committed == build_site.claims_markdown(CONTENT), (
        'tests/site_claims.md is out of date; run: python tools/site/build_site.py --write-claims')
    for item in CONTENT['works_today']:
        assert item['title'] in committed


def test_page_lists_exactly_the_data_driven_claims(tmp_path):
    site = copy_site(tmp_path)
    quiet_build(tmp_path / 'dist', site_dir=site)
    html = (tmp_path / 'dist' / 'index.html').read_text(encoding='utf-8')
    assert html.count('<li id="works-') == len(CONTENT['works_today'])
    assert html.count('<tr role="row" id="feature-') == len(CONTENT['features'])
    for item in CONTENT['works_today']:  # hidden machine-readable evidence next to every visible claim
        assert f'data-evidence="{" ".join(item["evidence"])}"' in html
