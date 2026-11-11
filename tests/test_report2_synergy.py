"""SPEC-50 section 5 synergy fixture: contested and corroborated matches, hostile text, empty calibration directory."""
from __future__ import annotations

import re

import pytest
from test_report2_support import FIXED_TIME, hostile_project, synergy_sections

from patchtrace.report2.assemble import build_report
from patchtrace.report2.calibration_block import build_calibration_block
from patchtrace.report2.render_html import render_html
from patchtrace.report2.render_json import finalize, render_json
from patchtrace.report2.render_md import render_md
from patchtrace.reports import _snapshot


@pytest.fixture
def empty_calibration(tmp_path, monkeypatch):
    monkeypatch.setattr('patchtrace.calibration.artifact.BUNDLED_DIR', tmp_path)
    assert list(tmp_path.iterdir()) == []


def _export():
    project, a, b = hostile_project()
    report = build_report(_snapshot(project, False, True, None), include_code=False, include_notes=True,
                          sections=synergy_sections(a, b), generated_at=FIXED_TIME)
    return finalize(report), a, b


def test_report2_display_level_ordinal_without_artifact(empty_calibration):
    data, _, _ = _export()
    assert data['calibration']['display_level'] == 'ordinal'
    assert data['calibration'] == build_calibration_block().model_dump()
    blob = render_json(data)
    assert 'shown_p' not in blob
    assert [k for k in re.findall(r'"([a-z_]+)":', blob) if k in {'p', 'probability', 'shown_p', 'band'}] == []


def test_report2_synergy_hostile_names_and_channels(empty_calibration):
    data, a, b = _export()
    rows = {r['match_id']: r for r in data['engine_evidence']['rows']}
    # channels: corroborated A with rz-diff unknown, contested B, side by side
    assert (rows[a]['verdict'], rows[a]['missing_engines']) == ('corroborated', ['rz-diff'])
    assert rows[b]['verdict'] == 'contested'
    assert {c['engine']: c['state'] for c in rows[a]['channels']}['rz-diff'] == 'absent'
    assert data['sections_present'] == ['advisories', 'build_facts', 'engine_evidence', 'leads', 'symbols']
    assert any('Series context' in u for u in data['unknowns'])

    # escaping, JSON: bidi control is the visible token, newline flattened, no raw control
    blob = render_json(data)
    assert '<U+202E>gnidnuf<script>alert(1)</script>?# Injected' in blob and '\u202e' not in blob

    # HTML: no script, no href, one style covered by a hash, no attribute built from data
    page = render_html(data)
    assert '<script' not in page and ' href=' not in page and page.count('<style>') == 1
    assert "'unsafe-inline'" not in page and 'sha256-' in page
    assert '&lt;U+202E&gt;gnidnuf&lt;script&gt;' in page

    # Markdown: single-line heading, advisory inside a long fence, no live link, no row break
    md = render_md(data)
    headings = [line for line in md.split('\n') if line.startswith('### ') and 'gnidnuf' in line]
    assert len(headings) == 1 and '\n' not in headings[0]
    fence = max(re.findall(r'(?m)^(`{3,})$', md), key=len)
    assert len(fence) >= 6 and md.count(f'\n{fence}\n') >= 2
    before_fences = re.sub(r'(?ms)^(`{3,})\n.*?^\1$', '', md)
    assert '](' not in before_fences and not re.search(r'https?:', before_fences)
    # the three together: contested B and corroborated A appear in every format with the hostile name neutralized
    for rendered in (blob, page, md):
        assert 'contested' in rendered and 'corroborated' in rendered and 'rz-diff' in rendered
