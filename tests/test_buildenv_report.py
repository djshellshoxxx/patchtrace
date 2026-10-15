"""Build-environment report section (DIE D4): contract, orientation guard, size cap, injection fixtures."""
from __future__ import annotations

import json
import re

import pytest
from pe_build_fixtures import BuildSpec, build_with_facts
from test_buildenv_support import detects, fingerprint_of, pair_fingerprints

from patchtrace.buildenv import report
from patchtrace.buildenv.contracts import BuildEnvError
from patchtrace.buildenv.delta import compute_delta
from patchtrace.secondary.evidence_view import BANNED

HOSTILE = '<script>alert(1)</script> | [x](http://evil.example/a) `tick` C:\\Users\\victim\\secret.txt'


@pytest.fixture
def pair(tmp_path):
    older, newer = pair_fingerprints(tmp_path, 'diec-toolchain', 'toolchain')
    return older, newer, compute_delta(older, newer)


@pytest.fixture
def hostile(tmp_path):
    plain = build_with_facts(BuildSpec())
    older = fingerprint_of(tmp_path, plain, 'older', detects(('compiler', 'Microsoft Visual C/C++', '19.38')))
    newer = fingerprint_of(tmp_path, plain, 'newer', detects(('compiler', HOSTILE, '1.0'), ('packer', HOSTILE, '1')))
    return older, newer, compute_delta(older, newer)


def test_section_states_the_verdict_and_the_disclaimer(pair):
    section = report.build_section(*pair)
    assert section.contract == 'build-environment-report/1' and section.toolchain == 'differs'
    assert section.state == 'B4' and 'Toolchain differs between OLDER and NEWER' in section.state_text
    assert any(f.status == 'changed' for f in section.findings)
    assert section.disclaimer == 'Names come from signatures and header fields; they are not proof of how a file was built.'
    assert report.MAX_SECTION >= len(json.dumps(report.section_data(section)).encode())


def test_section_json_round_trips_through_the_strict_model(pair):
    section = report.build_section(*pair, technical=True)
    assert section.technical
    again = report.BuildEnvSection.model_validate_json(json.dumps(report.section_data(section)))
    assert again == section


def test_swapped_sides_are_a_mismatch(pair):
    older, newer, delta = pair
    with pytest.raises(BuildEnvError) as swapped:
        report.build_section(newer, older, delta)
    assert swapped.value.code == 'PT-BUILD-MISMATCH'


def test_oversized_section_is_a_limit_error(pair, monkeypatch):
    monkeypatch.setattr(report, 'MAX_SECTION', 200)
    with pytest.raises(BuildEnvError) as raised:
        report.build_section(*pair)
    assert raised.value.code == 'PT-BUILD-LIMIT'


def test_technical_block_is_dropped_before_the_section_fails(pair, monkeypatch):
    base = len(json.dumps(report.section_data(report.build_section(*pair))).encode())
    monkeypatch.setattr(report, 'MAX_SECTION', base + 10)
    assert report.build_section(*pair, technical=True).technical == ()


def test_redaction_removes_paths_and_credentials(hostile):
    data = report.section_data(report.build_section(*hostile))
    text = json.dumps(data)
    assert 'victim' not in text and 'secret.txt' not in text


def test_markdown_cannot_gain_rows_links_or_markup(hostile):
    data = report.section_data(report.build_section(*hostile))
    rendered = report.render_markdown(data)
    assert '<script>' not in rendered and '](http' not in rendered
    table = [line for line in rendered.splitlines() if line.startswith('| ')]
    assert len(table) == len(data['findings']) + 1
    assert all(re.sub(r'\\\|', '', line).count('|') == 6 for line in table)


def test_html_escapes_every_value(hostile):
    data = report.section_data(report.build_section(*hostile))
    rendered = report.render_html(data)
    assert '<script>' not in rendered and '&lt;script&gt;' in rendered
    assert rendered.count('<table>') == 1 and rendered.count('<section>') == 1


def test_rendered_sections_keep_the_banned_words_out(pair):
    data = report.section_data(report.build_section(*pair, technical=True))
    for rendered in (report.render_markdown(data), report.render_html(data)):
        lowered = rendered.lower().replace('provenance', '')  # the spec's own heading, not a claim
        assert not [word for word in BANNED if re.search(rf'\b{re.escape(word)}', lowered)]
        assert 'not proof of how a file was built' in rendered.replace('\\', '')
