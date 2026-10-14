"""Report export (SPEC-28 sections J and L): canonical JSON, escaped Markdown and atomic files.

Advisory text is untrusted. These tests feed hostile text (markup, Markdown, bidi and C0/C1 controls, tag
characters, long cells, `javascript:` and autolink URLs) through the real import -> explain -> render path and
through the escaper directly, and compare byte-identical goldens (`tests/fixtures/csaf/expected/`, LF only).
Regenerate goldens after a deliberate change with `PATCHTRACE_UPDATE_GOLDENS=1 python -m pytest
tests/test_intel_reports.py`, then review the diff. Every fixture is SYNTHETIC."""
from __future__ import annotations

import json
import os
import re
import unicodedata
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence import reports
from patchtrace.intelligence.contracts import IntelError, IntelligenceReport
from patchtrace.intelligence.csaf.identity import project_identities
from patchtrace.intelligence.explain import build_report
from patchtrace.intelligence.reports import escape_md, plain_text
from patchtrace.intelligence.storage import AdvisoryStore
from patchtrace.service import ProjectService

FIXTURES = Path(__file__).parent / 'fixtures' / 'csaf'
EXPECTED = FIXTURES / 'expected'
UPDATE = os.environ.get('PATCHTRACE_UPDATE_GOLDENS') == '1'
SCENARIOS = {
    'single': (('synthetic-advisory-rev1.json',), 'CVE-2099-10001'),
    'revisions-vex': (('synthetic-advisory-rev1.json', 'synthetic-advisory-rev2.json', 'synthetic-vex.json'),
                      'CVE-2099-10001'),
    'hostile': (('injection/hostile-advisory.json',), 'CVE-2099-10001'),
}
UNSAFE = frozenset({'Cc', 'Cf', 'Cs', 'Co', 'Cn'})
SPECIAL = '\\`*_{}[]()#+-.!|~=^$@:'
# Everything escape_md may emit: a visible control marker, an escaped special, a fixed HTML entity, or a plain
# character that is neither special nor a control. Anything else (a bare special, a newline) is not inert.
INERT = re.compile(r'(?:\\u[0-9a-f]{4}|\\U[0-9a-f]{8}|\\[' + re.escape(SPECIAL) + r']'
                   r'|&(?:amp|lt|gt|quot|#x27);|[^' + re.escape(SPECIAL + '&<>"\'') + r'\x00-\x1f\x7f-\x9f])*')


def inert(text: str) -> bool:
    return INERT.fullmatch(text) is not None and not any(unicodedata.category(c) in UNSAFE for c in text)


# ---------------------------------------------------------------------------------------------- the escaper

ESCAPES = [
    ('plain', 'plain text 123', 'plain text 123'),
    ('script-tag', '<script>alert(1)</script>', r'&lt;script&gt;alert\(1\)&lt;/script&gt;'),
    ('img-onerror', '<img src=x onerror=alert(1)>', r'&lt;img src\=x onerror\=alert\(1\)&gt;'),
    ('md-link', '[click](javascript:alert(1))', r'\[click\]\(javascript\:alert\(1\)\)'),
    ('md-image', '![pixel](https://evil.example/p.png)', r'\!\[pixel\]\(https\://evil\.example/p\.png\)'),
    ('emphasis', '**bold** _under_ `code` ~~strike~~', r'\*\*bold\*\* \_under\_ \`code\` \~\~strike\~\~'),
    ('line-start-markers', '# h - b 1. i > q', r'\# h \- b 1\. i &gt; q'),
    ('rules-and-fences', '--- === ``` ~~~', r'\-\-\- \=\=\= \`\`\` \~\~\~'),
    ('table-pipe', 'a | b', r'a \| b'),
    ('autolink-url', 'https://evil.example/x?a=1&b=2', r'https\://evil\.example/x?a\=1&amp;b\=2'),
    ('www-and-email', 'www.evil.example evil@evil.example', r'www\.evil\.example evil\@evil\.example'),
    ('javascript-url', 'javascript:alert(document.cookie)', r'javascript\:alert\(document\.cookie\)'),
    ('mention-math-issue', '@user $x$ #123', r'\@user \$x\$ \#123'),
    ('braces-caret-plus', '{x} ^ + =', r'\{x\} \^ \+ \='),
    ('entities-stay-text', '&amp; &lt;b&gt;', r'&amp;amp; &amp;lt;b&amp;gt;'),
    ('quotes', 'say "hi" it\'s', 'say &quot;hi&quot; it&#x27;s'),
    ('backslash', r'C:\Windows\System32', r'C\:\\Windows\\System32'),
    ('bidi-override', '\u202eevil\u202c', r'\u202eevil\u202c'),
    ('bidi-isolates', 'a\u2066b\u2069c\u200ed', r'a\u2066b\u2069c\u200ed'),
    ('c0-controls', 'a\x1b[31mb\x00c\x07d', r'a\u001b\[31mb\u0000c\u0007d'),
    ('del-and-c1', 'a\x7fb\x80c\x9bd\x9fe', r'a\u007fb\u0080c\u009bd\u009fe'),
    ('format-chars', 'a\u200bb\u200dc\ufeffd\u00ade\u2060f', r'a\u200bb\u200dc\ufeffd\u00ade\u2060f'),
    ('tag-chars', 'a\U000e0041b', r'a\U000e0041b'),
    ('private-use', 'a\ue000b', r'a\ue000b'),
    ('lone-surrogate', 'a\ud800b', r'a\ud800b'),
    ('line-breaks-flatten', 'a\nb\r\nc\x85d\u2028e\u2029f\vg\fh', 'a b c d e f g h'),
    ('whitespace-collapses', '  a \t\t b   ', 'a b'),
    ('whitespace-only', ' \n\t ', ''),
    ('only-controls', '\x1b\x00', r'\u001b\u0000'),
    ('unicode-text-kept', 'Ünïcödé — 漏洞 😀', 'Ünïcödé — 漏洞 😀'),
    ('harmless-punctuation', '100% done; ok, yes?', '100% done; ok, yes?'),
    ('nbsp-is-layout', 'a\u00a0b', 'a\u00a0b'),
    ('empty', '', ''),
]


@pytest.mark.parametrize(('given_text', 'expected'), [pytest.param(g, e, id=i) for i, g, e in ESCAPES])
def test_escape_md_table(given_text, expected):
    assert escape_md(given_text) == expected
    assert inert(expected)


def test_long_text_is_truncated_with_a_visible_marker():
    assert escape_md('x' * 5000, limit=300) == 'x' * 300 + ' \u2026 4700 more characters'
    assert escape_md('x' * 5000, limit=None) == 'x' * 5000
    assert escape_md('abc   \n', limit=3) == 'abc'  # trailing blanks are not content


def test_truncation_never_splits_an_escape_sequence():
    assert escape_md('<' * 10, limit=3) == '&lt;&lt;&lt; \u2026 7 more characters'
    assert escape_md('\u202e' * 4, limit=2) == r'\u202e\u202e' + ' \u2026 2 more characters'


def test_default_limits_are_the_documented_ones():
    assert (reports.MAX_CELL, reports.MAX_PROSE, reports.MAX_ROWS) == (300, 2000, 100)
    assert escape_md('y' * 400).endswith('100 more characters')


@settings(max_examples=300, deadline=None)
@given(st.text(alphabet=st.one_of(st.characters(), st.sampled_from(sorted(set(SPECIAL + '&<>"\' \n\t\r\x1b\x85'
                                                                               '\u202e\u200b\ue000\u2028')))),
               max_size=120))
def test_escaped_text_is_always_inert(text):
    out = escape_md(text, limit=60)
    assert inert(out)
    assert len(out) <= 60 * 10 + 40


def test_plain_text_is_for_terminals_only():
    assert plain_text('a<b>&"c\n\x1b[0m\u202e') == 'a<b>&"c \\u001b[0m\\u202e'
    assert plain_text('x' * 500, 100) == 'x' * 100 + ' \u2026 400 more characters'
    assert plain_text('\x9b2J\u2028') == r'\u009b2J'


# ---------------------------------------------------------------------------------------------- scenarios

@pytest.fixture(scope='module')
def built(tmp_path_factory):
    """name -> IntelligenceReport for each scenario (one sample project each, fixed stamps and file names)."""
    out = {}
    for name, (files, cve) in SCENARIOS.items():
        with ProjectService.sample(tmp_path_factory.mktemp(name) / 'case') as service:
            store = AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id,
                                  service.project.revision)
            for day, relative in enumerate(files, start=1):
                store.add((FIXTURES / relative).read_bytes(), origin='local-import', uri=None,
                          file_name=Path(relative).name, retrieved_at=f'2099-03-0{day}T00:00:00Z')
            advisories, _ = store.for_cve(cve)
            out[name] = build_report(cve, advisories, *project_identities(service.project.artifacts, service.root))
    return out


def check_golden(name: str, data: bytes) -> None:
    path = EXPECTED / name
    if UPDATE:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    expected = path.read_bytes()
    if expected != data:
        at = next((i for i, (a, b) in enumerate(zip(expected, data, strict=False)) if a != b),
                  min(len(expected), len(data)))
        raise AssertionError(f'{name} differs at byte {at} (golden {len(expected)} B, produced {len(data)} B): '
                             f'{expected[max(0, at - 40):at + 40]!r} != {data[max(0, at - 40):at + 40]!r}; '
                             'rerun with PATCHTRACE_UPDATE_GOLDENS=1 and review the diff if this is deliberate')


@pytest.mark.parametrize('name', SCENARIOS)
def test_json_matches_the_golden_byte_for_byte(built, name):
    check_golden(f'{name}.report.json', reports.render(built[name], 'json'))


@pytest.mark.parametrize('name', SCENARIOS)
def test_markdown_matches_the_golden_byte_for_byte(built, name):
    check_golden(f'{name}.report.md', reports.render(built[name], 'md'))


@pytest.mark.parametrize('fmt', ['json', 'md'])
@pytest.mark.parametrize('name', SCENARIOS)
def test_exports_are_utf8_lf_without_bom_and_end_in_one_newline(built, name, fmt):
    data = reports.render(built[name], fmt)
    assert b'\r' not in data and not data.startswith(b'\xef\xbb\xbf')
    assert data.endswith(b'\n') and not data.endswith(b'\n\n')
    data.decode('utf-8')  # strict


@pytest.mark.parametrize('name', SCENARIOS)
def test_json_is_canonical_ascii_and_round_trips(built, name):
    text = reports.to_json(built[name])
    assert text.isascii()  # bidi and control characters can only appear as \uXXXX escapes
    assert IntelligenceReport.model_validate_json(text) == built[name]
    assert json.loads(text) == built[name].model_dump(mode='json')
    assert text == json.dumps(json.loads(text), indent=2, sort_keys=True) + '\n'  # sorted keys, 2-space indent


def test_json_export_keeps_hostile_text_complete_and_markdown_truncates_it(built):
    report, md = built['hostile'], reports.to_markdown(built['hostile'])
    note = report.facts[0].notes[0].text
    assert len(note) > reports.MAX_PROSE
    assert json.loads(reports.to_json(report))['facts'][0]['notes'][0]['text'] == note  # complete in the JSON
    assert 'more characters' in md and ' filler' * 300 not in md  # shortened in the Markdown


def structure_ok(md: str) -> list[str]:
    """Lines that are not one of the renderer's own block shapes (empty list = every line is structural)."""
    shapes = (re.compile(r'#{1,3} \S.*'), re.compile(r'\| .* \|'), re.compile(r'- \S.*'), re.compile(r'  - \S.*'),
              re.compile(r'[A-Z(][^|]*'))
    return [line for line in md.splitlines() if line and not any(s.fullmatch(line) for s in shapes)]


def table_blocks(md: str) -> list[list[str]]:
    blocks, current = [], []
    for line in md.splitlines():
        if line.startswith('|'):
            current.append(line)
        elif current:
            blocks.append(current)
            current = []
    return blocks + ([current] if current else [])


@pytest.mark.parametrize('name', SCENARIOS)
def test_markdown_has_no_active_content(built, name):
    md = reports.to_markdown(built[name])
    assert '<' not in md and '>' not in md  # every HTML-significant character is an entity
    assert not re.search(r'(?<!\\)\]\(', md) and not re.search(r'(?<!\\)!\[', md)
    assert not re.search(r'(?<!\\)://', md) and not re.search(r'(?<![\\\w])www\.', md)
    assert not re.search(r'(?<!\\)javascript:', md, re.IGNORECASE)
    assert not [c for c in md if c != '\n' and unicodedata.category(c) in UNSAFE]
    assert structure_ok(md) == []
    for block in table_blocks(md):
        widths = {len(re.split(r'(?<!\\)\|', row.strip())) for row in block}
        assert len(widths) == 1, block[:3]
    assert md.count('\n# ') + md.startswith('# ') == 1  # exactly one title


def test_hostile_markdown_shows_controls_and_markup_as_text(built):
    md = reports.to_markdown(built['hostile'])
    for visible in (r'\u202e', r'\u001b', r'\u0000', r'\u009b', r'\U000e0041', r'\ue000', r'\u200b'):
        assert visible in md
    assert '&lt;script&gt;' in md and '&lt;img src\\=x onerror\\=alert\\(1\\)&gt;' in md
    assert r'javascript\:alert\(document\.cookie\)' in md
    assert 'x' * 301 not in md and ' \u2026 ' in md  # the 990-character product name is a truncated cell


def test_markdown_states_what_it_is_and_never_claims_verification(built):
    md = reports.to_markdown(built['single'])
    assert 'does not show that this CVE is present in, or fixed by, any function or binary' in md
    assert not re.search(r'\b(probab|likelihood|confidence score|proven|certain)', md, re.IGNORECASE)
    for heading in ('## Sources', '## Applicability', '## Advisory facts', '## CWE profile', '## Patch hypotheses',
                    '## Search anchors', '## Unknowns', '## Limitations'):
        assert heading in md


def test_markdown_lists_both_artifacts_with_their_mapping_tiers(built):
    md = reports.to_markdown(built['single'])
    assert '### Older artifact' in md and '### Newer artifact' in md
    assert '`advisory-file-hash`' in md and '`relationship-from-verified-component`' in md
    assert '`known_affected`' in md and '`fixed`' in md  # status evidence of the older and the newer side


def test_row_caps_are_visible(built, monkeypatch):
    monkeypatch.setattr(reports, 'MAX_ROWS', 1)
    md = reports.to_markdown(built['single'])
    assert 'more row(s) omitted' in md


def test_summary_is_plain_text_without_controls(built):
    for name in SCENARIOS:
        text = reports.summary(built[name])
        assert '\n' in text and not [c for c in text if c != '\n' and unicodedata.category(c) in UNSAFE]
        assert built[name].cve in text and 'Traceback' not in text
    assert 'affected' in reports.summary(built['single'])


# ---------------------------------------------------------------------------------------------- files

def test_format_is_chosen_by_suffix_only():
    assert reports.format_for(Path('out/report.json')) == 'json'
    assert reports.format_for(Path('REPORT.MD')) == 'md'
    for bad in ('report', 'report.txt', 'report.html', 'report.md.exe'):
        with pytest.raises(IntelError) as info:
            reports.format_for(Path(bad))
        assert info.value.code == 'PT-INTEL-INPUT'


def test_unknown_format_is_refused(built):
    with pytest.raises(IntelError):
        reports.render(built['single'], 'html')


def test_export_replaces_atomically_and_keeps_the_old_file_on_failure(tmp_path, monkeypatch):
    target = tmp_path / 'report.md'
    reports.write_export(target, b'old\n')
    reports.write_export(target, b'new\n')
    assert target.read_bytes() == b'new\n'

    def boom(*_args):
        raise PermissionError('locked')
    monkeypatch.setattr(os, 'replace', boom)
    with pytest.raises(IntelError) as info:
        reports.write_export(target, b'third\n')
    assert info.value.code == 'PT-INTEL-STORAGE'
    assert target.read_bytes() == b'new\n'
    assert [p.name for p in tmp_path.iterdir()] == ['report.md']  # no temporary file left behind


def test_export_to_a_missing_directory_is_a_storage_error(tmp_path):
    with pytest.raises(IntelError) as info:
        reports.write_export(tmp_path / 'missing' / 'report.json', b'{}\n')
    assert info.value.code == 'PT-INTEL-STORAGE'
