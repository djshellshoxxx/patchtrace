"""SPEC-50 RPT2-1: normalization, escaping matrix and fence helper (hermetic, deterministic)."""
from __future__ import annotations

import html.parser
import re

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from patchtrace.report2 import text
from patchtrace.reports import ExportError

BIDI = ['\u200e', '\u200f', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u2066', '\u2067', '\u2068',
        '\u2069', '\u061c']
BIDI_RE = re.compile('[\u200e\u200f\u202a-\u202e\u2066-\u2069\u061c]')
ANY_TEXT = st.text(alphabet=st.one_of(st.characters(), st.sampled_from(
    BIDI + ['\ud800', '\udfff', '`', '|', '<', '>', ']', '(', '\n', '\r', '\t', '\ufeff', '\x85'])), max_size=80)
PROP = settings(max_examples=150, deadline=None)


def test_lone_surrogate_becomes_replacement_char():
    assert text.normalize_text('x\ud800y', max_chars=100) == 'x\ufffdy'


def test_lone_surrogate_regression_raises_encoding_code_at_the_boundary():
    with pytest.raises(ExportError, match='PT-EXPORT-ENCODING'):
        text.encode_report('x\ud800y')
    assert text.encode_report('x\u00e9y') == 'x\u00e9y'.encode()


@pytest.mark.parametrize('char', BIDI, ids=[f'u{ord(c):04x}' for c in BIDI])
def test_bidi_controls_become_visible_tokens(char):
    out = text.normalize_text(f'a{char}b', max_chars=100)
    assert out == f'a<U+{ord(char):04X}>b'


def test_hostile_function_name_from_the_spec_is_neutralized():
    out = text.normalize_text('\u202egnidnuf<script>alert(1)</script>\n# Injected', max_chars=512)
    assert out.startswith('<U+202E>gnidnuf') and '\n' not in out and '\u202e' not in out


def test_controls_replaced_and_layout_kept_only_when_verbatim():
    raw = 'a\x00b\x1bc\x7fd\x85e\ufeff\tf\ng'
    assert text.normalize_text(raw, max_chars=100) == 'a?b?c?d?e??f?g'
    assert text.normalize_text(raw, verbatim=True, max_chars=100) == 'a?b?c?d?e?\tf\ng'


def test_verbatim_crlf_folds_to_lf_and_lone_cr_is_a_control():
    assert text.normalize_text('a\r\nb\rc', verbatim=True, max_chars=100) == 'a\nb?c'


def test_nfc_is_not_applied():
    decomposed = 'e\u0301'
    assert text.normalize_text(decomposed, max_chars=10) == decomposed


def test_cap_adds_marker_with_omitted_count():
    assert text.normalize_text('x' * 10, max_chars=4) == 'xxxx[truncated 6 chars]'
    assert text.normalize_text('x' * 4, max_chars=4) == 'xxxx'


def test_documented_caps_are_pinned():
    assert (text.CAP_NAME, text.CAP_EVIDENCE, text.CAP_ADVISORY, text.CAP_NOTES) == (512, 8192, 4096, 16384)
    assert text.CAP_CODE == 1 << 20
    assert (text.MAX_MATCHES, text.MAX_ADVISORIES, text.MAX_BUILD_FACTS, text.MAX_EVIDENCE_ROWS) == (
        10000, 1000, 5000, 2000)


def test_fence_length_exceeds_longest_backtick_run():
    assert text.fence_for('no ticks') == '```'
    assert text.fence_for('a ``` b') == '````'
    assert text.fence_for('`' * 7 + ' x `` y') == '`' * 8


def test_fenced_block_cannot_be_closed_by_its_content():
    block = text.md_fence('```\n# Injected\n[x](https://e.example)\n`````')
    lines = block.split('\n')
    fence = lines[0]
    assert set(fence) == {'`'} and len(fence) == 6 and lines[-1] == fence
    assert not any(line.strip().startswith(fence) for line in lines[1:-1])


def test_html_text_escapes_markup_quotes_and_bidi():
    out = text.html_text('<script>"x"</script>\u202e&')
    assert '<' not in out and '"' not in out and '\u202e' not in out and '&amp;' in out and '&lt;U+202E&gt;' in out


def test_html_pre_keeps_newlines_but_escapes():
    assert text.html_pre('a<b>\nc') == 'a&lt;b&gt;\nc'


def test_markdown_heading_is_one_line_and_escaped():
    out = text.md_heading('# Injected\n\n- item\r\n[l](https://x.example)')
    assert '\n' not in out and not out.startswith('#') and '\\[' in out and '\\:' in out


def test_markdown_cell_keeps_row_intact():
    out = text.md_cell('a | b\n| c |\t[x](y)')
    assert '\n' not in out and out.count('\\|') == 3 and '|' not in re.sub(r'\\\|', '', out)


def test_markdown_paragraph_neutralizes_html_and_autolinks():
    out = text.md_paragraph('<b>bold</b> https://evil.example/y www.evil.example a@b.example')
    assert '<' not in out and 'https:' not in out and 'www.' not in out
    assert _unescaped_specials(out) == []


@pytest.mark.parametrize('mode,expected', [
    ('text', 'https://evil.example/x'), ('defanged', 'hxxps://evil[.]example/x'), ('removed', '[URL REMOVED]')],
    ids=['text', 'defanged', 'removed'])
def test_display_url_modes(mode, expected):
    assert text.display_url('https://evil.example/x', mode) == expected


def test_display_url_rejects_unknown_mode():
    with pytest.raises(ValueError):
        text.display_url('https://e.example', 'link')


def test_json_dumps_is_sorted_and_keeps_unicode():
    assert text.json_dumps({'b': 1, 'a': '\u00e9'}) == '{"a": "\u00e9", "b": 1}'


@pytest.mark.parametrize('good,bad', [('a-1', 'A'), ('x' * 64, 'x' * 65), ('m0', 'a b'), ('a', '"onload')],
                         ids=['upper', 'long', 'space', 'quote'])
def test_generated_ids_only(good, bad):
    assert text.safe_id(good) == good
    with pytest.raises(ValueError):
        text.safe_id(bad)


# --- properties (spec section 10) -------------------------------------------------------------------------

@PROP
@given(ANY_TEXT, st.booleans())
def test_prop_normalize_output_encodes_and_has_no_bidi_or_surrogates(value, verbatim):
    out = text.normalize_text(value, verbatim=verbatim, max_chars=10000)
    out.encode('utf-8')
    assert not BIDI_RE.search(out)
    allowed = '\n\t' if verbatim else ''
    assert all((ord(c) >= 0x20 and not 0x7F <= ord(c) <= 0x9F) or c in allowed for c in out)


@PROP
@given(ANY_TEXT)
def test_prop_normalization_is_idempotent_below_the_cap(value):
    once = text.normalize_text(value, verbatim=True, max_chars=100000)
    assert text.normalize_text(once, verbatim=True, max_chars=100000) == once


_SPECIAL = set('\\`*_{}[]()#+.!|>~:-@/=<')


def _unescaped_specials(out: str) -> list[str]:
    """Tiny CommonMark-ish checker: every special character must be backslash-escaped."""
    found, i = [], 0
    while i < len(out):
        if out[i] == '\\' and i + 1 < len(out):
            i += 2
            continue
        if out[i] in _SPECIAL:
            found.append(out[i])
        i += 1
    return found


@PROP
@given(ANY_TEXT)
def test_prop_markdown_inline_escapers_leave_no_live_syntax(value):
    for fn in (text.md_heading, text.md_cell, text.md_paragraph):
        out = fn(value)
        out.encode('utf-8')
        assert '\n' not in out and not BIDI_RE.search(out)
        assert _unescaped_specials(out) == []


@PROP
@given(ANY_TEXT)
def test_prop_markdown_fence_cannot_be_closed_by_content(value):
    block = text.md_fence(value)
    lines = block.split('\n')
    fence = lines[0]
    assert re.fullmatch('`{3,}', fence) and lines[-1] == fence
    assert not any(re.match(' {0,3}`{' + str(len(fence)) + r',}\s*$', line) for line in lines[1:-1])
    assert not BIDI_RE.search(block)


class _Tags(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.attrs = [], []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs += attrs


@PROP
@given(ANY_TEXT)
def test_prop_html_escapers_introduce_no_tags_or_attributes(value):
    for fn in (text.html_text, text.html_pre):
        parser = _Tags()
        parser.feed(f'<p>{fn(value)}</p>')
        parser.close()
        assert parser.tags == ['p'] and parser.attrs == []
        assert not BIDI_RE.search(fn(value))
