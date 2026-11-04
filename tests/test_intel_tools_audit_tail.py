"""Regression tests for the open low-severity tool-adapter rows C-16, C-19 and C-20 of
`docs/audits/20261015-intelligence-kev-rules-fabric-pilot.md` (gameplan KBB-04). Written red against the pre-fix
code. Pure: no tool is executed, no network."""
from __future__ import annotations

import string
import time

import pytest
from pydantic import ValidationError

from patchtrace.intelligence.tools import delta, process
from patchtrace.intelligence.tools.common import EvidenceLink, ToolError, ToolManifest, ToolRun

SHA = 'a' * 64

# ---- C-16: a user name or directory with a space never survives `sanitize` ---------------------------------------

LEAKS = {
    'audit': ('error opening C:\\Users\\John Smith\\AppData\\Local\\x.dll', 'error opening x.dll'),
    'slashes': ('error opening C:/Users/John Smith/AppData/x.dll', 'error opening x.dll'),
    'repr': ("No such file: 'C:\\\\Users\\\\John Smith\\\\AppData\\\\x.dll'", "No such file: 'x.dll'"),
    'unc': ('cannot read \\\\fileserver\\John Smith\\rules\\x.yml: denied', 'cannot read x.yml: denied'),
    'home': ('failed to load /home/john smith/x.so', 'failed to load x.so'),
    'mac': ('failed to load /Users/John Smith/Library/x.dylib now', 'failed to load x.dylib now'),
    'deep-home': ('failed to load /mnt/data/home/john smith/x.so', 'failed to load x.so'),
    'two-paths': ('copy C:\\Users\\John Smith\\a.dll to D:\\John Smith\\b.dll', 'copy a.dll to b.dll'),
    'user-dir': ('cannot access C:\\Users\\John Smith', 'cannot access <path>'),
    'user-dir-sep': ('cannot access C:\\Users\\John Smith\\', 'cannot access <path>'),
    'home-dir': ('cannot access /home/john smith: denied', 'cannot access <path>: denied'),
}


@pytest.mark.parametrize('text, expected', list(LEAKS.values()), ids=list(LEAKS))
def test_sanitize_drops_every_directory_component_even_with_spaces(text, expected):
    clean = process.sanitize(text)
    assert 'john' not in clean.lower() and 'smith' not in clean.lower()
    assert clean == expected


# Verifier repro on the first C-16 fix: an apostrophe ended a component, and `<`, `{`, `>` (or a letter) before a
# POSIX path stopped it from being anchored, so the user name leaked.
QUOTED_LEAKS = {
    'apos-win': ("error opening C:\\Users\\O'Brien Smith\\AppData\\x.dll", 'error opening x.dll'),
    'apos-home': ("failed to load /home/o'brien smith/x.so", 'failed to load x.so'),
    'apos-dir': ("error opening D:\\Work Dir\\John Smith's files\\x.dll", 'error opening x.dll'),
    'apos-user': ("cannot access C:\\Users\\O'Brien: denied", 'cannot access <path>: denied'),
    'angle': ('at </home/john smith/x.so>', 'at <x.so>'),
    'brace': ('{/home/john smith/x.so}', '{x.so}'),
    'arrow': ('x->/home/john smith/x.so', 'x->x.so'),
    'paren': ('(/home/john smith/x.so)', '(x.so)'),
    'flag': ('-I/home/john smith/include', '-Iinclude'),
    'assign': ('path=/mnt/data/home/john smith/x.so', 'path=x.so'),
    'no-drive': ('cannot access \\Users\\John Smith\\x.dll', 'cannot access x.dll'),
    'dquote': ('"C:\\Users\\John Smith\\x.dll" missing', '"x.dll" missing'),
    'xp': ('error opening C:\\Documents and Settings\\John Smith\\x.dll', 'error opening x.dll'),
    'lead-comma': ('failed /mnt/a,b/home/john smith/x.so', 'failed x.so'),
}


@pytest.mark.parametrize('text, expected', list(QUOTED_LEAKS.values()), ids=list(QUOTED_LEAKS))
def test_sanitize_drops_user_names_with_apostrophes_or_after_any_punctuation(text, expected):
    clean = process.sanitize(text)
    assert not any(word in clean.lower() for word in ('john', 'smith', 'brien', 'work dir')), clean
    assert clean == expected


@pytest.mark.parametrize('before', [*string.punctuation, ' ', '\t', 'x'], ids=lambda c: f'{ord(c):02x}')
def test_no_character_before_a_rooted_path_lets_a_user_name_through(before):
    for path in ('/home/john smith/x.so', '/Users/John Smith/x.dylib', 'C:\\Users\\John Smith\\x.dll',
                 '\\\\server\\John Smith\\x.dll', "C:\\Users\\Jo'hn Smith\\x.dll"):
        clean = process.sanitize(f'open {before}{path}{before} end')
        assert 'john' not in clean.lower() and 'smith' not in clean.lower(), (before, path, clean)


# Verifier repro: the first C-16 fix scanned to the end of the line at every `/` after `,`, `=`, `(` or `[`, so one
# 64 KiB line took about 12 s (runner.py calls `excerpt` on up to 256 KiB of stderr). The bound is about 50 times
# what a linear scan needs here, and far below what the quadratic scan took.
HOSTILE_RUNS = [',/a', '=/a', '(/a', '[/a', '{/a', '>/a', '-/a', '//a', '\\\\a', "'/a", ' /home/a', ',/home/a',
                'C:\\a ', "C:\\a'", '\\Users\\a ']


@pytest.mark.parametrize('unit', HOSTILE_RUNS, ids=[f'u{i}' for i in range(len(HOSTILE_RUNS))])
def test_path_scrubbing_stays_linear_on_hostile_lines(unit):
    line = (unit * (64 * 1024 // len(unit) + 1))[:64 * 1024]
    started = time.perf_counter()
    process.sanitize(line, len(line))
    process.excerpt(line)
    assert time.perf_counter() - started <= 1.5


def test_error_line_search_over_a_large_stdout_stays_bounded():
    stdout = '\n'.join([',/a' * 5_000] * 16)  # 240 KB with no error word, so every line is sanitized 3 times
    started = time.perf_counter()
    process.first_error_line(stdout)
    assert time.perf_counter() - started <= 3.0


def test_a_directory_with_a_space_never_survives():
    assert process.sanitize('rules in D:\\Program Files\\capa rules\\x.yml are stale') == 'rules in x.yml are stale'


def test_excerpt_and_error_line_scrub_the_same_way():
    stderr = 'note: start\nERROR: cannot open C:\\Users\\John Smith\\AppData\\Local\\Temp\\pt\\artifact.bin\n'
    assert process.first_error_line(stderr) == 'ERROR: cannot open artifact.bin'
    assert 'John' not in process.excerpt(stderr) and 'artifact.bin' in process.excerpt(stderr)


def test_text_without_an_anchored_path_is_unchanged():
    for text in ('capa v9.1.0', 'error: rule syntax: unexpected key at line 3', 'invalid PE header (0x5A4D)'):
        assert process.sanitize(text) == text
    assert process.sanitize('error in C:\\Users\\bob\\tool.exe') == 'error in tool.exe'


def test_tool_text_still_keeps_slashes_in_names():
    assert process.tool_text('compiler: C/C++ packer: UPX/LZMA') == 'compiler: C/C++ packer: UPX/LZMA'


# ---- C-19: a function id with a trailing newline is not `rva:0x<hex>` --------------------------------------------

@pytest.mark.parametrize('value', ['rva:0x10\n', 'rva:0x10\r\n', 'rva:0x10 '], ids=['lf', 'crlf', 'space'])
def test_function_id_with_trailing_text_is_refused(value):
    with pytest.raises(ValidationError):
        EvidenceLink(tool_run_id='r1', artifact_sha256=SHA, function_id=value, rva=16, attribution='function-start')


def test_function_id_in_canonical_form_is_accepted():
    link = EvidenceLink(tool_run_id='r1', artifact_sha256=SHA, function_id='rva:0x10', rva=16,
                        attribution='function-start')
    assert link.function_id == 'rva:0x10'


# ---- C-20: a delta with no run on either side is a typed input error ---------------------------------------------

def test_compute_without_any_run_is_a_typed_input_error():
    with pytest.raises(ToolError) as caught:
        delta.compute(None, None, None, None)
    assert caught.value.code == 'PT-TOOL-INPUT'


def test_compute_with_one_run_is_still_not_comparable():
    manifest = ToolManifest(engine='capa', version='9.1.0', executable_sha256='e' * 64, license='Apache-2.0',
                            rules_source='embedded', supported=True)
    run = ToolRun(run_id='run-newer', engine='capa', side='newer', input_artifact_hash=SHA, config_digest='d' * 64,
                  cache_key='c' * 64, started_at='t', elapsed=0, status='ok', evidence_count=0, profile='basic',
                  manifest=manifest)
    result = delta.compute(None, None, run, None)
    assert not result.comparable and result.engine == 'capa'
    assert result.reasons == ('no stored run for the older artifact',)
