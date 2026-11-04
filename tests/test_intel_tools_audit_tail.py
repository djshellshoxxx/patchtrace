"""Regression tests for the open low-severity tool-adapter rows C-16, C-19 and C-20 of
`docs/audits/20261015-intelligence-kev-rules-fabric-pilot.md` (gameplan KBB-04). Written red against the pre-fix
code. Pure: no tool is executed, no network."""
from __future__ import annotations

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
