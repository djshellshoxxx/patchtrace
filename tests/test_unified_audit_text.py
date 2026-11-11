"""U7 audit (docs/audits/20261015-unified-audit.md): untrusted text that reaches the unified engine or its panes is
bounded and scrubbed of surrogates and of every invisible or bidirectional character, not only of the controls."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from patchtrace.models import FunctionMatch, FunctionRecord
from patchtrace.unified.contracts import SideRef, strip_unsafe
from patchtrace.unified.extract.decomp import read_decomp
from patchtrace.unified.pair_text import RowCodeSource
from patchtrace.unified.read_text import clean
from patchtrace.unified.sources import snapshot_from_project

# every format character that reorders or hides text: LRM, RLM, ALM, zero-width, word joiner, BOM, soft hyphen, the
# deprecated 206A-206F controls
INVISIBLE = ['‎', '‏', '؜', '​', '‍', '⁠', '﻿', '­', '⁪']
IDS = ['lrm', 'rlm', 'alm', 'zwsp', 'zwj', 'word-joiner', 'bom', 'soft-hyphen', 'deprecated']


def test_strip_unsafe_replaces_surrogates_controls_and_invisibles_and_can_keep_layout():
    assert strip_unsafe('a\ud800b\udc00') == 'a�b�'
    assert strip_unsafe('a\x1b‮b') == 'a��b'
    assert strip_unsafe('x\ty\nz', keep_layout=True) == 'x\ty\nz'
    assert strip_unsafe('x؜y\x00', keep_layout=True, replacement='?') == 'x?y?'
    assert strip_unsafe('plain text 1234') == 'plain text 1234'


@pytest.mark.parametrize('char', INVISIBLE, ids=IDS)
def test_read_model_clean_removes_invisible_characters(char):
    shown = clean(f'ab{char}cd')
    assert char not in shown and shown.startswith('ab') and shown.endswith('cd')


@pytest.mark.parametrize('char', INVISIBLE, ids=IDS)
def test_decompiler_text_is_scrubbed_of_invisible_characters(tmp_path, char):
    line = json.dumps({'side': 'older', 'rva': 4096, 'status': 'ok', 'code': f'puts("a{char}b");\n'})
    path = tmp_path / 'decomp.jsonl'
    path.write_text(line + '\n', encoding='utf-8', newline='\n')
    code = read_decomp(path, 'older', [4096])[4096].code
    assert char not in code and code.endswith(';\n')


@pytest.mark.parametrize('char', INVISIBLE, ids=IDS)
def test_the_decompiled_pane_never_shows_a_stored_invisible_character(char):
    ref = SideRef(rva=0x10, name='f', kind='function')
    records = {('older', 0x10): ('ok', f'int f() {{\n  return "a{char}b\x1b";\n}}')}
    side = RowCodeSource()._c_side(records, 'older', (ref,))
    assert len(side.lines) == 3
    assert all(char not in line and '\x1b' not in line for line in side.lines)


def test_a_function_name_with_a_lone_surrogate_does_not_stop_the_snapshot():
    def function(name):
        return FunctionRecord(artifact_id='a', run_id='r', name=name, address='0x1000', callees=['c\udc00'],
                              callers=['d\ud800'])
    match = FunctionMatch(run_id='r', category='modified', older=[function('f\ud800')], newer=[function('g')])
    snapshot = snapshot_from_project(SimpleNamespace(matches=[match]), 'r')
    only = snapshot[0]
    assert only.older[0].name == 'f�' and only.older[0].callees == ('c�',)
    assert only.older[0].callers == ('d�',)
