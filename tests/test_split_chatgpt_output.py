"""tools/split_chatgpt_output.py: path safety, fence stripping and the no-overwrite default."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location('split_chatgpt_output', Path(__file__).resolve().parents[1] / 'tools' / 'split_chatgpt_output.py')
tool = importlib.util.module_from_spec(SPEC)
sys.modules['split_chatgpt_output'] = tool
SPEC.loader.exec_module(tool)

ANSWER = """Here you go.
=== FILE: docs/specs/panels/kev.md ===
```markdown
# KEV panel
body
```
NEXT: capabilities
=== FILE: tests/fixtures/kb/a.json ===
{"a": 1}
"""


def test_parse_strips_fences_and_next_lines():
    blocks = tool.parse(ANSWER)
    assert [b.path for b in blocks] == ['docs/specs/panels/kev.md', 'tests/fixtures/kb/a.json']
    assert blocks[0].text == '# KEV panel\nbody\n'
    assert blocks[1].text == '{"a": 1}\n'


@pytest.mark.parametrize('raw', ['../x.md', '/etc/passwd', 'C:/x.md', 'docs\\x.md', 'src/patchtrace/x.py', 'docs/../src/x.py', ''],
                         ids=['dotdot', 'abs', 'drive', 'backslash', 'src', 'dotdot-inside', 'empty'])
def test_unsafe_paths_are_rejected(raw):
    assert tool.check_path(raw) is not None


@pytest.mark.parametrize('raw', ['docs/a.md', 'tests/test_x.py', 'tools/calibration/catalogue/x.json'], ids=['docs', 'tests', 'calib'])
def test_allowed_paths(raw):
    assert tool.check_path(raw) is None


def test_apply_writes_lf_and_never_overwrites(tmp_path):
    source = tmp_path / 'saved.md'
    source.write_text(ANSWER, encoding='utf-8')
    assert tool.main([str(source), '--root', str(tmp_path)]) == 0           # dry run
    assert not (tmp_path / 'docs').exists()
    assert tool.main([str(source), '--root', str(tmp_path), '--apply']) == 0
    target = tmp_path / 'docs' / 'specs' / 'panels' / 'kev.md'
    assert target.read_bytes() == b'# KEV panel\nbody\n'
    target.write_text('mine', encoding='utf-8')
    assert tool.main([str(source), '--root', str(tmp_path), '--apply']) == 1  # exists: rejected, not overwritten
    assert target.read_text(encoding='utf-8') == 'mine'


def test_no_headers_is_a_usage_error(tmp_path):
    source = tmp_path / 'x.md'
    source.write_text('nothing here', encoding='utf-8')
    assert tool.main([str(source), '--root', str(tmp_path)]) == 2
