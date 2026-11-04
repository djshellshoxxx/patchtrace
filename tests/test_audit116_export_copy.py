"""Audit #116 P2: export policy copy must not claim blanket path redaction when code/evidence stay verbatim."""
from pathlib import Path

import pytest

UI = Path(__file__).resolve().parents[1] / 'src' / 'patchtrace' / 'ui.py'


@pytest.mark.xfail(strict=True, reason='audit116#4: ExportDialog says absolute paths are redacted although '
                   'verbatim code/evidence keep them; owner GUI worker (ui.py is frozen)')
def test_export_policy_copy_qualifies_path_redaction():
    text = UI.read_text(encoding='utf-8')
    start = text.index('Absolute source paths are redacted')
    assert 'code' in text[start:start + 300].lower().split('review the preview')[0]
