"""B-0: optional dependency probe never raises and reports missing capabilities actionably."""
from __future__ import annotations

import pytest

from patchtrace import optional_deps


def test_probe_covers_every_registered_name():
    caps = optional_deps.probe()
    assert tuple(caps) == optional_deps.NAMES == ('rapidfuzz', 'pygments', 'pefile', 'yara-x')
    assert {c.extra for c in caps.values()} == {'search', 'workbench', 'rules'}


def test_missing_capability_is_actionable(monkeypatch):
    extra, dist, _module, _error = optional_deps._REGISTRY['pefile']
    monkeypatch.setitem(optional_deps._REGISTRY, 'pefile', (extra, dist, None, "ImportError('x')"))
    cap = optional_deps.probe(('pefile',))['pefile']
    assert not cap.available and cap.version == '' and 'patchtrace[workbench]' in cap.detail
    assert not optional_deps.available('pefile')
    assert 'missing=pefile' in optional_deps.summary_line()


def test_unknown_name_raises():
    with pytest.raises(KeyError):
        optional_deps.probe(('nope',))


def test_summary_line_shape():
    line = optional_deps.summary_line()
    assert line.startswith('optional-deps: present=') and ' missing=' in line
