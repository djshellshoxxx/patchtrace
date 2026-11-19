"""Current CLI/worker parity on authored PE data; no target or tool execution."""
from __future__ import annotations

import threading
from types import SimpleNamespace

from test_intel_tools_pe import KERNEL32, MSVC_RICH, _image, _strings_code

from patchtrace.gui.projection import ProjectKey
from patchtrace.service import ProjectService
from patchtrace.strings.cli import compute
from patchtrace.strings.qt_panel import Request, scan_builtin


def test_dock_and_cli_preserve_api_cues_and_review_order(tmp_path):
    paths = {}
    for side, extra in (('older', False), ('newer', True)):
        functions = ['OutputDebugStringA'] + (['GetProcAddress'] if extra else [])
        strings = {'s_text': b'plain text here\0'}
        if extra:
            strings['s_api'] = b'GetProcAddress\0'
        paths[side] = tmp_path / f'{side}.exe'
        paths[side].write_bytes(_image(_strings_code, {KERNEL32: functions}, strings, rich=MSVC_RICH))
    service = ProjectService.create(paths['older'], paths['newer'], 'strings', tmp_path / 'case')
    try:
        artifacts = {a.side: a for a in service.project.artifacts}
        key = ProjectKey(str(service.root), service.project.id, service.project.revision, None,
                         artifacts['older'].sha256, artifacts['newer'].sha256)
        request = Request(key, *(service.root / artifacts[s].relative_path for s in ('older', 'newer')),
                          artifacts['older'].sha256, artifacts['newer'].sha256,
                          root=service.root, project=service.project.model_copy(deep=True))
        expected = compute(SimpleNamespace(source='builtin', anchors=None, min_length=4), service,
                           threading.Event())
        actual = scan_builtin(request, threading.Event(), lambda *_: None)
        api = next(c for c in actual.delta.changes if c.display == 'GetProcAddress')
        assert 'api-name' in api.cues
        def fields(delta):
            return [(c.id, c.status, c.cues, c.review_tier, c.reasons) for c in delta.changes]
        assert fields(actual.delta) == fields(expected.delta)
    finally:
        service.close()
