"""WB3-S7c `strings.compose`: the one comparison behind `patchtrace strings list|delta|explain|export` and the
Strings dock. Synthetic PE images (bytes, never executed) read with the built-in scan; fake stores; no Qt."""
from __future__ import annotations

import hashlib
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_intel_tools_pe import KERNEL32, MSVC_RICH, _image, _strings_code

from patchtrace.strings import compose
from patchtrace.strings.contracts import StringsError
from patchtrace.strings.pairing import NO_ANALYSIS, Image, inspect_image
from patchtrace.strings.sources import FlossEvidenceSource

API = 'GetProcAddress'


def imports_pair() -> tuple[bytes, bytes]:
    """The newer build imports GetProcAddress and adds a string equal to that name; the older build has neither."""
    older = _image(_strings_code, {KERNEL32: ['OutputDebugStringA']}, {'s_text': b'plain text here\0'},
                   rich=MSVC_RICH)
    newer = _image(_strings_code, {KERNEL32: ['OutputDebugStringA', API]},
                   {'s_text': b'plain text here\0', 's_api': API.encode() + b'\0'}, rich=MSVC_RICH)
    return older, newer


def builtin_inputs(tmp_path: Path, pair: tuple[bytes, bytes], cancel: threading.Event):
    sources, images = {}, {}
    for side, data in zip(('older', 'newer'), pair, strict=True):
        path = tmp_path / f'{side}.exe'
        path.write_bytes(data)
        sha = hashlib.sha256(data).hexdigest()
        images[side] = inspect_image(path, sha)
        sources[side] = compose.builtin_source(path, sha, side, 4, images[side], cancel), 'builtin-scan'
    return sources, images


def test_cues_know_the_imports_of_each_build(tmp_path):
    cancel = threading.Event()
    sources, images = builtin_inputs(tmp_path, imports_pair(), cancel)
    computed = compose.compare(sources, images, None, None, None, cancel)
    found = [c for c in computed.delta.changes if c.display == API]
    assert [c.status for c in found] == ['only-newer'] and 'api-name' in found[0].cues
    assert computed.sources == {'older': 'builtin-scan', 'newer': 'builtin-scan'}
    assert computed.pairing_reason == NO_ANALYSIS and computed.delta.comparable


def test_progress_names_each_side_in_order(tmp_path):
    cancel, seen = threading.Event(), []
    sources, images = builtin_inputs(tmp_path, imports_pair(), cancel)
    compose.compare(sources, images, None, None, None, cancel, progress=lambda *a: seen.append(a))
    assert seen == [('older', 1, 2), ('newer', 2, 2)]


def test_a_cancelled_comparison_reads_nothing():
    class Never:
        def load(self):
            raise AssertionError('a cancelled comparison must not read a source')
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(StringsError) as raised:
        compose.compare({'older': (Never(), 'builtin-scan'), 'newer': (Never(), 'builtin-scan')},
                        {'older': Image(), 'newer': Image()}, None, None, None, cancel)
    assert raised.value.code == 'PT-STR-CANCEL'


class Store:
    """A ToolStore stand-in: FLOSS evidence for the sides in `stored`."""

    def __init__(self, *stored: str) -> None:
        self.stored, self.reads = stored, []

    def latest(self, engine: str, side: str):
        self.reads.append((engine, side))
        if side not in self.stored:
            return None
        run = SimpleNamespace(raw_sidecar=f'floss-{side}-{"d" * 64}.json', options={},
                              manifest=SimpleNamespace(executable_sha256='e' * 64, version='3.1.1'))
        return run, SimpleNamespace(side=side)


ARTIFACTS = {'older': SimpleNamespace(side='older'), 'newer': SimpleNamespace(side='newer')}


def test_builtin_never_reads_the_store():
    store = Store('older', 'newer')
    found = compose.stored_sources('builtin', store, ARTIFACTS)
    assert found == {'older': None, 'newer': None} and store.reads == []
    assert compose.missing_floss('builtin', found) is None


def test_auto_takes_stored_floss_per_side_and_the_scan_elsewhere():
    found = compose.stored_sources('auto', Store('newer'), ARTIFACTS)
    assert found['older'] is None and isinstance(found['newer'], FlossEvidenceSource)
    assert compose.missing_floss('auto', found) is None


def test_floss_names_the_first_side_without_stored_results():
    assert compose.missing_floss('floss', compose.stored_sources('floss', Store('newer'), ARTIFACTS)) == 'older'
    assert compose.missing_floss('floss', compose.stored_sources('floss', Store('older'), ARTIFACTS)) == 'newer'
    assert compose.missing_floss('floss', compose.stored_sources('floss', Store('older', 'newer'), ARTIFACTS)) is None


def test_importing_compose_loads_no_qt():
    code = (f'import sys; sys.path.insert(0, {str(Path(compose.__file__).parents[2])!r}); '
            'import patchtrace.strings.compose; '
            'bad = [m for m in sys.modules if m.startswith(("PySide6", "patchtrace.ui", "patchtrace.gui.qt"))]; '
            'sys.exit(1 if bad else 0)')
    assert subprocess.run([sys.executable, '-I', '-c', code], check=False).returncode == 0
