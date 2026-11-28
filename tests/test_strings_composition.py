"""CLI/dock composition parity on authored PE bytes; no target or extractor execution."""
from __future__ import annotations

import hashlib
import threading
from types import SimpleNamespace

import pytest
from strings_pe import synergy_pair

from patchtrace.gui.projection import ProjectKey
from patchtrace.intelligence.contracts import Anchor, AnchorSet
from patchtrace.service import ProjectService
from patchtrace.strings import cli
from patchtrace.strings.contracts import StringsError


@pytest.fixture
def service(tmp_path):
    pair = synergy_pair()
    for side in ('older', 'newer'):
        data = getattr(pair, side)
        if side == 'older':
            # Equal-length import-name replacement adds an API-name delta without moving PE fields.
            data = data.replace(b'OutputDebugStringA', b'GetCurrentThreadId')
        (tmp_path / f'{side}.exe').write_bytes(data)
    with ProjectService.create(tmp_path / 'older.exe', tmp_path / 'newer.exe',
                               'composition', tmp_path / 'case') as found:
        yield found


def request_for(service, **kwargs):
    from patchtrace.strings.qt_panel import Request
    artifacts = {artifact.side: artifact for artifact in service.project.artifacts}
    key = ProjectKey(str(service.root), service.project.id, service.project.revision, None,
                     artifacts['older'].sha256, artifacts['newer'].sha256)
    return Request(key, *(service.root / artifacts[side].relative_path for side in ('older', 'newer')),
                   *(artifacts[side].sha256 for side in ('older', 'newer')),
                   root=service.root, project=service.project.model_copy(deep=True), **kwargs)


def cli_result(service, anchors=None):
    return cli.compute(SimpleNamespace(source='builtin', anchors=anchors, min_length=4), service, threading.Event())


def test_builtin_dock_delta_equals_cli_including_real_imports_and_regions(service):
    from patchtrace.strings.qt_panel import scan_builtin
    expected = cli_result(service)
    actual = scan_builtin(request_for(service), threading.Event(), lambda *_: None)
    api = next(change for change in expected.delta.changes if change.display == 'OutputDebugStringA')
    assert 'api-name' in api.cues
    message = next(change for change in expected.delta.changes if change.display == 'index %u exceeds length %u')
    assert message.newer.region == 'rdata'
    assert actual.delta == expected.delta


def test_explicit_anchor_file_has_identical_dock_cues_and_hits(service, tmp_path):
    from patchtrace.strings.qt_panel import scan_builtin
    anchor = Anchor(anchor_id=hashlib.sha256(b'anchor').hexdigest(), kind='string', value='exceeds length',
                    source='csaf-title', quality='explicit', label='authored advisory phrase')
    path = tmp_path / 'anchors.json'
    path.write_text(AnchorSet(cve='CVE-2026-0001', anchors=(anchor,)).model_dump_json(), encoding='utf-8')
    expected = cli_result(service, path)
    actual = scan_builtin(request_for(service, anchors_path=path), threading.Event(), lambda *_: None)
    assert len(expected.delta.anchors.hits) == 1
    assert actual.delta == expected.delta
    assert 'advisory-text' in next(change for change in actual.delta.changes
                                   if change.display == 'index %u exceeds length %u').cues


def test_pre_cancelled_dock_does_not_inspect_artifacts(service, monkeypatch):
    from patchtrace.strings import pairing
    from patchtrace.strings.qt_panel import scan_builtin

    def unexpected(*_args, **_kwargs):
        raise AssertionError('cancelled comparison opened an artifact')

    monkeypatch.setattr(pairing, 'inspect_image', unexpected)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(StringsError) as caught:
        scan_builtin(request_for(service), cancel, lambda *_: None)
    assert caught.value.code == 'PT-STR-CANCEL'


@pytest.mark.parametrize('payload', [
    '{"cve":"CVE-2026-0001","cve":"CVE-2026-0002"}',
    '{"cve":"CVE-2026-0001","unknown":NaN}',
], ids=['duplicate', 'nonfinite'])
def test_anchor_reader_refuses_non_strict_json(service, tmp_path, payload):
    path = tmp_path / 'anchors.json'
    path.write_text(payload, encoding='utf-8')
    with pytest.raises(StringsError) as caught:
        cli_result(service, path)
    assert caught.value.code == 'PT-STR-INPUT'


def _context_inputs(tmp_path):
    from test_strings_regions import RDATA, sec

    from patchtrace.strings.pairing import Image
    from patchtrace.strings.scan import BuiltinScanSource
    payloads = {'older': b'\0ordinary older text\0',
                'newer': b'\0ExplicitExport\0OtherSideImport\0HintOnlyAPI\0resource phrase\0AKIAIOSFODNN7EXAMPLE\0'}
    sources, images = {}, {}
    for side, data in payloads.items():
        path = tmp_path / f'{side}.bin'
        path.write_bytes(data)
        sources[side] = (BuiltinScanSource(path, artifact_sha256=hashlib.sha256(data).hexdigest(), side=side,
                                           offset_to_rva=lambda off: 0x4000 + off), 'builtin-scan')
        overview = SimpleNamespace(
            imports=SimpleNamespace(dlls=(SimpleNamespace(functions=('OtherSideImport',) if side == 'older' else ()),)),
            exports=SimpleNamespace(names=('ExplicitExport',) if side == 'newer' else ()),
            sections=(sec('.rsrc', 0x4000, 0x1000, RDATA),))
        images[side] = Image(overview=overview)
    anchors = AnchorSet(cve='CVE-2026-0001', anchors=tuple(
        Anchor(anchor_id=hashlib.sha256(value.encode()).hexdigest(), kind=kind, value=value,
               source='csaf-title', quality='explicit', label='authored hint')
        for kind, value in [('api', 'HintOnlyAPI'), ('string', 'resource phrase'),
                            ('string', 'AKIAIOSFODNN7EXAMPLE')]))
    return sources, images, anchors


def test_composition_uses_export_cross_build_advisory_and_section_context(tmp_path):
    from patchtrace.strings.compose import compare
    sources, images, anchors = _context_inputs(tmp_path)
    found = compare(sources, images, None, None, anchors, threading.Event())
    rows = {row.display: row for row in found.delta.changes}
    assert 'api-name' in rows['ExplicitExport'].cues
    assert 'dynamic-api' in rows['OtherSideImport'].cues
    assert {'dynamic-api', 'advisory-api'} <= set(rows['HintOnlyAPI'].cues)
    assert {'resource', 'advisory-text'} <= set(rows['resource phrase'].cues)
    assert rows['resource phrase'].newer.region == 'resource'
    secret = next(row for row in found.delta.changes if 'secret-like' in row.cues)
    assert 'AKIAIOSFODNN7EXAMPLE' not in secret.display
    assert secret.value_sha256 not in {hit.string_id for hit in found.delta.anchors.hits}
    assert len(found.delta.anchors.hits) == 2


@pytest.mark.parametrize('stage', ['source', 'pairing', 'delta', 'anchors'])
def test_cancellation_at_stage_boundary_refuses_partial_comparison(tmp_path, monkeypatch, stage):
    from patchtrace.strings import anchors as anchor_module
    from patchtrace.strings import delta, pairing
    from patchtrace.strings.compose import compare
    sources, images, anchors = _context_inputs(tmp_path)
    cancel = threading.Event()
    target, name = {'source': (sources['older'][0], 'load'), 'pairing': (pairing, 'project_links'),
                    'delta': (delta, 'compute_delta'), 'anchors': (anchor_module, 'attach_anchors')}[stage]
    original = getattr(target, name)

    def stop_after(*args, **kwargs):
        result = original(*args, **kwargs)
        cancel.set()
        return result

    monkeypatch.setattr(target, name, stop_after)
    with pytest.raises(StringsError) as caught:
        compare(sources, images, None, None, anchors, cancel)
    assert caught.value.code == 'PT-STR-CANCEL'


def test_anchor_reader_measures_bytes_and_refuses_the_first_byte_over_budget(tmp_path, monkeypatch):
    from patchtrace.strings import compose
    path = tmp_path / 'anchors.json'
    raw = AnchorSet(cve='CVE-2026-0001').model_dump_json().encode('utf-8')
    monkeypatch.setattr(compose, 'MAX_ANCHOR_FILE', len(raw))
    path.write_bytes(raw)
    assert compose.load_anchors(path).cve == 'CVE-2026-0001'
    path.write_bytes(raw + b' ')
    with pytest.raises(StringsError, match='too large'):
        compose.load_anchors(path)
