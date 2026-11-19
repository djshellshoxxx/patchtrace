"""Bounded diagnostic observations from authored IR; no native producer or target execution."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_unified_live_tool import load_tool
from unified_extract_builder import SHA, document_set, function, pe_view, write_jsonl

from patchtrace.unified.ir import schema
from patchtrace.unified.ir.ingest import ExpectedSide, ingest


def build_result(root, *, label='older', ordinal=1, mode='analyze', alias='first-alias', text='RET #0', count=1):
    directory = root / f'{label}-{ordinal}-{mode}'
    directory.mkdir()
    records = [function(0x1000 + 16 * n, [('ret',)], name=f'fn{n}', aliases=(alias,), texts=[text])
               for n in range(count)]
    raw = write_jsonl(directory / 'source.jsonl', document_set(*records, sha=SHA, mode=mode))
    ir = directory / 'ir'
    ir.mkdir()
    built = ingest(raw, ExpectedSide(label, SHA, pe_view(), mode=mode), out_dir=ir)
    packed = None
    if mode == 'analyze':
        packed = directory / 'program.gzf'
        packed.write_bytes(b'authored placeholder; never parsed by a native producer')
    result = {'manifest': built.manifest, 'directory': ir, 'jsonl': raw.read_bytes(), 'mode': mode,
              'gzf': packed, 'probe': dict.fromkeys(('ghidra', 'java', 'pyghidra', 'python'), 'authored'),
              'extract_seconds': 0.0, 'ingest_seconds': 0.0, 'stderr_tail': ''}
    return result


@pytest.fixture
def setup(tmp_path):
    tool = load_tool()
    work = tmp_path / 'work'
    work.mkdir()
    out = tmp_path / 'out'
    out.mkdir()
    side = SimpleNamespace(label='older', sha256=SHA, other_sha256='12' * 32, work=work, pe=pe_view())
    return tool, work, out, side


def documents(out):
    return [(path, json.loads(path.read_text(encoding='utf-8')))
            for path in sorted(out.glob('live-unified-diagnostics-*.json'))]


def writer(setup, **kwargs):
    tool, work, out, _side = setup
    return tool._RunDiagnostics(out, work, 'authored-tag', **kwargs)


def test_default_quotas_are_exact_and_separate_from_native_limits(setup):
    tool, *_ = setup
    expected = {
        'DIAGNOSTIC_FILE_BYTES': 12 * 1024 ** 2, 'DIAGNOSTIC_PAIR_BYTES': 48 * 1024 ** 2,
        'DIAGNOSTIC_ATTEMPTS': 4, 'DIAGNOSTIC_JSONL_BYTES': 4 * 1024 ** 2,
        'DIAGNOSTIC_JSONL_RECORDS': 4098, 'DIAGNOSTIC_IR_BYTES': 4 * 1024 ** 2,
        'DIAGNOSTIC_IR_ROWS': 32768, 'DIAGNOSTIC_FN_ROWS': 4096,
        'DIAGNOSTIC_FN_BYTES': 512 * 1024, 'DIAGNOSTIC_ROW_BYTES': 16 * 1024,
        'DIAGNOSTIC_META_BYTES': 128 * 1024, 'DIAGNOSTIC_SECONDS': 2,
        'DIAGNOSTIC_SQL_STEPS': 2_000_000,
    }
    assert {name: getattr(tool, name) for name in expected} == expected
    assert tool.EXTRACT_TIMEOUT_S == 1200


def test_complete_capture_round_trips_exact_inputs_and_identity(setup, tmp_path):
    tool, work, out, side = setup
    result = build_result(work)
    original_ir = (result['directory'] / schema.DB_NAME).read_bytes()
    writer(setup).capture(side, 1, result)
    [(path, doc)] = documents(out)
    assert path.stat().st_size <= tool.DIAGNOSTIC_FILE_BYTES and doc['complete'] is True
    assert doc['contract'] == 'live-unified-diagnostics/1'
    assert (doc['side'], doc['analyze_ordinal']) == ('older', 1)
    assert doc['metadata']['pair'] == {'older': SHA, 'newer': side.other_sha256}
    assert doc['metadata']['manifest'] == result['manifest'].model_dump(mode='json')
    assert doc['metadata']['source']['tool_sha256'] == hashlib.sha256(Path(tool.__file__).read_bytes()).hexdigest()
    for key, raw in [('jsonl', result['jsonl']), ('ir', original_ir)]:
        payload = doc[key]
        assert payload['status'] == 'complete'
        assert base64.b64decode(payload['data_base64'], validate=True) == raw
        assert payload['bytes'] == len(raw) and payload['sha256'] == hashlib.sha256(raw).hexdigest()
    assert doc['functions']['columns'] == list(schema.COLUMNS['fn'])
    assert doc['functions']['status'] == 'complete' and doc['functions']['retained_rows'] == 1
    assert 'first-alias' in json.dumps(doc['functions']['rows'])
    decoded = tmp_path / 'decoded.sqlite3'
    decoded.write_bytes(base64.b64decode(doc['ir']['data_base64']))
    db = schema.open_readonly(decoded)
    try:
        assert schema.content_digest(db) == result['manifest'].content_digest
        assert doc['ir']['row_counts'] == {table: db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
                                          for table in schema.TABLES}
    finally:
        db.close()


def test_non_function_difference_is_preserved_without_redefining_digest(setup, tmp_path):
    _tool, work, out, side = setup
    first = build_result(work, ordinal=1, text='RET original')
    second = build_result(work, ordinal=2, text='RET changed annotation')
    assert first['manifest'].content_digest != second['manifest'].content_digest
    diag = writer(setup)
    diag.capture(side, 1, first)
    diag.capture(side, 2, second)
    captured = [doc for _path, doc in documents(out)]
    assert captured[0]['functions']['rows'] == captured[1]['functions']['rows']
    for ordinal, (doc, result) in enumerate(zip(captured, (first, second), strict=True)):
        path = tmp_path / f'decoded-{ordinal}.sqlite3'
        path.write_bytes(base64.b64decode(doc['ir']['data_base64']))
        db = schema.open_readonly(path)
        try:
            assert schema.content_digest(db) == result['manifest'].content_digest
        finally:
            db.close()


@pytest.mark.parametrize('component,constant', [('jsonl', 'DIAGNOSTIC_JSONL_BYTES'), ('ir', 'DIAGNOSTIC_IR_BYTES')])
@pytest.mark.parametrize('over', [False, True])
def test_payload_byte_boundary_is_observed_before_encoding(setup, monkeypatch, component, constant, over):
    tool, work, out, side = setup
    result = build_result(work)
    size = len(result['jsonl']) if component == 'jsonl' else (result['directory'] / schema.DB_NAME).stat().st_size
    monkeypatch.setattr(tool, constant, size - int(over))
    writer(setup).capture(side, 1, result)
    doc = documents(out)[0][1]
    assert doc[component]['status'] == ('omitted' if over else 'complete')
    assert ('data_base64' in doc[component]) is not over
    if over:
        assert doc['complete'] is False and doc[component]['reason'] == 'byte-cap'


@pytest.mark.parametrize('over', [False, True])
def test_jsonl_record_boundary_is_not_a_silent_prefix(setup, monkeypatch, over):
    tool, work, out, side = setup
    result = build_result(work, count=2)
    monkeypatch.setattr(tool, 'DIAGNOSTIC_JSONL_RECORDS', 4 - int(over))
    writer(setup).capture(side, 1, result)
    doc = documents(out)[0][1]
    assert doc['jsonl']['status'] == ('omitted' if over else 'complete')
    if over:
        assert doc['jsonl']['reason'] == 'record-cap' and 'sha256' not in doc['jsonl']


@pytest.mark.parametrize('over', [False, True])
def test_ir_total_row_cap_is_distinct_from_function_projection(setup, monkeypatch, over):
    tool, work, out, side = setup
    result = build_result(work, count=2)
    db = schema.open_readonly(result['directory'] / schema.DB_NAME)
    try:
        total = sum(db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in schema.TABLES)
    finally:
        db.close()
    monkeypatch.setattr(tool, 'DIAGNOSTIC_IR_ROWS', total - int(over))
    writer(setup).capture(side, 1, result)
    doc = documents(out)[0][1]
    assert doc['ir']['status'] == ('omitted' if over else 'complete')
    if over:
        assert doc['ir']['reason'] == 'row-cap' and 'data_base64' not in doc['ir']


def test_function_row_cap_retains_an_explicit_prefix_and_complete_binary(setup, monkeypatch):
    tool, work, out, side = setup
    result = build_result(work, count=3)
    monkeypatch.setattr(tool, 'DIAGNOSTIC_FN_ROWS', 2)
    writer(setup).capture(side, 1, result)
    doc = documents(out)[0][1]
    assert not doc['complete'] and doc['ir']['status'] == 'complete'
    assert doc['functions']['status'] == 'prefix' and doc['functions']['retained_rows'] == 2
    assert doc['functions']['source_rows'] == 3 and len(doc['functions']['rows']) == 2


def test_large_function_row_is_not_dumped_before_its_cap(setup, monkeypatch):
    tool, work, out, side = setup
    result = build_result(work, alias='q' * 300)
    monkeypatch.setattr(tool, 'DIAGNOSTIC_ROW_BYTES', 128)
    writer(setup).capture(side, 1, result)
    doc = documents(out)[0][1]
    assert doc['functions']['status'] == 'omitted' and doc['functions']['retained_rows'] == 0
    assert doc['functions']['reason'] == 'row-byte-cap' and doc['ir']['status'] == 'complete'


def test_function_component_byte_cap_is_enforced_in_utf8(setup, monkeypatch):
    tool, work, out, side = setup
    result = build_result(work, alias='四' * 300, count=4)
    monkeypatch.setattr(tool, 'DIAGNOSTIC_FN_BYTES', 2048)
    writer(setup).capture(side, 1, result)
    doc = documents(out)[0][1]
    payload = json.dumps(doc['functions'], ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    assert len(payload) <= 2048 and doc['functions']['status'] in {'prefix', 'omitted'}
    assert not doc['complete']


def test_metadata_failure_preserves_independent_payload_and_is_not_complete(setup, monkeypatch):
    tool, work, out, side = setup
    result = build_result(work)
    monkeypatch.setattr(tool, 'DIAGNOSTIC_META_BYTES', 1024)
    writer(setup).capture(side, 1, result)
    doc = documents(out)[0][1]
    assert doc['metadata']['status'] == 'omitted' and doc['metadata']['reason'] == 'metadata-cap'
    assert doc['jsonl']['status'] == 'complete' and not doc['complete']


def test_snapshot_hash_change_is_reported_without_losing_jsonl(setup):
    _tool, work, out, side = setup
    result = build_result(work)
    path = result['directory'] / schema.DB_NAME
    path.write_bytes(path.read_bytes() + b'changed after ingest')
    writer(setup).capture(side, 1, result)
    doc = documents(out)[0][1]
    assert doc['ir']['status'] == 'error' and doc['ir']['reason'] == 'hash-mismatch'
    assert doc['jsonl']['status'] == 'complete' and not doc['complete']


def test_hash_matching_malformed_snapshot_is_not_complete(setup):
    _tool, work, out, side = setup
    result = build_result(work)
    raw = b'authored malformed database'
    (result['directory'] / schema.DB_NAME).write_bytes(raw)
    result['manifest'] = result['manifest'].model_copy(update={'file_sha256': hashlib.sha256(raw).hexdigest()})
    writer(setup).capture(side, 1, result)
    doc = documents(out)[0][1]
    assert doc['ir']['status'] == 'error' and 'data_base64' not in doc['ir']
    assert doc['jsonl']['status'] == 'complete' and not doc['complete']


def test_symlink_snapshot_is_not_read_or_deleted(setup, tmp_path):
    _tool, work, out, side = setup
    result = build_result(work)
    path = result['directory'] / schema.DB_NAME
    foreign = tmp_path / 'foreign.sqlite3'
    path.rename(foreign)
    try:
        path.symlink_to(foreign)
    except OSError:
        pytest.skip('symlink creation unavailable on this host')
    before = foreign.read_bytes()
    writer(setup).capture(side, 1, result)
    doc = documents(out)[0][1]
    assert doc['ir']['status'] == 'error' and doc['ir']['reason'] == 'nonregular'
    assert path.is_symlink() and foreign.read_bytes() == before


def test_same_tag_invocations_have_distinct_exclusive_files(setup):
    _tool, work, out, side = setup
    result = build_result(work)
    writer(setup).capture(side, 1, result)
    old = {p.name: p.read_bytes() for p, _d in documents(out)}
    writer(setup).capture(side, 1, result)
    assert len(documents(out)) == 2
    assert all((out / name).read_bytes() == data for name, data in old.items())
    assert len({doc['invocation_id'] for _path, doc in documents(out)}) == 2


def test_collision_spends_slot_and_never_retries_or_overwrites(setup, monkeypatch):
    tool, work, out, side = setup
    result = build_result(work)
    monkeypatch.setattr(tool.uuid, 'uuid4', lambda: SimpleNamespace(hex='1' * 32))
    path = out / ('live-unified-diagnostics-' + '1' * 32 + '-older-analyze-1.json')
    path.write_bytes(b'foreign evidence')
    diag = writer(setup)
    diag.capture(side, 1, result)
    assert path.read_bytes() == b'foreign evidence'
    path.unlink()  # test removes its own blocker, not product cleanup or permission to retry
    diag.capture(side, 1, result)
    assert not path.exists()


def test_four_attempts_and_pair_bytes_have_no_failure_refund(setup, monkeypatch):
    tool, work, out, side = setup
    result = build_result(work)
    monkeypatch.setattr(tool, 'DIAGNOSTIC_PAIR_BYTES', tool.DIAGNOSTIC_FILE_BYTES)
    diag = writer(setup)
    diag.capture(side, 1, result)
    for label, ordinal in [('older', 2), ('newer', 1), ('newer', 2), ('older', 1)]:
        diag.capture(SimpleNamespace(**{**vars(side), 'label': label}), ordinal, result)
    assert len(documents(out)) == 1
    assert sum(p.stat().st_size for p, _d in documents(out)) <= tool.DIAGNOSTIC_PAIR_BYTES


def test_deadline_is_checked_again_after_the_existing_reader_open(setup, monkeypatch):
    tool, work, out, side = setup
    result = build_result(work)
    clock = [0.0]
    original = tool.schema.open_readonly

    def open_then_exhaust(path):
        connection = original(path)
        clock[0] = 3.0
        return connection

    monkeypatch.setattr(tool.schema, 'open_readonly', open_then_exhaust)
    writer(setup, clock=lambda: clock[0]).capture(side, 1, result)
    doc = documents(out)[0][1]
    assert doc['ir']['reason'] == 'deadline' and not doc['complete']


def test_post_open_query_progress_is_bounded(setup, monkeypatch):
    tool, work, out, side = setup
    result = build_result(work, count=20)
    monkeypatch.setattr(tool, 'DIAGNOSTIC_SQL_STEPS', 1)
    writer(setup).capture(side, 1, result)
    doc = documents(out)[0][1]
    assert doc['ir']['status'] == 'error' and doc['ir']['reason'] == 'query-cap'
    assert not doc['complete']


def test_failing_diagnostic_reporter_never_raises_or_changes_a_capture_failure(setup, monkeypatch):
    tool, work, out, side = setup
    result = build_result(work)

    class BrokenStream:
        def write(self, _text):
            raise RuntimeError('sensitive sink details')

    monkeypatch.setattr(tool.sys, 'stderr', BrokenStream())
    monkeypatch.setattr(tool, 'DIAGNOSTIC_PAIR_BYTES', 0)
    writer(setup).capture(side, 1, result)
    assert not list(out.iterdir())


def test_partial_write_is_visible_and_cannot_be_announced_saved(setup, monkeypatch, capsys):
    tool, work, out, side = setup
    result = build_result(work)
    original = Path.open

    class BrokenWrite:
        def __init__(self, target):
            self.target = target

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.target.close()

        def write(self, data):
            self.target.write(data[:10])
            raise OSError('sensitive write details')

    def open_with_failure(path, mode='r', *args, **kwargs):
        handle = original(path, mode, *args, **kwargs)
        if path.parent == out and mode == 'xb':
            return BrokenWrite(handle)
        return handle

    monkeypatch.setattr(Path, 'open', open_with_failure)
    writer(setup).capture(side, 1, result)
    [path] = list(out.glob('*.json'))
    assert path.read_bytes() and not path.read_bytes().endswith(b'}\n')
    stderr = capsys.readouterr().err
    assert 'write-error' in stderr and 'sensitive write details' not in stderr and 'saved' not in stderr
