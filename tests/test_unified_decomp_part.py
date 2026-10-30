"""S3b: the pipeline writes the decompiled C of the on-demand decompile as the additive result part `decomp.jsonl.gz`
(07 s6). Hermetic: the extractor output is a fake, the staged result is a real one from the recorded probe pair."""
from __future__ import annotations

import dataclasses
import threading
from types import SimpleNamespace

import pytest
from test_unified_wire_compute import probe, run

from patchtrace.unified import pipeline, store
from patchtrace.unified.extract.decomp import DecompRecord, part_lines
from patchtrace.unified.limits import DEFAULT_LIMITS
from patchtrace.unified.pair_text import RowCodeSource

SIDES = ('older', 'newer')


def rec(side, rva, status='ok', code='int f(void)\n{\n  return 1;\n}'):
    return DecompRecord(side, rva, status, code if status == 'ok' else None)


def staged_result(tmp_path):
    inputs, addr, ir = probe(tmp_path)
    return run(tmp_path, inputs, addr, ir=ir)


def test_lines_are_ordered_scrubbed_and_closed_in_shape():
    lines = part_lines({'newer': {0x2000: rec('newer', 0x2000, code='a\x1b[31m‮b\r\n')},
                        'older': {0x1100: rec('older', 0x1100, 'timeout'), 0x1000: rec('older', 0x1000)}})
    assert [(x['side'], x['rva'], x['status']) for x in lines] == [
        ('older', 0x1000, 'ok'), ('older', 0x1100, 'timeout'), ('newer', 0x2000, 'ok')]
    assert all(set(x) == {'side', 'rva', 'status', 'code'} for x in lines)
    assert lines[1]['code'] is None
    assert not any(ch in lines[2]['code'] for ch in '\x1b‮\r')


@pytest.mark.parametrize('limits', [dataclasses.replace(DEFAULT_LIMITS, l29_pseudo_chars=10),
                                    dataclasses.replace(DEFAULT_LIMITS, l29_pseudo_lines=2)], ids=['chars', 'lines'])
def test_text_over_the_l29_caps_becomes_a_failed_record_without_text(limits):
    (line,) = part_lines({'older': {0x1000: rec('older', 0x1000, code='one\ntwo\nthree\nfour')}}, limits)
    assert (line['status'], line['code']) == ('failed', None)


def test_the_part_is_added_to_the_manifest_verified_and_read_by_the_code_pane(tmp_path):
    before, directory = staged_result(tmp_path)
    records = {'older': {0x1000: rec('older', 0x1000)}, 'newer': {0x1000: rec('newer', 0x1000, 'failed')}}
    assert pipeline._store_decomp(directory, records, DEFAULT_LIMITS) == ()
    manifest = store.verify_result_dir(directory)
    part = next(p for p in manifest.parts if p.name == 'decomp.jsonl.gz')
    assert part.records == 2 and part.bytes > 0 and len(part.sha256) == 64
    assert manifest.result_id == before.result_id and manifest.counts == before.counts      # additive only
    found = RowCodeSource._read_decomp(directory / 'decomp.jsonl.gz', part)
    assert found[('older', 0x1000)] == ('ok', rec('older', 0x1000).code)
    assert found[('newer', 0x1000)] == ('failed', None)


def test_no_records_writes_no_part(tmp_path):
    _before, directory = staged_result(tmp_path)
    assert pipeline._store_decomp(directory, {}, DEFAULT_LIMITS) == ()
    assert not (directory / 'decomp.jsonl.gz').exists()
    assert all(p.name != 'decomp.jsonl.gz' for p in store.verify_result_dir(directory).parts)


def test_a_part_over_the_size_limit_costs_the_text_not_the_result(tmp_path):
    _before, directory = staged_result(tmp_path)
    tiny = dataclasses.replace(DEFAULT_LIMITS, l30_part_bytes=16)
    notes = pipeline._store_decomp(directory, {'older': {0x1000: rec('older', 0x1000)}}, tiny)
    assert notes == ('decompile-part-skipped:part-too-large',)
    assert sorted(p.name for p in directory.iterdir()) == ['facts.jsonl.gz', 'manifest.json', 'rows.jsonl.gz']
    store.verify_result_dir(directory)


@pytest.mark.parametrize('failure', ['write', 'register', 'registered', 'register-unified'])
def test_failed_optional_part_storage_rolls_back_and_keeps_the_result_valid(tmp_path, monkeypatch, failure):
    before, directory = staged_result(tmp_path)
    original = {p.name: p.read_bytes() for p in directory.iterdir()}
    real_add = store.add_part

    def fail_write(staged, name, *args):
        (staged / f'{name}.part').write_bytes(b'partial gzip')
        raise OSError('simulated write failure')

    def fail_register(staged, part):
        if failure == 'registered':
            real_add(staged, part)
        else:
            (staged / f'{store.MANIFEST}.part').write_bytes(b'partial manifest')
        if failure == 'register-unified':
            from patchtrace.unified.limits import UnifiedError
            raise UnifiedError('PT-UNIFIED-STORE', 'simulated registration failure', reason='replace-failed')
        raise OSError('simulated registration failure')

    monkeypatch.setattr(store, 'write_part' if failure == 'write' else 'add_part',
                        fail_write if failure == 'write' else fail_register)
    notes = pipeline._store_decomp(directory, {'older': {0x1000: rec('older', 0x1000)}}, DEFAULT_LIMITS)
    assert len(notes) == 1 and notes[0].startswith('decompile-part-skipped:')
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == original
    assert store.verify_result_dir(directory) == before


def test_optional_part_cleanup_failure_refuses_publication(tmp_path, monkeypatch):
    _before, directory = staged_result(tmp_path)

    def fail_register(*args):
        raise OSError('simulated registration failure')

    original_unlink = type(directory).unlink

    def fail_cleanup(path, *args, **kwargs):
        if path == directory / store.DECOMP:
            raise OSError('simulated cleanup failure')
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(store, 'add_part', fail_register)
    monkeypatch.setattr(type(directory), 'unlink', fail_cleanup)
    from patchtrace.unified.limits import UnifiedError
    with pytest.raises(UnifiedError) as error:
        pipeline._store_decomp(directory, {'older': {0x1000: rec('older', 0x1000)}}, DEFAULT_LIMITS)
    assert error.value.code == 'PT-UNIFIED-STORE' and error.value.reason == 'decompile-cleanup-failed'


def fake_request(tmp_path):
    plan = SimpleNamespace(run_id='r1', older_sha256='a' * 64, newer_sha256='b' * 64)
    return SimpleNamespace(root=tmp_path, plan=plan, backend=object(), gzf_recorded={}, total_ram_bytes=None,
                           artifacts={side: tmp_path / f'{side}.dll' for side in SIDES})


def test_decompile_returns_every_record_of_the_sides_that_ran(tmp_path, monkeypatch):
    pairs = ((0x1000, 0x2000), (0x1100, 0x2100))
    monkeypatch.setattr(pipeline, '_retained_gzf', lambda request, side: (tmp_path / f'{side}.gzf', 'c' * 64))

    def fake(job, budget, progress, runner=None):
        records = {rva: rec(job.side, rva, ('ok', 'timeout')[i]) for i, rva in enumerate(job.rvas)}
        return SimpleNamespace(records=records, cleanup=lambda: None)
    monkeypatch.setattr(pipeline, 'decompile_side', fake)
    texts, reason, records = pipeline._decompile(fake_request(tmp_path), pairs, threading.Event(), None, None,
                                                 DEFAULT_LIMITS)
    assert reason is None
    assert texts == {'older': {0x1000: rec('older', 0x1000).code}, 'newer': {0x2000: rec('newer', 0x2000).code}}
    assert {side: {rva: r.status for rva, r in found.items()} for side, found in records.items()} == {
        'older': {0x1000: 'ok', 0x1100: 'timeout'}, 'newer': {0x2000: 'ok', 0x2100: 'timeout'}}


def test_without_a_backend_nothing_is_decompiled_and_no_record_exists(tmp_path):
    request = fake_request(tmp_path)
    request.backend = None
    assert pipeline._decompile(request, ((1, 2),), threading.Event(), None, None, DEFAULT_LIMITS) == (
        {'older': {}, 'newer': {}}, 'no-backend', {})
