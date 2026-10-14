"""SPEC-10b §6.2-6.3, §6.6 (C3-3/C3-4): snapshot, in-process pipeline, identity, orientation, address basis."""
from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from binexport_builder import NEWER, SHA, raw, valid

from patchtrace.secondary import binexport_pipeline as pipeline
from patchtrace.secondary.binexport_identity import (
    PeLayout,
    accept_pair,
    architecture_warning,
    classify_identity,
    detect_address_basis,
)
from patchtrace.secondary.binexport_limits import BinExportLimits, Budget
from patchtrace.secondary.binexport_models import BinExportSummary
from patchtrace.secondary.binexport_snapshot import take_snapshot
from patchtrace.secondary.contracts import SecondaryError

LIMITS = BinExportLimits()


def write(tmp_path: Path, data: bytes, name='x.BinExport') -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def inspect(tmp_path, data, sha=SHA, role='older', **kw):
    src = write(tmp_path, data)
    snapshot = tmp_path / f'snap-{role}'
    snapshot.unlink(missing_ok=True)  # a rejected in-process snapshot stays for its caller; start clean
    return pipeline.inspect_binexport(src, snapshot, artifact_sha256=sha, role=role,
                                      limits=kw.pop('limits', LIMITS), budget=Budget(), **kw)


def reason_of(fn, *a, **kw) -> tuple[str, str]:
    with pytest.raises(SecondaryError) as info:
        fn(*a, **kw)
    return info.value.code, info.value.reason


# --- snapshot (T8/T9) ---

def test_snapshot_copies_and_hashes(tmp_path):
    data = raw(valid())
    snap = take_snapshot(write(tmp_path, data), tmp_path / 's', LIMITS)
    assert snap.path.read_bytes() == data and snap.sha256 == hashlib.sha256(data).hexdigest()
    assert snap.size == len(data)
    assert reason_of(take_snapshot, tmp_path / 'x.BinExport', tmp_path / 's', LIMITS)[1] == 'worker_crash'  # 'x'


@pytest.mark.parametrize('setup, expected', [
    (lambda t: t / 'missing', ('PT-SECONDARY-INPUT', 'unreadable')),
    (lambda t: t, ('PT-SECONDARY-INPUT', 'not_regular_file')),
    (lambda t: write(t, b''), ('PT-SECONDARY-INPUT', 'empty_file')),
    (lambda t: write(t, b'1234'), ('PT-SECONDARY-LIMIT', 'too_large')),
])
def test_snapshot_rejections(tmp_path, setup, expected):
    limits = BinExportLimits(max_file_bytes=3)
    assert reason_of(take_snapshot, setup(tmp_path), tmp_path / 'snap', limits) == expected
    assert not (tmp_path / 'snap').exists()


@pytest.mark.skipif(not hasattr(os, 'O_NOFOLLOW'), reason='O_NOFOLLOW is POSIX-only; Windows has no symlink race here')
def test_snapshot_refuses_symlink_and_fifo(tmp_path):
    target = write(tmp_path, raw(valid()))
    link = tmp_path / 'link.BinExport'
    link.symlink_to(target)
    assert reason_of(take_snapshot, link, tmp_path / 's1', LIMITS)[1] == 'unreadable'
    fifo = tmp_path / 'fifo'
    os.mkfifo(fifo)
    assert reason_of(take_snapshot, fifo, tmp_path / 's2', LIMITS)[1] == 'not_regular_file'


def test_snapshot_detects_growth_and_shrink(tmp_path, monkeypatch):
    src = write(tmp_path, b'abcdef')
    real_fstat = os.fstat

    def fake_stat(size):
        def fstat(fd):
            st = real_fstat(fd)
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid, st.st_gid, size,
                                   st.st_atime, st.st_mtime, st.st_ctime))
        return fstat
    monkeypatch.setattr(os, 'fstat', fake_stat(3))  # file "grew" after fstat
    assert reason_of(take_snapshot, src, tmp_path / 's1', LIMITS)[1] == 'file_changed_during_read'
    monkeypatch.setattr(os, 'fstat', fake_stat(3))
    assert reason_of(take_snapshot, src, tmp_path / 's2', BinExportLimits(max_file_bytes=4)) == \
        ('PT-SECONDARY-LIMIT', 'too_large')  # grew past the cap while being read
    assert not (tmp_path / 's1').exists() and not (tmp_path / 's2').exists()


# --- pipeline ---

def test_pipeline_summary(tmp_path):
    data = raw(valid(functions=3))
    s = inspect(tmp_path, data, pe_layout=PeLayout(0x140000000, 0x10000, 'IMAGE_FILE_MACHINE_AMD64'))
    assert isinstance(s, BinExportSummary) and s.contract == 'binexport-summary/1'
    assert s.file_sha256 == hashlib.sha256(data).hexdigest() and s.file_size == len(data)
    assert s.function_addresses == (0x140001000, 0x140001100, 0x140001200) and s.vertex_types == (0, 0, 0)
    assert (s.id_binding, s.address_basis, s.role, s.timestamp) == ('sha256', 'va', 'older', 1_760_000_000)
    assert s.protobuf_version == '7.36.2' and s.warnings == ()
    assert s.counts['vertex'] == 3 and s.counts['instruction'] == 6
    assert BinExportSummary.model_validate_json(s.model_dump_json()) == s
    assert (tmp_path / 'snap-older').read_bytes() == data


def test_summary_has_no_file_strings():
    fields = set(BinExportSummary.model_fields)
    assert not fields & {'mangled_name', 'demangled_name', 'string_table', 'names', 'comments'}


@pytest.mark.parametrize('data, kind', [
    (b'SQLite format 3\x00' + b'\x00' * 100, 'sqlite'), (b'PK\x03\x04' + b'\x00' * 30, 'zip'),
    (b'%PDF-1.7\n', 'pdf'), (b'\x7fELF\x02\x01\x01', 'elf'), (b'MZ\x90\x00\x03', 'pe'),
    (b'  {"a": 1}', 'json'), (b'\xef\xbb\xbf[1, 2]', 'json'),
])
def test_lookalikes_explained(tmp_path, data, kind):
    assert reason_of(inspect, tmp_path, data) == ('PT-SECONDARY-INPUT', f'lookalike_{kind}')


def test_trailing_garbage_and_parse_failure(tmp_path):
    # A truncated nested message passes the top-level scan but fails the real parse.
    bad_nested = b'\x0a\x03\x12\x01x' + b'\x42\x03\x0a\x05\x08'
    assert reason_of(inspect, tmp_path, bad_nested) == ('PT-SECONDARY-INPUT', 'parse_failed')
    nested_group = b'\x0a\x03\x12\x01x' + b'\x42\x02\x0a\x00' + b'\x2a\x02\x0b\x0c'  # instruction w/ group
    with pytest.raises(SecondaryError) as info:
        inspect(tmp_path, nested_group)
    assert info.value.code == 'PT-SECONDARY-INPUT'


def test_deep_nested_groups_rejected_by_upb(tmp_path):
    payload = b'\x0b' * 150 + b'\x0c' * 150  # unknown group nesting inside an instruction record
    data = b'\x0a\x03\x12\x01x' + b'\x42\x02\x0a\x00' + b'\x2a' + bytes([len(payload) & 0x7F | 0x80, len(payload) >> 7]) \
        + payload
    assert reason_of(inspect, tmp_path, data)[0] == 'PT-SECONDARY-INPUT'


def test_unsupported_runtime_reported(tmp_path, monkeypatch):
    from patchtrace.secondary.binexport_proto import ProtoUnavailable

    def unavailable():
        raise ProtoUnavailable('protobuf_not_upb')
    monkeypatch.setattr(pipeline, 'load_binexport2_class', unavailable)
    assert reason_of(inspect, tmp_path, raw(valid())) == ('PT-SECONDARY-UNSUPPORTED', 'protobuf_not_upb')


def test_alloc_failure_is_oom_not_input(monkeypatch):
    assert pipeline.alloc_failure(ValueError("Error parsing message with type 'BinExport2': Arena alloc failed"),
                                  LIMITS)
    assert not pipeline.alloc_failure(ValueError('Error parsing message'), LIMITS)
    monkeypatch.setattr('patchtrace.secondary.binexport_limits.peak_memory_bytes', lambda: 95)
    assert pipeline.alloc_failure(ValueError('x'), BinExportLimits(memory_bytes=100))
    assert not pipeline.alloc_failure(ValueError('x'), BinExportLimits(memory_bytes=200))


def test_peak_memory_measurement_available():
    from patchtrace.secondary.binexport_limits import peak_memory_bytes
    peak = peak_memory_bytes()
    assert peak is not None and peak > 1024 * 1024, (sys.platform, peak)


# --- identity / orientation / basis ---

def test_identity_classes(tmp_path):
    assert classify_identity(SHA.upper(), SHA, False) == 'sha256'
    assert reason_of(classify_identity, NEWER, SHA, True) == ('PT-SECONDARY-PAIR', 'executable_id_mismatch')
    for value, kind in (('d' * 32, 'md5'), ('', 'empty'), ('  ', 'empty'), ('not-a-hash', 'other')):
        assert reason_of(classify_identity, value, SHA, False) == ('PT-SECONDARY-INPUT', f'executable_id_{kind}')
        assert classify_identity(value, SHA, True) == kind
    with pytest.raises(ValueError):
        classify_identity(SHA, SHA.upper(), False)


def test_unbound_id_needs_explicit_override(tmp_path):
    m = valid()
    m.meta_information.executable_id = 'e' * 32
    assert reason_of(inspect, tmp_path, raw(m)) == ('PT-SECONDARY-INPUT', 'executable_id_md5')
    s = inspect(tmp_path, raw(m), role='newer', accept_unbound=True)
    assert s.id_binding == 'md5' and s.executable_id == 'e' * 32


def test_address_basis_and_architecture():
    layout = PeLayout(0x140000000, 0x10000, 'IMAGE_FILE_MACHINE_AMD64')
    assert detect_address_basis((0x140001000, 0x14000F000), layout) == 'va'
    assert detect_address_basis((0x1000, 0xF000), layout) == 'rva'
    assert detect_address_basis((0x1000, 0x140001000), layout) == 'unknown'
    assert detect_address_basis((0x1000,), None) == 'unknown'
    assert architecture_warning('x86-64', layout) is None
    assert architecture_warning('AARCH64-64', layout) == 'architecture_mismatch'
    assert architecture_warning('ARM-32', PeLayout(0, 1, None)) is None


def _accepted(sha, role, file_sha, basis='va', binding='sha256'):
    s = BinExportSummary(file_sha256=file_sha, file_size=10, executable_id=sha, executable_name='n',
                         architecture_name='x86-64', timestamp=None, id_binding=binding, role=role,
                         address_basis=basis, counts={}, function_addresses=(1,), vertex_types=(0,), warnings=(),
                         protobuf_version='7.36.2', descriptor_proto_sha256='e' * 64)
    return SimpleNamespace(snapshot_path=Path('/snap'), summary=s)  # AcceptedBinExport shape


def test_accept_pair_guards():
    older, newer = _accepted(SHA, 'older', '1' * 64), _accepted(NEWER, 'newer', '2' * 64)
    accept_pair(older, newer, SHA, NEWER)
    assert reason_of(accept_pair, older, newer, SHA, SHA) == ('PT-SECONDARY-PAIR', 'identical_pair')
    assert reason_of(accept_pair, older, _accepted(NEWER, 'newer', '1' * 64), SHA, NEWER) == \
        ('PT-SECONDARY-PAIR', 'same_file_twice')
    assert reason_of(accept_pair, newer, older, SHA, NEWER) == ('PT-SECONDARY-ORIENTATION', 'orientation_swapped')
    swapped_ids = (_accepted(NEWER, 'older', '1' * 64), _accepted(SHA, 'newer', '2' * 64))
    assert reason_of(accept_pair, *swapped_ids, SHA, NEWER) == ('PT-SECONDARY-ORIENTATION', 'orientation_swapped')
    wrong = _accepted('f' * 64, 'newer', '2' * 64)
    assert reason_of(accept_pair, older, wrong, SHA, NEWER) == ('PT-SECONDARY-PAIR', 'executable_id_mismatch')
    rva = _accepted(NEWER, 'newer', '2' * 64, basis='rva')
    assert reason_of(accept_pair, older, rva, SHA, NEWER) == ('PT-SECONDARY-PAIR', 'address_basis_mixed')
    accept_pair(older, _accepted('', 'newer', '2' * 64, basis='unknown', binding='empty'), SHA, NEWER)
