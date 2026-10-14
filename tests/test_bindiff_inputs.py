"""SPEC-29 §3: pairing/orientation of accepted `.BinExport` inputs and TOCTOU-safe working copies.

Inputs are plain stand-ins satisfying the local `AcceptedBinExportLike` Protocol (the frozen C3 -> C4 seam),
so these tests never import the C3 BinExport2 modules.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import pytest

from patchtrace.secondary.bindiff_inputs import (
    AcceptedBinExportLike,
    BoundPair,
    bind_pair,
    copy_and_hash,
)
from patchtrace.secondary.contracts import SecondaryError

OLD, NEW, THIRD = 'a' * 64, 'b' * 64, 'c' * 64


@dataclass(frozen=True)
class Summary:
    file_sha256: str
    executable_id: str
    id_binding: str
    architecture_name: str = 'x86-64'


@dataclass(frozen=True)
class Accepted:
    snapshot_path: Path
    summary: Summary


def accepted(tmp_path: Path, name: str, executable_id: str, binding: str | None = None,
             arch: str = 'x86-64') -> Accepted:
    path = tmp_path / f'{name}.BinExport'
    data = f'FAKE-BINEXPORT {executable_id}\n{name}\n'.encode()
    path.write_bytes(data)
    if binding is None:
        binding = 'sha256' if len(executable_id) == 64 else ('md5' if len(executable_id) == 32 else
                                                            'empty' if not executable_id else 'other')
    return Accepted(path, Summary(hashlib.sha256(data).hexdigest(), executable_id, binding, arch))


def kinds(exc: pytest.ExceptionInfo) -> tuple[str, str | None]:
    return exc.value.code, exc.value.kind


def test_protocol_is_structural(tmp_path):
    assert isinstance(accepted(tmp_path, 'o', OLD), AcceptedBinExportLike)


def test_matching_sha256_ids_bind(tmp_path):
    pair = bind_pair(accepted(tmp_path, 'o', OLD), accepted(tmp_path, 'n', NEW), OLD, NEW)
    assert isinstance(pair, BoundPair) and not pair.asserted
    assert pair.older.executable_id == OLD and pair.newer.executable_id == NEW
    prov = pair.provenance()
    assert prov['binexport_binding'] == 'sha256'
    assert prov['older_binexport_sha256'] == pair.older.file_sha256


def test_uppercase_and_padded_ids_normalise(tmp_path):
    pair = bind_pair(accepted(tmp_path, 'o', f' {OLD.upper()} ', 'sha256'), accepted(tmp_path, 'n', NEW), OLD, NEW)
    assert pair.older.executable_id == OLD


def test_swapped_ids_are_orientation(tmp_path):
    with pytest.raises(SecondaryError) as info:
        bind_pair(accepted(tmp_path, 'o', NEW), accepted(tmp_path, 'n', OLD), OLD, NEW)
    assert kinds(info) == ('PT-SECONDARY-ORIENTATION', 'binexport-orientation')
    assert 'swapped' in info.value.message


def test_one_side_carrying_the_other_artifact_is_orientation(tmp_path):
    with pytest.raises(SecondaryError) as info:
        bind_pair(accepted(tmp_path, 'o', OLD), accepted(tmp_path, 'n', OLD), OLD, NEW)
    assert kinds(info) == ('PT-SECONDARY-ORIENTATION', 'binexport-orientation')


def test_third_file_is_wrong_artifact(tmp_path):
    with pytest.raises(SecondaryError) as info:
        bind_pair(accepted(tmp_path, 'o', OLD), accepted(tmp_path, 'n', THIRD), OLD, NEW)
    assert kinds(info) == ('PT-SECONDARY-PAIR', 'binexport-wrong-artifact')
    assert 'newer' in info.value.message and str(tmp_path) not in info.value.message


@pytest.mark.parametrize('ident', ['', '1' * 32, '1' * 40, 'not-a-hash'])
def test_unbound_ids_refused_by_default(tmp_path, ident):
    with pytest.raises(SecondaryError) as info:
        bind_pair(accepted(tmp_path, 'o', ident), accepted(tmp_path, 'n', NEW), OLD, NEW)
    assert kinds(info) == ('PT-SECONDARY-INPUT', 'binexport-unbound')
    assert 'older' in info.value.message


def test_explicit_override_binds_and_is_recorded(tmp_path):
    pair = bind_pair(accepted(tmp_path, 'o', '1' * 32), accepted(tmp_path, 'n', NEW), OLD, NEW,
                     accept_unbound=True)
    assert pair.asserted and pair.older.asserted and not pair.newer.asserted
    assert pair.provenance()['binexport_binding'] == 'asserted:older=md5,newer=sha256'
    assert pair.expected_file_hashes() == ('1' * 32, NEW)


def test_override_never_hides_a_sha256_mismatch(tmp_path):
    with pytest.raises(SecondaryError) as info:
        bind_pair(accepted(tmp_path, 'o', '1' * 32), accepted(tmp_path, 'n', THIRD), OLD, NEW,
                  accept_unbound=True)
    assert info.value.code == 'PT-SECONDARY-PAIR'


def test_identical_asserted_ids_refused(tmp_path):
    with pytest.raises(SecondaryError) as info:
        bind_pair(accepted(tmp_path, 'o', '1' * 32), accepted(tmp_path, 'n', '1' * 32), OLD, NEW,
                  accept_unbound=True)
    assert info.value.code == 'PT-SECONDARY-PAIR'


def test_same_snapshot_twice_refused(tmp_path):
    one = accepted(tmp_path, 'o', OLD)
    other = Accepted(one.snapshot_path, Summary(one.summary.file_sha256, NEW, 'sha256'))
    with pytest.raises(SecondaryError) as info:
        bind_pair(one, other, OLD, NEW)
    assert kinds(info) == ('PT-SECONDARY-PAIR', 'binexport-same-file')


def test_identical_artifacts_refused(tmp_path):
    with pytest.raises(SecondaryError) as info:
        bind_pair(accepted(tmp_path, 'o', OLD), accepted(tmp_path, 'n', OLD), OLD, OLD)
    assert info.value.code == 'PT-SECONDARY-PAIR'


def test_architecture_mismatch_refused(tmp_path):
    with pytest.raises(SecondaryError) as info:
        bind_pair(accepted(tmp_path, 'o', OLD), accepted(tmp_path, 'n', NEW, arch='arm64'), OLD, NEW)
    assert kinds(info) == ('PT-SECONDARY-PAIR', 'binexport-arch-mismatch')


def test_copy_and_hash_copies_and_refuses_existing_destination(tmp_path):
    src = tmp_path / 'src.BinExport'
    src.write_bytes(b'x' * 3000)
    dst = tmp_path / 'in' / 'older.BinExport'
    dst.parent.mkdir()
    assert copy_and_hash(src, dst) == hashlib.sha256(b'x' * 3000).hexdigest()
    assert dst.read_bytes() == src.read_bytes() and not dst.is_symlink()
    with pytest.raises(SecondaryError) as info:
        copy_and_hash(src, dst)
    assert kinds(info) == ('PT-SECONDARY-RUN', 'workdir-error')


def test_copy_and_hash_enforces_size_cap(tmp_path):
    src = tmp_path / 'big.BinExport'
    src.write_bytes(b'x' * 2048)
    with pytest.raises(SecondaryError) as info:
        copy_and_hash(src, tmp_path / 'out.BinExport', max_bytes=1024)
    assert info.value.code == 'PT-SECONDARY-LIMIT'


def test_copy_and_hash_rejects_non_regular_sources(tmp_path):
    real = tmp_path / 'real.BinExport'
    real.write_bytes(b'x')
    sources = [tmp_path]  # a directory is never a valid snapshot
    link = tmp_path / 'link.BinExport'
    try:
        link.symlink_to(real)
        sources.append(link)
    except (OSError, NotImplementedError):
        pass  # Windows without symlink privilege: the directory case still runs
    for index, source in enumerate(sources):
        with pytest.raises(SecondaryError) as info:
            copy_and_hash(source, tmp_path / f'out{index}.BinExport')
        assert kinds(info) == ('PT-SECONDARY-RUN', 'workdir-error')
