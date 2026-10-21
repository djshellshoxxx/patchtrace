"""SPEC-53 GHR-1: mode resolution, PDB identity reader and identity-gated staging (hermetic, no network)."""
from __future__ import annotations

import os
import struct
import uuid

import pytest

from patchtrace.pe_overview.models import CodeViewInfo
from patchtrace.symbols import modes, pdbid, staging

G1 = '11111111-2222-3333-4444-555555555555'
G2 = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'


def make_pdb(guid: str, age: int, *, dbi_age: int | None = None, block: int = 512, pad: int = 0) -> bytes:
    info = struct.pack('<III', 20000404, 1, age) + uuid.UUID(guid).bytes_le
    dbi = struct.pack('<iII', -1, 19990903, age if dbi_age is None else dbi_age) + bytes(52)
    streams = [b'', info, b'', dbi]
    data_blocks: list[bytes] = []
    locs: list[list[int]] = []
    nxt = 3
    for s in streams:
        idx = []
        for i in range(0, len(s), block):
            idx.append(nxt + len(data_blocks))
            data_blocks.append(s[i:i + block].ljust(block, b'\0'))
        locs.append(idx)
    for _ in range(pad):
        data_blocks.append(bytes(block))
    directory = struct.pack('<I', len(streams)) + b''.join(struct.pack('<I', len(s)) for s in streams)
    directory += b''.join(struct.pack(f'<{len(i)}I', *i) for i in locs)
    dir_idx = nxt + len(data_blocks)
    n_dir = -(-len(directory) // block)
    dir_blocks = [directory[i:i + block].ljust(block, b'\0') for i in range(0, len(directory), block)]
    map_idx = dir_idx + n_dir
    table = struct.pack(f'<{n_dir}I', *range(dir_idx, dir_idx + n_dir)).ljust(block, b'\0')
    total = map_idx + 1
    head = pdbid.MAGIC + struct.pack('<6I', block, 1, total, len(directory), 0, map_idx)
    return head.ljust(block, b'\0') + bytes(2 * block) + b''.join(data_blocks + dir_blocks) + table


def cv(path: str, guid: str = G1, age: int = 3) -> CodeViewInfo:
    return CodeViewInfo(path, guid, age)


# ---- modes ----------------------------------------------------------------------------------

def test_resolve_mode_matrix():
    assert modes.resolve_mode('', False) == 'off' and modes.resolve_mode('', True) == 'online'
    assert modes.resolve_mode('local', False) == 'local' and modes.resolve_mode('off', False) == 'off'
    for bad in (('bogus', False), ('local', True), ('off', True)):
        with pytest.raises(modes.SymbolError) as exc:
            modes.resolve_mode(*bad)
        assert exc.value.code == 'PT-SYMBOL-MODE'
    assert [modes.cache_policy(m) for m in modes.SYMBOL_MODES] == ['disabled', 'local', 'online']


# ---- identity reader ------------------------------------------------------------------------

@pytest.mark.parametrize('block', [512, 4096])
def test_identity_roundtrip_uses_dbi_age(tmp_path, block):
    path = tmp_path / 'a.pdb'
    path.write_bytes(make_pdb(G1, 9, dbi_age=3, block=block, pad=2))
    assert pdbid.read_pdb_identity(path) == pdbid.PdbIdentity(G1, 3)


@pytest.mark.parametrize('mutate', [
    lambda b: b[:100], lambda b: b'X' + b[1:], lambda b: b + b'\0', lambda b: b[:44] + struct.pack('<I', 7) + b[48:],
    lambda b: b[:40] + struct.pack('<I', 0) + b[44:], lambda b: b'',
])
def test_identity_rejects_hostile_input(tmp_path, mutate):
    path = tmp_path / 'bad.pdb'
    path.write_bytes(mutate(make_pdb(G1, 3)))
    with pytest.raises(modes.SymbolError) as exc:
        pdbid.read_pdb_identity(path)
    assert exc.value.code == 'PT-SYMBOL-PDB-INVALID'


# ---- wants ----------------------------------------------------------------------------------

def test_want_from_codeview_takes_basename_only():
    w = staging.want_from_codeview('older', cv('C:\\build\\obj\\..\\x\\Foo.PDB'))
    assert w and w.pdb_name == 'Foo.PDB' and w.guid_age == '11111111222233334444555555555555' + '3'
    for bad in (cv(''), cv('x.dll'), cv('a/..'), cv('a/b.pdb', guid='nope'), cv('a/b.pdb', age=-1)):
        assert staging.want_from_codeview('older', bad) is None
    assert staging.want_from_codeview('older', None) is None and staging.want_from_codeview('x', cv('a.pdb')) is None


# ---- staging --------------------------------------------------------------------------------

def folder(tmp_path, name='pdbs'):
    d = tmp_path / name
    d.mkdir()
    return d


def test_stage_matching_pdb_and_digest_stable(tmp_path):
    d = folder(tmp_path)
    (d / 'FOO.pdb').write_bytes(make_pdb(G1, 3))
    wants = [staging.want_from_codeview('older', cv('c:/x/foo.pdb')), staging.want_from_codeview('newer', cv('foo.pdb'))]
    res = staging.stage_symbols(wants, [str(d)], tmp_path / 'store')
    assert len(res.staged) == 1 and res.skipped == () and res.staged[0].side == 'both'
    s = res.staged[0]
    out = tmp_path / 'store' / 'foo.pdb' / s.guid_age / 'foo.pdb'
    assert out.is_file() and out.stat().st_size == s.size and (d / 'FOO.pdb').is_file()  # copied, not moved
    again = staging.stage_symbols(wants, [str(d)], tmp_path / 'store2')
    assert again.digest == res.digest and len(res.digest) == 64
    assert staging.stage_symbols([], [], tmp_path / 's3').digest != res.digest


@pytest.mark.parametrize('pdb, reason', [
    (lambda: make_pdb(G2, 3), 'guid_mismatch'), (lambda: make_pdb(G1, 4), 'age_mismatch'),
    (lambda: b'not a pdb', 'unreadable'),
])
def test_decoy_pdb_is_not_staged(tmp_path, pdb, reason):
    d = folder(tmp_path)
    (d / 'foo.pdb').write_bytes(pdb())
    res = staging.stage_symbols([staging.want_from_codeview('older', cv('foo.pdb'))], [str(d)], tmp_path / 'store')
    assert res.staged == () and [(s.reason) for s in res.skipped] == [reason]
    assert not [p for p in (tmp_path / 'store').rglob('*') if p.is_file()]  # rejected copy removed


def test_not_found_and_second_folder_wins(tmp_path):
    a, b = folder(tmp_path, 'a'), folder(tmp_path, 'b')
    want = staging.want_from_codeview('older', cv('foo.pdb'))
    assert staging.stage_symbols([want], [a], tmp_path / 's1').skipped[0].reason == 'not_found'
    (a / 'foo.pdb').write_bytes(make_pdb(G2, 3))
    (b / 'foo.pdb').write_bytes(make_pdb(G1, 3))
    res = staging.stage_symbols([want], [a, b], tmp_path / 's2')
    assert len(res.staged) == 1 and res.skipped == ()


@pytest.mark.skipif(os.name == 'nt', reason='symlink creation needs privileges on Windows')
def test_symlink_candidate_refused(tmp_path):
    d, other = folder(tmp_path), folder(tmp_path, 'o')
    (other / 'real.pdb').write_bytes(make_pdb(G1, 3))
    (d / 'foo.pdb').symlink_to(other / 'real.pdb')
    res = staging.stage_symbols([staging.want_from_codeview('older', cv('foo.pdb'))], [d], tmp_path / 's')
    assert res.staged == () and res.skipped[0].reason == 'unreadable'


def test_oversize_pdb_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(staging, 'MAX_PDB_BYTES', 100)
    d = folder(tmp_path)
    (d / 'foo.pdb').write_bytes(make_pdb(G1, 3))
    res = staging.stage_symbols([staging.want_from_codeview('older', cv('foo.pdb'))], [d], tmp_path / 's')
    assert res.skipped[0].reason == 'too_large'


def test_dir_validation_and_cancel(tmp_path):
    with pytest.raises(modes.SymbolError):
        staging.validate_dirs(['relative'])
    with pytest.raises(modes.SymbolError):
        staging.validate_dirs([str(tmp_path / 'missing')])
    with pytest.raises(modes.SymbolError):
        staging.validate_dirs([str(tmp_path)] * (modes.MAX_PDB_DIRS + 1))
    d = folder(tmp_path)
    (d / 'foo.pdb').write_bytes(make_pdb(G1, 3))
    with pytest.raises(modes.SymbolError) as exc:
        staging.stage_symbols([staging.want_from_codeview('older', cv('foo.pdb'))], [d], tmp_path / 's',
                              cancel=lambda: True)
    assert exc.value.code == 'PT-CANCEL'


def test_staged_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(staging, 'MAX_STAGED', 1)
    d = folder(tmp_path)
    (d / 'a.pdb').write_bytes(make_pdb(G1, 3))
    (d / 'b.pdb').write_bytes(make_pdb(G1, 3))
    wants = [staging.want_from_codeview('older', cv('a.pdb')), staging.want_from_codeview('older', cv('b.pdb'))]
    res = staging.stage_symbols(wants, [d], tmp_path / 's')
    assert len(res.staged) == 1 and res.skipped[0].reason == 'limit'
