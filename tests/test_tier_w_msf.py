"""SPEC-33 s5.4: stdlib MSF/PDB reader. Real self-made PDBs (tests/fixtures/tier_w, clang+lld, MIT) plus
synthetic MSF containers for OMAP/stripped/thunk and hostile cases; fuzzing proves only MsfError escapes."""
from __future__ import annotations

import struct
import sys
import uuid

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from tier_w_builders import (
    ROOT,
    TIER_W_FIXTURES,
    build_msf,
    dbi_stream,
    gproc32,
    module_stream,
    pdb_info_stream,
    pub32,
    section_header,
    sym_record,
)

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview.inspect import inspect_pe

sys.path.insert(0, str(ROOT))
from tools.calibration.tier_w import msf  # noqa: E402

V1_PDB, V2_PDB = TIER_W_FIXTURES / 'tiny_v1.pdb', TIER_W_FIXTURES / 'tiny_v2.pdb'
GUID = uuid.UUID('00112233-4455-6677-8899-aabbccddeeff')


def codeview(pe_path):
    with VerifiedArtifactReader.open_path(pe_path) as reader:
        return inspect_pe(reader).codeview


def test_fixture_identity_matches_pe_codeview():
    for version in ('v1', 'v2'):
        cv = codeview(TIER_W_FIXTURES / f'tiny_{version}.pe')
        info = msf.read_identity(TIER_W_FIXTURES / f'tiny_{version}.pdb')
        assert (info.guid, info.age) == (cv.guid, cv.age) and cv.pdb_path == f'tiny_{version}.pdb'
        assert info.machine == 0x8664 and not info.stripped and not info.omap
        assert info.guid_age == uuid.UUID(cv.guid).hex.upper() + '1'


def test_fixture_functions_merge_rule():
    idx = msf.read_pdb(V1_PDB)
    assert len(idx.publics) == 21 and len(idx.procedures) == 21 and idx.warnings == ()
    funcs = {f.name: f for f in idx.functions()}
    assert funcs['same_a'].aliases == 1 and funcs['same_a'].public_names == ('same_a', 'same_b')
    assert funcs['worker.cold.1'].size == 12  # public (asm label) name wins over the proc name worker_cold
    assert funcs['?scale@@YAHH@Z'].rva != funcs['?scale@@YA_J_J@Z'].rva  # overloads stay distinct
    assert [f.size for f in idx.functions() if f.name == 'helper'] == [11, 4]  # static name collision
    assert all(f.kind == 'private' for f in funcs.values())
    data = {s.name: s for s in idx.publics if not s.is_function}
    assert set(data) == {'dispatch', '__security_cookie'} and data['dispatch'].segment == 2
    v2 = {f.name: f for f in msf.read_pdb(V2_PDB).functions()}
    assert v2['rewrite_me'].size == 268 and funcs['rewrite_me'].size == 140
    assert 'parse_header_ex' in v2 and 'parse_header' not in v2 and 'added_later' in v2


def synthetic(*, flags=0, omap=None, original=None, procs=b'', publics=None, thunk=False, sig=4):
    publics = publics if publics is not None else pub32('alpha', 0x10) + pub32('beta', 0x40) + pub32('gdata', 8, 2, 0)
    mod = module_stream(procs + (sym_record(0x1102, struct.pack('<IIIIHHB', 0, 0, 0, 0x60, 1, 7, 0) + b'thk\0')
                                 if thunk else b''))
    if sig != 4:
        mod = struct.pack('<I', sig) + mod[4:]
    streams = [b'', pdb_info_stream(GUID.bytes_le, 3), b'', None, publics,
               section_header(b'.text', 0x200, 0x1000) + section_header(b'.data', 0x100, 0x2000), mod]
    dbg = {5: 5}
    if omap is not None:
        streams.append(b''.join(struct.pack('<II', a, b) for a, b in omap))
        dbg[4] = len(streams) - 1
    if original is not None:
        streams.append(original)
        dbg[10] = len(streams) - 1
    streams[3] = dbi_stream(age=2, sym_stream=4, modules=[(6, len(mod), 'm.obj')], flags=flags, opt_dbg=dbg)
    return build_msf(streams)


def test_synthetic_publics_procs_thunks_and_flags(tmp_path):
    path = tmp_path / 'a.pdb'
    path.write_bytes(synthetic(flags=0x2, procs=gproc32('alpha_impl', 0x10, 0x30), thunk=True))
    idx = msf.read_pdb(path)
    assert idx.info.guid == str(GUID) and idx.info.age == 2 and idx.info.info_age == 3 and idx.info.stripped
    funcs = {f.name: f for f in idx.functions()}
    assert funcs['alpha'].rva == 0x1010 and funcs['alpha'].size == 0x30 and funcs['alpha'].kind == 'private'
    assert funcs['beta'].kind == 'public' and funcs['beta'].size is None
    assert funcs['thk'].thunk and funcs['thk'].size == 7 and funcs['thk'].rva == 0x1060
    assert 'gdata' not in funcs and idx.info.guid_age == GUID.hex.upper() + '2'


def test_omap_mapping(tmp_path):
    original = section_header(b'.text', 0x200, 0x5000) + section_header(b'.data', 0x100, 0x6000)
    path = tmp_path / 'o.pdb'
    path.write_bytes(synthetic(omap=[(0x5000, 0x1000), (0x5020, 0), (0x5030, 0x1200)], original=original))
    idx = msf.read_pdb(path)
    rvas = {s.name: s.rva for s in idx.publics}
    assert idx.info.omap and rvas['alpha'] == 0x1010 and rvas['beta'] == 0x1210
    path.write_bytes(synthetic(omap=[(0x1000, 0x1000), (0x1020, 0)]))
    idx = msf.read_pdb(path)
    assert {s.name: s.rva for s in idx.publics}['beta'] is None and any('OMAP' in w for w in idx.warnings)
    table = msf.Omap(struct.pack('<IIII', 0x100, 0x900, 0x200, 0))
    assert table.map(0x50) is None and table.map(0x150) == 0x950 and table.map(0x250) is None


def test_unknown_module_signature_warns(tmp_path):
    path = tmp_path / 's.pdb'
    path.write_bytes(synthetic(procs=gproc32('x', 0, 4), sig=9))
    idx = msf.read_pdb(path)
    assert idx.procedures == () and any('signature' in w for w in idx.warnings)


def corrupt(data: bytes, offset: int, value: bytes) -> bytes:
    return data[:offset] + value + data[offset + len(value):]


@pytest.mark.parametrize('case', ['magic', 'v2', 'bsize', 'nblocks', 'dirbytes', 'mapaddr', 'trunc', 'block',
                                  'record', 'name', 'dbisig', 'nodbi'])
def test_hostile_inputs_raise_msf_error(tmp_path, case):
    good = synthetic(procs=gproc32('p', 0, 4))
    bs = 512
    data = {
        'magic': corrupt(good, 0, b'Microsoft C/C++ MSF 6.00'),
        'v2': msf.MAGIC_V2 + good[len(msf.MAGIC_V2):],
        'bsize': corrupt(good, 32, struct.pack('<I', 1000)),
        'nblocks': corrupt(good, 40, struct.pack('<I', 10_000)),
        'dirbytes': corrupt(good, 44, struct.pack('<I', 0x7FFFFFFF)),
        'mapaddr': corrupt(good, 52, struct.pack('<I', 0)),
        'trunc': good[:len(good) - bs // 2],
        'block': None, 'record': None, 'name': None, 'dbisig': None, 'nodbi': None,
    }[case]
    if case == 'block':
        (map_addr,) = struct.unpack_from('<I', good, 52)
        data = corrupt(good, map_addr * bs, struct.pack('<I', 0xFFFF))
    elif case == 'record':
        data = synthetic(publics=struct.pack('<HH', 0x7000, 0x110E) + b'\0' * 12)
    elif case == 'name':
        data = synthetic(publics=sym_record(0x110E, struct.pack('<IIH', 2, 0, 1) + b'x' * 10))
    elif case == 'dbisig':
        data = synthetic()
        index = data.find(struct.pack('<iI', -1, 19990903))
        data = corrupt(data, index, struct.pack('<i', 7))
    elif case == 'nodbi':
        data = build_msf([b'', pdb_info_stream(GUID.bytes_le, 1)])
    path = tmp_path / 'h.pdb'
    path.write_bytes(data)
    with pytest.raises(msf.MsfError):
        msf.read_pdb(path)


def test_cancel_and_missing_file(tmp_path):
    with pytest.raises(msf.MsfError, match='cancelled'):
        msf.read_pdb(V1_PDB, cancel=lambda: True)
    with pytest.raises(msf.MsfError, match='unreadable'):
        msf.read_identity(tmp_path / 'missing.pdb')
    assert msf.is_pdb_magic(V1_PDB.read_bytes()[:64]) and not msf.is_pdb_magic(b'MZ' + b'\0' * 62)


FIXTURE_BYTES = V1_PDB.read_bytes()


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.lists(st.tuples(st.integers(0, len(FIXTURE_BYTES) - 1), st.integers(0, 255)), min_size=1, max_size=24),
       st.integers(1, len(FIXTURE_BYTES)))
def test_fuzz_mutated_fixture_only_msf_error(tmp_path, edits, keep):
    data = bytearray(FIXTURE_BYTES)
    for offset, value in edits:
        data[offset] = value
    path = tmp_path / 'f.pdb'
    path.write_bytes(bytes(data[:keep]))
    try:
        idx = msf.read_pdb(path)
    except msf.MsfError:
        return
    assert isinstance(idx.functions(), list)


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.binary(min_size=0, max_size=4096))
def test_fuzz_random_bytes_after_magic(tmp_path, tail):
    path = tmp_path / 'r.pdb'
    path.write_bytes(msf.MAGIC + tail)
    with pytest.raises(msf.MsfError):
        msf.read_pdb(path)
