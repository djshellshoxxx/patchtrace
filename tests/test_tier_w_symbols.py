"""SPEC-33 s5 (LBL-21): symbol-map/1 builder, llvm-pdbutil adapter, Ghidra exporter script and headless driver.
Self-made fixtures only. Live llvm-pdbutil / Ghidra checks record BLOCKED (xfail with the reason) when the tool is
absent; they are never silently skipped."""
from __future__ import annotations

import ast
import json
import os
import shutil
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from tier_w_builders import ROOT, TIER_W_FIXTURES

from patchtrace.jobs import ProcessResult

sys.path.insert(0, str(ROOT))
from tools.calibration.tier_w import msf  # noqa: E402
from tools.calibration.tier_w import symbols as S  # noqa: E402
from tools.calibration.tier_w import symbols_ghidra as G  # noqa: E402
from tools.calibration.tier_w import symbols_llvm as L  # noqa: E402
from tools.calibration.tier_w.contracts import (  # noqa: E402
    Image,
    PdbRef,
    Producer,
    load_ghidra_raw,
    load_symbol_map,
)
from tools.calibration.tier_w.paths import Layout, TierWError  # noqa: E402
from tools.calibration.tier_w.pe_tables import PeView  # noqa: E402

PE1, PDB1 = TIER_W_FIXTURES / 'tiny_v1.pe', TIER_W_FIXTURES / 'tiny_v1.pdb'
IMAGE = Image(file_name='x.sys', sha256='ab' * 32, image_base=0x1000, size_of_image=0x4000, machine='x64')
SECTIONS = (msf.Section('.text', 0x1000, 0x800), msf.Section('.data', 0x2000, 0x100))


def raw(*functions, unnamed=0, truncated=0):
    return load_ghidra_raw(json.dumps({
        'contract': 'ghidra-symbols/1', 'ghidra_version': '12.0.4', 'python': 'x', 'file_name': 'x.sys',
        'image_base': 0x1000, 'executable_sha256': None, 'pdb': {'loaded': False, 'file': None, 'guid': None,
                                                                  'age': None},
        'functions': list(functions), 'unnamed': unnamed, 'truncated': truncated}).encode())


def gfn(rva, names, ranges=None, thunk=False):
    return {'rva': rva, 'ranges': ranges if ranges is not None else [[rva, rva + 16]], 'thunk': thunk,
            'names': [{'name': n, 'source': s, 'primary': p} for n, s, p in names]}


def build(**kw):
    kw.setdefault('pdata', {})
    kw.setdefault('index', None)
    kw.setdefault('ghidra', None)
    kw.setdefault('pdb', PdbRef())
    return S.build_symbol_map(image=IMAGE, producer=Producer(tool='ghidra', version='t'), tier='test', **kw)


# ---- builder ----------------------------------------------------------------------------------------------------

def test_msf_export_roundtrips_with_pdb_proc_sizes(tmp_path):
    layout = Layout(tmp_path / 'root')
    path = S.export_msf(PE1, PDB1, layout)
    doc = load_symbol_map(path.read_bytes())
    assert path == layout.symbols(doc.image.sha256, 'msf') and doc.tier == 'W' and doc.producer.tool == 'msf'
    by = {s.name: s for s in doc.symbols}
    assert by['memcpy'].size == 358 and by['memcpy'].size_source == 'pdb-proc' and by['memcpy'].kind == 'private'
    assert by['memcpy'].ranges == ((by['memcpy'].rva, by['memcpy'].rva + 358),)
    assert by['same_a'].aliases == 1  # ICF: another public name shares the address
    assert [s.rva for s in doc.symbols] == sorted({s.rva for s in doc.symbols})
    assert doc.pdb.guid == 'e71e07e3-99bc-13c3-4c4c-44205044422e' and doc.pdb.stripped is False
    assert doc.stats.functions == len(doc.symbols) == 20


def test_pdata_fills_sizes_when_a_public_has_no_procedure():
    publics = (msf.PdbSymbol('pub_only', 1, 0, 0x1000, 'public', True, None),)
    info = msf.read_identity(PDB1)
    doc = build(index=msf.PdbIndex(info, publics, (), SECTIONS, ()), pdata={0x1000: 40, 0x1100: 8})
    (sym,) = doc.symbols
    assert (sym.size, sym.size_source, sym.kind) == (40, 'pdata', 'public')


def test_pdata_skips_chained_and_empty_entries():
    entries = [SimpleNamespace(begin=1, end=5, chained=False), SimpleNamespace(begin=9, end=20, chained=True),
               SimpleNamespace(begin=7, end=7, chained=False)]
    assert S.pdata_sizes(entries) == {1: 4}


def test_ghidra_names_follow_the_selection_order():
    doc = build(ghidra=raw(
        gfn(0x1000, [('plain', 'IMPORTED', True), ('?mangled@@YAXXZ', 'IMPORTED', False)]),
        gfn(0x1100, [('zeta', 'IMPORTED', False), ('alpha', 'IMPORTED', False), ('prim', 'IMPORTED', True)]),
        gfn(0x1200, [('Ordinal_7', 'IMPORTED', True), ('entry', 'IMPORTED', False), ('.hidden', 'IMPORTED', False)]),
        gfn(0x1300, [('user_label', 'USER_DEFINED', True)]),
        unnamed=2))
    by = {s.rva: s for s in doc.symbols}
    assert [by[r].name for r in sorted(by)] == ['?mangled@@YAXXZ', 'prim']
    assert by[0x1000].aliases == 1 and by[0x1100].aliases == 2
    assert (by[0x1000].size, by[0x1000].size_source, by[0x1000].kind) == (16, 'ghidra-body', 'unknown')
    assert doc.stats.unnamed == 2 + 2 and doc.stats.dropped == 0


def test_ghidra_body_wins_and_ghidra_only_functions_are_dropped_with_a_pdb_index():
    info = msf.read_identity(PDB1)
    procs = (msf.PdbSymbol('f', 1, 0, 0x1000, 'private', True, 10),)
    index = msf.PdbIndex(info, (), procs, SECTIONS, ('w1',))
    ghidra = raw(gfn(0x1000, [('f', 'IMPORTED', True)], ranges=[[0x1000, 0x1010], [0x1100, 0x1108]], thunk=True),
                 gfn(0x1200, [('g', 'IMPORTED', True)]), unnamed=3, truncated=1)
    doc = build(index=index, ghidra=ghidra)
    (sym,) = doc.symbols
    assert (sym.size, sym.size_source, sym.thunk, len(sym.ranges)) == (24, 'ghidra-body', True, 2)
    assert (doc.stats.dropped, doc.stats.unnamed) == (1, 3)
    assert 'w1' in doc.warnings and any('truncated' in w for w in doc.warnings)


def test_a_map_needs_some_input():
    with pytest.raises(TierWError) as err:
        build()
    assert err.value.code == 'PT-TIERW-INPUT'


def test_symbols_are_sorted_by_rva():
    doc = build(ghidra=raw(gfn(0x1200, [('b', 'IMPORTED', True)]), gfn(0x1000, [('a', 'IMPORTED', True)])))
    assert [s.name for s in doc.symbols] == ['a', 'b']


# ---- llvm-pdbutil adapter ---------------------------------------------------------------------------------------

PUBLICS = """\
                       Public Symbols
============================================================
  Records
     196 | S_PUB32 [size = 28] `clamp_index`
           flags = function, addr = 0001:0928
     248 | S_PUB32 [size = 24] `dispatch`
           flags = none, addr = 0002:0016
"""
SYMBOLS = """\
  Mod 0000 | `C:\\src\\core_c.obj`:
       4 | S_OBJNAME [size = 20] sig=0, `core_c.obj`
     100 | S_GPROC32 [size = 48] `memcpy`
           parent = 0, end = 364, addr = 0001:0000, code size = 358
           type = `0x1003 (void*)`, debug start = 0, debug end = 0, flags = opt debuginfo
     148 | S_FRAMEPROC [size = 32]
     500 | S_THUNK32 [size = 30] `j_f`
           parent = 0, end = 0, next = 0, addr = 0001:0960, code size = 5, thunk = standard
"""


def parse(text, warnings=None):
    return L.parse_dump(text.splitlines(), SECTIONS, [] if warnings is None else warnings)


def test_parse_publics_maps_segment_offset_through_the_section_table():
    a, b = parse(PUBLICS)
    assert (a.name, a.rva, a.is_function, a.kind) == ('clamp_index', 0x1000 + 928, True, 'public')
    assert (b.name, b.rva, b.is_function) == ('dispatch', 0x2000 + 16, False)


def test_parse_symbols_reads_procedures_and_thunks_only():
    mem, thunk = parse(SYMBOLS)
    assert (mem.name, mem.rva, mem.size, mem.thunk, mem.kind) == ('memcpy', 0x1000, 358, False, 'private')
    assert (thunk.name, thunk.rva, thunk.size, thunk.thunk) == ('j_f', 0x1000 + 960, 5, True)


@pytest.mark.parametrize('text', ['`x`\n flags = function, addr = 0009:0001\n', '`x`\n flags = function, addr = 0003:0001\n'],
                         ids=['segment-9', 'segment-3'])
def test_a_segment_outside_the_table_fails_the_export(text):
    head = '   1 | S_PUB32 [size = 24] '
    with pytest.raises(TierWError) as err:
        parse(head + text)
    assert err.value.code == 'PT-TIERW-VERIFY'


def test_unknown_detail_shape_is_a_warning_and_five_in_a_row_fail():
    one = '   1 | S_PUB32 [size = 24] `a`\n   something else\n' + PUBLICS
    warnings = []
    assert [s.name for s in parse(one, warnings)] == ['clamp_index', 'dispatch'] and len(warnings) == 1
    bad = '   1 | S_PUB32 [size = 24] `a`\n   odd\n' * 5
    with pytest.raises(TierWError) as err:
        parse(bad)
    assert err.value.code == 'PT-TIERW-VERIFY'


def test_a_good_record_resets_the_malformed_streak():
    bad = '   1 | S_PUB32 [size = 24] `a`\n   odd\n'
    assert len(parse(bad * 4 + PUBLICS + bad * 4)) == 2


def _fake_tool(tmp_path, outputs):
    tool = tmp_path / 'llvm-pdbutil'
    tool.write_text('')

    def run(argv, timeout):
        out = tmp_path / f'out{len(list(tmp_path.glob("out*")))}.txt'
        out.write_text(outputs[argv[1] if argv[1] == '--version' else argv[2]], encoding='utf-8')
        return out
    return tool, run


def test_llvm_index_assembles_publics_and_procedures(tmp_path):
    tool, run = _fake_tool(tmp_path, {'--version': 'LLVM (http://llvm.org/):\n  LLVM version 18.1.3\n',
                                      '--publics': PUBLICS, '--symbols': SYMBOLS})
    index, version = L.llvm_index(tool, PDB1, SECTIONS, run)
    assert version.endswith('18.1.3') and len(index.publics) == 2 and len(index.procedures) == 2
    assert index.info.age == 1


def test_llvm_index_refuses_omap_and_a_missing_tool(tmp_path, monkeypatch):
    tool, run = _fake_tool(tmp_path, {'--version': 'LLVM version 18\n'})
    with pytest.raises(TierWError) as err:
        L.llvm_index(tmp_path / 'absent', PDB1, SECTIONS, run)
    assert err.value.code == 'PT-TIERW-BLOCKED'
    real = msf.read_identity(PDB1)
    monkeypatch.setattr(msf, 'read_identity', lambda p: type(real)(**{**real.__dict__, 'omap': True}))
    with pytest.raises(TierWError, match='OMAP'):
        L.llvm_index(tool, PDB1, SECTIONS, run)


def test_oversized_output_is_an_error_not_a_truncated_parse(tmp_path, monkeypatch):
    tool, run = _fake_tool(tmp_path, {'--version': 'LLVM version 18\n', '--publics': PUBLICS, '--symbols': SYMBOLS})
    monkeypatch.setattr(L, 'OUTPUT_CAP', 10)
    with pytest.raises(TierWError) as err:
        L.llvm_index(tool, PDB1, SECTIONS, run)
    assert err.value.code == 'PT-TIERW-LIMIT'
    assert not list(tmp_path.glob('out*'))


def test_unrecognised_version_output_fails(tmp_path):
    tool, run = _fake_tool(tmp_path, {'--version': 'hello\n'})
    with pytest.raises(TierWError, match='not recognised'):
        L.tool_version(tool, run)


def test_live_llvm_pdbutil_agrees_with_the_stdlib_reader():
    exe = shutil.which('llvm-pdbutil') or shutil.which('llvm-pdbutil-18')
    if exe is None:
        pytest.xfail('BLOCKED: llvm-pdbutil is not installed on this runner')
    with PeView(PE1) as view:
        sections = view.sections()
    index, version = L.llvm_index(Path(exe), PDB1, sections)
    ours = msf.read_pdb(PDB1, fallback_sections=sections)
    key = lambda idx: {(f.name, f.rva, f.size) for f in idx.functions()}  # noqa: E731
    assert 'LLVM version' in version and key(index) == key(ours)


# ---- Ghidra exporter script and headless driver -----------------------------------------------------------------

def test_exporter_script_is_jython_compatible_python():
    tree = ast.parse(G.SCRIPT.read_text(encoding='utf-8'))
    forbidden = (ast.JoinedStr, ast.AnnAssign, ast.NamedExpr, ast.AsyncFunctionDef, ast.Match, ast.Nonlocal)
    assert not [n for n in ast.walk(tree) if isinstance(n, forbidden)]
    funcs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    assert not [f for f in funcs if f.returns or f.args.kwonlyargs or any(a.annotation for a in f.args.args)]
    assert G.SCRIPT.read_text(encoding='utf-8').startswith('#@runtime Jython')


class Program:
    """Just enough of Ghidra's Program API for the exporter (no Ghidra needed)."""

    def __init__(self):
        offset = lambda v: SimpleNamespace(getOffset=lambda: v)  # noqa: E731
        entry = offset(0x140001000)
        rng = SimpleNamespace(getMinAddress=lambda: offset(0x140001000), getMaxAddress=lambda: offset(0x14000100F))
        fn = SimpleNamespace(isExternal=lambda: False, getEntryPoint=lambda: entry, isThunk=lambda: False,
                             getBody=lambda: SimpleNamespace(getAddressRanges=lambda: [rng]))
        ext = SimpleNamespace(isExternal=lambda: True)
        bare = SimpleNamespace(isExternal=lambda: False, getEntryPoint=lambda: offset(0x140002000),
                               isThunk=lambda: False,
                               getBody=lambda: SimpleNamespace(getAddressRanges=lambda: [rng]))
        self.fns = [fn, ext, bare]
        self.entry = entry
        self.base = offset(0x140000000)

    def getImageBase(self):
        return self.base

    def getFunctionManager(self):
        return SimpleNamespace(getFunctions=lambda forward: self.fns)

    def getSymbolTable(self):
        def symbols(addr):
            if addr is not self.entry:
                return [SimpleNamespace(getSource=lambda: SimpleNamespace(toString=lambda: 'DEFAULT'),
                                        getName=lambda: 'FUN_x', isPrimary=lambda: True)]
            return [SimpleNamespace(getSource=lambda: SimpleNamespace(toString=lambda: 'IMPORTED'),
                                    getName=lambda: 'DriverEntry', isPrimary=lambda: True)]
        return SimpleNamespace(getSymbols=symbols)

    def getOptions(self, name):
        return SimpleNamespace(getBoolean=lambda k, d: True, getString=lambda k, d: 'a.pdb' if k == 'PDB File' else 'g',
                               getInt=lambda k, d: 1)

    def getName(self):
        return 'x.sys'

    def getExecutableSHA256(self):
        return 'ab' * 32


def test_exporter_emits_a_valid_ghidra_symbols_document(tmp_path):
    namespace = {'__name__': 'ghidra_script'}
    exec(compile(G.SCRIPT.read_text(encoding='utf-8'), str(G.SCRIPT), 'exec'), namespace)  # noqa: S102 (our own script)
    out = tmp_path / 'raw.json'
    namespace['export'](Program(), str(out))
    doc = load_ghidra_raw(out.read_bytes())
    assert [(f.rva, f.ranges, f.names[0].name) for f in doc.functions] == [(0x1000, ((0x1000, 0x1010),), 'DriverEntry')]
    assert (doc.unnamed, doc.truncated, doc.pdb.loaded, doc.pdb.age) == (1, 0, True, 1)


def _ghidra_tree(tmp_path):
    support = tmp_path / 'ghidra' / 'support'
    support.mkdir(parents=True)
    (support / ('analyzeHeadless.bat' if sys.platform == 'win32' else 'analyzeHeadless')).write_text('')
    return tmp_path / 'ghidra'


def test_headless_argv_runs_the_post_script_in_a_throwaway_project(tmp_path):
    exe = G.launcher(_ghidra_tree(tmp_path))
    argv = G.headless_argv(exe, tmp_path / 'p', 'tw', tmp_path / 'img.sys', tmp_path / 'out.json')
    assert argv[0] == str(exe) and '-deleteProject' in argv
    assert argv[argv.index('-postScript') + 1] == 'ghidra_export_symbols.py'
    assert argv[argv.index('-import') + 1] == str(tmp_path / 'img.sys')


def test_bat_launcher_refuses_shell_metacharacters(tmp_path):
    with pytest.raises(TierWError) as err:
        G.headless_argv(Path('C:/g/support/analyzeHeadless.bat'), Path('C:/p&q'), 'tw', Path('C:/i.sys'), Path('C:/o.json'))
    assert err.value.code == 'PT-TIERW-CONFIG'


def test_private_env_points_config_and_cache_at_the_workdir(tmp_path):
    env = G.private_env(tmp_path, {'PATH': '/bin', 'HOME': '/home/x', 'XDG_CONFIG_HOME': '/home/x/.config'})
    assert env['XDG_CONFIG_HOME'] == str(tmp_path / 'xdg-config') and 'HOME' not in env


def test_export_headless_returns_the_validated_document(tmp_path):
    ghidra = _ghidra_tree(tmp_path)
    seen = {}

    def run(argv, **kw):
        seen.update(kw)
        Path(argv[argv.index('-postScript') + 2]).write_text(json.dumps(json.loads(
            json.dumps({'contract': 'ghidra-symbols/1', 'ghidra_version': '12', 'python': 'x', 'file_name': 'x',
                        'image_base': 0, 'executable_sha256': None, 'pdb': {'loaded': False},
                        'functions': [], 'unnamed': 0, 'truncated': 0}))), encoding='utf-8')
        return ProcessResult(0, '')
    work = tmp_path / 'w'
    doc = G.export_headless(ghidra, tmp_path / 'img.sys', work, environ={'PATH': '/bin'}, run=run)
    assert doc.contract == 'ghidra-symbols/1' and seen['env']['XDG_CACHE_HOME'] == str(work / 'xdg-cache')
    assert isinstance(seen['cancel'], threading.Event) and seen['timeout_seconds'] > 0


@pytest.mark.parametrize('result,code', [(ProcessResult(1, 'boom'), 'PT-TIERW-VERIFY'),
                                         (ProcessResult(-1, '', 'cancelled'), 'PT-TIERW-CANCEL'),
                                         (ProcessResult(0, ''), 'PT-TIERW-VERIFY')],
                         ids=['nonzero', 'cancelled', 'no-output'])
def test_export_headless_failures_are_typed(tmp_path, result, code):
    with pytest.raises(TierWError) as err:
        G.export_headless(_ghidra_tree(tmp_path), tmp_path / 'i.sys', tmp_path / 'w', run=lambda argv, **kw: result)
    assert err.value.code == code


def test_missing_ghidra_is_blocked_with_a_reason(tmp_path):
    assert G.blocked_reason(None) == 'no --ghidra-dir given'
    assert 'launcher' in G.blocked_reason(tmp_path)
    assert G.blocked_reason(_ghidra_tree(tmp_path)) is None
    with pytest.raises(TierWError) as err:
        G.export_headless(tmp_path, tmp_path / 'i.sys', tmp_path / 'w')
    assert err.value.code == 'PT-TIERW-BLOCKED'


def test_dotted_workdir_is_refused_before_anything_runs(tmp_path):
    with pytest.raises(TierWError) as err:
        G.export_headless(_ghidra_tree(tmp_path), tmp_path / 'i.sys', tmp_path / '.hidden' / 'w')
    assert err.value.code == 'PT-TIERW-CONFIG'


def test_live_ghidra_export_runs_or_records_blocked(tmp_path):
    ghidra = os.environ.get('PATCHTRACE_GHIDRA_DIR')
    reason = G.blocked_reason(Path(ghidra) if ghidra else None)
    if reason:
        pytest.xfail(f'BLOCKED: {reason}')
    doc = G.export_headless(Path(ghidra), PE1, tmp_path / 'ptg')
    assert doc.contract == 'ghidra-symbols/1' and doc.functions
