"""SPEC-31 S3b: the `decompile` mode of the extractor script (extract/ghidra_script.py, 03 s4, 05 s2.8) against fakes.

The script is loaded as a plain module; Ghidra, its decompiler and the project are duck-typed fakes (the fakes of
tests/test_unified_ghidra_script.py where they exist). What only a live Ghidra can prove is in docs/qa.md
[S3b:decompile]. Nothing here executes a target binary."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pe_builder import PeSpec, SectionSpec, build_pe
from test_unified_ghidra_script import (
    BASE,
    JAVA,
    FakeFile,
    FakeProject,
    fake_importer,
    program_with,
    script,
    valid_request,
    write_request,
)

from patchtrace.unified.extract import runner
from patchtrace.unified.extract.decomp import read_decomp
from patchtrace.unified.limits import DEFAULT_LIMITS

LIBRARY = 'ghidra.app.decompiler.DecompInterface'


class Address:
    def __init__(self, offset):
        self.offset = offset

    def add(self, delta):
        if not 0 <= delta < 1 << 32:
            raise ValueError('AddressOutOfBoundsException')
        return Address(self.offset + delta)

    def getOffset(self):
        return self.offset


class Function:
    def __init__(self, rva, external=False):
        self.rva, self.external = rva, external

    def isExternal(self):
        return self.external


class Results:
    def __init__(self, text=None, *, timed_out=False, completed=True):
        self.text, self.timed_out, self.completed = text, timed_out, completed

    def isTimedOut(self):
        return self.timed_out

    def decompileCompleted(self):
        return self.completed

    def getDecompiledFunction(self):
        return None if self.text is None else SimpleNamespace(getC=lambda: self.text)


class Decompiler:
    """DecompInterface: results by function RVA (an Exception instance is raised), a log of every call."""

    def __init__(self, results, *, opens=True):
        self.results, self.opens = results, opens
        self.programs, self.calls, self.disposed = [], [], False

    def openProgram(self, program):
        self.programs.append(program)
        return self.opens

    def decompileFunction(self, function, seconds, monitor):
        self.calls.append((function.rva, seconds, monitor))
        outcome = self.results[function.rva]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def dispose(self):
        self.disposed = True


class Program:
    def __init__(self, functions, sha):
        self.table, self.sha = {f.rva: f for f in functions}, sha

    def getImageBase(self):
        return Address(BASE)

    def getFunctionManager(self):
        return SimpleNamespace(getFunctionAt=lambda address: self.table.get(address.offset - BASE))

    def getExecutableSHA256(self):
        return self.sha

    def getLanguageID(self):
        return 'x86:LE:64:default'


@pytest.fixture
def decomp(tmp_path, monkeypatch):
    """Everything `run()` touches outside the target, in decompile mode: JVM start, Ghidra classes, the project."""
    artifact = tmp_path / 'a.dll'
    artifact.write_bytes(build_pe(PeSpec(kind='dll', image_base=BASE, sections=[SectionSpec('.text', b'\x90' * 64)])))
    packed = tmp_path / 'g.gzf'
    packed.write_bytes(b'packed program')
    for name in ('out', 'work'):
        (tmp_path / name).mkdir()
    log = []
    state = SimpleNamespace(log=log, analyzed=True, missing=[], missing_decompiler=[], artifact=artifact, packed=packed,
                            decompiler=None, program=None, tmp=tmp_path)

    def create_project(directory, name, temporary):
        log.append(('project', directory, name, temporary))
        return FakeProject(state.program, log)

    def make_java():
        java = SimpleNamespace(**vars(JAVA))
        java.missing, java.missing_decompiler = list(state.missing), list(state.missing_decompiler)
        java.GhidraProject = SimpleNamespace(createProject=create_project)
        java.File = FakeFile
        java.GhidraProgramUtilities = SimpleNamespace(isAnalyzed=lambda program: state.analyzed)
        java.DecompInterface = lambda: state.decompiler
        return java

    class Loader:
        def load(self):
            return make_java()

    monkeypatch.setattr(script, 'Java', Loader)
    monkeypatch.setattr(script, 'start_jvm', lambda directory, heap: log.append(('jvm', directory, heap)))
    monkeypatch.setenv('GHIDRA_INSTALL_DIR', str(tmp_path / 'ghidra'))
    monkeypatch.setitem(script.CANCEL, 'flag', False)
    state.sha = hashlib.sha256(artifact.read_bytes()).hexdigest()

    def request(rvas=(0x1000,), **change):
        digest = hashlib.sha256(packed.read_bytes()).hexdigest()
        document = valid_request(tmp_path, artifact_path=str(artifact), artifact_sha256=state.sha, mode='decompile',
                                 gzf_path=str(packed), gzf_sha256=digest, analysis_options={}, limits={},
                                 decompile_rvas=list(rvas))
        document.update(change)
        return document

    def install(results, functions=None, **kw):
        rvas = sorted(results) if functions is None else functions
        state.decompiler = Decompiler(results, **kw)
        state.program = Program([Function(rva) for rva in rvas], state.sha)
        return state.decompiler

    state.request, state.install = request, install
    return state


def lines(directory):
    return [json.loads(line) for line in (Path(directory) / 'decomp.jsonl').read_text(encoding='utf-8').splitlines()]


# --- the request -----------------------------------------------------------------------------------------------------

def test_a_decompile_request_is_accepted_and_malformed_ones_are_not(tmp_path, decomp):
    good = decomp.request((0x1000, 0x1100))
    assert script.load_request(write_request(tmp_path, good))['decompile_rvas'] == [0x1000, 0x1100]
    bad = [dict(decompile_rvas=[]), dict(decompile_rvas=[0x1100, 0x1000]), dict(decompile_rvas=[0x1000, 0x1000]),
           dict(decompile_rvas=[-1]), dict(decompile_rvas=[True]), dict(decompile_rvas=['4096']),
           dict(decompile_rvas=list(range(65))), dict(gzf_path=None, gzf_sha256=None), dict(gzf_sha256=None),
           dict(decompile_rvas=[0x1000], limits={'l41_decompile_pairs': 0})]
    for change in bad:
        with pytest.raises(script.ScriptExit) as caught:
            script.load_request(write_request(tmp_path, {**good, **change}))
        assert (caught.value.code, caught.value.reason) == (2, 'bad-request'), change
    for mode in ('analyze', 'gzf'):                    # the RVAs belong to decompile mode alone
        other = valid_request(tmp_path, mode=mode, decompile_rvas=[0x1000],
                              **({'gzf_path': str(tmp_path / 'g.gzf'), 'gzf_sha256': 'cd' * 32, 'analysis_options': {}}
                                 if mode == 'gzf' else {}))
        with pytest.raises(script.ScriptExit):
            script.load_request(write_request(tmp_path, other))


def test_the_pair_cap_may_be_lowered_by_the_request_but_the_default_is_l41(tmp_path, decomp):
    assert script._DEFAULT_LIMITS['l41_decompile_pairs'] == DEFAULT_LIMITS.l41_decompile_pairs == 64
    many = decomp.request(range(64))
    assert len(script.load_request(write_request(tmp_path, many))['decompile_rvas']) == 64
    with pytest.raises(script.ScriptExit):
        script.load_request(write_request(tmp_path, {**many, 'limits': {'l41_decompile_pairs': 10}}))


# --- the session -----------------------------------------------------------------------------------------------------

def test_run_decompile_opens_the_retained_gzf_and_decompiles_only_the_requested_functions(decomp, tmp_path):
    trap = AssertionError('a function that was not requested was decompiled')
    decompiler = decomp.install({0x1000: Results('int a(void) { return 1; }'), 0x1100: trap,
                                 0x1200: Results('int c(void) { return 3; }')})
    assert script.run(decomp.request((0x1000, 0x1200))) == 0
    assert [entry[0] for entry in decomp.log] == ['jvm', 'project', 'import', 'close']
    assert decomp.log[2][1] == str(decomp.packed)                       # the retained program, never the artifact
    assert decompiler.programs == [decomp.program] and decompiler.disposed
    assert [(rva, seconds) for rva, seconds, _monitor in decompiler.calls] == [(0x1000, 60), (0x1200, 60)]
    assert decompiler.calls[0][2] == 'monitor'
    assert lines(tmp_path / 'out') == [
        {'side': 'older', 'rva': 0x1000, 'status': 'ok', 'code': 'int a(void) { return 1; }'},
        {'side': 'older', 'rva': 0x1200, 'status': 'ok', 'code': 'int c(void) { return 3; }'}]
    assert not (tmp_path / 'out' / 'ir.jsonl').exists()
    assert json.loads((tmp_path / 'out' / 'progress.json').read_text(encoding='utf-8'))['phase'] == 'done'
    records = read_decomp(tmp_path / 'out' / 'decomp.jsonl', 'older', [0x1000, 0x1200])      # the reader accepts it
    assert records[0x1000].code == 'int a(void) { return 1; }'


def test_every_function_level_problem_is_one_failed_or_timed_out_record(decomp, tmp_path):
    results = {0x1000: Results('ok text'), 0x1100: Results(timed_out=True), 0x1200: Results('x', completed=False),
               0x1300: Results(None), 0x1400: RuntimeError('decompiler fault'), 0x1500: Results('   \n'),
               0x1700: Results('y' * 40), 0x1800: Results('a\nb\nc\nd')}
    decompiler = decomp.install(results, functions=[0x1000, 0x1100, 0x1200, 0x1300, 0x1400, 0x1500, 0x1700, 0x1800])
    decomp.program.table[0x1600] = Function(0x1600, external=True)
    results[0x1600] = AssertionError('an external function must not be decompiled')
    rvas = (0x1000, 0x1100, 0x1200, 0x1300, 0x1400, 0x1500, 0x1600, 0x1700, 0x1800, 0x1900)    # 0x1900: no function
    assert script.run(decomp.request(rvas, limits={'l29_pseudo_chars': 30, 'l29_pseudo_lines': 3})) == 0
    got = {item['rva']: (item['status'], item['code']) for item in lines(tmp_path / 'out')}
    assert got == {0x1000: ('ok', 'ok text'), 0x1100: ('timeout', None), 0x1200: ('failed', None),
                   0x1300: ('failed', None), 0x1400: ('failed', None), 0x1500: ('failed', None),
                   0x1600: ('failed', None), 0x1700: ('failed', None), 0x1800: ('failed', None),
                   0x1900: ('failed', None)}
    assert 0x1600 not in {rva for rva, _s, _m in decompiler.calls} and decompiler.disposed
    assert 0x1900 not in {rva for rva, _s, _m in decompiler.calls}
    records = read_decomp(tmp_path / 'out' / 'decomp.jsonl', 'older', rvas)          # the reader takes every status
    assert {rva: (rec.status, rec.code) for rva, rec in records.items()} == got


def test_an_address_outside_the_program_is_a_failed_function_not_a_failed_run(decomp, tmp_path):
    decomp.install({0x1000: Results('fine')})
    assert script.run(decomp.request((0x1000, 1 << 40))) == 0
    assert [(item['rva'], item['status']) for item in lines(tmp_path / 'out')] == [(0x1000, 'ok'), (1 << 40, 'failed')]


def test_code_is_cleaned_but_keeps_its_lines_and_tabs():
    text = 'int f(void)\r\n{\r\n\treturn 0;\x1b[31m‮\x00 \ud800\n}\rend'
    assert script.clean_code(text) == 'int f(void)\n{\n\treturn 0;?[31m?? ?\n}\nend'
    assert script.clean_code(b'bytes'.decode()) == 'bytes' and script.clean_code(12) == '12'


def test_the_run_budget_and_the_function_timeout_bound_every_call(decomp, tmp_path, monkeypatch):
    decompiler = decomp.install({0x1000: Results('a'), 0x1100: Results('b'), 0x1200: Results('c'),
                                 0x1300: RuntimeError('never asked')})
    ticks = iter([1000.0, 1000.0, 1098.0, 1150.0, 1150.0])           # the deadline, then one reading per function
    monkeypatch.setattr(script, 'time', SimpleNamespace(monotonic=lambda: next(ticks)))
    limits = {'l41_decompile_fn_s': 5, 'l41_decompile_run_s': 100}
    assert script.run(decomp.request((0x1000, 0x1100, 0x1200, 0x1300), limits=limits)) == 0
    assert [(rva, seconds) for rva, seconds, _m in decompiler.calls] == [(0x1000, 5), (0x1100, 2)]     # min(fn, left)
    assert [(item['rva'], item['status']) for item in lines(tmp_path / 'out')] == [
        (0x1000, 'ok'), (0x1100, 'ok'), (0x1200, 'timeout'), (0x1300, 'timeout')]      # spent: not even attempted


def test_an_unavailable_decompiler_is_unsupported_and_everything_is_closed(decomp, tmp_path):
    decompiler = decomp.install({0x1000: Results('a')}, opens=False)
    with pytest.raises(script.ScriptExit) as caught:
        script.run(decomp.request())
    assert (caught.value.code, caught.value.reason) == (4, 'decompiler-unavailable')
    assert decompiler.disposed and decomp.log[-1] == ('close',) and not (tmp_path / 'out' / 'decomp.jsonl').exists()
    decomp.missing_decompiler = [LIBRARY]                          # the class itself is missing: stop before the project
    decomp.log.clear()
    with pytest.raises(script.ScriptExit) as caught:
        script.run(decomp.request())
    assert caught.value.reason == 'decompiler-unavailable' and 'project' not in [e[0] for e in decomp.log]


@pytest.mark.parametrize('what,reason', [('artifact', 'artifact-hash'), ('gzf', 'program-hash'),
                                         ('program', 'program-hash'), ('analysis', 'gzf-not-analyzed')])
def test_decompile_refuses_wrong_inputs_unanalysed_programs_and_other_binaries(decomp, what, reason):
    decomp.install({0x1000: Results('a')})
    request = decomp.request()
    if what == 'artifact':
        decomp.artifact.write_bytes(decomp.artifact.read_bytes() + b'\0')
    elif what == 'gzf':
        decomp.packed.write_bytes(b'another program')
    elif what == 'program':
        decomp.program.sha = 'ee' * 32
    else:
        decomp.analyzed = False
    with pytest.raises(script.ScriptExit) as caught:
        script.run(request)
    assert (caught.value.code, caught.value.reason) == (3, reason)
    assert not decomp.decompiler.calls                                # nothing was decompiled
    assert ('jvm' in [e[0] for e in decomp.log]) == (what in ('program', 'analysis'))   # file hashes come first


def test_cancel_stops_the_decompile_loop_and_still_disposes(decomp, tmp_path):
    class Cancelling(Decompiler):
        def decompileFunction(self, function, seconds, monitor):
            script.CANCEL['flag'] = True
            return super().decompileFunction(function, seconds, monitor)

    decompiler = Cancelling({0x1000: Results('a'), 0x1100: Results('b')})
    decomp.decompiler = decompiler
    decomp.program = Program([Function(0x1000), Function(0x1100)], decomp.sha)
    with pytest.raises(script.ScriptExit) as caught:
        script.run(decomp.request((0x1000, 0x1100)))
    assert (caught.value.code, caught.value.reason) == (5, 'cancelled')
    assert [rva for rva, _s, _m in decompiler.calls] == [0x1000] and decompiler.disposed
    assert not (tmp_path / 'out' / 'decomp.jsonl').exists() and decomp.log[-1] == ('close',)


def test_a_failing_dispose_never_masks_the_result(decomp, tmp_path):
    decompiler = decomp.install({0x1000: Results('a')})
    decompiler.dispose = lambda: (_ for _ in ()).throw(RuntimeError('dispose failed'))
    assert script.run(decomp.request()) == 0 and lines(tmp_path / 'out')[0]['status'] == 'ok'


# --- class resolution and the self-check ------------------------------------------------------------------------------------

def test_the_decompiler_class_is_loaded_apart_from_the_required_ones(monkeypatch):
    monkeypatch.setattr(script, 'importlib', fake_importer())
    java = script.Java().load()
    assert java.missing == [] and java.missing_decompiler == [] and java.DecompInterface.name == 'DecompInterface'
    monkeypatch.setattr(script, 'importlib', fake_importer(missing=(LIBRARY,)))
    java = script.Java().load()
    assert java.missing == [] and java.missing_decompiler == [LIBRARY]           # analysis modes still work


def test_the_self_check_reports_a_missing_decompiler_class(monkeypatch, capsys):
    monkeypatch.setattr(script, 'start_jvm', lambda *args: None)
    monkeypatch.setattr(script, 'importlib', fake_importer(missing=(LIBRARY,)))
    assert script.self_check('/ghidra') == 4
    report = json.loads(capsys.readouterr().out)['self_check']
    assert report['ok'] is False and report['missing'] == [LIBRARY]


def test_the_analysis_modes_do_not_need_the_decompiler(decomp, tmp_path, monkeypatch):
    """A Ghidra without the decompiler class still extracts: only `decompile` mode asks for it."""
    program = program_with(2)
    program.getLanguageID = lambda: 'x86:LE:64:default'
    program.sha = decomp.sha
    decomp.program = program
    decomp.missing_decompiler = [LIBRARY]
    monkeypatch.setattr(script, 'new_byte_array', lambda length: bytearray(length))
    request = valid_request(tmp_path, artifact_path=str(decomp.artifact), artifact_sha256=decomp.sha, mode='gzf',
                            gzf_path=str(decomp.packed),
                            gzf_sha256=hashlib.sha256(decomp.packed.read_bytes()).hexdigest(), analysis_options={})
    assert script.run(request) == 0 and (tmp_path / 'out' / 'ir.jsonl').is_file()


def test_the_new_failure_slug_is_in_the_runner_table():
    assert runner._REASONS['decompiler-unavailable'] == 'PT-UNIFIED-UNSUPPORTED'
    assert {module for module, _attr in script.DECOMPILER_CLASSES} == {'ghidra.app.decompiler'}
