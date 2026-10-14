"""SPEC-31 S1: the extractor script (extract/ghidra_script.py) without Ghidra.

The script is a DATA file that runs in the user's external Python; here it is loaded as a plain module and its
helpers run against small duck-typed fakes of the Ghidra objects. What only a live Ghidra can prove is in
tests/live/ (the `live-unified` workflow). Nothing here executes a target binary."""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from pe_builder import PeSpec, SectionSpec, build_pe

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.unified import extract
from patchtrace.unified.contracts import ExtractRequest
from patchtrace.unified.ir import operands as operands_module
from patchtrace.unified.ir.pe_tables import read_pe_tables

SCRIPT = Path(extract.__file__).parent / extract.SCRIPT_NAME
BASE = 0x180000000


def load_script():
    spec = importlib.util.spec_from_file_location('pt_ir_extract_under_test', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


script = load_script()


# --- static properties ----------------------------------------------------------------------------------------------

def imported_modules(tree):
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {a.name.split('.')[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            found.add((node.module or '').split('.')[0] or '.' * node.level)
    return found


def test_ghidra_script_imports_no_patchtrace():
    tree = ast.parse(SCRIPT.read_text(encoding='utf-8'))
    modules = imported_modules(tree)
    assert modules <= set(sys.stdlib_module_names) | {'pyghidra', 'jpype'}, modules
    assert not modules & {'patchtrace', 'ghidriff', 'socket', 'ssl', 'urllib', 'http', 'subprocess', 'ctypes',
                          'multiprocessing', 'ftplib', 'smtplib', 'shutil', 'tempfile'}


def test_script_runs_no_dynamic_code_and_spawns_nothing():
    tree = ast.parse(SCRIPT.read_text(encoding='utf-8'))
    names = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert not names & {'eval', 'exec', 'compile', '__import__', 'input'}
    attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not attributes & {'system', 'popen', 'Popen', 'spawn', 'execv', 'execve', 'startfile', 'urlopen'}
    assert 'Runtime' not in attributes and 'ProcessBuilder' not in attributes   # no Java process spawning either


def test_script_has_no_raw_non_ascii_or_bidi_characters():
    text = SCRIPT.read_text(encoding='utf-8')
    assert all(ord(c) < 128 for c in text)


def test_script_operand_flag_table_equals_ir_operands():
    table = script.EXPECTED_OPERAND_FLAGS
    assert table['INDIRECT'] == operands_module.OPTYPE_INDIRECT
    assert table['REGISTER'] == operands_module.OPTYPE_REGISTER
    assert table['ADDRESS'] == operands_module.OPTYPE_ADDRESS
    assert table['SCALAR'] == operands_module.OPTYPE_SCALAR
    assert table['DYNAMIC'] == operands_module.OPTYPE_DYNAMIC
    assert len(set(table.values())) == len(table) and all(v & (v - 1) == 0 for v in table.values())   # single bits


def test_script_digest_helpers_equal_the_package_helpers():
    for mode, options in (('analyze', {'PDB Universal': 'false'}), ('gzf', {}), ('analyze', {'b': '2', 'a': 'ü'})):
        assert script.analysis_options_digest(mode, options) == extract.analysis_options_digest(mode, options)
    sample = {'z': [1, {'b': None, 'a': 'x'}], 'a': 'é'}
    assert script.canonical_json(sample) == extract.canonical_json(sample)
    assert script.script_sha256() == extract.script_sha256() == hashlib.sha256(SCRIPT.read_bytes()).hexdigest()


def test_script_request_keys_equal_the_extract_request_contract():
    assert set(script._REQUEST_KEYS) == set(ExtractRequest.model_fields)
    assert script.CONTRACT_REQUEST == ExtractRequest.model_fields['contract'].default
    assert script.CONTRACT_EXTRACT == 'ir-extract/1'


def test_script_default_limits_match_the_unified_limits():
    from patchtrace.unified.limits import DEFAULT_LIMITS
    for key, value in script._DEFAULT_LIMITS.items():
        assert getattr(DEFAULT_LIMITS, key) == value, key


def test_script_name_sources_and_reason_slugs_are_closed_sets():
    from patchtrace.unified.extract import runner
    text = SCRIPT.read_text(encoding='utf-8')
    emitted = set(re.findall(r"ScriptExit\(\w+, '([a-z-]+)'\)", text)) | {'crash', 'cancelled'}
    assert emitted <= set(runner._REASONS), emitted - set(runner._REASONS)
    assert set(script._SOURCE_NAMES) == {'DEFAULT', 'ANALYSIS', 'AI', 'IMPORTED', 'USER_DEFINED'}


# --- pure helpers -------------------------------------------------------------------------------------------------------

def test_clean_text_replaces_controls_surrogates_and_caps_length():
    assert script.clean_text('a\x00b\x1bc‮d⁦e\x7ff\x9fg', 100) == 'a?b?c?d?e?f?g'
    assert script.clean_text('x' * 500, 10) == 'x' * 10 and script.clean_text('plain text 123', 100) == 'plain text 123'
    assert script.clean_text('lone \ud800 surrogate', 100) == 'lone ? surrogate'
    assert script.clean_text('café', 100) == 'café' and script.clean_text(12, 5) == '12'


def test_import_keys_and_parts():
    assert script.import_key('KERNEL32.DLL', 'CreateFileW') == 'kernel32.dll!CreateFileW'
    assert script.import_key('USER32.dll', 'Ordinal_12') == 'user32.dll!#12'
    assert script.import_key('x.dll', '#7', None) == 'x.dll!#7'
    assert script.import_key('x.dll', 'label', 'Original') == 'x.dll!Original'
    assert script.import_key(None, None) == 'unknown!unknown'
    assert script.import_parts('kernel32.dll!CreateFileW') == {'dll': 'kernel32.dll', 'name': 'CreateFileW', 'ordinal': None}
    assert script.import_parts('x.dll!#12') == {'dll': 'x.dll', 'name': None, 'ordinal': 12}


def test_flow_kinds_and_hex_of():
    assert [script.flow_kind(n) for n in ('FALL_THROUGH', 'UNCONDITIONAL_JUMP', 'JUMP_OVERRIDE_UNCONDITIONAL',
                                          'CONDITIONAL_JUMP', 'COMPUTED_JUMP', 'CONDITIONAL_COMPUTED_JUMP',
                                          'CALL_RETURN', 'anything')] == [
        'fall', 'jump', 'jump', 'cond', 'switch', 'switch', 'call-return', 'call-return']
    assert script.hex_of([0, 7, -1, -128, 127]) == '0007ff807f' and script.hex_of(None) is None


def test_to_bytes_handles_signed_java_buffers():
    assert script._to_bytes(bytearray(b'\x01\xff')) == b'\x01\xff'
    assert script._to_bytes([1, -1, -128]) == b'\x01\xff\x80'


def test_parse_pe_header_matches_the_independent_pe_tables_reader(tmp_path):
    path = tmp_path / 'x.dll'
    path.write_bytes(build_pe(PeSpec(kind='dll', image_base=BASE, sections=[SectionSpec('.text', b'\x90' * 64)])))
    with VerifiedArtifactReader.open_path(path) as reader:
        tables = read_pe_tables(reader)
    assert script.parse_pe_header(str(path)) == {'image_base': tables.image_base, 'size_of_image': tables.size_of_image}


@pytest.mark.parametrize('content,reason', [(b'', 'unsupported-format'), (b'MZ' + b'\0' * 200, 'unsupported-format'),
                                            (b'ELF' + b'\0' * 200, 'unsupported-format'),
                                            (None, 'unsupported-format')], ids=['empty', 'nope', 'elf', 'missing'])
def test_parse_pe_header_rejects_non_pe_files(tmp_path, content, reason):
    path = tmp_path / 'x.bin'
    if content is not None:
        path.write_bytes(content)
    with pytest.raises(script.ScriptExit) as caught:
        script.parse_pe_header(str(path))
    assert (caught.value.code, caught.value.reason) == (4, reason)


def test_parse_pe_header_rejects_pe32(tmp_path):
    path = tmp_path / 'x.dll'
    path.write_bytes(build_pe(PeSpec(pe32plus=False, kind='dll', sections=[SectionSpec('.text', b'\x90' * 64)])))
    with pytest.raises(script.ScriptExit) as caught:
        script.parse_pe_header(str(path))
    assert (caught.value.code, caught.value.reason) == (4, 'unsupported-language')


def test_file_sha256_streams(tmp_path):
    path = tmp_path / 'f.bin'
    path.write_bytes(b'abc' * 100_000)
    assert script.file_sha256(str(path)) == hashlib.sha256(b'abc' * 100_000).hexdigest()


def valid_request(tmp_path, **changes):
    request = {'contract': 'ir-extract-request/1', 'side': 'older', 'artifact_path': str(tmp_path / 'a.dll'),
               'artifact_sha256': 'ab' * 32, 'mode': 'analyze', 'gzf_path': None, 'gzf_sha256': None,
               'out_dir': str(tmp_path / 'out'), 'work_dir': str(tmp_path / 'work'), 'max_heap_mb': 4096,
               'analysis_options': {'PDB Universal': 'false'}, 'limits': {'l01_functions_per_side': 5},
               'decompile_rvas': []}
    request.update(changes)
    return request


def write_request(tmp_path, request, name='request.json'):
    path = tmp_path / name
    path.write_text(request if isinstance(request, str) else json.dumps(request), encoding='utf-8')
    return str(path)


def test_load_request_accepts_what_the_s0a_contract_writes(tmp_path):
    model = ExtractRequest(side='newer', artifact_path=str(tmp_path / 'a.dll'), artifact_sha256='ab' * 32,
                           mode='gzf', gzf_path=str(tmp_path / 'g.gzf'), gzf_sha256='cd' * 32,
                           out_dir=str(tmp_path / 'out'), work_dir=str(tmp_path / 'w'), max_heap_mb=2048,
                           analysis_options={}, limits={'l06_fn_instructions': 7})
    loaded = script.load_request(write_request(tmp_path, model.model_dump_json()))
    assert loaded['mode'] == 'gzf' and loaded['limits'] == {'l06_fn_instructions': 7} and loaded['side'] == 'newer'
    assert script.load_request(write_request(tmp_path, valid_request(tmp_path)))['mode'] == 'analyze'


@pytest.mark.parametrize('name,change', [
    ('contract', {'contract': 'ir-extract-request/2'}), ('side', {'side': 'both'}), ('mode', {'mode': 'turbo'}),
    ('relative', {'out_dir': 'relative/out'}), ('hash', {'artifact_sha256': 'AB' * 32}),
    ('heap', {'max_heap_mb': 100}), ('heapbool', {'max_heap_mb': True}), ('options', {'analysis_options': {'a': 1}}),
    ('limits', {'limits': {'l01_functions_per_side': -1}}), ('limitbool', {'limits': {'l01_functions_per_side': True}}),
    ('rvas', {'decompile_rvas': 'x'}), ('gzfless', {'mode': 'gzf'}),
    ('analyzegzf', {'gzf_path': '/tmp/g.gzf', 'gzf_sha256': 'cd' * 32}),
], ids=lambda value: value if isinstance(value, str) else '')
def test_load_request_rejects_bad_values(tmp_path, name, change):
    with pytest.raises(script.ScriptExit) as caught:
        script.load_request(write_request(tmp_path, valid_request(tmp_path, **change)))
    assert (caught.value.code, caught.value.reason) == (2, 'bad-request')


def test_load_request_rejects_structural_problems(tmp_path):
    good = valid_request(tmp_path)
    extra = dict(good, surprise=1)
    missing = {k: v for k, v in good.items() if k != 'limits'}
    duplicate = json.dumps(good)[:-1] + ', "side": "newer"}'
    for text in (json.dumps(extra), json.dumps(missing), duplicate, json.dumps(good).replace('4096', 'NaN'),
                 json.dumps(good).replace('4096', 'Infinity'), '[]', '', '{', 'null'):
        with pytest.raises(script.ScriptExit) as caught:
            script.load_request(write_request(tmp_path, text))
        assert caught.value.reason == 'bad-request'
    with pytest.raises(script.ScriptExit):
        script.load_request(str(tmp_path / 'absent.json'))


def test_progress_file_is_written_atomically(tmp_path):
    progress = script.ProgressFile(str(tmp_path))
    progress.write('functions', 5, None)
    assert json.loads((tmp_path / 'progress.json').read_text(encoding='utf-8')) == {'phase': 'functions', 'done': 5,
                                                                                    'total': None}
    assert not (tmp_path / 'progress.json.part').exists()
    progress.write('done', 7, 9)
    assert json.loads((tmp_path / 'progress.json').read_text(encoding='utf-8'))['total'] == 9
    script.ProgressFile(str(tmp_path / 'missing-dir')).write('x', 1, 1)         # advisory: never raises


# --- fakes of the Ghidra objects ----------------------------------------------------------------------------------------

class Addr:
    def __init__(self, offset, memory=True, external=False):
        self.offset, self.memory, self.external = offset, memory, external

    def isMemoryAddress(self):
        return self.memory

    def isExternalAddress(self):
        return self.external

    def getOffset(self):
        return self.offset


def A(rva):
    return Addr(BASE + rva)


class Register:
    def __init__(self, name):
        self.name = name

    def getName(self):
        return self.name


class Scalar:
    def __init__(self, value):
        self.value = value

    def getSignedValue(self):
        return self.value


class Mask:
    def __init__(self, data):
        self.data = data

    def getBytes(self):
        return self.data


class RefType:
    def __init__(self, name='DATA', call=False, jump=False):
        self.name, self.call, self.jump = name, call, jump

    def __str__(self):
        return self.name

    def isCall(self):
        return self.call

    def isJump(self):
        return self.jump


class Loc:
    def __init__(self, library, label, original=None):
        self.library, self.label, self.original = library, label, original

    def getLibraryName(self):
        return self.library

    def getLabel(self):
        return self.label

    def getOriginalImportedName(self):
        return self.original


class Ref:
    def __init__(self, to=None, kind='DATA', stack=None, external=None, call=False, jump=False):
        self.to, self.kind, self.stack, self.external, self.call, self.jump = to, kind, stack, external, call, jump

    def getReferenceType(self):
        return RefType(self.kind, self.call, self.jump)

    def isStackReference(self):
        return self.stack is not None

    def getStackOffset(self):
        return self.stack

    def isExternalReference(self):
        return self.external is not None

    def getExternalLocation(self):
        return self.external

    def isMemoryReference(self):
        return self.to is not None and self.stack is None and self.external is None

    def getToAddress(self):
        return self.to


class Flow:
    def __init__(self, name='FALL_THROUGH', call=False, jump=False, computed=False):
        self.name, self.call, self.jump, self.computed = name, call, jump, computed

    def __str__(self):
        return self.name

    def isCall(self):
        return self.call

    def isJump(self):
        return self.jump

    def isComputed(self):
        return self.computed


class Proto:
    """Hashable by identity like the Java InstructionPrototype the script caches masks by."""

    def __init__(self, instruction):
        self.instruction = instruction

    def getInstructionMask(self):
        return Mask(self.instruction.imask)

    def getOperandValueMask(self, index):
        mask = self.instruction.ops[index].get('mask')
        return Mask(mask) if mask is not None else None


class Insn:
    def __init__(self, rva, length=1, mnem='NOP', flow=None, ops=(), imask=(0xff,), refs_from=(), text=None):
        self.rva, self.length, self.mnem, self.flow = rva, length, mnem, flow or Flow()
        self.ops, self.imask, self.refs_from, self.text = list(ops), list(imask), list(refs_from), text or mnem
        self.proto = Proto(self)

    def __str__(self):
        return self.text

    def getPrototype(self):
        return self.proto

    def getNumOperands(self):
        return len(self.ops)

    def getOpObjects(self, i):
        return self.ops[i].get('objs', [])

    def getOperandReferences(self, i):
        return self.ops[i].get('refs', [])

    def getOperandType(self, i):
        return self.ops[i].get('type', 0)

    def getLength(self):
        return self.length

    def getMnemonicString(self):
        return self.mnem

    def getFlowType(self):
        return self.flow

    def getAddress(self):
        return A(self.rva)

    def getReferencesFrom(self):
        return self.refs_from


class Rng:
    def __init__(self, rva, length):
        self.rva, self.length = rva, length

    def getMinAddress(self):
        return A(self.rva)

    def getLength(self):
        return self.length


class Body:
    def __init__(self, *ranges):
        self.ranges = [Rng(*r) for r in ranges]

    def getAddressRanges(self):
        return self.ranges

    def contains(self, address):
        return any(r.rva <= address.offset - BASE < r.rva + r.length for r in self.ranges)


class Func:
    def __init__(self, rva, body, insns=(), name='fn', source='USER_DEFINED', thunk=None, final=None, external=False,
                 location=None, blocks=()):
        self.rva, self.body, self.insns, self.name, self.source = rva, body, list(insns), name, source
        self.thunk, self.final, self.external, self.location, self.blocks = thunk, final, external, location, blocks

    def getEntryPoint(self):
        return A(self.rva) if not self.external else Addr(self.rva, memory=False, external=True)

    def getBody(self):
        return self.body

    def getSymbol(self):
        return SimpleNamespace(getSource=lambda: self.source) if self.source is not None else None

    def getName(self):
        return self.name

    def isThunk(self):
        return self.thunk is not None or self.final is not None

    def getThunkedFunction(self, recursive):
        return self.final if recursive else self.thunk

    def isExternal(self):
        return self.external

    def getExternalLocation(self):
        return self.location


class Memory:
    def __init__(self, image=None, unreadable=()):
        self.image, self.unreadable = image or {}, set(unreadable)

    def getBytes(self, address, buffer):
        rva = address.offset - BASE
        if rva in self.unreadable or rva not in self.image:
            raise RuntimeError('MemoryAccessException')
        data = self.image[rva]
        buffer[:len(data)] = data


class Listing:
    def __init__(self, data=None):
        self.data = data or {}
        self.current = []

    def getInstructions(self, body, forward):
        return [i for i in self.current if body.contains(i.getAddress()) or not body.ranges]

    def getDataAt(self, address):
        return self.data.get(address.offset - BASE)


class Dest:
    def __init__(self, rva, flow):
        self.rva, self.flow = rva, flow

    def getDestinationAddress(self):
        return A(self.rva)

    def getFlowType(self):
        return self.flow


class Block:
    def __init__(self, rva, count, dests=()):
        self.rva, self.count, self.dests = rva, count, list(dests)

    def getFirstStartAddress(self):
        return A(self.rva)

    def getNumAddresses(self):
        return self.count

    def getDestinations(self, monitor):
        pending = list(self.dests)
        return SimpleNamespace(hasNext=lambda: bool(pending), next=lambda: pending.pop(0))


class Model:
    def __init__(self):
        self.blocks = []

    def getCodeBlocksContaining(self, body, monitor):
        return list(self.blocks)


class RefMan:
    def __init__(self, slots=None):
        self.slots = slots or {}

    def getReferencesFrom(self, address):
        return self.slots.get(address.offset - BASE, [])


class SymTab:
    def __init__(self, labels=None, boom=False):
        self.labels, self.boom = labels or {}, boom

    def getSymbols(self, address):
        if self.boom:
            raise RuntimeError('symbol table unreadable')
        return [SimpleNamespace(getName=lambda n=n: n) for n in self.labels.get(address.offset - BASE, [])]


class Program:
    def __init__(self, listing=None, memory=None, refman=None, symtab=None, functions=(), sha='ab' * 32):
        self.listing, self.memory = listing or Listing(), memory or Memory()
        self.refman, self.symtab, self.model = refman or RefMan(), symtab or SymTab(), Model()
        self.functions, self.sha, self.log = list(functions), sha, []
        self.options = SimpleNamespace()

    def getListing(self):
        return self.listing

    def getMemory(self):
        return self.memory

    def getReferenceManager(self):
        return self.refman

    def getSymbolTable(self):
        return self.symtab

    def getImageBase(self):
        return Addr(BASE)

    def getExecutableSHA256(self):
        return self.sha

    def getCompilerSpec(self):
        return SimpleNamespace(getCompilerSpecID=lambda: 'windows')

    def getFunctionManager(self):
        return SimpleNamespace(getFunctionCount=lambda: len(self.functions), getFunctions=lambda forward: iter(self.functions))

    def getOptions(self, name):
        return self.options

    def startTransaction(self, name):
        self.log.append(('start', name))
        return 7

    def endTransaction(self, transaction, commit):
        self.log.append(('end', transaction, commit))


JAVA = SimpleNamespace(Register=Register, Scalar=Scalar, Address=Addr, TaskMonitor=SimpleNamespace(DUMMY='monitor'),
                       Program=SimpleNamespace(ANALYSIS_PROPERTIES='Analyzers'), missing=[],
                       Application=SimpleNamespace(getApplicationVersion=lambda: '12.0.4'),
                       System=SimpleNamespace(getProperty=lambda key: '21.0.1'),
                       new_byte_array=lambda n: bytearray(n), BasicBlockModel=lambda program: program.model)


def make_ctx(program=None, limits=None):
    return script.Context(JAVA, program or Program(), BASE, 0x5000, limits or {})


# --- Context and operand/instruction records ------------------------------------------------------------------------------

def test_context_rva_is_none_outside_the_image_and_for_non_memory_addresses():
    ctx = make_ctx()
    assert ctx.rva(A(0x1234)) == 0x1234 and ctx.rva(Addr(BASE + 0x5000)) is None and ctx.rva(Addr(BASE - 1)) is None
    assert ctx.rva(Addr(0x10, memory=False)) is None and ctx.rva(None) is None and ctx.rva(object()) is None


def test_operand_objects_are_typed_and_capped():
    ctx = make_ctx()
    instruction = Insn(0x1000, ops=[{'objs': [Register('RAX'), Scalar(-5), A(0x2000), Addr(5), 'what'] + [Scalar(1)] * 9}])
    objs = script.operand_objs(ctx, instruction, 0)
    assert objs[:4] == [['reg', 'RAX'], ['scalar', -5], ['addr', 0x2000], ['addr', None]]
    assert len(objs) == 7 and ctx.warnings == {'unknown-op-object': 1}      # 8 objects looked at, one unknown dropped


def test_operand_refs_cover_stack_external_image_and_import_slots():
    slot_ref = Ref(external=Loc('KERNEL32.dll', 'ExitProcess'), kind='EXTERNAL')
    ctx = make_ctx(Program(refman=RefMan({0x3000: [slot_ref]})))
    instruction = Insn(0x1000, ops=[{'refs': [
        Ref(stack=-24, kind='STACK_READ'), Ref(external=Loc('USER32.dll', 'MessageBoxA'), kind='EXTERNAL'),
        Ref(to=A(0x2000), kind='DATA'), Ref(to=A(0x3000), kind='READ'), Ref(to=Addr(BASE + 0x9000), kind='DATA')]}])
    refs, targets = script.operand_refs(ctx, instruction, 0)
    assert refs == [['STACK_READ', 'stack:-24'], ['EXTERNAL', 'ext:user32.dll!MessageBoxA'], ['DATA', 'rva:8192'],
                    ['READ', 'ext:kernel32.dll!ExitProcess']]
    assert [t.offset - BASE for t in targets] == [0x2000, 0x3000]
    assert ctx.slots == {BASE + 0x3000: 'kernel32.dll!ExitProcess', BASE + 0x2000: None}   # cached per address


def test_operand_and_instruction_records_cache_masks_per_prototype():
    ctx = make_ctx()
    op = {'type': 0x2008, 'mask': [0, 0, -1, -1], 'objs': [A(0x2000)], 'refs': [Ref(to=A(0x2000))]}
    nomask = {'type': 0x200, 'objs': [Register('EAX')]}
    instruction = Insn(0x1000, length=5, mnem='JMP' * 20, ops=[op, nomask], imask=[-1, 0, 0, 0, 0],
                       flow=Flow('UNCONDITIONAL_JUMP' + 'X' * 40), text='JMP 0x2000')
    record, text, targets = script.instruction_record(ctx, instruction, 3)
    assert record[:4] == [3, 5, 'JMPJMPJMPJMPJMPJMPJMPJMPJMPJMPJM'[:32], 'ff00000000']
    assert record[4][0] == [0x2008, '0000ffff', [['addr', 0x2000]], [['DATA', 'rva:8192']]]
    assert record[4][1] == [0x200, None, [['reg', 'EAX']], []] and len(record[5]) == 48 and text == 'JMP 0x2000'
    assert len(targets) == 1 and (('i', instruction.proto) in ctx.masks) and (('o', instruction.proto, 0) in ctx.masks)


def test_call_entries_classify_calls_jumps_imports_and_computed_flows():
    ctx = make_ctx()
    body = Body((0x1000, 0x40))
    call = Insn(0x1010, flow=Flow('UNCONDITIONAL_CALL', call=True), refs_from=[
        Ref(to=A(0x2000), kind='UNCONDITIONAL_CALL', call=True), Ref(to=A(0x1020), kind='DATA'),
        Ref(external=Loc('A.dll', 'F'), kind='EXTERNAL', call=True), Ref(to=Addr(5, memory=False, external=True),
                                                                       kind='X', call=True)])
    assert script.call_entries(ctx, call, 0x1010, body) == [[0x1010, 0x2000, None, 'call'], [0x1010, None, 'a.dll!F', 'call']]
    jump_out = Insn(0x1020, flow=Flow('UNCONDITIONAL_JUMP', jump=True),
                    refs_from=[Ref(to=A(0x3000), kind='UNCONDITIONAL_JUMP', jump=True)])
    jump_in = Insn(0x1024, flow=Flow('CONDITIONAL_JUMP', jump=True),
                   refs_from=[Ref(to=A(0x1030), kind='CONDITIONAL_JUMP', jump=True)])
    assert script.call_entries(ctx, jump_out, 0x1020, body) == [[0x1020, 0x3000, None, 'jump']]
    assert script.call_entries(ctx, jump_in, 0x1024, body) == []
    computed = Insn(0x1030, flow=Flow('COMPUTED_CALL', call=True, computed=True))
    assert script.call_entries(ctx, computed, 0x1030, body) == [[0x1030, None, None, 'call']]
    assert script.call_entries(ctx, Insn(0x1040), 0x1040, body) == []
    outside = Insn(0x1050, flow=Flow('UNCONDITIONAL_CALL', call=True),
                   refs_from=[Ref(to=Addr(BASE + 0x9999), kind='X', call=True)])
    assert script.call_entries(ctx, outside, 0x1050, body) == []


def test_string_entries_hash_utf8_cap_prefix_and_dedupe():
    text = 'héllo ' + 'w' * 100
    data = {0x2000: SimpleNamespace(hasStringValue=lambda: True, getLength=lambda: 200, getValue=lambda: text),
            0x2100: SimpleNamespace(hasStringValue=lambda: False),
            0x2200: SimpleNamespace(hasStringValue=lambda: True, getLength=lambda: 10 ** 6, getValue=lambda: 'big')}
    ctx = make_ctx(Program(listing=Listing(data)))
    entries = script.string_entries(ctx, [A(0x2000), A(0x2000), A(0x2100), A(0x2200), A(0x2300)], 0x1004)
    assert entries == [[0x1004, hashlib.sha256(text.encode()).hexdigest(), len(text), text[:64]]]
    assert ctx.warnings == {'string-too-long': 1} and list(ctx.strings) == [BASE + 0x2000, BASE + 0x2100, BASE + 0x2200,
                                                                            BASE + 0x2300]


def test_block_records_keep_only_same_function_successors_sorted_by_target_and_kind():
    program = Program()
    program.model.blocks = [
        Block(0x1020, 3, [Dest(0x1000, Flow('CONDITIONAL_JUMP')), Dest(0x9000, Flow('UNCONDITIONAL_JUMP'))]),
        Block(0x1000, 4, [Dest(0x1020, Flow('CONDITIONAL_JUMP')), Dest(0x1010, Flow('FALL_THROUGH')),
                          Dest(0x1010, Flow('CONDITIONAL_JUMP'))]),
        Block(0x1010, 2, [Dest(0x1020, Flow('FALL_THROUGH'))]), Block(0x9000, 1)]
    program.model.blocks.append(Block(0x70000, 1))                   # outside the image (0x5000): dropped
    ctx = make_ctx(program)
    rvas = [0x1000, 0x1002, 0x1004, 0x1006, 0x1010, 0x1012, 0x1020, 0x1021, 0x1022]
    records = script.block_records(ctx, Body((0x1000, 0x30)), rvas)
    assert records == [[0x1000, 4, 4, [0x1010, 0x1010, 0x1020], ['fall', 'cond', 'cond']],
                       [0x1010, 2, 2, [0x1020], ['fall']], [0x1020, 3, 3, [0x1000], ['cond']]]


def test_function_names_filter_ordinal_placeholders_and_unknown_sources():
    labels = {0x1000: ['fn', 'alias_b', 'alias_a', 'Ordinal_12', 'ordinal_1', 'alias_a']}
    ctx = make_ctx(Program(symtab=SymTab(labels)))
    name, source, aliases = script.function_names(ctx, Func(0x1000, Body((0x1000, 4)), name='fn', source='IMPORTED'))
    assert (name, source, aliases) == ('fn', 'IMPORTED', ['alias_a', 'alias_b', 'ordinal_1'])
    assert script.function_names(ctx, Func(0x1000, Body((0x1000, 4)), source='MYSTERY'))[1] == 'DEFAULT'
    assert ctx.warnings == {'unknown-name-source': 1}
    assert script.function_names(ctx, Func(0x1000, Body((0x1000, 4)), source=None))[1] == 'DEFAULT'
    many = make_ctx(Program(symtab=SymTab({0x1000: [f'alias{i:02d}' for i in range(40)]})))
    assert len(script.function_names(many, Func(0x1000, Body((0x1000, 4))))[2]) == script.MAX_ALIASES
    broken = make_ctx(Program(symtab=SymTab(boom=True)))
    assert script.function_names(broken, Func(0x1000, Body((0x1000, 4))))[2] == [] and broken.warnings == {
        'aliases-unreadable': 1}


def test_thunk_fields_resolve_internal_and_imported_targets():
    ctx = make_ctx()
    plain = Func(0x1000, Body((0x1000, 4)))
    assert script.thunk_fields(ctx, plain) == (None, None)
    target = Func(0x2000, Body((0x2000, 4)))
    assert script.thunk_fields(ctx, Func(0x1000, Body((0x1000, 4)), thunk=target, final=target)) == (0x2000, None)
    external = Func(0x0, Body(), external=True, location=Loc('KERNEL32.dll', 'Sleep'))
    imported = Func(0x1000, Body((0x1000, 4)), thunk=external, final=external)
    assert script.thunk_fields(ctx, imported) == (None, {'dll': 'kernel32.dll', 'name': 'Sleep', 'ordinal': None})


def test_function_ranges_sort_and_warn_about_ranges_outside_the_image():
    ctx = make_ctx()
    body = Body((0x1100, 8), (0x1000, 0x10))
    body.ranges.append(Rng(0x7000_0000 - BASE + BASE, 4))              # far outside
    assert script.function_ranges(ctx, body) == [[0x1000, 0x10], [0x1100, 8]]
    assert ctx.warnings == {'range-outside-image': 1}


def test_read_raw_joins_ranges_and_reports_unreadable_memory():
    memory = Memory({0x1000: b'\x01\x02', 0x1100: b'\x03'}, unreadable=())
    ctx = make_ctx(Program(memory=memory))
    body = Body((0x1000, 2), (0x1100, 1))
    assert script.read_raw(ctx, body, [[0x1000, 2], [0x1100, 1]]) == b'\x01\x02\x03'
    broken = make_ctx(Program(memory=Memory({0x1000: b'\x01\x02'}, unreadable=[0x1100])))
    assert script.read_raw(broken, body, []) is None and broken.warnings == {'raw-unreadable': 1}


# --- extract_function ----------------------------------------------------------------------------------------------------------

def function_with(instructions, *, ranges=((0x1000, 3),), image=None, **kw):
    body = Body(*ranges)
    function = Func(0x1000, body, name='sample', **kw)
    listing = Listing()
    listing.current = list(instructions)
    memory = Memory(image if image is not None else {0x1000: b'\x90\x90\xc3'})
    program = Program(listing=listing, memory=memory, symtab=SymTab({0x1000: ['sample', 'alias']}))
    program.model.blocks = [Block(0x1000, 3)]
    return function, program


def test_extract_function_builds_the_ir_extract_record():
    insns = [Insn(0x1000, mnem='NOP'), Insn(0x1001, mnem='NOP'), Insn(0x1002, mnem='RET', flow=Flow('RETURN'))]
    function, program = function_with(insns)
    ctx = make_ctx(program)
    record = script.extract_function(ctx, function)
    assert record['rva'] == 0x1000 and record['ranges'] == [[0x1000, 3]] and record['raw'] == '9090c3'
    assert record['name'] == 'sample' and record['aliases'] == ['alias'] and record['kind'] == 'normal'
    assert [i[2] for i in record['insns']] == ['NOP', 'NOP', 'RET'] and [i[0] for i in record['insns']] == [0, 1, 2]
    assert record['blocks'] == [[0x1000, 3, 3, [], []]] and record['text'] == ['NOP', 'NOP', 'RET']
    assert record['truncated'] is False and ctx.instructions == 3 and 'lib' in record
    json.dumps(record)


def test_extract_function_with_two_ranges_uses_function_relative_offsets():
    insns = [Insn(0x1000, mnem='NOP', length=2), Insn(0x1100, mnem='RET', flow=Flow('RETURN'))]
    function, program = function_with(insns, ranges=((0x1000, 2), (0x1100, 1)),
                                      image={0x1000: b'\x90\x90', 0x1100: b'\xc3'})
    record = script.extract_function(make_ctx(program), function)
    assert record['ranges'] == [[0x1000, 2], [0x1100, 1]] and record['raw'] == '9090c3'
    assert [i[0] for i in record['insns']] == [0, 2]


def test_extract_function_skips_entries_outside_the_image_and_empty_bodies():
    outside = Func(0x1000, Body((0x1000, 2)))
    outside.getEntryPoint = lambda: Addr(BASE + 0x90000)
    ctx = make_ctx()
    assert script.extract_function(ctx, outside) is None and ctx.warnings == {'entry-outside-image': 1}
    assert script.extract_function(ctx, Func(0x1000, Body())) is None and ctx.warnings['empty-body'] == 1


def test_extract_function_marks_caps_and_keeps_the_header_only():
    many = tuple((0x1000 + 0x10 * i, 4) for i in range(script.MAX_RANGES + 1))
    function, program = function_with([], ranges=many)
    ctx = make_ctx(program)
    record = script.extract_function(ctx, function)
    assert record['truncated'] is True and record['insns'] == [] and record['raw'] is None
    assert len(record['ranges']) == script.MAX_RANGES and ctx.warnings == {'ranges-capped': 1}

    function, program = function_with([], ranges=((0x1000, 100),))
    ctx = make_ctx(program, {'l06_fn_raw_bytes': 50})
    record = script.extract_function(ctx, function)
    assert record['raw'] is None and record['insns'] == [] and ctx.warnings == {'function-oversize': 1}

    function, program = function_with([Insn(0x1000), Insn(0x1001), Insn(0x1002)])
    ctx = make_ctx(program, {'l06_fn_instructions': 2})
    record = script.extract_function(ctx, function)
    assert record['truncated'] is True and record['insns'] == [] and ctx.warnings == {'function-truncated': 1}


def test_extract_function_leaves_body_empty_on_unreadable_or_inconsistent_data():
    function, program = function_with([Insn(0x1000)], image={})
    ctx = make_ctx(program)
    assert script.extract_function(ctx, function)['raw'] is None and ctx.warnings == {'raw-unreadable': 1}
    function, program = function_with([Insn(0x1000)], image={0x1000: b'\x90\x90'})   # fewer bytes than the range
    record = script.extract_function(make_ctx(program), function)
    assert record['raw'] is not None and len(record['raw']) == 6
    function, program = function_with([])
    stray = Insn(0x1001)
    stray.getAddress = lambda: Addr(0x10, memory=False)                  # e.g. a stack or register space address
    program.listing.getInstructions = lambda body, forward: [Insn(0x1000), stray]
    ctx = make_ctx(program)
    record = script.extract_function(ctx, function)
    assert record['insns'] == [] and ctx.warnings == {'instruction-outside-image': 1}


def test_thunk_function_record_carries_target_and_import():
    external = Func(0x0, Body(), external=True, location=Loc('USER32.dll', 'MessageBoxW'))
    function, program = function_with([Insn(0x1000), Insn(0x1001), Insn(0x1002)], thunk=external, final=external)
    record = script.extract_function(make_ctx(program), function)
    assert record['kind'] == 'thunk' and record['import'] == {'dll': 'user32.dll', 'name': 'MessageBoxW', 'ordinal': None}


# --- _write_ir: header, footer, caps, cancellation -------------------------------------------------------------------------------

def small_function(rva, name):
    insns = [Insn(rva, mnem='RET', flow=Flow('RETURN'))]
    function = Func(rva, Body((rva, 1)), name=name)
    return function, insns, {rva: b'\xc3'}


def program_with(count, external=0):
    listing, image, functions = Listing(), {}, []
    for index in range(count):
        function, insns, data = small_function(0x1000 + 0x10 * index, f'f{index}')
        functions.append(function)
        image.update(data)
        listing.current += insns
    for index in range(external):
        functions.append(Func(0x0, Body(), name=f'ext{index}', external=True))
    program = Program(listing=listing, memory=Memory(image), functions=functions)
    program.model.blocks = [Block(0x1000, 1)]
    return program


def read_lines(path):
    return [json.loads(line) for line in Path(path).read_text(encoding='utf-8').splitlines()]


def request_for(tmp_path, **limits):
    (tmp_path / 'out').mkdir(exist_ok=True)
    return valid_request(tmp_path, limits=limits, analysis_options={'PDB Universal': 'false'})


def test_write_ir_emits_header_functions_and_footer(tmp_path):
    program = program_with(3, external=2)
    request = request_for(tmp_path)
    progress = script.ProgressFile(request['out_dir'])
    assert script._write_ir(request, JAVA, program, {'size_of_image': 0x5000}, 'x86:LE:64:default', progress) == 0
    lines = read_lines(tmp_path / 'out' / 'ir.jsonl')
    header, *functions, footer = lines
    assert header['type'] == 'header' and header['contract'] == 'ir-extract/1' and header['image_base'] == BASE
    assert header['artifact_sha256'] == 'ab' * 32 and header['program_sha256'] == 'ab' * 32
    assert header['producer']['mode'] == 'analyze' and header['producer']['symbols'] == 'none'
    assert header['producer']['analysis_options_digest'] == extract.analysis_options_digest(
        'analyze', {'PDB Universal': 'false'})
    assert header['producer']['script_sha256'] == script.script_sha256() and header['producer']['ghidra'] == '12.0.4'
    assert [f['rva'] for f in functions] == [0x1000, 0x1010, 0x1020] and footer == {
        'type': 'footer', 'functions': 3, 'instructions': 3, 'status': 'complete', 'warnings': []}
    assert json.loads((tmp_path / 'out' / 'progress.json').read_text(encoding='utf-8'))['phase'] == 'done'


@pytest.mark.parametrize('limits,expected', [({'l01_functions_per_side': 2}, 'functions-cap'),
                                              ({'l02_instructions_per_side': 2}, 'instructions-cap')],
                         ids=['functions', 'insns'])
def test_write_ir_caps_make_a_partial_footer(tmp_path, limits, expected):
    request = request_for(tmp_path, **limits)
    script._write_ir(request, JAVA, program_with(5), {'size_of_image': 0x5000}, 'x86:LE:64:default',
                     script.ProgressFile(request['out_dir']))
    footer = read_lines(tmp_path / 'out' / 'ir.jsonl')[-1]
    assert footer['status'] == 'partial' and footer['functions'] == 2 and footer['warnings'] == [f'{expected}:1']


def test_write_ir_gzf_mode_reports_primary_symbols(tmp_path):
    request = dict(request_for(tmp_path), mode='gzf', gzf_path=str(tmp_path / 'g.gzf'), gzf_sha256='cd' * 32,
                   analysis_options={})
    script._write_ir(request, JAVA, program_with(1), {'size_of_image': 0x5000}, 'x86:LE:64:default',
                     script.ProgressFile(request['out_dir']))
    producer = read_lines(tmp_path / 'out' / 'ir.jsonl')[0]['producer']
    assert producer['mode'] == 'gzf' and producer['symbols'] == 'primary'
    assert producer['analysis_options_digest'] == extract.analysis_options_digest('gzf', {})


def test_write_ir_stops_when_cancelled(tmp_path, monkeypatch):
    request = request_for(tmp_path)
    monkeypatch.setitem(script.CANCEL, 'flag', True)
    with pytest.raises(script.ScriptExit) as caught:
        script._write_ir(request, JAVA, program_with(3), {'size_of_image': 0x5000}, 'x86:LE:64:default',
                         script.ProgressFile(request['out_dir']))
    assert (caught.value.code, caught.value.reason) == (5, 'cancelled')


# --- analysis options ------------------------------------------------------------------------------------------------------------

class Options:
    def __init__(self, types):
        self.types, self.set = types, {}

    def getType(self, name):
        return self.types.get(name, 'NO_TYPE')

    def __getattr__(self, name):
        if name.startswith('set'):
            return lambda key, value: self.set.__setitem__((name, key), value)
        raise AttributeError(name)


def test_set_analysis_options_uses_the_declared_type_and_ends_the_transaction():
    program = Program()
    program.options = Options({'b': 'BOOLEAN_TYPE', 'i': 'INT_TYPE', 'l': 'LONG_TYPE', 's': 'STRING_TYPE',
                               'd': 'DOUBLE_TYPE', 'f': 'FLOAT_TYPE'})
    script.set_analysis_options(JAVA, program, {'b': ' True ', 'i': '42', 'l': '7', 's': 'text', 'd': '1.5', 'f': '2'})
    assert program.options.set == {('setBoolean', 'b'): True, ('setInt', 'i'): 42, ('setLong', 'l'): 7,
                                   ('setString', 's'): 'text', ('setDouble', 'd'): 1.5, ('setFloat', 'f'): 2.0}
    assert program.log == [('start', 'PatchTrace analysis options'), ('end', 7, True)]


@pytest.mark.parametrize('options', [{'i': 'nope'}, {'missing': 'x'}], ids=['value', 'type'])
def test_bad_analysis_options_are_reported_and_the_transaction_still_ends(options):
    program = Program()
    program.options = Options({'i': 'INT_TYPE'})
    with pytest.raises(script.ScriptExit) as caught:
        script.set_analysis_options(JAVA, program, options)
    assert (caught.value.code, caught.value.reason) == (2, 'bad-option') and program.log[-1][0] == 'end'


# --- Java class resolution, self-check and main ---------------------------------------------------------------------------------------

def fake_importer(missing=(), flags=None):
    table = dict(flags or script.EXPECTED_OPERAND_FLAGS)

    def import_module(name):
        modules = {}
        for module_name, attr in script.REQUIRED_CLASSES:
            if f'{module_name}.{attr}' in missing:
                continue
            value = SimpleNamespace(**table) if attr == 'OperandType' else SimpleNamespace(name=attr)
            modules.setdefault(module_name, SimpleNamespace())
            setattr(modules[module_name], attr, value)
        if name not in modules:
            raise ImportError(name)
        return modules[name]
    return SimpleNamespace(import_module=import_module)


def test_java_load_resolves_all_classes_and_checks_the_operand_flag_table(monkeypatch):
    monkeypatch.setattr(script, 'importlib', fake_importer())
    assert script.Java().load().missing == []
    monkeypatch.setattr(script, 'importlib', fake_importer(missing=('ghidra.program.model.scalar.Scalar',)))
    assert script.Java().load().missing == ['ghidra.program.model.scalar.Scalar']
    wrong = dict(script.EXPECTED_OPERAND_FLAGS, ADDRESS=0x1)
    monkeypatch.setattr(script, 'importlib', fake_importer(flags=wrong))
    assert script.Java().load().missing == ['operand-flags']
    partial = {k: v for k, v in script.EXPECTED_OPERAND_FLAGS.items() if k != 'COP'}
    monkeypatch.setattr(script, 'importlib', fake_importer(flags=partial))
    assert script.Java().load().missing == ['operand-flags']


def test_script_self_check_lists_missing_classes(monkeypatch, capsys):
    monkeypatch.setattr(script, 'start_jvm', lambda *args: None)
    monkeypatch.setattr(script, 'importlib', fake_importer(missing=('ghidra.base.project.GhidraProject',
                                                                    'java.io.File')))
    assert script.self_check('/ghidra') == 4
    report = json.loads(capsys.readouterr().out)['self_check']
    assert report['ok'] is False and report['missing'] == ['ghidra.base.project.GhidraProject', 'java.io.File']
    monkeypatch.setattr(script, 'importlib', fake_importer())
    assert script.self_check('/ghidra') == 0
    assert json.loads(capsys.readouterr().out)['self_check']['ok'] is True


def test_self_check_needs_an_install_directory(monkeypatch, capsys):
    monkeypatch.delenv('GHIDRA_INSTALL_DIR', raising=False)
    assert script.self_check() == 4
    assert json.loads(capsys.readouterr().out)['self_check'] == {'ok': False, 'missing': ['GHIDRA_INSTALL_DIR']}


def test_start_jvm_reports_missing_pyghidra_and_launcher_failures(monkeypatch):
    monkeypatch.setitem(sys.modules, 'pyghidra', None)
    monkeypatch.setitem(sys.modules, 'pyghidra.launcher', None)
    with pytest.raises(script.ScriptExit) as caught:
        script.start_jvm('/ghidra', 1024)
    assert (caught.value.code, caught.value.reason) == (4, 'pyghidra-missing')

    started = []

    class Launcher:
        def __init__(self, install_dir):
            started.append(('init', str(install_dir)))

        def add_vmargs(self, *args):
            started.append(('vmargs', args))

        def start(self):
            started.append(('start',))

    monkeypatch.setitem(sys.modules, 'pyghidra.launcher', SimpleNamespace(HeadlessPyGhidraLauncher=Launcher))
    script.start_jvm('/ghidra', 2048)
    assert started == [('init', str(Path('/ghidra'))), ('vmargs', ('-Xmx2048m',)), ('start',)]

    class Failing(Launcher):
        def start(self):
            raise RuntimeError('no JVM here: /secret/path')

    monkeypatch.setitem(sys.modules, 'pyghidra.launcher', SimpleNamespace(HeadlessPyGhidraLauncher=Failing))
    with pytest.raises(script.ScriptExit) as caught:
        script.start_jvm('/ghidra', 2048)
    assert caught.value.reason == 'jvm-start' and '/secret' not in str(caught.value)


@pytest.fixture
def quiet_signals(monkeypatch):
    """main() installs signal handlers; keep pytest's own SIGINT handling intact."""
    recorded = []
    fake = SimpleNamespace(SIGTERM=15, SIGINT=2, SIGBREAK=21, signal=lambda number, handler: recorded.append(number))
    monkeypatch.setattr(script, 'signal', fake)
    return recorded


def run_main(argv, capsys):
    code = script.main(argv)
    captured = capsys.readouterr()
    lines = [json.loads(line) for line in captured.out.splitlines() if line.startswith('{')]
    return code, lines, captured.err


def test_main_exit_codes_and_error_documents(tmp_path, monkeypatch, capsys, quiet_signals):
    monkeypatch.setenv('GHIDRA_INSTALL_DIR', str(tmp_path / 'ghidra'))
    assert run_main([], capsys)[:2] == (2, [{'error': {'reason': 'bad-request'}}])
    assert run_main(['--request', str(tmp_path / 'absent.json')], capsys)[:2] == (2, [{'error': {'reason': 'bad-request'}}])
    assert set(quiet_signals) >= {2, 15}

    (tmp_path / 'out').mkdir()
    (tmp_path / 'work').mkdir()
    artifact = tmp_path / 'a.dll'
    artifact.write_bytes(b'MZ not the expected content')
    request = write_request(tmp_path, valid_request(tmp_path))
    assert run_main(['--request', request], capsys)[:2] == (3, [{'error': {'reason': 'artifact-hash'}}])
    assert json.loads((tmp_path / 'out' / 'progress.json').read_text(encoding='utf-8'))['phase'] == 'start'

    decompile = write_request(tmp_path, valid_request(tmp_path, mode='decompile'), 'decompile.json')
    assert run_main(['--request', decompile], capsys)[:2] == (4, [{'error': {'reason': 'unsupported-mode'}}])


def test_main_reports_crashes_by_class_name_only(tmp_path, monkeypatch, capsys, quiet_signals):
    def explode(request):
        raise ValueError('secret /home/victim/path')

    monkeypatch.setattr(script, 'run', explode)
    monkeypatch.setattr(script, 'load_request', lambda path: {})
    code, lines, err = run_main(['--request', 'x'], capsys)
    assert code == 1 and lines == [{'error': {'reason': 'crash'}}]
    assert 'ValueError' in err and 'secret' not in err and 'victim' not in err


def test_main_maps_keyboard_interrupt_to_cancelled(monkeypatch, capsys, quiet_signals):
    def interrupted(request):
        raise KeyboardInterrupt

    monkeypatch.setattr(script, 'run', interrupted)
    monkeypatch.setattr(script, 'load_request', lambda path: {})
    assert run_main(['--request', 'x'], capsys)[:2] == (5, [{'error': {'reason': 'cancelled'}}])


def test_signal_handler_sets_the_cancel_flag(monkeypatch):
    monkeypatch.setitem(script.CANCEL, 'flag', False)
    script._on_signal(15, None)
    assert script.CANCEL['flag'] is True
    monkeypatch.setitem(script.CANCEL, 'flag', False)


def test_probe_versions_are_clean_and_bounded():
    probe = script.probe_versions(JAVA)
    assert set(probe) == {'ghidra', 'pyghidra', 'java', 'python', 'script_sha256'}
    assert probe['ghidra'] == '12.0.4' and probe['java'] == '21.0.1' and len(probe['script_sha256']) == 64
    assert script.probe_versions(None)['ghidra'] == 'unknown'
    JAVA.missing = ['x']
    try:
        assert script.probe_versions(JAVA)['ghidra'] == 'unknown'
    finally:
        JAVA.missing = []


# --- run(): the Ghidra session control flow with a fake project ---------------------------------------------------------------------

class FakeFile:
    def __init__(self, path):
        self.path = path


class FakeProject:
    def __init__(self, program, log, close_fails=False):
        self.program, self.log, self.close_fails = program, log, close_fails

    def importProgram(self, file):
        self.log.append(('import', file.path))
        return self.program

    def saveAsPackedFile(self, program, file, overwrite):
        Path(file.path).write_bytes(b'GZF')
        self.log.append(('save', Path(file.path).name, overwrite))

    def close(self):
        self.log.append(('close',))
        if self.close_fails:
            raise RuntimeError('close failed')


@pytest.fixture
def session(tmp_path, monkeypatch):
    """Everything `run()` touches outside the target: JVM start, Ghidra classes, pyghidra.analyze."""
    artifact = tmp_path / 'a.dll'
    artifact.write_bytes(build_pe(PeSpec(kind='dll', image_base=BASE, sections=[SectionSpec('.text', b'\x90' * 64)])))
    packed = tmp_path / 'g.gzf'
    packed.write_bytes(b'packed program')
    for name in ('out', 'work'):
        (tmp_path / name).mkdir()
    log = []
    state = SimpleNamespace(log=log, analyzed=True, program=None, close_fails=False, missing=[], import_none=False,
                            artifact=artifact, packed=packed)

    def create_project(directory, name, temporary):
        log.append(('project', directory, name, temporary))
        return FakeProject(None if state.import_none else state.program, log, state.close_fails)

    def make_java():
        java = SimpleNamespace(**vars(JAVA))
        java.missing = list(state.missing)
        java.GhidraProject = SimpleNamespace(createProject=create_project)
        java.File = FakeFile
        java.GhidraProgramUtilities = SimpleNamespace(isAnalyzed=lambda program: state.analyzed)
        return java

    class Loader:
        def load(self):
            return make_java()

    monkeypatch.setattr(script, 'Java', Loader)
    monkeypatch.setattr(script, 'start_jvm', lambda directory, heap: log.append(('jvm', directory, heap)))
    monkeypatch.setattr(script, 'new_byte_array', lambda length: bytearray(length))
    monkeypatch.setitem(sys.modules, 'pyghidra', SimpleNamespace(analyze=lambda program: log.append(('analyze',))))
    monkeypatch.setenv('GHIDRA_INSTALL_DIR', str(tmp_path / 'ghidra'))
    program = program_with(2)
    program.getLanguageID = lambda: 'x86:LE:64:default'
    program.sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    program.options = Options({'PDB Universal': 'BOOLEAN_TYPE'})
    state.program = program
    state.request = lambda **change: dict(
        valid_request(tmp_path, artifact_path=str(artifact), artifact_sha256=program.sha), **change)
    return state


def gzf_request(session):
    digest = hashlib.sha256(session.packed.read_bytes()).hexdigest()
    return session.request(mode='gzf', gzf_path=str(session.packed), gzf_sha256=digest, analysis_options={})


def test_run_analyze_mode_imports_analyses_saves_the_gzf_and_writes_the_ir(session, tmp_path, capsys):
    assert script.run(session.request()) == 0
    steps = [entry[0] for entry in session.log]
    assert steps == ['jvm', 'project', 'import', 'analyze', 'save', 'close']
    assert session.log[0][2] == 4096 and session.log[1][1:] == (str(tmp_path / 'work'), 'pt', True)
    assert session.log[2][1] == str(session.artifact) and session.log[4] == ('save', 'program.gzf', True)
    assert (tmp_path / 'out' / 'program.gzf').read_bytes() == b'GZF' and (tmp_path / 'out' / 'ir.jsonl').is_file()
    assert session.program.log[0] == ('start', 'PatchTrace analysis options')          # PDB Universal=false applied
    assert json.loads(capsys.readouterr().out.splitlines()[0])['probe']['ghidra'] == '12.0.4'
    assert json.loads((tmp_path / 'out' / 'progress.json').read_text(encoding='utf-8'))['phase'] == 'done'


def test_run_gzf_mode_imports_the_retained_program_and_never_analyses(session, tmp_path):
    assert script.run(gzf_request(session)) == 0
    assert [e[0] for e in session.log] == ['jvm', 'project', 'import', 'close']
    assert session.log[2][1] == str(session.packed) and not (tmp_path / 'out' / 'program.gzf').exists()
    assert read_lines(tmp_path / 'out' / 'ir.jsonl')[0]['producer']['mode'] == 'gzf'


def test_run_refuses_a_gzf_that_was_not_analysed(session):
    session.analyzed = False
    with pytest.raises(script.ScriptExit) as caught:
        script.run(gzf_request(session))
    assert (caught.value.code, caught.value.reason) == (3, 'gzf-not-analyzed') and session.log[-1] == ('close',)


@pytest.mark.parametrize('what,reason', [('artifact', 'artifact-hash'), ('gzf', 'program-hash'),
                                         ('program', 'program-hash')])
def test_run_refuses_wrong_inputs_before_or_after_import(session, what, reason):
    request = gzf_request(session) if what == 'gzf' else session.request()
    if what == 'artifact':
        session.artifact.write_bytes(session.artifact.read_bytes() + b'\0')
    elif what == 'gzf':
        session.packed.write_bytes(b'another program')
    else:
        session.program.sha = 'ee' * 32
    with pytest.raises(script.ScriptExit) as caught:
        script.run(request)
    assert (caught.value.code, caught.value.reason) == (3, reason)
    started_jvm = 'jvm' in [entry[0] for entry in session.log]
    assert started_jvm == (what == 'program')                  # file hashes are checked before the JVM starts


def test_run_rejects_other_languages_unimportable_files_and_missing_classes(session):
    session.program.getLanguageID = lambda: 'x86:LE:32:default'
    with pytest.raises(script.ScriptExit) as caught:
        script.run(session.request())
    assert (caught.value.code, caught.value.reason) == (4, 'unsupported-language') and session.log[-1] == ('close',)
    session.program.getLanguageID = lambda: 'x86:LE:64:default'
    session.import_none = True
    with pytest.raises(script.ScriptExit) as caught:
        script.run(session.request())
    assert caught.value.reason == 'import-failed'
    session.import_none = False
    for missing, reason in ((['operand-flags'], 'operand-flags'),
                            (['ghidra.base.project.GhidraProject'], 'ghidra-version')):
        session.missing = missing
        with pytest.raises(script.ScriptExit) as caught:
            script.run(session.request())
        assert (caught.value.code, caught.value.reason) == (4, reason)


def test_run_needs_the_private_directories_and_the_install_dir(session, tmp_path, monkeypatch):
    with pytest.raises(script.ScriptExit) as caught:
        script.run(session.request(out_dir=str(tmp_path / 'absent')))
    assert (caught.value.code, caught.value.reason) == (2, 'bad-request')
    monkeypatch.delenv('GHIDRA_INSTALL_DIR')
    with pytest.raises(script.ScriptExit) as caught:
        script.run(session.request())
    assert (caught.value.code, caught.value.reason) == (4, 'ghidra-version')


def test_a_failing_project_close_never_masks_the_result(session):
    session.close_fails = True
    assert script.run(session.request()) == 0
    session.analyzed = False
    with pytest.raises(script.ScriptExit) as caught:
        script.run(gzf_request(session))
    assert caught.value.reason == 'gzf-not-analyzed'
