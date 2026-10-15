"""Hand-assembled x86-64 snippets -> `ir-extract/1` documents -> the REAL ingest -> `IrReader` (SPEC-31 S3 tests).

Encodings and Ghidra-style masks (instruction mask, per-operand value masks, operand types, reference lists) are
copied from the REAL Ghidra 12.0.4 records in tests/fixtures/unified/*.ir.jsonl (see 03 s12.1); the assembler covers
only the shapes the S3 tests need. Basic blocks are derived the way Ghidra's simple block model derives them for
these shapes (a call does not end a block; a direct branch, a return, a computed jump and a tail call do). Nothing
here executes a binary, so a result built from it is a synthetic unit test, never live evidence.

A function is a list of items: `('label', name)` or an instruction tuple (see `ENCODERS`). Branch targets are
labels of the same function; `sym` maps names to RVAs for functions (call targets) and globals.
"""
from __future__ import annotations

import hashlib
import json
import struct
import tempfile
from pathlib import Path

from unified_extract_builder import BASE, SIZE, footer, header, pe_view, write_jsonl

from patchtrace.unified.ir.ingest import ExpectedSide, ingest
from patchtrace.unified.ir.pe_tables import PeTables, Section
from patchtrace.unified.ir.reader import IrReader

OLD_SHA, NEW_SHA = '11' * 32, '22' * 32
TEXT, RDATA, DATA = 0x1000, 0x2000, 0x3000
SECTIONS = ((TEXT, 0x2000), (RDATA, 0x3000), (DATA, 0x4000))      # (start, end); .text executable
DATA_SECTIONS = ((RDATA, 0x3000), (DATA, 0x4000))

R32 = {'EAX': 0, 'ECX': 1, 'EDX': 2, 'EBX': 3, 'ESP': 4, 'EBP': 5, 'ESI': 6, 'EDI': 7}
R64 = {'RAX': 0, 'RCX': 1, 'RDX': 2, 'RBX': 3, 'RSP': 4, 'RBP': 5, 'RSI': 6, 'RDI': 7}
R8 = {'AL': 0, 'CL': 1, 'DL': 2, 'BL': 3}
CC = {'O': 0, 'NO': 1, 'C': 2, 'NC': 3, 'Z': 4, 'NZ': 5, 'BE': 6, 'A': 7, 'S': 8, 'NS': 9, 'P': 10, 'NP': 11,
      'L': 12, 'GE': 13, 'LE': 14, 'G': 15}
OPT_REG, OPT_SCALAR, OPT_ADDR_DATA, OPT_ADDR_CODE, OPT_DYN = 512, 16384, 8320, 8256, 4194304
OPT_ADDR_DYN, OPT_LEA_SCALAR, OPT_INDIRECT_ADDR = 4202496, 24576, 8324
FALL, COND, UNCOND, COMPUTED_JUMP = 'FALL_THROUGH', 'CONDITIONAL_JUMP', 'UNCONDITIONAL_JUMP', 'COMPUTED_JUMP'
CALL_FLOW, COMPUTED_CALL, TERMINATOR, CALL_TERMINATOR = 'UNCONDITIONAL_CALL', 'COMPUTED_CALL', 'TERMINATOR', \
    'CALL_TERMINATOR'


def _rel32(target: int, end: int) -> bytes:
    return struct.pack('<i', target - end)


def _dword(value: int) -> bytes:
    return struct.pack('<I', value & 0xFFFFFFFF)


class Resolver:
    """Names -> RVAs. `labels` are function-local; `sym` holds functions and globals."""

    def __init__(self, labels: dict[str, int], sym: dict[str, int], lenient: bool):
        self.labels, self.sym, self.lenient = labels, sym, lenient

    def __call__(self, name) -> int:
        if isinstance(name, int):
            return name
        if name in self.labels:
            return self.labels[name]
        if name in self.sym:
            return self.sym[name]
        if self.lenient:
            return 0
        raise KeyError(f'unknown label or symbol {name!r}')


def _insn(raw: bytes, imask: str, ops: list, mnem: str, flow: str, text: str, **meta) -> dict:
    return {'raw': raw, 'imask': imask, 'ops': ops, 'mnem': mnem, 'flow': flow, 'text': text, **meta}


def _va(rva: int) -> str:
    return f'0x{BASE + rva:x}'


# --- encoders: (rva, resolver, *args) -> instruction dict ---------------------------------------------------------------

def e_mov_rr(rva, r, dst, src):
    raw = bytes((0x89, 0xC0 | R32[src] << 3 | R32[dst]))
    return _insn(raw, 'ffc0', [[OPT_REG, '0007', [['reg', dst]], []], [OPT_REG, '0038', [['reg', src]], []]], 'MOV',
                 FALL, f'MOV {dst},{src}')


def e_mov_ri(rva, r, dst, value):
    raw = bytes((0xB8 + R32[dst],)) + _dword(value)
    return _insn(raw, 'f800000000', [[OPT_REG, '0700000000', [['reg', dst]], []],
                                     [OPT_SCALAR, '00ffffffff', [['scalar', value]], []]], 'MOV', FALL,
                 f'MOV {dst},0x{value:x}')


def _group1(rva, r, opcode_base, mnem, reg, value, wide=False):
    if wide:
        raw = bytes((0x81, opcode_base | R32[reg])) + struct.pack('<i', value)
        mask = '0000ffffffff'
        ops = [[OPT_REG, '000700000000', [['reg', reg]], []], [OPT_SCALAR, mask, [['scalar', value]], []]]
        return _insn(raw, 'fff800000000', ops, mnem, FALL, f'{mnem} {reg},0x{value:x}')
    raw = bytes((0x83, opcode_base | R32[reg])) + struct.pack('<b', value)
    return _insn(raw, 'fff800', [[OPT_REG, '000700', [['reg', reg]], []], [OPT_SCALAR, '0000ff', [['scalar', value]], []]],
                 mnem, FALL, f'{mnem} {reg},0x{value:x}')


def e_cmp_ri(rva, r, reg, value, wide=False):
    return _group1(rva, r, 0xF8, 'CMP', reg, value, wide)


def e_add_ri(rva, r, reg, value, wide=False):
    return _group1(rva, r, 0xC0, 'ADD', reg, value, wide)


def e_sub_ri(rva, r, reg, value, wide=False):
    return _group1(rva, r, 0xE8, 'SUB', reg, value, wide)


def _rsp_adjust(rva, r, modrm, mnem, value):
    raw = bytes((0x48, 0x83, modrm)) + struct.pack('<b', value)
    return _insn(raw, 'f8fff800', [[OPT_REG, '00000700', [['reg', 'RSP']], []],
                                   [OPT_SCALAR, '000000ff', [['scalar', value]], []]], mnem, FALL,
                 f'{mnem} RSP,0x{value:x}')


def e_sub_rsp(rva, r, value):
    return _rsp_adjust(rva, r, 0xEC, 'SUB', value)


def e_add_rsp(rva, r, value):
    return _rsp_adjust(rva, r, 0xC4, 'ADD', value)


def e_test_rr(rva, r, a, b):
    raw = bytes((0x85, 0xC0 | R32[b] << 3 | R32[a]))
    return _insn(raw, 'ffc0', [[OPT_REG, '0007', [['reg', a]], []], [OPT_REG, '0038', [['reg', b]], []]], 'TEST', FALL,
                 f'TEST {a},{b}')


def e_xor_rr(rva, r, a, b):
    raw = bytes((0x31, 0xC0 | R32[b] << 3 | R32[a]))
    return _insn(raw, 'ffc0', [[OPT_REG, '0007', [['reg', a]], []], [OPT_REG, '0038', [['reg', b]], []]], 'XOR', FALL,
                 f'XOR {a},{b}')


def e_nop(rva, r):
    return _insn(b'\x90', 'ff', [], 'NOP', FALL, 'NOP')


def e_int3(rva, r):
    return _insn(b'\xcc', 'ff', [], 'INT3', FALL, 'INT3')


def e_ret(rva, r):
    return _insn(b'\xc3', 'ff', [], 'RET', TERMINATOR, 'RET')


def _branch_op(target: int, flow: str, length: int) -> list:
    ref = [[flow, f'rva:{target}']]
    return [[OPT_ADDR_CODE, '00' * (length - 1) + 'ff' if length == 2 else '00ffffffff', [['addr', target]], ref]]


def e_jcc(rva, r, cc, label):
    target = r(label)
    raw = bytes((0x70 + CC[cc], (target - (rva + 2)) & 0xFF))
    return _insn(raw, 'ff00', _branch_op(target, COND, 2), f'J{cc}', COND, f'J{cc} {_va(target)}', branch=target)


def e_jmp(rva, r, label):
    target = r(label)
    raw = bytes((0xEB, (target - (rva + 2)) & 0xFF))
    return _insn(raw, 'ff00', _branch_op(target, UNCOND, 2), 'JMP', UNCOND, f'JMP {_va(target)}', branch=target)


def e_call(rva, r, name):
    target = r(name)
    return _insn(b'\xe8' + _rel32(target, rva + 5), 'ff00000000', _branch_op(target, 'UNCONDITIONAL_CALL', 5),
                 'CALL', CALL_FLOW, f'CALL {_va(target)}', call=(target, None, 'call'))


def e_tail_call(rva, r, name):
    target = r(name)
    return _insn(b'\xe9' + _rel32(target, rva + 5), 'ff00000000', _branch_op(target, 'UNCONDITIONAL_CALL', 5),
                 'JMP', CALL_TERMINATOR, f'JMP {_va(target)}', call=(target, None, 'call'), terminal=True)


def e_call_iat(rva, r, slot, key):
    slot = r(slot)
    return _insn(b'\xff\x15' + _rel32(slot, rva + 6), 'ffff00000000',
                 [[OPT_ADDR_DATA, '0000ffffffff', [['addr', slot]], [['READ', 'ext:' + key]]]], 'CALL', COMPUTED_CALL,
                 f'CALL qword ptr [{_va(slot)}]', call=(None, key, 'call'))


def e_jmp_iat(rva, r, slot, key):
    slot = r(slot)
    return _insn(b'\xff\x25' + _rel32(slot, rva + 6), 'ffff00000000',
                 [[OPT_INDIRECT_ADDR, '0000ffffffff', [['addr', slot]], [['INDIRECTION', 'ext:' + key]]]], 'JMP',
                 COMPUTED_JUMP, f'JMP qword ptr [{_va(slot)}]', call=(None, key, 'jump'), terminal=True)


def e_call_reg(rva, r, reg):
    return _insn(bytes((0xFF, 0xD0 | R64[reg])), 'fff8', [[OPT_REG, '0007', [['reg', reg]], []]], 'CALL',
                 COMPUTED_CALL, f'CALL {reg}', call=(None, None, 'call'))


def e_switch_jmp(rva, r, reg, labels):
    return _insn(bytes((0xFF, 0xE0 | R64[reg])), 'fff8', [[516, '0007', [['reg', reg]], []]], 'JMP', COMPUTED_JUMP,
                 f'JMP {reg}', switch=[r(label) for label in labels], terminal=True)


def e_load_g(rva, r, reg, data, string=None):
    target = r(data)
    raw = bytes((0x8B, 0x05 | R32[reg] << 3)) + _rel32(target, rva + 6)
    return _insn(raw, 'ffc700000000', [[OPT_REG, '003800000000', [['reg', reg]], []],
                                       [OPT_ADDR_DATA, '0000ffffffff', [['addr', target]], [['READ', f'rva:{target}']]]],
                 'MOV', FALL, f'MOV {reg},dword ptr [{_va(target)}]', string=string, data=target)


def e_store_g(rva, r, data, reg):
    target = r(data)
    raw = bytes((0x89, 0x05 | R32[reg] << 3)) + _rel32(target, rva + 6)
    return _insn(raw, 'ffc700000000', [[OPT_ADDR_DATA, '0000ffffffff', [['addr', target]], [['WRITE', f'rva:{target}']]],
                                       [OPT_REG, '003800000000', [['reg', reg]], []]],
                 'MOV', FALL, f'MOV dword ptr [{_va(target)}],{reg}', data=target)


def e_lea_g(rva, r, reg, data, string=None):
    target = r(data)
    raw = bytes((0x48, 0x8D, 0x05 | R64[reg] << 3)) + _rel32(target, rva + 7)
    return _insn(raw, 'f8ffc700000000', [[OPT_REG, '00003800000000', [['reg', reg]], []],
                                         [OPT_LEA_SCALAR, '000000ffffffff', [['scalar', BASE + target]],
                                          [['DATA', f'rva:{target}']]]],
                 'LEA', FALL, f'LEA {reg},[{_va(target)}]', string=string, data=target)


def e_load_m(rva, r, reg, base, disp):
    """MOV reg32, dword ptr [base64 + disp8] with a non-frame base (a struct field read)."""
    raw = bytes((0x8B, 0x40 | R32[reg] << 3 | R64[base])) + struct.pack('<b', disp)
    return _insn(raw, 'ffc000', [[OPT_REG, '003800', [['reg', reg]], []],
                                 [OPT_DYN, '0007ff', [['reg', base], ['scalar', disp]], []]], 'MOV', FALL,
                 f'MOV {reg},dword ptr [{base} + 0x{disp:x}]')


def e_store_m(rva, r, base, disp, reg):
    raw = bytes((0x89, 0x40 | R32[reg] << 3 | R64[base])) + struct.pack('<b', disp)
    return _insn(raw, 'ffc000', [[OPT_DYN, '0007ff', [['reg', base], ['scalar', disp]], []],
                                 [OPT_REG, '003800', [['reg', reg]], []]], 'MOV', FALL,
                 f'MOV dword ptr [{base} + 0x{disp:x}],{reg}')


def e_load_s(rva, r, reg, disp):
    """MOV reg32, dword ptr [RSP + disp8]: a stack operand with a stack reference."""
    raw = bytes((0x8B, 0x44 | R32[reg] << 3, 0x24)) + struct.pack('<b', disp)
    return _insn(raw, 'ffc73800', [[OPT_REG, '00380000', [['reg', reg]], []],
                                   [OPT_ADDR_DYN, '000007ff', [['reg', 'RSP'], ['scalar', disp]], [['READ', f'stack:{disp}']]]], 'MOV', FALL,
                 f'MOV {reg},dword ptr [RSP + 0x{disp:x}]')


def e_store_s(rva, r, disp, reg):
    raw = bytes((0x89, 0x44 | R32[reg] << 3, 0x24)) + struct.pack('<b', disp)
    return _insn(raw, 'ffc73800', [[OPT_ADDR_DYN, '000007ff', [['reg', 'RSP'], ['scalar', disp]], [['WRITE', f'stack:{disp}']]],
                                    [OPT_REG, '00380000', [['reg', reg]], []]], 'MOV',
                 FALL, f'MOV dword ptr [RSP + 0x{disp:x}],{reg}')


def e_load_tab(rva, r, reg, base, index, table):
    """MOV reg32, dword ptr [base64 + index64*4 + table_rva]: an RVA-form table operand (SIB + disp32 = table RVA)."""
    target = r(table)
    raw = bytes((0x8B, 0x84 | R32[reg] << 3, 0x80 | R64[index] << 3 | R64[base])) + _dword(target)
    return _insn(raw, 'ffc70000000000', [[OPT_REG, '00380000000000', [['reg', reg]], []],
                                         [OPT_ADDR_DYN, '0000ffffffffff', [['reg', base], ['reg', index], ['scalar', 4]],
                                          [['DATA', f'rva:{target}']]]],
                 'MOV', FALL, f'MOV {reg},dword ptr [{base} + {index}*0x4 + {_va(target)}]', data=target)


def e_setcc(rva, r, cc, reg8):
    return _insn(bytes((0x0F, 0x90 + CC[cc], 0xC0 | R8[reg8])), 'ffffc0', [[OPT_REG, '000007', [['reg', reg8]], []]],
                 f'SET{cc}', FALL, f'SET{cc} {reg8}')


def e_cmov(rva, r, cc, dst, src):
    raw = bytes((0x0F, 0x40 + CC[cc], 0xC0 | R32[dst] << 3 | R32[src]))
    return _insn(raw, 'ffffc0', [[OPT_REG, '000038', [['reg', dst]], []], [OPT_REG, '000007', [['reg', src]], []]],
                 f'CMOV{cc}', FALL, f'CMOV{cc} {dst},{src}')


ENCODERS = {
    'mov_rr': e_mov_rr, 'mov_ri': e_mov_ri, 'cmp_ri': e_cmp_ri, 'add_ri': e_add_ri, 'sub_ri': e_sub_ri,
    'sub_rsp': e_sub_rsp, 'add_rsp': e_add_rsp, 'test_rr': e_test_rr, 'xor_rr': e_xor_rr, 'nop': e_nop,
    'int3': e_int3, 'ret': e_ret, 'jcc': e_jcc, 'jmp': e_jmp, 'call': e_call, 'tail_call': e_tail_call,
    'call_iat': e_call_iat, 'jmp_iat': e_jmp_iat, 'call_reg': e_call_reg, 'switch_jmp': e_switch_jmp,
    'load_g': e_load_g, 'store_g': e_store_g, 'lea_g': e_lea_g, 'load_m': e_load_m, 'store_m': e_store_m,
    'load_s': e_load_s, 'store_s': e_store_s, 'load_tab': e_load_tab, 'setcc': e_setcc, 'cmov': e_cmov,
}


# --- layout, blocks, records ---------------------------------------------------------------------------------------------

def assemble(rva: int, items: list, sym: dict[str, int]) -> tuple[list[dict], dict[str, int]]:
    """Two passes: lengths first (targets are irrelevant to them), then the final encodings."""
    labels: dict[str, int] = {}
    cursor = rva
    for item in items:
        if item[0] == 'label':
            labels[item[1]] = cursor
        else:
            cursor += len(ENCODERS[item[0]](cursor, Resolver({}, sym, True), *item[1:])['raw'])
    out, cursor = [], rva
    resolver = Resolver(labels, sym, False)
    for item in items:
        if item[0] == 'label':
            continue
        encoded = ENCODERS[item[0]](cursor, resolver, *item[1:])
        encoded['rva'] = cursor
        out.append(encoded)
        cursor += len(encoded['raw'])
    return out, labels


def _blocks(rva: int, instructions: list[dict]) -> list[list]:
    leaders = {rva}
    for index, insn in enumerate(instructions):
        ends = insn['flow'] in (COND, UNCOND, TERMINATOR, COMPUTED_JUMP, CALL_TERMINATOR)
        if 'branch' in insn:
            leaders.add(insn['branch'])
        leaders.update(insn.get('switch', ()))
        if ends and index + 1 < len(instructions):
            leaders.add(instructions[index + 1]['rva'])
    starts = sorted(leaders)
    own = {insn['rva'] for insn in instructions}
    starts = [s for s in starts if s in own]
    out = []
    for number, start in enumerate(starts):
        stop = starts[number + 1] if number + 1 < len(starts) else None
        members = [i for i in instructions if i['rva'] >= start and (stop is None or i['rva'] < stop)]
        last = members[-1]
        end = last['rva'] + len(last['raw'])
        edges: list[tuple[int, str]] = []
        if last['flow'] == COND:
            edges = [(last['branch'], 'cond')] + ([(end, 'fall')] if stop is not None else [])
        elif last['flow'] == UNCOND:
            edges = [(last['branch'], 'jump')]
        elif last.get('switch'):
            edges = [(t, 'switch') for t in dict.fromkeys(last['switch'])]
        elif last['flow'] in (TERMINATOR, CALL_TERMINATOR, COMPUTED_JUMP):
            edges = []
        elif stop is not None:
            edges = [(stop, 'fall')]
        order = {'fall': 0, 'jump': 1, 'cond': 2, 'switch': 3, 'call-return': 4}
        edges = [(t, k) for t, k in edges if t in starts]          # Ghidra keeps successors of the same function only
        edges.sort(key=lambda item: (item[0], order[item[1]]))
        out.append([start, end - start, len(members), [t for t, _ in edges], [k for _, k in edges]])
    return out


def function(rva: int, items: list, *, name: str = 'f', sym: dict[str, int] | None = None, kind: str = 'normal',
             thunk_target: int | None = None, imp: dict | None = None, name_src: str = 'USER_DEFINED',
             aliases: tuple = (), blocks: list | None = None) -> dict:
    """One `fn` line (`ir-extract/1`). `blocks` overrides the derived blocks: [[start, length, n_insn, succ, kinds]]."""
    instructions, _labels = assemble(rva, items, sym or {})
    raw = b''.join(i['raw'] for i in instructions)
    insns, calls, strings, offset = [], [], [], 0
    for insn in instructions:
        length = len(insn['raw'])
        insns.append([offset, length, insn['mnem'], insn['imask'], insn['ops'], insn['flow']])
        offset += length
        if 'call' in insn:
            target, key, ckind = insn['call']
            calls.append([insn['rva'], target, key, ckind])
        if insn.get('string') is not None:
            text = insn['string']
            strings.append([insn['rva'], hashlib.sha256(text.encode('utf-8')).hexdigest(), len(text), text[:64]])
    return {'type': 'fn', 'rva': rva, 'ranges': [[rva, len(raw)]], 'name': name, 'name_src': name_src,
            'aliases': list(aliases), 'kind': kind, 'thunk_target': thunk_target, 'import': imp, 'lib': False,
            'raw': raw.hex(), 'truncated': False, 'blocks': blocks if blocks is not None else _blocks(rva, instructions),
            'insns': insns, 'calls': calls, 'strings': strings, 'text': [i['text'] for i in instructions]}


def sites(fn: dict) -> list[int]:
    """RVA of every instruction of a built `fn` line."""
    return [fn['rva'] + insn[0] for insn in fn['insns']]


# --- readers ------------------------------------------------------------------------------------------------------------

def eh_json(*, handler: int | None = None, scopes: list | None = None, codes: str = '0104010004', prolog: int = 4,
            flags: int = 0, version: int = 1) -> str:
    """The normalised EH signature of 03 s12.6 as `pe_tables` writes it."""
    document = {'v': 1, 'ver': version, 'fl': flags | (1 if handler is not None else 0), 'prolog': prolog,
                'frame': [0, 0], 'codes': codes, 'handler': handler,
                'hlen': None if scopes is None else 4 + 16 * len(scopes), 'scopes': scopes}
    return json.dumps(document, sort_keys=True, separators=(',', ':'))


def big_pe(size: int, *, eh: dict | None = None, warnings: tuple = ()) -> PeTables:
    """An image of `size` bytes whose code sections are .text (0x1000-0x2000) and everything from 0x4000 up."""
    tables = PeTables(image_base=BASE, size_of_image=size, warnings=list(warnings),
                      sections=(Section('.text', TEXT, RDATA, True), Section('.rdata', RDATA, 0x4000, False),
                                Section('.more', 0x4000, size, True)))
    tables.eh.update(eh or {})
    return tables


def build_reader(tmp_path: Path, label: str, functions: list[dict], *, sha: str, eh: dict | None = None,
                 warnings: tuple = (), size: int | None = None) -> IrReader:
    """Ingest `functions` for real and open the sidecar (the same code path as a production IR)."""
    n_insn = sum(len(f['insns']) for f in functions)
    work = Path(tempfile.mkdtemp(prefix=f'{label}-', dir=tmp_path))      # unique: a test may build several images
    path = write_jsonl(work / 'ir.jsonl', [header(sha, mode='analyze', size=size or SIZE), *functions,
                                           footer(len(functions), n_insn)])
    out = work / 'out'
    out.mkdir()
    pe = big_pe(size, eh=eh, warnings=warnings) if size else pe_view(eh=eh, warnings=warnings)
    result = ingest(path, ExpectedSide('older', sha, pe, mode='analyze'), out_dir=out)
    return IrReader.open(result.directory)


def build_pair(tmp_path: Path, old: list[dict], new: list[dict], *, old_eh: dict | None = None,
               new_eh: dict | None = None) -> tuple[IrReader, IrReader]:
    return (build_reader(tmp_path, 'old', old, sha=OLD_SHA, eh=old_eh),
            build_reader(tmp_path, 'new', new, sha=NEW_SHA, eh=new_eh))


# --- the whole chain: IR -> FactsContext -> verdict ----------------------------------------------------------------------

def decided(older: int, newer: int, *, decision: str = 'matched', tier: str = 'A'):
    """A decided row for a chosen pair; `mapped` (may map targets for proofs) iff matched with tier A or M."""
    from patchtrace.unified.contracts import Atom, Support
    from patchtrace.unified.fusion.arbiter import Decided
    atom = Atom(source='ghidriff', step='SymbolsHash', tier=tier, cardinality='1:1', cls='E-NAME', older_rva=older,
                newer_rva=newer)
    return Decided(older=(older,), newer=(newer,), decision=decision,
                   support=(Support(component='K1', tier=tier, atom_index=0),), contest=None, atoms=(atom,), hints=(),
                   pair=(older, newer), mapped=decision == 'matched' and tier in ('A', 'M'))


class Run:
    """The verdicts of every same-named function pair of two hand-built images."""

    def __init__(self, judged: dict, contexts, older: IrReader, newer: IrReader):
        self.judged, self.context, self.older, self.newer = judged, contexts, older, newer

    def __getitem__(self, name: str):
        return self.judged[name]

    def facts(self, name: str):
        return self.judged[name].facts

    def verdict(self, name: str) -> tuple[str, str | None]:
        facts = self.judged[name].facts
        return facts.verdict, facts.proof


def run_facts(tmp_path: Path, old: list[dict], new: list[dict], *, matches=(), identical: bool = False,
              sections=DATA_SECTIONS, tentative: tuple = (), old_eh: dict | None = None, new_eh: dict | None = None,
              bindiff: dict | None = None, names: tuple | None = None, limits=None, decompiled=None):
    """Build both images, match functions by name (tier A rows; `tentative` names get a tier-B row that maps nothing),
    collect the evidence and judge every pair. `decompiled` is the S3b side -> rva -> C text map."""
    from patchtrace.unified import keys
    from patchtrace.unified.addressing import AddressMap, PeLayout
    from patchtrace.unified.facts import verdict
    from patchtrace.unified.facts.channels import FactsContext
    from patchtrace.unified.facts.irchannels import IrSides
    from patchtrace.unified.limits import DEFAULT_LIMITS
    limits = limits or DEFAULT_LIMITS
    older, newer = build_pair(tmp_path, old, new, old_eh=old_eh, new_eh=new_eh)
    by_new = {f['name']: f['rva'] for f in new}
    rows = [decided(f['rva'], by_new[f['name']], tier='B' if f['name'] in tentative else 'A')
            for f in old if f['name'] in by_new and (names is None or f['name'] in names)]
    layout = PeLayout(image_base=BASE, size_of_image=SIZE)
    sides = IrSides(older, newer, older_sections=tuple(sections), newer_sections=tuple(sections), identical=identical)
    context = FactsContext.build(older_sha256=OLD_SHA, newer_sha256=NEW_SHA, addr=AddressMap(layout, layout),
                                 matches=list(matches), rows=rows, bindiff_flags=bindiff or {}, ir_sides=sides,
                                 limits=limits, decompiled=decompiled)
    names_by_rva = {f['rva']: f['name'] for f in old}
    judged = {names_by_rva[row.pair[0]]: verdict.judge(keys.row_id(OLD_SHA, NEW_SHA, row.older, row.newer),
                                                       row.decision, context.collect(row), limits) for row in rows}
    return Run(judged, context, older, newer)


__all__ = ['BASE', 'SIZE', 'OLD_SHA', 'NEW_SHA', 'SECTIONS', 'DATA_SECTIONS', 'function', 'build_reader', 'build_pair',
           'eh_json', 'sites', 'ENCODERS', 'decided', 'run_facts', 'Run']
