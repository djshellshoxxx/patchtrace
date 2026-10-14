"""Hand-built `ir-extract/1` documents for the S1 ingest tests (SPEC-31 03 s12.3).

Instruction encodings and masks are copied from real Ghidra 12.0.4 output (docs/specs/unified-engine/03-extraction.md
s12.1); the tiny assembler below covers only the shapes the tests need. Nothing here runs a binary."""
from __future__ import annotations

import json
import struct
from array import array
from pathlib import Path

from patchtrace.unified.ir.pe_tables import PeTables, Primary, Section

BASE = 0x180000000
SIZE = 0x5000
SHA = 'ab' * 32
TEXT = 0x1000


def pe_view(*, relocs=(), primaries=None, eh=None, warnings=()) -> PeTables:
    tables = PeTables(image_base=BASE, size_of_image=SIZE,
                      sections=(Section('.text', 0x1000, 0x2000, True), Section('.rdata', 0x2000, 0x3000, False),
                                Section('.data', 0x3000, 0x4000, False)),
                      relocs=array('I', sorted(relocs)), warnings=list(warnings))
    for begin, (end, chunks) in (primaries or {}).items():
        tables.primaries[begin] = Primary(begin, end, 0x2800, list(chunks))
    tables.eh.update(eh or {})
    return tables


def header(sha=SHA, *, mode='analyze', image_base=BASE, size=SIZE, analyzed=True, symbols=None, script='cd' * 32,
           options='ef' * 32, ghidra='12.0.4', language='x86:LE:64:default'):
    return {'type': 'header', 'contract': 'ir-extract/1', 'artifact_sha256': sha, 'program_sha256': sha,
            'image_base': image_base, 'size_of_image': size, 'language': language, 'compiler': 'windows',
            'producer': {'mode': mode, 'ghidra': ghidra, 'pyghidra': '3.0.2', 'java': '21.0.12', 'python': '3.12.10',
                         'script_sha256': script, 'analysis_options_digest': options, 'analyzed': analyzed,
                         'symbols': symbols or ('primary' if mode == 'gzf' else 'none')}}


def footer(functions, instructions, status='complete', warnings=()):
    return {'type': 'footer', 'functions': functions, 'instructions': instructions, 'status': status,
            'warnings': list(warnings)}


def _reg(name, optype=512, mask='0007'):
    return [optype, mask, [['reg', name]], []]


def _insn(off, raw, imask, flow, ops, mnem):
    return {'off': off, 'raw': raw, 'imask': imask, 'flow': flow, 'ops': ops, 'mnem': mnem}


def assemble(rva, spec):
    """spec = (name, *args) -> instruction dict with `length` (offsets are filled in by `function`)."""
    name = spec[0]
    if name == 'cmp':               # CMP ECX,imm8
        value = spec[1]
        return _insn(0, '83f9' + struct.pack('<b', value).hex(), 'fff800', 'FALL_THROUGH',
                     [[512, '000700', [['reg', 'ECX']], []], [16384, '0000ff', [['scalar', value]], []]], 'CMP')
    if name == 'mov':               # MOV EAX,EDX
        return _insn(0, '89d0', 'ffc0', 'FALL_THROUGH', [_reg('EAX'), _reg('EDX', mask='0038')], 'MOV')
    if name == 'movimm':            # MOV EAX,imm32
        value = spec[1]
        return _insn(0, 'b8' + struct.pack('<i', value).hex(), 'ff00000000', 'FALL_THROUGH',
                     [[512, '0000000000', [['reg', 'EAX']], []], [16384, '00ffffffff', [['scalar', value]], []]], 'MOV')
    if name == 'ret':
        return _insn(0, 'c3', 'ff', 'TERMINATOR', [], 'RET')
    if name == 'nop':
        return _insn(0, '90', 'ff', 'FALL_THROUGH', [], 'NOP')
    if name == 'int3':
        return _insn(0, 'cc', 'ff', 'FALL_THROUGH', [], 'INT3')
    if name in ('jcc', 'jmp'):      # rel8 branch to an absolute RVA; length 2
        target, opcode, mnem, flow = spec[1], (0x74 if name == 'jcc' else 0xEB), ('JZ' if name == 'jcc' else 'JMP'), (
            'CONDITIONAL_JUMP' if name == 'jcc' else 'UNCONDITIONAL_JUMP')
        rel = target - (rva + 2)
        return _insn(0, bytes((opcode, rel & 0xFF)).hex(), 'ff00', flow,
                     [[8256, '00ff', [['addr', target]], [[flow, f'rva:{target}']]]], mnem)
    if name == 'call':              # CALL rel32
        target = spec[1]
        rel = target - (rva + 5)
        return _insn(0, 'e8' + struct.pack('<i', rel).hex(), 'ff00000000', 'UNCONDITIONAL_CALL',
                     [[8256, '00ffffffff', [['addr', target]], [['UNCONDITIONAL_CALL', f'rva:{target}']]]], 'CALL')
    if name == 'lea':               # LEA RDX,[rip + disp32] -> target
        target = spec[1]
        rel = target - (rva + 7)
        return _insn(0, '488d15' + struct.pack('<i', rel).hex(), 'f8ffc700000000', 'FALL_THROUGH',
                     [[512, '00003800000000', [['reg', 'RDX']], []],
                      [24576, '000000ffffffff', [['scalar', BASE + target]], [['DATA', f'rva:{target}']]]], 'LEA')
    if name == 'iatcall':           # CALL qword ptr [IAT slot] with an import key
        slot, key = spec[1], spec[2]
        rel = slot - (rva + 6)
        return _insn(0, 'ff15' + struct.pack('<i', rel).hex(), 'ffff00000000', 'COMPUTED_CALL',
                     [[8320, '0000ffffffff', [['addr', slot]], [['READ', f'ext:{key}']]]], 'CALL')
    raise ValueError(name)


def function(rva, specs, *, name='f', blocks=None, calls=(), strings=(), kind='normal', imp=None, thunk_target=None,
             aliases=(), name_src='USER_DEFINED', ranges=None, texts=None, raw_override=None, truncated=False):
    """One `fn` line. `blocks` = [(start_index, [succ block indexes], [kinds])] over the instruction list; default one."""
    instructions, offset, cursor = [], 0, rva
    for spec in specs:
        item = assemble(cursor, spec)
        item['off'] = offset
        instructions.append(item)
        offset += len(item['raw']) // 2
        cursor += len(item['raw']) // 2
    raw = ''.join(i['raw'] for i in instructions)
    insns = [[i['off'], len(i['raw']) // 2, i['mnem'], i['imask'], i['ops'], i['flow']] for i in instructions]
    starts = [rva + i['off'] for i in instructions]
    if blocks is None:
        blocks = [(0, [], [])]
    block_records = []
    for number, (first, succ, kinds) in enumerate(blocks):
        last = blocks[number + 1][0] if number + 1 < len(blocks) else len(instructions)
        length = sum(len(instructions[k]['raw']) // 2 for k in range(first, last))
        block_records.append([starts[first], length, last - first, [starts[blocks[s][0]] for s in succ], list(kinds)])
    return {'type': 'fn', 'rva': rva, 'ranges': ranges or [[rva, offset]], 'name': name, 'name_src': name_src,
            'aliases': list(aliases), 'kind': kind, 'thunk_target': thunk_target, 'import': imp, 'lib': False,
            'raw': raw_override if raw_override is not None else raw, 'truncated': truncated, 'blocks': block_records,
            'insns': insns, 'calls': [list(c) for c in calls], 'strings': [list(s) for s in strings],
            'text': texts if texts is not None else [f'{i["mnem"]} #{k}' for k, i in enumerate(instructions)]}


def write_jsonl(path: Path, documents) -> Path:
    with open(path, 'w', encoding='utf-8', newline='\n') as handle:
        for document in documents:
            handle.write(json.dumps(document, separators=(',', ':')) + '\n')
    return path


def instruction_count(*functions) -> int:
    return sum(len(fn['insns']) for fn in functions)


def document_set(*functions, sha=SHA, mode='analyze', **header_kwargs):
    return [header(sha, mode=mode, **header_kwargs), *functions, footer(len(functions), instruction_count(*functions))]
