"""PatchTrace SPEC-31 ProgramIR extractor. Runs INSIDE the user's external Python (pyghidra + Ghidra), never in PatchTrace.

Rules (docs/specs/unified-engine/03-extraction.md s4, s12): imports only the standard library, `pyghidra`, `jpype`
(through pyghidra) and Ghidra/Java classes; never imports `patchtrace` or `ghidriff`; computes no hash beyond
SHA-256 of the input file, of the packaged script itself and of string values; writes only below `out_dir` and
`work_dir`; makes no network access; iterates deterministically (functions by ascending entry). The target binary
is only ever loaded as data by Ghidra, never executed.

usage: python pt_ir_extract.py --request request.json     (modes `gzf`, `analyze` and `decompile`)
       python pt_ir_extract.py --self-check                (no request; lists missing Ghidra classes)
`decompile` (05 s2.8, S3b) re-opens the retained GZF of one side, decompiles ONLY the requested RVAs and writes
`decomp.jsonl` (one `{side, rva, status, code}` line per RVA, status ok | timeout | failed); it writes no `ir.jsonl`.
Exit codes: 0 ok, 2 bad request, 3 input mismatch, 4 unsupported, 5 cancelled by signal, other = crash.
stdout: first line `{"probe": {...}}`; on failure the last line is `{"error": {"reason": "<slug>"}}`.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import math
import os
import platform
import re
import signal
import struct
import sys
import time
from bisect import bisect_right
from pathlib import Path

CONTRACT_REQUEST = 'ir-extract-request/1'
CONTRACT_EXTRACT = 'ir-extract/1'
EXIT_OK, EXIT_BAD_REQUEST, EXIT_MISMATCH, EXIT_UNSUPPORTED, EXIT_CANCELLED = 0, 2, 3, 4, 5
PROGRESS_EVERY = 500
MAX_RANGES = 64
MAX_ALIASES = 16
MAX_NAME = 512
MAX_TEXT = 256
MAX_PREFIX = 64
MAX_OPS = 6
MAX_OBJS = 8
MAX_REFS = 8
# OperandType flags of Ghidra 12.0.4 (03 s12.1). The ingest hard-codes ADDRESS, SCALAR, REGISTER, DYNAMIC and
# INDIRECT; the whole table is compared with the live class at start and on --self-check (exit 4, operand-flags).
EXPECTED_OPERAND_FLAGS = {
    'READ': 0x1, 'WRITE': 0x2, 'INDIRECT': 0x4, 'IMMEDIATE': 0x8, 'RELATIVE': 0x10, 'IMPLICIT': 0x20, 'CODE': 0x40,
    'DATA': 0x80, 'PORT': 0x100, 'REGISTER': 0x200, 'LIST': 0x400, 'FLAG': 0x800, 'TEXT': 0x1000, 'ADDRESS': 0x2000,
    'SCALAR': 0x4000, 'BIT': 0x8000, 'BYTE': 0x10000, 'WORD': 0x20000, 'QUADWORD': 0x40000, 'SIGNED': 0x80000,
    'FLOAT': 0x100000, 'COP': 0x200000, 'DYNAMIC': 0x400000,
}
REQUIRED_CLASSES = (
    ('ghidra.base.project', 'GhidraProject'), ('ghidra.framework', 'Application'),
    ('ghidra.program.model.address', 'Address'), ('ghidra.program.model.block', 'BasicBlockModel'),
    ('ghidra.program.model.lang', 'OperandType'), ('ghidra.program.model.lang', 'Register'),
    ('ghidra.program.model.listing', 'Program'), ('ghidra.program.model.scalar', 'Scalar'),
    ('ghidra.program.model.symbol', 'SourceType'), ('ghidra.program.util', 'GhidraProgramUtilities'),
    ('ghidra.util.task', 'TaskMonitor'), ('java.io', 'File'), ('java.lang', 'System'),
)
DECOMPILER_CLASSES = (('ghidra.app.decompiler', 'DecompInterface'),)    # `decompile` mode only (S3b)
_SOURCE_NAMES = ('DEFAULT', 'ANALYSIS', 'AI', 'IMPORTED', 'USER_DEFINED')
_HEX = re.compile(r'^[0-9a-f]{64}$')
_ORDINAL = re.compile(r'^(?:#|Ordinal_)(\d{1,6})$')
_ORDINAL_LABEL = re.compile(r'^Ordinal_\d{1,6}$')
_CONTROL = re.compile('[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]')
_CODE_CONTROL = re.compile('[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]')   # TAB and LF stay
_REQUEST_KEYS = ('contract', 'side', 'artifact_path', 'artifact_sha256', 'mode', 'gzf_path', 'gzf_sha256', 'out_dir',
                 'work_dir', 'max_heap_mb', 'analysis_options', 'limits', 'decompile_rvas')
_DEFAULT_LIMITS = {'l01_functions_per_side': 250_000, 'l02_instructions_per_side': 20_000_000,
                   'l05_string_bytes': 64 * 1024, 'l06_fn_raw_bytes': 16 * 1024 * 1024,
                   'l06_fn_instructions': 100_000, 'l29_pseudo_chars': 2_000_000, 'l29_pseudo_lines': 20_000,
                   'l41_decompile_pairs': 64, 'l41_decompile_fn_s': 60, 'l41_decompile_run_s': 600}
CANCEL = {'flag': False}


class ScriptExit(Exception):
    """Controlled failure: `reason` is a slug the runner maps to a PT-UNIFIED code (03 s9, s12.7)."""

    def __init__(self, code: int, reason: str):
        super().__init__(f'{code}:{reason}')
        self.code = code
        self.reason = reason


# --- pure helpers (unit-tested without Ghidra) ---------------------------------------------------------------------

def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def analysis_options_digest(mode: str, options: dict) -> str:
    """Same definition as `patchtrace.unified.extract.analysis_options_digest` (a test pins both)."""
    return hashlib.sha256(canonical_json({'mode': mode, 'options': dict(options)}).encode('utf-8')).hexdigest()


def clean_text(value: object, limit: int) -> str:
    """Text for the JSONL: lone surrogates and control characters become '?', length capped."""
    text = str(value)
    if len(text) > limit:
        text = text[:limit]
    if text.isascii():
        return text if text.isprintable() else _CONTROL.sub('?', text)
    return _CONTROL.sub('?', text.encode('utf-8', 'replace').decode('utf-8'))


def dump_line(record: dict) -> str:
    return json.dumps(record, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def import_key(library: object, label: object, original: object = None) -> str:
    """`<dll lower case>!<name>` or `<dll lower case>!#<ordinal>` (03 s12.3)."""
    dll = clean_text(library or 'unknown', 128).lower().strip() or 'unknown'
    name = clean_text(original or label or 'unknown', 160).strip() or 'unknown'
    match = _ORDINAL.match(name) or _ORDINAL.match(clean_text(label or '', 40))
    return f'{dll}!#{match.group(1)}' if match else f'{dll}!{name}'


def import_parts(key: str) -> dict:
    dll, _, name = key.partition('!')
    match = re.fullmatch(r'#(\d{1,6})', name)
    return {'dll': dll, 'name': None if match else name, 'ordinal': int(match.group(1)) if match else None}


def hex_of(data: object) -> str | None:
    if data is None:
        return None
    return bytes(int(b) & 0xFF for b in data).hex()


def flow_kind(flow_name: str) -> str:
    """Edge kind of a block destination (03 s12.3)."""
    if flow_name in ('FALL_THROUGH',):
        return 'fall'
    if flow_name in ('UNCONDITIONAL_JUMP', 'JUMP_OVERRIDE_UNCONDITIONAL'):
        return 'jump'
    if flow_name in ('CONDITIONAL_JUMP',):
        return 'cond'
    if flow_name in ('COMPUTED_JUMP', 'CONDITIONAL_COMPUTED_JUMP'):
        return 'switch'
    return 'call-return'


def parse_pe_header(path: str) -> dict:
    """ImageBase and SizeOfImage of a PE32+ file straight from its headers (stdlib only)."""
    try:
        with open(path, 'rb') as stream:
            head = stream.read(4096)
            if len(head) < 0x40 or head[:2] != b'MZ':
                raise ScriptExit(EXIT_UNSUPPORTED, 'unsupported-format')
            lfanew = struct.unpack_from('<I', head, 0x3C)[0]
            if lfanew + 24 + 112 > len(head):
                stream.seek(0)
                head = stream.read(lfanew + 24 + 112 + 16)
            if lfanew + 24 + 60 > len(head) or head[lfanew:lfanew + 4] != b'PE\0\0':
                raise ScriptExit(EXIT_UNSUPPORTED, 'unsupported-format')
            optional = lfanew + 24
            if struct.unpack_from('<H', head, optional)[0] != 0x20B:
                raise ScriptExit(EXIT_UNSUPPORTED, 'unsupported-language')
            return {'image_base': struct.unpack_from('<Q', head, optional + 24)[0],
                    'size_of_image': struct.unpack_from('<I', head, optional + 56)[0]}
    except (OSError, struct.error):
        raise ScriptExit(EXIT_UNSUPPORTED, 'unsupported-format') from None


def file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        while chunk := stream.read(1 << 22):
            digest.update(chunk)
    return digest.hexdigest()


def _is_abs(value: object) -> bool:
    return isinstance(value, str) and (value.startswith('/') or bool(re.match(r'^[A-Za-z]:[\\/]', value)))


def load_request(path: str) -> dict:
    """Strict request validation (the runner wrote it with the S0a `ExtractRequest` model)."""
    def reject_constant(name):
        raise ValueError(name)

    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError('duplicate key')
            out[key] = value
        return out

    try:
        with open(path, 'rb') as stream:
            data = stream.read(1 << 20)
        request = json.loads(data.decode('utf-8'), object_pairs_hook=pairs, parse_constant=reject_constant)
    except (OSError, ValueError):
        raise ScriptExit(EXIT_BAD_REQUEST, 'bad-request') from None
    if not isinstance(request, dict) or set(request) != set(_REQUEST_KEYS) or request['contract'] != CONTRACT_REQUEST:
        raise ScriptExit(EXIT_BAD_REQUEST, 'bad-request')
    ok = (request['side'] in ('older', 'newer') and request['mode'] in ('gzf', 'analyze', 'decompile')
          and all(_is_abs(request[k]) for k in ('artifact_path', 'out_dir', 'work_dir'))
          and isinstance(request['artifact_sha256'], str) and _HEX.match(request['artifact_sha256'])
          and type(request['max_heap_mb']) is int and request['max_heap_mb'] >= 512
          and isinstance(request['analysis_options'], dict)
          and all(isinstance(k, str) and isinstance(v, str) for k, v in request['analysis_options'].items())
          and isinstance(request['limits'], dict)
          and all(isinstance(k, str) and type(v) is int and v >= 0 for k, v in request['limits'].items())
          and isinstance(request['decompile_rvas'], list))
    if request['mode'] in ('gzf', 'decompile'):
        ok = ok and _is_abs(request['gzf_path']) and isinstance(request['gzf_sha256'], str) \
            and bool(_HEX.match(request['gzf_sha256']))
    else:
        ok = ok and request['gzf_path'] is None and request['gzf_sha256'] is None
    ok = ok and _valid_rvas(request)
    if not ok:
        raise ScriptExit(EXIT_BAD_REQUEST, 'bad-request')
    return request


def _valid_rvas(request: dict) -> bool:
    """`decompile_rvas`: empty unless the mode is `decompile`, then 1..L-41 unique ascending non-negative integers."""
    rvas = request['decompile_rvas']
    if request['mode'] != 'decompile':
        return rvas == []
    cap = {**_DEFAULT_LIMITS, **request['limits']}['l41_decompile_pairs']
    return 0 < len(rvas) <= cap and all(type(rva) is int and rva >= 0 for rva in rvas) and rvas == sorted(set(rvas))


class ProgressFile:
    """`progress.json` {phase, done, total} (<= 4 KiB), written as `.part` then replaced (03 s3)."""

    def __init__(self, directory: str):
        self.path = os.path.join(directory, 'progress.json')

    def write(self, phase: str, done: int, total: int | None) -> None:
        text = json.dumps({'phase': phase, 'done': int(done), 'total': None if total is None else int(total)},
                          separators=(',', ':'))
        part = self.path + '.part'
        try:
            with open(part, 'w', encoding='utf-8', newline='\n') as stream:
                stream.write(text)
            os.replace(part, self.path)
        except OSError:
            pass  # progress is advisory; a locked file never fails the extraction


# --- Java access (duck-typed so tests can substitute fakes) -----------------------------------------------------

class Java:
    """Lazily resolved Ghidra/Java classes (03 s4). `load` raises ScriptExit(4, ...) naming the missing classes."""

    def __init__(self):
        self.missing: list[str] = []
        self.missing_decompiler: list[str] = []      # only `decompile` mode needs these

    def load(self) -> Java:
        for module_name, attr in REQUIRED_CLASSES:
            try:
                setattr(self, attr, getattr(importlib.import_module(module_name), attr))
            except (ImportError, AttributeError):
                self.missing.append(f'{module_name}.{attr}')
        for module_name, attr in DECOMPILER_CLASSES:
            try:
                setattr(self, attr, getattr(importlib.import_module(module_name), attr))
            except (ImportError, AttributeError):
                self.missing_decompiler.append(f'{module_name}.{attr}')
        if not self.missing:
            live = {}
            for name in EXPECTED_OPERAND_FLAGS:
                try:
                    live[name] = int(getattr(self.OperandType, name))
                except (AttributeError, TypeError, ValueError):
                    live[name] = None
            if live != EXPECTED_OPERAND_FLAGS:
                self.missing.append('operand-flags')
        return self


def start_jvm(ghidra_dir: str, heap_mb: int) -> None:
    """pyghidra.start() takes no VM arguments in 3.0.2, so the launcher object is used (03 s4)."""
    try:
        from pyghidra.launcher import HeadlessPyGhidraLauncher
    except ImportError:
        raise ScriptExit(EXIT_UNSUPPORTED, 'pyghidra-missing') from None
    try:
        launcher = HeadlessPyGhidraLauncher(install_dir=Path(ghidra_dir))
        launcher.add_vmargs(f'-Xmx{int(heap_mb)}m')
        launcher.start()
    except ScriptExit:
        raise
    except Exception:  # noqa: BLE001 - any launcher failure is "unsupported runtime", reported by slug only
        raise ScriptExit(EXIT_UNSUPPORTED, 'jvm-start') from None


def probe_versions(java: Java | None) -> dict:
    def version(name: str) -> str:
        try:
            from importlib import metadata
            return metadata.version(name)
        except Exception:  # noqa: BLE001
            return 'unknown'
    probe = {'ghidra': 'unknown', 'pyghidra': version('pyghidra'), 'java': 'unknown',
             'python': platform.python_version(), 'script_sha256': script_sha256()}
    if java is not None and not java.missing:
        try:
            probe['ghidra'] = str(java.Application.getApplicationVersion())
        except Exception:  # noqa: BLE001
            pass
        try:
            probe['java'] = str(java.System.getProperty('java.version'))
        except Exception:  # noqa: BLE001
            pass
    return {k: clean_text(v, 64) for k, v in probe.items()}


def script_sha256() -> str:
    try:
        return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except OSError:
        return '0' * 64


def self_check(ghidra_dir: str | None = None) -> int:
    """No request: starts a small JVM, resolves every class the script needs and prints what is missing."""
    ghidra_dir = ghidra_dir or os.environ.get('GHIDRA_INSTALL_DIR', '')
    if not ghidra_dir:
        _print({'self_check': {'ok': False, 'missing': ['GHIDRA_INSTALL_DIR']}})
        return EXIT_UNSUPPORTED
    start_jvm(ghidra_dir, 512)
    java = Java().load()
    missing = [*java.missing, *java.missing_decompiler]
    _print({'self_check': {'ok': not missing, 'missing': missing, 'versions': probe_versions(java)}})
    return EXIT_OK if not missing else EXIT_UNSUPPORTED


def _print(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, separators=(',', ':')) + '\n')
    sys.stdout.flush()


# --- extraction ---------------------------------------------------------------------------------------------------

class Context:
    """State shared by the per-function extraction helpers."""

    def __init__(self, java, program, base: int, size_of_image: int, limits: dict):
        self.java = java
        self.program = program
        self.base = base
        self.hi = base + size_of_image
        self.limits = {**_DEFAULT_LIMITS, **limits}
        self.listing = program.getListing()
        self.memory = program.getMemory()
        self.refman = program.getReferenceManager()
        self.symtab = program.getSymbolTable()
        self.blocks = java.BasicBlockModel(program)
        self.monitor = java.TaskMonitor.DUMMY
        self.masks: dict = {}
        self.slots: dict = {}
        self.strings: dict = {}
        self.warnings: dict[str, int] = {}
        self.instructions = 0

    def warn(self, slug: str) -> None:
        self.warnings[slug] = self.warnings.get(slug, 0) + 1

    def rva(self, address) -> int | None:
        """RVA of a memory address inside the image, else None (stack, register, external, other blocks)."""
        if address is None:
            return None
        try:
            if not address.isMemoryAddress():
                return None
            offset = int(address.getOffset())
        except Exception:  # noqa: BLE001 - fakes and exotic address spaces
            return None
        return offset - self.base if self.base <= offset < self.hi else None


def external_key(location) -> str:
    return import_key(location.getLibraryName(), location.getLabel(), _optional(location, 'getOriginalImportedName'))


def _optional(obj, method: str):
    try:
        value = getattr(obj, method)()
    except Exception:  # noqa: BLE001
        return None
    return None if value is None else str(value)


def slot_import_key(ctx: Context, address) -> str | None:
    """Import key when `address` is a pointer slot (IAT entry) holding an external reference."""
    offset = int(address.getOffset())
    if offset in ctx.slots:
        return ctx.slots[offset]
    key = None
    try:
        for reference in ctx.refman.getReferencesFrom(address):
            if reference.isExternalReference():
                key = external_key(reference.getExternalLocation())
                break
    except Exception:  # noqa: BLE001
        key = None
    ctx.slots[offset] = key
    return key


def operand_objs(ctx: Context, instruction, index: int) -> list:
    java = ctx.java
    out = []
    for obj in list(instruction.getOpObjects(index))[:MAX_OBJS]:
        if isinstance(obj, java.Register):
            out.append(['reg', str(obj.getName())[:16]])
        elif isinstance(obj, java.Scalar):
            out.append(['scalar', int(obj.getSignedValue())])
        elif isinstance(obj, java.Address):
            out.append(['addr', ctx.rva(obj)])
        else:
            ctx.warn('unknown-op-object')
    return out


def operand_refs(ctx: Context, instruction, index: int) -> tuple[list, list]:
    """(refs, memory targets): refs as in 03 s12.3, targets are the in-image addresses (for string detection)."""
    out, targets = [], []
    for reference in list(instruction.getOperandReferences(index))[:MAX_REFS]:
        name = str(reference.getReferenceType())[:40]
        if reference.isStackReference():
            out.append([name, f'stack:{int(reference.getStackOffset())}'])
        elif reference.isExternalReference():
            out.append([name, 'ext:' + external_key(reference.getExternalLocation())])
        elif reference.isMemoryReference():
            target = reference.getToAddress()
            rva = ctx.rva(target)
            if rva is None:
                continue
            key = slot_import_key(ctx, target)
            out.append([name, f'ext:{key}' if key is not None else f'rva:{rva}'])
            targets.append(target)
    return out, targets


def operand_record(ctx: Context, instruction, index: int, prototype) -> tuple[list, list]:
    mask = ctx.masks.get(('o', prototype, index))
    if mask is None:
        value = prototype.getOperandValueMask(index)
        mask = ctx.masks[('o', prototype, index)] = (hex_of(value.getBytes()) if value is not None else None,)
    refs, targets = operand_refs(ctx, instruction, index)
    return [int(instruction.getOperandType(index)), mask[0], operand_objs(ctx, instruction, index), refs], targets


def instruction_record(ctx: Context, instruction, offset: int) -> tuple[list, str, list]:
    prototype = instruction.getPrototype()
    mask = ctx.masks.get(('i', prototype))
    if mask is None:
        value = prototype.getInstructionMask()
        mask = ctx.masks[('i', prototype)] = (hex_of(value.getBytes()) if value is not None else None,)
    operands, targets = [], []
    for i in range(min(int(instruction.getNumOperands()), MAX_OPS)):
        record, found = operand_record(ctx, instruction, i, prototype)
        operands.append(record)
        targets += found
    record = [offset, int(instruction.getLength()), str(instruction.getMnemonicString())[:32], mask[0],
              operands, str(instruction.getFlowType())[:48]]
    return record, clean_text(instruction, MAX_TEXT), targets


def call_entries(ctx: Context, instruction, site: int, body) -> list:
    """`calls` of one instruction (03 s12.3): calls, and jumps that leave the function; imports by key."""
    flow = instruction.getFlowType()
    is_call = bool(flow.isCall())
    if not (is_call or flow.isJump()):
        return []
    kind = 'call' if is_call else 'jump'
    entries = []
    for reference in instruction.getReferencesFrom():
        ref_type = reference.getReferenceType()
        if not (ref_type.isCall() if is_call else ref_type.isJump()):
            continue
        target = reference.getToAddress()
        if reference.isExternalReference():
            entries.append([site, None, external_key(reference.getExternalLocation()), kind])
        elif bool(target.isExternalAddress()):
            continue
        else:
            rva = ctx.rva(target)
            if rva is None or (not is_call and body.contains(target)):
                continue
            entries.append([site, rva, None, kind])
    if is_call and not entries and flow.isComputed():
        entries.append([site, None, None, 'call'])  # unresolved indirect call: still a call (n_call)
    return entries


def string_entries(ctx: Context, targets: list, site: int) -> list:
    out = []
    for target in targets:
        offset = int(target.getOffset())
        if offset not in ctx.strings:
            ctx.strings[offset] = _string_at(ctx, target)
        found = ctx.strings[offset]
        if found is not None and [site, *found] not in out:
            out.append([site, *found])
    return out


def _string_at(ctx: Context, address):
    data = ctx.listing.getDataAt(address)
    if data is None or not data.hasStringValue():
        return None
    if int(data.getLength()) > ctx.limits['l05_string_bytes']:
        ctx.warn('string-too-long')
        return None
    value = str(data.getValue())
    text = value.encode('utf-8', 'replace')
    return [hashlib.sha256(text).hexdigest(), len(value), clean_text(value, MAX_PREFIX)]


def block_records(ctx: Context, body, instruction_rvas: list[int]) -> list:
    """Basic blocks of the function; successors are block starts of the same function only (03 s12.1 item 5)."""
    raw = []
    for block in ctx.blocks.getCodeBlocksContaining(body, ctx.monitor):
        start = ctx.rva(block.getFirstStartAddress())
        if start is None:
            continue
        edges = []
        iterator = block.getDestinations(ctx.monitor)
        while iterator.hasNext():
            reference = iterator.next()
            edges.append((ctx.rva(reference.getDestinationAddress()), flow_kind(str(reference.getFlowType()))))
        raw.append((start, int(block.getNumAddresses()), edges))
    raw.sort(key=lambda item: item[0])
    starts = [item[0] for item in raw]
    counts = [0] * len(raw)
    for rva in instruction_rvas:
        position = bisect_right(starts, rva) - 1
        if position >= 0:
            counts[position] += 1
    known = set(starts)
    order = {'fall': 0, 'jump': 1, 'cond': 2, 'switch': 3, 'call-return': 4}
    out = []
    for (start, length, edges), n_insn in zip(raw, counts, strict=True):
        kept = sorted(((t, k) for t, k in edges if t in known), key=lambda item: (item[0], order[item[1]]))
        out.append([start, length, n_insn, [t for t, _ in kept], [k for _, k in kept]])
    return out


def function_ranges(ctx: Context, body) -> list[list[int]]:
    ranges = []
    for item in body.getAddressRanges():
        rva = ctx.rva(item.getMinAddress())
        if rva is None:
            ctx.warn('range-outside-image')
            continue
        ranges.append([rva, int(item.getLength())])
    ranges.sort()
    return ranges


def read_raw(ctx: Context, body, ranges: list[list[int]]) -> bytes | None:
    java = ctx.java
    out = bytearray()
    for item in body.getAddressRanges():
        length = int(item.getLength())
        buffer = java.new_byte_array(length)
        try:
            ctx.memory.getBytes(item.getMinAddress(), buffer)
        except Exception:  # noqa: BLE001 - MemoryAccessException on uninitialised memory
            ctx.warn('raw-unreadable')
            return None
        out += _to_bytes(buffer)
    return bytes(out)


def _to_bytes(buffer) -> bytes:
    """Java byte[] -> bytes (signed values); the buffer protocol is much faster than a Python loop."""
    try:
        return bytes(memoryview(buffer).cast('B'))
    except (TypeError, ValueError, NotImplementedError):
        return bytes(int(b) & 0xFF for b in buffer)


def thunk_fields(ctx: Context, function) -> tuple[int | None, dict | None]:
    if not function.isThunk():
        return None, None
    target = function.getThunkedFunction(False)
    final = function.getThunkedFunction(True)
    thunk_rva = None
    if target is not None and not target.isExternal():
        thunk_rva = ctx.rva(target.getEntryPoint())
    imported = None
    if final is not None and final.isExternal():
        location = final.getExternalLocation()
        if location is not None:
            imported = import_parts(external_key(location))
    return thunk_rva, imported


def function_names(ctx: Context, function) -> tuple[str, str, list[str]]:
    symbol = function.getSymbol()
    source = clean_text(symbol.getSource() if symbol is not None else 'DEFAULT', 16)
    if source not in _SOURCE_NAMES:
        ctx.warn('unknown-name-source')
        source = 'DEFAULT'
    name = clean_text(function.getName(), MAX_NAME)
    aliases = set()
    try:
        for other in ctx.symtab.getSymbols(function.getEntryPoint()):
            label = clean_text(other.getName(), MAX_NAME)
            if label and label != name and not _ORDINAL_LABEL.match(label):   # PE export placeholders are no aliases
                aliases.add(label)
    except Exception:  # noqa: BLE001
        ctx.warn('aliases-unreadable')
    return name, source, sorted(aliases)[:MAX_ALIASES]


def extract_function(ctx: Context, function) -> dict | None:
    """One `fn` line of ir-extract/1 (03 s12.3) or None for a function outside the image."""
    entry = ctx.rva(function.getEntryPoint())
    if entry is None:
        ctx.warn('entry-outside-image')
        return None
    body = function.getBody()
    ranges = function_ranges(ctx, body)
    if not ranges:
        ctx.warn('empty-body')
        return None
    name, source, aliases = function_names(ctx, function)
    thunk_rva, imported = thunk_fields(ctx, function)
    record = {'type': 'fn', 'rva': entry, 'ranges': ranges[:MAX_RANGES], 'name': name, 'name_src': source,
              'aliases': aliases, 'kind': 'thunk' if function.isThunk() else 'normal', 'thunk_target': thunk_rva,
              'import': imported, 'lib': False, 'raw': None, 'truncated': False, 'blocks': [], 'insns': [],
              'calls': [], 'strings': [], 'text': []}
    total = sum(length for _, length in ranges)
    if len(ranges) > MAX_RANGES:
        ctx.warn('ranges-capped')
        record['truncated'] = True
        return record
    if total > ctx.limits['l06_fn_raw_bytes']:
        ctx.warn('function-oversize')
        return record
    raw = read_raw(ctx, body, ranges)
    if raw is None or len(raw) != total:
        return record
    starts, cursor = [], 0
    for rva, length in ranges:
        starts.append((rva, cursor, length))
        cursor += length

    def offset_of(rva: int) -> int:
        for start, base, length in starts:
            if start <= rva < start + length:
                return base + rva - start
        raise ValueError('instruction outside the function ranges')

    insns, texts, calls, strings, rvas = [], [], [], [], []
    limit = ctx.limits['l06_fn_instructions']
    for instruction in ctx.listing.getInstructions(body, True):
        if len(insns) >= limit:
            ctx.warn('function-truncated')
            record['truncated'] = True
            return record
        site = ctx.rva(instruction.getAddress())
        if site is None:
            ctx.warn('instruction-outside-image')
            return record
        item, text, targets = instruction_record(ctx, instruction, offset_of(site))
        insns.append(item)
        texts.append(text)
        rvas.append(site)
        calls += call_entries(ctx, instruction, site, body)
        strings += string_entries(ctx, targets, site)
    ctx.instructions += len(insns)
    record.update(raw=raw.hex(), insns=insns, text=texts, calls=calls, strings=strings,
                  blocks=block_records(ctx, body, rvas))
    return record


def set_analysis_options(java, program, options: dict) -> None:
    """Set boolean/int/long/string/double/float analysis options by their declared type (as Ghidriff does)."""
    properties = program.getOptions(java.Program.ANALYSIS_PROPERTIES)
    transaction = program.startTransaction('PatchTrace analysis options')
    try:
        for name in sorted(options):
            value = options[name]
            kind = str(properties.getType(name))
            if kind == 'BOOLEAN_TYPE':
                properties.setBoolean(name, value.strip().lower() == 'true')
            elif kind == 'INT_TYPE':
                properties.setInt(name, int(value))
            elif kind == 'LONG_TYPE':
                properties.setLong(name, int(value))
            elif kind == 'STRING_TYPE':
                properties.setString(name, value)
            elif kind == 'DOUBLE_TYPE':
                properties.setDouble(name, float(value))
            elif kind == 'FLOAT_TYPE':
                properties.setFloat(name, float(value))
            else:
                raise ScriptExit(EXIT_BAD_REQUEST, 'bad-option')
    except ValueError:
        raise ScriptExit(EXIT_BAD_REQUEST, 'bad-option') from None
    finally:
        program.endTransaction(transaction, True)


def new_byte_array(length: int):
    import jpype
    return jpype.JArray(jpype.JByte)(length)


def run(request: dict) -> int:
    """gzf / analyze extraction (03 s4) and the on-demand decompile of S3b (05 s2.8). Raises ScriptExit for every
    controlled failure."""
    out_dir, work_dir = request['out_dir'], request['work_dir']
    mode = request['mode']
    if not (os.path.isdir(out_dir) and os.path.isdir(work_dir)):
        raise ScriptExit(EXIT_BAD_REQUEST, 'bad-request')
    ghidra_dir = os.environ.get('GHIDRA_INSTALL_DIR', '')
    if not ghidra_dir:
        raise ScriptExit(EXIT_UNSUPPORTED, 'ghidra-version')
    progress = ProgressFile(out_dir)
    progress.write('start', 0, None)
    try:
        artifact_hash = file_sha256(request['artifact_path'])
    except OSError:
        raise ScriptExit(EXIT_MISMATCH, 'artifact-hash') from None
    if artifact_hash != request['artifact_sha256']:
        raise ScriptExit(EXIT_MISMATCH, 'artifact-hash')
    if mode in ('gzf', 'decompile') and file_sha256(request['gzf_path']) != request['gzf_sha256']:
        raise ScriptExit(EXIT_MISMATCH, 'program-hash')
    header_pe = parse_pe_header(request['artifact_path'])
    start_jvm(ghidra_dir, request['max_heap_mb'])
    java = Java().load()
    java.new_byte_array = new_byte_array
    _print({'probe': probe_versions(java)})
    if java.missing:
        raise ScriptExit(EXIT_UNSUPPORTED, 'operand-flags' if java.missing == ['operand-flags'] else 'ghidra-version')
    if mode == 'decompile' and getattr(java, 'missing_decompiler', None):
        raise ScriptExit(EXIT_UNSUPPORTED, 'decompiler-unavailable')
    project = java.GhidraProject.createProject(work_dir, 'pt', True)
    try:
        progress.write('import', 0, None)
        source = request['gzf_path'] if mode in ('gzf', 'decompile') else request['artifact_path']
        program = project.importProgram(java.File(source))
        if program is None:
            raise ScriptExit(EXIT_UNSUPPORTED, 'import-failed')
        language = str(program.getLanguageID())
        if not language.startswith('x86:LE:64'):
            raise ScriptExit(EXIT_UNSUPPORTED, 'unsupported-language')
        if mode in ('gzf', 'decompile'):
            if not java.GhidraProgramUtilities.isAnalyzed(program):
                raise ScriptExit(EXIT_MISMATCH, 'gzf-not-analyzed')
        else:
            progress.write('analyze', 0, None)
            if request['analysis_options']:
                set_analysis_options(java, program, request['analysis_options'])
            import pyghidra
            pyghidra.analyze(program)  # acquires the script bundle host; GhidraProject.analyze() would raise an NPE
            project.saveAsPackedFile(program, java.File(os.path.join(out_dir, 'program.gzf')), True)
        if str(program.getExecutableSHA256()) != request['artifact_sha256']:
            raise ScriptExit(EXIT_MISMATCH, 'program-hash')
        if mode == 'decompile':
            return _write_decomp(request, java, program, progress)
        return _write_ir(request, java, program, header_pe, language, progress)
    finally:
        try:
            project.close()
        except Exception:  # noqa: BLE001 - cleanup must not mask the primary failure
            pass


# --- on-demand decompile (S3b, 05 s2.8) ------------------------------------------------------------------------------

def clean_code(value: object) -> str:
    """Decompiled C text for the JSONL: CRLF becomes LF, TAB and LF stay, other controls and lone surrogates become '?'."""
    text = str(value).replace('\r\n', '\n').replace('\r', '\n')
    return _CODE_CONTROL.sub('?', text.encode('utf-8', 'replace').decode('utf-8'))


def decompile_function(decompiler, functions, base, rva: int, seconds: int, limits: dict, monitor) -> tuple[str, str | None]:
    """(status, code) of ONE requested function: `ok` with its C text, `timeout`, or `failed` (no function at the RVA,
    an external function, a decompiler error, no text, or text over L-29). A function-level problem never raises."""
    try:
        function = functions.getFunctionAt(base.add(rva))
    except Exception:  # noqa: BLE001 - an address outside the program
        return 'failed', None
    if function is None or function.isExternal():
        return 'failed', None
    try:
        results = decompiler.decompileFunction(function, seconds, monitor)
    except Exception:  # noqa: BLE001 - a decompiler fault is one failed function, not a failed run
        return 'failed', None
    if results is None:
        return 'failed', None
    if results.isTimedOut():
        return 'timeout', None
    if not results.decompileCompleted():
        return 'failed', None
    produced = results.getDecompiledFunction()
    text = None if produced is None else produced.getC()
    if text is None:
        return 'failed', None
    code = clean_code(text)
    if not code.strip() or len(code) > limits['l29_pseudo_chars'] or code.count('\n') + 1 > limits['l29_pseudo_lines']:
        return 'failed', None
    return 'ok', code


def _write_decomp(request: dict, java, program, progress: ProgressFile) -> int:
    """Decompile exactly `decompile_rvas` of the retained program and write `decomp.jsonl` (03 s4): one line per RVA in
    ascending order, never a function outside the request. Each function gets at most L-41 seconds and the run at most
    L-41 seconds in all; once the run budget is spent the remaining RVAs are `timeout` without being attempted."""
    limits = {**_DEFAULT_LIMITS, **request['limits']}
    rvas, side = request['decompile_rvas'], request['side']
    base, functions = program.getImageBase(), program.getFunctionManager()
    decompiler = java.DecompInterface()
    records = []
    try:
        if not decompiler.openProgram(program):
            raise ScriptExit(EXIT_UNSUPPORTED, 'decompiler-unavailable')
        deadline = time.monotonic() + limits['l41_decompile_run_s']
        progress.write('decompile', 0, len(rvas))
        for number, rva in enumerate(rvas):
            if CANCEL['flag']:
                raise ScriptExit(EXIT_CANCELLED, 'cancelled')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                status, code = 'timeout', None
            else:
                seconds = max(1, min(limits['l41_decompile_fn_s'], math.ceil(remaining)))
                status, code = decompile_function(decompiler, functions, base, rva, seconds, limits,
                                                  java.TaskMonitor.DUMMY)
            records.append({'side': side, 'rva': rva, 'status': status, 'code': code})
            progress.write('decompile', number + 1, len(rvas))
    finally:
        try:
            decompiler.dispose()
        except Exception:  # noqa: BLE001 - cleanup must not mask the primary failure
            pass
    with open(os.path.join(request['out_dir'], 'decomp.jsonl'), 'w', encoding='utf-8', newline='\n') as out:
        for record in records:
            out.write(dump_line(record) + '\n')
    progress.write('done', len(records), len(rvas))
    return EXIT_OK


def _write_ir(request: dict, java, program, header_pe: dict, language: str, progress: ProgressFile) -> int:
    mode, limits = request['mode'], request['limits']
    base = int(program.getImageBase().getOffset())
    ctx = Context(java, program, base, header_pe['size_of_image'], limits)
    producer = {'mode': mode, **{k: v for k, v in probe_versions(java).items() if k != 'script_sha256'},
                'script_sha256': script_sha256(),
                'analysis_options_digest': analysis_options_digest(mode, request['analysis_options']),
                'analyzed': True, 'symbols': 'primary' if mode == 'gzf' else 'none'}
    header = {'type': 'header', 'contract': CONTRACT_EXTRACT, 'artifact_sha256': request['artifact_sha256'],
              'program_sha256': str(program.getExecutableSHA256()), 'image_base': base,
              'size_of_image': header_pe['size_of_image'], 'language': clean_text(language, 64),
              'compiler': clean_text(program.getCompilerSpec().getCompilerSpecID(), 64), 'producer': producer}
    functions = program.getFunctionManager()
    total = int(functions.getFunctionCount())
    cap_f, cap_i = ctx.limits['l01_functions_per_side'], ctx.limits['l02_instructions_per_side']
    count, status = 0, 'complete'
    with open(os.path.join(request['out_dir'], 'ir.jsonl'), 'w', encoding='utf-8', newline='\n') as out:
        out.write(dump_line(header) + '\n')
        progress.write('functions', 0, total)
        for function in functions.getFunctions(True):
            if CANCEL['flag']:
                raise ScriptExit(EXIT_CANCELLED, 'cancelled')
            if function.isExternal():
                continue
            if count >= cap_f:
                ctx.warn('functions-cap')
                status = 'partial'
                break
            if ctx.instructions >= cap_i:
                ctx.warn('instructions-cap')
                status = 'partial'
                break
            record = extract_function(ctx, function)
            if record is None:
                continue
            out.write(dump_line(record) + '\n')
            count += 1
            if count % PROGRESS_EVERY == 0:
                progress.write('functions', count, total)
        warnings = [f'{slug}:{n}' for slug, n in sorted(ctx.warnings.items())][:64]
        out.write(dump_line({'type': 'footer', 'functions': count, 'instructions': ctx.instructions,
                             'status': status, 'warnings': warnings}) + '\n')
    progress.write('done', count, total)
    return EXIT_OK


def _on_signal(_number, _frame) -> None:
    CANCEL['flag'] = True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='pt_ir_extract')
    parser.add_argument('--request')
    parser.add_argument('--self-check', action='store_true')
    args = parser.parse_args(argv)
    for name in ('SIGTERM', 'SIGINT', 'SIGBREAK'):
        if hasattr(signal, name):
            try:
                signal.signal(getattr(signal, name), _on_signal)
            except (ValueError, OSError):
                pass
    started = time.monotonic()
    try:
        if args.self_check:
            return self_check()
        if not args.request:
            raise ScriptExit(EXIT_BAD_REQUEST, 'bad-request')
        return run(load_request(args.request))
    except ScriptExit as exc:
        _print({'error': {'reason': exc.reason}})
        return exc.code
    except KeyboardInterrupt:
        _print({'error': {'reason': 'cancelled'}})
        return EXIT_CANCELLED
    except Exception as exc:  # noqa: BLE001 - class name only, never the message (untrusted text)
        sys.stderr.write(f'pt_ir_extract crashed: {type(exc).__name__} after {math.floor(time.monotonic() - started)} s\n')
        _print({'error': {'reason': 'crash'}})
        return 1


if __name__ == '__main__':
    sys.exit(main())
