"""Strict, hand-written validation of the extractor's untrusted JSON Lines (`ir-extract/1`, 02 s2, 03 s12.3).

Header and footer go through the S0a pydantic models; `fn` lines (millions of them) are validated here with plain
type checks (pydantic would cost minutes, R04 s7). Everything is rejected, never repaired: unknown or missing keys,
NaN/Infinity, floats, duplicate keys, booleans where integers are required, out-of-range values, malformed hex.
A failure is `PT-UNIFIED-IR` with reason `bad-record-<field>`.
"""
from __future__ import annotations

import json
import re
from bisect import bisect_right
from dataclasses import dataclass
from typing import NamedTuple

from ..contracts import IrExtractFooter, IrExtractHeader
from ..limits import UnifiedError, UnifiedLimits

NAME_SOURCES = ('DEFAULT', 'ANALYSIS', 'IMPORTED', 'USER_DEFINED', 'AI')
EDGE_KINDS = ('fall', 'jump', 'cond', 'switch', 'call-return')
MAX_RANGES, MAX_ALIASES, MAX_NAME, MAX_TEXT, MAX_PREFIX, MAX_OPS, MAX_OBJS, MAX_REFS = 64, 16, 512, 256, 64, 6, 8, 8
INT64_MIN, INT64_MAX = -(2 ** 63), 2 ** 63 - 1
_FN_KEYS = frozenset({'type', 'rva', 'ranges', 'name', 'name_src', 'aliases', 'kind', 'thunk_target', 'import', 'lib',
                      'raw', 'truncated', 'blocks', 'insns', 'calls', 'strings', 'text'})
_HEX = re.compile(r'^(?:[0-9a-f]{2})*$')
_SHA = re.compile(r'^[0-9a-f]{64}$')
_MNEMONIC = re.compile(r'^[A-Za-z0-9_.]{1,32}$')
_FLOW = re.compile(r'^[A-Z_]{3,48}$')
_REFTYPE = re.compile(r'^[A-Z_]{1,40}$')
_REGISTER = re.compile(r'^[A-Za-z0-9_.]{1,16}$')
_IMPORT_KEY = re.compile(r'^[^\x00-\x20!]{1,128}![^\x00-\x1f\x7f]{1,256}$')
_RVA_REF = re.compile(r'^rva:(0|[1-9][0-9]{0,9})$')
_STACK_REF = re.compile(r'^stack:(0|-?[1-9][0-9]{0,9})$')
_CONTROL = re.compile('[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]')


class Block(NamedTuple):
    rva: int
    length: int
    n_insn: int
    succ: tuple[int, ...]
    kinds: tuple[str, ...]


class RawOp(NamedTuple):
    optype: int
    mask: bytes | None
    objs: tuple
    refs: tuple


class RawInsn(NamedTuple):
    off: int
    length: int
    mnem: str
    imask: bytes | None
    ops: tuple[RawOp, ...]
    flow: str


@dataclass(slots=True)
class FnRec:
    rva: int
    ranges: list[tuple[int, int]]
    name: str
    name_src: str
    aliases: list[str]
    kind: str
    thunk_target: int | None
    imp: dict | None
    lib: bool
    raw: bytes | None
    truncated: bool
    blocks: list[Block]
    insns: list[RawInsn]
    calls: list[tuple]
    strings: list[tuple]
    texts: list[str]
    sanitized: int = 0


def bad(field: str, code: str = 'PT-UNIFIED-IR') -> UnifiedError:
    return UnifiedError(code, 'The extractor output failed strict validation', reason=f'bad-record-{field}')


def fail(reason: str, message: str = 'The extractor output is incomplete or malformed') -> UnifiedError:
    """Structural failures with their own spec slugs (03 s9): no-output, no-footer, truncated, trailing-data."""
    return UnifiedError('PT-UNIFIED-IR', message, reason=reason)


def _reject_constant(name):
    raise ValueError(name)


def _reject_float(text):
    raise ValueError(text)


def _pairs(items):
    out = {}
    for key, value in items:
        if key in out:
            raise ValueError('duplicate key')
        out[key] = value
    return out


def parse_json_line(line: bytes | str) -> dict:
    """Strict JSON object parse: duplicate keys, NaN/Infinity, floats and lone surrogates are errors."""
    try:
        text = line.decode('utf-8') if isinstance(line, bytes) else line
        document = json.loads(text, object_pairs_hook=_pairs, parse_constant=_reject_constant,
                              parse_float=_reject_float)
    except (ValueError, RecursionError):
        raise bad('json') from None
    if not isinstance(document, dict):
        raise bad('json')
    return document


def _int(value, field, low=INT64_MIN, high=INT64_MAX) -> int:
    if type(value) is not int or not low <= value <= high:
        raise bad(field)
    return value


def _rva(value, field, size_of_image) -> int:
    return _int(value, field, 0, size_of_image - 1)


def _text(value, field, limit, *, counter: list[int] | None = None) -> str:
    if type(value) is not str or len(value) > limit:
        raise bad(field)
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        raise bad(field) from None
    if counter is not None and _CONTROL.search(value):
        counter[0] += 1
        return _CONTROL.sub('?', value)
    return value


def _hex(value, field, *, allow_none=False, limit=None, exact=None) -> bytes | None:
    if value is None and allow_none:
        return None
    if type(value) is not str or (limit is not None and len(value) > 2 * limit) or not _HEX.match(value):
        raise bad(field)
    data = bytes.fromhex(value)
    if exact is not None and len(data) != exact:
        raise bad(field)
    return data


def _list(value, field, limit) -> list:
    if type(value) is not list or len(value) > limit:
        raise bad(field)
    return value


def parse_header(document: dict, expected_sha256: str, other_sha256: str | None = None):
    """Header via the S0a model; both hashes must equal the project artifact (PAIR) and not the OTHER side's
    (ORIENTATION: the IR of the newer file was supplied as the older one, or the pair was swapped)."""
    try:
        header = IrExtractHeader.model_validate_json(json.dumps(document))
    except ValueError:
        raise bad('header') from None
    if header.artifact_sha256 != expected_sha256 or header.program_sha256 != expected_sha256:
        if other_sha256 is not None and header.artifact_sha256 == other_sha256:
            raise UnifiedError('PT-UNIFIED-ORIENTATION', 'The extractor output belongs to the other side of the pair',
                               reason='reversed-side')
        raise UnifiedError('PT-UNIFIED-PAIR', 'The extractor analysed a different file than the project artifact',
                           reason='artifact-hash')
    if not header.language.startswith('x86:LE:64'):
        raise UnifiedError('PT-UNIFIED-UNSUPPORTED', 'Only x86-64 images are supported', reason='unsupported-language')
    return header


def parse_footer(document: dict):
    try:
        return IrExtractFooter.model_validate_json(json.dumps(document))
    except ValueError:
        raise bad('footer') from None


def _parse_ranges(value, size_of_image: int) -> list[tuple[int, int]]:
    ranges = []
    previous_end = -1
    for item in _list(value, 'ranges', MAX_RANGES):
        if type(item) is not list or len(item) != 2:
            raise bad('ranges')
        start, length = _rva(item[0], 'ranges', size_of_image), _int(item[1], 'ranges', 1, size_of_image)
        if start < previous_end or start + length > size_of_image:
            raise bad('ranges')
        previous_end = start + length
        ranges.append((start, length))
    if not ranges:
        raise bad('ranges')
    return ranges


def _parse_objs(value) -> tuple:
    out = []
    for item in _list(value, 'objs', MAX_OBJS):
        if type(item) is not list or len(item) != 2:
            raise bad('objs')
        kind, payload = item
        if kind == 'reg':
            if type(payload) is not str or not _REGISTER.match(payload):
                raise bad('objs')
        elif kind == 'scalar':
            _int(payload, 'objs')
        elif kind == 'addr':
            if payload is not None:
                _int(payload, 'objs', 0, 2 ** 32 - 1)
        else:
            raise bad('objs')
        out.append((kind, payload))
    return tuple(out)


def _parse_refs(value) -> tuple:
    out = []
    for item in _list(value, 'refs', MAX_REFS):
        if type(item) is not list or len(item) != 2 or type(item[0]) is not str or not _REFTYPE.match(item[0]) \
                or type(item[1]) is not str:
            raise bad('refs')
        text = item[1]
        if not (_RVA_REF.match(text) or _STACK_REF.match(text)
                or (text.startswith('ext:') and _IMPORT_KEY.match(text[4:]))):
            raise bad('refs')
        out.append((item[0], text))
    return tuple(out)


def _parse_insn(item, length_cap: int) -> RawInsn:
    if type(item) is not list or len(item) != 6:
        raise bad('insns')
    off, length, mnem, imask, ops, flow = item
    _int(off, 'insns', 0, length_cap)
    _int(length, 'insns', 1, 15)
    if type(mnem) is not str or not _MNEMONIC.match(mnem) or type(flow) is not str or not _FLOW.match(flow):
        raise bad('insns')
    imask_bytes = _hex(imask, 'insns', allow_none=True, exact=length)
    parsed = []
    for op in _list(ops, 'ops', MAX_OPS):
        if type(op) is not list or len(op) != 4:
            raise bad('ops')
        optype = _int(op[0], 'ops', 0, 2 ** 31 - 1)
        parsed.append(RawOp(optype, _hex(op[1], 'ops', allow_none=True, exact=length), _parse_objs(op[2]),
                            _parse_refs(op[3])))
    return RawInsn(off, length, mnem, imask_bytes, tuple(parsed), flow)


def _parse_blocks(value, size_of_image: int) -> list[Block]:
    blocks = []
    for item in _list(value, 'blocks', 2 ** 22):
        if type(item) is not list or len(item) != 5:
            raise bad('blocks')
        start, length = _rva(item[0], 'blocks', size_of_image), _int(item[1], 'blocks', 1, size_of_image)
        n_insn = _int(item[2], 'blocks', 0, 2 ** 31)
        succ, kinds = item[3], item[4]
        if type(succ) is not list or type(kinds) is not list or len(succ) != len(kinds):
            raise bad('blocks')
        for target, kind in zip(succ, kinds, strict=True):
            _rva(target, 'blocks', size_of_image)
            if kind not in EDGE_KINDS:
                raise bad('blocks')
        if blocks and start <= blocks[-1].rva:
            raise bad('blocks')
        blocks.append(Block(start, length, n_insn, tuple(succ), tuple(kinds)))
    starts = {block.rva for block in blocks}
    if any(target not in starts for block in blocks for target in block.succ):
        raise bad('blocks')
    return blocks


def _parse_calls(value, size_of_image: int) -> list[tuple]:
    out = []
    for item in _list(value, 'calls', 2 ** 22):
        if type(item) is not list or len(item) != 4 or item[3] not in ('call', 'jump'):
            raise bad('calls')
        site = _rva(item[0], 'calls', size_of_image)
        target = None if item[1] is None else _rva(item[1], 'calls', size_of_image)
        key = item[2]
        if key is not None and (type(key) is not str or not _IMPORT_KEY.match(key)):
            raise bad('calls')
        if target is not None and key is not None:
            raise bad('calls')
        out.append((site, target, key, item[3]))
    return out


def _parse_strings(value, size_of_image: int, counter: list[int]) -> list[tuple]:
    out = []
    for item in _list(value, 'strings', 2 ** 22):
        if type(item) is not list or len(item) != 4:
            raise bad('strings')
        site = _rva(item[0], 'strings', size_of_image)
        if type(item[1]) is not str or not _SHA.match(item[1]):
            raise bad('strings')
        out.append((site, item[1], _int(item[2], 'strings', 0, 2 ** 31),
                    _text(item[3], 'strings', MAX_PREFIX, counter=counter)))
    return out


def parse_fn(document: dict, size_of_image: int, limits: UnifiedLimits) -> FnRec:
    """Validate one `fn` line (all keys required) and return its typed record."""
    if set(document) != _FN_KEYS or document['type'] != 'fn':
        raise bad('keys')
    counter = [0]
    rva = _rva(document['rva'], 'rva', size_of_image)
    ranges = _parse_ranges(document['ranges'], size_of_image)
    if not any(start <= rva < start + length for start, length in ranges):
        raise bad('rva')
    if document['name_src'] not in NAME_SOURCES or document['kind'] not in ('normal', 'thunk'):
        raise bad('kind')
    name = _text(document['name'], 'name', MAX_NAME, counter=counter)
    aliases = [_text(alias, 'aliases', MAX_NAME, counter=counter) for alias in _list(document['aliases'], 'aliases',
                                                                                     MAX_ALIASES)]
    thunk_target = document['thunk_target']
    if thunk_target is not None:
        thunk_target = _rva(thunk_target, 'thunk-target', size_of_image)
    imported = document['import']
    if imported is not None:
        if type(imported) is not dict or set(imported) != {'dll', 'name', 'ordinal'}:
            raise bad('import')
        _text(imported['dll'], 'import', 128)
        if imported['name'] is not None:
            _text(imported['name'], 'import', 256)
        if imported['ordinal'] is not None:
            _int(imported['ordinal'], 'import', 0, 65535)
        if not imported['dll'] or (imported['name'] is None) == (imported['ordinal'] is None):
            raise bad('import')
    if type(document['lib']) is not bool or type(document['truncated']) is not bool:
        raise bad('flags')
    total = sum(length for _, length in ranges)
    raw = _hex(document['raw'], 'raw', allow_none=True, limit=limits.l06_fn_raw_bytes)
    if raw is not None and len(raw) != total:
        raise bad('raw')
    insns = [_parse_insn(item, total) for item in _list(document['insns'], 'insns', limits.l06_fn_instructions)]
    texts = [_text(item, 'text', MAX_TEXT, counter=counter) for item in _list(document['text'], 'text',
                                                                              limits.l06_fn_instructions)]
    record = FnRec(rva, ranges, name, document['name_src'], sorted(aliases), document['kind'], thunk_target, imported,
                   document['lib'], raw, document['truncated'], _parse_blocks(document['blocks'], size_of_image),
                   insns, _parse_calls(document['calls'], size_of_image),
                   _parse_strings(document['strings'], size_of_image, counter), texts)
    record.sanitized = counter[0]
    if len(texts) != len(insns):
        raise bad('text')
    if raw is None and (insns or record.blocks or record.calls or record.strings):
        raise bad('raw')
    for insn in insns:
        if insn.off + insn.length > total:
            raise bad('insns')
    return record


def check_instruction_layout(record: FnRec) -> list[int]:
    """RVA of every instruction; each must lie wholly inside one range and follow the previous without overlap."""
    starts, bases, cursor = [], [], 0
    for start, length in record.ranges:
        starts.append(cursor)
        bases.append((start, length))
        cursor += length
    out, previous_end = [], 0
    for insn in record.insns:
        if insn.off < previous_end:
            raise bad('insns')
        index = bisect_right(starts, insn.off) - 1
        start, length = bases[index]
        within = insn.off - starts[index]
        if within + insn.length > length:
            raise bad('insns')
        out.append(start + within)
        previous_end = insn.off + insn.length
    return out
