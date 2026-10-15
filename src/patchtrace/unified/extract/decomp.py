"""S3b: the strict reader of `decomp.jsonl`, the output of the extractor's `decompile` mode (03 s4, 05 s2.8). Pure.

The extractor child is outside PatchTrace's trust: every line is validated and nothing is repaired. A line is
`{"side": ..., "rva": ..., "status": "ok" | "timeout" | "failed", "code": <text> | null}`; `code` is text exactly for
`ok` and bounded by L-29 (characters and lines). Only the requested RVAs may appear, each exactly once, and every
requested RVA must appear. A failure is `PT-UNIFIED-EXTRACT` with reason `bad-decomp-<field>` or `no-decomp`.
"""
from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..contracts import strip_unsafe
from ..limits import DEFAULT_LIMITS, UnifiedError, UnifiedLimits

STATUSES = ('ok', 'timeout', 'failed')
_KEYS = frozenset({'side', 'rva', 'status', 'code'})
PART_LINE_TEXT_BYTES = 3 * 1024 * 1024    # below the 4 MiB line cap of a stored part (store.LINE_MAX_BYTES)
JSON_EXPANSION = 12          # an ASCII JSON line spends up to 12 bytes (two \uXXXX escapes) on one character


@dataclass(frozen=True)
class DecompRecord:
    side: str
    rva: int
    status: str
    code: str | None


def _bad(field: str) -> UnifiedError:
    return UnifiedError('PT-UNIFIED-EXTRACT', 'The decompiler output failed strict validation',
                        reason=f'bad-decomp-{field}')


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


def _parse_line(line: bytes) -> dict:
    try:
        document = json.loads(line.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=_reject_constant,
                              parse_float=_reject_float)
    except (ValueError, RecursionError):
        raise _bad('json') from None
    if not isinstance(document, dict):
        raise _bad('json')
    return document


def _code(value: object, limits: UnifiedLimits) -> str:
    if type(value) is not str or not value:
        raise _bad('code')
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        raise _bad('code') from None
    if len(value) > limits.l29_pseudo_chars or value.count('\n') + 1 > limits.l29_pseudo_lines:
        raise _bad('code-cap')
    return strip_unsafe(value, keep_layout=True, replacement='?')


def read_decomp(path: Path, side: str, rvas: Sequence[int],
                limits: UnifiedLimits = DEFAULT_LIMITS) -> dict[int, DecompRecord]:
    """The records of one side keyed by RVA (ascending). Raises for a missing or symlinked file, an unknown, repeated
    or missing RVA, a foreign side, a status outside the closed set, `code` where there must be none (or none where
    there must be some), an over-long line or text, floats, NaN and duplicate keys."""
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise UnifiedError('PT-UNIFIED-EXTRACT', 'The decompiler produced no output', reason='no-decomp')
    wanted = set(rvas)
    line_cap = limits.l29_pseudo_chars * JSON_EXPANSION + 4096
    found: dict[int, DecompRecord] = {}
    with path.open('rb') as stream:
        while True:
            line = stream.readline(line_cap + 1)
            if not line:
                break
            if len(line) > line_cap:
                raise _bad('line')
            if not line.strip():
                continue
            document = _parse_line(line)
            if set(document) != _KEYS or document['side'] != side:
                raise _bad('keys')
            rva, status, code = document['rva'], document['status'], document['code']
            if type(rva) is not int or rva not in wanted or rva in found:
                raise _bad('rva')
            if status not in STATUSES:
                raise _bad('status')
            if (status == 'ok') != (code is not None):
                raise _bad('code')
            found[rva] = DecompRecord(side, rva, status, None if code is None else _code(code, limits))
    if set(found) != wanted:
        raise _bad('missing')
    return dict(sorted(found.items()))


def part_lines(records: Mapping[str, Mapping[int, DecompRecord]],
               limits: UnifiedLimits = DEFAULT_LIMITS) -> list[dict]:
    """The lines of the stored part `decomp.jsonl.gz` (S3b, 07 s6): `{side, rva, status, code}`, older side first, RVAs
    ascending. The text is scrubbed again (the part is the product's own output, never the extractor's bytes) and a
    text over L-29 (characters, lines) or whose JSON line would exceed the part line cap becomes `failed` without
    text: a bounded part is better than none, and the code pane says why a function has no text."""
    out = []
    for side in ('older', 'newer'):
        for rva, record in sorted(records.get(side, {}).items()):
            status, code = record.status, record.code
            if code is not None:
                code = strip_unsafe(code, keep_layout=True, replacement='?')
                too_long = len(code) > limits.l29_pseudo_chars or code.count('\n') + 1 > limits.l29_pseudo_lines
                if too_long or len(json.dumps(code, ensure_ascii=False).encode('utf-8')) > PART_LINE_TEXT_BYTES:
                    status, code = 'failed', None
            out.append({'side': side, 'rva': rva, 'status': status, 'code': code if status == 'ok' else None})
    return out
