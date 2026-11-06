"""Bounded reader for DER/BER-shaped data with definite lengths (SPEC-51 7.3), used on attacker-controlled PKCS#7.

Reads structure only: tag, length, children. It is not a validator and makes no signature claim. Indefinite
lengths, lengths that run past their parent, tag numbers over four continuation bytes, more than `max_depth`
levels, more than `max_nodes` nodes and inputs over `max_bytes` are refused with a typed `DerError`. The parse is
iterative, so a deeply nested input cannot exhaust the Python stack. Nothing else is ever raised by `parse`.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from patchtrace.hostile_text import is_hostile

INVALID = 'signature_der_invalid'
OVER_CAP = 'signature_der_over_cap'
_CONSTRUCTED = 0x20
_MAX_TAG_BYTES = 4
_MAX_LENGTH_BYTES = 4
_MAX_TEXT = 1024
_TEXT_TAGS = frozenset({0x0C, 0x12, 0x13, 0x14, 0x16, 0x19, 0x1A, 0x1B, 0x1C, 0x1E})
SEQUENCE, SET, INTEGER, BIT_STRING, OCTET_STRING, OBJECT_ID = 0x10, 0x11, 0x02, 0x03, 0x04, 0x06
UTC_TIME, GENERALIZED_TIME = 0x17, 0x18


class DerError(Exception):
    """`code` is `signature_der_invalid` or `signature_der_over_cap`."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class DerLimits:
    max_bytes: int = 262144
    max_depth: int = 32
    max_nodes: int = 20000


@dataclass(frozen=True, slots=True)
class Node:
    """One element. `cls` is 0 universal, 1 application, 2 context, 3 private; offsets index `data`."""

    cls: int
    constructed: bool
    tag: int
    start: int
    body: int
    end: int
    data: bytes
    children: tuple[Node, ...] = ()

    @property
    def content(self) -> bytes:
        return self.data[self.body:self.end]

    @property
    def raw(self) -> bytes:
        return self.data[self.start:self.end]

    def is_universal(self, tag: int) -> bool:
        return self.cls == 0 and self.tag == tag

    def is_context(self, number: int) -> bool:
        return self.cls == 2 and self.tag == number


DEFAULT_DER_LIMITS = DerLimits()


def parse(data: bytes, limits: DerLimits = DEFAULT_DER_LIMITS) -> Node:
    """The first element of `data`; bytes after it are left alone (`Node.end` says where it stopped)."""
    if len(data) > limits.max_bytes:
        raise DerError(OVER_CAP, f'input of {len(data)} bytes exceeds {limits.max_bytes}')
    budget = [limits.max_nodes]
    return _element(data, 0, len(data), 1, limits, budget)


def _header(data: bytes, pos: int, end: int) -> tuple[int, bool, int, int, int]:
    """(cls, constructed, tag, body offset, end offset) of the element starting at `pos`."""
    if pos >= end:
        raise DerError(INVALID, 'element starts past the end of its parent')
    first = data[pos]
    cls, constructed, tag = first >> 6, bool(first & _CONSTRUCTED), first & 0x1F
    pos += 1
    if tag == 0x1F:
        tag, count = 0, 0
        while True:
            if pos >= end or count >= _MAX_TAG_BYTES:
                raise DerError(INVALID, 'unterminated or oversized tag number')
            byte = data[pos]
            pos += 1
            count += 1
            tag = (tag << 7) | (byte & 0x7F)
            if not byte & 0x80:
                break
    if pos >= end:
        raise DerError(INVALID, 'missing length')
    size = data[pos]
    pos += 1
    if size == 0x80:
        raise DerError(INVALID, 'indefinite length is not supported')
    if size & 0x80:
        count = size & 0x7F
        if count > _MAX_LENGTH_BYTES or pos + count > end:
            raise DerError(INVALID, 'oversized or truncated length')
        size = int.from_bytes(data[pos:pos + count], 'big')
        pos += count
    if size > end - pos:
        raise DerError(INVALID, 'declared length runs past its parent')
    return cls, constructed, tag, pos, pos + size


def _element(data: bytes, start: int, limit: int, depth: int, limits: DerLimits, budget: list[int]) -> Node:
    """Parse one element and, iteratively, everything below it."""
    cls, constructed, tag, body, end = _header(data, start, limit)
    root: list = [cls, constructed, tag, start, body, end, []]
    stack = [(root, body)]  # (open element, position of its next child)
    budget[0] -= 1
    if budget[0] < 0:
        raise DerError(OVER_CAP, 'too many nodes')
    while stack:
        parent, pos = stack[-1]
        if not parent[1] or pos >= parent[5]:
            stack.pop()
            continue
        if len(stack) >= limits.max_depth and parent[1]:
            # The parent is constructed and at the depth cap: any child would be one level too deep.
            raise DerError(OVER_CAP, f'nesting deeper than {limits.max_depth}')
        c_cls, c_constructed, c_tag, c_body, c_end = _header(data, pos, parent[5])
        budget[0] -= 1
        if budget[0] < 0:
            raise DerError(OVER_CAP, 'too many nodes')
        child: list = [c_cls, c_constructed, c_tag, pos, c_body, c_end, []]
        parent[6].append(child)
        stack[-1] = (parent, c_end)
        stack.append((child, c_body))
    return _freeze(data, root)


def _freeze(data: bytes, raw: list) -> Node:
    # Children are frozen bottom-up without recursion.
    order, todo = [], [raw]
    while todo:
        item = todo.pop()
        order.append(item)
        todo.extend(item[6])
    built: dict[int, Node] = {}
    for item in reversed(order):
        built[id(item)] = Node(item[0], item[1], item[2], item[3], item[4], item[5], data,
                               tuple(built[id(c)] for c in item[6]))
    return built[id(raw)]


def decode_oid(node: Node) -> str | None:
    if not node.is_universal(OBJECT_ID) or not node.content or node.content[-1] & 0x80:
        return None
    arcs: list[int] = []
    value = 0
    for byte in node.content:
        value = (value << 7) | (byte & 0x7F)
        # Malformed source OIDs can have a huge base-128 arc: refuse before
        # int-to-decimal conversion or unbounded integer accumulation.
        if value.bit_length() > 127:
            return None
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    if len(arcs) > 64:
        return None
    first = arcs[0]
    head = (0, first) if first < 40 else (1, first - 40) if first < 80 else (2, first - 80)
    return '.'.join(str(a) for a in (*head, *arcs[1:]))


def decode_int(node: Node) -> int | None:
    if not node.is_universal(INTEGER) or not node.content:
        return None
    return int.from_bytes(node.content, 'big', signed=True)


def decode_text(node: Node) -> str:
    """A string element as display-safe text (hostile characters become '?'); non-text elements give ''."""
    if node.cls != 0 or node.tag not in _TEXT_TAGS:
        return ''
    if node.tag == 0x1E:
        text = node.content.decode('utf-16-be', errors='replace')
    elif node.tag == 0x0C:
        text = node.content.decode('utf-8', errors='replace')
    else:
        text = node.content.decode('latin-1')
    return ''.join('?' if is_hostile(ch) else ch for ch in text[:_MAX_TEXT])


def decode_time(node: Node) -> str | None:
    """UTCTime or GeneralizedTime in 'Z' form as ISO 8601 UTC, else None (offsets and fractions are refused)."""
    if node.cls != 0 or node.tag not in (UTC_TIME, GENERALIZED_TIME):
        return None
    try:
        text = node.content.decode('ascii')
    except UnicodeDecodeError:
        return None
    if node.tag == UTC_TIME:
        if len(text) != 13 or not text.endswith('Z') or not text[:-1].isdigit():
            return None
        year = int(text[:2])
        text = f'{2000 + year if year < 50 else 1900 + year}{text[2:]}'
    elif len(text) != 15 or not text.endswith('Z') or not text[:-1].isdigit():
        return None
    try:
        return datetime.strptime(text[:-1], '%Y%m%d%H%M%S').strftime('%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
        return None
