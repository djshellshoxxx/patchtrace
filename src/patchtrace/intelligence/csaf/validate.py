"""CSAF 2.0 document validation (SPEC-28 section E). Pure stdlib; never executes or renders advisory content.

Three layers, in order:
1. ``parse_json``: strict UTF-8 JSON (no BOM, no duplicate keys, no NaN/Infinity, bounded integers) and the
   processing limits (bytes, depth, nodes, string length);
2. the official CSAF 2.0 JSON Schema's validation keywords, interpreted over ``schema_data.CSAF_SCHEMA`` (generated
   from the vendored OASIS schema; ECMA-262 patterns translated to Python ``re``);
3. the implemented mandatory tests of CSAF 2.0 §6.1 plus optional tests 6.2.1 and 6.2.20 (warnings).

Any error rejects the document; nothing is ever partially accepted. Findings never quote advisory text beyond
short, sanitized identifiers.
"""
from __future__ import annotations

import json
import math
import re
import threading
from collections import Counter, defaultdict, deque
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ..contracts import Finding, IntelError, ValidationReport
from . import schema_data

VALIDATOR_VERSION = 1
PROFILES = ('csaf_base', 'csaf_security_incident_response', 'csaf_informational_advisory',
            'csaf_security_advisory', 'csaf_vex')
TESTS_RUN = ('json', 'limit', 'schema', '6.1.1', '6.1.2', '6.1.3', '6.1.4', '6.1.5', '6.1.6', '6.1.7', '6.1.14',
             '6.1.15', '6.1.16', '6.1.17', '6.1.18', '6.1.19', '6.1.20', '6.1.21', '6.1.22', '6.1.23', '6.1.24',
             '6.1.25', '6.1.26', '6.1.27.1', '6.1.27.2', '6.1.27.3', '6.1.27.4', '6.1.27.5', '6.1.27.6',
             '6.1.27.7', '6.1.27.8', '6.1.27.9', '6.1.27.10', '6.1.27.11', '6.1.28', '6.1.29', '6.1.30', '6.1.31',
             '6.1.32', '6.1.33', '6.2.1', '6.2.20')
TESTS_NOT_IMPLEMENTED = ('6.1.8', '6.1.9', '6.1.10', '6.1.11', '6.1.12', '6.1.13', '6.2.2-6.2.19', '6.3')
STATUS_GROUPS = {'first_affected': 'affected', 'known_affected': 'affected', 'last_affected': 'affected',
                 'known_not_affected': 'not affected', 'first_fixed': 'fixed', 'fixed': 'fixed',
                 'under_investigation': 'under investigation'}
VEX_LABELS = frozenset({'component_not_present', 'inline_mitigations_already_exist',
                        'vulnerable_code_cannot_be_controlled_by_adversary', 'vulnerable_code_not_in_execute_path',
                        'vulnerable_code_not_present'})
RANGE_WORDS = ('<', '<=', '>', '>=', 'after', 'all', 'before', 'earlier', 'later', 'prior', 'versions')
_CANCEL_EVERY = 4096


@dataclass(frozen=True)
class Limits:
    max_bytes: int = 16 * 1024 * 1024
    max_depth: int = 64
    max_nodes: int = 2_000_000
    max_string: int = 1_048_576
    max_vulnerabilities: int = 10_000
    max_products: int = 100_000
    max_findings: int = 200


LIMITS = Limits()


class ValidationFailed(IntelError):
    """A document that failed the schema or a mandatory test; ``report`` lists every finding (capped)."""

    def __init__(self, report: ValidationReport):
        first = report.errors[0]
        super().__init__('PT-INTEL-VALIDATE', f'{len(report.errors)} validation error(s){" (truncated)" if report.truncated else ""}; '
                         f'first: [{first.test}] {first.pointer or "/"}: {first.message}', pointer=first.pointer)
        self.report = report


def _cancelled(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise IntelError('PT-INTEL-CANCEL', 'validation cancelled', recoverable=True)


def escape_token(token: str | int) -> str:
    """RFC 6901 reference token."""
    return str(token).replace('~', '~0').replace('/', '~1')


def safe_label(value: object, limit: int = 60) -> str:
    """Short printable rendering of an advisory-supplied identifier for messages (never full text)."""
    text = value if isinstance(value, str) else repr(value)
    text = ''.join(ch if ch.isprintable() and ch not in '‪‫‬‭‮⁦⁧⁨⁩'
                   else f'\\u{ord(ch):04x}' for ch in text)
    return text if len(text) <= limit else text[:limit - 1] + '…'


# ---------------------------------------------------------------------------------------------- 1. strict JSON

def _strict_loads(text: str):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise _DuplicateKey(key)
            value[key] = item
        return value

    def constant(name):
        raise _BadNumber(name)

    def finite(value: str):
        number = float(value)
        if not math.isfinite(number):  # 1e999 parses to inf without reaching parse_constant
            raise _BadNumber(value[:20])
        return number

    def bounded(value: str):
        if len(value) > 4300:
            raise _BadNumber('integer with more than 4300 digits')
        return int(value)

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant, parse_float=finite,
                      parse_int=bounded)


class _DuplicateKey(ValueError):
    def __init__(self, key):
        super().__init__(key)
        self.key = key


class _BadNumber(ValueError):
    pass


def parse_json(raw: bytes, *, limits: Limits = LIMITS, what: str = 'CSAF document', max_bytes: int | None = None):
    """Strict JSON parse with processing limits. Raises IntelError (FORMAT or LIMIT); never returns partial data."""
    if type(raw) is not bytes:
        raise IntelError('PT-INTEL-INPUT', f'{what} must be bytes')
    cap = limits.max_bytes if max_bytes is None else max_bytes
    if len(raw) > cap:
        raise IntelError('PT-INTEL-LIMIT', f'{what} is {len(raw)} bytes; the limit is {cap}')
    if raw.startswith(b'\xef\xbb\xbf'):
        raise IntelError('PT-INTEL-FORMAT', f'{what} starts with a byte order mark (RFC 8259 forbids it)')
    try:
        text = raw.decode('utf-8', errors='strict')
    except UnicodeDecodeError as exc:
        raise IntelError('PT-INTEL-FORMAT', f'{what} is not valid UTF-8 (byte {exc.start})') from None
    try:
        value = _strict_loads(text)
    except _DuplicateKey as exc:
        raise IntelError('PT-INTEL-FORMAT', f'{what} has an ambiguous duplicate key {safe_label(exc.key)!s}') from None
    except _BadNumber as exc:
        raise IntelError('PT-INTEL-FORMAT', f'{what} has an invalid number ({safe_label(str(exc), 40)})') from None
    except RecursionError:
        raise IntelError('PT-INTEL-LIMIT', f'{what} nesting exceeds the parser limit') from None
    except ValueError as exc:
        raise IntelError('PT-INTEL-FORMAT', f'{what} is not valid JSON ({safe_label(str(exc), 80)})') from None
    _check_shape(value, limits, what)
    return value


def _check_shape(value, limits: Limits, what: str) -> None:
    """Iterative depth/node/string bounds (no recursion: the input is hostile until proven otherwise)."""
    nodes = 0
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > limits.max_nodes:
            raise IntelError('PT-INTEL-LIMIT', f'{what} has more than {limits.max_nodes} JSON values')
        if isinstance(item, dict):
            if depth > limits.max_depth:
                raise IntelError('PT-INTEL-LIMIT', f'{what} nesting exceeds {limits.max_depth} levels')
            for key, sub in item.items():
                if len(key) > limits.max_string:
                    raise IntelError('PT-INTEL-LIMIT', f'{what} has a key longer than {limits.max_string} characters')
                stack.append((sub, depth + 1))
        elif isinstance(item, list):
            if depth > limits.max_depth:
                raise IntelError('PT-INTEL-LIMIT', f'{what} nesting exceeds {limits.max_depth} levels')
            stack.extend((sub, depth + 1) for sub in item)
        elif isinstance(item, str) and len(item) > limits.max_string:
            raise IntelError('PT-INTEL-LIMIT', f'{what} has a string longer than {limits.max_string} characters')


# ---------------------------------------------------------------------------------------------- 2. schema keywords

def translate_pattern(pattern: str) -> str:
    """ECMA-262 (JSON Schema) regex to Python ``re``: ``\\d``/``\\w`` are ASCII, ``.`` excludes line
    terminators and ``$`` means end of input (Python's ``$`` would also match before a final newline)."""
    out: list[str] = []
    i, in_class = 0, False
    while i < len(pattern):
        ch = pattern[i]
        if ch == '\\' and i + 1 < len(pattern):
            nxt = pattern[i + 1]
            if nxt == 'd':
                out.append('0-9' if in_class else '[0-9]')
            elif nxt == 'w':
                out.append('A-Za-z0-9_' if in_class else '[A-Za-z0-9_]')
            elif nxt == 'D' and not in_class:
                out.append('[^0-9]')
            elif nxt == 'W' and not in_class:
                out.append('[^A-Za-z0-9_]')
            else:
                out.append(ch + nxt)
            i += 2
            continue
        if in_class:
            if ch == ']':
                in_class = False
            out.append(ch)
        elif ch == '[':
            in_class = True
            out.append(ch)
        elif ch == '.':
            out.append('[^\\n\\r\\u2028\\u2029]')
        elif ch == '$':
            out.append('\\Z')
        else:
            out.append(ch)
        i += 1
    return ''.join(out)


_PATTERNS: dict[str, re.Pattern] = {}


def _pattern(pattern: str) -> re.Pattern:
    compiled = _PATTERNS.get(pattern)
    if compiled is None:
        compiled = _PATTERNS[pattern] = re.compile(translate_pattern(pattern))
    return compiled


_DATE_TIME = re.compile(r'([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?'
                        r'([Zz]|([+-])([0-9]{2}):([0-9]{2}))')
_URI = re.compile(r'[A-Za-z][A-Za-z0-9+.\-]*:[^\s\x00-\x1f\x7f-\x9f]+')


def parse_date_time(value: str) -> datetime | None:
    """RFC 3339 date-time (JSON Schema ``format: date-time``) as an aware datetime, or None."""
    m = _DATE_TIME.fullmatch(value) if isinstance(value, str) else None
    if m is None:
        return None
    try:
        offset = timedelta(0)
        if m.group(9):
            hours, minutes = int(m.group(10)), int(m.group(11))
            if hours > 23 or minutes > 59:
                return None
            offset = timedelta(hours=hours, minutes=minutes) * (1 if m.group(9) == '+' else -1)
        second = int(m.group(6))
        if second > 60:
            return None
        fraction = m.group(7) or ''
        micro = int((fraction[1:] + '000000')[:6]) if fraction else 0
        return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)),
                        min(second, 59), micro, tzinfo=timezone(offset))
    except ValueError:
        return None


def _format_ok(fmt: str, value: str) -> bool:
    if fmt == 'date-time':
        return parse_date_time(value) is not None
    return _URI.fullmatch(value) is not None  # 'uri': absolute (scheme) and no whitespace/control characters


_CVSS = {'cvss-v2.0': (('2.0',), False), 'cvss-v3.0': (('3.0',), True), 'cvss-v3.1': (('3.1',), True)}
_SEVERITIES = frozenset({'NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'})


class _Collector:
    def __init__(self, limits: Limits, cancel: threading.Event | None):
        self.errors: list[Finding] = []
        self.warnings: list[Finding] = []
        self.truncated = False
        self.limits = limits
        self.cancel = cancel
        self.steps = 0

    def add(self, test: str, pointer: str, message: str, severity: str = 'error') -> None:
        bucket = self.errors if severity == 'error' else self.warnings
        if len(bucket) >= self.limits.max_findings:
            self.truncated = True
            return
        bucket.append(Finding(test=test, severity=severity, pointer=pointer, message=message[:500]))

    def tick(self) -> None:
        self.steps += 1
        if self.steps % _CANCEL_EVERY == 0:
            _cancelled(self.cancel)


class _Schema:
    def __init__(self, root: dict, collector: _Collector):
        self.defs = root.get('$defs', {})
        self.c = collector

    def check(self, schema: dict, value, pointer: str) -> None:
        self.c.tick()
        if '$ref' in schema:
            self.check(self.defs[schema['$ref'].rsplit('/', 1)[1]], value, pointer)
        if '$external' in schema:
            self._cvss(schema['$external'], value, pointer)
        expected = schema.get('type')
        if expected is not None and not _is_type(expected, value):
            self.c.add('schema', pointer, f'expected {expected}, found {_type_name(value)}')
            return
        if 'enum' in schema and value not in schema['enum']:
            self.c.add('schema', pointer, f'value {safe_label(value)} is not one of the allowed values')
        if isinstance(value, str):
            if 'minLength' in schema and len(value) < schema['minLength']:
                self.c.add('schema', pointer, f'string shorter than {schema["minLength"]}')
            if 'pattern' in schema and not _pattern(schema['pattern']).search(value):
                self.c.add('schema', pointer, f'value {safe_label(value)} does not match the required pattern')
            if 'format' in schema and not _format_ok(schema['format'], value):
                self.c.add('schema', pointer, f'value {safe_label(value)} is not a valid {schema["format"]}')
        if isinstance(value, dict):
            self._object(schema, value, pointer)
        elif isinstance(value, list):
            self._array(schema, value, pointer)
        if 'oneOf' in schema:
            matches = sum(1 for sub in schema['oneOf'] if self._matches(sub, value, pointer))
            if matches != 1:
                self.c.add('schema', pointer, f'must match exactly one alternative (matched {matches})')

    def _object(self, schema: dict, value: dict, pointer: str) -> None:
        for name in schema.get('required', ()):
            if name not in value:
                self.c.add('schema', pointer, f'required property {name!r} is missing')
        if 'minProperties' in schema and len(value) < schema['minProperties']:
            self.c.add('schema', pointer, f'needs at least {schema["minProperties"]} properties')
        if 'maxProperties' in schema and len(value) > schema['maxProperties']:
            self.c.add('schema', pointer, f'allows at most {schema["maxProperties"]} properties')
        properties = schema.get('properties')
        if properties is None:
            return
        for key, sub in value.items():
            child = f'{pointer}/{escape_token(key)}'
            if key in properties:
                self.check(properties[key], sub, child)
            else:
                self.c.add('6.2.20', child, f'additional property {safe_label(key)} is not defined by CSAF 2.0',
                           severity='warning')

    def _array(self, schema: dict, value: list, pointer: str) -> None:
        if 'minItems' in schema and len(value) < schema['minItems']:
            self.c.add('schema', pointer, f'needs at least {schema["minItems"]} items')
        if schema.get('uniqueItems'):
            seen: set[str] = set()
            for index, item in enumerate(value):
                key = json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
                if key in seen:
                    self.c.add('schema', f'{pointer}/{index}', 'duplicate item in an array that requires unique items')
                seen.add(key)
        items = schema.get('items')
        if items is not None:
            for index, item in enumerate(value):
                self.check(items, item, f'{pointer}/{index}')

    def _matches(self, schema: dict, value, pointer: str) -> bool:
        probe = _Collector(Limits(max_findings=1), self.c.cancel)
        _Schema({'$defs': self.defs}, probe).check(schema, value, pointer)
        return not probe.errors

    def _cvss(self, kind: str, value, pointer: str) -> None:
        versions, severity = _CVSS[kind]
        if not isinstance(value, dict):
            self.c.add('schema', pointer, f'{kind} object expected')
            return
        if value.get('version') not in versions:
            self.c.add('schema', f'{pointer}/version', f'{kind} requires version {versions[0]}')
        vector = value.get('vectorString')
        prefix = f'CVSS:{versions[0]}/' if severity else ''
        if not isinstance(vector, str) or not vector or len(vector) > 1000 or not vector.startswith(prefix):
            self.c.add('schema', f'{pointer}/vectorString', f'{kind} requires a vectorString')
        score = value.get('baseScore')
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 10:
            self.c.add('schema', f'{pointer}/baseScore', f'{kind} requires a baseScore between 0 and 10')
        if severity and value.get('baseSeverity') not in _SEVERITIES:
            self.c.add('schema', f'{pointer}/baseSeverity', f'{kind} requires a baseSeverity')


def _is_type(expected: str, value) -> bool:
    if expected == 'object':
        return isinstance(value, dict)
    if expected == 'array':
        return isinstance(value, list)
    if expected == 'string':
        return isinstance(value, str)
    if expected == 'boolean':
        return isinstance(value, bool)
    if expected == 'integer':
        return isinstance(value, int) and not isinstance(value, bool)
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _type_name(value) -> str:
    for name, kind in (('null', type(None)), ('boolean', bool), ('integer', int), ('number', float),
                       ('string', str), ('array', list), ('object', dict)):
        if isinstance(value, kind):
            return name
    return type(value).__name__


def check_schema(value, schema: dict, *, limits: Limits = LIMITS,
                 cancel: threading.Event | None = None) -> tuple[list[Finding], list[Finding], bool]:
    """Interpret ``schema`` (a generated constraint table) over ``value``; returns (errors, warnings, truncated)."""
    collector = _Collector(limits, cancel)
    _Schema(schema, collector).check(schema, value, '')
    return collector.errors, collector.warnings, collector.truncated


# ---------------------------------------------------------------------------------------------- 3. mandatory tests

@dataclass(frozen=True)
class _Version:
    integer: bool
    major: int
    minor: int
    patch: int
    pre: tuple
    text_core: str  # without build metadata

    @property
    def prerelease(self) -> bool:
        return bool(self.pre)


_SEMVER = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?')


def _version(text: str) -> _Version | None:
    if re.fullmatch(r'0|[1-9][0-9]*', text):
        return _Version(True, int(text), 0, 0, (), text)
    m = _SEMVER.fullmatch(text)
    if m is None:
        return None
    pre = tuple((0, int(p), '') if p.isdigit() else (1, 0, p) for p in m.group(4).split('.')) if m.group(4) else ()
    core = text.split('+', 1)[0]
    return _Version(False, int(m.group(1)), int(m.group(2)), int(m.group(3)), pre, core)


def _precedence(v: _Version) -> tuple:
    # SemVer 2.0.0 §11: a pre-release sorts before its release; build metadata never counts.
    return (v.major, v.minor, v.patch, 0 if v.pre else 1, v.pre)


def _product_definitions(doc: dict) -> Iterator[tuple[str, str]]:
    """(product_id, JSON pointer) of every Full Product Name definition (§6.1.2 paths), document order."""
    tree = doc.get('product_tree') or {}
    stack = deque([(tree.get('branches'), '/product_tree/branches')])
    while stack:
        branches, base = stack.popleft()
        for index, branch in enumerate(branches or ()):
            pointer = f'{base}/{index}'
            product = branch.get('product')
            if isinstance(product, dict):
                yield product['product_id'], f'{pointer}/product/product_id'
            if isinstance(branch.get('branches'), list):
                stack.append((branch['branches'], f'{pointer}/branches'))
    for index, item in enumerate(tree.get('full_product_names') or ()):
        yield item['product_id'], f'/product_tree/full_product_names/{index}/product_id'
    for index, item in enumerate(tree.get('relationships') or ()):
        yield item['full_product_name']['product_id'], f'/product_tree/relationships/{index}/full_product_name/product_id'


def iter_branches(doc: dict) -> Iterator[tuple[dict, str, tuple]]:
    """Every branch object with its pointer and ancestor path, breadth-first, without recursion."""
    tree = doc.get('product_tree') or {}
    queue = deque([(tree.get('branches'), '/product_tree/branches', ())])
    while queue:
        branches, base, path = queue.popleft()
        for index, branch in enumerate(branches or ()):
            pointer = f'{base}/{index}'
            here = (*path, (branch.get('category'), branch.get('name')))
            yield branch, pointer, here
            if isinstance(branch.get('branches'), list):
                queue.append((branch['branches'], f'{pointer}/branches', here))


def _references(doc: dict) -> Iterator[tuple[str, str]]:
    """(product_id, pointer) of every §6.1.1 product reference."""
    tree = doc.get('product_tree') or {}
    for g, group in enumerate(tree.get('product_groups') or ()):
        for i, pid in enumerate(group['product_ids']):
            yield pid, f'/product_tree/product_groups/{g}/product_ids/{i}'
    for r, rel in enumerate(tree.get('relationships') or ()):
        yield rel['product_reference'], f'/product_tree/relationships/{r}/product_reference'
        yield rel['relates_to_product_reference'], f'/product_tree/relationships/{r}/relates_to_product_reference'
    for v, vuln in enumerate(doc.get('vulnerabilities') or ()):
        for status, ids in (vuln.get('product_status') or {}).items():
            for i, pid in enumerate(ids):
                yield pid, f'/vulnerabilities/{v}/product_status/{status}/{i}'
        for name, key in (('remediations', 'product_ids'), ('scores', 'products'), ('threats', 'product_ids')):
            for k, item in enumerate(vuln.get(name) or ()):
                for i, pid in enumerate(item.get(key) or ()):
                    yield pid, f'/vulnerabilities/{v}/{name}/{k}/{key}/{i}'


class _Tests:
    def __init__(self, doc: dict, c: _Collector):
        self.doc = doc
        self.c = c
        self.tree = doc.get('product_tree') or {}
        self.vulns = doc.get('vulnerabilities') or []
        self.category = doc['document']['category']
        self.defined: dict[str, list[str]] = defaultdict(list)
        for pid, pointer in _product_definitions(doc):
            self.defined[pid].append(pointer)
        self.groups: dict[str, list[str]] = defaultdict(list)
        self.group_members: dict[str, tuple[str, ...]] = {}
        for g, group in enumerate(self.tree.get('product_groups') or ()):
            self.groups[group['group_id']].append(f'/product_tree/product_groups/{g}/group_id')
            self.group_members.setdefault(group['group_id'], tuple(group['product_ids']))

    def run(self) -> None:
        for test in (self.t_6_1_1, self.t_6_1_2, self.t_6_1_3, self.t_6_1_4, self.t_6_1_5, self.t_6_1_6,
                     self.t_6_1_7, self.t_revision_history, self.t_6_1_15, self.t_6_1_23, self.t_6_1_24,
                     self.t_6_1_25, self.t_6_1_26, self.t_profiles, self.t_6_1_28, self.t_6_1_29, self.t_6_1_31,
                     self.t_6_1_32, self.t_6_1_33, self.t_6_2_1):
            _cancelled(self.c.cancel)
            test()

    def t_6_1_1(self) -> None:
        for pid, pointer in _references(self.doc):
            if pid not in self.defined:
                self.c.add('6.1.1', pointer, f'product id {safe_label(pid)} is not defined in the product tree')
        for v, vuln in enumerate(self.vulns):  # flags are not a 6.1.1 path in CSAF 2.0: warn only
            for k, flag in enumerate(vuln.get('flags') or ()):
                for i, pid in enumerate(flag.get('product_ids') or ()):
                    if pid not in self.defined:
                        self.c.add('6.1.1', f'/vulnerabilities/{v}/flags/{k}/product_ids/{i}',
                                   f'flag references undefined product id {safe_label(pid)}', severity='warning')

    def t_6_1_2(self) -> None:
        for pid, pointers in self.defined.items():
            for pointer in pointers[1:]:
                self.c.add('6.1.2', pointer, f'product id {safe_label(pid)} is defined more than once')
        if len(self.defined) > self.c.limits.max_products:
            self.c.add('limit', '/product_tree', f'more than {self.c.limits.max_products} product definitions')

    def t_6_1_3(self) -> None:
        # Iterative three-colour DFS over relationship-defined products: P -> product_reference,
        # relates_to_product_reference. Any back edge is a circular definition.
        edges: dict[str, tuple[str, str]] = {}
        where: dict[str, str] = {}
        for r, rel in enumerate(self.tree.get('relationships') or ()):
            pid = rel['full_product_name']['product_id']
            edges.setdefault(pid, (rel['product_reference'], rel['relates_to_product_reference']))
            where.setdefault(pid, f'/product_tree/relationships/{r}/full_product_name/product_id')
        state: dict[str, int] = {}
        reported: set[str] = set()
        for start in edges:
            if state.get(start):
                continue
            state[start] = 1
            stack = [(start, iter(edges[start]))]
            while stack:
                node, children = stack[-1]
                child = next(children, None)
                if child is None:
                    state[node] = 2
                    stack.pop()
                    continue
                if child not in edges:
                    continue
                if state.get(child) == 1:
                    if child not in reported:
                        reported.add(child)
                        self.c.add('6.1.3', where[child], f'product id {safe_label(child)} has a circular definition')
                elif not state.get(child):
                    state[child] = 1
                    stack.append((child, iter(edges[child])))

    def _group_refs(self) -> Iterator[tuple[str, str, str]]:
        for v, vuln in enumerate(self.vulns):
            for name in ('remediations', 'threats', 'flags'):
                for k, item in enumerate(vuln.get(name) or ()):
                    for i, gid in enumerate(item.get('group_ids') or ()):
                        yield gid, f'/vulnerabilities/{v}/{name}/{k}/group_ids/{i}', name

    def t_6_1_4(self) -> None:
        for gid, pointer, name in self._group_refs():
            if gid not in self.groups:
                self.c.add('6.1.4', pointer, f'group id {safe_label(gid)} is not defined in the product tree',
                           severity='warning' if name == 'flags' else 'error')

    def t_6_1_5(self) -> None:
        for gid, pointers in self.groups.items():
            for pointer in pointers[1:]:
                self.c.add('6.1.5', pointer, f'group id {safe_label(gid)} is defined more than once')

    def t_6_1_6(self) -> None:
        for v, vuln in enumerate(self.vulns):
            seen: dict[str, str] = {}
            for status, ids in sorted((vuln.get('product_status') or {}).items()):
                group = STATUS_GROUPS.get(status)
                if group is None:
                    continue
                for i, pid in enumerate(ids):
                    other = seen.setdefault(pid, group)
                    if other != group:
                        self.c.add('6.1.6', f'/vulnerabilities/{v}/product_status/{status}/{i}',
                                   f'product id {safe_label(pid)} is both "{other}" and "{group}"')

    def t_6_1_7(self) -> None:
        for v, vuln in enumerate(self.vulns):
            seen: Counter = Counter()
            for s, score in enumerate(vuln.get('scores') or ()):
                versions = []
                if 'cvss_v2' in score:
                    versions.append(score['cvss_v2'].get('version'))
                if 'cvss_v3' in score:
                    versions.append(score['cvss_v3'].get('version'))
                for pid in score.get('products') or ():
                    for version in versions:
                        seen[(pid, version)] += 1
                        if seen[(pid, version)] == 2:
                            self.c.add('6.1.7', f'/vulnerabilities/{v}/scores/{s}',
                                       f'product id {safe_label(pid)} has more than one CVSS {version} score')

    def t_revision_history(self) -> None:
        """6.1.14, 6.1.16-6.1.22 and 6.1.30 (all read the same revision history)."""
        tracking = self.doc['document']['tracking']
        status = tracking['status']
        base = '/document/tracking/revision_history'
        items = []
        for index, item in enumerate(tracking['revision_history']):
            items.append((parse_date_time(item['date']), index, _version(item['number']), item['number']))
        doc_version = _version(tracking['version'])
        if doc_version is None or any(v is None for _, _, v, _ in items) or any(d is None for d, _, _, _ in items):
            return  # the schema layer already reported the malformed value
        kinds = {doc_version.integer, *(v.integer for _, _, v, _ in items)}
        if len(kinds) > 1:
            self.c.add('6.1.30', '/document/tracking/version', 'integer and semantic versioning are mixed')
            return
        ordered = sorted(items, key=lambda t: (t[0], t[1]))
        for (_, _, prev, _), (_, index, cur, _) in zip(ordered, ordered[1:], strict=False):
            if _precedence(cur) < _precedence(prev):
                self.c.add('6.1.14', f'{base}/{index}/number', 'revision numbers are not ascending by date')
        last = ordered[-1][2]
        def comparable(v: _Version) -> tuple:
            return (v.major, v.minor, v.patch, () if status == 'draft' else v.pre)
        if comparable(doc_version) != comparable(last):
            self.c.add('6.1.16', '/document/tracking/version',
                       'document version differs from the latest revision history number')
        zero = doc_version.major == 0
        if (zero or doc_version.prerelease) and status != 'draft':
            self.c.add('6.1.17', '/document/tracking/status', 'version 0, 0.y.z or a pre-release requires status draft')
        for _, index, version, _ in items:
            if status in ('final', 'interim') and version.major == 0:
                self.c.add('6.1.18', f'{base}/{index}/number', 'a released document lists revision 0 or 0.y.z')
            if version.prerelease:
                self.c.add('6.1.19', f'{base}/{index}/number', 'revision history lists a pre-release version')
        if status in ('final', 'interim') and doc_version.prerelease:
            self.c.add('6.1.20', '/document/tracking/version', 'a final or interim document has a pre-release version')
        majors = [v.major for _, _, v, _ in ordered]
        if majors[0] not in (0, 1):
            self.c.add('6.1.21', f'{base}/{ordered[0][1]}/number', 'the first revision must be 0 or 1')
        for (_, _, prev, _), (_, index, cur, _) in zip(ordered, ordered[1:], strict=False):
            if cur.major - prev.major > 1:
                self.c.add('6.1.21', f'{base}/{index}/number', f'revision {prev.major + 1} is missing')
        seen: set[str] = set()
        for _, index, version, _ in items:
            key = version.text_core
            if key in seen:
                self.c.add('6.1.22', f'{base}/{index}/number', 'revision number defined more than once')
            seen.add(key)

    def t_6_1_15(self) -> None:
        document = self.doc['document']
        if document['publisher']['category'] == 'translator' and not document.get('source_lang'):
            self.c.add('6.1.15', '/document/source_lang', 'a translator document needs source_lang')

    def t_6_1_23(self) -> None:
        seen: set[str] = set()
        for v, vuln in enumerate(self.vulns):
            cve = vuln.get('cve')
            if cve is None:
                continue
            if cve in seen:
                self.c.add('6.1.23', f'/vulnerabilities/{v}/cve', f'{safe_label(cve)} is used by more than one item')
            seen.add(cve)
        if len(self.vulns) > self.c.limits.max_vulnerabilities:
            self.c.add('limit', '/vulnerabilities', f'more than {self.c.limits.max_vulnerabilities} vulnerabilities')

    def t_6_1_24(self) -> None:
        for v, vuln in enumerate(self.vulns):
            seen: set[tuple] = set()
            for k, item in enumerate(vuln.get('involvements') or ()):
                key = (item.get('party'), item.get('date'))
                if key in seen:
                    self.c.add('6.1.24', f'/vulnerabilities/{v}/involvements/{k}', 'party listed twice for one date')
                seen.add(key)

    def _helpers(self) -> Iterator[tuple[dict, str]]:
        for branch, pointer, _ in iter_branches(self.doc):
            if isinstance(branch.get('product'), dict):
                yield branch['product'], f'{pointer}/product'
        for index, item in enumerate(self.tree.get('full_product_names') or ()):
            yield item, f'/product_tree/full_product_names/{index}'
        for index, item in enumerate(self.tree.get('relationships') or ()):
            yield item['full_product_name'], f'/product_tree/relationships/{index}/full_product_name'

    def t_6_1_25(self) -> None:
        for product, pointer in self._helpers():
            for h, entry in enumerate((product.get('product_identification_helper') or {}).get('hashes') or ()):
                algorithms = [f.get('algorithm') for f in entry.get('file_hashes') or ()]
                for name, count in Counter(algorithms).items():
                    if count > 1:
                        self.c.add('6.1.25', f'{pointer}/product_identification_helper/hashes/{h}',
                                   f'hash algorithm {safe_label(name)} is used more than once')

    def t_6_1_26(self) -> None:
        category = self.category
        if category in PROFILES:
            return
        squashed = re.sub(r'[-\s_]', '', category).lower()
        names = {re.sub(r'[-\s_]', '', p).lower() for p in PROFILES if p != 'csaf_base'}
        names |= {re.sub(r'[-\s_]', '', p[5:]).lower() for p in PROFILES if p != 'csaf_base'}
        if squashed in names or category.lower().startswith('csaf_'):
            self.c.add('6.1.26', '/document/category', f'category {safe_label(category)} is reserved or prohibited')

    def t_profiles(self) -> None:
        document, category = self.doc['document'], self.category
        if category in ('csaf_informational_advisory', 'csaf_security_incident_response'):
            notes = document.get('notes') or ()
            if not any(n.get('category') in ('description', 'details', 'general', 'summary') for n in notes):
                self.c.add('6.1.27.1', '/document/notes', 'needs a description, details, general or summary note')
            if not any(r.get('category') == 'external' for r in document.get('references') or ()):
                self.c.add('6.1.27.2', '/document/references', 'needs at least one external reference')
        if category == 'csaf_informational_advisory' and 'vulnerabilities' in self.doc:
            self.c.add('6.1.27.3', '/vulnerabilities', 'an informational advisory has no vulnerabilities')
        if category not in ('csaf_security_advisory', 'csaf_vex'):
            return
        if 'product_tree' not in self.doc:
            self.c.add('6.1.27.4', '/product_tree', 'the product tree is required by this profile')
        if 'vulnerabilities' not in self.doc:
            self.c.add('6.1.27.11', '/vulnerabilities', 'vulnerabilities are required by this profile')
        for v, vuln in enumerate(self.vulns):
            pointer = f'/vulnerabilities/{v}'
            if 'notes' not in vuln:
                self.c.add('6.1.27.5', pointer, 'each vulnerability needs notes in this profile')
            status = vuln.get('product_status') or {}
            if category == 'csaf_security_advisory' and 'product_status' not in vuln:
                self.c.add('6.1.27.6', pointer, 'each vulnerability needs product_status in this profile')
            if category != 'csaf_vex':
                continue
            if not any(k in status for k in ('fixed', 'known_affected', 'known_not_affected', 'under_investigation')):
                self.c.add('6.1.27.7', f'{pointer}/product_status', 'a VEX item needs fixed, known_affected, '
                           'known_not_affected or under_investigation')
            if 'cve' not in vuln and 'ids' not in vuln:
                self.c.add('6.1.27.8', pointer, 'a VEX item needs cve or ids')
            impact = self._covered(vuln, ('flags',)) | self._covered(vuln, ('threats',), category='impact')
            for i, pid in enumerate(status.get('known_not_affected') or ()):
                if pid not in impact:
                    self.c.add('6.1.27.9', f'{pointer}/product_status/known_not_affected/{i}',
                               f'no impact statement for {safe_label(pid)}')
            action = self._covered(vuln, ('remediations',))
            for i, pid in enumerate(status.get('known_affected') or ()):
                if pid not in action:
                    self.c.add('6.1.27.10', f'{pointer}/product_status/known_affected/{i}',
                               f'no action statement for {safe_label(pid)}')

    def _covered(self, vuln: dict, names: tuple[str, ...], category: str | None = None) -> set[str]:
        out: set[str] = set()
        for name in names:
            for item in vuln.get(name) or ():
                if category is not None and item.get('category') != category:
                    continue
                out.update(item.get('product_ids') or ())
                for gid in item.get('group_ids') or ():
                    out.update(self.group_members.get(gid, ()))
        return out

    def t_6_1_28(self) -> None:
        document = self.doc['document']
        lang, source = document.get('lang'), document.get('source_lang')
        if lang and source and lang.lower() == source.lower():
            self.c.add('6.1.28', '/document/source_lang', 'source language equals the document language')

    def t_6_1_29(self) -> None:
        for v, vuln in enumerate(self.vulns):
            for k, item in enumerate(vuln.get('remediations') or ()):
                if not item.get('product_ids') and not item.get('group_ids'):
                    self.c.add('6.1.29', f'/vulnerabilities/{v}/remediations/{k}', 'remediation names no product')

    def t_6_1_31(self) -> None:
        for branch, pointer, _ in iter_branches(self.doc):
            if branch.get('category') != 'product_version':
                continue
            name = str(branch.get('name', '')).lower()
            if any(word in name for word in RANGE_WORDS):
                self.c.add('6.1.31', f'{pointer}/name', f'product_version {safe_label(branch.get("name"))} looks like a range')

    def t_6_1_32(self) -> None:
        for v, vuln in enumerate(self.vulns):
            for k, flag in enumerate(vuln.get('flags') or ()):
                if not flag.get('product_ids') and not flag.get('group_ids'):
                    self.c.add('6.1.32', f'/vulnerabilities/{v}/flags/{k}', 'flag names no product')

    def t_6_1_33(self) -> None:
        for v, vuln in enumerate(self.vulns):
            owners: dict[str, int] = {}
            for k, flag in enumerate(vuln.get('flags') or ()):
                if flag.get('label') not in VEX_LABELS:
                    continue
                products = set(flag.get('product_ids') or ())
                for gid in flag.get('group_ids') or ():
                    products.update(self.group_members.get(gid, ()))
                for pid in sorted(products):
                    if pid in owners:
                        self.c.add('6.1.33', f'/vulnerabilities/{v}/flags/{k}',
                                   f'{safe_label(pid)} has more than one VEX justification flag')
                    owners.setdefault(pid, k)

    def t_6_2_1(self) -> None:
        if self.category == 'csaf_informational_advisory':
            return
        used = {pid for pid, _ in _references(self.doc)}
        for vuln in self.vulns:
            for flag in vuln.get('flags') or ():
                used.update(flag.get('product_ids') or ())
        for pid, pointers in self.defined.items():
            if pid not in used:
                self.c.add('6.2.1', pointers[0], f'product id {safe_label(pid)} is never referenced', severity='warning')


def validate_document(doc, *, limits: Limits = LIMITS, cancel: threading.Event | None = None) -> ValidationReport:
    """Schema keywords, then (only on a schema-valid document) the mandatory and optional tests."""
    if not isinstance(doc, dict):
        raise IntelError('PT-INTEL-FORMAT', 'a CSAF document is a JSON object')
    document = doc.get('document')
    version = document.get('csaf_version') if isinstance(document, dict) else None
    if version != '2.0':
        raise IntelError('PT-INTEL-UNSUPPORTED', f'csaf_version {safe_label(version)} is not supported; only 2.0')
    collector = _Collector(limits, cancel)
    _Schema(schema_data.CSAF_SCHEMA, collector).check(schema_data.CSAF_SCHEMA, doc, '')
    if not collector.errors:
        _Tests(doc, collector).run()
    category = document.get('category') if isinstance(document.get('category'), str) else ''
    key = _finding_key
    return ValidationReport(validator_version=VALIDATOR_VERSION, document_category=category[:1000],
                            errors=tuple(sorted(collector.errors, key=key)),
                            warnings=tuple(sorted(collector.warnings, key=key)), tests_run=TESTS_RUN,
                            tests_not_implemented=TESTS_NOT_IMPLEMENTED, truncated=collector.truncated)


def _finding_key(f: Finding) -> tuple:
    return (f.pointer, f.test, f.message)


def load_document(raw: bytes, *, limits: Limits = LIMITS,
                  cancel: threading.Event | None = None) -> tuple[dict, ValidationReport]:
    """Parse and validate exact bytes. Returns (document, report) only for an accepted document; otherwise
    raises ``IntelError`` (FORMAT/LIMIT/UNSUPPORTED/CANCEL) or ``ValidationFailed`` (with the full report)."""
    _cancelled(cancel)
    doc = parse_json(raw, limits=limits)
    report = validate_document(doc, limits=limits, cancel=cancel)
    if report.errors:
        raise ValidationFailed(report)
    return doc, report


def provider_metadata_errors(value, cancel: threading.Event | None = None) -> list[Finding]:
    """Provider-metadata (§7.1.7) schema check; returns the errors (an empty list means acceptable)."""
    errors, _warnings, _ = check_schema(value, schema_data.PROVIDER_SCHEMA, cancel=cancel)
    return errors

