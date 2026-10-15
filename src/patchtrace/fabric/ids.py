"""Identities, key grammars and the semantic checks of the fabric (FAB-integration-plan.md s4, s7). Pure.

Each id is `enrichment.identity.domain_id(<domain>, 1, payload)` over canonical JSON; the domains are listed in
`DOMAINS`. Labels, facets, tool names and timestamps are never identity, and optional fields that are None are left
out of a witness payload so that an additive field never changes an old id. The `pair:` key re-derives the SPEC-31
`unified.keys.row_id` formula (and PIL's `candidate_key`) so that this package imports no other feature; a test pins
the three to each other.

Producers build records with `make_witness` and `make_anchor`, which sanitise text, derive the ids and raise typed
`PT-FAB-*` errors. Anything that arrives from elsewhere (a store, a sidecar, another producer) goes through
`verify_anchor`, which recomputes every id and re-applies `check_anchor`.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Iterable, Mapping

from pydantic import ValidationError

from ..enrichment.identity import domain_id
from .contracts import (
    KINDS,
    ROLES_BY_KIND,
    SHA256_RE,
    Anchor,
    PairRef,
    Ref,
    Witness,
    clean_line,
)
from .limits import DEFAULT_LIMITS, FabricError

DOMAINS = ('fabric-anchor', 'fabric-witness', 'fabric-anchors', 'fabric-origins', 'unified-row')
_L = DEFAULT_LIMITS
_RVA_MAX = 2**32 - 1
_ZERO = '0' * 64
_PAIR_KEY = re.compile(r'pair:[0-9a-f]{64}')
_IMAGE_KEY = re.compile(r'image:([0-9a-f]{64}):rva:0x[0-9a-f]{1,8}')
_RULE_KEY = re.compile(r'patch:R-[A-Z0-9-]{1,40}@[A-Za-z0-9._/-]{1,40}|yara:[0-9a-f]{12}\.v[0-9]{1,6}')
_BUILD_KEY = re.compile(r'[a-z][a-z0-9_]{0,31}=.{1,160}')
_CVE_KEY = re.compile(r'CVE-[0-9]{4}-[0-9]{4,19}')
_CWE_KEY = re.compile(r'CWE-[1-9][0-9]{0,5}')
_KB_KEY = re.compile(r'KB[0-9]{5,9}')
_ORDINAL_KEY = re.compile(r'[a-z0-9_.-]{1,64}!#[0-9]{1,5}')
_DLL = re.compile(r'[a-z0-9_.-]{1,64}')
_ORDINAL_TEXT = re.compile(r'(.+)!#([0-9]{1,5})')
_ASCII_LOWER = {code: code + 32 for code in range(ord('A'), ord('Z') + 1)}


def _error(code: str, message: str, reason: str) -> FabricError:
    return FabricError(code, message, reason=reason)


def _key_error(reason: str, message: str = 'The key does not match the grammar of its kind') -> FabricError:
    return _error('PT-FAB-KEY', message, reason)


# --- identities -----------------------------------------------------------------------------------------------------

def anchor_id(kind: str, key: str, side: str, role: str, subject: str | None) -> str:
    return domain_id('fabric-anchor', 1, {'kind': kind, 'key': key, 'side': side, 'role': role, 'subject': subject})


def witness_id(witness: Witness) -> str:
    payload = witness.model_dump(mode='json', exclude_none=True)
    del payload['witness_id']
    return domain_id('fabric-witness', 1, payload)


def anchors_digest(anchors: Iterable[Anchor]) -> str:
    """Order-independent digest of a set of anchors and their witnesses (a cache-key input for consumers)."""
    rows = sorted([anchor.anchor_id, [witness.witness_id for witness in anchor.witnesses]] for anchor in anchors)
    return domain_id('fabric-anchors', 1, rows)


# --- keys -----------------------------------------------------------------------------------------------------------

def _sha(value: object, reason: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise _key_error(reason, 'A SHA-256 must be 64 lower-case hex digits')
    return value


def _rva(value: object, reason: str) -> int:
    if type(value) is not int or not 0 <= value <= _RVA_MAX:
        raise _key_error(reason, 'An RVA must be an int in 0..2**32-1')
    return value


def pair_key(older_sha256: str, newer_sha256: str, older_rvas: Iterable[int], newer_rvas: Iterable[int]) -> str:
    """`pair:` + the SPEC-31 row id: orientation-sensitive, independent of RVA order, one side may be empty."""
    sides = {}
    for side, values in (('older', older_rvas), ('newer', newer_rvas)):
        items = [_rva(value, f'{side}-rva') for value in values]
        if len(set(items)) != len(items):
            raise _key_error(f'{side}-rva-duplicate', 'The RVAs of one side must be unique')
        sides[side] = sorted(items)
    if not sides['older'] and not sides['newer']:
        raise _key_error('pair-empty', 'A pair needs at least one RVA')
    return 'pair:' + domain_id('unified-row', 1, {
        'older_sha256': _sha(older_sha256, 'older-sha256'), 'newer_sha256': _sha(newer_sha256, 'newer-sha256'),
        'older_rvas': sides['older'], 'newer_rvas': sides['newer']})


def pair_key_of(pair: PairRef) -> str:
    return pair_key(pair.older_sha256, pair.newer_sha256, pair.older_rvas, pair.newer_rvas)


def image_key(artifact_sha256: str, rva: int) -> str:
    """A function of one image by RVA (the `rva:0x<hex>` function id of the tool adapters, qualified by the image)."""
    return f'image:{_sha(artifact_sha256, "artifact-sha256")}:rva:0x{_rva(rva, "rva"):x}'


def pair_members(pair: PairRef) -> tuple[str, ...]:
    """The `image:` keys of the functions a pair names, older side first."""
    return (*(image_key(pair.older_sha256, rva) for rva in pair.older_rvas),
            *(image_key(pair.newer_sha256, rva) for rva in pair.newer_rvas))


def string_key(value: str) -> str:
    """SHA-256 of the NFC text with ASCII letters lower-cased (UTF-8). Unicode case folding is avoided on purpose: the
    Unicode database differs between Python versions and a content key must not. For lower-case ASCII text it equals
    the plain SHA-256 of the bytes."""
    if not isinstance(value, str) or not value:
        raise _key_error('text-empty', 'A string key needs non-empty text')
    folded = unicodedata.normalize('NFC', value).translate(_ASCII_LOWER)
    try:
        return hashlib.sha256(folded.encode('utf-8')).hexdigest()
    except UnicodeEncodeError:
        raise _key_error('text-encoding', 'A string key needs UTF-8 encodable text') from None


def api_key(name: str) -> str:
    """The join key of a named import (CAP-integration-plan s4): module qualifier dropped (up to the last `!` or `.`),
    ASCII lower case, a trailing a or w folded when at least 4 characters remain. Join-only: never displayed. Apply it
    once, to the name as the tool reports it: a second application can fold again."""
    if not isinstance(name, str):
        raise _key_error('name-type', 'An import name must be text')
    text = name.strip()
    if not all(0x21 <= ord(char) <= 0x7E for char in text):
        raise _key_error('name-charset', 'An import name is ASCII without spaces or controls')
    text = re.split(r'[!.]', text)[-1]
    if not text:
        raise _key_error('name-empty', 'An import name must not be empty')
    if text.startswith('#'):
        raise _key_error('name-ordinal', 'An ordinal import keeps its module: use ordinal_key')
    text = text.lower()
    if len(text) - 1 >= 4 and text[-1] in 'aw':
        text = text[:-1]
    if len(text) > _L.f06_key_chars:
        raise _key_error('name-length', 'An import name is too long')
    return text


def ordinal_key(dll: str, ordinal: int) -> str:
    """`<dll>!#<n>`: an ordinal means something only within its DLL (the PE import lookup table, 16-bit ordinal)."""
    if type(ordinal) is not int or not 0 <= ordinal <= 0xFFFF:
        raise _key_error('ordinal', 'An import ordinal is a 16-bit number')
    name = dll.strip().lower() if isinstance(dll, str) else ''
    if name.endswith('.dll'):
        name = name[:-4]
    if not _DLL.fullmatch(name):
        raise _key_error('ordinal-dll', 'An ordinal import needs the name of its DLL')
    return f'{name}!#{ordinal}'


def _upper_ascii(value: object, reason: str) -> str:
    if not isinstance(value, str) or not value.isascii():
        raise _key_error(reason, 'The identifier must be ASCII text')
    return value.strip().upper()


def cve_key(value: str) -> str:
    text = _upper_ascii(value, 'cve')
    if not _CVE_KEY.fullmatch(text):
        raise _key_error('cve', 'Not a CVE id')
    return text


def cwe_key(value: str) -> str:
    text = _upper_ascii(value, 'cwe')
    if re.fullmatch(r'[0-9]+', text):
        text = 'CWE-' + text
    elif re.fullmatch(r'CWE[0-9]+', text):
        text = 'CWE-' + text[3:]
    if not _CWE_KEY.fullmatch(text):
        raise _key_error('cwe', 'Not a CWE id')
    return text


def kb_key(value: str) -> str:
    text = _upper_ascii(value, 'kb')
    if re.fullmatch(r'[0-9]+', text):
        text = 'KB' + text
    if not _KB_KEY.fullmatch(text):
        raise _key_error('kb', 'Not a KB article id')
    return text


def key_for_value(kind: str, value: str) -> str | None:
    """The key a display value stands for (`AnchorReader.resolve`). None means the value is not a key of that kind: only
    a `function` name, which readers match against the facet `name`."""
    if kind not in KINDS:
        raise _error('PT-FAB-KIND', 'Unknown anchor kind', 'kind')
    if kind in ('string', 'advisory_phrase'):
        return string_key(value)
    if kind == 'import':
        ordinal = _ORDINAL_TEXT.fullmatch(value.strip()) if isinstance(value, str) else None
        return ordinal_key(ordinal.group(1), int(ordinal.group(2))) if ordinal else api_key(value)
    converters = {'cve': cve_key, 'cwe': cwe_key, 'kb': kb_key}
    if kind in converters:
        return converters[kind](value)
    if not isinstance(value, str):
        raise _key_error('value-type', 'The value must be text')
    if kind == 'function':
        if not value.startswith(('pair:', 'image:')):
            return None
        if not _function_key_ok(value):
            raise _key_error('key-grammar')
        return value
    return unicodedata.normalize('NFC', value)


# --- semantic checks ------------------------------------------------------------------------------------------------

def _function_key_ok(key: str) -> bool:
    return bool(_PAIR_KEY.fullmatch(key) or _IMAGE_KEY.fullmatch(key))


def _import_key_ok(key: str) -> bool:
    if _ORDINAL_KEY.fullmatch(key):
        return True
    return (all(0x21 <= ord(char) <= 0x7E for char in key) and key == key.lower() and not set(key) & {'!', '.'}
            and not key.startswith('#'))


def _key_ok(kind: str, key: str) -> bool:
    if kind == 'function':
        return _function_key_ok(key)
    if kind in ('string', 'advisory_phrase'):
        return bool(SHA256_RE.fullmatch(key))
    if kind == 'import':
        return _import_key_ok(key)
    if kind == 'capability':
        return unicodedata.is_normalized('NFC', key)
    if kind == 'rule':
        return bool(_RULE_KEY.fullmatch(key))
    if kind == 'build_fact':
        return bool(_BUILD_KEY.fullmatch(key)) and unicodedata.is_normalized('NFC', key)
    pattern = {'cve': _CVE_KEY, 'kb': _KB_KEY, 'cwe': _CWE_KEY}[kind]
    return bool(pattern.fullmatch(key))


def _is_pair(anchor: Anchor) -> bool:
    return anchor.kind == 'function' and anchor.key.startswith('pair:')


def _orientation(reason: str, message: str) -> FabricError:
    return _error('PT-FAB-ORIENTATION', message, reason)


def _check_side(anchor: Anchor) -> None:
    if anchor.kind == 'function':
        allowed = ('both',) if _is_pair(anchor) else ('older', 'newer')
        if anchor.side not in allowed:
            raise _orientation('function-side', 'A pair is on both sides and an image function on one')
    if anchor.role == 'observed' and anchor.side == 'none':
        raise _orientation('observed-needs-side', 'An observation names the side it was made on')
    if anchor.role == 'hint' and anchor.side != 'none':
        raise _orientation('hint-has-no-side', 'A hint is not tied to a side')


def _check_subject(anchor: Anchor) -> None:
    if anchor.subject is None:
        return
    if anchor.kind == 'function':
        raise _error('PT-FAB-INPUT', 'A function anchor is a subject, not about one', 'function-has-no-subject')
    if not _function_key_ok(anchor.subject):
        raise _key_error('subject-grammar', 'The subject must be a pair or an image function key')


def _check_pair(anchor: Anchor) -> None:
    if _is_pair(anchor):
        if anchor.pair is None:
            raise _key_error('pair-required', 'A pair key needs its pair record')
        if pair_key_of(anchor.pair) != anchor.key:
            raise _key_error('pair-key-mismatch', 'The pair record does not reproduce the key')
    elif anchor.pair is not None:
        raise _key_error('pair-unexpected', 'Only a pair key carries a pair record')


def check_anchor(anchor: Anchor) -> None:
    """The semantic rules of s4: key grammar, roles by kind, sides, subject, pair record, input hash of a one-sided
    observation. Raises `FabricError`; the message never repeats the offending value."""
    if not _key_ok(anchor.kind, anchor.key):
        raise _key_error('key-grammar')
    if anchor.role not in ROLES_BY_KIND[anchor.kind]:
        raise _error('PT-FAB-INPUT', 'The role is not allowed for this kind', 'role-not-allowed')
    _check_side(anchor)
    _check_subject(anchor)
    _check_pair(anchor)
    if anchor.role == 'observed' and anchor.side in ('older', 'newer'):
        if any(witness.input_sha256 is None for witness in anchor.witnesses):
            raise _orientation('input-sha-missing', 'A one-sided observation names the artifact it was made on')


def verify_anchor(anchor: Anchor) -> None:
    """Recompute every id (`PT-FAB-INTEGRITY` on a mismatch) and re-apply `check_anchor`."""
    def tampered(reason: str) -> FabricError:
        return _error('PT-FAB-INTEGRITY', 'The record does not match its own identity', reason)

    if _is_pair(anchor) and anchor.pair is not None and pair_key_of(anchor.pair) != anchor.key:
        raise tampered('pair-key')
    if any(witness_id(witness) != witness.witness_id for witness in anchor.witnesses):
        raise tampered('witness-id')
    if anchor_id(anchor.kind, anchor.key, anchor.side, anchor.role, anchor.subject) != anchor.anchor_id:
        raise tampered('anchor-id')
    check_anchor(anchor)


def check_orientation(anchor: Anchor, older_sha256: str, newer_sha256: str) -> None:
    """Check an anchor against the pair its project is bound to; a reversed pair or an observation made on the other
    image is `orientation-swapped`, a hash that is neither is a mismatch. `PT-FAB-ORIENTATION` on any."""
    if anchor.pair is not None:
        bound = (anchor.pair.older_sha256, anchor.pair.newer_sha256)
        if bound != (older_sha256, newer_sha256):
            swapped = bound == (newer_sha256, older_sha256)
            raise _orientation('orientation-swapped' if swapped else 'pair-mismatch',
                               'The pair is not the pair this project compares')
    expected = {'older': older_sha256, 'newer': newer_sha256}.get(anchor.side)
    other = {'older': newer_sha256, 'newer': older_sha256}.get(anchor.side)
    image = _IMAGE_KEY.fullmatch(anchor.key) if anchor.kind == 'function' else None
    shas = [witness.input_sha256 for witness in anchor.witnesses if witness.input_sha256 is not None]
    shas += [image.group(1)] if image else []
    for sha in shas:
        if expected is None:
            if sha not in (older_sha256, newer_sha256):
                raise _orientation('input-sha-mismatch', 'The artifact is neither image of this project')
        elif sha != expected:
            raise _orientation('orientation-swapped' if sha == other else 'input-sha-mismatch',
                               'The observation was made on another image than its side names')
    subject = _IMAGE_KEY.fullmatch(anchor.subject) if anchor.subject is not None else None
    if subject is not None:
        if subject.group(1) not in (older_sha256, newer_sha256):
            raise _orientation('subject-sha-mismatch', 'The subject function is in neither image of this project')
        if expected is not None and subject.group(1) != expected:
            raise _orientation('subject-side-mismatch', 'The subject function is in the other image')


# --- builders -------------------------------------------------------------------------------------------------------

def _shape(model: str, exc: ValidationError) -> FabricError:
    """A record that fails its shape: the first failing field becomes the reason slug (field names are ours)."""
    loc = next((part for part in exc.errors()[0]['loc'] if isinstance(part, str)), '')
    slug = re.sub(r'[^a-z0-9]+', '-', f'{model}-{loc}'.lower()).strip('-')[:48]
    return _error('PT-FAB-INPUT', 'A record field is malformed', slug)


def _facets(facets: Mapping[str, object] | Iterable[tuple[str, object]]) -> tuple[tuple[str, str], ...]:
    items = facets.items() if isinstance(facets, Mapping) else facets
    return tuple(sorted(((str(name), clean_line(value, _L.f07_facet_chars)) for name, value in items),
                        key=lambda facet: facet[0]))


def make_witness(*, producer: str, batch: str, source: str, origins: Iterable[str], label: object,
                 facets: Mapping[str, object] | Iterable[tuple[str, object]] = (), tool: object = None,
                 tool_version: object = None, input_sha256: str | None = None, ref: Ref | None = None) -> Witness:
    """Build a witness: untrusted text is sanitised, origin tags and facets are put in canonical order, the id is
    derived. Whether `origins` agrees with the registry is checked when a store accepts the anchor."""
    fields = {
        'producer': producer, 'batch': batch, 'source': source, 'origins': tuple(sorted(set(origins))),
        'label': clean_line(label, _L.f05_label_chars), 'facets': _facets(facets),
        'tool': None if tool is None else clean_line(tool, _L.f15_tool_chars),
        'tool_version': None if tool_version is None else clean_line(tool_version, _L.f15_tool_chars),
        'input_sha256': input_sha256, 'ref': ref}
    try:
        probe = Witness(witness_id=_ZERO, **fields)
    except ValidationError as exc:
        raise _shape('witness', exc) from None
    return probe.model_copy(update={'witness_id': witness_id(probe)})


def make_anchor(*, kind: str, side: str, role: str, witnesses: Iterable[Witness], key: str | None = None,
                subject: str | None = None, pair: PairRef | None = None) -> Anchor:
    """Build an anchor: witnesses are de-duplicated and sorted, the ids are derived (a pair key from its pair record),
    and `check_anchor` raises a typed error for anything the s4 rules refuse."""
    if kind not in KINDS:
        raise _error('PT-FAB-KIND', 'Unknown anchor kind', 'kind')
    if key is None:
        if pair is None:
            raise _key_error('key-missing', 'An anchor needs a key or a pair record')
        key = pair_key_of(pair)
    members = tuple(witnesses)
    if not all(isinstance(witness, Witness) for witness in members):
        raise _error('PT-FAB-INPUT', 'A record field is malformed', 'anchor-witnesses')
    ordered = tuple({w.witness_id: w for w in sorted(members, key=lambda w: w.witness_id)}.values())
    try:
        probe = Anchor(anchor_id=_ZERO, kind=kind, key=key, side=side, role=role, subject=subject, pair=pair,
                       witnesses=ordered)
    except ValidationError as exc:
        raise _shape('anchor', exc) from None
    anchor = probe.model_copy(update={'anchor_id': anchor_id(kind, key, side, role, subject)})
    check_anchor(anchor)
    return anchor
