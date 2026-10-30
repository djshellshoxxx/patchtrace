"""Content cues: fixed-vocabulary, rule-based labels for a string. No wordlist, no model; a missing cue means
unknown, never a negative claim. Cues explain review order and are never a score."""
from __future__ import annotations

import re
from collections.abc import Collection
from dataclasses import dataclass

from patchtrace.strings.regions import REGION_RESOURCE

CUE_VOCABULARY = (
    'message', 'format', 'path', 'registry', 'url', 'guid', 'api-name', 'dynamic-api', 'dll-name', 'pdb-path',
    'version', 'identifier', 'advisory-text', 'advisory-api', 'lookalike', 'secret-like', 'resource',
    'noise-like')
MAX_CUES = 8
ADVISORY_MIN_LENGTH = 8

# A width never starts with 0 (that is the 0 flag), so flags and width cannot both match a run of zeros: linear (#105).
_FORMAT = re.compile(r'%[-+ #0]*(?:[1-9][0-9]*|\*)?(?:\.(?:[0-9]+|\*))?(?:hh|h|ll|l|j|z|t|L|I32|I64|I)?[diouxXeEfgGaAcCsSpn]')
_REGISTRY = re.compile(r'(?:HKEY_[A-Z_]+|HK(?:LM|CU|CR|U|CC))\\|\\Registry\\(?:Machine|User)|'
                       r'(?:Software|System\\CurrentControlSet)\\', re.IGNORECASE)
_URL = re.compile(r'\b(?:https?|ftps?|file|wss?|ldaps?|smb)://\S+', re.IGNORECASE)
_GUID = re.compile(r'\{?[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?')
_DLL = re.compile(r'[\w.-]{1,64}\.dll', re.IGNORECASE)
_PDB = re.compile(r'\S.*\.pdb', re.IGNORECASE)
_VERSION = re.compile(r'[vV]?\d{1,5}(?:\.\d{1,5}){2,3}')
_IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z0-9_]{3,}')
_CAMEL = re.compile(r'[a-z0-9][A-Z]')
_ABS_PATH = re.compile(r'[A-Za-z]:[\\/]|\\\\[^\\/\s]+[\\/]|\\\?\?\\|\\Device\\|/[\w.-]+(?:/[\w.-]+)+')
_REL_PATH = re.compile(r'[\w.$-]+(?:\\[\w.$ -]+)*\\[\w.$ -]+\.\w{1,5}')
_SECRETS = (
    ('aws-access-key', re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b')),
    ('private-key', re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----')),
    ('github-token', re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}')),
    ('slack-token', re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}')),
    ('google-api-key', re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b')),
    ('jwt', re.compile(r'\beyJ[\w-]{5,}\.eyJ[\w-]{5,}\.[\w-]+')),
)
_STRUCTURAL = frozenset({'format', 'path', 'registry', 'url', 'guid', 'dll-name', 'pdb-path', 'version',
                         'identifier', 'api-name', 'dynamic-api', 'secret-like', 'message'})


@dataclass(frozen=True, slots=True)
class CueContext:
    """Facts about the string's own build and the project's anchors. Empty means nothing is known."""
    imports: Collection[str] = frozenset()
    exports: Collection[str] = frozenset()
    other_side_imports: Collection[str] = frozenset()
    api_hints: Collection[str] = frozenset()
    advisory_phrases: Collection[str] = ()
    region: str | None = None


def secret_kind(text: str) -> str | None:
    """Kind label of a credential-shaped value, or None. The kind is safe to show; the value is not."""
    for kind, pattern in _SECRETS:
        if pattern.search(text):
            return kind
    return None


def is_noise_like(text: str) -> bool:
    if len(text) < 4:
        return False
    if sum(c.isalnum() for c in text) * 2 < len(text):
        return True
    if len(text) >= 6 and len(set(text)) <= 2:
        return True
    if len(text) >= 5 and ' ' not in text and text.isalpha():
        flips = sum(a.islower() != b.islower() for a, b in zip(text, text[1:], strict=False))
        return flips * 2 >= len(text)
    return False


def _is_message(text: str) -> bool:
    words = [w for w in text.split() if sum(c.isalpha() for c in w) >= 2]
    return len(words) >= 2 and len(text) >= 8


def _is_identifier(text: str) -> bool:
    return (bool(_IDENTIFIER.fullmatch(text)) and ('_' in text or bool(_CAMEL.search(text)))
            and not is_noise_like(text))


def _advisory_text(text: str, phrases: Collection[str]) -> bool:
    folded = text.casefold()
    return any(p and (folded == p or (len(p) >= ADVISORY_MIN_LENGTH and p in folded)) for p in phrases)


def _api_cues(text: str, ctx: CueContext) -> set[str]:
    cues: set[str] = set()
    if text in ctx.imports or text in ctx.exports:
        cues.add('api-name')
    elif text in ctx.api_hints or text in ctx.other_side_imports:
        cues.add('dynamic-api')
    if text in ctx.api_hints:
        cues.add('advisory-api')
    return cues


def _shape_cues(text: str) -> set[str]:
    cues: set[str] = set()
    if _FORMAT.search(text.replace('%%', '')):
        cues.add('format')
    if _REGISTRY.match(text):
        cues.add('registry')
    elif _ABS_PATH.match(text) or _REL_PATH.fullmatch(text):
        cues.add('path')
    if _URL.search(text):
        cues.add('url')
    if _GUID.fullmatch(text):
        cues.add('guid')
    if _DLL.fullmatch(text):
        cues.add('dll-name')
    if _PDB.fullmatch(text):
        cues.add('pdb-path')
    if _VERSION.fullmatch(text):
        cues.add('version')
    if _is_identifier(text):
        cues.add('identifier')
    return cues


def cues_for(text: str, ctx: CueContext | None = None, *, lookalike: bool = False) -> tuple[str, ...]:
    """Cues in vocabulary order, at most MAX_CUES. `lookalike` is set by the caller that paired the string."""
    ctx = ctx or CueContext()
    cues = _shape_cues(text) | _api_cues(text, ctx)
    if secret_kind(text):
        cues = (cues - {'identifier'}) | {'secret-like'}
    elif _is_message(text) and not cues & {'path', 'registry', 'url', 'guid', 'dll-name', 'pdb-path', 'version'}:
        cues.add('message')
    if _advisory_text(text, ctx.advisory_phrases):
        cues.add('advisory-text')
    if lookalike:
        cues.add('lookalike')
    if ctx.region == REGION_RESOURCE:
        cues.add('resource')
    if not cues & _STRUCTURAL and is_noise_like(text):
        cues.add('noise-like')
    return tuple(c for c in CUE_VOCABULARY if c in cues)[:MAX_CUES]
