"""Versioned CWE lexicon (SPEC-28 section H). Pure and deterministic; advisory text is only matched, never
rendered or executed.

Order of evidence: the CSAF ``cwe`` field (an advisory claim) first, CWE identifiers written in the advisory
text second, then curated vocabulary. Matching works on tokens (NFKC, casefolded, HTML entities decoded and
tags removed for matching only), so "use-after-free", "use after free" and "<b>use</b>-after-free" agree and
"freeing" never matches "free". A hit is negated when a cue (``not``, ``no``, ``cannot``, ``n't``, ``free of``,
...) precedes it within 4 tokens in the same clause with no scope terminator in between, or when it is followed by
a negated existence predicate ("is not present", "cannot occur", "is no longer possible"); "requires no user
interaction" or "does not require authentication" negate a requirement, not the weakness. Only ``weakness``
terms derive a CWE; impact words such as "remote code execution" are effects, and
generic phrases ("memory corruption", "improper input validation") are weak at best. Vague text is never
classified confidently. CWE names below were transcribed without live access to cwe.mitre.org and are
display labels only.
"""
from __future__ import annotations

import functools
import html
import re
import unicodedata
from dataclasses import dataclass

from ..enrichment.identity import domain_id
from .contracts import CVEFact, CweClassification, CweProfile, TermHit

LEXICON_VERSION = 'cwe-lexicon/1'
MAX_SOURCE_CHARS = 65_536
TEXT_NOTE_CATEGORIES = frozenset({'description', 'details', 'faq', 'general', 'other', 'summary'})

FAMILIES: dict[str, tuple[str, ...]] = {
    'memory-write': ('CWE-787', 'CWE-120', 'CWE-121', 'CWE-122', 'CWE-123'),
    'memory-read': ('CWE-125', 'CWE-126', 'CWE-127'),
    'bounds': ('CWE-119', 'CWE-129', 'CWE-131', 'CWE-805'),
    'lifetime': ('CWE-416', 'CWE-415', 'CWE-672', 'CWE-825'),
    'null-deref': ('CWE-476',),
    'pointer': ('CWE-822', 'CWE-824'),
    'integer': ('CWE-190', 'CWE-191', 'CWE-197', 'CWE-681'),
    'type': ('CWE-843', 'CWE-704'),
    'race': ('CWE-362', 'CWE-367'),
    'authentication': ('CWE-287', 'CWE-290', 'CWE-306'),
    'authorization': ('CWE-284', 'CWE-285', 'CWE-269', 'CWE-732', 'CWE-862', 'CWE-863'),
    'path': ('CWE-22', 'CWE-59', 'CWE-73'),
    'info-exposure': ('CWE-200', 'CWE-209'),
    'uninitialized': ('CWE-457', 'CWE-908', 'CWE-909'),
    'resource': ('CWE-400', 'CWE-401', 'CWE-674', 'CWE-770', 'CWE-772', 'CWE-835'),
    'input': ('CWE-20', 'CWE-1284'),
    'injection': ('CWE-77', 'CWE-78', 'CWE-79', 'CWE-89', 'CWE-94'),
    'deserialization': ('CWE-502',),
    'search-path': ('CWE-426', 'CWE-427'),
    'crypto-verify': ('CWE-295', 'CWE-347'),
    'format-string': ('CWE-134',),
    'off-by-one': ('CWE-193',),
}
_FAMILY_OF = {cwe: name for name, members in FAMILIES.items() for cwe in members}

CWE_NAMES: dict[str, str] = {
    'CWE-20': 'Improper Input Validation', 'CWE-22': 'Path Traversal', 'CWE-59': 'Link Following',
    'CWE-73': 'External Control of File Name or Path', 'CWE-77': 'Command Injection',
    'CWE-78': 'OS Command Injection', 'CWE-79': 'Cross-site Scripting', 'CWE-89': 'SQL Injection',
    'CWE-94': 'Code Injection',
    'CWE-119': 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
    'CWE-120': 'Classic Buffer Overflow', 'CWE-121': 'Stack-based Buffer Overflow',
    'CWE-122': 'Heap-based Buffer Overflow', 'CWE-123': 'Write-what-where Condition',
    'CWE-125': 'Out-of-bounds Read', 'CWE-126': 'Buffer Over-read', 'CWE-127': 'Buffer Under-read',
    'CWE-129': 'Improper Validation of Array Index', 'CWE-131': 'Incorrect Calculation of Buffer Size',
    'CWE-134': 'Use of Externally-Controlled Format String',
    'CWE-190': 'Integer Overflow or Wraparound', 'CWE-191': 'Integer Underflow (Wrap or Wraparound)',
    'CWE-193': 'Off-by-one Error', 'CWE-197': 'Numeric Truncation Error',
    'CWE-200': 'Exposure of Sensitive Information',
    'CWE-209': 'Information Exposure Through an Error Message', 'CWE-269': 'Improper Privilege Management',
    'CWE-284': 'Improper Access Control', 'CWE-285': 'Improper Authorization',
    'CWE-287': 'Improper Authentication', 'CWE-290': 'Authentication Bypass by Spoofing',
    'CWE-295': 'Improper Certificate Validation', 'CWE-306': 'Missing Authentication for Critical Function',
    'CWE-347': 'Improper Verification of Cryptographic Signature', 'CWE-362': 'Race Condition',
    'CWE-367': 'Time-of-check Time-of-use (TOCTOU) Race Condition', 'CWE-400': 'Uncontrolled Resource Consumption',
    'CWE-401': 'Missing Release of Memory after Effective Lifetime', 'CWE-415': 'Double Free',
    'CWE-416': 'Use After Free', 'CWE-426': 'Untrusted Search Path', 'CWE-427': 'Uncontrolled Search Path Element',
    'CWE-457': 'Use of Uninitialized Variable', 'CWE-476': 'NULL Pointer Dereference',
    'CWE-502': 'Deserialization of Untrusted Data', 'CWE-672': 'Operation on a Resource after Expiration or Release',
    'CWE-674': 'Uncontrolled Recursion', 'CWE-681': 'Incorrect Conversion between Numeric Types',
    'CWE-704': 'Incorrect Type Conversion or Cast', 'CWE-732': 'Incorrect Permission Assignment for Critical Resource',
    'CWE-770': 'Allocation of Resources Without Limits or Throttling', 'CWE-772': 'Missing Release of Resource',
    'CWE-787': 'Out-of-bounds Write', 'CWE-805': 'Buffer Access with Incorrect Length Value',
    'CWE-822': 'Untrusted Pointer Dereference', 'CWE-824': 'Access of Uninitialized Pointer',
    'CWE-825': 'Expired Pointer Dereference', 'CWE-835': 'Infinite Loop',
    'CWE-843': 'Type Confusion', 'CWE-862': 'Missing Authorization', 'CWE-863': 'Incorrect Authorization',
    'CWE-908': 'Use of Uninitialized Resource', 'CWE-909': 'Missing Initialization of Resource',
    'CWE-1284': 'Improper Validation of Specified Quantity in Input',
}


@dataclass(frozen=True)
class Term:
    term_id: str
    phrases: tuple[str, ...]
    cwe_ids: tuple[str, ...]
    scope: str
    strength: str


def _w(term_id: str, phrases: tuple[str, ...], cwe: str, strength: str = 'strong') -> Term:
    return Term(term_id, phrases, (cwe,), 'weakness', strength)


def _e(term_id: str, phrases: tuple[str, ...], scope: str = 'effect') -> Term:
    return Term(term_id, phrases, (), scope, 'weak')


TERMS: tuple[Term, ...] = (
    _w('use-after-free', ('use after free', 'freed memory reuse'), 'CWE-416'),
    _w('dangling-pointer', ('dangling pointer',), 'CWE-416'),
    _w('double-free', ('double free',), 'CWE-415'),
    _w('expired-pointer', ('expired pointer dereference',), 'CWE-825'),
    _w('out-of-bounds-write', ('out of bounds write', 'write past the end'), 'CWE-787'),
    _w('buffer-overflow', ('buffer overflow',), 'CWE-787'),
    _w('heap-overflow', ('heap based buffer overflow', 'heap buffer overflow', 'heap overflow', 'pool overflow',
                         'pool based buffer overflow'), 'CWE-122'),
    _w('stack-overflow-buffer', ('stack based buffer overflow', 'stack buffer overflow'), 'CWE-121'),
    _w('stack-overflow-ambiguous', ('stack overflow',), 'CWE-121', 'weak'),
    _w('classic-overflow', ('buffer copy without checking size of input', 'classic buffer overflow'), 'CWE-120'),
    _w('write-what-where', ('write what where',), 'CWE-123'),
    _w('out-of-bounds-read', ('out of bounds read', 'read past the end'), 'CWE-125'),
    _w('over-read', ('buffer over read', 'buffer overread'), 'CWE-126'),
    _w('out-of-bounds-access', ('out of bounds access', 'out of bounds memory access'), 'CWE-119'),
    _w('memory-corruption', ('memory corruption', 'heap corruption', 'pool corruption'), 'CWE-119', 'weak'),
    _w('buffer-overrun', ('buffer overrun',), 'CWE-119', 'weak'),
    _w('array-index', ('improper validation of array index',), 'CWE-129'),
    _w('array-index-weak', ('array index',), 'CWE-129', 'weak'),
    _w('buffer-size', ('incorrect calculation of buffer size',), 'CWE-131'),
    _w('incorrect-length', ('buffer access with incorrect length value',), 'CWE-805'),
    _w('integer-overflow', ('integer overflow', 'integer wraparound', 'integer wrap around'), 'CWE-190'),
    _w('integer-underflow', ('integer underflow',), 'CWE-191'),
    _w('numeric-truncation', ('numeric truncation',), 'CWE-197'),
    _w('numeric-conversion', ('incorrect conversion between numeric types',), 'CWE-681'),
    _w('format-string', ('uncontrolled format string', 'externally controlled format string',
                         'format string vulnerability', 'format string injection', 'format string bug'), 'CWE-134'),
    _w('format-string-weak', ('format string',), 'CWE-134', 'weak'),
    _w('off-by-one', ('off by one error', 'off by one bug', 'off by one vulnerability', 'off by one condition'),
       'CWE-193'),
    _w('off-by-one-weak', ('off by one',), 'CWE-193', 'weak'),
    _w('null-deref', ('null pointer dereference', 'null pointer deref', 'null dereference'), 'CWE-476'),
    _w('untrusted-pointer', ('untrusted pointer dereference',), 'CWE-822'),
    _w('uninitialized-pointer', ('uninitialized pointer',), 'CWE-824'),
    _w('type-confusion', ('type confusion', 'access of resource using incompatible type'), 'CWE-843'),
    _w('race-condition', ('race condition', 'concurrent execution using shared resource'), 'CWE-362'),
    _w('toctou', ('time of check time of use', 'toctou'), 'CWE-367'),
    _w('improper-authentication', ('improper authentication', 'authentication bypass'), 'CWE-287'),
    _w('missing-authentication', ('missing authentication',), 'CWE-306'),
    _w('improper-access-control', ('improper access control',), 'CWE-284'),
    _w('improper-authorization', ('improper authorization',), 'CWE-285'),
    _w('missing-authorization', ('missing authorization',), 'CWE-862'),
    _w('incorrect-authorization', ('incorrect authorization',), 'CWE-863'),
    _w('privilege-management', ('improper privilege management',), 'CWE-269'),
    _w('permission-assignment', ('incorrect permission assignment', 'incorrect default permissions'), 'CWE-732'),
    _w('path-traversal', ('path traversal', 'directory traversal'), 'CWE-22'),
    _w('link-following', ('link following', 'improper link resolution', 'symbolic link following'), 'CWE-59'),
    _w('symlink-weak', ('symlink', 'symbolic link'), 'CWE-59', 'weak'),
    _w('info-exposure', ('exposure of sensitive information', 'information exposure'), 'CWE-200'),
    _w('uninitialized-memory', ('uninitialized memory', 'use of uninitialized resource'), 'CWE-908'),
    _w('uninitialized-variable', ('uninitialized variable', 'use of uninitialized variable'), 'CWE-457'),
    _w('uninitialized-weak', ('uninitialized',), 'CWE-908', 'weak'),
    _w('memory-leak', ('memory leak', 'missing release of memory'), 'CWE-401'),
    _w('resource-exhaustion', ('uncontrolled resource consumption', 'resource exhaustion'), 'CWE-400'),
    _w('infinite-loop', ('infinite loop',), 'CWE-835'),
    _w('uncontrolled-recursion', ('uncontrolled recursion',), 'CWE-674'),
    _w('input-validation', ('improper input validation', 'insufficient input validation'), 'CWE-20', 'weak'),
    _w('command-injection', ('command injection',), 'CWE-77'),
    _w('os-command-injection', ('os command injection',), 'CWE-78'),
    _w('xss', ('cross site scripting',), 'CWE-79'),
    _w('sql-injection', ('sql injection',), 'CWE-89'),
    _w('code-injection', ('code injection',), 'CWE-94'),
    _w('deserialization', ('deserialization of untrusted data', 'unsafe deserialization',
                           'insecure deserialization'), 'CWE-502'),
    _w('untrusted-search-path', ('untrusted search path',), 'CWE-426'),
    _w('uncontrolled-search-path', ('uncontrolled search path',), 'CWE-427'),
    _w('dll-planting', ('dll hijacking', 'dll planting', 'binary planting'), 'CWE-427', 'weak'),
    _w('certificate-validation', ('improper certificate validation',), 'CWE-295'),
    _w('signature-verification', ('improper verification of cryptographic signature',), 'CWE-347'),
    _e('effect-rce', ('remote code execution', 'arbitrary code execution', 'code execution')),
    _e('effect-eop', ('elevation of privilege', 'privilege escalation', 'escalation of privilege')),
    _e('effect-dos', ('denial of service',)),
    _e('effect-info', ('information disclosure',)),
    _e('effect-sfb', ('security feature bypass',)),
    _e('effect-spoofing', ('spoofing',)),
    _e('effect-tampering', ('tampering',)),
    _e('primitive-arbitrary-write', ('arbitrary write', 'arbitrary memory write'), 'primitive'),
    _e('primitive-arbitrary-read', ('arbitrary read', 'arbitrary memory read'), 'primitive'),
)

NEGATION_TOKENS = frozenset({'not', 'no', 'never', 'cannot', 'without', 'neither', 'nor', 'unaffected', 'none',
                             'impossible'})
NEGATION_PAIRS = frozenset({('free', 'of'), ('rather', 'than'), ('instead', 'of'), ('no', 'longer')})
TERMINATORS = frozenset({',', ';', ':', '(', ')', 'but', 'however', 'although', 'though', 'which', 'that', 'because',
                         'leading', 'resulting', 'allowing', 'causing', 'and', 'whereas', 'while', 'so', 'who'})
BEFORE = 4
# A cue after the phrase negates the weakness only as a predicate of its existence: "is not present", "cannot occur",
# "is no longer possible". "requires no user interaction", "without authentication" and "does not require/allow/need"
# describe an attack condition or a capability of a weakness that is there (audit C-07), so they are not cues.
AFTER_CUES = frozenset({'not', 'never', 'cannot', 'impossible'})  # also any "...n't" contraction and "no longer"
AFTER_AUXILIARIES = frozenset({'is', 'are', 'was', 'were', 'be', 'been', 'does', 'do', 'did', 'can', 'could', 'will',
                               'would', 'may', 'might', 'should', 'has', 'have', 'had'})
AFTER_BE = frozenset({'be', 'been', 'being'})
EXISTENCE = frozenset({'present', 'possible', 'occur', 'occurs', 'occurred', 'exist', 'exists', 'existed', 'happen',
                       'happens', 'arise', 'arises', 'found', 'detected', 'observed', 'reproducible', 'reproduced',
                       'applicable', 'relevant', 'vulnerable', 'affected'})
_TOKEN = re.compile(r"[a-z0-9]+(?:'[a-z]+)?|[,;:()]")
_SENTENCE = re.compile(r'(?<=[.!?])\s+|\n+')
_TAG = re.compile(r'<[^<>]{0,200}>')
_CWE_TEXT = re.compile(r'^[1-9][0-9]{0,5}$')


def family(cwe_id: str) -> str | None:
    return _FAMILY_OF.get(cwe_id)


@functools.cache  # the lexicon is module data fixed at import; every profile and every pilot input record asked again
def lexicon_digest() -> str:
    table = [{'id': t.term_id, 'phrases': list(t.phrases), 'cwe': list(t.cwe_ids), 'scope': t.scope,
              'strength': t.strength} for t in TERMS]
    return domain_id('cwe-lexicon', 1, {'terms': table, 'families': {k: list(v) for k, v in FAMILIES.items()},
                                        'negation': sorted(NEGATION_TOKENS), 'pairs': sorted(map(list, NEGATION_PAIRS)),
                                        'terminators': sorted(TERMINATORS), 'window': BEFORE,
                                        'after': {'cues': sorted(AFTER_CUES), 'auxiliaries': sorted(AFTER_AUXILIARIES),
                                                  'be': sorted(AFTER_BE), 'existence': sorted(EXISTENCE)}})


def _canonical(text: str) -> str:
    text = html.unescape(_TAG.sub(' ', unicodedata.normalize('NFKC', text)))
    return unicodedata.normalize('NFKC', text).casefold().replace('’', "'")


_PHRASES: list[tuple[tuple[str, ...], Term, str]] = sorted(
    ((tuple(_TOKEN.findall(_canonical(p))), term, p) for term in TERMS for p in term.phrases),
    key=lambda item: -len(item[0]))
_BY_FIRST: dict[str, list[tuple[int, tuple[tuple[str, ...], Term, str]]]] = {}
for _order, _entry in enumerate(_PHRASES):
    _BY_FIRST.setdefault(_entry[0][0], []).append((_order, _entry))


def _negation(tokens: list[str], start: int, end: int) -> str | None:
    """Return the cue that negates tokens[start:end], or None."""
    for distance in range(1, BEFORE + 1):
        i = start - distance
        if i < 0:
            break
        token = tokens[i]
        if token in TERMINATORS:
            break
        if token in NEGATION_TOKENS or token.endswith("n't"):
            return token
        if i > 0 and (tokens[i - 1], token) in NEGATION_PAIRS:
            return f'{tokens[i - 1]} {token}'
    return _after_cue(tokens, end)


def _after_cue(tokens: list[str], end: int) -> str | None:
    """The cue of ``[auxiliary] cue [be] predicate`` right after the phrase, where the predicate states that the
    weakness exists or occurs ("is not present", "cannot occur", "was not found", "is no longer possible")."""
    i = end
    if i < len(tokens) and tokens[i] in AFTER_AUXILIARIES:
        i += 1
    if i >= len(tokens):
        return None
    cue = tokens[i]
    if cue == 'impossible':
        return cue
    if cue in AFTER_CUES or cue.endswith("n't"):
        i += 1
    elif cue == 'no' and tokens[i + 1:i + 2] == ['longer']:
        cue, i = 'no longer', i + 2
    else:
        return None
    if i < len(tokens) and tokens[i] in AFTER_BE:
        i += 1
    return cue if i < len(tokens) and tokens[i] in EXISTENCE else None


def _match(tokens: list[str], phrase: tuple[str, ...], at: int) -> bool:
    if at + len(phrase) > len(tokens):
        return False
    last = len(phrase) - 1
    for k, word in enumerate(phrase):
        token = tokens[at + k]
        if token != word and not (k == last and token == word + 's'):
            return False
    return True


@dataclass(frozen=True)
class _Hit:
    term: Term
    phrase: str
    negated: str | None
    pointer: str
    excerpt: str


def _scan(text: str, pointer: str) -> list[_Hit]:
    hits: list[_Hit] = []
    for sentence in _SENTENCE.split(_canonical(text)):
        tokens = _TOKEN.findall(sentence)
        taken: list[tuple[int, int]] = []
        excerpt = ' '.join(sentence.split())[:240]
        for at in range(len(tokens)):
            # CWE identifiers written in the text: tokens "cwe", "<digits>".
            if tokens[at] == 'cwe' and at + 1 < len(tokens) and _CWE_TEXT.match(tokens[at + 1]):
                cwe = f'CWE-{tokens[at + 1]}'
                hits.append(_Hit(Term('cwe-id-in-text', (cwe.lower(),), (cwe,), 'weakness', 'strong'), cwe,
                                 _negation(tokens, at, at + 2), pointer, excerpt))
        found = []
        for at, token in enumerate(tokens):
            for order, (phrase, term, canonical) in _BY_FIRST.get(token, ()):
                if _match(tokens, phrase, at):
                    found.append((order, at, len(phrase), term, canonical))
        for _order, at, length, term, canonical in sorted(found, key=lambda f: (f[0], f[1])):
            end = at + length  # longest phrases first; a match inside an accepted one is suppressed
            if any(s <= at and end <= e for s, e in taken):
                continue
            taken.append((at, end))
            hits.append(_Hit(term, canonical, _negation(tokens, at, end), pointer, excerpt))
    return hits


def _sources(fact: CVEFact) -> list[tuple[str, str]]:
    out = []
    if fact.title:
        out.append((fact.title, f'{fact.pointer}/title'))
    out += [(note.text, note.pointer) for note in fact.notes if note.category in TEXT_NOTE_CATEGORIES]
    out += [(threat.details, f'{threat.pointer}/details') for threat in fact.threats if threat.category == 'impact']
    return out


def _term_hit(hit: _Hit) -> TermHit:
    return TermHit(term_id=hit.term.term_id, phrase=hit.phrase[:200], cwe_ids=hit.term.cwe_ids,
                   scope=hit.term.scope, strength=hit.term.strength, negated=hit.negated is not None,
                   negation_cue=hit.negated, pointer=hit.pointer, excerpt=hit.excerpt)


def _hit_key(hit: TermHit) -> tuple:
    return (hit.pointer, hit.term_id, hit.phrase, hit.excerpt, hit.negated)


def classify(fact: CVEFact) -> CweProfile:
    """CWE profile of one vulnerability item. ``fact.cve`` must be set (profiles are per CVE)."""
    if fact.cve is None:
        raise ValueError('classify needs a vulnerability item with a CVE')
    limitations: list[str] = []
    hits: list[_Hit] = []
    sources = _sources(fact)
    for text, pointer in sources:
        if len(text) > MAX_SOURCE_CHARS:
            limitations.append(f'only the first {MAX_SOURCE_CHARS} characters of {pointer} were classified')
            text = text[:MAX_SOURCE_CHARS]
        hits += _scan(text, pointer)
    by_cwe: dict[str, dict] = {}

    def entry(cwe_id: str, basis: str, confidence: str, assessment: str, pointers=()) -> dict:
        record = by_cwe.setdefault(cwe_id, {'basis': basis, 'confidence': confidence, 'assessment': assessment,
                                            'hits': [], 'pointers': set()})
        record['pointers'].update(pointers)
        return record

    if fact.cwe is not None:
        entry(fact.cwe.id, 'explicit-csaf-cwe', 'explicit', 'advisory-claim', (fact.cwe.pointer,))
    live = [h for h in hits if h.negated is None]
    for hit in live:
        if hit.term.term_id == 'cwe-id-in-text':
            record = entry(hit.term.cwe_ids[0], 'cwe-id-in-text', 'phrase-match', 'advisory-claim')
            record['hits'].append(hit)
            record['pointers'].add(hit.pointer)
    for strength in ('strong', 'weak'):
        for hit in live:
            if hit.term.scope != 'weakness' or hit.term.term_id == 'cwe-id-in-text' or hit.term.strength != strength:
                continue
            record = entry(hit.term.cwe_ids[0], 'curated-vocabulary', 'phrase-match' if strength == 'strong' else 'weak',
                           'rule-hypothesis')
            record['hits'].append(hit)
            record['pointers'].add(hit.pointer)
    classifications = tuple(sorted(
        (CweClassification(cwe_id=cwe_id, family=family(cwe_id) or 'unmapped', basis=r['basis'],
                           confidence=r['confidence'], assessment=r['assessment'],
                           hits=tuple(sorted({_term_hit(h) for h in r['hits']}, key=_hit_key)),
                           pointers=tuple(sorted(r['pointers'])))
         for cwe_id, r in by_cwe.items()),
        key=lambda c: (('explicit', 'phrase-match', 'weak').index(c.confidence), c.cwe_id)))
    disagreements = []
    explicit = [c for c in classifications if c.basis == 'explicit-csaf-cwe']
    for e in explicit:
        for other in classifications:
            if other.basis != 'explicit-csaf-cwe' and other.confidence != 'weak' and other.family != e.family:
                disagreements.append(f'explicit {e.cwe_id} ({e.family}) and {other.basis} {other.cwe_id} '
                                     f'({other.family}) differ; both are kept and neither is resolved')
    if explicit:
        status = 'explicit'
    elif any(c.confidence == 'phrase-match' for c in classifications):
        status = 'derived'
    elif classifications:
        status = 'weak'
    elif sources:
        status = 'vague'
    else:
        status = 'none'
    negated = sorted({_term_hit(h) for h in hits if h.negated is not None}, key=_hit_key)
    effects = sorted({_term_hit(h) for h in live if h.term.scope in ('effect', 'primitive')}, key=_hit_key)
    return CweProfile(cve=fact.cve, lexicon_version=LEXICON_VERSION, lexicon_digest=lexicon_digest(), status=status,
                      classifications=classifications, negated_hits=tuple(negated), effect_hits=tuple(effects),
                      disagreements=tuple(sorted(disagreements)), limitations=tuple(limitations))
