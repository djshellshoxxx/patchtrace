"""Look-alike pairing: two strings that read the same but differ in code points (homoglyphs, width forms,
invisible characters). Pure; the key is for pairing only and never an identity."""
from __future__ import annotations

import difflib
import unicodedata
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

DIFF_LIMIT = 32

# Cyrillic and Greek letters that render like Latin ones in common fonts. NFKC does not fold them.
_CONFUSABLES = {
    '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041a': 'K', '\u041c': 'M', '\u041d': 'H', '\u041e': 'O',
    '\u0420': 'P', '\u0421': 'C', '\u0422': 'T', '\u0425': 'X', '\u0430': 'a', '\u0435': 'e', '\u043e': 'o',
    '\u0440': 'p', '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0455': 's', '\u0456': 'i', '\u0458': 'j',
    '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0396': 'Z', '\u0397': 'H', '\u0399': 'I', '\u039a': 'K',
    '\u039c': 'M', '\u039d': 'N', '\u039f': 'O', '\u03a1': 'P', '\u03a4': 'T', '\u03a5': 'Y', '\u03a7': 'X',
    '\u03bf': 'o', '\u03bd': 'v',
}


def lookalike_key(text: str) -> str:
    """NFKC, invisible format characters dropped, homoglyphs folded to Latin, then casefolded."""
    folded = unicodedata.normalize('NFKC', text)
    kept = ''.join(_CONFUSABLES.get(c, c) for c in folded if unicodedata.category(c) != 'Cf')
    return kept.casefold()


@dataclass(frozen=True, slots=True)
class CodepointDiff:
    older_index: int
    older: str
    newer_index: int
    newer: str


@dataclass(frozen=True, slots=True)
class LookalikePair:
    older: str
    newer: str


def codepoint_diff(older: str, newer: str, limit: int = DIFF_LIMIT) -> tuple[CodepointDiff, ...]:
    matcher = difflib.SequenceMatcher(None, older, newer, autojunk=False)
    out = [CodepointDiff(i1, older[i1:i2], j1, newer[j1:j2])
           for tag, i1, i2, j1, j2 in matcher.get_opcodes() if tag != 'equal']
    return tuple(out[:limit])


def describe_codepoints(chars: str) -> str:
    """`U+0415 CYRILLIC CAPITAL LETTER IE` per character, for the detail pane; never the raw character."""
    return ', '.join(f'U+{ord(c):04X} {unicodedata.name(c, "<unnamed>")}' for c in chars) or '(none)'


def pair_lookalikes(only_older: Iterable[str], only_newer: Iterable[str]) -> tuple[LookalikePair, ...]:
    """Pair an only-older and an only-newer value with the same key. Only unambiguous one-to-one groups pair,
    so a guess is never made between several candidates."""
    old: dict[str, set[str]] = defaultdict(set)
    new: dict[str, set[str]] = defaultdict(set)
    for value in only_older:
        old[lookalike_key(value)].add(value)
    for value in only_newer:
        new[lookalike_key(value)].add(value)
    pairs = []
    for key in sorted(old.keys() & new.keys()):
        if len(old[key]) == 1 and len(new[key]) == 1:
            (a,), (b,) = old[key], new[key]
            pairs.append(LookalikePair(a, b))
    return tuple(pairs)
