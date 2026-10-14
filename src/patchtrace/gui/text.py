"""Untrusted-text safety and claim-wording rules for the GUI (GUI plan 8.4 and section 6). Pure: no Qt.

`sanitize_text` is the one gate every label, status line, announcement and tooltip value passes through.
`ClaimsProfile` is a panel's list of wording its view-model must never emit; panel tests sweep every string
they produce through `violations`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

LABEL_LIMIT = 200
VIEW_LIMIT = 4_000

# Removed after the line breaks were rewritten (so only NUL..BS and SO..US are left of C0, and a kept tab or
# newline survives): DEL, the C1 controls, lone surrogates (not encodable), the bidi controls (ALM, LRM, RLM,
# LRE..RLO, LRI..PDI) and the Unicode line and paragraph separators. The 8-digit escapes keep this file free of
# raw special characters.
_STRIP = re.compile('[\x00-\x08\x0e-\x1f\x7f-\x9f\U0000d800-\U0000dfff\U0000061c\U0000200e\U0000200f'
                    '\U0000202a-\U0000202e\U00002066-\U00002069\U00002028\U00002029]')
_BREAK_RUN = re.compile('[\t\n\v\f\r\x85]+')
_NEWLINE = re.compile('\r\n?|[\v\f\x85]')


def sanitize_text(value: object, limit: int = LABEL_LIMIT, *, multiline: bool = False) -> str:
    """Plain text that is safe to put in a label, status line or view: bounded, idempotent and encodable.

    Single line (default): a run of line breaks and tabs becomes one space, so an embedded newline cannot forge a
    second line. `multiline=True` keeps tabs and newlines (every break form becomes `\\n`) for views. Everything in
    `_ALWAYS` and every other control character is removed. Never HTML-escapes: Qt plain-text sinks do not
    interpret markup, and rich-text sinks escape separately.
    """
    text = '' if value is None else str(value)
    text = _STRIP.sub('', _NEWLINE.sub('\n', text) if multiline else _BREAK_RUN.sub(' ', text))
    limit = max(0, limit)
    if len(text) <= limit:
        return text
    return text[:limit] if limit <= 3 else text[:limit - 3] + '...'


@dataclass(frozen=True, slots=True)
class ClaimsProfile:
    """Wording a panel must never emit. Stems match the start of a word ('probab' hits 'probably'); words and
    phrases match whole words only ('safe' does not hit 'safeguard'). Matching is case-insensitive and runs after
    the `allowed_phrases` (sanctioned negations such as 'not a probability') are removed."""

    banned_stems: tuple[str, ...] = ()
    banned_words: tuple[str, ...] = ()
    allowed_phrases: tuple[str, ...] = ()

    def violations(self, text: object) -> tuple[str, ...]:
        """The banned stems and words found in `text`, sorted and unique."""
        stems, words, allowed = _patterns(self)
        lowered = '' if text is None else str(text).lower()
        if allowed is not None:
            lowered = allowed.sub(' ', lowered)  # a space, so the neighbours cannot glue into a banned word
        return tuple(sorted({name for name, pattern in (*stems, *words) if pattern.search(lowered)}))


@lru_cache(maxsize=64)
def _patterns(profile: ClaimsProfile):
    def compile_all(names: tuple[str, ...], tail: str):
        return tuple((name.lower(), re.compile(r'(?<!\w)' + re.escape(name.lower()) + tail)) for name in names if name)

    allowed = sorted({phrase.lower() for phrase in profile.allowed_phrases if phrase}, key=len, reverse=True)
    return (compile_all(profile.banned_stems, ''), compile_all(profile.banned_words, r'(?!\w)'),
            re.compile('|'.join(map(re.escape, allowed))) if allowed else None)


# The C6 evidence rules (`secondary.evidence_view.BANNED`) and the negations C6 sanctions: a panel that talks only
# about function pairing must never talk about vulnerabilities, safety or probability.
CLAIMS_PAIRING = ClaimsProfile(
    banned_stems=('probab', 'likelihood', 'vulnerab', 'exploit'),
    banned_words=('confidence %', 'safe', 'secure', 'fixed', 'verified', 'proven', 'certain'),
    allowed_phrases=('not a vulnerability assessment', 'not vulnerabilities', 'not a probability'))

# The default: the claim drift every panel avoids (section 6) without banning the advisory vocabulary that the KB
# and KEV panels legitimately show. Panels with their own rules pass their own profile.
CLAIMS_NEUTRAL = ClaimsProfile(
    banned_stems=('probab', 'likelihood'),
    banned_words=('confidence %', 'safe', 'fixed', 'proven'),
    allowed_phrases=('not a probability',))
