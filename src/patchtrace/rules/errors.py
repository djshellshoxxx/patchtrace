"""``PT-RULE-*`` codes and ``RuleError`` (YRX-integration-plan section 7). Stdlib only, pure.

A ``RuleError`` message is a fixed template (labels and numbers); rule text, file names and engine output are untrusted and
never become part of it. ``diagnostics`` may carry a sanitized stderr tail for a support log and is never shown as the
message.
"""
from __future__ import annotations

import re
from typing import Literal, get_args

ErrorCode = Literal[
    'PT-RULE-INPUT',        # bad selection or contract
    'PT-RULE-LIMIT',        # a cap was hit (including the worker memory cap)
    'PT-RULE-STALE',        # artifact or project moved since the rule was derived
    'PT-RULE-INTEGRITY',    # hash or row/sidecar mismatch
    'PT-RULE-UNAVAILABLE',  # yara_x or the decoder is missing or the probe failed (blocked state R1)
    'PT-RULE-ENGINE',       # worker crash, panic or non-zero exit
    'PT-RULE-TIMEOUT',      # a deadline passed
    'PT-RULE-CANCEL',       # cooperative cancel
    'PT-RULE-MASK',         # no verified function extent or no mask source (bytes unavailable)
    'PT-RULE-DECODE',       # invalid instruction
    'PT-RULE-COMPILE',      # a generated rule failed to compile (bug or engine drift)
    'PT-RULE-GATE',         # accept or export refused by a hard gate
    'PT-RULE-STORAGE',      # row write failed
    'PT-RULE-EXPORT',       # export path or policy refused
]
CODES: tuple[str, ...] = get_args(ErrorCode)
# CLI exit codes (envelope enrichment-cli/1): 2 invalid input, refusal or unavailable engine; 3 runtime failure; 5 cancelled.
# Exit 4 (complete but empty) and the partial-coverage 3 depend on the result, so the caller decides them, not a code.
EXIT_CODES: dict[str, int] = {
    'PT-RULE-INPUT': 2, 'PT-RULE-UNAVAILABLE': 2, 'PT-RULE-GATE': 2, 'PT-RULE-EXPORT': 2,
    'PT-RULE-LIMIT': 3, 'PT-RULE-STALE': 3, 'PT-RULE-INTEGRITY': 3, 'PT-RULE-ENGINE': 3, 'PT-RULE-TIMEOUT': 3,
    'PT-RULE-MASK': 3, 'PT-RULE-DECODE': 3, 'PT-RULE-COMPILE': 3, 'PT-RULE-STORAGE': 3, 'PT-RULE-CANCEL': 5}
MESSAGE_CHARS = 400
REASON_PATTERN = r'[a-z0-9-]{1,48}'
_REASON = re.compile(REASON_PATTERN)


class RuleError(Exception):
    """Typed, user-safe failure. ``reason`` is an optional machine slug (``worker-oom``, ``engine-missing``, ...)."""

    def __init__(self, code: str, message: str, *, reason: str | None = None, diagnostics: str = ''):
        if code not in CODES:
            raise ValueError(f'unknown rules error code {code!r}')
        if reason is not None and not _REASON.fullmatch(reason):
            raise ValueError('rules error reason must be a slug [a-z0-9-]{1,48}')
        self.code = code
        self.message = str(message)[:MESSAGE_CHARS]
        self.reason = reason
        self.diagnostics = diagnostics
        super().__init__(f'{code}: {self.message}' + (f' [{reason}]' if reason else ''))

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.code]
