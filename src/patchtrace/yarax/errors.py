"""Typed `PT-RULE-*` failures (plan s7). Messages are user-safe: no raw tool output, no local paths."""
from __future__ import annotations

from typing import Literal, get_args

ErrorCode = Literal['PT-RULE-INPUT', 'PT-RULE-LIMIT', 'PT-RULE-STALE', 'PT-RULE-INTEGRITY', 'PT-RULE-UNAVAILABLE',
                    'PT-RULE-ENGINE', 'PT-RULE-TIMEOUT', 'PT-RULE-CANCEL', 'PT-RULE-MASK', 'PT-RULE-DECODE',
                    'PT-RULE-COMPILE', 'PT-RULE-GATE', 'PT-RULE-STORAGE', 'PT-RULE-EXPORT']
ERROR_CODES: tuple[str, ...] = get_args(ErrorCode)


class RulesError(Exception):
    def __init__(self, code: ErrorCode, message: str):
        super().__init__(f'{code}: {message}')
        self.code = code
        self.message = message
