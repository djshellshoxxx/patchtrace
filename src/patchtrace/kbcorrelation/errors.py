"""``PT-KBC-*`` codes, ``KbcIssue`` and ``OperationResult`` (KB-integration-plan 7.4 and 7.2). Pure.

Acquisition and enrichment codes are nested in ``details`` and never re-mapped. Messages are fixed templates or
labels and numbers; untrusted document text is never placed in ``message``.
"""
from __future__ import annotations

from typing import Annotated, Any, Generic, Literal, TypeVar

from pydantic import Field, model_validator

from .contracts import Contract, Reason, Short

CODES = ('PT-KBC-INPUT', 'PT-KBC-SCOPE', 'PT-KBC-CONSENT', 'PT-KBC-SOURCE', 'PT-KBC-PRODUCT', 'PT-KBC-LINEAGE',
         'PT-KBC-ACQUIRE', 'PT-KBC-VERIFY', 'PT-KBC-UNSUPPORTED', 'PT-KBC-STALE', 'PT-KBC-STATE', 'PT-KBC-STORAGE',
         'PT-KBC-LIMIT', 'PT-KBC-CANCEL', 'PT-KBC-INTERNAL')
ErrorCode = Literal['PT-KBC-INPUT', 'PT-KBC-SCOPE', 'PT-KBC-CONSENT', 'PT-KBC-SOURCE', 'PT-KBC-PRODUCT',
                    'PT-KBC-LINEAGE', 'PT-KBC-ACQUIRE', 'PT-KBC-VERIFY', 'PT-KBC-UNSUPPORTED', 'PT-KBC-STALE',
                    'PT-KBC-STATE', 'PT-KBC-STORAGE', 'PT-KBC-LIMIT', 'PT-KBC-CANCEL', 'PT-KBC-INTERNAL']
Status = Literal['ok', 'partial', 'unknown', 'unsupported', 'cancelled', 'error']

# CLI exit codes (envelope enrichment-cli/1): 0 ok; 2 invalid arguments, consent, contradiction, unsupported;
# 3 runtime failure or partial coverage; 5 cancelled. Exit 4 (complete in scope but empty) depends on the value, so
# it is decided by the caller, not by a code.
EXIT_CODES = {'PT-KBC-INPUT': 2, 'PT-KBC-SCOPE': 2, 'PT-KBC-CONSENT': 2, 'PT-KBC-UNSUPPORTED': 2,
              'PT-KBC-SOURCE': 3, 'PT-KBC-PRODUCT': 3, 'PT-KBC-LINEAGE': 3, 'PT-KBC-ACQUIRE': 3, 'PT-KBC-VERIFY': 3,
              'PT-KBC-STALE': 3, 'PT-KBC-STATE': 3, 'PT-KBC-STORAGE': 3, 'PT-KBC-LIMIT': 3, 'PT-KBC-INTERNAL': 3,
              'PT-KBC-CANCEL': 5}
STATUS_EXIT = {'ok': 0, 'partial': 3, 'unknown': 4, 'unsupported': 2, 'cancelled': 5, 'error': 3}

T = TypeVar('T')


class KbcIssue(Contract):
    code: ErrorCode
    message: Annotated[str, Field(min_length=1, max_length=500)]
    recoverable: bool = True
    source_id: Short | None = None
    details: dict[str, Any] | None = None

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.code]


class OperationResult(Contract, Generic[T]):  # noqa: UP046 (PEP 695 syntax needs Python 3.12)
    status: Status
    value: T | None = None
    issues: tuple[KbcIssue, ...] = ()
    warnings: tuple[Reason, ...] = ()

    @model_validator(mode='after')
    def _consistent(self):
        if self.status == 'ok' and self.issues:
            raise ValueError('an ok result carries no issues')
        if self.status in ('error', 'unsupported', 'cancelled') and not self.issues:
            raise ValueError(f'a {self.status} result needs at least one issue')
        if self.status in ('error', 'unsupported', 'cancelled') and self.value is not None:
            raise ValueError(f'a {self.status} result carries no value')
        return self

    @property
    def exit_code(self) -> int:
        if self.status in ('error', 'unsupported', 'cancelled') and self.issues:
            return max(i.exit_code for i in self.issues) if self.status != 'cancelled' else 5
        return STATUS_EXIT[self.status]
