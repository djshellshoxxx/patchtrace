"""Operation-owned input capabilities and read checkpoints (core-held-inputs.md)."""
from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Literal, Protocol

ReadCheckpoint = Callable[[int], None]
ReadFailure = Literal['cancelled', 'limited', 'changed', 'unavailable', 'invalid']
_MESSAGES = {
    'cancelled': 'the input operation was cancelled',
    'limited': 'the input operation exceeded its captured limit',
    'changed': 'the held input identity or bytes changed',
    'unavailable': 'the held input reader is unavailable',
    'invalid': 'the input reader contract is invalid',
}


class InputReadError(ValueError):
    def __init__(self, reason: ReadFailure):
        if type(reason) is not str or reason not in _MESSAGES:
            raise ValueError('PT-INPUT: invalid input-reader failure reason')
        self.reason = reason
        super().__init__(f'PT-INPUT: {_MESSAGES[reason]}')


class HeldInput(Protocol):
    """The provider verifies a captured name/object, owns its reader and accounts each read.

    A path is a binding assertion, never authority for opening a different input.
    The provider retains its original, closes only the borrowed stream, and
    observes its original budget/cancel before/after bounded reads and seeks.
    """

    def check(self, path: Path) -> None: ...

    def open_reader(self, path: Path) -> AbstractContextManager[BinaryIO]: ...


@dataclass(frozen=True)
class PairInputReaders:
    older: HeldInput = field(repr=False)
    newer: HeldInput = field(repr=False)
    checkpoint: ReadCheckpoint = field(repr=False)

    def __post_init__(self):
        if not callable(self.checkpoint) or any(
                not callable(getattr(reader, name, None))
                for reader in (self.older, self.newer) for name in ('check', 'open_reader')):
            raise InputReadError('invalid')

    def __reduce__(self):
        raise TypeError('operation input readers cannot be serialized')
