"""Pure CAB member-name admission. Logical names never authorize host paths."""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from .contracts import AcquisitionError

MAX_NAME_BYTES = 1024
MAX_ENTRIES = 50_000
_DEVICES = frozenset({'con', 'prn', 'aux', 'nul', 'conin$', 'conout$', 'clock$',
                      *(prefix + digit for prefix in ('com', 'lpt') for digit in '123456789\u00b9\u00b2\u00b3')})
_FORBIDDEN = frozenset('<>:"|?*')


def _refuse(message='unsafe logical package member name'):
    raise AcquisitionError('PT-ACQ-INPUT', message)


def _limit(value, ceiling):
    if type(value) is not int or not 1 <= value <= ceiling:
        _refuse('invalid package name limit')


@dataclass(frozen=True, slots=True)
class MemberName:
    raw_hex: str
    path: str
    collision_key: str
    basename: str


def decode_member_name(raw: bytes, *, utf8: bool, max_bytes: int = MAX_NAME_BYTES) -> MemberName:
    """Preserve raw spelling; normalize separators only in the logical display path."""
    _limit(max_bytes, MAX_NAME_BYTES)
    if type(raw) is not bytes or type(utf8) is not bool or not raw:
        _refuse()
    if len(raw) > max_bytes:
        raise AcquisitionError('PT-ACQ-LIMIT', 'package member name exceeds its byte limit')
    try:
        text = raw.decode('utf-8' if utf8 else 'ascii', errors='strict')
    except UnicodeError:
        _refuse('unsupported or malformed package member-name encoding')
    path = text.replace('\\', '/')
    components = path.split('/')
    if len(components) > 64:
        raise AcquisitionError('PT-ACQ-LIMIT', 'package member has too many logical components')
    for component in components:
        if (not component or component in {'.', '..'} or component.startswith(' ')
                or component.endswith(('.', ' ')) or any(char in _FORBIDDEN for char in component)
                or any(unicodedata.category(char).startswith('C') or unicodedata.category(char) in {'Zl', 'Zp'}
                       for char in component)):
            _refuse()
        if len(component.encode('utf-16-le')) // 2 > 255:
            raise AcquisitionError('PT-ACQ-LIMIT', 'package member component exceeds its Windows limit')
        stem = component.split('.', 1)[0].rstrip(' .').casefold()
        if stem in _DEVICES:
            _refuse('reserved Windows member name')
    key = unicodedata.normalize('NFC', unicodedata.normalize('NFC', path).casefold())
    return MemberName(raw.hex(), path, key, components[-1])


class NameRegistry:
    """One CAB occurrence's file identities, including implicit parent directories."""

    def __init__(self, *, max_entries: int = MAX_ENTRIES, max_bytes: int = MAX_NAME_BYTES):
        _limit(max_entries, MAX_ENTRIES)
        _limit(max_bytes, MAX_NAME_BYTES)
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._files: set[str] = set()
        self._parents: set[str] = set()

    @property
    def count(self) -> int:
        return len(self._files)

    def add(self, raw: bytes, *, utf8: bool) -> MemberName:
        name = decode_member_name(raw, utf8=utf8, max_bytes=self._max_bytes)
        components = name.collision_key.split('/')
        parents = {'/'.join(components[:index]) for index in range(1, len(components))}
        if (name.collision_key in self._files or name.collision_key in self._parents
                or parents.intersection(self._files)):
            _refuse('package member names collide or alias a logical parent')
        if self.count >= self._max_entries:
            raise AcquisitionError('PT-ACQ-LIMIT', 'package member population exceeds its limit')
        self._files.add(name.collision_key)
        self._parents.update(parents)
        return name
