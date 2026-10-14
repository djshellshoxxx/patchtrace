"""Data directory naming and presence."""
from __future__ import annotations

from collections.abc import Sequence

from .models import DataDirectory

DIRECTORY_NAMES = (
    'Export', 'Import', 'Resource', 'Exception', 'Security', 'BaseReloc', 'Debug', 'Architecture',
    'GlobalPtr', 'TLS', 'LoadConfig', 'BoundImport', 'IAT', 'DelayImport', 'CLR', 'Reserved',
)


def parse_directories(raw: Sequence[tuple[int, int]]) -> tuple[DataDirectory, ...]:
    out = []
    for i, (rva, size) in enumerate(raw):
        name = DIRECTORY_NAMES[i] if i < len(DIRECTORY_NAMES) else f'Directory{i}'
        out.append(DataDirectory(i, name, rva, size, rva != 0 and size != 0))
    return tuple(out)
