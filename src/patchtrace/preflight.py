"""Lightweight preliminary artifact comparison without disk IO or analysis engines.

Only data already validated and saved with the project is shown here. This is
not PE parsing, a signature verification, or a statement about file authenticity.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Artifact


@dataclass(frozen=True, slots=True)
class OverviewRow:
    field: str
    older: str
    newer: str


def overview_rows(older: Artifact, newer: Artifact) -> tuple[OverviewRow, ...]:
    """Return an immutable, strictly oriented comparison of saved input facts.

    This function performs no filesystem IO or hashing: the SHA-256 fields were
    recorded on project creation. Future PE inspectors can add independently
    sourced rows rather than conflating recorded metadata with current bytes.
    """
    if older.side != 'older' or newer.side != 'newer':
        raise ValueError('Expected explicitly oriented older and newer artifacts')
    delta = newer.size - older.size
    return (
        OverviewRow('File name', older.name, newer.name),
        OverviewRow('File size', f'{older.size:,} bytes', f'{newer.size:,} bytes'),
        OverviewRow('Size change (newer - older)', '—', f'{delta:+,} bytes'),
        OverviewRow('SHA-256', older.sha256, newer.sha256),
        OverviewRow('Content hash comparison', '—',
                    'Identical' if older.sha256 == newer.sha256 else 'Different'),
        OverviewRow('Format', older.format, newer.format),
        OverviewRow('Architecture', older.architecture, newer.architecture),
    )
