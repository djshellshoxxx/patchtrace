"""Bounded, read-only preliminary PE inspection (SPEC-26 D). See docs/specs/pe-overview.md."""
from .compare import compare_overviews
from .inspect import inspect_pe
from .models import (
    ChecksumInfo,
    CodeLabel,
    CodeViewInfo,
    FieldComparison,
    FileRange,
    Limits,
    OverlayInfo,
    PackerHint,
    PeKind,
    PeOverview,
    PeWarning,
    SectionInfo,
    SectionMap,
)

__all__ = [
    'ChecksumInfo', 'CodeLabel', 'CodeViewInfo', 'FieldComparison', 'FileRange', 'Limits', 'OverlayInfo',
    'PackerHint', 'PeKind', 'PeOverview', 'PeWarning', 'SectionInfo', 'SectionMap', 'compare_overviews',
    'inspect_pe',
]
