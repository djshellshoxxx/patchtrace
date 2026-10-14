"""Symbol-name decoration facts (WBQ slice S10; docs/specs/program-e/WBQ-integration-plan.md section 7).

Pure and Qt-free: names are only text, input is bounded to 512 characters, and nothing is loaded or executed.
What this package cannot read stays unknown (no qualified name) instead of being guessed.
"""
from .decoration import MAX_QUALIFIED_NAME_CHARS, Decoration, parse_decoration
from .kinds import KINDS, MAX_NAME_BYTES, DecorationKind, core_name

__all__ = ['KINDS', 'MAX_NAME_BYTES', 'MAX_QUALIFIED_NAME_CHARS', 'Decoration', 'DecorationKind', 'core_name',
           'parse_decoration']
