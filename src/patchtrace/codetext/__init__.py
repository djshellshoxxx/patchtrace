"""`codetext/1`: the pure core of code colours and token marks for the Workbench panes (WBQ S7).

Lexical tokens for decompiled C and Ghidra assembly (`tokens`), the Ghidra name classes behind them (`names`) and the
dark palette with its contrast helpers (`palette`). Qt-free and free of third-party imports: Pygments is only a test
oracle (tests/test_codetext_tokens.py). Everything here describes text; none of it is evidence. See
docs/specs/program-e/WBQ-integration-plan.md sections 6 to 9.
"""
from .names import AUTO_NAME, TEMP_NAME, AutoName, classify_name, is_temp_name, parse_auto_name
from .palette import (
    MARK_STATES,
    MIN_MARK_CONTRAST,
    MIN_TEXT_CONTRAST,
    ROLE_BY_KIND,
    ROLES,
    MarkStyle,
    Palette,
    Style,
    contrast_ratio,
    guard_color,
)
from .tokens import (
    KINDS,
    MAX_DOCUMENT_CHARS,
    MAX_LINE_CHARS,
    Language,
    LineTokens,
    Token,
    open_comment_lines,
    tokenize,
    tokenize_line,
)

CONTRACT = 'codetext/1'

__all__ = [
    'AUTO_NAME', 'CONTRACT', 'KINDS', 'MARK_STATES', 'MAX_DOCUMENT_CHARS', 'MAX_LINE_CHARS', 'MIN_MARK_CONTRAST',
    'MIN_TEXT_CONTRAST', 'ROLES', 'ROLE_BY_KIND', 'TEMP_NAME', 'AutoName', 'Language', 'LineTokens', 'MarkStyle',
    'Palette', 'Style', 'Token', 'classify_name', 'contrast_ratio', 'guard_color', 'is_temp_name',
    'open_comment_lines', 'parse_auto_name', 'tokenize', 'tokenize_line',
]
