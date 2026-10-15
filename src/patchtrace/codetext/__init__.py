"""`codetext/1`: the pure core of code colours and token marks for the Workbench panes (WBQ S7 and S8).

Lexical tokens for decompiled C and Ghidra assembly (`tokens`), the Ghidra name classes behind them (`names`) and the
dark palette with its contrast helpers (`palette`) are S7. S8 adds the operand classes of the text path (`operands`),
the target and rename oracles (`oracle`), the token marks of one displayed row pair (`intraline`, records in `marks`)
and the model a windowed highlighter reads (`model`). Qt-free and free of third-party imports: Pygments is only a test
oracle (tests/test_codetext_tokens.py). Everything here describes text; none of it is evidence. See
docs/specs/program-e/WBQ-integration-plan.md sections 6 to 9.
"""
from .intraline import (
    MAX_DP_CELLS,
    MAX_PAIR_TOKENS,
    NO_DIFFERENCE,
    SIMILARITY_GATE,
    SMALL_EDIT,
    diff_row,
    long_line_sentence,
)
from .marks import LABELS, SIDES, FormatSpan, Mark, MarkState, RowMarks, Side, StyleKey
from .model import (
    LRU_LINES,
    MAX_PAIRS_PER_REFRESH,
    MAX_WORK_PER_REFRESH,
    CodeTextModel,
    Found,
    Refresh,
    utf16_length,
    utf16_offset,
)
from .names import AUTO_NAME, TEMP_NAME, AutoName, classify_name, is_temp_name, parse_auto_name
from .operands import (
    OPERAND_CLASSES,
    ImageRange,
    Operand,
    OperandClass,
    OperandSource,
    TextOperandSource,
    number_value,
)
from .oracle import (
    MatchPairOracle,
    NullOracle,
    NullRenameOracle,
    RenameOracle,
    RenameState,
    Target,
    TargetKind,
    TargetOracle,
    TargetState,
)
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
    'AUTO_NAME', 'CONTRACT', 'KINDS', 'LABELS', 'LRU_LINES', 'MARK_STATES', 'MAX_DOCUMENT_CHARS', 'MAX_DP_CELLS',
    'MAX_LINE_CHARS', 'MAX_PAIRS_PER_REFRESH', 'MAX_PAIR_TOKENS', 'MAX_WORK_PER_REFRESH', 'MIN_MARK_CONTRAST',
    'MIN_TEXT_CONTRAST', 'NO_DIFFERENCE', 'OPERAND_CLASSES', 'ROLES', 'ROLE_BY_KIND', 'SIDES', 'SIMILARITY_GATE',
    'SMALL_EDIT', 'TEMP_NAME', 'AutoName', 'CodeTextModel', 'FormatSpan', 'Found', 'ImageRange', 'Language',
    'LineTokens', 'Mark', 'MarkState', 'MarkStyle', 'MatchPairOracle', 'NullOracle', 'NullRenameOracle', 'Operand',
    'OperandClass', 'OperandSource', 'Palette', 'Refresh', 'RenameOracle', 'RenameState', 'RowMarks', 'Side',
    'Style', 'StyleKey', 'Target', 'TargetKind', 'TargetOracle', 'TargetState', 'TextOperandSource', 'Token',
    'classify_name', 'contrast_ratio', 'diff_row', 'guard_color', 'is_temp_name', 'long_line_sentence',
    'number_value', 'open_comment_lines', 'parse_auto_name', 'tokenize', 'tokenize_line', 'utf16_length',
    'utf16_offset',
]
