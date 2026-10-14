"""State, notice, progress, failure and chip values shared by every panel (GUI plan 7 and 8.4). Pure: no Qt.

The copy is plain ASCII and the single source for what a panel says when it has nothing, or not everything, to
show: a blank panel reads as "no findings", so every kind has words. Interpolated values are sanitized first,
because reasons and messages can come from tools and advisories.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from .text import LABEL_LIMIT, VIEW_LIMIT, sanitize_text

NOTICE_CHARS = 400
STAGE_LIMIT = 80
CHIP_TEXT_LIMIT = 40
TASK_CODE = 'PT-GUI-TASK'

STATE_COPY: dict[str, str] = {
    'no-project': 'Open a project to use {title}.',
    'idle': '{title} has no results yet. {hint}',
    'loading': 'Loading {noun}...',
    'refreshing': 'Refreshing {noun}...',
    'ready': '',
    'partial': 'Partial result: {reasons}. Missing evidence is unknown, not disagreement.',
    'stale': '{title} is stale: {reason}. It is shown for reference only.',
    'blocked': '{title} is unavailable: {reason} {remedy}',
    'error': '{title} could not be loaded: {code}: {message}. Earlier results are unchanged.',
    'too-large': 'Too many rows to display ({n}). Narrow the filter.',
    'unsupported': '{title} is not supported here: {reason}',
    'cancelled': 'Cancelled. Earlier results are unchanged.',
}
STATE_KINDS = tuple(STATE_COPY)
FACTORY_COPY = '{title} could not be created: PT-GUI-FACTORY: {exception}. Other panels are unaffected.'
_TRIM = frozenset({('partial', 'reasons'), ('stale', 'reason'), ('error', 'message')})  # the template adds the '.'

# Only error > stale > partial > ready is specified; the rest is the order in which a panel can still act on what
# it shows. `loading` is only ever the first load (see `loading_kind`).
PRECEDENCE = ('no-project', 'unsupported', 'blocked', 'error', 'too-large', 'cancelled', 'stale', 'partial',
              'loading', 'refreshing', 'ready', 'idle')

ACTION_LABELS = {'retry': 'Retry', 'copy': 'Copy details', 'setup': 'Open setup', 'refresh': 'Refresh'}
_ACTION_NAMES = {'retry': 'Retry loading {title}', 'copy': 'Copy {title} details',
                 'setup': 'Open setup for {title}', 'refresh': 'Refresh {title}'}
_ACTIONS = {'stale': ('refresh',), 'blocked': ('setup',), 'error': ('retry', 'copy')}


class _Blank(dict):
    def __missing__(self, key: str) -> str:
        return ''


@dataclass(frozen=True, slots=True)
class StateModel:
    kind: str
    text: str
    detail: str = ''
    actions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in STATE_COPY:
            raise ValueError(f'unknown state kind {self.kind!r:.40}')


def state_text(kind: str, title: str, **fields: object) -> str:
    """The words for a state. Absent fields read as nothing; a field the template ends with '.' loses its own."""
    if kind not in STATE_COPY:
        raise ValueError(f'unknown state kind {kind!r:.40}')
    values = _Blank(title=sanitize_text(title))
    for name, value in fields.items():
        text = sanitize_text(value)
        values[name] = text.rstrip('. ') if (kind, name) in _TRIM else text
    return ' '.join(STATE_COPY[kind].format_map(values).split())


def state_model(kind: str, title: str, *, detail: str = '', **fields: object) -> StateModel:
    return StateModel(kind, state_text(kind, title, **fields), sanitize_text(detail, VIEW_LIMIT, multiline=True),
                      _ACTIONS.get(kind, ()))


def factory_failure(title: str, exception_class: str) -> StateModel:
    """The error shown in place of a panel whose factory raised: the class name only, never its message."""
    values = _Blank(title=sanitize_text(title), exception=sanitize_text(exception_class, STAGE_LIMIT))
    return StateModel('error', ' '.join(FACTORY_COPY.format_map(values).split()))


def action_name(action: str, title: str) -> str:
    """The accessible name of a state button; it carries the panel title so that it is unique in the window."""
    return _ACTION_NAMES[action].format(title=sanitize_text(title))


def dominant(kinds: Iterable[str]) -> str:
    """The state to show when several apply at once; `idle` when none does."""
    present = set(kinds)
    unknown = present - set(PRECEDENCE)
    if unknown:
        raise ValueError(f'unknown state kinds {sorted(unknown)!r:.80}')
    return next((kind for kind in PRECEDENCE if kind in present), 'idle')


def loading_kind(has_content: bool) -> str:
    return 'refreshing' if has_content else 'loading'


# ---- notices, progress, failures --------------------------------------------------------------------------------

NOTICE_LEVELS = ('caution', 'notice')
NOTICE_SCOPES = ('project', 'session')
_NOTICE_KEY = re.compile(r'[a-z][a-z0-9_.-]{0,63}')


@dataclass(frozen=True, slots=True)
class NoticeModel:
    """One line above the central workspace (a pre-flight or calibration note); never modal."""

    key: str
    level: str
    text: str
    detail: str = ''
    dismissible: bool = True
    scope: str = 'project'

    def __post_init__(self) -> None:
        if _NOTICE_KEY.fullmatch(self.key) is None:
            raise ValueError(f'bad notice key {self.key!r:.40}')
        if self.level not in NOTICE_LEVELS or self.scope not in NOTICE_SCOPES:
            raise ValueError(f'bad notice level or scope {self.level!r:.20} {self.scope!r:.20}')
        text = sanitize_text(self.text, NOTICE_CHARS)
        if not text:
            raise ValueError('a notice needs text')
        object.__setattr__(self, 'text', text)
        object.__setattr__(self, 'detail', sanitize_text(self.detail, VIEW_LIMIT, multiline=True))


@dataclass(frozen=True, slots=True)
class Progress:
    """`total=None` is indeterminate."""

    stage: str
    done: int = 0
    total: int | None = None
    message: str = ''

    def __post_init__(self) -> None:
        if self.done < 0 or (self.total is not None and self.total < 0):
            raise ValueError('progress counts cannot be negative')
        object.__setattr__(self, 'stage', sanitize_text(self.stage, STAGE_LIMIT))
        object.__setattr__(self, 'message', sanitize_text(self.message, LABEL_LIMIT))


@dataclass(frozen=True, slots=True)
class TaskFailure:
    """What crosses from a worker thread: the exception class only, so a path or secret in a message cannot."""

    exception_class: str
    code: str = TASK_CODE

    def __post_init__(self) -> None:
        object.__setattr__(self, 'exception_class', sanitize_text(self.exception_class, STAGE_LIMIT))

    @classmethod
    def of(cls, error: BaseException) -> TaskFailure:
        return cls(type(error).__name__)


# ---- chips ------------------------------------------------------------------------------------------------------

CHIP_SHAPES = ('round', 'square', 'diamond', 'dashed')
CHIP_TOKENS = ('ok', 'change', 'caution', 'info', 'muted', 'alt', 'error', 'plain')


@dataclass(frozen=True, slots=True)
class ChipSpec:
    """A status chip is text + an ASCII glyph + a shape; colour (`token`) is only a redundant extra."""

    key: str
    glyph: str
    text: str
    shape: str
    token: str

    def __post_init__(self) -> None:
        if not self.key or len(self.key) > 64:
            raise ValueError('a chip needs a key of at most 64 characters')
        if not (1 <= len(self.glyph) <= 2 and self.glyph.isascii() and self.glyph.isprintable()
                and ' ' not in self.glyph):
            raise ValueError(f'chip glyph must be 1-2 printable ASCII characters: {self.glyph!r:.20}')
        if self.shape not in CHIP_SHAPES or self.token not in CHIP_TOKENS:
            raise ValueError(f'bad chip shape or token {self.shape!r:.20} {self.token!r:.20}')
        text = sanitize_text(self.text, CHIP_TEXT_LIMIT)
        if not text:
            raise ValueError('a chip needs text')
        object.__setattr__(self, 'text', text)


def chip_collisions(chips: Iterable[ChipSpec]) -> tuple[tuple[str, str], ...]:
    """Pairs of chip keys that share a (glyph, shape): within one table each pair must be unique."""
    first: dict[tuple[str, str], str] = {}
    clashes = []
    for chip in chips:
        slot = (chip.glyph, chip.shape)
        if slot in first:
            clashes.append((first[slot], chip.key))
        else:
            first[slot] = chip.key
    return tuple(clashes)
