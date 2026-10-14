"""Panel registry: the PanelSpec a feature declares, the manifest slot that reserves its place, loading, and the lint
behind `patchtrace panels check` (GUI plan 7, 8.1, 8.2). Pure: no Qt, and a feature's Qt module is imported only
when its factory runs.

The manifest (`patchtrace/panel_manifest.py`) reserves id, area, tab group and shortcut for every planned panel,
built or not, so collisions are caught before a second panel exists. A built spec must agree with its slot.
"""
from __future__ import annotations

import re
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, Protocol

from .anchors import ANCHOR_KINDS, CODE_KINDS
from .anchors import NAV_HISTORY as NAV_HISTORY
from .capabilities import CAP_CODE, Availability, is_capability_id
from .shortcuts import FRAMEWORK, RESERVED, normalize, panel_shortcut_error
from .state import NOTICE_CHARS as NOTICE_CHARS
from .text import CLAIMS_NEUTRAL, LABEL_LIMIT, ClaimsProfile, sanitize_text

if TYPE_CHECKING:
    from ..tooltips import TooltipEntry
    from .anchors import AnchorRef, NavResult
    from .ports import MutationPort, NavigationPort, ProjectPort, ShellPort
    from .projection import ProjectKey

# ---- limits (GUI plan 7) ----------------------------------------------------------------------------------------
# LABEL_LIMIT, NAV_HISTORY and NOTICE_CHARS are enforced by the modules that own them and are listed here too.

MAX_PANELS = 32
PANEL_ID = re.compile(r'[a-z][a-z0-9_]{1,23}')  # append-only: a retired id stays reserved
AREAS = ('left', 'right', 'top', 'bottom', 'none')  # 'none' = no dock (cards, chips, banners, tips)
TITLE_LIMIT = 32
NAME_LIMIT = 80
DESCRIPTION_LIMIT = 160
TABLE_ROWS = 100_000
CLIPBOARD_BYTES = 16 * 1024
GRAPH_NODES = 500
GRAPH_EDGES = 2_000
GRAPH_NODES_MAX = 2_000
GRAPH_EDGES_MAX = 8_000
CODE_CHARS = 200_000
PROGRESS_HZ = 10
ANNOUNCE_GAP_S = 1.5
SELECTION_DEBOUNCE_MS = 120
JOIN_TIMEOUT_S = 5
PALETTE_RESULTS = 50
FOCUS_ORDER_MIN = 100  # F6 order: built-in regions use 10/20/30/90, panels 100 and up
TEACH_MEANING_LIMIT = 300
TEACH_STEPS = 4
TEACH_STEP_LIMIT = 200

MANIFEST_CODE = 'PT-GUI-MANIFEST'
TIPS_CODE = 'PT-GUI-TIPS'

Area = Literal['left', 'right', 'top', 'bottom', 'none']


def is_panel_id(text: object) -> bool:
    return isinstance(text, str) and PANEL_ID.fullmatch(text) is not None


def tip_prefix(panel_id: str) -> str:
    return f'{panel_id}.'


def dock_name(panel_id: str) -> str:
    """The dock's objectName; it is also the dock's tooltip id."""
    return f'{panel_id}.dock'


def toggle_name(panel_id: str) -> str:
    """The View-menu toggle action's objectName and tooltip id."""
    return f'{panel_id}.action'


def settings_prefix(panel_id: str) -> str:
    return f'{panel_id}/'


def accessible_name(title: str) -> str:
    return f'{title} panel'


# ---- what a feature declares ------------------------------------------------------------------------------------


def _available() -> Availability:
    return Availability(True)


@dataclass(frozen=True, slots=True, kw_only=True)
class CommandSpec:
    """One menu and palette command of a panel."""

    id: str
    title: str
    run: Callable[[], None]
    tip_id: str | None = None
    shortcut: str | None = None
    group: str = 'Panels'
    keywords: tuple[str, ...] = ()
    enabled: Callable[[], Availability] = _available


@dataclass(frozen=True, slots=True)
class TeachTopic:
    """Data for the guide (E-5): what a thing means and up to four next steps. Claims-swept like all panel text."""

    id: str
    meaning: str
    next: tuple[str, ...]
    commands: tuple[str, ...] = ()


class PanelController(Protocol):
    """What the host calls on a built panel. All hooks are optional in practice: the Qt base class supplies no-ops."""

    def widget(self) -> object | None: ...
    def focus_target(self) -> object | None: ...
    def project_changed(self, key: ProjectKey | None) -> None: ...
    def selection_changed(self, match_id: str | None) -> None: ...
    def busy_changed(self, busy: bool) -> None: ...
    def capabilities_changed(self) -> None: ...
    def theme_changed(self, tokens: object) -> None: ...
    def show_anchor(self, anchor: AnchorRef) -> NavResult: ...
    def shutdown(self) -> None: ...


@dataclass(frozen=True, slots=True, eq=False)
class PanelSpec:
    """A panel's whole declaration. `factory` runs once on the GUI thread at first show and builds every widget; it
    starts no thread and reads no disk. Compared by identity (the tip mappings are dicts)."""

    id: str
    title: str
    factory: Callable[[PanelContext], PanelController]
    area: Area = 'right'
    tabify_with: str | None = None
    shortcut: str | None = None
    focus_order: int = FOCUS_ORDER_MIN
    group: str = 'Panels'
    requires: tuple[str, ...] = ()
    claims: ClaimsProfile = CLAIMS_NEUTRAL
    tips: Mapping[str, TooltipEntry] = field(default_factory=dict)
    tip_templates: Mapping[str, TooltipEntry] = field(default_factory=dict)
    extra_tip_prefixes: tuple[str, ...] = ()
    commands: tuple[CommandSpec, ...] = ()
    teach: tuple[TeachTopic, ...] = ()
    anchors_in: frozenset[str] = frozenset()
    anchors_out: frozenset[str] = frozenset()
    default_visible: bool = False
    eager: bool = False
    minimum_em: tuple[int, int] = (40, 14)
    contract: int = 1


@dataclass(frozen=True, slots=True)
class PanelContext:
    """What a factory receives: its spec and one object per port."""

    spec: PanelSpec
    project: ProjectPort
    mutate: MutationPort
    nav: NavigationPort
    shell: ShellPort

    @property
    def tasks(self) -> object:
        return self.shell.tasks

    @property
    def settings(self) -> object:
        return self.shell.settings

    @property
    def theme(self) -> object:
        return self.shell.theme

    @property
    def announce(self) -> Callable[..., None]:
        return self.shell.announce


# ---- the manifest and loading it --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ManifestEntry:
    """A reserved slot. `load` imports `module` inside its body (so nothing of a feature loads before it is asked
    for, and PyInstaller still sees the import) and returns its `PANEL`."""

    id: str
    module: str
    load: Callable[[], PanelSpec]
    area: str
    tabify_with: str | None = None
    shortcut: str | None = None


@dataclass(frozen=True, slots=True)
class Loaded:
    specs: Mapping[str, PanelSpec]  # built panels by manifest id, in manifest order
    not_built: tuple[str, ...]
    errors: Mapping[str, str]  # manifest id -> exception class name; never a message
    forbidden: Mapping[str, tuple[str, ...]]  # manifest id -> forbidden modules that load newly imported
    cancelled: bool = False


FORBIDDEN_ROOTS = frozenset({'PySide6', 'shiboken6', 'PyQt5', 'PyQt6', 'networkx', 'rapidfuzz', 'pygments', 'yara',
                             'yara_x'})


def forbidden_modules(names: Iterable[str]) -> tuple[str, ...]:
    """Qt, the heavy libraries a spec module must not pull in, and the Qt UI modules, from loaded module names."""
    found = set()
    for name in names:
        root = name.partition('.')[0]
        if root in FORBIDDEN_ROOTS:
            found.add(root)
        elif name in ('patchtrace.ui', 'patchtrace.gui.qt') or name.startswith(('patchtrace.ui_', 'patchtrace.gui.qt.')):
            found.add(name)
    return tuple(sorted(found))


def _imported() -> tuple[str, ...]:
    return forbidden_modules(name for name, module in list(sys.modules.items()) if module is not None)


def _is_not_built(module: str, error: ModuleNotFoundError) -> bool:
    """The expected module, or a package above it (`patchtrace.search` when `panel.py` and its package are both
    absent), is what is missing. A missing dependency of an existing module is an error, not an absent feature."""
    name = error.name or ''
    return bool(name) and name != 'patchtrace' and (module == name or module.startswith(name + '.'))


def load_manifest(entries: Sequence[ManifestEntry], cancelled: Callable[[], bool] = lambda: False) -> Loaded:
    """Call every loader. A missing expected module is `not_built`; anything else a loader raises is recorded by
    class name and never stops the others. `cancelled` is polled before each loader."""
    specs: dict[str, PanelSpec] = {}
    not_built: list[str] = []
    errors: dict[str, str] = {}
    forbidden: dict[str, tuple[str, ...]] = {}
    for entry in entries:
        if cancelled():
            return Loaded(specs, tuple(not_built), errors, forbidden, True)
        before = set(_imported())
        try:
            spec = entry.load()
        except ModuleNotFoundError as error:
            if _is_not_built(entry.module, error):
                not_built.append(entry.id)
            else:
                errors[entry.id] = type(error).__name__
        except Exception as error:  # noqa: BLE001 - a feature module may raise anything; it must not hide the others
            errors[entry.id] = type(error).__name__
        else:
            if isinstance(spec, PanelSpec):
                specs[entry.id] = spec
            else:
                errors[entry.id] = 'NotAPanelSpec'
        added = set(_imported()) - before
        if added:
            forbidden[entry.id] = tuple(sorted(added))
    return Loaded(specs, tuple(not_built), errors, forbidden)


# ---- lint -------------------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Finding:
    code: str  # PT-GUI-MANIFEST, PT-GUI-TIPS or PT-GUI-CAP
    panel: str  # the manifest id; '' for the manifest as a whole
    rule: str
    message: str

    def __post_init__(self) -> None:
        object.__setattr__(self, 'message', sanitize_text(self.message, LABEL_LIMIT))

    def as_dict(self) -> dict[str, str]:
        return {'code': self.code, 'panel': self.panel, 'rule': self.rule, 'message': self.message}


@dataclass(frozen=True, slots=True)
class LintReport:
    findings: tuple[Finding, ...]
    warnings: tuple[str, ...] = ()


def _module_ok(module: str) -> bool:
    parts = module.split('.')
    return len(parts) >= 2 and parts[0] == 'patchtrace' and all(part.isidentifier() for part in parts)


def lint_entries(entries: Sequence[ManifestEntry]) -> list[Finding]:
    """The rules that need no spec: ids, areas, modules, shortcuts and tab groups of the reserved slots."""
    found: list[Finding] = []

    def add(panel: str, rule: str, message: str) -> None:
        found.append(Finding(MANIFEST_CODE, panel, rule, message))

    if len(entries) > MAX_PANELS:
        add('', 'count', f'{len(entries)} panels exceed the limit of {MAX_PANELS}')
    first: dict[str, ManifestEntry] = {}
    claimed: dict[str, str] = {}
    for entry in entries:
        if not is_panel_id(entry.id):
            add(entry.id, 'id', 'a panel id is 2-24 characters of a-z, 0-9 and _, starting with a letter')
        if entry.id in first:
            add(entry.id, 'duplicate-id', f'panel id {entry.id} is used twice')
        first.setdefault(entry.id, entry)
        if entry.area not in AREAS:
            add(entry.id, 'area', f'area {entry.area!r:.30} is not one of {", ".join(AREAS)}')
        if not _module_ok(entry.module):
            add(entry.id, 'module', f'module {entry.module!r:.60} is not a module inside patchtrace')
        if entry.area == 'none' and (entry.shortcut is not None or entry.tabify_with is not None):
            add(entry.id, 'none-dock', 'a panel without a dock has no shortcut and no tab group')
        if entry.shortcut is None:
            continue
        problem = panel_shortcut_error(entry.shortcut)
        if problem is not None:
            add(entry.id, 'shortcut', f'shortcut {entry.shortcut!r:.30} {problem}')
            continue
        key = normalize(entry.shortcut)
        taken = RESERVED.get(key) or FRAMEWORK.get(key)
        if taken is not None:
            add(entry.id, 'reserved-shortcut', f'{key} is used by {taken}')
        elif key in claimed:
            add(entry.id, 'duplicate-shortcut', f'{key} is already used by {claimed[key]}')
        else:
            claimed[key] = entry.id
    for entry in entries:
        if entry.tabify_with is None:
            continue
        target = first.get(entry.tabify_with)
        if target is None:
            problem = f'tab group {entry.tabify_with!r:.30} is not in the manifest'
        elif entry.tabify_with == entry.id:
            problem = 'a panel cannot join its own tab group'
        elif target.tabify_with is not None:
            problem = f'{target.id} is itself tabbed with {target.tabify_with}'
        elif target.area != entry.area:
            problem = f'{target.id} is in the {target.area} area, not {entry.area}'
        else:
            continue
        add(entry.id, 'tabify', problem)
    return found


class _Cross:
    """What the per-spec rules share: the manifest, the keys in use and the tooltip ids that already exist."""

    def __init__(self, entries: Sequence[ManifestEntry]) -> None:
        from ..tooltips import REGISTRY, TEMPLATES
        self.panel_prefixes = {tip_prefix(entry.id) for entry in entries}
        self.existing = {**REGISTRY, **TEMPLATES}
        self.existing_what = {tip.what: tip_id for tip_id, tip in self.existing.items()}
        self.keys = {key: entry.id for entry in entries if entry.shortcut and (key := normalize(entry.shortcut))}
        self.extra_prefixes: dict[str, str] = {}


def _tip_problem(entry: object) -> str | None:
    for name in ('what', 'why', 'effect'):
        if not isinstance(getattr(entry, name, None), str) or not getattr(entry, name):
            return f'needs a non-empty {name} line'
    if any(char in str(getattr(entry, name, '')) for name in ('what', 'why', 'effect', 'source', 'availability')
           for char in '<>'):
        return 'must be plain text without angle brackets'
    return None


def _lint_tips(spec: PanelSpec, cross: _Cross) -> list[Finding]:
    found: list[Finding] = []

    def add(rule: str, message: str) -> None:
        found.append(Finding(TIPS_CODE, spec.id, rule, message))

    own = tip_prefix(spec.id)
    allowed = [own]
    for prefix in spec.extra_tip_prefixes:
        if not prefix.endswith('.') or len(prefix) < 2:
            add('tip-extra-prefix', f'prefix {prefix!r:.30} must end with a dot')
        elif prefix in cross.panel_prefixes - {own}:
            add('tip-extra-prefix', f'prefix {prefix!r:.30} belongs to another panel')
        elif cross.extra_prefixes.setdefault(prefix, spec.id) != spec.id:
            add('tip-extra-prefix', f'prefix {prefix!r:.30} is also declared by {cross.extra_prefixes[prefix]}')
        else:
            allowed.append(prefix)
    both = [*spec.tips.items(), *spec.tip_templates.items()]
    for tip_id in sorted(set(spec.tips) & set(spec.tip_templates)):
        add('tip-conflict', f'{tip_id} is both a tip and a template')
    if spec.area != 'none':
        for required in (dock_name(spec.id), toggle_name(spec.id)):
            if required not in spec.tips:
                add('tip-required', f'tip {required} is required')
    seen_what: dict[str, str] = {}
    for tip_id, entry in both:
        if not tip_id.startswith(tuple(allowed)):
            add('tip-prefix', f'tip id {tip_id!r:.60} is outside {", ".join(allowed)}')
        problem = _tip_problem(entry)
        if problem is not None:
            add('tip-entry', f'{tip_id} {problem}')
            continue
        existing = cross.existing.get(tip_id)
        if existing is not None and existing != entry:
            add('tip-conflict', f'{tip_id} is already registered with different text')
        for owner in (seen_what.get(entry.what), cross.existing_what.get(entry.what)):
            if owner is not None and owner != tip_id:
                add('tip-duplicate', f'{tip_id} repeats the What line of {owner}')
        seen_what.setdefault(entry.what, tip_id)
    return found


def _swept_texts(spec: PanelSpec) -> Iterable[tuple[str, str]]:
    yield 'title', str(spec.title)
    for tip_id, entry in [*spec.tips.items(), *spec.tip_templates.items()]:
        yield tip_id, ' '.join(str(getattr(entry, name, '')) for name in
                               ('what', 'why', 'effect', 'source', 'availability'))
    for command in spec.commands:
        yield command.id, ' '.join((command.title, *command.keywords))
    for topic in spec.teach:
        yield topic.id, ' '.join((topic.meaning, *topic.next))


def _lint_commands_and_teach(spec: PanelSpec, cross: _Cross) -> list[Finding]:
    found: list[Finding] = []

    def add(rule: str, message: str) -> None:
        found.append(Finding(MANIFEST_CODE, spec.id, rule, message))

    own = tip_prefix(spec.id)
    seen: set[str] = set()
    for command in spec.commands:
        if not command.id.startswith(own):
            add('command-id', f'command id {command.id!r:.40} must start with {own}')
        if command.id in seen:
            add('command-duplicate', f'command {command.id} is declared twice')
        seen.add(command.id)
        if not command.title or len(command.title) > NAME_LIMIT:
            add('command-title', f'command {command.id} needs a title of at most {NAME_LIMIT} characters')
        if command.shortcut is None:
            continue
        key = normalize(command.shortcut)
        if key is None:
            add('command-shortcut', f'command {command.id}: {command.shortcut!r:.30} is not a key sequence')
        elif (taken := RESERVED.get(key) or FRAMEWORK.get(key)) is not None:
            add('command-reserved', f'command {command.id}: {key} is used by {taken}')
        elif key in cross.keys:
            add('command-taken', f'command {command.id}: {key} is already used by {cross.keys[key]}')
        else:
            cross.keys[key] = f'{spec.id} command {command.id}'
    topics: set[str] = set()
    for topic in spec.teach:
        if not topic.id.startswith(own):
            add('teach-id', f'teach id {topic.id!r:.40} must start with {own}')
        if topic.id in topics:
            add('teach-duplicate', f'teach topic {topic.id} is declared twice')
        topics.add(topic.id)
        if not topic.meaning:
            add('teach-empty', f'teach topic {topic.id} has no meaning')
        elif len(topic.meaning) > TEACH_MEANING_LIMIT:
            add('teach-meaning', f'teach topic {topic.id}: meaning is over {TEACH_MEANING_LIMIT} characters')
        if len(topic.next) > TEACH_STEPS:
            add('teach-steps', f'teach topic {topic.id} has more than {TEACH_STEPS} steps')
        if any(not step or len(step) > TEACH_STEP_LIMIT for step in topic.next):
            add('teach-step', f'teach topic {topic.id}: each step is 1-{TEACH_STEP_LIMIT} characters')
    return found


def _lint_spec(entry: ManifestEntry, spec: PanelSpec, cross: _Cross) -> list[Finding]:
    found: list[Finding] = []

    def add(rule: str, message: str, code: str = MANIFEST_CODE) -> None:
        found.append(Finding(code, entry.id, rule, message))

    if spec.id != entry.id:
        add('spec-id', f'the spec says {spec.id!r:.30} but its manifest slot is {entry.id}')
        return found  # everything else is relative to the id
    if spec.contract != 1:
        add('contract', f'contract {spec.contract!r:.10} is not 1')
    if not (isinstance(spec.title, str) and spec.title and sanitize_text(spec.title, TITLE_LIMIT) == spec.title):
        add('title', f'the title must be 1-{TITLE_LIMIT} plain characters')
    mine = (spec.area, spec.tabify_with, spec.shortcut and (normalize(spec.shortcut) or spec.shortcut))
    slot = (entry.area, entry.tabify_with, entry.shortcut and (normalize(entry.shortcut) or entry.shortcut))
    if mine != slot:
        add('placement', f'area, tab group and shortcut {mine} differ from the manifest slot {slot}')
    if not isinstance(spec.focus_order, int) or spec.focus_order < FOCUS_ORDER_MIN:
        add('focus-order', f'focus_order must be {FOCUS_ORDER_MIN} or more')
    for capability in spec.requires:
        if not is_capability_id(capability):
            add('requires', f'{capability!r:.40} is not a capability id', CAP_CODE)
    for name in ('anchors_in', 'anchors_out'):
        unknown = sorted(kind for kind in getattr(spec, name) if kind not in ANCHOR_KINDS)
        if unknown:
            add('anchors', f'{name} lists unknown kinds: {", ".join(map(str, unknown))}')
    found += _lint_tips(spec, cross)
    found += _lint_commands_and_teach(spec, cross)
    for where, text in _swept_texts(spec):
        hits = spec.claims.violations(text)
        if hits:
            add('claims', f'{where}: {", ".join(hits)}')
    return found


def lint(entries: Sequence[ManifestEntry], loaded: Loaded | None = None) -> LintReport:
    """Every `PT-GUI-MANIFEST` rule: the static ones over the slots and, for panels that loaded, the ones over their
    specs. Emitting anchors that no built panel handles is a warning, not a finding."""
    found = lint_entries(entries)
    warnings: list[str] = []
    if loaded is not None:
        cross = _Cross(entries)
        slots: dict[str, ManifestEntry] = {}
        for entry in entries:
            slots.setdefault(entry.id, entry)
        for panel_id, spec in loaded.specs.items():
            if panel_id in slots:
                found += _lint_spec(slots[panel_id], spec, cross)
        for panel_id, modules in loaded.forbidden.items():
            found.append(Finding(MANIFEST_CODE, panel_id, 'imports',
                                 f'loading the panel also imported: {", ".join(modules)}'))
        handled = set(CODE_KINDS).union(*(spec.anchors_in for spec in loaded.specs.values()))
        for panel_id, spec in loaded.specs.items():
            lost = sorted(kind for kind in spec.anchors_out if kind in ANCHOR_KINDS and kind not in handled)
            if lost:
                warnings.append(f'{panel_id} emits {", ".join(lost)} anchors that no built panel handles')
    return LintReport(tuple(found), tuple(warnings))
