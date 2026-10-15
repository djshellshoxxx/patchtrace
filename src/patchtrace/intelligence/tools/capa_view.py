"""Pure view-model of the capability changes (CAP-3): rows, filters, grouping, state text, detail, provenance block,
teach hooks. No Qt, no I/O: the Capabilities panel (CAP-6) only draws what is built here.

Wording is neutral on purpose. A change says a behaviour that capa's rules recognise appeared, disappeared or moved
between functions; it never says what the change is for, and nothing here implies a defect, a severity or an intent.
Rows are ordered by namespace and rule name, never by count or importance; ATT&CK/MBC labels appear only in the detail
text and as an explicit grouping choice. All strings that come from the tool are escaped text, never markup.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from .capa_pairs import MAX_ROWS, PairCapabilityDelta, PairCell, PairChange, PairGroup, Unattributed
from .common import (
    MAX_FEATURES,
    CapabilityEvidence,
    FeatureRef,
    ToolManifest,
    ToolRun,
    display_text,
    redacted_display,
    secret_kind,
)

MAX_DISPLAY_ROWS = MAX_ROWS
EXPAND_LIMIT = 20
DETAIL_LIMIT = 4000
CLIPBOARD_LIMIT = 16 * 1024
FilterMode = Literal['changes', 'gained', 'lost', 'moved', 'unchanged', 'not-compared', 'all']
GroupBy = Literal['namespace', 'function-pair', 'attack', 'mbc', 'none']
FILTERS: tuple[tuple[FilterMode, str], ...] = (
    ('changes', 'Changes (gained, lost, moved)'), ('gained', 'Gained'), ('lost', 'Lost'), ('moved', 'Moved'),
    ('unchanged', 'Same'), ('not-compared', 'Not compared'), ('all', 'All'))
GROUPINGS: tuple[tuple[GroupBy, str], ...] = (
    ('namespace', 'Namespace'), ('function-pair', 'Function pair'), ('attack', 'ATT&CK tactic label'),
    ('mbc', 'MBC objective label'), ('none', 'None'))
CHANGES_FILTER = frozenset({'gained', 'lost', 'moved'})
GLYPHS = {'gained': '+', 'lost': '-', 'moved': '~', 'unchanged': '=', 'not-compared': '?'}
LABELS = {'gained': 'Gained', 'lost': 'Lost', 'moved': 'Moved', 'unchanged': 'Same', 'not-compared': 'Not compared'}
# Fills are neutral (never red or green); the text and glyph always carry the meaning. Black text on every fill is
# >= 4.5:1 and every fill is >= 3:1 against the dark theme background (checked by tests).
BADGE_COLORS = {'gained': '#a9c1de', 'lost': '#c9b8e6', 'moved': '#f0b429', 'unchanged': '#cfcfcf',
                'not-compared': '#cfcfcf'}
BADGE_TEXT = '#000000'
FOOTER = ('Capabilities are behaviours that capa rules recognise in code. A change means a recognised behaviour '
          'appeared, disappeared or moved between functions. It does not say what the change is for, and it says '
          'nothing about defects or about the intent of the code. capa does not follow calls, so a behaviour may '
          'only have moved.')
ACCESSIBLE_NAMES = {
    'dock': 'Capabilities panel', 'tabs': 'Capability views', 'tree': 'Capability changes by function pair',
    'filter': 'Filter capability changes', 'group': 'Group capability changes by',
    'search': 'Search capabilities by rule, namespace or function', 'detail': 'Selected capability change details',
    'copy': 'Copy provenance of selected capability change',
    'goto': 'Go to selected function pair in the navigator', 'run': 'Run capa on both files',
    'cancel': 'Cancel capa run', 'path': 'capa executable path'}
STATE_TEXT = {
    'C0': 'Open a project to compare capabilities.',
    'C1': ('capa is not set up. Capability comparison needs the separate program capa 9.x. PatchTrace never '
           'downloads it by itself. Choose an installed capa on the Setup tab or follow the setup steps there.'),
    'C2': ('No capability results for this project yet. Run capa on the Setup tab to compare the behaviours capa '
           'recognises in the older and the newer file.'),
    'C3': 'Running capa on the {side} file ({n} of 2). This can take several minutes per file.',
    'C4': '',
    'C5': ("capa did not finish for the {side} file ({reason}). A missing result is unknown, not 'no "
           "capabilities'. No comparison is shown."),
    'C6': 'Capability results could not be assembled: {code}: {message}. Stored capa results are unchanged.',
    'C7': ('These results describe a different file pair, capa setup or analysis than the one on screen. Values '
           'are kept for reference only. Run capa again to refresh.'),
    'C8': ('Function pairs are not available for this project (no completed comparison), so changes cannot be '
           'tied to functions. Totals per side are shown without pairs.'),
    'C9': ('capa recognises the same behaviours in the matched functions of both files. This does not mean the '
           'code is the same: capa only recognises behaviours its rules describe.'),
    'C10': 'The configured capa cannot be used: {reason}.',
    'C11': 'Too many rows to display ({n}). Narrow the filter.',
    'C12': 'capa reported {m} matches; PatchTrace kept {n}. The list is incomplete.',
    'C13': ("Stored capa results predate this panel's coverage data. Refresh re-reads the saved capa output; capa "
            'is not run again.')}
FLAG_WORDS = {
    'toolchain-changed': 'the compiler or linker differs between the files', 'packed': 'a file looks packed',
    'protected': 'a file looks protected', 'heuristic-only': 'toolchain detection rests on weak signs',
    'environment-unknown': 'the toolchain of a file is unknown',
    'capa-limitation': 'capa reports a limitation for a file',
    'function-recovery-shift': 'capa recovered very different numbers of functions'}
REASON_TEXT = {'library-function': 'library function', 'function-not-recovered': 'function not found by capa',
               'evidence-truncated': 'capa output was cut'}
UNATTRIBUTED_TEXT = {
    'file-scope': 'matches the whole file', 'instruction-scope': 'matches one instruction, no function named',
    'basic-block-without-layout': 'matches a block, no function named',
    'address-rejected': 'address is outside the image', 'function-not-paired': 'function has no matched pair'}
TEACH = {
    'cap.gained': ('capa recognises this behaviour in the newer function but not in the older one. Next: open both '
                   'functions and look for the calls or constants listed under Why capa matched on the other side.'),
    'cap.lost': ('capa recognises this behaviour in the older function but not in the newer one. Next: open both '
                 'functions and look for the calls or constants listed under Why capa matched on the other side.'),
    'cap.moved': ('capa saw this behaviour in different functions in the two files. Usually code moved: a helper '
                  'was added, inlined or split. Next: open the counterpart rows and compare the calls they '
                  'contain; if the same calls appear, nothing new was added.'),
    'cap.same': ('capa recognises this behaviour in both functions. That does not mean the code is the same. '
                 'Next: compare the function text in the code panes if the pair is of interest.'),
    'cap.not_compared.library': ('capa skipped this function because it looks like a known library routine, so '
                                 'nothing can be said about it. Next: compare the function text in the code panes.'),
    'cap.not_compared.not_found': ('capa did not find this function, so nothing can be said about it. Next: '
                                   'compare the function text in the code panes.'),
    'cap.not_compared.truncated': ('capa output for this side was cut, so a missing match proves nothing. Next: '
                                   'raise the output limit or compare the function text in the code panes.'),
    'cap.detection_difference': ('the matched functions are unchanged, yet capa\'s result differs; the difference '
                                 'comes from analysis, not from new code. Next: compare the function text to '
                                 'confirm the code is the same.'),
    'cap.unattributed.file': ('capa matched this on the file as a whole, so it names no function. Next: look at '
                              'the sections and headers of both files.'),
    'cap.unattributed.instruction': ('capa matched this on a single instruction and names no function. Next: '
                                     'search both files for the instruction or the calls listed in the rule.'),
    'cap.unattributed.other': ('capa matched this but PatchTrace cannot tie it to a matched function pair. Next: '
                               'compare the matching functions by hand.'),
    'cap.new_function': ('this behaviour is recognised in a function that exists only in the newer file. Next: '
                         'open the new function and compare it with the code that calls it.'),
    'cap.removed_function': ('this behaviour was recognised in a function that exists only in the older file. '
                             'Next: look at the callers in the newer file for a replacement.')}
CAUTION_RULES = "capa's rules are written mainly for hostile software, so ordinary code can match them."
CAUTION_SAME = 'Same means recognised on both sides, not identical code.'
CAUTION_MOVED = ('The same behaviour was gained in one function and lost in another: it may have moved rather '
                 'than been added or removed.')
CAUTION_NOISE = ("The matched functions are unchanged, yet capa's result differs; the difference comes from "
                 'analysis, not from new code.')
CAUTION_LIBRARY = 'Building-block rule: capa uses it inside other rules; it is not a behaviour on its own.'
TEACH_IDS = tuple(TEACH)


def _text(value: str, limit: int = 256) -> str:
    return value if value.isprintable() and len(value) <= limit else display_text(value, limit)


def cell_text(cell: PairCell) -> str:
    if cell.state == 'present':
        return f'present, {cell.matches} match' + ('' if cell.matches == 1 else 'es')
    if cell.state == 'not-evaluated':
        return f'not evaluated: {REASON_TEXT[cell.reason]}'
    return 'absent' if cell.state == 'absent' else 'no function'


def _rvas(rvas: Sequence[int]) -> str:
    shown = ', '.join(f'0x{rva:x}' for rva in rvas[:3])
    return shown + (f' +{len(rvas) - 3}' if len(rvas) > 3 else '')


def pair_text(group: PairGroup | None, group_id: str) -> str:
    if group is None:
        return _text(group_id, 80)
    return ' '.join(part for part in (f'{group.category}:', _rvas(group.older_rvas), '->', _rvas(group.newer_rvas))
                    if part)


def namespace_prefix(namespace: str | None) -> str:
    return '/'.join((namespace or '').split('/')[:2]) or '(no namespace)'


@dataclass(frozen=True, slots=True)
class ViewRow:
    """One prebuilt table row: short strings only, so drawing a cell costs no work."""
    change: PairChange
    rule: str
    namespace: str
    older: str
    newer: str
    status: str
    pair: str
    haystack: str


@dataclass(frozen=True)
class ViewOptions:
    filter: FilterMode = 'changes'
    group_by: GroupBy = 'namespace'
    search: str = ''
    show_noise: bool = False
    show_unattributed: bool = False
    show_library: bool = False


@dataclass(frozen=True)
class ViewGroup:
    key: str
    label: str
    rows: tuple[ViewRow, ...]


@dataclass(frozen=True)
class Arrangement:
    groups: tuple[ViewGroup, ...]
    shown: int
    too_many: int | None = None
    expanded: bool = False
    unattributed: tuple[str, ...] = ()


@dataclass(frozen=True)
class RunInfo:
    """What the copy block and the detail pane say about the run (never read from the tool again)."""
    project: str = ''
    analysis_run_id: str = ''
    stale: bool = False
    older_run: ToolRun | None = None
    newer_run: ToolRun | None = None


def build_row(change: PairChange, pairs: Mapping[str, str], names: Mapping[str, str]) -> ViewRow:
    rule, namespace = _text(change.rule_id), _text(change.namespace or '')
    pair = pairs.get(change.group_id) or _text(change.group_id, 80)
    return ViewRow(change, rule, namespace, cell_text(change.older), cell_text(change.newer),
                   f'{GLYPHS[change.change]} {LABELS[change.change]}', pair,
                   f'{rule}\n{namespace}\n{names.get(change.group_id, "")}'.lower())


def rules_label(manifest: ToolManifest) -> str:
    """How the rule set is named to the analyst (also printed by `intel-tools probe`)."""
    if manifest.rules_source == 'directory' and manifest.rules_sha256:
        return f'custom folder, digest {manifest.rules_sha256[:8]}'
    if manifest.rules_source == 'embedded':
        return f'built-in rules of capa {manifest.version or "?"} (embedded)'
    return 'no rule set'


def flags_banner(delta: PairCapabilityDelta) -> str:
    words = sorted({FLAG_WORDS[flag.code] for flag in delta.flags})
    return ('Comparison may be distorted: ' + '; '.join(words) + '.') if words else ''


class CapabilityView:
    """Everything the panel shows for one `PairCapabilityDelta`; rebuilt only when the delta changes."""

    def __init__(self, delta: PairCapabilityDelta, groups: Sequence[PairGroup] = (),
                 rule_hashes: Mapping[str, str] | None = None, info: RunInfo | None = None):
        self.delta = delta
        self.info = info or RunInfo()
        self.rule_hashes = rule_hashes or {}
        by_id = {group.group_id: group for group in groups}
        self.groups = by_id
        pairs = {gid: pair_text(group, gid) for gid, group in by_id.items()}
        names = {gid: ' '.join((*group.older_names, *group.newer_names)) for gid, group in by_id.items()}
        self.rows = tuple(build_row(change, pairs, names) for change in delta.changes)

    # ---- table ------------------------------------------------------------------------------------------------
    def summary(self) -> str:
        counts, coverage = self.delta.counts, self.delta.coverage
        text = (f"{counts.get('gained', 0)} gained | {counts.get('lost', 0)} lost | {counts.get('moved', 0)} moved | "
                f"{counts.get('unchanged', 0)} unchanged | {counts.get('not-compared', 0)} not compared")
        if counts.get('detection-difference'):
            text += f" | {counts['detection-difference']} detection differences"
        if coverage is not None:
            text += (f' | capa evaluated both sides of {coverage.both_evaluated} of {coverage.matched_groups} '
                     'matched pairs')
        return text

    def _wanted(self, options: ViewOptions) -> Callable[[ViewRow], bool]:
        allowed = CHANGES_FILTER if options.filter == 'changes' else (
            None if options.filter == 'all' else frozenset({options.filter}))
        needle = options.search.strip().lower()

        def wanted(row: ViewRow) -> bool:
            change = row.change
            if change.noise == 'detection-difference' and not options.show_noise:
                return False
            if change.kind == 'library' and not options.show_library:
                return False
            if allowed is not None and change.change not in allowed:
                return False
            return not needle or needle in row.haystack
        return wanted

    def arrange(self, options: ViewOptions | None = None) -> Arrangement:
        options = options or ViewOptions()
        wanted = self._wanted(options)
        rows = [row for row in self.rows if wanted(row)]
        unattributed = self.unattributed_lines(options.search) if options.show_unattributed else ()
        if len(rows) > MAX_DISPLAY_ROWS:
            return Arrangement((), len(rows), too_many=len(rows), unattributed=unattributed)
        buckets: dict[str, list[ViewRow]] = defaultdict(list)
        labels: dict[str, str] = {}
        for row in rows:
            for key, label in self._group_keys(row, options.group_by):
                buckets[key].append(row)
                labels[key] = label
        noise_key = '~noise'
        groups = []
        for key in sorted(buckets, key=lambda k: (k == noise_key, labels[k].lower(), k)):
            ordered = sorted(buckets[key], key=lambda r: (r.namespace, r.rule, r.change.scope, r.change.group_id))
            groups.append(ViewGroup(key, labels[key], tuple(ordered)))
        return Arrangement(tuple(groups), len(rows), expanded=len(rows) <= EXPAND_LIMIT, unattributed=unattributed)

    def _group_keys(self, row: ViewRow, group_by: GroupBy) -> list[tuple[str, str]]:
        change = row.change
        if change.noise == 'detection-difference':
            return [('~noise', 'Detection differences (same code, different detection)')]
        if group_by == 'namespace':
            prefix = namespace_prefix(change.namespace)
            return [(prefix, _text(prefix))]
        if group_by == 'function-pair':
            return [(change.group_id, row.pair)]
        if group_by in ('attack', 'mbc'):
            names = sorted({label.group for label in change.labels if label.scheme == group_by})
            return [(f'{group_by}:{name}', f'Rule label (grouping only): {_text(name, 80)}') for name in names] or [
                (f'{group_by}:', f'Rule label (grouping only): none ({group_by.upper()})')]
        return [('all', 'All changes')]

    def unattributed_lines(self, search: str = '') -> tuple[str, ...]:
        needle = search.strip().lower()
        lines = []
        for item in self.delta.unattributed:
            line = (f'{_text(item.rule_id)} ({item.scope}): {self.unattributed_change(item)}, '
                    f'{UNATTRIBUTED_TEXT[item.reason]}')
            if not needle or needle in line.lower() or needle in (item.namespace or '').lower():
                lines.append(line)
        return tuple(lines)

    @staticmethod
    def unattributed_change(item: Unattributed) -> str:
        return {'gained': 'only in the newer file', 'lost': 'only in the older file',
                'unchanged': 'in both files'}[item.change]

    # ---- detail ----------------------------------------------------------------------------------------------
    def explain(self, row: ViewRow) -> tuple[str, str]:
        """(teach id, fixed text) for a row; no model, no data-dependent wording."""
        change = row.change
        if change.noise == 'detection-difference':
            key = 'cap.detection_difference'
        elif change.change == 'moved':
            key = 'cap.moved'
        elif change.change == 'not-compared':
            cell = change.older if change.older.state == 'not-evaluated' else change.newer
            key = {'library-function': 'cap.not_compared.library',
                   'evidence-truncated': 'cap.not_compared.truncated'}.get(cell.reason, 'cap.not_compared.not_found')
        elif change.change == 'gained':
            key = 'cap.new_function' if change.older.state == 'no-function' else 'cap.gained'
        elif change.change == 'lost':
            key = 'cap.removed_function' if change.newer.state == 'no-function' else 'cap.lost'
        else:
            key = 'cap.same'
        return key, TEACH[key]

    def explain_unattributed(self, item: Unattributed) -> tuple[str, str]:
        key = {'file-scope': 'cap.unattributed.file',
               'instruction-scope': 'cap.unattributed.instruction'}.get(item.reason, 'cap.unattributed.other')
        return key, TEACH[key]

    def cautions(self, row: ViewRow) -> list[str]:
        change = row.change
        lines = [CAUTION_RULES]
        if change.noise == 'detection-difference':
            lines.append(CAUTION_NOISE)
        if change.change == 'moved':
            lines.append(CAUTION_MOVED)
        if change.change == 'unchanged':
            lines.append(CAUTION_SAME)
        if change.kind == 'library':
            lines.append(CAUTION_LIBRARY)
        banner = flags_banner(self.delta)
        if banner:
            lines.append(banner)
        return lines

    def _features(self, cell: PairCell) -> list[str]:
        out = []
        for feature in cell.features[:MAX_FEATURES]:
            out.append(self._feature(feature))
        return out

    @staticmethod
    def _feature(feature: FeatureRef) -> str:
        value = redacted_display(_text(feature.value, 120), secret_kind(feature.value))
        where = f' at 0x{feature.rva:x}' if feature.rva is not None else ''
        return f'{feature.kind} {value}{where}'

    def where(self, row: ViewRow) -> str:
        change = row.change
        group = self.groups.get(change.group_id)
        names = ''
        if group is not None and (group.older_names or group.newer_names):
            names = (f' ({", ".join(group.older_names[:2]) or "-"} -> {", ".join(group.newer_names[:2]) or "-"})')
        match = f', match {_text(change.match_id, 64)}' if change.match_id else ''
        return f'{row.pair}{names}{match}'

    def detail(self, row: ViewRow) -> str:
        change = row.change
        sha = self.rule_hashes.get(change.rule_id)
        rule = f'{_text(change.namespace or "(none)")}, scope {change.scope}' + (
            f', rule sha256 {sha[:12]}' if sha else '') + (', building-block rule' if change.kind == 'library' else '')
        labels = [f'{label.scheme.upper() if label.scheme == "mbc" else "ATT&CK"}: '
                  f'{_text(label.group, 80)} / {_text(label.name, 120)} ({_text(label.ident, 32)})'
                  for label in change.labels] or ['none']
        sections = [
            ('Change', f'{row.status} ({row.rule})'), ('Where', self.where(row)),
            ('Older', f'{row.older}' + self._side_features(change.older)),
            ('Newer', f'{row.newer}' + self._side_features(change.newer)),
            ('Why capa matched', '\n'.join(self._features(change.older) + self._features(change.newer)) or 'none'),
            ('Rule', rule), ('Rule labels (grouping only)', '\n'.join(labels)),
            ('Cautions', '\n'.join(self.cautions(row))), ('Next steps', self.explain(row)[1]),
            ('Provenance', self._provenance_line())]
        text = '\n\n'.join(f'{head}\n{body}' for head, body in sections)
        return text if len(text) <= DETAIL_LIMIT else text[:DETAIL_LIMIT - 3] + '...'

    @staticmethod
    def _side_features(cell: PairCell) -> str:
        return f' ({len(cell.features)} features listed)' if cell.features else ''

    def _provenance_line(self) -> str:
        run = self.info.older_run
        if run is None:
            return 'capa run details are not available'
        manifest = run.manifest
        return (f'capa {manifest.version}, executable sha256 {(manifest.executable_sha256 or "?")[:12]}, '
                f'{rules_label(manifest)}, backend {manifest.backend or "?"}')

    # ---- copy, accessibility, navigation ---------------------------------------------------------------------
    def provenance_text(self, row: ViewRow) -> str:
        """Deterministic plain text for Ctrl+C: LF, at most 16 KiB."""
        change, info = row.change, self.info
        group = self.groups.get(change.group_id)
        sides = ''
        if group is not None:
            sides = (f'older {_rvas(group.older_rvas) or "-"} {", ".join(group.older_names[:2])} -> newer '
                     f'{_rvas(group.newer_rvas) or "-"} {", ".join(group.newer_names[:2])}')
        lines = ['PatchTrace capability change (behaviours recognised by capa rules; says nothing about defects)',
                 f'Project: {_text(info.project)}, analysis run: {_text(info.analysis_run_id)}'
                 + (', STALE' if info.stale else ''),
                 f'Pair: {_text(change.group_id, 160)}, match {_text(change.match_id or "none", 128)}, '
                 f'{change.category}' + (f', {sides}' if sides else ''),
                 f'Change: {LABELS[change.change]}, rule {row.rule}, scope {change.scope}, namespace '
                 f'{row.namespace or "(none)"}', f'Older: {row.older}', f'Newer: {row.newer}']
        older, newer = info.older_run, info.newer_run
        if older is not None and newer is not None:
            manifest = older.manifest
            options = ', '.join(f'{k}={v}' for k, v in sorted(older.options.items()))
            lines += [f'capa {manifest.version}, executable sha256 {manifest.executable_sha256}, rules '
                      f'{rules_label(manifest)} ({manifest.rules_identity()}), backend {manifest.backend}, '
                      f'options {options}',
                      f'Older run {older.run_id} artifact sha256 {older.input_artifact_hash}; newer run '
                      f'{newer.run_id} artifact sha256 {newer.input_artifact_hash}']
        lines += ['Cautions:', *(f'- {line}' for line in self.cautions(row))]
        data = ('\n'.join(lines) + '\n').encode('utf-8')
        return data.decode('utf-8', 'ignore') if len(data) <= CLIPBOARD_LIMIT else \
            data[:CLIPBOARD_LIMIT - 4].decode('utf-8', 'ignore') + '...\n'

    @staticmethod
    def accessible_text(row: ViewRow) -> str:
        change = row.change
        older, _sep, newer = f' {row.pair.split(": ", 1)[-1]} '.partition(' -> ')
        pair = f'{older.strip() or "none"} to {newer.strip() or "none"}'
        return (f'Capability {row.rule}, {LABELS[change.change].lower()}, older {row.older.replace(",", "")}, '
                f'newer {row.newer.replace(",", "")}, function pair {pair}')

    @staticmethod
    def group_accessible_text(group: ViewGroup, kind: str = 'Namespace') -> str:
        count = len(group.rows)
        return f'{kind} {group.label}, {count} change' + ('' if count == 1 else 's')

    @staticmethod
    def goto(row: ViewRow) -> tuple[str | None, str]:
        """(stored match id to open, else the text to copy): a jump only ever targets a stored match."""
        change = row.change
        return (change.match_id, row.pair) if change.match_id else (None, row.pair)


@dataclass(frozen=True)
class StateInputs:
    project_open: bool = True
    running: tuple[str, int] | None = None          # (side, n of 2)
    assembly_error: tuple[str, str] | None = None   # (code, message)
    stale: bool = False
    failed_side: tuple[str, str] | None = None      # (side, reason): one side did not finish
    tool_reason: str | None = None                  # probe said the configured capa is unusable
    tool_configured: bool = False
    has_results: bool = False
    needs_refresh: bool = False
    delta: PairCapabilityDelta | None = None
    reported_matches: int | None = None
    kept_matches: int | None = None
    too_many: int | None = None


@dataclass(frozen=True)
class ViewState:
    id: str
    text: str
    table: bool          # the rows of the comparison are shown
    banner: str = ''     # an extra line above the table (truncation)


def resolve_state(inputs: StateInputs) -> ViewState:
    """First applicable state wins; C6 over C7 over C5 over C10 over C4 (C0 and C3 are not about results)."""
    def state(sid: str, table: bool = False, banner: str = '', **fields) -> ViewState:
        return ViewState(sid, STATE_TEXT[sid].format(**fields), table, banner)
    delta = inputs.delta
    if not inputs.project_open:
        return state('C0')
    if inputs.running is not None:
        return state('C3', side=inputs.running[0], n=inputs.running[1])
    if inputs.assembly_error is not None:
        return state('C6', code=_text(inputs.assembly_error[0], 40), message=_text(inputs.assembly_error[1], 200))
    if inputs.stale and delta is not None:
        return state('C7', table=True)
    if inputs.failed_side is not None:
        return state('C5', side=inputs.failed_side[0], reason=_text(inputs.failed_side[1], 120))
    if inputs.tool_reason is not None and not inputs.has_results:
        return state('C10', reason=_text(inputs.tool_reason, 200))
    if not inputs.has_results:
        return state('C2' if inputs.tool_configured else 'C1')
    if inputs.needs_refresh or delta is None:
        return state('C13')
    if inputs.too_many is not None:
        return state('C11', n=inputs.too_many)
    if delta.pairing == 'unavailable':
        return state('C8')
    banner = STATE_TEXT['C12'].format(m=inputs.reported_matches, n=inputs.kept_matches) if (
        delta.truncated and inputs.reported_matches is not None) else ''
    counts = delta.counts
    if not banner and not any(counts.get(name) for name in ('gained', 'lost', 'moved', 'not-compared')):
        return state('C9', table=True)
    return state('C4', table=True, banner=banner)


def rule_hashes(*sides: Iterable[CapabilityEvidence]) -> dict[str, str]:
    """rule id -> rule sha256 from the capabilities of both sides (for the detail pane)."""
    found: dict[str, str] = {}
    for capabilities in sides:
        for item in capabilities:
            found.setdefault(item.rule_id, item.rule_sha256)
    return found

