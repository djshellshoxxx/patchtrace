"""Export of an accepted rule version as a `.yar` text file (plan s7, s8). Pure apart from the one file it writes.

Accepting and exporting are separate actions: nothing is exported by accepting. The header holds no local paths and no
user names; function names appear only when the analyst opts in. A hard check that has not passed (separation,
compile, secrets) refuses the export; informational findings need an explicit acknowledgement and are recorded.
"""
from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ..enrichment.identity import domain_id
from . import gates as gate_checks
from .contracts import (
    EXPORT_MARKER,
    ExportRecord,
    MatrixRun,
    RuleCandidate,
    RuleDecision,
    RuleVersion,
    text_sha256,
)
from .errors import RulesError
from .matrix import GridSummary, summarize
from .store import Clock, RuleStore, atomic_write, utc_now
from .synth import parse_rule

HARD_GATES = ('sep', 'compile', 'secret')
_BASENAME = re.compile(r'[A-Za-z0-9_.-]{1,128}')
_UNSAFE = re.compile(r'[^A-Za-z0-9 _.,:;@#%+=()\[\]{}!~/-]')
YARA_X_LICENSE = 'BSD-3-Clause'
ORIGIN = ('Origin: byte patterns copied from the analysed files on the analyst\'s computer. If those files are '
          'third-party software, check its licence before sharing this rule or committing it to a repository.')
MEANING = 'A match means a file contains this pattern. It does not show whether the file is affected by a flaw.'


def ascii_text(value: str, limit: int = 120) -> str:
    """Header-safe text: printable ASCII only, quotes and slashes folded away, so a value cannot end its comment."""
    return _UNSAFE.sub('?', value.replace('"', "'").replace('//', '/ /'))[:limit]


@dataclass(frozen=True)
class Checklist:
    hard: tuple[str, ...]       # block the export
    warnings: tuple[str, ...]   # need "Export with these warnings"


def checklist(version: RuleVersion, candidate: RuleCandidate, run: MatrixRun | None,
              current_engine: str | None) -> Checklist:
    state = {g.gate_id: g.state for g in candidate.gates}
    hard = [f'{gate} is {state.get(gate, "unknown")}' for gate in HARD_GATES if state.get(gate) != 'pass']
    hard += [f'{gate} failed' for gate in gate_checks.refused(candidate.gates) if gate not in HARD_GATES]
    warnings: list[str] = []
    if candidate.unvetted:
        warnings.append('the change was not reviewed as material; the analyst confirmed it')
    if state.get('dist') == 'unknown':
        warnings.append('the two builds may differ in toolchain')
    if run is None:
        warnings.append('not tested on any build or clean file')
    else:
        summary = summarize(run, candidate.rule_name)
        if summary.clean == 0:
            warnings.append('not checked on clean files')
        if summary.unexpected_hits or summary.unexpected_misses:
            warnings.append(f'{summary.unexpected_hits} unexpected matches and {summary.unexpected_misses} '
                            'unexpected misses in the test grid')
        if summary.not_scanned:
            warnings.append(f'{summary.not_scanned} files were not scanned')
        if current_engine is not None and summary.engine_version != current_engine:
            warnings.append('the test grid is stale: the YARA-X version changed')
    return Checklist(tuple(hard), tuple(warnings))


def _change_line(candidate: RuleCandidate, names: bool) -> str:
    source = candidate.source
    where = [f'{side} RVA {ref.rva:#x}' for side, ref in (('older', source.older), ('newer', source.newer))
             if ref is not None]
    review = 'reviewed as material' if source.materiality == 'material' else 'confirmed as material by the analyst'
    return (f'Source change: {source.category} function at {" and ".join(where)}, {review}; '
            f'function names {"included" if names else "omitted"}')


def _tested_line(accepted: str, tested: tuple[MatrixRun, str] | None, rule_name: str) -> str:
    if tested is None:
        return f'Accepted {accepted}. Not tested'
    run, at = tested
    s: GridSummary = summarize(run, rule_name)
    return (f'Accepted {accepted}. Tested {at}: {s.builds} builds, {s.clean} clean files, '
            f'{s.unexpected_hits} unexpected matches, {s.not_scanned} not scanned')


def header(version: RuleVersion, candidate: RuleCandidate, decision: RuleDecision | None,
           tested: tuple[MatrixRun, str] | None, *, product_version: str, older_name: str, newer_name: str,
           include_names: bool) -> str:
    source, engine = version.source, version.engine
    decoder = f' and {engine.decoder} {engine.decoder_version}' if engine.decoder_version != 'none' else ''
    lines = [
        EXPORT_MARKER,
        f'Rule {candidate.rule_name} version {version.version}, label "{ascii_text(decision.analyst_label if decision else "")}"',
        f'Built by PatchTrace {ascii_text(product_version, 32)} with YARA-X {ascii_text(engine.version, 32)} '
        f'({YARA_X_LICENSE}){decoder}',
        f'Project {ascii_text(source.project_id, 128)}, analysis run {ascii_text(source.run_id, 128)}',
        f'Older build {ascii_text(older_name, 128)} sha256 {source.older_sha256}; '
        f'newer build {ascii_text(newer_name, 128)} sha256 {source.newer_sha256}',
        _change_line(candidate, include_names),
        _tested_line(version.created_at, tested, candidate.rule_name)]
    anchors = sorted({*(decision.cve if decision else ()), *(decision.kb if decision else ()),
                      *(decision.cwe if decision else ()), *source.cwe})
    if anchors:
        lines.append('Advisory anchors given by the analyst and not checked by this rule: ' + ' '.join(anchors))
    lines += [ORIGIN, MEANING]
    return ''.join(f'// {line}\n' for line in lines)


def _inside_git_tree(directory: Path) -> bool:
    return any((parent / '.git').exists() for parent in (directory, *directory.parents))


def check_destination(out: Path, *, allow_git_tree: bool) -> Path:
    path = Path(out)
    if path.suffix != '.yar' or not _BASENAME.fullmatch(path.name):
        raise RulesError('PT-RULE-EXPORT', 'The export file must be named like rule.yar (letters, digits, _ . -).')
    parent = path.parent.resolve()
    if not parent.is_dir():
        raise RulesError('PT-RULE-EXPORT', 'The export folder does not exist.')
    if (parent / path.name).exists():
        raise RulesError('PT-RULE-EXPORT', 'The export file already exists; choose a new name.')
    if _inside_git_tree(parent) and not allow_git_tree:
        raise RulesError('PT-RULE-EXPORT', 'The export folder is inside a Git working tree; the rule contains byte '
                         'patterns copied from the analysed files. Confirm with the Git tree option to save it there.')
    return parent / path.name


def render(store: RuleStore, version: RuleVersion, *, product_version: str, older_name: str, newer_name: str,
           include_names: bool) -> str:
    """Header plus rule text, with the rule body re-parsed so no header or name option can change the grammar."""
    candidate = store.candidate_for(version)
    if candidate is None:
        raise RulesError('PT-RULE-INTEGRITY', 'The candidate of this rule version is missing from the project.')
    decision = store.decision_of(version)
    body = store.resynthesize(version, candidate, decision, include_names=include_names)
    if EXPORT_MARKER in body or parse_rule(body).name != candidate.rule_name:
        raise RulesError('PT-RULE-INTEGRITY', 'The rule text failed its strict re-parse.')
    head = header(version, candidate, decision, store.latest_test(version.version_id), product_version=product_version,
                  older_name=older_name, newer_name=newer_name, include_names=include_names)
    return head + '\n' + body


def export_rule(store: RuleStore, version: RuleVersion, out: Path, *, product_version: str, older_name: str,
                newer_name: str, include_names: bool = False, allow_git_tree: bool = False,
                with_warnings: bool = False, current_engine: str | None = None,
                now: Clock = utc_now) -> tuple[ExportRecord, Sequence[str]]:
    """Check, render and write one `.yar` file; returns the stored export record and the acknowledged warnings."""
    candidate = store.candidate_for(version)
    if candidate is None:
        raise RulesError('PT-RULE-INTEGRITY', 'The candidate of this rule version is missing from the project.')
    tested = store.latest_test(version.version_id)
    found = checklist(version, candidate, tested[0] if tested else None, current_engine)
    if found.hard:
        raise RulesError('PT-RULE-GATE', 'Export refused: ' + '; '.join(found.hard))
    if found.warnings and not with_warnings:
        raise RulesError('PT-RULE-GATE', 'Export needs confirmation: ' + '; '.join(found.warnings))
    destination = check_destination(out, allow_git_tree=allow_git_tree)
    text = render(store, version, product_version=product_version, older_name=older_name, newer_name=newer_name,
                  include_names=include_names)
    data = text.encode('utf-8')
    try:
        atomic_write(destination, data)
    except OSError:
        raise RulesError('PT-RULE-EXPORT', 'The export file could not be written.') from None
    stamp = now()
    record = ExportRecord(
        export_id=domain_id('rule-export', 1, {'version': version.version_id, 'sha256': text_sha256(text),
                                               'at': stamp}),
        version_id=version.version_id, basename=destination.name, sha256=text_sha256(text), exported_at=stamp,
        warnings=tuple(w[:512] for w in found.warnings))
    store.add_export(record, version)
    return record, found.warnings
