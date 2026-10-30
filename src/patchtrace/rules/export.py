"""Saving an accepted rule as a local `.yar` file (YRX-integration-plan sections 7 and 8, "Export header").

Export is its own action, separate from accepting: accepting stores a version in the project and writes no file; exporting
reads a stored version and writes one file the analyst names. Nothing is uploaded and nothing is overwritten.

Hard checks refuse the export (`PT-RULE-GATE`): the stored rule must separate its pair, compile and hold no secret-looking
string (the strings are checked again here, from the text that would be written). Informational findings (never tested, the
grid is incomplete, it has unexpected results, the engine moved since) do not refuse, but they are returned as warnings and
the caller must say it accepts them. The header carries no path and no user name; function names only when asked for.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from pydantic import TypeAdapter, ValidationError

from .. import __version__
from ..enrichment.identity import domain_id
from ..intelligence.tools.common import secret_kind
from . import synth
from .contracts import (
    DECODER_PIN,
    ENGINE_PIN,
    ExportRecord,
    MatrixRun,
    RuleCandidate,
    RuleDecision,
    RuleVersion,
)
from .errors import RuleError
from .matrix import totals
from .store import accepted_text

MARKER = 'patchtrace-rule-export/1'
HARD_GATES = ('sep', 'compile', 'secret')
ORIGIN = ('Origin: byte patterns copied from the analysed files on the analyst\'s computer. If those files are third-party '
          'software, check its licence before sharing this rule or committing it to a repository.')
_STRING_LINE = re.compile(r'(?m)^\s*\$s[0-9]+ = "(.*)"')
_CHANGE = {'modified': 'modified function at older RVA {older} and newer RVA {newer}',
           'removed': 'removed function at older RVA {older}', 'added': 'added function at newer RVA {newer}'}


@dataclass(frozen=True)
class ExportPlan:
    text: str
    warnings: tuple[str, ...]
    rule_name: str


def tested_run(version: RuleVersion, runs: list[MatrixRun]) -> MatrixRun | None:
    """The newest finished grid (complete or partial) that holds exactly this version of the rule."""
    for run in runs:   # newest first
        if run.status in ('complete', 'partial') and any(
                (r.version_id, r.rule_sha256) == (version.version_id, version.rule_sha256) for r in run.rules):
            return run
    return None


def check_hard_gates(candidate: RuleCandidate | None, text: str) -> None:
    if candidate is None:
        raise RuleError('PT-RULE-INTEGRITY', 'The candidate of this rule version is not stored', reason='candidate-missing')
    states = {gate.gate_id: gate.state for gate in candidate.gates}
    failed = [gate_id for gate_id in HARD_GATES if states.get(gate_id) not in ('pass', 'waived')]
    if failed:
        raise RuleError('PT-RULE-GATE', f'The rule does not pass the required checks: {", ".join(failed)}',
                        reason='hard-gate')
    for literal in _STRING_LINE.findall(text):
        if secret_kind(synth.unescape(literal).decode('latin-1')):
            raise RuleError('PT-RULE-GATE', 'The rule holds a secret-looking string', reason='secret')


def _tested_line(version: RuleVersion, run: MatrixRun | None) -> str:
    if run is None:
        return 'Not tested'
    column = next(i for i, r in enumerate(run.rules) if r.version_id == version.version_id)
    count = totals(run, column)
    return (f'Tested {run.finished_at}: {count.builds} builds, {count.clean} clean files, '
            f'{count.unexpected_hit} unexpected matches, {count.not_scanned} not scanned')


def warnings_for(version: RuleVersion, run: MatrixRun | None, engine_version: str | None) -> tuple[str, ...]:
    if run is None:
        return ('not-tested',)
    column = next(i for i, r in enumerate(run.rules) if r.version_id == version.version_id)
    count = totals(run, column)
    found = []
    if count.not_scanned:
        found.append('not-scanned')
    if count.unexpected_hit or count.unexpected_miss:
        found.append('unexpected-results')
    if engine_version is not None and run.engine.version != engine_version:
        found.append('grid-stale')
    return tuple(found)


def _change_line(version: RuleVersion, candidate: RuleCandidate, include_names: bool) -> str:
    source = version.source
    where = {name: f'0x{ref.rva:x}' for name, ref in (('older', source.older), ('newer', source.newer)) if ref}
    review = 'reviewed as material' if not candidate.unvetted else 'not reviewed as material, confirmed by the analyst'
    names = 'function names included' if include_names else 'function names omitted'
    return f'Source change: {_CHANGE[source.category].format(**where)}, {review}; {names}'


def header_lines(version: RuleVersion, decision: RuleDecision, candidate: RuleCandidate, run: MatrixRun | None, *,
                 include_names: bool, basenames: Mapping[str, str]) -> list[str]:
    source, engine = version.source, version.engine
    decoder = '' if engine.decoder == 'none' else f' and {engine.decoder} {engine.decoder_version or DECODER_PIN}'
    named = {side: f'{basenames[side]} ' if side in basenames else '' for side in ('older', 'newer')}
    lines = [
        MARKER,
        f'Rule {candidate.rule_name} version {version.version}, label "{decision.analyst_label}"',
        f'Built by PatchTrace {__version__} with YARA-X {engine.version or ENGINE_PIN} (BSD-3-Clause){decoder}',
        f'Project {source.project_id}, analysis run {source.run_id}',
        f'Older build {named["older"]}sha256 {source.older_sha256}; newer build {named["newer"]}sha256 {source.newer_sha256}',
        _change_line(version, candidate, include_names),
        f'Accepted {version.created_at}. {_tested_line(version, run)}']
    advisories = [*decision.cve, *decision.kb, *decision.cwe]
    if advisories:
        lines.append('Advisory anchors given by the analyst and not checked by this rule: ' + ' '.join(advisories))
    lines += [ORIGIN, synth.STATEMENT]
    return lines


def build(version: RuleVersion, decision: RuleDecision, candidate: RuleCandidate | None, runs: list[MatrixRun], *,
          include_names: bool = False, basenames: Mapping[str, str] | None = None, engine_version: str | None = None
          ) -> ExportPlan:
    """The text of the file and the informational warnings; raises `PT-RULE-GATE` or `PT-RULE-INTEGRITY` when a hard check
    fails. With `include_names` the rule is written again with the function names the pair carries (they may come from
    symbol files), so its text differs from the stored version in exactly those meta lines."""
    if decision.decision_id != version.decision_id or decision.action != 'accept':
        raise RuleError('PT-RULE-INTEGRITY', 'The decision does not belong to this version', reason='decision-mismatch')
    text = version.rule_text
    if include_names and candidate is not None:
        text = accepted_text(candidate, decision, version.version, include_names=True)
    check_hard_gates(candidate, text)
    run = tested_run(version, runs)
    lines = header_lines(version, decision, candidate, run, include_names=include_names, basenames=basenames or {})
    return ExportPlan(synth.with_header(text, lines), warnings_for(version, run, engine_version), candidate.rule_name)


# --- the file --------------------------------------------------------------------------------------------------------

def _in_git_tree(folder: Path) -> bool:
    return any((parent / '.git').exists() for parent in (folder, *folder.parents))


_BASENAME = TypeAdapter(Annotated[str, *ExportRecord.model_fields['basename'].metadata])


def write(plan: ExportPlan, version: RuleVersion, out: Path, *, allow_git_tree: bool = False,
          now: datetime | None = None) -> ExportRecord:
    """Creates `out` (never replaces a file), LF line ends, and returns the record to store: the basename and the hash."""
    if out.suffix != '.yar':
        raise RuleError('PT-RULE-EXPORT', 'The file name must end in .yar', reason='suffix')
    try:    # the record must hold the name; check before the file exists, never after (#105 BUG-RULE-3)
        _BASENAME.validate_python(out.name)
    except ValidationError:
        raise RuleError('PT-RULE-EXPORT', 'The file name is too long or not plain text (at most 128 characters)',
                        reason='name') from None
    folder = out.resolve().parent
    if not folder.is_dir():
        raise RuleError('PT-RULE-EXPORT', 'The folder of the file does not exist', reason='no-folder')
    if _in_git_tree(folder) and not allow_git_tree:
        raise RuleError('PT-RULE-EXPORT', 'The file would be inside a Git working tree; confirm that you want that',
                        reason='git-tree')
    data = plan.text.encode('ascii')
    try:
        with open(out, 'x', encoding='ascii', newline='\n') as handle:
            handle.write(plan.text)
    except FileExistsError:
        raise RuleError('PT-RULE-EXPORT', 'The file already exists; PatchTrace does not replace files',
                        reason='exists') from None
    except OSError:
        out.unlink(missing_ok=True)   # 'x' made it, so it is ours and holds at most a part of the text
        raise RuleError('PT-RULE-EXPORT', 'The file could not be written', reason='write-failed') from None
    stamp = (now or datetime.now(UTC)).isoformat(timespec='seconds')
    digest = hashlib.sha256(data).hexdigest()
    return ExportRecord(export_id=domain_id('rule-export', 1, {'version_id': version.version_id, 'sha256': digest,
                                                               'exported_at': stamp}),
                        version_id=version.version_id, basename=out.name, sha256=digest, exported_at=stamp,
                        warnings=tuple(sorted(plan.warnings)))
