"""Ghidriff from raw PDiff JSON the user placed, read through the production `normalize_ghidriff`. Ghidra, Java and
Ghidriff are not run by this tool; a missing import is `blocked`."""
from __future__ import annotations

import re
from pathlib import Path

from ...common import strict_json
from ...tier_r import contracts as C
from .common import EngineOutput, Prediction, blocked, failed, to_rva

MAX_IMPORT_BYTES = 256 * 1024 * 1024

_HEX = re.compile(r'(?:0x)?([0-9a-fA-F]{1,16})$')


def _ghidra_address(text: object) -> int | None:
    if not isinstance(text, str):
        return None
    found = _HEX.search(text.strip().rsplit(':', 1)[-1])
    return int(found.group(1), 16) if found else None


def normalized(raw: dict, labels: C.KnownAnswerLabels, symbols: str, raw_sha256: str | None = None):
    """(project, run, matches): the production identity check and normalisation of one raw PDiff JSON."""
    from patchtrace.models import AnalysisRun, Artifact, ComparisonProject
    from patchtrace.normalization import normalize_ghidriff, verify_diff_identity
    older_sha, newer_sha = (s.sha256 if symbols == 'hidden' else s.debug_sha256 for s in (labels.older, labels.newer))
    run = AnalysisRun(status='completed', raw_sha256=raw_sha256)
    project = ComparisonProject(
        name=labels.pair_id, runs=[run],
        artifacts=[Artifact(side='older', name=labels.older.file_name, sha256=older_sha, size=max(labels.older.size, 1),
                            relative_path='older/image'),
                   Artifact(side='newer', name=labels.newer.file_name, sha256=newer_sha, size=max(labels.newer.size, 1),
                            relative_path='newer/image')])
    verify_diff_identity(raw, project)
    return project, run, normalize_ghidriff(raw, project, run.id)


def from_ghidriff(raw: dict, labels: C.KnownAnswerLabels, symbols: str) -> EngineOutput:
    """Raw Ghidriff PDiff JSON -> output, through the production `verify_diff_identity` + `normalize_ghidriff`."""
    _, _, matches = normalized(raw, labels, symbols)
    base = labels.older.image_base
    predictions, old_only, new_only, unaddressed = [], set(), set(), 0
    for match in matches:
        old = match.older[0] if match.older else None
        new = match.newer[0] if match.newer else None
        old_addr = _ghidra_address(old.address) if old else None
        new_addr = _ghidra_address(new.address) if new else None
        if match.category == 'removed':
            if old_addr is None:
                unaddressed += 1
            else:
                old_only.add(to_rva(old_addr, base))
        elif match.category == 'added':
            if new_addr is None:
                unaddressed += 1
            else:
                new_only.add(to_rva(new_addr, base))
        elif old_addr is None or new_addr is None:
            unaddressed += 1
        else:
            ratio = (old.metadata or {}).get('upstream_similarity')
            milli = round(ratio * 1000) if isinstance(ratio, int | float) and not isinstance(ratio, bool) else None
            predictions.append(Prediction(to_rva(old_addr, base), to_rva(new_addr, base), True, milli,
                                          old.metadata.get('upstream_name'), new.metadata.get('upstream_name')))
    return EngineOutput('ghidriff', 'ok', version=raw.get('program_options', {}).get('version')
                        if isinstance(raw.get('program_options'), dict)
                        and isinstance(raw['program_options'].get('version'), str) else None,
                        predictions=tuple(predictions), old_only=frozenset(old_only), new_only=frozenset(new_only),
                        implicit_unchanged=True, ignored_unaddressed=unaddressed)


class GhidriffImportProvider:
    """`<imports>/<pair_id>.ghidriff.json` (raw PDiff JSON) placed by the user, read by `normalize_ghidriff`."""
    engine = 'ghidriff'

    def __init__(self, imports: Path | None):
        self.imports = None if imports is None else Path(imports)

    def __call__(self, labels, symbols):
        path = None if self.imports is None else self.imports / f'{labels.pair_id}.ghidriff.json'
        if path is None or not path.is_file():
            return blocked(self.engine, f'no imported {labels.pair_id}.ghidriff.json exists in the imports folder '
                           '(Ghidra/Java/Ghidriff are not run by this tool)')
        try:
            if path.stat().st_size > MAX_IMPORT_BYTES:
                return failed(self.engine, 'ghidriff JSON exceeds 256 MiB')
            raw = strict_json(path.read_bytes())
            return from_ghidriff(raw, labels, symbols)
        except (OSError, ValueError, RecursionError) as exc:
            return failed(self.engine, f'ghidriff import rejected: {exc}')
