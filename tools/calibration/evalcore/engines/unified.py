"""`unified`: the unified engine's own `unified-match/1` rows mapped to evalcore predictions (LBL s7.1).

Reported as its own engine, never pooled with another. Identity: `matched` and `tentative` rows with one function per side
are paired; `candidate`, `contested`, `ambiguous` and `unknown` rows abstain (counted in `ignored_unaddressed`, never
scored as wrong); `older-only` and `newer-only` rows are unpaired. Flag: `material` and `review` flag, `unchanged` and
`cosmetic` do not, and `unknown` or `not-applicable` abstains, because unknown is not a negative vote. A paired row whose
flag abstains is therefore left out of the predictions (the scorer cannot represent "paired, no opinion on change"; see
the gap noted in docs/modules.md). The lead list is ordered by materiality, then by more change classes, then by RVA.
Unified rows carry RVAs already, so no image base is subtracted.
"""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from patchtrace.unified import store
from patchtrace.unified.contracts import UnifiedMatch
from patchtrace.unified.limits import UnifiedError

from .common import EngineOutput, Prediction, blocked, failed

FORMAT = 'unified-match/1'
PAIRED = frozenset({'matched', 'tentative'})
FLAGGED = {'material': 0, 'review': 1}
NOT_FLAGGED = frozenset({'unchanged', 'cosmetic'})


def _prediction(row: UnifiedMatch) -> Prediction | None:
    """None when the row abstains on the change flag."""
    if row.materiality not in FLAGGED and row.materiality not in NOT_FLAGGED:
        return None
    old, new = row.older[0], row.newer[0]
    key = (FLAGGED.get(row.materiality, 2), -len(row.change_classes), old.rva)
    return Prediction(old.rva, new.rva, row.materiality in FLAGGED, None, old.name, new.name, order_key=key)


def from_rows(rows: Iterable[UnifiedMatch], version: str = FORMAT) -> EngineOutput:
    predictions, old_only, new_only, unaddressed = [], set(), set(), 0
    for row in rows:
        if row.decision == 'older-only' and len(row.older) == 1:
            old_only.add(row.older[0].rva)
        elif row.decision == 'newer-only' and len(row.newer) == 1:
            new_only.add(row.newer[0].rva)
        elif row.decision in PAIRED and len(row.older) == len(row.newer) == 1 and (p := _prediction(row)):
            predictions.append(p)
        else:
            unaddressed += 1
    return EngineOutput('unified', 'ok', version=version, predictions=tuple(predictions), old_only=frozenset(old_only),
                        new_only=frozenset(new_only), ignored_unaddressed=unaddressed)


def read_rows_file(path: Path) -> list[UnifiedMatch]:
    """A plain LF-framed `unified-match/1` JSON-lines file (the known-answer fixtures; no gzip, no row-id check)."""
    return [store.parse_line(line + b'\n', UnifiedMatch) for line in Path(path).read_bytes().split(b'\n') if line]


class UnifiedProvider:
    """Reads `<results>/<pair_id>/` (a published result directory) or `<results>/<pair_id>.unified.jsonl`; a pair with
    neither is blocked, not absent, so the run reports `unified` as waiting for the engine."""
    engine = 'unified'

    def __init__(self, results: Path | None):
        self.results = None if results is None else Path(results)

    def __call__(self, labels, symbols):
        if self.results is None:
            return blocked(self.engine, 'no unified results folder was given')
        folder, flat = self.results / labels.pair_id, self.results / f'{labels.pair_id}.unified.jsonl'
        try:
            if folder.is_dir():
                manifest, _ = store.read_manifest(folder)
                if (manifest.older_sha256, manifest.newer_sha256) != (labels.older.sha256, labels.newer.sha256):
                    return failed(self.engine, f'the unified result in {folder.name} is for a different image pair')
                return from_rows(store.read_rows(folder, manifest), manifest.contract)
            if flat.is_file():
                return from_rows(read_rows_file(flat))
        except (UnifiedError, ValueError, OSError) as exc:
            return failed(self.engine, f'the unified result could not be read: {exc}')
        return blocked(self.engine, f'no unified result for {labels.pair_id} exists in the results folder')
