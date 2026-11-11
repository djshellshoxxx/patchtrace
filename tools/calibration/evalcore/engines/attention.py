"""`attention`: the shipped lead list (enrichment change signals + `ranking.rank`, formula `attention/1`) over a Ghidriff
result the user placed (`<imports>/<pair_id>.ghidriff.json`, decompiled code included).

What is measured is the list the analyst is shown: a pairing is flagged when its score is above zero (at least one change
signal), ordered by `RankingEntry.rank` (smaller first). Pairs with equal scores are ordered by the product's own
deterministic tie-break (pairing id), so a rank inside a tie is arbitrary but is the one displayed. The pairing identity
and the implicit-unchanged upper bound are Ghidriff's, because the lead list is computed over Ghidriff's matches: this
engine adds a ranking, not a second opinion on identity. Ghidra, Java and Ghidriff are not run here.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from patchtrace.enrichment import pipeline
from patchtrace.enrichment.contracts import EnrichmentError

from ...common import strict_json
from ...tier_r import contracts as C
from .common import EngineOutput, Prediction, blocked, failed, to_rva
from .ghidriff import MAX_IMPORT_BYTES, normalized

FORMULA = 'attention/1'


def from_ranking(result: pipeline.PipelineResult, labels: C.KnownAnswerLabels) -> EngineOutput:
    if result.ranking is None:
        return failed('attention', 'the lead list could not be computed (ranking stage unavailable)')
    views = {m.pairing_id: m for m in result.views.matches}
    base = labels.older.image_base
    predictions, old_only, new_only, unaddressed = [], set(), set(), 0
    for entry in result.ranking.entries:
        match = views[entry.pairing_id]
        old, new = (match.older[0] if len(match.older) == 1 else None), (match.newer[0] if len(match.newer) == 1 else None)
        if (len(match.older), len(match.newer)) == (1, 0) and old.address is not None:
            old_only.add(to_rva(old.address, base))
        elif (len(match.older), len(match.newer)) == (0, 1) and new.address is not None:
            new_only.add(to_rva(new.address, base))
        elif old is None or new is None or old.address is None or new.address is None or len(match.older) != len(match.newer):
            unaddressed += 1
        else:
            predictions.append(Prediction(to_rva(old.address, base), to_rva(new.address, base), entry.score > 0, None,
                                          old.name, new.name, order_key=(entry.rank,)))
    return EngineOutput('attention', 'ok', version=FORMULA, predictions=tuple(predictions),
                        old_only=frozenset(old_only), new_only=frozenset(new_only), implicit_unchanged=True,
                        ignored_unaddressed=unaddressed)


class AttentionProvider:
    engine = 'attention'

    def __init__(self, imports: Path | None):
        self.imports = None if imports is None else Path(imports)

    def __call__(self, labels, symbols):
        path = None if self.imports is None else self.imports / f'{labels.pair_id}.ghidriff.json'
        if path is None or not path.is_file():
            return blocked(self.engine, f'no imported {labels.pair_id}.ghidriff.json exists in the imports folder '
                           '(the lead list is computed over a Ghidriff result with decompiled code)')
        try:
            if path.stat().st_size > MAX_IMPORT_BYTES:
                return failed(self.engine, 'ghidriff JSON exceeds 256 MiB')
            data = path.read_bytes()
            project, _, matches = normalized(strict_json(data), labels, symbols, hashlib.sha256(data).hexdigest())
            project.matches.extend(matches)
            return from_ranking(pipeline.run(project), labels)
        except (OSError, ValueError, RecursionError, EnrichmentError) as exc:
            return failed(self.engine, f'attention input rejected: {exc}')
