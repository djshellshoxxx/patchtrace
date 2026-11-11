"""SPEC-32 s11: known-answer labels (+ optional engine candidates) -> hash-chained annotation log -> `calibration-labels/1`.

Every candidate pair (a truth `same` pair or a pair an engine proposed) gets one `blind` event by the synthetic annotator
`known-answer/<label_source>` with guideline `ka-1`; `label.consolidate` then yields records with `source` =
`synthetic-exact`. Answers come from the construction, never from a human or an LLM:
`same` = the pair is a truth pair; `no-counterpart` = a touched function has none; `different` = both functions are
labelled but not each other's counterpart; `indeterminate` = a touched function is ambiguous. Candidates with an unlabelled
side (runtime functions) are skipped and counted. The log is written in bulk with the exact chain format of
`label.AnnotationLog` (seq, prev_sha256, sha256), so `AnnotationLog.events()` verifies it. Timestamps are the fixed
placeholder below: the log is byte-reproducible.
"""
from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..common import canonical_json
from ..contracts import LabelRecord
from ..label import GENESIS, AnnotationLog, consolidate
from . import contracts as C
from .evaluate import EngineOutput
from .pe import read_pe

GUIDELINE = 'ka-1'
TS = '1970-01-01T00:00:00Z'
NATURAL_STRATA = frozenset({'release', 'cve', 'control'})   # LBL s2: every engine candidate of these pairs is natural
BodyReader = Callable[[str, int, int], bytes]       # (image sha256, rva, size) -> code bytes


@dataclass(frozen=True)
class Candidate:
    pair: str
    match_id: str
    old_rva: int
    new_rva: int
    answer: str
    subtype: str | None
    sampling: dict
    engines: tuple[str, ...]


def match_id(old_rva: int, new_rva: int) -> str:
    return f'{old_rva:x}:{new_rva:x}'


def _ambiguous(f: C.FunctionLabel) -> bool:
    return f.label == 'ambiguous' or f.identity == 'ambiguous'


def sampling_of(labels: C.KnownAnswerLabels, engines: Sequence[str]) -> dict:
    """Natural = an engine candidate (right or wrong) of a release, CVE or control pair. Mutation, noise, A/A and
    suite candidates are adversarial. A truth pair that no engine proposed is not a candidate of any engine, so it
    can never be natural: a natural stratum of truth pairs only would contain no negative at all."""
    if not engines:
        return {'stratum': 'adversarial', 'stage': 'known-answer-truth', 'p_incl': 1.0}
    stratum = 'natural' if labels.stratum in NATURAL_STRATA else 'adversarial'
    return {'stratum': stratum, 'stage': 'engine-candidate', 'p_incl': 1.0}


def candidates(labels: C.KnownAnswerLabels, outputs: Mapping[str, EngineOutput] | None = None
               ) -> tuple[list[Candidate], dict[str, int]]:
    """Truth pairs plus every engine-proposed pair, each with its constructed answer. Returns (candidates, skipped)."""
    by_old = {f.old_rva: f for f in labels.functions if f.old_rva is not None}
    by_new = {f.new_rva: f for f in labels.functions if f.new_rva is not None}
    proposed: dict[tuple[int, int], set[str]] = {}
    for engine, out in sorted((outputs or {}).items()):
        if out.status == 'ok':
            for p in out.predictions:
                proposed.setdefault((p.old_rva, p.new_rva), set()).add(engine)
    truth = {(f.old_rva, f.new_rva): f for f in labels.functions if f.identity == 'same' and not _ambiguous(f)}
    skipped = Counter()
    found = []
    for key in sorted(set(truth) | set(proposed)):
        ro, rn = by_old.get(key[0]), by_new.get(key[1])
        if ro is None or rn is None:
            skipped['unlabelled-side'] += 1
            continue
        if key in truth:
            answer, subtype = 'same', (truth[key].taxonomy[0] if truth[key].taxonomy else None)
        elif _ambiguous(ro) or _ambiguous(rn):
            answer, subtype = 'indeterminate', None
        elif ro.identity == 'no-counterpart' or rn.identity == 'no-counterpart':
            answer, subtype = 'no-counterpart', None
        else:
            answer, subtype = 'different', None
        engines = tuple(sorted(proposed.get(key, ())))
        found.append(Candidate(labels.pair_id, match_id(*key), key[0], key[1], answer, subtype,
                               sampling_of(labels, engines), engines))
    return found, dict(skipped)


def annotator_name(labels: C.KnownAnswerLabels) -> str:
    return f'known-answer/{labels.label_source}'


def append_events(log: AnnotationLog, events: Iterable[dict]) -> int:
    """Bulk append continuing the existing chain (one verification pass instead of one per event)."""
    existing = log.events()
    prev = existing[-1]['sha256'] if existing else GENESIS
    seq = len(existing)
    lines = []
    for fields in events:
        seq += 1
        event = dict(fields, seq=seq, prev_sha256=prev)
        event['sha256'] = prev = hashlib.sha256(canonical_json(event)).hexdigest()
        lines.append(canonical_json(event) + b'\n')
    if lines:
        log.path.parent.mkdir(parents=True, exist_ok=True)
        with open(log.path, 'ab') as handle:
            handle.write(b''.join(lines))
    return len(lines)


def write_log(docs: Sequence[C.KnownAnswerLabels], log: AnnotationLog, *,
              outputs: Mapping[str, Mapping[str, EngineOutput]] | None = None) -> dict:
    """Append one blind event per not-yet-logged candidate. `outputs[pair_id][engine]` are optional engine candidates."""
    done = {(e['pair'], e['match_id'], e['annotator']) for e in log.events()}
    new_events, skipped, total = [], Counter(), 0
    for labels in sorted(docs, key=lambda d: d.pair_id):
        found, skip = candidates(labels, (outputs or {}).get(labels.pair_id))
        skipped.update(skip)
        for c in found:
            total += 1
            if (c.pair, c.match_id, annotator_name(labels)) in done:
                continue
            new_events.append({'pair': c.pair, 'match_id': c.match_id, 'annotator': annotator_name(labels),
                               'phase': 'blind', 'A': c.answer, 'subtype': c.subtype, 'guideline': GUIDELINE,
                               'ts': TS, 'time_spent_s': 0})
    return {'appended': append_events(log, new_events), 'candidates': total, 'skipped': dict(skipped)}


class StoreBodyReader:
    """Reads code bytes from `<store>/images/<sha>/<file>` of the stripped engine image (parsed once per image).
    `names` (image sha256 -> file name) is filled by `consolidate_labels` from the label documents."""

    def __init__(self, store: Path):
        self.store, self.names, self._images = Path(store), {}, {}

    def __call__(self, sha: str, rva: int, size: int) -> bytes:
        if sha not in self._images:
            self._images[sha] = read_pe(self.store / 'images' / sha / self.names[sha])
        return self._images[sha].read(rva, size)


def consolidate_labels(docs: Sequence[C.KnownAnswerLabels], log: AnnotationLog, read_body: BodyReader,
                       *, outputs: Mapping[str, Mapping[str, EngineOutput]] | None = None) -> tuple[list[dict], dict]:
    """`calibration-labels/1` records (validated, sorted) for the logged candidates; stats from `label.consolidate`."""
    meta: dict[tuple[str, str], dict] = {}
    for labels in docs:
        by_old = {f.old_rva: f for f in labels.functions if f.old_rva is not None}
        by_new = {f.new_rva: f for f in labels.functions if f.new_rva is not None}
        names = getattr(read_body, 'names', None)
        if names is not None:
            names[labels.older.sha256], names[labels.newer.sha256] = labels.older.file_name, labels.newer.file_name
        found, _ = candidates(labels, (outputs or {}).get(labels.pair_id))
        for c in found:
            fo, fn = by_old[c.old_rva], by_new[c.new_rva]
            meta[(c.pair, c.match_id)] = {
                'older': {'rva': c.old_rva, 'size': fo.old_size, 'body_sha256': hashlib.sha256(
                    read_body(labels.older.sha256, c.old_rva, fo.old_size)).hexdigest()},
                'newer': {'rva': c.new_rva, 'size': fn.new_size, 'body_sha256': hashlib.sha256(
                    read_body(labels.newer.sha256, c.new_rva, fn.new_size)).hexdigest()},
                'source': 'synthetic-exact', 'sampling': c.sampling}
    records, stats = consolidate(log.events(), meta)
    out = [LabelRecord.model_validate_json(canonical_json(r)).model_dump(mode='json') for r in records]
    return sorted(out, key=lambda r: (r['pair'], r['match_id'])), {'pending': len(stats['pending']),
                                                                    'reveal_changes': stats['reveal_changes']}


def dump_jsonl(records: Sequence[dict]) -> bytes:
    return b''.join(canonical_json(r) + b'\n' for r in records)
