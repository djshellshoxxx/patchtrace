"""Blind labelling workflow (spec §5.2, §5.5): append-only, hash-chained JSONL annotation log + terminal mode.

Annotators never see engine scores, verdicts, match types or (in the blind pass) symbol names. No LLM output
is ever stored as a label. A local HTML/127.0.0.1 server front-end is a later slice; terminal mode is complete.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path

from .common import canonical_json

GENESIS = '0' * 64
ANSWERS = {'s': 'same', 'd': 'different', 'n': 'no-counterpart', 'i': 'indeterminate'}
# Keys hidden from annotators (anchoring/blinding). Matched case-insensitively at any depth.
BLIND_DENY = frozenset({'ratio', 'similarity', 'similarity_milli', 'confidence', 'confidence_milli', 'quality',
                        'match_types', 'verdict', 'tier', 'evidence_index', 'status', 'algorithm', 'flags',
                        'score', 'p', 'name', 'fullname', 'older_name', 'newer_name', 'upstream_name',
                        'symbol', 'symbols'})


class ChainError(ValueError):
    pass


def blind_view(item, reveal_names: bool = False):
    deny = BLIND_DENY - ({'name', 'fullname', 'older_name', 'newer_name', 'upstream_name', 'symbol', 'symbols'}
                         if reveal_names else set())
    if isinstance(item, Mapping):
        return {k: blind_view(v, reveal_names) for k, v in item.items() if str(k).lower() not in deny}
    if isinstance(item, list | tuple):
        return [blind_view(v, reveal_names) for v in item]
    return item


class AnnotationLog:
    """Append-only; every line carries seq, prev_sha256 and its own sha256 over the canonical event."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def events(self) -> list[dict]:
        if not self.path.exists():
            return []
        out, prev = [], GENESIS
        for number, line in enumerate(self.path.read_bytes().splitlines(), 1):
            event = json.loads(line)
            claimed = event.pop('sha256', None)
            if event.get('seq') != number or event.get('prev_sha256') != prev:
                raise ChainError(f'line {number}: sequence or chain broken')
            if hashlib.sha256(canonical_json(event)).hexdigest() != claimed:
                raise ChainError(f'line {number}: content was edited')
            event['sha256'] = claimed
            out.append(event)
            prev = claimed
        return out

    def append(self, **fields) -> dict:
        existing = self.events()
        event = dict(fields)
        event['seq'] = len(existing) + 1
        event['prev_sha256'] = existing[-1]['sha256'] if existing else GENESIS
        event['sha256'] = hashlib.sha256(canonical_json(event)).hexdigest()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, 'ab') as handle:
            handle.write(canonical_json(event) + b'\n')
            handle.flush()
            os.fsync(handle.fileno())
        return event


def run_terminal(items: Sequence[Mapping], log: AnnotationLog, annotator: str, *, guideline: str = 'g1',
                 input_fn: Callable[[str], str] = input, output_fn: Callable[[str], None] = print,
                 clock: Callable[[], float] = time.monotonic, wall: Callable[[], str] | None = None) -> int:
    """Label `items` (each with 'pair' and 'match_id' plus display data). Returns the number recorded."""
    wall = wall or (lambda: time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
    done = {(e['pair'], e['match_id']) for e in log.events() if e['annotator'] == annotator
            and e['phase'] == 'blind'}
    recorded = 0
    for item in items:
        key = (item['pair'], item['match_id'])
        if key in done:
            continue
        output_fn(json.dumps(blind_view(dict(item)), indent=2, sort_keys=True, default=str))
        start = clock()
        answer = ''
        while answer not in ANSWERS:
            answer = input_fn('A? [s]ame [d]ifferent [n]o-counterpart [i]ndeterminate [q]uit: ').strip().lower()
            if answer == 'q':
                return recorded
        subtype = input_fn('subtype N1..N12 or blank: ').strip().upper() or None
        if subtype is not None and subtype not in {f'N{i}' for i in range(1, 13)}:
            subtype = None
        log.append(pair=key[0], match_id=key[1], annotator=annotator, phase='blind', A=ANSWERS[answer],
                   subtype=subtype, guideline=guideline, ts=wall(), time_spent_s=round(clock() - start, 3))
        recorded += 1
    return recorded


def consolidate(events: Iterable[dict], meta: Mapping[tuple[str, str], Mapping]) -> tuple[list[dict], dict]:
    """Final `calibration-labels/1` records: adjudication > unanimous blind labels; disagreements without
    adjudication stay pending. Returns (records, stats)."""
    blind: dict[tuple[str, str], dict[str, dict]] = {}
    adjudicated: dict[tuple[str, str], dict] = {}
    reveal_changes = 0
    for e in events:
        key = (e['pair'], e['match_id'])
        if e['phase'] == 'blind':
            blind.setdefault(key, {})[e['annotator']] = e
        elif e['phase'] == 'adjudication':
            adjudicated[key] = e
        elif e['phase'] == 'reveal' and blind.get(key, {}).get(e['annotator'], {}).get('A') != e['A']:
            reveal_changes += 1
    records, pending = [], []
    for key in sorted(blind):
        if key not in meta:
            continue
        labels = blind[key]
        if key in adjudicated:
            final, adj = adjudicated[key], True
        elif len({e['A'] for e in labels.values()}) == 1:
            final, adj = next(iter(labels.values())), False
        else:
            pending.append(key)
            continue
        m = meta[key]
        records.append({'pair': key[0], 'match_id': key[1], 'older': m['older'], 'newer': m['newer'],
                        'A': final['A'], 'subtype': final.get('subtype'), 'B': None, 'C': None, 'D': None,
                        'source': m.get('source', 'human'), 'annotators': sorted(labels),
                        'adjudicated': adj, 'guideline': final.get('guideline', 'g1'), 'sampling': m['sampling'],
                        'notes': ''})
    return records, {'pending': pending, 'reveal_changes': reveal_changes}
