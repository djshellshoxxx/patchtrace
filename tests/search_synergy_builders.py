"""Synthetic known-answer project for the WB1 synergy test (plan section 5): invented names and text only.

F1 `ClfsValidateContainerSize` (modified, a bound check is added, attention rank 1), F2 `ClfsCopyRecordHeader`
(modified, cosmetic, rank 2), F3 `ClfsReadBlock` (modified, rank 3), D `ClfsDumpState` (unchanged, repeats
"container size" in log strings). A FLOSS-shaped segment holds a string that only the newer build has, located in
F1; an advisory segment holds CVE-2099-10001. Tool and advisory groups arrive through `extra_specs`, the hook a
later source slice replaces with its own build specs.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from search_builders import RUN, _function, make_service

from patchtrace.enrichment.contracts import RankingEntry, RankingResult
from patchtrace.models import FunctionMatch
from patchtrace.search.segment import SegmentDoc
from patchtrace.search.sources.base import SourceSpec

FLOSS_STRING = 'Container size exceeds limit'
ADVISORY_TEXT = 'an oversized container size'
EMPTY_RAW = {'strings': {'added': [], 'deleted': []}, 'symbols': {'added': [], 'deleted': []}}
F1_OLD = 'int ClfsValidateContainerSize(int n) {\n    return 0;\n}'
F1_NEW = ('int ClfsValidateContainerSize(int n) {\n    if (container_size > 0x10000) return 0xc000000d;\n'
          '    return 0;\n}')
DUMP = 'void ClfsDumpState(void) {\n' + ''.join(f'    log("container size {i}");\n' for i in range(6)) + '}'


def _match(mid: str, name: str, old: str, new: str, category: str = 'modified') -> FunctionMatch:
    return FunctionMatch(id=mid, run_id=RUN, category=category, quality='high',
                         older=[_function('older', f'{mid}-old', name, '140001000', old)],
                         newer=[_function('newer', f'{mid}-new', name, '140001000', new)])


def matches() -> list[FunctionMatch]:
    return [_match('m-f1', 'ClfsValidateContainerSize', F1_OLD, F1_NEW),
            _match('m-f2', 'ClfsCopyRecordHeader', 'void a(void) { x = 1; }', 'void a(void) { x = 2; }'),
            _match('m-f3', 'ClfsReadBlock', 'int r(void) { return 1; }', 'int r(void) { return 2; }'),
            _match('m-d', 'ClfsDumpState', DUMP, DUMP, 'unchanged')]


def make_project(root: Path, *, seed: int | None = None):
    service = make_service(root, seed=seed, raw=EMPTY_RAW)
    found = matches()
    if seed is not None:
        import random
        random.Random(seed).shuffle(found)
    service.project.matches = found
    service.project.annotations = []
    service.project.interpretations = []
    return service


def attention(_project):
    """`load_default`-shaped port: F1, F2, F3 ranked 1..3 (an ordinal, no score semantics)."""
    entries = tuple(RankingEntry(pairing_id=f'{i:064x}', match_id=mid, rank=i, score=0, raw=0, strong_groups=0,
                                 evidence='complete') for i, mid in enumerate(('m-f1', 'm-f2', 'm-f3'), 1))
    return RankingResult(config_digest='a' * 64, input_digest='b' * 64, entries=entries, status='complete'), (), ''


def _spec(group: str, kinds: tuple[str, ...], side: str | None, docs: list[SegmentDoc]) -> SourceSpec:
    return SourceSpec(group, kinds, ('text',), side, {'docs': [(d.kind, d.subject, d.display) for d in docs]},
                      lambda: tuple(docs))


def extra_specs(_request):
    string = SegmentDoc('string', 'newer', 'm-f1-new', FLOSS_STRING, 0,
                        value_sha=hashlib.sha256(FLOSS_STRING.encode()).hexdigest(), text_title=FLOSS_STRING)
    advisory = SegmentDoc('advisory', None, 'CVE-2099-10001', 'CVE-2099-10001', 0, text_title='CVE-2099-10001',
                          text_body=ADVISORY_TEXT)
    return (_spec('tool:floss:older', ('string',), 'older', []),
            _spec('tool:floss:newer', ('string',), 'newer', [string]), _spec('adv', ('advisory',), None, [advisory]))
