"""Shared synthetic fixtures for SPEC-09 tests: in-memory pair projects (no I/O)."""
from __future__ import annotations

from patchtrace.models import AnalysisRun, Artifact, ComparisonProject, FunctionMatch, FunctionRecord

HASHES = [f'{i:x}' * 64 for i in range(1, 9)]


def fn(name: str, address: int | None, code: str | None = None) -> tuple:
    return name, address, code


class PairBuilder:
    def __init__(self, older_sha: str, newer_sha: str, name: str = 'pair'):
        self.older = Artifact(side='older', name='o.dll', sha256=older_sha, size=1,
                              relative_path=f'artifacts/{older_sha}.bin')
        self.newer = Artifact(side='newer', name='n.dll', sha256=newer_sha, size=1,
                              relative_path=f'artifacts/{newer_sha}.bin')
        self.run = AnalysisRun(status='completed')
        self.matches: list[FunctionMatch] = []
        self.name = name

    def _rec(self, side, spec):
        name, address, code = spec
        artifact = self.older if side == 'older' else self.newer
        return FunctionRecord(artifact_id=artifact.id, run_id=self.run.id, name=name,
                              address=None if address is None else f'{address:x}', code=code)

    def rel(self, category, older=(), newer=(), match_types=('SymbolsHash',), ratio=None, manual=False):
        olds = [self._rec('older', s) for s in older]
        news = [self._rec('newer', s) for s in newer]
        if ratio is not None:
            for f in olds + news:
                f.metadata['upstream_similarity'] = ratio
        self.matches.append(FunctionMatch(run_id=self.run.id, older=olds, newer=news, category=category,
                                          match_types=list(match_types), manual=manual))
        return self

    def one(self, old, new, **kw):
        return self.rel('modified', [old], [new], **kw)

    def build(self) -> ComparisonProject:
        return ComparisonProject(name=self.name, artifacts=[self.older, self.newer], runs=[self.run],
                                 matches=self.matches)
