"""Local plan of a manual pair import (KB-integration-plan 7.2 `PairPlan`, 8.1 `import-pair`; slice K3). Pure.

A `PairPlan` lists network requests and is absent for local files, so E0 has this smaller record: what an import will
do with the two files, bound by a ``plan_sha`` that also names the attach in the workspace journal and attempt log.
It makes no request; the network plan (E1) is `kbcorrelation/1` `PairPlan`.
"""
from __future__ import annotations

from dataclasses import dataclass

from .contracts import PairProposal, domain_id

STEPS = (
    'Hash both files and check that each is an AMD64 PE file (they are never run).',
    'Create the comparison project in the chosen directory.',
    'Attach the advisory context: what the vendor states and which checks could not be made.',
)


@dataclass(frozen=True)
class LocalPlan:
    plan_sha: str
    pair_id: str
    older_sha: str
    newer_sha: str
    steps: tuple[str, ...] = STEPS
    network_requests: int = 0

    def as_dict(self) -> dict:
        return {'plan_sha': self.plan_sha, 'pair_id': self.pair_id, 'older_sha': self.older_sha,
                'newer_sha': self.newer_sha, 'steps': list(self.steps), 'network_requests': self.network_requests}

    @property
    def text(self) -> str:
        lines = [f'Local import plan {self.plan_sha[:12]}: no network request is made.']
        lines += [f'{n}. {step}' for n, step in enumerate(self.steps, 1)]
        return '\n'.join(lines)


def local_plan(pair: PairProposal) -> LocalPlan:
    sha = domain_id('kbc.localplan', 1, {'pair_id': pair.pair_id, 'older': pair.older.sha256,
                                         'newer': pair.newer.sha256})
    return LocalPlan(plan_sha=sha, pair_id=pair.pair_id, older_sha=pair.older.sha256, newer_sha=pair.newer.sha256)
