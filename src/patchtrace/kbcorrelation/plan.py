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


@dataclass(frozen=True)
class IndexPlan:
    """What a file-index pair would need before any fetch. No request is listed: the exact request list, hosts and
    consent-bound ``plan_sha`` belong to the acquisition step (E1), so this is a preview and carries no consent."""
    pair_id: str
    older_sha: str
    newer_sha: str
    older_availability: str
    newer_availability: str
    network_requests: int = 0

    def as_dict(self) -> dict:
        return {'pair_id': self.pair_id, 'older_sha256': self.older_sha, 'newer_sha256': self.newer_sha,
                'older_availability': self.older_availability, 'newer_availability': self.newer_availability,
                'network_requests': self.network_requests, 'consent_required': True}

    @property
    def text(self) -> str:
        return (f'Index pair {self.pair_id[:12]}: older file {self.older_availability}, newer file '
                f'{self.newer_availability}. No request is planned or made here; fetching needs the acquisition step '
                'with your consent, and a file is checked against its expected SHA-256 and never run.')


def index_plan(pair: PairProposal) -> IndexPlan:
    return IndexPlan(pair_id=pair.pair_id, older_sha=pair.older.sha256, newer_sha=pair.newer.sha256,
                     older_availability=pair.older.availability, newer_availability=pair.newer.availability)
