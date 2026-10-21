"""Live proposal for the panel (`rules.live`) on the SYNTHETIC `capa-api` images: the pair comes from a project match, the
bytes and imports from the verified builds, the checks from the engine. Nothing is accepted and nothing is stored here."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
import rules_fixtures as rf

from patchtrace.models import FunctionMatch, FunctionRecord
from patchtrace.rules import live
from patchtrace.rules.errors import RuleError


@pytest.fixture
def bench(tmp_path):
    pytest.importorskip('yara_x', reason='YARA-X (pip install "patchtrace[rules]") is not installed')
    pytest.importorskip('iced_x86')
    bench = rf.Bench(tmp_path)
    yield bench
    bench.close()


def record(side, rva, name='TerminateStub'):
    return FunctionRecord(artifact_id=side, run_id='r', name=name, address=hex(0x140000000 + rva),
                          address_space='virtual')


def project_of(match):
    return SimpleNamespace(id='proj-live', revision=3, matches=[match])


@pytest.fixture
def world(bench, tmp_path):
    paths = {}
    for side in rf.SIDES:
        paths[side] = tmp_path / f'{side}.exe'
        paths[side].write_bytes(bench.build('capa-api', side).data)
    shas = tuple(bench.build('capa-api', side).sha256 for side in rf.SIDES)
    return (paths['older'], paths['newer'], *shas)


def removed(review='accepted'):
    return FunctionMatch(run_id='run-1', older=[record('older', 0x104D)], category='removed', review=review)


def request_of(world, match=None, confirm=True):
    match = match or removed()
    return live.prepare(project_of(match), world, match.id, confirm_material=confirm)


def test_only_an_accepted_one_to_one_match_seeds_rules(world):
    for review in ('unreviewed', 'rejected', 'needs-review'):
        match = removed(review)
        with pytest.raises(RuleError) as caught:
            live.prepare(project_of(match), world, match.id)
        assert caught.value.reason == 'not-accepted'
    with pytest.raises(RuleError) as caught:
        live.prepare(project_of(removed()), world, 'nope')
    assert caught.value.reason == 'no-such-match'
    split = FunctionMatch(run_id='r', older=[record('older', 1), record('older', 2)], newer=[record('newer', 1)],
                          category='modified', review='accepted')
    with pytest.raises(RuleError) as caught:
        live.prepare(project_of(split), world, split.id)
    assert caught.value.reason == 'not-one-to-one'


def test_an_unconfirmed_change_is_refused_not_guessed_material(bench, world):
    check = rf.engine_checker({side: bench.build('capa-api', side).data for side in rf.SIDES})
    with pytest.raises(RuleError) as caught:
        live.run_proposal(request_of(world, confirm=False), checker=check)
    assert caught.value.reason == 'not-material'


def test_without_exception_data_the_bytes_are_unavailable_and_nothing_is_guessed(bench, world):
    check = rf.engine_checker({side: bench.build('capa-api', side).data for side in rf.SIDES})
    proposal = live.run_proposal(request_of(world), checker=check)
    assert proposal.candidates == () and proposal.rejected[0].reason == 'bytes-unavailable'
    assert 'Bytes are unavailable' in proposal.rejected[0].sentence()


def test_a_confirmed_change_with_a_verified_extent_yields_an_unvetted_candidate(bench, world, monkeypatch):
    from patchtrace.pe_overview.tables import PeTables
    monkeypatch.setattr(PeTables, 'function_extent', lambda self, rva: 24 if rva == 0x104D else None)  # as .pdata would
    check = rf.engine_checker({side: bench.build('capa-api', side).data for side in rf.SIDES})
    proposal = live.run_proposal(request_of(world), checker=check)
    (candidate,) = proposal.candidates
    assert candidate.direction == 'older' and candidate.unvetted
    assert (candidate.source.older.rva, candidate.source.older.size) == (0x104D, 24)
    unavailable = [c.channel for c in proposal.coverage if c.coverage.older == 'unavailable']
    assert unavailable == ['strings', 'capabilities']   # unknown is reported, never "none found"


def test_a_missing_build_is_stale_not_a_crash(world):
    older, newer, *_ = world
    older.unlink()
    with pytest.raises(RuleError) as caught:
        live.run_proposal(request_of(world))
    assert caught.value.code == 'PT-RULE-STALE'
