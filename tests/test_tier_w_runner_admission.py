"""Tier-W resume requires actual backend/condition evidence before crediting rows."""
from __future__ import annotations

import os

import pytest
from test_tier_w_runner import BASE, CID, FakeGhidriff, H, V, cell, corpus, lines, run, store_matches

from patchtrace.service import ProjectService
from tools.calibration.tier_w import runner as R
from tools.calibration.tier_w.paths import Layout, TierWError


def settings(doc, condition=H):
    by_id = {entry.id: entry for entry in doc.binaries}
    pair = doc.pairs[0]
    return {'older_sha256': by_id[pair.older].sha256, 'newer_sha256': by_id[pair.newer].sha256,
            'allow_symbol_downloads': condition == V,
            'symbol_policy': 'online' if condition == V else 'disabled'}


def seed(root, doc, *, condition=H, updates=None, rows=None, version='ghidriff-test'):
    pair = doc.pairs[0]
    by_id = {entry.id: entry for entry in doc.binaries}
    project = Layout(root).run_dir(CID, pair.id, condition) / 'project'
    if not (project / 'project.sqlite3').exists():
        files = [root / 'binaries' / by_id[ref].sha256 / by_id[ref].file_name
                 for ref in (pair.older, pair.newer)]
        R.create_project(*files, 'authored resume', project)
    store_matches(project, rows or (([BASE + 0x1000], [BASE + 0x1010], 'modified'),), version)
    with ProjectService.open(project, maintenance=False) as service:
        snapshot = service.project.model_copy(deep=True)
        values = {'settings': settings(doc, condition), **(updates or {})}
        snapshot.runs[-1] = snapshot.runs[-1].model_copy(update=values)
        service.store.save(snapshot)
    return project


@pytest.mark.parametrize('fault', ['backend', 'missing-settings', 'policy', 'download-flag', 'input-hash'])
def test_existing_unproven_run_is_blocked_without_relabelling_or_execution(tmp_path, fault):
    root = tmp_path / 'ptcal'
    doc = corpus(root, names=('a',))
    evidence = settings(doc)
    updates = {'settings': evidence}
    if fault == 'backend':
        updates['backend'] = 'analyst-import'
    elif fault == 'missing-settings':
        updates['settings'] = {}
    elif fault == 'policy':
        evidence['symbol_policy'] = 'online'
    elif fault == 'download-flag':
        evidence['allow_symbol_downloads'] = 0  # bool identity, not truthiness
    else:
        evidence['older_sha256'] = '0' * 64
    project = seed(root, doc, updates=updates)
    with ProjectService.open(project, maintenance=False) as service:
        before = service.project.model_dump(mode='json')
    fake = FakeGhidriff()
    record = run(root, doc, fake)
    assert cell(record).blocked == 1 and not fake.calls and not lines(root)
    with ProjectService.open(project, maintenance=False) as service:
        assert service.project.model_dump(mode='json') == before


def test_only_latest_condition_eligible_run_is_credited(tmp_path):
    root = tmp_path / 'ptcal'
    doc = corpus(root, names=('a',))
    seed(root, doc, version='old-version')
    seed(root, doc, rows=(([BASE + 0x1200], [BASE + 0x1220], 'modified'),), version='new-version')
    fake = FakeGhidriff()
    record = run(root, doc, fake)
    assert cell(record).ok == 1 and not fake.calls
    assert [(row.older_rva, row.newer_rva, row.engine_version) for row in lines(root)] == [
        (0x1200, 0x1220, 'new-version')]


def test_fresh_invocation_cannot_credit_an_unqualified_completed_result(tmp_path):
    root = tmp_path / 'ptcal'
    doc = corpus(root, names=('a',))
    calls = []

    def invalid(_config, project, _cancel):
        calls.append(project)
        seed(root, doc, updates={'backend': 'other-engine'})

    record = run(root, doc, invalid)
    assert len(calls) == 1 and cell(record).failed == 1 and not lines(root)


@pytest.mark.parametrize('destination', ['run-record', 'binary', 'project-database', 'binary-hardlink'])
def test_output_aliases_are_refused_before_factory_or_engine_work(tmp_path, destination):
    root = tmp_path / 'ptcal'
    doc = corpus(root, names=('a',))
    binary = doc.binaries[0]
    source = root / 'binaries' / binary.sha256 / binary.file_name
    before = source.read_bytes()
    target = Layout(root).matches(CID)
    if destination == 'run-record':
        target = target.with_name('run.json')
    elif destination == 'binary':
        target = source
    elif destination == 'project-database':
        target = Layout(root).run_dir(CID, doc.pairs[0].id, H) / 'project' / 'project.sqlite3'
    else:
        target.parent.mkdir(parents=True)
        os.link(source, target)
    calls = []

    def factory(*args):
        calls.append('factory')
        pytest.fail('output admission must precede project creation')

    def invoker(*args):
        calls.append('invoker')
        pytest.fail('output admission must precede engine invocation')

    with pytest.raises(TierWError) as caught:
        R.run_corpus(Layout(root), doc, corpus_id=CID, config_factory=lambda condition: {}, factory=factory,
                     invoker=invoker, matches_path=target)
    assert caught.value.code == 'PT-TIERW-CONFIG' and not calls
    assert source.read_bytes() == before


def test_duplicate_binary_ids_and_empty_engine_selection_fail_before_writes(tmp_path):
    root = tmp_path / 'ptcal'
    doc = corpus(root, names=('a',))
    duplicate = doc.model_copy(update={'binaries': (*doc.binaries, doc.binaries[0])})
    for value, kwargs in ((duplicate, {}), (doc, {'conditions': ()})):
        with pytest.raises(TierWError) as caught:
            run(root, value, **kwargs)
        assert caught.value.code == 'PT-TIERW-INPUT'
    assert not (root / 'tier-w').exists()
