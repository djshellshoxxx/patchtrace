"""Constructed runner evidence survives cancellation and paired-publication failures."""
from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path

import pytest
from test_tier_w_runner import BASE, CID, FakeGhidriff, H, V, corpus, run
from test_tier_w_runner_admission import seed

from tools.calibration.tier_w import runner as R
from tools.calibration.tier_w.contracts import load_run_record
from tools.calibration.tier_w.paths import Layout, TierWError, dumps


def selected(root):
    matches = Layout(root).matches(CID)
    return matches, matches.with_name('run.json')


def snapshot(root):
    return tuple(path.read_bytes() for path in selected(root))


def retained(root, summary):
    folder = selected(root)[0].parent / '.tier-w-run-history' / hashlib.sha256(summary).hexdigest()
    raw = (folder / 'matches.jsonl').read_bytes()
    assert (folder / 'run.json').read_bytes() == summary
    assert load_run_record(summary).matches_sha256 == hashlib.sha256(raw).hexdigest()
    return raw


def prior_and_new(root):
    doc = corpus(root, names=('a',))
    run(root, doc)
    before = snapshot(root)
    seed(root, doc, rows=(([BASE + 0x1200], [BASE + 0x1220], 'modified'),), version='next-version')
    return doc, before


@pytest.mark.parametrize('kind', ['event', 'file'])
def test_cancelled_rerun_preserves_selected_pair_and_retains_current_attempt(tmp_path, kind):
    root = tmp_path / 'ptcal'
    doc, before = prior_and_new(root)
    event = threading.Event()
    if kind == 'event':
        event.set()
    else:
        Layout(root).cancel_file.touch()
    fake = FakeGhidriff()
    result = run(root, doc, fake, cancel=event)
    assert result.status == 'cancelled' and not fake.calls
    assert snapshot(root) == before
    assert retained(root, before[1]) == before[0]
    assert retained(root, dumps(result.model_dump(mode='json'))) == b''


@pytest.mark.parametrize('boundary', ['first-before', 'second-before', 'second-after'])
@pytest.mark.parametrize('kind', ['io', 'interrupt'])
def test_publication_failure_restores_prior_pair_and_preserves_primary(tmp_path, monkeypatch, boundary, kind):
    root = tmp_path / 'ptcal'
    doc, before = prior_and_new(root)
    matches, summary = selected(root)
    replace = os.replace
    primary = OSError('authored publication failure') if kind == 'io' else KeyboardInterrupt('authored interrupt')
    raised = False

    def fail(source, destination, *args, **kwargs):
        nonlocal raised
        target = Path(destination)
        chosen = matches if boundary == 'first-before' else summary
        if target == chosen and not raised:
            raised = True
            if boundary == 'second-after':
                replace(source, destination, *args, **kwargs)
            raise primary
        return replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, 'replace', fail)
    with pytest.raises(BaseException) as caught:
        run(root, doc)
    assert caught.value is primary and raised
    assert snapshot(root) == before
    assert retained(root, before[1]) == before[0]


def test_cancel_between_selected_replacements_restores_previous_pair(tmp_path, monkeypatch):
    root = tmp_path / 'ptcal'
    doc, before = prior_and_new(root)
    matches, _summary = selected(root)
    event = threading.Event()
    replace = os.replace

    def trip(source, destination, *args, **kwargs):
        result = replace(source, destination, *args, **kwargs)
        if Path(destination) == matches:
            event.set()
        return result

    monkeypatch.setattr(os, 'replace', trip)
    result = run(root, doc, cancel=event)
    assert result.status == 'cancelled'
    assert snapshot(root) == before
    assert retained(root, before[1]) == before[0]
    assert retained(root, dumps(result.model_dump(mode='json'))) != before[0]


@pytest.mark.parametrize('fault', ['missing-record', 'foreign-corpus', 'wrong-digest'])
def test_invalid_prior_pair_is_refused_before_engine_or_project_work(tmp_path, fault):
    root = tmp_path / 'ptcal'
    doc = corpus(root, names=('a',))
    record = run(root, doc)
    matches, summary = selected(root)
    if fault == 'missing-record':
        summary.unlink()
    elif fault == 'foreign-corpus':
        summary.write_bytes(dumps(record.model_dump(mode='json') | {'corpus_id': 'tier-w-other'}))
    else:
        matches.write_bytes(b'foreign data\n')
    before = tuple(path.read_bytes() if path.exists() else None for path in (matches, summary))
    fake = FakeGhidriff()
    with pytest.raises(TierWError):
        run(root, doc, fake)
    assert not fake.calls
    assert tuple(path.read_bytes() if path.exists() else None for path in (matches, summary)) == before


def test_partial_run_can_resume_and_both_complete_generations_are_retained(tmp_path):
    root = tmp_path / 'ptcal'
    doc = corpus(root)
    first = run(root, doc, FakeGhidriff(raises=(doc.pairs[0].id,)))
    before = snapshot(root)
    assert first.status == 'partial'
    second = run(root, doc)
    assert second.status == 'ok'
    assert snapshot(root) != before
    assert retained(root, before[1]) == before[0]
    assert retained(root, dumps(second.model_dump(mode='json'))) == snapshot(root)[0]


def test_restoration_failure_preserves_primary_and_prior_history(tmp_path, monkeypatch):
    root = tmp_path / 'ptcal'
    doc, before = prior_and_new(root)
    matches, summary = selected(root)
    replace = os.replace
    primary = OSError('authored second publication failure')

    def fail(source, destination, *args, **kwargs):
        if Path(destination) == summary:
            raise primary
        if Path(source).name.startswith('restore-'):
            raise KeyboardInterrupt('authored restoration cancellation')
        return replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, 'replace', fail)
    with pytest.raises(OSError) as caught:
        run(root, doc)
    assert caught.value is primary
    assert 'restoration failed' in primary.__notes__[0]
    assert matches.read_bytes() != before[0] and summary.read_bytes() == before[1]
    assert retained(root, before[1]) == before[0]
    with pytest.raises(TierWError, match='mismatched digest'):
        run(root, doc)


def test_failed_cancellation_restoration_is_reported_and_retains_prior_pair(tmp_path, monkeypatch):
    root = tmp_path / 'ptcal'
    doc, before = prior_and_new(root)
    matches, _summary = selected(root)
    event = threading.Event()
    replace = os.replace

    def trip(source, destination, *args, **kwargs):
        if Path(source).name.startswith('restore-'):
            raise OSError('authored restoration failure')
        result = replace(source, destination, *args, **kwargs)
        if Path(destination) == matches:
            event.set()
        return result

    monkeypatch.setattr(os, 'replace', trip)
    with pytest.raises(TierWError, match='needs recovery'):
        run(root, doc, cancel=event)
    assert retained(root, before[1]) == before[0]


def test_failure_does_not_erase_an_observed_foreign_destination(tmp_path, monkeypatch):
    root = tmp_path / 'ptcal'
    doc, before = prior_and_new(root)
    matches, summary = selected(root)
    replace = os.replace
    primary = OSError('authored publication failure')
    foreign = b'foreign evidence\n'
    replacement = matches.with_name('foreign-object')
    replacement.write_bytes(foreign)

    def fail(source, destination, *args, **kwargs):
        if Path(destination) == summary:
            replace(replacement, matches)
            raise primary
        return replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, 'replace', fail)
    with pytest.raises(OSError) as caught:
        run(root, doc)
    assert caught.value is primary
    assert matches.read_bytes() == foreign and summary.read_bytes() == before[1]
    assert retained(root, before[1]) == before[0]


@pytest.mark.parametrize('same_inode', [False, True])
def test_replacement_source_mutation_never_receives_a_success_receipt(tmp_path, monkeypatch, same_inode):
    root = tmp_path / 'ptcal'
    doc, before = prior_and_new(root)
    matches, summary = selected(root)
    replace = os.replace
    armed = True

    def mutate(source, destination, *args, **kwargs):
        nonlocal armed
        if Path(destination) == matches and armed:
            armed = False
            source = Path(source)
            foreign = b'x' * source.stat().st_size
            if not same_inode:
                source.unlink()
            source.write_bytes(foreign)
        return replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, 'replace', mutate)
    with pytest.raises(TierWError, match='identity or bytes changed'):
        run(root, doc)
    assert summary.read_bytes() == before[1]
    assert retained(root, before[1]) == before[0]


def test_history_failure_aborts_before_changing_selected_files(tmp_path, monkeypatch):
    root = tmp_path / 'ptcal'
    doc, before = prior_and_new(root)
    publish = R.owned.publish_bytes
    primary = OSError('authored history write failure')

    def fail(path, *args, **kwargs):
        if R.HISTORY in Path(path).parts and Path(path).name == 'run.json':
            raise primary
        return publish(path, *args, **kwargs)

    monkeypatch.setattr(R.owned, 'publish_bytes', fail)
    with pytest.raises(OSError) as caught:
        run(root, doc)
    assert caught.value is primary and snapshot(root) == before


def test_first_publication_preserves_a_concurrent_creator(tmp_path, monkeypatch):
    root = tmp_path / 'ptcal'
    doc = corpus(root, names=('a',))
    matches, summary = selected(root)
    publish = R.owned.publish_bytes
    foreign = b'concurrently created matches\n'

    def insert(path, *args, **kwargs):
        if Path(path) == matches:
            matches.write_bytes(foreign)
        return publish(path, *args, **kwargs)

    monkeypatch.setattr(R.owned, 'publish_bytes', insert)
    with pytest.raises(FileExistsError):
        run(root, doc)
    assert matches.read_bytes() == foreign and not summary.exists()


def test_unchanged_rerun_keeps_selected_inodes(tmp_path):
    root = tmp_path / 'ptcal'
    doc = corpus(root, names=('a',))
    first = run(root, doc)
    identities = [path.stat().st_ino for path in selected(root)]
    assert run(root, doc) == first
    assert [path.stat().st_ino for path in selected(root)] == identities


@pytest.mark.parametrize('name', ['.tier-w-run-history', '.TIER-W-RUN-HISTORY'])
def test_history_is_reserved_before_engine_or_project_work(tmp_path, name):
    root = tmp_path / 'ptcal'
    doc = corpus(root, names=('a',))
    fake = FakeGhidriff()
    target = selected(root)[0].parent / name / 'preserved-generation' / 'matches.jsonl'
    with pytest.raises(TierWError) as caught:
        R.run_corpus(Layout(root), doc, corpus_id=CID, config_factory=lambda condition: {},
                     invoker=fake, matches_path=target)
    assert caught.value.code == 'PT-TIERW-CONFIG' and not fake.calls
    assert not root.joinpath('tier-w').exists()


@pytest.mark.parametrize('kind', ['matches', 'record'])
def test_output_budget_failure_preserves_prior_selected_pair(tmp_path, monkeypatch, kind):
    root = tmp_path / 'ptcal'
    doc, before = prior_and_new(root)
    kwargs = {}
    if kind == 'matches':
        seed(root, doc, rows=tuple(([BASE + 0x1200 + i], [BASE + 0x1220 + i], 'modified') for i in range(8)))
        monkeypatch.setattr(R, 'MATCHES_LIMIT', len(before[0]))
    else:
        kwargs['conditions'] = (H, V)
        monkeypatch.setattr(R, 'DOC_LIMIT', len(before[1]))
    with pytest.raises(TierWError) as caught:
        run(root, doc, **kwargs)
    assert caught.value.code == 'PT-TIERW-LIMIT'
    assert snapshot(root) == before


@pytest.mark.parametrize('traversal', [False, True])
def test_linked_output_parent_is_rejected_before_any_project_work(tmp_path, traversal):
    root = tmp_path / 'ptcal'
    doc = corpus(root, names=('a',))
    ordinary = root / 'ordinary'
    ordinary.mkdir()
    link = root / 'linked'
    try:
        link.symlink_to(ordinary, target_is_directory=True)
    except OSError:
        pytest.skip('directory symlinks unavailable to this account')
    target = link / '..' / 'selected' / 'matches.jsonl' if traversal else link / 'matches.jsonl'
    calls = []

    def factory(*args):
        calls.append('project')
        raise AssertionError('unsafe output admission must precede project creation')

    with pytest.raises(TierWError) as caught:
        R.run_corpus(Layout(root), doc, corpus_id=CID, config_factory=lambda condition: {},
                     factory=factory, invoker=FakeGhidriff(), matches_path=target)
    assert caught.value.code == 'PT-TIERW-CONFIG' and not calls


def test_cancel_switch_cannot_become_a_matches_output(tmp_path):
    root = tmp_path / 'ptcal'
    doc = corpus(root, names=('a',))
    fake = FakeGhidriff()
    with pytest.raises(TierWError) as caught:
        R.run_corpus(Layout(root), doc, corpus_id=CID, config_factory=lambda condition: {},
                     invoker=fake, matches_path=Layout(root).cancel_file)
    assert caught.value.code == 'PT-TIERW-CONFIG' and not fake.calls
    assert not root.joinpath('tier-w').exists()
