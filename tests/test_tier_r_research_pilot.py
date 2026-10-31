"""Research selection and observation invariants; no substitute is native evidence."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from tools.calibration.tier_r import contracts as C
from tools.calibration.tier_r import research_pilot as P
from tools.calibration.tier_r.schemas import example_labels


def labels():
    return C.load_labels(C.dump_json(C.finalize_labels(example_labels())))


def review(doc):
    keys = [P.function_key(f) for f in doc.functions]
    return {'pair_id': doc.pair_id, 'labels_digest_sha256': doc.digest_sha256,
            'reviewer': 'independent automated test reviewer', 'review_kind': 'test-only',
            'accepted_keys': keys[1:], 'ambiguous_keys': keys[:1], 'evidence': ['synthetic test']}


def test_review_selection_is_bound_and_does_not_rewrite_original_truth():
    doc = labels()
    before = doc.model_dump(mode='json')
    selected, scope = P.select_truth(doc, review(doc))
    assert doc.model_dump(mode='json') == before
    assert selected.functions[0].identity == 'ambiguous'
    assert selected.functions[0].label == 'ambiguous'
    assert scope['status'] == 'reviewed-selection'
    assert scope['original_labels_sha256'] == doc.digest_sha256
    assert len(selected.functions) == len(doc.functions)


@pytest.mark.parametrize('damage', ['digest', 'pair', 'unknown', 'overlap', 'duplicate', 'reviewer', 'incomplete'])
def test_invalid_acceptance_cannot_promote_candidates(damage):
    doc = labels()
    item = review(doc)
    if damage == 'digest':
        item['labels_digest_sha256'] = '0' * 64
    elif damage == 'pair':
        item['pair_id'] = 'different'
    elif damage == 'unknown':
        item['accepted_keys'][0] = [None, 'invented', None, 1, 2]
    elif damage == 'overlap':
        item['ambiguous_keys'] += item['accepted_keys'][:1]
    elif damage == 'duplicate':
        item['accepted_keys'] *= 2
    elif damage == 'reviewer':
        item['reviewer'] = ''
    else:
        item['accepted_keys'] = item['accepted_keys'][:-1]
    with pytest.raises(ValueError):
        P.select_truth(doc, item)


def test_no_review_means_exploratory_not_accepted():
    doc = labels()
    selected, scope = P.select_truth(doc, None)
    assert selected is doc
    assert scope['status'] == 'exploratory-candidates'


def row(old, new, decision, materiality='unknown'):
    return SimpleNamespace(older=tuple(old), newer=tuple(new), decision=decision, materiality=materiality)


def test_unified_only_unique_matched_decisions_enter_correspondence_metrics():
    rows = [row([1], [2], 'matched', 'material'), row([3], [4], 'matched', 'review'),
            row([5], [6], 'matched', 'cosmetic'), row([7], [], 'older-only'),
            row([], [8], 'newer-only'), row([9], [10], 'tentative', 'material'),
            row([11], [12], 'contested'), row([13], [14, 15], 'matched')]
    observations, coverage = P.unified_observations(rows)
    assert observations == [(1, 2, True), (3, 4, None), (5, 6, False), (7, None, None), (None, 8, None)]
    assert coverage['abstained_rows'] == 3
    assert coverage['rows'] == 8
    assert coverage['decisions']['tentative'] == 1


def test_wrong_project_binding_fails_before_reusing_primary():
    doc = labels()
    project = SimpleNamespace(artifacts=[SimpleNamespace(side='older', sha256='0' * 64),
                                         SimpleNamespace(side='newer', sha256=doc.newer.sha256)])
    with pytest.raises(ValueError, match='artifact'):
        P.verify_project(doc, project)


def test_unknown_matched_materiality_is_abstention_on_change():
    observations, _ = P.unified_observations([row([1], [2], 'matched', 'not-applicable')])
    assert observations == [(1, 2, None)]


@pytest.mark.parametrize(('backend', 'resumed', 'settings', 'provenance', 'executed'), [
    ('ghidriff', False, {}, 'executed-now', True),
    ('ghidriff', True, {}, 'persisted-native', False),
    ('ghidriff-import', False, {}, 'persisted-import-or-sample', False),
    ('ghidriff-import', False, {'cache_origin': {}}, 'persisted-import-or-sample', False),
    ('ghidriff', False, {'cache_origin': {'run_id': 'previous'}}, 'persisted-native-cache', False),
    ('ghidriff', True, {'cache_origin': {}}, 'persisted-native-cache', False),
    ('ghidriff', False, {'cache_origin': None}, 'persisted-native-cache', False),
])
def test_execution_provenance_never_credits_cached_imported_or_resumed_runs(
        backend, resumed, settings, provenance, executed):
    """Metadata-only unit cases; these substitutes do not establish any native execution."""
    run = SimpleNamespace(backend=backend, settings=settings)
    observed = P._execution_provenance(run, resumed=resumed)
    assert observed == {'execution_provenance': provenance, 'native_execution_in_this_invocation': executed}


def pilot_cli(tmp_path, monkeypatch, output, *, work=None, during_run=None):
    """Exercise real CLI file handling; the substitute proves no native compatibility."""
    monkeypatch.chdir(tmp_path)
    source = tmp_path / 'labels.json'
    source.write_bytes(C.dump_json(labels().model_dump(mode='json')))
    work = work or tmp_path / 'work'
    calls = []
    def fake_run(*_args, **_kwargs):
        calls.append(True)
        work.mkdir(parents=True, exist_ok=True)
        if during_run:
            during_run()
        return {'engines': {'ghidriff': {'status': 'ok'}}}
    monkeypatch.setattr(P, 'run_pilot', fake_run)
    code = P.main(['--labels', str(source), '--store', str(tmp_path / 'store'),
                   '--work', str(work), '--output', str(output), '--ghidra-dir', str(tmp_path / 'ghidra')])
    return code, calls


@pytest.mark.parametrize('kind', ['outside', 'traversal', 'relative', 'nested', 'extension', 'repository'])
def test_cli_rejects_unsafe_receipt_before_engine_work(tmp_path, monkeypatch, kind):
    work = tmp_path / 'work'
    output = {'outside': tmp_path / 'unrelated.json', 'traversal': work / '..' / 'escaped.json',
              'relative': P.Path('receipt.json'), 'nested': work / 'primary' / 'receipt.json',
              'extension': work / 'record.py', 'repository': tmp_path / 'repo' / 'receipt.json'}[kind]
    if kind == 'repository':
        work = output.parent
        monkeypatch.setattr(P, '__file__', str(work / 'tools' / 'calibration' / 'tier_r' / 'research_pilot.py'))
    code, calls = pilot_cli(tmp_path, monkeypatch, output, work=work)
    assert code == 2
    assert calls == []
    assert not output.exists()


def test_cli_preserves_existing_receipt_before_engine_work(tmp_path, monkeypatch):
    output = tmp_path / 'work' / 'receipt.json'
    output.parent.mkdir()
    output.write_bytes(b'original receipt')
    code, calls = pilot_cli(tmp_path, monkeypatch, output)
    assert code == 2
    assert calls == []
    assert output.read_bytes() == b'original receipt'


@pytest.mark.parametrize('kind', ['file', 'work-directory'])
def test_cli_rejects_symlinked_receipt_paths(tmp_path, monkeypatch, kind):
    work = tmp_path / 'work'
    target = tmp_path / 'original.json'
    target.write_bytes(b'original input')
    output = work / 'receipt.json'
    try:
        if kind == 'file':
            work.mkdir()
            output.symlink_to(target)
        else:
            actual = tmp_path / 'actual'
            actual.mkdir()
            work.symlink_to(actual, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f'host cannot create symlinks: {exc}')
    code, calls = pilot_cli(tmp_path, monkeypatch, output)
    assert code == 2
    assert calls == []
    assert target.read_bytes() == b'original input'


def test_cli_exclusively_publishes_new_contained_receipt(tmp_path, monkeypatch):
    output = tmp_path / 'work' / 'receipt.json'
    code, calls = pilot_cli(tmp_path, monkeypatch, output)
    assert code == 0
    assert calls == [True]
    assert P.strict_json(output.read_bytes()) == {'engines': {'ghidriff': {'status': 'ok'}}}


def test_cli_preserves_receipt_created_during_analysis(tmp_path, monkeypatch):
    output = tmp_path / 'work' / 'receipt.json'
    code, calls = pilot_cli(tmp_path, monkeypatch, output,
                            during_run=lambda: output.write_bytes(b'concurrent receipt'))
    assert code == 2
    assert calls == [True]
    assert output.read_bytes() == b'concurrent receipt'
