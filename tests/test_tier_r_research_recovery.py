"""Recovery boundaries through real readers/publication and substituted engine work."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_tier_r_receipt_parent_race import _invoke
from test_tier_r_research_build import substituted_factory  # noqa: F401

from tools.calibration.tier_r import contracts as C
from tools.calibration.tier_r import research_audit as A
from tools.calibration.tier_r import research_build as B
from tools.calibration.tier_r import research_observers as O
from tools.calibration.tier_r import research_pilot as P
from tools.calibration.tier_r.schemas import example_labels


def _labels():
    return C.load_labels(C.dump_json(C.finalize_labels(example_labels())))


def _review(doc):
    return {'pair_id': doc.pair_id, 'labels_digest_sha256': doc.digest_sha256,
            'reviewer': 'test reviewer', 'review_kind': 'unit-only',
            'accepted_keys': [P.function_key(f) for f in doc.functions], 'ambiguous_keys': []}


def test_observation_budget_counts_duplicates_before_deduplication(monkeypatch):
    monkeypatch.setattr(A, 'MAX_PREDICTIONS', 3)
    seen = []

    def repeated():
        for index in range(100):
            seen.append(index)
            yield (1, 2, None)

    with pytest.raises(ValueError, match='limit'):
        A.supplemental_metrics(_labels(), repeated())
    assert seen == [0, 1, 2, 3]


def test_unified_row_budget_counts_abstentions(monkeypatch):
    monkeypatch.setattr(P, 'MAX_PREDICTIONS', 2)
    seen = []

    def rows():
        for index in range(100):
            seen.append(index)
            yield SimpleNamespace(older=(1,), newer=(2,), decision='contested', materiality='unknown')

    with pytest.raises(ValueError, match='limit'):
        P.unified_observations(rows())
    assert seen == [0, 1, 2]


def test_review_cannot_use_boolean_alias_for_integer_address():
    body = _labels().model_dump(mode='json')
    selected = next(index for index, function in enumerate(body['functions']) if function['old_rva'] is not None)
    body['functions'][selected]['old_rva'] = 1
    doc = C.load_labels(C.dump_json(C.finalize_labels(body)))
    review = _review(doc)
    review['accepted_keys'][selected][3] = True
    with pytest.raises(ValueError, match='uint32'):
        P.select_truth(doc, review)


@pytest.mark.parametrize('damage', ['unknown-field', 'long-reviewer', 'many-references', 'nontext-reference'])
def test_review_metadata_is_strict_and_bounded(damage):
    doc = _labels()
    review = _review(doc)
    if damage == 'unknown-field':
        review['native_execution'] = True
    elif damage == 'long-reviewer':
        review['reviewer'] = 'x' * 513
    elif damage == 'many-references':
        review['evidence'] = ['reference'] * 257
    else:
        review['evidence'] = [{'untrusted': 'object'}]
    with pytest.raises(ValueError):
        P.select_truth(doc, review)


def _pilot_args(tmp_path, monkeypatch):
    labels = tmp_path / 'labels.json'
    labels.write_bytes(C.dump_json(_labels().model_dump(mode='json')))
    monkeypatch.setattr(P, 'run_pilot', lambda *a, **k: pytest.fail('invalid input reached engine work'))
    return labels, ['--labels', str(labels), '--store', str(tmp_path / 'store'),
                    '--work', str(tmp_path / 'work'), '--output', str(tmp_path / 'work' / 'receipt.json'),
                    '--ghidra-dir', str(tmp_path / 'ghidra')]


@pytest.mark.parametrize('which', ['labels', 'review'])
def test_cli_refuses_metadata_over_budget_before_engine_work(tmp_path, monkeypatch, which):
    _labels_path, args = _pilot_args(tmp_path, monkeypatch)
    if which == 'labels':
        monkeypatch.setattr(C, 'MAX_LABEL_BYTES', 8)
    else:
        review = tmp_path / 'review.json'
        review.write_text(json.dumps(_review(_labels())))
        args += ['--review', str(review)]
        monkeypatch.setattr(P, 'MAX_REVIEW_BYTES', 8)
    assert P.main(args) == 2
    assert not (tmp_path / 'work').exists()


@pytest.mark.skipif(os.name != 'posix', reason='POSIX FIFO admission control')
@pytest.mark.parametrize('which', ['labels', 'review'])
def test_cli_refuses_fifo_metadata_without_opening_it(tmp_path, monkeypatch, which):
    labels, args = _pilot_args(tmp_path, monkeypatch)
    if which == 'labels':
        labels.unlink()
        special = labels
    else:
        special = tmp_path / 'review.json'
        args += ['--review', str(special)]
    os.mkfifo(special)
    assert P.main(args) == 2
    assert not (tmp_path / 'work').exists()


@pytest.mark.parametrize('raw', [b'{"pair_id":"a","pair_id":"b"}', b'[' * 2000 + b']' * 2000])
def test_cli_rejects_duplicate_or_deep_review_json(tmp_path, monkeypatch, raw):
    run_pilot = P.run_pilot
    _labels_path, args = _pilot_args(tmp_path, monkeypatch)
    monkeypatch.setattr(P, 'run_pilot', run_pilot)
    monkeypatch.setattr(P.ProjectService, 'create', lambda *a, **k: pytest.fail('invalid review reached engine work'))
    review = tmp_path / 'review.json'
    review.write_bytes(raw)
    assert P.main([*args, '--review', str(review)]) == 2
    assert not (tmp_path / 'work').exists()


def test_recovered_default_suite_has_real_declared_sources():
    suite, bases = B._suite_bases(B.DEFAULT_SUITE)
    assert suite.pairs and set(bases) == set(suite.versions)
    assert all(base.files == ('r1.c',) for base in bases.values())
    assert all((base.root / base.files[0]).is_file() for base in bases.values())


def test_suite_entry_budget_is_shared_across_versions(monkeypatch):
    monkeypatch.setattr(B, 'MAX_SUITE_ENTRIES', 1)
    with pytest.raises(ValueError, match='entry limit'):
        B._suite_bases(B.DEFAULT_SUITE)


def test_suite_source_bytes_are_bounded_before_compilation(monkeypatch):
    monkeypatch.setattr(B, 'MAX_SOURCE_BYTES', 8)
    with pytest.raises(ValueError, match='byte limit'):
        B._suite_bases(B.DEFAULT_SUITE)


@pytest.mark.parametrize('version', ['.', '..'])
def test_suite_refuses_dot_versions_before_source_discovery(tmp_path, monkeypatch, version):
    body = json.loads((B.DEFAULT_SUITE / 'suite.json').read_bytes())
    body['versions'][0] = version
    (tmp_path / 'suite.json').write_text(json.dumps(body))
    monkeypatch.setattr(B, '_source_files', lambda *a: pytest.fail('dot version reached source discovery'))
    with pytest.raises(ValueError, match='traversal'):
        B._suite_bases(tmp_path)


def test_source_tree_refuses_links_and_preserves_external_file(tmp_path):
    root = tmp_path / 'version'
    root.mkdir()
    target = tmp_path / 'source.c'
    target.write_text('int untouched;')
    try:
        (root / 'linked.c').symlink_to(target)
    except OSError:
        pytest.skip('native symbolic links unavailable')
    with pytest.raises(ValueError, match='linked'):
        B._source_files(root)
    assert target.read_text() == 'int untouched;'


@pytest.mark.usefixtures('substituted_factory')
def test_matrix_limit_precedes_tool_probe(monkeypatch, tmp_path):
    monkeypatch.setattr(B, 'MAX_MATRIX_CELLS', 1)
    monkeypatch.setattr(B, 'probe', lambda: pytest.fail('oversized matrix reached tool probing'))
    with pytest.raises(ValueError, match='cell limit'):
        B.build_pilot(tmp_path / 'store', profiles=('msvc-free', 'mingw-clang'), opts=('O2',))


@pytest.mark.usefixtures('substituted_factory')
def test_research_rerun_preserves_preexisting_label_evidence(tmp_path):
    store = tmp_path / 'store'
    first = B.build_pilot(store, profiles=('msvc-free',), opts=('O2',))
    path = Path(first['entries'][0]['labels_path'])
    path.write_bytes(b'previous separately owned labels')
    again = B.build_pilot(store, profiles=('msvc-free',), opts=('O2',))
    assert again['status'] == 'blocked'
    assert again['entries'][0]['stage'] == 'persist'
    assert path.read_bytes() == b'previous separately owned labels'


@pytest.mark.skipif(os.name != 'posix', reason='POSIX mutation of an open leaf')
@pytest.mark.parametrize('kind', ['build', 'pilot'])
@pytest.mark.parametrize('damage', ['replace-leaf', 'same-inode'])
def test_receipt_success_requires_exact_owned_leaf_bytes(monkeypatch, tmp_path, capsys, kind, damage):
    output = tmp_path / 'work' / 'receipt.json'
    output.parent.mkdir()
    sync = os.fsync

    def corrupt(fd):
        sync(fd)
        if damage == 'replace-leaf':
            output.rename(output.with_suffix('.retained'))
            output.write_bytes(b'foreign replacement')
        else:
            with output.open('r+b') as stream:
                stream.write(b'X' * output.stat().st_size)

    monkeypatch.setattr(os, 'fsync', corrupt)
    code, receipt = _invoke(monkeypatch, tmp_path, output, kind)
    assert code == 2
    error = json.loads(capsys.readouterr().out)
    assert error['receipt'] == receipt and error['status'] == 'error'
    if damage == 'replace-leaf':
        assert output.read_bytes() == b'foreign replacement'
        assert json.loads(output.with_suffix('.retained').read_bytes()) == receipt
    else:
        assert set(output.read_bytes()) == {ord('X')}


@pytest.mark.parametrize('kind', ['build', 'pilot'])
def test_short_receipt_write_keeps_completed_work(monkeypatch, tmp_path, capsys, kind):
    original = os.fdopen

    class ShortWriter:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def write(self, raw):
            return self.stream.write(raw[:-1])

        def __getattr__(self, name):
            return getattr(self.stream, name)

    def fdopen(fd, mode='r', *args, **kwargs):
        stream = original(fd, mode, *args, **kwargs)
        return ShortWriter(stream) if mode == 'w+b' else stream

    if os.name != 'posix':
        pytest.skip('POSIX descriptor wrapper control')
    monkeypatch.setattr(os, 'fdopen', fdopen)
    output = tmp_path / 'work' / 'receipt.json'
    output.parent.mkdir()
    code, receipt = _invoke(monkeypatch, tmp_path, output, kind)
    assert code == 2
    assert json.loads(capsys.readouterr().out)['receipt'] == receipt


def _unified_fixture(tmp_path, monkeypatch, *, cleanup_failure=False, wrong_bytes=False, cleanup_interrupt=False):
    doc = _labels()
    root = tmp_path / 'project'
    gzf = root / 'runs' / 'unit' / 'unified' / 'gzf'
    gzf.mkdir(parents=True)
    artifacts = []
    for label, own in (('older', doc.older), ('newer', doc.newer)):
        (gzf / f'{label}.gzf').write_bytes(b'unit-only packed program')
        (root / f'{label}.dll').write_bytes(b'unit-only image')
        artifacts.append(SimpleNamespace(side=label, sha256=own.sha256, relative_path=f'{label}.dll'))
    project = SimpleNamespace(artifacts=artifacts, runs=[SimpleNamespace(status='completed', id='unit')])
    service = SimpleNamespace(root=root, project=project)
    closed, extracted = [], []

    class Side:
        def __init__(self, label, *_args):
            self.label = label
            self.sha256 = '0' * 64 if wrong_bytes else getattr(doc, label).sha256

        def run(self, *_args):
            extracted.append(self.label)
            return {'directory': root, 'manifest': SimpleNamespace(content_digest='a' * 64),
                    'extract_seconds': 0.1, 'ingest_seconds': 0.2}

        def close(self):
            closed.append(self.label)
            if cleanup_interrupt and self.label == 'older':
                raise KeyboardInterrupt('unit cleanup cancellation')
            if cleanup_failure:
                raise OSError(f'{self.label} cleanup failed')

    monkeypatch.setattr(P, 'Side', Side)
    monkeypatch.setattr(P, 'place_ir', lambda *_a: None)
    outcome = SimpleNamespace(rows=[], rows_sha256='b' * 64, model_dump=lambda **_k: {'unit_only': True})
    monkeypatch.setattr(P, 'outcome_of', lambda *_a: outcome)
    return doc, service, closed, extracted


def test_warm_cache_and_cleanup_errors_keep_first_unified_result(tmp_path, monkeypatch):
    doc, service, closed, extracted = _unified_fixture(tmp_path, monkeypatch, cleanup_failure=True)
    attempts = []

    def pipeline(*_a):
        attempts.append(True)
        if len(attempts) == 2:
            raise OSError('warm cache unavailable')
        return SimpleNamespace(status='ok')

    monkeypatch.setattr(P.pipeline, 'run_unified', pipeline)
    result = P._unified(service, doc, doc, None, tmp_path / 'extraction')
    assert result['status'] == 'ok' and result['outcome'] == {'unit_only': True}
    assert result['observations'] == [] and result['coverage']['rows'] == 0
    assert result['warm_cache']['status'] == 'failed' and 'warm cache' in result['warm_cache']['reason']
    assert len(result['cleanup_errors']) == 2
    assert extracted == closed == ['older', 'newer']


def test_unified_cleanup_does_not_shadow_initial_failure(tmp_path, monkeypatch):
    doc, service, closed, _extracted = _unified_fixture(tmp_path, monkeypatch, cleanup_failure=True)

    def fail(*_a):
        raise ValueError('first comparison failed')

    monkeypatch.setattr(P.pipeline, 'run_unified', fail)
    with pytest.raises(ValueError, match='first comparison') as found:
        P._unified(service, doc, doc, None, tmp_path / 'extraction')
    assert closed == ['older', 'newer']
    assert any('cleanup' in note for note in found.value.__notes__)


def test_unified_refuses_wrong_opened_bytes_before_extraction(tmp_path, monkeypatch):
    doc, service, closed, extracted = _unified_fixture(tmp_path, monkeypatch, wrong_bytes=True)
    with pytest.raises(ValueError, match='input bytes'):
        P._unified(service, doc, doc, None, tmp_path / 'extraction')
    assert closed == ['older'] and extracted == []


@pytest.mark.parametrize('primary_failure', [False, True])
def test_unified_cleanup_interrupt_attempts_all_closes_and_preserves_primary(tmp_path, monkeypatch, primary_failure):
    doc, service, closed, _extracted = _unified_fixture(tmp_path, monkeypatch, cleanup_interrupt=True)

    def pipeline(*_a):
        if primary_failure:
            raise ValueError('first comparison failed')
        return SimpleNamespace(status='ok')

    monkeypatch.setattr(P.pipeline, 'run_unified', pipeline)
    expected = ValueError if primary_failure else KeyboardInterrupt
    with pytest.raises(expected) as found:
        P._unified(service, doc, doc, None, tmp_path / 'extraction')
    assert closed == ['older', 'newer']
    if primary_failure:
        assert 'first comparison' in str(found.value)
        assert any('KeyboardInterrupt' in note for note in found.value.__notes__)


def test_unified_cleanup_cancellation_is_not_suppressed_by_callers_active_exception(tmp_path, monkeypatch):
    doc, service, closed, _extracted = _unified_fixture(tmp_path, monkeypatch, cleanup_interrupt=True)
    monkeypatch.setattr(P.pipeline, 'run_unified', lambda *_a: SimpleNamespace(status='ok'))
    try:
        raise RuntimeError('unrelated caller failure')
    except RuntimeError as unrelated:
        with pytest.raises(KeyboardInterrupt, match='cleanup cancellation'):
            P._unified(service, doc, doc, None, tmp_path / 'extraction')
        assert not getattr(unrelated, '__notes__', [])
    assert closed == ['older', 'newer']


def _resumed_primary(tmp_path, monkeypatch):
    doc = _labels()
    root = tmp_path / 'project'
    root.mkdir()
    raw = {'old_meta': {'Executable SHA256': doc.older.sha256},
           'new_meta': {'Executable SHA256': doc.newer.sha256},
           'matches': {'address_matches': {}, 'name_matches': {}},
           'functions': {'modified': [], 'added': [], 'deleted': []}}
    path = root / 'raw.json'
    path.write_bytes(C.dump_json(raw))
    run = SimpleNamespace(id='unit', status='completed', raw_path='raw.json',
                          raw_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                          backend='ghidriff', backend_version='unit-only', settings={})
    artifacts = [SimpleNamespace(side=label, sha256=getattr(doc, label).sha256)
                 for label in ('older', 'newer')]
    service = SimpleNamespace(root=root, project=SimpleNamespace(artifacts=artifacts, runs=[run]), close=lambda: None)
    monkeypatch.setattr(P.ProjectService, 'open', lambda _path: service)
    return doc, service, path


def test_primary_cleanup_keeps_completed_result_and_attempts_secondary(tmp_path, monkeypatch):
    doc, service, _raw = _resumed_primary(tmp_path, monkeypatch)
    attempted = []

    def close():
        raise OSError('primary cleanup failed')

    def secondary(*_args, **_kwargs):
        def run(*_a):
            attempted.append(True)
            return SimpleNamespace(status='blocked', reason='unit-only secondary', version=None)
        return run

    service.close = close
    monkeypatch.setattr(P, 'RzDiffProvider', secondary)
    result = P.run_pilot(doc, tmp_path / 'store', SimpleNamespace(timeout_seconds=1), tmp_path / 'work',
                         rz_diff='unit-only', primary_project=service.root)
    primary = result['engines']['ghidriff']
    assert primary['status'] == 'ok' and primary['execution_provenance'] == 'persisted-native'
    assert primary['native_execution_in_this_invocation'] is False
    assert result['cleanup_error']['reason'] == 'primary cleanup failed'
    assert result['engines']['rz-diff']['status'] == 'blocked' and attempted == [True]


@pytest.mark.parametrize('damage', ['raw-byte-limit', 'raw-digest'])
def test_primary_raw_rejection_preserves_saved_evidence(tmp_path, monkeypatch, damage):
    doc, service, path = _resumed_primary(tmp_path, monkeypatch)
    if damage == 'raw-byte-limit':
        monkeypatch.setattr(P, 'MAX_IMPORT_BYTES', 8)
    else:
        path.write_bytes(path.read_bytes() + b' ')
    expected = path.read_bytes()
    result = P.run_pilot(doc, tmp_path / 'store', None, tmp_path / 'work', primary_project=service.root)
    assert result['engines']['ghidriff']['status'] == 'failed'
    assert result['engines']['unified']['status'] == 'not-run'
    assert path.read_bytes() == expected


def test_new_primary_hash_mismatch_precedes_backend_execution(tmp_path, monkeypatch):
    doc, service, _path = _resumed_primary(tmp_path, monkeypatch)
    service.project.artifacts[0].sha256 = '0' * 64
    closed = []
    service.close = lambda: closed.append(True)
    monkeypatch.setattr(P.ProjectService, 'create', lambda *_a: service)
    monkeypatch.setattr(P, 'image_path', lambda *_a: tmp_path / 'unit-only.dll')
    monkeypatch.setattr(P.backend_module, 'run_comparison', lambda *_a: pytest.fail('mismatched pair reached backend'))
    result = P.run_pilot(doc, tmp_path / 'store', None, tmp_path / 'work')
    assert result['engines']['ghidriff']['status'] == 'failed' and closed == [True]
    assert 'binding' in result['engines']['ghidriff']['reason']


@pytest.mark.parametrize('budget', ['functions', 'address-edges'])
def test_raw_row_budgets_precede_production_normalization(tmp_path, monkeypatch, budget):
    doc, service, path = _resumed_primary(tmp_path, monkeypatch)
    raw = json.loads(path.read_bytes())
    if budget == 'functions':
        monkeypatch.setattr(O, 'MAX_FUNCTIONS', 1)
        raw['functions']['added'] = [{'address': f'{doc.newer.image_base + rva:x}'} for rva in (1, 2)]
    else:
        monkeypatch.setattr(O, 'MAX_PREDICTIONS', 1)
        raw['matches']['address_matches'] = {f'{doc.older.image_base + 1:x}':
            [[f'{doc.newer.image_base + rva:x}', []] for rva in (1, 2)]}
    path.write_bytes(C.dump_json(raw))
    service.project.runs[0].raw_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(P, 'normalized', lambda *_a: pytest.fail('over-budget raw entered normalizer'))
    result = P.run_pilot(doc, tmp_path / 'store', None, tmp_path / 'work', primary_project=service.root)
    assert result['engines']['ghidriff']['status'] == 'failed'
    assert 'limit' in result['engines']['ghidriff']['reason']
    assert result['engines']['unified']['status'] == 'not-run'
