"""Small producer/CLI/actual-reader controls for #157; no corpus or training fit."""
from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path

import pytest
from test_tier_r_output_persistence import LABELS, provider, store_labels

from tools.calibration import train
from tools.calibration.common import canonical_json
from tools.calibration.common import digest as document_digest
from tools.calibration.tier_r import cli
from tools.calibration.tier_r import contracts as C
from tools.calibration.tier_r import evaluate as E
from tools.calibration.tier_r import output_store as OS
from tools.calibration.tier_r import report_schemas as RS


def answer_with_keys(keys):
    document = RS.example_engine_output()
    for prediction, key in zip(document['predictions'], keys, strict=True):
        prediction['changed'] = True
        if key is None:
            prediction.pop('order_key', None)
        else:
            prediction['order_key'] = key
    return document


@pytest.mark.parametrize('keys', [([1], ['first']), (['first'], None), ([0, 1], [0, 'next'])])
def test_incomparable_effective_keys_rejected_by_actual_reader_before_ranking(tmp_path, keys):
    raw = canonical_json(answer_with_keys(keys))
    with pytest.raises(C.ContractError, match='comparab'):
        RS.load_engine_output(raw)
    (tmp_path / 'answer.json').write_bytes(raw)
    with pytest.raises(train.TrainError, match='comparab'):
        train.load_outputs(tmp_path)


@pytest.mark.parametrize('keys', [([0, 1], [1, 'next']), ([1], [1, 0]), ([1], None), (None, None)])
def test_comparable_prefixes_fallback_and_ties_keep_existing_ranking(keys):
    document = answer_with_keys(keys)
    parsed = RS.load_engine_output(canonical_json(document))
    output = train._output_from_doc(parsed)
    from tools.calibration.evalcore.change import flagged_ranks
    assert len(flagged_ranks(E.to_engine_pairs(output, 'hidden'))) == 2
    assert E.engine_output_doc(output, LABELS, 'hidden')['predictions'] == document['predictions']


def test_invalid_scalar_is_rejected_before_its_json_encoding(tmp_path, monkeypatch):
    document = RS.example_engine_output()
    document['predictions'][0]['old_name'] = 'x' * 513
    encoded = []
    original = OS.json.JSONEncoder.iterencode

    def trace(self, value, *args, **kwargs):
        for chunk in original(self, value, *args, **kwargs):
            if 'x' * 513 in chunk:
                encoded.append(chunk)
            yield chunk

    store = OS.OutputStore(tmp_path / 'managed')
    monkeypatch.setattr(OS.json.JSONEncoder, 'iterencode', trace)
    with pytest.raises(OS.OutputError):
        store.write('invalid', 'rz-diff', document)
    assert encoded == []


@pytest.mark.parametrize('field,value', [('old_name', 'x' * 513), ('version', 'x' * 201)])
def test_invalid_producer_bounds_fail_consistently_without_or_with_retention(tmp_path, field, value):
    answer = provider().outputs[LABELS.pair_id]
    if field == 'version':
        answer = dataclasses.replace(answer, version=value)
    else:
        answer = dataclasses.replace(answer, predictions=(dataclasses.replace(answer.predictions[0], old_name=value),
                                                         *answer.predictions[1:]))
    owner = E.StaticProvider('rz-diff', {LABELS.pair_id: answer})
    for destination in (None, tmp_path / 'managed'):
        report = E.evaluate([LABELS], [owner], output_dir=destination, b_count=20)
        pair = report['pairs'][0]
        assert pair['status'] == 'failed' and pair['metrics'] is None and pair['output_sha256'] is None


def test_long_upstream_names_and_versions_are_preserved_through_score_and_retention(tmp_path):
    base = provider().outputs[LABELS.pair_id]
    long_name, long_version = 'visible-symbol-' + 'x' * 500, 'producer-version-' + 'v' * 500
    answer = dataclasses.replace(
        base, version=long_version,
        predictions=(dataclasses.replace(base.predictions[0], old_name=long_name, new_name=long_name),
                     *base.predictions[1:]))
    owner = E.StaticProvider('rz-diff', {LABELS.pair_id: answer})
    unretained = E.evaluate([LABELS], [owner], b_count=20)
    assert unretained['pairs'][0]['status'] == 'ok' and unretained['pairs'][0]['metrics'] is not None
    folder = tmp_path / 'outputs'
    retained = E.evaluate([LABELS], [owner], output_dir=folder, b_count=20)
    assert retained['pairs'][0]['status'] == 'ok' and retained['pairs'][0]['output_sha256']
    parsed = RS.load_engine_output((folder / OS.output_file_name(LABELS.pair_id, 'rz-diff')).read_bytes())
    assert parsed.predictions[0].old_name == long_name == parsed.predictions[0].new_name
    assert parsed.version == long_version
    feature_rows = train.build_pair_rows(
        LABELS, {'rz-diff': (train._output_from_doc(parsed), retained['pairs'][0]['output_sha256'])}, 'G')
    assert feature_rows.engine_runs[0].version == long_version


def test_failed_valid_json_is_preserved_but_not_adopted_by_actual_loader(tmp_path, monkeypatch):
    original = OS.os.link

    def mutate(source, destination, **kwargs):
        result = original(source, destination, **kwargs)
        if Path(destination).name.endswith('.rz-diff.json'):
            value = json.loads(Path(destination).read_bytes())
            value['predictions'][0]['old_name'] = 'valid but uncredited'
            Path(destination).write_bytes(canonical_json(value))
        return result

    monkeypatch.setattr(OS.os, 'link', mutate)
    folder = tmp_path / 'managed'
    report = E.evaluate([LABELS], [provider()], output_dir=folder, b_count=20)
    assert report['pairs'][0]['status'] == 'failed' and report['pairs'][0]['output_sha256'] is None
    assert RS.load_engine_output((folder / f'{LABELS.pair_id}.rz-diff.json').read_bytes())
    assert train.load_outputs(folder) == {}


def test_unfinished_managed_run_cannot_fall_back_to_loose_loading(tmp_path):
    store = OS.OutputStore(tmp_path / 'managed')
    store.write('pending', 'rz-diff', RS.example_engine_output())
    with pytest.raises(train.TrainError, match='credit|complet'):
        train.load_outputs(store.folder)


def test_actual_cli_credits_exact_bytes_and_reader_refuses_later_mutation(tmp_path, monkeypatch, capsys):
    store = store_labels(tmp_path)
    monkeypatch.setattr(cli.E, 'default_providers', lambda *args, **kwargs: [provider()])
    assert cli.main(['evaluate', '--store', str(store), '--engines', 'rz-diff']) == cli.OK
    summary = json.loads(capsys.readouterr().out)
    folder = Path(summary['outputs'])
    report = C.load_report(Path(summary['report']).read_bytes())
    loaded = train.load_outputs(folder)
    assert next(iter(loaded.values()))[1] == report.pairs[0].output_sha256
    path = folder / f'{LABELS.pair_id}.rz-diff.json'
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == report.pairs[0].output_sha256
    value = json.loads(raw)
    value['predictions'][0]['old_name'] = 'later valid mutation'
    path.write_bytes(canonical_json(value))
    with pytest.raises(train.TrainError, match='digest|bytes'):
        train.load_outputs(folder)
    assert path.exists()


def test_parent_of_even_one_managed_run_is_not_an_implicit_selection(tmp_path):
    E.evaluate([LABELS], [provider()], output_dir=tmp_path / 'run', b_count=20)
    with pytest.raises(train.TrainError, match='select|managed'):
        train.load_outputs(tmp_path)


def test_legacy_loading_is_explicitly_unverified_and_can_be_refused(tmp_path):
    (tmp_path / 'old.json').write_bytes(canonical_json(RS.example_engine_output()))
    with pytest.warns(train.LegacyOutputWarning, match='unverified'):
        assert len(train.load_outputs(tmp_path)) == 1
    with pytest.raises(train.TrainError, match='legacy'):
        train.load_outputs(tmp_path, allow_legacy=False)


@pytest.mark.parametrize('state', ['missing-credit', 'broken-marker-link', 'broken-credit-link', 'bad-marker',
                                  'unreadable-marker', 'credit-without-marker'])
def test_managed_metadata_failures_never_select_legacy(tmp_path, monkeypatch, state):
    folder = tmp_path / 'managed'
    E.evaluate([LABELS], [provider()], output_dir=folder, b_count=20)
    marker, credit = folder / OS.MANAGED_MARKER, folder / OS.CREDIT_FILE
    if state == 'missing-credit':
        credit.unlink()
    elif state in ('broken-marker-link', 'broken-credit-link'):
        path = marker if state == 'broken-marker-link' else credit
        path.unlink()
        try:
            path.symlink_to(folder / 'missing-target')
        except OSError:
            pytest.skip('symlink creation unavailable on this test host')
    elif state == 'bad-marker':
        marker.write_bytes(b'{}')
    elif state == 'credit-without-marker':
        marker.unlink()
    else:
        read = OS.read_output_bytes

        def deny(path, *args):
            if Path(path) == marker:
                raise OS.OutputError('marker unreadable: injected permission failure')
            return read(path, *args)

        monkeypatch.setattr(OS, 'read_output_bytes', deny)
    with pytest.raises(train.TrainError):
        train.load_outputs(folder)
    assert (folder / f'{LABELS.pair_id}.rz-diff.json').is_file()


@pytest.mark.parametrize('field,value', [('older_sha256', 'f' * 64), ('newer_sha256', 'f' * 64),
                                       ('engine', 'ghidriff'), ('symbols', 'visible'), ('version', 'other'),
                                       ('pair_id', 'foreign'), ('report_sha256', 'f' * 64),
                                       ('output_sha256', 'f' * 64)])
def test_credit_owner_and_exact_byte_binding_cannot_be_substituted(tmp_path, field, value):
    folder = tmp_path / 'managed'
    E.evaluate([LABELS], [provider()], output_dir=folder, b_count=20)
    assert len(train.load_outputs(folder)) == 1
    path = folder / OS.CREDIT_FILE
    manifest = json.loads(path.read_bytes())
    manifest['outputs'][0][field] = value
    path.write_bytes(canonical_json(manifest))
    with pytest.raises(train.TrainError):
        train.load_outputs(folder)


@pytest.mark.parametrize('mutation', ['duplicate-record', 'duplicate-report', 'duplicate-pair', 'foreign-input',
                                     'failed-credit', 'missing-success-digest', 'bad-report-digest'])
def test_reports_must_uniquely_credit_the_retained_owner(tmp_path, mutation):
    folder = tmp_path / 'managed'
    E.evaluate([LABELS], [provider()], output_dir=folder, b_count=20)
    path = folder / OS.CREDIT_FILE
    manifest = json.loads(path.read_bytes())
    report = manifest['reports'][0]
    if mutation == 'duplicate-record':
        manifest['outputs'].append(manifest['outputs'][0])
    elif mutation == 'duplicate-report':
        manifest['reports'].append(report)
    elif mutation == 'duplicate-pair':
        report['pairs'].append(report['pairs'][0])
    elif mutation == 'foreign-input':
        report['inputs'][0]['pair_id'] = 'other-input'
    elif mutation == 'failed-credit':
        report['pairs'][0]['status'] = 'failed'
    elif mutation == 'missing-success-digest':
        report['pairs'][0]['output_sha256'] = None
    else:
        report['notes'].append('changed without updating digest')
    if mutation not in ('duplicate-record', 'duplicate-report', 'bad-report-digest'):
        report['report_sha256'] = document_digest(report, 'report_sha256')
        manifest['outputs'][0]['report_sha256'] = report['report_sha256']
    path.write_bytes(canonical_json(manifest))
    with pytest.raises(train.TrainError):
        train.load_outputs(folder)


def test_finalize_rechecks_written_bytes_before_credit(tmp_path):
    store = OS.OutputStore(tmp_path / 'managed')
    answer = provider().outputs[LABELS.pair_id]
    store.write(LABELS.pair_id, 'rz-diff', E.engine_output_doc(answer, LABELS, 'hidden'))
    report = E.evaluate([LABELS], [provider()], b_count=20)
    path = store.folder / f'{LABELS.pair_id}.rz-diff.json'
    changed = json.loads(path.read_bytes())
    changed['predictions'][0]['old_name'] = 'changed after write returned'
    path.write_bytes(canonical_json(changed))
    with pytest.raises(OS.OutputError, match='digest'):
        store.finalize([report])
    assert path.exists() and not (store.folder / OS.CREDIT_FILE).exists()
    with pytest.raises(train.TrainError, match='completed'):
        train.load_outputs(store.folder)


def test_credit_publication_failure_withholds_the_evaluation_report(tmp_path, monkeypatch):
    link = OS.os.link

    def deny(source, destination, **kwargs):
        if Path(destination).name == OS.CREDIT_FILE:
            raise OSError('credit publication unavailable')
        return link(source, destination, **kwargs)

    monkeypatch.setattr(OS.os, 'link', deny)
    folder = tmp_path / 'managed'
    with pytest.raises(OS.OutputError):
        E.evaluate([LABELS], [provider()], output_dir=folder, b_count=20)
    assert (folder / f'{LABELS.pair_id}.rz-diff.json').is_file()
    with pytest.raises(train.TrainError, match='incomplete'):
        train.load_outputs(folder)


def test_marker_publication_precedes_every_provider(tmp_path, monkeypatch):
    class MustNotRun:
        engine = 'rz-diff'

        def __call__(self, *args):
            pytest.fail('provider ran before its managed marker was published')

    def deny(*args, **kwargs):
        raise NotImplementedError('hardlinks unavailable')

    monkeypatch.setattr(OS.os, 'link', deny)
    with pytest.raises(OS.OutputError):
        E.evaluate([LABELS], [MustNotRun()], output_dir=tmp_path / 'managed', b_count=20)
    assert not list((tmp_path / 'managed').iterdir())


def test_duplicate_and_unflagged_keys_follow_existing_scorer_selection():
    document = answer_with_keys(([1], ['unselected']))
    document['predictions'][1].update(old_rva=document['predictions'][0]['old_rva'],
                                       new_rva=document['predictions'][0]['new_rva'])
    parsed = RS.load_engine_output(canonical_json(document))
    assert len(E.to_engine_pairs(train._output_from_doc(parsed), 'hidden').pairs) == 3  # one match + old/new only
    document = answer_with_keys(([1], ['unflagged']))
    document['predictions'][1]['changed'] = False
    assert RS.load_engine_output(canonical_json(document))


def test_transfer_api_preserves_raw_bytes_and_multiple_report_owners(tmp_path):
    from test_tier_r_eval_metrics import FUNCS, make_labels

    other = make_labels(FUNCS, pair_id='other-transfer')
    answer = provider().outputs[LABELS.pair_id]
    store = OS.OutputStore(tmp_path / 'managed')
    reports = []
    for labels in (LABELS, other):
        owner = E.StaticProvider('rz-diff', {labels.pair_id: answer})
        reports.append(E.evaluate([labels], [owner], b_count=20))
        raw = canonical_json(E.engine_output_doc(answer, labels, 'hidden'))
        assert store.write_raw(labels.pair_id, 'rz-diff', raw) == hashlib.sha256(raw).hexdigest()
        assert (store.folder / f'{labels.pair_id}.rz-diff.json').read_bytes() == raw
    store.finalize(reports)
    assert len(train.load_outputs(store.folder, allow_legacy=False)) == 2
    assert all((store.folder / name).is_file() for name in OS.MANAGED_FILES)
    with pytest.raises(OS.OutputError, match='finalized'):
        store.write_raw('later', 'rz-diff', raw)


def test_existing_unified_in_memory_provider_remains_supported_without_widening_storage(tmp_path):
    from test_evalcore_unified import FIXTURES
    from test_evalcore_unified import LABELS as unified_labels

    from tools.calibration.evalcore.engines.unified import UnifiedProvider

    owner = UnifiedProvider(FIXTURES)
    answer = owner(unified_labels, 'hidden')
    report = E.evaluate([unified_labels], [owner], b_count=20)
    assert report['pairs'][0]['status'] == 'ok'
    assert report['pairs'][0]['output_sha256'] == RS.output_sha256(E.engine_output_doc(answer, unified_labels, 'hidden'))
    stored = E.evaluate([unified_labels], [owner], output_dir=tmp_path / 'managed', b_count=20)
    assert stored['pairs'][0]['status'] == 'failed'
    assert stored['pairs'][0]['metrics'] is None and stored['pairs'][0]['output_sha256'] is None
    assert train.load_outputs(tmp_path / 'managed', allow_legacy=False) == {}


def test_incomparable_producer_is_refused_before_metrics_on_both_paths(tmp_path):
    answer = provider().outputs[LABELS.pair_id]
    predictions = tuple(dataclasses.replace(row, changed=True, order_key=key)
                        for row, key in zip(answer.predictions[:2], ((1,), ('first',)), strict=True))
    owner = E.StaticProvider('rz-diff', {LABELS.pair_id: dataclasses.replace(answer, predictions=predictions)})
    for destination in (None, tmp_path / 'managed'):
        report = E.evaluate([LABELS], [owner], output_dir=destination, b_count=20)
        pair = report['pairs'][0]
        assert pair['status'] == 'failed' and pair['metrics'] is None and pair['output_sha256'] is None
        assert 'comparab' in pair['reason']
