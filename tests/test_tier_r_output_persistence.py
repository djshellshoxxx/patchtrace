"""Retain the exact normalized output behind each successful report reference.

All providers and labels here are constructed controls, never a native engine,
actual corpus evaluation, Tier W input, or numerical-calibration claim.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from test_tier_r_eval_metrics import FUNCS, make_labels

from tools.calibration.common import canonical_json
from tools.calibration.tier_r import cli
from tools.calibration.tier_r import contracts as C
from tools.calibration.tier_r import evaluate as E
from tools.calibration.tier_r import output_store as OS
from tools.calibration.tier_r import report_schemas as RS

LABELS = make_labels(FUNCS, pair_id='retained-synthetic')


def provider(engine='rz-diff', *, returned_engine=None):
    output = E.EngineOutput(
        returned_engine or engine, 'ok', version='constructed-control',
        predictions=(E.Prediction(0x1000, 0x1000, False, 1000), E.Prediction(0x1020, 0x1020, True, 900)),
    )
    return E.StaticProvider(engine, {LABELS.pair_id: output})


def store_labels(tmp_path):
    store = tmp_path / 'store'
    labels = store / 'labels'
    labels.mkdir(parents=True)
    (labels / f'{LABELS.pair_id}.json').write_bytes(C.dump_json(LABELS.model_dump(mode='json')))
    return store


def test_default_cli_retains_the_document_referenced_by_the_report(tmp_path, monkeypatch, capsys):
    store = store_labels(tmp_path)
    monkeypatch.setattr(cli.E, 'default_providers', lambda *args, **kwargs: [provider()])
    assert cli.main(['evaluate', '--store', str(store), '--engines', 'rz-diff']) == cli.OK
    result = json.loads(capsys.readouterr().out)
    report = C.load_report(Path(result['report']).read_bytes())
    files = [p for p in store.rglob('*.json')
             if hashlib.sha256(p.read_bytes()).hexdigest() == report.pairs[0].output_sha256]
    assert len(files) == 1, 'successful report digest has no retained normalized evidence'
    raw = files[0].read_bytes()
    doc = RS.load_engine_output(raw)
    assert doc.engine == 'rz-diff' and doc.older_sha256 == LABELS.older.sha256
    assert doc.newer_sha256 == LABELS.newer.sha256 and doc.symbols == 'hidden'
    assert files[0].parent == Path(result['outputs'])


def test_foreign_provider_engine_is_not_scored_or_credited():
    report = E.evaluate([LABELS], [provider(returned_engine='ghidriff')], b_count=20)
    pair = report['pairs'][0]
    assert pair['status'] == 'failed' and pair['output_sha256'] is None and pair['metrics'] is None
    assert report['engines'][0]['runs'] == 0


def test_duplicate_provider_ownership_is_rejected_before_execution():
    with pytest.raises(C.ContractError, match='duplicate.*engine'):
        E.evaluate([LABELS], [provider(), provider()], b_count=20)


def test_explicit_library_retention_keeps_visible_image_identity(tmp_path):
    outputs = tmp_path / 'outputs'
    report = E.evaluate([LABELS], [provider()], symbols='visible', output_dir=outputs, b_count=20)
    raw = (outputs / OS.output_file_name(LABELS.pair_id, 'rz-diff')).read_bytes()
    parsed = RS.load_engine_output(raw)
    assert parsed.older_sha256 == LABELS.older.debug_sha256
    assert parsed.newer_sha256 == LABELS.newer.debug_sha256 and parsed.symbols == 'visible'
    assert hashlib.sha256(raw).hexdigest() == report['pairs'][0]['output_sha256']


@pytest.mark.parametrize('existing', ['empty', 'nonempty', 'file', 'link'])
def test_existing_output_destination_is_never_adopted(tmp_path, existing):
    outputs = tmp_path / 'outputs'
    if existing in ('empty', 'nonempty'):
        outputs.mkdir()
        if existing == 'nonempty':
            (outputs / 'previous.json').write_bytes(b'previous evidence')
    elif existing == 'file':
        outputs.write_bytes(b'previous evidence')
    else:
        target = tmp_path / 'elsewhere'
        target.mkdir()
        try:
            outputs.symlink_to(target, target_is_directory=True)
        except OSError:
            pytest.skip('symlink creation unavailable on this test host')

    class MustNotRun:
        engine = 'rz-diff'

        def __call__(self, *args):
            pytest.fail('provider ran without an exclusive output directory')

    with pytest.raises(OS.OutputError, match='fresh output directory'):
        E.evaluate([LABELS], [MustNotRun()], output_dir=outputs, b_count=20)
    if existing == 'nonempty':
        assert (outputs / 'previous.json').read_bytes() == b'previous evidence'
    elif existing == 'file':
        assert outputs.read_bytes() == b'previous evidence'


@pytest.mark.parametrize('failure', [PermissionError('denied'), OSError('hard links unsupported'),
                                     NotImplementedError('hard links unavailable')])
def test_publication_failure_gets_no_metrics_or_digest(tmp_path, monkeypatch, failure):
    link = os.link

    def fail(src, dst, **kwargs):
        if Path(dst).name == OS.output_file_name(LABELS.pair_id, 'rz-diff'):
            raise failure
        return link(src, dst, **kwargs)

    monkeypatch.setattr(OS.os, 'link', fail)
    outputs = tmp_path / 'outputs'
    report = E.evaluate([LABELS], [provider()], output_dir=outputs, b_count=20)
    pair = report['pairs'][0]
    assert pair['status'] == 'failed' and pair['metrics'] is None and pair['output_sha256'] is None
    assert report['engines'][0]['runs'] == 0 and report['engines'][0]['failures'] == 1
    assert {p.name for p in outputs.iterdir()} == set(OS.MANAGED_FILES)


def test_later_write_failure_preserves_prior_success(tmp_path, monkeypatch):
    other = make_labels(FUNCS, pair_id='second-synthetic')
    answer = provider().outputs[LABELS.pair_id]
    owner = E.StaticProvider('rz-diff', {LABELS.pair_id: answer, other.pair_id: answer})
    link = os.link

    def fail_second(src, dst, **kwargs):
        if Path(dst).name.startswith(other.pair_id):
            raise PermissionError('injected second publication failure')
        return link(src, dst, **kwargs)

    monkeypatch.setattr(OS.os, 'link', fail_second)
    outputs = tmp_path / 'outputs'
    report = E.evaluate([LABELS, other], [owner], output_dir=outputs, b_count=20)
    first, second = report['pairs']
    assert first['status'] == 'ok' and second['status'] == 'failed'
    path = outputs / OS.output_file_name(LABELS.pair_id, 'rz-diff')
    assert hashlib.sha256(path.read_bytes()).hexdigest() == first['output_sha256']
    assert second['output_sha256'] is None and second['metrics'] is None
    assert report['engines'][0]['runs'] == 1 and report['engines'][0]['status'] == 'partial'


def test_racing_existing_artifact_is_never_replaced(tmp_path, monkeypatch):
    link = os.link
    previous = b'concurrent evidence must remain'

    def compete(src, dst, **kwargs):
        if Path(dst).name == OS.output_file_name(LABELS.pair_id, 'rz-diff'):
            Path(dst).write_bytes(previous)
        return link(src, dst, **kwargs)

    monkeypatch.setattr(OS.os, 'link', compete)
    outputs = tmp_path / 'outputs'
    report = E.evaluate([LABELS], [provider()], output_dir=outputs, b_count=20)
    path = outputs / OS.output_file_name(LABELS.pair_id, 'rz-diff')
    assert path.read_bytes() == previous
    assert report['pairs'][0]['status'] == 'failed' and report['pairs'][0]['output_sha256'] is None


def test_changed_published_bytes_are_not_credited(tmp_path, monkeypatch):
    link = os.link

    def corrupt(src, dst, **kwargs):
        result = link(src, dst, **kwargs)
        if Path(dst).name == OS.output_file_name(LABELS.pair_id, 'rz-diff'):
            Path(dst).write_bytes(b'changed after stage flush')
        return result

    monkeypatch.setattr(OS.os, 'link', corrupt)
    report = E.evaluate([LABELS], [provider()], output_dir=tmp_path / 'outputs', b_count=20)
    assert report['pairs'][0]['status'] == 'failed' and report['pairs'][0]['output_sha256'] is None


def test_output_directory_replacement_is_not_a_successful_run(tmp_path, monkeypatch):
    outputs, moved = tmp_path / 'outputs', tmp_path / 'original-run'
    publish = OS.publish_bytes

    def move_before_publication(path, raw):
        if Path(path).name == OS.output_file_name(LABELS.pair_id, 'rz-diff'):
            outputs.rename(moved)
            outputs.mkdir()
        return publish(path, raw)

    monkeypatch.setattr(OS, 'publish_bytes', move_before_publication)
    with pytest.raises(OS.OutputError, match='ownership changed'):
        E.evaluate([LABELS], [provider()], output_dir=outputs, b_count=20)
    assert moved.is_dir()


def test_capped_serialization_fails_without_publishing(tmp_path, monkeypatch):
    monkeypatch.setattr(OS, 'MAX_ENGINE_OUTPUT_BYTES', 50)
    outputs = tmp_path / 'outputs'
    report = E.evaluate([LABELS], [provider()], output_dir=outputs, b_count=20)
    assert report['pairs'][0]['status'] == 'failed' and report['pairs'][0]['output_sha256'] is None
    assert {p.name for p in outputs.iterdir()} == set(OS.MANAGED_FILES)


def test_repeated_cli_runs_keep_equal_reports_at_distinct_paths(tmp_path, monkeypatch, capsys):
    store = store_labels(tmp_path)
    monkeypatch.setattr(cli.E, 'default_providers', lambda *args, **kwargs: [provider()])
    args = ['evaluate', '--store', str(store), '--engines', 'rz-diff']
    assert cli.main(args) == cli.OK
    first = json.loads(capsys.readouterr().out)
    first_bytes = Path(first['report']).read_bytes()
    assert cli.main(args) == cli.OK
    second = json.loads(capsys.readouterr().out)
    assert first['report'] != second['report'] and first['outputs'] != second['outputs']
    assert first['report_sha256'] == second['report_sha256']
    assert Path(first['report']).read_bytes() == Path(second['report']).read_bytes() == first_bytes


@pytest.mark.parametrize('existing_suffix', ['.json', '.md'])
def test_cli_report_failure_retains_prior_bytes_and_completed_output(tmp_path, monkeypatch, capsys, existing_suffix):
    store = store_labels(tmp_path)
    monkeypatch.setattr(cli.E, 'default_providers', lambda *args, **kwargs: [provider()])
    output_path = tmp_path / 'report.json'
    previous = output_path.with_suffix(existing_suffix)
    previous.write_bytes(b'prior report must not change')
    assert cli.main(['evaluate', '--store', str(store), '--engines', 'rz-diff', '--out', str(output_path)]) == cli.USAGE
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'error' and previous.read_bytes() == b'prior report must not change'
    report = C.load_report(C.dump_json(result['report_data']))
    path = Path(result['outputs']) / OS.output_file_name(LABELS.pair_id, 'rz-diff')
    assert hashlib.sha256(path.read_bytes()).hexdigest() == report.pairs[0].output_sha256


def test_actual_attention_import_and_ranking_are_retained(tmp_path, capsys):
    from test_evalcore_engines import NEW_CODE, OLD_CODE, _fn, _ghidriff

    from tools.calibration import train
    from tools.calibration.evalcore.engines.attention import AttentionProvider

    store = store_labels(tmp_path)
    imports = store / 'imports'
    imports.mkdir()
    imported = _ghidriff(LABELS)
    imported['functions']['modified'][1]['new']['code'] = NEW_CODE
    imported['functions']['modified'].append(
        {'old': _fn('E', 0x1040, OLD_CODE), 'new': _fn('E', 0x1040, OLD_CODE), 'ratio': 0.99,
         'match_types': ['ExactBytes'], 'diff_type': ['code']})
    (imports / f'{LABELS.pair_id}.ghidriff.json').write_text(json.dumps(imported), encoding='utf-8')
    assert cli.main(['evaluate', '--store', str(store), '--engines', 'attention']) == cli.OK
    result = json.loads(capsys.readouterr().out)
    report = C.load_report(Path(result['report']).read_bytes())
    raw = (Path(result['outputs']) / OS.output_file_name(LABELS.pair_id, 'attention')).read_bytes()
    parsed = RS.load_engine_output(raw)
    assert parsed.engine == 'attention' and parsed.version == 'attention/1' and parsed.predictions
    assert any(p.order_key for p in parsed.predictions)
    assert hashlib.sha256(raw).hexdigest() == report.pairs[0].output_sha256
    original = AttentionProvider(imports)(LABELS, 'hidden')
    replay, replay_digest = train.load_outputs(Path(result['outputs']))[
        (LABELS.older.sha256, LABELS.newer.sha256, 'attention')]
    assert replay_digest == report.pairs[0].output_sha256
    assert sorted(p.order_key for p in original.predictions if p.changed) == [(1,), (2,)]
    assert any(not p.changed and p.order_key for p in original.predictions)
    assert E.to_engine_pairs(replay, 'hidden') == E.to_engine_pairs(original, 'hidden')
    assert E.score_pair(LABELS, replay) == E.score_pair(LABELS, original)
    assert raw == canonical_json(E.engine_output_doc(original, LABELS, 'hidden'))
    replay_report = E.evaluate([LABELS], [E.StaticProvider('attention', {LABELS.pair_id: replay})])
    assert C.dump_json(replay_report) == Path(result['report']).read_bytes()
    # Faithful loading does not make attention a calibration feature engine.
    with pytest.raises(train.TrainError, match='no usable engine output'):
        train.profile_for(('attention',))


def test_validation_preserves_original_bytes_and_absent_defaults(tmp_path):
    document = RS.example_engine_output()
    document.pop('version')
    document['predictions'][0].update(old_name='e\u0301\u00e9', order_key=[1, 2.5, 'e\u0301\u00e9'])
    raw = canonical_json(document)
    store = OS.OutputStore(tmp_path / 'outputs')
    digest = store.write('byte-control', 'rz-diff', document)
    retained = (store.folder / 'byte-control.rz-diff.json').read_bytes()
    assert retained == raw and OS.canonical_output_bytes(document) == raw
    assert digest == hashlib.sha256(raw).hexdigest()
    parsed = RS.load_engine_output(retained)
    assert tuple(type(p) for p in parsed.predictions[0].order_key) == (int, float, str)
    assert b'"version"' not in retained and 'e\u0301\u00e9' in retained.decode('utf-8')
    assert 'order_key' not in json.loads(retained)['predictions'][1]


def test_existing_no_key_fixture_retains_its_pinned_bytes(tmp_path):
    fixture = Path(__file__).resolve().parents[1] / 'docs/schemas/corpus/report-examples/valid-engine-output-rz-diff.json'
    # Exact original fixture/canonical bytes at source checkpoint 06b56a69320ce289cd0d1fb62675b4dc5b148fca.
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == '2d5f1487b3f13fa68f35e3701841b50ecdc33b9913cc022dc08a86da673be1c8'
    document = json.loads(fixture.read_bytes())
    raw = canonical_json(document)
    store = OS.OutputStore(tmp_path / 'outputs')
    digest = store.write('old-fixture', 'rz-diff', document)
    assert digest == '9eeadb7eeb97bec042bf91f4a34e020cf21e69d86620bbe9fc121b93c215af35'
    assert (store.folder / 'old-fixture.rz-diff.json').read_bytes() == raw
    assert b'order_key' not in raw


@pytest.mark.parametrize('pair_id', ['../escape', 'x/y', 'x\\y', '', 'a' * 97])
def test_output_name_cannot_escape_its_owner_directory(tmp_path, pair_id):
    store = OS.OutputStore(tmp_path / 'outputs')
    with pytest.raises(OS.OutputError, match='invalid pair identifier'):
        store.write(pair_id, 'rz-diff', RS.example_engine_output())
    assert {p.name for p in store.folder.iterdir()} == {OS.MANAGED_MARKER}


def test_invalid_or_foreign_document_never_publishes(tmp_path):
    store = OS.OutputStore(tmp_path / 'outputs')
    document = RS.example_engine_output()
    document['unexpected_payload'] = 'rejected'
    with pytest.raises(OS.OutputError, match='output invalid'):
        store.write('invalid', 'rz-diff', document)
    document = RS.example_engine_output()
    with pytest.raises(OS.OutputError, match='provider owner'):
        store.write('foreign', 'ghidriff', document)
    assert {p.name for p in store.folder.iterdir()} == {OS.MANAGED_MARKER}


@pytest.mark.parametrize('bad_key', [[True], [None], [[]], [{}], [1] * 17, ['x' * 513],
                                   [float('nan')], [float('inf')], [float('-inf')]])
def test_order_keys_reject_non_scalars_nonfinite_and_excessive_values(tmp_path, bad_key):
    document = RS.example_engine_output()
    document['predictions'][0]['order_key'] = bad_key
    store = OS.OutputStore(tmp_path / 'outputs')
    with pytest.raises(OS.OutputError):
        store.write('invalid-control', 'rz-diff', document)
    assert {p.name for p in store.folder.iterdir()} == {OS.MANAGED_MARKER}


def test_serialized_infinite_float_is_rejected_by_output_contract():
    document = RS.example_engine_output()
    document['predictions'][0]['order_key'] = [1.5]
    raw = canonical_json(document).replace(b'[1.5]', b'[1e999]')
    with pytest.raises(C.ContractError):
        RS.load_engine_output(raw)


def test_cli_explicit_output_directory_is_fresh_and_cannot_be_reused(tmp_path, monkeypatch, capsys):
    store = store_labels(tmp_path)
    outputs = tmp_path / 'chosen-run'
    monkeypatch.setattr(cli.E, 'default_providers', lambda *args, **kwargs: [provider()])
    args = ['evaluate', '--store', str(store), '--engines', 'rz-diff', '--outputs', str(outputs)]
    assert cli.main(args) == cli.OK
    first = json.loads(capsys.readouterr().out)
    assert first['outputs'] == str(outputs)
    evidence = {p.name: p.read_bytes() for p in outputs.iterdir()}
    assert cli.main(args) == cli.USAGE
    second = json.loads(capsys.readouterr().out)
    assert second['status'] == 'error' and 'fresh output directory' in second['error']
    assert {p.name: p.read_bytes() for p in outputs.iterdir()} == evidence


def test_api_retention_is_opt_in_and_does_not_change_report_bytes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    memory = E.evaluate([LABELS], [provider()], b_count=20)
    assert not list(tmp_path.iterdir())
    retained = E.evaluate([LABELS], [provider()], output_dir=tmp_path / 'outputs', b_count=20)
    assert C.dump_json(memory) == C.dump_json(retained)


def test_failed_stage_fsync_publishes_no_success(tmp_path, monkeypatch):
    fsync = os.fsync
    calls = 0

    def fail(*args):
        nonlocal calls
        calls += 1
        if calls == 2:  # Marker succeeds; this fault targets the following engine-output stage.
            raise OSError('injected storage flush failure')
        return fsync(*args)

    monkeypatch.setattr(OS.os, 'fsync', fail)
    outputs = tmp_path / 'outputs'
    report = E.evaluate([LABELS], [provider()], output_dir=outputs, b_count=20)
    assert report['pairs'][0]['status'] == 'failed' and report['pairs'][0]['metrics'] is None
    assert report['pairs'][0]['output_sha256'] is None
    assert {p.name for p in outputs.iterdir()} == set(OS.MANAGED_FILES)


def test_cli_default_output_publication_failure_is_a_failed_pair(tmp_path, monkeypatch, capsys):
    store = store_labels(tmp_path)
    monkeypatch.setattr(cli.E, 'default_providers', lambda *args, **kwargs: [provider()])
    link = os.link

    def deny_output(src, dst, **kwargs):
        if store / 'outputs' in Path(dst).parents and Path(dst).name == OS.output_file_name(LABELS.pair_id, 'rz-diff'):
            raise PermissionError('injected output permission failure')
        return link(src, dst, **kwargs)

    monkeypatch.setattr(OS.os, 'link', deny_output)
    assert cli.main(['evaluate', '--store', str(store), '--engines', 'rz-diff']) == cli.FINDINGS
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'failed' and result['engines'] == {'rz-diff': 'failed'}
    report = C.load_report(Path(result['report']).read_bytes())
    assert report.pairs[0].status == 'failed' and report.pairs[0].metrics is None
    assert report.pairs[0].output_sha256 is None
    assert {p.name for p in Path(result['outputs']).iterdir()} == set(OS.MANAGED_FILES)
