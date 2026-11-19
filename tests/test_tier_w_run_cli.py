"""CLI wiring to the real runner/store/publication path with an authored engine boundary.

Synthetic images are only read; the configured Python and Ghidra paths are never executed.
These tests establish adapter mechanics, not native engine compatibility.
"""
from __future__ import annotations

import hashlib
import json
import sys

import pytest
from test_tier_w_cli import CID, cli, invoke
from test_tier_w_cli import root as root
from test_tier_w_runner import FakeGhidriff, corpus

from tools.calibration import corpus as C
from tools.calibration.tier_w import runner as R
from tools.calibration.tier_w.contracts import load_run_record
from tools.calibration.tier_w.paths import Layout, write_json


@pytest.fixture
def configured(tmp_path, root):
    layout = Layout(root)
    doc = corpus(root)
    write_json(layout.pairs(CID), doc.model_dump(mode='json'))
    ghidra = tmp_path / 'configured-ghidra'
    properties = ghidra / 'Ghidra' / 'application.properties'
    properties.parent.mkdir(parents=True)
    properties.write_text('application.version=authored-fixture\n', encoding='utf-8')
    return layout, doc, ('--python', sys.executable, '--ghidra-dir', str(ghidra))


def run(capsys, root, config, *options):
    return invoke(capsys, root, 'run', *config, *options, '--corpus-id', CID)


def test_cli_runs_hidden_through_real_store_and_reuses_qualified_results(configured, root, capsys, monkeypatch):
    layout, _doc, config = configured
    fake = FakeGhidriff()

    def invoke_engine(*args):
        print('authored backend progress, not a summary')
        return fake(*args)

    monkeypatch.setattr(R, 'run_pair', invoke_engine)
    code, body = run(capsys, root, config, '--timeout', '600')
    assert code == 0 and body['status'] == body['attempt_status'] == 'ok'
    assert len(fake.calls) == 2 and body['pairs'] == 2 and body['matches'] == 4
    assert all(config.allow_symbol_downloads is False and config.timeout_seconds == 600
               for _pair, condition, config, _path in fake.calls if condition == 'h')
    selected = layout.matches(CID).with_name('run.json').read_bytes()
    record = load_run_record(selected)
    assert record.matches_sha256 == hashlib.sha256(layout.matches(CID).read_bytes()).hexdigest()
    assert (root / body['attempt_record']).read_bytes() == selected
    again_code, again = run(capsys, root, config, '--timeout', '600')
    assert again_code == 0 and again['attempt_record'] == body['attempt_record'] and len(fake.calls) == 2


def test_cancelled_rerun_receipt_names_attempt_and_preserves_selected_pair(configured, root, capsys, monkeypatch):
    layout, _doc, config = configured
    first_doc = corpus(root, names=('a',))
    write_json(layout.pairs(CID), first_doc.model_dump(mode='json'))
    monkeypatch.setattr(R, 'run_pair', FakeGhidriff())
    assert run(capsys, root, config)[0] == 0
    selected = {path: path.read_bytes() for path in (layout.matches(CID), layout.matches(CID).with_name('run.json'))}
    second_doc = corpus(root, names=('a', 'b'))
    write_json(layout.pairs(CID), second_doc.model_dump(mode='json'))
    fake = FakeGhidriff(after=lambda cancel: cancel.set())
    monkeypatch.setattr(R, 'run_pair', fake)
    code, body = run(capsys, root, config)
    assert code == 5 and body['status'] == body['attempt_status'] == 'cancelled'
    assert {path: path.read_bytes() for path in selected} == selected
    attempted = load_run_record((root / body['attempt_record']).read_bytes())
    assert attempted.status == 'cancelled' and attempted.pairs == 2
    assert len(fake.calls) == 1  # the first pair's provenance-qualified completed run was reused


@pytest.mark.parametrize('outcome,expected', [('missing', 3), ('failed', 1)])
def test_cli_keeps_blocked_and_failed_engine_results_distinct(configured, root, capsys, monkeypatch, outcome, expected):
    layout, _doc, config = configured
    doc = corpus(root, names=('z',), missing=(('z', 'older'),) if outcome == 'missing' else ())
    write_json(layout.pairs(CID), doc.model_dump(mode='json'))
    fake = FakeGhidriff(raises=(doc.pairs[0].id,))
    monkeypatch.setattr(R, 'run_pair', fake)
    code, body = run(capsys, root, config)
    assert code == expected and body['problems'] == 1
    assert len(fake.calls) == (outcome == 'failed')
    assert load_run_record((root / body['attempt_record']).read_bytes()).status == body['attempt_status']


@pytest.mark.parametrize('damage', ['foreign-corpus', 'unowned-prior'])
def test_cli_refuses_foreign_run_inputs_before_engine_work(configured, root, capsys, monkeypatch, damage):
    layout, doc, config = configured
    fake = FakeGhidriff()
    monkeypatch.setattr(R, 'run_pair', fake)
    if damage == 'foreign-corpus':
        write_json(layout.pairs(CID), doc.model_copy(update={'corpus_id': 'tier-w-other'}).model_dump(mode='json'))
    else:
        path = layout.matches(CID)
        path.parent.mkdir(parents=True)
        path.write_bytes(b'foreign unpaired prior output')
    code, body = run(capsys, root, config)
    assert code == (1 if damage == 'unowned-prior' else 2) and not fake.calls
    if damage == 'unowned-prior':
        assert body['code'] == 'PT-TIERW-VERIFY'
        assert layout.matches(CID).read_bytes() == b'foreign unpaired prior output'


def test_cli_empty_pairs_do_not_manufacture_a_successful_run(configured, root, capsys, monkeypatch):
    layout, doc, config = configured
    write_json(layout.pairs(CID), doc.model_copy(update={'pairs': ()}).model_dump(mode='json'))
    fake = FakeGhidriff()
    monkeypatch.setattr(R, 'run_pair', fake)
    code, body = run(capsys, root, config)
    assert code == 1 and body['pairs'] == 0 and not fake.calls and not layout.matches(CID).exists()
    assert 'attempt_record' not in body


def test_cli_refuses_online_condition_before_any_engine_or_output(configured, root, capsys, monkeypatch):
    layout, _doc, config = configured
    fake = FakeGhidriff()
    monkeypatch.setattr(R, 'run_pair', fake)
    code, body = run(capsys, root, config, '--condition', 'symbols-visible')
    assert code == 3 and body['code'] == 'PT-TIERW-BLOCKED' and not fake.calls
    assert not layout.matches(CID).exists()


@pytest.mark.parametrize('timeout', ['0', '-1', '59', '86401', 'nan'])
def test_cli_run_timeout_is_bounded_before_corpus_io(root, capsys, timeout):
    code, body = run(capsys, root, (), '--timeout', timeout)
    assert code == 2 and body['code'] == 'PT-TIERW-INPUT' and not root.exists()


def test_cli_requires_a_real_configured_backend_before_project_creation(configured, root, capsys, monkeypatch):
    layout, _doc, config = configured
    fake = FakeGhidriff()
    monkeypatch.setattr(R, 'run_pair', fake)
    code, body = run(capsys, root, config, '--python', str(root / 'missing-python'))
    assert code == 2 and body['code'] == 'PT-TIERW-CONFIG' and not fake.calls
    assert not layout.matches(CID).parent.exists()


def test_direct_native_cli_is_refused_in_ci(configured, root, capsys, monkeypatch):
    layout, _doc, config = configured
    fake = FakeGhidriff()
    monkeypatch.setattr(R, 'run_pair', fake)
    code = cli().main(['run', *config, '--corpus-id', CID], {C.ROOT_ENV: str(root), 'CI': 'true'})
    lines = capsys.readouterr().out.strip().splitlines()
    assert code == 2 and len(lines) == 1 and json.loads(lines[0])['code'] == 'PT-TIERW-CONFIG'
    assert not fake.calls and not layout.matches(CID).exists()
