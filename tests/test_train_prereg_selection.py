"""Preregistration claims are backed by exact recorded bytes, before corpus access.

Only small constructed Tier R documents and temporary protocol files are used;
these tests do not open or consume a real locked evaluation.
"""
from __future__ import annotations

import hashlib
import json

import pytest
from test_train_helpers import write_world

from tools.calibration import train as T


@pytest.fixture
def protocol(tmp_path):
    path = tmp_path / 'protocol.md'
    path.write_bytes(b'constructed protocol, not a real preregistration\n')
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    qa = tmp_path / 'qa.md'
    qa.write_text(f'| C9-PREREG-v1 | {sha} | synthetic test record |\n', encoding='utf-8')
    return path, qa, sha


def args_for(tmp_path, protocol, *, command='run', unlocked=False, smoke=False):
    path, qa, _ = protocol
    args = T.build_parser().parse_args([
        command, '--rows', str(tmp_path / 'rows'), '--out', str(tmp_path / 'out'),
        '--prereg', str(path), *(['--smoke'] if smoke else []),
    ])
    # Keep the reproduction against the pre-repair parser meaningful: the old
    # _run sees the same request, rather than merely rejecting a new CLI option.
    args.qa = str(qa)
    args.unlocked_prereg = unlocked
    return args


@pytest.mark.parametrize('command', ['run', 'shift'])
@pytest.mark.parametrize('record', ['missing', 'mismatch', 'pending', 'ambiguous', 'lookalike', 'prose'])
def test_invalid_lock_record_is_rejected_before_corpus_read(tmp_path, protocol, monkeypatch, command, record):
    _, qa, sha = protocol
    texts = {
        'mismatch': f'| C9-PREREG-v1 | {"0" * 64} |\n',
        'pending': '| C9-PREREG-v1 | PENDING |\n',
        'ambiguous': f'| C9-PREREG-v1 | {sha} |\n| C9-PREREG-v1 | {"0" * 64} |\n',
        'lookalike': f'| NOT-C9-PREREG-v1 | {sha} |\n',
        'prose': f'Example C9-PREREG-v1 uses {sha} but is not a lock row.\n',
    }
    if record == 'missing':
        qa.unlink()
    else:
        qa.write_text(texts[record], encoding='utf-8')
    args = args_for(tmp_path, protocol, command=command)
    monkeypatch.setattr(T, '_inputs', lambda *_: pytest.fail('corpus opened before preregistration validation'))
    with pytest.raises(T.TrainError, match='PT-KA-PREREG'):
        T._run(args, only_shift=command == 'shift')
    assert not (tmp_path / 'out').exists()


@pytest.mark.parametrize('unlocked', [False, True])
def test_crlf_protocol_is_rejected_before_corpus_read(tmp_path, protocol, monkeypatch, unlocked):
    path, _, _ = protocol
    path.write_bytes(b'protocol\r\n')
    args = args_for(tmp_path, protocol, unlocked=unlocked)
    monkeypatch.setattr(T, '_inputs', lambda *_: pytest.fail('corpus opened before LF verification'))
    with pytest.raises(T.TrainError, match='CR'):
        T._run(args)


def test_verified_protocol_cannot_claim_smoke_configuration(tmp_path, protocol, monkeypatch):
    args = args_for(tmp_path, protocol, smoke=True)
    monkeypatch.setattr(T, '_inputs', lambda *_: pytest.fail('corpus opened for mislabeled smoke run'))
    with pytest.raises(T.TrainError, match='unlocked'):
        T._run(args)


def test_invalid_qa_encoding_is_a_controlled_preregistration_error(tmp_path, protocol, monkeypatch):
    protocol[1].write_bytes(b'\xff')
    args = args_for(tmp_path, protocol)
    monkeypatch.setattr(T, '_inputs', lambda *_: pytest.fail('corpus opened before QA verification'))
    with pytest.raises(T.TrainError, match='PT-KA-PREREG'):
        T._run(args)


def test_unlocked_flag_without_protocol_is_refused_before_corpus_read(tmp_path, protocol, monkeypatch):
    args = args_for(tmp_path, protocol, unlocked=True)
    args.prereg = None
    monkeypatch.setattr(T, '_inputs', lambda *_: pytest.fail('corpus opened for invalid request'))
    with pytest.raises(T.TrainError, match='requires --prereg'):
        T._run(args)


@pytest.mark.parametrize('unlocked', [False, True])
def test_real_small_report_uses_only_verified_protocol_sha(tmp_path, protocol, unlocked):
    labels, outputs = write_world(tmp_path / 'world', n_lineages=1, n_funcs=4)
    args = args_for(tmp_path, protocol, unlocked=unlocked)
    args.rows, args.labels, args.outputs = None, str(labels), str(outputs)
    if unlocked:
        protocol[1].unlink()  # An explicit rehearsal needs no claimed lock.
    code, summary = T._run(args)
    assert code == T.FINDINGS  # Too few independent lineages, never a passing calibration.
    report = json.loads((tmp_path / 'out' / 'report.json').read_bytes())
    assert report['prereg_sha256'] == (None if unlocked else protocol[2])
    assert report['dataset']['preregistered'] is (not unlocked)
    assert all(g['status'] == 'insufficient-data' for g in report['gates'].values())
    if unlocked:
        assert summary['unlocked_rehearsal']['source_sha256'] == protocol[2]
        args.prereg, args.unlocked_prereg, args.out = None, False, str(tmp_path / 'plain')
        _, plain = T._run(args)
        assert summary['train_key'] == plain['train_key']
        assert (tmp_path / 'plain' / 'report.json').read_bytes() == (tmp_path / 'out' / 'report.json').read_bytes()
    assert not list(tmp_path.rglob('*.lock'))


@pytest.mark.parametrize('command', ['run', 'shift'])
def test_cli_rejects_unrecorded_protocol_with_controlled_error(tmp_path, protocol, monkeypatch, capsys, command):
    path, qa, _ = protocol
    qa.unlink()
    monkeypatch.setattr(T, '_inputs', lambda *_: pytest.fail('CLI read inputs before validation'))
    code = T.main([command, '--rows', str(tmp_path / 'rows'), '--out', str(tmp_path / 'out'),
                   '--prereg', str(path), '--qa', str(qa)])
    assert code == T.USAGE
    error = json.loads(capsys.readouterr().err)
    assert error['code'] == 'PT-KA-PREREG' and error['status'] == 'error'
    assert not (tmp_path / 'out').exists()


def test_cli_rehearsal_flag_reaches_placeholder_report(tmp_path, protocol, capsys):
    path, qa, sha = protocol
    labels, outputs = write_world(tmp_path / 'world', n_lineages=1, n_funcs=4)
    qa.unlink()
    code = T.main(['run', '--labels', str(labels), '--outputs', str(outputs), '--out', str(tmp_path / 'out'),
                   '--prereg', str(path), '--qa', str(qa), '--unlocked-prereg', '--smoke'])
    assert code == T.FINDINGS
    summary = json.loads(capsys.readouterr().out)
    assert summary['unlocked_rehearsal']['source_sha256'] == sha
    report = json.loads((tmp_path / 'out' / 'report.json').read_bytes())
    assert report['prereg_sha256'] is None and not report['dataset']['preregistered']


@pytest.mark.parametrize('wrapper', [
    '```markdown\n{row}\n```',
    '~~~markdown\n{row}\n~~~',
    '````markdown\n```\n{row}\n````',
    '```markdown\n``` ```\n{row}\n```',
    '<!-- proposed future lock\n{row}\n-->',
    '    {row}',
    ' {row}',
    '  {row}',
    '   {row}',
    '\t{row}',
    ' \t{row}',
    '<!-- prefix -->{row}',
    '- ```markdown\n  {row}\n  ```',
])
def test_example_or_commented_rows_cannot_record_a_lock(tmp_path, protocol, monkeypatch, wrapper):
    _, qa, sha = protocol
    row = f'| C9-PREREG-v1 | {sha} |'
    qa.write_text('Example only, no lock:\n\n' + wrapper.format(row=row) + '\n', encoding='utf-8')
    monkeypatch.setattr(T, '_inputs', lambda *_: pytest.fail('corpus read with an example digest'))
    with pytest.raises(T.TrainError, match='PT-KA-PREREG'):
        T._run(args_for(tmp_path, protocol))


@pytest.mark.parametrize('example', [
    '```markdown\n{row}\n```',
    '<!-- example\n{row}\n-->',
    '```html\n<!-- unclosed only inside the example\n```',
])
def test_example_row_does_not_shadow_real_record(tmp_path, protocol, example):
    from tools.calibration.prereg_gate import select

    path, qa, sha = protocol
    false_row = f'| C9-PREREG-v1 | {"0" * 64} |'
    qa.write_text(example.format(row=false_row) + f'\n\n| C9-PREREG-v1 | {sha} |\n', encoding='utf-8')
    assert select(path, qa).sha == sha


@pytest.mark.parametrize('tag', ['pre', 'script', 'style', 'textarea', 'div', 'custom-element'])
@pytest.mark.parametrize('real_row_after', [False, True])
def test_raw_html_qa_is_refused_even_if_a_later_row_looks_valid(tmp_path, protocol, tag, real_row_after):
    from tools.calibration.prereg_gate import PreregGateError, select

    path, qa, sha = protocol
    row = f'| C9-PREREG-v1 | {sha} |'
    qa.write_text(f'<{tag}>\n{row}\n</{tag}>\n' + (f'\n{row}\n' if real_row_after else ''), encoding='utf-8')
    with pytest.raises(PreregGateError, match='unsupported QA format'):
        select(path, qa)


def test_inline_raw_html_cannot_hide_a_record(tmp_path, protocol):
    from tools.calibration.prereg_gate import PreregGateError, select

    path, qa, sha = protocol
    qa.write_text(f'Example <span hidden>\n| C9-PREREG-v1 | {sha} |\n</span>\n', encoding='utf-8')
    with pytest.raises(PreregGateError, match='unsupported QA format'):
        select(path, qa)


@pytest.mark.parametrize('opening', ['<pre\n>\n', '<script\n', '<div\nhidden>\n'])
def test_multiline_unclosed_html_is_refused(tmp_path, protocol, opening):
    from tools.calibration.prereg_gate import PreregGateError, select

    path, qa, sha = protocol
    qa.write_text(opening + f'| C9-PREREG-v1 | {sha} |\n', encoding='utf-8')
    with pytest.raises(PreregGateError, match='unsupported QA format'):
        select(path, qa)


def test_multiline_inline_code_is_conservatively_refused(tmp_path, protocol):
    from tools.calibration.prereg_gate import PreregGateError, select

    path, qa, sha = protocol
    qa.write_text(f'Example `\n| C9-PREREG-v1 | {sha} |\n`\n', encoding='utf-8')
    with pytest.raises(PreregGateError, match='unsupported QA format'):
        select(path, qa)


def test_existing_qa_prose_and_inline_path_examples_allow_a_real_record(tmp_path, protocol):
    from pathlib import Path

    from tools.calibration.prereg_gate import select

    path, qa, sha = protocol
    existing = (Path(__file__).resolve().parents[1] / 'docs' / 'qa.md').read_text(encoding='utf-8')
    qa.write_text(existing + f'\n\n| C9-PREREG-v1 | {sha} | synthetic test record |\n', encoding='utf-8')
    assert select(path, qa).sha == sha


@pytest.mark.parametrize('example', ['`<pre>` and ``<script> `literal` </script>``', '```html\n<pre>\n```'])
def test_html_as_code_is_allowed_before_a_visible_record(tmp_path, protocol, example):
    from tools.calibration.prereg_gate import select

    path, qa, sha = protocol
    qa.write_text(example + f'\n\n| C9-PREREG-v1 | {sha} |\n', encoding='utf-8')
    assert select(path, qa).sha == sha
