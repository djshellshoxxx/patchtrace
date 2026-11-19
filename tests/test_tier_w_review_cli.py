"""Offline audit -> authored terminal responses -> real chained log -> audit report.

Only self-made PE/PDB fixtures are read. No target, backend or network executes.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import stat
import sys

import pytest
from test_tier_w_cli import CID, invoke, labelled, step, write_matches
from test_tier_w_cli import root as root

from tools.calibration.label import AnnotationLog
from tools.calibration.tier_w.audit import AuditReport
from tools.calibration.tier_w.contracts import load_audit_key


@pytest.fixture
def prepared(tmp_path, capsys, root):
    return labelled(tmp_path, capsys, root)


def audit(capsys, root):
    return step(capsys, root, 'audit', '--seed', 'authored-seed', '--rate', '1')


def queue(layout):
    path = layout.review_dir(CID) / 'queue.jsonl'
    return [json.loads(line) for line in path.read_bytes().splitlines()]


class Terminal(io.StringIO):
    def isatty(self):
        return True


def one_response(monkeypatch, capsys, root, answer='d'):
    monkeypatch.setattr(sys, 'stdin', Terminal(f'{answer}\n\nq\n'))
    return invoke(capsys, root, 'review', '--annotator', 'authored-reviewer', '--corpus-id', CID)


def test_audit_truth_fallback_is_bound_blind_and_reads_real_bytes(prepared, root, capsys):
    result = audit(capsys, root)
    key_raw = (prepared.review_dir(CID) / 'audit-key.json').read_bytes()
    key = load_audit_key(key_raw)
    header, *items = queue(prepared)
    assert key.population == result['population'] == 'truth'
    assert len(items) == len(key.items) == result['sampled'] == 15
    assert header['audit_sha256'] == hashlib.sha256(key_raw).hexdigest()
    assert header['corpus_id'] == key.corpus_id == CID
    assert all(set(item) == {'pair', 'match_id', 'stratum', 'older', 'newer'} for item in items)
    assert all(set(item[side]) == {'rva', 'size', 'body_sha256', 'preview_hex'}
               for item in items for side in ('older', 'newer'))
    assert all(0 < len(item['older']['preview_hex']) <= 256 for item in items)
    assert all(len(item['older']['body_sha256']) == 64 for item in items)
    assert not (prepared.review_dir(CID) / 'annotations.jsonl').exists()


def test_audit_prefers_candidate_population(prepared, root, capsys):
    write_matches(root)
    step(capsys, root, 'labels')
    result = audit(capsys, root)
    key = load_audit_key((prepared.review_dir(CID) / 'audit-key.json').read_bytes())
    assert key.population == result['population'] == 'candidates'
    assert {item.match_id for item in key.items} == {item['match_id'] for item in queue(prepared)[1:]}
    assert all(item.match_id.startswith('m') for item in key.items)


def test_identical_audit_reuses_bytes_but_changed_seed_preserves_prior(prepared, root, capsys):
    audit(capsys, root)
    folder = prepared.review_dir(CID)
    before = {p.name: p.read_bytes() for p in folder.iterdir()}
    again = audit(capsys, root)
    assert again['reused'] is True
    assert {p.name: p.read_bytes() for p in folder.iterdir()} == before
    code, body = invoke(capsys, root, 'audit', '--seed', 'another-seed', '--rate', '1', '--corpus-id', CID)
    assert code == 2 and body['code'] == 'PT-TIERW-INPUT'
    assert {p.name: p.read_bytes() for p in folder.iterdir()} == before


def test_human_terminal_log_resume_and_real_error_report(prepared, root, capsys, monkeypatch):
    audit(capsys, root)
    code, body = one_response(monkeypatch, capsys, root)
    assert code == 1 and body['recorded'] == 1 and body['remaining'] == 14
    folder = prepared.review_dir(CID)
    path = folder / 'annotations.jsonl'
    [event] = AnnotationLog(path).events()
    assert event['A'] == 'different' and event['phase'] == 'blind'
    assert event['corpus_id'] == CID and event['tier'] == 'W'
    assert event['audit_sha256'] == hashlib.sha256((folder / 'audit-key.json').read_bytes()).hexdigest()
    assert event['queue_sha256'] == hashlib.sha256((folder / 'queue.jsonl').read_bytes()).hexdigest()
    before = path.read_bytes()
    monkeypatch.setattr(sys, 'stdin', Terminal('q\n'))
    code, body = invoke(capsys, root, 'review', '--annotator', 'authored-reviewer', '--corpus-id', CID)
    assert code == 1 and body['recorded'] == 0 and path.read_bytes() == before
    code, body = invoke(capsys, root, 'audit-report', '--corpus-id', CID)
    report = AuditReport.model_validate_json((folder / 'audit-report.json').read_bytes())
    assert code == 1 and body['audit_status'] == report.status == 'insufficient'
    assert report.reviewed == 1 and sum(part.errors for part in report.strata.values()) == 1


def test_no_reviewed_answers_remain_insufficient(prepared, root, capsys):
    audit(capsys, root)
    code, body = invoke(capsys, root, 'audit-report', '--corpus-id', CID)
    assert code == 1 and body['audit_status'] == 'insufficient' and body['reviewed'] == 0
    assert not (prepared.review_dir(CID) / 'annotations.jsonl').exists()


def test_noninteractive_review_is_blocked_without_fabricated_answers(prepared, root, capsys, monkeypatch):
    audit(capsys, root)
    monkeypatch.setattr(sys, 'stdin', io.StringIO('s\n'))
    code, body = invoke(capsys, root, 'review', '--annotator', 'owner', '--corpus-id', CID)
    assert code == 3 and body['status'] == 'blocked'
    assert not (prepared.review_dir(CID) / 'annotations.jsonl').exists()


@pytest.mark.parametrize('damage', ['foreign-pair', 'conflicting-duplicate'])
def test_audit_refuses_label_ownership_before_writing(prepared, root, capsys, damage):
    path = next(prepared.labels_dir(CID).glob('*.detail.jsonl'))
    rows = [json.loads(line) for line in path.read_bytes().splitlines()]
    if damage == 'foreign-pair':
        rows[0]['pair'] = 'tw.foreign.0000000000'
    else:
        other = copy.deepcopy(rows[0])
        other['older']['size'] += 1
        rows.append(other)
    path.write_text('\n'.join(json.dumps(row) for row in rows) + '\n', encoding='utf-8')
    code, body = invoke(capsys, root, 'audit', '--rate', '1', '--corpus-id', CID)
    assert code == 2 and body['code'] == 'PT-TIERW-INPUT'
    assert not prepared.review_dir(CID).exists()


@pytest.mark.parametrize('damage', ['foreign-corpus', 'hidden-field', 'duplicate', 'wrong-binding'])
def test_review_refuses_unbound_or_unblinded_queue_before_prompt(prepared, root, capsys, monkeypatch, damage):
    audit(capsys, root)
    path = prepared.review_dir(CID) / 'queue.jsonl'
    rows = queue(prepared)
    if damage == 'foreign-corpus':
        rows[0]['corpus_id'] = 'tier-w-other'
    elif damage == 'hidden-field':
        rows[1]['name'] = 'must not reach annotator'
    elif damage == 'duplicate':
        rows[2] = rows[1]
    else:
        rows[0]['audit_sha256'] = 'f' * 64
    path.write_text('\n'.join(json.dumps(row) for row in rows) + '\n', encoding='utf-8')
    monkeypatch.setattr(sys, 'stdin', Terminal('s\n'))
    code, body = invoke(capsys, root, 'review', '--annotator', 'owner', '--corpus-id', CID)
    assert code == 2 and body['code'] == 'PT-TIERW-INPUT'
    assert not (prepared.review_dir(CID) / 'annotations.jsonl').exists()


@pytest.mark.parametrize('damage', ['chain', 'foreign-key', 'second-annotator'])
def test_audit_report_refuses_foreign_or_changed_annotations_and_keeps_prior(prepared, root, capsys, monkeypatch, damage):
    audit(capsys, root)
    one_response(monkeypatch, capsys, root)
    invoke(capsys, root, 'audit-report', '--corpus-id', CID)
    folder = prepared.review_dir(CID)
    report = folder / 'audit-report.json'
    before = report.read_bytes()
    log = folder / 'annotations.jsonl'
    event = json.loads(log.read_bytes())
    if damage == 'chain':
        event['A'] = 'same'
        log.write_text(json.dumps(event) + '\n', encoding='utf-8')
    elif damage == 'foreign-key':
        event['audit_sha256'] = 'e' * 64
        from tools.calibration.common import canonical_json
        event['sha256'] = hashlib.sha256(canonical_json({k: v for k, v in event.items() if k != 'sha256'})).hexdigest()
        log.write_text(json.dumps(event) + '\n', encoding='utf-8')
    else:
        values = {k: v for k, v in event.items() if k not in {'seq', 'prev_sha256', 'sha256'}}
        values.update(annotator='second-person', match_id=queue(prepared)[2]['match_id'])
        AnnotationLog(log).append(**values)
    code, body = invoke(capsys, root, 'audit-report', '--corpus-id', CID)
    assert code == 2 and body['code'] == 'PT-TIERW-INPUT' and report.read_bytes() == before


@pytest.mark.parametrize('option,value', [('--rate', 'nan'), ('--rate', '0'), ('--size-change', 'inf'),
                                         ('--size-change', '-1'), ('--seed', 's' * 65)])
def test_audit_parameters_are_validated_before_io(root, capsys, option, value):
    code, body = invoke(capsys, root, 'audit', option, value, '--corpus-id', CID)
    assert code == 2 and body['code'] == 'PT-TIERW-INPUT' and not root.exists()


@pytest.mark.parametrize('damage', ['binary-identity', 'label-bytes', 'population-count'])
def test_report_cannot_reuse_audit_after_its_population_changes(prepared, root, capsys, damage):
    audit(capsys, root)
    invoke(capsys, root, 'audit-report', '--corpus-id', CID)
    folder = prepared.review_dir(CID)
    report = folder / 'audit-report.json'
    before = report.read_bytes()
    if damage == 'binary-identity':
        path = prepared.pairs(CID)
        raw = json.loads(path.read_bytes())
        raw['binaries'][0]['sha256'] = 'e' * 64
        path.write_text(json.dumps(raw), encoding='utf-8')
    elif damage == 'label-bytes':
        path = next(prepared.labels_dir(CID).glob('*.detail.jsonl'))
        path.write_bytes(path.read_bytes() + path.read_bytes().splitlines()[0] + b'\n')
    else:
        path = folder / 'audit-key.json'
        raw = json.loads(path.read_bytes())
        raw['population_counts']['random'] += 100
        path.write_text(json.dumps(raw), encoding='utf-8')
        rows = queue(prepared)
        rows[0]['audit_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        (folder / 'queue.jsonl').write_text('\n'.join(json.dumps(row) for row in rows) + '\n', encoding='utf-8')
    code, body = invoke(capsys, root, 'audit-report', '--corpus-id', CID)
    assert code == 2 and body['code'] == 'PT-TIERW-INPUT' and report.read_bytes() == before


@pytest.mark.parametrize('damage', ['foreign-corpus', 'malformed'])
def test_report_refuses_to_replace_unowned_prior_report(prepared, root, capsys, damage):
    audit(capsys, root)
    invoke(capsys, root, 'audit-report', '--corpus-id', CID)
    path = prepared.review_dir(CID) / 'audit-report.json'
    raw = json.loads(path.read_bytes())
    raw['corpus_id'] = 'tier-w-other'
    path.write_text(json.dumps(raw) if damage == 'foreign-corpus' else '{', encoding='utf-8')
    before = path.read_bytes()
    code, body = invoke(capsys, root, 'audit-report', '--corpus-id', CID)
    assert code == 2 and body['code'] == 'PT-TIERW-INPUT' and path.read_bytes() == before


def test_label_population_has_a_total_input_byte_budget(prepared, root, capsys, monkeypatch):
    from tools.calibration.tier_w import review_cli
    path = next(prepared.labels_dir(CID).glob('*.detail.jsonl'))
    monkeypatch.setattr(review_cli, 'POPULATION_BYTES', len(path.read_bytes()) - 1, raising=False)
    code, _body = invoke(capsys, root, 'audit', '--rate', '1', '--corpus-id', CID)
    assert code == 2 and not prepared.review_dir(CID).exists()


def test_append_budget_preserves_completed_human_answers(prepared, root, capsys, monkeypatch):
    from tools.calibration.tier_w import review_cli
    audit(capsys, root)
    one_response(monkeypatch, capsys, root)
    path = prepared.review_dir(CID) / 'annotations.jsonl'
    before = path.read_bytes()
    monkeypatch.setattr(review_cli, 'LOG_LIMIT', len(before) + 1, raising=False)
    code, body = one_response(monkeypatch, capsys, root)
    assert code == 2 and body['code'] == 'PT-TIERW-LIMIT' and path.read_bytes() == before


@pytest.mark.parametrize('damage', ['rva', 'body-sha', 'preview', 'image-bytes'])
def test_review_revalidates_actual_bytes_before_accepting_answers(prepared, root, capsys, monkeypatch, damage):
    audit(capsys, root)
    if damage == 'image-bytes':
        binary = next((root / 'binaries').rglob('*.dll'))
        raw = bytearray(binary.read_bytes())
        raw[-1] ^= 1
        binary.write_bytes(raw)
    else:
        rows = queue(prepared)
        side = rows[1]['older']
        if damage == 'rva':
            side['rva'] += 1
        elif damage == 'body-sha':
            side['body_sha256'] = 'f' * 64
        else:
            side['preview_hex'] = 'ff'
        (prepared.review_dir(CID) / 'queue.jsonl').write_text(
            '\n'.join(json.dumps(row) for row in rows) + '\n', encoding='utf-8')
    code, body = one_response(monkeypatch, capsys, root)
    assert code == 2 and body['code'] == 'PT-TIERW-INPUT'
    assert not (prepared.review_dir(CID) / 'annotations.jsonl').exists()


def test_cancellation_during_verified_image_open_keeps_prior_audit(prepared, root, capsys, monkeypatch):
    from tools.calibration.tier_w import review_cli
    audit(capsys, root)
    folder = prepared.review_dir(CID)
    before = {path.name: path.read_bytes() for path in folder.iterdir()}
    real_view = review_cli.PeView

    def cancel_then_open(*args, **kwargs):
        prepared.cancel_file.touch()
        return real_view(*args, **kwargs)

    monkeypatch.setattr(review_cli, 'PeView', cancel_then_open)
    code, body = invoke(capsys, root, 'audit', '--seed', 'authored-seed', '--rate', '1', '--corpus-id', CID)
    assert code == 5 and body['code'] == 'PT-TIERW-CANCEL'
    assert {path.name: path.read_bytes() for path in folder.iterdir()} == before


def test_hardlinked_annotation_target_is_not_appended(prepared, root, capsys, monkeypatch, tmp_path):
    audit(capsys, root)
    one_response(monkeypatch, capsys, root)
    path = prepared.review_dir(CID) / 'annotations.jsonl'
    before = path.read_bytes()
    alias = tmp_path / 'foreign-annotation-alias.jsonl'
    os.link(path, alias)
    code, body = one_response(monkeypatch, capsys, root)
    assert code == 2 and body['code'] == 'PT-TIERW-INPUT'
    assert path.read_bytes() == alias.read_bytes() == before


def test_hardlinked_report_target_preserves_foreign_alias_permissions(prepared, root, capsys, monkeypatch, tmp_path):
    audit(capsys, root)
    invoke(capsys, root, 'audit-report', '--corpus-id', CID)
    path = prepared.review_dir(CID) / 'audit-report.json'
    before = path.read_bytes()
    alias = tmp_path / 'foreign-report-alias.json'
    os.link(path, alias)
    path.chmod(stat.S_IRUSR)
    mode = stat.S_IMODE(alias.stat().st_mode)
    one_response(monkeypatch, capsys, root)
    code, body = invoke(capsys, root, 'audit-report', '--corpus-id', CID)
    assert code == 2 and body['code'] == 'PT-TIERW-INPUT'
    assert path.read_bytes() == alias.read_bytes() == before and stat.S_IMODE(alias.stat().st_mode) == mode


def test_cancelled_queue_publication_resumes_exact_key(prepared, root, capsys, monkeypatch):
    from tools.calibration.tier_w import review_cli
    real_publish = review_cli.owned.publish_bytes
    stopped = False

    def publish_then_cancel(path, *args, **kwargs):
        nonlocal stopped
        result = real_publish(path, *args, **kwargs)
        if path.name == 'audit-key.json' and not stopped:
            prepared.cancel_file.touch()
            stopped = True
        return result

    monkeypatch.setattr(review_cli.owned, 'publish_bytes', publish_then_cancel)
    code, body = invoke(capsys, root, 'audit', '--seed', 'authored-seed', '--rate', '1', '--corpus-id', CID)
    folder = prepared.review_dir(CID)
    assert code == 5 and body['code'] == 'PT-TIERW-CANCEL'
    key_raw = (folder / 'audit-key.json').read_bytes()
    assert not (folder / 'queue.jsonl').exists()
    prepared.cancel_file.unlink()
    assert audit(capsys, root)['sampled'] == 15
    assert (folder / 'audit-key.json').read_bytes() == key_raw and (folder / 'queue.jsonl').is_file()
