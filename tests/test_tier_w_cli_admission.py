"""Recovered CLI must bind local documents to the requested corpus and binary."""
from __future__ import annotations

import copy
import json

import pytest
from test_tier_w_cli import CID, invoke, place, prepare, source, step, write_matches

from tools.calibration.tier_w.contracts import load_pairs
from tools.calibration.tier_w.paths import Layout


@pytest.mark.parametrize('date', ['2026-02-29', '2026-13-01', '2026-00-01', '2026-04-31'])
def test_impossible_calendar_date_is_refused_before_catalogue_write(tmp_path, capsys, date):
    root = tmp_path / 'ptcal'
    code, result = invoke(capsys, root, 'catalogue', '--corpus-id', CID,
                          '--from-file', str(source(tmp_path)), '--data-date', date,
                          '--family', 'tiny.dll=usermode-dll')
    assert code == 2 and result['code'] == 'PT-TIERW-INPUT'
    assert not Layout(root).base.exists()


@pytest.mark.parametrize('kind,command', [('pairs', 'status'), ('pairs', 'labels'),
                                         ('manifest', 'fetch-plan')])
def test_foreign_corpus_document_is_refused(tmp_path, capsys, kind, command):
    root = tmp_path / 'ptcal'
    prepare(tmp_path, capsys, root)
    layout = Layout(root)
    path = layout.pairs(CID) if kind == 'pairs' else layout.manifest(CID)
    document = json.loads(path.read_bytes())
    document['corpus_id'] = 'tier-w-foreign'
    path.write_text(json.dumps(document), encoding='utf-8')
    before = {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
    code, result = invoke(capsys, root, command, '--corpus-id', CID)
    assert code == 2 and result['code'] == 'PT-TIERW-INPUT'
    assert {p: p.read_bytes() for p in root.rglob('*') if p.is_file()} == before


@pytest.mark.parametrize('field,value', [('sha256', 'f' * 64), ('file_name', 'foreign.dll'),
                                        ('producer', 'ghidra'), ('tier', 'R')])
def test_foreign_symbol_map_never_replaces_existing_labels(tmp_path, capsys, field, value):
    root = tmp_path / 'ptcal'
    prepare(tmp_path, capsys, root)
    place(root)
    step(capsys, root, 'symbols')
    step(capsys, root, 'labels')
    layout = Layout(root)
    binary = load_pairs(layout.pairs(CID).read_bytes()).binaries[0]
    path = layout.symbols(binary.sha256, 'msf')
    document = json.loads(path.read_bytes())
    if field in {'sha256', 'file_name'}:
        document['image'][field] = value
    elif field == 'producer':
        document['producer']['tool'] = value
    else:
        document[field] = value
    path.write_text(json.dumps(document), encoding='utf-8')
    folder = layout.labels_dir(CID)
    before = {p.name: p.read_bytes() for p in folder.iterdir()}
    code, result = invoke(capsys, root, 'labels', '--corpus-id', CID)
    assert code == 2 and result['code'] == 'PT-TIERW-INPUT'
    assert {p.name: p.read_bytes() for p in folder.iterdir()} == before


def test_foreign_later_symbol_map_does_not_replace_earlier_pair_labels(tmp_path, capsys):
    root = tmp_path / 'ptcal'
    prepare(tmp_path, capsys, root)
    place(root)
    step(capsys, root, 'symbols')
    step(capsys, root, 'labels')
    layout = Layout(root)
    path = layout.pairs(CID)
    document = json.loads(path.read_bytes())
    foreign = copy.deepcopy(document['binaries'][-1])
    original_sha = foreign['sha256']
    foreign.update(id='tw.foreign-binary', sha256='f' * 64)
    document['binaries'].append(foreign)
    pair = copy.deepcopy(document['pairs'][-1])
    pair.update(id='tw.foreign-pair', newer=foreign['id'])
    document['pairs'].append(pair)
    path.write_text(json.dumps(document), encoding='utf-8')
    layout.symbols(foreign['sha256'], 'msf').write_bytes(layout.symbols(original_sha, 'msf').read_bytes())
    folder = layout.labels_dir(CID)
    for label in folder.iterdir():
        label.write_bytes(b'previous committed result\n')
    before = {p.name: p.read_bytes() for p in folder.iterdir()}
    code, result = invoke(capsys, root, 'labels', '--corpus-id', CID)
    assert code == 2 and result['code'] == 'PT-TIERW-INPUT'
    assert {p.name: p.read_bytes() for p in folder.iterdir()} == before


def test_invalid_audit_report_does_not_replace_previous_evaluation(tmp_path, capsys):
    root = tmp_path / 'ptcal'
    prepare(tmp_path, capsys, root)
    place(root)
    step(capsys, root, 'symbols')
    step(capsys, root, 'labels')
    write_matches(root)
    step(capsys, root, 'evaluate')
    layout = Layout(root)
    layout.report(CID).write_bytes(b'previous committed evaluation\n')
    audit = layout.review_dir(CID) / 'audit-report.json'
    audit.parent.mkdir(parents=True, exist_ok=True)
    audit.write_text('{"contract":"foreign"}', encoding='utf-8')
    outputs = [layout.report(CID), layout.base / 'export' / 'aggregate.json',
               layout.base / 'export' / 'aggregate.md']
    before = {p: p.read_bytes() for p in outputs}
    code, result = invoke(capsys, root, 'evaluate', '--corpus-id', CID)
    assert code == 2 and result['code'] == 'PT-TIERW-INPUT'
    assert {p: p.read_bytes() for p in outputs} == before
