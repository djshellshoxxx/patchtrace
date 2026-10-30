"""SPEC-DA-01 Mode A: project import, storage, reconciliation and the `diaphora` CLI. Synthetic result databases."""
from __future__ import annotations

import json

import pytest
from diaphora_support import make_result, row
from test_nway_series import builds, create, import_pair, jrun  # noqa: F401  (real on-disk pair projects)

from patchtrace import cli
from patchtrace.diaphora import bridge
from patchtrace.diaphora.contracts import KIND, DiaphoraMatchSet
from patchtrace.service import ProjectService


@pytest.fixture
def pair(capsys, builds, tmp_path):  # noqa: F811
    root = tmp_path / 's'
    code, doc, _ = create(capsys, builds[:3], root)
    assert code == 0, doc
    project = root / doc['result']['pair_projects'][0]['path']
    import_pair(project, [(('f', 0x180001000, 'v0'), ('f', 0x180001010, 'v1'), 0.75),
                          (('g', 0x180001100, 'v0'), ('g', 0x180001110, 'v1'), 0.9)])
    return project


def run(args, capsys):
    code = cli.main([str(a) for a in args])
    out, err = capsys.readouterr()
    return code, out, err


def jdia(args, capsys):
    code, out, err = run(['diaphora', *args, '--json'], capsys)
    return code, (json.loads(out) if out.strip() else None), err


def result_file(tmp_path, rows=None, unmatched=()):
    return make_result(tmp_path / 'r.diaphora', rows if rows is not None else [
        row(),                                                         # agrees with Ghidriff f
        row(a1='180001100', a2='180001120'),                           # same older endpoint, other newer: disagreement
        row(a1='180001200', n1='h', a2='180001210', n2='h')],          # Diaphora-only
        unmatched)


def test_inspect_needs_no_project(tmp_path, capsys):
    code, doc, _ = jdia(['inspect', result_file(tmp_path)], capsys)
    assert code == 0 and doc['command'] == 'diaphora inspect' and doc['result']['matches']['best'] == 3
    assert 'secret-host' not in json.dumps(doc)


def test_inspect_failure_is_exit_2(tmp_path, capsys):
    bad = tmp_path / 'bad'
    bad.write_bytes(b'x' * 200)
    code, doc, err = jdia(['inspect', bad], capsys)
    assert code == 2 and 'PT-DIAPHORA-DB' in err and doc['status'] == 'failed'


def test_import_requires_a_binding(pair, tmp_path, capsys):
    code, doc, err = jdia(['import', pair, '--diff', result_file(tmp_path)], capsys)
    assert code == 2 and 'PT-DIAPHORA-PROVENANCE' in err
    with ProjectService.open(pair) as service:
        assert service.store is not None
        from patchtrace.diaphora.service import stored_sets
        assert stored_sets(service) == []


def test_attested_import_stores_and_reconciles(pair, tmp_path, capsys):
    code, doc, _ = jdia(['import', pair, '--diff', result_file(tmp_path), '--user-attest-pair'], capsys)
    assert code == 0, doc
    result = doc['result']
    assert result['trust'] == 'user-attested' and result['matches'] == 3
    assert result['counts'] == {'agreement': 1, 'disagreement': 1, 'absent': 0, 'not-comparable': 0}
    assert result['diaphora_only'] == 1
    code, shown, _ = jdia(['show', pair], capsys)
    assert code == 0 and shown['result']['sets'][0]['trust'] == 'user-attested'
    with ProjectService.open(pair) as service:
        from patchtrace.diaphora.service import stored_sets
        ((entry, match_set),) = stored_sets(service)
        assert entry.kind == KIND and isinstance(match_set, DiaphoraMatchSet) and not entry.stale
        assert entry.id == match_set.entry_id


def test_reimport_replaces_the_same_row(pair, tmp_path, capsys):
    path = result_file(tmp_path)
    for _ in range(2):
        assert jdia(['import', pair, '--diff', path, '--user-attest-pair'], capsys)[0] == 0
    with ProjectService.open(pair) as service:
        from patchtrace.diaphora.service import stored_sets
        assert len(stored_sets(service)) == 1


def test_manifest_binding_and_tamper(pair, tmp_path, capsys):
    path = result_file(tmp_path)
    import hashlib
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    with ProjectService.open(pair) as service:
        sides = {a.side: a.sha256 for a in service.project.artifacts}
    doc = {'contract': 'diaphora-diff/1', 'orientation': 'older->newer', 'older_binary_sha256': sides['older'],
           'newer_binary_sha256': sides['newer'], 'result_sha256': sha}
    manifest = tmp_path / 'm.json'
    manifest.write_text(json.dumps(doc))
    code, out, _ = jdia(['import', pair, '--diff', path, '--manifest', manifest], capsys)
    assert code == 0 and out['result']['trust'] == 'manifest-bound'
    swapped = dict(doc, older_binary_sha256=sides['newer'], newer_binary_sha256=sides['older'])
    manifest.write_text(json.dumps(swapped))
    code, _out, err = jdia(['import', pair, '--diff', path, '--manifest', manifest], capsys)
    assert code == 2 and 'PT-DIAPHORA-ORIENTATION' in err
    manifest.write_text(json.dumps(dict(doc, result_sha256='0' * 64)))
    code, _out, err = jdia(['import', pair, '--diff', path, '--manifest', manifest], capsys)
    assert code == 2 and 'PT-DIAPHORA-PROVENANCE' in err


def test_unverified_addresses_are_not_comparable_never_agreement(pair, tmp_path, capsys):
    path = result_file(tmp_path, [row(a1='1000', a2='1010')])       # looks like RVAs: ambiguous against base 0x180000000
    code, out, _ = jdia(['import', pair, '--diff', path, '--user-attest-pair'], capsys)
    assert code == 0 and out['result']['counts']['agreement'] == 0


def test_project_without_a_completed_run_is_refused(tmp_path, capsys, builds):  # noqa: F811
    root = tmp_path / 'empty'
    code, doc, _ = create(capsys, builds[:3], root)
    project = root / doc['result']['pair_projects'][0]['path']
    code, _out, err = jdia(['import', project, '--diff', result_file(tmp_path), '--user-attest-pair'], capsys)
    assert code == 2 and 'no completed analysis run' in err


def test_show_without_data_is_no_results(pair, capsys):
    code, doc, _ = jdia(['show', pair], capsys)
    assert code == 4 and doc['result'] == {'sets': []}


def test_bridge_is_read_only_and_priorities(pair, tmp_path):
    from patchtrace.diaphora.address_map import ImageMap
    from patchtrace.diaphora.result_import import import_result
    m = ImageMap(0x180000000, 0x2000)
    with ProjectService.open(pair) as service:
        matches = list(service.project.matches)
        before = [x.model_dump_json() for x in matches]
        report = bridge.reconcile(matches, import_result(
            result_file(tmp_path), older_sha256='a' * 64, newer_sha256='b' * 64, trust='user-attested',
            older_map=m, newer_map=m))
        assert [x.model_dump_json() for x in matches] == before
    assert report.counts()['agreement'] == 1 and report.counts()['disagreement'] == 1
    assert len(report.diaphora_only) == 1 and report.limitations


def test_verb_is_discoverable_without_qt():
    from patchtrace.cli_commands import discover
    verbs, broken = discover()
    assert 'diaphora' in verbs and not broken
