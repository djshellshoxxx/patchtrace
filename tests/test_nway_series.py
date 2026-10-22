"""SPEC-09 series persistence, discovery, staleness and CLI over real on-disk pair projects."""
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from test_jobs import fake_runtime, write_backend  # noqa: F401  (fixture reuse: never real Ghidra)

from patchtrace import cli
from patchtrace.nway import series as store
from patchtrace.nway.contracts import NwayError
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


@pytest.fixture
def builds(tmp_path):
    paths = []
    for i in range(4):
        path = tmp_path / 'in' / f'b{i}.dll'
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(synthetic_pe(i))
        paths.append(path)
    return paths


def run(args, capsys):
    code = cli.main([str(a) for a in args])
    out, err = capsys.readouterr()
    return code, out, err


def jrun(args, capsys):
    code, out, err = run([*args, '--json'], capsys)
    return code, json.loads(out), err


def func(name, address, code):
    return {'name': name, 'fullname': name, 'address': f'{address:x}', 'code': code, 'calling': [],
            'called': [], 'sig': f'int {name}(void)'}


def import_pair(path: Path, modified, added=(), deleted=(), matches=None):
    """Import a synthetic Ghidriff result into an existing pair project (as the GUI import does)."""
    with ProjectService.open(path) as service:
        sides = {a.side: a.sha256 for a in service.project.artifacts}
        raw = {'old_meta': {'SHA256': sides['older']}, 'new_meta': {'SHA256': sides['newer']},
               'functions': {'added': list(added), 'deleted': list(deleted), 'modified': [
                   {'old': func(*o), 'new': func(*n), 'diff': '', 'diff_type': ['code'], 'ratio': r,
                    'match_types': ['SymbolsHash']} for o, n, r in modified]}}
        if matches is not None:
            raw['matches'] = matches
        file = path.parent / f'{path.name}.raw.json'
        file.write_text(json.dumps(raw))
        service.import_diff(file)
        file.unlink()


def create(capsys, builds, root, *extra):
    return jrun(['series', 'create', '--builds', *builds, '--root', root, *extra], capsys)


def populated(capsys, builds, root, *extra):
    code, doc, _ = create(capsys, builds[:3], root, *extra)
    assert code == 0, doc
    plan = [root / p['path'] for p in doc['result']['pair_projects']]
    import_pair(plan[0], [(('f', 0x1000, 'v0'), ('f', 0x1010, 'v1'), 0.75),
                          (('g', 0x2000, 'g0'), ('g', 0x2000, 'g1'), None)])
    import_pair(plan[1], [(('f', 0x1010, 'v1'), ('f', 0x1020, 'v2'), 0.5)],
                deleted=[func('g', 0x2000, 'g1')])
    code, doc, _ = create(capsys, builds[:3], root, *extra)
    assert code == 0, doc
    return plan, doc


def test_create_without_run_makes_validated_pair_projects(builds, tmp_path, capsys):
    root = tmp_path / 'series'
    code, doc, _ = create(capsys, builds[:3], root, '--labels', 'RTM', 'CU1', 'CU2')
    assert code == 0 and doc['contract'] == 'enrichment-cli/1' and doc['command'] == 'series create'
    result = doc['result']
    assert len(result['created']) == 2 and result['chains'] == 0
    assert [(p['from_ordinal'], p['to_ordinal'], p['run_id']) for p in result['pair_projects']] == [
        (0, 1, None), (1, 2, None)]
    assert any('without a completed run' in w for w in doc['warnings'])
    series = store.load(root / 'series.json')
    assert [b.label for b in series.builds] == ['RTM', 'CU1', 'CU2']
    for ref, (i, j) in zip(series.pair_projects, [(0, 1), (1, 2)], strict=True):
        with ProjectService.open(root / ref.path) as service:
            sides = {a.side: a.sha256 for a in service.project.artifacts}
        assert (sides['older'], sides['newer']) == (series.builds[i].artifact_sha256,
                                                    series.builds[j].artifact_sha256)
    before = (root / 'series.json').read_bytes()
    code, doc, _ = create(capsys, builds[:3], root, '--labels', 'RTM', 'CU1', 'CU2')
    assert code == 0 and doc['result']['created'] == []
    assert (root / 'series.json').read_bytes() == before


def test_chains_from_imported_pairs_and_filters(builds, tmp_path, capsys):
    root = tmp_path / 's'
    _, doc = populated(capsys, builds, root)
    assert doc['result']['chains'] == 1
    code, doc, _ = jrun(['series', 'chains', root / 'series.json'], capsys)
    assert code == 0 and doc['status'] == 'complete'
    [chain] = doc['result']['chains']
    assert [(n['ordinal'], n['address'], n['name']) for n in chain['nodes']] == [
        (0, 0x1000, 'f'), (1, 0x1010, 'f'), (2, 0x1020, 'f')]
    assert [e['ratio_text'] for e in chain['edges']] == ['0.75', '0.5']
    assert chain['status'] == 'inferred' and chain['stale'] is False
    assert run(['series', 'chains', root / 'series.json', '--address', '0x1010'], capsys)[0] == 0
    code, doc, _ = jrun(['series', 'chains', root / 'series.json', '--function', 'g'], capsys)
    assert code == 4 and doc['result']['chains'] == []
    code, out, _ = run(['series', 'chains', root / 'series.json'], capsys)
    assert code == 0 and '[b0.dll] f@1000 -> [b1.dll] f@1010 -> [b2.dll] f@1020' in out


def test_stale_after_pair_rematch_and_recompute_is_deterministic(builds, tmp_path, capsys):
    root = tmp_path / 's'
    plan, _ = populated(capsys, builds, root)
    first = (root / 'series.json').read_bytes()
    with ProjectService.open(plan[1]) as service:
        match = next(m for m in service.project.matches if m.category == 'modified')
        service.correct_match(match.id, [match.older[0].id], [match.newer[0].id], 'modified', 'analyst check')
    code, doc, _ = jrun(['series', 'chains', root / 'series.json'], capsys)
    assert code == 0 and doc['status'] == 'stale' and doc['result']['stale_pairs'] == [1]
    assert doc['result']['chains'][0]['stale'] is True
    assert any('pair 1→2' in w for w in doc['warnings'])
    assert create(capsys, builds[:3], root)[0] == 0
    code, doc, _ = jrun(['series', 'chains', root / 'series.json'], capsys)
    assert doc['status'] == 'complete' and doc['result']['chains'][0]['edges'][1]['manual'] is True
    assert (root / 'series.json').read_bytes() != first
    again = (root / 'series.json').read_bytes()
    assert create(capsys, builds[:3], root)[0] == 0
    assert (root / 'series.json').read_bytes() == again


def test_discovery_is_independent_of_directory_names(builds, tmp_path, capsys):
    root = tmp_path / 's'
    plan, _ = populated(capsys, builds, root)
    before = store.load(root / 'series.json')
    plan[0].rename(root / 'zzz')
    plan[1].rename(root / 'aaa')
    (root / 'series.json').unlink()
    assert create(capsys, builds[:3], root)[0] == 0
    after = store.load(root / 'series.json')
    assert after.series_id == before.series_id and after.chains == before.chains
    assert [p.path for p in after.pair_projects] == ['zzz', 'aaa']


def test_duplicate_or_mismatched_pair_projects_are_rejected(builds, tmp_path, capsys):
    root = tmp_path / 's'
    assert create(capsys, builds[:3], root)[0] == 0
    ProjectService.create(builds[0], builds[1], 'dup', root / 'dup').close()
    code, doc, err = create(capsys, builds[:3], root)
    assert code == 2 and 'several pair projects' in doc['error']
    root2 = tmp_path / 's2'
    ProjectService.create(builds[1], builds[0], 'reversed', root2 / f'pair-0-1-{store.sha256_file(builds[0])[:12]}-'
                          f'{store.sha256_file(builds[1])[:12]}').close()
    code, doc, _ = create(capsys, builds[:3], root2)
    assert code == 2 and 'does not hold builds 0→1' in doc['error']


@pytest.mark.parametrize('pick', [lambda b: b[:2], lambda b: [b[0], b[1], b[0]]])
def test_build_count_and_uniqueness_exit_2(builds, tmp_path, capsys, pick):
    code, doc, _ = create(capsys, pick(builds), tmp_path / 's')
    assert code == 2 and 'PT-NWAY-INPUT' in doc['error']


def test_labels_must_match_builds(builds, tmp_path, capsys):
    code, doc, _ = create(capsys, builds[:3], tmp_path / 's', '--labels', 'a', 'b')
    assert code == 2


def test_series_file_of_another_series_is_not_overwritten(builds, tmp_path, capsys):
    root = tmp_path / 's'
    assert create(capsys, builds[:3], root)[0] == 0
    code, doc, _ = create(capsys, builds[1:4], root)
    assert code == 2 and 'another series' in doc['error']


def test_locked_pair_project_is_respected(builds, tmp_path, capsys):
    root = tmp_path / 's'
    assert create(capsys, builds[:3], root)[0] == 0
    ref = store.load(root / 'series.json').pair_projects[0]
    holder = ProjectService.open(root / ref.path)
    try:
        code, doc, _ = create(capsys, builds[:3], root)
        assert code == 2 and 'locked' in doc['error']
    finally:
        holder.close()


def test_tampered_series_file_rejected(builds, tmp_path, capsys):
    root = tmp_path / 's'
    assert create(capsys, builds[:3], root)[0] == 0
    path = root / 'series.json'
    data = json.loads(path.read_text())
    for mutate in (lambda d: d['builds'].reverse(), lambda d: d['pair_projects'][0].update(path='/etc'),
                   lambda d: d.update(schema='nway/2'), lambda d: d.update(extra=1)):
        copy = json.loads(json.dumps(data))
        mutate(copy)
        path.write_text(json.dumps(copy))
        with pytest.raises(NwayError, match='PT-NWAY-STORAGE'):
            store.load(path)
    path.write_text('{"schema": "nway/1", "schema": "nway/1"}')
    assert run(['series', 'chains', path], capsys)[0] == 2


def test_missing_pair_project_marks_stale(builds, tmp_path, capsys):
    root = tmp_path / 's'
    plan, _ = populated(capsys, builds, root)
    plan[0].rename(tmp_path / 'moved')
    code, doc, _ = jrun(['series', 'chains', root / 'series.json'], capsys)
    assert doc['status'] == 'stale' and doc['result']['stale_pairs'] == [0]


FAKE_GHIDRIFF = '''import hashlib
old, new = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
def h(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def f(p, a): return {"name": "f", "fullname": "f", "address": a, "code": "code-" + h(p)[:8], "calling": [], "called": []}
raw = {"old_meta": {"SHA256": h(old)}, "new_meta": {"SHA256": h(new)},
       "functions": {"added": [], "deleted": [], "modified": [{"old": f(old, "1000"), "new": f(new, "1000"),
                     "diff": "", "diff_type": ["code"], "ratio": 0.9, "match_types": ["ExactMnemonicsFunctionHasher"]}]}}
(out/"json"/"a-b.ghidriff.json").write_text(json.dumps(raw))
'''


def test_create_run_uses_backend_path_with_fake_runtime(fake_runtime, builds, capsys):  # noqa: F811
    tmp, package, _, config = fake_runtime
    write_backend(package, FAKE_GHIDRIFF)
    root = tmp / 'series'
    args = ['--run', '--direct', '--python', config.python_executable, '--ghidra-dir', config.ghidra_dir]
    code, doc, err = create(capsys, builds[:3], root, *args)
    assert code == 0, (doc, err)
    assert all(p['run_id'] for p in doc['result']['pair_projects']) and doc['result']['direct_project']['run_id']
    code, doc, _ = jrun(['series', 'chains', root / 'series.json'], capsys)
    [chain] = doc['result']['chains']
    assert chain['status'] == 'confirmed' and chain['weakest_match_type'] == 'ExactMnemonicsFunctionHasher'
    # Pairs with a completed run are reused, not re-run.
    before = store.load(root / 'series.json')
    assert create(capsys, builds[:3], root, *args)[0] == 0
    assert store.load(root / 'series.json') == before


def test_run_options_require_run(builds, tmp_path, capsys):
    code, doc, _ = create(capsys, builds[:3], tmp_path / 's', '--python', sys.executable)
    assert code == 2


def test_pure_modules_import_no_qt_or_network():
    code = ('import sys, patchtrace.nway.graph, patchtrace.nway.contracts, patchtrace.nway.series, '
            'patchtrace.nway.pair_access, patchtrace.nway.view_model;'
            'bad = {"PySide6", "subprocess", "ssl", "http.client", "urllib.request"} & set(sys.modules);'
            'print(sorted(bad))')
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True,
                            env={**os.environ, 'PYTHONPATH': str(Path(cli.__file__).parents[1])})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == '[]'


def test_cancel_before_run_exits_5(fake_runtime, builds, capsys, monkeypatch):  # noqa: F811
    tmp, package, _, config = fake_runtime
    write_backend(package, FAKE_GHIDRIFF)
    original = threading.Event

    class Preset(original):
        def __init__(self):
            super().__init__()
            self.set()
    monkeypatch.setattr(cli.threading, 'Event', Preset)
    code, doc, _ = create(capsys, builds[:3], tmp / 's', '--run', '--python', config.python_executable,
                          '--ghidra-dir', config.ghidra_dir)
    assert code == 5


def test_failed_pair_run_is_recorded_and_exits_3(fake_runtime, builds, capsys):  # noqa: F811
    tmp, package, _, config = fake_runtime
    write_backend(package, 'sys.exit(7)\n')
    root = tmp / 's'
    code, doc, _ = create(capsys, builds[:3], root, '--run', '--python', config.python_executable,
                          '--ghidra-dir', config.ghidra_dir)
    assert code == 3 and doc['status'] == 'partial' and len(doc['warnings']) >= 2
    ref = store.load(root / 'series.json').pair_projects[0]
    with ProjectService.open(root / ref.path) as service:
        assert [r.status for r in service.project.runs] == ['failed']


def test_unchanged_pair_from_raw_address_matches_extends_chain(builds, tmp_path, capsys):
    root = tmp_path / 's'
    code, doc, _ = create(capsys, builds[:3], root)
    plan = [root / p['path'] for p in doc['result']['pair_projects']]
    import_pair(plan[0], [], matches={'address_matches': {'1000': [['1010', ['ExactBytesFunctionHasher']]]},
                                      'name_matches': {'f': [['f', ['ExactBytesFunctionHasher']]]}})
    import_pair(plan[1], [(('f', 0x1010, 'v1'), ('f', 0x1020, 'v2'), 0.5)])
    code, doc, _ = create(capsys, builds[:3], root)
    assert code == 0 and doc['result']['chains'] == 1
    assert any('no matches section' in w for w in doc['warnings'])  # pair 1 raw lacks matches
    [chain] = store.load(root / 'series.json').chains
    assert [(n.ordinal, n.address, n.name) for n in chain.nodes] == [(0, 0x1000, None), (1, 0x1010, 'f'),
                                                                    (2, 0x1020, 'f')]
    first = chain.edges[0]
    assert (first.category, first.match_types, first.ratio_text, first.manual) == (
        'unchanged', ('ExactBytesFunctionHasher',), None, False)
    assert store.load(root / 'series.json').pair_projects[1].notes


def test_tampered_raw_output_is_rejected(builds, tmp_path, capsys):
    root = tmp_path / 's'
    code, doc, _ = create(capsys, builds[:3], root)
    plan = [root / p['path'] for p in doc['result']['pair_projects']]
    import_pair(plan[0], [], matches={'address_matches': {}})
    project = store.read_project(plan[0])
    assert store.read_raw_matches(plan[0], project) == ({'address_matches': {}}, ())
    raw = plan[0] / project.runs[-1].raw_path
    raw.chmod(0o644)
    raw.write_text(raw.read_text().replace('{}', '{"1": [["2", []]]}', 1))
    # Tampering after the project snapshot was read: series computation re-verifies the hash itself.
    with pytest.raises(NwayError, match='recorded SHA-256'):
        store.read_raw_matches(plan[0], project)
    # Through the CLI, ProjectService.open already refuses the changed raw file.
    code, doc, _ = create(capsys, builds[:3], root)
    assert code == 2 and 'preserved raw output' in doc['error']


def test_symbol_flags_are_validated_before_any_work(capsys, builds, tmp_path):
    """SPEC-53 section 8: online needs explicit consent, PDB folders only fit local mode, flags need --run."""
    root = tmp_path / 's'
    python, ghidra = sys.executable, str(tmp_path)
    run_args = ['--run', '--python', python, '--ghidra-dir', ghidra]
    code, doc, _ = create(capsys, builds[:3], root, *run_args, '--symbols', 'online')
    assert code == 2 and 'PT-SYMBOL-NETWORK-REFUSED' in json.dumps(doc)
    code, doc, _ = create(capsys, builds[:3], root, *run_args, '--symbol-dir', str(tmp_path))
    assert code == 2 and 'PT-SYMBOL-MODE' in json.dumps(doc)
    code, doc, _ = create(capsys, builds[:3], root, '--symbols', 'local')
    assert code == 2 and not root.exists()
