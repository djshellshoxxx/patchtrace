"""SPEC-33 s11: `python -m tools.calibration.tier_w <cmd>`. Hermetic: the self-made tiny_v1/tiny_v2 PE+PDB fixtures, a
made-up Winbindex record over their bytes, sockets patched to raise; no Microsoft data, no Ghidra, nothing executed."""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
from argparse import Namespace
from pathlib import Path

import pytest
from tier_w_builders import ROOT, TIER_W_FIXTURES, TINY, gz, tiny_winbindex_doc

sys.path.insert(0, str(ROOT))
from tools.calibration import corpus  # noqa: E402
from tools.calibration.common import strict_json  # noqa: E402
from tools.calibration.tier_w import run_local as R  # noqa: E402
from tools.calibration.tier_w.contracts import load_pairs  # noqa: E402
from tools.calibration.tier_w.fetch import guid_age, pdb_request, sha256_file  # noqa: E402
from tools.calibration.tier_w.paths import Layout  # noqa: E402

CID = 'tier-w-t'
NAME = 'tiny.dll'
HOSTS = 'winbindex.m417z.com,msdl.microsoft.com'
HEXRUN = re.compile(r'[0-9a-f]{16,}')


def cli():
    from tools.calibration.tier_w import cli as module
    return module


@pytest.fixture
def root(tmp_path, monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError('Tier-W CLI test attempted network access')
    monkeypatch.setattr(socket, 'create_connection', refuse)
    monkeypatch.setattr(socket.socket, 'connect', refuse)
    return tmp_path / 'ptcal'


def invoke(capsys, root, *argv):
    code = cli().main(list(argv), {corpus.ROOT_ENV: str(root)})
    out = capsys.readouterr().out
    lines = out.strip().splitlines()
    assert len(lines) == 1, out
    return code, strict_json(lines[0])


def step(capsys, root, *argv):
    code, doc = invoke(capsys, root, *argv, '--corpus-id', CID)
    assert code == 0 and doc['status'] == 'ok' and doc['exit'] == 0, doc
    return doc


def source(tmp_path) -> Path:
    path = tmp_path / 'in' / f'{NAME}.json.gz'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(gz(tiny_winbindex_doc()))
    return path


def prepare(tmp_path, capsys, root):
    step(capsys, root, 'catalogue', '--from-file', str(source(tmp_path)), '--data-date', '2026-10-01',
         '--family', f'{NAME}=usermode-dll')
    step(capsys, root, 'pairs', '--allow-incomplete')


def place(root, *, pdbs=True):
    """What `fetch` would leave behind: binaries at <root>/binaries/<sha256>/<name>, PDBs at Layout.pdb."""
    for stem in TINY:
        pe = TIER_W_FIXTURES / f'{stem}.pe'
        target = root / 'binaries' / sha256_file(pe) / NAME
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(pe, target)
        if pdbs:
            name, guid, age = pdb_request(pe)
            pdb = Layout(root).pdb(name, guid_age(guid, age))
            pdb.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(TIER_W_FIXTURES / f'{stem}.pdb', pdb)


def write_matches(root) -> tuple[str, int]:
    """Synthetic engine output: every truth pair but the last, one crossed match, and a symbols-visible copy."""
    layout = Layout(root)
    pair = load_pairs(layout.pairs(CID).read_bytes()).pairs[0].id
    truth = [json.loads(line) for line in (layout.labels_dir(CID) / f'{pair}.truth.jsonl').read_text(encoding='utf-8').splitlines()]
    rvas = [tuple(int(v, 16) for v in t['match_id'].removeprefix('sym:').split('-')) for t in truth]
    hidden = [*rvas[:-1], (rvas[0][0], rvas[1][1])]
    lines = [json.dumps({'contract': 'tier-w-matches/1', 'tier': 'W', 'pair': pair, 'engine': 'ghidriff',
                         'condition': cond, 'match_id': f'm{i}', 'older_rva': o, 'newer_rva': n})
             for cond in ('symbols-hidden', 'symbols-visible') for i, (o, n) in enumerate(hidden)]
    path = layout.base / 'runs' / CID / 'matches.jsonl'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8', newline='\n')
    return pair, len(rvas)


def files_outside(tmp_path: Path, root: Path) -> set[Path]:
    return {p for p in tmp_path.rglob('*') if p.is_file() and root not in p.parents}


# ---- the offline chain ---------------------------------------------------------------------------------------------

def test_offline_chain_end_to_end(tmp_path, root, capsys, monkeypatch):
    cwd = tmp_path / 'cwd'
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    src = source(tmp_path)
    before = files_outside(tmp_path, root)
    docs = {}
    docs['catalogue'] = step(capsys, root, 'catalogue', '--from-file', str(src), '--data-date', '2026-10-01',
                             '--family', f'{NAME}=usermode-dll')
    assert docs['catalogue']['catalogues'] == 1 and docs['catalogue']['builds'] == 2
    docs['pairs'] = step(capsys, root, 'pairs', '--allow-incomplete')
    assert docs['pairs']['pairs'] == 1 and docs['pairs']['binaries'] == 2 and docs['pairs']['complete'] is False
    docs['fetch-plan'] = step(capsys, root, 'fetch-plan')
    sizes = sum((TIER_W_FIXTURES / f'{s}.pe').stat().st_size for s in TINY)
    assert docs['fetch-plan']['planned'] == docs['fetch-plan']['missing'] == 2
    assert docs['fetch-plan']['bytes'] == docs['fetch-plan']['missing_bytes'] == sizes
    assert docs['fetch-plan']['disk_needed'] > sizes
    place(root)
    docs['symbols'] = step(capsys, root, 'symbols', '--producer', 'msf')
    assert docs['symbols']['exported'] == 2 and docs['symbols']['missing_pdbs'] == 0
    docs['labels'] = step(capsys, root, 'labels')
    assert docs['labels']['labelled'] == 1 and docs['labels']['truth'] == 15
    assert docs['labels']['excluded'] == {'absent-in-newer': 2, 'absent-in-older': 2, 'alias': 1, 'non-unique': 1,
                                          'no-size': 0, 'size-ratio': 0}
    pair, truth = write_matches(root)
    docs['evaluate'] = step(capsys, root, 'evaluate')
    layout = Layout(root)
    report = json.loads(layout.report(CID).read_text(encoding='utf-8'))
    cell = report['cells']['ghidriff']
    assert (cell['symbols-hidden']['overall']['correct'], cell['symbols-hidden']['overall']['wrong']) == (truth - 1, 1)
    assert cell['symbols-visible'] == {'status': 'insufficient-labels', 'reason': 'circular'}
    aggregate = json.loads((layout.base / 'export' / 'aggregate.json').read_text(encoding='utf-8'))
    assert aggregate['contract'] == 'tier-w-aggregate/1' and aggregate['classes']['usermode-dll']['pairs'] == 1
    assert (layout.base / 'export' / 'aggregate.md').read_text(encoding='utf-8').startswith('> Derived from')
    assert docs['evaluate']['matches'] == 2 * truth and docs['evaluate']['cells'] == {'scored': 1, 'circular': 1}
    docs['status'] = step(capsys, root, 'status')
    assert docs['status']['manifest'] is True and docs['status']['report'] is True
    assert docs['status']['binaries'] == {'planned': 2, 'present': 2} and docs['status']['labelled'] == 1
    assert files_outside(tmp_path, root) == before and not any(cwd.iterdir())
    secrets = (str(tmp_path), str(root), NAME, 'tiny', pair, 'tw.', '.pdb')
    for stage, doc in docs.items():
        view = json.dumps(R.aggregate_only(doc))
        assert not any(s in view for s in secrets) and not HEXRUN.search(view), (stage, view)


def test_symbols_with_a_missing_pdb_is_partial(tmp_path, root, capsys):
    prepare(tmp_path, capsys, root)
    place(root, pdbs=False)
    code, doc = invoke(capsys, root, 'symbols', '--corpus-id', CID)
    assert code == 1 and doc['status'] == 'partial' and doc['missing_pdbs'] == 2 and doc['exported'] == 0


def test_evaluate_without_matches_exits_one_with_a_reason(tmp_path, root, capsys):
    prepare(tmp_path, capsys, root)
    code, doc = invoke(capsys, root, 'evaluate', '--corpus-id', CID)
    assert code == 1 and doc['status'] == 'partial' and 'matches' in doc['reason']
    assert not Layout(root).report(CID).exists()


# ---- argv contract with run_local ----------------------------------------------------------------------------------

@pytest.mark.parametrize('stage', list(R.STAGES), ids=list(R.STAGES))
@pytest.mark.parametrize('consent', [HOSTS, ''], ids=['consent', 'none'])
def test_every_run_local_stage_argv_parses(stage, consent):
    args = Namespace(corpus_id=CID, consent_hosts=consent, python='py', ghidra_dir='gd', timeout=99)
    argv = R.stage_argv(stage, args, 'python')
    assert argv[1:3] == ['-m', 'tools.calibration.tier_w']
    parsed = cli().build_parser().parse_args(argv[3:])
    assert parsed.command == stage and parsed.corpus_id == CID


def test_run_local_sees_the_cli():
    assert R.cli_available() is True


def test_module_entry_point_prints_one_json_line(tmp_path):
    env = {**os.environ, corpus.ROOT_ENV: str(tmp_path / 'ptcal'),
           'PYTHONPATH': os.pathsep.join((str(ROOT / 'src'), str(ROOT)))}
    done = subprocess.run([sys.executable, '-m', 'tools.calibration.tier_w', 'run', '--corpus-id', CID],
                          cwd=ROOT, env=env, capture_output=True, timeout=120, check=False)
    lines = done.stdout.decode('utf-8').strip().splitlines()
    assert done.returncode == 3 and len(lines) == 1 and 'LBL-23' in strict_json(lines[0])['message']


# ---- explicit exits ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('argv, code', [
    (['catalogue'], 2), (['catalogue', '--consent-hosts', ''], 2), (['catalogue', '--consent-hosts', 'example.com'], 2),
    (['catalogue', '--consent-hosts', 'msdl.microsoft.com'], 2), (['catalogue', '--consent-hosts', HOSTS], 3),
    (['resolve'], 2), (['resolve', '--consent-hosts', f'{HOSTS},example.com'], 2), (['resolve', '--consent-hosts', HOSTS], 3),
    (['fetch'], 2), (['fetch', '--consent-hosts', 'winbindex.m417z.com'], 2), (['fetch', '--consent-hosts', HOSTS], 3),
], ids=['cat', 'cat-empty', 'cat-foreign', 'cat-wrong', 'cat-ok', 'res', 'res-foreign', 'res-ok', 'fet', 'fet-wrong',
        'fet-ok'])
def test_network_stages_need_consent_and_are_not_wired(root, capsys, argv, code):
    got, doc = invoke(capsys, root, *argv, '--corpus-id', CID)
    assert got == code and doc['exit'] == code
    assert ('not wired' in doc['message']) == (code == 3)
    assert doc['status'] == ('blocked' if code == 3 else 'failed')


@pytest.mark.parametrize('command', ['audit', 'review', 'audit-report', 'run'], ids=['audit', 'review', 'report', 'run'])
def test_unwired_stages_exit_blocked(root, capsys, command):
    code, doc = invoke(capsys, root, command, '--corpus-id', CID)
    assert code == 3 and doc['status'] == 'blocked' and doc['code'] == 'PT-TIERW-BLOCKED'
    assert ('LBL-23' in doc['message']) == (command == 'run')


def test_root_inside_the_work_tree_is_refused(capsys):
    inside = ROOT / 'tmp-tier-w-root'
    code, doc = invoke(capsys, inside, 'status', '--corpus-id', CID)
    assert code == 2 and 'inside the work tree' in doc['message'] and not inside.exists()


@pytest.mark.parametrize('corpus_id', ['bad id', 'tier-x-1', ''], ids=['space', 'prefix', 'empty'])
def test_bad_corpus_id_is_refused(root, capsys, corpus_id):
    code, doc = invoke(capsys, root, 'status', '--corpus-id', corpus_id)
    assert code == 2 and doc['code'] == 'PT-TIERW-INPUT' and not root.exists()


@pytest.mark.parametrize('argv', [['pairs'], ['nope', '--corpus-id', CID], ['pairs', '--corpus-id', CID, '--bogus']],
                         ids=['no-id', 'command', 'option'])
def test_usage_errors_print_one_json_line(root, capsys, argv):
    code, doc = invoke(capsys, root, *argv)
    assert code == 2 and doc['status'] == 'failed' and doc['code'] == 'PT-TIERW-INPUT'


def test_cancel_file_exits_five(tmp_path, root, capsys):
    prepare(tmp_path, capsys, root)
    place(root)
    Layout(root).cancel_file.write_text('stop', encoding='utf-8')
    code, doc = invoke(capsys, root, 'symbols', '--corpus-id', CID)
    assert code == 5 and doc['status'] == 'cancelled'
    assert not list((Layout(root).base / 'symbols').glob('*.json'))


def test_catalogue_input_errors_exit_two(tmp_path, root, capsys):
    bad_date = invoke(capsys, root, 'catalogue', '--from-file', str(source(tmp_path)), '--data-date', '2026/10/01',
                      '--family', f'{NAME}=usermode-dll', '--corpus-id', CID)
    unknown_family = invoke(capsys, root, 'catalogue', '--from-file', str(source(tmp_path)), '--corpus-id', CID)
    assert bad_date[0] == unknown_family[0] == 2 and 'family' in unknown_family[1]['message']


def test_pairs_without_a_catalogue_exits_two(root, capsys):
    code, doc = invoke(capsys, root, 'pairs', '--corpus-id', CID)
    assert code == 2 and 'catalogue' in doc['message']


@pytest.mark.parametrize('problems, code', [([], 0), (['x: PDB file'], 1)], ids=['clean', 'finding'])
def test_guard_reports_findings(root, capsys, monkeypatch, problems, code):
    monkeypatch.setattr(corpus, 'guard', lambda worktree, manifest=None: problems)
    got, doc = invoke(capsys, root, 'guard', '--corpus-id', CID)
    assert got == code and doc['findings'] == len(problems)


# ---- verifier regressions (G-TW-CLI-r) -----------------------------------------------------------------------------

FOREIGN = {'contract': 'tier-w-matches/1', 'tier': 'W', 'pair': 'tw.other.0000000000', 'engine': 'ghidriff',
           'condition': 'symbols-hidden', 'match_id': 'm0', 'older_rva': 4096, 'newer_rva': 4096}


def labelled(tmp_path, capsys, root) -> Layout:
    prepare(tmp_path, capsys, root)
    place(root)
    step(capsys, root, 'symbols')
    step(capsys, root, 'labels')
    return Layout(root)


def label_files(root) -> dict[str, bytes]:
    folder = Layout(root).labels_dir(CID)
    return {p.name: p.read_bytes() for p in sorted(folder.glob('*.jsonl'))} if folder.is_dir() else {}


def exported_sides(files: dict[str, bytes]) -> tuple[int, int]:
    sides = [side for name, data in files.items() if name.endswith('.detail.jsonl')
             for row in map(json.loads, data.decode('utf-8').splitlines())
             for side in (row['older'], row['newer']) if side.get('rva') is not None]
    return sum(s['exported'] for s in sides), sum(not s['exported'] for s in sides)


@pytest.mark.parametrize('damage', ['gone', 'corrupt'], ids=['gone', 'corrupt'])
def test_labels_never_record_unknown_exports_as_not_exported(tmp_path, root, capsys, damage):
    labelled(tmp_path, capsys, root)
    before = label_files(root)
    assert exported_sides(before)[0] > 0
    if damage == 'gone':
        shutil.rmtree(root / 'binaries')
    else:
        for pe in (root / 'binaries').rglob(NAME):
            pe.write_bytes(b'MZ' + bytes(64))
    code, doc = invoke(capsys, root, 'labels', '--corpus-id', CID)
    assert exported_sides(label_files(root)) == exported_sides(before) and label_files(root) == before
    assert code == 1 and doc['status'] == 'partial' and doc['exports_unknown'] == 1 and doc['labelled'] == 0
    shutil.rmtree(Layout(root).labels_dir(CID))
    code, doc = invoke(capsys, root, 'labels', '--corpus-id', CID)
    assert code == 1 and doc['exports_unknown'] == 1 and label_files(root) == {}


@pytest.mark.parametrize('value', ['0', '2', '-5', 'nan', 'inf', '-inf', 'x'],
                         ids=['zero', 'two', 'neg', 'nan', 'inf', 'ninf', 'text'])
def test_labels_ratio_min_out_of_range_is_an_input_error(tmp_path, root, capsys, value):
    prepare(tmp_path, capsys, root)
    place(root)
    step(capsys, root, 'symbols')
    code, doc = invoke(capsys, root, 'labels', '--corpus-id', CID, f'--ratio-min={value}')
    assert code == 2 and doc['status'] == 'failed' and doc['code'] == 'PT-TIERW-INPUT' and 'ratio-min' in doc['message']
    assert label_files(root) == {}


@pytest.mark.parametrize('value', ['1', '0.5', '1e-9'], ids=['one', 'half', 'tiny'])
def test_labels_ratio_min_in_range_is_accepted(tmp_path, root, capsys, value):
    prepare(tmp_path, capsys, root)
    place(root)
    step(capsys, root, 'symbols')
    step(capsys, root, 'labels', f'--ratio-min={value}')


def test_evaluate_with_only_foreign_matches_exits_one_and_keeps_outputs(tmp_path, root, capsys):
    layout = labelled(tmp_path, capsys, root)
    write_matches(root)
    step(capsys, root, 'evaluate')
    outputs = (layout.report(CID), layout.base / 'export' / 'aggregate.json', layout.base / 'export' / 'aggregate.md')
    before = [p.read_bytes() for p in outputs]
    layout.matches(CID).write_text(json.dumps(FOREIGN) + '\n', encoding='utf-8', newline='\n')
    code, doc = invoke(capsys, root, 'evaluate', '--corpus-id', CID)
    assert code == 1 and doc['status'] == 'partial' and doc['matches'] == 0 and doc['foreign_matches'] == 1
    assert 'matches' in doc['reason']
    assert [p.read_bytes() for p in outputs] == before


def test_evaluate_with_only_foreign_matches_writes_nothing(tmp_path, root, capsys):
    layout = labelled(tmp_path, capsys, root)
    layout.matches(CID).parent.mkdir(parents=True, exist_ok=True)
    layout.matches(CID).write_text(json.dumps(FOREIGN) + '\n', encoding='utf-8', newline='\n')
    code, doc = invoke(capsys, root, 'evaluate', '--corpus-id', CID)
    assert code == 1 and doc['matches'] == 0 and 'matches' in doc['reason']
    assert not layout.report(CID).exists() and not (layout.base / 'export').exists()
