"""SPEC-32 s12 CLI: exit codes, the `corpus known-answer` hook, BLOCKED reporting. Engine files in these tests are SYNTHETIC
(hand-made .BinDiff / Ghidriff JSON): they exercise the plumbing, not a live engine. One end-to-end test builds a real
tiny suite with the local toolchain (BLOCKED, recorded, when the toolchain is missing)."""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest
from bindiff_builder import build
from test_tier_r_eval_engines import _ghidriff
from test_tier_r_eval_metrics import FUNCS, make_labels
from tier_r_helpers import require

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration import contracts as K  # noqa: E402
from tools.calibration import corpus  # noqa: E402
from tools.calibration.tier_r import cli  # noqa: E402
from tools.calibration.tier_r import contracts as C  # noqa: E402

LABELS = make_labels(FUNCS, pair_id='syn-eng')
BASE = 0x180000000


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv('PATCHTRACE_CALIB_ROOT', str(tmp_path / 'calib'))
    folder = tmp_path / 'calib' / 'known-answer'
    (folder / 'labels').mkdir(parents=True)
    (folder / 'labels' / 'syn-eng.json').write_bytes(C.dump_json(LABELS.model_dump(mode='json')))
    return folder


def run(capsys, *argv):
    code = cli.main(list(argv))
    text = capsys.readouterr().out
    return code, (json.loads(text) if text.strip() else {})


def test_mutate_plants_builds_and_labels_a_tiny_suite_pair(record_live_status, capsys, store):
    require(record_live_status, 'msvc-free')
    code, doc = run(capsys, 'mutate', '--suite', str(ROOT / 'corpus/ours/_template/tiny'), '--operator', 'cmp-flip',
                    '--seed', '1000')
    assert (code, doc['status'], doc['disagreements']) == (0, 'ok', 0)
    labels = C.load_labels((store / 'labels' / doc['written'][0]).read_bytes())
    assert labels.stratum == 'mutation' and labels.case['mutation_case']['operator'] == 'cmp-flip'
    assert sum(f.label == 'changed' for f in labels.functions) == 1


def test_mutate_unknown_operator_is_an_error_not_blocked(capsys, store):
    code, doc = run(capsys, 'mutate', '--suite', str(ROOT / 'corpus/ours/_template/tiny'), '--operator', 'nope',
                    '--seed', '1')
    assert code == 2 and doc['status'] == 'error'


def test_aa_and_noise_default_to_the_first_suite_version(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(cli.F, 'run_noise', lambda session, base: seen.append(base.tag) or ([], []))
    monkeypatch.setenv('PATCHTRACE_CALIB_ROOT', str(tmp_path / 'calib'))
    args = types.SimpleNamespace(suite=str(ROOT / 'corpus/ours/_template/tiny'), version=None, card=None, side='old',
                                 store=None)
    session = types.SimpleNamespace(store=tmp_path)
    assert cli._base(args, session).tag == 'v1'
    assert cli.main(['noise', '--suite', str(ROOT / 'corpus/ours/_template/tiny')]) in (0, 3)


def test_build_card_reports_identical_images_as_skipped(capsys, monkeypatch, store):
    def boom(*a, **k):
        raise cli.F.IdenticalImages('card-x: identical')
    monkeypatch.setattr(cli.F, 'run_card', boom)
    monkeypatch.setattr(cli, '_card', lambda cid: object())
    code, doc = run(capsys, 'build-card', 'card-x')
    assert (code, doc['status'], doc['written']) == (0, 'skipped', []) and 'identical' in doc['reason']


def test_evaluate_uses_the_rz_diff_environment_variable(capsys, monkeypatch, store):
    seen = {}

    def providers(store_, imports, *, rz_diff, engines):
        seen['rz'] = rz_diff
        return {}
    monkeypatch.setattr(cli.E, 'default_providers', providers)
    monkeypatch.setenv('RZ_DIFF', '/opt/rizin/bin/rz-diff')
    run(capsys, 'evaluate', '--engines', 'rz-diff')
    assert seen['rz'] == '/opt/rizin/bin/rz-diff'


def test_corpus_hook_dispatches_to_the_tier_r_cli(capsys):
    assert corpus.main(['known-answer', 'catalogue-check']) == 0
    assert json.loads(capsys.readouterr().out)['command'] == 'catalogue-check'


@pytest.mark.parametrize('argv', [['bogus'], [], ['evaluate', '--symbols', 'maybe']], ids=['unknown', 'none', 'bad-flag'])
def test_argparse_errors_exit_2(capsys, argv):
    assert cli.main(argv) == 2
    capsys.readouterr()


def test_usage_errors_exit_2(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv('PATCHTRACE_CALIB_ROOT', str(tmp_path / 'empty'))
    assert run(capsys, 'evaluate')[0] == 2                                   # no label folder
    assert run(capsys, 'evaluate', '--store', str(ROOT / 'x'))[0] == 2       # inside the work tree
    assert run(capsys, 'evaluate', '--engines', 'ida')[0] == 2


def test_evaluate_with_nothing_installed_is_blocked_exit_3(capsys, store, monkeypatch):
    monkeypatch.setenv('PATH', str(store))                                   # no rz-diff on PATH
    code, doc = run(capsys, 'evaluate')
    assert code == 3 and doc['status'] == 'blocked' and set(doc['blocked']) == {'rz-diff', 'bindiff', 'ghidriff', 'attention'}
    report = Path(doc['report'])
    assert C.load_report(report.read_bytes()).report_sha256 == doc['report_sha256']
    md = report.with_suffix('.md').read_text(encoding='utf-8')
    assert md.count('BLOCKED') == 4 and doc['report_sha256'] in md


def test_evaluate_with_imports_scores_and_exits_0(capsys, store):
    imports = store / 'imports'
    imports.mkdir()
    build(imports / 'syn-eng.BinDiff', hashes=(LABELS.older.sha256, LABELS.newer.sha256),
          functions=[(1, BASE + 0x1000, 'a', BASE + 0x1000, 'a', 1.0, 1.0, 0, 7)])
    (imports / 'syn-eng.ghidriff.json').write_text(json.dumps(_ghidriff()))
    code, doc = run(capsys, 'evaluate', '--engines', 'bindiff,ghidriff')
    assert (code, doc['status'], doc['engines']) == (0, 'ok', {'bindiff': 'ok', 'ghidriff': 'ok'})
    report = C.load_report(Path(doc['report']).read_bytes())
    assert report.strata['authored']['bindiff'].identity_tp == 1
    assert report.strata['authored']['ghidriff'].identity_tp == 6
    # same inputs, same report path and digest
    assert run(capsys, 'evaluate', '--engines', 'bindiff,ghidriff')[1]['report_sha256'] == doc['report_sha256']


def test_evaluate_failed_engine_exits_1(capsys, store):
    imports = store / 'imports'
    imports.mkdir()
    (imports / 'syn-eng.BinDiff').write_bytes(b'not sqlite')
    code, doc = run(capsys, 'evaluate', '--engines', 'bindiff')
    assert code == 1 and doc['status'] == 'failed'


def test_schemas_command_regenerates_the_committed_files(capsys, tmp_path):
    code, doc = run(capsys, 'schemas', '--out', str(tmp_path / 'schemas'))
    assert code == 0
    committed = ROOT / 'docs' / 'schemas' / 'corpus'
    for written in doc['written']:
        rel = Path(written).relative_to(tmp_path / 'schemas')
        assert (tmp_path / 'schemas' / rel).read_bytes() == (committed / rel).read_bytes(), rel


def test_catalogue_check_is_clean(capsys):
    code, doc = run(capsys, 'catalogue-check')
    assert (code, doc['problems']) == (0, [])


def test_toolchain_reports_profiles_and_blocked_rzdiff(capsys, monkeypatch):
    code, doc = run(capsys, 'toolchain')
    assert code in (0, 3) and set(doc['profiles']) == {'msvc-free', 'mingw-gcc', 'mingw-clang'}
    assert (code == 0) == (doc['status'] == 'ok')


def test_real_suite_end_to_end_manifest_and_annotation(capsys, store, record_live_status, monkeypatch):
    """Real clang/lld build of corpus/ours/_template/tiny, then manifest and annotation over the real images.
    Engines are not run (--engines bindiff,ghidriff without imports): BLOCKED, never a score."""
    require(record_live_status, 'msvc-free')
    (store / 'labels' / 'syn-eng.json').unlink()          # only the real pair below
    code, doc = run(capsys, 'build-suite', str(ROOT / 'corpus' / 'ours' / '_template' / 'tiny'))
    assert code == 0 and doc['cross_check_problems'] == []
    code, doc = run(capsys, 'evaluate', '--engines', 'bindiff,ghidriff')
    assert code == 3 and doc['status'] == 'blocked'
    code, doc = run(capsys, 'manifest', '--tool-git', 'testsha')
    assert code == 0 and doc['binaries'] == 2
    manifest = corpus.load_manifest(Path(doc['manifest']).read_bytes())
    assert {b.tier for b in manifest.binaries} == {'R'}
    code, doc = run(capsys, 'annotate')
    assert code == 0 and doc['pending'] == 0 and doc['records'] == doc['candidates'] > 0
    records = K.load_labels(Path(doc['labels']).read_bytes())
    assert {r.source for r in records} == {'synthetic-exact'} and all(r.A == 'same' for r in records)
    assert run(capsys, 'annotate')[1]['appended'] == 0                      # idempotent
