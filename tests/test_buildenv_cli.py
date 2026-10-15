"""`patchtrace build-env` (DIE D4): exit codes, envelope, read-only behaviour and hostile text.

`cli.py` is frozen for this slice, so the tests mount the module's own `register` on a local parser (`invoke`); the
integrator's 6-line hook only adds the same call. DiE results are seeded into the stored tool rows the way
`intel-tools run` writes them; nothing is executed and no network is used."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from test_buildenv_support import GOLDENS, LINUX_DB, PIN, detects, evidence_of
from test_intel_tools_pe import PAIRS

from patchtrace.artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
from patchtrace.buildenv import cli as bcli
from patchtrace.cli import CliError
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.tools.common import ToolManifest, ToolRun
from patchtrace.intelligence.tools.store import ToolStore
from patchtrace.nway import series as nway_series
from patchtrace.service import ProjectService


def invoke(capsys, *argv, cancel: threading.Event | None = None):
    parser = argparse.ArgumentParser(prog='patchtrace')
    sub = parser.add_subparsers(dest='command', required=True)

    def common(p):
        p.add_argument('--json', action='store_true')
        return p
    handlers: dict = {}
    bcli.register(sub, common, handlers)
    args = parser.parse_args(['build-env', *argv])
    try:
        code = handlers['build-env'](args, cancel or threading.Event())
    except CliError as error:
        code = error.code
    out, err = capsys.readouterr()
    return code, out, err


def make_project(tmp_path, pair: str = 'diec-toolchain') -> Path:
    older, newer = PAIRS[pair]()
    (tmp_path / 'o.exe').write_bytes(older)
    (tmp_path / 'n.exe').write_bytes(newer)
    service = ProjectService.create(tmp_path / 'o.exe', tmp_path / 'n.exe', 'case', tmp_path / 'case')
    root = service.root
    service.close()
    return root


def seed_die(root: Path, side: str, raw: bytes, *, input_hash: str | None = None) -> None:
    service = ProjectService.open(root)
    try:
        artifact = next(a for a in service.project.artifacts if a.side == side)
        tools = ToolStore(EnrichmentStore(service.store), service.root, service.project.id, service.project.revision)
        tools.publish_evidence(evidence_of(raw, side, artifact.sha256))
        manifest = ToolManifest(engine='diec', license='MIT', supported=True, version='3.21',
                                executable_sha256='e' * 64, rules_sha256=LINUX_DB, rules_source='directory')
        tools.publish_run(ToolRun(
            run_id=f'run-{side}', engine='diec', side=side, input_artifact_hash=input_hash or artifact.sha256,
            config_digest=PIN, cache_key=PIN, started_at='2026-10-14T00:00:00Z', elapsed=5, status='ok',
            profile='full', options={'argv': 'diec/1', 'mode': 'signature'}, manifest=manifest))
    finally:
        service.close()


def seed_pair(root: Path, kind: str) -> None:
    for side in ('older', 'newer'):
        seed_die(root, side, (GOLDENS / f'diec-{kind}-{side}.json').read_bytes())


def make_unreadable(monkeypatch, *sides: str) -> None:
    """The project verifies its copies on open, so a side that cannot be read later is simulated at the reader."""
    real = VerifiedArtifactReader.open_artifact

    def open_artifact(artifact, root, cancel=None):
        if artifact.side in sides:
            raise ArtifactBytesError('missing', 'gone')
        return real(artifact, root, cancel)
    monkeypatch.setattr(VerifiedArtifactReader, 'open_artifact', staticmethod(open_artifact))


def doc(out: str) -> dict:
    document = json.loads(out)
    assert document['contract'] == 'enrichment-cli/1'
    return document


# --- show -------------------------------------------------------------------------------------------------------------

def test_show_without_stored_tool_results_says_not_run(tmp_path, capsys):
    root = make_project(tmp_path)
    code, out, _err = invoke(capsys, 'show', str(root), '--json')
    document = doc(out)
    assert code == 0 and document['command'] == 'build-env show' and document['status'] == 'complete'
    assert [(s['side'], s['status'], s['die']) for s in document['result']['sides']] == [
        ('older', 'read', 'not-run'), ('newer', 'read', 'not-run')]
    assert any(f['key'] == 'linker_field' for f in document['result']['sides'][0]['facts'])
    assert str(tmp_path) not in out and 'technical' not in document['result']['sides'][0]


def test_show_uses_stored_die_rows_and_technical_adds_raw_details(tmp_path, capsys):
    root = make_project(tmp_path)
    seed_pair(root, 'toolchain')
    code, out, _err = invoke(capsys, 'show', str(root), '--side', 'newer', '--technical', '--json')
    [side] = doc(out)['result']['sides']
    assert code == 0 and side['side'] == 'newer' and side['die'] == 'ok'
    assert any(f['source'] == 'diec' for f in side['facts'])
    assert side['technical']['die_database_sha256'] == LINUX_DB and side['technical']['die_argv_version'] == 'diec/1'
    assert 'rich' in side['technical']


def test_show_text_is_plain_and_ends_with_the_disclaimer(tmp_path, capsys):
    root = make_project(tmp_path)
    code, out, _err = invoke(capsys, 'show', str(root))
    assert code == 0 and 'OLDER o.exe' in out and 'NEWER n.exe' in out
    assert out.rstrip().endswith('they are not proof of how a file was built.') and str(tmp_path) not in out


def test_show_one_unreadable_side_is_exit_3_and_prints_the_other(tmp_path, capsys, monkeypatch):
    root = make_project(tmp_path)
    make_unreadable(monkeypatch, 'older')
    code, out, _err = invoke(capsys, 'show', str(root), '--json')
    older, newer = doc(out)['result']['sides']
    assert code == 3 and doc(out)['status'] == 'partial'
    assert (older['status'], older['error'], newer['status']) == ('unreadable', 'PT-BUILD-INPUT', 'read')


def test_show_nothing_readable_is_exit_2(tmp_path, capsys, monkeypatch):
    root = make_project(tmp_path)
    make_unreadable(monkeypatch, 'older', 'newer')
    code, out, _err = invoke(capsys, 'show', str(root), '--json')
    assert code == 2 and doc(out)['status'] == 'failed'


def test_show_invalid_project_is_exit_2(tmp_path, capsys):
    assert invoke(capsys, 'show', str(tmp_path / 'missing'), '--json')[0] == 2


def test_cancelled_run_is_exit_5(tmp_path, capsys):
    root = make_project(tmp_path)
    flag = threading.Event()
    flag.set()
    code, out, _err = invoke(capsys, 'show', str(root), '--json', cancel=flag)
    assert code == 5 and doc(out)['status'] == 'cancelled'
    flag = threading.Event()
    flag.set()
    assert invoke(capsys, 'delta', str(root), '--json', cancel=flag)[0] == 5


def test_hostile_detection_text_is_plain_in_show_output(tmp_path, capsys):
    root = make_project(tmp_path)
    raw = detects(('compiler', 'Evil‮<img src=x>\x1b[31m\x07' + 'A' * 400, '1⁦.0'))
    seed_die(root, 'older', raw)
    code, out, _err = invoke(capsys, 'show', str(root), '--side', 'older')
    assert code == 0 and all(ch not in out for ch in ('‮', '⁦', '\x1b', '\x07'))
    assert max(len(line) for line in out.splitlines()) < 400


# --- delta ------------------------------------------------------------------------------------------------------------

def test_delta_toolchain_differs_is_exit_0(tmp_path, capsys):
    root = make_project(tmp_path)
    seed_pair(root, 'toolchain')
    code, out, _err = invoke(capsys, 'delta', str(root), '--json')
    result = doc(out)['result']
    assert code == 0 and result['toolchain'] == 'differs' and result['state'] == 'B4'
    assert result['orientation'] == 'older->newer' and result['die'] == {'older': 'ok', 'newer': 'ok'}
    assert any(c['status'] == 'changed' for c in result['changes']) and result['noise'][0]['effect']
    assert str(tmp_path) not in out


def test_delta_same_toolchain_with_nothing_found_is_exit_4(tmp_path, capsys):
    root = make_project(tmp_path, 'diec-same')
    seed_pair(root, 'same')
    code, out, _err = invoke(capsys, 'delta', str(root), '--json')
    result = doc(out)['result']
    assert code == 4 and result['toolchain'] == 'same' and result['state'] == 'B3'


def test_delta_without_die_is_unknown_not_a_difference(tmp_path, capsys):
    root = make_project(tmp_path)
    code, out, _err = invoke(capsys, 'delta', str(root), '--json')
    result = doc(out)['result']
    assert code == 4 and result['toolchain'] == 'unknown' and result['die'] == {'older': 'not-run', 'newer': 'not-run'}
    assert 'die-not-run' in result['reasons']


def test_delta_with_die_on_one_side_only_is_partial_exit_3(tmp_path, capsys):
    root = make_project(tmp_path)
    seed_die(root, 'newer', (GOLDENS / 'diec-toolchain-newer.json').read_bytes())
    code, out, _err = invoke(capsys, 'delta', str(root), '--json')
    document = doc(out)
    assert code == 3 and document['status'] == 'partial' and 'die-one-side' in document['result']['reasons']
    assert document['result']['toolchain'] != 'differs'


def test_delta_ignores_stored_results_of_another_file_and_says_so(tmp_path, capsys):
    root = make_project(tmp_path)
    seed_die(root, 'older', (GOLDENS / 'diec-toolchain-older.json').read_bytes(), input_hash='f' * 64)
    code, out, err = invoke(capsys, 'delta', str(root), '--json')
    document = doc(out)
    assert code == 3 and document['result']['die']['older'] == 'not-run'
    assert any('older' in w and 'another file' in w for w in document['warnings'])


def test_delta_with_an_unreadable_side_compares_nothing(tmp_path, capsys, monkeypatch):
    root = make_project(tmp_path)
    make_unreadable(monkeypatch, 'newer')
    code, out, _err = invoke(capsys, 'delta', str(root), '--json')
    document = doc(out)
    assert code == 3 and document['result']['delta'] is None and document['result']['unreadable'] == ['newer']
    make_unreadable(monkeypatch, 'older', 'newer')
    assert invoke(capsys, 'delta', str(root), '--json')[0] == 2


def test_cli_never_writes_to_the_project(tmp_path, capsys):
    root = make_project(tmp_path)
    seed_pair(root, 'toolchain')
    service = ProjectService.open(root)
    revision = service.project.revision
    rows = service.store.connection.execute('SELECT COUNT(*) FROM enrichment_entries').fetchone()[0]
    service.close()
    invoke(capsys, 'show', str(root))
    invoke(capsys, 'delta', str(root))
    service = ProjectService.open(root)
    try:
        after = service.store.connection.execute('SELECT COUNT(*) FROM enrichment_entries').fetchone()[0]
        assert (service.project.revision, after) == (revision, rows)
    finally:
        service.close()


# --- timeline ---------------------------------------------------------------------------------------------------------

@pytest.fixture
def series_dir(tmp_path):
    files = []
    toolchain = PAIRS['diec-toolchain']()
    for name, data in (('b0.exe', PAIRS['floss-static']()[0]), ('b1.exe', toolchain[0]), ('b2.exe', toolchain[1])):
        (tmp_path / name).write_bytes(data)
        files.append(tmp_path / name)
    root = tmp_path / 'series'
    plan = nway_series.prepare(files, root)
    nway_series.save(nway_series.compute(plan), root / 'series.json')
    return root


def test_timeline_without_die_is_partial_exit_3(series_dir, capsys):
    code, out, _err = invoke(capsys, 'timeline', str(series_dir), '--json')
    result = doc(out)['result']
    assert code == 3 and [(h['from'], h['to'], h['status']) for h in result['hops']] == [
        (0, 1, 'not-run'), (1, 2, 'not-run')]
    assert str(series_dir) not in out and all(h['toolchain'] in ('same', 'differs', 'unknown') for h in result['hops'])


def test_timeline_compares_a_hop_with_stored_results_and_stays_partial_without_the_rest(series_dir, capsys):
    hop_one = next(p for p in series_dir.iterdir() if p.is_dir() and p.name.startswith('pair-1-2-'))
    seed_pair(hop_one, 'toolchain')
    code, out, _err = invoke(capsys, 'timeline', str(series_dir), '--json')
    hops = doc(out)['result']['hops']
    assert code == 3 and [h['status'] for h in hops] == ['not-run', 'complete'] and hops[1]['toolchain'] == 'differs'


def test_timeline_invalid_series_folder_is_exit_2(tmp_path, capsys):
    assert invoke(capsys, 'timeline', str(tmp_path), '--json')[0] == 2
    (tmp_path / 'series.json').write_text('{}', encoding='utf-8', newline='\n')
    assert invoke(capsys, 'timeline', str(tmp_path), '--json')[0] == 2


# --- isolation --------------------------------------------------------------------------------------------------------

def test_cli_paths_import_no_qt():
    code = ('import sys\nimport patchtrace.buildenv.cli, patchtrace.buildenv.store, patchtrace.buildenv.report\n'
            'sys.exit(1 if any(name.split(".")[0] in ("PySide6", "PyQt5", "PyQt6") for name in sys.modules) else 0)')
    assert subprocess.run([sys.executable, '-c', code], check=False).returncode == 0
