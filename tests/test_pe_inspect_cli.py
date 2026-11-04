"""`patchtrace inspect` (SPEC-51 D2-5): arguments, trust-mode consent, exit codes, envelope, read-only and no absolute
paths. Nothing is executed and no network is used."""
from __future__ import annotations

import argparse
import json
import threading
from pathlib import Path

import pytest
from pe_meta_builder import meta_pe

from patchtrace import cli as main_cli
from patchtrace.cli import CliError
from patchtrace.cli_commands import discover
from patchtrace.pe_overview import cli as icli
from patchtrace.service import ProjectService


def invoke(capsys, *argv, cancel: threading.Event | None = None):
    parser = argparse.ArgumentParser(prog='patchtrace')
    sub = parser.add_subparsers(dest='command', required=True)
    handlers: dict = {}

    def common(p):
        p.add_argument('--json', action='store_true')
        return p
    icli.register(sub, common, handlers)
    args = parser.parse_args(['inspect', *argv])
    try:
        code = handlers['inspect'](args, cancel or threading.Event())
        message = ''
    except CliError as error:
        code, message = error.code, str(error)
    out, err = capsys.readouterr()
    return code, out, err, message


def make_project(tmp_path: Path, older: bytes, newer: bytes) -> Path:
    (tmp_path / 'older.exe').write_bytes(older)
    (tmp_path / 'newer.exe').write_bytes(newer)
    service = ProjectService.create(tmp_path / 'older.exe', tmp_path / 'newer.exe', 'case', tmp_path / 'case')
    root = service.root
    service.close()
    return root


@pytest.fixture
def pair(tmp_path):
    older = meta_pe('1.0.0.0', 'asInvoker')[0]
    newer = meta_pe('1.0.1.0', 'requireAdministrator', signed=False, sections_extra=b'\xCC')[0]
    return make_project(tmp_path, older, newer)


def test_both_sides_json_envelope(pair, capsys, tmp_path):
    code, out, _err, _msg = invoke(capsys, str(pair), '--json')
    assert code == 0
    doc = json.loads(out)
    assert (doc['contract'], doc['command'], doc['status']) == ('enrichment-cli/1', 'inspect', 'complete')
    result = doc['result']
    assert result['contract'] == 'pe-inspect/1'
    assert [s['side'] for s in result['sides']] == ['older', 'newer']
    older, newer = result['sides']
    assert older['labels']['embedded'] == 'Signature present, digest matches file; trust not evaluated on this platform'
    assert newer['labels']['embedded'] == 'Not signed'
    assert older['labels']['catalog'] == 'Not checked'
    assert older['signatures'][0]['digest_match'] is True and older['signatures'][0]['chain'] == 'not_evaluated'
    rows = {r['field']: r for r in result['comparison']}
    assert rows['Requested execution level']['status'] == 'changed'
    assert result['comparison'][0]['status'] == 'changed'
    assert result['trust'] == {'mode': 'offline', 'consent_online': False, 'network_used': False}
    assert str(tmp_path) not in out  # no absolute path anywhere


def test_output_is_stable(pair, capsys):
    first = invoke(capsys, str(pair), '--json')[1]
    second = invoke(capsys, str(pair), '--json')[1]
    assert first == second


def test_one_side_has_no_comparison(pair, capsys):
    code, out, _err, _msg = invoke(capsys, str(pair), '--side', 'older', '--json')
    result = json.loads(out)['result']
    assert code == 0 and [s['side'] for s in result['sides']] == ['older'] and result['comparison'] == []


def test_text_output_names_the_labels_and_changes(pair, capsys):
    code, out, _err, _msg = invoke(capsys, str(pair))
    assert code == 0
    assert 'OLDER' in out and 'NEWER' in out and 'Not signed' in out
    assert 'privilege request changed' in out
    assert 'newer build requests administrator rights and is not signed' in out


def test_online_trust_requires_consent(pair, capsys):
    code, out, _err, message = invoke(capsys, str(pair), '--trust', 'online', '--json')
    assert code == 2 and 'PT-PE-CONSENT-REQUIRED' in message and out == ''


def test_consent_without_online_is_invalid(pair, capsys):
    code, _out, _err, message = invoke(capsys, str(pair), '--consent-online')
    assert code == 2 and 'PT-PE-CONSENT-REQUIRED' not in message and '--trust online' in message


@pytest.mark.parametrize('argv', [['--trust', 'cache'], ['--trust', 'online', '--consent-online']],
                         ids=['cache', 'online-consented'])
def test_revocation_modes_are_unavailable_in_this_build(pair, capsys, argv):
    code, _out, _err, message = invoke(capsys, str(pair), *argv)
    assert code == 3 and 'PT-PE-TRUST-UNAVAILABLE' in message


def _not_pe_for(monkeypatch, sides_not_pe: set[int]):
    """Ingestion only admits AMD64 PE32+ headers, so a side that reads as not_pe is simulated at the parser seam."""
    import patchtrace.pe_overview as package
    from patchtrace.pe_overview import PeOverview
    real, calls = package.inspect_pe, []

    def fake(reader, **kw):
        calls.append(1)
        if len(calls) - 1 in sides_not_pe:
            return PeOverview(size=reader.size, sha256=reader.sha256, status='not_pe')
        return real(reader, **kw)
    monkeypatch.setattr(package, 'inspect_pe', fake)


def test_no_pe_input_exits_4(pair, capsys, monkeypatch):
    _not_pe_for(monkeypatch, {0, 1})
    code, out, _err, _msg = invoke(capsys, str(pair), '--json')
    assert code == 4
    assert [s['status'] for s in json.loads(out)['result']['sides']] == ['not_pe', 'not_pe']


def test_one_unreadable_side_is_a_partial_failure(pair, capsys, monkeypatch):
    _not_pe_for(monkeypatch, {1})
    code, out, _err, _msg = invoke(capsys, str(pair), '--json')
    doc = json.loads(out)
    assert code == 3 and doc['status'] == 'partial'
    assert [s['status'] for s in doc['result']['sides']] == ['read', 'not_pe']
    assert doc['result']['comparison'] == []


def test_cancel_exits_5(pair, capsys):
    cancel = threading.Event()
    cancel.set()
    code, out, _err, _msg = invoke(capsys, str(pair), '--json', cancel=cancel)
    assert code == 5 and json.loads(out)['status'] == 'cancelled'


def test_project_is_not_modified(pair, capsys):
    before = {p: p.read_bytes() for p in pair.rglob('*') if p.is_file() and p.suffix != '.sqlite3-wal'
              and 'artifacts' in p.parts}
    invoke(capsys, str(pair), '--json')
    assert before and all(p.read_bytes() == data for p, data in before.items())


def test_verb_is_discovered_through_a_small_adapter():
    verbs, failed = discover()
    assert 'inspect' in verbs and not failed
    assert 'inspect' not in main_cli.COMMANDS
    source = (Path(main_cli.__file__).parent / 'cli_commands' / 'inspect.py').read_text(encoding='utf-8')
    assert len(source.splitlines()) <= 25
    assert 'PySide6' not in source


def test_end_to_end_through_the_real_entry_point(pair, capsys):
    code = main_cli.main(['inspect', str(pair), '--json'])
    out = capsys.readouterr().out
    assert code == 0 and json.loads(out)['command'] == 'inspect'
