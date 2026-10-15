"""`patchtrace strings` through the real `cli.main` on the synthetic SYN-WB3-1 pair (built-in scan; no FLOSS)."""
from __future__ import annotations

import hashlib
import json
import threading

import pytest
from strings_pe import synergy_pair

from patchtrace import cli
from patchtrace.intelligence.contracts import Anchor, AnchorSet
from patchtrace.service import ProjectService
from patchtrace.strings import cli as strings_cli
from patchtrace.strings.contracts import StringsError
from patchtrace.strings.scan import BuiltinScanSource
from patchtrace.strings.table import FLAG_SECRET

EXCEEDS = 'index %u exceeds length %u'


@pytest.fixture(scope='module')
def root(tmp_path_factory):
    base = tmp_path_factory.mktemp('strings-cli')
    pair = synergy_pair()
    for side, data in (('older', pair.older), ('newer', pair.newer)):
        (base / f'{side}.exe').write_bytes(data)
    service = ProjectService.create(base / 'older.exe', base / 'newer.exe', 'strings', base / 'case')
    path = service.root
    service.store.close()
    return path


def invoke(capsys, *argv):
    code = cli.main(['strings', *argv])
    out, err = capsys.readouterr()
    return code, out, err


def document(out):
    return json.loads(out)


def test_scan_builtin_smoke_path_is_one_json_object(root, capsys):
    code, out, err = invoke(capsys, 'scan', str(root), '--builtin', '--json')
    doc = document(out)
    assert code == 0 and doc['contract'] == 'enrichment-cli/1' and doc['command'] == 'strings scan'
    assert out.count('\n') == 1 and doc['status'] == 'complete' and doc['result']['source'] == 'builtin-scan'
    assert [s['side'] for s in doc['result']['sides']] == ['older', 'newer']
    assert all(s['rows_kept'] > 0 and s['stages']['static']['state'] == 'complete' for s in doc['result']['sides'])
    assert str(root) not in out


def test_scan_requires_builtin(root, capsys):
    code, out, err = invoke(capsys, 'scan', str(root), '--json')
    assert code == 2 and document(out)['status'] == 'failed' and '--builtin' in err


def test_delta_has_the_added_message_and_no_path(root, capsys):
    code, out, _err = invoke(capsys, 'delta', str(root), '--json')
    doc = document(out)['result']
    assert code == 0 and doc['contract'] == 'strings-delta/1' and doc['comparable']
    added = [c for c in doc['changes'] if c['display'] == EXCEEDS]
    assert [c['status'] for c in added] == ['only-newer'] and 'format' in added[0]['cues']
    assert doc['sources'] == {'older': 'builtin-scan', 'newer': 'builtin-scan'} and str(root) not in out


def test_list_filters_by_change_and_cue(root, capsys):
    code, out, _err = invoke(capsys, 'list', str(root), '--change', 'only-older', '--json')
    older = document(out)['result']['changes']
    assert code == 0 and older and {c['status'] for c in older} == {'only-older'}
    code, out, _err = invoke(capsys, 'list', str(root), '--cue', 'format', '--side', 'newer', '--json')
    assert code == 0 and {c['display'] for c in document(out)['result']['changes']} >= {EXCEEDS}
    code, out, _err = invoke(capsys, 'list', str(root), '--limit', '1', '--json')
    assert len(document(out)['result']['changes']) == 1


def test_list_without_matches_is_exit_4(root, capsys):
    code, out, _err = invoke(capsys, 'list', str(root), '--cue', 'guid', '--json')
    assert code == 4 and document(out)['status'] == 'complete' and document(out)['result']['total'] == 0


def test_list_text_output_is_plain_lines(root, capsys):
    code, out, _err = invoke(capsys, 'list', str(root))
    assert code == 0 and '+ only-newer' in out and EXCEEDS in out


def test_explain_one_string(root, capsys):
    _code, out, _err = invoke(capsys, 'delta', str(root), '--json')
    change = next(c for c in document(out)['result']['changes'] if c['display'] == EXCEEDS)
    code, out, _err = invoke(capsys, 'explain', str(root), '--id', change['id'], '--json')
    result = document(out)['result']
    assert code == 0 and result['change']['id'] == change['id']
    assert result['provenance']['newer'][0]['source'] == 'builtin-scan'


def test_explain_unknown_id_is_exit_2(root, capsys):
    code, out, _err = invoke(capsys, 'explain', str(root), '--id', 'f' * 64, '--json')
    assert code == 2 and document(out)['status'] == 'failed'


def test_source_floss_without_stored_evidence_is_exit_2(root, capsys):
    code, out, err = invoke(capsys, 'delta', str(root), '--source', 'floss', '--json')
    assert code == 2 and 'intel-tools run' in err and document(out)['result'] is None


def test_anchor_file_feeds_cues_and_hits(root, tmp_path, capsys):
    anchor = Anchor(anchor_id=hashlib.sha256(b'a').hexdigest(), kind='string', value='exceeds length',
                    source='csaf-title', quality='explicit', label='advisory phrase')
    path = tmp_path / 'anchors.json'
    path.write_text(AnchorSet(cve='CVE-2026-0001', anchors=(anchor,)).model_dump_json(), encoding='utf-8')
    code, out, _err = invoke(capsys, 'delta', str(root), '--anchors', str(path), '--json')
    result = document(out)['result']
    assert code == 0 and [h['match'] for h in result['anchors']['hits']] == ['substring']
    assert 'advisory-text' in next(c for c in result['changes'] if c['display'] == EXCEEDS)['cues']


@pytest.mark.parametrize('content', ['{not json', '{"cve": "nope"}'], ids=['syntax', 'schema'])
def test_bad_anchor_file_is_exit_2(root, tmp_path, capsys, content):
    path = tmp_path / 'anchors.json'
    path.write_text(content, encoding='utf-8')
    code, _out, err = invoke(capsys, 'delta', str(root), '--anchors', str(path), '--json')
    assert code == 2 and 'AnchorSet' in err and str(tmp_path) not in err


@pytest.mark.parametrize('fmt', ['json', 'csv'])
def test_export_writes_atomically_and_refuses_to_clobber(root, tmp_path, capsys, fmt):
    target = tmp_path / f'out.{fmt}'
    code, out, _err = invoke(capsys, 'export', str(root), '--out', str(target), '--format', fmt, '--json')
    result = document(out)['result']
    assert code == 0 and result['file'] == target.name and result['redacted'] and result['rows'] > 0
    assert hashlib.sha256(target.read_bytes()).hexdigest() == result['sha256'] and str(tmp_path) not in out
    code, out, _err = invoke(capsys, 'export', str(root), '--out', str(target), '--format', fmt, '--json')
    assert code == 2 and document(out)['status'] == 'failed'
    code, _out, _err = invoke(capsys, 'export', str(root), '--out', str(target), '--format', fmt, '--force')
    assert code == 0 and [p.name for p in tmp_path.iterdir()] == [target.name]


def test_cancelled_scan_is_exit_5(root):
    argv = ['strings', 'scan', str(root), '--builtin']
    args = cli._parser(argv).parse_args(argv)
    stop = threading.Event()
    stop.set()
    with pytest.raises(cli.CliError) as raised:
        strings_cli.dispatch(args, stop)
    assert raised.value.code == cli.CANCELLED


def test_table_from_source_keeps_the_basis_and_flags_secrets(tmp_path):
    path = tmp_path / 'a.bin'
    path.write_bytes(b'\0AKIAIOSFODNN7EXAMPLE\0plain words here\0')
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    table = strings_cli.table_from_source(BuiltinScanSource(path, artifact_sha256=sha, side='newer').load())
    assert table.basis.side == 'newer' and table.basis.parts[0].source == 'builtin-scan' and len(table) == 2
    assert [bool(row.flags & FLAG_SECRET) for row in table] == [True, False]
    assert strings_cli.reveal_map({'newer': table}) == {
        hashlib.sha256(b'AKIAIOSFODNN7EXAMPLE').hexdigest(): 'AKIAIOSFODNN7EXAMPLE'}


def test_a_project_without_both_artifacts_is_a_typed_input_error():
    class Service:
        class project:
            artifacts = ()
    with pytest.raises(StringsError) as raised:
        strings_cli._artifacts(Service)
    assert raised.value.code == 'PT-STR-INPUT'
