"""K3: the offline E0 acceptance script (KB-integration-plan 10.1), sockets denied. Steps 1-4 and 6 live here; step 5
(`rank` then `kb leads`) belongs to slice K4a, which owns `cli_leads` and the leads golden.

Reconciled count (K0f/K1 note): the baseline month holds 5 edge rows, 4 vendor-remediation edges plus 1 mention-only,
where plan 10.1 step 1 wrote "4 edges, 1 mention-only". The CLI reports `edges == 4`, `mention_only == 1`,
`edge_rows == 5`, and this script asserts exactly that.

Step 6 kills a real child process (SIGKILL where it exists, else `os._exit`) at a named crash point of the import, then
repairs from this process, as a second `kb` invocation would.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import BASELINE, NOW, Kb, fixture, write_pair

from patchtrace.service import ProjectService

pytestmark = pytest.mark.usefixtures('no_sockets')
HERE = Path(__file__).resolve().parent
SRC = HERE.parent / 'src'
CVE = 'CVE-2099-20001'
KILLED = (-9, 137)  # SIGKILL, or the os._exit(137) fallback

DRIVER = '''
import os, signal, sys
from patchtrace.kbcorrelation import cli, wiring

class Clock:
    def now_utc(self):
        return %(now)r

crash, nth, hits = os.environ.get('KBC_CRASH_AT'), int(os.environ.get('KBC_CRASH_NTH', '1')), [0]

def fault(point):
    if point == crash:
        hits[0] += 1
        if hits[0] == nth:
            if hasattr(signal, 'SIGKILL'):
                os.kill(os.getpid(), signal.SIGKILL)
            os._exit(137)

sys.exit(cli.main(sys.argv[1:], env=wiring.build_env(clock=Clock(), fault=fault)))
'''


@pytest.fixture
def kb(tmp_path, capsys):
    return Kb(tmp_path, capsys)


@pytest.fixture
def lead(kb):
    """Step 1 and the search that opens the investigation the later steps use."""
    kb.loaded()
    code, doc = kb.search('KB5099001')
    assert code == 0
    return doc['result']['investigation_id']


def test_step1_import_baseline_and_malformed_files(kb):
    code, doc, _ = kb('index', 'import', fixture(BASELINE))
    result = doc['result']
    assert code == 0 and len(result['documents']) == 1
    assert (result['totals']['edges'], result['totals']['mention_only'], result['totals']['edge_rows']) == (4, 1, 5)
    assert result['coverage']['state'] == 'complete_in_scope'
    before = kb('index', 'status')[1]['result']['documents']
    for bad in ('cvrf-2099-Feb-duplicate-key.json', 'cvrf-2099-Feb-dialect-unknown.xml'):
        code, doc, _ = kb('index', 'import', fixture(bad))
        assert code == 2 and doc['result']['index_changed'] is False
    assert kb('index', 'status')[1]['result']['documents'] == before


def test_step2_search_scopes_and_exit_codes(kb, tmp_path):
    kb.loaded()
    code, doc = kb.search('KB5099001')
    result = doc['result']
    assert code == 0
    assert {e['cve'] for e in result['edges']} == {CVE}
    assert sorted(e['product'] for e in result['edges']) == ['Example OS 24H2 ARM64', 'Example OS 24H2 x64']
    assert [e['cve'] for e in result['mention_only']] == ['CVE-2099-20003']
    assert kb.search('KB5099777')[0] == 4
    scope = tmp_path / 'scope.json'
    scope.write_text(json.dumps({'months': ['2099-Feb', '2099-Mar']}), encoding='utf-8')
    code, doc = kb.search('KB5099777', '--scope-file', str(scope))
    assert code == 3 and doc['status'] == 'partial'
    assert kb.search('KB12')[0] == 2


def test_step3_import_pair_grades_attaches_and_refuses_blocked_pairs(kb, tmp_path, lead):
    older, newer = write_pair(tmp_path)
    code, doc, _ = kb('import-pair', lead, '--older', str(older), '--newer', str(newer), '--project',
                      str(tmp_path / 'P'), '--name', 'demo')
    pair = doc['result']['pair']
    assert code == 0 and doc['result']['project']['state'] == 'attached'
    assert (pair['grade'], pair['lineage_state'], pair['fix_boundary']) == ('B', 'user-asserted', 'unverified')
    assert (tmp_path / 'P' / 'project.sqlite3').is_file() and list((tmp_path / 'P' / 'kb' / 'sources').glob('*.gz'))
    same_old, same_new = write_pair(tmp_path / 'same', newer=older.read_bytes())
    code, doc, _ = kb('import-pair', 'new', '--older', str(same_old), '--newer', str(same_new), '--project',
                      str(tmp_path / 'P2'))
    assert code == 4 and doc['status'] == 'unavailable'
    assert 'IDENTICAL_CONTENT' in doc['result']['pair']['reason_codes']
    assert not (tmp_path / 'P2').exists()
    old, renamed = write_pair(tmp_path / 'ren', newer_name='renamed.sys')
    argv = ['import-pair', 'new', '--older', str(old), '--newer', str(renamed), '--project', str(tmp_path / 'P3')]
    code, doc, _ = kb(*argv)
    assert code == 2 and doc['error'].startswith('NAME_MISMATCH') and not (tmp_path / 'P3').exists()
    assert kb(*argv, '--confirm-same-component')[0] == 0


def test_step4_explain_reports_the_stated_cwe_hypothesis_unknowns_and_coverage(kb, tmp_path, lead):
    older, newer = write_pair(tmp_path)
    kb('import-pair', lead, '--older', str(older), '--newer', str(newer), '--project', str(tmp_path / 'P'))
    code, doc, _ = kb('explain', str(tmp_path / 'P'), '--cve', CVE)
    row = doc['result']['cves'][0]
    assert code == 0 and row['card']['stated_cwe'] == 'CWE-125' and row['card']['stated_by'] == 'stated by vendor (CVRF)'
    assert [h['rule_id'] for h in row['hypotheses']] == ['R-MEMORY-READ']
    assert row['card']['applicability'].startswith('unknown') and row['card']['kev'] == 'not-loaded'
    assert doc['result']['coverage'][0]['state'] == 'complete_in_scope' and doc['result']['limitations']
    assert kb('explain', str(tmp_path / 'P'), '--cve', 'CVE-2099-20002')[0] == 4
    plain = kb('explain', str(tmp_path / 'P'), as_json=False)[1]
    assert 'stated by vendor (CVRF)' in plain and 'R-MEMORY-READ' in plain


def test_a_project_without_context_is_exit_4_with_the_kb17_copy(kb, tmp_path):
    old, new = write_pair(tmp_path)
    project = ProjectService.create(old, new, 'plain', tmp_path / 'plain')
    project.close()
    code, doc, _ = kb('explain', str(tmp_path / 'plain'))
    assert code == 4 and doc['status'] == 'unavailable'


def driver_run(tmp_path, argv, crash=None, nth=1):
    env = {**os.environ, 'PYTHONPATH': str(SRC), 'PYTHONFAULTHANDLER': '1'}
    env.pop('KBC_CRASH_AT', None)
    if crash:
        env.update(KBC_CRASH_AT=crash, KBC_CRASH_NTH=str(nth))
    return subprocess.run([sys.executable, '-c', DRIVER % {'now': NOW}, *argv], env=env, capture_output=True,
                          text=True, timeout=180, cwd=str(tmp_path), check=False)


@pytest.mark.parametrize('crash,nth', [('after_project_create', 1), ('before_cas', 4), ('after_sidecar_write', 1),
                                       ('attach_before_row', 1), ('before_cas', 5)],
                         ids=['create', 'cas-create', 'sidecar', 'row', 'cas-final'])
def test_step6_kill_after_project_creation_then_repair_is_idempotent(kb, tmp_path, lead, crash, nth):
    older, newer = write_pair(tmp_path)
    project = tmp_path / 'P'
    argv = ['import-pair', lead, '--older', str(older), '--newer', str(newer), '--project', str(project),
            '--workspace', str(kb.workspace), '--json']
    proc = driver_run(tmp_path, argv, crash, nth)
    assert proc.returncode in KILLED, proc.stderr
    assert (project / 'project.sqlite3').is_file()
    repair = ('attach', str(project), '--investigation', lead, '--repair')
    code, doc, _ = kb(*repair)
    assert code == 0 and [link['state'] for link in doc['result']['links']] == ['attached']
    first_state = hashlib.sha256((project / 'project.sqlite3').read_bytes()).hexdigest()
    code, again, _ = kb(*repair)
    assert code == 0 and again['result']['links'] == doc['result']['links']
    assert hashlib.sha256((project / 'project.sqlite3').read_bytes()).hexdigest() == first_state
    assert kb('explain', str(project), '--cve', CVE)[0] == 0
    service = ProjectService.open(project, maintenance=False)
    try:
        assert [a.side for a in service.project.artifacts] == ['older', 'newer']
    finally:
        service.close()
    assert list((project / 'kb' / 'investigations').glob('*.json')) and list((project / 'kb' / 'sources').glob('*.gz'))


def test_step6_export_is_escaped_without_local_paths_and_backup_restores_the_sidecars(kb, tmp_path, lead):
    older, newer = write_pair(tmp_path)
    project = tmp_path / 'P'
    kb('import-pair', lead, '--older', str(older), '--newer', str(newer), '--project', str(project))
    out = tmp_path / 'out.md'
    code, doc, _ = kb('export', str(project), str(out))
    text = out.read_text(encoding='utf-8')
    assert code == 0 and doc['result']['file'] == 'out.md' and str(tmp_path) not in text + json.dumps(doc)
    assert 'R\\-MEMORY\\-READ' in text and '<' not in text and '\r' not in text
    as_json = tmp_path / 'out.json'
    assert kb('export', str(project), str(as_json))[0] == 0 and str(tmp_path) not in as_json.read_text('utf-8')
    service = ProjectService.open(project, maintenance=False)
    try:
        backup = service.backup(tmp_path / 'backup')
    finally:
        service.close()

    def tree(root: Path):
        return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (root / 'kb').rglob('*') if p.is_file()}
    assert tree(backup) == tree(project) and tree(project)
    assert kb('explain', str(backup), '--cve', CVE)[0] == 0  # the restored copy still carries its rows

