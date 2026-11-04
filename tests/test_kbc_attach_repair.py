"""`kb attach --repair` (KB-integration-plan 7.5 and 8.1; todo K2 "kb attach --repair verb"). Synthetic; offline.

Repair is explicit: without ``--repair`` the verb only previews, per interrupted attach, what the repair would create,
add, keep or replace, and changes nothing. A repair that replaces a stored project row first writes a verified backup
of the project database (``verified_backup``); a failed backup refuses the whole repair. Nothing is ever deleted: a
differing source sidecar is kept aside before it is rewritten, and analyst notes and user files stay as they were.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import FixedClock, Kb, write_pair

from patchtrace import verified_backup
from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.store import WorkspaceStore
from patchtrace.service import ProjectService

pytestmark = pytest.mark.usefixtures('no_sockets')

EARLIER = 'Wording of an earlier context build.'


class Interrupt:
    """Crash-point seam that raises ``error`` at the first ``at`` reached after ``after`` (or at once)."""

    def __init__(self, at: str, *, after: str | None = None, error: type[BaseException] = RuntimeError):
        self.at, self.after, self.error = at, after, error
        self.armed, self.fired = after is None, False

    def __call__(self, point: str) -> None:
        if point == self.after:
            self.armed = True
        if self.armed and not self.fired and point == self.at:
            self.fired = True
            raise self.error('interrupted by the test')


def interrupted_attach(tmp_path: Path, capsys, fault: Interrupt) -> tuple[Kb, str, Path]:
    """An import-pair whose attach stopped at ``fault``; returns a fault-free ``kb``, the investigation, the project."""
    first = Kb(tmp_path, capsys, env=wiring.build_env(clock=FixedClock(), fault=fault))
    first.loaded()
    _, doc = first.search('KB5099001')
    inv = doc['result']['investigation_id']
    older, newer = write_pair(tmp_path)
    project = tmp_path / 'P'
    code, _, _ = first('import-pair', inv, '--older', str(older), '--newer', str(newer), '--project', str(project))
    assert code == 3 and fault.fired and (project / 'project.sqlite3').is_file()
    return Kb(tmp_path, capsys), inv, project


def pending(tmp_path, capsys):
    """Context-pending: the attach failed before its first project row (journal done, no context row)."""
    return interrupted_attach(tmp_path, capsys, Interrupt('attach_before_row'))


def unfinished(tmp_path, capsys):
    """Every row written, the final revision never committed (journal ``created``)."""
    return interrupted_attach(tmp_path, capsys, Interrupt('before_cas', after='attach_before_row'))


def project_rows(project: Path) -> dict[str, dict]:
    port = wiring.RealProjectPort()
    project_id = port.open_project(str(project))
    return {f'{kind}:{key}': json.loads(body) for kind in ('kb-investigation', 'kb-context')
            for key, body in port.list_rows(project_id, kind).items()}


def make_context_differ(project: Path) -> str:
    """The stored context row no longer equals the one a repair rebuilds (an earlier build, another clock)."""
    port = wiring.RealProjectPort()
    project_id = port.open_project(str(project))
    (key, body), = port.list_rows(project_id, 'kb-context').items()
    stored = json.loads(body)
    stored['context']['unknowns'] = [*stored['context']['unknowns'], EARLIER]
    port.put_row(project_id, 'kb-context', key, json.dumps(stored).encode())
    return f'kb-context:{key}'


def workspace_state(kb: Kb, inv: str):
    with WorkspaceStore(kb.workspace, create=False) as ws:
        return ws.journal_ops(), ws.attempts(inv), ws.decisions(inv), ws.current_revision(inv)


def tree(project: Path) -> dict[str, bytes]:
    """Project files except the databases (compared by their rows) and the lock every project open rewrites."""
    return {p.relative_to(project).as_posix(): p.read_bytes() for p in sorted(project.rglob('*'))
            if p.is_file() and p.name != '.patchtrace.lock' and '.sqlite3' not in p.name}


def repair_backups(project: Path) -> list[Path]:
    return sorted((project / 'backups').glob('project-pre-kb-repair-*.sqlite3'))


def changes(doc: dict) -> list[tuple[str, str, str | None]]:
    return [(c['target'], c['action'], c['name']) for step in doc['result']['repair_plan'] for c in step['changes']]


def test_attach_without_repair_previews_the_changes_and_changes_nothing(tmp_path, capsys):
    kb, inv, project = pending(tmp_path, capsys)
    before = (workspace_state(kb, inv), project_rows(project), tree(project))
    code, doc, _ = kb('attach', str(project), '--investigation', inv)
    assert code == 3 and doc['contract'] == 'enrichment-cli/1' and doc['command'] == 'kb attach'
    assert doc['status'] == 'partial' and doc['result']['backups'] == []
    (step,) = doc['result']['repair_plan']
    assert step['state'] == 'done' and step['project_id'] == doc['result']['links'][0]['project_id']
    planned = changes(doc)
    assert {(target, action) for target, action, _ in planned} == {('sidecar', 'keep'), ('row', 'add')}
    assert [name.split(':')[0] for target, _, name in planned if target == 'row'] == ['kb-investigation',
                                                                                      'kb-context']
    assert all(action != 'delete' for _, action, _ in planned)
    assert (workspace_state(kb, inv), project_rows(project), tree(project)) == before
    assert repair_backups(project) == []
    code, text, _ = kb('attach', str(project), '--investigation', inv, as_json=False)
    assert code == 3 and '"kb attach --repair" would' in text and 'add row kb-context:' in text
    assert 'keep ' not in text and 'Nothing is deleted' in text and str(tmp_path) not in text


def test_repair_follows_the_preview_and_needs_no_backup_when_it_only_adds(tmp_path, capsys):
    kb, inv, project = pending(tmp_path, capsys)
    _, preview, _ = kb('attach', str(project), '--investigation', inv)
    code, doc, _ = kb('attach', str(project), '--investigation', inv, '--repair')
    assert code == 0 and doc['status'] == 'complete'
    assert [link['state'] for link in doc['result']['links']] == ['attached']
    assert doc['result']['repair_plan'] == preview['result']['repair_plan'] and doc['result']['backups'] == []
    assert {name for target, _, name in changes(preview) if target == 'row'} == set(project_rows(project))
    assert repair_backups(project) == []
    code, again, _ = kb('attach', str(project), '--investigation', inv, '--repair')
    assert code == 0 and again['result']['repair_plan'] == [] and again['result']['links'] == doc['result']['links']


@pytest.mark.parametrize('point,after,state', [('after_project_create', None, 'intent'),
                                               ('before_cas', 'after_project_create', 'created')],
                         ids=['intent', 'created'])
def test_the_preview_names_what_an_unfinished_create_will_write(tmp_path, capsys, point, after, state):
    kb, inv, project = interrupted_attach(tmp_path, capsys, Interrupt(point, after=after))
    _, preview, _ = kb('attach', str(project), '--investigation', inv)
    assert [step['state'] for step in preview['result']['repair_plan']] == [state]
    planned = changes(preview)
    assert (planned[0] == ('project', 'create', None)) is (state == 'intent')
    assert {action for target, action, _ in planned if target != 'project'} == {'add'}
    code, doc, _ = kb('attach', str(project), '--investigation', inv, '--repair')
    assert code == 0 and doc['result']['backups'] == []
    assert {name for target, _, name in planned if target == 'row'} == set(project_rows(project))
    assert all((project / name).is_file() for target, _, name in planned if target == 'sidecar')


def test_a_replaced_row_is_kept_in_a_verified_backup_written_before_the_repair(tmp_path, capsys):
    kb, inv, project = unfinished(tmp_path, capsys)
    row = make_context_differ(project)
    _, preview, _ = kb('attach', str(project), '--investigation', inv)
    assert ('row', 'replace', row) in changes(preview) and 'replace row kb-context:' in kb(
        'attach', str(project), '--investigation', inv, as_json=False)[1]
    code, doc, _ = kb('attach', str(project), '--investigation', inv, '--repair')
    assert code == 0 and [link['state'] for link in doc['result']['links']] == ['attached']
    (backup,) = repair_backups(project)
    assert doc['result']['backups'] == [backup.relative_to(project).as_posix()]
    copy = sqlite3.connect(f'{backup.as_uri()}?mode=ro', uri=True)
    try:
        assert copy.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        kept = copy.execute('SELECT body FROM enrichment_entries WHERE id=?', (row,)).fetchone()[0]
    finally:
        copy.close()
    assert EARLIER in json.loads(kept)['context']['unknowns']  # the replaced bytes survive in the backup
    assert EARLIER not in project_rows(project)[row]['context']['unknowns']
    assert kb('explain', str(project))[0] == 0
    code, again, _ = kb('attach', str(project), '--investigation', inv, '--repair')
    assert code == 0 and again['result']['repair_plan'] == [] and repair_backups(project) == [backup]


def test_a_backup_that_fails_verification_refuses_the_repair_and_changes_nothing(tmp_path, capsys, monkeypatch):
    kb, inv, project = unfinished(tmp_path, capsys)
    row = make_context_differ(project)

    def unverified(*args, **kwargs):
        raise verified_backup.BackupError('PT-STORAGE: pre-kb-repair database backup failed verification (test)')

    monkeypatch.setattr(verified_backup, 'write_verified_backup', unverified)
    before = (workspace_state(kb, inv), project_rows(project), tree(project))
    code, doc, err = kb('attach', str(project), '--investigation', inv, '--repair')
    assert code == 3 and doc['status'] == 'failed' and doc['result'] is None
    assert doc['error'].startswith('PT-KBC-STORAGE') and 'backup' in doc['error'] and 'Traceback' not in err
    assert (workspace_state(kb, inv), project_rows(project), tree(project)) == before
    assert EARLIER in project_rows(project)[row]['context']['unknowns']


def test_repair_never_deletes_analyst_data_and_keeps_a_differing_sidecar_aside(tmp_path, capsys):
    kb, inv, project = pending(tmp_path, capsys)
    service = ProjectService.open(project, maintenance=False)
    try:
        service.annotate(service.project.artifacts[0].id, 'Analyst note written before the repair.')
    finally:
        service.close()
    (project / 'analyst.txt').write_text('my own notes\n', encoding='utf-8', newline='\n')
    (source,) = (project / 'kb' / 'sources').glob('*.json.gz')
    source.write_bytes(b'damaged sidecar bytes')
    decisions = workspace_state(kb, inv)[2]
    _, preview, _ = kb('attach', str(project), '--investigation', inv)
    assert ('sidecar', 'replace', f'kb/sources/{source.name}') in changes(preview)
    code, doc, _ = kb('attach', str(project), '--investigation', inv, '--repair')
    assert code == 0 and [link['state'] for link in doc['result']['links']] == ['attached']
    assert (project / 'analyst.txt').read_text(encoding='utf-8') == 'my own notes\n'
    service = ProjectService.open(project, maintenance=False)
    try:
        assert [a.text for a in service.project.annotations] == ['Analyst note written before the repair.']
    finally:
        service.close()
    (aside,) = source.parent.glob(f'{source.name}.replaced-*')
    assert aside.read_bytes() == b'damaged sidecar bytes' and source.read_bytes()[:2] == b'\x1f\x8b'
    assert workspace_state(kb, inv)[2] == decisions
    assert kb('explain', str(project))[0] == 0


def test_attach_exit_codes_for_arguments_and_cancellation(tmp_path, capsys):
    kb, inv, project = pending(tmp_path, capsys)
    assert kb('attach', str(project))[0] == 2  # --investigation is required
    code, doc, _ = kb('attach', str(project), '--investigation', '00000000-0000-4000-8000-00000000dead', '--repair')
    assert code == 2 and doc['status'] == 'failed' and 'PT-KBC-INPUT' in doc['error']
    stop = Kb(tmp_path, capsys, env=wiring.build_env(clock=FixedClock(), fault=Interrupt(
        'attach_before_row', error=KeyboardInterrupt)))
    code, doc, _ = stop('attach', str(project), '--investigation', inv, '--repair')
    assert code == 5 and doc['status'] == 'cancelled'
    code, doc, _ = kb('attach', str(project), '--investigation', inv, '--repair')
    assert code == 0 and [link['state'] for link in doc['result']['links']] == ['attached']
