"""D-kb-2 / KBF-06 s6 (KEV half): `pilot leads` reads the CISA KEV catalog `patchtrace kev` keeps in use.

Each CVE context carries `listed` (with its date) or `not-in-snapshot` with the snapshot id, and the run records
`PilotInputs.kev_snapshot_id`. KEV is CVE context only: it never changes the leads of a CVE or their order, and no
catalog, an empty folder or a store that cannot be read is `unknown`, never "not listed" and never an error of the run.
The catalog is the SYNTHETIC 2099 fixture with two ids replaced by pilot CVEs (not CISA data); the advisories are the
synthetic pilot fixtures. Nothing here is live evidence.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from patchtrace import cli
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.storage import AdvisoryStore
from patchtrace.kev import store as kev_store
from patchtrace.kev.contracts import KevError
from patchtrace.kev.service import KevService
from patchtrace.pilot import collect, read_model
from patchtrace.pilot.contracts import Kev
from patchtrace.pilot.service import localize
from patchtrace.service import ProjectService

TESTS = Path(__file__).resolve().parent
KEV_FIXTURE = TESTS / 'fixtures' / 'kev' / 'kev-synthetic-2099.json'
ADVISORIES = TESTS / 'fixtures' / 'pilot' / 'synergy-1'
SAMPLE_ADVISORY = ADVISORIES / 'sample-cwe125-advisory.json'   # CVE-2099-30001: maps the sample's builds, has a fit
TWO_CVE_ADVISORY = ADVISORIES / 'synthetic-pilot-advisory.json'  # CVE-2099-20001 and CVE-2099-20002
LISTED, ALSO_LISTED, UNLISTED = 'CVE-2099-20001', 'CVE-2099-30001', 'CVE-2099-20002'
LISTED_ON, ALSO_LISTED_ON = '2099-02-27', '2099-02-20'  # the dateAdded of the two fixture entries that are re-keyed


@pytest.fixture(autouse=True)
def _no_installed_catalog(monkeypatch, tmp_path_factory):
    """The CLI default folder of this process is an empty one, so no catalog installed on the machine takes part."""
    empty = tmp_path_factory.mktemp('no-kev-data')
    monkeypatch.setenv('LOCALAPPDATA', str(empty))
    monkeypatch.setenv('XDG_DATA_HOME', str(empty))


@pytest.fixture
def project(tmp_path):
    with ProjectService.sample(tmp_path / 'case') as service:
        root = service.root
    for source in (SAMPLE_ADVISORY, TWO_CVE_ADVISORY):
        with ProjectService.open(root) as service:
            AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id,
                          service.project.revision).add(source.read_bytes(), origin='local-import', uri=None,
                                                        file_name=source.name, retrieved_at='2099-03-01T00:00:00Z')
    return root


def install_catalog(folder: Path, scratch: Path, *, extra: dict[int, str] | None = None) -> str:
    """Install the synthetic catalog, re-keyed to list two pilot CVEs, into a KEV store under `folder`; its snapshot id."""
    document = json.loads(KEV_FIXTURE.read_text(encoding='utf-8'))
    entries = document['vulnerabilities']
    for index, cve in {0: LISTED, 1: ALSO_LISTED, **(extra or {})}.items():
        entries[index]['cveID'] = cve
    source = scratch / 'kev-pilot-synthetic.json'
    source.write_text(json.dumps(document, indent=1), encoding='utf-8', newline='\n')
    return KevService(folder).import_file(source).meta.snapshot_id


def assess(root: Path, **options):
    """(Collected, PilotAssessment) of one run, read the way `pilot leads` reads it."""
    with ProjectService.open(root) as service:
        collected = collect.collect(service, EnrichmentStore(service.store), cancel=threading.Event(), **options)
        return collected, localize(collected, collect.CONFIG, threading.Event())


def kev_of(assessment) -> dict[str, Kev]:
    return {c.cve: c.kev for c in assessment.cves}


def lead_order(assessment) -> dict[str | None, list[tuple]]:
    """Per CVE list (None = code only): every lead's key, rank, tie and class, in the order the run gives them."""
    lists = {None: [], **{c.cve: [] for c in assessment.cves}}
    for lead in assessment.leads:
        lists[lead.cve].append((lead.candidate_key, lead.rank, lead.tie.model_dump(), lead.lead_class))
    return lists


def leads_json(root: Path, capsys, *extra) -> tuple[int, dict]:
    code = cli.main(['pilot', 'leads', str(root), '--json', '--dry-run', '--limit', '0', *map(str, extra)])
    out, _err = capsys.readouterr()
    document = json.loads(out)
    assert document['contract'] == 'enrichment-cli/1'
    return code, document


# --- the collected inputs ---------------------------------------------------------------------------------------------

def test_a_listed_cve_carries_its_date_and_snapshot_and_an_unlisted_one_the_snapshot_only(project, tmp_path):
    snapshot = install_catalog(tmp_path / 'kev', tmp_path)
    collected, assessment = assess(project, kev_dir=tmp_path / 'kev')
    assert kev_of(assessment) == {
        LISTED: Kev(state='listed', date_added=LISTED_ON, snapshot_id=snapshot),
        ALSO_LISTED: Kev(state='listed', date_added=ALSO_LISTED_ON, snapshot_id=snapshot),
        UNLISTED: Kev(state='not-in-snapshot', snapshot_id=snapshot)}
    assert assessment.inputs.kev_snapshot_id == snapshot == collected.kev.snapshot_id()
    assert {c.cve: c.kev for c in collected.contexts} == kev_of(assessment) and collected.notes == ()


@pytest.mark.parametrize('folder', ['missing', 'empty', 'leftover'], ids=['missing', 'empty', 'leftover'])
def test_without_a_catalog_every_cve_is_unknown_and_the_result_is_the_one_of_no_kev_read(project, tmp_path, folder):
    kev_dir = tmp_path / 'kev'
    if folder != 'missing':
        (kev_dir / kev_store.SNAPSHOT_DIR).mkdir(parents=True)
    if folder == 'leftover':  # a crashed install leaves a temporary file: it is not a catalog
        (kev_dir / kev_store.SNAPSHOT_DIR / kev_store.tmp_name('x.json.gz')).write_bytes(b'partial')
    unread_collected, unread = assess(project)  # no folder named: KEV is not read (the Leads dock's call)
    collected, assessment = assess(project, kev_dir=kev_dir)
    assert set(kev_of(assessment).values()) == {Kev(state='unknown')} and len(assessment.cves) == 3
    assert assessment.inputs.kev_snapshot_id is None and collected.kev.snapshot_id() is None
    assert assessment.result_id == unread.result_id and assessment.inputs == unread.inputs
    assert collected.notes == unread_collected.notes == () and lead_order(assessment) == lead_order(unread)
    assert not kev_dir.exists() if folder == 'missing' else True  # reading never creates the folder


def _garbage_pointer(kev_dir: Path, _scratch: Path) -> None:
    kev_dir.mkdir()
    (kev_dir / kev_store.CURRENT_FILE).write_bytes(b'{"not": "a pointer"')


def _garbage_snapshot(kev_dir: Path, scratch: Path) -> None:
    install_catalog(kev_dir, scratch)
    for path in (kev_dir / kev_store.SNAPSHOT_DIR).iterdir():
        path.write_bytes(b'garbage, not gzip')


def _garbage_meta(kev_dir: Path, scratch: Path) -> None:
    install_catalog(kev_dir, scratch)
    (kev_dir / kev_store.CURRENT_FILE).unlink()
    for path in (kev_dir / kev_store.META_DIR).iterdir():
        path.write_bytes(b'\x00\xff')


DAMAGE = {'pointer': _garbage_pointer, 'snapshot': _garbage_snapshot, 'meta': _garbage_meta}


@pytest.mark.parametrize('damage', sorted(DAMAGE), ids=sorted(DAMAGE))
def test_a_store_that_cannot_be_read_is_unknown_with_one_note(project, tmp_path, damage):
    DAMAGE[damage](tmp_path / 'kev', tmp_path)
    unread = assess(project)[1]
    collected, assessment = assess(project, kev_dir=tmp_path / 'kev')
    assert set(kev_of(assessment).values()) == {Kev(state='unknown')}
    assert assessment.inputs.kev_snapshot_id is None and assessment.result_id == unread.result_id
    assert collected.notes == (collect.KEV_UNREADABLE,)


@pytest.mark.parametrize('error', [KevError('PT-KEV-STORAGE', 'a catalog file cannot be read'), PermissionError(13, 'x'),
                                   ValueError('x')], ids=['kev', 'os', 'value'])
def test_a_failing_read_is_unknown_with_the_note_never_an_error_of_the_run(project, tmp_path, monkeypatch, error):
    install_catalog(tmp_path / 'kev', tmp_path)

    def fails(_self):
        raise error
    monkeypatch.setattr(kev_store.KevStore, 'load_current', fails)
    collected, assessment = assess(project, kev_dir=tmp_path / 'kev')
    assert set(kev_of(assessment).values()) == {Kev(state='unknown')} and assessment.inputs.kev_snapshot_id is None
    assert collected.notes == (collect.KEV_UNREADABLE,)


def test_a_damaged_pointer_falls_back_to_the_stored_catalog_and_says_so(project, tmp_path):
    snapshot = install_catalog(tmp_path / 'kev', tmp_path)
    (tmp_path / 'kev' / kev_store.CURRENT_FILE).write_bytes(b'damaged')
    collected, assessment = assess(project, kev_dir=tmp_path / 'kev')
    assert kev_of(assessment)[LISTED] == Kev(state='listed', date_added=LISTED_ON, snapshot_id=snapshot)
    assert assessment.inputs.kev_snapshot_id == snapshot
    assert collected.notes == (f'CISA KEV: {kev_store.NOTE_DAMAGED_POINTER}',)


def test_kev_never_changes_the_leads_of_a_cve_or_their_order(project, tmp_path):
    install_catalog(tmp_path / 'kev', tmp_path)
    unread = assess(project)[1]
    read = assess(project, kev_dir=tmp_path / 'kev')[1]
    assert lead_order(read) == lead_order(unread) and lead_order(read)[ALSO_LISTED]  # the listed CVE has leads
    assert [c.cve for c in read.cves] == [c.cve for c in unread.cves]
    assert [c.counts for c in read.cves] == [c.counts for c in unread.cves]
    assert read.queue_count == unread.queue_count and read.channels == unread.channels
    assert read.result_id != unread.result_id  # the snapshot is an input of the result, so it is part of its identity


def test_a_catalog_id_longer_than_a_pilot_cve_does_not_stop_the_catalog(project, tmp_path):
    """KEV accepts up to nineteen digits after the year; such an id names no CVE a run can hold and is passed over."""
    snapshot = install_catalog(tmp_path / 'kev', tmp_path, extra={2: 'CVE-2099-' + '7' * 19})
    assessment = assess(project, kev_dir=tmp_path / 'kev')[1]
    assert kev_of(assessment)[LISTED] == Kev(state='listed', date_added=LISTED_ON, snapshot_id=snapshot)


def test_the_note_claims_nothing():
    note = collect.KEV_UNREADABLE.lower()
    for phrase in read_model.CLAIMS.allowed_phrases:
        note = note.replace(phrase.lower(), '')
    assert not [stem for stem in read_model.CLAIMS.banned_stems if stem in note], collect.KEV_UNREADABLE


# --- the command ------------------------------------------------------------------------------------------------------

def test_pilot_leads_json_shows_the_kev_record_of_each_cve(project, tmp_path, capsys):
    snapshot = install_catalog(tmp_path / 'kev', tmp_path)
    code, document = leads_json(project, capsys, '--kev-dir', tmp_path / 'kev')
    assert code == 0 and document['warnings'] == []
    assert {c['cve']: c['kev'] for c in document['result']['cves']} == {
        LISTED: {'state': 'listed', 'date_added': LISTED_ON, 'snapshot_id': snapshot},
        ALSO_LISTED: {'state': 'listed', 'date_added': ALSO_LISTED_ON, 'snapshot_id': snapshot},
        UNLISTED: {'state': 'not-in-snapshot', 'date_added': None, 'snapshot_id': snapshot}}
    assert cli.main(['pilot', 'leads', str(project), '--dry-run', '--kev-dir', str(tmp_path / 'kev')]) == 0
    out = capsys.readouterr().out
    assert f'CISA KEV: listed (added {LISTED_ON})' in out
    assert f'CISA KEV: not in the snapshot {snapshot[:12]}; absence says nothing about exploitation' in out


def test_pilot_leads_reads_the_folder_of_patchtrace_kev_by_default(project, tmp_path, capsys, monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'local'))
    snapshot = install_catalog(kev_store.default_kev_dir(), tmp_path)
    assert kev_store.default_kev_dir().is_relative_to(tmp_path)
    code, document = leads_json(project, capsys)
    assert code == 0 and {c['cve']: c['kev']['state'] for c in document['result']['cves']}[LISTED] == 'listed'
    assert {c['kev']['snapshot_id'] for c in document['result']['cves']} == {snapshot}


def test_pilot_leads_with_an_unreadable_catalog_warns_and_keeps_its_exit_code(project, tmp_path, capsys):
    _garbage_pointer(tmp_path / 'kev', tmp_path)
    missing_code, missing = leads_json(project, capsys, '--kev-dir', tmp_path / 'absent')
    code, document = leads_json(project, capsys, '--kev-dir', tmp_path / 'kev')
    assert code == missing_code == 0 and document['status'] == missing['status']
    assert document['warnings'] == [collect.KEV_UNREADABLE] and missing['warnings'] == []
    assert document['result']['result_id'] == missing['result']['result_id']
    assert {c['kev']['state'] for c in document['result']['cves']} == {'unknown'}
