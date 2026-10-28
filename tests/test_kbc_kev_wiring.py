"""K8 (KEV part): ``kb leads`` reads the local KEV catalog in use through the production path (KB-integration-plan 9;
KEV-integration-plan 4 and 6). Offline (sockets denied), synthetic data only.

The catalog is installed with the real ``kev`` service into a temporary folder and read back through ``kb leads
--kev-dir`` or the default folder, so these tests cover the wiring the CLI ships, not an injected fake. KEV may move a
CVE group and label it; it must never change which functions a group holds, their order or any other evidence chip.
"""
from __future__ import annotations

import gzip
import json

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import NOW, Kb
from kbc_k4a_golden import all_text, banned_in
from kbc_k4a_support import analysed_project
from kev_helpers import document, entry, render

from patchtrace.kbcorrelation import cli
from patchtrace.kbcorrelation.adapters import kev as kev_adapter
from patchtrace.kbcorrelation.adapters.kev import KevExploitation, load_exploitation
from patchtrace.kbcorrelation.leads import KevFact, KevSource
from patchtrace.kev import store as kev_store
from patchtrace.kev.contracts import utc
from patchtrace.kev.service import KevService

pytestmark = pytest.mark.usefixtures('no_sockets')
CVE_A, CVE_B = 'CVE-2099-20001', 'CVE-2099-20002'
MOMENT = utc(NOW)                                              # the KB clock of the Kb harness: 2099-02-15


@pytest.fixture
def kb(tmp_path, capsys):
    return Kb(tmp_path, capsys)


@pytest.fixture
def project(kb, tmp_path, capsys):
    return analysed_project(kb, tmp_path, capsys)


def install(folder, *, released='2099-02-14T12:00:00Z', version='2099.02.14', listed=(CVE_A,)):
    """Install a catalog listing ``listed`` with the real ``kev`` service (what ``patchtrace kev import`` does)."""
    rows = [entry(i + 1, cveID=cve, dateAdded='2099-02-12', dueDate='2099-03-05') for i, cve in enumerate(listed)]
    rows.append(entry(90, cveID='CVE-2098-00090'))
    source = folder.parent / f'catalog-{version}.json'
    source.write_bytes(render(document(rows, catalogVersion=version, dateReleased=released)))
    return KevService(folder, now=lambda: MOMENT).import_file(source)


def leads(kb, project, *extra):
    code, doc, _ = kb('leads', str(project), *extra)
    return code, doc['result']


def kev_chip(lead):
    return next(c for c in lead['chips'] if c['channel'] == 'exploitation')


def evidence(result):
    """Every group's functions, in order, with every chip except the KEV one; plus the unattributed list."""
    def strip(lead):
        return (lead['subject'], lead['rank_basis'],
                [(c['channel'], c['state'], c['text']) for c in lead['chips'] if c['channel'] != 'exploitation'])
    return ({g['group']: [strip(lead) for lead in g['leads']] for g in result['groups']},
            [strip(lead) for lead in result['unattributed']])


# ------------------------------------------------------------------------------------------- the production path

def test_valid_snapshot_is_read_through_kb_leads(kb, project, tmp_path):
    folder = tmp_path / 'kev'
    installed = install(folder)
    code, result = leads(kb, project, '--kev-dir', str(folder))
    assert code == 0
    groups = {g['group']: g for g in result['groups']}
    assert groups[CVE_A]['kev'] == 'listed'
    assert groups[CVE_A]['kev_text'] == ('KEV listed 2099-02-12 (catalog 2099.02.14, 1 day old); a CVE-level fact, not '
                                         'about this function')
    assert all(kev_chip(lead)['state'] == 'supports' for lead in groups[CVE_A]['leads'])
    source = result['kev_source']
    assert source['state'] == 'loaded'
    assert source['snapshot_id'] == installed.meta.snapshot_id
    assert (source['catalog_version'], source['date_released']) == ('2099.02.14', '2099-02-14T12:00:00Z')
    assert (source['source'], source['authenticity']) == ('local-import', 'unverified-local-file')
    assert (source['freshness'], source['age_days'], source['banner']) == ('fresh', 1, None)
    assert source['retrieved_at'] == installed.meta.retrieved_at
    assert 'Not listed does not mean not exploited.' in source['text']
    assert banned_in(all_text(result)) == []


def test_default_folder_is_the_kev_store_in_use(kb, project, tmp_path, monkeypatch):
    folder = tmp_path / 'default-kev'
    install(folder)
    monkeypatch.setattr(kev_adapter, 'default_kev_dir', lambda: folder)
    code, result = leads(kb, project)
    assert code == 0
    assert result['kev_source']['state'] == 'loaded'
    assert {g['group']: g['kev'] for g in result['groups']}[CVE_A] == 'listed'


def test_missing_folder_reads_not_loaded_and_creates_nothing(kb, project, tmp_path):
    folder = tmp_path / 'absent' / 'kev'
    code, result = leads(kb, project, '--kev-dir', str(folder))
    assert code == 0
    assert not folder.parent.exists()
    assert result['kev_source']['state'] == 'not-loaded'
    assert result['kev_source']['text'] == kev_adapter.TEXT_NOT_LOADED
    assert {g['kev'] for g in result['groups']} == {'no-snapshot'}
    assert all(g['kev_text'] == 'KEV: not loaded' for g in result['groups'])


def test_empty_folder_reads_not_loaded(kb, project, tmp_path):
    folder = tmp_path / 'kev'
    folder.mkdir()
    code, result = leads(kb, project, '--kev-dir', str(folder))
    assert code == 0
    assert result['kev_source']['state'] == 'not-loaded'


def test_outdated_snapshot_says_so_on_every_kev_text(kb, project, tmp_path):
    folder = tmp_path / 'kev'
    install(folder, released='2099-01-01T00:00:00Z', version='2099.01.01')
    code, doc, _ = kb('leads', str(project), '--kev-dir', str(folder))
    assert code == 0
    source = doc['result']['kev_source']
    assert (source['freshness'], source['age_days']) == ('stale', 45)
    assert source['banner'] and 'may have been added since' in source['banner']
    groups = {g['group']: g for g in doc['result']['groups']}
    assert groups[CVE_A]['kev_text'].startswith('KEV listed 2099-02-12 (catalog 2099.01.01, 45 days old; it may lack '
                                                'newer entries)')
    for group in groups.values():
        if group['kev'] == 'not-listed':
            assert 'it may lack newer entries' in group['kev_text']
            assert 'not listed does not mean not exploited' in group['kev_text']


def test_future_snapshot_points_at_the_clock(kb, project, tmp_path):
    folder = tmp_path / 'kev'
    install(folder, released='2099-03-01T00:00:00Z', version='2099.03.01')
    code, result = leads(kb, project, '--kev-dir', str(folder))
    assert code == 0
    assert result['kev_source']['freshness'] == 'future'
    assert "check this computer's clock" in {g['group']: g for g in result['groups']}[CVE_A]['kev_text']


def test_damaged_snapshot_reads_unreadable_and_the_leads_still_come(kb, project, tmp_path):
    folder = tmp_path / 'kev'
    install(folder)
    for path in (folder / kev_store.SNAPSHOT_DIR).iterdir():
        path.write_bytes(gzip.compress(b'{"not": "a catalog"}'))
    code, result = leads(kb, project, '--kev-dir', str(folder))
    assert code == 0
    assert result['kev_source']['state'] == 'unreadable'
    assert result['kev_source']['text'] == kev_adapter.TEXT_UNREADABLE
    assert {g['kev'] for g in result['groups']} == {'no-snapshot'}


def test_malformed_files_only_read_unreadable(kb, project, tmp_path):
    folder = tmp_path / 'kev'
    (folder / kev_store.META_DIR).mkdir(parents=True)
    (folder / kev_store.META_DIR / ('0' * 64 + '.json')).write_text('{', encoding='utf-8')
    (folder / kev_store.CURRENT_FILE).write_text('not json', encoding='utf-8')
    code, result = leads(kb, project, '--kev-dir', str(folder))
    assert code == 0
    assert result['kev_source']['state'] == 'unreadable'


def test_kev_never_changes_evidence_membership_or_order(kb, project, tmp_path):
    folder = tmp_path / 'kev'
    _, without = leads(kb, project, '--kev-dir', str(tmp_path / 'absent'))
    install(folder, listed=(CVE_A, CVE_B))
    _, with_kev = leads(kb, project, '--kev-dir', str(folder))
    assert evidence(with_kev) == evidence(without)
    assert [g['group'] for g in with_kev['groups'] if g['kev'] == 'listed']  # the snapshot was really used
    assert with_kev['not_applicable'] == without['not_applicable']


def test_output_is_deterministic(kb, project, tmp_path):
    folder = tmp_path / 'kev'
    install(folder)
    first = leads(kb, project, '--kev-dir', str(folder))
    second = leads(kb, project, '--kev-dir', str(folder))
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_text_report_names_the_snapshot(kb, project, tmp_path, capsys):
    folder = tmp_path / 'kev'
    install(folder)
    assert cli.main(['leads', str(project), '--workspace', str(kb.workspace), '--kev-dir', str(folder)],
                    env=kb.env) == 0
    text = capsys.readouterr().out
    assert 'KEV: catalog 2099.02.14 (1 day old; from a local file, unverified).' in text


# ------------------------------------------------------------------------------------------- the adapter alone

def test_adapter_answers_known_unknown_invalid_and_several_cves(tmp_path):
    folder = tmp_path / 'kev'
    installed = install(folder, listed=(CVE_A, CVE_B))
    kev = load_exploitation(folder, MOMENT)
    snapshot = installed.meta.snapshot_id
    assert kev.status(CVE_A) == KevFact('listed', '2099-02-12', snapshot, catalog_version='2099.02.14',
                                        freshness='fresh', age_days=1)
    assert kev.status(CVE_B).state == 'listed'
    assert kev.status('CVE-2099-29999') == KevFact('not-listed', None, snapshot, catalog_version='2099.02.14',
                                                   freshness='fresh', age_days=1)
    assert kev.status('not a cve').state == 'no-snapshot'      # says nothing about any CVE
    assert kev.source.state == 'loaded' and kev.source.notes == ()


def test_adapter_accepts_a_clock_callable(tmp_path):
    folder = tmp_path / 'kev'
    install(folder)
    assert load_exploitation(folder, lambda: MOMENT).source.age_days == 1


def test_adapter_without_a_catalog_answers_no_snapshot():
    kev = KevExploitation(None, KevSource())
    assert kev.status(CVE_A) == KevFact('no-snapshot')
    assert kev.source.state == 'not-loaded'


def test_adapter_reports_a_repaired_store_note(tmp_path):
    folder = tmp_path / 'kev'
    install(folder)
    (folder / kev_store.CURRENT_FILE).write_text('damaged', encoding='utf-8')
    kev = load_exploitation(folder, MOMENT)
    assert kev.source.state == 'loaded'
    assert kev.source.notes == (kev_store.NOTE_DAMAGED_POINTER,)


def test_leads_imports_no_kev_internals():
    import ast
    from pathlib import Path

    import patchtrace.kbcorrelation.leads as leads_module
    tree = ast.parse(Path(leads_module.__file__).read_text(encoding='utf-8'))
    modules = {node.module or '' for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not any('kev' in name for name in modules)


def test_unrelated_files_in_the_folder_are_not_a_catalog(tmp_path):
    folder = tmp_path / 'kev'
    (folder / 'notes').mkdir(parents=True)
    (folder / 'notes' / 'readme.txt').write_text('x', encoding='utf-8')
    (folder / kev_store.SNAPSHOT_DIR).mkdir()
    (folder / kev_store.SNAPSHOT_DIR / ('a' * 64 + '.json.gz' + kev_store.TMP_SUFFIX)).write_bytes(b'')
    assert load_exploitation(folder, MOMENT).source.state == 'not-loaded'
