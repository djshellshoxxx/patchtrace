"""K3/K5 glue: `kb pairs` and `kb plan` resolve pair candidates from Winbindex records saved in the offline workspace
(KB-integration-plan 7.2 pair rules, 8.1). Synthetic records; sockets denied; nothing is fetched."""
from __future__ import annotations

import gzip
import json

import kbc_helpers as h
import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import NOW, Kb, write_pair
from kbc_k5_support import FIXTURES, record

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.ports import IndexPort
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore

pytestmark = pytest.mark.usefixtures('no_sockets')
DRV, NET = 'exampledrv.sys', 'examplenet.sys'
ARM64 = 0xAA64


@pytest.fixture
def kb(tmp_path, capsys):
    return Kb(tmp_path, capsys)


def cvrf() -> bytes:
    """The baseline month with a product name the alias catalog maps to the Winbindex key 11-24H2."""
    return h.read_fixture_bytes('cvrf-2099-Feb.json').replace(
        b'Example OS 24H2 x64', b'Windows 11 Version 24H2 for x64-based Systems')


def load_month(kb: Kb) -> None:
    raw = cvrf()
    with WorkspaceStore(kb.workspace) as ws:
        ws.add_document(import_bytes(raw, now=NOW), raw)


def save_record(kb: Kb, name: str = DRV, date: str = '2099-02-12', doc: dict | None = None, gz: bool = False) -> None:
    folder = kb.workspace / wiring.INDEX_DIR
    folder.mkdir(parents=True, exist_ok=True)
    body = json.dumps(record(name) if doc is None else doc).encode('utf-8')
    (folder / f'{name}@{date}.json{".gz" if gz else ""}').write_bytes(gzip.compress(body) if gz else body)


def investigation(kb: Kb) -> tuple[str, dict[str, str]]:
    """Investigation id and the product scope ids by label (client amd64, server)."""
    code, doc = kb.search('CVE-2099-20001')
    assert code == 0
    scopes = doc['result']['scopes']
    pick = {'client': next(s for s in scopes if s['family'] == 'windows-client' and s['architecture'] == 'amd64'),
            'server': next(s for s in scopes if s['family'] == 'windows-server')}
    return doc['result']['investigation_id'], {k: v['scope_id'] for k, v in pick.items()}


@pytest.fixture
def ready(kb):
    load_month(kb)
    return kb, *investigation(kb)


# ---------------------------------------------------------------------------------------------------- kb pairs

def test_changed_in_kb_gives_a_grade_a_pending_pair_and_skipped_entries_make_it_partial(ready):
    kb, inv, scopes = ready
    save_record(kb)
    code, doc, _ = kb('pairs', inv, '--product', scopes['client'], '--file', DRV)
    (pair,) = doc['result']['pairs']
    assert (code, doc['status']) == (3, 'partial') and doc['result']['skipped_rows'] == 2
    assert (pair['grade'], pair['bytes_state'], pair['lineage_state']) == ('A', 'pending', 'index-adjacent')
    assert pair['older_sha256'] == 'c' * 64 and pair['newer_sha256'] == 'd' * 64
    assert 'INDEX_GAP' in pair['reason_codes'] and doc['warnings']


def test_a_clean_record_is_complete_and_names_the_confounding_window(ready):
    kb, inv, scopes = ready
    save_record(kb, NET)
    code, doc, _ = kb('pairs', inv, '--product', scopes['client'], '--file', NET)
    (pair,) = doc['result']['pairs']
    assert (code, doc['status'], doc['result']['skipped_rows']) == (0, 'complete', 0)
    assert pair['changed_in_kb'] == 'no' and pair['window'] == ['KB5097000', 'KB5098000']
    assert 'WINDOW_CONFOUNDED' in pair['reason_codes']


def test_the_selected_product_and_entered_names_come_from_earlier_steps(ready):
    kb, inv, scopes = ready
    save_record(kb, NET)
    assert kb('components', inv, '--product', scopes['client'], '--file', NET)[0] == 0
    code, doc, _ = kb('pairs', inv)  # no flags: the product and name are the investigation's
    assert code == 0 and doc['result']['pairs'][0]['file_name'] == NET


def test_legacy_product_identity_is_retained_but_cannot_resolve_current_pairs(kb, monkeypatch):
    from patchtrace.kbcorrelation import products
    from patchtrace.kbcorrelation.contracts import domain_id

    def legacy_id(facts):
        informative = facts.family != 'unknown' and facts.release is not None and not facts.conflicts
        return domain_id('kbc.scope', 1, {
            'family': facts.family, 'release': facts.release, 'architecture': facts.architecture,
            'channel': facts.channel, 'edition': facts.edition, 'build': None,
            'name': None if informative else facts.name_key})

    with monkeypatch.context() as previous:
        previous.setattr(products, 'scope_id_for', legacy_id)
        load_month(kb)
        inv, scopes = investigation(kb)
        assert kb('components', inv, '--product', scopes['client'], '--file', NET)[0] == 0
        older, newer = write_pair(kb.workspace.parent)
        project = kb.workspace.parent / 'legacy-project'
        assert kb('import-pair', inv, '--older', str(older), '--newer', str(newer),
                  '--project', str(project))[0] == 0
        old_export = kb.workspace.parent / 'legacy-before.json'
        assert kb('export', str(project), str(old_export))[0] == 0
    save_record(kb, NET)
    with WorkspaceStore(kb.workspace) as ws:
        before = ws.current_revision(inv).model_dump_json()
    code, doc, _ = kb('pairs', inv, '--product', scopes['client'], '--file', NET)
    assert code != 0 and 'repeat the search' in str(doc)
    with WorkspaceStore(kb.workspace) as ws:
        assert ws.current_revision(inv).model_dump_json() == before
    after_export = kb.workspace.parent / 'legacy-after.json'
    assert kb('export', str(project), str(after_export))[0] == 0
    assert after_export.read_bytes() == old_export.read_bytes()
    assert json.loads(after_export.read_bytes())['scope_id'] == scopes['client']
    # A new explicit search returns the corrected scope and can resolve the retained index bytes.
    fresh, current = investigation(kb)
    assert current['client'] != scopes['client']
    code, doc, _ = kb('pairs', fresh, '--product', current['client'], '--file', NET)
    assert code == 0 and doc['result']['pairs']


def test_newest_record_wins_and_gzip_is_read(ready):
    kb, inv, scopes = ready
    stale = record(NET)
    stale.clear()  # an older, empty record must lose to the newer one
    save_record(kb, NET, '2098-01-01', stale)
    save_record(kb, NET, '2099-02-12', gz=True)
    code, doc, _ = kb('pairs', inv, '--product', scopes['client'], '--file', NET)
    assert code == 0 and len(doc['result']['pairs']) == 1


def test_no_saved_records_keeps_the_offline_unavailable_answer(ready):
    kb, inv, scopes = ready
    code, doc, _ = kb('pairs', inv)
    assert (code, doc['status'], doc['result']['pairs']) == (4, 'unavailable', [])
    assert 'import-pair' in doc['result']['reason'] or 'not available offline' in doc['result']['reason']


def test_a_file_without_a_record_is_named_and_is_not_a_negative(ready):
    kb, inv, scopes = ready
    save_record(kb, NET)
    code, doc, _ = kb('pairs', inv, '--product', scopes['client'], '--file', DRV)
    assert (code, doc['status']) == (4, 'unavailable')
    assert doc['result']['files_without_record'] == [DRV] and doc['result']['pairs'] == []


def test_server_scope_is_a_stated_gap_not_an_empty_answer(ready):
    kb, inv, scopes = ready
    save_record(kb)
    code, doc, _ = kb('pairs', inv, '--product', scopes['server'], '--file', DRV)
    (res,) = doc['result']['resolutions']
    assert code == 4 and res['blockers'] == ['SERVER_NOT_COVERED'] and 'Server-only' in res['note']


def test_scope_without_an_index_key_is_not_guessed(kb):
    raw = h.read_fixture_bytes('cvrf-2099-Feb.json')  # "Example OS" has no Winbindex key
    with WorkspaceStore(kb.workspace) as ws:
        ws.add_document(import_bytes(raw, now=NOW), raw)
    save_record(kb)
    inv, scopes = investigation(kb)
    code, doc, _ = kb('pairs', inv, '--product', scopes['client'], '--file', DRV)
    assert code == 4 and doc['result']['resolutions'][0]['blockers'] == ['NO_NEWER']


@pytest.mark.parametrize('argv,needle', [([], 'Choose the product'), (['--product', 'f' * 64], 'not one of the products'),
                                         (['--product', '{client}', '--file', 'bad/x.sys'], 'directory part')],
                         ids=['no-product', 'wrong-product', 'bad-name'])
def test_input_errors_are_exit_2(ready, argv, needle):
    kb, inv, scopes = ready
    save_record(kb)
    code, doc, err = kb('pairs', inv, *[a.format(**scopes) for a in argv])
    assert code == 2 and needle in doc['error'] and err.startswith('error:')


def test_without_a_file_name_the_answer_is_the_kb7_text(ready):
    kb, inv, scopes = ready
    save_record(kb)
    code, doc, _ = kb('pairs', inv, '--product', scopes['client'])
    assert code == 4 and doc['result']['reason'] == 'no file name'


def test_pairs_does_not_advance_the_investigation(ready):
    kb, inv, scopes = ready
    save_record(kb, NET)
    kb('pairs', inv, '--product', scopes['client'], '--file', NET)
    with WorkspaceStore(kb.workspace) as ws:
        rev = ws.current_revision(inv)
    assert rev.selected_scope_id is None and rev.state == 'METADATA_READY'


# ---------------------------------------------------------------------------------------------------- kb plan

def test_plan_previews_the_first_unblocked_pair_without_any_request(ready):
    kb, inv, scopes = ready
    save_record(kb, NET)
    code, doc, _ = kb('plan', inv, '--product', scopes['client'], '--file', NET)
    plan = doc['result']['plan']
    assert code == 0 and plan['network_requests'] == 0 and plan['consent_required'] is True
    assert plan['older_sha256'] == '1' * 64 and plan['newer_sha256'] == '2' * 64
    text = kb('plan', inv, '--product', scopes['client'], '--file', NET, as_json=False)[1]
    assert 'No request is planned or made' in text


def test_plan_accepts_a_pair_id_prefix_and_rejects_an_unknown_one(ready):
    kb, inv, scopes = ready
    save_record(kb, NET)
    flags = ('--product', scopes['client'], '--file', NET)
    pair_id = kb('pairs', inv, *flags)[1]['result']['pairs'][0]['pair_id']
    assert kb('plan', inv, '--pair', pair_id[:12], *flags)[1]['result']['plan']['pair_id'] == pair_id
    code, doc, _ = kb('plan', inv, '--pair', 'ffffffffffff', *flags)
    assert code == 2 and 'not a candidate' in doc['error']


def test_plan_of_a_blocked_pair_is_exit_2_with_the_reason_text(ready):
    kb, inv, scopes = ready
    doc = record(DRV)
    for entry in doc.values():
        entry['fileInfo']['machineType'] = ARM64
    save_record(kb, DRV, doc=doc)
    flags = ('--product', scopes['client'], '--file', DRV)
    pair_id = kb('pairs', inv, *flags)[1]['result']['pairs'][0]['pair_id']
    code, out, _ = kb('plan', inv, '--pair', pair_id, *flags)
    assert code == 2 and out['result']['pair']['grade'] == 'X' and out['result']['plan'] is None
    assert 'compares AMD64 PE files' in out['error']


def test_plan_without_candidates_is_unavailable(ready):
    kb, inv, scopes = ready
    save_record(kb, NET)
    code, doc, _ = kb('plan', inv, '--product', scopes['server'], '--file', NET)
    assert (code, doc['status']) == (4, 'unavailable') and doc['result']['plan'] is None


# ---------------------------------------------------------------------------------------------------- wiring

def test_workspace_file_index_is_an_index_port_returning_json_mappings(tmp_path):
    folder = tmp_path / wiring.INDEX_DIR
    folder.mkdir()
    (folder / f'{DRV}@2099-02-12.json').write_bytes((FIXTURES / f'{DRV}.json').read_bytes())
    index = wiring.WorkspaceFileIndex(tmp_path)
    assert isinstance(index, IndexPort) and index.available() and index.has_record(DRV)
    mappings = index.rows_for(DRV, '11-24H2')
    assert mappings and all(isinstance(m, dict) for m in mappings)
    json.dumps(mappings)  # JSON-compatible: no sibling type leaks across the port
    rows, skipped = index.rows(DRV, '11-24H2')
    assert rows and skipped == 2
    assert index.rows_for(NET, '11-24H2') == [] and not index.has_record(NET)


@pytest.mark.parametrize('body,code', [(b'{not json', 'PT-KBC-SOURCE'), (b'[]', 'PT-KBC-SOURCE')],
                         ids=['bad-json', 'not-object'])
def test_a_damaged_record_is_a_typed_error(tmp_path, body, code):
    folder = tmp_path / wiring.INDEX_DIR
    folder.mkdir()
    (folder / f'{DRV}@2099-02-12.json').write_bytes(body)
    with pytest.raises(KbcStoreError) as caught:
        wiring.WorkspaceFileIndex(tmp_path).rows_for(DRV, '11-24H2')
    assert caught.value.code == code


def test_an_empty_workspace_has_no_index(tmp_path):
    assert not wiring.WorkspaceFileIndex(tmp_path).available()
