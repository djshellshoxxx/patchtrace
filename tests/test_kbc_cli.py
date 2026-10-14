"""K3: the `kb` dispatcher: grammar, envelope, exit codes 0/2/3/4/5 (KB-integration-plan 8.1). Synthetic; offline."""
from __future__ import annotations

import json
import re

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import BASELINE, Kb, fixture, write_pair

from patchtrace.kbcorrelation import cli
from patchtrace.kbcorrelation import context as ctx
from patchtrace.kbcorrelation import pairs as pr
from patchtrace.kbcorrelation import plan as plan_mod
from patchtrace.kbcorrelation import service as svc
from patchtrace.kbcorrelation.service import RELATION_LABEL

pytestmark = pytest.mark.usefixtures('no_sockets')


@pytest.fixture
def kb(tmp_path, capsys):
    return Kb(tmp_path, capsys)


def test_every_json_call_writes_exactly_one_enrichment_cli_document(kb):
    kb.loaded()
    code, doc, err = kb('search', 'KB5099001', '--offline')
    assert code == 0 and doc['contract'] == 'enrichment-cli/1' and doc['command'] == 'kb search'
    assert doc['result']['contract'] == 'kbcorrelation/1' and err == ''


@pytest.mark.parametrize('argv,code', [
    (['search', 'KB12'], 2), (['search', 'banana'], 2), (['nope'], 2), (['search'], 2),
    (['search', 'KB5099001', '--months', '2099-Feb', '--scope-file', 'x.json'], 2),
    (['search', 'KB5099001', '--consent-hosts', 'a.example.invalid'], 2), (['plan', 'x'], 2),
], ids=['short-kb', 'word', 'verb', 'no-lead', 'two-scopes', 'consent', 'plan'])
def test_invalid_arguments_are_exit_2_with_a_failed_document(kb, argv, code):
    got, doc, err = kb(*argv)
    assert got == code and doc['status'] == 'failed' and doc['result'] is None and err.startswith('error:')


def test_help_is_exit_0_and_lists_the_verbs(kb, capsys):
    assert cli.main(['--help']) == 0
    text = capsys.readouterr().out
    assert all(verb in text for verb in ('search', 'import-pair', 'attach', 'explain', 'export', 'index'))


def test_search_exit_codes_found_not_observed_partial_and_empty(kb, tmp_path):
    empty, doc = kb.search()
    assert empty == 3 and doc['result']['coverage']['state'] == 'not_searched'  # nothing loaded is never "no result"
    kb.loaded()
    assert kb.search()[0] == 0
    assert kb.search('KB5099777')[0] == 4
    scope = tmp_path / 'scope.json'
    scope.write_text(json.dumps({'months': ['2099-Feb', '2099-Jan']}), encoding='utf-8')
    code, doc = kb.search('KB5099777', '--scope-file', str(scope))
    assert code == 3 and doc['status'] == 'partial'
    scope.write_text('{not json', encoding='utf-8')
    assert kb.search('KB5099001', '--scope-file', str(scope))[0] == 2


def test_bare_digits_and_cve_leads_work_at_the_edge(kb):
    kb.loaded()
    code, doc = kb.search('5099001')
    assert code == 0 and doc['result']['lead'] == {'kind': 'kb', 'value': 'KB5099001'}
    code, doc = kb.search('cve-2099-20001')
    assert code == 0 and {e['kb'] for e in doc['result']['edges']} == {'KB5099001', 'KB5099002'}
    assert doc['result']['cards'][0]['stated_by'] == 'stated by vendor (CVRF)'


def test_products_components_pairs_and_plan_verbs(kb):
    kb.loaded()
    _, doc = kb.search()
    inv = doc['result']['investigation_id']
    code, products, _ = kb('products', inv)
    assert code == 0 and len(products['result']['products']) == 2
    assert kb('pairs', inv)[0] == 4
    code, doc, _ = kb('components', inv, '--file', 'x.sys')
    assert code == 2 and 'Choose the product' in doc['error']
    amd64 = next(p['scope_id'] for p in products['result']['products'] if p['architecture'] == 'amd64')
    code, doc, _ = kb('components', inv, '--product', amd64, '--file', 'clfs.sys')
    assert code == 0 and doc['result']['hints'][0]['basename'] == 'clfs.sys'
    code, doc, _ = kb('components', inv, '--file', 'bad/name.sys')
    assert code == 2
    code, doc, _ = kb('plan', inv)
    assert code == 2 and 'PT-KBC-UNSUPPORTED' in doc['error']


def test_import_pair_dry_run_and_text_mode(kb, tmp_path):
    kb.loaded()
    older, newer = write_pair(tmp_path)
    code, text, _ = kb('import-pair', 'new', '--older', str(older), '--newer', str(newer), '--project',
                       str(tmp_path / 'P'), '--dry-run', as_json=False)
    assert code == 0 and 'no network request' in text and not (tmp_path / 'P').exists()


def test_a_damaged_workspace_is_a_runtime_error_not_a_traceback(kb, tmp_path):
    kb.workspace.mkdir()
    (kb.workspace / 'kbc.sqlite3').write_bytes(b'not a database' * 100)
    code, doc, err = kb('search', 'KB5099001')
    assert code == 3 and 'PT-KBC-STORAGE' in doc['error'] and 'Traceback' not in err


def test_index_verbs_run_through_the_assembler(kb):
    code, doc, _ = kb('index', 'import', fixture(BASELINE))
    assert code == 0 and doc['command'] == 'kb index import' and doc['result']['totals']['edges'] == 4
    assert kb('index', 'status')[0] == 0 and kb('index', 'verify')[0] == 0
    assert kb('index', 'plan', '--months', '2099-Feb')[0] == 0
    assert kb('index', '--help', as_json=False)[0] == 0



BANNED = re.compile(r'\b(?:probab\w*|likelihood|confidence|proven|certain\w*|safe\w*|secure\w*|is fixed|was fixed|'
                    r'patched|exploitable)\b', re.IGNORECASE)


def test_kb_strings_banned_words(kb, tmp_path):
    """Plan 6 guard 'hypothesis read as a fix': no KB-authored text or output promises likelihood, proof or safety."""
    kb.loaded()
    _, doc = kb.search()
    inv = doc['result']['investigation_id']
    older, newer = write_pair(tmp_path)
    kb('import-pair', inv, '--older', str(older), '--newer', str(newer), '--project', str(tmp_path / 'P'))
    texts = [kb('search', 'KB5099001', as_json=False)[1], kb('search', 'KB5099777', as_json=False)[1],
             kb('products', inv, as_json=False)[1], kb('pairs', inv, as_json=False)[1],
             kb('explain', str(tmp_path / 'P'), as_json=False)[1]]
    texts += [v for v in (*pr.REASON_TEXT.values(), *plan_mod.STEPS, *RELATION_LABEL.values(), ctx.LIMITATION,
                          ctx.APPLICABILITY, svc.TEXT_KB6, svc.TEXT_KB7, svc.TEXT_KB8, svc.TEXT_KB13, svc.TEXT_KB17,
                          svc.TEXT_PAIRS_E0)]
    assert [m.group(0) for t in texts for m in BANNED.finditer(t)] == []
