"""CAP-7: capability hints for the hypothesis engine (`capability-hints/1`) and the rules inventory extractor.
The committed inventory is DERIVED from real capa 9.4.0 results (matched rules only), so it is UNVERIFIED as a
rule pack. Hypotheses are built from literal CWE ids. Hermetic; no Qt."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from intel_tools_support import FIXTURES, image_getter
from test_capa_synergy import api_delta

from patchtrace.intelligence import hypotheses as hy
from patchtrace.intelligence import lexicon as lx
from patchtrace.intelligence.contracts import CVEFact, CweRef
from patchtrace.intelligence.tools import capa_hints
from patchtrace.intelligence.tools.capa_hints import FAMILY_TAGS, HINTS, TAGS, api_key, capability_context

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'src'
INVENTORY = FIXTURES / 'capa' / 'rules-inventory-9.4.0.json'
_spec = importlib.util.spec_from_file_location('capa_rules_inventory', ROOT / 'tools' / 'capa_rules_inventory.py')
inventory_tool = importlib.util.module_from_spec(_spec)
sys.modules['capa_rules_inventory'] = inventory_tool
_spec.loader.exec_module(inventory_tool)


def hypotheses_of(cwe: str):
    fact = CVEFact(source_id='b' * 64, cve='CVE-2099-30000', pointer='/vulnerabilities/0',
                   cwe=CweRef(id=cwe, name='synthetic', pointer='/vulnerabilities/0/cwe'))
    return hy.hypotheses_for(lx.classify(fact))


@pytest.fixture
def images(tmp_path):
    get, close = image_getter(tmp_path)
    yield get
    close()


@pytest.fixture
def api_changes(images):
    *_unused, result = api_delta(images)
    return result.changes


def namespaces() -> list[str]:
    return [r['namespace'] for r in json.loads(INVENTORY.read_text(encoding='utf-8'))['rules'] if r['namespace']]


# ---- the table ---------------------------------------------------------------------------------------------------

def test_every_hint_resolves_in_pinned_inventory():
    known = namespaces()
    for hint in HINTS:
        assert any(n == hint.namespace_prefix or n.startswith(hint.namespace_prefix + '/') for n in known), hint.id


def test_inventory_is_labelled_derived_and_holds_no_rule_text():
    document = json.loads(INVENTORY.read_text(encoding='utf-8'))
    assert document['status'] == 'derived-unverified' and 'DERIVED/UNVERIFIED' in document['warning']
    assert set(document['rules'][0]) == {'name', 'namespace', 'scopes', 'lib', 'rule_sha256'}
    assert 'rule:' not in INVENTORY.read_text(encoding='utf-8')


def test_table_is_consistent_with_the_hypothesis_rules():
    families = {rule.family for rule in hy.RULES}
    assert set(FAMILY_TAGS) <= families and len(FAMILY_TAGS) <= 6
    assert {t for tags in FAMILY_TAGS.values() for t in tags} <= {h.tag for h in HINTS} <= set(TAGS)
    assert len({h.id for h in HINTS}) == len(HINTS)


# ---- joins -------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('name, key', [('kernel32.CreateFileA', 'createfile'), ('CreateFileW', 'createfile'),
                                       ('ZwCreateFile', 'zwcreatefile'), ('ntdll!NtCreateFile', 'ntcreatefile'),
                                       ('Beta', 'beta'), ('RtlDosPathNameToNtPathName_U', 'rtldospathnametontpathname_u')],
                         ids=['module-A', 'W', 'plain', 'bang', 'too-short', 'underscore'])
def test_api_key_folds_module_case_and_suffix(name, key):
    assert api_key(name) == key


def test_path_hypothesis_gets_exactly_one_context_on_the_write_pair(api_changes):
    (context,) = capability_context(hypotheses_of('CWE-73'), api_changes)
    assert (context.rule_id, context.group_id, context.support) == ('R-PATH', 'm:log', 'context')
    assert [(o.rule_id, o.change) for o in context.observations] == [('write file on Windows', 'gained')]
    assert context.hint_ids == ('H-FILE-SYSTEM',) and context.lineage == ('D_capa_rules',)
    assert context.observations[0].observation_key == next(
        c.observation_key for c in api_changes if c.rule_id == 'write file on Windows')


def test_context_is_deterministic_and_order_independent(api_changes):
    forward = capability_context(hypotheses_of('CWE-73'), api_changes)
    assert forward == capability_context(hypotheses_of('CWE-73'), reversed(api_changes))


def test_api_hint_hit_joins_without_a_namespace_tag(api_changes):
    log = next(c for c in api_changes if c.rule_id == 'write file on Windows')
    apis = {f.value for f in log.newer.features if f.kind == 'api'}
    assert apis
    hypothesis = hypotheses_of('CWE-73').hypotheses[0].model_copy(update={'api_hints': tuple(sorted(apis))})
    other = log.model_copy(update={'namespace': 'host-interaction/other'})
    (context,) = capability_context(hypotheses_of('CWE-73').model_copy(update={'hypotheses': (hypothesis,)}), [other])
    assert context.api_hint_hits == tuple(sorted(apis)) and context.hint_ids == ()


def test_lost_capability_reads_the_older_side(api_changes):
    log = next(c for c in api_changes if c.rule_id == 'write file on Windows')
    apis = tuple(sorted(f.value for f in log.newer.features if f.kind == 'api'))
    hypothesis = hypotheses_of('CWE-73').hypotheses[0].model_copy(update={'api_hints': apis, 'family': 'input'})
    wrapped = hypotheses_of('CWE-73').model_copy(update={'hypotheses': (hypothesis,)})
    assert capability_context(wrapped, [log])   # gained: newer side holds the API
    assert not capability_context(wrapped, [log.model_copy(update={'change': 'lost'})])   # older side has none


@pytest.mark.parametrize('cwe', ['CWE-787', 'CWE-416', 'CWE-190', 'CWE-362'], ids=['write', 'lifetime', 'integer', 'race'])
def test_memory_safety_families_get_no_tag_context(api_changes, cwe):
    assert capability_context(hypotheses_of(cwe), api_changes) == ()


@pytest.mark.parametrize('update', [{'change': 'moved'}, {'change': 'not-compared'}, {'change': 'unchanged'},
                                    {'noise': 'detection-difference'}, {'relocation': 'candidate'},
                                    {'kind': 'library'}, {'category': 'unchanged'}],
                         ids=['moved', 'not-compared', 'unchanged', 'noise', 'relocation', 'library', 'unchanged-pair'])
def test_only_clean_gained_or_lost_rows_join(api_changes, update):
    log = next(c for c in api_changes if c.rule_id == 'write file on Windows')
    assert capability_context(hypotheses_of('CWE-73'), [log.model_copy(update=update)]) == ()


def test_absence_never_contradicts(api_changes):
    assert capability_context(hypotheses_of('CWE-73'), []) == ()
    unrelated = [c for c in api_changes if c.rule_id == 'terminate process']
    assert capability_context(hypotheses_of('CWE-73'), unrelated) == ()
    assert not {name for name in capa_hints.MechanismContext.model_fields if 'contradict' in name}


def test_hostile_text_stays_data(api_changes):
    log = next(c for c in api_changes if c.rule_id == 'write file on Windows')
    hostile = log.model_copy(update={'rule_id': '<script>alert(1)</script>‮'})
    (context,) = capability_context(hypotheses_of('CWE-73'), [hostile])
    assert context.observations[0].rule_id == '<script>alert(1)</script>‮' and context.support == 'context'


def test_module_does_not_import_qt():
    code = (f"import sys; sys.path.insert(0, {str(SRC)!r}); import patchtrace.intelligence.tools.capa_hints; "
            "sys.exit(any(m.split('.')[0] in ('PySide6', 'PyQt5', 'PyQt6') for m in sys.modules))")
    assert subprocess.run([sys.executable, '-c', code], check=False).returncode == 0


# ---- the inventory extractor -------------------------------------------------------------------------------------

RULE = b"""rule:
  meta:
    name: synthetic test rule
    namespace: test/synthetic/area
    authors:
      - nobody@example.invalid
    scopes:
      static: function
      dynamic: call
    lib: true
  features:
    - api: SyntheticApi
"""


def test_scan_rules_reads_meta_and_hashes_the_file(tmp_path):
    (tmp_path / 'sub').mkdir()
    (tmp_path / 'sub' / 'a.yml').write_bytes(RULE)
    (tmp_path / 'sub' / 'old.yml').write_bytes(b'rule:\n  meta:\n    name: "quoted"\n    scope: basic block\n  features: []\n')
    (tmp_path / 'broken.yml').write_bytes(b'rule:\n  meta:\n    namespace: x\n')
    entries, skipped = inventory_tool.scan_rules(tmp_path)
    by_name = {e['name']: e for e in entries}
    assert by_name['synthetic test rule'] == {
        'name': 'synthetic test rule', 'namespace': 'test/synthetic/area', 'scopes': {'static': 'function', 'dynamic': 'call'},
        'lib': True, 'rule_sha256': hashlib.sha256(RULE).hexdigest()}
    assert by_name['quoted']['scopes'] == {'static': 'basic block'} and by_name['quoted']['namespace'] is None
    assert skipped == ['broken.yml']


def test_from_results_reproduces_the_committed_inventory(tmp_path):
    out = tmp_path / 'inv.json'
    results = [str(FIXTURES / 'capa' / f'capa-api-{side}.json') for side in ('older', 'newer')]
    assert inventory_tool.main(['--from-results', *results, '--capa-version', '9.4.0', '-o', str(out)]) == 0
    assert out.read_bytes() == INVENTORY.read_bytes() and b'\r' not in out.read_bytes()


def test_rules_dir_inventory_is_complete_and_cli_exit_codes(tmp_path, capsys):
    rules = tmp_path / 'rules'
    rules.mkdir()
    (rules / 'a.yml').write_bytes(RULE)
    assert inventory_tool.main(['--rules-dir', str(rules), '--capa-version', '9.4.0']) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'complete'
    empty = tmp_path / 'empty'
    empty.mkdir()
    assert inventory_tool.main(['--rules-dir', str(empty), '--capa-version', '9.4.0']) == 3
    assert inventory_tool.main(['--from-results', str(tmp_path / 'missing.json'), '--capa-version', '9.4.0']) == 2
