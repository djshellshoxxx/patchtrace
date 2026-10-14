"""SPEC-32 contracts: known-answer-labels/1 invariants, loaders (strict JSON, digest), recipes, mutation cases, input
views of case-card/1 and suite/1, and the generated schemas/examples in docs/schemas/corpus/. Synthetic data only."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration.tier_r import contracts as C  # noqa: E402
from tools.calibration.tier_r import schemas as S  # noqa: E402

H = {k: hashlib.sha256(k.encode()).hexdigest() for k in ('a', 'b', 'c', 'd', 'r')}


def side(sha: str, debug: str) -> dict:
    return {'sha256': sha, 'debug_sha256': debug, 'pdb_sha256': None, 'size': 4096, 'file_name': 'tiny.dll',
            'image_base': 0x180000000,
            'source': {'suite': '_template/tiny', 'version': 'v1', 'license_spdx': 'MIT'},
            'build': {'profile': 'msvc-free', 'compiler': 'clang', 'compiler_version': '18.1.3', 'opt': 'O2',
                      'recipe_digest': H['r']}}


def func(name, old, new, label='unchanged', identity='same', **extra) -> dict:
    rec = {'name': name, 'file': 'tiny.c', 'variant': None, 'old_rva': old, 'new_rva': new,
           'old_size': None if old is None else 16, 'new_size': None if new is None else 16,
           'identity': identity, 'label': label, 'change_kind': None,
           'body': 'identical' if old is not None and new is not None else 'n/a',
           'label_source': 'authored-truth', 'check': 'ok', 'taxonomy': [], 'notes': ''}
    rec.update(extra)
    return rec


def labels(**over) -> dict:
    doc = {'contract': 'known-answer-labels/1', 'pair_id': 'ours-template-tiny-v1-v2', 'stratum': 'authored',
           'method': 'suite', 'project': 'tiny', 'lineage': 'L-ours-_template-tiny', 'family': 'synthetic',
           'older': side(H['a'], H['b']), 'newer': side(H['c'], H['d']), 'label_source': 'authored-truth',
           'functions': [func('tiny_add', 0x1000, 0x1000),
                         func('tiny_clamp', 0x1010, 0x1010, 'changed', change_kind='bounds-check-added',
                              body='different'),
                         func('tiny_old_only', 0x1040, None, 'no-counterpart', 'no-counterpart'),
                         func('tiny_new_only', None, 0x1040, 'no-counterpart', 'no-counterpart')],
           'summary': {}, 'case': {'intent': 'demo'}, 'notes': []}
    doc.update(over)
    return doc


def test_finalize_sorts_summarizes_and_digests_deterministically():
    a = C.finalize_labels(labels())
    b = C.finalize_labels(labels(functions=list(reversed(labels()['functions']))))
    assert a == b and C.dump_json(a) == C.dump_json(b)
    assert a['summary']['by_label'] == {'changed': 1, 'no-counterpart': 2, 'unchanged': 1}
    assert [f['name'] for f in a['functions']][0] == 'tiny_new_only'  # (None -> -1) sorts first
    loaded = C.load_labels(C.dump_json(a))
    assert loaded.digest_sha256 == a['digest_sha256']


@pytest.mark.parametrize('mutate, text', [
    (lambda d: d['functions'].append(func('x', 0x2000, None)), 'identity same needs both'),
    (lambda d: d['functions'].append(func('x', 0x2000, 0x2000, 'changed')), 'needs a change_kind'),
    (lambda d: d['functions'].append(func('x', 0x2000, 0x2000, change_kind='oops')), 'carries no change_kind'),
    (lambda d: d['functions'].append(func('x', 0x2000, 0x2010, 'unchanged', 'ambiguous')), 'identity ambiguous'),
    (lambda d: d['functions'].append(func('x', 0x1000, 0x3000)), 'unique'),
    (lambda d: d.update(newer=side(H['a'], H['d'])), 'identical outside the aa stratum'),
    (lambda d: d.update(stratum='release'), 'does not produce stratum'),
    (lambda d: d['functions'].append(func('x', 0x2000, 0x2000, label_source='source-diff')), 'label_source'),
    (lambda d: d['functions'].append(func('x', 0x2000, 0x2000, file='../etc/passwd')), 'file'),
    (lambda d: d['functions'].append(func('x', 0x2000, 0x2000, body='n/a', old_size=None)), 'size'),
])
def test_label_invariants_rejected(mutate, text):
    doc = labels()
    mutate(doc)
    with pytest.raises(ValidationError) as info:
        C.finalize_labels(doc)
    assert text in str(info.value)


def test_loader_rejects_tamper_duplicates_nan_and_oversize():
    good = C.finalize_labels(labels())
    raw = C.dump_json(good)
    edited = json.loads(raw)
    edited['functions'][0]['notes'] = 'edited'
    with pytest.raises(C.ContractError, match='digest'):
        C.load_labels(C.dump_json(edited))
    with pytest.raises(C.ContractError, match='strict JSON'):
        C.load_labels(b'{"contract": "known-answer-labels/1", "contract": "x"}')
    with pytest.raises(C.ContractError, match='strict JSON'):
        C.load_labels(b'{"x": NaN}')
    with pytest.raises(C.ContractError, match='too large'):
        C.load_labels(b' ' * (C.MAX_LABEL_BYTES + 1))
    unsorted = dict(good)
    unsorted['functions'] = list(reversed(good['functions']))
    with pytest.raises(C.ContractError, match='sorted'):
        C.load_labels(C.dump_json(unsorted))


def test_aa_pairs_may_be_byte_identical():
    doc = labels(stratum='aa', method='aa-rebuild', label_source='same-source', newer=side(H['a'], H['b']),
                 functions=[func('tiny_add', 0x1000, 0x1000, label_source='same-source')],
                 reproducibility={'byte_identical': True})
    assert C.finalize_labels(doc)['reproducibility']['byte_identical'] is True


def recipe(**over) -> dict:
    doc = {'contract': 'tier-r-recipe/1', 'project': 'zlib', 'family': 'compression',
           'upstream_git': 'https://github.com/madler/zlib.git', 'license_spdx': 'Zlib', 'license_file': 'LICENSE',
           'license_evidence': 'LICENSE: provided as-is', 'libc': 'mingw', 'output': 'zlib1.dll',
           'sources': ['*.c'], 'exclude': ['gz*.c'], 'defines': ['ZLIB_DLL', 'NO_GZIP=1'],
           'pins': [{'ref': 'v1.3', 'commit': 'a' * 40, 'license_sha256': H['a']},
                    {'ref': 'v1.3.1', 'commit': 'b' * 40, 'license_sha256': H['b']}],
           'variants': [{'match': ['v1.3.1'], 'defines': ['ZLIB_DLL']}]}
    doc.update(over)
    return doc


def test_recipe_book_valid_and_variant_resolution():
    book = C.load_recipes(json.dumps({'contract': 'tier-r-recipes/1', 'recipes': [recipe()]}).encode())
    zlib = book.get('zlib')
    assert zlib.pin_for('b' * 40).ref == 'v1.3.1'
    assert zlib.resolved('v1.3', 'a' * 40)['defines'] == ('ZLIB_DLL', 'NO_GZIP=1')
    assert zlib.resolved('v1.3.1', 'b' * 40)['defines'] == ('ZLIB_DLL',)


@pytest.mark.parametrize('over, text', [
    ({'license_spdx': 'GPL-2.0-only'}, 'permissive'),
    ({'defines': ['X=$(rm -rf /)']}, 'unsafe define'),
    ({'cflags': ['-fplugin=evil.so']}, 'allow-list'),
    ({'upstream_git': 'http://github.com/a/b'}, 'upstream_git'),
    ({'sources': ['../outside/*.c']}, 'sources'),
    ({'pins': [{'ref': 'v1', 'commit': 'a' * 40, 'license_sha256': H['a']},
               {'ref': 'v2', 'commit': 'a' * 40, 'license_sha256': H['a']}]}, 'duplicate pin'),
])
def test_recipe_rejects_unsafe_or_non_permissive(over, text):
    with pytest.raises(C.ContractError) as info:
        C.load_recipes(json.dumps({'contract': 'tier-r-recipes/1', 'recipes': [recipe(**over)]}).encode())
    assert text in str(info.value)


def mutation_case(**over) -> dict:
    doc = {'contract': 'mutation-case/1', 'case_id': 'tiny-cmp-flip-7', 'operator': 'cmp-flip', 'kind': 'semantic',
           'seed': 7, 'base': {'suite': '_template/tiny', 'version': 'v1', 'license_spdx': 'MIT'},
           'target_file': 'tiny.c', 'target_function': 'tiny_clamp',
           'site': {'file': 'tiny.c', 'line': 6, 'column': 11, 'before': '>', 'after': '>='},
           'attempts': 1, 'rejected': [], 'patch_sha256': H['a']}
    doc.update(over)
    return doc


def test_mutation_case_kind_must_match_operator():
    assert C.load_mutation_case(json.dumps(mutation_case()).encode()).operator == 'cmp-flip'
    with pytest.raises(C.ContractError, match='semantic'):
        C.load_mutation_case(json.dumps(mutation_case(kind='cosmetic')).encode())
    with pytest.raises(C.ContractError):
        C.load_mutation_case(json.dumps(mutation_case(operator='rm-rf')).encode())


def test_input_views_read_template_suite_and_cards():
    suite = C.load_suite((ROOT / 'corpus' / 'ours' / '_template' / 'tiny' / 'suite.json').read_bytes())
    assert suite.versions == ('v1', 'v2') and suite.pairs[0].truth[1].kind == 'bounds-check-added'
    card = {'contract': 'case-card/1', 'id': 'zlib-cve-2022-37434', 'project': 'zlib',
            'upstream_git': 'https://github.com/madler/zlib.git', 'license_spdx': 'Zlib', 'license_evidence': 'x',
            'old': {'ref': 'parent', 'commit': 'a' * 40}, 'new': {'ref': 'fix', 'commit': 'b' * 40},
            'kind': 'bounds-only', 'cve': ['CVE-2022-37434'], 'semantic_change': True,
            'changed_functions': [{'name': 'inflate', 'file': 'inflate.c', 'change': 'bound'}],
            'extra_note_from_finder': 'ignored'}
    (parsed,) = C.load_cards(json.dumps([card]).encode())
    assert parsed.stratum == 'cve' and parsed.changed_functions[0].name == 'inflate'
    assert C.validate_json(C.CaseCard, dict(card, kind='no-op', semantic_change=False)).stratum == 'control'
    with pytest.raises(C.ContractError):
        C.load_cards(json.dumps(card).encode())  # not an array


def test_report_digest_checked():
    report = {'contract': 'tier-r-report/1', 'symbols': 'hidden', 'inputs': [], 'engines': [], 'strata': {},
              'pairs': [], 'wrong_matches': [], 'wrong_matches_truncated': 0, 'notes': []}
    from tools.calibration.common import digest
    report['report_sha256'] = digest(report, 'report_sha256')
    assert C.load_report(json.dumps(report).encode()).symbols == 'hidden'
    report['symbols'] = 'visible'
    with pytest.raises(C.ContractError, match='digest'):
        C.load_report(json.dumps(report).encode())


def test_schemas_and_examples_are_current_and_examples_behave():
    rendered = S.render()
    folder = ROOT / 'docs' / 'schemas' / 'corpus'
    assert {'KnownAnswerLabels.json', 'Recipe.json', 'MutationCase.json', 'TierRReport.json'} <= set(rendered)
    for name, text in rendered.items():
        assert (folder / name).read_text(encoding='utf-8') == text, name
    examples = sorted((folder / 'examples').glob('*.json'))
    assert any(p.name.startswith('valid-') for p in examples) and any(p.name.startswith('invalid-') for p in examples)
    assert {p.name for p in examples} == set(S.examples())
    for name, doc in S.examples().items():
        assert (folder / 'examples' / name).read_bytes() == C.dump_json(doc), name
    for path in examples:
        ok, _ = S.check_example(path)
        assert ok == path.name.startswith('valid-'), path.name
