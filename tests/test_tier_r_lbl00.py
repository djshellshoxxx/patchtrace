"""LBL-00 contract freeze: 14 added operators and `layer`, recipe `libs`, additive `tier-r-report/1` sections, and the
`corpus.py known-answer` hook. Synthetic data only; invalid documents are redigested so only structure can fail."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration.tier_r import contracts as C  # noqa: E402
from tools.calibration.tier_r import schemas as S  # noqa: E402

NEW_SEMANTIC = ('signedness-flip', 'callee-swap', 'field-offset', 'global-swap', 'index-swap', 'branch-swap',
                'buf-resize', 'string-literal', 'api-use')
OPT = ('loop-extract', 'hotcoldsplit', 'mergefunc', 'always-inline', 'partial-inliner')


def _dump(doc) -> bytes:
    return json.dumps(doc).encode()


def _redigest(doc: dict) -> dict:
    doc['report_sha256'] = C.digest(doc, 'report_sha256')
    return doc


def test_operator_registry_counts_and_kinds():
    assert len(C.SEMANTIC_OPERATORS) == 19 and len(C.COSMETIC_OPERATORS) == 11
    assert set(NEW_SEMANTIC) <= set(C.SEMANTIC_OPERATORS) and set(OPT) == set(C.OPT_OPERATORS)
    assert set(C.SEMANTIC_OPERATORS) | set(C.COSMETIC_OPERATORS) == set(C.Operator.__args__)


@pytest.mark.parametrize('op', NEW_SEMANTIC)
def test_new_semantic_operator_valid_and_kind_enforced(op):
    doc = S.example_mutation() | {'operator': op}
    assert C.load_mutation_case(_dump(doc)).layer == 'source'
    with pytest.raises(C.ContractError):
        C.load_mutation_case(_dump(doc | {'kind': 'cosmetic'}))


@pytest.mark.parametrize('op', OPT)
def test_opt_operator_requires_opt_layer(op):
    doc = S.example_mutation() | {'operator': op, 'kind': 'cosmetic', 'layer': 'opt'}
    assert C.load_mutation_case(_dump(doc)).layer == 'opt'
    with pytest.raises(C.ContractError, match='layer opt'):
        C.load_mutation_case(_dump(doc | {'layer': 'ir'}))


def test_source_operator_cannot_use_opt_layer():
    with pytest.raises(C.ContractError, match='layer opt'):
        C.load_mutation_case(_dump(S.example_mutation() | {'layer': 'opt'}))


def test_recipe_libs_resolve_and_variant_override():
    recipe = C.load_recipes(_dump(S.example_recipes_libs())).recipes[0]
    assert recipe.libs == ('bcrypt', 'ws2_32')
    assert recipe.resolved('v0', 'f' * 40)['libs'] == ('bcrypt', 'ws2_32')
    assert recipe.resolved('v1.3', 'f' * 40)['libs'] == ('bcrypt',)
    assert C.load_recipes(_dump(S.example_recipes())).recipes[0].libs == ()


@pytest.mark.parametrize('lib', ['../x.lib', '-lfoo', 'a b', 'C:\\x.lib', ''],
                         ids=['dotdot', 'flag', 'space', 'drive', 'empty'])
def test_recipe_libs_reject_paths_and_flags(lib):
    doc = S.example_recipes_libs()
    doc['recipes'][0]['libs'] = [lib]
    with pytest.raises(C.ContractError):
        C.load_recipes(_dump(doc))


def test_old_report_still_loads_and_extended_roundtrips():
    old = C.load_report(_dump(S.example_report()))
    assert old.labels is None and old.rank is None and old.curves == () and old.scope_ids == ()
    new = C.load_report(_dump(S.example_report_extended()))
    assert new.rank['authored']['attention'].tie_rule == 'midrank' and new.engines[-1].engine == 'unified'


@pytest.mark.parametrize('engine', ['unified', 'attention'])
def test_report_engine_literal_accepts_new_engines(engine):
    doc = S.example_report()
    doc['pairs'][0]['engine'] = engine
    assert C.load_report(_dump(_redigest(doc))).pairs[0].engine == engine


@pytest.mark.parametrize('mutate', [
    lambda d: d['rank']['authored'].update(ensemble=d['rank']['authored']['attention']),
    lambda d: d['rank'].update(bogus=d['rank']['authored']),
    lambda d: d['labels']['authored']['rz-diff'].update(maybe=d['labels']['authored']['rz-diff']['changed']),
    lambda d: d['rank']['authored']['attention']['hit_at'].pop('20'),
    lambda d: d['labels']['authored']['rz-diff']['changed']['rate'].update(undefined=True),
    lambda d: d['coverage'][0].update(completed=5),
    lambda d: d['rank']['authored']['attention'].update(tie_rule='first'),
    lambda d: d.update(unknown_extra=1),
], ids=['engine-key', 'stratum-key', 'label-key', 'hit-keys', 'undefined-numbers', 'coverage-sum', 'tie-rule',
        'extra-field'])
def test_extended_report_rejects_bad_sections(mutate):
    doc = S.example_report_extended()
    mutate(doc)
    with pytest.raises(C.ContractError):
        C.load_report(_dump(_redigest(doc)))


def test_corpus_known_answer_hook(monkeypatch, capsys):
    import importlib.util
    import types

    from tools.calibration import corpus
    real = importlib.util.find_spec
    monkeypatch.setattr(importlib.util, 'find_spec', lambda name: None if name.endswith('tier_r.cli') else real(name))
    assert corpus.main(['known-answer', 'x']) == 2 and 'not available' in capsys.readouterr().err
    fake = types.ModuleType('tools.calibration.tier_r.cli')
    fake.main = lambda argv: 40 + len(argv)
    monkeypatch.setitem(sys.modules, 'tools.calibration.tier_r.cli', fake)
    monkeypatch.setattr(importlib.util, 'find_spec', lambda name: object())
    assert corpus.main(['known-answer', 'a', 'b']) == 42
