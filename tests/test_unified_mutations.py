"""SPEC-31 S6a planted mutants for gate G-U2 (tools/unified/mutations).

Pure part: the class registry against 08-evaluation s1 and the deterministic C generator. Compiler part (clang + lld-link
+ LLVM tools, the SPEC-32 `msvc-free` profile): every class compiles, builds and is labelled by the factory. Missing tools
are recorded as BLOCKED (tests/tier_r_helpers.py), never reported as a pass."""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
sys.path[:0] = [str(ROOT), str(TESTS)]
from tier_r_helpers import require  # noqa: E402

from tools.unified.mutations import classes, templates  # noqa: E402

SPEC = (ROOT / 'docs' / 'specs' / 'unified-engine' / '08-evaluation.md').read_text(encoding='utf-8')
IDS = [c.id for c in classes.CLASSES]


def test_every_class_names_the_words_of_the_gate_and_the_gate_names_no_other_class():
    gate_row = next(line for line in SPEC.splitlines() if line.startswith('| G-U2'))
    for entry in (*classes.CLASSES, *classes.PENDING):
        assert entry.spec_phrase in gate_row, entry.id
    listed = gate_row.split('classes:', 1)[1].split('|')[0]
    base_phrases = [c.spec_phrase for c in classes.CLASSES if not c.review_finding]
    assert all(p in listed for p in base_phrases) and len(base_phrases) == 8


def test_ids_are_unique_c_safe_and_pending_classes_say_what_they_need():
    ids = [e.id for e in (*classes.CLASSES, *classes.PENDING)]
    assert len(ids) == len(set(ids))
    assert all(re.fullmatch(r'[a-z]+(-[a-z]+)*', i) for i in ids)
    assert all(len(p.needs) > 10 and len(p.reason) > 30 for p in classes.PENDING)
    assert {p.id for p in classes.PENDING} == {'moved-rva-call', 'try-scope'}


def test_frame_only_must_land_in_review_and_every_other_class_in_material_or_review():
    by_id = {c.id: c for c in classes.CLASSES}
    assert by_id['buf-resize'].verdicts == ('review',)
    assert all(c.verdicts == ('material', 'review') for c in classes.CLASSES if c.id != 'buf-resize')
    assert all('cosmetic' not in c.verdicts and 'unchanged' not in c.verdicts for c in classes.CLASSES)


def test_classes_that_only_change_an_address_operand_use_the_symbolic_acceptance():
    symbolic = {c.id for c in classes.CLASSES if c.acceptance == 'symbolic'}
    assert symbolic == {'callee-swap', 'global-swap'}


@pytest.mark.parametrize('cid', IDS)
def test_generation_is_deterministic_and_seed_sensitive(cid):
    a, b = templates.generate(cid, 6, seed=1), templates.generate(cid, 6, seed=1)
    other = templates.generate(cid, 6, seed=2)
    assert a.base_source() == b.base_source()
    assert [a.mutant(i)[0] for i in range(6)] == [b.mutant(i)[0] for i in range(6)]
    assert a.base_source() != other.base_source()


@pytest.mark.parametrize('cid', IDS)
def test_a_mutant_differs_from_the_base_by_exactly_one_function_and_the_recorded_edit(cid):
    module = templates.generate(cid, 5, seed=3)
    base = module.base_source()
    for index in range(5):
        source, edit = module.mutant(index)
        assert source != base
        old_fn, new_fn = module.function_source(index), module.function_source(index, edit['attempt'])
        assert base.count(old_fn) == 1 and source.count(new_fn) == 1
        assert source.replace(new_fn, old_fn) == base                    # nothing else moved
        assert edit['before'] != edit['after'] and edit['function'] == module.names[index]
        assert edit['class'] == cid and edit['slots']


@pytest.mark.parametrize('cid', IDS)
def test_names_are_unique_prefixed_identifiers_and_every_function_is_defined_once(cid):
    module = templates.generate(cid, 24, seed=1)
    stem = 'ka_' + cid.replace('-', '_') + '_'
    assert len(set(module.names)) == 24 and all(re.fullmatch(stem + r'\d\d', n) for n in module.names)
    base = module.base_source()
    assert all(len(re.findall(rf'\b{n}\(', base)) == 1 for n in module.names)


@pytest.mark.parametrize('cid', IDS)
def test_every_function_has_alternative_edits_for_the_equivalent_mutant_retry(cid):
    module = templates.generate(cid, 12, seed=1)
    assert min(module.attempts(i) for i in range(12)) >= 1
    for index in range(12):
        rendered = {module.function_source(index, a) for a in range(module.attempts(index))}
        assert len(rendered) == module.attempts(index) and module.function_source(index) not in rendered


def test_the_generator_is_freestanding_c_and_never_names_a_system_header_or_microsoft_api():
    for cid in IDS:
        text = templates.generate(cid, 24, seed=1).base_source()
        assert '#include' not in text and '__try' not in text and 'asm' not in text
        assert not re.search(r'windows|microsoft|ntoskrnl|winbindex', text, re.I)


def test_an_unknown_class_or_a_silly_count_is_refused():
    with pytest.raises(KeyError):
        templates.generate('nope', 3, seed=1)
    for bad in (0, 100):
        with pytest.raises(ValueError, match='count'):
            templates.generate('constant', bad, seed=1)


# ---- compiler part ---------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('cid', IDS)
def test_every_class_compiles_as_freestanding_c11_for_the_windows_target(cid, record_live_status, tmp_path):
    chain = require(record_live_status, 'msvc-free')
    from tools.calibration.tier_r.toolchain import run_tool
    module = templates.generate(cid, 4, seed=1)
    for index in range(4):
        for attempt in range(module.attempts(index)):
            path = tmp_path / f'{cid}-{index}-{attempt}.c'
            path.write_text(module.mutant(index, attempt)[0], encoding='utf-8', newline='\n')
            run_tool([chain.path('clang'), '--target=x86_64-pc-windows-msvc', '-std=c11', '-ffreestanding',
                      '-fsyntax-only', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', str(path)],
                     check=True)


# ---- driver: build and label through the SPEC-32 factory --------------------------------------------------------------------------

def _session(record_live_status, tmp_path):
    from tools.calibration.tier_r import factory as F
    chain = require(record_live_status, 'msvc-free')
    return F.Session(chain, tmp_path / 'store')


@pytest.mark.parametrize('cid', IDS)
def test_each_class_builds_once_labels_the_planted_function_and_nothing_else(cid, record_live_status, tmp_path):
    from tools.calibration.tier_r import contracts as C
    from tools.unified.mutations import driver
    session = _session(record_live_status, tmp_path)
    module = templates.generate(cid, 2, seed=1)
    result = driver.build_mutants(session, module, work=tmp_path / 'work')
    assert len(result.docs) == 2 and not result.exhausted
    assert len(session.builds) == 1 + 2                                  # one base image shared by both mutants
    for index, doc in enumerate(result.docs):
        assert C.load_labels(C.dump_json(doc)).pair_id == doc['pair_id']   # strict round trip
        assert (doc['stratum'], doc['method'], doc['label_source']) == ('mutation', 'mutation', 'planted-mutation')
        target = module.names[index]
        planted = [f for f in doc['functions'] if f['label'] == 'changed']
        assert [f['name'] for f in planted] == [target]
        assert planted[0]['change_kind'] == cid and planted[0]['check'] == 'ok'
        rest = [f for f in doc['functions'] if f['name'] != target]
        assert rest and {f['label'] for f in rest} == {'unchanged'}, {f['name']: f['label'] for f in rest}
        assert doc['case']['unified_class'] == cid and doc['case']['target'] == target
        assert doc['case']['verdicts'] == list(classes.BY_ID[cid].verdicts)
        if classes.BY_ID[cid].acceptance == 'symbolic':
            assert planted[0]['body'] == 'address-only'                  # masked bodies are equal by design
        else:
            assert planted[0]['body'] == 'different'


def _synthetic(class_id, skeleton, values, *edits):
    return templates.Module(class_id, 0, templates._BASE, ('ka_syn_00',), (templates.Template(skeleton, values, edits),))


def test_an_equivalent_mutant_is_retried_with_the_next_edit(record_live_status, tmp_path):
    from tools.unified.mutations import driver
    session = _session(record_live_status, tmp_path)
    module = _synthetic('constant', 'u32 ${name}(u32 a)\n{\n    /* ${note} */\n    return a * ${k}u;\n}\n',
                        {'name': 'ka_syn_00', 'note': 'one', 'k': '4113'}, {'note': 'two'}, {'k': '4117'})
    result = driver.build_mutants(session, module, work=tmp_path / 'work')
    assert len(result.docs) == 1 and result.docs[0]['case']['attempts'] == 2
    assert [r['attempt'] for r in result.rejected] == [0] and 'unchanged' in result.rejected[0]['reason']
    assert result.docs[0]['case']['rejected'] == result.rejected


def test_a_function_whose_every_edit_is_equivalent_is_exhausted_not_labelled(record_live_status, tmp_path):
    from tools.unified.mutations import driver
    session = _session(record_live_status, tmp_path)
    module = _synthetic('constant', 'u32 ${name}(u32 a)\n{\n    /* ${note} */\n    return a * 4113u;\n}\n',
                        {'name': 'ka_syn_00', 'note': 'one'}, {'note': 'two'}, {'note': 'three'})
    result = driver.build_mutants(session, module, work=tmp_path / 'work')
    assert result.docs == [] and result.exhausted == [0] and len(result.rejected) == 2


def test_a_symbolic_class_with_a_comment_only_edit_is_exhausted_too(record_live_status, tmp_path):
    from tools.unified.mutations import driver
    session = _session(record_live_status, tmp_path)
    module = _synthetic('callee-swap', 'int ${name}(int x)\n{\n    /* ${note} */\n    return x * 3;\n}\n',
                        {'name': 'ka_syn_00', 'note': 'one'}, {'note': 'two'})
    result = driver.build_mutants(session, module, work=tmp_path / 'work')
    assert result.docs == [] and result.exhausted == [0]


def _sides(before, after):
    from types import SimpleNamespace

    from tools.calibration.tier_r.bodyhash import Disassembly

    def make(texts):
        return SimpleNamespace(disasm=Disassembly([0x1000 + 4 * k for k in range(len(texts))], texts, {}, 0, 0x2000, ''))
    return make(before), make(after)


def _record(**fields):
    return {'check': 'disagree', 'body': 'address-only', 'old_rva': 0x1000, 'new_rva': 0x1000, 'old_size': 8,
            'new_size': 8, 'notes': 'x', **fields}


def test_a_symbolic_edit_is_accepted_only_when_the_symbol_references_differ():
    from tools.unified.mutations import driver
    mclass = classes.BY_ID['callee-swap']
    old, new = _sides(['call <ka_h0>', 'ret'], ['call <ka_h1>', 'ret'])
    record = _record()
    assert driver._check(mclass, record, old, new) is None
    assert record['check'] == 'ok' and 'another symbol' in record['notes']
    old, new = _sides(['call <ka_h0>', 'ret'], ['call <ka_h0>', 'ret'])
    reason = driver._check(mclass, _record(), old, new)
    assert reason is not None and 'symbol references are equal' in reason


def test_a_masked_class_never_falls_back_to_the_symbolic_proof():
    from tools.unified.mutations import driver
    old, new = _sides(['call <ka_h0>'], ['call <ka_h1>'])
    assert driver._check(classes.BY_ID['constant'], _record(), old, new) == 'the planted edit left the code unchanged'


def test_symbol_refs_keep_symbols_and_drop_local_labels_and_other_functions():
    from tools.calibration.tier_r.bodyhash import Disassembly
    from tools.unified.mutations import driver
    disasm = Disassembly(addresses=[0x1000, 0x1004, 0x1008, 0x1010], texts=[
        'call\t <ka_h0>', 'add\tesi, dword ptr  <ka_gv_3>', 'jne\t <L0>', 'call\t <ka_other>'], labels={},
        image_base=0, image_end=0x2000, tool_version='')
    assert driver.symbol_refs(disasm, 0x1000, 0x10) == ('ka_h0', 'ka_gv_3')
    assert driver.symbol_refs(disasm, 0x1010, 0x4) == ('ka_other',)
