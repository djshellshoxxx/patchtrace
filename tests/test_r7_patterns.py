"""R7 prototype guard-to-sink motif, entirely synthetic; not a security-classification oracle."""
import pytest
from tools.research.r7.patterns import assess_guard_to_sink
from tools.research.r7.slicer import Op, Scope

OLD = Scope('a' * 64, 0x1000, 'c' * 64)
NEW = Scope('b' * 64, 0x2000, 'd' * 64)


def op(uid, rva, opcode, ins=(), out=None, ctrl=()):
    return Op(uid, rva, opcode, tuple(ins), out, tuple(ctrl))


def old_unguarded():
    return (op('old', 0x1000, 'STORE', ('param:buffer', 'param:length')) ,)


def new_guarded():
    return (op('cmp', 0x2000, 'INT_LESSEQUAL', ('param:length', 'param:cap'), 'u:valid'),
            op('br', 0x2002, 'CBRANCH', ('u:valid',)),
            op('new', 0x2004, 'STORE', ('param:buffer', 'param:length'), ctrl=('br',)))


def assess(old=None, new=None):
    return assess_guard_to_sink(old if old is not None else old_unguarded(),
                                new if new is not None else new_guarded(),
                                old_scope=OLD, new_scope=NEW,
                                old_sink_uid='old', new_sink_uid='new')


def test_positive_control_linked_comparison_to_sink_is_only_candidate():
    result = assess()
    assert result.status == 'candidate'
    assert result.rule_id == 'R7-STRUCTURAL-GUARD-DELTA/0'
    assert result.evidence_uids == ('cmp', 'br', 'new')
    assert 'control-dependence-not-verified' in result.unknowns
    assert 'old-new-sink-correspondence-not-verified' in result.unknowns
    assert result.sink_types == ('STORE', 'STORE')


def test_new_check_on_unrelated_value_is_negative():
    changed = (op('cmp', 0x2000, 'INT_LESSEQUAL', ('param:other', 'param:cap'), 'u:valid'),
               op('br', 0x2002, 'CBRANCH', ('u:valid',)),
               op('new', 0x2004, 'STORE', ('param:buffer', 'param:length'), ctrl=('br',)))
    assert assess(new=changed).status == 'not-observed'


def test_old_version_already_has_a_linked_check_is_not_added_guard():
    old = (op('cmp0', 0x1000, 'INT_LESS', ('param:length', 'param:cap'), 'u:valid'),
           op('br0', 0x1002, 'CBRANCH', ('u:valid',)),
           op('old', 0x1004, 'STORE', ('param:buffer', 'param:length'), ctrl=('br0',)))
    assert assess(old=old).status == 'not-observed'


def test_missing_control_dependency_is_not_a_detected_guard():
    new = (op('cmp', 0x2000, 'INT_LESS', ('param:length', 'param:cap'), 'u:valid'),
           op('br', 0x2002, 'CBRANCH', ('u:valid',)),
           op('new', 0x2004, 'STORE', ('param:buffer', 'param:length')))
    assert assess(new=new).status == 'not-observed'


def test_unresolved_new_control_is_inconclusive():
    new = (op('new', 0x2004, 'STORE', ('param:buffer', 'param:length'), ctrl=('unknown-br',)),)
    r = assess(new=new)
    assert r.status == 'inconclusive'
    assert 'missing-control:unknown-br' in r.unknowns


def test_ambiguous_new_predicate_reaching_defs_is_inconclusive():
    new = (*new_guarded()[:1], op('cmp2', 0x2001, 'INT_LESSEQUAL', ('param:length', 'param:cap'), 'u:valid'),
           *new_guarded()[1:])
    r = assess(new=new)
    assert r.status == 'inconclusive'
    assert 'multiple-defs:u:valid' in r.unknowns


def test_old_opaque_guard_is_inconclusive_not_added():
    old = (op('legacy', 0x1000, 'CALLIND', ('param:length',)),
           op('old', 0x1004, 'STORE', ('param:buffer', 'param:length'), ctrl=('legacy',)))
    r = assess(old=old)
    assert r.status == 'inconclusive'
    assert 'older-unresolved-control' in r.unknowns


def test_different_sink_types_cannot_be_claimed_corresponding():
    new = (*new_guarded()[:-1], op('new', 0x2004, 'LOAD', ('param:buffer', 'param:length'), ctrl=('br',)))
    assert assess(new=new).status == 'inconclusive'


def test_malformed_old_new_provenance_is_rejected():
    with pytest.raises(ValueError):
        assess_guard_to_sink(old_unguarded(), new_guarded(), old_scope=OLD, new_scope=OLD,
                             old_sink_uid='old', new_sink_uid='new')


def test_missing_sink_cannot_be_passed_as_positive():
    with pytest.raises(ValueError):
        assess_guard_to_sink(old_unguarded(), new_guarded(), old_scope=OLD, new_scope=NEW,
                             old_sink_uid='absent', new_sink_uid='new')


def test_input_operation_cap_is_applied_before_unbounded_consumption():
    def enormous():
        for i in range(4098):
            if i > 4096:
                raise AssertionError('must not consume beyond cap')
            yield op(f'n{i}', i, 'COPY')
    with pytest.raises(ValueError, match='too many'):
        assess_guard_to_sink(old_unguarded(), enormous(), old_scope=OLD, new_scope=NEW,
                             old_sink_uid='old', new_sink_uid='new')


def test_candidate_never_assigns_cwe_or_security_verdict():
    r = assess()
    assert not hasattr(r, 'cwe')
    assert not hasattr(r, 'is_vulnerability')
    assert 'path-feasibility-not-verified' in r.unknowns


def test_qualifying_guard_plus_unresolved_other_control_abstains():
    new = (op('cmp', 0x2000, 'INT_LESSEQUAL', ('param:length', 'param:cap'), 'u:valid'),
           op('br', 0x2002, 'CBRANCH', ('u:valid',)),
           op('new', 0x2004, 'STORE', ('param:buffer', 'param:length'), ctrl=('br', 'unknown')))
    r = assess(new=new)
    assert r.status == 'inconclusive'
    assert 'missing-control:unknown' in r.unknowns
