"""SPEC-31 S3 audit (card fct): verdict precedence (05 s2.5, s7) for the decompiler-relative proof COS-PSEUDO/1.

`register-only`, `address-only`, `frame` and `eh` stay `review` (05 s2.5): there is no register-renaming proof in v1,
because calling-convention registers make it unsound, and the decompiler is exactly the channel that may not show a
register change (it alpha-renames `in_`/`unaff_` registers and drops arguments beyond an inferred prototype, R-04).
So an IR `register-only` delta forbids COS-PSEUDO/1 like the other blocking classes (05 s7). Hand-assembled x86-64
through the real ingest with S3b decompiler text; synthetic, never live Ghidra evidence."""
from __future__ import annotations

import pytest
from test_unified_ir_facts import image
from unified_facts_builder import run_facts

from patchtrace.unified.contracts import Delta
from patchtrace.unified.facts import Evidence, IrEvidence, verdict

TEXT = 'void FUN_180001000(void)\n{\n  helper();\n  return;\n}\n'
SAME_TEXT = {'older': {0x1000: TEXT}, 'newer': {0x1000: TEXT}}


def test_an_argument_register_change_the_decompiler_drops_is_never_cosmetic(tmp_path):
    """`mov ecx, eax; call helper` -> `mov edx, eax; call helper`: the argument moves to another register; with an
    inferred prototype of no parameters the decompiled text of both sides is identical."""
    old = [('mov_rr', 'ECX', 'EAX'), ('call', 'helper'), ('ret',)]
    new = [('mov_rr', 'EDX', 'EAX'), ('call', 'helper'), ('ret',)]
    facts = run_facts(tmp_path, image(old), image(new), decompiled=SAME_TEXT).facts('f')
    assert dict(facts.channels)['C6'] == 'equal'
    assert facts.verdict == 'review' and facts.proof is None, (facts.verdict, facts.proof)
    assert [d.cls for d in facts.deltas] == ['register-only']


def test_the_same_text_still_proves_a_moved_function_with_mapped_targets(tmp_path):
    """Control: equal decompiler text over a pair whose IR shows no blocking delta keeps its proof."""
    body = [('mov_rr', 'ECX', 'EAX'), ('call', 'helper'), ('ret',)]
    facts = run_facts(tmp_path, image(body), image(body, f_rva=0x1100), decompiled={
        'older': {0x1000: TEXT}, 'newer': {0x1100: TEXT}}).facts('f')
    assert facts.verdict in ('unchanged', 'cosmetic') and facts.proof is not None


@pytest.mark.parametrize('cls', ['register-only', 'frame', 'eh', 'cfg', 'unknown', 'block-added'],
                         ids=['register', 'frame', 'eh', 'cfg', 'unknown', 'block'])
def test_blocking_classes_forbid_the_decompiler_proof_in_both_modes(cls):
    states = {'C0': 'differs', 'C1': 'differs', 'C2': 'differs', 'C3': 'equal', 'C4': 'equal', 'C5': 'equal',
              'C6': 'equal', 'C8': 'unavailable'}
    delta = Delta(cls=cls, channel='C2', older_rva=0x1000, newer_rva=0x1000)
    for ir in (IrEvidence(False, False, False), None):
        evidence = Evidence(states=states, deltas=(delta,), anchors=(None,), targets=(1, 0, 0), eh='absent',
                            change_signal=False, diff_types=(), limits_hit=(), ir=ir)
        facts = verdict.judge('a' * 64, 'matched', evidence).facts
        assert (facts.verdict, facts.proof) == ('review', None), (cls, ir)


def test_the_rule_versions_changed_by_the_fct_audit_move_the_result_key():
    """Verdicts computed with the old rules must be recomputed, never served from the cache (02 s5)."""
    from patchtrace.unified.registry import CHANNEL_VERSIONS, PROOF_VERSIONS
    channels, proofs = dict(CHANNEL_VERSIONS), dict(PROOF_VERSIONS)
    # fct audit (2026-11-04): C1, C2 and datamap moved to 2; A-30/A-31 (2026-11-11): datamap 3, align 2
    assert (channels['C1'], channels['C2'], channels['datamap'], channels['align']) == (2, 2, 3, 2)
    assert (proofs['COS-LAYOUT/1'], proofs['COS-PSEUDO/1']) == (2, 2)
