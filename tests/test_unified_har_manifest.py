"""SPEC-31 harness audit (card har): the corpus manifest takes the accepted verdicts of a mutant from the class registry,
never from the label document, and lists a malformed mutant document as ignored instead of crashing."""
from __future__ import annotations

import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path[:0] = [str(TESTS.parent), str(TESTS), str(TESTS.parent / 'src')]
from unified_s6_helpers import label_doc, mutation_doc  # noqa: E402

from tools.unified.corpus import manifest as corpus_manifest  # noqa: E402
from tools.unified.mutations import classes  # noqa: E402


def with_case(**case):
    return label_doc('mut-x-00', 'mutation', target='ka_constant_00', case=case)


def test_a_mutant_document_that_accepts_a_leak_verdict_is_ignored_not_trusted():
    for verdicts in (['material', 'cosmetic'], ['unchanged'], ['material', 'review', 'unknown']):
        doc = with_case(unified_class='constant', target='ka_constant_00', verdicts=verdicts)
        built = corpus_manifest.build([doc], {})
        assert built.pairs == () and any('verdicts' in x for x in built.ignored), verdicts


def test_a_mutant_document_without_target_or_verdicts_is_ignored_not_a_crash():
    for case in ({'unified_class': 'constant'}, {'unified_class': 'constant', 'target': 'f'},
                 {'unified_class': 'constant', 'verdicts': ['material', 'review']}):
        built = corpus_manifest.build([with_case(**case)], {})
        assert built.pairs == () and len(built.ignored) == 1


def test_the_accepted_verdicts_of_a_valid_mutant_are_the_registry_ones():
    doc = mutation_doc('mut-buf-00', 'buf-resize', 'ka_buf_resize_00')
    built = corpus_manifest.build([doc], {})
    assert built.pairs[0].mutation.verdicts == classes.BY_ID['buf-resize'].verdicts == ('review',)
    both = mutation_doc('mut-constant-00', 'constant', 'ka_constant_00')
    assert corpus_manifest.build([both], {}).pairs[0].mutation.verdicts == ('material', 'review')
