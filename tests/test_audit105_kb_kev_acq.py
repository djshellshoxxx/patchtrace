"""Issue #105 dispositions in the KB/KEV/acquisition scope that existing regression tests do not pin.
Synthetic, offline."""
from __future__ import annotations

import kbc_helpers as h
import pytest
from kbc_k1_support import NOW, json_bytes, no_sockets  # noqa: F401

from patchtrace.acquisition import winbindex
from patchtrace.kbcorrelation.contracts import SearchScope
from patchtrace.kbcorrelation.index import ReverseIndex
from patchtrace.kbcorrelation.sources.importer import import_bytes

pytestmark = pytest.mark.usefixtures('no_sockets')


def revised(current, kb):
    doc = h.cvrf_document([h.vulnerability(
        h.CVE_A, 'rev', remediations=[h.remediation(2, kb[2:], [h.PRODUCT_CLIENT])])], release_id='2099-Feb')
    doc['document']['current_release_date'] = current
    return import_bytes(json_bytes(doc), now=NOW)


def test_a105_kbc12_a_named_superseded_file_is_reported_as_superseded_not_as_a_silent_absence():
    """KBC-12 is by design (owner decision open): the active revision answers, and the named older file's hit is
    listed apart under SUPERSEDED with a warning, so 'not observed' is never the only thing said."""
    old, new = revised('2099-02-13', 'KB5099601'), revised('2099-03-05', 'KB5099602')
    index = ReverseIndex()
    assert index.add(old) and index.add(new)
    got = index.lookup_kb('KB5099601', scope=SearchScope(kind='provided_files', doc_ids=(old.doc_id,)), now=NOW)
    assert got.status == 'not_observed' and not got.edges
    assert [e.kb for e in got.superseded] == ['KB5099601']
    assert any(w.startswith('SUPERSEDED') for w in got.warnings)


@pytest.mark.parametrize('separator', [' ', ' ', '\x1b', '\x85'], ids=['zl', 'zp', 'esc', 'nel'])
def test_a105_acq1_line_and_paragraph_separators_never_survive_winbindex_text(separator):
    cleaned = winbindex._clean(f'a{separator}b', 100)
    assert separator not in cleaned and len(cleaned) == 3


def test_a105_acq1_winbindex_text_is_bounded():
    assert len(winbindex._clean('x' * 10_000, 64)) == 64


def test_a105_rule5_deeply_nested_expectations_fail_typed(tmp_path):
    """RULE-5 (rules/matrix.py, owner rules): the nesting is refused as a typed RuleError, not a RecursionError."""
    from patchtrace.rules.errors import RuleError
    from patchtrace.rules.matrix import read_expectations
    path = tmp_path / 'expect.json'
    path.write_bytes(b'[' * 50_000 + b']' * 50_000)
    with pytest.raises(RuleError) as caught:
        read_expectations(path)
    assert caught.value.code == 'PT-RULE-INPUT'
