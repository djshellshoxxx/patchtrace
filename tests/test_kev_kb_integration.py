"""kb_adapter over fake edges: structural typing, de-duplication, no-catalog and hostile input. Hermetic."""
from __future__ import annotations

from test_kev_synergy import DETECTORS, EDGES, RELEASED, Edge, Ranked, Row, make_catalog

from patchtrace.kev import kb_adapter
from patchtrace.kev.kb_adapter import summary_line, worklist

C1 = 'CVE-2099-10001'
VIEW = Ranked((Row('m-a', 1, frozenset({'BND'})), Row('m-b', 2, frozenset({'SIZE'})), Row('m-c', 3, frozenset())))


def test_duplicate_edges_collapse_to_one_section_with_the_first_kb():
    edges = [Edge('KB1', C1, ('CWE-787',)), Edge('KB2', ' cve-2099-10001 ', ('CWE-787',))]
    [section] = worklist(edges, make_catalog(), VIEW, DETECTORS, RELEASED)
    assert (section.cve_id, section.kb, section.candidates) == (C1, 'KB1', ('m-a', 'm-b'))


def test_candidates_follow_ranking_rank_not_input_order():
    shuffled = Ranked(tuple(reversed(VIEW.entries)))
    [section] = worklist([Edge('KB1', C1, ('CWE-787',))], make_catalog(), shuffled, DETECTORS, RELEASED)
    assert section.candidates == ('m-a', 'm-b')


def test_no_catalog_gives_no_catalog_cells_and_a_neutral_summary():
    sections = worklist(EDGES, None, VIEW, DETECTORS, RELEASED, order='kev-first')
    assert [s.cell.text for s in sections] == ['No catalog'] * 3
    assert [s.cve_id for s in sections] == [e.cve for e in EDGES]
    assert summary_line(sections, None, RELEASED).startswith('No KEV catalog is loaded.')
    assert all(s.timeline is None for s in sections)


def test_hostile_cve_text_is_bounded_and_never_listed():
    hostile = 'CVE-2099-10001\x1b[31m<script>' + 'A' * 500
    [section] = worklist([Edge('KB1', hostile, ())], make_catalog(), VIEW, DETECTORS, RELEASED)
    assert section.lookup.status == 'invalid-id'
    assert '\x1b' not in section.cve_id and len(section.cve_id) <= 64


def test_unknown_cwe_set_means_abstention_per_cwe_and_empty_edge_cwes_do_not():
    [section] = worklist([Edge('KB1', C1, ('CWE-416', 'CWE-999'))], make_catalog(), VIEW, DETECTORS, RELEASED)
    assert len(section.abstentions) == 2 and section.candidates == ()
    [plain] = worklist([Edge('KB1', C1, ())], make_catalog(), VIEW, DETECTORS, RELEASED)
    assert plain.abstentions == () and plain.candidates == ()


def test_adapter_does_not_import_kb_or_ranking_modules():
    source = kb_adapter.__file__
    imports = [line for line in open(source, encoding='utf-8').read().splitlines() if line.startswith(('import ', 'from '))]
    assert not any(name in line for line in imports for name in ('kbcorrelation', 'enrichment'))
