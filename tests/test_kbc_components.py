"""K3: component hints, tiers D and E only in E0 (KB-integration-plan 3, 7.2 `ComponentHint`). Pure; synthetic."""
from __future__ import annotations

import pytest

from patchtrace.kbcorrelation import components as comp
from patchtrace.kbcorrelation.contracts import CveCard, SourceRef

SCOPE = 'a' * 64
REF = SourceRef(doc_id='b' * 64, pointer='/vulnerabilities/0', assertion='advisory_fact')


def card(cve: str, title: str) -> CveCard:
    return CveCard(cve=cve, source_kind='cvrf', title=title)


@pytest.mark.parametrize('raw,expected', [('exampledrv.sys', 'exampledrv.sys'), ('  ExampleDrv.SYS ', 'exampledrv.sys')],
                         ids=['plain', 'case-space'])
def test_names_are_lowercased_basenames(raw, expected):
    assert comp.normalise_name(raw) == expected


@pytest.mark.parametrize('raw', ['dir/x.sys', 'dir\\x.sys', 'x.txt', 'con.dll', '', '..', 'x y.sys'],
                         ids=['slash', 'backslash', 'suffix', 'device', 'empty', 'dots', 'space'])
def test_bad_names_are_refused(raw):
    with pytest.raises(ValueError):
        comp.normalise_name(raw)


def test_analyst_name_is_tier_e_and_not_evidence():
    hints, truncated = comp.hints_for([], {}, ['clfs.sys'], SCOPE)
    assert not truncated and [(h.basename, h.tier, h.changed_in_kb) for h in hints] == [('clfs.sys', 'E', 'unknown')]
    assert hints[0].reasons == ('entered by the analyst',) and hints[0].claim_refs == ()
    assert comp.selectable(hints)


def test_title_name_is_tier_d_with_a_pointer_and_never_selects_a_file():
    cards = [card('CVE-2099-20001', 'Elevation in clfs.sys driver'), card('CVE-2099-20002', 'No module here')]
    hints, _ = comp.hints_for(cards, {'CVE-2099-20001': REF}, [], SCOPE)
    assert [(h.basename, h.tier) for h in hints] == [('clfs.sys', 'D')]
    assert hints[0].claim_refs == (REF,) and 'CVE-2099-20001' in hints[0].reasons[0]
    assert not comp.selectable(hints)


def test_same_name_from_title_and_analyst_is_one_hint_at_the_documented_tier():
    hints, _ = comp.hints_for([card('CVE-2099-20001', 'Flaw in ExampleDrv.sys')], {}, ['exampledrv.sys'], SCOPE)
    assert len(hints) == 1 and hints[0].tier == 'D' and len(hints[0].reasons) == 2


def test_hints_sort_by_tier_then_name_and_the_limit_is_flagged():
    cards = [card('CVE-2099-20001', 'z.dll and a.sys')]
    hints, truncated = comp.hints_for(cards, {}, ['b.sys'], SCOPE, limit=2)
    assert [h.basename for h in hints] == ['a.sys', 'z.dll'] and truncated


def test_hint_ids_are_stable_and_scope_bound():
    first = comp.hints_for([], {}, ['x.sys'], SCOPE)[0][0]
    again = comp.hints_for([], {}, ['x.sys'], SCOPE)[0][0]
    other = comp.hints_for([], {}, ['x.sys'], 'c' * 64)[0][0]
    assert first.hint_id == again.hint_id != other.hint_id
