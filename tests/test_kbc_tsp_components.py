"""Telephony provider filenames use ordinary PE selection, never target execution."""
from __future__ import annotations

import pytest

from patchtrace.acquisition.contracts import (
    AcquisitionError,
    AcquisitionQuery,
    symbol_server_url,
    validate_file_name,
)
from patchtrace.kbcorrelation.components import hints_for, normalise_name, selectable
from patchtrace.kbcorrelation.contracts import CveCard, SourceRef


def test_tsp_name_can_enter_metadata_and_symbol_plans():
    assert validate_file_name('remotesp.tsp') == 'remotesp.tsp'
    assert AcquisitionQuery(file_name='remotesp.tsp').file_name == 'remotesp.tsp'
    assert symbol_server_url('remotesp.tsp', 1, 4096) == (
        'https://msdl.microsoft.com/download/symbols/remotesp.tsp/000000011000/remotesp.tsp')


def test_analyst_tsp_selection_keeps_unknown_evidence():
    assert normalise_name(' RemoteSp.TSP ') == 'remotesp.tsp'
    hints, truncated = hints_for([], {}, ['remotesp.tsp'], 'a' * 64)
    assert not truncated and selectable(hints)
    assert [(h.basename, h.tier, h.changed_in_kb, h.claim_refs) for h in hints] == [
        ('remotesp.tsp', 'E', 'unknown', ())]


def test_title_tsp_name_stays_contextual_with_its_source_pointer():
    cve = 'CVE-2099-12345'
    source = SourceRef(doc_id='b' * 64, pointer='/Vulnerability/0', assertion='advisory_fact')
    card = CveCard(cve=cve, source_kind='cvrf', title='Issue in RemoteSp.TSP')
    hints, truncated = hints_for([card], {cve: source}, [], 'a' * 64)
    assert not truncated and not selectable(hints)
    assert [(h.basename, h.tier, h.changed_in_kb, h.claim_refs) for h in hints] == [
        ('remotesp.tsp', 'D', 'unknown', (source,))]


@pytest.mark.parametrize('name', [
    'con.tsp', 'nul.tsp', 'com1.tsp', 'lpt1.tsp', '../remotesp.tsp', 'dir/remotesp.tsp',
    r'dir\remotesp.tsp', 'remotesp.tsp:stream', 'remotesp.tsp.', 'remotesp.tsp ',
    'remotesp.tsp\x00', 'remotesp.tspx', 'remotesp.tsp.txt',
])
def test_tsp_extension_does_not_relax_basename_boundaries(name):
    with pytest.raises(AcquisitionError):
        validate_file_name(name)
