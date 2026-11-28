"""Independent review regression: a Unicode basename cannot become an ASCII identity."""
from __future__ import annotations

import pytest

from patchtrace.acquisition.contracts import AcquisitionError
from tests.package_support import contracts, inventory, part, selection


@pytest.mark.parametrize('basename', ['\u212aERNEL.DLL', '\u039aERNEL.DLL', '\uff2bERNEL.DLL', '\u017fample.dll'])
def test_selected_basename_is_ascii_before_any_case_conversion(basename):
    raw = basename.encode('utf-8')
    member = part(name=raw, utf8=True, state='reverified', basis='content')
    receipt = inventory(parts=(member,), mode='recursive')
    expected = 'sample.dll' if basename.endswith('ample.dll') else 'kernel.dll'
    choice = selection(receipt, member, expected_basename=expected)
    with pytest.raises(AcquisitionError) as error:
        contracts().select_member(receipt, choice)
    assert error.value.code == 'PT-ACQ-INPUT'
    # Unicode inventory/raw identity remains intact; only PE selection refuses.
    assert receipt.parts[0].logical_path == basename
    assert receipt.parts[0].raw_name_hex == raw.hex()


@pytest.mark.parametrize('name', ['kernel.dll', 'KERNEL.DLL', 'KeRnEl.DlL', '\u03a3-folder/KERNEL.DLL'])
def test_ascii_basename_selection_keeps_case_support_and_unicode_parent_names(name):
    member = part(name=name.encode('utf-8'), utf8=True, state='reverified', basis='content')
    receipt = inventory(parts=(member,), mode='recursive')
    choice = selection(receipt, member, expected_basename='kernel.dll')
    assert contracts().select_member(receipt, choice) == member
    assert receipt.parts[0].logical_path == name
