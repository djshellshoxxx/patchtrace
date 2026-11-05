"""Catalog signature probe (SPEC-51 D2-4): mapping, consent and platform rules over a fake probe. The real Windows
call is NOT exercised here; its acceptance is a recorded blocked item (needs Windows CI)."""
from __future__ import annotations

import sys

import pytest

from patchtrace.pe_overview.catalog_win import CatalogProbe, ConsentRequired, verify_catalog
from patchtrace.pe_overview.labels import CATALOG_LABELS, catalog_label


def fake(found=True, name=r'C:\Windows\System32\CatRoot\{F750E6C3}\Microsoft-Windows-Foo.cat', hresult=0, record=None):
    def probe(path, mode):
        if record is not None:
            record.append((path, mode))
        return CatalogProbe(found, name if found else None, hresult)
    return probe


@pytest.mark.parametrize('found,hresult,state', [
    (True, 0, 'present_trusted_no_revocation_check'),
    (True, 0x800B0109, 'present_untrusted'),
    (True, 0x80096010, 'present_untrusted'),
    (False, 0x800B0100, 'absent'),
], ids=['trusted', 'untrusted-root', 'bad-hash', 'absent'])
def test_probe_result_maps_to_a_state(found, hresult, state):
    result = verify_catalog('x.dll', probe=fake(found, hresult=hresult), platform='win32')
    assert result.state == state and result.hresult == (hresult & 0xFFFFFFFF)


def test_catalog_name_is_a_cleaned_basename():
    result = verify_catalog('x.dll', probe=fake(name='C:\\a\\b\\evil\u202e\x1b[31m.cat'), platform='win32')
    assert result.catalog_name == 'evil??[31m.cat'


def test_absent_has_no_name():
    assert verify_catalog('x.dll', probe=fake(False), platform='win32').catalog_name is None


def test_a_failing_probe_is_unavailable_not_an_exception():
    def boom(path, mode):
        raise OSError('no API')
    result = verify_catalog('x.dll', probe=boom, platform='win32')
    assert (result.state, result.hresult, result.catalog_name) == ('unavailable', None, None)


def test_other_platforms_never_touch_the_probe():
    seen = []
    result = verify_catalog('x.dll', probe=fake(record=seen), platform='linux')
    assert result.state == 'unavailable' and seen == []


@pytest.mark.skipif(sys.platform == 'win32', reason='asserts the non-Windows default')
def test_default_platform_is_this_one():
    seen = []
    assert verify_catalog('x.dll', probe=fake(record=seen)).state == 'unavailable' and seen == []


def test_online_revocation_needs_consent():
    seen = []
    with pytest.raises(ConsentRequired) as caught:
        verify_catalog('x.dll', mode='online', probe=fake(record=seen), platform='win32')
    assert 'PT-PE-CONSENT-REQUIRED' in str(caught.value) and seen == []
    verify_catalog('x.dll', mode='online', consent=True, probe=fake(record=seen), platform='win32')
    assert seen == [('x.dll', 'online')]


@pytest.mark.parametrize('mode', ['offline', 'cache'])
def test_offline_and_cache_need_no_consent(mode):
    seen = []
    verify_catalog('x.dll', mode=mode, probe=fake(record=seen), platform='win32')
    assert seen == [('x.dll', mode)]


def test_unknown_mode_is_rejected():
    with pytest.raises(ValueError):
        verify_catalog('x.dll', mode='sometimes', probe=fake(), platform='win32')


def test_every_state_has_a_closed_label():
    states = ('present_trusted_no_revocation_check', 'present_untrusted', 'absent', 'not_checked', 'unavailable')
    assert {catalog_label(s) for s in states} <= set(CATALOG_LABELS)


@pytest.mark.skipif(sys.platform != 'win32', reason='needs Windows CI; recorded as a blocked acceptance item')
def test_real_probe_on_a_system_dll_read_in_place():  # pragma: no cover - Windows CI only
    result = verify_catalog(r'C:\Windows\System32\kernel32.dll')
    assert result.state in ('present_trusted_no_revocation_check', 'present_untrusted', 'absent', 'unavailable')
