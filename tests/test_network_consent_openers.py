"""Each shipped opener is unreachable without its consent object, and with one it reaches urllib exactly once, for the
exact consented URL (SPEC-42 R1, rows 1 to 6). The default openers are the real ones; the network guard
(tests/network_guard.py) stops the single consented request, so nothing leaves the process.

The LLM opener (rows 7 and 8) is owned by SPEC-41 and tested with the provider modules."""
from __future__ import annotations

import pytest
from network_guard import Attempt, NetworkAttempt, network_guard_fixture  # noqa: F401

from patchtrace.acquisition import transport as acquisition
from patchtrace.acquisition.contracts import AcquisitionError
from patchtrace.enrichment import intelligence
from patchtrace.enrichment.contracts import EnrichmentError
from patchtrace.intelligence.contracts import IntelError
from patchtrace.intelligence.csaf import transport as csaf

SYMBOL_URL = 'https://msdl.microsoft.com/download/symbols/ntdll.dll/000000011000/ntdll.dll'
OTHER_SYMBOL_URL = SYMBOL_URL.replace('000000011000', '000000021000')
CVE = 'CVE-2024-38063'
PROVIDER_METADATA = 'https://msrc.microsoft.com/csaf/provider-metadata.json'


# --- Winbindex and the Microsoft symbol server (acquisition) ------------------------------------------------------

def test_acquisition_opener_is_not_reached_without_consent(network_guard):
    consent = acquisition.AcquisitionConsent.for_urls([SYMBOL_URL])
    transport = acquisition.Transport()
    with pytest.raises(AcquisitionError) as refused:
        transport.probe(OTHER_SYMBOL_URL, consent)
    assert refused.value.code == 'PT-ACQ-CONFIG'
    with pytest.raises(AcquisitionError) as metadata:
        transport.fetch_metadata('ntdll.dll', consent)  # the Winbindex host was not consented either
    assert metadata.value.code == 'PT-ACQ-CONFIG'
    assert network_guard.attempts == []


@pytest.mark.parametrize('url', [
    'http://msdl.microsoft.com/download/symbols/ntdll.dll/000000011000/ntdll.dll',
    'https://download.microsoft.com/download/symbols/ntdll.dll/000000011000/ntdll.dll',
    'https://analyst:pw@msdl.microsoft.com/download/symbols/ntdll.dll/000000011000/ntdll.dll',
    'https://msdl.microsoft.com:8443/download/symbols/ntdll.dll/000000011000/ntdll.dll',
], ids=['http', 'other-host', 'userinfo', 'port'])
def test_acquisition_opener_refuses_a_consented_url_outside_its_allowlist(url, network_guard):
    with pytest.raises(AcquisitionError) as refused:
        acquisition.Transport().probe(url, acquisition.AcquisitionConsent.for_urls([url]))
    assert refused.value.code == 'PT-ACQ-NETWORK'
    assert network_guard.attempts == []


def test_acquisition_opener_makes_exactly_the_consented_request(network_guard):
    with pytest.raises(NetworkAttempt):
        acquisition.Transport().probe(SYMBOL_URL, acquisition.AcquisitionConsent.for_urls([SYMBOL_URL]))
    assert network_guard.claim() == [Attempt('urllib', SYMBOL_URL)]


# --- NVD and MSRC CVE data (enrichment) ---------------------------------------------------------------------------

def test_cve_opener_is_not_reached_unless_every_request_is_consented(network_guard):
    plan = intelligence.plan_requests([CVE], ['nvd', 'msrc'])
    with pytest.raises(EnrichmentError) as refused:
        intelligence.fetch_all(plan, intelligence.FetchConsent.for_plan(plan[:1]))
    assert refused.value.code == 'PT-ENRICH-CONFIG'
    assert network_guard.attempts == []


def test_cve_opener_makes_exactly_the_consented_request(network_guard):
    plan = intelligence.plan_requests([CVE], ['nvd'])
    with pytest.raises(NetworkAttempt):
        intelligence.fetch_all(plan, intelligence.FetchConsent.for_plan(plan))
    assert network_guard.claim() == [Attempt('urllib', plan[0].url)]


# --- Microsoft CSAF advisories ------------------------------------------------------------------------------------

def test_csaf_opener_needs_consent_and_refuses_urls_outside_the_allowlist(network_guard):
    with pytest.raises(IntelError) as unconsented:
        csaf.CsafTransport(None)
    assert unconsented.value.code == 'PT-INTEL-CONFIG'
    with pytest.raises(IntelError):
        csaf.CsafConsent.for_hosts(['evil.example'])
    transport = csaf.CsafTransport(csaf.CsafConsent.for_hosts(['msrc.microsoft.com']))
    for url in ('https://evil.example/csaf/provider-metadata.json', 'http://msrc.microsoft.com/csaf/x.json',
                'https://msrc.microsoft.com/other/x.json', 'https://msrc.microsoft.com:8443/csaf/x.json'):
        with pytest.raises(IntelError) as refused:
            transport.get(url, 'provider-metadata')
        assert refused.value.code == 'PT-INTEL-CONFIG'
    assert network_guard.attempts == []


def test_csaf_opener_makes_exactly_the_consented_request(network_guard):
    transport = csaf.CsafTransport(csaf.CsafConsent.for_hosts(['msrc.microsoft.com']))
    with pytest.raises(NetworkAttempt):
        transport.get(PROVIDER_METADATA, 'provider-metadata')
    assert network_guard.claim() == [Attempt('urllib', PROVIDER_METADATA)]


def test_offline_csaf_reads_the_cache_and_opens_nothing(tmp_path, network_guard):
    transport = csaf.CsafTransport(None, offline=True, cache=csaf.OfflineCache(tmp_path / 'cache'))
    with pytest.raises(IntelError) as missing:
        transport.get(PROVIDER_METADATA, 'provider-metadata')
    assert missing.value.code == 'PT-INTEL-NOTFOUND'
    assert network_guard.attempts == []
