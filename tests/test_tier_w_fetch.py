"""SPEC-33 s4 (LBL-20): PDB identity and URL, SymbolTransport, fetch/resume/ledger, disk preflight, binary fetch.
Self-made fixtures only (tests/fixtures/tier_w); the opener is a fake, so there is no network and no Microsoft data."""
from __future__ import annotations

import hashlib
import sys
import threading
from types import SimpleNamespace

import pytest
from tier_w_builders import ROOT, TIER_W_FIXTURES

from patchtrace.acquisition.contracts import AcquisitionError, PlannedDownload
from patchtrace.acquisition.transport import AcquisitionConsent

sys.path.insert(0, str(ROOT))
from tools.calibration.tier_w import fetch as F  # noqa: E402
from tools.calibration.tier_w.paths import Layout, TierWError  # noqa: E402
from tools.calibration.tier_w.transport import SymbolTransport, pdb_cap_bytes  # noqa: E402

PE1, PDB1, PDB2 = (TIER_W_FIXTURES / n for n in ('tiny_v1.pe', 'tiny_v1.pdb', 'tiny_v2.pdb'))
KEY = 'E71E07E399BC13C34C4C44205044422E1'
BLOB = 'https://acct.blob.core.windows.net/c/x?sig=SECRET'
URL = f'https://msdl.microsoft.com/download/symbols/tiny_v1.pdb/{KEY}/tiny_v1.pdb'


class Resp:
    def __init__(self, status=200, body=b'', headers=None):
        self.status, self.headers, self._body = status, headers or {}, body

    def read(self, size):
        return self.read1(size)

    def read1(self, size):
        chunk, self._body = self._body[:size], self._body[size:]
        return chunk

    def close(self):
        pass


class Opener:
    def __init__(self, *responses):
        self.queue, self.calls = list(responses), []

    def __call__(self, method, url, headers, timeout):
        self.calls.append((method, url))
        return self.queue.pop(0)


def serve(body: bytes, *, redirect=True):
    first = [Resp(302, headers={'Location': BLOB})] if redirect else []
    return Opener(*first, Resp(200, body, {'Content-Length': str(len(body))}))


def fixture(tmp_path, opener, **kw):
    layout = Layout(tmp_path / 'root')
    transport = SymbolTransport(opener=opener, sleep=lambda s, c: None, min_interval=0, **kw)
    return layout, F.Ledger(layout, 'tier-w-t'), transport, AcquisitionConsent.for_urls([URL])


def test_identity_url_and_key():
    name, guid, age = F.pdb_request(PE1)
    assert (name, age) == ('tiny_v1.pdb', 1)
    assert F.guid_age(guid, age) == KEY
    assert F.pdb_url(name, guid, age) == URL


@pytest.mark.parametrize('path', ['C:\\x\\a.pdb', '/a/b/a.pdb'], ids=['win', 'posix'])
def test_pdb_name_takes_the_basename(path):
    assert F.pdb_name(path) == 'a.pdb'


@pytest.mark.parametrize('path', ['a.exe', 'a b.pdb', '..\\..\\', 'x' * 130 + '.pdb', ''],
                         ids=['ext', 'space', 'dots', 'long', 'empty'])
def test_pdb_name_rejects_odd_names(path):
    with pytest.raises(TierWError) as err:
        F.pdb_name(path)
    assert err.value.code == 'PT-TIERW-INPUT'


def test_fetch_pdb_follows_one_blob_redirect_and_records_host_only(tmp_path):
    layout, ledger, transport, consent = fixture(tmp_path, serve(PDB1.read_bytes()))
    result = F.fetch_pdb(PE1, layout, ledger, transport, consent)
    final = layout.pdb('tiny_v1.pdb', KEY)
    assert result['status'] == 'fetched' and final.read_bytes() == PDB1.read_bytes()
    assert not final.stat().st_mode & 0o222
    event = ledger.last('pdb-fetched')
    assert event['redirect_host'] == 'acct.blob.core.windows.net' and 'SECRET' not in str(ledger.log.events())
    assert event['contract'] == 'tier-w-fetch/1' and event['tier'] == 'W'
    assert list(layout.staging.iterdir()) == []


def test_fetch_pdb_resumes_without_a_request(tmp_path):
    opener = serve(PDB1.read_bytes())
    layout, ledger, transport, consent = fixture(tmp_path, opener)
    F.fetch_pdb(PE1, layout, ledger, transport, consent)
    before = len(opener.calls)
    assert F.fetch_pdb(PE1, layout, ledger, transport, consent)['status'] == 'resumed'
    assert len(opener.calls) == before


def test_fetch_pdb_refetches_when_the_stored_file_changed(tmp_path):
    layout, ledger, transport, consent = fixture(tmp_path, serve(PDB1.read_bytes()))
    F.fetch_pdb(PE1, layout, ledger, transport, consent)
    final = layout.pdb('tiny_v1.pdb', KEY)
    final.chmod(0o600)
    final.write_bytes(b'tampered')
    transport.opener = serve(PDB1.read_bytes())
    assert F.fetch_pdb(PE1, layout, ledger, transport, consent)['status'] == 'fetched'
    assert final.read_bytes() == PDB1.read_bytes()


def test_fetch_pdb_404_is_missing_not_an_error(tmp_path):
    layout, ledger, transport, consent = fixture(tmp_path, Opener(Resp(404)))
    assert F.fetch_pdb(PE1, layout, ledger, transport, consent)['status'] == 'missing'
    assert ledger.last('pdb-missing')['guid_age'] == KEY


def test_fetch_pdb_rejects_a_non_msf_body(tmp_path):
    layout, ledger, transport, consent = fixture(tmp_path, serve(b'<html>nope</html>'))
    result = F.fetch_pdb(PE1, layout, ledger, transport, consent)
    assert result == {'status': 'rejected', 'guid_age': KEY, 'reason': 'not-msf'}
    assert list(layout.staging.iterdir()) == []


def test_fetch_pdb_rejects_a_pdb_with_another_identity(tmp_path):
    layout, ledger, transport, consent = fixture(tmp_path, serve(PDB2.read_bytes()))
    assert F.fetch_pdb(PE1, layout, ledger, transport, consent)['reason'] == 'identity-mismatch'
    assert ledger.last('pdb-rejected')['reason'] == 'identity-mismatch'
    assert not layout.pdb('tiny_v1.pdb', KEY).exists()
    assert list(layout.staging.iterdir()) == []


def test_download_cap_is_enforced_and_cleans_up(tmp_path):
    layout, ledger, transport, consent = fixture(tmp_path, serve(PDB1.read_bytes()))
    with pytest.raises(AcquisitionError) as err:
        F.fetch_pdb(PE1, layout, ledger, transport, consent, cap=1000)
    assert err.value.code == 'PT-ACQ-LIMIT' and list(layout.staging.iterdir()) == []


@pytest.mark.parametrize('location', ['https://evil.example/x', 'http://acct.blob.core.windows.net/x'],
                         ids=['foreign-host', 'plain-http'])
def test_redirect_outside_the_blob_host_is_refused(tmp_path, location):
    layout, ledger, transport, consent = fixture(tmp_path, Opener(Resp(302, headers={'Location': location})))
    with pytest.raises(AcquisitionError) as err:
        F.fetch_pdb(PE1, layout, ledger, transport, consent)
    assert err.value.code == 'PT-ACQ-NETWORK'


def test_second_redirect_is_refused(tmp_path):
    two = Opener(Resp(302, headers={'Location': BLOB}), Resp(302, headers={'Location': BLOB}))
    layout, ledger, transport, consent = fixture(tmp_path, two)
    with pytest.raises(AcquisitionError) as err:
        F.fetch_pdb(PE1, layout, ledger, transport, consent)
    assert err.value.code == 'PT-ACQ-NETWORK'


def test_unconsented_url_never_reaches_the_opener(tmp_path):
    opener = serve(PDB1.read_bytes())
    layout, ledger, transport, _ = fixture(tmp_path, opener)
    other = AcquisitionConsent.for_urls(['https://msdl.microsoft.com/download/symbols/other.pdb/AA1/other.pdb'])
    with pytest.raises(AcquisitionError) as err:
        F.fetch_pdb(PE1, layout, ledger, transport, other)
    assert err.value.code == 'PT-ACQ-CONFIG' and opener.calls == []


def test_every_request_waits_for_the_min_interval(tmp_path):
    now, waits = [100.0], []

    def sleep(seconds, cancel):
        waits.append(seconds)
        now[0] += seconds

    layout = Layout(tmp_path / 'root')
    transport = SymbolTransport(opener=serve(PDB1.read_bytes()), min_interval=2.0, clock=lambda: now[0], sleep=sleep)
    F.fetch_pdb(PE1, layout, F.Ledger(layout, 'tier-w-t'), transport, AcquisitionConsent.for_urls([URL]))
    assert waits == [pytest.approx(2.0)]  # the redirect hop waited; the very first request did not


def test_cancel_before_a_request_raises_and_leaves_no_partial(tmp_path):
    cancel = threading.Event()
    cancel.set()
    layout, ledger, transport, consent = fixture(tmp_path, serve(PDB1.read_bytes()), cancel=cancel)
    with pytest.raises(AcquisitionError) as err:
        F.fetch_pdb(PE1, layout, ledger, transport, consent)
    assert err.value.code == 'PT-ACQ-CANCEL' and list(layout.staging.iterdir()) == []


def test_cancel_file_is_detected(tmp_path):
    layout = Layout(tmp_path)
    assert not F.cancelled(layout)
    layout.cancel_file.parent.mkdir(parents=True)
    layout.cancel_file.write_text('')
    assert F.cancelled(layout)


@pytest.mark.parametrize('mib', [0, 2049], ids=['zero', 'over-max'])
def test_pdb_cap_bounds(mib):
    with pytest.raises(AcquisitionError):
        pdb_cap_bytes(mib)
    assert pdb_cap_bytes(2048) == 2048 * 2**20


def test_ledger_is_hash_chained_and_tamper_evident(tmp_path):
    layout = Layout(tmp_path)
    ledger = F.Ledger(layout, 'tier-w-t')
    ledger.record('a')
    ledger.record('b', n=1)
    assert [e['seq'] for e in ledger.log.events()] == [1, 2]
    path = layout.ledger('tier-w-t')
    path.write_bytes(path.read_bytes().replace(b'"n":1', b'"n":2'))
    with pytest.raises(Exception, match='edited'):
        ledger.log.events()


# ---- plan, consent, disk ----------------------------------------------------------------------------------------

def _manifest(**over):
    sha = 'ab' * 32
    binary = {'id': 'w-1', 'tier': 'W', 'file_name': 'afd.sys', 'sha256': sha, 'size': 5000,
              'winbindex': {'timestamp': 0x5A3B2C1D, 'virtual_size': 0x3000}}
    binary.update(over)
    return SimpleNamespace(binaries=(SimpleNamespace(sha256=sha, record_sha256='cd' * 32),)), {'binaries': [binary]}


def test_plan_binaries_builds_the_symbol_server_url():
    pairs, manifest = _manifest()
    (planned,) = F.plan_binaries(pairs, manifest)
    assert planned.url == 'https://msdl.microsoft.com/download/symbols/afd.sys/5A3B2C1D3000/afd.sys'
    assert (planned.side, planned.size, planned.record_sha256) == ('older', 5000, 'cd' * 32)


@pytest.mark.parametrize('over', [{'size': None}, {'winbindex': {'timestamp': 1, 'virtual_size': 0}},
                                  {'sha256': 'ef' * 32}], ids=['no-size', 'no-image-size', 'unknown-binary'])
def test_plan_binaries_refuses_incomplete_entries(over):
    with pytest.raises(TierWError) as err:
        F.plan_binaries(*_manifest(**over))
    assert err.value.code == 'PT-TIERW-INPUT'


def test_consent_needs_every_host_named():
    assert F.consent_for([URL], ['msdl.microsoft.com']).urls == frozenset([URL])
    with pytest.raises(TierWError) as err:
        F.consent_for([URL], ['winbindex.m417z.com'])
    assert err.value.code == 'PT-TIERW-CONFIG'


def test_disk_estimate_and_preflight(tmp_path):
    mib = 2**20
    need = F.disk_needed([1 * mib, 10 * mib], pdb_cap=16 * mib)
    assert need == 11 * mib + (4 * mib + 16 * mib) + 2**30
    F.ensure_disk(tmp_path / 'not' / 'yet', need, free=lambda p: need)
    with pytest.raises(TierWError) as err:
        F.ensure_disk(tmp_path, need, free=lambda p: need - 1)
    assert err.value.code == 'PT-TIERW-CONFIG'


# ---- binaries ---------------------------------------------------------------------------------------------------

def _planned_pe():
    data = PE1.read_bytes()
    return data, PlannedDownload(
        side='older', file_name='afd.sys', sha256=hashlib.sha256(data).hexdigest(), size=len(data),
        record_sha256='cd' * 32, url='https://msdl.microsoft.com/download/symbols/afd.sys/5A3B2C1D3000/afd.sys')


def test_fetch_binary_stores_read_only_and_resumes(tmp_path):
    data, planned = _planned_pe()
    layout, ledger, transport, _ = fixture(tmp_path, serve(data))
    consent = AcquisitionConsent.for_urls([planned.url])
    root = tmp_path / 'root'
    assert F.fetch_binary(planned, root, layout, ledger, transport, consent)['status'] == 'fetched'
    final = root / 'binaries' / planned.sha256 / 'afd.sys'
    assert final.read_bytes() == data and not final.stat().st_mode & 0o222
    assert ledger.last('binary-fetched')['winbindex_record_sha256'] == 'cd' * 32
    assert F.fetch_binary(planned, root, layout, ledger, transport, consent)['status'] == 'resumed'


def test_fetch_binary_rejects_a_hash_mismatch(tmp_path):
    data, planned = _planned_pe()
    layout, ledger, transport, _ = fixture(tmp_path, serve(data[:-1] + b'\x01'))
    consent = AcquisitionConsent.for_urls([planned.url])
    with pytest.raises(AcquisitionError) as err:
        F.fetch_binary(planned, tmp_path / 'root', layout, ledger, transport, consent)
    assert err.value.code == 'PT-ACQ-VERIFY'
    assert not (tmp_path / 'root' / 'binaries').exists()
