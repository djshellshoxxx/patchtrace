"""SPEC-08 §4.5-4.7: identification, staging, wrong-hash rejection, promotion. No network."""
from __future__ import annotations

import hashlib
import json
import struct
import zlib

import pytest

from patchtrace.acquisition import quarantine as q
from patchtrace.acquisition import transport as tr
from patchtrace.acquisition import winbindex as wb
from patchtrace.acquisition.contracts import AcquisitionError
from patchtrace.sample import synthetic_pe

BLOB = 'https://store.blob.core.windows.net/a?sig=S'


def crc_wrap(payload: bytes) -> bytes:
    return struct.pack('<I', zlib.crc32(payload)) + payload


def write(tmp_path, data, name='f.bin'):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_identify_formats(tmp_path):
    assert q.identify(write(tmp_path, synthetic_pe(0))) == ('pe', 0x8664)
    pe32 = bytearray(synthetic_pe(0))
    offset = struct.unpack_from('<I', pe32, 0x3C)[0]
    struct.pack_into('<H', pe32, offset + 4, 0x14C)
    assert q.identify(write(tmp_path, bytes(pe32))) == ('unknown', 0x14C)
    assert q.identify(write(tmp_path, crc_wrap(b'PA30' + b'\1' * 9000))) == ('pa30', None)
    assert q.identify(write(tmp_path, crc_wrap(b'PA31' + b'\2' * 10))) == ('pa31', None)
    bad = bytearray(crc_wrap(b'PA30' + b'\1' * 10))
    bad[-1] ^= 1
    assert q.identify(write(tmp_path, bytes(bad))) == ('unknown', None)
    assert q.identify(write(tmp_path, b'PA30rawmsdelta')) == ('pa30', None)
    assert q.identify(write(tmp_path, b'MZ')) == ('unknown', None)
    assert q.identify(write(tmp_path, b'hello world')) == ('unknown', None)


class Opener:
    def __init__(self, bodies):
        self.bodies, self.calls = bodies, []

    def __call__(self, method, url, headers, timeout):
        self.calls.append((method, url))
        if 'blob' in url:
            return Resp(200, self.bodies[url.split('#')[-1]])
        return Resp(302, headers={'Location': f'{BLOB}#{url}'})


class Resp:
    def __init__(self, status, body=b'', headers=None):
        self.status, self.headers, self._body = status, headers or {}, body

    def read(self, size):
        out, self._body = self._body[:size], self._body[size:]
        return out

    def close(self):
        pass


def candidates(older: bytes, newer: bytes):
    doc = {}
    for i, data in enumerate((older, newer)):
        sha = hashlib.sha256(data).hexdigest()
        doc[sha] = {'fileInfo': {'sha256': sha, 'size': len(data), 'machineType': 34404,
                                 'timestamp': 0x1000 + i, 'virtualSize': 0x5000},
                    'windowsVersions': {'11-24H2': {f'KB{i}': {'updateInfo': {'releaseDate': f'2026-0{i + 1}-01'}}}}}
    result = wb.parse(json.dumps(doc).encode(), 'demo.sys', '2026-10-12', compressed=False)
    return result.candidates


def plan_for(older: bytes, newer: bytes, served=None):
    old, new = candidates(older, newer)
    plan = q.make_plan(old, new, wb.direct_url(old), wb.direct_url(new))
    bodies = served or {d.url: (older if d.side == 'older' else newer) for d in plan.downloads}
    return plan, tr.Transport(opener=Opener(bodies), sleep=lambda s, c: None)


def test_end_to_end_acquire_and_promote(tmp_path):
    older, newer = synthetic_pe(0), synthetic_pe(1)
    plan, transport = plan_for(older, newer)
    consent = tr.AcquisitionConsent.for_urls(d.url for d in plan.downloads)
    staging = q.create_staging(tmp_path)
    acquired = [q.acquire(d, consent, staging, transport) for d in plan.downloads]
    assert [a.format for a in acquired] == ['pe', 'pe']
    assert acquired[0].sha256 == hashlib.sha256(older).hexdigest()
    assert acquired[0].provenance.redirect_host == 'store.blob.core.windows.net'
    assert 'sig=' not in acquired[0].model_dump_json()
    assert 'Authenticode' in acquired[0].authenticity
    service = q.promote(acquired[0], acquired[1], 'demo', tmp_path / 'project')
    try:
        names = {a.side: (a.name, a.sha256) for a in service.project.artifacts}
        assert names['older'] == ('demo.sys', acquired[0].sha256)
        notes = [n for n in service.project.annotations if n.text.startswith(q.ANNOTATION_PREFIX)]
        assert len(notes) == 2
        record = json.loads(notes[0].text[len(q.ANNOTATION_PREFIX):])
        assert record['provenance']['source_url'].startswith('https://msdl.microsoft.com/')
        assert 'path' not in record
    finally:
        service.close()
    q.remove_staging(staging)
    assert not staging.exists()


def test_wrong_hash_never_reaches_staging_as_artifact(tmp_path):
    older, newer = synthetic_pe(0), synthetic_pe(1)
    plan, _ = plan_for(older, newer)
    transport = tr.Transport(opener=Opener({d.url: newer for d in plan.downloads}), sleep=lambda s, c: None)
    staging = q.create_staging(tmp_path)
    consent = tr.AcquisitionConsent.for_urls(d.url for d in plan.downloads)
    with pytest.raises(AcquisitionError) as err:
        q.acquire(plan.downloads[0], consent, staging, transport)
    assert err.value.code == 'PT-ACQ-VERIFY'
    assert list((staging / 'older').iterdir()) == []


def test_non_pe_cannot_be_promoted(tmp_path):
    older, newer = crc_wrap(b'PA30' + b'\0' * 50), synthetic_pe(1)
    plan, transport = plan_for(older, newer)
    consent = tr.AcquisitionConsent.for_urls(d.url for d in plan.downloads)
    staging = q.create_staging(tmp_path)
    acquired = [q.acquire(d, consent, staging, transport) for d in plan.downloads]
    assert acquired[0].format == 'pa30'
    with pytest.raises(AcquisitionError, match='not an AMD64 PE'):
        q.promote(acquired[0], acquired[1], 'x', tmp_path / 'p')
    assert not (tmp_path / 'p' / 'project.sqlite3').exists()
    with pytest.raises(AcquisitionError):
        q.promote(acquired[1], acquired[0], 'x', tmp_path / 'p')


def test_plan_requires_x64_downloadable_distinct_builds():
    old, new = candidates(synthetic_pe(0), synthetic_pe(1))
    with pytest.raises(AcquisitionError):
        q.make_plan(old, old, wb.direct_url(old), wb.direct_url(old))
    with pytest.raises(AcquisitionError):
        q.make_plan(old, new, 'https://evil.example/demo.sys', wb.direct_url(new))
    arm = old.model_copy(update={'machine_type': 43620})
    with pytest.raises(AcquisitionError, match='x64'):
        q.make_plan(arm, new, wb.direct_url(old), wb.direct_url(new))
